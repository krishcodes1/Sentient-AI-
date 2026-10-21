"""Tests for the Site rules routes (api/routes/security_site_rules.py): they
prove that every route is owner-only; that GET lists the owner's rules, the
four built-in categories with their kinds and site counts, the recent hits
and whether the switch is on; that POST stores a rule and answers its JSON
(201), with each refusal the owner can meet answered 422 with its plain
sentence and a duplicate 409; that PATCH and DELETE change or remove one
rule (404 for an unknown one); that PUT sets a category and "Always ask"
resets it; that Check explains which rule applies (even with the switch
off); that a write whose audit row fails is a 500 that changes nothing; and
that a rule made through the API applies to the very next browser call.

Why it exists: these routes are the only way site rules change (never from
chat), so who may call them, what they refuse and how fast a change takes
effect are the feature. Runs on the test database (SQLite, or Postgres via
TEST_DATABASE_URL); no browser, no network.
"""

from __future__ import annotations

import uuid
from typing import Any

import pytest
import pytest_asyncio
from sqlalchemy import select, update

from models.audit import AuditLog
from models.browser_site_rule import BrowserSiteRule
from models.user import User
from services.security.call_checks import CallFacts, Refuse
from services.site_rules import messages
from services.site_rules import store as store_module
from services.site_rules.service import SiteRulesService
from tests.conftest import auth_headers, make_user

BASE = "/api/security/site-rules"


@pytest.fixture
def app_state(monkeypatch):
    """main.app's state with no installation and no site-rules service (other
    tests may have wired one); a test sets its own."""
    from main import app

    monkeypatch.setattr(app.state, "installation", None, raising=False)
    monkeypatch.setattr(app.state, "site_rules", None, raising=False)
    return app.state


async def _user(session_factory, email: str, *, admin: bool) -> tuple[Any, dict[str, str]]:
    user, token = await make_user(session_factory, email)
    if admin:
        async with session_factory() as session:
            await session.execute(update(User).where(User.id == user.id).values(is_admin=True))
            await session.commit()
    return user, auth_headers(token)


@pytest_asyncio.fixture
async def owner(session_factory):
    return await _user(session_factory, "owner@example.com", admin=True)


async def _rows(session_factory) -> list[BrowserSiteRule]:
    async with session_factory() as session:
        return list((await session.execute(select(BrowserSiteRule))).scalars().all())


async def _audit(session_factory) -> list[AuditLog]:
    async with session_factory() as session:
        result = await session.execute(
            select(AuditLog).where(AuditLog.connector_name == "site_rules").order_by(AuditLog.timestamp)
        )
        return list(result.scalars().all())


class FakeInstallation:
    def __init__(self, keys: set[str] | None = None, *, raises: bool = False) -> None:
        self.keys, self.raises = keys or set(), raises

    async def enabled_keys(self) -> set[str]:
        if self.raises:
            raise RuntimeError("settings unreadable")
        return self.keys


@pytest.mark.asyncio
async def test_every_site_rules_route_is_owner_only(client, session_factory, app_state):
    _, member = await _user(session_factory, "member@example.com", admin=False)
    some_id = str(uuid.uuid4())
    calls = [
        ("GET", BASE, None),
        ("POST", BASE, {"site": "example-casino.com", "include_subdomains": True, "kind": "blocked"}),
        ("PATCH", f"{BASE}/{some_id}", {"kind": "trusted"}),
        ("DELETE", f"{BASE}/{some_id}", None),
        ("PUT", f"{BASE}/categories/banks", {"kind": "blocked"}),
        ("POST", f"{BASE}/check", {"site": "chase.com"}),
    ]
    for method, url, body in calls:
        anonymous = await client.request(method, url, json=body)
        assert anonymous.status_code in (401, 403), (method, url)
        as_member = await client.request(method, url, json=body, headers=member)
        assert as_member.status_code == 403, (method, url)
    assert await _rows(session_factory) == []


@pytest.mark.asyncio
async def test_get_lists_rules_categories_recent_hits_and_whether_the_switch_is_on(
    client, session_factory, app_state, owner
):
    _, headers = owner
    empty = await client.get(BASE, headers=headers)
    assert empty.status_code == 200
    view = empty.json()
    assert view["enabled"] is True and view["rules"] == [] and view["recent"] == []
    assert view["max_rules"] == 500
    assert [c["key"] for c in view["categories"]] == ["banks", "brokers", "crypto", "government"]
    banks = view["categories"][0]
    assert banks["label"] == "Banks and money accounts"
    assert banks["kind"] == banks["default_kind"] == "always_ask"
    assert banks["site_count"] == len(banks["sites"]) and "chase.com" in banks["sites"]
    assert all(not site.startswith("*.") for c in view["categories"] for site in c["sites"])

    created = await client.post(
        BASE, json={"site": "https://www.Chase.com/x", "include_subdomains": True, "kind": "trusted"}, headers=headers
    )
    assert created.status_code == 201
    await client.put(f"{BASE}/categories/crypto", json={"kind": "blocked"}, headers=headers)

    service = SiteRulesService(session_factory, enabled=_on)
    service.record_hit(
        user_id="someone", host="secure.chase.com", kind="always_ask", where="read",
        verdict=service_verdict(), audit=False,
    )
    app_state.site_rules = service
    app_state.installation = FakeInstallation(set())  # the switch off
    view = (await client.get(BASE, headers=headers)).json()
    assert view["enabled"] is False
    (rule,) = view["rules"]
    assert rule["pattern"] == "*.chase.com" and rule["host"] == "chase.com"
    assert rule["include_subdomains"] is True and rule["kind"] == "trusted"
    assert rule["overrides_builtin"] is True
    assert {c["key"]: c["kind"] for c in view["categories"]}["crypto"] == "blocked"
    (hit,) = view["recent"]
    assert (hit["host"], hit["kind"], hit["where"], hit["count"]) == ("secure.chase.com", "always_ask", "read", 1)
    assert "user_id" not in hit
    # A switch that cannot be read counts as on.
    app_state.installation = FakeInstallation(raises=True)
    assert (await client.get(BASE, headers=headers)).json()["enabled"] is True
    app_state.installation = FakeInstallation({"browser_site_rules"})
    assert (await client.get(BASE, headers=headers)).json()["enabled"] is True


async def _on() -> bool:
    return True


def service_verdict():
    from services.site_rules.snapshot import SiteVerdict

    return SiteVerdict("always_ask", source="builtin", pattern="*.chase.com", category="banks")


@pytest.mark.asyncio
async def test_post_creates_a_rule_and_answers_its_json(client, session_factory, app_state, owner):
    user, headers = owner
    response = await client.post(
        BASE,
        json={"site": "https://www.Example-Casino.com/x?y=1", "include_subdomains": True, "kind": "blocked"},
        headers=headers,
    )
    assert response.status_code == 201
    body = response.json()
    assert body["pattern"] == "*.example-casino.com" and body["host"] == "example-casino.com"
    assert body["include_subdomains"] is True and body["kind"] == "blocked"
    assert body["overrides_builtin"] is False
    assert body["created_at"] and body["updated_at"]
    (row,) = await _rows(session_factory)
    assert str(row.id) == body["id"] and row.created_by == user.id
    (entry,) = await _audit(session_factory)
    assert entry.action == "site_rule_created"
    assert "example-casino" not in repr(entry.request_data)
    exact = await client.post(
        BASE, json={"site": "docs.example.org", "include_subdomains": False, "kind": "trusted"}, headers=headers
    )
    assert exact.status_code == 201 and exact.json()["pattern"] == "docs.example.org"
    assert exact.json()["include_subdomains"] is False


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "body, detail",
    [
        ({"site": "   ", "kind": "blocked"}, messages.EMPTY_SITE),
        ({"site": "ftp://files.example.com", "kind": "blocked"}, messages.NOT_WEB),
        ({"site": "ex*ample.com", "kind": "blocked"}, messages.STAR_INSIDE),
        ({"site": "exa mple.com", "kind": "blocked"}, messages.UNREADABLE_SITE),
        ({"site": "localhost", "kind": "blocked"}, messages.SINGLE_LABEL),
        ({"site": "10.0.0.1", "include_subdomains": True, "kind": "blocked"}, messages.IP_SUBDOMAINS),
        ({"site": "co.uk", "include_subdomains": True, "kind": "blocked"}, messages.too_broad("*.co.uk")),
        ({"site": "*.com", "kind": "blocked"}, messages.too_broad("*.com")),
        ({"site": "x" * 5000 + ".com", "kind": "blocked"}, messages.TOO_LONG),
        ({"site": "example.com", "kind": "nope"}, messages.BAD_KIND),
        ({"site": "accounts.google.com", "kind": "blocked"}, messages.protected_block("accounts.google.com")),
        ({"site": "xn--pple-43d.com", "kind": "trusted"}, messages.lookalike_trust("xn--pple-43d.com", "apple.com")),
    ],
    ids=lambda value: str(value)[:40] if isinstance(value, dict) else "detail",
)
async def test_validation_refusals_are_422_with_the_plain_reason(
    client, session_factory, app_state, owner, body, detail
):
    _, headers = owner
    response = await client.post(BASE, json={"include_subdomains": False, **body}, headers=headers)
    assert response.status_code == 422
    assert response.json() == {"detail": detail}
    assert await _rows(session_factory) == [] and await _audit(session_factory) == []


@pytest.mark.asyncio
async def test_a_duplicate_is_409(client, session_factory, app_state, owner):
    _, headers = owner
    body = {"site": "example-casino.com", "include_subdomains": True, "kind": "blocked"}
    assert (await client.post(BASE, json=body, headers=headers)).status_code == 201
    again = await client.post(BASE, json={**body, "site": "https://WWW.example-casino.com/", "kind": "trusted"}, headers=headers)
    assert again.status_code == 409
    assert again.json() == {"detail": messages.duplicate_rule("example-casino.com")}
    assert len(await _rows(session_factory)) == 1 and len(await _audit(session_factory)) == 1


@pytest.mark.asyncio
async def test_patch_changes_the_kind_and_404s_for_an_unknown_id(client, session_factory, app_state, owner):
    _, headers = owner
    created = (
        await client.post(BASE, json={"site": "example-casino.com", "include_subdomains": True, "kind": "blocked"}, headers=headers)
    ).json()
    changed = await client.patch(f"{BASE}/{created['id']}", json={"kind": "always_ask"}, headers=headers)
    assert changed.status_code == 200 and changed.json()["kind"] == "always_ask"
    assert changed.json()["id"] == created["id"]
    for unknown in (str(uuid.uuid4()), "not-a-uuid"):
        missing = await client.patch(f"{BASE}/{unknown}", json={"kind": "trusted"}, headers=headers)
        assert missing.status_code == 404 and missing.json() == {"detail": messages.NO_SUCH_RULE}
    bad = await client.patch(f"{BASE}/{created['id']}", json={"kind": "maybe"}, headers=headers)
    assert bad.status_code == 422 and bad.json() == {"detail": messages.BAD_KIND}
    events = [entry.action for entry in await _audit(session_factory)]
    assert events == ["site_rule_created", "site_rule_updated"]
    # Blocking a sign-in host by changing an existing rule is refused too.
    protected = (
        await client.post(BASE, json={"site": "login.live.com", "include_subdomains": False, "kind": "always_ask"}, headers=headers)
    ).json()
    refused = await client.patch(f"{BASE}/{protected['id']}", json={"kind": "blocked"}, headers=headers)
    assert refused.status_code == 422 and "cannot be blocked" in refused.json()["detail"]


@pytest.mark.asyncio
async def test_delete_removes_the_rule_and_a_second_delete_is_404(client, session_factory, app_state, owner):
    _, headers = owner
    created = (
        await client.post(BASE, json={"site": "example-casino.com", "include_subdomains": False, "kind": "blocked"}, headers=headers)
    ).json()
    first = await client.delete(f"{BASE}/{created['id']}", headers=headers)
    assert first.status_code == 204 and first.content == b""
    assert await _rows(session_factory) == []
    second = await client.delete(f"{BASE}/{created['id']}", headers=headers)
    assert second.status_code == 404 and second.json() == {"detail": messages.NO_SUCH_RULE}
    assert [entry.action for entry in await _audit(session_factory)] == ["site_rule_created", "site_rule_deleted"]


@pytest.mark.asyncio
async def test_put_category_sets_and_resets_the_override(client, session_factory, app_state, owner):
    _, headers = owner
    blocked = await client.put(f"{BASE}/categories/brokers", json={"kind": "blocked"}, headers=headers)
    assert blocked.status_code == 200
    body = blocked.json()
    assert (body["key"], body["kind"], body["default_kind"]) == ("brokers", "blocked", "always_ask")
    assert body["label"] == "Brokers and investing" and body["site_count"] == len(body["sites"])
    assert [(row.target_type, row.target, row.kind) for row in await _rows(session_factory)] == [
        ("category", "brokers", "blocked")
    ]
    reset = await client.put(f"{BASE}/categories/brokers", json={"kind": "always_ask"}, headers=headers)
    assert reset.status_code == 200 and reset.json()["kind"] == "always_ask"
    assert await _rows(session_factory) == []
    unknown = await client.put(f"{BASE}/categories/casinos", json={"kind": "blocked"}, headers=headers)
    assert unknown.status_code == 404 and unknown.json() == {"detail": messages.NO_SUCH_CATEGORY}
    bad = await client.put(f"{BASE}/categories/banks", json={"kind": "sometimes"}, headers=headers)
    assert bad.status_code == 422 and bad.json() == {"detail": messages.BAD_KIND}
    events = [(entry.action, entry.request_data) for entry in await _audit(session_factory)]
    assert events == [
        ("site_category_changed", {"category": "brokers", "kind": "blocked", "previous_kind": "always_ask"}),
        ("site_category_changed", {"category": "brokers", "kind": "always_ask", "previous_kind": "blocked"}),
    ]


@pytest.mark.asyncio
async def test_check_explains_which_rule_applies_to_a_site(client, session_factory, app_state, owner):
    _, headers = owner
    builtin = (await client.post(f"{BASE}/check", json={"site": "secure.chase.com"}, headers=headers)).json()
    assert builtin == {
        "host": "secure.chase.com",
        "kind": "always_ask",
        "source": "builtin",
        "category": "banks",
        "rule_id": None,
        "pattern": "*.chase.com",
        "protected": False,
        "enabled": True,
        "explanation": (
            "secure.chase.com is on the built-in Banks and money accounts list, so Crawler asks "
            "before every action there and notes when it reads there."
        ),
    }
    created = (
        await client.post(BASE, json={"site": "example-casino.com", "include_subdomains": True, "kind": "blocked"}, headers=headers)
    ).json()
    owned = (await client.post(f"{BASE}/check", json={"site": "https://play.example-casino.com/x"}, headers=headers)).json()
    assert (owned["kind"], owned["source"], owned["rule_id"]) == ("blocked", "owner", created["id"])
    assert owned["explanation"] == (
        "Your rule for example-casino.com and subdomains (Blocked) covers play.example-casino.com, "
        "so Crawler never opens it or acts on it."
    )
    nothing = (await client.post(f"{BASE}/check", json={"site": "example.org"}, headers=headers)).json()
    assert nothing["kind"] is None and nothing["explanation"] == messages.EXPLAIN_NONE.format(host="example.org")
    # With the switch off the answer says so, and still explains the rule.
    app_state.installation = FakeInstallation(set())
    off = (await client.post(f"{BASE}/check", json={"site": "secure.chase.com"}, headers=headers)).json()
    assert off["enabled"] is False and off["kind"] == "always_ask"
    assert off["explanation"].startswith(messages.EXPLAIN_OFF_PREFIX)
    # A site Crawler cannot read is a plain 422.
    for site, detail in (
        ("", messages.EMPTY_SITE),
        ("mailto:a@b.c", messages.NOT_WEB),
        ("*", messages.STAR_INSIDE),
        ("ex*ample.com", messages.STAR_INSIDE),
    ):
        refused = await client.post(f"{BASE}/check", json={"site": site}, headers=headers)
        assert refused.status_code == 422 and refused.json() == {"detail": detail}, site


@pytest.mark.asyncio
async def test_a_write_whose_audit_row_fails_is_500_and_changes_nothing(
    client, session_factory, app_state, owner, monkeypatch
):
    _, headers = owner

    async def broken_audit(*_args: Any, **_kwargs: Any) -> None:
        raise RuntimeError("audit table locked")

    monkeypatch.setattr(store_module, "append_audit_log", broken_audit)
    response = await client.post(
        BASE, json={"site": "example-casino.com", "include_subdomains": True, "kind": "blocked"}, headers=headers
    )
    assert response.status_code == 500 and response.json() == {"detail": messages.SAVE_FAILED}
    assert await _rows(session_factory) == []
    category = await client.put(f"{BASE}/categories/banks", json={"kind": "blocked"}, headers=headers)
    assert category.status_code == 500 and await _rows(session_factory) == []


@pytest.mark.asyncio
async def test_a_rule_made_through_the_api_applies_to_the_next_browser_call(
    client, session_factory, app_state, owner
):
    _, headers = owner
    service = SiteRulesService(session_factory, enabled=_on)
    await service.refresh()
    app_state.site_rules = service
    check = service.call_check(page_origin=lambda _user: None)
    call = CallFacts(
        stage="turn",
        user_id="ann",
        tool_name="browser.read",
        canonical="browser.read",
        arguments={"action": "open", "url": "https://www.example-casino.com/"},
    )
    assert not isinstance(await check.check(call), Refuse)
    created = await client.post(
        BASE, json={"site": "example-casino.com", "include_subdomains": True, "kind": "blocked"}, headers=headers
    )
    assert created.status_code == 201
    # The route refreshed the process's snapshot: no wait for its TTL.
    refused = await check.check(call)
    assert isinstance(refused, Refuse) and refused.rule == "site_blocked"
    hook = service.guard_hook_for("ann")
    assert hook.navigation_reason("https://www.example-casino.com/", exempt=False) == messages.NAVIGATION_BLOCKED
    # Removing it applies just as fast.
    removed = await client.delete(f"{BASE}/{created.json()['id']}", headers=headers)
    assert removed.status_code == 204
    assert not isinstance(await check.check(call), Refuse)
    await service.drain()


@pytest.mark.asyncio
async def test_a_refresh_that_fails_after_a_write_still_answers_and_leaves_the_snapshot_stale(
    client, session_factory, app_state, owner
):
    _, headers = owner

    class Unrefreshable:
        def __init__(self) -> None:
            self.invalidated = 0

        def invalidate(self) -> None:
            self.invalidated += 1

        async def refresh(self) -> None:
            raise RuntimeError("database gone")

        def recent(self) -> list[dict[str, Any]]:
            return []

    service = Unrefreshable()
    app_state.site_rules = service
    response = await client.post(
        BASE, json={"site": "example-casino.com", "include_subdomains": True, "kind": "blocked"}, headers=headers
    )
    assert response.status_code == 201 and len(await _rows(session_factory)) == 1
    assert service.invalidated == 1
