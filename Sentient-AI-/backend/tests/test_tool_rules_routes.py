"""Tests for the Security page's Tool rules routes (api/routes/security_tool_rules.py): they
prove every route refuses anyone signed out (401) and any account that is not the owner (403);
that the owner sees the four built-in rules with their switches, their own rules oldest first
with plain summaries, the limits and operators the form needs and their organisation domains
(read-only); that adding a rule answers it with its summary and audits ``tool_rule_created``
with no condition value, and a refused rule is a 422 whose detail is the validator's reason
exactly (never echoing a secret-shaped value); that removing a rule or turning a built-in off
sends the owner a fact-only notice on their channels while adding a rule or turning one on
sends none; that a failed or missing notice never undoes the change (and the skip is logged);
that unknown ids and keys are 404s; that the preview counts matching reads and writes, flags
MCP patterns, answers ``valid: false`` with the reason for a bad draft and saves nothing; that
the catalog lists every tool a rule can name with its argument names and none of the runtime's
own tools; that an unreadable store shows ``store_ok: false`` and an unwired one is a 503; and
that a rule added here applies to the very next turn.

Why it exists: these routes are the only way to change what Crawler asks before (no chat
command, channel or tool can), so a hole here is a hole in every rule. A stolen web session
that loosens protection must be visible on the owner's other channels. Everything runs against
the real app over ASGI with SQLite; the owner sender and the organisation-domain helper are
recording fakes on ``app.state``.
"""

from __future__ import annotations

import uuid
from types import SimpleNamespace
from typing import Any, Optional

import pytest
import pytest_asyncio
from sqlalchemy import select, update
from structlog.testing import capture_logs

from models.audit import AuditLog
from models.user import User
from services.security.tool_rules import DbToolRuleStore, InMemoryToolRuleStore, ToolRulesCheck, texts
from services.security.tool_rules.builtins import BUILTIN_KEYS, MANY_RECIPIENTS, builtin
from services.security.tool_rules.grammar import LIMITS, OPS, catalog
from tests.conftest import auth_headers, make_user
from tests.test_call_checks_runtime import AUTO_GOOGLE_TOOLS, DRAFT, Run, call

BASE = "/api/security/tool-rules"
OWNER = "owner@myco.com"
MEMBER = "member@myco.com"
# Condition values that must never reach an audit row or a log line.
THIRD_PARTY = "someone@vendor-billing.example"


class Outbox:
    """app.state.owner_send: records every notice; ``fail`` makes it raise, ``deliver``
    False makes it answer "not delivered"."""

    def __init__(self) -> None:
        self.sent: list[tuple[str, str]] = []
        self.fail = False
        self.deliver = True

    async def send(self, user_id: str, text: str) -> bool:
        if self.fail:
            raise ConnectionError("telegram down")
        self.sent.append((user_id, text))
        return self.deliver


class OrgDomains:
    def __init__(self, domains: frozenset[str] = frozenset({"myco.com"})) -> None:
        self.domains = domains
        self.fail = False

    async def for_user(self, user_id: str) -> frozenset[str]:
        if self.fail:
            raise ConnectionError("database unreachable")
        return self.domains


class Switch:
    def __init__(self) -> None:
        self.on = True

    async def __call__(self) -> bool:
        return self.on


async def make_account(session_factory, email: str, *, admin: bool) -> tuple[User, dict[str, str]]:
    user, token = await make_user(session_factory, email=email)
    if admin:
        async with session_factory() as session:
            await session.execute(update(User).where(User.id == user.id).values(is_admin=True))
            await session.commit()
    return user, auth_headers(token)


@pytest_asyncio.fixture
async def env(client, session_factory):
    """The real store over the test database, a check reading a scripted switch, a recording
    owner sender and an organisation-domain helper on app.state (restored afterwards)."""
    from main import app

    store = DbToolRuleStore(session_factory)
    switch = Switch()
    orgs = OrgDomains()
    outbox = Outbox()
    check = ToolRulesCheck(store, enabled=switch, org_domains=orgs.for_user)
    saved = dict(app.state._state)
    app.state.tool_rules_store = store
    app.state.tool_rules_check = check
    app.state.org_domains = orgs
    app.state.owner_send = outbox.send
    owner, headers = await make_account(session_factory, OWNER, admin=True)
    try:
        yield SimpleNamespace(
            app=app,
            client=client,
            store=store,
            check=check,
            switch=switch,
            orgs=orgs,
            outbox=outbox,
            owner=owner,
            headers=headers,
            session_factory=session_factory,
        )
    finally:
        app.state._state.clear()
        app.state._state.update(saved)


async def audit_rows(session_factory, action: Optional[str] = None) -> list[AuditLog]:
    async with session_factory() as session:
        stmt = select(AuditLog).order_by(AuditLog.seq)
        if action is not None:
            stmt = stmt.where(AuditLog.action == action)
        return list((await session.execute(stmt)).scalars())


RULE = {
    "name": "Outside guests on Outlook events",
    "tool": "Microsoft.Create_Event",
    "conditions": [{"arg": "attendees", "op": "domain_not_in", "value": ["MyCo.com", "myco.org"]}],
}


async def add(env, body: Optional[dict[str, Any]] = None) -> dict[str, Any]:
    resp = await env.client.post(BASE, json=body or RULE, headers=env.headers)
    assert resp.status_code == 201, resp.text
    return resp.json()


# ---------------------------------------------------------------------------
# Who may call the routes
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_every_tool_rules_route_refuses_anyone_signed_out_and_any_non_owner(env):
    _member, member_headers = await make_account(env.session_factory, MEMBER, admin=False)
    routes = [
        ("GET", BASE, None),
        ("POST", BASE, RULE),
        ("DELETE", f"{BASE}/{uuid.uuid4()}", None),
        ("PUT", f"{BASE}/builtins/{MANY_RECIPIENTS}", {"enabled": False}),
        ("POST", f"{BASE}/preview", {"tool": "google_workspace.*", "conditions": []}),
        ("GET", f"{BASE}/catalog", None),
    ]
    for method, path, body in routes:
        kwargs: dict[str, Any] = {"json": body} if body is not None else {}
        signed_out = await env.client.request(method, path, **kwargs)
        assert signed_out.status_code == 401, (method, path)
        member = await env.client.request(method, path, headers=member_headers, **kwargs)
        assert member.status_code == 403, (method, path)
        assert member.json()["detail"] == "Only the owner of this install can change this."
    # Nothing a refused caller sent was stored, switched or announced.
    assert await env.store.list_rules() == []
    assert (await env.store.snapshot()).builtins_off == frozenset()
    assert env.outbox.sent == [] and await audit_rows(env.session_factory) == []


# ---------------------------------------------------------------------------
# Reading the page
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_the_owner_sees_builtins_rules_limits_operators_and_their_organisation_domains(env):
    created = await add(env)
    second = await add(
        env,
        {"name": "Large refunds", "tool": "mcp.stripe.*", "conditions": [{"arg": "amount", "op": "number_gt", "value": 500}]},
    )
    resp = await env.client.get(BASE, headers=env.headers)
    assert resp.status_code == 200
    view = resp.json()
    assert view["enabled"] is True and view["store_ok"] is True
    assert [b["key"] for b in view["builtins"]] == list(BUILTIN_KEYS)
    for item in view["builtins"]:
        rule = builtin(item["key"])
        assert rule is not None
        assert (item["name"], item["description"], item["enabled"], item["changed_at"]) == (
            rule.name, rule.description, True, None,
        )
    assert [r["id"] for r in view["rules"]] == [created["id"], second["id"]]
    assert view["rules"][1] == {
        "id": second["id"],
        "name": "Large refunds",
        "tool": "mcp.stripe.*",
        "conditions": [{"arg": "amount", "op": "number_gt", "value": 500}],
        "summary": 'Ask before any mcp.stripe.* call when "amount" is more than 500.',
        "created_at": second["created_at"],
        "created_by": OWNER,
    }
    assert view["org_domains"] == ["myco.com"]
    assert view["limits"] == dict(LIMITS) == {
        "max_rules": 50, "max_conditions": 5, "max_list_items": 50,
        "max_value_chars": 200, "max_regex_chars": 100, "regex_text_cap": 4000,
    }
    assert [o["op"] for o in view["operators"]] == list(OPS)
    kinds = {o["op"]: (o["label"], o["value"]) for o in view["operators"]}
    assert kinds["equals"] == ("is", "text") and kinds["in_list"][1] == "list"
    assert kinds["number_gt"][1] == "number" and kinds["regex"][1] == "pattern"

    # The switch off, a built-in off and a domain lookup that fails are all shown as they are.
    env.switch.on = False
    env.orgs.fail = True
    await env.client.put(f"{BASE}/builtins/{MANY_RECIPIENTS}", json={"enabled": False}, headers=env.headers)
    view = (await env.client.get(BASE, headers=env.headers)).json()
    assert view["enabled"] is False and view["org_domains"] == []
    [many] = [b for b in view["builtins"] if b["key"] == MANY_RECIPIENTS]
    assert many["enabled"] is False and many["changed_at"]


@pytest.mark.asyncio
async def test_an_unreadable_store_shows_store_ok_false_and_an_unwired_one_is_a_503(env):
    env.app.state.tool_rules_store = InMemoryToolRuleStore(error=True)
    view = (await env.client.get(BASE, headers=env.headers)).json()
    assert view["store_ok"] is False and view["rules"] == []
    assert all(b["enabled"] for b in view["builtins"])
    # A write that cannot reach the store says so plainly and changes nothing.
    resp = await env.client.post(BASE, json=RULE, headers=env.headers)
    assert resp.status_code == 503
    assert resp.json()["detail"] == "The tool rules could not be read or saved just now. Try again in a moment."

    del env.app.state.tool_rules_store
    for method, path in (("GET", BASE), ("POST", BASE), ("DELETE", f"{BASE}/{uuid.uuid4()}")):
        resp = await env.client.request(method, path, json=RULE if method == "POST" else None, headers=env.headers)
        assert resp.status_code == 503 and resp.json()["detail"] == "Tool rules are not available right now."


# ---------------------------------------------------------------------------
# Adding a rule
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_creating_a_rule_returns_it_with_a_summary_and_audits_tool_rule_created(env):
    body = {
        "name": "Big mailings to the press",
        "tool": "google_workspace.send_email",
        "conditions": [
            {"arg": "to", "op": "domain_in", "value": ["nytimes.com", "wsj.com"]},
            {"arg": "cc", "op": "in_list", "value": [THIRD_PARTY]},
        ],
    }
    with capture_logs() as logs:
        created = await add(env, body)
    assert uuid.UUID(created["id"])
    assert (created["name"], created["tool"], created["created_by"]) == (
        "Big mailings to the press", "google_workspace.send_email", OWNER,
    )
    assert created["conditions"] == body["conditions"]
    assert created["summary"] == (
        'Ask before google_workspace.send_email when "to" has an address or link at nytimes.com, '
        f'wsj.com and "cc" is one of "{THIRD_PARTY}".'
    )
    [row] = await audit_rows(env.session_factory, "tool_rule_created")
    assert row.user_id == env.owner.id
    assert row.request_data["rule_id"] == created["id"]
    assert row.request_data["args"] == ["to", "cc"] and row.request_data["ops"] == ["domain_in", "in_list"]
    for value in (THIRD_PARTY, "nytimes", "wsj"):
        assert value not in str(row.request_data) and value not in str(logs)
    # Normalised on the way in: lower-case glob, IDNA domains.
    created = await add(env)
    assert created["tool"] == "microsoft.create_event"
    assert created["conditions"][0]["value"] == ["myco.com", "myco.org"]
    # Adding narrows: no notice.
    assert env.outbox.sent == []


@pytest.mark.asyncio
async def test_a_refused_rule_is_a_422_whose_detail_is_the_validator_reason(env):
    await add(env)
    secret = "sk-live-" + "Ab3d" * 8
    cases = [
        ({**RULE, "name": "mail bob@evil.example"}, texts.NAME_INVALID),
        ({**RULE, "name": "Outside guests on Outlook events"}, texts.NAME_TAKEN),
        ({**RULE, "name": "Another name"}, texts.identical_rule("Outside guests on Outlook events")),
        ({**RULE, "name": "Bad glob", "tool": "google workspace/*"}, texts.TOOL_CHARSET),
        ({**RULE, "name": "Search only", "tool": "tools.find"}, texts.TOOL_RUNTIME_ONLY),
        ({**RULE, "name": "Too many", "conditions": [{"arg": "to", "op": "contains", "value": "x"}] * 6}, texts.TOO_MANY_CONDITIONS),
        (
            {**RULE, "name": "Slow pattern", "conditions": [{"arg": "body", "op": "regex", "value": "a.*b.*c"}]},
            texts.PATTERN_OPEN_REPEATS,
        ),
        (
            {**RULE, "name": "Nested", "conditions": [{"arg": "body", "op": "regex", "value": "(a+)+$"}]},
            texts.PATTERN_NESTED,
        ),
        ({**RULE, "name": "Holds a key", "conditions": [{"arg": "token", "op": "equals", "value": secret}]}, texts.SECRET_VALUE),
        ({"name": "No tool"}, texts.TOOL_MISSING),
    ]
    for body, reason in cases:
        resp = await env.client.post(BASE, json=body, headers=env.headers)
        assert resp.status_code == 422, (body, resp.text)
        assert resp.json() == {"detail": reason}
        assert secret not in resp.text
    assert len(await env.store.list_rules()) == 1
    assert len(await audit_rows(env.session_factory, "tool_rule_created")) == 1


# ---------------------------------------------------------------------------
# Loosening changes notify the owner
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_deleting_a_rule_notifies_the_owner_on_their_channels(env):
    created = await add(env)
    resp = await env.client.delete(f"{BASE}/{created['id']}", headers=env.headers)
    assert resp.status_code == 204 and resp.content == b""
    assert await env.store.list_rules() == []
    assert env.outbox.sent == [(str(env.owner.id), texts.rule_removed_notice("Outside guests on Outlook events"))]
    assert env.outbox.sent[0][1] == (
        'Security: a tool rule was removed: "Outside guests on Outlook events". Crawler will no '
        "longer ask before the calls it matched. If this wasn't you, sign in and check "
        "Security → Tool rules."
    )
    [row] = await audit_rows(env.session_factory, "tool_rule_deleted")
    assert row.request_data["rule_id"] == created["id"] and "myco" not in str(row.request_data)


@pytest.mark.asyncio
async def test_turning_a_builtin_off_notifies_the_owner_and_turning_it_on_does_not(env):
    path = f"{BASE}/builtins/{MANY_RECIPIENTS}"
    resp = await env.client.put(path, json={"enabled": False}, headers=env.headers)
    assert resp.status_code == 200
    out = resp.json()
    rule = builtin(MANY_RECIPIENTS)
    assert rule is not None
    assert (out["key"], out["name"], out["description"], out["enabled"]) == (
        MANY_RECIPIENTS, rule.name, rule.description, False,
    )
    assert out["changed_at"]
    assert env.outbox.sent == [(str(env.owner.id), texts.builtin_off_notice(rule.text))]
    assert env.outbox.sent[0][1] == (
        'Security: a built-in safety rule was turned off: "More than 10 recipients". Crawler will '
        "no longer ask before one action addresses more than 10 people. If this wasn't you, turn "
        "it back on in Security → Tool rules."
    )
    # Off again changes nothing: no second notice and no second row.
    await env.client.put(path, json={"enabled": False}, headers=env.headers)
    assert len(env.outbox.sent) == 1
    # On narrows: no notice, but it is audited.
    resp = await env.client.put(path, json={"enabled": True}, headers=env.headers)
    assert resp.status_code == 200 and resp.json()["enabled"] is True
    assert len(env.outbox.sent) == 1
    rows = await audit_rows(env.session_factory, "tool_rule_builtin_changed")
    assert [r.request_data for r in rows] == [
        {"key": MANY_RECIPIENTS, "enabled": False},
        {"key": MANY_RECIPIENTS, "enabled": True},
    ]


@pytest.mark.asyncio
async def test_a_failed_notice_never_undoes_the_change(env):
    created = await add(env)
    env.outbox.fail = True
    with capture_logs() as logs:
        resp = await env.client.delete(f"{BASE}/{created['id']}", headers=env.headers)
        assert resp.status_code == 204
        resp = await env.client.put(f"{BASE}/builtins/{MANY_RECIPIENTS}", json={"enabled": False}, headers=env.headers)
        assert resp.status_code == 200 and resp.json()["enabled"] is False
    assert await env.store.list_rules() == []
    assert (await env.store.snapshot()).builtins_off == frozenset({MANY_RECIPIENTS})
    failed = [entry for entry in logs if entry["event"] == "tool_rules_owner_notice_failed"]
    assert [(f["change"], f["error_type"]) for f in failed] == [
        ("rule_removed", "ConnectionError"), ("builtin_off", "ConnectionError"),
    ]
    # A sender that answers "not delivered" leaves the change standing too.
    env.outbox.fail, env.outbox.deliver = False, False
    resp = await env.client.put(f"{BASE}/builtins/outside_share", json={"enabled": False}, headers=env.headers)
    assert resp.status_code == 200 and resp.json()["enabled"] is False


@pytest.mark.asyncio
async def test_without_an_owner_sender_on_app_state_the_change_stands_and_the_skip_is_logged(env):
    created = await add(env)
    del env.app.state.owner_send
    with capture_logs() as logs:
        assert (await env.client.delete(f"{BASE}/{created['id']}", headers=env.headers)).status_code == 204
        resp = await env.client.put(f"{BASE}/builtins/untrusted_link", json={"enabled": False}, headers=env.headers)
    assert resp.status_code == 200 and resp.json()["enabled"] is False
    assert await env.store.list_rules() == []
    skipped = [entry["change"] for entry in logs if entry["event"] == "tool_rules_owner_notice_skipped"]
    assert skipped == ["rule_removed", "builtin_off"]
    assert env.outbox.sent == []


@pytest.mark.asyncio
async def test_an_unknown_rule_id_or_builtin_key_is_a_404(env):
    for rule_id in (str(uuid.uuid4()), "not-a-uuid"):
        resp = await env.client.delete(f"{BASE}/{rule_id}", headers=env.headers)
        assert resp.status_code == 404 and resp.json() == {"detail": "No such tool rule."}
    resp = await env.client.put(f"{BASE}/builtins/no_such_rule", json={"enabled": False}, headers=env.headers)
    assert resp.status_code == 404 and resp.json() == {"detail": "No such built-in rule."}
    assert env.outbox.sent == [] and await audit_rows(env.session_factory) == []


# ---------------------------------------------------------------------------
# Preview and catalog
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_preview_lists_matching_tools_counts_reads_and_saves_nothing(env):
    resp = await env.client.post(
        f"{BASE}/preview",
        json={"tool": "google_workspace.*", "conditions": [{"arg": "to", "op": "domain_in", "value": ["nytimes.com"]}]},
        headers=env.headers,
    )
    assert resp.status_code == 200
    preview = resp.json()
    every = [(name, category) for name, category, _args in catalog() if name.startswith("google_workspace.")]
    reads = sum(1 for _name, category in every if category == "read")
    assert preview["valid"] is True and preview["error"] is None
    assert preview["summary"] == 'Ask before any google_workspace.* call when "to" has an address or link at nytimes.com.'
    assert (preview["reads"], preview["writes"]) == (reads, len(every) - reads)
    assert reads > 0 and preview["writes"] > 0
    assert len(preview["matches"]) == min(len(every), 50)
    assert preview["truncated"] is (len(every) > 50)
    assert {"tool": "google_workspace.send_email", "category": "write"} in preview["matches"]
    assert preview["mcp"] is False

    one = (await env.client.post(f"{BASE}/preview", json={"tool": "google_workspace.send_email", "conditions": []}, headers=env.headers)).json()
    assert one["matches"] == [{"tool": "google_workspace.send_email", "category": "write"}]
    assert (one["reads"], one["writes"], one["truncated"]) == (0, 1, False)
    assert one["summary"] == "Ask before every google_workspace.send_email call."
    mcp = (await env.client.post(f"{BASE}/preview", json={"tool": "mcp.github.*", "conditions": []}, headers=env.headers)).json()
    assert mcp["valid"] is True and mcp["mcp"] is True and mcp["matches"] == []
    everything = (await env.client.post(f"{BASE}/preview", json={"tool": "*", "conditions": []}, headers=env.headers)).json()
    assert everything["truncated"] is True and len(everything["matches"]) == 50
    assert everything["reads"] + everything["writes"] == len(catalog())

    assert await env.store.list_rules() == [] and await audit_rows(env.session_factory) == []


@pytest.mark.asyncio
async def test_preview_of_an_invalid_draft_answers_valid_false_with_the_reason_not_a_422(env):
    cases = [
        ({"tool": "Tools.Find", "conditions": []}, texts.TOOL_RUNTIME_ONLY),
        ({"tool": "google_workspace.send_email", "conditions": [{"arg": "body", "op": "regex", "value": "(a|aa)*"}]}, texts.PATTERN_NESTED),
        ({"tool": "google_workspace.send_email", "conditions": [{"arg": "amount", "op": "number_gt", "value": "lots"}]}, texts.needs_number("is more than")),
        ({"tool": "", "conditions": []}, texts.TOOL_MISSING),
    ]
    for body, reason in cases:
        resp = await env.client.post(f"{BASE}/preview", json=body, headers=env.headers)
        assert resp.status_code == 200, resp.text
        preview = resp.json()
        assert preview["valid"] is False and preview["error"] == reason, body
        assert preview["summary"] == ""
    # A valid glob with a bad condition still shows what the glob covers.
    preview = (await env.client.post(f"{BASE}/preview", json=cases[1][0], headers=env.headers)).json()
    assert preview["matches"] == [{"tool": "google_workspace.send_email", "category": "write"}]


@pytest.mark.asyncio
async def test_the_catalog_lists_every_tool_rules_can_cover_with_its_argument_names_and_no_runtime_tools(env):
    resp = await env.client.get(f"{BASE}/catalog", headers=env.headers)
    assert resp.status_code == 200
    body = resp.json()
    assert body["mcp_hint"] == "mcp.<server>.<tool>"
    tools = {t["tool"]: t for t in body["tools"]}
    assert [t["tool"] for t in body["tools"]] == sorted(tools)
    assert not any(name == "tools.find" or name.startswith("tutor.") for name in tools)
    send = tools["google_workspace.send_email"]
    assert send["category"] == "write" and "to" in send["args"]
    assert tools["google_workspace.share_file"]["args"] and "email" in tools["google_workspace.share_file"]["args"]
    assert {t["category"] for t in body["tools"]} <= {"read", "write", "delete", "execute", "financial"}
    assert len(body["tools"]) == len(catalog())


# ---------------------------------------------------------------------------
# A rule added here applies to the next turn
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_a_rule_added_through_the_route_applies_to_the_next_turn(env):
    # The same store and check main.py wires: the route's write drops the snapshot cache.
    run = Run([env.check])
    first = await run.chat(call(DRAFT, to="ann@example.com", subject="Notes", body="Hi"), tools=AUTO_GOOGLE_TOOLS)
    assert first.pending_approvals == []  # the auto tier ran it: no rule yet
    await add(
        env,
        {"name": "Drafts to example", "tool": "google_workspace.create_draft",
         "conditions": [{"arg": "to", "op": "domain_in", "value": ["example.com"]}]},
    )
    second = await run.chat(call(DRAFT, to="ann@example.com", subject="Notes", body="Hi"), tools=AUTO_GOOGLE_TOOLS)
    [pending] = second.pending_approvals
    assert pending.reason.endswith("Tool rule: Drafts to example.")
    assert [n["kind"] for n in pending.security_notes] == ["tool_rule"]
    assert pending.security_notes[0]["text"] == (
        'Your tool rule "Drafts to example": "to" has an address or link at example.com.'
    )
    assert [c["tool"] for c in run.executor.calls] == [DRAFT]
