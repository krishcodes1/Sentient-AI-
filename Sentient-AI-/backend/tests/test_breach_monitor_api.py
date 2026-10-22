"""Tests for the breach monitor's routes (api/routes/security_breach.py): they
prove the owner-only routes answer 403 to a standard user and 503 until the
service is wired; that the overview lists the owner's own addresses and
findings with the report's state; that adding validates by hand (a 422 never
echoes what was typed), refuses duplicates, the sign-in address and the
eleventh, and audits ids only; that another owner's address or finding is a
404; that the sign-in address can be paused but not removed; that Check now
answers 409 with the report's reason without a key, 429 with Retry-After
moments after a check, and a 200 "not checked" with a plain note when the
lookup failed; that findings are acknowledged one by one or all at once; that
no answer carries the HIBP key or a key field; that the password range proxy
works for any signed-in user without an HIBP key, answers 403 when the owner
turned breach checks off (503 when the report cannot be read), refuses a bad
prefix without reaching the service, limits each user, answers 503 "not
checked" on a failure, and writes no audit row and no log line with the
prefix or the entry count; and that the account export carries the watched
addresses and their breaches.

Why it exists: these routes are where an owner's addresses and the breaches
found for them leave the server, and where anyone's password-hash prefix
passes through it. A route that answered another owner's row, echoed an
address in an error, logged a prefix next to a user id, or let the proxy run
with breach checks off would each break a promise the Security page makes. A
scripted HIBP and a fake range lookup stand in for the network; an autouse
guard fails any request that is not the test client talking to the app.
"""

from __future__ import annotations

import json
import uuid
from datetime import date, datetime, timedelta, timezone
from types import SimpleNamespace
from typing import Any, Optional

import httpx
import pytest
import pytest_asyncio
from sqlalchemy import select, update
from structlog.testing import capture_logs

from api.routes import security_breach as breach_routes
from core.config import SERVICE_KEY_FIELDS, settings
from models.audit import AuditLog
from models.breach_watch import BreachWatchFinding
from models.user import User
from services.breach.hibp import Breach, Unavailable
from services.breach.pwned_passwords import PwnedPasswordsUnavailable
from services.installation import InstallationService
from services.notifications.breach_monitor import BreachMonitorService
from services.notifications.sweeper import capability_gate
from tests.conftest import auth_headers, make_user

T0 = datetime(2026, 10, 14, 9, 0, tzinfo=timezone.utc)
# Built by concatenation so no literal key is ever in the source (scaffold C6).
KEY = "0123456789abcdef" * 2
OWNER = "kash@example.com"
OTHER_OWNER = "pat@example.net"
MEMBER = "member@example.com"
PREFIX = "5BAA6"
SUFFIX = "1E4C9B93F3F0682250B6CF8331B7EE68FD8"
BLOCKED_REASON = (
    "Breach checks use your own Have I Been Pwned key, and none is saved yet. "
    "Add one in Security → Service keys."
)

_real_send = httpx.AsyncClient.send


@pytest.fixture(autouse=True)
def _no_network(monkeypatch):
    """Any httpx request that is not the test client talking to the app fails the test
    (host only in the message: the HIBP URL carries an address)."""

    async def guarded_send(self, request, *args, **kwargs):
        if request.url.host != "testserver":
            raise AssertionError(f"network call to {request.url.host}")
        return await _real_send(self, request, *args, **kwargs)

    monkeypatch.setattr(httpx.AsyncClient, "send", guarded_send)


class Clock:
    def __init__(self, now: datetime = T0) -> None:
        self.now = now

    def __call__(self) -> datetime:
        return self.now


class FakePacer:
    def __init__(self) -> None:
        self.estimate = 0.0

    def wait_estimate(self) -> float:
        return self.estimate


class FakeHibp:
    """breaches_for scripted per address (a list of Breach or an exception); every call is
    recorded with the key it carried."""

    def __init__(self) -> None:
        self.answers: dict[str, Any] = {}
        self.calls: list[tuple[str, str]] = []
        self.pacer = FakePacer()

    async def breaches_for(
        self, address: str, api_key: str, *, deadline_s: Optional[float] = None
    ) -> list[Breach]:
        self.calls.append((address, api_key))
        answer = self.answers.get(address, [])
        if isinstance(answer, BaseException):
            raise answer
        return list(answer)


class Outbox:
    def __init__(self) -> None:
        self.sent: list[tuple[str, str]] = []

    async def send(self, user_id: str, text: str) -> bool:
        self.sent.append((user_id, text))
        return True


class FakeRange:
    """Stands in for pwned_passwords.fetch_range: records each prefix it is asked for."""

    def __init__(self) -> None:
        self.prefixes: list[str] = []
        self.answer: Any = [(SUFFIX, 52256), ("0" * 35, 3)]

    async def __call__(self, prefix: str, **_kwargs: Any) -> list[tuple[str, int]]:
        self.prefixes.append(prefix)
        if isinstance(self.answer, BaseException):
            raise self.answer
        return list(self.answer)


def breach(name: str, *, sensitive: bool = False) -> Breach:
    return Breach(
        name=name,
        title=name.replace("_", " "),
        domain=f"{name.lower()}.com",
        breach_date=date(2026, 8, 30),
        added_at=datetime(2026, 10, 1, tzinfo=timezone.utc),
        pwn_count=1000,
        data_classes=("Email addresses", "Passwords"),
        verified=True,
        sensitive=sensitive,
        fabricated=False,
        spam_list=False,
    )


async def make_account(session_factory, email: str, *, admin: bool) -> tuple[User, dict[str, str]]:
    user, token = await make_user(session_factory, email=email)
    if admin:
        async with session_factory() as session:
            await session.execute(update(User).where(User.id == user.id).values(is_admin=True))
            await session.commit()
    return user, auth_headers(token)


@pytest_asyncio.fixture
async def env(client, session_factory, monkeypatch):
    """The installation service and a breach monitor over a scripted HIBP on app.state, with
    no service key in the environment and fresh rate-limit buckets."""
    from main import app

    for attr in SERVICE_KEY_FIELDS.values():
        monkeypatch.setattr(settings, attr, None, raising=False)
    breach_routes._reset_rate_limits()
    fake_range = FakeRange()
    monkeypatch.setattr(breach_routes, "fetch_range", fake_range)
    installation = InstallationService(session_factory)
    hibp = FakeHibp()
    outbox = Outbox()
    clock = Clock()

    async def api_key() -> Optional[str]:
        return await installation.service_key("hibp")

    service = BreachMonitorService(
        session_factory,
        api_key=api_key,
        send=outbox.send,
        enabled=capability_gate(installation, "breach_monitor"),
        client=hibp,  # type: ignore[arg-type]
        clock=clock,
    )
    saved = dict(app.state._state)
    app.state.installation = installation
    app.state.breach_monitor = service
    owner, owner_headers = await make_account(session_factory, OWNER, admin=True)
    try:
        yield SimpleNamespace(
            app=app,
            client=client,
            installation=installation,
            service=service,
            hibp=hibp,
            outbox=outbox,
            clock=clock,
            range=fake_range,
            owner=owner,
            headers=owner_headers,
            session_factory=session_factory,
        )
    finally:
        app.state._state.clear()
        app.state._state.update(saved)
        breach_routes._reset_rate_limits()


def save_key(env, monkeypatch) -> None:
    """The owner's HIBP key, through the environment (the env-wins path)."""
    monkeypatch.setattr(settings, "HIBP_API_KEY", KEY, raising=False)
    env.installation.invalidate()


async def audit_rows(session_factory, action: Optional[str] = None) -> list[AuditLog]:
    async with session_factory() as session:
        stmt = select(AuditLog).order_by(AuditLog.seq)
        if action is not None:
            stmt = stmt.where(AuditLog.action == action)
        return list((await session.execute(stmt)).scalars())


def _keys_in(value: Any) -> set[str]:
    """Every dict key anywhere in a JSON value."""
    found: set[str] = set()
    if isinstance(value, dict):
        for key, item in value.items():
            found.add(str(key))
            found |= _keys_in(item)
    elif isinstance(value, list):
        for item in value:
            found |= _keys_in(item)
    return found


BREACH_ROUTES = (
    ("GET", "/api/security/breach", None),
    ("POST", "/api/security/breach/addresses", {"address": "me.alt@example.org"}),
    ("PATCH", f"/api/security/breach/addresses/{uuid.uuid4()}", {"paused": True}),
    ("DELETE", f"/api/security/breach/addresses/{uuid.uuid4()}", None),
    ("POST", f"/api/security/breach/addresses/{uuid.uuid4()}/check", None),
    ("POST", f"/api/security/breach/findings/{uuid.uuid4()}/acknowledge", None),
    ("POST", "/api/security/breach/findings/acknowledge-all", None),
)


# ---------------------------------------------------------------------------
# Who may call what
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_breach_routes_answer_403_to_a_standard_user(env):
    _, member = await make_account(env.session_factory, MEMBER, admin=False)
    for method, path, body in BREACH_ROUTES:
        resp = await env.client.request(method, path, json=body, headers=member)
        assert resp.status_code == 403, (method, path)
        assert resp.json()["detail"] == "Only the owner of this install can change this."
    # Nothing was created for the standard user, and nothing was looked up.
    assert env.hibp.calls == []


@pytest.mark.asyncio
async def test_the_breach_routes_answer_503_until_the_service_is_wired(env):
    delattr(env.app.state, "breach_monitor")
    for method, path, body in BREACH_ROUTES:
        resp = await env.client.request(method, path, json=body, headers=env.headers)
        assert resp.status_code == 503, (method, path)
        assert resp.json()["detail"] == "The server is still starting. Try again shortly."


# ---------------------------------------------------------------------------
# The overview and the owner's edits
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_the_overview_lists_the_owners_addresses_and_findings_and_the_reports_state(
    env, monkeypatch
):
    # Without a key: blocked, with the report's reason, and the sign-in row is made at once.
    resp = await env.client.get("/api/security/breach", headers=env.headers)
    assert resp.status_code == 200
    body = resp.json()
    assert body["state"] == "blocked" and body["reason"] == BLOCKED_REASON
    assert body["switch_on"] is True and body["key_configured"] is False
    assert (body["check_every_days"], body["max_addresses"]) == (7, 10)
    assert body["account_note"] is None
    assert body["attribution"] == {
        "text": "Breach data: Have I Been Pwned",
        "url": "https://haveibeenpwned.com",
    }
    (account,) = body["addresses"]
    assert account["address"] == OWNER and account["source"] == "account"
    assert account["hint"] == "k•••@example.com" and account["readable"] is True
    assert body["findings"] == []
    assert env.hibp.calls == []  # the overview never sends anything

    # Another owner's rows never show.
    other, other_headers = await make_account(env.session_factory, OTHER_OWNER, admin=True)
    await env.client.post(
        "/api/security/breach/addresses",
        json={"address": "theirs@example.org"},
        headers=other_headers,
    )

    # With a key: on, and a check's findings are listed.
    save_key(env, monkeypatch)
    env.hibp.answers[OWNER] = [breach("ExampleShop"), breach("Adobe")]
    checked = await env.client.post(
        f"/api/security/breach/addresses/{account['id']}/check", headers=env.headers
    )
    assert checked.status_code == 200 and checked.json()["outcome"] == "checked"
    body = (await env.client.get("/api/security/breach", headers=env.headers)).json()
    assert body["state"] == "on" and body["reason"] == ""
    assert body["key_configured"] is True
    assert [row["address"] for row in body["addresses"]] == [OWNER]
    assert sorted(f["name"] for f in body["findings"]) == ["Adobe", "ExampleShop"]
    assert all(f["address_id"] == account["id"] for f in body["findings"])
    assert body["addresses"][0]["breach_count"] == 2 and body["addresses"][0]["new_count"] == 2

    # Switched off: "off", and the owner's switch reads false.
    await env.installation.set_capabilities({"breach_monitor": False}, actor_id=env.owner.id)
    body = (await env.client.get("/api/security/breach", headers=env.headers)).json()
    assert body["state"] == "off" and body["switch_on"] is False
    assert body["reason"] == "Turned off by the owner."


@pytest.mark.asyncio
async def test_a_sign_in_address_that_is_not_a_mailbox_gets_the_account_note(env):
    admin, headers = await make_account(env.session_factory, "admin@localhost", admin=True)
    body = (await env.client.get("/api/security/breach", headers=headers)).json()
    assert body["addresses"] == []
    assert body["account_note"] == (
        "Your sign-in address (admin@localhost) is not a mailbox address Have I Been Pwned can "
        "look up. Add the addresses you use below."
    )


@pytest.mark.asyncio
async def test_adding_validates_refuses_duplicates_the_sign_in_address_and_the_eleventh_and_audits_without_the_address(
    env,
):
    await env.client.get("/api/security/breach", headers=env.headers)
    resp = await env.client.post(
        "/api/security/breach/addresses",
        json={"address": "  Me.Alt@Example.org "},
        headers=env.headers,
    )
    assert resp.status_code == 201
    row = resp.json()
    assert row["address"] == "me.alt@example.org" and row["source"] == "added"
    assert row["status"] == "active" and row["readable"] is True

    # Refusals by hand: fixed sentences, never what was typed.
    bad_inputs: list[Any] = [
        {"address": "two@example.org, three@example.org"},
        {"address": "secret-typo@@example.org"},
        {"address": 42},
        {"address": None},
        {},
    ]
    for payload in bad_inputs:
        resp = await env.client.post(
            "/api/security/breach/addresses", json=payload, headers=env.headers
        )
        assert resp.status_code == 422, payload
        assert resp.json() == {"detail": "Enter one email address, like name@example.com."}
        assert "secret-typo" not in resp.text and "three@" not in resp.text
    for raw in (b"not json secret-typo@example.org", b'["secret-typo@example.org"]'):
        resp = await env.client.post(
            "/api/security/breach/addresses",
            content=raw,
            headers={**env.headers, "Content-Type": "application/json"},
        )
        assert resp.status_code == 422
        assert resp.json() == {"detail": "The request body must be a JSON object."}
    big = await env.client.post(
        "/api/security/breach/addresses",
        json={"address": "x" * 5000 + "@example.org"},
        headers=env.headers,
    )
    assert big.status_code == 422 and "xxxx" not in big.text

    duplicate = await env.client.post(
        "/api/security/breach/addresses",
        json={"address": "ME.ALT@example.org"},
        headers=env.headers,
    )
    assert duplicate.status_code == 409
    assert duplicate.json()["detail"] == "That address is already watched."
    sign_in = await env.client.post(
        "/api/security/breach/addresses", json={"address": OWNER}, headers=env.headers
    )
    assert sign_in.status_code == 409
    assert sign_in.json()["detail"] == "That is your sign-in address; it is already watched."

    for i in range(9):
        added = await env.client.post(
            "/api/security/breach/addresses",
            json={"address": f"extra{i}@example.org"},
            headers=env.headers,
        )
        assert added.status_code == 201
    eleventh = await env.client.post(
        "/api/security/breach/addresses",
        json={"address": "eleventh@example.org"},
        headers=env.headers,
    )
    assert eleventh.status_code == 422
    assert eleventh.json()["detail"] == "You can watch at most 10 addresses."

    rows = await audit_rows(env.session_factory, "breach_address_added")
    assert len(rows) == 10
    assert rows[0].request_data == {"address_id": row["id"], "source": "added"}
    for audit in rows:
        text = json.dumps(audit.request_data) + (audit.endpoint or "")
        assert "example.org" not in text and "@" not in text
        assert audit.connector_name == "breach_monitor"
    # Adding sends nothing: the first lookup is the tab's own Check now.
    assert env.hibp.calls == []


@pytest.mark.asyncio
async def test_another_owners_address_or_finding_is_a_404(env, monkeypatch):
    save_key(env, monkeypatch)
    other, other_headers = await make_account(env.session_factory, OTHER_OWNER, admin=True)
    theirs = (
        await env.client.post(
            "/api/security/breach/addresses",
            json={"address": "theirs@example.org"},
            headers=other_headers,
        )
    ).json()
    env.hibp.answers["theirs@example.org"] = [breach("ExampleShop")]
    report = (
        await env.client.post(
            f"/api/security/breach/addresses/{theirs['id']}/check", headers=other_headers
        )
    ).json()
    (their_finding,) = report["new_findings"]

    address_paths = (
        ("PATCH", f"/api/security/breach/addresses/{theirs['id']}", {"paused": True}),
        ("DELETE", f"/api/security/breach/addresses/{theirs['id']}", None),
        ("POST", f"/api/security/breach/addresses/{theirs['id']}/check", None),
    )
    for method, path, payload in address_paths:
        resp = await env.client.request(method, path, json=payload, headers=env.headers)
        assert resp.status_code == 404, (method, path)
        assert resp.json() == {"detail": "No such address."}
    resp = await env.client.post(
        f"/api/security/breach/findings/{their_finding['id']}/acknowledge", headers=env.headers
    )
    assert resp.status_code == 404 and resp.json() == {"detail": "No such breach."}
    # An id that is not a UUID is the same 404, never echoed.
    for path in (
        "/api/security/breach/addresses/not-a-uuid-secret/check",
        "/api/security/breach/findings/not-a-uuid-secret/acknowledge",
    ):
        resp = await env.client.post(path, headers=env.headers)
        assert resp.status_code == 404 and "secret" not in resp.text
    # Acknowledge-all touches only this owner's findings.
    assert (
        await env.client.post("/api/security/breach/findings/acknowledge-all", headers=env.headers)
    ).json() == {"acknowledged": 0}
    async with env.session_factory() as session:
        still = await session.get(BreachWatchFinding, uuid.UUID(their_finding["id"]))
        assert still is not None and still.acknowledged_at is None
    # Their row is untouched and was looked up once, by its owner.
    assert env.hibp.calls == [("theirs@example.org", KEY)]


@pytest.mark.asyncio
async def test_the_sign_in_address_cannot_be_removed_but_can_be_paused(env):
    body = (await env.client.get("/api/security/breach", headers=env.headers)).json()
    account_id = body["addresses"][0]["id"]

    removed = await env.client.delete(
        f"/api/security/breach/addresses/{account_id}", headers=env.headers
    )
    assert removed.status_code == 409
    assert removed.json()["detail"] == (
        "Your sign-in address is always watched while breach monitoring is on. Pause it instead."
    )

    paused = await env.client.patch(
        f"/api/security/breach/addresses/{account_id}", json={"paused": True}, headers=env.headers
    )
    assert paused.status_code == 200 and paused.json()["status"] == "paused"
    for not_bool in ({"paused": "yes"}, {"paused": 1}, {}):
        resp = await env.client.patch(
            f"/api/security/breach/addresses/{account_id}", json=not_bool, headers=env.headers
        )
        assert resp.status_code == 422 and resp.json() == {
            "detail": "Send paused as true or false."
        }
    resumed = await env.client.patch(
        f"/api/security/breach/addresses/{account_id}", json={"paused": False}, headers=env.headers
    )
    assert resumed.status_code == 200 and resumed.json()["status"] == "active"

    # A typed address can be removed, and is gone afterwards.
    alt = (
        await env.client.post(
            "/api/security/breach/addresses",
            json={"address": "me.alt@example.org"},
            headers=env.headers,
        )
    ).json()
    gone = await env.client.delete(
        f"/api/security/breach/addresses/{alt['id']}", headers=env.headers
    )
    assert gone.status_code == 204
    body = (await env.client.get("/api/security/breach", headers=env.headers)).json()
    assert [row["source"] for row in body["addresses"]] == ["account"]

    actions = [row.action for row in await audit_rows(env.session_factory)]
    assert "breach_address_paused" in actions and "breach_address_resumed" in actions
    (removal,) = await audit_rows(env.session_factory, "breach_address_removed")
    assert removal.request_data == {"address_id": alt["id"], "findings_removed": 0}
    paused_row = (await audit_rows(env.session_factory, "breach_address_paused"))[0]
    assert paused_row.request_data == {"address_id": account_id, "source": "account"}


# ---------------------------------------------------------------------------
# Check now
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_check_now_answers_409_with_the_reports_reason_without_a_key(env):
    body = (await env.client.get("/api/security/breach", headers=env.headers)).json()
    account_id = body["addresses"][0]["id"]
    resp = await env.client.post(
        f"/api/security/breach/addresses/{account_id}/check", headers=env.headers
    )
    assert resp.status_code == 409
    assert resp.json() == {"detail": BLOCKED_REASON}
    assert env.hibp.calls == []

    # Switched off: the report's own reason too, and still nothing sent.
    await env.installation.set_capabilities({"breach_monitor": False}, actor_id=env.owner.id)
    resp = await env.client.post(
        f"/api/security/breach/addresses/{account_id}/check", headers=env.headers
    )
    assert resp.status_code == 409
    assert resp.json() == {"detail": "Turned off by the owner."}
    assert env.hibp.calls == []


@pytest.mark.asyncio
async def test_check_now_answers_inline_with_the_new_findings_and_sends_no_channel_message(
    env, monkeypatch
):
    save_key(env, monkeypatch)
    alt = (
        await env.client.post(
            "/api/security/breach/addresses",
            json={"address": "me.alt@example.org"},
            headers=env.headers,
        )
    ).json()
    env.hibp.answers["me.alt@example.org"] = [
        breach("ExampleShop"),
        breach("Hidden", sensitive=True),
    ]
    resp = await env.client.post(
        f"/api/security/breach/addresses/{alt['id']}/check", headers=env.headers
    )
    assert resp.status_code == 200
    report = resp.json()
    assert report["outcome"] == "checked" and report["note"] == "Found in 2 new breaches."
    assert report["address"]["id"] == alt["id"] and report["address"]["breach_count"] == 2
    assert sorted(f["name"] for f in report["new_findings"]) == ["ExampleShop", "Hidden"]
    assert all(f["alerted_at"] is not None for f in report["new_findings"])
    assert env.outbox.sent == []
    assert env.hibp.calls == [("me.alt@example.org", KEY)]


@pytest.mark.asyncio
async def test_check_now_answers_429_with_retry_after_when_checked_moments_ago(env, monkeypatch):
    save_key(env, monkeypatch)
    body = (await env.client.get("/api/security/breach", headers=env.headers)).json()
    account_id = body["addresses"][0]["id"]
    first = await env.client.post(
        f"/api/security/breach/addresses/{account_id}/check", headers=env.headers
    )
    assert first.status_code == 200

    again = await env.client.post(
        f"/api/security/breach/addresses/{account_id}/check", headers=env.headers
    )
    assert again.status_code == 429
    assert again.headers["Retry-After"] == "300"
    assert again.json() == {"detail": "Checked moments ago. Try again in 300 seconds."}

    # A busy pacer is a 429 too, with its own sentence, and nothing is sent.
    env.clock.now += timedelta(minutes=10)
    env.hibp.pacer.estimate = 40.2
    paced = await env.client.post(
        f"/api/security/breach/addresses/{account_id}/check", headers=env.headers
    )
    assert paced.status_code == 429 and paced.headers["Retry-After"] == "41"
    assert paced.json() == {
        "detail": "Crawler is pacing lookups to your key's limit. Try again in 41 seconds."
    }
    assert len(env.hibp.calls) == 1

    # A paused address is a 409 with the store's sentence.
    env.hibp.pacer.estimate = 0.0
    await env.client.patch(
        f"/api/security/breach/addresses/{account_id}", json={"paused": True}, headers=env.headers
    )
    paused = await env.client.post(
        f"/api/security/breach/addresses/{account_id}/check", headers=env.headers
    )
    assert paused.status_code == 409
    assert paused.json() == {"detail": "This address is paused. Resume it first."}


@pytest.mark.asyncio
async def test_a_failed_check_now_is_a_200_not_checked_with_a_plain_note(env, monkeypatch):
    save_key(env, monkeypatch)
    body = (await env.client.get("/api/security/breach", headers=env.headers)).json()
    account_id = body["addresses"][0]["id"]
    env.hibp.answers[OWNER] = Unavailable("down for kash@example.com")
    resp = await env.client.post(
        f"/api/security/breach/addresses/{account_id}/check", headers=env.headers
    )
    assert resp.status_code == 200
    report = resp.json()
    assert report["outcome"] == "not_checked" and report["new_findings"] == []
    assert report["note"] == (
        "Not checked: Have I Been Pwned could not be reached. Crawler tries again in 1 hour."
    )
    assert report["address"]["last_error_code"] == "unavailable"
    assert report["address"]["last_error"] == "Have I Been Pwned could not be reached."
    assert "no breaches" not in resp.text.lower() and "down for" not in resp.text

    # With checks switched off afterwards, the overview no longer promises a retry.
    await env.installation.set_capabilities({"breach_monitor": False}, actor_id=env.owner.id)
    env.hibp.answers[OWNER] = []
    async with env.session_factory() as session:
        from models.breach_watch import BreachWatchAddress

        await session.execute(
            update(BreachWatchAddress)
            .where(BreachWatchAddress.id == uuid.UUID(account_id))
            .values(last_error_code="rate_limited")
        )
        await session.commit()
    body = (await env.client.get("/api/security/breach", headers=env.headers)).json()
    assert body["addresses"][0]["last_error"] == "Have I Been Pwned asked Crawler to slow down."


# ---------------------------------------------------------------------------
# Findings
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_acknowledging_one_and_all_findings(env, monkeypatch):
    save_key(env, monkeypatch)
    body = (await env.client.get("/api/security/breach", headers=env.headers)).json()
    account_id = body["addresses"][0]["id"]
    env.hibp.answers[OWNER] = [breach("One"), breach("Two"), breach("Three")]
    report = (
        await env.client.post(
            f"/api/security/breach/addresses/{account_id}/check", headers=env.headers
        )
    ).json()
    first = report["new_findings"][0]

    one = await env.client.post(
        f"/api/security/breach/findings/{first['id']}/acknowledge", headers=env.headers
    )
    assert one.status_code == 200
    assert one.json()["id"] == first["id"] and one.json()["acknowledged_at"] is not None
    body = (await env.client.get("/api/security/breach", headers=env.headers)).json()
    assert body["addresses"][0]["new_count"] == 2
    # Unhandled first.
    assert [f["acknowledged_at"] is None for f in body["findings"]] == [True, True, False]

    everything = await env.client.post(
        "/api/security/breach/findings/acknowledge-all", headers=env.headers
    )
    assert everything.status_code == 200 and everything.json() == {"acknowledged": 2}
    body = (await env.client.get("/api/security/breach", headers=env.headers)).json()
    assert body["addresses"][0]["new_count"] == 0
    assert all(f["acknowledged_at"] is not None for f in body["findings"])

    rows = await audit_rows(env.session_factory, "breach_findings_acknowledged")
    assert [row.request_data for row in rows] == [
        {"count": 1, "finding_id": first["id"]},
        {"count": 2},
    ]


@pytest.mark.asyncio
async def test_no_response_carries_the_hibp_key_or_a_key_field(env, monkeypatch):
    save_key(env, monkeypatch)
    answers: list[httpx.Response] = []
    answers.append(await env.client.get("/api/security/breach", headers=env.headers))
    account_id = answers[0].json()["addresses"][0]["id"]
    env.hibp.answers[OWNER] = [breach("ExampleShop")]
    answers.append(
        await env.client.post(
            "/api/security/breach/addresses",
            json={"address": "me.alt@example.org"},
            headers=env.headers,
        )
    )
    answers.append(
        await env.client.post(
            f"/api/security/breach/addresses/{account_id}/check", headers=env.headers
        )
    )
    answers.append(
        await env.client.patch(
            f"/api/security/breach/addresses/{account_id}",
            json={"paused": True},
            headers=env.headers,
        )
    )
    answers.append(
        await env.client.post("/api/security/breach/findings/acknowledge-all", headers=env.headers)
    )
    answers.append(
        await env.client.post(
            "/api/security/pwned-passwords/range", json={"prefix": PREFIX}, headers=env.headers
        )
    )
    answers.append(await env.client.get("/api/security/breach", headers=env.headers))
    for resp in answers:
        assert resp.status_code in (200, 201), resp.text
        assert KEY not in resp.text and KEY.upper() not in resp.text
        assert not {
            key for key in _keys_in(resp.json()) if "key" in key.lower() and key != "key_configured"
        }
        assert "api_key" not in resp.text and "hibp-api-key" not in resp.text


# ---------------------------------------------------------------------------
# The password range proxy
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_the_password_range_route_works_for_any_signed_in_user_without_an_hibp_key(env):
    _, member = await make_account(env.session_factory, MEMBER, admin=False)
    resp = await env.client.post(
        "/api/security/pwned-passwords/range", json={"prefix": PREFIX.lower()}, headers=member
    )
    assert resp.status_code == 200
    assert resp.json() == {
        "prefix": PREFIX,
        "suffixes": [[SUFFIX, 52256], ["0" * 35, 3]],
        "source": "Pwned Passwords by Have I Been Pwned (haveibeenpwned.com)",
    }
    # Only the uppercase prefix went on, and no HIBP account lookup happened.
    assert env.range.prefixes == [PREFIX]
    assert env.hibp.calls == []
    # Signed out: 401.
    anonymous = await env.client.post(
        "/api/security/pwned-passwords/range", json={"prefix": PREFIX}
    )
    assert anonymous.status_code in (401, 403)


@pytest.mark.asyncio
async def test_the_password_range_route_answers_403_when_the_owner_turned_breach_checks_off(env):
    await env.installation.set_capabilities({"breach_monitor": False}, actor_id=env.owner.id)
    _, member = await make_account(env.session_factory, MEMBER, admin=False)
    for headers in (member, env.headers):
        resp = await env.client.post(
            "/api/security/pwned-passwords/range", json={"prefix": PREFIX}, headers=headers
        )
        assert resp.status_code == 403
        assert resp.json() == {
            "detail": "The owner turned off breach checks in Settings → Permissions."
        }
    assert env.range.prefixes == []


@pytest.mark.asyncio
async def test_the_password_range_route_fails_closed_when_the_report_cannot_be_read(
    env, monkeypatch
):
    async def unreadable():
        raise RuntimeError("database down")

    monkeypatch.setattr(env.installation, "capability_statuses", unreadable)
    resp = await env.client.post(
        "/api/security/pwned-passwords/range", json={"prefix": PREFIX}, headers=env.headers
    )
    assert resp.status_code == 503
    assert resp.json() == {"detail": "Breach checks are unavailable right now."}
    overview = await env.client.get("/api/security/breach", headers=env.headers)
    assert overview.status_code == 503
    assert env.range.prefixes == []


@pytest.mark.asyncio
async def test_the_password_range_route_refuses_a_bad_prefix_without_reaching_the_service(env):
    refusal = {
        "detail": "Send the first 5 characters of the password's SHA-1 fingerprint (0-9, A-F)."
    }
    for payload in (
        {"prefix": "5BAA"},
        {"prefix": "5BAA61"},
        {"prefix": "5BAAG"},
        {"prefix": "hunter2"},
        {"prefix": 12345},
        {"prefix": None},
        {"password": "hunter2"},
    ):
        resp = await env.client.post(
            "/api/security/pwned-passwords/range", json=payload, headers=env.headers
        )
        assert resp.status_code == 422, payload
        assert resp.json() == refusal
        assert "hunter2" not in resp.text
    resp = await env.client.post(
        "/api/security/pwned-passwords/range",
        content=b"hunter2",
        headers={**env.headers, "Content-Type": "application/json"},
    )
    assert resp.status_code == 422 and "hunter2" not in resp.text
    assert env.range.prefixes == []


@pytest.mark.asyncio
async def test_the_password_range_route_rate_limits_each_user(env):
    _, member = await make_account(env.session_factory, MEMBER, admin=False)
    for _ in range(20):
        ok = await env.client.post(
            "/api/security/pwned-passwords/range", json={"prefix": PREFIX}, headers=member
        )
        assert ok.status_code == 200
    limited = await env.client.post(
        "/api/security/pwned-passwords/range", json={"prefix": PREFIX}, headers=member
    )
    assert limited.status_code == 429
    wait = int(limited.headers["Retry-After"])
    assert 1 <= wait <= 61
    assert limited.json() == {"detail": f"Too many password checks. Try again in {wait} seconds."}
    assert len(env.range.prefixes) == 20
    # Another user has their own window.
    other = await env.client.post(
        "/api/security/pwned-passwords/range", json={"prefix": PREFIX}, headers=env.headers
    )
    assert other.status_code == 200


@pytest.mark.asyncio
async def test_the_password_range_route_answers_503_not_checked_when_the_service_fails(env):
    failures: list[BaseException] = [
        PwnedPasswordsUnavailable(reason)
        for reason in ("http_status", "timeout", "too_large", "refused_by_policy")
    ]
    # Even an error nobody planned for is "not checked", never a 500 or "not found".
    failures.append(RuntimeError(f"boom while asking for {PREFIX}"))
    with capture_logs() as logs:
        for failure in failures:
            env.range.answer = failure
            resp = await env.client.post(
                "/api/security/pwned-passwords/range", json={"prefix": PREFIX}, headers=env.headers
            )
            assert resp.status_code == 503
            assert resp.json() == {
                "detail": "Not checked: the Pwned Passwords service could not be reached."
            }
            assert "suffixes" not in resp.text and "boom" not in resp.text
    failed = [entry for entry in logs if entry["event"] == "pwned_range_failed"]
    assert [entry["reason"] for entry in failed] == [
        "http_status",
        "timeout",
        "too_large",
        "refused_by_policy",
        "RuntimeError",
    ]
    for entry in logs:
        assert PREFIX not in json.dumps(entry, default=str)


@pytest.mark.asyncio
async def test_the_password_range_route_writes_no_audit_row_and_logs_no_prefix_and_no_count(env):
    before = len(await audit_rows(env.session_factory))
    entries = [(f"{i:035X}", i + 1) for i in range(37)]
    env.range.answer = entries
    with capture_logs() as logs:
        resp = await env.client.post(
            "/api/security/pwned-passwords/range", json={"prefix": PREFIX}, headers=env.headers
        )
        assert resp.status_code == 200 and len(resp.json()["suffixes"]) == 37
        env.range.answer = PwnedPasswordsUnavailable("timeout")
        failed = await env.client.post(
            "/api/security/pwned-passwords/range", json={"prefix": PREFIX}, headers=env.headers
        )
        assert failed.status_code == 503
    assert len(await audit_rows(env.session_factory)) == before

    served = [entry for entry in logs if entry["event"] == "pwned_range_served"]
    assert len(served) == 1
    # SEC-F13: the user only, no key holding the number of suffixes, no value equal to it.
    assert set(served[0]) - {"event", "log_level"} == {"user_id"}
    assert served[0]["user_id"] == str(env.owner.id)
    for entry in logs:
        assert 37 not in [value for value in entry.values() if isinstance(value, int)]
        text = json.dumps(entry, default=str)
        assert PREFIX not in text and PREFIX.lower() not in text and SUFFIX not in text
        assert not any("count" in str(key) or "entries" in str(key) for key in entry)


# ---------------------------------------------------------------------------
# The account export
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_the_account_export_includes_the_watched_addresses_and_their_breaches(
    env, monkeypatch
):
    save_key(env, monkeypatch)
    body = (await env.client.get("/api/security/breach", headers=env.headers)).json()
    account_id = body["addresses"][0]["id"]
    await env.client.post(
        "/api/security/breach/addresses",
        json={"address": "me.alt@example.org"},
        headers=env.headers,
    )
    env.hibp.answers[OWNER] = [breach("ExampleShop")]
    await env.client.post(f"/api/security/breach/addresses/{account_id}/check", headers=env.headers)

    resp = await env.client.get("/api/auth/export", headers=env.headers)
    assert resp.status_code == 200
    data = json.loads(resp.text)
    section = data["breach_watch"]
    assert [(row["address"], row["source"]) for row in section] == [
        (OWNER, "account"),
        ("me.alt@example.org", "added"),
    ]
    (found,) = section[0]["findings"]
    assert found["name"] == "ExampleShop" and found["breach_date"] == "2026-08-30"
    assert section[1]["findings"] == []
    # Never a sealed blob, a digest or a key.
    text = json.dumps(section)
    assert "address_sealed" not in text and "address_digest" not in text and KEY not in text
