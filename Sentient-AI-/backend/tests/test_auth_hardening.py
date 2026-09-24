"""Auth-route and rate-limit-attribution hardening tests.

Covers gaps that had no coverage before:
- X-Forwarded-For is trusted only from a trusted proxy peer, so a directly
  reachable client cannot mint a fresh rate-limit bucket per request (which
  would defeat the login brute-force throttle).
- Failed logins are also counted per ACCOUNT and lock it, which is the half
  of the brute-force bound an attacker cannot widen by changing address.
- Destructive account operations (email change, deletion) re-authenticate,
  so a stolen bearer token cannot take the account over or destroy it.
- Accounts are keyed on a normalized (lowercased) email, so casing cannot
  create duplicate accounts or lock a user out.
- The register -> login -> me happy path, wrong-password 401, and duplicate
  registration 409.
- Settings rejects an unknown LLM provider with 422 instead of deferring to
  a later 502 mid-chat.
"""

from __future__ import annotations

import ipaddress

import httpx
import pytest
import pytest_asyncio

from api.middleware.security import RateLimitMiddleware
from services.auth import login_lockout


@pytest_asyncio.fixture(autouse=True)
async def _isolate_lockout_state():
    """The lockout counter is a module-level singleton, so one test's
    failures would otherwise lock an account another test signs into."""
    await login_lockout.clear()
    yield
    await login_lockout.clear()


# ---------------------------------------------------------------------------
# Rate-limit client-IP attribution (unit — no app needed)
# ---------------------------------------------------------------------------


class _FakeReq:
    def __init__(self, peer: str | None, xff: str | None):
        self.client = type("C", (), {"host": peer})() if peer else None
        self.headers = {"x-forwarded-for": xff} if xff else {}


def _limiter(trusted: list[str]) -> RateLimitMiddleware:
    return RateLimitMiddleware(app=None, trusted_proxies=trusted, redis_url="")


def test_xff_honored_only_from_trusted_peer():
    limiter = _limiter(["10.0.0.0/8"])
    # Trusted proxy peer -> XFF (the real client) is used.
    assert limiter._get_client_ip(_FakeReq("10.1.2.3", "203.0.113.9")) == "203.0.113.9"


def test_xff_ignored_from_untrusted_peer():
    limiter = _limiter(["10.0.0.0/8"])
    # Untrusted peer -> XFF spoof is ignored; the peer is the bucket key.
    req = _FakeReq("198.51.100.7", "203.0.113.9")
    assert limiter._get_client_ip(req) == "198.51.100.7"


def test_spoofed_xff_cannot_mint_new_buckets():
    """From an untrusted peer, rotating X-Forwarded-For must NOT change the
    attributed IP — otherwise each request lands in a fresh bucket and the
    brute-force throttle is meaningless."""
    limiter = _limiter([])  # trust nothing
    ips = {
        limiter._get_client_ip(_FakeReq("198.51.100.7", f"203.0.113.{i}"))
        for i in range(1, 20)
    }
    assert ips == {"198.51.100.7"}


def test_malformed_xff_falls_back_to_peer():
    limiter = _limiter(["10.0.0.0/8"])
    assert limiter._get_client_ip(_FakeReq("10.0.0.1", "not-an-ip")) == "10.0.0.1"


def test_empty_trusted_list_never_trusts_xff():
    limiter = _limiter([])
    assert limiter._get_client_ip(_FakeReq("10.0.0.1", "203.0.113.9")) == "10.0.0.1"


def test_default_trusted_proxies_cover_private_ranges():
    from core.config import Settings

    # The shipped default (not the local .env override) trusts private/
    # loopback ranges where a reverse proxy sits.
    defaults = Settings.model_fields["TRUSTED_PROXIES"].default
    nets = [ipaddress.ip_network(c) for c in defaults]
    assert any(ipaddress.ip_address("127.0.0.1") in n for n in nets)
    assert any(ipaddress.ip_address("10.1.2.3") in n for n in nets)
    assert any(ipaddress.ip_address("172.20.0.5") in n for n in nets)


# ---------------------------------------------------------------------------
# Per-account lockout
# ---------------------------------------------------------------------------


async def _register(client: httpx.AsyncClient, email: str, password="password-123"):
    resp = await client.post(
        "/api/auth/register", json={"email": email, "password": password}
    )
    assert resp.status_code == 201, resp.text
    return resp


@pytest.mark.asyncio
async def test_repeated_failures_lock_the_account(client: httpx.AsyncClient, monkeypatch):
    from core.config import settings

    monkeypatch.setattr(settings, "LOCKOUT_THRESHOLD", 3)
    await _register(client, "lockme@example.com")

    for _ in range(3):
        bad = await client.post(
            "/api/auth/login",
            json={"email": "lockme@example.com", "password": "wrong-password"},
        )
        assert bad.status_code == 401

    locked = await client.post(
        "/api/auth/login",
        json={"email": "lockme@example.com", "password": "wrong-password"},
    )
    assert locked.status_code == 429
    assert int(locked.headers["Retry-After"]) > 0


@pytest.mark.asyncio
async def test_lockout_refuses_even_the_correct_password(
    client: httpx.AsyncClient, monkeypatch
):
    """A lock that the real password opens is not a lock: the attacker's
    last guess would simply succeed."""
    from core.config import settings

    monkeypatch.setattr(settings, "LOCKOUT_THRESHOLD", 2)
    await _register(client, "stilllocked@example.com")

    for _ in range(2):
        await client.post(
            "/api/auth/login",
            json={"email": "stilllocked@example.com", "password": "nope"},
        )

    resp = await client.post(
        "/api/auth/login",
        json={"email": "stilllocked@example.com", "password": "password-123"},
    )
    assert resp.status_code == 429


@pytest.mark.asyncio
async def test_lockout_survives_a_rotating_source_address(
    client: httpx.AsyncClient, session_factory, monkeypatch
):
    """The point of counting per account: an attacker who changes source
    address every attempt defeats the per-IP bucket, and must still hit the
    account's own ceiling."""
    from core.config import settings
    from main import app

    monkeypatch.setattr(settings, "LOCKOUT_THRESHOLD", 3)
    await _register(client, "rotating@example.com")

    async def _attempt(source: str, password: str):
        transport = httpx.ASGITransport(app=app, client=(source, 54321))
        async with httpx.AsyncClient(
            transport=transport, base_url="http://testserver"
        ) as rotating:
            return await rotating.post(
                "/api/auth/login",
                json={"email": "rotating@example.com", "password": password},
            )

    for i in range(3):
        assert (await _attempt(f"203.0.113.{i + 1}", "wrong")).status_code == 401

    blocked = await _attempt("203.0.113.99", "password-123")
    assert blocked.status_code == 429


@pytest.mark.asyncio
async def test_successful_login_clears_the_failure_counter(
    client: httpx.AsyncClient, monkeypatch
):
    from core.config import settings

    monkeypatch.setattr(settings, "LOCKOUT_THRESHOLD", 3)
    await _register(client, "typo@example.com")

    for _ in range(2):
        await client.post(
            "/api/auth/login", json={"email": "typo@example.com", "password": "oops"}
        )
    ok = await client.post(
        "/api/auth/login",
        json={"email": "typo@example.com", "password": "password-123"},
    )
    assert ok.status_code == 200

    # The two earlier typos must not carry over into the next session.
    for _ in range(2):
        again = await client.post(
            "/api/auth/login", json={"email": "typo@example.com", "password": "oops"}
        )
        assert again.status_code == 401


@pytest.mark.asyncio
async def test_unknown_address_gets_the_same_lockout_response(
    client: httpx.AsyncClient, monkeypatch
):
    """Tracking only real accounts would make the 429 an existence oracle:
    'this address locked out' would mean 'this address has an account'."""
    from core.config import settings

    monkeypatch.setattr(settings, "LOCKOUT_THRESHOLD", 2)
    for _ in range(2):
        resp = await client.post(
            "/api/auth/login",
            json={"email": "ghost@example.com", "password": "guess"},
        )
        assert resp.status_code == 401

    assert (
        await client.post(
            "/api/auth/login",
            json={"email": "ghost@example.com", "password": "guess"},
        )
    ).status_code == 429


@pytest.mark.asyncio
async def test_lockout_is_scoped_to_one_account(
    client: httpx.AsyncClient, monkeypatch
):
    from core.config import settings

    monkeypatch.setattr(settings, "LOCKOUT_THRESHOLD", 2)
    await _register(client, "victim@example.com")
    await _register(client, "bystander@example.com")

    for _ in range(2):
        await client.post(
            "/api/auth/login",
            json={"email": "victim@example.com", "password": "wrong"},
        )

    ok = await client.post(
        "/api/auth/login",
        json={"email": "bystander@example.com", "password": "password-123"},
    )
    assert ok.status_code == 200


@pytest.mark.asyncio
async def test_lockout_expires_after_its_window():
    """The lock is a delay, not a permanent denial — otherwise anyone who
    knows an address can keep its owner out for good."""
    from services.auth import AccountLockout

    lockout = AccountLockout(threshold=1, duration_minutes=1)
    assert await lockout.record_failure("expiry@example.com") == 60
    assert await lockout.seconds_remaining("expiry@example.com") > 0

    # Fast-forward past the window rather than sleeping through it.
    state = next(iter(lockout._states.values()))
    state.locked_until -= 61
    assert await lockout.seconds_remaining("expiry@example.com") == 0


@pytest.mark.asyncio
async def test_lockout_keys_are_hashed():
    """Attempted addresses accumulate for every login failure, including
    typo'd and probed ones; storing them verbatim turns the counter into a
    list of addresses someone tried."""
    from services.auth import AccountLockout

    lockout = AccountLockout(threshold=5)
    await lockout.record_failure("Secret.Person@example.com")
    assert "secret.person@example.com" not in "".join(lockout._states)
    # Casing must not create a second counter, or the ceiling is per spelling.
    assert len(lockout._states) == 1
    await lockout.record_failure("SECRET.PERSON@EXAMPLE.COM")
    assert len(lockout._states) == 1


# ---------------------------------------------------------------------------
# Re-authentication for destructive account operations
# ---------------------------------------------------------------------------


async def _logged_in(client: httpx.AsyncClient, email: str) -> dict[str, str]:
    await _register(client, email)
    login = await client.post(
        "/api/auth/login", json={"email": email, "password": "password-123"}
    )
    return {"Authorization": f"Bearer {login.json()['access_token']}"}


@pytest.mark.asyncio
async def test_email_change_requires_the_current_password(client: httpx.AsyncClient):
    headers = await _logged_in(client, "takeover@example.com")

    resp = await client.patch(
        "/api/auth/profile",
        headers=headers,
        json={"email": "attacker@example.com"},
    )
    assert resp.status_code == 403
    me = await client.get("/api/auth/me", headers=headers)
    assert me.json()["email"] == "takeover@example.com"


@pytest.mark.asyncio
async def test_email_change_rejects_a_wrong_password(client: httpx.AsyncClient):
    headers = await _logged_in(client, "wrongconfirm@example.com")

    resp = await client.patch(
        "/api/auth/profile",
        headers=headers,
        json={"email": "attacker@example.com", "current_password": "not-it"},
    )
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_email_change_succeeds_with_the_current_password(
    client: httpx.AsyncClient,
):
    headers = await _logged_in(client, "rename@example.com")

    resp = await client.patch(
        "/api/auth/profile",
        headers=headers,
        json={"email": "renamed@example.com", "current_password": "password-123"},
    )
    assert resp.status_code == 200, resp.text
    assert resp.json()["email"] == "renamed@example.com"


@pytest.mark.asyncio
async def test_name_change_still_needs_no_password(client: httpx.AsyncClient):
    """Re-authentication is for irreversible operations; applying it to an
    editable display name would only train users to retype the password."""
    headers = await _logged_in(client, "nameonly@example.com")

    resp = await client.patch(
        "/api/auth/profile", headers=headers, json={"name": "New Name"}
    )
    assert resp.status_code == 200
    assert resp.json()["name"] == "New Name"


@pytest.mark.asyncio
async def test_account_deletion_requires_the_current_password(
    client: httpx.AsyncClient,
):
    # The first account owns the install and may not delete itself (see
    # test_admin_role), so the account under test is the second one.
    await _register(client, "owner@example.com")
    headers = await _logged_in(client, "deleteme@example.com")

    bare = await client.request("DELETE", "/api/auth/account", headers=headers)
    assert bare.status_code == 403

    wrong = await client.request(
        "DELETE",
        "/api/auth/account",
        headers=headers,
        json={"current_password": "not-my-password"},
    )
    assert wrong.status_code == 403

    # The account is still there and still usable.
    assert (await client.get("/api/auth/me", headers=headers)).status_code == 200

    confirmed = await client.request(
        "DELETE",
        "/api/auth/account",
        headers=headers,
        json={"current_password": "password-123"},
    )
    assert confirmed.status_code == 204
    assert (await client.get("/api/auth/me", headers=headers)).status_code == 401


# ---------------------------------------------------------------------------
# Email normalization
# ---------------------------------------------------------------------------


def test_normalize_email():
    from core.validation import normalize_email

    assert normalize_email("  Bob.Smith@Example.COM ") == "bob.smith@example.com"


@pytest.mark.asyncio
async def test_register_lowercases_email_and_login_is_case_insensitive(client: httpx.AsyncClient):
    reg = await client.post(
        "/api/auth/register",
        json={"email": "Casey@Example.com", "password": "password-123"},
    )
    assert reg.status_code == 201, reg.text
    assert reg.json()["email"] == "casey@example.com"

    # Log in with different casing — must resolve to the same account.
    login = await client.post(
        "/api/auth/login",
        json={"email": "CASEY@EXAMPLE.COM", "password": "password-123"},
    )
    assert login.status_code == 200, login.text
    assert login.json()["access_token"]


@pytest.mark.asyncio
async def test_duplicate_registration_differing_only_in_case_is_rejected(
    client: httpx.AsyncClient,
):
    first = await client.post(
        "/api/auth/register",
        json={"email": "dup@example.com", "password": "password-123"},
    )
    assert first.status_code == 201
    second = await client.post(
        "/api/auth/register",
        json={"email": "DUP@Example.com", "password": "password-123"},
    )
    assert second.status_code == 409


# ---------------------------------------------------------------------------
# Auth happy path + failure modes
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_register_login_me_flow(client: httpx.AsyncClient):
    await client.post(
        "/api/auth/register",
        json={"email": "flow@example.com", "password": "password-123", "name": "Flow"},
    )
    login = await client.post(
        "/api/auth/login",
        json={"email": "flow@example.com", "password": "password-123"},
    )
    token = login.json()["access_token"]
    me = await client.get("/api/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert me.status_code == 200
    assert me.json()["email"] == "flow@example.com"
    assert me.json()["name"] == "Flow"


@pytest.mark.asyncio
async def test_wrong_password_is_401(client: httpx.AsyncClient):
    await client.post(
        "/api/auth/register",
        json={"email": "wp@example.com", "password": "password-123"},
    )
    bad = await client.post(
        "/api/auth/login",
        json={"email": "wp@example.com", "password": "wrong-password"},
    )
    assert bad.status_code == 401


@pytest.mark.asyncio
async def test_short_password_rejected(client: httpx.AsyncClient):
    resp = await client.post(
        "/api/auth/register",
        json={"email": "short@example.com", "password": "short"},
    )
    assert resp.status_code == 422


# ---------------------------------------------------------------------------
# Settings: unknown provider rejected up front
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_settings_rejects_unknown_provider(client: httpx.AsyncClient):
    await client.post(
        "/api/auth/register",
        json={"email": "settings@example.com", "password": "password-123"},
    )
    login = await client.post(
        "/api/auth/login",
        json={"email": "settings@example.com", "password": "password-123"},
    )
    token = login.json()["access_token"]
    resp = await client.patch(
        "/api/auth/settings",
        json={"llm_provider": "totally-not-a-provider"},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 422
    assert "provider" in resp.text.lower()


@pytest.mark.asyncio
async def test_settings_accepts_known_provider_case_insensitively(client: httpx.AsyncClient):
    await client.post(
        "/api/auth/register",
        json={"email": "prov@example.com", "password": "password-123"},
    )
    login = await client.post(
        "/api/auth/login",
        json={"email": "prov@example.com", "password": "password-123"},
    )
    token = login.json()["access_token"]
    # A new account follows the install (no model of its own), so pinning a
    # provider names the model too.
    resp = await client.patch(
        "/api/auth/settings",
        json={"llm_provider": "OpenAI", "llm_model": "gpt-4o"},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 200
    assert resp.json()["llm_provider"] == "openai"
