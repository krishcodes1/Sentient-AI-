"""Auth-route and rate-limit-attribution hardening tests.

Covers gaps that had no coverage before:
- X-Forwarded-For is trusted only from a trusted proxy peer, so a directly
  reachable client cannot mint a fresh rate-limit bucket per request (which
  would defeat the login brute-force throttle).
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

from api.middleware.security import RateLimitMiddleware


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
    resp = await client.patch(
        "/api/auth/settings",
        json={"llm_provider": "OpenAI"},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 200
    assert resp.json()["llm_provider"] == "openai"
