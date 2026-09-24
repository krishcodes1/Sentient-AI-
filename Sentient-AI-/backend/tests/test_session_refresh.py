"""Tests for POST /auth/refresh: refresh requires an already-valid token, extends
expiry while carrying the original session start forward, is refused past the
absolute session cap, and stops immediately after a password change.

Why it exists: Refresh trades a hard 60-minute expiry for a longer-lived but
still bounded session on a possibly-stolen token, so these pin the limits on
that trade.

POST /auth/refresh — extending a session without a second credential.

A hard 60-minute expiry logs the user out mid-conversation. Refresh trades
that for a longer useful life on a stolen token, so the properties worth
pinning are the limits on that trade: refresh requires an already-valid
token, it cannot outrun the absolute session cap, and a password change
still kills it instantly.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from core.config import settings
from core.security import create_access_token, verify_access_token
from tests.conftest import auth_headers


async def _register_and_login(client, email: str = "session@example.com"):
    await client.post(
        "/api/auth/register", json={"email": email, "password": "password-123"}
    )
    login = await client.post(
        "/api/auth/login", json={"email": email, "password": "password-123"}
    )
    return login.json()["access_token"]


@pytest.mark.asyncio
async def test_refresh_requires_authentication(client):
    resp = await client.post("/api/auth/refresh")
    assert resp.status_code in (401, 403)


@pytest.mark.asyncio
async def test_refresh_rejects_a_garbage_token(client):
    resp = await client.post(
        "/api/auth/refresh", headers=auth_headers("not-a-jwt")
    )
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_refresh_returns_a_working_token(client):
    token = await _register_and_login(client)

    resp = await client.post("/api/auth/refresh", headers=auth_headers(token))
    assert resp.status_code == 200
    new_token = resp.json()["access_token"]

    me = await client.get("/api/auth/me", headers=auth_headers(new_token))
    assert me.status_code == 200
    assert me.json()["email"] == "session@example.com"


@pytest.mark.asyncio
async def test_refresh_extends_the_expiry(client):
    token = await _register_and_login(client, "extend@example.com")
    original_exp = verify_access_token(token)["exp"]

    # Issue the refresh from a token minted a while ago, so the new expiry
    # is provably later rather than merely equal within the same second.
    aged = create_access_token(
        data={
            "sub": verify_access_token(token)["sub"],
            "email": "extend@example.com",
            "epoch": 0,
            "sst": int(
                (datetime.now(timezone.utc) - timedelta(minutes=30)).timestamp()
            ),
        },
        expires_delta=timedelta(minutes=5),
    )
    resp = await client.post("/api/auth/refresh", headers=auth_headers(aged))
    assert resp.status_code == 200

    new_exp = verify_access_token(resp.json()["access_token"])["exp"]
    assert new_exp > verify_access_token(aged)["exp"]
    assert new_exp >= original_exp


@pytest.mark.asyncio
async def test_refresh_carries_the_session_start_forward(client):
    """Otherwise each refresh would restart the clock and the absolute cap
    would never be reached — the whole point of the cap."""
    token = await _register_and_login(client, "carry@example.com")
    started = verify_access_token(token)["sst"]

    current = token
    for _ in range(3):
        resp = await client.post(
            "/api/auth/refresh", headers=auth_headers(current)
        )
        assert resp.status_code == 200
        current = resp.json()["access_token"]
        assert verify_access_token(current)["sst"] == started


@pytest.mark.asyncio
async def test_refresh_refuses_past_the_absolute_session_cap(client):
    user_token = await _register_and_login(client, "capped@example.com")
    sub = verify_access_token(user_token)["sub"]

    # A token that is still valid, but whose session began longer ago than
    # the cap allows.
    too_old = create_access_token(
        data={
            "sub": sub,
            "email": "capped@example.com",
            "epoch": 0,
            "sst": int(
                (
                    datetime.now(timezone.utc)
                    - timedelta(hours=settings.SESSION_MAX_HOURS + 1)
                ).timestamp()
            ),
        }
    )
    # It still authenticates ordinary requests...
    assert (
        await client.get("/api/auth/me", headers=auth_headers(too_old))
    ).status_code == 200
    # ...but cannot be extended.
    resp = await client.post("/api/auth/refresh", headers=auth_headers(too_old))
    assert resp.status_code == 401
    assert str(settings.SESSION_MAX_HOURS) in resp.json()["detail"]


@pytest.mark.asyncio
async def test_password_change_stops_refresh_immediately(client):
    """Revocation must not be escapable by refreshing."""
    token = await _register_and_login(client, "revoked@example.com")

    change = await client.post(
        "/api/auth/password",
        headers=auth_headers(token),
        json={"current_password": "password-123", "new_password": "password-456"},
    )
    assert change.status_code == 204

    resp = await client.post("/api/auth/refresh", headers=auth_headers(token))
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_refresh_of_a_token_without_a_session_claim_is_bounded(client):
    """Tokens minted before session tracking existed must not gain an
    unbounded session — their own issue time is used as the start."""
    user_token = await _register_and_login(client, "legacy@example.com")
    sub = verify_access_token(user_token)["sub"]

    legacy = create_access_token(
        data={"sub": sub, "email": "legacy@example.com", "epoch": 0}
    )
    resp = await client.post("/api/auth/refresh", headers=auth_headers(legacy))
    assert resp.status_code == 200
    # The refreshed token now carries a session start, so the cap applies
    # from here on rather than never.
    assert "sst" in verify_access_token(resp.json()["access_token"])
