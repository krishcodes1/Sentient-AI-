"""Production-hardening tests.

Covers the launch-readiness fixes:
- SECRET_KEY / ENCRYPTION_KEY are validated at startup, so the committed
  .env.example placeholders (or any weak key) fail loudly instead of
  silently signing every session token with a public string.
- production_warnings() surfaces risky-but-legal production config.
- /api/health reflects real database reachability (503 when down).
- Registration can be disabled and the password policy is configurable.
- Password change bumps token_epoch, revoking outstanding JWTs.
"""

from __future__ import annotations

import base64
import os
import secrets

import pytest
from pydantic import ValidationError

from core.config import Settings, settings
from tests.conftest import auth_headers, make_user

_GOOD_SECRET = secrets.token_urlsafe(48)
_GOOD_ENC = base64.urlsafe_b64encode(os.urandom(32)).decode()


def _settings(**overrides):
    kwargs = {"SECRET_KEY": _GOOD_SECRET, "ENCRYPTION_KEY": _GOOD_ENC}
    kwargs.update(overrides)
    # _env_file=None: validate exactly the values under test, without the
    # developer's local .env bleeding in.
    return Settings(_env_file=None, **kwargs)


# ---------------------------------------------------------------------------
# Key validation at startup
# ---------------------------------------------------------------------------


def test_placeholder_secret_key_rejected():
    with pytest.raises(ValidationError, match="placeholder"):
        _settings(SECRET_KEY="REPLACE_ME_run_the_command_above")


def test_short_secret_key_rejected():
    with pytest.raises(ValidationError, match="at least 32"):
        _settings(SECRET_KEY="tooshort")


def test_strong_secret_key_accepted():
    assert _settings().SECRET_KEY == _GOOD_SECRET


def test_placeholder_encryption_key_rejected():
    # The .env.example placeholder decodes to 24 bytes, not 32 — before
    # this validator existed it only failed on the first connector save.
    with pytest.raises(ValidationError):
        _settings(ENCRYPTION_KEY="REPLACE_ME_run_the_command_above")


def test_non_base64_encryption_key_rejected():
    with pytest.raises(ValidationError):
        _settings(ENCRYPTION_KEY="!!!not-base64!!!")


def test_wrong_length_encryption_key_rejected():
    with pytest.raises(ValidationError):
        _settings(ENCRYPTION_KEY=base64.urlsafe_b64encode(os.urandom(16)).decode())


def test_password_min_length_cannot_go_below_8():
    with pytest.raises(ValidationError):
        _settings(PASSWORD_MIN_LENGTH=4)


# ---------------------------------------------------------------------------
# Production warnings
# ---------------------------------------------------------------------------


def test_no_warnings_outside_production():
    cfg = _settings(ENVIRONMENT="development")
    assert cfg.production_warnings() == []


def test_production_warns_on_risky_defaults():
    cfg = _settings(ENVIRONMENT="production")
    text = " ".join(cfg.production_warnings())
    assert "localhost" in text  # default CORS origin
    assert "AUDIT_HMAC_KEY" in text
    assert "ALLOW_REGISTRATION" in text
    assert "ALLOWED_HOSTS" in text


def test_production_clean_config_has_no_warnings():
    cfg = _settings(
        ENVIRONMENT="production",
        CORS_ORIGINS=["https://assistant.example.com"],
        AUDIT_HMAC_KEY=secrets.token_urlsafe(48),
        ALLOW_REGISTRATION=False,
        ALLOWED_HOSTS=["assistant.example.com"],
    )
    assert cfg.production_warnings() == []


# ---------------------------------------------------------------------------
# Health endpoint
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_health_ok_with_reachable_database(client):
    resp = await client.get("/api/health")
    assert resp.status_code == 200
    assert resp.json()["status"] == "healthy"


@pytest.mark.asyncio
async def test_health_503_when_database_unreachable(client):
    from core.database import get_db
    from main import app

    class _DeadSession:
        async def execute(self, *_args, **_kwargs):
            raise ConnectionError("database is down")

        async def rollback(self):
            pass

    async def _dead_db():
        yield _DeadSession()

    app.dependency_overrides[get_db] = _dead_db
    try:
        resp = await client.get("/api/health")
    finally:
        app.dependency_overrides.pop(get_db, None)
    assert resp.status_code == 503
    assert resp.json()["status"] == "unhealthy"


# ---------------------------------------------------------------------------
# Registration gate + password policy
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_registration_disabled_returns_403(client, monkeypatch):
    monkeypatch.setattr(settings, "ALLOW_REGISTRATION", False)
    resp = await client.post(
        "/api/auth/register",
        json={"email": "new@example.com", "password": "password-123"},
    )
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_configured_password_min_length_enforced(client, monkeypatch):
    monkeypatch.setattr(settings, "PASSWORD_MIN_LENGTH", 12)
    resp = await client.post(
        "/api/auth/register",
        json={"email": "new@example.com", "password": "8chars-ok"},
    )
    assert resp.status_code == 422
    assert "12" in resp.json()["detail"]


# ---------------------------------------------------------------------------
# Token revocation on password change
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_password_change_revokes_outstanding_tokens(client, session_factory):
    resp = await client.post(
        "/api/auth/register",
        json={"email": "epoch@example.com", "password": "password-123"},
    )
    assert resp.status_code == 201

    login = await client.post(
        "/api/auth/login",
        json={"email": "epoch@example.com", "password": "password-123"},
    )
    old_token = login.json()["access_token"]

    me = await client.get("/api/auth/me", headers=auth_headers(old_token))
    assert me.status_code == 200

    change = await client.post(
        "/api/auth/password",
        headers=auth_headers(old_token),
        json={"current_password": "password-123", "new_password": "password-456"},
    )
    assert change.status_code == 204

    # The pre-change token is now revoked...
    me_again = await client.get("/api/auth/me", headers=auth_headers(old_token))
    assert me_again.status_code == 401

    # ...and a fresh login issues a working epoch-1 token.
    relogin = await client.post(
        "/api/auth/login",
        json={"email": "epoch@example.com", "password": "password-456"},
    )
    assert relogin.status_code == 200
    new_token = relogin.json()["access_token"]
    me_new = await client.get("/api/auth/me", headers=auth_headers(new_token))
    assert me_new.status_code == 200


@pytest.mark.asyncio
async def test_legacy_token_without_epoch_claim_still_works(client, session_factory):
    # make_user mints a token with no epoch claim; a user whose column is 0
    # must accept it (upgrade back-compat).
    _user, token = await make_user(session_factory, email="legacy@example.com")
    resp = await client.get("/api/auth/me", headers=auth_headers(token))
    assert resp.status_code == 200
