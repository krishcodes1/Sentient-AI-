"""Tests for production hardening: SECRET_KEY and ENCRYPTION_KEY are validated at
startup, `production_warnings()` flags risky defaults, `/api/health` reflects
real database reachability, registration can be disabled, and a password change
revokes outstanding JWTs via `token_epoch`.

Why it exists: Guards the launch-readiness fixes so the committed
`.env.example` placeholder keys, or any other weak key, fail loudly at startup
instead of silently signing every session with a public secret.

Production-hardening tests.

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

import httpx
import pytest
import structlog
from pydantic import ValidationError

import main as main_module
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
    assert "TRUSTED_PROXIES" in text  # default trusts every private range


def test_production_clean_config_has_no_warnings():
    cfg = _settings(
        ENVIRONMENT="production",
        CORS_ORIGINS=["https://assistant.example.com"],
        AUDIT_HMAC_KEY=secrets.token_urlsafe(48),
        ALLOW_REGISTRATION=False,
        ALLOWED_HOSTS=["assistant.example.com"],
        TRUSTED_PROXIES=["127.0.0.1/32"],
    )
    assert cfg.production_warnings() == []


def test_trusted_proxy_warning_names_the_ranges_it_objects_to():
    """The shipped default trusts every RFC1918 range, which any host on
    the same network can exploit to spoof its client IP. Keeping the
    default (the compose topology needs it) is only acceptable if the
    deployment is told, by range, what it is trusting."""
    cfg = _settings(ENVIRONMENT="production", TRUSTED_PROXIES=["10.0.0.0/8", "::1/128"])
    warning = next(w for w in cfg.production_warnings() if "TRUSTED_PROXIES" in w)
    assert "10.0.0.0/8" in warning
    # Loopback is where a co-located proxy legitimately lives — not a risk.
    assert "::1/128" not in warning


def test_loopback_only_trusted_proxies_is_not_flagged():
    cfg = _settings(
        ENVIRONMENT="production", TRUSTED_PROXIES=["127.0.0.0/8", "::1/128"]
    )
    assert not any("TRUSTED_PROXIES" in w for w in cfg.production_warnings())


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


# ---------------------------------------------------------------------------
# Global exception handler never logs raw exception text
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_global_exception_handler_never_logs_the_raw_exception_text(monkeypatch):
    """An unhandled exception's ``str()`` can carry secrets (a bad API key
    echoed back by a driver, a token embedded in a failed URL, ...). The
    handler must log only the exception's type and the request's path and
    method — never the exception text itself — while leaving the client
    response body unchanged.

    Uses a private ASGI transport (rather than the shared ``client``
    fixture) with ``raise_app_exceptions=False``: Starlette's
    ServerErrorMiddleware always re-raises after invoking the registered
    handler so a real server (or a log shipper) still sees the traceback,
    and httpx's default transport propagates that re-raise into the test
    instead of returning the handler's response.
    """
    secret = "sk-SECRET-0123456789abcdef"

    async def _boom():
        raise RuntimeError(f"connection failed while using key {secret}")

    main_module.app.add_api_route("/__test_only_explode__", _boom, methods=["GET"])
    # Fresh logger instance so this test's capture isn't skipped because an
    # earlier test already cached main's logger with different processors
    # (structlog's cache_logger_on_first_use binds on first use).
    monkeypatch.setattr(main_module, "logger", structlog.get_logger(main_module.__name__))

    try:
        transport = httpx.ASGITransport(
            app=main_module.app, client=("192.0.2.99", 54321), raise_app_exceptions=False
        )
        async with httpx.AsyncClient(
            transport=transport, base_url="http://testserver"
        ) as http_client:
            with structlog.testing.capture_logs() as logs:
                resp = await http_client.get("/__test_only_explode__")
    finally:
        main_module.app.router.routes[:] = [
            route
            for route in main_module.app.router.routes
            if getattr(route, "path", None) != "/__test_only_explode__"
        ]

    assert resp.status_code == 500
    body = resp.json()
    assert body["detail"] == "Internal server error"
    assert "request_id" in body
    assert secret not in resp.text

    assert all(secret not in str(entry) for entry in logs)
    events = {entry["event"]: entry for entry in logs}
    entry = events["unhandled_exception"]
    assert entry["error_type"] == "RuntimeError"
    assert entry["path"] == "/__test_only_explode__"
    assert entry["method"] == "GET"
    assert "error" not in entry
    assert secret not in repr(entry)
