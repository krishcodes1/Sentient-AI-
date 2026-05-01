"""Tests for the P0 production-hardening surface area.

Covers:
- ``Settings.validate_for_environment`` rejects insecure prod configs.
- ``RequestIDMiddleware`` echoes / generates the ``X-Request-ID`` header.
- ``TrustProxyMiddleware`` only trusts ``X-Forwarded-For`` from allowlisted
  client IPs.
- ``GET /api/health`` reflects DB liveness and degrades to HTTP 503 when
  the database probe raises.
"""

from __future__ import annotations

import base64
import os
from typing import Any

import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient

from api.middleware.request_id import HEADER as REQUEST_ID_HEADER
from api.middleware.request_id import RequestIDMiddleware
from api.middleware.trust_proxy import TrustProxyMiddleware
from core.config import ConfigurationError, Settings


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


_VALID_B64_32_BYTES = base64.urlsafe_b64encode(b"\x01" * 32).decode()


def _make_prod_settings(**overrides: Any) -> Settings:
    """Build a Settings instance pinned to production with safe defaults.

    Tests override individual fields to assert each validation rule fires.
    """
    base: dict[str, Any] = dict(
        ENVIRONMENT="production",
        SECRET_KEY="x" * 64,
        ENCRYPTION_KEY=_VALID_B64_32_BYTES,
        DATABASE_URL="postgresql+asyncpg://prod:strongpw@db.internal:5432/sentientai",
        CORS_ORIGINS=["https://app.example.com"],
        ALLOWED_HOSTS=["app.example.com"],
        LLM_PROVIDER="ollama",  # ollama doesn't need an API key
    )
    base.update(overrides)
    return Settings(**base)


# ---------------------------------------------------------------------------
# A. Config validation
# ---------------------------------------------------------------------------


def test_config_validation_rejects_localhost_db_in_prod() -> None:
    s = _make_prod_settings(
        DATABASE_URL="postgresql+asyncpg://prod:strongpw@localhost:5432/sentientai"
    )
    with pytest.raises(ConfigurationError, match="DATABASE_URL"):
        s.validate_for_environment()


def test_config_validation_rejects_placeholder_secret_in_prod() -> None:
    s = _make_prod_settings(SECRET_KEY="replace-me")
    with pytest.raises(ConfigurationError, match="SECRET_KEY"):
        s.validate_for_environment()


def test_config_validation_rejects_short_secret_in_prod() -> None:
    s = _make_prod_settings(SECRET_KEY="too-short")
    with pytest.raises(ConfigurationError, match="SECRET_KEY"):
        s.validate_for_environment()


def test_config_validation_rejects_default_creds_in_db_url_in_prod() -> None:
    s = _make_prod_settings(
        DATABASE_URL="postgresql+asyncpg://sentientai:sentientai@db.internal:5432/sentientai"
    )
    with pytest.raises(ConfigurationError, match="sentientai:sentientai"):
        s.validate_for_environment()


def test_config_validation_rejects_wildcard_cors_in_prod() -> None:
    s = _make_prod_settings(CORS_ORIGINS=["*"])
    with pytest.raises(ConfigurationError, match="CORS"):
        s.validate_for_environment()


def test_config_validation_rejects_wildcard_allowed_hosts_in_prod() -> None:
    s = _make_prod_settings(ALLOWED_HOSTS=["*"])
    with pytest.raises(ConfigurationError, match="ALLOWED_HOSTS"):
        s.validate_for_environment()


def test_config_validation_rejects_empty_allowed_hosts_in_prod() -> None:
    s = _make_prod_settings(ALLOWED_HOSTS=[])
    with pytest.raises(ConfigurationError, match="ALLOWED_HOSTS"):
        s.validate_for_environment()


def test_config_validation_requires_provider_api_key_in_prod() -> None:
    s = _make_prod_settings(LLM_PROVIDER="anthropic", ANTHROPIC_API_KEY=None)
    with pytest.raises(ConfigurationError, match="ANTHROPIC_API_KEY"):
        s.validate_for_environment()


def test_config_validation_passes_in_dev() -> None:
    """Dev environment must skip all production-only assertions."""
    s = Settings(
        ENVIRONMENT="development",
        SECRET_KEY="replace-me",  # would fail in prod
        ENCRYPTION_KEY=_VALID_B64_32_BYTES,
        DATABASE_URL="postgresql+asyncpg://sentientai:sentientai@localhost:5432/sentientai",
        CORS_ORIGINS=["*"],
    )
    # No exception expected.
    s.validate_for_environment()


def test_config_validation_passes_with_clean_prod_config() -> None:
    s = _make_prod_settings()
    s.validate_for_environment()


# ---------------------------------------------------------------------------
# B. RequestIDMiddleware
# ---------------------------------------------------------------------------


def _build_app_with(*middlewares: tuple[type, dict[str, Any]]) -> FastAPI:
    """Construct a tiny FastAPI app with the given middlewares wired."""
    app = FastAPI()
    for mw_cls, kwargs in middlewares:
        app.add_middleware(mw_cls, **kwargs)

    @app.get("/echo")
    async def echo(request: Any) -> dict[str, Any]:  # type: ignore[no-untyped-def]
        return {
            "client_host": request.client.host if request.client else None,
            "request_id": getattr(request.state, "request_id", None),
        }

    return app


@pytest.mark.asyncio
async def test_request_id_propagated_in_response_header() -> None:
    """A request without an X-Request-ID gets a generated one in the response."""
    app = _build_app_with((RequestIDMiddleware, {}))
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        resp = await ac.get("/echo")
    assert resp.status_code == 200
    rid = resp.headers.get(REQUEST_ID_HEADER)
    assert rid is not None and len(rid) >= 16
    assert resp.json()["request_id"] == rid


@pytest.mark.asyncio
async def test_request_id_uses_inbound_header_if_present() -> None:
    """A client-supplied X-Request-ID is honoured and echoed back."""
    app = _build_app_with((RequestIDMiddleware, {}))
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        resp = await ac.get(
            "/echo",
            headers={REQUEST_ID_HEADER: "client-supplied-id-123"},
        )
    assert resp.status_code == 200
    assert resp.headers[REQUEST_ID_HEADER] == "client-supplied-id-123"
    assert resp.json()["request_id"] == "client-supplied-id-123"


# ---------------------------------------------------------------------------
# C. TrustProxyMiddleware
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_trust_proxy_ignores_xff_from_untrusted_client() -> None:
    """When the direct client is not in the trusted CIDR list, XFF is ignored."""
    app = _build_app_with(
        # Only 10.0.0.0/8 is trusted; ASGI test client connects as 127.0.0.1.
        (TrustProxyMiddleware, {"trusted_networks": ["10.0.0.0/8"]}),
    )
    transport = ASGITransport(app=app, client=("127.0.0.1", 5555))
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        resp = await ac.get(
            "/echo",
            headers={"X-Forwarded-For": "203.0.113.7, 10.0.0.5"},
        )
    assert resp.status_code == 200
    # XFF was ignored because 127.0.0.1 is not in 10.0.0.0/8.
    assert resp.json()["client_host"] == "127.0.0.1"


@pytest.mark.asyncio
async def test_trust_proxy_uses_xff_from_trusted_client() -> None:
    """When the direct client IS trusted, the first XFF entry becomes client.host."""
    app = _build_app_with(
        (TrustProxyMiddleware, {"trusted_networks": ["127.0.0.0/8"]}),
    )
    transport = ASGITransport(app=app, client=("127.0.0.1", 5555))
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        resp = await ac.get(
            "/echo",
            headers={"X-Forwarded-For": "203.0.113.7, 10.0.0.5"},
        )
    assert resp.status_code == 200
    # XFF was honoured because 127.0.0.1 is in 127.0.0.0/8.
    assert resp.json()["client_host"] == "203.0.113.7"


@pytest.mark.asyncio
async def test_trust_proxy_no_op_when_no_networks_configured() -> None:
    """Empty trusted_networks list disables the feature entirely."""
    app = _build_app_with(
        (TrustProxyMiddleware, {"trusted_networks": []}),
    )
    transport = ASGITransport(app=app, client=("10.0.0.5", 5555))
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        resp = await ac.get(
            "/echo",
            headers={"X-Forwarded-For": "203.0.113.7"},
        )
    assert resp.status_code == 200
    assert resp.json()["client_host"] == "10.0.0.5"


# ---------------------------------------------------------------------------
# D. /api/health
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_health_returns_healthy_with_db_up(client: AsyncClient) -> None:
    """With the test SQLite engine reachable, /api/health returns 200 healthy."""
    resp = await client.get("/api/health")
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "healthy"
    assert body["db"] == "ok"
    assert body["redis"] == "skipped"
    assert "version" in body
    assert "uptime_seconds" in body


@pytest.mark.asyncio
async def test_health_returns_503_when_db_down(
    client: AsyncClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    """If the DB probe raises, the endpoint must report 503 + db: err."""
    import main as main_module

    class _BoomSession:
        async def __aenter__(self) -> "_BoomSession":
            return self

        async def __aexit__(self, *exc: Any) -> None:
            return None

        async def execute(self, *_args: Any, **_kwargs: Any) -> Any:
            raise RuntimeError("simulated db outage")

    def _boom_factory() -> _BoomSession:
        return _BoomSession()

    monkeypatch.setattr(main_module, "async_session", _boom_factory)

    resp = await client.get("/api/health")
    assert resp.status_code == 503
    body = resp.json()
    assert body["status"] == "degraded"
    assert body["db"] == "err"
