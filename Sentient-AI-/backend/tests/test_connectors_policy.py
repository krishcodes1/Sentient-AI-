"""Connectors-route policy tests: 'custom' type rejection and
MCP-aware health reporting."""

from __future__ import annotations

import pytest

from tests.conftest import auth_headers, make_user
from tests.test_mcp import FakeTransport, _make_mcp_connector


# ---------------------------------------------------------------------------
# 'custom' connector type
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_create_custom_connector_rejected_with_422(client, session_factory):
    """No code path can produce tools, dispatch, or test a 'custom'
    connector, so creating one (and storing an encrypted credential that
    nothing can ever use) must be refused."""
    _, token = await make_user(session_factory)

    response = await client.post(
        "/api/connectors/",
        headers=auth_headers(token),
        json={
            "connector_type": "custom",
            "display_name": "My Custom Thing",
            "auth_method": "api_key",
            "credentials": {"api_key": "secret"},
        },
    )
    assert response.status_code == 422
    assert "custom connectors are not yet supported" in response.json()["detail"]


def test_custom_enum_value_kept_for_forward_compat():
    from models.connector import ConnectorType

    assert ConnectorType.custom.value == "custom"


# ---------------------------------------------------------------------------
# granted_scopes validation against the first-party catalog
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_unknown_scopes_rejected_on_create(client, session_factory):
    _, token = await make_user(session_factory)
    response = await client.post(
        "/api/connectors/",
        headers=auth_headers(token),
        json={
            "connector_type": "canvas",
            "display_name": "bad scopes",
            "auth_method": "bearer_token",
            "credentials": {
                "base_url": "https://s.instructure.com",
                "access_token": "t",
            },
            "granted_scopes": ["not.a.real.scope", "'; DROP TABLE users;--"],
        },
    )
    assert response.status_code == 422
    assert "Unknown scope" in response.json()["detail"]


@pytest.mark.asyncio
async def test_financial_scope_rejected(client, session_factory):
    """crypto.trade is a financial scope, deliberately absent from the
    catalog, so granting it is refused up front."""
    _, token = await make_user(session_factory)
    response = await client.post(
        "/api/connectors/",
        headers=auth_headers(token),
        json={
            "connector_type": "robinhood",
            "display_name": "trade grab",
            "auth_method": "api_key",
            "credentials": {"api_key": "k", "api_secret": "s"},
            "granted_scopes": ["crypto.read", "crypto.trade"],
        },
    )
    assert response.status_code == 422
    assert "crypto.trade" in response.json()["detail"]


@pytest.mark.asyncio
async def test_valid_scopes_accepted(client, session_factory):
    _, token = await make_user(session_factory)
    response = await client.post(
        "/api/connectors/",
        headers=auth_headers(token),
        json={
            "connector_type": "canvas",
            "display_name": "good scopes",
            "auth_method": "bearer_token",
            "credentials": {
                "base_url": "https://s.instructure.com",
                "access_token": "t",
            },
            "granted_scopes": ["courses.read", "submissions.write"],
        },
    )
    assert response.status_code == 201


@pytest.mark.asyncio
async def test_mcp_scopes_not_validated(client, session_factory):
    """MCP servers expose dynamic tools, so their scope names are free-form
    and must not be rejected by the first-party catalog check."""
    _, token = await make_user(session_factory)
    response = await client.post(
        "/api/connectors/",
        headers=auth_headers(token),
        json={
            "connector_type": "mcp",
            "display_name": "mcp server",
            "auth_method": "api_key",
            "credentials": {"url": "https://mcp.example.com/rpc"},
            "granted_scopes": ["anything.goes", "custom.scope"],
        },
    )
    assert response.status_code == 201


# ---------------------------------------------------------------------------
# MCP health via the activity registry
# ---------------------------------------------------------------------------


async def _health_entry(client, token, connector_id):
    response = await client.get("/api/connectors/health", headers=auth_headers(token))
    assert response.status_code == 200
    return next(e for e in response.json() if e["id"] == str(connector_id))


@pytest.mark.asyncio
async def test_mcp_health_degraded_until_activity_then_healthy(
    client, session_factory
):
    from services.mcp.activity import mcp_activity

    user, token = await make_user(session_factory)
    connector_id = await _make_mcp_connector(session_factory, user.id)

    mcp_activity.reset()
    try:
        # Fresh server: no recorded activity -> degraded / Never (same
        # contract as any never-used connector type).
        entry = await _health_entry(client, token, connector_id)
        assert entry["status"] == "degraded"
        assert entry["last_check"] == "Never"

        # Errors alone do not make it healthy.
        mcp_activity.record_error(connector_id, "connection refused")
        entry = await _health_entry(client, token, connector_id)
        assert entry["status"] == "degraded"

        # A successful call flips it to healthy with a real last_check.
        mcp_activity.record_success(connector_id)
        entry = await _health_entry(client, token, connector_id)
        assert entry["status"] == "healthy"
        assert entry["last_check"] != "Never"
    finally:
        mcp_activity.reset()


@pytest.mark.asyncio
async def test_mcp_dispatch_records_activity_seen_by_health(client, session_factory):
    """End to end: a working MCP server reports healthy after a
    successful dispatch (previously it was permanently 'degraded')."""
    from services.mcp.activity import mcp_activity
    from services.mcp.client import MCPClient
    from services.mcp.integration import MCPConnectorLoader, MCPDispatcher

    user, token = await make_user(session_factory)
    connector_id = await _make_mcp_connector(session_factory, user.id)

    mcp_activity.reset()
    try:
        dispatcher = MCPDispatcher(
            MCPConnectorLoader(session_factory),
            client_factory=lambda ref: MCPClient(
                FakeTransport(tools=[{"name": "search_notes"}])
            ),
        )
        result = await dispatcher.execute(
            "mcp.notes_server.search_notes", {"q": "x"}, str(user.id)
        )
        assert result["ok"] is True

        entry = await _health_entry(client, token, connector_id)
        assert entry["status"] == "healthy"
    finally:
        mcp_activity.reset()
