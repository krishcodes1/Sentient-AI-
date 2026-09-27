"""End-to-end pipeline tests for the Slack connector: tool offering, the runtime
permission decision and the connector executor, with only HTTP mocked.

Why it exists: unit tests prove each Slack method; these prove the registry
line, catalog, permission rows, always-confirm layers, credential decryption,
scope checks, the real factory (network policy armed) and result
normalisation all fit together for ``slack.*`` tools.

It uses ``services.agent.tool_registry`` (build_tools, RuntimePermissionAdapter,
ConnectorToolExecutor) and ``services.connectors.factory.create_connector``,
wrapped so the built connector talks to ``httpx.MockTransport`` while its real
network-policy hook still runs. No network, no real credentials.
"""

from __future__ import annotations

import json
from typing import Any

import httpx
import pytest

import core.network_security as netsec
import services.connectors.factory as factory
from services.agent.tool_registry import (
    CONNECTOR_CATALOG,
    ConnectorSpec,
    ConnectorToolExecutor,
    RuntimePermissionAdapter,
    build_tools,
)
from services.connectors.slack import SlackConnector

BOT = "xoxb-test-token"


@pytest.fixture
def slack_http(monkeypatch):
    """Route every Slack connector the real factory builds to a mock transport."""
    monkeypatch.setattr(netsec, "check_ssrf", lambda url: netsec.SSRFCheckResult(safe=True))
    seen: list[httpx.Request] = []
    built: list[SlackConnector] = []
    real_create = factory.create_connector

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        method = request.url.path.rsplit("/", 1)[-1]
        if method == "conversations.list":
            return httpx.Response(
                200,
                json={
                    "ok": True,
                    "channels": [
                        {"id": "C0123ABCD", "name": "general", "is_member": True},
                    ],
                },
            )
        if method == "chat.postMessage":
            return httpx.Response(200, json={"ok": True, "channel": "C0123ABCD", "ts": "9.9"})
        return httpx.Response(200, json={"ok": False, "error": "unknown_method"})

    def create(connector_type: str, credentials: dict[str, Any], **kwargs: Any):
        connector = real_create(connector_type, credentials, **kwargs)
        assert isinstance(connector, SlackConnector)
        # Mock transport, but the connector's own policy hook still checks
        # every request against the "slack" allowlist.
        connector._http_client = httpx.AsyncClient(
            transport=httpx.MockTransport(handler),
            event_hooks={"request": [connector._enforce_network_policy]},
        )
        built.append(connector)
        return connector

    monkeypatch.setattr(factory, "create_connector", create)
    return seen, built


async def _slack_row(session_factory, user_id, scopes: tuple[str, ...]) -> None:
    from core.security import encrypt_credentials
    from models.connector import AuthMethod, ConnectorConfig

    async with session_factory() as session:
        session.add(
            ConnectorConfig(
                user_id=user_id,
                connector_type="slack",
                display_name="Acme Slack",
                auth_method=AuthMethod.bearer_token,
                encrypted_credentials=encrypt_credentials(json.dumps({"bot_token": BOT})),
                granted_scopes=list(scopes),
                rate_limit_per_minute=30,
            )
        )
        await session.commit()


def test_catalog_and_build_tools_label_slack_tools():
    assert "slack" in CONNECTOR_CATALOG
    specs = {spec.action: spec for spec in CONNECTOR_CATALOG["slack"]}
    assert {a for a, s in specs.items() if s.starter} == {
        "list_channels",
        "get_history",
        "list_users",
    }
    granted = (
        "channels.read",
        "messages.read",
        "messages.send",
        "reactions.write",
        "messages.write",
        "channels.write",
    )
    tools = {
        t.name: t
        for t in build_tools(
            [ConnectorSpec("slack", granted_scopes=granted, permission_tier="auto_approve")],
            user_default_tier="auto_approve",
            include_builtins=False,
        )
    }
    # Always-confirm actions stay on an approval card even under auto-approve.
    for name in ("post_message", "delete_message", "archive_channel"):
        assert tools[f"slack.{name}"].permission_tier == "approval"
    assert tools["slack.list_channels"].permission_tier == "auto"
    assert tools["slack.add_reaction"].permission_tier == "auto"
    # Scopes that were not granted are not offered.
    assert "slack.search_messages" not in tools and "slack.set_status" not in tools
    assert tools["slack.list_channels"].starter is True
    assert tools["slack.get_thread"].starter is False


@pytest.mark.asyncio
async def test_runtime_permission_adapter_decisions():
    adapter = RuntimePermissionAdapter()
    assert await adapter.check("u1", "slack.list_channels", {}) == "approved"
    for name in (
        "post_message",
        "reply_in_thread",
        "upload_file",
        "schedule_message",
        "delete_message",
        "archive_channel",
    ):
        assert await adapter.check("u1", f"slack.{name}", {}) == "requires_approval"


@pytest.mark.asyncio
async def test_executor_runs_a_read_through_the_real_factory(session_factory, slack_http):
    from tests.conftest import make_user

    seen, built = slack_http
    user, _ = await make_user(session_factory)
    await _slack_row(session_factory, user.id, ("channels.read",))
    executor = ConnectorToolExecutor(session_factory=session_factory)

    result = await executor.execute("slack.list_channels", {"limit": 5}, str(user.id))

    assert result["ok"] is True, result
    assert result["connector"] == "slack" and result["action"] == "list_channels"
    assert result["result"] == {
        "items": [{"id": "C0123ABCD", "name": "general", "is_member": True}],
        "count": 1,
    }
    assert {"sanitized", "execution_time_ms"} <= set(result)
    (request,) = seen
    assert request.url.host == "slack.com" and request.url.path == "/api/conversations.list"
    assert request.headers["Authorization"] == f"Bearer {BOT}"
    assert built[0]._network_policy_key == "slack"
    assert BOT not in json.dumps(result)


@pytest.mark.asyncio
async def test_executor_refuses_then_runs_an_always_confirm_post(session_factory, slack_http):
    from tests.conftest import make_user

    seen, _ = slack_http
    user, _ = await make_user(session_factory)
    await _slack_row(session_factory, user.id, ("messages.send",))
    executor = ConnectorToolExecutor(session_factory=session_factory)
    args = {
        "channel": "C0123ABCD",
        "text": "Ship it https://intranet.example/x",
        "user_confirmed": True,
    }  # smuggled flag is stripped by the executor

    refused = await executor.execute("slack.post_message", args, str(user.id))
    assert refused["ok"] is False and refused["requires_approval"] is True
    assert "always needs your approval" in refused["error"]
    assert seen == []

    approved = await executor.execute("slack.post_message", args, str(user.id), approved=True)
    assert approved["ok"] is True, approved
    assert approved["connector"] == "slack" and approved["action"] == "post_message"
    assert approved["result"] == {"channel": "C0123ABCD", "ts": "9.9", "posted": True}
    (request,) = seen
    assert request.url.path == "/api/chat.postMessage"
    body = json.loads(request.content)
    assert body["unfurl_links"] is False and body["unfurl_media"] is False


@pytest.mark.asyncio
async def test_executor_refuses_a_tool_whose_scope_was_not_granted(session_factory, slack_http):
    from tests.conftest import make_user

    seen, _ = slack_http
    user, _ = await make_user(session_factory)
    await _slack_row(session_factory, user.id, ("channels.read",))
    executor = ConnectorToolExecutor(session_factory=session_factory)
    result = await executor.execute(
        "slack.delete_message",
        {"channel": "C0123ABCD", "ts": "1.2"},
        str(user.id),
        approved=True,
    )
    assert result["ok"] is False
    assert seen == []
