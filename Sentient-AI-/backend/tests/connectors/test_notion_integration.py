"""End-to-end test of the Notion connector through the real agent pipeline.

Why it exists: the unit tests call NotionConnector directly; this file proves
the registry wiring holds. build_tools offers Notion's tools with the right
starter and approval labels, RuntimePermissionAdapter sends always-confirm
actions to the approval card, and ConnectorToolExecutor runs a READ and an
always-confirm action with the real factory (credentials decrypted from a
real connector row), refusing the latter until it is approved.
Connects to: services/agent/tool_registry.py (build_tools,
RuntimePermissionAdapter, ConnectorToolExecutor), services/connectors/
factory.py and registry.py, services/connectors/notion.py. Only the
connector's HTTP transport is replaced (httpx.MockTransport); no network.
"""

from __future__ import annotations

import json

import httpx
import pytest

from services.agent.tool_registry import (
    ConnectorSpec,
    ConnectorToolExecutor,
    RuntimePermissionAdapter,
    build_tools,
)

TOKEN = "ntn_test_fake_integration_secret_1111111111"  # obviously fake
DB = "2b3c4d5e6f704809a1b2c3d4e5f6a7b8"
PAGE = "1a2b3c4d5e6f47809a1b2c3d4e5f6a7b"
ALL_SCOPES = ("notion.read", "notion.write", "notion.comment", "notion.delete")


@pytest.fixture
def notion_http(monkeypatch) -> list[httpx.Request]:
    """Real factory, with the built connector's HTTP sent to a mock Notion."""
    import services.connectors.factory as factory_module

    real_create = factory_module.create_connector
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        if request.url.path == f"/v1/databases/{DB}":
            return httpx.Response(
                200,
                json={
                    "object": "database",
                    "id": DB,
                    "title": [{"type": "text", "plain_text": "Tasks"}],
                    "properties": {"Name": {"type": "title", "title": {}}},
                },
            )
        if request.url.path == f"/v1/pages/{PAGE}":
            return httpx.Response(200, json={"object": "page", "id": PAGE, "archived": True})
        return httpx.Response(404, json={"code": "object_not_found"})

    def create_with_mock_transport(connector_type, credentials, **kwargs):
        connector = real_create(connector_type, credentials, **kwargs)
        assert connector._network_policy_key == "notion"  # the factory armed the policy
        connector._http_client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
        return connector

    monkeypatch.setattr(factory_module, "create_connector", create_with_mock_transport)
    return seen


async def _notion_row(session_factory, user_id, scopes=ALL_SCOPES):
    from core.security import encrypt_credentials
    from models.connector import AuthMethod, ConnectorConfig

    async with session_factory() as session:
        row = ConnectorConfig(
            user_id=user_id,
            connector_type="notion",
            display_name="Work Notion",
            auth_method=AuthMethod.bearer_token,
            encrypted_credentials=encrypt_credentials(json.dumps({"access_token": TOKEN})),
            granted_scopes=list(scopes),
            rate_limit_per_minute=30,
        )
        session.add(row)
        await session.commit()


def test_build_tools_labels_notion_starters_and_always_confirm_actions():
    tools = {
        tool.name: tool
        for tool in build_tools(
            [ConnectorSpec("notion", granted_scopes=ALL_SCOPES)], include_builtins=False
        )
    }
    assert "notion.search" in tools and "notion.delete_block" in tools
    assert {name for name, tool in tools.items() if tool.starter} == {
        "notion.search",
        "notion.get_page",
        "notion.query_database",
    }
    assert tools["notion.get_page"].permission_tier == "auto"
    assert tools["notion.create_page"].permission_tier == "approval"
    assert tools["notion.add_comment"].permission_tier == "approval"
    assert tools["notion.archive_page"].permission_tier == "approval"


def test_auto_approve_tier_never_relabels_always_confirm_actions():
    tools = {
        tool.name: tool
        for tool in build_tools(
            [ConnectorSpec("notion", granted_scopes=ALL_SCOPES, permission_tier="auto_approve")],
            user_default_tier="auto_approve",
            include_builtins=False,
        )
    }
    assert tools["notion.create_page"].permission_tier == "auto"
    for name in ("notion.add_comment", "notion.archive_page", "notion.delete_block"):
        assert tools[name].permission_tier == "approval", name


def test_read_scope_only_offers_only_reads():
    tools = build_tools(
        [ConnectorSpec("notion", granted_scopes=("notion.read",))], include_builtins=False
    )
    names = {tool.name for tool in tools}
    assert "notion.get_page" in names
    assert not names & {"notion.create_page", "notion.add_comment", "notion.delete_block"}


@pytest.mark.asyncio
async def test_permission_adapter_decisions():
    adapter = RuntimePermissionAdapter()
    assert await adapter.check("u1", "notion.search", {}) == "approved"
    assert await adapter.check("u1", "notion.update_block", {}) == "requires_approval"
    for name in ("notion.add_comment", "notion.archive_page", "notion.delete_block"):
        assert await adapter.check("u1", name, {}) == "requires_approval", name


@pytest.mark.asyncio
async def test_executor_runs_a_read_through_the_real_factory(session_factory, notion_http):
    from tests.conftest import make_user

    user, _ = await make_user(session_factory)
    await _notion_row(session_factory, user.id)

    result = await ConnectorToolExecutor(session_factory=session_factory).execute(
        "notion.get_database", {"database_id": DB}, str(user.id)
    )

    assert result["ok"] is True, result
    assert result["connector"] == "notion"
    assert result["action"] == "get_database"
    assert result["result"] == {"id": DB, "title": "Tasks", "properties": {"Name": "title"}}
    (request,) = notion_http
    assert request.url.raw_path == f"/v1/databases/{DB}".encode()
    assert request.headers["Authorization"] == f"Bearer {TOKEN}"  # decrypted from the row
    assert request.headers["Notion-Version"] == "2022-06-28"
    assert TOKEN not in json.dumps(result)


@pytest.mark.asyncio
async def test_executor_refuses_unapproved_archive_and_runs_it_approved(
    session_factory, notion_http
):
    from tests.conftest import make_user

    user, _ = await make_user(session_factory)
    await _notion_row(session_factory, user.id)
    executor = ConnectorToolExecutor(session_factory=session_factory)

    # The model cannot approve its own call by smuggling user_confirmed.
    refused = await executor.execute(
        "notion.archive_page", {"page_id": PAGE, "user_confirmed": True}, str(user.id)
    )
    assert refused["ok"] is False
    assert refused["requires_approval"] is True
    assert notion_http == []

    approved = await executor.execute(
        "notion.archive_page", {"page_id": PAGE}, str(user.id), approved=True
    )
    assert approved["ok"] is True, approved
    assert approved["action"] == "archive_page"
    assert approved["result"] == {"id": PAGE, "archived": True}
    (request,) = notion_http
    assert (request.method, request.url.raw_path) == ("PATCH", f"/v1/pages/{PAGE}".encode())
    assert json.loads(request.content) == {"archived": True}


@pytest.mark.asyncio
async def test_executor_refuses_a_write_whose_scope_was_not_granted(session_factory, notion_http):
    from tests.conftest import make_user

    user, _ = await make_user(session_factory)
    await _notion_row(session_factory, user.id, scopes=("notion.read",))

    result = await ConnectorToolExecutor(session_factory=session_factory).execute(
        "notion.delete_block", {"block_id": PAGE}, str(user.id), approved=True
    )
    assert result["ok"] is False
    assert "notion.delete" in result["error"]
    assert notion_http == []
