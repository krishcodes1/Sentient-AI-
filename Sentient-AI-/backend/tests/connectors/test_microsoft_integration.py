"""Pipeline tests for the Microsoft 365 connector: the offered tools, the
runtime permission decision and the real executor, with only the HTTP
transport replaced.

Why it exists: the unit tests call connector methods directly; these prove
that a stored ``microsoft`` connector row flows through ``build_tools``
(starter and always-confirm labelling), ``RuntimePermissionAdapter`` and
``ConnectorToolExecutor.execute`` (real factory, real network-policy hook,
credential decryption, confirmation handling) and yields the normalized
result shape ``{ok, connector, action, result, ...}``.
Connects to ``services/agent/tool_registry.py``, ``services/connectors/factory.py``
and ``services/connectors/microsoft.py``. No real network: the connector's
client is an ``httpx.MockTransport`` and ``check_ssrf`` is stubbed.
"""

from __future__ import annotations

import json
from typing import Any

import httpx
import pytest

import core.network_security as netsec
from services.agent.tool_registry import (
    CONNECTOR_CATALOG,
    ConnectorSpec,
    ConnectorToolExecutor,
    RuntimePermissionAdapter,
    build_tools,
)

TOKEN = "EwB-integration-test-token"  # obviously fake
PUBLIC_IP = "20.190.151.68"


@pytest.fixture
def graph(monkeypatch) -> dict[str, Any]:
    """Route every connector the real factory builds to a mock Graph.

    The real ``create_connector`` runs (credential validation, policy
    arming); only the client is swapped, and it keeps the connector's own
    network-policy hook so the allowlist still decides.
    """
    import services.connectors.factory as factory_module

    monkeypatch.setattr(
        netsec,
        "check_ssrf",
        lambda url: netsec.SSRFCheckResult(safe=True, resolved_ip=PUBLIC_IP, resolved_ips=(PUBLIC_IP,)),
    )
    state: dict[str, Any] = {"requests": [], "created": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        state["requests"].append(request)
        if request.method == "DELETE":
            return httpx.Response(204)
        return httpx.Response(
            200,
            json={
                "value": [
                    {
                        "id": "m1",
                        "subject": "Invoice",
                        "from": {"emailAddress": {"address": "ann@contoso.com"}},
                        "bodyPreview": "Please pay",
                    }
                ]
            },
        )

    real_create = factory_module.create_connector

    def create(connector_type, credentials, **kwargs):
        connector = real_create(connector_type, credentials, **kwargs)
        state["created"] += 1
        connector._http_client = httpx.AsyncClient(
            transport=httpx.MockTransport(handler),
            event_hooks={"request": [connector._enforce_network_policy]},
        )
        return connector

    monkeypatch.setattr(factory_module, "create_connector", create)
    return state


async def _microsoft_row(session_factory, user_id, *, scopes: list[str]) -> None:
    from core.security import encrypt_credentials
    from models.connector import AuthMethod, ConnectorConfig

    credentials = {
        "access_token": TOKEN,
        "refresh_token": "refresh-test-token",
        "expires_at": 4_102_444_800,  # 2100: never due for a refresh here
        "token_type": "Bearer",
        "granted_scopes": ["Mail.Read", "Mail.ReadWrite"],
        "oauth_provider": "microsoft",
    }
    async with session_factory() as session:
        session.add(
            ConnectorConfig(
                user_id=user_id,
                connector_type="microsoft",
                display_name="Work Outlook",
                auth_method=AuthMethod.oauth2,
                encrypted_credentials=encrypt_credentials(json.dumps(credentials)),
                granted_scopes=scopes,
                rate_limit_per_minute=30,
            )
        )
        await session.commit()


def test_catalog_and_offered_tools_carry_starter_and_always_confirm():
    specs = {spec.action: spec for spec in CONNECTOR_CATALOG["microsoft"]}
    assert specs["list_messages"].starter and specs["delete_message"].always_confirm

    tools = build_tools(
        [
            ConnectorSpec(
                "microsoft",
                granted_scopes=("mail.read", "mail.write", "mail.send"),
                permission_tier="auto_approve",
            )
        ],
        user_default_tier="auto_approve",
        include_builtins=False,
    )
    by_name = {tool.name: tool for tool in tools}
    assert all(name.startswith("microsoft.") for name in by_name)
    # Only the granted areas are offered.
    assert "microsoft.list_events" not in by_name and "microsoft.search_files" not in by_name
    assert by_name["microsoft.list_messages"].permission_tier == "auto"
    assert by_name["microsoft.list_messages"].starter is True
    assert by_name["microsoft.get_message"].starter is False
    # auto_approve relabels an ordinary write, never an always-confirm one.
    assert by_name["microsoft.create_draft"].permission_tier == "auto"
    for name in ("send_mail", "reply", "forward", "delete_message"):
        assert by_name[f"microsoft.{name}"].permission_tier == "approval", name


@pytest.mark.asyncio
async def test_runtime_permission_adapter_decisions():
    adapter = RuntimePermissionAdapter()
    assert await adapter.check("u", "microsoft.list_messages", {}) == "approved"
    assert await adapter.check("u", "microsoft.create_event", {}) == "requires_approval"
    assert await adapter.check("u", "microsoft.delete_message", {}) == "requires_approval"
    assert await adapter.check("u", "microsoft.send_mail", {}) == "requires_approval"
    assert await adapter.check("u", "microsoft.no_such_action", {}) == "blocked"


@pytest.mark.asyncio
async def test_executor_runs_a_read_through_the_real_factory(session_factory, graph):
    from tests.conftest import make_user

    user, _ = await make_user(session_factory)
    await _microsoft_row(session_factory, user.id, scopes=["mail.read"])
    executor = ConnectorToolExecutor(session_factory=session_factory)

    result = await executor.execute("microsoft.list_messages", {"limit": 2}, str(user.id))

    assert result["ok"] is True, result
    assert result["connector"] == "microsoft"
    assert result["action"] == "list_messages"
    assert result["result"]["count"] == 1
    assert result["result"]["items"][0]["subject"] == "Invoice"
    assert {"sanitized", "execution_time_ms"} <= set(result)
    (request,) = graph["requests"]
    assert request.url.host == "graph.microsoft.com"
    assert request.url.raw_path.startswith(b"/v1.0/me/mailFolders/inbox/messages?")
    assert request.url.params["$top"] == "2"
    assert request.headers["Authorization"] == f"Bearer {TOKEN}"
    assert TOKEN not in json.dumps(result)


@pytest.mark.asyncio
async def test_executor_refuses_an_ungranted_scope(session_factory, graph):
    from tests.conftest import make_user

    user, _ = await make_user(session_factory)
    await _microsoft_row(session_factory, user.id, scopes=["mail.read"])
    executor = ConnectorToolExecutor(session_factory=session_factory)

    result = await executor.execute("microsoft.delete_message", {"message_id": "m1"}, str(user.id), approved=True)

    assert result["ok"] is False
    # The refusal comes from the scope check (not a lookup, decryption or
    # approval failure): it names the missing scope and asks for no approval.
    assert "'mail.write' has not been granted" in result["error"]
    assert not result.get("requires_approval")
    assert graph["requests"] == [] and graph["created"] == 0


@pytest.mark.asyncio
async def test_executor_always_confirm_refused_unapproved_and_run_approved(session_factory, graph):
    from tests.conftest import make_user

    user, _ = await make_user(session_factory)
    await _microsoft_row(session_factory, user.id, scopes=["mail.read", "mail.write"])
    executor = ConnectorToolExecutor(session_factory=session_factory)

    refused = await executor.execute(
        "microsoft.delete_message", {"message_id": "m1", "user_confirmed": True}, str(user.id)
    )
    assert refused["ok"] is False
    assert refused["requires_approval"] is True
    assert graph["requests"] == [] and graph["created"] == 0

    done = await executor.execute(
        "microsoft.delete_message", {"message_id": "m/1"}, str(user.id), approved=True
    )
    assert done["ok"] is True, done
    assert done["connector"] == "microsoft" and done["action"] == "delete_message"
    assert done["result"] == {"deleted": True, "id": "m/1"}
    (request,) = graph["requests"]
    assert request.method == "DELETE"
    assert request.url.raw_path == b"/v1.0/me/messages/m%2F1"
