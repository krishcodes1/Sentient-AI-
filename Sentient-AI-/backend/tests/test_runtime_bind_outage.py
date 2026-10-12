"""Tests that a card whose facts cannot be read because storage is down is
the call's own error, never a security block: a goals.delete whose bind hits
a database error makes no card, emits no blocked event and adds no
BlockedAction; it is audited as tool_blocked under its rule, and the model
is told rule "storage" so it can say to try again.

Why it exists: every channel shows a blocked event as a security block, so
an ordinary outage while a card is bound must never reach the user as one
(runtime._PRECHECK_FAILURE_RULES). No model and no database: a scripted
provider and a session factory whose sessions fail to open.
"""

from __future__ import annotations

import uuid
from typing import Any

import pytest
from sqlalchemy.exc import OperationalError

from core.config import settings
from services.agent.approvals import InMemoryApprovalStore
from services.agent.providers import LLMResponse, ToolCall
from services.agent.runtime import AgentRuntime
from services.agent.tool_registry import (
    ConnectorToolExecutor,
    RuntimePermissionAdapter,
    build_tools,
)
from services.capabilities import REGISTRY, statuses_by_key
from services.capabilities import report as capability_report
from services.capabilities.base import ReportContext
from services.tools.goals import STORAGE_ERROR, GoalsToolkit
from tests.conftest import use_provider
from tests.test_agent_runtime_vision import RecordingAudit, RecordingProvider

USER = str(uuid.uuid4())
GOAL = str(uuid.uuid4())
_CTX = ReportContext(
    in_container=False, platform="win32", telegram_configured=False, browser_installed=False
)


class _DownSession:
    """A session that cannot be opened: the database is down."""

    async def __aenter__(self) -> _DownSession:
        raise OperationalError("SELECT", {}, Exception("database is down"))

    async def __aexit__(self, *exc: Any) -> bool:
        return False


async def _gate() -> Any:
    switches = {c.key: c.key == "goals" for c in REGISTRY}
    return statuses_by_key(capability_report(switches, _CTX, use_cache=False))


def _runtime(provider: RecordingProvider) -> tuple[AgentRuntime, RecordingAudit, Any]:
    executor = ConnectorToolExecutor(
        goals_toolkit=GoalsToolkit(lambda: _DownSession()), capability_gate=_gate
    )
    audit = RecordingAudit()
    store = InMemoryApprovalStore()
    runtime = AgentRuntime(
        config=settings,
        permission_engine=RuntimePermissionAdapter(capability_gate=_gate),
        tool_executor=executor,
        audit_service=audit,
        approval_store=store,
    )
    use_provider(runtime, provider)
    return runtime, audit, store


def _script() -> RecordingProvider:
    return RecordingProvider(
        [
            LLMResponse(
                content="",
                tool_calls=[ToolCall(id="t1", name="goals.delete", arguments={"goal_id": GOAL})],
            ),
            LLMResponse(content="Goal storage is down; try again shortly."),
        ]
    )


def _tools() -> list[Any]:
    return build_tools(
        [], enabled_capabilities=frozenset({"goals"}), user_default_tier="user_confirm"
    )


@pytest.mark.asyncio
async def test_a_storage_error_while_binding_a_card_is_never_a_security_block():
    provider = _script()
    runtime, audit, store = _runtime(provider)
    events = [
        event
        async for event in runtime.stream_chat(
            messages=[{"role": "user", "content": "Delete my 5k goal."}],
            tools=_tools(),
            user_id=USER,
        )
    ]
    kinds = [event["type"] for event in events]
    assert "blocked" not in kinds and "pending_approval" not in kinds
    assert kinds[-1] == "done"
    assert await store.list_pending(USER) == []
    # Audited as a refusal with its rule, which is how it is told apart.
    [row] = [e for e in audit.entries if e["event"] == "tool_blocked"]
    assert row["tool"] == "goals.delete" and row["rule"] == "storage"
    # The model is told the call's own error, to say "try again".
    shown = str(provider.calls[1]["messages"])
    assert STORAGE_ERROR in shown and "storage" in shown


@pytest.mark.asyncio
async def test_the_blocking_turn_adds_no_blocked_action_and_returns_the_rule():
    runtime, _audit, _store = _runtime(_script())
    response = await runtime.chat(
        messages=[{"role": "user", "content": "Delete my 5k goal."}],
        tools=_tools(),
        user_id=USER,
    )
    assert response.blocked_actions == [] and response.pending_approvals == []
    [call] = response.tool_calls
    assert call["result"]["rule"] == "storage" and call["result"]["ok"] is False
