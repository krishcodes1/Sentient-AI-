"""Approval-flow tests: DB persistence, ownership, single-use, expiry,
concurrency (double-execute race), and the runtime's approve/deny
behavior including the ``approved=True`` hand-off to the executor.
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone

import pytest

from services.agent.approvals import DbApprovalStore, InMemoryApprovalStore


@pytest.mark.asyncio
async def test_db_store_create_list_decide(session_factory):
    from tests.conftest import make_user

    user, _ = await make_user(session_factory)
    store = DbApprovalStore(session_factory=session_factory)

    action = await store.create(
        user_id=str(user.id),
        tool_name="google_workspace.send_email",
        arguments={"to": "x@y.com", "subject": "hi", "body": "test"},
        reason="needs approval",
        ttl_minutes=15,
    )
    assert action.expires_at is not None

    pending = await store.list_pending(str(user.id))
    assert [p.action_id for p in pending] == [action.action_id]

    outcome, decided = await store.decide(action.action_id, str(user.id), approved=True)
    assert outcome == "ok"
    assert decided is not None
    assert decided.tool_name == "google_workspace.send_email"

    # Single use: a decided action cannot be decided again.
    outcome, _ = await store.decide(action.action_id, str(user.id), approved=True)
    assert outcome == "not_found"
    assert await store.list_pending(str(user.id)) == []


@pytest.mark.asyncio
async def test_db_store_enforces_ownership(session_factory):
    from tests.conftest import make_user

    user_a, _ = await make_user(session_factory, "a@example.com")
    user_b, _ = await make_user(session_factory, "b@example.com")
    store = DbApprovalStore(session_factory=session_factory)

    action = await store.create(
        user_id=str(user_a.id),
        tool_name="canvas.submit_assignment",
        arguments={},
        reason="needs approval",
    )

    # B cannot approve A's action — and the attempt does not consume it.
    outcome, _ = await store.decide(action.action_id, str(user_b.id), approved=True)
    assert outcome == "not_found"
    assert len(await store.list_pending(str(user_a.id))) == 1


@pytest.mark.asyncio
async def test_db_store_expires_actions(session_factory):
    from tests.conftest import make_user

    user, _ = await make_user(session_factory)
    store = DbApprovalStore(session_factory=session_factory)

    action = await store.create(
        user_id=str(user.id),
        tool_name="google_workspace.send_email",
        arguments={},
        reason="needs approval",
        ttl_minutes=0,  # expires immediately
    )

    assert await store.list_pending(str(user.id)) == []
    outcome, _ = await store.decide(action.action_id, str(user.id), approved=True)
    # list_pending already flipped it to expired; deciding an expired
    # action must never succeed, whichever path marked it first.
    assert outcome in ("expired", "not_found")


@pytest.mark.asyncio
async def test_db_store_decide_is_single_use_under_concurrency(session_factory):
    """Two (or more) simultaneous decisions on the same pending action must
    yield exactly one 'ok' — the conditional UPDATE + FOR UPDATE lock in
    DbApprovalStore.decide closes the double-execute race."""
    from tests.conftest import make_user

    user, _ = await make_user(session_factory)
    store = DbApprovalStore(session_factory=session_factory)

    action = await store.create(
        user_id=str(user.id),
        tool_name="google_workspace.send_email",
        arguments={"to": "x@y.com", "subject": "s", "body": "b"},
        reason="needs approval",
    )

    outcomes = await asyncio.gather(
        *[
            store.decide(action.action_id, str(user.id), approved=(i % 2 == 0))
            for i in range(8)
        ]
    )
    oks = [o for o, _ in outcomes if o == "ok"]
    assert len(oks) == 1
    assert all(o in ("ok", "not_found") for o, _ in outcomes)


@pytest.mark.asyncio
async def test_memory_store_expiry_and_ownership():
    store = InMemoryApprovalStore()
    action = await store.create(
        user_id="user-1",
        tool_name="t.a",
        arguments={},
        reason="r",
        ttl_minutes=0,
    )
    assert await store.list_pending("user-1") == []
    outcome, _ = await store.decide(action.action_id, "user-1", approved=True)
    assert outcome in ("expired", "not_found")

    live = await store.create(
        user_id="user-1", tool_name="t.a", arguments={}, reason="r"
    )
    outcome, _ = await store.decide(live.action_id, "someone-else", approved=True)
    assert outcome == "not_found"


# ---------------------------------------------------------------------------
# Runtime integration
# ---------------------------------------------------------------------------


class FakeProvider:
    """LLM stand-in: first call requests a tool, follow-up returns text."""

    def __init__(self, tool_calls):
        self._tool_calls = tool_calls
        self.calls = 0

    async def complete(self, messages, tools=None):
        from services.agent.providers import LLMResponse

        self.calls += 1
        if self.calls == 1:
            return LLMResponse(content="working on it", tool_calls=self._tool_calls)
        return LLMResponse(content="done")

    async def stream(self, messages, tools=None):
        yield "done"


class RecordingExecutor:
    def __init__(self):
        self.calls = []

    async def execute(self, tool_name, arguments, user_id, approved=False):
        self.calls.append(
            {"tool": tool_name, "arguments": arguments, "approved": approved}
        )
        return {"ok": True, "result": "executed"}


class RecordingAudit:
    def __init__(self):
        self.entries = []

    async def log(self, entry):
        self.entries.append(entry)


def _build_runtime(session_factory, tool_calls):
    from core.config import settings
    from services.agent.runtime import AgentRuntime
    from services.agent.tool_registry import RuntimePermissionAdapter

    executor = RecordingExecutor()
    audit = RecordingAudit()
    runtime = AgentRuntime(
        config=settings,
        permission_engine=RuntimePermissionAdapter(),
        tool_executor=executor,
        audit_service=audit,
        approval_store=DbApprovalStore(session_factory=session_factory),
    )
    runtime._provider = FakeProvider(tool_calls)
    return runtime, executor, audit


@pytest.mark.asyncio
async def test_runtime_parks_write_action_and_executes_on_approval(session_factory):
    from services.agent.providers import ToolCall
    from services.agent.tool_registry import ConnectorSpec, build_tools
    from tests.conftest import make_user

    user, _ = await make_user(session_factory)
    runtime, executor, audit = _build_runtime(
        session_factory,
        [ToolCall(id="tc1", name="google_workspace.send_email",
                  arguments={"to": "x@y.com", "subject": "s", "body": "b"})],
    )
    tools = build_tools([ConnectorSpec("google_workspace")])

    response = await runtime.chat(
        messages=[{"role": "user", "content": "email x@y.com"}],
        tools=tools,
        user_id=str(user.id),
    )

    # Nothing executed yet; one pending approval persisted with expiry.
    assert executor.calls == []
    assert len(response.pending_approvals) == 1
    approval = response.pending_approvals[0]
    assert approval.expires_at is not None
    assert any(e["event"] == "tool_pending_approval" for e in audit.entries)

    # Survives a "restart": a fresh runtime sees the same pending action.
    runtime2, executor2, audit2 = _build_runtime(session_factory, [])
    pending = await runtime2.list_pending_approvals(str(user.id))
    assert [p.action_id for p in pending] == [approval.action_id]

    # Approval executes with approved=True (unlocks per-call confirmation)
    # and reports the originating conversation so the route can persist
    # the outcome into the transcript.
    result = await runtime2.approve_action(approval.action_id, str(user.id))
    assert result["tool"] == "google_workspace.send_email"
    assert "conversation_id" in result
    assert executor2.calls == [
        {
            "tool": "google_workspace.send_email",
            "arguments": {"to": "x@y.com", "subject": "s", "body": "b"},
            "approved": True,
        }
    ]
    assert any(e["event"] == "tool_approved_and_executed" for e in audit2.entries)

    # The action is consumed.
    again = await runtime2.approve_action(approval.action_id, str(user.id))
    assert "error" in again


@pytest.mark.asyncio
async def test_runtime_deny_drops_action_without_executing(session_factory):
    from services.agent.providers import ToolCall
    from services.agent.tool_registry import ConnectorSpec, build_tools
    from tests.conftest import make_user

    user, _ = await make_user(session_factory)
    runtime, executor, audit = _build_runtime(
        session_factory,
        [ToolCall(id="tc1", name="canvas.submit_assignment",
                  arguments={"course_id": "1", "assignment_id": "2",
                             "submission_data": {}})],
    )
    tools = build_tools([ConnectorSpec("canvas")])

    response = await runtime.chat(
        messages=[{"role": "user", "content": "submit my work"}],
        tools=tools,
        user_id=str(user.id),
    )
    approval = response.pending_approvals[0]

    result = await runtime.deny_action(approval.action_id, str(user.id))
    assert result["denied"] is True
    assert result["action_id"] == approval.action_id
    assert result["tool"] == "canvas.submit_assignment"
    assert executor.calls == []
    assert any(e["event"] == "tool_denied" for e in audit.entries)


@pytest.mark.asyncio
async def test_runtime_approval_rejects_foreign_user(session_factory):
    from services.agent.providers import ToolCall
    from services.agent.tool_registry import ConnectorSpec, build_tools
    from tests.conftest import make_user

    user_a, _ = await make_user(session_factory, "a@example.com")
    user_b, _ = await make_user(session_factory, "b@example.com")
    runtime, executor, _ = _build_runtime(
        session_factory,
        [ToolCall(id="tc1", name="google_workspace.send_email",
                  arguments={"to": "x@y.com", "subject": "s", "body": "b"})],
    )
    tools = build_tools([ConnectorSpec("google_workspace")])
    response = await runtime.chat(
        messages=[{"role": "user", "content": "email"}],
        tools=tools,
        user_id=str(user_a.id),
    )
    approval = response.pending_approvals[0]

    result = await runtime.approve_action(approval.action_id, str(user_b.id))
    assert "error" in result
    assert executor.calls == []


@pytest.mark.asyncio
async def test_runtime_injects_system_prompt_and_wraps_tool_results(session_factory):
    """The first provider call must carry the security system prompt; the
    follow-up call must wrap tool output in the untrusted-data envelope
    as a user-role message (never role='tool', which Anthropic rejects)."""
    from services.agent.providers import ToolCall
    from services.agent.runtime import SECURITY_SYSTEM_PROMPT
    from services.agent.tool_registry import ConnectorSpec, build_tools
    from tests.conftest import make_user

    user, _ = await make_user(session_factory)

    seen_messages = []

    class InspectingProvider(FakeProvider):
        async def complete(self, messages, tools=None):
            seen_messages.append(list(messages))
            return await super().complete(messages, tools)

    runtime, executor, _ = _build_runtime(
        session_factory,
        [ToolCall(id="tc1", name="canvas.get_courses", arguments={})],
    )
    runtime._provider = InspectingProvider(
        [ToolCall(id="tc1", name="canvas.get_courses", arguments={})]
    )
    tools = build_tools([ConnectorSpec("canvas")])

    response = await runtime.chat(
        messages=[{"role": "user", "content": "what are my courses?"}],
        tools=tools,
        user_id=str(user.id),
    )

    assert response.content == "done"
    assert executor.calls[0]["approved"] is False

    first_call, follow_up_call = seen_messages
    assert first_call[0]["role"] == "system"
    assert first_call[0]["content"] == SECURITY_SYSTEM_PROMPT

    roles = [m["role"] for m in follow_up_call]
    assert "tool" not in roles
    envelope = follow_up_call[-1]
    assert envelope["role"] == "user"
    assert 'trust="untrusted"' in envelope["content"]
    assert "canvas.get_courses" in envelope["content"]


@pytest.mark.asyncio
async def test_auto_approve_tier_executes_write_without_parking(session_factory):
    """A connector whose effective tier is auto_approve (connector AND user
    default) runs write tools immediately with approved=True — no pending
    action is created. Financial tools stay impossible: they are never in
    the offered list and the permission adapter blocks them regardless."""
    from services.agent.providers import ToolCall
    from services.agent.tool_registry import ConnectorSpec, build_tools
    from tests.conftest import make_user

    user, _ = await make_user(session_factory)
    runtime, executor, audit = _build_runtime(
        session_factory,
        [ToolCall(id="tc1", name="google_workspace.send_email",
                  arguments={"to": "x@y.com", "subject": "s", "body": "b"})],
    )
    tools = build_tools(
        [ConnectorSpec("google_workspace", permission_tier="auto_approve")],
        user_default_tier="auto_approve",
    )

    response = await runtime.chat(
        messages=[{"role": "user", "content": "email x@y.com"}],
        tools=tools,
        user_id=str(user.id),
    )

    assert response.pending_approvals == []
    assert executor.calls == [
        {
            "tool": "google_workspace.send_email",
            "arguments": {"to": "x@y.com", "subject": "s", "body": "b"},
            "approved": True,
        }
    ]
    assert any(e["event"] == "tool_executed" for e in audit.entries)


@pytest.mark.asyncio
async def test_auto_approve_tier_never_unlocks_financial_tools(session_factory):
    """Even if a financial tool call is requested under an auto_approve
    connector, the permission adapter hard-blocks it (4-layer block)."""
    from services.agent.providers import ToolCall
    from services.agent.tool_registry import ConnectorSpec, build_tools
    from tests.conftest import make_user

    user, _ = await make_user(session_factory)
    runtime, executor, _ = _build_runtime(
        session_factory,
        [ToolCall(id="tc1", name="robinhood.execute_trade",
                  arguments={"symbol": "BTC", "side": "buy"})],
    )
    tools = build_tools(
        [ConnectorSpec("robinhood", permission_tier="auto_approve")],
        user_default_tier="auto_approve",
    )
    assert all(t.name != "robinhood.execute_trade" for t in tools)

    response = await runtime.chat(
        messages=[{"role": "user", "content": "buy bitcoin"}],
        tools=tools,
        user_id=str(user.id),
    )

    assert executor.calls == []
    assert any(
        b.tool_name == "robinhood.execute_trade" for b in response.blocked_actions
    )
