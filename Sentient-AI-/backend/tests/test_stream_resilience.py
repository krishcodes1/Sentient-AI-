"""Streaming resilience and audit-ordering hardening.

Covers the production fixes for:
- Client disconnect mid-SSE: the chat turn's completed side effects must
  still be persisted (on_orphaned at the runtime level, the detached
  session fallback at the route level).
- Heartbeats during silent stretches, so proxies never time the stream out.
- Audit ordering: intent is recorded fail-closed BEFORE a tool executes;
  post-execution audit failures never fail a turn whose side effect
  already happened.
- The per-user provider cache is bounded.
"""

from __future__ import annotations

import asyncio

import pytest
from sqlalchemy import select

from core.config import settings
from services.agent.approvals import InMemoryApprovalStore
from services.agent.providers import LLMResponse, ToolCall
from services.agent.runtime import AgentRuntime
from services.agent.tool_registry import (
    ConnectorSpec,
    RuntimePermissionAdapter,
    build_tools,
)
from tests.test_streaming import (
    RecordingAudit,
    RecordingExecutor,
    ScriptedProvider,
    _auth,
    _runtime,
)


class SlowProvider(ScriptedProvider):
    """ScriptedProvider that stalls before answering, leaving a window in
    which the test can disconnect (or heartbeats can fire)."""

    def __init__(self, responses, delay: float):
        super().__init__(responses)
        self._delay = delay

    async def complete(self, messages, tools=None):
        await asyncio.sleep(self._delay)
        return await super().complete(messages, tools)


class FailingAudit(RecordingAudit):
    """Audit service that raises on selected event types."""

    def __init__(self, fail_events: set[str]):
        super().__init__()
        self._fail_events = fail_events

    async def log(self, entry):
        if entry.get("event") in self._fail_events:
            raise ConnectionError("audit store unavailable")
        await super().log(entry)


# ---------------------------------------------------------------------------
# Disconnect handling
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_orphaned_stream_invokes_on_orphaned_with_result():
    """Closing the stream generator mid-turn must not lose the turn: the
    chat task keeps running and on_orphaned receives its response."""
    orphaned: asyncio.Queue = asyncio.Queue()

    async def on_orphaned(response):
        await orphaned.put(response)

    runtime = _runtime(SlowProvider([LLMResponse(content="Slow answer.")], 0.3))
    agen = runtime.stream_chat(
        messages=[{"role": "user", "content": "hi"}],
        tools=[],
        user_id="u1",
        on_orphaned=on_orphaned,
    )

    events: list = []

    async def consume():
        async for event in agen:
            events.append(event)

    # Cancel the consumer mid-drain — exactly what Starlette does to the
    # response generator when the client disconnects.
    consumer = asyncio.create_task(consume())
    await asyncio.sleep(0.1)
    assert events and events[0]["type"] == "start"
    consumer.cancel()
    await asyncio.gather(consumer, return_exceptions=True)

    response = await asyncio.wait_for(orphaned.get(), timeout=5.0)
    assert response.content == "Slow answer."


@pytest.mark.asyncio
async def test_completed_stream_does_not_invoke_on_orphaned():
    calls: list = []

    async def on_orphaned(response):
        calls.append(response)

    runtime = _runtime(ScriptedProvider([LLMResponse(content="Done.")]))
    events = [
        e
        async for e in runtime.stream_chat(
            messages=[{"role": "user", "content": "hi"}],
            tools=[],
            user_id="u1",
            on_orphaned=on_orphaned,
        )
    ]
    assert events[-1]["type"] == "done"
    await asyncio.sleep(0.05)  # give any stray callback a chance to fire
    assert calls == []


@pytest.mark.asyncio
async def test_disconnect_while_sending_done_persists_the_turn_once():
    """The consumer received ``done`` and then dropped before it finished
    handling it (the route was still sending the frame to the client).

    From the moment ``done`` is handed over the consumer owns persistence —
    the route saves it from its own finally — so on_orphaned must NOT also
    fire. When it did, the same turn was written twice and its tokens were
    counted twice.
    """
    orphaned: list = []
    consumer_persisted: list = []

    async def on_orphaned(response):
        orphaned.append(response.content)

    runtime = _runtime(ScriptedProvider([LLMResponse(content="Hi there.")]))
    agen = runtime.stream_chat(
        messages=[{"role": "user", "content": "hi"}],
        tools=[],
        user_id="u1",
        on_orphaned=on_orphaned,
    )
    got_done = asyncio.Event()

    async def route_like():
        # Mirrors api/routes/agent.py event_stream: remember done, persist
        # from finally when the saved frame never went out.
        turn_done = saved = False
        try:
            async for event in agen:
                if event["type"] == "done":
                    turn_done = True
                    got_done.set()
                    await asyncio.sleep(10)  # stuck writing the frame
            saved = True
        finally:
            if turn_done and not saved:
                consumer_persisted.append(True)
            await agen.aclose()

    consumer = asyncio.create_task(route_like())
    await asyncio.wait_for(got_done.wait(), timeout=5.0)
    consumer.cancel()
    await asyncio.gather(consumer, return_exceptions=True)
    for _ in range(10):
        await asyncio.sleep(0.02)  # let any stray orphan callback run

    assert consumer_persisted == [True]
    assert orphaned == []


@pytest.mark.asyncio
async def test_stream_disconnect_persists_turn_via_detached_session(
    client, session_factory, monkeypatch
):
    """HTTP-level: a client that aborts the SSE stream mid-turn still gets
    the assistant message persisted (via the detached session fallback)."""
    from api.routes import agent as agent_routes
    from main import app
    from models.conversation import Message, MessageRole

    monkeypatch.setattr(agent_routes, "_detached_session_factory", session_factory)

    runtime = _runtime(SlowProvider([LLMResponse(content="Survived the drop.")], 0.4))
    app.dependency_overrides[agent_routes.get_runtime] = lambda: runtime
    try:
        headers = await _auth(client, "dropper@example.com")
        conv = await client.post(
            "/api/agent/conversations", json={"title": "D"}, headers=headers
        )
        conv_id = conv.json()["id"]

        # Open the stream and abandon it after the first frame.
        try:
            async with client.stream(
                "POST",
                f"/api/agent/conversations/{conv_id}/messages/stream",
                json={"content": "hello"},
                headers=headers,
            ) as resp:
                assert resp.status_code == 200
                async for _chunk in resp.aiter_text():
                    break  # got the first frame; now vanish
        except Exception:
            # Some transports surface the abort as an error; the assertion
            # below is what matters.
            pass

        # The turn finishes in the background and must be persisted.
        saved = None
        for _ in range(60):
            await asyncio.sleep(0.1)
            async with session_factory() as session:
                result = await session.execute(
                    select(Message).where(
                        Message.role == MessageRole.assistant,
                        Message.content == "Survived the drop.",
                    )
                )
                saved = result.scalar_one_or_none()
            if saved is not None:
                break
        assert saved is not None, "assistant turn was lost on client disconnect"
    finally:
        app.dependency_overrides.pop(agent_routes.get_runtime, None)


# ---------------------------------------------------------------------------
# Heartbeats
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_stream_emits_ping_during_silence():
    runtime = _runtime(SlowProvider([LLMResponse(content="Finally.")], 1.0))
    runtime._HEARTBEAT_SECONDS = 0.3
    events = [
        e
        async for e in runtime.stream_chat(
            messages=[{"role": "user", "content": "hi"}], tools=[], user_id="u1"
        )
    ]
    types = [e["type"] for e in events]
    assert "ping" in types
    assert types[-1] == "done"


# ---------------------------------------------------------------------------
# Audit ordering
# ---------------------------------------------------------------------------


def _tool_turn_provider():
    return ScriptedProvider(
        [
            LLMResponse(
                content="",
                tool_calls=[ToolCall(id="t1", name="canvas.get_courses", arguments={})],
            ),
            LLMResponse(content="Here are your courses."),
        ]
    )


@pytest.mark.asyncio
async def test_intent_is_audited_before_execution():
    executor = RecordingExecutor()
    runtime = _runtime(_tool_turn_provider(), executor=executor)
    audit = runtime._audit
    await runtime.chat(
        messages=[{"role": "user", "content": "my courses?"}],
        tools=build_tools([ConnectorSpec("canvas")]),
        user_id="u1",
    )
    events = [e["event"] for e in audit.entries]
    assert "tool_executing" in events
    assert "tool_executed" in events
    assert events.index("tool_executing") < events.index("tool_executed")
    assert len(executor.calls) == 1


@pytest.mark.asyncio
async def test_audit_failure_refuses_execution_fail_closed():
    executor = RecordingExecutor()
    runtime = _runtime(_tool_turn_provider(), executor=executor)
    runtime._audit = FailingAudit({"tool_executing"})
    response = await runtime.chat(
        messages=[{"role": "user", "content": "my courses?"}],
        tools=build_tools([ConnectorSpec("canvas")]),
        user_id="u1",
    )
    assert executor.calls == []  # the tool must NOT run unaudited
    assert any(b.policy == "audit_required" for b in response.blocked_actions)


@pytest.mark.asyncio
async def test_post_execution_audit_failure_does_not_fail_turn():
    executor = RecordingExecutor()
    runtime = _runtime(_tool_turn_provider(), executor=executor)
    runtime._audit = FailingAudit({"tool_executed"})
    response = await runtime.chat(
        messages=[{"role": "user", "content": "my courses?"}],
        tools=build_tools([ConnectorSpec("canvas")]),
        user_id="u1",
    )
    # The side effect happened; the turn must complete and carry the result.
    assert len(executor.calls) == 1
    assert response.content
    assert response.tool_calls


@pytest.mark.asyncio
async def test_approve_action_audit_failure_skips_execution():
    executor = RecordingExecutor()
    runtime = _runtime(ScriptedProvider([]), executor=executor)
    runtime._audit = FailingAudit({"tool_approved"})
    stored = await runtime._approvals.create(
        user_id="u1",
        tool_name="google_workspace.send_email",
        arguments={"to": "a@b.c"},
        reason="test",
        conversation_id=None,
        ttl_minutes=5,
    )
    result = await runtime.approve_action(stored.action_id, "u1")
    assert "error" in result
    assert executor.calls == []  # approved but unauditable -> not executed


# ---------------------------------------------------------------------------
# Provider cache bound
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_provider_cache_is_bounded():
    runtime = AgentRuntime(
        config=settings,
        permission_engine=RuntimePermissionAdapter(),
        tool_executor=RecordingExecutor(),
        audit_service=RecordingAudit(),
        approval_store=InMemoryApprovalStore(),
    )
    for i in range(runtime._PROVIDER_CACHE_MAX + 8):
        runtime._resolve_provider("ollama", f"model-{i}")
    assert len(runtime._provider_cache) == runtime._PROVIDER_CACHE_MAX
    # Let the eviction close() tasks run before the loop closes.
    await asyncio.sleep(0.05)
