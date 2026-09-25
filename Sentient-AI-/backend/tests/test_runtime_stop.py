"""Tests for stopping a running task: the runtime checks the user's stop
before every model round and before each tool call, ends the turn with a short
reply built from counts, audits the skipped calls and the stop, and keeps the
stream's done frame; POST /api/agent/stop records a stop for the signed-in user.

Why it exists: before this, only computer_control read the stop, so the web
Stop button or a Telegram /stop left a browsing, search or multi-tool turn
running to its end. These tests pin that a stop ends any turn at the next step
boundary, never in the middle of a started tool call, that it reaches every
channel as a normal reply, that a stop landing while a turn is still being set
up is kept, that one landing while a call is checked or a round ends is kept
too (no card is raised and no call started after it), that nothing the user
does later (a new message, an Approve tap on any card) un-stops a turn that is
still running, and how stops and approvals combine, as the runtime documents.
"""

from __future__ import annotations

import asyncio
import json
from typing import Any

import pytest

from core.config import settings
from services.agent import cancel
from services.agent.approvals import InMemoryApprovalStore
from services.agent.providers import LLMResponse, ToolCall
from services.agent.runtime import (
    USER_STOPPED_POLICY,
    USER_STOPPED_REASON,
    AgentRuntime,
    PermissionEngine,
    PromptGuard,
    Tool,
    stopped_reply,
)
from tests.conftest import auth_headers, make_user, use_provider
from tests.test_agent_runtime_vision import RecordingAudit, RecordingProvider

USER = "u-stop"
OTHER = "u-stop-other"

SEARCH = Tool(
    name="web.search",
    description="search",
    parameters={"type": "object", "properties": {}},
    connector_type="web",
)
FETCH = Tool(
    name="web.fetch_page",
    description="fetch",
    parameters={"type": "object", "properties": {}},
    connector_type="web",
)
SEND = Tool(
    name="google_workspace.send_email",
    description="send",
    parameters={"type": "object", "properties": {}},
    connector_type="google_workspace",
    permission_tier="approval",
)

ONE_RAN_ONE_SKIPPED = "Stopped. I didn't finish: 1 step was skipped. 1 step ran before the stop."


@pytest.fixture(autouse=True)
def flags():
    """User ids whose stop is forgotten before and after each test; tests
    with database users add theirs. Stops live in process memory, so one
    left behind would leak into later tests."""
    touched = {USER, OTHER}
    for uid in touched:
        cancel.clear(uid)
    yield touched
    for uid in touched:
        cancel.clear(uid)


class Gate(PermissionEngine):
    """Approves every call except the named ones, which need approval."""

    def __init__(self, gated: set[str] | None = None) -> None:
        self._gated = gated or set()

    async def check(self, user_id, tool_name, arguments):
        return "requires_approval" if tool_name in self._gated else "approved"


class StopDuring:
    """Executor that presses Stop while one named call is running, then lets
    that call finish: the stop arrives mid-call, as a real one would."""

    def __init__(self, stop_on: str | None = None) -> None:
        self.stop_on = stop_on
        self.calls: list[str] = []
        # Whether the flag was set when each call started.
        self.saw_stop: list[bool] = []

    async def execute(self, tool_name, arguments, user_id, approved=False, *, task_id=None):
        self.calls.append(tool_name)
        self.saw_stop.append(cancel.is_cancelled(user_id))
        if tool_name == self.stop_on:
            cancel.request_cancel(user_id)
            await asyncio.sleep(0)  # the call keeps running after the stop
        return {"ok": True, "result": f"{tool_name} finished"}


class StopOnInputScan(PromptGuard):
    """Presses Stop while the user's message is scanned: after the turn
    lifted the old flag, before its first model round."""

    def __init__(self) -> None:
        self._armed = True

    async def scan_input(self, content, user_id):
        if self._armed:
            self._armed = False
            cancel.request_cancel(user_id)
        return {"safe": True}


class Blocking:
    """Executor that holds web.search open until released, so a test can
    act (Stop, Approve, a new message) while a tool call is running."""

    def __init__(self) -> None:
        self.started = asyncio.Event()
        self.release = asyncio.Event()
        self.calls: list[str] = []

    async def execute(self, tool_name, arguments, user_id, approved=False, *, task_id=None):
        self.calls.append(tool_name)
        if tool_name == "web.search":
            self.started.set()
            await self.release.wait()
        return {"ok": True}


def calls(*names: str) -> LLMResponse:
    return LLMResponse(
        content="Working on it.",
        tool_calls=[
            ToolCall(id=f"c{i}", name=name, arguments={"q": name}) for i, name in enumerate(names)
        ],
    )


def runtime_with(
    provider: Any,
    executor: Any = None,
    *,
    guard: PromptGuard | None = None,
    gated: set[str] | None = None,
    audit: Any = None,
    store: Any = None,
) -> AgentRuntime:
    runtime = AgentRuntime(
        config=settings,
        permission_engine=Gate(gated),
        prompt_guard=guard or PromptGuard(),
        audit_service=audit or RecordingAudit(),
        approval_store=store or InMemoryApprovalStore(),
        tool_executor=executor or StopDuring(),
    )
    use_provider(runtime, provider)
    runtime._CONTENT_CHUNK_DELAY = 0
    return runtime


def ask(text: str = "look it up") -> list[dict[str, Any]]:
    return [{"role": "user", "content": text}]


def sse_frames(body: str) -> list[tuple[str, dict[str, Any]]]:
    frames: list[tuple[str, dict[str, Any]]] = []
    for block in body.split("\n\n"):
        event, data = "", None
        for line in block.splitlines():
            if line.startswith("event:"):
                event = line[len("event:") :].strip()
            elif line.startswith("data:"):
                data = json.loads(line[len("data:") :].strip())
        if event and data is not None:
            frames.append((event, data))
    return frames


# -- the reply --------------------------------------------------------------------


def test_the_reply_is_built_from_counts_only():
    assert stopped_reply(ran=0, skipped=0) == "Stopped. I didn't finish the task."
    assert stopped_reply(ran=2, skipped=0) == (
        "Stopped. I didn't finish the task. 2 steps ran before the stop."
    )
    assert stopped_reply(ran=1, skipped=1) == ONE_RAN_ONE_SKIPPED
    assert stopped_reply(ran=0, skipped=3) == "Stopped. I didn't finish: 3 steps were skipped."


# -- the two boundaries -------------------------------------------------------------


@pytest.mark.asyncio
async def test_a_stop_before_the_first_round_ends_the_turn_without_a_model_call():
    provider = RecordingProvider([calls("web.search")])
    executor = StopDuring()
    audit = RecordingAudit()
    runtime = runtime_with(provider, executor, guard=StopOnInputScan(), audit=audit)

    response = await runtime.chat(messages=ask(), tools=[SEARCH], user_id=USER)

    assert provider.calls == [] and executor.calls == []
    assert response.stopped is True
    assert response.content == "Stopped. I didn't finish the task."
    assert response.tool_calls == [] and response.blocked_actions == []
    assert [e["event"] for e in audit.entries] == ["turn_stopped"]
    row = audit.entries[0]
    assert row["user_id"] == USER and row["policy"] == USER_STOPPED_POLICY
    assert row["arguments"] == {"steps_ran": 0, "steps_skipped": 0}
    # Nothing lifted it: the stop stands until the user starts new work.
    assert cancel.is_cancelled(USER) is True


@pytest.mark.asyncio
async def test_a_stop_while_a_tool_runs_ends_the_turn_before_the_next_model_round():
    provider = RecordingProvider([calls("web.search"), LLMResponse(content="never asked for")])
    executor = StopDuring(stop_on="web.search")
    runtime = runtime_with(provider, executor)

    response = await runtime.chat(messages=ask(), tools=[SEARCH], user_id=USER)

    assert len(provider.calls) == 1  # the follow-up round never ran
    # The call that was running when Stop arrived finished and is recorded.
    assert executor.calls == ["web.search"]
    assert response.tool_calls[0]["name"] == "web.search"
    assert response.tool_calls[0]["result"] == {"ok": True, "result": "web.search finished"}
    assert response.stopped is True
    assert response.content == "Stopped. I didn't finish the task. 1 step ran before the stop."


@pytest.mark.asyncio
async def test_a_stop_between_two_tool_calls_skips_the_rest_of_the_round():
    provider = RecordingProvider(
        [calls("web.search", "web.fetch_page", "google_workspace.send_email")]
    )
    executor = StopDuring(stop_on="web.search")
    audit = RecordingAudit()
    store = InMemoryApprovalStore()
    runtime = runtime_with(
        provider, executor, audit=audit, store=store, gated={"google_workspace.send_email"}
    )

    response = await runtime.chat(messages=ask(), tools=[SEARCH, FETCH, SEND], user_id=USER)

    assert executor.calls == ["web.search"]
    assert len(provider.calls) == 1
    assert response.content == (
        "Stopped. I didn't finish: 2 steps were skipped. 1 step ran before the stop."
    )
    # A skipped approval-gated call is not parked for approval either.
    assert response.pending_approvals == [] and await store.list_pending(USER) == []
    # Skipped is not a security block: every channel renders blocked_actions
    # as "blocked by security policy".
    assert response.blocked_actions == []

    assert [(e["event"], e.get("tool")) for e in audit.entries] == [
        ("tool_executing", "web.search"),
        ("tool_executed", "web.search"),
        ("tool_blocked", "web.fetch_page"),
        ("tool_blocked", "google_workspace.send_email"),
        ("turn_stopped", None),
    ]
    for entry in audit.entries[2:4]:
        assert entry["policy"] == USER_STOPPED_POLICY
        assert entry["reason"] == USER_STOPPED_REASON
    assert audit.entries[2]["arguments"] == {"q": "web.fetch_page"}
    assert audit.entries[4]["arguments"] == {"steps_ran": 1, "steps_skipped": 2}
    assert audit.entries[4]["reason"] == response.content


@pytest.mark.asyncio
async def test_another_users_stop_does_not_touch_this_turn():
    cancel.request_cancel(OTHER)
    provider = RecordingProvider([calls("web.search"), LLMResponse(content="Found it.")])
    runtime = runtime_with(provider)

    response = await runtime.chat(messages=ask(), tools=[SEARCH], user_id=USER)

    assert response.stopped is False and response.content == "Found it."
    assert cancel.is_cancelled(OTHER) is True


@pytest.mark.asyncio
async def test_the_next_turn_is_not_stopped_by_the_earlier_stop():
    provider = RecordingProvider([calls("web.search"), LLMResponse(content="Here you go.")])
    runtime = runtime_with(provider, StopDuring(stop_on="web.search"))

    first = await runtime.chat(messages=ask(), tools=[SEARCH], user_id=USER)
    assert first.stopped is True and cancel.is_cancelled(USER) is True

    second = await runtime.chat(messages=ask("try again"), tools=[SEARCH], user_id=USER)
    assert second.stopped is False and second.content == "Here you go."
    assert cancel.is_cancelled(USER) is False


@pytest.mark.asyncio
async def test_a_stop_after_the_callers_mark_ends_the_turn_before_any_model_call():
    """The route takes the mark when it accepts the message; a stop that
    lands before chat() starts (while tools and memory load) still counts."""
    accepted = cancel.mark(USER)
    cancel.request_cancel(USER)
    provider = RecordingProvider([LLMResponse(content="never asked for")])
    runtime = runtime_with(provider)

    response = await runtime.chat(messages=ask(), tools=[SEARCH], user_id=USER, stop_mark=accepted)

    assert provider.calls == [] and response.stopped is True


@pytest.mark.asyncio
async def test_a_stop_before_the_callers_mark_does_not_touch_the_turn():
    cancel.request_cancel(USER)
    accepted = cancel.mark(USER)
    provider = RecordingProvider([LLMResponse(content="Here you go.")])
    runtime = runtime_with(provider)

    response = await runtime.chat(messages=ask(), tools=[SEARCH], user_id=USER, stop_mark=accepted)

    assert response.stopped is False and response.content == "Here you go."


@pytest.mark.asyncio
async def test_a_new_message_does_not_unstop_a_turn_that_is_still_running():
    """Turn A is stopped while its tool runs; before A reaches its next
    boundary the user sends another message, whose turn takes a fresh mark.
    A still ends as stopped, and the new turn runs normally."""
    executor = Blocking()
    provider = RecordingProvider([calls("web.search"), LLMResponse(content="Second answer.")])
    runtime = runtime_with(provider, executor)
    turn_a = asyncio.create_task(runtime.chat(messages=ask(), tools=[SEARCH], user_id=USER))
    await asyncio.wait_for(executor.started.wait(), timeout=5)

    cancel.request_cancel(USER)
    second = await runtime.chat(messages=ask("something else"), tools=[], user_id=USER)
    executor.release.set()
    first = await asyncio.wait_for(turn_a, timeout=5)

    assert second.stopped is False and second.content == "Second answer."
    assert first.stopped is True
    assert len(provider.calls) == 2  # turn A never asked the model again


@pytest.mark.asyncio
async def test_a_final_text_round_is_kept_when_the_stop_lands_during_it():
    """A stop pressed during the model call that produces the final answer
    has nothing left to skip: the answer stands and the turn is not marked
    stopped (its next boundary would have been the end)."""

    class StopInComplete(RecordingProvider):
        async def complete(self, messages, tools=None):
            cancel.request_cancel(USER)
            return await super().complete(messages, tools)

    provider = StopInComplete([LLMResponse(content="final answer")])
    runtime = runtime_with(provider)

    response = await runtime.chat(messages=ask(), tools=[SEARCH], user_id=USER)

    assert response.content == "final answer" and response.stopped is False


@pytest.mark.asyncio
async def test_a_stopped_turn_is_not_replayed_from_the_cache():
    provider = RecordingProvider([LLMResponse(content="Four.")])
    runtime = runtime_with(provider, guard=StopOnInputScan())

    first = await runtime.chat(messages=ask("2+2?"), tools=[], user_id=USER, conversation_id="c1")
    assert first.stopped is True and provider.calls == []

    again = await runtime.chat(messages=ask("2+2?"), tools=[], user_id=USER, conversation_id="c1")
    assert again.content == "Four." and len(provider.calls) == 1


@pytest.mark.asyncio
async def test_the_stop_rows_land_in_the_audit_chain(session_factory, flags):
    from sqlalchemy import select

    from models.audit import AuditLog, AuditStatus
    from services.audit import RuntimeAuditLogger

    user, _ = await make_user(session_factory, "stop-audit@example.com")
    flags.add(str(user.id))
    runtime = runtime_with(
        RecordingProvider([calls("web.search", "web.fetch_page")]),
        StopDuring(stop_on="web.search"),
        audit=RuntimeAuditLogger(session_factory=session_factory),
    )

    await runtime.chat(messages=ask(), tools=[SEARCH, FETCH], user_id=str(user.id))

    async with session_factory() as s:
        rows = (
            (
                await s.execute(
                    select(AuditLog).where(AuditLog.user_id == user.id).order_by(AuditLog.seq)
                )
            )
            .scalars()
            .all()
        )
    stop_rows = [r for r in rows if r.reasoning_chain.get("policy") == USER_STOPPED_POLICY]
    assert [
        (r.connector_name, r.action, r.status, r.reasoning_chain["event"]) for r in stop_rows
    ] == [
        ("web", "fetch_page", AuditStatus.blocked, "tool_blocked"),
        ("agent", "turn_stopped", AuditStatus.blocked, "turn_stopped"),
    ]
    assert stop_rows[0].reasoning_chain["reason"] == USER_STOPPED_REASON


# -- stops that land while a call is checked or a round ends ----------------------
#
# A call's checks (permission, argument scan) and its intent row can wait on the
# database, and so can the end of a round. A stop landing in one of those waits
# is caught before the call is parked or started, and before the round ends.


class StopWhileChecking(Gate):
    """Presses Stop while the permission check for *stop_on* is in flight
    (the production adapter awaits the capability gate there)."""

    def __init__(self, stop_on: str, gated: set[str] | None = None) -> None:
        super().__init__(gated)
        self.stop_on = stop_on

    async def check(self, user_id, tool_name, arguments):
        if tool_name == self.stop_on:
            cancel.request_cancel(user_id)
        return await super().check(user_id, tool_name, arguments)


class StopWhileScanningArguments(PromptGuard):
    """Presses Stop while the arguments of *stop_on* are scanned."""

    def __init__(self, stop_on: str) -> None:
        self.stop_on = stop_on

    async def scan_input(self, content, user_id):
        if self.stop_on in content:
            cancel.request_cancel(user_id)
        return {"safe": True}


class StopWhileLogging(RecordingAudit):
    """Presses Stop while the *event* row (for *tool*, when given) is
    written: a database write in production."""

    def __init__(self, event: str, tool: str | None = None) -> None:
        super().__init__()
        self.event = event
        self.tool = tool

    async def log(self, entry):
        if entry.get("event") == self.event and self.tool in (None, entry.get("tool")):
            cancel.request_cancel(entry["user_id"])
        await super().log(entry)


def recording_sink() -> tuple[list[dict[str, Any]], Any]:
    events: list[dict[str, Any]] = []

    async def sink(event: dict[str, Any]) -> None:
        events.append(event)

    return events, sink


@pytest.mark.asyncio
@pytest.mark.parametrize("stops_in", ["permission check", "argument scan"])
async def test_a_stop_while_a_call_is_checked_skips_it_instead_of_raising_a_card(stops_in):
    """No card is raised after the stop, so there is none whose approval
    could resume the task the user stopped."""
    provider = RecordingProvider(
        [calls("web.search", SEND.name), LLMResponse(content="never asked for")]
    )
    executor = StopDuring()
    audit = RecordingAudit()
    store = InMemoryApprovalStore()
    runtime = runtime_with(provider, executor, audit=audit, store=store, gated={SEND.name})
    if stops_in == "permission check":
        runtime._permissions = StopWhileChecking(SEND.name, gated={SEND.name})
    else:
        runtime._guard = StopWhileScanningArguments(SEND.name)

    response = await runtime.chat(messages=ask(), tools=[SEARCH, SEND], user_id=USER)

    assert response.stopped is True and response.content == ONE_RAN_ONE_SKIPPED
    assert response.pending_approvals == [] and await store.list_pending(USER) == []
    assert response.blocked_actions == []
    assert executor.calls == ["web.search"] and len(provider.calls) == 1
    assert [(e["event"], e.get("tool"), e.get("policy")) for e in audit.entries] == [
        ("tool_executing", "web.search", None),
        ("tool_executed", "web.search", None),
        ("tool_blocked", SEND.name, USER_STOPPED_POLICY),
        ("turn_stopped", None, USER_STOPPED_POLICY),
    ]
    assert audit.entries[3]["arguments"] == {"steps_ran": 1, "steps_skipped": 1}


@pytest.mark.asyncio
async def test_a_stop_while_the_intent_row_is_written_keeps_the_call_from_starting():
    provider = RecordingProvider([calls("web.search", "web.fetch_page")])
    executor = StopDuring()
    audit = StopWhileLogging("tool_executing", "web.fetch_page")
    runtime = runtime_with(provider, executor, audit=audit)
    events, sink = recording_sink()

    response = await runtime.chat(
        messages=ask(), tools=[SEARCH, FETCH], user_id=USER, event_sink=sink
    )

    assert executor.calls == ["web.search"]
    assert [e["data"]["name"] for e in events if e["type"] == "tool_call"] == ["web.search"]
    assert response.stopped is True and response.content == ONE_RAN_ONE_SKIPPED
    assert [t["name"] for t in response.tool_calls] == ["web.search"]
    # The intent row stays, followed by the row saying the call never ran.
    assert [(e["event"], e.get("tool"), e.get("policy")) for e in audit.entries] == [
        ("tool_executing", "web.search", None),
        ("tool_executed", "web.search", None),
        ("tool_executing", "web.fetch_page", None),
        ("tool_blocked", "web.fetch_page", USER_STOPPED_POLICY),
        ("turn_stopped", None, USER_STOPPED_POLICY),
    ]
    assert audit.entries[4]["arguments"] == {"steps_ran": 1, "steps_skipped": 1}


def assert_the_round_ended_as_stopped(response, audit, events, *, ran: int) -> None:
    assert response.stopped is True
    assert response.content == stopped_reply(ran=ran, skipped=0)
    assert audit.entries[-1]["event"] == "turn_stopped"
    assert audit.entries[-1]["arguments"] == {"steps_ran": ran, "steps_skipped": 0}
    assert [e["data"] for e in events if e["type"] == "stopped"] == [
        {"policy": USER_STOPPED_POLICY, "steps_ran": ran, "steps_skipped": 0}
    ]


@pytest.mark.asyncio
async def test_a_stop_outranks_a_handoff_that_ends_the_round():
    """The stop lands while the round's last call runs, and that call hits a
    page only a person can clear."""
    browser = Tool(
        name="browser.read",
        description="read",
        parameters={"type": "object", "properties": {}},
        connector_type="browser",
    )

    class HandoffDuringStop:
        async def execute(self, tool_name, arguments, user_id, approved=False, *, task_id=None):
            cancel.request_cancel(user_id)
            return {"ok": False, "needs_human": {"detail": "a sign-in page"}}

    audit = RecordingAudit()
    runtime = runtime_with(
        RecordingProvider([calls("browser.read")]), HandoffDuringStop(), audit=audit
    )
    events, sink = recording_sink()

    response = await runtime.chat(messages=ask(), tools=[browser], user_id=USER, event_sink=sink)

    assert_the_round_ended_as_stopped(response, audit, events, ran=1)


@pytest.mark.asyncio
async def test_a_stop_while_a_block_is_recorded_ends_the_turn_as_stopped():
    """Every call of the round was blocked, and the stop lands while the
    block is being recorded."""

    class BlockThenStop(Gate):
        async def check(self, user_id, tool_name, arguments):
            return "blocked"

        async def get_block_reason(self, user_id, tool_name, arguments):
            cancel.request_cancel(user_id)
            return "Blocked by the owner's policy."

    executor = StopDuring()
    audit = RecordingAudit()
    runtime = runtime_with(RecordingProvider([calls("web.fetch_page")]), executor, audit=audit)
    runtime._permissions = BlockThenStop()
    events, sink = recording_sink()

    response = await runtime.chat(messages=ask(), tools=[FETCH], user_id=USER, event_sink=sink)

    assert executor.calls == []
    assert [b.tool_name for b in response.blocked_actions] == ["web.fetch_page"]
    assert_the_round_ended_as_stopped(response, audit, events, ran=0)


@pytest.mark.asyncio
async def test_a_stop_while_a_card_is_recorded_ends_the_turn_and_the_resumed_task():
    """The card was raised before the stop, so it stays and can be approved;
    the turn still ends as stopped, and so does the turn that would resume
    the task after the approval."""
    executor = StopDuring()
    audit = StopWhileLogging("tool_pending_approval")
    store = InMemoryApprovalStore()
    runtime = runtime_with(
        RecordingProvider([calls(SEND.name)]),
        executor,
        audit=audit,
        store=store,
        gated={SEND.name},
    )
    events, sink = recording_sink()

    response = await runtime.chat(messages=ask(), tools=[SEND], user_id=USER, event_sink=sink)

    assert_the_round_ended_as_stopped(response, audit, events, ran=0)
    [pending] = response.pending_approvals
    assert [p.action_id for p in await store.list_pending(USER)] == [pending.action_id]
    outcome = await runtime.approve_action(pending.action_id, USER)
    assert executor.calls == [SEND.name]
    assert cancel.stopped_since(USER, outcome["resume_stop_mark"]) is True


@pytest.mark.asyncio
async def test_a_stop_just_before_the_card_is_stored_raises_no_card():
    """The card is stored in a task of its own, so the stop is checked once
    more there, with no await before the store stamps its created_at: a stop
    landing after the turn's own check (here, while the card's sentence is
    written) skips the call instead of raising a card after the stop."""

    class StopWhileDescribing(StopDuring):
        def describe_approval(self, tool_name, arguments, user_id):
            cancel.request_cancel(user_id)
            return "Send an email"

    audit = RecordingAudit()
    store = InMemoryApprovalStore()
    runtime = runtime_with(
        RecordingProvider([calls(SEND.name)]),
        StopWhileDescribing(),
        audit=audit,
        store=store,
        gated={SEND.name},
    )

    response = await runtime.chat(messages=ask(), tools=[SEND], user_id=USER)

    assert response.stopped is True
    assert response.content == stopped_reply(ran=0, skipped=1)
    assert response.pending_approvals == [] and await store.list_pending(USER) == []
    assert [(e["event"], e.get("tool"), e.get("policy")) for e in audit.entries] == [
        ("tool_blocked", SEND.name, USER_STOPPED_POLICY),
        ("turn_stopped", None, USER_STOPPED_POLICY),
    ]


# -- channels ---------------------------------------------------------------------


@pytest.mark.asyncio
async def test_the_stream_reports_the_stop_and_still_ends_with_done():
    provider = RecordingProvider([calls("web.search", "web.fetch_page")])
    runtime = runtime_with(provider, StopDuring(stop_on="web.search"))

    events = [
        e async for e in runtime.stream_chat(messages=ask(), tools=[SEARCH, FETCH], user_id=USER)
    ]

    types = [e["type"] for e in events]
    assert types[0] == "start" and types[-1] == "done"
    assert types.index("tool_result") < types.index("stopped") < types.index("content_delta")
    assert "blocked" not in types
    stopped = next(e for e in events if e["type"] == "stopped")
    assert stopped["data"] == {"policy": USER_STOPPED_POLICY, "steps_ran": 1, "steps_skipped": 1}
    text = "".join(e["data"]["text"] for e in events if e["type"] == "content_delta")
    assert text == events[-1]["data"]["content"] == ONE_RAN_ONE_SKIPPED


@pytest.mark.asyncio
async def test_the_sse_route_streams_the_stop_and_saves_the_reply(client, session_factory, flags):
    from api.routes import agent as agent_routes
    from main import app

    user, token = await make_user(session_factory, "stop-sse@example.com")
    flags.add(str(user.id))
    runtime = runtime_with(
        RecordingProvider([calls("web.search", "web.fetch_page")]),
        StopDuring(stop_on="web.search"),
    )
    app.dependency_overrides[agent_routes.get_runtime] = lambda: runtime
    try:
        conv = (
            await client.post("/api/agent/conversations", headers=auth_headers(token), json={})
        ).json()
        response = await client.post(
            f"/api/agent/conversations/{conv['id']}/messages/stream",
            headers=auth_headers(token),
            json={"content": "look it up"},
        )
    finally:
        app.dependency_overrides.pop(agent_routes.get_runtime, None)

    assert response.status_code == 200
    frames = sse_frames(response.text)
    names = [name for name, _ in frames]
    assert names.index("stopped") < names.index("done") < names.index("saved")
    assert dict(frames)["done"]["content"] == ONE_RAN_ONE_SKIPPED
    assert dict(frames)["saved"]["assistant_message"]["content"] == ONE_RAN_ONE_SKIPPED


@pytest.mark.asyncio
async def test_a_stopped_channel_turn_replies_with_the_stop_and_no_block(
    client, session_factory, flags
):
    """The Telegram poller sends the applier's content and lists "blocked"
    tools as a security block; a stop must arrive as its reply alone."""
    import uuid

    from sqlalchemy import select

    from api.routes.agent import build_chat_applier
    from main import app
    from models.conversation import Message, MessageRole

    user, _ = await make_user(session_factory, "stop-channel@example.com")
    flags.add(str(user.id))
    runtime = runtime_with(
        RecordingProvider([calls("web.search", "web.fetch_page")]),
        StopDuring(stop_on="web.search"),
    )
    saved = getattr(app.state, "agent_runtime", None)
    app.state.agent_runtime = runtime
    try:
        outcome = await build_chat_applier(app, session_factory=session_factory)(
            str(user.id), "look it up"
        )
    finally:
        app.state.agent_runtime = saved

    assert outcome["content"] == ONE_RAN_ONE_SKIPPED
    assert outcome["blocked"] == [] and outcome["pending_approvals"] == []
    assert outcome["tool_calls"] == ["web.search"]
    async with session_factory() as s:
        replies = (
            (
                await s.execute(
                    select(Message.content).where(
                        Message.conversation_id == uuid.UUID(outcome["conversation_id"]),
                        Message.role == MessageRole.assistant,
                    )
                )
            )
            .scalars()
            .all()
        )
    assert replies == [ONE_RAN_ONE_SKIPPED]


def stop_during_setup(monkeypatch, user_id: str) -> None:
    """Make the Stop land while the route is still building the turn's
    tools and memory (MCP tool listing can take seconds): after the message
    was accepted, before runtime.chat starts."""
    from api.routes import agent as agent_routes

    real_build = agent_routes._build_tools_and_memory

    async def build_then_stop(*args: Any, **kwargs: Any) -> Any:
        built = await real_build(*args, **kwargs)
        cancel.request_cancel(user_id)
        return built

    monkeypatch.setattr(agent_routes, "_build_tools_and_memory", build_then_stop)


@pytest.mark.asyncio
async def test_a_stop_while_the_web_turn_is_set_up_is_kept(
    client, session_factory, flags, monkeypatch
):
    from api.routes import agent as agent_routes
    from main import app

    user, token = await make_user(session_factory, "stop-setup-web@example.com")
    flags.add(str(user.id))
    stop_during_setup(monkeypatch, str(user.id))
    provider = RecordingProvider([calls("web.search"), LLMResponse(content="ran to the end")])
    executor = StopDuring()
    runtime = runtime_with(provider, executor)
    app.dependency_overrides[agent_routes.get_runtime] = lambda: runtime
    try:
        conv = (
            await client.post("/api/agent/conversations", headers=auth_headers(token), json={})
        ).json()
        response = await client.post(
            f"/api/agent/conversations/{conv['id']}/messages/stream",
            headers=auth_headers(token),
            json={"content": "look it up"},
        )
    finally:
        app.dependency_overrides.pop(agent_routes.get_runtime, None)

    assert provider.calls == [] and executor.calls == []
    frames = dict(sse_frames(response.text))
    assert frames["stopped"]["steps_ran"] == 0
    assert frames["done"]["content"] == "Stopped. I didn't finish the task."


@pytest.mark.asyncio
async def test_a_stop_while_the_channel_turn_is_set_up_is_kept(
    client, session_factory, flags, monkeypatch
):
    """The Telegram path: the applier accepts the message, then does DB work
    and lists tools before runtime.chat runs; a /stop in that window ends
    the turn instead of being wiped when it starts."""
    from api.routes.agent import build_chat_applier
    from main import app

    user, _ = await make_user(session_factory, "stop-setup-race@example.com")
    uid = str(user.id)
    flags.add(uid)
    stop_during_setup(monkeypatch, uid)
    provider = RecordingProvider(
        [calls("web.search", "web.fetch_page"), LLMResponse(content="ran to the end")]
    )
    executor = StopDuring()
    runtime = runtime_with(provider, executor)
    saved = getattr(app.state, "agent_runtime", None)
    app.state.agent_runtime = runtime
    try:
        outcome = await build_chat_applier(app, session_factory=session_factory)(uid, "go")
    finally:
        app.state.agent_runtime = saved

    assert outcome["content"] == "Stopped. I didn't finish the task."
    assert executor.calls == [] and provider.calls == []


@pytest.mark.asyncio
async def test_a_channel_can_pass_the_mark_it_took_when_the_message_arrived(
    client, session_factory, flags
):
    """A message that waited behind the chat's previous turn (the poller runs
    one turn per chat at a time) is stopped by a /stop sent while it waited,
    when the poller hands over the mark it took on arrival."""
    from api.routes.agent import build_chat_applier
    from main import app

    user, _ = await make_user(session_factory, "stop-queued@example.com")
    uid = str(user.id)
    flags.add(uid)
    arrived = cancel.mark(uid)
    cancel.request_cancel(uid)
    provider = RecordingProvider([LLMResponse(content="never asked for")])
    runtime = runtime_with(provider)
    saved = getattr(app.state, "agent_runtime", None)
    app.state.agent_runtime = runtime
    try:
        outcome = await build_chat_applier(app, session_factory=session_factory)(
            uid, "go", stop_mark=arrived
        )
    finally:
        app.state.agent_runtime = saved

    assert outcome["content"] == "Stopped. I didn't finish the task."
    assert provider.calls == []


# -- approvals --------------------------------------------------------------------


@pytest.mark.asyncio
async def test_approving_after_a_stop_runs_the_approved_action():
    executor = StopDuring()
    runtime = runtime_with(RecordingProvider(), executor)
    parked = await runtime._approvals.create(
        user_id=USER,
        tool_name="google_workspace.send_email",
        arguments={"to": "prof@school.edu"},
        reason="r",
        conversation_id="conv-1",
    )
    cancel.request_cancel(USER)  # Stop pressed while the card waited

    outcome = await runtime.approve_action(parked.action_id, USER)

    assert executor.calls == ["google_workspace.send_email"]
    assert executor.saw_stop == [False]  # the tap came after that stop
    assert outcome["result"] == {"ok": True, "result": "google_workspace.send_email finished"}
    # The turn that resumes the task answers to that stop.
    assert cancel.stopped_since(USER, outcome["resume_stop_mark"]) is True


@pytest.mark.asyncio
async def test_a_stop_after_the_tap_reaches_the_approved_actions_own_checks():
    """The computer toolkit checks the stop again just before input is sent;
    inside an approved action that check answers for the tap's mark."""
    seen: list[bool] = []

    class StopMidAction:
        async def execute(self, tool_name, arguments, user_id, approved=False, *, task_id=None):
            seen.append(cancel.is_cancelled(user_id))
            cancel.request_cancel(user_id)
            seen.append(cancel.is_cancelled(user_id))
            return {"ok": True}

    runtime = runtime_with(RecordingProvider(), StopMidAction())
    parked = await runtime._approvals.create(
        user_id=USER, tool_name="desktop.act", arguments={}, reason="r", conversation_id="c"
    )

    await runtime.approve_action(parked.action_id, USER)

    assert seen == [False, True]


@pytest.mark.asyncio
async def test_an_approve_tap_on_another_card_does_not_unstop_a_running_turn():
    """Stop pressed while turn A's tool runs, then the user approves a card
    from another conversation before A reaches its next boundary: the tap
    runs its own action and A still ends as stopped."""
    executor = Blocking()
    provider = RecordingProvider(
        [calls("web.search"), LLMResponse(content="kept going after the stop")]
    )
    runtime = runtime_with(provider, executor)
    parked = await runtime._approvals.create(
        user_id=USER,
        tool_name="google_workspace.send_email",
        arguments={"to": "a@b.c"},
        reason="r",
        conversation_id="other-conv",
    )
    turn = asyncio.create_task(runtime.chat(messages=ask(), tools=[SEARCH], user_id=USER))
    await asyncio.wait_for(executor.started.wait(), timeout=5)

    cancel.request_cancel(USER)  # Stop
    await runtime.approve_action(parked.action_id, USER)  # an unrelated Approve tap
    executor.release.set()
    response = await asyncio.wait_for(turn, timeout=5)

    assert executor.calls == ["web.search", "google_workspace.send_email"]
    assert response.stopped is True, response.content
    assert len(provider.calls) == 1


async def approve_over_http(
    client,
    session_factory,
    flags,
    email: str,
    provider: Any,
    executor: Any,
    *,
    stop_before_the_card: bool = False,
    stop_while_it_waits: bool = False,
) -> tuple[Any, list[dict[str, Any]], str]:
    """Park a send_email card in a new conversation, approve it through
    POST /api/agent/approvals/{id}, and return the decision response, the
    conversation's messages and the user id."""
    from api.routes import agent as agent_routes
    from main import app
    from tests.test_resume_after_approval import _park_action, _runtime

    runtime, _ = _runtime(session_factory, provider, executor)
    app.dependency_overrides[agent_routes.get_runtime] = lambda: runtime
    try:
        user, token = await make_user(session_factory, email)
        uid = str(user.id)
        flags.add(uid)
        conv = (
            await client.post("/api/agent/conversations", headers=auth_headers(token), json={})
        ).json()
        if stop_before_the_card:
            cancel.request_cancel(uid)
        action = await _park_action(session_factory, user, conv["id"])
        if stop_while_it_waits:
            cancel.request_cancel(uid)
        decided = await client.post(
            f"/api/agent/approvals/{action.action_id}",
            headers=auth_headers(token),
            json={"approved": True},
        )
        messages = (
            await client.get(f"/api/agent/conversations/{conv['id']}", headers=auth_headers(token))
        ).json()["messages"]
    finally:
        app.dependency_overrides.pop(agent_routes.get_runtime, None)
    return decided, messages, uid


@pytest.mark.asyncio
async def test_a_stop_while_the_card_waited_runs_the_action_then_stops_the_resumed_turn(
    client, session_factory, flags
):
    """The task was stopped while its card waited: approving the card still
    runs the approved action, but the task does not carry on quietly."""
    from tests.test_resume_after_approval import ScriptedProvider

    provider = ScriptedProvider([LLMResponse(content="Sent. Anything else?")])
    executor = StopDuring()
    decided, messages, _ = await approve_over_http(
        client,
        session_factory,
        flags,
        "stop-while-waiting@example.com",
        provider,
        executor,
        stop_while_it_waits=True,
    )

    assert decided.status_code == 200
    assert "resume_stop_mark" not in decided.json()["result"]
    assert executor.calls == ["google_workspace.send_email"] and executor.saw_stop == [False]
    assert provider.calls == []
    assert "[Approved] Executed" in messages[0]["content"]
    assert messages[1]["content"] == "Stopped. I didn't finish the task."


@pytest.mark.asyncio
async def test_a_stop_from_before_the_card_was_raised_does_not_stop_the_resumed_turn(
    client, session_factory, flags
):
    from tests.test_resume_after_approval import ScriptedProvider

    provider = ScriptedProvider([LLMResponse(content="Sent. Anything else?")])
    decided, messages, _ = await approve_over_http(
        client,
        session_factory,
        flags,
        "stop-before-card@example.com",
        provider,
        StopDuring(),
        stop_before_the_card=True,
    )

    assert decided.status_code == 200
    assert len(provider.calls) == 1
    assert messages[1]["content"] == "Sent. Anything else?"


@pytest.mark.asyncio
async def test_a_stop_pressed_while_the_approved_action_runs_ends_the_resumed_turn(
    client, session_factory, flags
):
    from tests.test_resume_after_approval import ScriptedProvider

    provider = ScriptedProvider([LLMResponse(content="Sent. Anything else?")])
    executor = StopDuring(stop_on="google_workspace.send_email")
    decided, messages, uid = await approve_over_http(
        client, session_factory, flags, "stop-resume@example.com", provider, executor
    )

    assert decided.status_code == 200
    assert executor.calls == ["google_workspace.send_email"] and executor.saw_stop == [False]
    # The Stop pressed while the action ran ended the resumed turn before it
    # asked the model anything.
    assert provider.calls == []
    assert "[Approved] Executed" in messages[0]["content"]
    assert messages[1]["content"] == "Stopped. I didn't finish the task."
    assert cancel.is_cancelled(uid) is True


@pytest.mark.asyncio
async def test_a_stop_during_the_resumed_turn_stops_it(client, session_factory, flags):
    from tests.test_resume_after_approval import ScriptedProvider

    provider = ScriptedProvider([calls("web.search"), LLMResponse(content="never asked for")])
    executor = StopDuring(stop_on="web.search")
    decided, messages, _ = await approve_over_http(
        client, session_factory, flags, "stop-mid-resume@example.com", provider, executor
    )

    assert decided.status_code == 200
    assert executor.calls == ["google_workspace.send_email", "web.search"]
    assert len(provider.calls) == 1  # no round after the stop
    assert messages[-1]["content"] == (
        "Stopped. I didn't finish the task. 1 step ran before the stop."
    )


# -- POST /api/agent/stop -----------------------------------------------------------


@pytest.mark.asyncio
async def test_the_stop_endpoint_requires_sign_in(client):
    assert (await client.post("/api/agent/stop")).status_code in (401, 403)
    garbage = await client.post("/api/agent/stop", headers=auth_headers("not-a-jwt"))
    assert garbage.status_code == 401


@pytest.mark.asyncio
async def test_the_stop_endpoint_stops_the_caller_only_and_audits_it(
    client, session_factory, flags
):
    from sqlalchemy import select

    from models.audit import AuditLog, AuditStatus

    user, token = await make_user(session_factory, "stop-endpoint@example.com")
    bystander, _ = await make_user(session_factory, "stop-bystander@example.com")
    flags.update({str(user.id), str(bystander.id)})

    response = await client.post("/api/agent/stop", headers=auth_headers(token))

    assert response.status_code == 200 and response.json() == {"ok": True}
    assert cancel.is_cancelled(str(user.id)) is True
    assert cancel.is_cancelled(str(bystander.id)) is False
    async with session_factory() as s:
        rows = (
            (await s.execute(select(AuditLog).where(AuditLog.user_id == user.id))).scalars().all()
        )
    assert [(r.connector_name, r.action, r.status, r.endpoint) for r in rows] == [
        ("agent", "stop_requested", AuditStatus.approved, "/api/agent/stop")
    ]
    assert rows[0].reasoning_chain == {
        "event": "stop_requested",
        "policy": USER_STOPPED_POLICY,
        "channel": "web",
    }


@pytest.mark.asyncio
async def test_the_web_stop_ends_a_turn_that_is_running(client, session_factory, flags):
    user, token = await make_user(session_factory, "stop-live@example.com")
    flags.add(str(user.id))
    started, release = asyncio.Event(), asyncio.Event()

    class SlowSearch:
        def __init__(self) -> None:
            self.calls: list[str] = []

        async def execute(self, tool_name, arguments, user_id, approved=False, *, task_id=None):
            self.calls.append(tool_name)
            started.set()
            await release.wait()
            return {"ok": True}

    executor = SlowSearch()
    provider = RecordingProvider(
        [calls("web.search", "web.fetch_page"), LLMResponse(content="never asked for")]
    )
    runtime = runtime_with(provider, executor)
    turn = asyncio.create_task(
        runtime.chat(messages=ask(), tools=[SEARCH, FETCH], user_id=str(user.id))
    )
    await asyncio.wait_for(started.wait(), timeout=5)

    stop = await client.post("/api/agent/stop", headers=auth_headers(token))
    assert stop.status_code == 200
    release.set()  # the search that was running finishes normally
    response = await asyncio.wait_for(turn, timeout=5)

    assert response.stopped is True and response.content == ONE_RAN_ONE_SKIPPED
    assert executor.calls == ["web.search"] and len(provider.calls) == 1
