"""Concurrency and failure-mode tests for the approval flow and runtime.

These cover the incidents that would be SILENT in production: a
double-clicked approval sending two emails, a raced approve/deny that runs
what the user rejected, an expired or foreign action that executes anyway,
a per-user rate limiter that miscounts when requests overlap, and a
connector exception that turns one bad tool call into a failed turn.

Every race is driven with ``asyncio.gather`` against the REAL
``DbApprovalStore`` (backed by the ``session_factory`` fixture), so the
interleaving is genuine rather than a sequence of calls dressed up as one.
The executors below yield control at their own await points to widen the
window a buggy implementation would fall into.
"""

from __future__ import annotations

import asyncio

import pytest

from core.config import settings
from services.agent.approvals import DbApprovalStore
from services.agent.providers import LLMResponse, ToolCall
from services.agent.runtime import AgentRuntime
from services.agent.tool_registry import (
    ConnectorSpec,
    RuntimePermissionAdapter,
    build_tools,
)
from tests.conftest import auth_headers, make_user
from tests.test_streaming import RecordingAudit

SEND_EMAIL = "google_workspace.send_email"
EMAIL_ARGS = {"to": "prof@school.edu", "subject": "s", "body": "b"}


# ---------------------------------------------------------------------------
# Fakes
# ---------------------------------------------------------------------------


class CountingExecutor:
    """Records every invocation and yields control while "running".

    The append happens BEFORE the awaits, so a second entry proves a real
    double-execution rather than a slow first one; the awaits give the
    event loop a chance to run a racing caller into the same window.
    """

    def __init__(self, result=None, fail_marker: str | None = None) -> None:
        self.calls: list[dict] = []
        self._result = result if result is not None else {"ok": True, "result": "sent"}
        self._fail_marker = fail_marker

    async def execute(self, tool_name, arguments, user_id, approved=False):
        self.calls.append(
            {
                "tool": tool_name,
                "arguments": dict(arguments),
                "user_id": user_id,
                "approved": approved,
            }
        )
        for _ in range(3):
            await asyncio.sleep(0)
        if self._fail_marker is not None and self._fail_marker in str(arguments):
            raise RuntimeError("connector unavailable")
        return self._result


class ExplodingExecutor:
    """Always raises — models a connector that is down mid-turn."""

    def __init__(self) -> None:
        self.calls: list[str] = []

    async def execute(self, tool_name, arguments, user_id, approved=False):
        self.calls.append(tool_name)
        await asyncio.sleep(0)
        raise RuntimeError("connector unavailable")


class EchoProvider:
    """Stateless completion: answers with the last user message.

    Statelessness is the point — one instance is shared by concurrent
    turns, so any cross-talk in the runtime (a mutated message list, a
    mis-scoped cache) shows up as an answer belonging to another turn.
    """

    def __init__(self) -> None:
        self.seen: list[list[dict]] = []

    async def complete(self, messages, tools=None):
        self.seen.append([dict(m) for m in messages])
        await asyncio.sleep(0)
        last_user = next(
            (str(m.get("content", "")) for m in reversed(messages) if m.get("role") == "user"),
            "",
        )
        return LLMResponse(content=f"answer:{last_user}")

    async def stream(self, messages, tools=None):
        yield "done"


class ToolThenAnswerProvider:
    """Requests one tool call per turn, then answers.

    Which branch to take is derived from the message list (the tool-result
    envelope is unmistakable), never from instance state, so concurrent
    turns sharing one provider cannot desynchronize each other.
    """

    def __init__(self, tool_name: str, write: bool = True) -> None:
        self._tool_name = tool_name
        self._write = write
        self.completions = 0

    async def complete(self, messages, tools=None):
        self.completions += 1
        await asyncio.sleep(0)
        last = str(messages[-1].get("content", ""))
        if "Tool execution finished" in last:
            return LLMResponse(content="all done")
        marker = next(
            (str(m.get("content", "")) for m in reversed(messages) if m.get("role") == "user"),
            "",
        )
        arguments = (
            {"to": f"{marker}@school.edu", "subject": "s", "body": "b"}
            if self._write
            else {"marker": marker}
        )
        return LLMResponse(
            content="",
            tool_calls=[ToolCall(id=f"tc-{marker}", name=self._tool_name, arguments=arguments)],
        )

    async def stream(self, messages, tools=None):
        yield "done"


def _runtime(session_factory, provider=None, executor=None):
    """Runtime wired to the real permission adapter and the DB approval
    store, so races exercise production code paths end to end."""
    executor = executor or CountingExecutor()
    audit = RecordingAudit()
    runtime = AgentRuntime(
        config=settings,
        permission_engine=RuntimePermissionAdapter(),
        tool_executor=executor,
        audit_service=audit,
        approval_store=DbApprovalStore(session_factory=session_factory),
    )
    runtime._provider = provider or EchoProvider()
    runtime._CONTENT_CHUNK_DELAY = 0
    return runtime, executor, audit


async def _make_conversation(session_factory, user, title: str) -> str:
    """Create a conversation row directly — pending actions carry an FK to
    it, which SQLite enforces in this suite."""
    from models.conversation import Conversation

    async with session_factory() as session:
        conversation = Conversation(user_id=user.id, title=title)
        session.add(conversation)
        await session.flush()
        conversation_id = str(conversation.id)
        await session.commit()
    return conversation_id


async def _park(session_factory, user, *, ttl_minutes: int = 15, conversation_id=None):
    """Persist one pending action the way the runtime would."""
    store = DbApprovalStore(session_factory=session_factory)
    return await store.create(
        user_id=str(user.id),
        tool_name=SEND_EMAIL,
        arguments=dict(EMAIL_ARGS),
        reason="needs approval",
        ttl_minutes=ttl_minutes,
        conversation_id=conversation_id,
    )


# ---------------------------------------------------------------------------
# Double-decide races on a single action
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_two_concurrent_approvals_execute_the_tool_exactly_once(session_factory):
    """The double-click case: two approvals of the same action land at once
    and the email must go out ONCE, with the loser told the action is gone."""
    user, _ = await make_user(session_factory, "race1@example.com")
    runtime, executor, _ = _runtime(session_factory)
    action = await _park(session_factory, user)

    first, second = await asyncio.gather(
        runtime.approve_action(action.action_id, str(user.id)),
        runtime.approve_action(action.action_id, str(user.id)),
    )

    results = [first, second]
    winners = [r for r in results if "error" not in r]
    losers = [r for r in results if "error" in r]
    assert len(winners) == 1
    assert len(losers) == 1
    assert winners[0]["tool"] == SEND_EMAIL
    assert "already processed" in losers[0]["error"]
    assert len(executor.calls) == 1
    assert executor.calls[0]["approved"] is True


@pytest.mark.asyncio
async def test_eight_concurrent_approvals_execute_the_tool_exactly_once(session_factory):
    """Widen the race: a retry storm on one action still sends one email."""
    user, _ = await make_user(session_factory, "race8@example.com")
    runtime, executor, audit = _runtime(session_factory)
    action = await _park(session_factory, user)

    results = await asyncio.gather(
        *[runtime.approve_action(action.action_id, str(user.id)) for _ in range(8)]
    )

    assert sum(1 for r in results if "error" not in r) == 1
    assert len(executor.calls) == 1
    # Exactly one approval was recorded, so the audit trail matches reality.
    assert sum(1 for e in audit.entries if e["event"] == "tool_approved") == 1
    assert sum(1 for e in audit.entries if e["event"] == "tool_approved_and_executed") == 1


@pytest.mark.asyncio
async def test_approve_raced_against_deny_has_exactly_one_winner(session_factory):
    """Approve and deny arrive together. One decision wins; the tool runs at
    most once, and never at all when the denial got there first."""
    user, _ = await make_user(session_factory, "racemixed@example.com")
    runtime, executor, audit = _runtime(session_factory)
    action = await _park(session_factory, user)

    approved, denied = await asyncio.gather(
        runtime.approve_action(action.action_id, str(user.id)),
        runtime.deny_action(action.action_id, str(user.id)),
    )

    outcomes = [approved, denied]
    assert sum(1 for r in outcomes if "error" not in r) == 1
    assert len(executor.calls) <= 1
    if "error" in approved:
        # The denial won: nothing may have executed.
        assert denied.get("denied") is True
        assert executor.calls == []
        assert any(e["event"] == "tool_denied" for e in audit.entries)
    else:
        assert len(executor.calls) == 1
        assert not any(e["event"] == "tool_denied" for e in audit.entries)


@pytest.mark.asyncio
async def test_concurrent_denials_record_a_single_denial(session_factory):
    """A denial is single-use too — four concurrent denials must not write
    four "user said no" rows into the audit trail."""
    user, _ = await make_user(session_factory, "racedeny@example.com")
    runtime, executor, audit = _runtime(session_factory)
    action = await _park(session_factory, user)

    results = await asyncio.gather(
        *[runtime.deny_action(action.action_id, str(user.id)) for _ in range(4)]
    )

    assert sum(1 for r in results if r.get("denied")) == 1
    assert sum(1 for e in audit.entries if e["event"] == "tool_denied") == 1
    assert executor.calls == []


# ---------------------------------------------------------------------------
# Expiry
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_approving_an_expired_action_reports_expiry_and_never_executes(
    session_factory,
):
    """An approval that arrives after the TTL is refused with the expiry
    error — the whole point of the TTL is that a stale click cannot act."""
    user, _ = await make_user(session_factory, "expired@example.com")
    runtime, executor, audit = _runtime(session_factory)
    action = await _park(session_factory, user, ttl_minutes=0)

    result = await runtime.approve_action(action.action_id, str(user.id))

    assert result == {"error": "Action expired before a decision was made"}
    assert executor.calls == []
    assert any(e["event"] == "tool_expired" for e in audit.entries)


@pytest.mark.asyncio
async def test_concurrent_approvals_of_an_expired_action_never_execute(session_factory):
    """Racing an expired action must not let one caller slip through the
    window between the expiry check and the status flip."""
    user, _ = await make_user(session_factory, "expiredrace@example.com")
    runtime, executor, _ = _runtime(session_factory)
    action = await _park(session_factory, user, ttl_minutes=0)

    results = await asyncio.gather(
        *[runtime.approve_action(action.action_id, str(user.id)) for _ in range(4)]
    )

    assert all("error" in r for r in results)
    assert executor.calls == []


# ---------------------------------------------------------------------------
# Ownership
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_approving_another_users_action_is_refused_and_leaves_it_pending(
    session_factory,
):
    """A foreign approval must neither execute nor consume the action —
    burning someone else's approval would be a silent denial-of-service."""
    owner, _ = await make_user(session_factory, "owner@example.com")
    stranger, _ = await make_user(session_factory, "stranger@example.com")
    runtime, executor, _ = _runtime(session_factory)
    action = await _park(session_factory, owner)

    result = await runtime.approve_action(action.action_id, str(stranger.id))

    assert "error" in result
    assert executor.calls == []
    store = DbApprovalStore(session_factory=session_factory)
    assert [p.action_id for p in await store.list_pending(str(owner.id))] == [
        action.action_id
    ]


@pytest.mark.asyncio
async def test_owner_and_stranger_racing_the_same_action_only_runs_for_the_owner(
    session_factory,
):
    """Ownership must hold under interleaving, not just in isolation."""
    owner, _ = await make_user(session_factory, "owner2@example.com")
    stranger, _ = await make_user(session_factory, "stranger2@example.com")
    runtime, executor, _ = _runtime(session_factory)
    action = await _park(session_factory, owner)

    owner_result, stranger_result = await asyncio.gather(
        runtime.approve_action(action.action_id, str(owner.id)),
        runtime.approve_action(action.action_id, str(stranger.id)),
    )

    assert "error" in stranger_result
    assert "error" not in owner_result
    assert len(executor.calls) == 1
    assert executor.calls[0]["user_id"] == str(owner.id)


# ---------------------------------------------------------------------------
# Concurrent chat turns for one user
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_concurrent_chat_turns_for_one_user_do_not_interfere(session_factory):
    """Six overlapping turns for the SAME user each get their own answer.

    A shared mutable message list or a cache keyed only by user would show
    up here as one turn answering another turn's question.
    """
    user, _ = await make_user(session_factory, "parallelchat@example.com")
    provider = EchoProvider()
    runtime, _, _ = _runtime(session_factory, provider=provider)

    prompts = [f"question-{i}" for i in range(6)]
    responses = await asyncio.gather(
        *[
            runtime.chat(
                messages=[{"role": "user", "content": prompt}],
                tools=[],
                user_id=str(user.id),
                conversation_id=f"conv-{i}",
            )
            for i, prompt in enumerate(prompts)
        ]
    )

    assert [r.content for r in responses] == [f"answer:{p}" for p in prompts]
    # Each turn reached the provider with exactly its own prompt.
    assert len(provider.seen) == 6
    assert sorted(str(m[-1]["content"]) for m in provider.seen) == sorted(prompts)


@pytest.mark.asyncio
async def test_concurrent_chat_turns_park_independent_approvals(session_factory):
    """Four overlapping turns that each hit a write tool must produce four
    distinct pending actions with their own arguments — a shared action id
    or crossed arguments would let one approval send another's email."""
    user, _ = await make_user(session_factory, "parallelpark@example.com")
    runtime, executor, _ = _runtime(
        session_factory, provider=ToolThenAnswerProvider(SEND_EMAIL)
    )
    tools = build_tools([ConnectorSpec("google_workspace")])

    markers = [f"send-{i}" for i in range(4)]
    # The persisted action carries the originating conversation (FK).
    conversations = {
        m: await _make_conversation(session_factory, user, m) for m in markers
    }
    responses = await asyncio.gather(
        *[
            runtime.chat(
                messages=[{"role": "user", "content": marker}],
                tools=tools,
                user_id=str(user.id),
                conversation_id=conversations[marker],
            )
            for marker in markers
        ]
    )

    assert executor.calls == [], "an approval-gated write must never auto-run"
    parked = [p for r in responses for p in r.pending_approvals]
    assert len(parked) == 4
    assert len({p.action_id for p in parked}) == 4
    assert sorted(p.arguments["to"] for p in parked) == sorted(
        f"{m}@school.edu" for m in markers
    )
    # Each parked action kept its OWN conversation — crossed ids would send
    # one turn's approval result into another turn's transcript.
    for approval in parked:
        marker = approval.arguments["to"].split("@")[0]
        assert approval.conversation_id == conversations[marker]

    pending = await runtime.list_pending_approvals(str(user.id))
    assert {p.action_id for p in pending} == {p.action_id for p in parked}


@pytest.mark.asyncio
async def test_rate_limiter_is_exact_under_concurrent_calls():
    """The sliding window must admit exactly ``limit`` messages even when
    twenty arrive in the same event-loop tick; an off-by-one here is how a
    "rate limited" account still gets to spend real provider budget."""
    from api.routes.agent import UserRateLimiter

    limiter = UserRateLimiter()

    async def attempt() -> bool:
        await asyncio.sleep(0)
        return limiter.allow("user-1", 5)

    verdicts = await asyncio.gather(*[attempt() for _ in range(20)])
    assert sum(verdicts) == 5


@pytest.mark.asyncio
async def test_rate_limiter_isolates_users_under_concurrency():
    """One user's burst must not consume another user's budget."""
    from api.routes.agent import UserRateLimiter

    limiter = UserRateLimiter()

    async def attempt(user_id: str) -> tuple[str, bool]:
        await asyncio.sleep(0)
        return user_id, limiter.allow(user_id, 3)

    calls = [attempt("user-a") for _ in range(10)] + [
        attempt("user-b") for _ in range(10)
    ]
    verdicts = await asyncio.gather(*calls)

    assert sum(ok for uid, ok in verdicts if uid == "user-a") == 3
    assert sum(ok for uid, ok in verdicts if uid == "user-b") == 3


class _FakeClock:
    """Stand-in for the ``time`` module the limiter reads.

    The limiter's whole contract is time-relative, so driving it with a real
    clock would mean either sleeping past a 60s window or asserting nothing
    about expiry. Only ``monotonic`` is used by the module under test.
    """

    def __init__(self) -> None:
        self.now = 0.0

    def monotonic(self) -> float:
        return self.now


def test_rate_limiter_does_not_retain_users_it_no_longer_tracks(monkeypatch):
    """The limiter must not accumulate one entry per distinct user id it has
    ever seen. A worker serving a large user base is long-lived; an entry
    that is never reclaimed is a leak that only shows up as steadily rising
    RSS weeks after deploy, with no request able to explain it."""
    import api.routes.agent as agent_routes

    clock = _FakeClock()
    monkeypatch.setattr(agent_routes, "time", clock)
    limiter = agent_routes.UserRateLimiter()

    # One-shot users, each arriving a second after the last: by the time
    # user N calls, everyone before N-60 is outside the window and their
    # state carries no information at all.
    for i in range(2000):
        clock.now = float(i)
        assert limiter.allow(f"user-{i}", 5) is True

    window_users = int(agent_routes.UserRateLimiter._WINDOW_SECONDS)
    assert len(limiter._events) <= window_users + 10, (
        f"tracked {len(limiter._events)} users after 2000 distinct callers; "
        "state must stay proportional to users active in the window"
    )


def test_rate_limiter_eviction_never_resets_a_throttled_user(monkeypatch):
    """Reclaiming stale entries must not hand a throttled user a fresh
    window. The victim is the least-recently-used key here — exactly the
    one an eviction pass looks at first — so an eviction policy that goes
    by age-of-entry instead of age-of-events would silently let a rate
    limited account keep spending provider budget."""
    import api.routes.agent as agent_routes

    clock = _FakeClock()
    monkeypatch.setattr(agent_routes, "time", clock)
    limiter = agent_routes.UserRateLimiter()

    assert [limiter.allow("victim", 3) for _ in range(3)] == [True, True, True]
    assert limiter.allow("victim", 3) is False

    # Heavy churn from other users, all inside the victim's 60s window, so
    # the victim becomes the oldest entry without its events expiring.
    for i in range(500):
        clock.now = 0.001 * i
        limiter.allow(f"other-{i}", 5)

    clock.now = 59.0
    assert limiter.allow("victim", 3) is False, "throttle lost to eviction pressure"

    # ...and the window still opens on its own schedule once it truly ages
    # out, so the fix cannot be "never evict the victim".
    clock.now = 61.0
    assert limiter.allow("victim", 3) is True


# ---------------------------------------------------------------------------
# Orphaned-turn persistence after a client disconnect
# ---------------------------------------------------------------------------


class StallingProvider:
    """Answers only after a delay, leaving a window to disconnect inside."""

    def __init__(self, delay: float = 0.3) -> None:
        self._delay = delay

    async def complete(self, messages, tools=None):
        await asyncio.sleep(self._delay)
        return LLMResponse(content="finished after the client left")

    async def stream(self, messages, tools=None):
        yield "done"


class _NonCoroutineAwaitable:
    """Awaitable that is NOT a coroutine — the exact shape
    ``asyncio.create_task`` rejects with TypeError.

    A Future, a task, and anything implementing ``__await__`` all satisfy the
    declared ``Awaitable`` contract of ``on_orphaned`` while failing that
    check, so this stands in for every such caller.
    """

    def __init__(self, sink: list, response) -> None:
        self._sink = sink
        self._response = response

    def __await__(self):
        self._sink.append(self._response)
        return iter(())  # completes immediately, yields to no one


class RecordingLogger:
    """Captures structlog ``error`` calls; other levels are no-ops."""

    def __init__(self) -> None:
        self.errors: list[tuple[str, dict]] = []

    def error(self, event, **kwargs) -> None:
        self.errors.append((event, kwargs))

    def __getattr__(self, _name):
        return lambda *args, **kwargs: None


async def _orphan_stream(runtime, on_orphaned) -> None:
    """Start a streaming turn and abandon it mid-flight — what Starlette
    does to the response generator when the client disconnects."""
    agen = runtime.stream_chat(
        messages=[{"role": "user", "content": "hi"}],
        tools=[],
        user_id="u1",
        on_orphaned=on_orphaned,
    )

    async def consume():
        async for _event in agen:
            pass

    consumer = asyncio.create_task(consume())
    await asyncio.sleep(0.05)
    consumer.cancel()
    await asyncio.gather(consumer, return_exceptions=True)


async def _wait_for(predicate, timeout: float = 2.0) -> bool:
    deadline = asyncio.get_running_loop().time() + timeout
    while asyncio.get_running_loop().time() < deadline:
        if predicate():
            return True
        await asyncio.sleep(0.02)
    return predicate()


@pytest.mark.asyncio
async def test_orphaned_callback_may_return_any_awaitable(session_factory):
    """``on_orphaned`` is declared as returning an Awaitable, but the
    disconnect path scheduled it with ``asyncio.create_task``, which accepts
    a coroutine and nothing else. The TypeError would be raised inside a
    done-callback — handed to the loop's exception handler, never to a
    caller — so the persistence of a turn whose side effects already
    happened would fail with nothing tying it to the request."""
    runtime, _, _ = _runtime(session_factory, provider=StallingProvider())
    persisted: list = []

    def on_orphaned(response):
        return _NonCoroutineAwaitable(persisted, response)

    loop = asyncio.get_running_loop()
    previous_handler = loop.get_exception_handler()
    unhandled: list = []
    loop.set_exception_handler(lambda _loop, context: unhandled.append(context))
    try:
        await _orphan_stream(runtime, on_orphaned)
        assert await _wait_for(lambda: bool(persisted)), "orphaned turn never persisted"
    finally:
        loop.set_exception_handler(previous_handler)

    assert [r.content for r in persisted] == ["finished after the client left"]
    assert unhandled == [], f"exception escaped into the event loop: {unhandled}"


@pytest.mark.asyncio
async def test_failing_orphaned_callback_is_logged_not_discarded(
    session_factory, monkeypatch
):
    """A callback that raises must leave a log line. On a detached task
    nobody retrieves, the exception surfaces (if ever) as a GC-time warning
    with no request context — the failure to record a real side effect would
    be invisible exactly when it matters."""
    import services.agent.runtime as runtime_module

    recorder = RecordingLogger()
    monkeypatch.setattr(runtime_module, "logger", recorder)

    runtime, _, _ = _runtime(session_factory, provider=StallingProvider())
    invoked: list = []

    async def on_orphaned(response):
        invoked.append(response)
        raise RuntimeError("transcript write failed")

    loop = asyncio.get_running_loop()
    previous_handler = loop.get_exception_handler()
    unhandled: list = []
    loop.set_exception_handler(lambda _loop, context: unhandled.append(context))
    try:
        await _orphan_stream(runtime, on_orphaned)
        assert await _wait_for(
            lambda: any(e == "orphaned_turn_persist_failed" for e, _ in recorder.errors)
        ), f"callback failure was never logged; errors={recorder.errors}"
    finally:
        loop.set_exception_handler(previous_handler)

    assert len(invoked) == 1
    logged = next(kw for e, kw in recorder.errors if e == "orphaned_turn_persist_failed")
    assert "transcript write failed" in logged["error"]
    assert unhandled == [], f"exception escaped into the event loop: {unhandled}"


# ---------------------------------------------------------------------------
# Executor failure modes
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_executor_exception_mid_turn_records_an_error_result(session_factory):
    """A connector blowing up must degrade to an error result inside the
    turn, not propagate out as an unhandled exception (a 500 for the user
    and a turn whose partial side effects are recorded nowhere)."""
    user, _ = await make_user(session_factory, "boom@example.com")
    runtime, executor, audit = _runtime(
        session_factory,
        provider=ToolThenAnswerProvider("canvas.get_courses", write=False),
        executor=ExplodingExecutor(),
    )
    tools = build_tools([ConnectorSpec("canvas")])

    response = await runtime.chat(
        messages=[{"role": "user", "content": "list my courses"}],
        tools=tools,
        user_id=str(user.id),
    )

    assert executor.calls == ["canvas.get_courses"]
    assert response.content == "all done"
    assert len(response.tool_calls) == 1
    assert "connector unavailable" in str(response.tool_calls[0]["result"])
    # The failure is still auditable: intent and outcome were both written.
    assert any(e["event"] == "tool_executing" for e in audit.entries)
    assert any(e["event"] == "tool_executed" for e in audit.entries)


@pytest.mark.asyncio
async def test_one_failing_tool_does_not_break_other_concurrent_turns(session_factory):
    """A connector failing for one user's turn must stay contained; the
    other in-flight turns still complete normally."""
    user, _ = await make_user(session_factory, "boomparallel@example.com")
    runtime, executor, _ = _runtime(
        session_factory,
        provider=ToolThenAnswerProvider("canvas.get_courses", write=False),
        executor=CountingExecutor(fail_marker="turn-2"),
    )
    tools = build_tools([ConnectorSpec("canvas")])

    markers = [f"turn-{i}" for i in range(4)]
    responses = await asyncio.gather(
        *[
            runtime.chat(
                messages=[{"role": "user", "content": marker}],
                tools=tools,
                user_id=str(user.id),
                conversation_id=f"conv-{marker}",
            )
            for marker in markers
        ]
    )

    assert len(executor.calls) == 4
    assert all(r.content == "all done" for r in responses)
    failed = [
        r
        for r in responses
        if "connector unavailable" in str(r.tool_calls[0]["result"])
    ]
    assert len(failed) == 1


@pytest.mark.asyncio
async def test_executor_exception_during_approval_is_returned_not_raised(
    session_factory,
):
    """Approval consumes the action before executing, so an executor crash
    must come back as a result the caller can render — raising here would
    500 the request and strand an already-consumed approval."""
    user, _ = await make_user(session_factory, "approveboom@example.com")
    runtime, executor, audit = _runtime(session_factory, executor=ExplodingExecutor())
    action = await _park(session_factory, user)

    result = await runtime.approve_action(action.action_id, str(user.id))

    assert result["tool"] == SEND_EMAIL
    assert "connector unavailable" in str(result["result"])
    assert executor.calls == [SEND_EMAIL]
    assert any(e["event"] == "tool_approved_and_executed" for e in audit.entries)

    # The action is still consumed — a failed send must not be retryable by
    # re-approving, which is how a duplicate email happens.
    again = await runtime.approve_action(action.action_id, str(user.id))
    assert "error" in again
    assert executor.calls == [SEND_EMAIL]


# ---------------------------------------------------------------------------
# HTTP layer
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_two_concurrent_approval_posts_yield_exactly_one_200(
    client, session_factory
):
    """The race as a user actually triggers it: two POSTs to
    /api/agent/approvals/{id} in flight at once."""
    from api.routes import agent as agent_routes
    from main import app

    runtime, executor, _ = _runtime(session_factory)
    app.dependency_overrides[agent_routes.get_runtime] = lambda: runtime
    try:
        user, token = await make_user(session_factory, "httprace@example.com")
        action = await _park(session_factory, user)

        first, second = await asyncio.gather(
            client.post(
                f"/api/agent/approvals/{action.action_id}",
                headers=auth_headers(token),
                json={"approved": True},
            ),
            client.post(
                f"/api/agent/approvals/{action.action_id}",
                headers=auth_headers(token),
                json={"approved": True},
            ),
        )

        statuses = sorted([first.status_code, second.status_code])
        assert statuses == [200, 404], f"got {statuses}"
        assert len(executor.calls) == 1
    finally:
        app.dependency_overrides.pop(agent_routes.get_runtime, None)


@pytest.mark.asyncio
async def test_concurrent_approve_and_deny_posts_yield_exactly_one_200(
    client, session_factory
):
    """Approve and deny POSTs racing over HTTP: one decision is recorded and
    the tool runs at most once (never, if the denial won)."""
    from api.routes import agent as agent_routes
    from main import app

    runtime, executor, _ = _runtime(session_factory)
    app.dependency_overrides[agent_routes.get_runtime] = lambda: runtime
    try:
        user, token = await make_user(session_factory, "httpmixed@example.com")
        action = await _park(session_factory, user)

        approve, deny = await asyncio.gather(
            client.post(
                f"/api/agent/approvals/{action.action_id}",
                headers=auth_headers(token),
                json={"approved": True},
            ),
            client.post(
                f"/api/agent/approvals/{action.action_id}",
                headers=auth_headers(token),
                json={"approved": False},
            ),
        )

        statuses = sorted([approve.status_code, deny.status_code])
        assert statuses == [200, 404], f"got {statuses}"
        if approve.status_code == 200:
            assert len(executor.calls) == 1
        else:
            assert executor.calls == []
    finally:
        app.dependency_overrides.pop(agent_routes.get_runtime, None)


@pytest.mark.asyncio
async def test_foreign_approval_post_is_refused_without_executing(
    client, session_factory
):
    """Ownership is enforced at the HTTP edge too: a valid JWT for another
    account cannot spend someone else's pending approval."""
    from api.routes import agent as agent_routes
    from main import app

    runtime, executor, _ = _runtime(session_factory)
    app.dependency_overrides[agent_routes.get_runtime] = lambda: runtime
    try:
        owner, _owner_token = await make_user(session_factory, "httpowner@example.com")
        _stranger, stranger_token = await make_user(
            session_factory, "httpstranger@example.com"
        )
        action = await _park(session_factory, owner)

        resp = await client.post(
            f"/api/agent/approvals/{action.action_id}",
            headers=auth_headers(stranger_token),
            json={"approved": True},
        )

        assert resp.status_code == 404
        assert executor.calls == []
        store = DbApprovalStore(session_factory=session_factory)
        assert len(await store.list_pending(str(owner.id))) == 1
    finally:
        app.dependency_overrides.pop(agent_routes.get_runtime, None)
