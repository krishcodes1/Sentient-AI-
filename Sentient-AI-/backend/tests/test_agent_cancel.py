"""Tests for the per-user stop registry (services/agent/cancel.py): a stop
is per user, it ends the work accepted before it and not the work accepted
after, a later mark never lifts it for older work, ``watching`` scopes the
answer to the work in progress (threads included), and a new turn starts
un-stopped.

Why it exists: the runtime checks this at every step boundary and
computer_control before every desktop action (and again just before input is
sent), so a stop must hold for exactly the user who asked and exactly the
work it was meant for: not lifted for a running turn by a new message or an
Approve tap, and not applied to a message sent after it.
"""

from __future__ import annotations

import asyncio
import threading
from datetime import datetime, timedelta, timezone

import pytest

from services.agent import cancel


@pytest.fixture(autouse=True)
def _clean_registry():
    cancel.clear("u1")
    cancel.clear("u2")
    yield
    cancel.clear("u1")
    cancel.clear("u2")


def test_nothing_is_cancelled_until_asked():
    assert cancel.is_cancelled("u1") is False


def test_a_request_holds_for_that_user_only():
    cancel.request_cancel("u1")
    assert cancel.is_cancelled("u1") is True
    assert cancel.is_cancelled("u2") is False


def test_clear_lifts_the_request_and_is_idempotent():
    cancel.request_cancel("u1")
    cancel.clear("u1")
    assert cancel.is_cancelled("u1") is False
    cancel.clear("u1")  # clearing an unset flag is fine
    assert cancel.is_cancelled("u1") is False


def test_requests_do_not_stack():
    cancel.request_cancel("u1")
    cancel.request_cancel("u1")
    cancel.clear("u1")
    assert cancel.is_cancelled("u1") is False


def test_flag_is_readable_from_worker_threads():
    # The computer toolkit reads the flag inside asyncio.to_thread.
    cancel.request_cancel("u1")
    seen: list[bool] = []
    worker = threading.Thread(target=lambda: seen.append(cancel.is_cancelled("u1")))
    worker.start()
    worker.join()
    assert seen == [True]


# ── marks ──────────────────────────────────────────────────────────────────────


def test_a_stop_counts_against_work_marked_before_it_only():
    before = cancel.mark("u1")
    cancel.request_cancel("u1")
    after = cancel.mark("u1")
    assert cancel.stopped_since("u1", before) is True
    assert cancel.stopped_since("u1", after) is False
    assert cancel.stopped_since("u2", before) is False


def test_new_work_never_lifts_a_stop_for_older_work():
    """What a new message or an Approve tap does: take a fresh mark. The
    running turn's older mark still answers stopped."""
    running = cancel.mark("u1")
    cancel.request_cancel("u1")
    cancel.mark("u1")  # a new message / an Approve tap
    assert cancel.stopped_since("u1", running) is True


def test_is_cancelled_answers_for_the_work_being_watched():
    running = cancel.mark("u1")
    cancel.request_cancel("u1")
    newer = cancel.mark("u1")
    # Outside any watched work: stopped, then started something since.
    assert cancel.is_cancelled("u1") is False
    with cancel.watching("u1", running):
        assert cancel.is_cancelled("u1") is True
        with cancel.watching("u1", newer):
            assert cancel.is_cancelled("u1") is False
        assert cancel.is_cancelled("u1") is True
        # Another user's check is not answered by u1's work.
        cancel.request_cancel("u2")
        assert cancel.is_cancelled("u2") is True
    assert cancel.is_cancelled("u1") is False


@pytest.mark.asyncio
async def test_watching_reaches_the_toolkits_worker_thread():
    running = cancel.mark("u1")
    with cancel.watching("u1", running):
        assert await asyncio.to_thread(cancel.is_cancelled, "u1") is False
        cancel.request_cancel("u1")
        assert await asyncio.to_thread(cancel.is_cancelled, "u1") is True


def test_mark_since_counts_a_stop_made_after_the_card_was_raised():
    raised = datetime.now(timezone.utc) - timedelta(seconds=5)
    cancel.request_cancel("u1")
    waiting = cancel.mark_since("u1", raised)
    assert cancel.stopped_since("u1", waiting) is True


def test_mark_since_ignores_a_stop_made_before_the_card_was_raised():
    cancel.request_cancel("u1")
    raised = datetime.now(timezone.utc) + timedelta(seconds=5)
    waiting = cancel.mark_since("u1", raised)
    assert cancel.stopped_since("u1", waiting) is False
    cancel.request_cancel("u1")  # a later stop still counts
    assert cancel.stopped_since("u1", waiting) is True


def test_clear_forgets_the_stop_for_all_work():
    running = cancel.mark("u1")
    cancel.request_cancel("u1")
    cancel.clear("u1")
    assert cancel.stopped_since("u1", running) is False


@pytest.mark.asyncio
async def test_a_new_turn_starts_unstopped_by_an_earlier_stop():
    from core.config import settings
    from services.agent.providers import LLMResponse, ToolCall
    from services.agent.runtime import AgentRuntime, PromptGuard, Tool, ToolExecutor
    from tests.conftest import use_provider

    seen: list[bool] = []

    class Executor(ToolExecutor):
        async def execute(self, tool_name, arguments, user_id, approved=False, *, task_id=None):
            seen.append(cancel.is_cancelled(user_id))
            return {"ok": True}

    class Allow:
        async def check(self, user_id, tool_name, arguments):
            return "approved"

    class Provider:
        def __init__(self):
            self.responses = [
                LLMResponse(content="", tool_calls=[ToolCall(id="t1", name="web.search", arguments={})]),
                LLMResponse(content="done"),
            ]

        async def complete(self, messages, tools=None):
            return self.responses.pop(0) if self.responses else LLMResponse(content="done")

        async def stream(self, messages, tools=None):
            yield "done"

    class PassGuard(PromptGuard):
        pass

    runtime = AgentRuntime(
        config=settings,
        permission_engine=Allow(),
        prompt_guard=PassGuard(),
        tool_executor=Executor(),
    )
    use_provider(runtime, Provider())

    cancel.request_cancel("u1")
    cancel.request_cancel("u2")
    await runtime.chat(
        messages=[{"role": "user", "content": "search something"}],
        tools=[Tool(name="web.search", description="search", parameters={})],
        user_id="u1",
    )
    assert seen == [False]  # the new turn started un-stopped
    assert cancel.is_cancelled("u1") is False
    assert cancel.is_cancelled("u2") is True  # another user's stop stands
