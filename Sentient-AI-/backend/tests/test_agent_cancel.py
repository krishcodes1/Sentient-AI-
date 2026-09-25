"""Tests for the per-user cancel registry (services/agent/cancel.py): a stop
request is per user, clearing it lifts it, and the runtime lifts it at the
start of every turn.

Why it exists: computer_control checks this flag before every desktop action
(and again just before input is sent), so a stop must hold for exactly the
user who asked, and a new message must not stay stopped forever.
"""

from __future__ import annotations

import threading

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


@pytest.mark.asyncio
async def test_the_runtime_clears_the_users_flag_at_the_start_of_a_turn():
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
