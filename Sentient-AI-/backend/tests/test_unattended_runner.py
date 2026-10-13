"""Tests for the unattended runner (services/automation/turns.py and
api/routes/agent.build_unattended_runner): a run writes its own message into
the task's conversation (made once, then reused), hands the runtime only that
message, the fenced tools, no memory block, no channel, an ``unattended:`` task
id and the UnattendedRun contract (the owner's prompt as trusted text, the
per-run cap from the owner's settings, the 180-minute card TTL), stores the
reply with its usage, and maps what happened to the outcome's status: skipped
for the daily budget, over budget, a parked card, stopped, timed out, a
provider that is not set up or failed.

Why it exists: this is the one place an agent turn starts with nobody
watching; each of these is a rule the runtime's fence relies on the runner to
set. A fake runtime and in-memory SQLite; no network, no model.
"""

from __future__ import annotations

import asyncio
import uuid
from types import SimpleNamespace
from typing import Any

import pytest
from sqlalchemy import select

from services.agent.providers import ProviderError, ProviderNotConfigured
from services.agent.runtime import AgentResponse, BlockedAction, PendingApproval, Tool
from services.automation.runner import UnattendedRequest
from services.automation.turns import UnattendedTurnRunner
from tests.conftest import make_user


def tool(name: str) -> Tool:
    return Tool(name=name, description=name, parameters={}, connector_type=name.split(".")[0])


class FakeRuntime:
    def __init__(self, response=None, error=None, hang=False):
        self.response = response or AgentResponse(
            content="Two things are due.",
            usage={"input_tokens": 300, "output_tokens": 40},
            provider="anthropic",
            model="claude-sonnet-4-6",
        )
        self.error = error
        self.hang = hang
        self.calls: list[dict[str, Any]] = []

    async def chat(self, **kwargs):
        self.calls.append(kwargs)
        if self.hang:
            await asyncio.sleep(10)
        if self.error is not None:
            raise self.error
        return self.response


def runner(session_factory, runtime, *, settings=None, tools=None):
    offered = tools or [
        tool("canvas.get_upcoming"),
        tool("canvas.get_courses"),
        tool("reminders.now"),
        tool("reminders.create"),
        tool("tools.find"),
    ]

    async def build_context(user, db, conversation):
        return SimpleNamespace(tools=offered, memory_block="MEMORIES", permissions_text="<permissions>p</permissions>")

    async def settings_source():
        return settings or {"run_cap_cents": 5, "day_cap_cents": 25, "runs_per_day": 24}

    from api.routes.agent import _usage_columns

    return UnattendedTurnRunner(
        runtime=lambda: runtime,
        session_factory=session_factory,
        build_context=build_context,
        usage_columns=_usage_columns,
        settings=settings_source,
    )


def request(user, **overrides) -> UnattendedRequest:
    fields: dict[str, Any] = {
        "user_id": str(user.id),
        "origin": "schedule:abc",
        "label": "Canvas summary",
        "prompt": "Summarise what is due on Canvas.",
        "reads": ("canvas.get_upcoming",),
        "writes": ("reminders.create",),
        "conversation_title": "Scheduled: Canvas summary",
        "run_id": "run-1",
    }
    fields.update(overrides)
    return UnattendedRequest(**fields)


async def messages(session_factory, conversation_id):
    from models.conversation import Message

    async with session_factory() as session:
        return list(
            (
                await session.execute(
                    select(Message)
                    .where(Message.conversation_id == uuid.UUID(conversation_id))
                    .order_by(Message.created_at)
                )
            )
            .scalars()
            .all()
        )


@pytest.mark.asyncio
async def test_a_run_gets_a_fresh_fenced_memoryless_turn_and_its_reply_is_stored(session_factory):
    from models.conversation import Conversation

    user, _ = await make_user(session_factory, "runner@example.com")
    runtime = FakeRuntime()
    outcome = await runner(session_factory, runtime).run(request(user))
    assert outcome.status == "ok" and outcome.reply == "Two things are due."
    assert outcome.usage == {"input_tokens": 300, "output_tokens": 40} and outcome.cost_usd > 0
    [call] = runtime.calls
    assert len(call["messages"]) == 1 and call["messages"][0]["role"] == "user"
    assert "Summarise what is due on Canvas." in call["messages"][0]["content"]
    assert call["memory_block"] is None and call["channel"] is None
    assert call["task_id"] == "unattended:run-1"
    assert call["permissions_text"] == "<permissions>p</permissions>"
    assert {t.name for t in call["tools"]} == {"canvas.get_upcoming", "reminders.now", "reminders.create"}
    run = call["unattended"]
    assert run.reads == frozenset({"canvas.get_upcoming", "reminders.now"})
    assert run.writes == frozenset({"reminders.create"})
    assert run.trusted_text == "Summarise what is due on Canvas."
    assert run.max_usd == pytest.approx(0.05) and run.card_ttl_minutes == 180 and run.origin == "schedule:abc"
    async with session_factory() as session:
        conversation = await session.get(Conversation, uuid.UUID(outcome.conversation_id))
    assert conversation.title == "Scheduled: Canvas summary" and conversation.origin == "schedule:abc"
    stored = await messages(session_factory, outcome.conversation_id)
    assert [m.role.value for m in stored] == ["user", "assistant"]
    assert stored[1].input_tokens == 300 and stored[1].llm_model == "claude-sonnet-4-6"
    assert outcome.message_id == str(stored[1].id)


@pytest.mark.asyncio
async def test_the_conversation_is_reused_and_a_deleted_one_is_made_again(session_factory):
    from models.conversation import Conversation

    user, _ = await make_user(session_factory, "reuse@example.com")
    first = await runner(session_factory, FakeRuntime()).run(request(user))
    again = await runner(session_factory, FakeRuntime()).run(request(user, conversation_id=first.conversation_id))
    assert again.conversation_id == first.conversation_id
    assert len(await messages(session_factory, first.conversation_id)) == 4
    async with session_factory() as session:
        await session.delete(await session.get(Conversation, uuid.UUID(first.conversation_id)))
        await session.commit()
    fresh = await runner(session_factory, FakeRuntime()).run(request(user, conversation_id=first.conversation_id))
    assert fresh.conversation_id != first.conversation_id


@pytest.mark.asyncio
async def test_a_foreign_conversation_is_never_written_into(session_factory):
    from models.conversation import Conversation

    owner, _ = await make_user(session_factory, "runner-owner@example.com")
    other, _ = await make_user(session_factory, "runner-other@example.com")
    foreign = uuid.uuid4()
    async with session_factory() as session:
        session.add(Conversation(id=foreign, user_id=other.id, title="Private"))
        await session.commit()
    outcome = await runner(session_factory, FakeRuntime()).run(request(owner, conversation_id=str(foreign)))
    assert outcome.conversation_id != str(foreign)
    assert await messages(session_factory, str(foreign)) == []


@pytest.mark.asyncio
async def test_an_exhausted_daily_budget_skips_the_run(session_factory):
    from services.automation.ledger import AutomationLedger

    user, _ = await make_user(session_factory, "runner-budget@example.com")
    ledger = AutomationLedger(session_factory)
    run_id = await ledger.start_run(user.id, "schedule:x", "schedule")
    await ledger.finish_run(run_id, status="ok", cost_usd=0.30)
    runtime = FakeRuntime()
    outcome = await runner(session_factory, runtime).run(request(user))
    assert outcome.status == "skipped_budget" and runtime.calls == []
    left = await runner(session_factory, runtime).budget_left(str(user.id))
    assert left.exhausted and left.runs_left == 23


@pytest.mark.asyncio
async def test_a_run_does_not_count_against_its_own_budget(session_factory):
    from services.automation.ledger import AutomationLedger

    user, _ = await make_user(session_factory, "runner-own-row@example.com")
    ledger = AutomationLedger(session_factory)
    settings = {"run_cap_cents": 5, "day_cap_cents": 25, "runs_per_day": 1}
    # The sweepers open the occurrence's ledger row ("running") before the
    # run; with one run a day allowed, that run still goes ahead.
    run_id = await ledger.start_run(user.id, "schedule:x", "schedule")
    runtime = FakeRuntime()
    shared = runner(session_factory, runtime, settings=settings)
    outcome = await shared.run(request(user, run_id=run_id))
    assert outcome.status == "ok" and len(runtime.calls) == 1
    await ledger.finish_run(run_id, status="ok", cost_usd=0.01)
    # The next one is over the day's single run.
    second = await ledger.start_run(user.id, "schedule:y", "schedule")
    assert (await shared.run(request(user, run_id=second))).status == "skipped_budget"
    assert len(runtime.calls) == 1
    assert (await shared.budget_left(str(user.id), exclude_run_id=second)).runs_left == 0


@pytest.mark.asyncio
async def test_a_run_with_no_free_slot_in_time_is_skipped_busy(session_factory):
    user, _ = await make_user(session_factory, "runner-busy@example.com")
    runtime = FakeRuntime()
    shared = runner(session_factory, runtime)
    shared._slots = asyncio.Semaphore(1)
    await shared._slots.acquire()  # another run holds the only slot
    outcome = await shared.run(request(user, queue_wait_s=0.05))
    assert outcome.status == "skipped_busy" and outcome.run_id == "run-1" and runtime.calls == []
    # A slot that frees while the run waits: it runs, and its own deadline
    # starts only then (the wait is not charged to it).
    waiting = asyncio.create_task(shared.run(request(user, queue_wait_s=5, deadline_s=0.2)))
    await asyncio.sleep(0.4)
    assert not waiting.done()
    shared._slots.release()
    assert (await waiting).status == "ok" and len(runtime.calls) == 1


@pytest.mark.asyncio
async def test_the_per_run_cap_never_exceeds_what_is_left_of_the_day(session_factory):
    from services.automation.ledger import AutomationLedger

    user, _ = await make_user(session_factory, "runner-left@example.com")
    ledger = AutomationLedger(session_factory)
    run_id = await ledger.start_run(user.id, "schedule:x", "schedule")
    await ledger.finish_run(run_id, status="ok", cost_usd=0.23)
    runtime = FakeRuntime()
    await runner(session_factory, runtime).run(request(user))
    assert runtime.calls[0]["unattended"].max_usd == pytest.approx(0.02)


@pytest.mark.parametrize(
    "response, status",
    [
        (AgentResponse(content="Stopped.", stopped=True), "stopped"),
        (AgentResponse(content="limit", unattended_stop="budget"), "over_budget"),
        (
            AgentResponse(
                content="Waiting.",
                pending_approvals=[PendingApproval(action_id="a", tool_name="reminders.create", arguments={}, reason="r")],
            ),
            "card_parked",
        ),
    ],
)
@pytest.mark.asyncio
async def test_outcome_statuses(session_factory, response, status):
    user, _ = await make_user(session_factory, f"status-{uuid.uuid4().hex[:6]}@example.com")
    outcome = await runner(session_factory, FakeRuntime(response)).run(request(user))
    assert outcome.status == status
    if status == "card_parked":
        assert outcome.cards == 1


@pytest.mark.asyncio
async def test_refused_calls_are_named_for_the_delivery(session_factory):
    user, _ = await make_user(session_factory, "refused@example.com")
    response = AgentResponse(
        content="Partly done.",
        blocked_actions=[
            BlockedAction("canvas.get_courses", "no", "unattended_fence"),
            BlockedAction("web.fetch_page", "no", "unattended_taint"),
            BlockedAction("x.y", "no", "prompt_guard"),
        ],
    )
    outcome = await runner(session_factory, FakeRuntime(response)).run(request(user))
    assert outcome.blocked == ("canvas.get_courses", "web.fetch_page")


@pytest.mark.parametrize(
    "error, status",
    [
        (ProviderNotConfigured("gemini", reason="not_set_up"), "not_configured"),
        (ProviderError("gemini", 500, "server error"), "failed"),
        (ValueError("bug"), "failed"),
    ],
)
@pytest.mark.asyncio
async def test_provider_failures_become_statuses_and_close_the_turn(session_factory, error, status):
    user, _ = await make_user(session_factory, f"fail-{uuid.uuid4().hex[:6]}@example.com")
    outcome = await runner(session_factory, FakeRuntime(error=error)).run(request(user))
    assert outcome.status == status
    stored = await messages(session_factory, outcome.conversation_id)
    assert [m.role.value for m in stored] == ["user", "assistant"]


@pytest.mark.asyncio
async def test_a_run_past_its_deadline_times_out(session_factory):
    user, _ = await make_user(session_factory, "deadline@example.com")
    outcome = await runner(session_factory, FakeRuntime(hang=True)).run(request(user, deadline_s=0.05))
    assert outcome.status == "timed_out"


@pytest.mark.asyncio
async def test_an_inactive_account_does_not_run(session_factory):
    from models.user import User

    user, _ = await make_user(session_factory, "runner-inactive@example.com")
    async with session_factory() as session:
        (await session.get(User, user.id)).is_active = False
        await session.commit()
    runtime = FakeRuntime()
    outcome = await runner(session_factory, runtime).run(request(user))
    assert outcome.status == "failed" and runtime.calls == []


@pytest.mark.asyncio
async def test_at_most_two_runs_at_once(session_factory):
    user, _ = await make_user(session_factory, "runner-slots@example.com")
    gate = asyncio.Event()
    active = {"now": 0, "peak": 0}

    class Slow(FakeRuntime):
        async def chat(self, **kwargs):
            active["now"] += 1
            active["peak"] = max(active["peak"], active["now"])
            await gate.wait()
            active["now"] -= 1
            return self.response

    shared = runner(session_factory, Slow())
    tasks = [asyncio.create_task(shared.run(request(user, run_id=f"r{i}"))) for i in range(3)]
    # Each run writes its conversation and message first (slower on
    # Postgres): wait for two to reach the runtime, then give a third the
    # chance to (wrongly) start.
    for _ in range(200):
        if active["peak"] >= 2:
            break
        await asyncio.sleep(0.025)
    await asyncio.sleep(0.2)
    assert active["peak"] == 2
    gate.set()
    await asyncio.gather(*tasks)
    assert active["peak"] == 2


@pytest.mark.asyncio
async def test_build_unattended_runner_uses_the_chat_pipeline_without_memory_or_mcp(session_factory):
    from api.routes.agent import build_unattended_runner
    from models.memory import Memory

    user, _ = await make_user(session_factory, "wired-runner@example.com")
    async with session_factory() as session:
        session.add(Memory(user_id=user.id, content="Prefers mornings"))
        await session.commit()
    runtime = FakeRuntime()
    app = SimpleNamespace(state=SimpleNamespace(agent_runtime=runtime, installation=None, mcp_catalog=object()))
    wired = build_unattended_runner(app, session_factory)
    outcome = await wired.run(request(user, reads=("web.search",), writes=()))
    assert outcome.status == "ok"
    [call] = runtime.calls
    assert call["memory_block"] is None
    assert {t.name for t in call["tools"]} == {"web.search", "reminders.now"}
    assert "<permissions>" in call["permissions_text"]
