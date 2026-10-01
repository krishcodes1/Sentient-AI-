"""Tests for the schedule sweeper (ScheduleService): it claims only due tasks
of an enabled kind, never runs one occurrence twice (two services on one
database, or a restart), skips a run more than 180 minutes late without
catching up, skips over-budget runs with one notice per 24 hours, stops a task
after five failures in a row with one message, runs at most two at once
within a deadline, records a run cut off by stop() as stopped, writes audit
rows without text, prunes old runs, rate-limits "run now", sends nudges, and
builds the daily briefing.

Why it exists: the sweeper runs agent turns and sends messages with nobody
watching; each of these limits is what keeps it from running something
twice, late, too often or too expensively. In-memory SQLite, a fake runner,
fake senders and a fixed clock; no network, no model, no Telegram.
"""

from __future__ import annotations

import asyncio
import json
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any

import pytest
from sqlalchemy import select

from services.automation.ledger import AutomationLedger
from services.automation.runner import BudgetState, UnattendedOutcome
from services.notifications.schedules import ERROR_LIMIT, ScheduleService
from services.scheduler import renderers
from tests.conftest import make_user

T0 = datetime(2026, 9, 29, 12, 0, tzinfo=timezone.utc)  # Tue 08:00 New York
DAILY = {"freq": "daily", "time": "08:00"}


class Clock:
    def __init__(self, now: datetime = T0) -> None:
        self.now = now

    def __call__(self) -> datetime:
        return self.now


class FakeRunner:
    def __init__(self, status: str = "ok", *, block: asyncio.Event | None = None, budget=None):
        self.status = status
        self.block = block
        self.requests: list[Any] = []
        self.budget = budget or BudgetState(usd_left=1.0, runs_left=10)
        self.budget_checks: list[Any] = []
        self.running = 0
        self.peak = 0

    async def run(self, request):
        self.requests.append(request)
        self.running += 1
        self.peak = max(self.peak, self.running)
        try:
            if self.block is not None:
                await self.block.wait()
            return UnattendedOutcome(
                status=self.status,
                reply="The prompt text says: here is the reply with private details.",
                usage={"input_tokens": 100, "output_tokens": 20},
                cost_usd=0.001,
                conversation_id=None,
                run_id=request.run_id,
            )
        finally:
            self.running -= 1

    async def budget_left(self, user_id, *, exclude_run_id=None):
        self.budget_checks.append(exclude_run_id)
        return self.budget


class Outbox:
    def __init__(self):
        self.sent: list[tuple[str, str, str]] = []

    def sender(self, channel: str, answer: bool = True):
        async def send(user_id, text):
            self.sent.append((channel, user_id, text))
            return answer

        return send


async def add_task(session_factory, user, **values) -> uuid.UUID:
    from models.scheduled_task import ScheduledTask

    task_id = uuid.uuid4()
    fields: dict[str, Any] = {
        "kind": "prompt",
        "label": f"Task {task_id.hex[:6]}",
        "prompt": "Summarise my Canvas due items, including the secret words ZEBRA-42.",
        "options": {"tools": ["canvas.get_upcoming"], "write_tools": []},
        "recurrence": DAILY,
        "timezone": "America/New_York",
        "channels": ["telegram"],
        "status": "active",
        "next_run_at": T0,
        "source": "agent",
        "created_at": T0 - timedelta(days=1),
        "updated_at": T0 - timedelta(days=1),
    }
    fields.update(values)
    async with session_factory() as session:
        session.add(ScheduledTask(id=task_id, user_id=user.id, **fields))
        await session.commit()
    return task_id


async def task_row(session_factory, task_id):
    from models.scheduled_task import ScheduledTask

    async with session_factory() as session:
        return await session.get(ScheduledTask, task_id)


async def runs(session_factory, task_id=None):
    from models.scheduled_task import AutomationRun

    async with session_factory() as session:
        query = select(AutomationRun)
        if task_id is not None:
            query = query.where(AutomationRun.task_id == task_id)
        return list((await session.execute(query)).scalars().all())


def service(session_factory, runner=None, outbox=None, clock=None, keys=frozenset({"scheduled_tasks"}), **kw):
    outbox = outbox or Outbox()

    async def enabled():
        if isinstance(keys, Exception):
            raise keys
        return keys

    return ScheduleService(
        session_factory,
        runner=runner or FakeRunner(),
        senders={"telegram": outbox.sender("telegram"), "slack": outbox.sender("slack")},
        enabled_keys=enabled,
        clock=clock or Clock(),
        delivery_pause_s=0,
        **kw,
    )


async def sweep(svc) -> int:
    count = await svc.sweep_once()
    await svc.wait_idle()
    return count


# ── claiming and running ───────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_a_due_task_runs_once_is_delivered_and_moves_to_its_next_run(session_factory):
    user, _ = await make_user(session_factory, "due@example.com")
    task_id = await add_task(session_factory, user)
    not_due = await add_task(session_factory, user, next_run_at=T0 + timedelta(hours=1))
    runner, outbox = FakeRunner(), Outbox()
    svc = service(session_factory, runner, outbox)
    assert await sweep(svc) == 1
    [request] = runner.requests
    assert request.origin == f"schedule:{task_id}" and request.reads == ("canvas.get_upcoming",)
    assert request.conversation_title.startswith("Scheduled: ")
    [(channel, uid, text)] = outbox.sent
    assert channel == "telegram" and uid == str(user.id) and "Tue 08:00" in text
    [run] = await runs(session_factory, task_id)
    assert run.status == "ok" and run.delivered == ["telegram"] and run.input_tokens == 100
    row = await task_row(session_factory, task_id)
    assert row.last_status == "ok" and row.consecutive_errors == 0
    assert row.next_run_at.replace(tzinfo=timezone.utc) == T0 + timedelta(days=1)
    assert await runs(session_factory, not_due) == []
    # Nothing is due any more.
    assert await sweep(svc) == 0 and len(runner.requests) == 1


@pytest.mark.asyncio
async def test_two_services_never_run_one_occurrence_twice(session_factory):
    from models.scheduled_task import ScheduledTask

    user, _ = await make_user(session_factory, "twice@example.com")
    task_id = await add_task(session_factory, user)
    runner = FakeRunner()
    a, b = service(session_factory, runner), service(session_factory, runner)
    keys = frozenset({"scheduled_tasks"})
    # First guard: the conditional claim has one winner.
    claims = await asyncio.gather(a._claim_due(T0, keys, 5), b._claim_due(T0, keys, 5))
    assert sorted(len(c) for c in claims) == [0, 1]
    [[claimed]] = [c for c in claims if c]
    assert claimed.scheduled_for == T0
    # Second guard: a worker that still holds the old due time (a restart
    # mid-claim, a slow replica) finds the occurrence already in the ledger.
    a._spawn(claimed)
    await a.wait_idle()
    assert len(runner.requests) == 1
    async with session_factory() as session:
        (await session.get(ScheduledTask, task_id)).next_run_at = T0
        await session.commit()
    assert await sweep(b) == 1
    assert len(runner.requests) == 1
    assert len(await runs(session_factory, task_id)) == 1
    ledger = AutomationLedger(session_factory)
    assert await ledger.start_run(user.id, f"schedule:{task_id}", "schedule", task_id=task_id, scheduled_for=T0) is None


@pytest.mark.asyncio
async def test_nothing_is_claimed_while_the_gate_is_off_or_unreadable(session_factory):
    user, _ = await make_user(session_factory, "gate@example.com")
    task_id = await add_task(session_factory, user)
    runner = FakeRunner()
    assert await sweep(service(session_factory, runner, keys=frozenset())) == 0
    assert await sweep(service(session_factory, runner, keys=RuntimeError("db down"))) == 0
    assert runner.requests == [] and await runs(session_factory) == []
    assert (await task_row(session_factory, task_id)).next_run_at.replace(tzinfo=timezone.utc) == T0


@pytest.mark.asyncio
async def test_the_gate_is_read_again_before_the_run(session_factory):
    user, _ = await make_user(session_factory, "regate@example.com")
    task_id = await add_task(session_factory, user)
    answers = iter([frozenset({"scheduled_tasks"}), frozenset()])
    svc = service(session_factory, FakeRunner())

    async def flipping():
        return next(answers)

    svc._enabled_keys = flipping
    assert await sweep(svc) == 1
    [run] = await runs(session_factory, task_id)
    assert run.status == "skipped_gate"


@pytest.mark.asyncio
async def test_inactive_users_are_skipped(session_factory):
    from models.user import User

    user, _ = await make_user(session_factory, "inactive@example.com")
    await add_task(session_factory, user)
    async with session_factory() as session:
        (await session.get(User, user.id)).is_active = False
        await session.commit()
    runner = FakeRunner()
    assert await sweep(service(session_factory, runner)) == 0 and runner.requests == []


@pytest.mark.asyncio
async def test_a_late_run_is_skipped_and_never_caught_up(session_factory):
    user, _ = await make_user(session_factory, "late@example.com")
    task_id = await add_task(session_factory, user, next_run_at=T0 - timedelta(hours=4))
    once = await add_task(
        session_factory,
        user,
        recurrence={"freq": "once", "time": "04:00", "date": "2026-09-29"},
        next_run_at=T0 - timedelta(hours=4),
    )
    runner = FakeRunner()
    assert await sweep(service(session_factory, runner)) == 2
    assert runner.requests == []
    assert [r.status for r in await runs(session_factory, task_id)] == ["skipped_late"]
    row = await task_row(session_factory, task_id)
    assert row.next_run_at.replace(tzinfo=timezone.utc) == T0 + timedelta(days=1)
    assert row.last_status == "skipped_late"
    assert (await task_row(session_factory, once)).status == "done"


@pytest.mark.asyncio
async def test_over_budget_runs_are_skipped_with_one_notice_a_day(session_factory):
    user, _ = await make_user(session_factory, "budget@example.com")
    first = await add_task(session_factory, user)
    second = await add_task(session_factory, user, next_run_at=T0 + timedelta(hours=1))
    clock, outbox = Clock(), Outbox()
    svc = service(session_factory, FakeRunner("skipped_budget"), outbox, clock)
    await sweep(svc)
    clock.now = T0 + timedelta(hours=1, minutes=1)
    await sweep(svc)
    assert [r.status for r in await runs(session_factory)] == ["skipped_budget", "skipped_budget"]
    notices = [t for _c, _u, t in outbox.sent if "budget" in t]
    assert len(notices) == 1 and len(outbox.sent) == 1
    assert (await task_row(session_factory, first)).last_status == "skipped_budget"
    assert (await task_row(session_factory, second)).last_status == "skipped_budget"


@pytest.mark.asyncio
async def test_a_run_with_no_free_runner_slot_is_skipped_not_failed(session_factory):
    user, _ = await make_user(session_factory, "busy@example.com")
    task_id = await add_task(session_factory, user, label="Morning summary")
    outbox = Outbox()
    runner = FakeRunner("skipped_busy")
    await sweep(service(session_factory, runner, outbox))
    assert runner.requests[0].queue_wait_s > 0
    [run] = await runs(session_factory, task_id)
    assert run.status == "skipped_busy"
    row = await task_row(session_factory, task_id)
    assert row.last_status == "skipped_busy" and row.consecutive_errors == 0 and row.status == "active"
    [(_c, _u, text)] = outbox.sent
    assert 'Skipped your scheduled task "Morning summary" for Tue 08:00' in text and "busy" in text


@pytest.mark.asyncio
async def test_waiting_for_a_runner_slot_is_not_charged_to_the_run_deadline(session_factory):
    """The real shared runner: another run holds the only slot for longer
    than this run's whole deadline; once it frees, this run goes ahead."""
    from tests.test_unattended_runner import FakeRuntime
    from tests.test_unattended_runner import runner as unattended_runner

    user, _ = await make_user(session_factory, "slot-wait@example.com")
    task_id = await add_task(session_factory, user)
    shared = unattended_runner(session_factory, FakeRuntime())
    shared._slots = asyncio.Semaphore(1)
    await shared._slots.acquire()
    svc = service(session_factory, shared, run_deadline_s=0.2, deadline_margin_s=0.1, queue_wait_s=5)
    assert await svc.sweep_once() == 1
    await asyncio.sleep(0.6)
    shared._slots.release()
    await svc.wait_idle()
    [run] = await runs(session_factory, task_id)
    assert run.status == "ok"
    assert (await task_row(session_factory, task_id)).consecutive_errors == 0


@pytest.mark.asyncio
async def test_five_failures_in_a_row_stop_the_task_with_one_message(session_factory):
    user, _ = await make_user(session_factory, "errors@example.com")
    task_id = await add_task(session_factory, user)
    clock, outbox = Clock(), Outbox()
    svc = service(session_factory, FakeRunner("failed"), outbox, clock)
    for day in range(ERROR_LIMIT + 1):
        clock.now = T0 + timedelta(days=day, minutes=1)
        await sweep(svc)
    row = await task_row(session_factory, task_id)
    assert row.status == "error" and row.consecutive_errors == ERROR_LIMIT
    assert len(await runs(session_factory, task_id)) == ERROR_LIMIT
    paused = [t for _c, _u, t in outbox.sent if "Paused your scheduled task" in t]
    assert len(paused) == 1


@pytest.mark.asyncio
async def test_at_most_two_runs_at_once(session_factory):
    user, _ = await make_user(session_factory, "concurrent@example.com")
    for _ in range(3):
        await add_task(session_factory, user)
    gate = asyncio.Event()
    runner = FakeRunner(block=gate)
    svc = service(session_factory, runner)
    assert await svc.sweep_once() == 2
    await asyncio.sleep(0.05)
    assert await svc.sweep_once() == 0  # no free slot
    gate.set()
    await svc.wait_idle()
    assert await sweep(svc) == 1
    assert runner.peak == 2 and len(runner.requests) == 3


@pytest.mark.asyncio
async def test_a_run_past_its_deadline_is_timed_out(session_factory):
    user, _ = await make_user(session_factory, "slow@example.com")
    task_id = await add_task(session_factory, user)
    svc = service(
        session_factory,
        FakeRunner(block=asyncio.Event()),
        run_deadline_s=0.05,
        deadline_margin_s=0,
        queue_wait_s=0,
    )
    await sweep(svc)
    [run] = await runs(session_factory, task_id)
    assert run.status == "timed_out"
    assert (await task_row(session_factory, task_id)).consecutive_errors == 1


@pytest.mark.asyncio
async def test_a_run_that_raises_is_recorded_as_failed(session_factory):
    user, _ = await make_user(session_factory, "raises@example.com")
    task_id = await add_task(session_factory, user)

    class Broken(FakeRunner):
        async def run(self, request):
            raise RuntimeError("https://x.example/?token=SECRET")

    await sweep(service(session_factory, Broken()))
    [run] = await runs(session_factory, task_id)
    assert run.status == "failed" and "SECRET" not in (run.error or "")
    assert (await task_row(session_factory, task_id)).consecutive_errors == 1


@pytest.mark.asyncio
async def test_stop_records_runs_in_flight_as_stopped(session_factory):
    user, _ = await make_user(session_factory, "stop@example.com")
    task_id = await add_task(session_factory, user)
    runner = FakeRunner(block=asyncio.Event())
    svc = service(session_factory, runner)
    await svc.sweep_once()
    # In flight means inside the runner: stopping while the run is still
    # writing its ledger row would cut a database call short (on Postgres
    # that strands the connection and its row lock).
    for _ in range(200):
        if runner.running:
            break
        await asyncio.sleep(0.025)
    assert runner.running == 1
    await svc.stop()
    [run] = await runs(session_factory, task_id)
    assert run.status == "stopped"


@pytest.mark.asyncio
async def test_audit_rows_hold_ids_and_statuses_never_text(session_factory):
    from models.audit import AuditLog

    user, _ = await make_user(session_factory, "audit@example.com")
    task_id = await add_task(session_factory, user, label="Private label words")
    await sweep(service(session_factory, FakeRunner()))
    async with session_factory() as session:
        rows = list(
            (await session.execute(select(AuditLog).where(AuditLog.connector_name == "schedule")))
            .scalars()
            .all()
        )
    assert [r.action for r in rows] == ["run"] and rows[0].endpoint == "schedule_sweeper"
    stored = json.dumps([r.request_data for r in rows]) + json.dumps([r.response_summary for r in rows])
    for text in ("ZEBRA-42", "Summarise", "private details", "Private label words"):
        assert text not in stored
    data = rows[0].request_data if isinstance(rows[0].request_data, dict) else json.loads(rows[0].request_data)
    assert data["task_id"] == str(task_id) and data["status"] == "ok" and data["tools"] == ["canvas.get_upcoming"]


@pytest.mark.asyncio
async def test_old_runs_are_pruned(session_factory):
    user, _ = await make_user(session_factory, "prune@example.com")
    ledger = AutomationLedger(session_factory, clock=lambda: T0 - timedelta(days=91))
    old = await ledger.start_run(user.id, "schedule:x", "manual")
    recent = await AutomationLedger(session_factory, clock=lambda: T0).start_run(user.id, "schedule:y", "manual")
    await sweep(service(session_factory))
    left = {str(r.id) for r in await runs(session_factory)}
    assert old not in left and recent in left
    assert await AutomationLedger(session_factory, clock=lambda: T0).prune() == 0


@pytest.mark.asyncio
async def test_spent_today_counts_runs_but_not_skips(session_factory):
    user, _ = await make_user(session_factory, "spent@example.com")
    ledger = AutomationLedger(session_factory, clock=lambda: T0)
    one = await ledger.start_run(user.id, "schedule:a", "schedule")
    await ledger.finish_run(one, status="ok", cost_usd=0.02)
    two = await ledger.start_run(user.id, "schedule:b", "schedule", status="skipped_late")
    await ledger.finish_run(two, status="skipped_late")
    assert await ledger.spent_today(user.id) == (0.02, 1)
    later = AutomationLedger(session_factory, clock=lambda: T0 + timedelta(hours=25))
    assert await later.spent_today(user.id) == (0.0, 0)


@pytest.mark.asyncio
async def test_run_now_is_rate_limited_gated_and_owner_scoped(session_factory):
    user, _ = await make_user(session_factory, "runnow@example.com")
    other, _ = await make_user(session_factory, "runnow-other@example.com")
    task_id = await add_task(session_factory, user, next_run_at=T0 + timedelta(hours=5))
    runner = FakeRunner()
    svc = service(session_factory, runner)
    first = await svc.run_now(user.id, task_id)
    await svc.wait_idle()
    assert first["ok"] is True and len(runner.requests) == 1
    [run] = await runs(session_factory, task_id)
    assert run.trigger == "manual"
    again = await svc.run_now(user.id, task_id)
    assert again["rate_limited"] is True and len(runner.requests) == 1
    assert (await svc.run_now(other.id, task_id))["not_found"] is True
    off = await service(session_factory, runner, keys=frozenset()).run_now(user.id, task_id)
    assert off["ok"] is False and "Scheduled tasks are off" in off["error"]


# ── nudges ──────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_nudges_render_without_a_model_and_skip_silently(session_factory):
    user, _ = await make_user(session_factory, "nudge@example.com")
    answers = {"text": "3 flashcards are due. Send /study to review."}

    async def render(session, user_id, now):
        return answers["text"]

    renderers.register_nudge_renderer("test_cards", "flashcards", render)
    try:
        runner, outbox, clock = FakeRunner(), Outbox(), Clock()
        svc = service(session_factory, runner, outbox, clock, keys=frozenset({"flashcards"}))
        task_id = await svc.upsert_nudge(
            user.id,
            renderer="test_cards",
            label="Flashcards due",
            recurrence=DAILY,
            timezone="America/New_York",
            channels=("telegram",),
        )
        # Upserting again changes the same row.
        assert await svc.upsert_nudge(
            user.id, renderer="test_cards", label="Flashcards due", recurrence=DAILY, timezone=None, channels=("telegram",)
        ) == task_id
        async with session_factory() as session:
            from models.scheduled_task import ScheduledTask

            row = await session.get(ScheduledTask, uuid.UUID(task_id))
            row.next_run_at = T0
            await session.commit()
        assert await sweep(svc) == 1
        assert runner.requests == [] and "3 flashcards are due" in outbox.sent[0][2]
        answers["text"] = None
        clock.now = T0 + timedelta(days=1, minutes=1)
        assert await sweep(svc) == 1 and len(outbox.sent) == 1
        statuses = sorted(r.status for r in await runs(session_factory, uuid.UUID(task_id)))
        assert statuses == ["ok", "skipped_empty"]
        assert await svc.cancel_nudge(user.id, renderer="test_cards") is True
        assert await svc.cancel_nudge(user.id, renderer="test_cards") is False
    finally:
        renderers.unregister_nudge_renderer("test_cards")


@pytest.mark.asyncio
async def test_a_nudge_needs_its_own_capability_not_scheduled_tasks(session_factory):
    user, _ = await make_user(session_factory, "nudge-gate@example.com")

    async def render(session, user_id, now):
        return "due"

    renderers.register_nudge_renderer("test_gate", "flashcards", render)
    try:
        task_id = await add_task(session_factory, user, kind="nudge", prompt=None, options={"renderer": "test_gate"})
        outbox = Outbox()
        assert await sweep(service(session_factory, outbox=outbox, keys=frozenset({"scheduled_tasks"}))) == 0
        # Its switch is off: the occurrence is skipped and the nudge moves on
        # to its next time (never made up later, never left due).
        row = await task_row(session_factory, task_id)
        assert row.next_run_at.replace(tzinfo=timezone.utc) == T0 + timedelta(days=1)
        assert row.last_status == "skipped_gate" and row.status == "active"
        assert outbox.sent == [] and await runs(session_factory, task_id) == []
        clock = Clock(T0 + timedelta(days=1, minutes=1))
        assert await sweep(service(session_factory, outbox=outbox, clock=clock, keys=frozenset({"flashcards"}))) == 1
        assert len(outbox.sent) == 1
    finally:
        renderers.unregister_nudge_renderer("test_gate")


@pytest.mark.asyncio
async def test_switched_off_nudges_never_crowd_out_the_due_tasks(session_factory):
    from models.scheduled_task import ScheduledTask
    from services.notifications.schedules import CLAIM_SCAN_LIMIT

    async def render(session, user_id, now):
        return "due"

    renderers.register_nudge_renderer("test_crowd", "flashcards", render)
    try:
        # More switched-off nudges than one scan reads, all due earlier than
        # the prompt task, which must still run on the first sweep.
        user, _ = await make_user(session_factory, "crowd@example.com")
        for _n in range(2 * CLAIM_SCAN_LIMIT + 5):
            await add_task(
                session_factory,
                user,
                kind="nudge",
                prompt=None,
                options={"renderer": "test_crowd"},
                next_run_at=T0 - timedelta(minutes=10),
            )
        owner, _ = await make_user(session_factory, "crowd-owner@example.com")
        task_id = await add_task(session_factory, owner)
        runner = FakeRunner()
        svc = service(session_factory, runner, keys=frozenset({"scheduled_tasks"}))
        assert await sweep(svc) == 1
        assert [r.origin for r in runner.requests] == [f"schedule:{task_id}"]
        assert await sweep(svc) == 0
        async with session_factory() as session:
            due = (
                await session.execute(
                    select(ScheduledTask).where(ScheduledTask.kind == "nudge", ScheduledTask.next_run_at <= T0)
                )
            ).scalars().all()
        assert list(due) == []
    finally:
        renderers.unregister_nudge_renderer("test_crowd")


@pytest.mark.asyncio
async def test_a_nudge_whose_renderer_is_gone_is_stopped_not_left_due(session_factory):
    user, _ = await make_user(session_factory, "nudge-gone@example.com")
    task_id = await add_task(session_factory, user, kind="nudge", prompt=None, options={"renderer": "no_such_one"})
    runner, outbox = FakeRunner(), Outbox()
    assert await sweep(service(session_factory, runner, outbox, keys=frozenset({"flashcards", "scheduled_tasks"}))) == 0
    row = await task_row(session_factory, task_id)
    assert row.status == "error" and row.last_error == "This reminder's feature is no longer available."
    assert outbox.sent == [] and await runs(session_factory, task_id) == []


# ── the briefing through the sweeper ──────────────────────────────────────────


class FakeReader:
    def __init__(self):
        self.reads: list[tuple[str, dict]] = []

    async def read(self, user_id, name, arguments, run_id):
        self.reads.append((name, arguments))
        if name == "web.research":
            return {"ok": True, "results": [{"ok": True, "title": "Rules update", "url": "https://news.example/a?utm=1", "host": "news.example"}]}, None
        return None, "not connected"


@pytest.mark.asyncio
async def test_the_briefing_runs_from_reads_and_lands_in_its_conversation(session_factory):
    from models.conversation import Conversation, Message

    user, _ = await make_user(session_factory, "briefing@example.com")
    task_id = await add_task(
        session_factory,
        user,
        kind="briefing",
        label="Daily briefing",
        prompt=None,
        options={"sections": ["canvas", "calendar"], "topic": "AI rules", "summary": False},
        channels=["telegram", "slack"],
    )
    reader, outbox, runner = FakeReader(), Outbox(), FakeRunner()
    svc = service(session_factory, runner, outbox, briefing_reader=reader, briefing_scan=lambda _t: True)
    assert await sweep(svc) == 1
    assert runner.requests == []  # no agent turn
    assert [name for name, _ in reader.reads] == ["web.research"]  # no connectors: not read
    assert {c for c, _u, _t in outbox.sent} == {"telegram", "slack"}
    text = outbox.sent[0][2]
    assert "Briefing for Tuesday 29 September" in text and "Not available: not connected." in text
    assert "https://news.example/a" in text and "utm=1" not in text
    row = await task_row(session_factory, task_id)
    assert row.conversation_id is not None
    async with session_factory() as session:
        conversation = await session.get(Conversation, row.conversation_id)
        assert conversation.origin == f"schedule:{task_id}" and conversation.title == "Scheduled: Daily briefing"
        messages = list(
            (await session.execute(select(Message).where(Message.conversation_id == conversation.id)))
            .scalars()
            .all()
        )
    assert len(messages) == 2
    [run] = await runs(session_factory, task_id)
    assert run.status == "ok" and set(run.delivered) == {"telegram", "slack", "web"}


@pytest.mark.asyncio
async def test_the_briefing_overview_budget_check_leaves_out_its_own_run(session_factory):
    user, _ = await make_user(session_factory, "briefing-own@example.com")
    task_id = await add_task(
        session_factory,
        user,
        kind="briefing",
        label="Daily briefing",
        prompt=None,
        options={"sections": ["canvas"], "summary": True},
    )
    runner = FakeRunner(budget=BudgetState(usd_left=0.0, runs_left=0))
    svc = service(session_factory, runner, briefing_reader=FakeReader(), briefing_scan=lambda _t: True)
    assert await sweep(svc) == 1
    [run] = await runs(session_factory, task_id)
    assert runner.budget_checks == [str(run.id)]
