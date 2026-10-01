"""Runs scheduled tasks in the background: every minute it claims the due ones,
runs each (a prompt as an unattended agent turn, the daily briefing from
direct reads, a feature's nudge from its renderer), records the occurrence in
the automation ledger, and sends the result to the owner's own linked chats
and the task's web conversation.

Why it exists: a scheduled task must keep working with no chat open and
survive restarts, without ever running one occurrence twice or catching up a
storm of missed ones. It is built on the shared sweeper design
(services/notifications/sweeper.py):
- the claim is a conditional UPDATE that moves ``next_run_at`` to the next
  occurrence counted from now (or marks a once task done), so a missed run
  is never made up; the ledger's unique (task, occurrence) row is the second
  guard, across workers and restarts;
- each kind has its own gate, read before claiming and again before every
  run: prompts and the briefing need "scheduled_tasks", a nudge needs its
  renderer's capability; a gate that cannot be read counts as off;
- a run more than 180 minutes late is skipped, a run over the owner's daily
  budget is skipped with one notice per 24 hours, at most two run at once,
  each within a deadline, and five failures in a row stop the task with one
  message;
- one audit row per run, holding ids, statuses, costs and tool names only;
  logs hold exception types only.
"""

from __future__ import annotations

import asyncio
import time
import uuid
from dataclasses import dataclass, replace
from datetime import datetime, timedelta, timezone
from typing import Any, Awaitable, Callable, Mapping, Optional

import structlog
from sqlalchemy import select, update
from sqlalchemy.exc import IntegrityError

from services.automation.conversations import (
    add_message,
    conversation_title,
    ensure_conversation,
    usage_columns,
)
from services.automation.delivery import Sender, compose, deliver
from services.automation.ledger import AutomationLedger
from services.automation.runner import (
    FAILED_STATUSES,
    UnattendedOutcome,
    UnattendedRequest,
)
from services.notifications.sweeper import SweepLoop, claim
from services.scheduler.recurrence import (
    next_after,
    parse_recurrence,
    recurrence_from_stored,
    short_when,
)
from services.scheduler.renderers import get_renderer
from services.scheduler.timezones import parse_zone

logger = structlog.get_logger(__name__)

SWEEP_INTERVAL_SECONDS = 60
MAX_CONCURRENT_RUNS = 2
RUN_DEADLINE_SECONDS = 180.0
# A prompt run gets this much on top of its own deadline before the sweeper
# gives up on it (the runner stops the turn itself at its deadline).
_DEADLINE_MARGIN_S = 30.0
# How long a prompt run may wait for a free slot on the shared unattended
# runner (trigger runs use it too). The wait is not part of the run's
# deadline; a run that gets no slot in time is "skipped_busy", not a failure.
QUEUE_WAIT_SECONDS = 300.0
LATE_GRACE_MINUTES = 180
ERROR_LIMIT = 5
RUN_NOW_COOLDOWN_SECONDS = 300
CLAIM_SCAN_LIMIT = 50
CLAIM_SCAN_PAGES = 10
PRUNE_EVERY = timedelta(days=1)
CAPABILITY = "scheduled_tasks"
_STOP_WAIT_S = 10.0

_UNREADABLE = "The schedule could not be read."
_NO_RENDERER = "This reminder's feature is no longer available."
_ERRORS = {
    "failed": "The run failed.",
    "timed_out": "The run took too long.",
    "not_configured": "No AI provider is set up.",
}


def _utc(value: datetime) -> datetime:
    return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value.astimezone(timezone.utc)


@dataclass(frozen=True)
class _Claim:
    """What a run needs from its task row, read when it was claimed."""

    id: uuid.UUID
    user_id: uuid.UUID
    kind: str
    label: str
    prompt: Optional[str]
    options: dict[str, Any]
    timezone: str
    channels: tuple[str, ...]
    conversation_id: Optional[uuid.UUID]
    scheduled_for: datetime
    trigger: str = "schedule"

    @property
    def origin(self) -> str:
        return f"schedule:{self.id}"


def _claim_of(row: Any, scheduled_for: datetime, trigger: str) -> _Claim:
    return _Claim(
        id=row.id,
        user_id=row.user_id,
        kind=row.kind,
        label=row.label,
        prompt=row.prompt,
        options=dict(row.options) if isinstance(row.options, dict) else {},
        timezone=row.timezone,
        channels=tuple(c for c in (row.channels or []) if isinstance(c, str)),
        conversation_id=row.conversation_id,
        scheduled_for=_utc(scheduled_for),
        trigger=trigger,
    )


class ScheduleService:
    """Sweeps due scheduled tasks and runs them (see the module docstring).

    ``runner`` is the unattended runner (app.state.unattended_runner);
    ``senders`` maps "telegram" / "slack" to ``send_text(user_id, text)``,
    which only ever reaches that user's own linked chat; ``enabled_keys``
    answers the owner's effectively-on capabilities; ``briefing_reader``,
    ``runtime`` and ``briefing_scan`` serve the daily briefing. ``clock``,
    ``interval_seconds``, ``max_concurrent``, ``run_deadline_s`` and
    ``audit`` are test seams."""

    def __init__(
        self,
        session_factory: Callable[[], Any],
        *,
        runner: Any = None,
        senders: Optional[Mapping[str, Sender]] = None,
        enabled_keys: Optional[Callable[[], Awaitable[frozenset[str]]]] = None,
        briefing_reader: Any = None,
        runtime: Optional[Callable[[], Any]] = None,
        briefing_scan: Optional[Callable[[str], bool]] = None,
        ledger: Optional[AutomationLedger] = None,
        clock: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
        interval_seconds: float = SWEEP_INTERVAL_SECONDS,
        max_concurrent: int = MAX_CONCURRENT_RUNS,
        run_deadline_s: float = RUN_DEADLINE_SECONDS,
        deadline_margin_s: float = _DEADLINE_MARGIN_S,
        queue_wait_s: float = QUEUE_WAIT_SECONDS,
        audit: bool = True,
        delivery_pause_s: float = 0.3,
    ) -> None:
        self._session_factory = session_factory
        self._deadline_margin_s = deadline_margin_s
        self._queue_wait_s = queue_wait_s
        self.runner = runner
        self.senders: dict[str, Sender] = dict(senders or {})
        self._enabled_keys = enabled_keys
        self._briefing_reader = briefing_reader
        self._runtime = runtime or (lambda: None)
        self._briefing_scan = briefing_scan
        self._clock = clock
        self._ledger = ledger or AutomationLedger(session_factory, clock=clock)
        self._max_concurrent = max_concurrent
        self._deadline = run_deadline_s
        self._audit_enabled = audit
        self._delivery_pause_s = delivery_pause_s
        self._running: dict[asyncio.Task[None], _Claim] = {}
        self._run_ids: dict[asyncio.Task[None], str] = {}
        self._run_now_at: dict[str, float] = {}
        self._last_prune: Optional[datetime] = None
        self._sweeper = SweepLoop(
            name="schedule", interval_seconds=interval_seconds, sweep=self.sweep_once
        )

    # -- lifecycle -----------------------------------------------------------

    async def start(self) -> None:
        await self._sweeper.start()

    async def stop(self) -> None:
        """Stop sweeping, then cancel the runs in flight; each is recorded as
        stopped. The wait is bounded, so a wedged run cannot hold shutdown."""
        await self._sweeper.stop()
        running = [task for task in self._running if not task.done()]
        for task in running:
            task.cancel()
        if running:
            await asyncio.wait(running, timeout=_STOP_WAIT_S)

    async def wait_idle(self) -> None:
        """Wait for the runs in flight (tests, shutdown)."""
        while True:
            tasks = [task for task in self._running if not task.done()]
            if not tasks:
                return
            await asyncio.gather(*tasks, return_exceptions=True)

    # -- gates ---------------------------------------------------------------

    async def _keys(self) -> Optional[frozenset[str]]:
        """The owner's effectively-on capabilities, or None when they cannot
        be read (every gate is then off)."""
        if self._enabled_keys is None:
            return frozenset({CAPABILITY})
        try:
            keys = await self._enabled_keys()
        except Exception as exc:
            logger.warning("schedule_gate_failed", error_type=type(exc).__name__)
            return None
        return frozenset(keys) if isinstance(keys, (set, frozenset, list, tuple)) else None

    @staticmethod
    def _gate_key(kind: str, options: Mapping[str, Any]) -> Optional[str]:
        if kind in ("prompt", "briefing"):
            return CAPABILITY
        if kind == "nudge":
            renderer = get_renderer(options.get("renderer"))
            return renderer.capability if renderer is not None else None
        return None

    async def _gate_on(self, kind: str, options: Mapping[str, Any]) -> bool:
        key = self._gate_key(kind, options)
        keys = await self._keys()
        return key is not None and keys is not None and key in keys

    # -- sweep ---------------------------------------------------------------

    async def sweep_once(self) -> int:
        """Claim the due tasks there is room for and start their runs.
        Returns how many were claimed."""
        now = self._clock()
        await self._maybe_prune(now)
        keys = await self._keys()
        if keys is None:
            return 0
        free = self._max_concurrent - sum(1 for task in self._running if not task.done())
        if free <= 0:
            return 0
        claims = await self._claim_due(now, keys, free)
        for item in claims:
            self._spawn(item)
        return len(claims)

    async def _claim_due(self, now: datetime, keys: frozenset[str], limit: int) -> list[_Claim]:
        from models.scheduled_task import ScheduledTask
        from models.user import User

        kinds = ["nudge"] + (["prompt", "briefing"] if CAPABILITY in keys else [])
        claims: list[_Claim] = []
        async with self._session_factory() as session:
            # Rows it moves on (switched off, stopped) are no longer due, so the
            # next page reads past them: they never crowd out the tasks that
            # can run. Bounded, so one sweep cannot spin.
            for _page in range(CLAIM_SCAN_PAGES):
                rows = (
                    (
                        await session.execute(
                            select(ScheduledTask)
                            .join(User, User.id == ScheduledTask.user_id)
                            .where(
                                ScheduledTask.status == "active",
                                ScheduledTask.next_run_at <= now,
                                ScheduledTask.kind.in_(kinds),
                                User.is_active.is_(True),
                            )
                            .order_by(ScheduledTask.next_run_at)
                            .limit(CLAIM_SCAN_LIMIT)
                        )
                    )
                    .scalars()
                    .all()
                )
                for row in rows:
                    if len(claims) >= limit:
                        break
                    options = row.options if isinstance(row.options, dict) else {}
                    gate = self._gate_key(row.kind, options)
                    if gate is None:
                        # A nudge whose renderer is gone can never run: stopped
                        # like an unreadable schedule, so it does not stay due
                        # at the front of every scan.
                        await session.execute(
                            update(ScheduledTask)
                            .where(ScheduledTask.id == row.id, ScheduledTask.status == "active")
                            .values(status="error", last_error=_NO_RENDERER, updated_at=now)
                            .execution_options(synchronize_session=False)
                        )
                        continue
                    rule = recurrence_from_stored(row.recurrence)
                    tz, _err = parse_zone(row.timezone)
                    if rule is None or tz is None:
                        await session.execute(
                            update(ScheduledTask)
                            .where(ScheduledTask.id == row.id, ScheduledTask.status == "active")
                            .values(status="error", last_error=_UNREADABLE, updated_at=now)
                            .execution_options(synchronize_session=False)
                        )
                        continue
                    # Read before the claim, as it was when found due.
                    candidate = _claim_of(row, row.next_run_at, "schedule")
                    nxt = next_after(rule, tz, now)
                    values: dict[str, Any] = {"updated_at": now}
                    if nxt is None:
                        values["status"] = "done"
                    else:
                        values["next_run_at"] = nxt
                    if gate not in keys:
                        # Its switch is off: this occurrence is skipped (moved
                        # on, never made up later), so rows that cannot run
                        # never crowd out the due tasks that can.
                        await session.execute(
                            update(ScheduledTask)
                            .where(
                                ScheduledTask.id == row.id,
                                ScheduledTask.status == "active",
                                ScheduledTask.next_run_at <= now,
                            )
                            .values(last_status="skipped_gate", **values)
                            .execution_options(synchronize_session=False)
                        )
                        continue
                    won = await claim(
                        session,
                        update(ScheduledTask)
                        .where(
                            ScheduledTask.id == row.id,
                            ScheduledTask.status == "active",
                            ScheduledTask.next_run_at <= now,
                        )
                        .values(**values)
                        # The database decides the winner; the loaded row is
                        # not re-evaluated in Python.
                        .execution_options(synchronize_session=False),
                    )
                    if won:
                        claims.append(candidate)
                if len(claims) >= limit or len(rows) < CLAIM_SCAN_LIMIT:
                    break
            await session.commit()
        return claims

    def _spawn(self, item: _Claim) -> None:
        task = asyncio.create_task(self._run_claim(item), name=f"schedule-run-{str(item.id)[:8]}")
        self._running[task] = item

        def forget(done: asyncio.Task[None]) -> None:
            self._running.pop(done, None)
            self._run_ids.pop(done, None)

        task.add_done_callback(forget)

    async def _maybe_prune(self, now: datetime) -> None:
        if self._last_prune is not None and now - self._last_prune < PRUNE_EVERY:
            return
        self._last_prune = now
        try:
            for _ in range(20):
                if await self._ledger.prune() == 0:
                    break
        except Exception as exc:
            logger.warning("schedule_prune_failed", error_type=type(exc).__name__)

    # -- one run -------------------------------------------------------------

    async def _run_claim(self, item: _Claim) -> None:
        task = asyncio.current_task()
        try:
            await self._run_inner(item, task)
        except asyncio.CancelledError:
            run_id = self._run_ids.get(task) if task is not None else None
            if run_id is not None:
                await asyncio.shield(self._record_stopped(item, run_id))
            raise
        except Exception as exc:
            logger.error("schedule_run_failed", task_id=str(item.id), error_type=type(exc).__name__)

    async def _record_stopped(self, item: _Claim, run_id: str) -> None:
        try:
            await self._ledger.finish_run(run_id, status="stopped")
            await self._after(item, "stopped", conversation_id=None)
        except Exception as exc:
            logger.warning("schedule_stop_not_recorded", error_type=type(exc).__name__)

    async def _skip(self, item: _Claim, status: str) -> Optional[str]:
        """Record an occurrence that did not run (late, gate off)."""
        run_id = await self._ledger.start_run(
            item.user_id,
            item.origin,
            item.trigger,
            task_id=item.id,
            scheduled_for=item.scheduled_for,
            status=status,
        )
        if run_id is None:
            return None
        await self._ledger.finish_run(run_id, status=status)
        await self._after(item, status, conversation_id=None)
        await self._audit(item, "skipped", {"run_id": run_id, "status": status})
        return run_id

    async def _run_inner(self, item: _Claim, task: Optional[asyncio.Task[Any]]) -> None:
        now = self._clock()
        if now - item.scheduled_for > timedelta(minutes=LATE_GRACE_MINUTES):
            await self._skip(item, "skipped_late")
            return
        if not await self._gate_on(item.kind, item.options):
            await self._skip(item, "skipped_gate")
            return
        run_id = await self._ledger.start_run(
            item.user_id, item.origin, item.trigger, task_id=item.id, scheduled_for=item.scheduled_for
        )
        if run_id is None:
            # Another worker (or an earlier sweep) owns this occurrence.
            return
        if task is not None:
            self._run_ids[task] = run_id
        try:
            # The runner's slot wait is bounded by queue_wait_s and is
            # budgeted here, on top of the run's own deadline.
            outcome = await asyncio.wait_for(
                self._execute(item, run_id, now),
                timeout=self._queue_wait_s + self._deadline + self._deadline_margin_s,
            )
        except asyncio.TimeoutError:
            outcome = UnattendedOutcome(status="timed_out", run_id=run_id)
        except Exception as exc:
            # Type only: the message can quote anything the run touched.
            logger.error("schedule_run_error", task_id=str(item.id), error_type=type(exc).__name__)
            outcome = UnattendedOutcome(status="failed", run_id=run_id)
        if outcome is None:
            # A nudge with nothing to say: skipped silently.
            await self._ledger.finish_run(run_id, status="skipped_empty")
            return
        if outcome.status == "skipped_budget":
            await self._ledger.finish_run(run_id, status="skipped_budget")
            await self._after(item, "skipped_budget", conversation_id=None)
            await self._audit(item, "skipped", {"run_id": run_id, "status": "skipped_budget"})
            await self._budget_notice(item, run_id)
            return
        if outcome.status == "skipped_busy":
            # No runner slot came free in time: the occurrence did not run
            # (no failure; the next one runs as usual).
            await self._ledger.finish_run(run_id, status="skipped_busy")
            await self._after(item, "skipped_busy", conversation_id=None)
            await self._audit(item, "skipped", {"run_id": run_id, "status": "skipped_busy"})
            await self._busy_notice(item)
            return
        delivered = await self._deliver(item, outcome)
        if outcome.conversation_id:
            delivered = (*delivered, "web")
        await self._ledger.finish_run(
            run_id,
            status=outcome.status,
            input_tokens=int(outcome.usage.get("input_tokens") or 0),
            output_tokens=int(outcome.usage.get("output_tokens") or 0),
            cost_usd=float(outcome.cost_usd or 0.0),
            delivered=list(delivered),
            error=_ERRORS.get(outcome.status),
            message_id=outcome.message_id,
        )
        await self._after(item, outcome.status, conversation_id=outcome.conversation_id)
        await self._audit(
            item,
            "run",
            {
                "run_id": run_id,
                "status": outcome.status,
                "trigger": item.trigger,
                "delivered": list(delivered),
                "cost_usd": round(float(outcome.cost_usd or 0.0), 6),
                "cards": outcome.cards,
                "tools": self._tool_names(item),
            },
        )

    async def _execute(self, item: _Claim, run_id: str, now: datetime) -> Optional[UnattendedOutcome]:
        if item.kind == "prompt":
            if self.runner is None:
                return UnattendedOutcome(status="failed", run_id=run_id)
            return await self.runner.run(
                UnattendedRequest(
                    user_id=str(item.user_id),
                    origin=item.origin,
                    label=item.label,
                    prompt=item.prompt or "",
                    reads=tuple(item.options.get("tools") or ()),
                    writes=tuple(item.options.get("write_tools") or ()),
                    conversation_id=str(item.conversation_id) if item.conversation_id else None,
                    conversation_title=conversation_title(item.label),
                    deadline_s=self._deadline,
                    run_id=run_id,
                    queue_wait_s=self._queue_wait_s,
                )
            )
        if item.kind == "briefing":
            return await self._briefing(item, run_id, now)
        if item.kind == "nudge":
            return await self._nudge(item, run_id, now)
        return UnattendedOutcome(status="failed", run_id=run_id)

    # -- the briefing and nudges -----------------------------------------------

    async def _accounts(self, user_id: uuid.UUID) -> list[Any]:
        from models.connector import ConnectorConfig, connector_type_key
        from services.scheduler.briefing import Account

        async with self._session_factory() as session:
            rows = (
                (
                    await session.execute(
                        select(ConnectorConfig).where(
                            ConnectorConfig.user_id == user_id,
                            ConnectorConfig.is_active.is_(True),
                        )
                    )
                )
                .scalars()
                .all()
            )
        return [
            Account(
                connector_type=connector_type_key(row.connector_type),
                connector_id=str(row.id),
                display_name=row.display_name or "",
            )
            for row in rows
        ]

    async def _briefing(self, item: _Claim, run_id: str, now: datetime) -> UnattendedOutcome:
        from models.user import User
        from services.scheduler.briefing import collect_briefing, make_overview, render_briefing

        tz, _err = parse_zone(item.timezone)
        if tz is None or self._briefing_reader is None:
            return UnattendedOutcome(status="failed", run_id=run_id)
        facts = await collect_briefing(
            self._briefing_reader,
            user_id=str(item.user_id),
            run_id=run_id,
            accounts=await self._accounts(item.user_id),
            sections=item.options.get("sections") or (),
            topic=item.options.get("topic") or None,
            tz=tz,
            now=now,
            scan=self._briefing_scan,
        )
        usage: dict[str, int] = {}
        provider = model = ""
        cost = 0.0
        if item.options.get("summary") is True and await self._overview_affordable(item, run_id):
            async with self._session_factory() as session:
                user = await session.get(User, item.user_id)
                pick = (user.llm_provider, user.llm_model) if user is not None else (None, None)
            overview = await make_overview(
                self._runtime(),
                render_briefing(facts),
                llm_provider=pick[0],
                llm_model=pick[1],
                scan=self._briefing_scan,
            )
            if overview is not None:
                from services.agent.runtime import estimate_usd

                facts.overview = overview.lines
                usage, provider, model = overview.usage, overview.provider, overview.model
                cost = estimate_usd(usage, provider, model)
        text = render_briefing(facts)
        conversation_id, message_id = await self._post_to_web(
            item, f"Daily briefing for {facts.day_label}", text, usage, provider, model
        )
        return UnattendedOutcome(
            status="ok",
            reply=text,
            usage=usage,
            cost_usd=cost,
            conversation_id=conversation_id,
            message_id=message_id,
            run_id=run_id,
            provider=provider,
            model=model,
        )

    async def _overview_affordable(self, item: _Claim, run_id: str) -> bool:
        budget_left = getattr(self.runner, "budget_left", None)
        if not callable(budget_left):
            return False
        try:
            # The briefing's own ledger row is open already: it does not
            # count against the budget it is checking.
            budget = await budget_left(str(item.user_id), exclude_run_id=run_id)
        except Exception as exc:
            logger.warning("schedule_budget_unreadable", error_type=type(exc).__name__)
            return False
        return not budget.exhausted

    async def _nudge(self, item: _Claim, run_id: str, now: datetime) -> Optional[UnattendedOutcome]:
        renderer = get_renderer(item.options.get("renderer"))
        if renderer is None:
            return UnattendedOutcome(status="failed", run_id=run_id)
        async with self._session_factory() as session:
            text = await renderer.render(session, str(item.user_id), now)
        if not text or not str(text).strip():
            return None
        return UnattendedOutcome(status="ok", reply=str(text).strip(), run_id=run_id)

    async def _post_to_web(
        self, item: _Claim, request_text: str, reply: str, usage: dict[str, int], provider: str, model: str
    ) -> tuple[Optional[str], Optional[str]]:
        """Write a briefing into the task's web conversation (made or
        reused); (conversation id, message id), or (None, None) on failure."""
        try:
            async with self._session_factory() as db:
                conversation = await ensure_conversation(
                    db, item.user_id, item.conversation_id, conversation_title(item.label), item.origin
                )
                await add_message(db, conversation, "user", request_text)
                columns = usage_columns(usage, provider, model) if usage else {}
                message = await add_message(db, conversation, "assistant", reply, **columns)
                ids = (str(conversation.id), str(message.id))
                await db.commit()
            return ids
        except Exception as exc:
            logger.warning("schedule_web_post_failed", error_type=type(exc).__name__)
            return None, None

    # -- after a run -----------------------------------------------------------

    async def _deliver(self, item: _Claim, outcome: UnattendedOutcome) -> tuple[str, ...]:
        tz, _err = parse_zone(item.timezone)
        when = short_when(item.scheduled_for, tz) if tz is not None else ""
        texts = {channel: compose(item.label, when, outcome, channel) for channel in item.channels}
        return await deliver(
            str(item.user_id), texts, item.channels, self.senders, pause_s=self._delivery_pause_s
        )

    async def _after(self, item: _Claim, status: str, *, conversation_id: Optional[str]) -> None:
        """Update the task after an occurrence: its last run and status,
        its conversation, and its error count; five failures in a row stop
        it with one message."""
        from models.scheduled_task import ScheduledTask

        now = self._clock()
        failed = status in FAILED_STATUSES
        stopped_now = False
        async with self._session_factory() as session:
            row = await session.get(ScheduledTask, item.id)
            if row is None:
                return
            row.last_run_at = now
            row.last_status = status
            row.updated_at = now
            if conversation_id and str(row.conversation_id or "") != conversation_id:
                row.conversation_id = uuid.UUID(conversation_id)
            if failed:
                row.consecutive_errors = (row.consecutive_errors or 0) + 1
                row.last_error = _ERRORS.get(status, "The run failed.")
                if row.consecutive_errors >= ERROR_LIMIT and row.status == "active":
                    row.status = "error"
                    stopped_now = True
            elif status in ("ok", "card_parked", "over_budget"):
                row.consecutive_errors = 0
                row.last_error = None
            failures = row.consecutive_errors
            await session.commit()
        if stopped_now:
            from services.notifications.page_watch import defang

            text = (
                f"⚠️ Paused your scheduled task \"{defang(item.label)}\" after "
                f"{failures} failed runs in a row. Last problem: {_ERRORS.get(status, 'the run failed')}\n"
                "Resume it from /schedules (Slack: reply \"schedules\") or ask Crawler, once "
                "the problem is fixed."
            )
            await deliver(str(item.user_id), [text], item.channels, self.senders, pause_s=0)
            await self._audit(item, "paused_after_errors", {"failures": failures, "status": "error"})

    async def _budget_notice(self, item: _Claim, run_id: str) -> None:
        """Tell the owner once per 24 hours that runs are being skipped for
        the daily budget."""
        since = self._clock() - timedelta(hours=24)
        try:
            earlier = await self._ledger.count_since(
                item.user_id, "skipped_budget", since, exclude=run_id
            )
        except Exception as exc:
            logger.warning("schedule_budget_notice_lookup_failed", error_type=type(exc).__name__)
            return
        if earlier:
            return
        text = (
            "⏸ Scheduled tasks are being skipped: today's budget for runs while you "
            "are away is used up. They run again once the last 24 hours are under it. The "
            "owner can change these budgets under \"Scheduled tasks and daily briefing\" in "
            "Settings → Permissions."
        )
        await deliver(str(item.user_id), [text], item.channels, self.senders, pause_s=0)

    async def _busy_notice(self, item: _Claim) -> None:
        """Tell the owner an occurrence was skipped because the runner was
        busy with other runs for the whole wait (rare; one message)."""
        from services.notifications.page_watch import defang

        tz, _err = parse_zone(item.timezone)
        when = short_when(item.scheduled_for, tz) if tz is not None else ""
        at = f" for {when}" if when else ""
        text = (
            f"⏸ Skipped your scheduled task \"{defang(item.label)}\"{at}: Crawler was busy "
            "with other runs while you were away. It runs again at its next time."
        )
        await deliver(str(item.user_id), [text], item.channels, self.senders, pause_s=0)

    @staticmethod
    def _tool_names(item: _Claim) -> list[str]:
        if item.kind == "prompt":
            return [
                str(n)
                for n in [*(item.options.get("tools") or ()), *(item.options.get("write_tools") or ())]
            ]
        if item.kind == "briefing":
            return [f"briefing.{s}" for s in item.options.get("sections") or ()]
        return [f"nudge.{item.options.get('renderer')}"]

    async def _audit(self, item: _Claim, action: str, data: dict[str, Any]) -> None:
        """One row in the owner's audit log for what the sweeper did on its
        own: ids, statuses, costs and tool names, never text."""
        if not self._audit_enabled:
            return
        from models.audit import AuditStatus
        from services.audit import append_audit_log

        try:
            async with self._session_factory() as session:
                await append_audit_log(
                    session,
                    user_id=item.user_id,
                    connector_name="schedule",
                    action=action,
                    endpoint="schedule_sweeper",
                    scope_used=CAPABILITY,
                    status=AuditStatus.approved,
                    request_data={"task_id": str(item.id), "kind": item.kind, **data},
                )
                await session.commit()
        except Exception as exc:
            logger.warning("schedule_audit_failed", error_type=type(exc).__name__)

    # -- run now ---------------------------------------------------------------

    async def run_now(self, user_id: Any, task_id: Any) -> dict[str, Any]:
        """Run one of the owner's tasks now (REST, Telegram, Slack): at most
        once per task per 5 minutes, through the same gates and budget."""
        from models.scheduled_task import ScheduledTask

        try:
            owner, target = uuid.UUID(str(user_id)), uuid.UUID(str(task_id))
        except (TypeError, ValueError):
            return {"ok": False, "error": "Scheduled task not found.", "not_found": True}
        async with self._session_factory() as session:
            row = (
                await session.execute(
                    select(ScheduledTask).where(
                        ScheduledTask.id == target, ScheduledTask.user_id == owner
                    )
                )
            ).scalar_one_or_none()
        if row is None:
            return {"ok": False, "error": "Scheduled task not found.", "not_found": True}
        options = row.options if isinstance(row.options, dict) else {}
        if not await self._gate_on(row.kind, options):
            from services import capabilities as registry

            key = self._gate_key(row.kind, options) or CAPABILITY
            try:
                reason = registry.get(key).when_denied
            except KeyError:
                reason = "This task's feature is turned off."
            return {"ok": False, "error": reason, "capability_off": True}
        key = str(target)
        last = self._run_now_at.get(key)
        mono = time.monotonic()
        if last is not None and mono - last < RUN_NOW_COOLDOWN_SECONDS:
            wait = int((RUN_NOW_COOLDOWN_SECONDS - (mono - last)) // 60) + 1
            return {
                "ok": False,
                "error": f"This task ran moments ago; try again in {wait} minute{'s' if wait != 1 else ''}.",
                "rate_limited": True,
            }
        self._run_now_at[key] = mono
        now = self._clock().replace(microsecond=0)
        self._spawn(replace(_claim_of(row, now, "manual"), scheduled_for=now))
        return {"ok": True, "started": True, "task_id": key, "label": row.label}

    # -- nudges (NudgeScheduler) -------------------------------------------------

    async def upsert_nudge(
        self,
        user_id: Any,
        *,
        renderer: str,
        label: str,
        recurrence: dict[str, Any],
        timezone: Optional[str],
        channels: tuple[str, ...],
    ) -> str:
        """Create or change the user's nudge for *renderer* and return its
        task id. Raises ValueError (a plain sentence) for an unknown
        renderer, a bad recurrence or label, or no known time zone."""
        from models.scheduled_task import ScheduledTask
        from models.user import User
        from services.tools.schedule import CHANNELS, clean_label

        if get_renderer(renderer) is None:
            raise ValueError(f"No nudge renderer is registered as {renderer!r}.")
        clean, err = clean_label(label)
        if clean is None:
            raise ValueError(err or "Invalid label.")
        rule, err = parse_recurrence(recurrence)
        if rule is None:
            raise ValueError(err or "Invalid recurrence.")
        owner = uuid.UUID(str(user_id))
        now = self._clock()
        async with self._session_factory() as session:
            rows = (
                (
                    await session.execute(
                        select(ScheduledTask).where(
                            ScheduledTask.user_id == owner, ScheduledTask.kind == "nudge"
                        )
                    )
                )
                .scalars()
                .all()
            )
            row = next(
                (r for r in rows if isinstance(r.options, dict) and r.options.get("renderer") == renderer),
                None,
            )
            # The zone: the call's, the nudge's own, the user's, the install's.
            zone_name = timezone or (row.timezone if row is not None else None)
            if not zone_name:
                zone_name = (
                    await session.execute(select(User.timezone).where(User.id == owner))
                ).scalar_one_or_none()
            if not zone_name:
                from services.tools.schedule import _default_timezone

                zone_name = _default_timezone()
            tz, _err = parse_zone(zone_name)
            if tz is None or zone_name is None:
                raise ValueError("timezone_required")
            nxt = next_after(rule, tz, now)
            if nxt is None:
                raise ValueError("That schedule never runs.")
            wanted = [c for c in CHANNELS if c in channels]
            if row is None:
                row = ScheduledTask(
                    id=uuid.uuid4(),
                    user_id=owner,
                    kind="nudge",
                    label=clean,
                    options={"renderer": renderer},
                    recurrence=rule.to_dict(),
                    timezone=zone_name,
                    channels=wanted,
                    status="active",
                    next_run_at=nxt,
                    consecutive_errors=0,
                    source="feature",
                    created_at=now,
                    updated_at=now,
                )
                session.add(row)
            else:
                row.label = clean
                row.recurrence = rule.to_dict()
                row.timezone = zone_name
                row.channels = wanted
                row.status = "active"
                row.consecutive_errors = 0
                row.next_run_at = nxt
                row.updated_at = now
            task_id = str(row.id)
            try:
                await session.commit()
            except IntegrityError:
                await session.rollback()
                raise ValueError(f'The user already has a scheduled task called "{clean}".') from None
        return task_id

    async def cancel_nudge(self, user_id: Any, *, renderer: str) -> bool:
        """Delete the user's nudge for *renderer*; False when there was none."""
        from models.scheduled_task import ScheduledTask

        owner = uuid.UUID(str(user_id))
        async with self._session_factory() as session:
            rows = (
                (
                    await session.execute(
                        select(ScheduledTask).where(
                            ScheduledTask.user_id == owner, ScheduledTask.kind == "nudge"
                        )
                    )
                )
                .scalars()
                .all()
            )
            found = [
                r for r in rows if isinstance(r.options, dict) and r.options.get("renderer") == renderer
            ]
            for row in found:
                await session.delete(row)
            await session.commit()
        return bool(found)
