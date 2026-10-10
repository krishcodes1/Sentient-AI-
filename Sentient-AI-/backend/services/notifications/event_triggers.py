"""Runs the app-event trigger sweeper: every minute it checks the due triggers
(each through its own connector row's existing READ action), queues what is
new, and then acts on the queue: a fixed-format message for a notify trigger,
or one unattended task run for a run_task trigger.

Why it exists: a trigger must keep working with no chat open and survive
restarts without ever firing one item twice or running a task more often than
the owner allowed. It is built on the shared sweeper design
(services/notifications/sweeper.py) and copies PageWatchService's pattern:

Phase A, detect. Only while the owner's "event_triggers" switch is on, re-read
before every check (a gate that cannot be read counts as off). Up to 20 due
triggers of active users are claimed with a conditional UPDATE of
``next_check_at`` (the lease). Each check has a 45 s deadline. The first
success records the baseline only. At most 5 new items are queued per check;
more become one "and N more" note; the unique index on (trigger, key) is the
dedupe guard. Failures back off; the fifth in a row stops the trigger with one
"Stopped trigger" message.

Phase B, act. Queued events are claimed pending -> running with a 5-minute
lease and a batch id. notify: the message is built in code
(services/triggers/facts.py: defanged, PromptGuard-withheld, never a mail
body) and sent through the owner's own Telegram and Slack. run_task: the
per-trigger daily cap and the shared unattended budget are checked first
(over a cap the events are suppressed, with one notice a day); while
"trigger_runs" is off the notify message goes out instead with a line saying
so; otherwise scheduler_briefing's one unattended runner runs the owner's
prompt with only that connector's reads (and, if allowed, its writes as
approval cards), the events' facts as untrusted seed data, 4 rounds and the
shared per-run cap, and the result is sent. A lease that expired in a crash
marks its events failed ("interrupted"); they are never re-run.

Phase C, once an hour: facts older than 7 days are deleted (rows older than
30 days go too) and the daily run counters reset at the UTC day change.

Audit rows (trigger_fired, trigger_run, trigger_suppressed, trigger_stopped)
hold ids, counts, statuses and costs only; logs hold ids and exception types.
The page-watch bridge (``enqueue_page_change``) queues a page.changed event
with the watch's label and host only, never page text.
"""

from __future__ import annotations

import asyncio
import re
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Awaitable, Callable, Optional

import structlog
from sqlalchemy import delete, func, null, select, update
from sqlalchemy.exc import IntegrityError

from services.agent.unattended import SeedResult
from services.automation.ledger import AutomationLedger
from services.automation.runner import FAILED_STATUSES, UnattendedOutcome, UnattendedRequest
from services.notifications.sweeper import SweepLoop, backoff_minutes, gate_open
from services.triggers import CAPABILITY, RUNS_CAPABILITY
from services.triggers import facts as shape
from services.triggers import sources as src

logger = structlog.get_logger(__name__)

SWEEP_INTERVAL_SECONDS = 60
MAX_CHECKS_PER_SWEEP = 20
CHECK_DEADLINE_SECONDS = 45.0
ERROR_LIMIT = 5
MAX_BACKOFF_MINUTES = 24 * 60
LEASE_MINUTES = 5
RUN_DEADLINE_SECONDS = 240.0
_DEADLINE_MARGIN_S = 30.0
# How long a task run may wait for a free slot on the shared unattended
# runner (scheduled runs use it too). The wait is not part of the run's
# deadline, and wait + deadline + margin stays inside the events' 5-minute
# lease; with no slot in time the events go back to the queue for the next
# sweep ("skipped_busy", not a failure).
QUEUE_WAIT_SECONDS = 20.0
MAX_ROUNDS = 4
MAX_CONCURRENT_RUNS = 2
# Task runs of all of one user's triggers in a UTC day.
MAX_USER_RUNS_PER_DAY = 30
TRIGGERS_PER_ACT = 50
FACTS_RETENTION_DAYS = 7
EVENTS_RETENTION_DAYS = 30
HOUSEKEEPING_EVERY = timedelta(hours=1)
_STOP_WAIT_S = 10.0
_MORE_RE = re.compile(r"^and ([0-9]{1,6}) more$")

_TERMINAL = ("notified", "ran", "suppressed", "failed")
# The notes of events suppressed by a cap (one notice a day covers them).
_CAP_NOTES = ("daily_limit", "user_daily_limit", "budget")
_OFFLINE = "The account this trigger reads was turned off or removed."
_RUN_ERRORS = {
    "failed": "The run failed.",
    "timed_out": "The run took too long.",
    "not_configured": "No AI provider is set up.",
}
# One message reaches Telegram and Slack alike, so a command is named for
# both (Slack keeps "/..." for its own slash commands).
_PENDING_HINT = '/pending; Slack: reply "pending"'

Send = Callable[[str, str], Awaitable[Any]]
Gate = Callable[[], Awaitable[bool]]


def _utc(value: Optional[datetime]) -> Optional[datetime]:
    if value is None:
        return None
    return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value.astimezone(timezone.utc)


def more_note(count: int) -> str:
    return f"and {count} more"


def _more_of(note: Optional[str]) -> int:
    match = _MORE_RE.match(note or "")
    return int(match.group(1)) if match else 0


@dataclass(frozen=True)
class _Claim:
    """What a check needs from its trigger row, read when it was claimed."""

    id: uuid.UUID
    user_id: uuid.UUID
    label: str
    source: str
    connector_id: Optional[uuid.UUID]
    filters: dict[str, Any]
    interval_minutes: int
    cursor: Optional[dict[str, Any]]
    baseline_at: Optional[datetime]
    consecutive_errors: int


@dataclass(frozen=True)
class _Trigger:
    """What acting on a batch needs from its trigger row."""

    id: uuid.UUID
    user_id: uuid.UUID
    label: str
    source: str
    connector_id: Optional[uuid.UUID]
    filters: dict[str, Any]
    mode: str
    prompt: Optional[str]
    allow_writes: bool
    max_runs_per_day: int
    conversation_id: Optional[uuid.UUID]

    @property
    def origin(self) -> str:
        return f"trigger:{self.id}"


@dataclass(frozen=True)
class _Event:
    id: uuid.UUID
    facts: dict[str, Any]
    note: Optional[str]


class TriggerService:
    """Sweeps due triggers, queues what they find and acts on the queue
    (see the module docstring).

    ``executor`` is the tool executor (``execute(name, args, user_id,
    approved=False)``); ``send(user_id, text)`` reaches only that user's own
    linked Telegram and Slack chats (main.fan_out_send); ``enabled`` and
    ``runs_enabled`` are the "event_triggers" and "trigger_runs" switches,
    re-read before every check and run (a gate that fails is off);
    ``runner`` is the one unattended runner (app.state.unattended_runner).
    ``clock``, ``scan``, ``ledger``, ``audit`` and the timings are test
    seams."""

    def __init__(
        self,
        session_factory: Callable[[], Any],
        *,
        executor: Any = None,
        send: Optional[Send] = None,
        enabled: Optional[Gate] = None,
        runs_enabled: Optional[Gate] = None,
        runner: Any = None,
        ledger: Optional[AutomationLedger] = None,
        clock: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
        scan: Optional[Callable[[str], bool]] = None,
        audit: bool = True,
        interval_seconds: float = SWEEP_INTERVAL_SECONDS,
        check_deadline_s: float = CHECK_DEADLINE_SECONDS,
        run_deadline_s: float = RUN_DEADLINE_SECONDS,
        max_concurrent_runs: int = MAX_CONCURRENT_RUNS,
    ) -> None:
        self._session_factory = session_factory
        self.executor = executor
        self.send = send
        self._enabled = enabled
        self._runs_enabled = runs_enabled
        self.runner = runner
        self._clock = clock
        self._ledger = ledger or AutomationLedger(session_factory, clock=clock)
        self._scan = scan
        self._audit_enabled = audit
        self._check_deadline_s = check_deadline_s
        self._run_deadline_s = run_deadline_s
        self._max_runs = max_concurrent_runs
        self._running: set[asyncio.Task[None]] = set()
        self._last_housekeeping: Optional[datetime] = None
        self._sweeper = SweepLoop(
            name="event_triggers", interval_seconds=interval_seconds, sweep=self.sweep_once
        )

    # -- lifecycle -----------------------------------------------------------

    async def start(self) -> None:
        await self._sweeper.start()

    async def stop(self) -> None:
        """Stop sweeping, then cancel the runs in flight (bounded wait); their
        events' leases expire and they are marked interrupted."""
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

    async def _on(self) -> bool:
        return await gate_open(self._enabled, CAPABILITY)

    async def _runs_on(self) -> bool:
        return await gate_open(self._runs_enabled, RUNS_CAPABILITY)

    # -- the sweep -----------------------------------------------------------

    async def sweep_once(self) -> int:
        """One pass: housekeeping (hourly), then detect and act while the
        switch is on. Returns how many triggers were checked."""
        now = self._clock()
        await self._maybe_housekeep(now)
        if not await self._on():
            return 0
        checked = await self._detect(now)
        await self._act()
        return checked

    # -- Phase A: detect -------------------------------------------------------

    async def _detect(self, now: datetime) -> int:
        claims = await self._claim_due(now)
        checked = 0
        for claim in claims:
            # Re-read before each check: a sweep can run for minutes, and
            # nothing is read once the owner turns it off. A claim left
            # unchecked is retried an interval later.
            if checked and not await self._on():
                break
            await self._check(claim)
            checked += 1
        return checked

    async def _claim_due(self, now: datetime) -> list[_Claim]:
        from models.event_trigger import EventTrigger
        from models.user import User

        async with self._session_factory() as session:
            rows = (
                (
                    await session.execute(
                        select(EventTrigger)
                        .join(User, User.id == EventTrigger.user_id)
                        .where(
                            EventTrigger.status == "active",
                            EventTrigger.source.in_(list(src.POLLED_SOURCES)),
                            EventTrigger.next_check_at <= now,
                            User.is_active.is_(True),
                        )
                        .order_by(EventTrigger.next_check_at)
                        .limit(MAX_CHECKS_PER_SWEEP)
                    )
                )
                .scalars()
                .all()
            )
            claims: list[_Claim] = []
            for row in rows:
                interval = max(1, int(row.interval_minutes or 1))
                # Whoever moves the row past "due" owns this check; the new
                # time is also the retry after a crash.
                result = await session.execute(
                    update(EventTrigger)
                    .where(
                        EventTrigger.id == row.id,
                        EventTrigger.status == "active",
                        EventTrigger.next_check_at <= now,
                    )
                    .values(next_check_at=now + timedelta(minutes=interval))
                    .execution_options(synchronize_session=False)
                )
                if getattr(result, "rowcount", 0) != 1:
                    continue
                claims.append(
                    _Claim(
                        id=row.id,
                        user_id=row.user_id,
                        label=row.label,
                        source=row.source,
                        connector_id=row.connector_id,
                        filters=dict(row.filters or {}),
                        interval_minutes=interval,
                        cursor=dict(row.cursor) if isinstance(row.cursor, dict) else None,
                        baseline_at=_utc(row.baseline_at),
                        consecutive_errors=row.consecutive_errors or 0,
                    )
                )
            await session.commit()
        return claims

    async def _connector_type(self, claim: _Claim) -> Optional[str]:
        """The pinned row's type while it is the owner's and active."""
        from models.connector import ConnectorConfig, connector_type_key

        if claim.connector_id is None:
            return None
        async with self._session_factory() as session:
            row = await session.get(ConnectorConfig, claim.connector_id)
            if row is None or row.user_id != claim.user_id or not row.is_active:
                return None
            return connector_type_key(row.connector_type)

    async def _check(self, claim: _Claim) -> None:
        now = self._clock()
        try:
            connector_type = await self._connector_type(claim)
        except Exception as exc:
            logger.warning("trigger_check_lookup_failed", trigger_id=str(claim.id), error_type=type(exc).__name__)
            return
        if connector_type is None:
            await self._record_failure(claim, _OFFLINE)
            return
        adapter = src.adapter_for(claim.source, connector_type)
        if adapter is None or self.executor is None:
            await self._record_failure(claim, "This trigger's app cannot be read here.")
            return
        target = src.CheckTarget(
            trigger_id=str(claim.id),
            user_id=str(claim.user_id),
            source=claim.source,
            connector_type=connector_type,
            connector_id=str(claim.connector_id),
            filters=claim.filters,
            label=claim.label,
            cursor=claim.cursor,
            baseline_at=claim.baseline_at,
        )
        try:
            # A total deadline: checks run one after another, so one app that
            # never answers must not hold every other trigger back.
            outcome = await asyncio.wait_for(
                src.run_check(adapter, src.make_call(self.executor, target), target, now),
                self._check_deadline_s,
            )
        except asyncio.CancelledError:
            raise
        except asyncio.TimeoutError:
            await self._record_failure(claim, "The app did not answer in time.")
            return
        except src.SourceError as exc:
            await self._record_failure(claim, str(exc))
            return
        except Exception as exc:
            await self._record_failure(claim, f"The check failed ({type(exc).__name__}).")
            return
        try:
            await self._record_success(claim, outcome, now)
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            logger.warning("trigger_record_failed", trigger_id=str(claim.id), error_type=type(exc).__name__)

    async def _record_success(self, claim: _Claim, outcome: src.CheckOutcome, now: datetime) -> None:
        from models.event_trigger import EventTrigger, TriggerEvent

        values: dict[str, Any] = {
            "cursor": outcome.cursor,
            "last_checked_at": now,
            "next_check_at": now + timedelta(minutes=claim.interval_minutes),
            "consecutive_errors": 0,
            "last_error": None,
            "updated_at": now,
        }
        if outcome.baseline:
            values["baseline_at"] = now
        async with self._session_factory() as session:
            result = await session.execute(
                update(EventTrigger)
                .where(EventTrigger.id == claim.id, EventTrigger.status == "active")
                .values(**values)
                .execution_options(synchronize_session=False)
            )
            await session.commit()
        if getattr(result, "rowcount", 0) != 1:
            # Paused or deleted meanwhile: nothing is queued.
            return
        queued = 0
        for index, (key, item) in enumerate(outcome.items):
            last = index == len(outcome.items) - 1
            async with self._session_factory() as session:
                session.add(
                    TriggerEvent(
                        id=uuid.uuid4(),
                        trigger_id=claim.id,
                        user_id=claim.user_id,
                        external_key=key,
                        status="pending",
                        facts=item.facts,
                        # A microsecond apart: one check's items keep their
                        # order in the message and the run.
                        detected_at=now + timedelta(microseconds=index),
                        note=more_note(outcome.more) if last and outcome.more else None,
                    )
                )
                try:
                    await session.commit()
                    queued += 1
                except IntegrityError:
                    # Already queued once (the unique index): never twice.
                    await session.rollback()
        logger.info(
            "trigger_checked",
            trigger_id=str(claim.id),
            baseline=outcome.baseline,
            queued=queued,
            more=outcome.more,
        )

    async def _record_failure(self, claim: _Claim, reason: str) -> None:
        from models.event_trigger import ERROR_MAX_CHARS, EventTrigger

        now = self._clock()
        failures = claim.consecutive_errors + 1
        reason = reason[:ERROR_MAX_CHARS]
        values: dict[str, Any] = {
            "last_checked_at": now,
            "consecutive_errors": failures,
            "last_error": reason,
            "updated_at": now,
        }
        stopped = failures >= ERROR_LIMIT
        if stopped:
            values["status"] = "error"
        else:
            wait = backoff_minutes(claim.interval_minutes, failures, MAX_BACKOFF_MINUTES)
            values["next_check_at"] = now + timedelta(minutes=wait)
        logger.info("trigger_check_failed", trigger_id=str(claim.id), failures=failures, stopped=stopped)
        try:
            async with self._session_factory() as session:
                result = await session.execute(
                    update(EventTrigger)
                    .where(EventTrigger.id == claim.id, EventTrigger.status == "active")
                    .values(**values)
                    .execution_options(synchronize_session=False)
                )
                await session.commit()
        except Exception as exc:
            logger.warning("trigger_record_failed", trigger_id=str(claim.id), error_type=type(exc).__name__)
            return
        if getattr(result, "rowcount", 0) == 1 and stopped:
            delivered = await self._deliver(claim.user_id, shape.stopped_text(claim.label, reason, failures))
            await self._audit(
                claim.user_id,
                "trigger_stopped",
                {"trigger_id": str(claim.id), "source": claim.source, "failures": failures, "delivered": delivered},
            )

    # -- the page-watch bridge -----------------------------------------------------

    async def enqueue_page_change(self, user_id: Any, watch_id: Any, label: str, host: str) -> int:
        """Queue one page.changed event for each of *user_id*'s active
        triggers naming *watch_id* (the page-watch sweeper calls this after
        a recorded change). Only the watch's label and host are kept, never
        page text. Returns how many were queued; nothing while the switch
        is off."""
        from models.event_trigger import EventTrigger, TriggerEvent

        if not await self._on():
            return 0
        try:
            owner, watch = uuid.UUID(str(user_id)), str(uuid.UUID(str(watch_id)))
        except (TypeError, ValueError):
            return 0
        now = self._clock()
        async with self._session_factory() as session:
            rows = (
                await session.execute(
                    select(EventTrigger.id, EventTrigger.filters).where(
                        EventTrigger.user_id == owner,
                        EventTrigger.source == "page.changed",
                        EventTrigger.status == "active",
                    )
                )
            ).all()
        targets = [r.id for r in rows if isinstance(r.filters, dict) and r.filters.get("watch_id") == watch]
        queued = 0
        for trigger_id in targets:
            async with self._session_factory() as session:
                session.add(
                    TriggerEvent(
                        id=uuid.uuid4(),
                        trigger_id=trigger_id,
                        user_id=owner,
                        external_key=shape.external_key("page.changed", f"{watch}@{now.isoformat()}"),
                        status="pending",
                        facts=shape.page_facts(label=label, host=host),
                        detected_at=now,
                    )
                )
                try:
                    await session.commit()
                    queued += 1
                except IntegrityError:
                    await session.rollback()
        return queued

    # -- Phase B: act -------------------------------------------------------------

    async def _act(self) -> None:
        from models.event_trigger import TriggerEvent

        await self._expire_leases(self._clock())
        async with self._session_factory() as session:
            ids = list(
                (
                    await session.execute(
                        select(TriggerEvent.trigger_id)
                        .where(TriggerEvent.status == "pending")
                        .group_by(TriggerEvent.trigger_id)
                        .order_by(func.min(TriggerEvent.detected_at))
                        .limit(TRIGGERS_PER_ACT)
                    )
                )
                .scalars()
                .all()
            )
        for trigger_id in ids:
            if not await self._on():
                return
            try:
                await self._act_on(trigger_id)
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                logger.warning("trigger_act_failed", trigger_id=str(trigger_id), error_type=type(exc).__name__)

    async def _load_trigger(self, trigger_id: uuid.UUID) -> tuple[Optional[_Trigger], str, bool]:
        """(the trigger, its status, whether its user is active)."""
        from models.event_trigger import EventTrigger
        from models.user import User

        async with self._session_factory() as session:
            row = await session.get(EventTrigger, trigger_id)
            if row is None:
                return None, "", False
            user = await session.get(User, row.user_id)
            trig = _Trigger(
                id=row.id,
                user_id=row.user_id,
                label=row.label,
                source=row.source,
                connector_id=row.connector_id,
                filters=dict(row.filters or {}),
                mode=row.mode,
                prompt=row.prompt,
                allow_writes=bool(row.allow_writes),
                max_runs_per_day=int(row.max_runs_per_day or 1),
                conversation_id=row.conversation_id,
            )
            return trig, row.status, bool(user is not None and user.is_active)

    async def _act_on(self, trigger_id: uuid.UUID) -> None:
        trig, status, user_active = await self._load_trigger(trigger_id)
        if trig is None:
            return
        if status != "active" or not user_active:
            # Held events of a paused or stopped trigger are not sent later.
            events = await self._claim_events(trig.id, limit=None)
            await self._finish(events, "suppressed", "paused" if status == "paused" else "inactive")
            return
        if trig.mode == "run_task" and sum(1 for t in self._running if not t.done()) >= self._max_runs:
            return  # left queued for the next sweep
        events = await self._claim_events(trig.id)
        if not events:
            return
        if trig.mode != "run_task":
            await self._notify(trig, events)
            return
        task = asyncio.create_task(self._run_batch(trig, events), name=f"trigger-run-{str(trig.id)[:8]}")
        self._running.add(task)
        task.add_done_callback(self._running.discard)

    async def _claim_events(self, trigger_id: uuid.UUID, *, limit: Optional[int] = shape.MAX_ITEMS_PER_BATCH) -> list[_Event]:
        """Move up to *limit* pending events of one trigger to running under
        a 5-minute lease and one batch id; the ones this caller won."""
        from models.event_trigger import TriggerEvent

        now = self._clock()
        batch = uuid.uuid4()
        claimed: list[_Event] = []
        async with self._session_factory() as session:
            query = (
                select(TriggerEvent.id, TriggerEvent.facts, TriggerEvent.note)
                .where(TriggerEvent.trigger_id == trigger_id, TriggerEvent.status == "pending")
                .order_by(TriggerEvent.detected_at, TriggerEvent.id)
            )
            if limit is not None:
                query = query.limit(limit)
            rows = (await session.execute(query)).all()
            for row in rows:
                result = await session.execute(
                    update(TriggerEvent)
                    .where(TriggerEvent.id == row.id, TriggerEvent.status == "pending")
                    .values(
                        status="running",
                        batch_id=batch,
                        claimed_until=now + timedelta(minutes=LEASE_MINUTES),
                    )
                    .execution_options(synchronize_session=False)
                )
                if getattr(result, "rowcount", 0) == 1:
                    claimed.append(
                        _Event(id=row.id, facts=dict(row.facts) if isinstance(row.facts, dict) else {}, note=row.note)
                    )
            await session.commit()
        return claimed

    async def _finish(self, events: list[_Event], status: str, note: Optional[str] = None) -> None:
        """Mark claimed events done; a note replaces theirs (the "and N
        more" note is kept when there is none)."""
        from models.event_trigger import NOTE_MAX_CHARS, TriggerEvent

        if not events:
            return
        now = self._clock()
        async with self._session_factory() as session:
            for event in events:
                values: dict[str, Any] = {"status": status, "handled_at": now, "claimed_until": None}
                if note is not None:
                    values["note"] = note[:NOTE_MAX_CHARS]
                await session.execute(
                    update(TriggerEvent)
                    .where(TriggerEvent.id == event.id, TriggerEvent.status == "running")
                    .values(**values)
                    .execution_options(synchronize_session=False)
                )
            await session.commit()

    async def _release(self, events: list[_Event]) -> None:
        """Put claimed events back in the queue (a run that could not
        start); the next sweep claims them again."""
        from models.event_trigger import TriggerEvent

        if not events:
            return
        async with self._session_factory() as session:
            await session.execute(
                update(TriggerEvent)
                .where(TriggerEvent.id.in_([e.id for e in events]), TriggerEvent.status == "running")
                .values(status="pending", batch_id=None, claimed_until=None)
                .execution_options(synchronize_session=False)
            )
            await session.commit()

    async def _expire_leases(self, now: datetime) -> int:
        """Events still running past their lease (a crash mid-way): failed as
        "interrupted", never re-run."""
        from models.event_trigger import TriggerEvent

        async with self._session_factory() as session:
            result = await session.execute(
                update(TriggerEvent)
                .where(TriggerEvent.status == "running", TriggerEvent.claimed_until < now)
                .values(status="failed", note="interrupted", handled_at=now, claimed_until=None)
                .execution_options(synchronize_session=False)
            )
            await session.commit()
        expired = int(getattr(result, "rowcount", 0) or 0)
        if expired:
            logger.info("trigger_events_interrupted", count=expired)
        return expired

    async def _user_zone(self, user_id: uuid.UUID) -> Any:
        from models.user import User
        from services.scheduler.timezones import parse_zone

        try:
            async with self._session_factory() as session:
                zone = (await session.execute(select(User.timezone).where(User.id == user_id))).scalar_one_or_none()
        except Exception:
            return None
        tz, _err = parse_zone(zone) if zone else (None, None)
        return tz

    async def _connector_type_of(self, trig: _Trigger) -> Optional[str]:
        from models.connector import ConnectorConfig, connector_type_key

        if trig.connector_id is None:
            return None
        async with self._session_factory() as session:
            row = await session.get(ConnectorConfig, trig.connector_id)
            if row is None or row.user_id != trig.user_id:
                return None
            return connector_type_key(row.connector_type)

    def _scanner(self) -> Callable[[str], bool]:
        return self._scan or shape.default_scan()

    async def _notice(self, trig: _Trigger, events: list[_Event], extra: tuple[str, ...] = ()) -> str:
        tz = await self._user_zone(trig.user_id)
        return shape.notify_text(
            trig.source,
            trig.label,
            [e.facts for e in events],
            more=sum(_more_of(e.note) for e in events),
            show_score=bool(trig.filters.get("show_score")),
            tz=tz,
            now=self._clock(),
            scan=self._scanner(),
            extra_lines=extra,
        )

    async def _notify(
        self,
        trig: _Trigger,
        events: list[_Event],
        *,
        extra: tuple[str, ...] = (),
        status: str = "notified",
        note: Optional[str] = None,
        conversation_id: Optional[str] = None,
    ) -> bool:
        text = await self._notice(trig, events, extra)
        delivered = await self._deliver(trig.user_id, text)
        await self._finish(events, status, note if note is not None else (None if delivered else "not delivered"))
        await self._fired(trig, conversation_id)
        await self._audit(
            trig.user_id,
            "trigger_fired",
            {
                "trigger_id": str(trig.id),
                "source": trig.source,
                "connector_type": await self._connector_type_of(trig),
                "events": len(events),
                "more": sum(_more_of(e.note) for e in events),
                "mode": trig.mode,
                "delivered": delivered,
            },
        )
        return delivered

    async def _fired(self, trig: _Trigger, conversation_id: Optional[str] = None) -> None:
        """Record that the trigger fired, and the thread its run wrote into.
        Best effort: the message already went out."""
        from models.event_trigger import EventTrigger

        values: dict[str, Any] = {"last_fired_at": self._clock()}
        if conversation_id:
            try:
                values["conversation_id"] = uuid.UUID(conversation_id)
            except ValueError:
                pass
        try:
            async with self._session_factory() as session:
                await session.execute(
                    update(EventTrigger)
                    .where(EventTrigger.id == trig.id)
                    .values(**values)
                    .execution_options(synchronize_session=False)
                )
                await session.commit()
        except Exception as exc:
            logger.warning("trigger_fired_not_recorded", trigger_id=str(trig.id), error_type=type(exc).__name__)

    # -- a task run -----------------------------------------------------------------

    async def _run_batch(self, trig: _Trigger, events: list[_Event]) -> None:
        try:
            await self._run_inner(trig, events)
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            logger.error("trigger_run_failed", trigger_id=str(trig.id), error_type=type(exc).__name__)

    async def _over_cap(self, trig: _Trigger) -> Optional[tuple[str, str]]:
        """(the reason the owner reads, the note) when a run would exceed a
        cap: this trigger's runs today, all the user's trigger runs today,
        or the shared unattended budget (a budget that cannot be read counts
        as spent)."""
        from models.event_trigger import EventTrigger

        today = self._clock().date()
        async with self._session_factory() as session:
            mine = (
                await session.execute(
                    select(EventTrigger.runs_today).where(
                        EventTrigger.id == trig.id, EventTrigger.runs_day == today
                    )
                )
            ).scalar_one_or_none() or 0
            everyone = (
                await session.execute(
                    select(func.coalesce(func.sum(EventTrigger.runs_today), 0)).where(
                        EventTrigger.user_id == trig.user_id, EventTrigger.runs_day == today
                    )
                )
            ).scalar_one() or 0
        if mine >= trig.max_runs_per_day:
            return (f"it already ran {trig.max_runs_per_day} times today, its daily limit.", "daily_limit")
        if everyone >= MAX_USER_RUNS_PER_DAY:
            return (f"your triggers already ran {MAX_USER_RUNS_PER_DAY} tasks today.", "user_daily_limit")
        try:
            budget = await self.runner.budget_left(str(trig.user_id))
        except Exception as exc:
            logger.warning("trigger_budget_unreadable", error_type=type(exc).__name__)
            return ("today's budget for tasks run while you are away could not be read.", "budget")
        if budget.exhausted:
            return ("today's budget for tasks run while you are away is used up.", "budget")
        return None

    async def _take_run(self, trig: _Trigger) -> bool:
        """Count one run for today, only while under the trigger's daily
        cap (a conditional UPDATE, so two sweeps cannot both pass it); a new
        UTC day starts from zero."""
        from models.event_trigger import EventTrigger

        today = self._clock().date()
        async with self._session_factory() as session:
            result = await session.execute(
                update(EventTrigger)
                .where(
                    EventTrigger.id == trig.id,
                    EventTrigger.runs_day == today,
                    EventTrigger.runs_today < EventTrigger.max_runs_per_day,
                )
                .values(runs_today=EventTrigger.runs_today + 1)
                .execution_options(synchronize_session=False)
            )
            if getattr(result, "rowcount", 0) != 1:
                result = await session.execute(
                    update(EventTrigger)
                    .where(
                        EventTrigger.id == trig.id,
                        (EventTrigger.runs_day.is_(None)) | (EventTrigger.runs_day != today),
                    )
                    .values(runs_day=today, runs_today=1)
                    .execution_options(synchronize_session=False)
                )
            await session.commit()
        return getattr(result, "rowcount", 0) == 1

    async def _give_back_run(self, trig: _Trigger) -> None:
        """Undo _take_run for a run that did not happen (the budget)."""
        from models.event_trigger import EventTrigger

        async with self._session_factory() as session:
            await session.execute(
                update(EventTrigger)
                .where(
                    EventTrigger.id == trig.id,
                    EventTrigger.runs_day == self._clock().date(),
                    EventTrigger.runs_today > 0,
                )
                .values(runs_today=EventTrigger.runs_today - 1)
                .execution_options(synchronize_session=False)
            )
            await session.commit()

    async def _suppress(self, trig: _Trigger, events: list[_Event], reason: str, note: str) -> None:
        """Over a cap: the events are suppressed, and the owner is told once
        per trigger per UTC day."""
        from models.event_trigger import TriggerEvent

        now = self._clock()
        day_start = now.replace(hour=0, minute=0, second=0, microsecond=0)
        async with self._session_factory() as session:
            earlier = (
                await session.execute(
                    select(func.count(TriggerEvent.id)).where(
                        TriggerEvent.trigger_id == trig.id,
                        TriggerEvent.status == "suppressed",
                        TriggerEvent.handled_at >= day_start,
                        TriggerEvent.id.not_in([e.id for e in events]),
                        TriggerEvent.note.in_(list(_CAP_NOTES)),
                    )
                )
            ).scalar_one()
        await self._finish(events, "suppressed", note)
        delivered = False
        if not earlier:
            delivered = await self._deliver(trig.user_id, shape.limit_text(trig.label, reason))
        await self._audit(
            trig.user_id,
            "trigger_suppressed",
            {"trigger_id": str(trig.id), "events": len(events), "reason": note, "notice_sent": delivered},
        )

    async def _run_inner(self, trig: _Trigger, events: list[_Event]) -> None:
        if not await self._runs_on():
            await self._notify(trig, events, extra=(shape.RUNS_OFF_LINE,), note="runs_off")
            return
        if self.runner is None:
            await self._notify(trig, events, extra=(shape.RUNNER_MISSING_LINE,), note="no_runner")
            return
        capped = await self._over_cap(trig)
        if capped is not None:
            await self._suppress(trig, events, *capped)
            return
        connector_type = await self._connector_type_of(trig)
        if connector_type is None:
            await self._notify(trig, events, extra=(shape.RUN_FAILED_LINE,), status="failed", note="no_account")
            return
        if not await self._take_run(trig):
            await self._suppress(
                trig,
                events,
                f"it already ran {trig.max_runs_per_day} times today, its daily limit.",
                "daily_limit",
            )
            return
        run_id = await self._ledger.start_run(trig.user_id, trig.origin, "event")
        items = [e.facts for e in events]
        more = sum(_more_of(e.note) for e in events)
        seed: dict[str, Any] = {"trigger": trig.label, "source": trig.source, "items": items}
        if more:
            seed["more_not_shown"] = more
        request = UnattendedRequest(
            user_id=str(trig.user_id),
            origin=trig.origin,
            label=trig.label,
            prompt=trig.prompt or "",
            reads=src.read_actions(connector_type),
            writes=src.write_actions(connector_type) if trig.allow_writes else (),
            connector_id=str(trig.connector_id),
            seed_results=(SeedResult("trigger.event", seed),),
            conversation_id=str(trig.conversation_id) if trig.conversation_id else None,
            conversation_title=f"Trigger: {trig.label}"[:512],
            max_rounds=MAX_ROUNDS,
            deadline_s=self._run_deadline_s,
            run_id=run_id,
            queue_wait_s=QUEUE_WAIT_SECONDS,
        )
        try:
            # The runner's slot wait is bounded by queue_wait_s and budgeted
            # here, on top of the run's own deadline.
            outcome = await asyncio.wait_for(
                self.runner.run(request),
                timeout=QUEUE_WAIT_SECONDS + self._run_deadline_s + _DEADLINE_MARGIN_S,
            )
        except asyncio.CancelledError:
            if run_id is not None:
                await asyncio.shield(self._ledger.finish_run(run_id, status="stopped"))
            raise
        except asyncio.TimeoutError:
            outcome = UnattendedOutcome(status="timed_out", run_id=run_id)
        except Exception as exc:
            logger.error("trigger_run_error", trigger_id=str(trig.id), error_type=type(exc).__name__)
            outcome = UnattendedOutcome(status="failed", run_id=run_id)
        await self._after_run(trig, events, outcome, run_id, connector_type)

    async def _after_run(
        self,
        trig: _Trigger,
        events: list[_Event],
        outcome: UnattendedOutcome,
        run_id: Optional[str],
        connector_type: str,
    ) -> None:
        delivered: tuple[str, ...] = ()
        if outcome.status == "skipped_busy":
            # No runner slot came free in time: nothing ran, so the run is
            # given back and the events wait for the next sweep.
            await self._give_back_run(trig)
            if run_id is not None:
                await self._ledger.finish_run(run_id, status="skipped_busy")
            await self._release(events)
            logger.info("trigger_run_deferred_busy", trigger_id=str(trig.id), events=len(events))
            return
        if outcome.status == "skipped_budget":
            await self._give_back_run(trig)
            if run_id is not None:
                await self._ledger.finish_run(run_id, status="skipped_budget")
            await self._suppress(
                trig, events, "today's budget for tasks run while you are away is used up.", "budget"
            )
            return
        if outcome.status in FAILED_STATUSES:
            line = shape.NOT_CONFIGURED_LINE if outcome.status == "not_configured" else shape.RUN_FAILED_LINE
            ok = await self._notify(
                trig,
                events,
                extra=(line,),
                status="failed",
                note=outcome.status,
                conversation_id=outcome.conversation_id,
            )
            delivered = ("chat",) if ok else ()
        else:
            text = shape.run_text(
                trig.label,
                outcome.reply,
                notes=self._run_notes(outcome),
                usage_line=self._usage(outcome),
                allowed=shape.allowed_hosts(connector_type, [e.facts for e in events]),
                web_title=f"Trigger: {trig.label}",
            )
            ok = await self._deliver(trig.user_id, text)
            delivered = ("chat",) if ok else ()
            await self._finish(events, "ran", "stopped" if outcome.status == "stopped" else None)
            await self._fired(trig, outcome.conversation_id)
        if outcome.conversation_id:
            delivered = (*delivered, "web")
        if run_id is not None:
            await self._ledger.finish_run(
                run_id,
                status=outcome.status,
                input_tokens=int(outcome.usage.get("input_tokens") or 0),
                output_tokens=int(outcome.usage.get("output_tokens") or 0),
                cost_usd=float(outcome.cost_usd or 0.0),
                delivered=list(delivered),
                error=_RUN_ERRORS.get(outcome.status),
                message_id=outcome.message_id,
            )
        await self._audit(
            trig.user_id,
            "trigger_run",
            {
                "trigger_id": str(trig.id),
                "run_id": run_id,
                "status": outcome.status,
                "events": len(events),
                "cards": outcome.cards,
                "cost_usd": round(float(outcome.cost_usd or 0.0), 6),
                "delivered": list(delivered),
            },
        )

    @staticmethod
    def _run_notes(outcome: UnattendedOutcome) -> list[str]:
        notes: list[str] = []
        if outcome.cards == 1:
            notes.append(f"1 action is waiting for your approval ({_PENDING_HINT}).")
        elif outcome.cards > 1:
            notes.append(f"{outcome.cards} actions are waiting for your approval ({_PENDING_HINT}).")
        if outcome.blocked:
            notes.append("Not run (outside this trigger's tools): " + ", ".join(outcome.blocked) + ".")
        if outcome.status == "over_budget":
            notes.append("Stopped at this run's budget.")
        elif outcome.status == "stopped":
            notes.append("Stopped because you asked Crawler to stop.")
        return notes

    @staticmethod
    def _usage(outcome: UnattendedOutcome) -> Optional[str]:
        if not outcome.usage:
            return None
        from services.notifications import cards

        return cards.usage_line({"usage": dict(outcome.usage), "provider": outcome.provider, "model": outcome.model})

    # -- delivery and audit -----------------------------------------------------------

    async def _deliver(self, user_id: uuid.UUID, text: str) -> bool:
        if self.send is None:
            return False
        try:
            # The owner's own linked chats only; False while none is linked.
            return (await self.send(str(user_id), text)) is True
        except Exception as exc:
            # Not retried: a broken channel must not turn into a storm.
            logger.warning("trigger_delivery_failed", error_type=type(exc).__name__)
            return False

    async def _audit(self, user_id: uuid.UUID, action: str, data: dict[str, Any]) -> None:
        """One row in the owner's audit log for what the sweeper did on its
        own: ids, counts, statuses and costs, never content or addresses."""
        if not self._audit_enabled:
            return
        from models.audit import AuditStatus
        from services.audit import append_audit_log

        status = AuditStatus.blocked if action in ("trigger_suppressed", "trigger_stopped") else AuditStatus.approved
        try:
            async with self._session_factory() as session:
                await append_audit_log(
                    session,
                    user_id=user_id,
                    connector_name="triggers",
                    action=action,
                    endpoint="trigger_sweeper",
                    scope_used=CAPABILITY,
                    status=status,
                    request_data=data,
                )
                await session.commit()
        except Exception as exc:
            logger.warning("trigger_audit_failed", error_type=type(exc).__name__)

    # -- Phase C: housekeeping --------------------------------------------------------

    async def _maybe_housekeep(self, now: datetime) -> None:
        if self._last_housekeeping is not None and now - self._last_housekeeping < HOUSEKEEPING_EVERY:
            return
        self._last_housekeeping = now
        try:
            await self.housekeep(now)
        except Exception as exc:
            logger.warning("trigger_housekeeping_failed", error_type=type(exc).__name__)

    async def housekeep(self, now: datetime) -> None:
        """Delete facts older than 7 days (and events older than 30), and
        reset yesterday's run counters."""
        from models.event_trigger import EventTrigger, TriggerEvent

        async with self._session_factory() as session:
            await session.execute(
                update(TriggerEvent)
                .where(
                    TriggerEvent.detected_at < now - timedelta(days=FACTS_RETENTION_DAYS),
                    TriggerEvent.status.in_(list(_TERMINAL)),
                    TriggerEvent.facts.is_not(None),
                )
                # SQL NULL, not a JSON null, so the next pass skips them.
                .values(facts=null())
                .execution_options(synchronize_session=False)
            )
            await session.execute(
                delete(TriggerEvent)
                .where(
                    TriggerEvent.detected_at < now - timedelta(days=EVENTS_RETENTION_DAYS),
                    TriggerEvent.status.in_(list(_TERMINAL)),
                )
                .execution_options(synchronize_session=False)
            )
            await session.execute(
                update(EventTrigger)
                .where(EventTrigger.runs_day.is_not(None), EventTrigger.runs_day != now.date())
                .values(runs_today=0, runs_day=now.date())
                .execution_options(synchronize_session=False)
            )
            await session.commit()
