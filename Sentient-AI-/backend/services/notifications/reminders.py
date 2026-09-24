"""Runs the background sweeper that claims due reminders and delivers them over
the user's linked channel.

Why it exists: Per-reminder timers die with the process; main.py starts this
poll loop so a reminder survives a restart and is claimed atomically before it
is sent.

Reminder delivery.

A single background sweeper claims due reminders and pushes them through
whatever out-of-band channel the user has linked (Telegram today). It is
deliberately a poll loop rather than per-reminder timers: timers do not
survive a restart, and a reminder that silently evaporates because the
process bounced is worse than one delivered a minute late.

Claiming is atomic — the sweeper flips ``scheduled`` to ``delivered`` with
a conditional UPDATE before sending, so two workers (or a restart mid-send)
cannot double-notify. The cost of that ordering is that a reminder lost to
a crash between claim and send is not retried; for a personal assistant
that is the right trade against sending the same nag twice.
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from typing import Any, Callable, Optional

import structlog
from sqlalchemy import select, update

logger = structlog.get_logger(__name__)

# How often to look for due reminders. A minute is well inside what anyone
# notices for a delivery-date nudge, and keeps the query rate trivial.
SWEEP_INTERVAL_SECONDS = 60

# Never deliver a reminder that came due while the server was off by more
# than this — waking up to a week of stale pings helps nobody. Older rows
# are marked delivered without sending.
STALE_AFTER_HOURS = 24


class ReminderService:
    """Sweeps due reminders and delivers them to a notification channel."""

    def __init__(
        self,
        session_factory: Callable[[], Any],
        send: Optional[Callable[[str, str], Any]] = None,
        interval_seconds: int = SWEEP_INTERVAL_SECONDS,
    ) -> None:
        self._session_factory = session_factory
        # send(user_id, text) -> awaitable; injected so the service does not
        # depend on any particular channel.
        self.send = send
        self._interval = interval_seconds
        self._task: Optional[asyncio.Task[None]] = None

    async def start(self) -> None:
        self._task = asyncio.create_task(self._loop(), name="reminder-sweeper")
        logger.info("reminder_sweeper_started", interval=self._interval)

    async def stop(self) -> None:
        if self._task is not None:
            self._task.cancel()
            try:
                await self._task
            except (asyncio.CancelledError, Exception):
                pass
            self._task = None

    async def _loop(self) -> None:
        while True:
            try:
                await self.sweep_once()
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                logger.warning("reminder_sweep_failed", error=str(exc))
            await asyncio.sleep(self._interval)

    async def sweep_once(self) -> int:
        """Deliver every reminder that is due. Returns how many were sent."""
        from models.reminder import Reminder, ReminderStatus

        now = datetime.now(timezone.utc)
        async with self._session_factory() as session:
            due = (
                (
                    await session.execute(
                        select(Reminder)
                        .where(
                            Reminder.status == ReminderStatus.scheduled,
                            Reminder.due_at <= now,
                        )
                        .order_by(Reminder.due_at)
                        .limit(50)
                    )
                )
                .scalars()
                .all()
            )
            claimed: list[tuple[str, str]] = []
            for reminder in due:
                # Conditional update: whoever flips the row owns delivery.
                result = await session.execute(
                    update(Reminder)
                    .where(
                        Reminder.id == reminder.id,
                        Reminder.status == ReminderStatus.scheduled,
                    )
                    .values(
                        status=ReminderStatus.delivered, delivered_at=now
                    )
                )
                if result.rowcount != 1:
                    continue
                due_at = reminder.due_at
                if due_at.tzinfo is None:
                    due_at = due_at.replace(tzinfo=timezone.utc)
                stale = (now - due_at).total_seconds() > STALE_AFTER_HOURS * 3600
                if stale:
                    logger.info(
                        "reminder_skipped_stale", reminder_id=str(reminder.id)
                    )
                    continue
                text = f"⏰ {reminder.title}"
                if reminder.note:
                    text += f"\n\n{reminder.note}"
                claimed.append((str(reminder.user_id), text))
            await session.commit()

        if self.send is None:
            return 0
        sent = 0
        for user_id, text in claimed:
            try:
                # The Telegram manager answers False while no poller runs
                # (or the user has no linked chat); that reminder is not
                # delivered, and is not retried either — same as a failure.
                if await self.send(user_id, text) is not False:
                    sent += 1
            except Exception as exc:
                # The row is already claimed; log loudly rather than retry,
                # so a broken channel cannot turn into a delivery storm.
                logger.warning(
                    "reminder_delivery_failed", user_id=user_id, error=str(exc)
                )
        return sent
