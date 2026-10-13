"""The ledger of unattended runs (the ``automation_runs`` table): opening a run
for one occurrence exactly once, closing it with its outcome, summing a
user's spend and run count over the last 24 hours, and pruning old rows.

Why it exists: the unique (task_id, scheduled_for) index makes ``start_run``
the idempotency guard across workers and restarts: a second start for the
same occurrence gets None and does nothing. Scheduled tasks and (wave 2)
event triggers share one ledger, so one daily budget covers both. Rows hold
ids, statuses, token counts and cost only.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Optional

import structlog
from sqlalchemy import delete, func, select, update
from sqlalchemy.exc import IntegrityError

logger = structlog.get_logger(__name__)

# Statuses that record an occurrence that did not run: they count toward
# neither the spend nor the runs-per-day limit.
SKIPPED_STATUSES = frozenset(
    {
        "skipped_late",
        "skipped_budget",
        "skipped_busy",
        "skipped_gate",
        "skipped_inactive",
        "skipped_empty",
    }
)
RUN_STATUSES = frozenset(
    {
        "running",
        "ok",
        "card_parked",
        "over_budget",
        "failed",
        "stopped",
        "timed_out",
        "not_configured",
    }
)
RETENTION_DAYS = 90
PRUNE_BATCH = 500
_ERROR_CHARS = 200
_FINISH_FIELDS = frozenset(
    {
        "status",
        "finished_at",
        "input_tokens",
        "output_tokens",
        "cost_usd",
        "delivered",
        "error",
        "message_id",
    }
)


def _uuid(value: Any) -> Optional[uuid.UUID]:
    if isinstance(value, uuid.UUID):
        return value
    try:
        return uuid.UUID(str(value))
    except (TypeError, ValueError):
        return None


class AutomationLedger:
    """``automation_runs`` through short-lived sessions of its own."""

    def __init__(
        self,
        session_factory: Callable[[], Any],
        *,
        clock: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
    ) -> None:
        self._session_factory = session_factory
        self._clock = clock

    async def start_run(
        self,
        user_id: Any,
        origin: str,
        trigger: str,
        *,
        task_id: Any = None,
        scheduled_for: Optional[datetime] = None,
        status: str = "running",
    ) -> Optional[str]:
        """Open the run of one occurrence and return its id, or None when
        that occurrence already has a row (another worker, or a restart,
        got there first). ``status`` is "running", or a skipped status for
        an occurrence recorded without running."""
        from models.scheduled_task import AutomationRun

        owner = _uuid(user_id)
        if owner is None:
            return None
        row = AutomationRun(
            id=uuid.uuid4(),
            user_id=owner,
            origin=origin[:64],
            task_id=_uuid(task_id) if task_id is not None else None,
            scheduled_for=scheduled_for,
            trigger=trigger[:8],
            status=status,
            started_at=self._clock(),
            input_tokens=0,
            output_tokens=0,
            cost_usd=0.0,
        )
        async with self._session_factory() as session:
            session.add(row)
            try:
                await session.commit()
            except IntegrityError:
                await session.rollback()
                return None
        return str(row.id)

    async def finish_run(self, run_id: Any, **fields: Any) -> None:
        """Record a run's outcome. Unknown fields are ignored; ``error`` is
        cut to its column; ``finished_at`` defaults to now."""
        from models.scheduled_task import AutomationRun

        target = _uuid(run_id)
        if target is None:
            return
        values = {k: v for k, v in fields.items() if k in _FINISH_FIELDS}
        values.setdefault("finished_at", self._clock())
        if isinstance(values.get("error"), str):
            values["error"] = values["error"][:_ERROR_CHARS]
        if "message_id" in values:
            values["message_id"] = _uuid(values["message_id"]) if values["message_id"] else None
        async with self._session_factory() as session:
            await session.execute(
                update(AutomationRun).where(AutomationRun.id == target).values(**values)
            )
            await session.commit()

    async def spent_today(self, user_id: Any, *, exclude: Any = None) -> tuple[float, int]:
        """(USD spent, runs made) by *user_id*'s unattended runs over the
        last 24 hours. Skipped occurrences count as neither, and neither
        does run *exclude* (the run whose budget is being checked, opened
        as "running" before it starts)."""
        from models.scheduled_task import AutomationRun

        owner = _uuid(user_id)
        if owner is None:
            return 0.0, 0
        since = self._clock() - timedelta(hours=24)
        query = select(
            func.coalesce(func.sum(AutomationRun.cost_usd), 0.0),
            func.count(AutomationRun.id),
        ).where(
            AutomationRun.user_id == owner,
            AutomationRun.started_at >= since,
            AutomationRun.status.not_in(SKIPPED_STATUSES),
        )
        skip = _uuid(exclude) if exclude is not None else None
        if skip is not None:
            query = query.where(AutomationRun.id != skip)
        async with self._session_factory() as session:
            spent, runs = (await session.execute(query)).one()
        return float(spent or 0.0), int(runs or 0)

    async def count_since(
        self, user_id: Any, status: str, since: datetime, *, exclude: Any = None
    ) -> int:
        """How many of *user_id*'s runs with *status* started at or after
        *since*, leaving out run *exclude* (for "one notice per 24 hours")."""
        from models.scheduled_task import AutomationRun

        owner = _uuid(user_id)
        if owner is None:
            return 0
        query = select(func.count(AutomationRun.id)).where(
            AutomationRun.user_id == owner,
            AutomationRun.status == status,
            AutomationRun.started_at >= since,
        )
        skip = _uuid(exclude) if exclude is not None else None
        if skip is not None:
            query = query.where(AutomationRun.id != skip)
        async with self._session_factory() as session:
            return int((await session.execute(query)).scalar_one() or 0)

    async def prune(self, older_than_days: int = RETENTION_DAYS, batch: int = PRUNE_BATCH) -> int:
        """Delete up to *batch* runs older than *older_than_days*; returns
        how many went. The sweeper calls it again while it keeps finding
        some, a batch at a time."""
        from models.scheduled_task import AutomationRun

        cutoff = self._clock() - timedelta(days=older_than_days)
        async with self._session_factory() as session:
            ids = (
                (
                    await session.execute(
                        select(AutomationRun.id)
                        .where(AutomationRun.started_at < cutoff)
                        .order_by(AutomationRun.started_at)
                        .limit(batch)
                    )
                )
                .scalars()
                .all()
            )
            if not ids:
                return 0
            await session.execute(delete(AutomationRun).where(AutomationRun.id.in_(list(ids))))
            await session.commit()
        return len(ids)
