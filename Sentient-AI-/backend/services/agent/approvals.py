"""Stores tool calls that are waiting for a human approve/deny decision, in memory
or in the database.

Why it exists: The runtime has to park an approval-gated call somewhere that
enforces ownership, single use and expiry whatever the backend; the runtime,
the Telegram poller and main.py go through this store rather than the
pending_actions table.

Pending-approval stores for the agent runtime.

When the permission engine says a tool call ``requires_approval``, the
runtime parks it in an approval store and surfaces it to the user. The
user's approve/deny decision is checked against the store, which enforces
three invariants regardless of backend:

- **Ownership**: only the user who triggered the action can decide it.
- **Single use**: a pending action can be decided exactly once.
- **Expiry**: undecided actions expire after a TTL and can never run.

``DbApprovalStore`` is the production backend (survives restarts, works
across workers). ``InMemoryApprovalStore`` backs unit tests and keeps the
runtime usable without a database.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Literal, Optional, Protocol

import structlog

logger = structlog.get_logger(__name__)

DEFAULT_TTL_MINUTES = 15

DecideOutcome = Literal["ok", "not_found", "expired"]


@dataclass(frozen=True)
class StoredAction:
    """Store-agnostic view of one pending action."""

    action_id: str
    user_id: str
    tool_name: str
    arguments: dict[str, Any]
    reason: str
    created_at: str
    expires_at: str
    conversation_id: Optional[str] = None
    # Populated when the arguments were derived from untrusted tool data;
    # rendered as a warning on the approval card.
    risk_note: Optional[str] = None


class ApprovalStore(Protocol):
    async def create(
        self,
        *,
        user_id: str,
        tool_name: str,
        arguments: dict[str, Any],
        reason: str,
        conversation_id: Optional[str] = None,
        ttl_minutes: int = DEFAULT_TTL_MINUTES,
        risk_note: Optional[str] = None,
    ) -> StoredAction: ...

    async def list_pending(self, user_id: str) -> list[StoredAction]: ...

    async def decide(
        self, action_id: str, user_id: str, approved: bool
    ) -> tuple[DecideOutcome, Optional[StoredAction]]: ...


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _as_utc(dt: datetime) -> datetime:
    """Normalize naive timestamps (SQLite backend) to UTC-aware."""
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt


# ---------------------------------------------------------------------------
# In-memory backend (tests / no-database fallback)
# ---------------------------------------------------------------------------


@dataclass
class _MemRecord:
    action: StoredAction
    expires: datetime
    status: str = "pending"


class InMemoryApprovalStore:
    """Single-process store. Pending actions are lost on restart — the
    production deployment injects ``DbApprovalStore`` instead."""

    def __init__(self) -> None:
        self._records: dict[str, _MemRecord] = {}

    async def create(
        self,
        *,
        user_id: str,
        tool_name: str,
        arguments: dict[str, Any],
        reason: str,
        conversation_id: Optional[str] = None,
        ttl_minutes: int = DEFAULT_TTL_MINUTES,
        risk_note: Optional[str] = None,
    ) -> StoredAction:
        now = _utcnow()
        expires = now + timedelta(minutes=ttl_minutes)
        action = StoredAction(
            action_id=str(uuid.uuid4()),
            user_id=user_id,
            tool_name=tool_name,
            arguments=dict(arguments),
            reason=reason,
            created_at=now.isoformat(),
            expires_at=expires.isoformat(),
            conversation_id=conversation_id,
            risk_note=risk_note,
        )
        self._records[action.action_id] = _MemRecord(action=action, expires=expires)
        return action

    async def list_pending(self, user_id: str) -> list[StoredAction]:
        now = _utcnow()
        out: list[StoredAction] = []
        for record in self._records.values():
            if record.status != "pending" or record.action.user_id != user_id:
                continue
            if record.expires <= now:
                record.status = "expired"
                continue
            out.append(record.action)
        return out

    async def decide(
        self, action_id: str, user_id: str, approved: bool
    ) -> tuple[DecideOutcome, Optional[StoredAction]]:
        record = self._records.get(action_id)
        if record is None or record.action.user_id != user_id or record.status != "pending":
            return "not_found", None
        if record.expires <= _utcnow():
            record.status = "expired"
            return "expired", None
        record.status = "approved" if approved else "denied"
        return "ok", record.action


# ---------------------------------------------------------------------------
# Database backend
# ---------------------------------------------------------------------------


class DbApprovalStore:
    """Persists pending actions in the ``pending_actions`` table.

    Opens its own short-lived sessions via the injected factory, because
    the runtime that calls it is a process-wide singleton with no request
    scope.
    """

    def __init__(self, session_factory: Optional[Callable[[], Any]] = None) -> None:
        if session_factory is None:
            from core.database import async_session

            session_factory = async_session
        self._session_factory = session_factory

    @staticmethod
    def _to_stored(row: Any) -> StoredAction:
        return StoredAction(
            action_id=str(row.id),
            user_id=str(row.user_id),
            tool_name=row.tool_name,
            arguments=dict(row.arguments or {}),
            reason=row.reason,
            created_at=_as_utc(row.created_at).isoformat(),
            expires_at=_as_utc(row.expires_at).isoformat(),
            conversation_id=str(row.conversation_id) if row.conversation_id else None,
            risk_note=getattr(row, "risk_note", None),
        )

    async def create(
        self,
        *,
        user_id: str,
        tool_name: str,
        arguments: dict[str, Any],
        reason: str,
        conversation_id: Optional[str] = None,
        ttl_minutes: int = DEFAULT_TTL_MINUTES,
        risk_note: Optional[str] = None,
    ) -> StoredAction:
        from models.pending_action import PendingAction

        now = _utcnow()
        row = PendingAction(
            user_id=uuid.UUID(user_id),
            conversation_id=uuid.UUID(conversation_id) if conversation_id else None,
            tool_name=tool_name,
            arguments=dict(arguments),
            reason=reason,
            risk_note=risk_note,
            created_at=now,
            expires_at=now + timedelta(minutes=ttl_minutes),
        )
        async with self._session_factory() as session:
            session.add(row)
            await session.flush()
            await session.refresh(row)
            stored = self._to_stored(row)
            await session.commit()
        return stored

    async def list_pending(self, user_id: str) -> list[StoredAction]:
        from sqlalchemy import select

        from models.pending_action import PendingAction, PendingActionStatus

        now = _utcnow()
        async with self._session_factory() as session:
            result = await session.execute(
                select(PendingAction)
                .where(
                    PendingAction.user_id == uuid.UUID(user_id),
                    PendingAction.status == PendingActionStatus.pending,
                )
                .order_by(PendingAction.created_at.asc())
            )
            rows = list(result.scalars().all())

            live: list[StoredAction] = []
            dirty = False
            for row in rows:
                if _as_utc(row.expires_at) <= now:
                    row.status = PendingActionStatus.expired
                    row.decided_at = now
                    dirty = True
                else:
                    live.append(self._to_stored(row))
            if dirty:
                await session.commit()
        return live

    async def decide(
        self, action_id: str, user_id: str, approved: bool
    ) -> tuple[DecideOutcome, Optional[StoredAction]]:
        """Decide a pending action exactly once, even under concurrency.

        Two layers guard the single-use invariant:

        1. ``SELECT ... FOR UPDATE`` row-locks the action on backends that
           support it (Postgres in production). SQLite — the test backend —
           ignores ``FOR UPDATE`` harmlessly.
        2. A conditional ``UPDATE ... WHERE status = 'pending'`` with a
           rowcount check, so on lockless backends (or across workers
           between lock acquisition windows) only ONE concurrent decision
           can flip the row out of ``pending``. The loser gets
           ``not_found`` and the tool is never executed twice.
        """
        from sqlalchemy import select, update

        from models.pending_action import PendingAction, PendingActionStatus

        try:
            action_uuid = uuid.UUID(action_id)
            user_uuid = uuid.UUID(user_id)
        except ValueError:
            return "not_found", None

        now = _utcnow()
        async with self._session_factory() as session:
            result = await session.execute(
                select(PendingAction)
                .where(
                    PendingAction.id == action_uuid,
                    PendingAction.user_id == user_uuid,
                )
                .with_for_update()
            )
            row = result.scalar_one_or_none()
            if row is None or row.status != PendingActionStatus.pending:
                return "not_found", None

            if _as_utc(row.expires_at) <= now:
                expired_update = await session.execute(
                    update(PendingAction)
                    .where(
                        PendingAction.id == action_uuid,
                        PendingAction.status == PendingActionStatus.pending,
                    )
                    .values(status=PendingActionStatus.expired, decided_at=now)
                )
                if expired_update.rowcount == 0:
                    await session.rollback()
                    return "not_found", None
                await session.commit()
                return "expired", None

            stored = self._to_stored(row)
            new_status = (
                PendingActionStatus.approved if approved else PendingActionStatus.denied
            )
            decided_update = await session.execute(
                update(PendingAction)
                .where(
                    PendingAction.id == action_uuid,
                    PendingAction.status == PendingActionStatus.pending,
                )
                .values(status=new_status, decided_at=now)
            )
            if decided_update.rowcount == 0:
                # Another request decided this action between our read and
                # write — it was consumed, so this caller loses.
                await session.rollback()
                return "not_found", None
            await session.commit()
        return "ok", stored
