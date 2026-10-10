"""Tutor mode's database side: loading a conversation's ``TutorTurn`` (its
stored state plus the owner's locks that apply to the user), writing the
state back merged, applying a ``/tutor`` command or the web toggle, the
owner's lock create/list/delete with their audit rows, and the check that
keeps a withheld tool's card from being approved in a tutor chat.

Why it exists: every place a turn runs (the web routes, the Telegram and
Slack appliers, the turn resumed after an approval) and every place the mode
is switched must read and write tutor state the same way. A lock applies to
a user only through rows whose ``user_id`` is theirs or NULL (every account),
so one account's locks never reach another. State is re-read and merged at
write time instead of held under FOR UPDATE, which keeps SQLite installs
working and never loses a command sent while a turn runs.

Connects to: models.tutor_lock.TutorLock, models.conversation.Conversation
(tutor_state), models.pending_action.PendingAction (the approval guard),
services/audit.append_audit_log, and services/tutor/state.py, locks.py,
commands.py, policy.py.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Callable, Optional

import structlog
from sqlalchemy import or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from models.audit import AuditStatus
from models.conversation import Conversation
from models.pending_action import PendingAction, PendingActionStatus
from models.tutor_lock import TutorLock
from models.user import User
from services.audit import append_audit_log
from services.tutor.commands import COMMAND_OFF, COMMAND_ON, COMMAND_STATUS, reply_for
from services.tutor.locks import MAX_LOCKS, CourseLock, LockDraft, validate_lock
from services.tutor.policy import APPROVAL_REFUSAL, TUTOR_MODE_POLICY, is_withheld
from services.tutor.state import TutorState, TutorTurn, merge_for_persist

logger = structlog.get_logger(__name__)

# The capability that switches the whole feature (services/capabilities).
CAPABILITY_KEY = "tutor_mode"
# Audit rows written here are filed under this pseudo-connector, with the
# event as the action, as the runtime files events that name no tool.
_AUDIT_CONNECTOR = "agent"


def _uuid(value: Any) -> Optional[uuid.UUID]:
    if isinstance(value, uuid.UUID):
        return value
    try:
        return uuid.UUID(str(value))
    except (TypeError, ValueError):
        return None


async def load_locks(db: AsyncSession, user_id: Any) -> list[CourseLock]:
    """The locks that apply to *user_id*: their own and every-account ones,
    oldest first (at most the install's cap)."""
    uid = _uuid(user_id)
    if uid is None:
        return []
    rows = (
        await db.execute(
            select(TutorLock)
            .where(or_(TutorLock.user_id == uid, TutorLock.user_id.is_(None)))
            .order_by(TutorLock.created_at, TutorLock.id)
            .limit(MAX_LOCKS)
        )
    ).scalars().all()
    return [CourseLock.from_row(row) for row in rows]


async def load_tutor_turn(
    db: AsyncSession,
    user: Any,
    conversation: Any,
    *,
    enabled: bool,
    channel: str,
    now: Optional[Callable[[], datetime]] = None,
) -> Optional[TutorTurn]:
    """The ``TutorTurn`` for one turn in *conversation*, or None when the
    ``tutor_mode`` capability is off (then nothing about tutor mode applies:
    no block, nothing withheld, locks dormant) or there is no conversation."""
    if not enabled or conversation is None:
        return None
    locks = await load_locks(db, getattr(user, "id", None))
    return TutorTurn(
        TutorState.from_stored(getattr(conversation, "tutor_state", None)),
        locks,
        channel=channel,
        conversation_id=str(getattr(conversation, "id", "")),
        now=now,
    )


async def persist_tutor_state(
    db: AsyncSession, conversation: Any, turn: Optional[TutorTurn]
) -> None:
    """Write *turn*'s state onto *conversation* when it changed, merged over
    what is stored now (re-read here; a command may have written while the
    turn ran). The caller's flush or commit writes it."""
    if turn is None or not turn.changed or conversation is None:
        return
    stored = (
        await db.execute(
            select(Conversation.tutor_state).where(Conversation.id == conversation.id)
        )
    ).scalar_one_or_none()
    merged = merge_for_persist(TutorState.from_stored(stored), turn.state)
    conversation.tutor_state = merged.to_stored()


async def audit_tutor_events(
    db: AsyncSession, user_id: Any, turn: TutorTurn, *, endpoint: str
) -> None:
    """Write *turn*'s pending tutor events as audit rows (ids and
    how-it-happened only; never message text)."""
    for event in turn.drain_events():
        name = str(event.pop("event"))
        await append_audit_log(
            db,
            user_id=str(user_id),
            connector_name=_AUDIT_CONNECTOR,
            action=name,
            endpoint=endpoint,
            scope_used=_AUDIT_CONNECTOR,
            status=AuditStatus.approved,
            reasoning_chain={"event": name},
            request_data=event,
        )


@dataclass(frozen=True)
class TutorView:
    """What the web shows about one conversation's tutor mode."""

    enabled: bool
    mode: str  # "off" | "on" | "locked"
    user_on: bool
    lock_scope: Optional[str] = None  # "course" | "account" while locked
    locked_by: Optional[str] = None  # the lock's sanitised label
    off_command: str = "/tutor off"

    def as_dict(self) -> dict[str, Any]:
        return {
            "enabled": self.enabled,
            "mode": self.mode,
            "user_on": self.user_on,
            "lock_scope": self.lock_scope,
            "locked_by": self.locked_by,
            "off_command": self.off_command,
        }


def view_of(turn: Optional[TutorTurn]) -> TutorView:
    if turn is None:
        return TutorView(enabled=False, mode="off", user_on=False)
    effective = turn.effective
    return TutorView(
        enabled=True,
        mode=effective.mode,
        user_on=turn.state.user_on,
        lock_scope=effective.source if effective.locked else None,
        locked_by=effective.label if effective.locked else None,
        off_command=turn.off_command,
    )


@dataclass(frozen=True)
class CommandOutcome:
    reply: str
    changed: bool
    view: TutorView


async def apply_command(
    db: AsyncSession,
    user: Any,
    conversation: Any,
    command: str,
    *,
    enabled: bool,
    channel: str,
    when_denied: str,
    via: Optional[str] = None,
    now: Optional[Callable[[], datetime]] = None,
) -> CommandOutcome:
    """Apply the person's ``/tutor on|off|status`` (or the web toggle, with
    ``via="ui"``) to *conversation*: the state is changed, merged over what
    is stored and audited, and the fixed reply comes back. The caller owns
    the transaction. With the capability off nothing changes and the reply
    is ``when_denied``."""
    if not enabled:
        return CommandOutcome(when_denied, False, view_of(None))
    turn = await load_tutor_turn(db, user, conversation, enabled=True, channel=channel, now=now)
    assert turn is not None
    if command in (COMMAND_ON, COMMAND_OFF):
        turn.set_user(command == COMMAND_ON, via=via or f"command:{channel}")
        await persist_tutor_state(db, conversation, turn)
        await audit_tutor_events(db, user.id, turn, endpoint=f"{channel}:/tutor")
    effective = turn.effective
    reply = reply_for(
        command if command in (COMMAND_ON, COMMAND_OFF) else COMMAND_STATUS,
        source=effective.source,
        label=effective.label,
        channel=channel,
        lock_labels=turn.lock_labels(),
    )
    return CommandOutcome(reply, turn.changed, view_of(turn))


# ---------------------------------------------------------------------------
# The owner's locks
# ---------------------------------------------------------------------------


async def list_locks(db: AsyncSession) -> list[TutorLock]:
    """Every lock on the install, oldest first (the owner's Settings list)."""
    return list(
        (
            await db.execute(
                select(TutorLock).order_by(TutorLock.created_at, TutorLock.id).limit(MAX_LOCKS)
            )
        )
        .scalars()
        .all()
    )


async def create_lock(
    db: AsyncSession,
    actor: User,
    *,
    scope: Any,
    user_id: Optional[uuid.UUID],
    canvas_course_id: Any = None,
    course_code: Any = None,
    course_name: Any = None,
    aliases: Any = None,
) -> TutorLock:
    """Validate and store one lock for *user_id* (None: every account),
    made by the owner *actor*, and audit it. Raises
    ``services.tutor.locks.LockValidationError`` with the reason."""
    existing = [CourseLock.from_row(row) for row in await list_locks(db)]
    draft: LockDraft = validate_lock(
        scope=scope,
        user_id=str(user_id) if user_id is not None else None,
        canvas_course_id=canvas_course_id,
        course_code=course_code,
        course_name=course_name,
        aliases=aliases,
        existing=existing,
    )
    row = TutorLock(
        user_id=user_id,
        scope=draft.scope,
        canvas_course_id=draft.canvas_course_id,
        course_code=draft.course_code,
        course_name=draft.course_name,
        aliases=list(draft.aliases) or None,
        label=draft.label,
        created_by=actor.id,
    )
    db.add(row)
    await db.flush()
    await _audit_lock(db, actor, "tutor_lock_created", row)
    return row


async def delete_lock(db: AsyncSession, actor: User, lock_id: Any) -> bool:
    """Delete one lock and audit it; False when there is no such lock."""
    uid = _uuid(lock_id)
    if uid is None:
        return False
    row = await db.get(TutorLock, uid)
    if row is None:
        return False
    await _audit_lock(db, actor, "tutor_lock_deleted", row)
    await db.delete(row)
    await db.flush()
    return True


async def _audit_lock(db: AsyncSession, actor: User, event: str, row: TutorLock) -> None:
    await append_audit_log(
        db,
        user_id=actor.id,
        connector_name=_AUDIT_CONNECTOR,
        action=event,
        endpoint="/api/tutor/locks",
        scope_used=_AUDIT_CONNECTOR,
        status=AuditStatus.approved,
        reasoning_chain={"event": event},
        request_data={
            "lock_id": str(row.id),
            "scope": row.scope,
            "target": "all" if row.user_id is None else "account",
            "label": row.label,
        },
    )


def applies_to_label(row: TutorLock, emails: dict[uuid.UUID, str]) -> str:
    """Who a lock applies to, as the Settings list shows it."""
    if row.user_id is None:
        return "every account"
    return emails.get(row.user_id, "an account")


# ---------------------------------------------------------------------------
# The approval guard
# ---------------------------------------------------------------------------


async def approval_refusal(
    db: AsyncSession, user: Any, action_id: Any, *, enabled: bool
) -> Optional[str]:
    """The refusal to give when *user* approves card *action_id*: its tool is
    withheld in tutor mode (canvas.submit_assignment) and the conversation
    it was parked in is in tutor mode now (a card made before the mode came
    on). None: the approval goes ahead as usual."""
    if not enabled:
        return None
    action_uuid = _uuid(action_id)
    user_id = _uuid(getattr(user, "id", None))
    if action_uuid is None or user_id is None:
        return None
    row = (
        await db.execute(
            select(PendingAction.tool_name, PendingAction.conversation_id).where(
                PendingAction.id == action_uuid,
                PendingAction.user_id == user_id,
                PendingAction.status == PendingActionStatus.pending,
            )
        )
    ).first()
    if row is None or row.conversation_id is None or not is_withheld(row.tool_name):
        return None
    conversation = (
        await db.execute(
            select(Conversation).where(
                Conversation.id == row.conversation_id, Conversation.user_id == user_id
            )
        )
    ).scalar_one_or_none()
    turn = await load_tutor_turn(db, user, conversation, enabled=True, channel="web")
    if turn is None or not turn.effective.on:
        return None
    return APPROVAL_REFUSAL


async def audit_approval_refusal(
    db: AsyncSession, user: Any, action_id: str, tool_name: str, reason: str
) -> None:
    """The ``tool_blocked`` row for an approval refused by tutor mode."""
    connector, _, action = tool_name.partition(".")
    await append_audit_log(
        db,
        user_id=str(user.id),
        connector_name=connector or _AUDIT_CONNECTOR,
        action=action or tool_name,
        endpoint="agent.tool_blocked",
        scope_used=connector or _AUDIT_CONNECTOR,
        status=AuditStatus.blocked,
        reasoning_chain={
            "event": "tool_blocked",
            "reason": reason,
            "policy": TUTOR_MODE_POLICY,
            "action_id": action_id,
        },
        response_summary=reason,
    )


async def export_locks(db: AsyncSession, user_id: Any) -> list[dict[str, Any]]:
    """The locks that apply to *user_id*, for their account export."""
    uid = _uuid(user_id)
    if uid is None:
        return []
    rows = (
        await db.execute(
            select(TutorLock)
            .where(or_(TutorLock.user_id == uid, TutorLock.user_id.is_(None)))
            .order_by(TutorLock.created_at, TutorLock.id)
            .limit(MAX_LOCKS)
        )
    ).scalars().all()
    return [
        {
            "scope": row.scope,
            "applies_to": "every account" if row.user_id is None else "this account",
            "label": row.label,
            "canvas_course_id": row.canvas_course_id,
            "course_code": row.course_code,
            "course_name": row.course_name,
            "aliases": row.aliases,
            "created_at": row.created_at,
        }
        for row in rows
    ]
