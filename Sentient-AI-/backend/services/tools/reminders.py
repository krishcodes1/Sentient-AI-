"""Implements the reminders.* built-in tools: read the clock, and create, list and
cancel the caller's reminders.

Why it exists: The tool registry dispatches reminders.* here with the caller's
identity, so the model can never address another user's reminders and the time
validation stops it scheduling one in the past.

Built-in reminder tools: read the clock, set, list and cancel reminders.

The agent sets reminders on the user's behalf from chat ("remind me
tomorrow at 9am to submit the report"). Rows land in the same
``reminders`` table the REST route writes, tagged ``source=agent`` so the
UI can show who set them, and the sweeper in
``services.notifications.reminders`` delivers them exactly as it does
user-created ones.

Three constraints shape the module:

- **Ownership.** ``user_id`` is the caller's identity as the executor
  knows it, never a tool argument; a model cannot address another user's
  reminders, and a foreign or unknown id reads as "not found" so the tool
  never confirms one exists.
- **Time.** Models are bad at clock arithmetic and have no idea what
  "tomorrow" is. ``now`` exists so the model reads the real clock (with
  the server's UTC offset) before computing an absolute ``due_at``; the
  validation here then refuses times in the past or absurdly far out
  rather than quietly scheduling a reminder nobody will ever see.
- **Cost.** Every field returned is small and bounded: the user pays per
  token for tool output.

Tool errors are results, not exceptions — the model has to read what went
wrong and try again.
"""

from __future__ import annotations

import inspect
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Awaitable, Callable, Optional

import structlog
from sqlalchemy import select
from sqlalchemy.exc import SQLAlchemyError

logger = structlog.get_logger(__name__)

# Same bounds as the REST route so the two write paths cannot disagree
# about what a valid reminder is.
_MAX_TITLE_CHARS = 200
_MAX_NOTE_CHARS = 2000
_MAX_HORIZON_DAYS = 3650
# One year in minutes; anything longer should be given as a date.
_MAX_DELAY_MINUTES = 525600
# Covers clock skew plus the model's own latency between reading the
# clock and calling create, so "remind me in a minute" is not rejected.
_PAST_GRACE_SECONDS = 60
_LIST_LIMIT = 20


def _error(message: str, **extra: Any) -> dict[str, Any]:
    return {"ok": False, "error": message, **extra}


def _not_found() -> dict[str, Any]:
    return _error("Reminder not found.", not_found=True)


def _utc(value: datetime) -> datetime:
    # SQLite hands back naive datetimes for timezone-aware columns; every
    # value written here is UTC, so that is the only reading of a naive one.
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _iso(value: datetime) -> str:
    return _utc(value).isoformat(timespec="seconds")


def _minutes_until(value: datetime, now: datetime) -> int:
    return round((_utc(value) - now).total_seconds() / 60)


def _clean_text(value: Any, field: str, limit: int) -> tuple[Optional[str], Optional[str]]:
    """Validate free text the model supplies. Returns (text, error)."""
    if not isinstance(value, str):
        return None, f"'{field}' must be a string."
    if "\x00" in value:
        # Postgres text columns cannot hold NUL and the driver fails deep
        # inside the write; the REST route rejects it at the boundary too.
        return None, f"'{field}' must not contain null bytes."
    text = value.strip()
    if len(text) > limit:
        return None, f"'{field}' is too long ({len(text)} chars; max {limit})."
    return text, None


class ReminderToolkit:
    """Executes the built-in ``reminders.*`` actions for one caller.

    ``session_factory`` is the application's async session factory. Without
    one the toolkit still tells the time but refuses every action that
    would touch the database (fail closed), matching how the executor
    treats connector tools.
    """

    def __init__(self, session_factory: Optional[Callable[[], Any]] = None) -> None:
        self._session_factory = session_factory

    # -- Dispatch ------------------------------------------------------------

    async def execute(
        self, action: str, params: dict[str, Any], user_id: str
    ) -> dict[str, Any]:
        """Run one ``reminders.*`` action as *user_id*. Unknown actions fail closed."""
        handlers: dict[str, Callable[..., Awaitable[dict[str, Any]]]] = {
            "now": self.now,
            "create": self.create,
            "list": self.list,
            "cancel": self.cancel,
        }
        handler = handlers.get(action)
        if handler is None:
            return _error(f"Unknown reminders action '{action}'.")

        # The owner is whoever the executor says is calling. A user_id the
        # model put in the arguments is dropped, not honored.
        params = {k: v for k, v in (params or {}).items() if k != "user_id"}
        try:
            inspect.signature(handler).bind(user_id, **params)
        except TypeError as exc:
            return _error(f"Invalid arguments for reminders.{action}: {exc}")

        try:
            return await handler(user_id, **params)
        except SQLAlchemyError as exc:
            logger.error("reminder_tool_db_error", action=action, error=str(exc))
            return _error("Reminder storage is unavailable; try again shortly.")
        except Exception as exc:  # noqa: BLE001 - a tool failure is a result
            logger.error("reminder_tool_unexpected_error", action=action, error=str(exc))
            return _error(f"Reminder action failed: {type(exc).__name__}")

    def _owner(self, user_id: str) -> Optional[uuid.UUID]:
        try:
            return uuid.UUID(str(user_id))
        except (TypeError, ValueError):
            return None

    # -- Actions -------------------------------------------------------------

    async def now(self, user_id: str) -> dict[str, Any]:
        """The current time, in UTC and in the server's local zone with offset."""
        local = datetime.now().astimezone()
        return {
            "ok": True,
            "now_utc": local.astimezone(timezone.utc).isoformat(timespec="seconds"),
            "now_local": local.isoformat(timespec="seconds"),
            "timezone": local.tzname() or "UTC",
            "weekday": local.strftime("%A"),
        }

    async def create(
        self,
        user_id: str,
        title: Any = None,
        note: Any = None,
        due_at: Any = None,
        delay_minutes: Any = None,
    ) -> dict[str, Any]:
        """Schedule a reminder for the caller at ``due_at`` or in ``delay_minutes``."""
        if self._session_factory is None:
            return _error("Reminders are not configured (no database session factory).")
        owner = self._owner(user_id)
        if owner is None:
            return _error("Reminders need a signed-in user.")

        clean_title, err = _clean_text(title, "title", _MAX_TITLE_CHARS)
        if err:
            return _error(err)
        if not clean_title:
            return _error("A non-empty 'title' is required.")
        clean_note: Optional[str] = None
        if note is not None:
            clean_note, err = _clean_text(note, "note", _MAX_NOTE_CHARS)
            if err:
                return _error(err)
            clean_note = clean_note or None

        if (due_at is None) == (delay_minutes is None):
            return _error(
                "Give exactly one of 'due_at' (ISO-8601) or 'delay_minutes'. "
                "For a clock or relative time, call reminders.now first."
            )

        now = datetime.now(timezone.utc)
        if delay_minutes is not None:
            if isinstance(delay_minutes, bool):
                return _error("'delay_minutes' must be an integer.")
            try:
                minutes = int(delay_minutes)
            except (TypeError, ValueError):
                return _error("'delay_minutes' must be an integer.")
            if not 1 <= minutes <= _MAX_DELAY_MINUTES:
                return _error(
                    f"'delay_minutes' must be between 1 and {_MAX_DELAY_MINUTES}; "
                    "use due_at for anything further out."
                )
            due = now + timedelta(minutes=minutes)
        else:
            if not isinstance(due_at, str) or not due_at.strip():
                return _error("'due_at' must be an ISO-8601 string.")
            try:
                parsed = datetime.fromisoformat(due_at.strip())
            except ValueError:
                return _error(
                    f"'due_at' is not ISO-8601: {due_at!r}. Use e.g. "
                    "2026-09-24T09:00:00-04:00 (call reminders.now for the offset)."
                )
            due = _utc(parsed)

        if (now - due).total_seconds() > _PAST_GRACE_SECONDS:
            return _error(
                f"due_at {_iso(due)} is in the past (now {_iso(now)}). "
                "Call reminders.now and recompute.",
                now_utc=_iso(now),
            )
        if due > now + timedelta(days=_MAX_HORIZON_DAYS):
            return _error("due_at is more than ten years away; that is almost certainly a typo.")

        from models.reminder import Reminder, ReminderSource

        reminder = Reminder(
            # Assigned here rather than by the column default so the id can
            # be reported without re-reading the row after commit.
            id=uuid.uuid4(),
            user_id=owner,
            title=clean_title,
            note=clean_note,
            due_at=due,
            source=ReminderSource.agent,
        )
        async with self._session_factory() as session:
            session.add(reminder)
            await session.commit()

        return {
            "ok": True,
            "reminder_id": str(reminder.id),
            "title": clean_title,
            "due_at": _iso(due),
            "due_at_local": due.astimezone().isoformat(timespec="seconds"),
            "due_in_minutes": _minutes_until(due, now),
        }

    async def list(self, user_id: str) -> dict[str, Any]:
        """The caller's scheduled reminders, soonest first."""
        if self._session_factory is None:
            return _error("Reminders are not configured (no database session factory).")
        owner = self._owner(user_id)
        if owner is None:
            return _error("Reminders need a signed-in user.")

        from models.reminder import Reminder, ReminderStatus

        async with self._session_factory() as session:
            rows = (
                (
                    await session.execute(
                        select(Reminder)
                        .where(
                            Reminder.user_id == owner,
                            Reminder.status == ReminderStatus.scheduled,
                        )
                        .order_by(Reminder.due_at)
                        .limit(_LIST_LIMIT)
                    )
                )
                .scalars()
                .all()
            )

        now = datetime.now(timezone.utc)
        reminders = []
        for row in rows:
            item: dict[str, Any] = {
                "id": str(row.id),
                "title": row.title,
                "due_at": _iso(row.due_at),
                "due_in_minutes": _minutes_until(row.due_at, now),
            }
            if row.note:
                item["note"] = row.note
            reminders.append(item)
        return {"ok": True, "count": len(reminders), "reminders": reminders}

    async def cancel(self, user_id: str, reminder_id: Any = None) -> dict[str, Any]:
        """Cancel one of the caller's scheduled reminders. The row is kept."""
        if self._session_factory is None:
            return _error("Reminders are not configured (no database session factory).")
        owner = self._owner(user_id)
        if owner is None:
            return _error("Reminders need a signed-in user.")
        try:
            target = uuid.UUID(str(reminder_id))
        except (TypeError, ValueError):
            return _not_found()

        from models.reminder import Reminder, ReminderStatus

        async with self._session_factory() as session:
            row = (
                await session.execute(
                    select(Reminder).where(
                        Reminder.id == target, Reminder.user_id == owner
                    )
                )
            ).scalar_one_or_none()
            if row is None:
                return _not_found()
            if row.status == ReminderStatus.delivered:
                return _error("That reminder was already delivered.", status="delivered")
            if row.status == ReminderStatus.scheduled:
                row.status = ReminderStatus.cancelled
                await session.commit()
            title = row.title

        return {
            "ok": True,
            "reminder_id": str(target),
            "title": title,
            "status": "cancelled",
        }
