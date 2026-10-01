"""Declares the ``event_triggers`` table (an owner-approved rule "when X happens
in a connected app, tell me, or run this task") and the ``trigger_events``
table (one row per new item a trigger saw, queued until it is sent or run).

Why it exists: the trigger sweeper (services/notifications/event_triggers.py)
claims due triggers by ``status`` and ``next_check_at`` with a conditional
UPDATE, and queues what each check found in ``trigger_events``, whose unique
(trigger_id, external_key) index is the guard that one item never fires
twice, across workers and restarts. A trigger is pinned to one connector row
and dies with it (ON DELETE CASCADE); it dies with its user too.

Statuses, sources and modes are plain strings validated in code (no Postgres
enum types): a new source or status never needs an ``ALTER TYPE``.
"""

from __future__ import annotations

import uuid
from datetime import date, datetime, timezone
from typing import Any, Optional

from sqlalchemy import (
    JSON,
    Boolean,
    Date,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    Uuid,
    false,
)
from sqlalchemy.orm import Mapped, mapped_column

from core.database import Base

# Column sizes. The toolkit's limits (services/tools/triggers.py) use the
# same numbers, so a row the tool accepted always fits; a test holds them
# equal.
LABEL_MAX_CHARS = 80
SOURCE_MAX_CHARS = 40
PROMPT_MAX_CHARS = 600
ERROR_MAX_CHARS = 200
NOTE_MAX_CHARS = 200
KEY_CHARS = 64

# active: checked on its interval; paused: kept, not checked, nothing sent;
# error: stopped after ERROR_LIMIT failed checks in a row.
TRIGGER_STATUSES = ("active", "paused", "error")
# notify: a fixed-format message built in code, no model; run_task: the
# owner's prompt run as one unattended turn (needs "trigger_runs" on).
TRIGGER_MODES = ("notify", "run_task")
# pending: queued; running: claimed (with a lease); notified / ran: done;
# suppressed: over a cap or the trigger paused; failed: the run failed, or
# a lease expired in a crash ("interrupted", never re-run).
EVENT_STATUSES = ("pending", "running", "notified", "ran", "suppressed", "failed")


def _now() -> datetime:
    return datetime.now(timezone.utc)


class EventTrigger(Base):
    __tablename__ = "event_triggers"
    __table_args__ = (
        # The sweeper's only claim query: active and due, soonest first.
        Index("ix_event_triggers_status_next_check_at", "status", "next_check_at"),
        # triggers.list and the per-user cap.
        Index("ix_event_triggers_user_id_created_at", "user_id", "created_at"),
        # The same rule twice is refused (the toolkit says so first).
        Index("ix_event_triggers_user_id_fingerprint", "user_id", "fingerprint", unique=True),
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid(), primary_key=True, default=uuid.uuid4)
    user_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(), ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )
    label: Mapped[str] = mapped_column(String(LABEL_MAX_CHARS), nullable=False)
    # One of services/triggers/sources.SOURCES.
    source: Mapped[str] = mapped_column(String(SOURCE_MAX_CHARS), nullable=False)
    # The one connector row the trigger reads (NULL only for page.changed).
    connector_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        Uuid(), ForeignKey("connector_configs.id", ondelete="CASCADE"), nullable=True
    )
    # Canonical, validated filters (senders, subject_contains, folder,
    # course_ids, show_score, lead_minutes, watch_id).
    filters: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    # sha256 of the canonical (source, connector_id, filters, mode, prompt).
    fingerprint: Mapped[str] = mapped_column(String(KEY_CHARS), nullable=False)
    mode: Mapped[str] = mapped_column(
        String(16), nullable=False, default="notify", server_default="notify"
    )
    # The owner's own words (mode "run_task" only).
    prompt: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    allow_writes: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default=false()
    )
    interval_minutes: Mapped[int] = mapped_column(Integer, nullable=False)
    max_runs_per_day: Mapped[int] = mapped_column(
        Integer, nullable=False, default=6, server_default="6"
    )
    # The UTC day runs_today counts (a different day reads as zero).
    runs_day: Mapped[Optional[date]] = mapped_column(Date, nullable=True)
    runs_today: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0, server_default="0"
    )
    status: Mapped[str] = mapped_column(
        String(12), nullable=False, default="active", server_default="active"
    )
    # {"watermark": iso8601, "seen": [up to 200 hex16 keys]}.
    cursor: Mapped[Optional[dict[str, Any]]] = mapped_column(JSON, nullable=True)
    # NULL: the next successful check records the baseline and fires nothing.
    baseline_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    next_check_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_checked_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    last_fired_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    consecutive_errors: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0, server_default="0"
    )
    # Always the sweeper's own sentence, never vendor or content text.
    last_error: Mapped[Optional[str]] = mapped_column(String(ERROR_MAX_CHARS), nullable=True)
    # The trigger's own thread ("Trigger: <label>"), made on the first run.
    conversation_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        Uuid(), ForeignKey("conversations.id", ondelete="SET NULL"), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_now
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_now, onupdate=_now
    )

    def __repr__(self) -> str:
        return f"<EventTrigger {self.id} source={self.source} status={self.status}>"


class TriggerEvent(Base):
    """One new item a trigger saw: its hashed external id, shaped and capped
    facts (untrusted content; nulled after 7 days), and what became of it.
    Never a mail body in a message the owner is sent."""

    __tablename__ = "trigger_events"
    __table_args__ = (
        # The dedupe guard: an insert conflict is caught as IntegrityError.
        Index(
            "ix_trigger_events_trigger_id_external_key",
            "trigger_id",
            "external_key",
            unique=True,
        ),
        # The act phase's claim and the purge.
        Index("ix_trigger_events_status_detected_at", "status", "detected_at"),
        Index("ix_trigger_events_user_id_detected_at", "user_id", "detected_at"),
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid(), primary_key=True, default=uuid.uuid4)
    trigger_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(), ForeignKey("event_triggers.id", ondelete="CASCADE"), nullable=False
    )
    user_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(), ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )
    # sha256 hex of "<source>:<external id>".
    external_key: Mapped[str] = mapped_column(String(KEY_CHARS), nullable=False)
    status: Mapped[str] = mapped_column(
        String(16), nullable=False, default="pending", server_default="pending"
    )
    facts: Mapped[Optional[dict[str, Any]]] = mapped_column(JSON, nullable=True)
    # The same value for the events one message or one run handled.
    batch_id: Mapped[Optional[uuid.UUID]] = mapped_column(Uuid(), nullable=True)
    claimed_until: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    detected_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_now
    )
    handled_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    # The sweeper's own short note ("and 3 more", "interrupted", "runs_off").
    note: Mapped[Optional[str]] = mapped_column(String(NOTE_MAX_CHARS), nullable=True)

    def __repr__(self) -> str:
        return f"<TriggerEvent {self.id} trigger={self.trigger_id} status={self.status}>"
