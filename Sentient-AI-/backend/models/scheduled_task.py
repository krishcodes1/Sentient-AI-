"""Declares the ``scheduled_tasks`` table (a prompt the owner approved to run
on a recurrence, the daily briefing, or a feature's nudge) and the
``automation_runs`` table (one row per unattended run or skipped occurrence,
with its status, tokens, cost and where it was delivered).

Why it exists: the schedule sweeper claims due tasks by ``status`` and
``next_run_at`` and records every occurrence in ``automation_runs``, whose
unique (task_id, scheduled_for) index is the guard that no occurrence ever
runs twice, across workers and restarts. The same ledger holds the runs of
event triggers (wave 2), so the per-user daily budget is one sum.

Statuses and kinds are plain strings validated in code (no Postgres enum
types): a new kind or status never needs an ``ALTER TYPE``.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any, Optional

from sqlalchemy import JSON, DateTime, Float, ForeignKey, Index, Integer, String, Text, Uuid
from sqlalchemy.orm import Mapped, mapped_column

from core.database import Base

# Column sizes. The toolkit's limits (services/tools/schedule.py) are the
# same numbers, so a row the tool accepted always fits; a test holds them
# equal.
LABEL_MAX_CHARS = 80
PROMPT_MAX_CHARS = 2000
ERROR_MAX_CHARS = 200
TIMEZONE_MAX_CHARS = 64
ORIGIN_MAX_CHARS = 64

# What a task is. "prompt": an unattended agent turn on the owner's own
# words; "briefing": the built-in daily briefing (code-built, one optional
# model call without tools); "nudge": a feature's reminder text rendered by
# a registered renderer with no model (services/scheduler/renderers.py).
TASK_KINDS = ("prompt", "briefing", "nudge")
# active: swept on schedule; paused: kept, not run; error: stopped after
# ERROR_LIMIT failures in a row; done: a once task that has run.
TASK_STATUSES = ("active", "paused", "error", "done")
# Where a task came from: the agent (behind an approval card), the owner's
# own REST call or channel command, or a feature (a nudge).
TASK_SOURCES = ("agent", "user", "feature")


def _now() -> datetime:
    return datetime.now(timezone.utc)


class ScheduledTask(Base):
    __tablename__ = "scheduled_tasks"
    __table_args__ = (
        # The sweeper's only query: active and due, soonest first.
        Index("ix_scheduled_tasks_status_next_run_at", "status", "next_run_at"),
        # One label per user; the briefing's fixed label keeps it to one.
        Index("ix_scheduled_tasks_user_id_label", "user_id", "label", unique=True),
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid(), primary_key=True, default=uuid.uuid4)
    user_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(), ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )
    kind: Mapped[str] = mapped_column(String(16), nullable=False)
    label: Mapped[str] = mapped_column(String(LABEL_MAX_CHARS), nullable=False)
    # The owner's own words (kind "prompt" only).
    prompt: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    # prompt: {tools, write_tools}; briefing: {sections, topic, summary};
    # nudge: {renderer}.
    options: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    # {freq, time, days?, day_of_month?, date?} (services/scheduler/recurrence.py).
    recurrence: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)
    timezone: Mapped[str] = mapped_column(String(TIMEZONE_MAX_CHARS), nullable=False)
    # A subset of ["telegram", "slack"]; the web conversation always gets it.
    channels: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    status: Mapped[str] = mapped_column(
        String(12), nullable=False, default="active", server_default="active"
    )
    next_run_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_run_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    last_status: Mapped[Optional[str]] = mapped_column(String(24), nullable=True)
    # Always the service's own sentence, never fetched or model text.
    last_error: Mapped[Optional[str]] = mapped_column(String(ERROR_MAX_CHARS), nullable=True)
    consecutive_errors: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0, server_default="0"
    )
    # The web conversation the runs write into ("Scheduled: <label>").
    # Deleting that chat means the next run starts a new one.
    conversation_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        Uuid(), ForeignKey("conversations.id", ondelete="SET NULL"), nullable=True
    )
    source: Mapped[str] = mapped_column(String(8), nullable=False, default="agent")
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_now
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_now, onupdate=_now
    )

    def __repr__(self) -> str:
        return f"<ScheduledTask {self.id} kind={self.kind} status={self.status}>"


class AutomationRun(Base):
    """One unattended run (or a skipped occurrence) of a scheduled task or,
    later, an event trigger. Holds ids, statuses, token counts and cost
    only: never the prompt, the reply or fetched text."""

    __tablename__ = "automation_runs"
    __table_args__ = (
        # The idempotency guard: one row per occurrence of a task. NULLs
        # (trigger runs, which have no task) never collide.
        Index(
            "ix_automation_runs_task_id_scheduled_for",
            "task_id",
            "scheduled_for",
            unique=True,
        ),
        # The rolling 24-hour budget sum per user.
        Index("ix_automation_runs_user_id_started_at", "user_id", "started_at"),
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid(), primary_key=True, default=uuid.uuid4)
    user_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(), ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )
    # "schedule:<task id>" or "trigger:<trigger id>".
    origin: Mapped[str] = mapped_column(String(ORIGIN_MAX_CHARS), nullable=False)
    task_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        Uuid(), ForeignKey("scheduled_tasks.id", ondelete="CASCADE"), nullable=True
    )
    scheduled_for: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    # "schedule" (the sweeper), "manual" (run now) or "event" (a trigger).
    trigger: Mapped[str] = mapped_column(String(8), nullable=False)
    status: Mapped[str] = mapped_column(String(24), nullable=False)
    started_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_now
    )
    finished_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    input_tokens: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    output_tokens: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    cost_usd: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    # The channels that received the result, e.g. ["telegram", "web"].
    delivered: Mapped[Optional[list[str]]] = mapped_column(JSON, nullable=True)
    error: Mapped[Optional[str]] = mapped_column(String(ERROR_MAX_CHARS), nullable=True)
    message_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        Uuid(), ForeignKey("messages.id", ondelete="SET NULL"), nullable=True
    )

    def __repr__(self) -> str:
        return f"<AutomationRun {self.id} origin={self.origin} status={self.status}>"
