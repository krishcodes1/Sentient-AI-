"""Scheduled reminders the assistant can set on the user's behalf.

The motivating case: the agent completes (or proposes) a purchase and the
user wants to be told when delivery is expected, without having to hold the
date themselves. A reminder is deliberately a dumb row — a due timestamp, a
short message, and a delivery record — because the value is in getting it
out of the user's head, not in modelling calendars.

Delivery is out-of-band (Telegram today), so a reminder is useful even when
nobody has the web UI open. ``delivered_at`` is the idempotency guard: the
sweeper only ever sends rows where it is NULL, so a restart mid-sweep
cannot double-send.
"""

from __future__ import annotations

import enum
import uuid
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import DateTime, Enum, ForeignKey, Index, String, Text, Uuid
from sqlalchemy.orm import Mapped, mapped_column

from core.database import Base


class ReminderSource(str, enum.Enum):
    """Who created the reminder — for provenance in the UI."""

    user = "user"    # set directly by the person
    agent = "agent"  # set by the assistant while completing a task


class ReminderStatus(str, enum.Enum):
    scheduled = "scheduled"
    delivered = "delivered"
    cancelled = "cancelled"


class Reminder(Base):
    __tablename__ = "reminders"
    __table_args__ = (
        # The sweeper's only query: due, still scheduled, oldest first.
        Index("ix_reminders_status_due_at", "status", "due_at"),
        Index("ix_reminders_user_id_due_at", "user_id", "due_at"),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        Uuid(),
        primary_key=True,
        default=uuid.uuid4,
    )
    user_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(),
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    title: Mapped[str] = mapped_column(String(200), nullable=False)
    note: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    due_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
    )
    status: Mapped[ReminderStatus] = mapped_column(
        Enum(ReminderStatus, name="reminder_status"),
        default=ReminderStatus.scheduled,
        server_default="scheduled",
        nullable=False,
    )
    source: Mapped[ReminderSource] = mapped_column(
        Enum(ReminderSource, name="reminder_source"),
        default=ReminderSource.user,
        server_default="user",
        nullable=False,
    )
    delivered_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )
