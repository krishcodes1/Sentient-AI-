"""Declares the ``errands`` table: one thing the owner asked Crawler to get done
on the web in the background (buy this perfume by the 20th), where it came
from, when it runs and how far it got.

Why it exists: an errand outlives any chat turn. It is planned days or months
ahead (from a calendar note or a chat), run by the errand sweeper on its day,
parked on the one purchase card while the owner decides, and retried when the
checkout page went stale. The row holds the owner's own words (title, item,
link, and the rest of what the note asked in ``details``), dates (a calendar
errand also keeps its event's day, ``event_day``, so a note is only taken as
deleted while that day is inside the calendar window read, and the hash of
the note as last read, ``source_fingerprint``, so a restart reads only a note
that changed), a status and the last message sent about it; never page text.

Connects to: services/automation/errands.py (the only writer), the
pending_actions row of its purchase card (``approval_action_id``) and the web
conversation its runs write into. Statuses are strings checked in code (no
Postgres enum), as for scheduled tasks. alembic 0033_errands creates the
table, 0034_errand_details adds ``details`` and ``event_day``,
0035_errand_fingerprint adds ``source_fingerprint``.
"""

from __future__ import annotations

import uuid
from datetime import date, datetime, timezone
from typing import Optional

from sqlalchemy import Date, DateTime, ForeignKey, Index, Integer, String, Text, Uuid
from sqlalchemy.orm import Mapped, mapped_column

from core.database import Base

TITLE_MAX_CHARS = 120
ITEM_MAX_CHARS = 500
DETAILS_MAX_CHARS = 500
LINK_MAX_CHARS = 2048
SOURCE_REF_MAX_CHARS = 255
MESSAGE_MAX_CHARS = 2000

# Where an errand came from.
ERRAND_SOURCES = ("calendar", "chat")
# planned: waits for its run_on day; running: a run is in flight;
# awaiting_approval: its purchase card waits for the owner; waiting: a page
# needs the owner (a sign-in) before it can go on; done, failed, cancelled:
# finished; unsure: the order was sent but not confirmed, so it may have been
# bought (finished, and never planned again: a retry could buy twice).
ERRAND_STATUSES = (
    "planned",
    "running",
    "awaiting_approval",
    "waiting",
    "done",
    "failed",
    "unsure",
    "cancelled",
)
OPEN_STATUSES = ("planned", "running", "awaiting_approval", "waiting")


def _now() -> datetime:
    return datetime.now(timezone.utc)


class Errand(Base):
    __tablename__ = "errands"
    __table_args__ = (
        # The sweeper's query: planned and due, soonest first.
        Index("ix_errands_status_run_on", "status", "run_on"),
        # One errand per calendar event: a daily calendar scan finds it again.
        # A chat errand has no source_ref, and NULLs never collide.
        Index("uq_errands_user_source_ref", "user_id", "source", "source_ref", unique=True),
        # The decision path finds an errand by its purchase card.
        Index("ix_errands_approval_action_id", "approval_action_id"),
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid(), primary_key=True, default=uuid.uuid4)
    user_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(), ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )
    source: Mapped[str] = mapped_column(String(16), nullable=False)
    source_ref: Mapped[Optional[str]] = mapped_column(String(SOURCE_REF_MAX_CHARS), nullable=True)
    source_updated: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    title: Mapped[str] = mapped_column(String(TITLE_MAX_CHARS), nullable=False)
    item: Mapped[str] = mapped_column(String(ITEM_MAX_CHARS), nullable=False)
    # Who it is for and anything else the owner asked about the purchase
    # (gift wrap, a size): the run reads it, messages name only the item.
    details: Mapped[Optional[str]] = mapped_column(String(DETAILS_MAX_CHARS), nullable=True)
    link: Mapped[Optional[str]] = mapped_column(String(LINK_MAX_CHARS), nullable=True)
    needed_by: Mapped[Optional[date]] = mapped_column(Date(), nullable=True)
    # A calendar errand's event day as the calendar listed it (None for a
    # chat errand).
    event_day: Mapped[Optional[date]] = mapped_column(Date(), nullable=True)
    # The hash of what the calendar note said when it was last read
    # (CalendarEvent.fingerprint): after a restart the finder reads the note
    # again only when it differs. Never the note itself.
    source_fingerprint: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    run_on: Mapped[date] = mapped_column(Date(), nullable=False)
    status: Mapped[str] = mapped_column(
        String(20), nullable=False, default="planned", server_default="planned"
    )
    attempts: Mapped[int] = mapped_column(Integer, nullable=False, default=0, server_default="0")
    # Crawler's own words to the owner about the last run (never page text
    # alone): what /errands shows under the errand.
    last_message: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    approval_action_id: Mapped[Optional[uuid.UUID]] = mapped_column(Uuid(), nullable=True)
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
        return f"<Errand {self.id} status={self.status}>"
