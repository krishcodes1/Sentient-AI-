"""Declares the ``page_watches`` table: one web page a user asked to be told
about when it changes, with its check interval, the hash and a short excerpt
of the last snapshot, when it was last checked and last changed, and its
health (status and consecutive failures).

Why it exists: The watch.* tools write these rows and the page-watch sweeper
claims due ones by ``status``/``next_check_at``; keeping only a hash and a
short excerpt means a watch never stores a whole third-party page, and
``last_changed_at`` is kept even when no Telegram chat is linked, so
watch.list can still report the change.

Page watches.

A watch is deliberately small: the URL the owner approved, a label for the
alert, how often to look, and just enough of the last snapshot to say what
changed (``last_hash`` decides whether it changed at all; ``last_excerpt``,
capped by the toolkit, is only for the summary). ``consecutive_errors`` and
``status`` are how the sweeper backs off a broken page and then stops
checking it; ``last_error`` is the sweeper's own short reason, never text
from the page.
"""

from __future__ import annotations

import enum
import uuid
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import DateTime, Enum, ForeignKey, Index, Integer, String, Text, Uuid
from sqlalchemy.orm import Mapped, mapped_column

from core.database import Base

# Column sizes. The toolkit's limits (services/tools/watch.py) are the same
# numbers, so a row the tool accepted always fits; a test holds them equal.
URL_MAX_CHARS = 500
LABEL_MAX_CHARS = 80
ERROR_MAX_CHARS = 200


class PageWatchStatus(str, enum.Enum):
    active = "active"  # checked on schedule
    paused = "paused"  # kept, not checked
    error = "error"  # stopped after too many failures in a row


class PageWatch(Base):
    __tablename__ = "page_watches"
    __table_args__ = (
        # The sweeper's only query: active and due, soonest first.
        Index("ix_page_watches_status_next_check_at", "status", "next_check_at"),
        # One watch per page per user; also serves the per-user list and count.
        Index("ix_page_watches_user_id_url", "user_id", "url", unique=True),
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
    )
    url: Mapped[str] = mapped_column(String(URL_MAX_CHARS), nullable=False)
    label: Mapped[str] = mapped_column(String(LABEL_MAX_CHARS), nullable=False)
    interval_minutes: Mapped[int] = mapped_column(Integer, nullable=False)
    # sha256 hex of the page's normalised readable text.
    last_hash: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    last_excerpt: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    last_checked_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    next_check_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
    )
    last_changed_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    status: Mapped[PageWatchStatus] = mapped_column(
        Enum(PageWatchStatus, name="page_watch_status"),
        default=PageWatchStatus.active,
        server_default="active",
        nullable=False,
    )
    consecutive_errors: Mapped[int] = mapped_column(
        Integer,
        default=0,
        server_default="0",
        nullable=False,
    )
    last_error: Mapped[Optional[str]] = mapped_column(
        String(ERROR_MAX_CHARS),
        nullable=True,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )
