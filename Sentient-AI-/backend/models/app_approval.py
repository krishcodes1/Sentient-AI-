"""Declares the ``app_approvals`` table: an app on this computer the owner
allowed Crawler to operate for a week, from one approval card, for requests
from one Telegram chat or one browser.

Why it exists: every desktop.act had its own card, and every card ended the
turn, so reading a day in Calendar took six taps and six full-context model
calls (spec 2026-09-25-weekly-app-approvals). A row here lets the runtime run
acts in that one app without a card until ``expires_at``, only for turns from
the same channel (``channel_kind`` + ``channel_key``: the Telegram chat id, or
the SHA-256 of the browser's device id, never the id itself).
services.agent.app_approvals is the only reader and writer, and migration
0015 mirrors these columns so ``create_all`` and the migrated schema stay
identical (tests/test_migrations.py).
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import DateTime, ForeignKey, Index, Integer, String, Uuid
from sqlalchemy.orm import Mapped, mapped_column

from core.database import Base


class AppApproval(Base):
    __tablename__ = "app_approvals"
    __table_args__ = (
        # The one read on the hot path: is this app allowed for this channel?
        Index(
            "ix_app_approvals_lookup",
            "user_id",
            "app_key",
            "channel_kind",
            "channel_key",
        ),
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
    # The tool the approval covers: "desktop.act".
    tool: Mapped[str] = mapped_column(String(64), nullable=False)
    # rules.squash of the weekly-list display name ("calendar"), and that
    # name as the owner saw it on the card ("Calendar").
    app_key: Mapped[str] = mapped_column(String(100), nullable=False)
    app_name: Mapped[str] = mapped_column(String(100), nullable=False)
    # "telegram" | "web" (app_approvals.Channel).
    channel_kind: Mapped[str] = mapped_column(String(16), nullable=False)
    channel_key: Mapped[str] = mapped_column(String(128), nullable=False)
    granted_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    revoked_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    last_used_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    uses: Mapped[int] = mapped_column(Integer, nullable=False, default=0, server_default="0")
    # The approval card whose "Allow for 7 days" button made (or last
    # renewed) this row. Not a foreign key: the audit log is the record.
    source_action_id: Mapped[Optional[uuid.UUID]] = mapped_column(Uuid(), nullable=True)

    def __repr__(self) -> str:
        return (
            f"<AppApproval {self.app_name} {self.channel_kind} "
            f"until {self.expires_at.isoformat() if self.expires_at else '?'}>"
        )
