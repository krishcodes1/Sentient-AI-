"""Declares the ``permission_grants`` table: one connection (a connector row)
whose low-risk changes the owner allowed without a card for 7 days, from one
approval card's "Allow low-risk changes" button.

Why it exists: a card for a small, undoable change (a star, a draft, a private
event) can offer to stop asking for that account for a week (permission
tiers, services/agent/permission_grants.py, the only reader and writer). The
row must outlive restarts and be readable by every worker and by the Telegram
and Slack channels. It is per user and per connection, not per channel, and
dies with the connector or the user (ON DELETE CASCADE). Migration
0023_permission_grants mirrors these columns so ``create_all`` and the
migrated schema stay identical (tests/test_migrations.py).
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import DateTime, ForeignKey, Index, Integer, String, Uuid
from sqlalchemy.orm import Mapped, mapped_column

from core.database import Base


class PermissionGrantRow(Base):
    __tablename__ = "permission_grants"
    __table_args__ = (
        # The one read on the hot path: does this connection have a live grant?
        Index("ix_permission_grants_lookup", "user_id", "connector_id", "kind"),
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
    connector_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(),
        ForeignKey("connector_configs.id", ondelete="CASCADE"),
        nullable=False,
    )
    # What the grant allows: "low_risk" (permission_grants.KIND_LOW_RISK).
    kind: Mapped[str] = mapped_column(String(32), nullable=False)
    # Where the button was pressed ("web" | "telegram" | "slack"), for the
    # Settings list only: a grant is not bound to a channel.
    granted_from: Mapped[Optional[str]] = mapped_column(String(16), nullable=True)
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
    # The approval card whose button made (or last renewed) this row. Not a
    # foreign key: the audit log is the record.
    source_action_id: Mapped[Optional[uuid.UUID]] = mapped_column(Uuid(), nullable=True)

    def __repr__(self) -> str:
        return (
            f"<PermissionGrant {self.kind} connector={self.connector_id} "
            f"until {self.expires_at.isoformat() if self.expires_at else '?'}>"
        )
