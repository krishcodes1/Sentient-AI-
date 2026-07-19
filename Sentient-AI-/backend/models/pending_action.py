from __future__ import annotations

import enum
import uuid
from datetime import datetime, timezone
from typing import Dict, Optional

from sqlalchemy import JSON, DateTime, Enum, ForeignKey, String, Text, Uuid
from sqlalchemy.orm import Mapped, mapped_column

from core.database import Base


class PendingActionStatus(str, enum.Enum):
    pending = "pending"
    approved = "approved"
    denied = "denied"
    expired = "expired"


class PendingAction(Base):
    """A tool call awaiting explicit user approval.

    Persisted (rather than held in runtime memory) so approvals survive
    process restarts and work across multiple workers. Rows are never
    deleted on decision — the decided status stays as a record alongside
    the audit log, and expired rows are flipped to ``expired`` lazily.
    """

    __tablename__ = "pending_actions"

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
    conversation_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        Uuid(),
        ForeignKey("conversations.id", ondelete="CASCADE"),
        nullable=True,
    )
    tool_name: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
    )
    arguments: Mapped[Dict] = mapped_column(
        JSON,
        nullable=False,
        default=dict,
    )
    reason: Mapped[str] = mapped_column(
        Text,
        nullable=False,
        default="",
    )
    status: Mapped[PendingActionStatus] = mapped_column(
        Enum(PendingActionStatus, name="pending_action_status"),
        nullable=False,
        default=PendingActionStatus.pending,
        index=True,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )
    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
    )
    decided_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    def __repr__(self) -> str:
        return f"<PendingAction {self.id} tool={self.tool_name} status={self.status}>"
