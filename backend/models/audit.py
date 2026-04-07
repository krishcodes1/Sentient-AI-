from __future__ import annotations

import enum
import uuid
from datetime import datetime, timezone

from sqlalchemy import DateTime, Enum, Float, ForeignKey, String, Text
from sqlalchemy.dialects.postgresql import JSON, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from core.database import Base


class AuditStatus(str, enum.Enum):
    approved = "approved"
    blocked = "blocked"
    pending = "pending"


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )
    user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
        index=True,
    )
    connector_name: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
    )
    action: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
    )
    endpoint: Mapped[str] = mapped_column(
        String(2048),
        nullable=False,
    )
    scope_used: Mapped[str] = mapped_column(
        String(512),
        nullable=False,
    )
    status: Mapped[AuditStatus] = mapped_column(
        Enum(AuditStatus, name="audit_status"),
        nullable=False,
    )
    reasoning_chain: Mapped[dict | list | None] = mapped_column(
        JSON,
        nullable=True,
    )
    detection_method: Mapped[str | None] = mapped_column(
        String(255),
        nullable=True,
    )
    confidence_score: Mapped[float | None] = mapped_column(
        Float,
        nullable=True,
    )
    request_data: Mapped[dict | None] = mapped_column(
        JSON,
        nullable=True,
    )
    response_summary: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )
    integrity_hash: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
    )
    request_id: Mapped[str] = mapped_column(
        String(36),
        nullable=False,
        index=True,
    )

    # Relationships
    user: Mapped["User"] = relationship(  # noqa: F821
        back_populates="audit_logs",
    )

    def __repr__(self) -> str:
        return f"<AuditLog {self.id} action={self.action} status={self.status}>"
