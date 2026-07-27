from __future__ import annotations

import enum
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Union

from sqlalchemy import (
    JSON,
    BigInteger,
    DateTime,
    Enum,
    Float,
    ForeignKey,
    String,
    Text,
    Uuid,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from core.database import Base


class AuditStatus(str, enum.Enum):
    approved = "approved"
    blocked = "blocked"
    pending = "pending"


class AuditLog(Base):
    __tablename__ = "audit_logs"

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
    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
        index=True,
    )
    # Monotonic per-user sequence number assigned at append time. The hash
    # chain needs a deterministic order: two rows written in the same
    # millisecond make ORDER BY timestamp ambiguous, which both weakens
    # verification and can produce spurious chain failures. Nullable because
    # rows written before this column existed have no seq (those are also
    # the rows carrying legacy unkeyed hashes); every new write sets it.
    seq: Mapped[Optional[int]] = mapped_column(
        BigInteger,
        nullable=True,
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
    reasoning_chain: Mapped[Optional[Union[Dict, List]]] = mapped_column(
        JSON,
        nullable=True,
    )
    detection_method: Mapped[Optional[str]] = mapped_column(
        String(255),
        nullable=True,
    )
    confidence_score: Mapped[Optional[float]] = mapped_column(
        Float,
        nullable=True,
    )
    request_data: Mapped[Optional[Dict]] = mapped_column(
        JSON,
        nullable=True,
    )
    response_summary: Mapped[Optional[str]] = mapped_column(
        Text,
        nullable=True,
    )
    integrity_hash: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
    )
    # Hash of the previous row in this user's audit chain. Forms a
    # tamper-evident chain so deletions or reorderings are detectable,
    # not just per-row tampering. Nullable for the first row in any
    # user's chain (genesis) and for legacy rows created before the
    # chain was introduced.
    previous_hash: Mapped[Optional[str]] = mapped_column(
        String(64),
        nullable=True,
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
