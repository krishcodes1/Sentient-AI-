from __future__ import annotations

import enum
import uuid
from datetime import datetime, timezone

from sqlalchemy import (
    Boolean,
    DateTime,
    Enum,
    ForeignKey,
    Integer,
    LargeBinary,
    String,
)
from sqlalchemy.dialects.postgresql import JSON, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from core.database import Base


class ConnectorType(str, enum.Enum):
    canvas = "canvas"
    google_workspace = "google_workspace"
    robinhood = "robinhood"
    custom = "custom"


class AuthMethod(str, enum.Enum):
    oauth2 = "oauth2"
    api_key = "api_key"
    bearer_token = "bearer_token"


class PermissionTier(str, enum.Enum):
    auto_approve = "auto_approve"
    user_confirm = "user_confirm"
    admin_only = "admin_only"
    hard_blocked = "hard_blocked"


class ConnectorConfig(Base):
    __tablename__ = "connector_configs"

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
    connector_type: Mapped[ConnectorType] = mapped_column(
        Enum(ConnectorType, name="connector_type"),
        nullable=False,
    )
    display_name: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
    )
    is_active: Mapped[bool] = mapped_column(
        Boolean,
        default=True,
        nullable=False,
    )
    auth_method: Mapped[AuthMethod] = mapped_column(
        Enum(AuthMethod, name="auth_method"),
        nullable=False,
    )
    encrypted_credentials: Mapped[bytes] = mapped_column(
        LargeBinary,
        nullable=False,
    )
    granted_scopes: Mapped[list[str]] = mapped_column(
        JSON,
        nullable=False,
        default=list,
    )
    permission_tier: Mapped[PermissionTier] = mapped_column(
        Enum(PermissionTier, name="permission_tier"),
        nullable=False,
        default=PermissionTier.user_confirm,
    )
    rate_limit_per_minute: Mapped[int] = mapped_column(
        Integer,
        default=30,
        nullable=False,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
        nullable=False,
    )

    # Relationships
    user: Mapped["User"] = relationship(  # noqa: F821
        back_populates="connectors",
    )

    def __repr__(self) -> str:
        return f"<ConnectorConfig {self.display_name} ({self.connector_type})>"
