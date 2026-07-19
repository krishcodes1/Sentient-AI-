from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import Boolean, DateTime, Integer, String, Uuid
from sqlalchemy.orm import Mapped, mapped_column, relationship

from core.database import Base


def _server_llm_defaults() -> tuple[str, str]:
    """Provider/model the server is configured for, resolved lazily so the
    model module never imports settings at class-definition time."""
    from core.config import settings

    return settings.LLM_PROVIDER, settings.LLM_MODEL


class User(Base):
    __tablename__ = "users"

    id: Mapped[uuid.UUID] = mapped_column(
        Uuid(),
        primary_key=True,
        default=uuid.uuid4,
    )
    email: Mapped[str] = mapped_column(
        String(320),
        unique=True,
        index=True,
        nullable=False,
    )
    name: Mapped[Optional[str]] = mapped_column(
        String(255),
        nullable=True,
    )
    hashed_password: Mapped[str] = mapped_column(
        String(128),
        nullable=False,
    )
    is_active: Mapped[bool] = mapped_column(
        Boolean,
        default=True,
        nullable=False,
    )
    # Account settings (surfaced and edited on the Settings page)
    default_permission_tier: Mapped[str] = mapped_column(
        String(32),
        default="user_confirm",
        server_default="user_confirm",
        nullable=False,
    )
    rate_limit: Mapped[int] = mapped_column(
        Integer,
        default=60,
        server_default="60",
        nullable=False,
    )
    # New accounts inherit the provider/model the server is actually
    # configured for, so chat works before the user ever opens Settings.
    llm_provider: Mapped[str] = mapped_column(
        String(32),
        default=lambda: _server_llm_defaults()[0],
        server_default="anthropic",
        nullable=False,
    )
    llm_model: Mapped[str] = mapped_column(
        String(128),
        default=lambda: _server_llm_defaults()[1],
        server_default="claude-sonnet-4-20250514",
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
    audit_logs: Mapped[list["AuditLog"]] = relationship(  # noqa: F821
        back_populates="user",
        lazy="selectin",
    )
    connectors: Mapped[list["ConnectorConfig"]] = relationship(  # noqa: F821
        back_populates="user",
        lazy="selectin",
    )
    conversations: Mapped[list["Conversation"]] = relationship(  # noqa: F821
        back_populates="user",
        lazy="selectin",
    )

    def __repr__(self) -> str:
        return f"<User {self.email}>"
