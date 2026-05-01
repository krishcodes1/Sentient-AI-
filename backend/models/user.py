from __future__ import annotations

import uuid
from datetime import datetime, timezone

from sqlalchemy import Boolean, DateTime, Integer, LargeBinary, String
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from core.database import Base


class User(Base):
    __tablename__ = "users"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )
    email: Mapped[str] = mapped_column(
        String(320),
        unique=True,
        index=True,
        nullable=False,
    )
    name: Mapped[str | None] = mapped_column(
        String(256),
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

    # LLM configuration (set during onboarding, changeable in settings)
    llm_provider: Mapped[str] = mapped_column(
        String(32),
        default="openai",
        nullable=False,
        server_default="openai",
    )
    llm_model: Mapped[str] = mapped_column(
        String(128),
        default="gpt-4o",
        nullable=False,
        server_default="gpt-4o",
    )
    llm_api_key_enc: Mapped[bytes | None] = mapped_column(
        LargeBinary,
        nullable=True,
    )
    onboarding_completed: Mapped[bool] = mapped_column(
        Boolean,
        default=False,
        nullable=False,
        server_default="false",
    )

    # Account lockout tracking (P0 hardening)
    failed_login_count: Mapped[int] = mapped_column(
        Integer,
        server_default="0",
        nullable=False,
    )
    lockout_until: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    # Email verification
    email_verified_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    verification_token_hash: Mapped[str | None] = mapped_column(
        String(64),
        nullable=True,
        index=True,
    )
    verification_expires_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    # Password reset flow
    password_reset_token_hash: Mapped[str | None] = mapped_column(
        String(64),
        nullable=True,
        index=True,
    )
    password_reset_expires_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
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
    channels: Mapped[list["Channel"]] = relationship(  # noqa: F821
        back_populates="user",
        lazy="selectin",
    )
    auth_sessions: Mapped[list["AuthSession"]] = relationship(  # noqa: F821
        back_populates="user",
        lazy="selectin",
        cascade="all, delete-orphan",
    )

    def __repr__(self) -> str:
        return f"<User {self.email}>"
