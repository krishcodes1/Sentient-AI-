from __future__ import annotations

import uuid
from datetime import datetime, timezone

from sqlalchemy import Boolean, DateTime, LargeBinary, String
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
