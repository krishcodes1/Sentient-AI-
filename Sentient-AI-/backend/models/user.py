from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import BigInteger, Boolean, DateTime, Index, Integer, String, Uuid
from sqlalchemy import false as sa_false
from sqlalchemy.orm import Mapped, mapped_column, relationship

from core.database import Base


class User(Base):
    __tablename__ = "users"
    __table_args__ = (
        # Unique so a one-time Telegram link code can never match two
        # accounts; NULLs (the steady state) are exempt from uniqueness.
        Index("ix_users_telegram_link_code", "telegram_link_code", unique=True),
    )

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
    # Incremented on password change to invalidate all outstanding JWTs:
    # tokens carry this value as a claim and get_current_user rejects a
    # mismatch. Tokens minted before the claim existed count as epoch 0.
    token_epoch: Mapped[int] = mapped_column(
        Integer,
        default=0,
        server_default="0",
        nullable=False,
    )
    # Owner of this deployment. The first account to register becomes the
    # admin (a self-hosted install's first user is the person who deployed
    # it); everyone after that is a standard user. This is what gives the
    # `admin_only` connector tier meaning — see build_tools.
    is_admin: Mapped[bool] = mapped_column(
        Boolean,
        default=False,
        # sa.false(), not the string "false": a string default renders as
        # the TEXT literal 'false' on SQLite, and rows backfilled with it
        # read back as the truthy string — every pre-existing account would
        # silently become an admin. sa.false() renders as `false` on
        # Postgres and `0` on SQLite, which is correct on both.
        server_default=sa_false(),
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
    # The account's own provider/model, or NULL for both: "use this
    # Crawler's default", resolved at turn time from the install settings
    # (the setup wizard or .env). NULL is the default for new accounts, so a
    # key the owner saves later — for any provider — reaches everyone who
    # never picked one. Stamping the server's pair at registration used to
    # pin accounts to whatever it was that day. When the provider is NULL
    # the model is ignored (and the Settings route keeps it NULL too).
    llm_provider: Mapped[Optional[str]] = mapped_column(
        String(32),
        default=None,
        nullable=True,
    )
    llm_model: Mapped[Optional[str]] = mapped_column(
        String(128),
        default=None,
        nullable=True,
    )
    # When enabled, saved memories are injected into the agent's system
    # prompt and the assistant may propose new ones (gated by approval).
    # Mirrors ChatGPT/Claude's user-facing memory toggle.
    memory_enabled: Mapped[bool] = mapped_column(
        Boolean,
        default=True,
        server_default="true",
        nullable=False,
    )
    # ── Telegram approvals ────────────────────────────────────────────────
    # Chat this user linked for approval notifications; NULL = not linked.
    # Linking happens via a one-time /start code (see services/notifications/
    # telegram.py) so a chat can never be attached without proof of control
    # of both the Crawler AI session and the Telegram account.
    telegram_chat_id: Mapped[Optional[int]] = mapped_column(
        BigInteger,
        nullable=True,
    )
    telegram_link_code: Mapped[Optional[str]] = mapped_column(
        String(64),
        nullable=True,
    )
    telegram_link_expires_at: Mapped[Optional[datetime]] = mapped_column(
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

    # Relationships.
    #
    # lazy="raise" is deliberate. These were previously lazy="selectin",
    # which made every authenticated request — get_current_user runs on all
    # of them — additionally SELECT every audit row, connector,
    # conversation, and memory belonging to the user (and, through
    # Conversation.messages, every message ever sent). Nothing reads these
    # collections: routes query what they need with explicit, filtered,
    # paginated selects. Raising turns any future accidental use into a
    # loud error instead of a silent full-history scan on the hot path.
    #
    # passive_deletes=True lets the database's ON DELETE CASCADE do the
    # work on account deletion, so the ORM never has to load the rows it
    # is about to delete (which lazy="raise" would refuse anyway).
    audit_logs: Mapped[list["AuditLog"]] = relationship(  # noqa: F821
        back_populates="user",
        lazy="raise",
        passive_deletes=True,
    )
    connectors: Mapped[list["ConnectorConfig"]] = relationship(  # noqa: F821
        back_populates="user",
        lazy="raise",
        passive_deletes=True,
    )
    conversations: Mapped[list["Conversation"]] = relationship(  # noqa: F821
        back_populates="user",
        lazy="raise",
        passive_deletes=True,
    )
    memories: Mapped[list["Memory"]] = relationship(  # noqa: F821
        back_populates="user",
        lazy="raise",
        cascade="all, delete-orphan",
        passive_deletes=True,
    )

    def __repr__(self) -> str:
        return f"<User {self.email}>"
