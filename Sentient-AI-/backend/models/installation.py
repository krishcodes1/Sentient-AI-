"""The one-row installation record: the owner's capability switches, the
server-wide AI provider and its encrypted keys, the encrypted Telegram bot
token, and whether first-run setup has been completed. Values in the
environment override this row (see services/installation.py)."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any, Optional

from sqlalchemy import (
    JSON,
    Boolean,
    DateTime,
    Integer,
    LargeBinary,
    String,
    Uuid,
    false,
    func,
)
from sqlalchemy.orm import Mapped, mapped_column

from core.database import Base

INSTALLATION_ROW_ID = 1


class Installation(Base):
    __tablename__ = "installation"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=False)
    # Server defaults mirror migration 0008 so a raw INSERT (a later
    # migration, a manual repair) still yields a valid row, and so the
    # migrated schema and create_all() stay identical (tests/test_migrations.py).
    capabilities: Mapped[dict[str, Any]] = mapped_column(
        JSON, nullable=False, default=dict, server_default="{}"
    )
    llm_provider: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    llm_model: Mapped[Optional[str]] = mapped_column(String(200), nullable=True)
    # AES-256-GCM blobs (core.security.encrypt_credentials) — never plaintext.
    llm_api_keys: Mapped[Optional[bytes]] = mapped_column(LargeBinary, nullable=True)
    telegram_bot_token: Mapped[Optional[bytes]] = mapped_column(LargeBinary, nullable=True)
    allow_registration: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default=false()
    )
    setup_completed_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
        server_default=func.now(),
    )
    updated_by_user_id: Mapped[Optional[uuid.UUID]] = mapped_column(Uuid(), nullable=True)
