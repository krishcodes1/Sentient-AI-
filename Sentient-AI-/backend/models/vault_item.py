"""Declares the ``vault_items`` table: one sealed secret per row (the owner's
payment card, later a site login) with a masked label and the sites it may
be used on.

Why it exists: The card must live encrypted under a key the database never
holds (purchases spec §4), so the row stores only the AES-GCM blob, a
``masked`` string safe to show anywhere ("Visa ····4242"), and the metadata
the checkout card needs. services.vault is the only reader and writer, and
migration 0010 mirrors these columns so ``create_all`` and the migrated
schema stay identical (tests/test_migrations.py).
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any, Optional

from sqlalchemy import (
    JSON,
    DateTime,
    ForeignKey,
    Index,
    LargeBinary,
    String,
    Uuid,
)
from sqlalchemy.orm import Mapped, mapped_column

from core.database import Base


class VaultItem(Base):
    __tablename__ = "vault_items"
    __table_args__ = (
        # The two reads: the owner's items, and the owner's card.
        Index("ix_vault_items_user_id_kind", "user_id", "kind"),
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
    # "card" | "login" (services.vault.service.KINDS).
    kind: Mapped[str] = mapped_column(String(16), nullable=False)
    label: Mapped[str] = mapped_column(String(120), nullable=False)
    # Hosts this item may be filled on; empty means "any checkout the
    # owner approves".
    origins: Mapped[list[Any]] = mapped_column(
        JSON, nullable=False, default=list, server_default="[]"
    )
    # Safe to show anywhere: "Visa ····4242" or "j***@school.edu".
    masked: Mapped[str] = mapped_column(String(64), nullable=False)
    # nonce || AES-256-GCM ciphertext, aad "vault_items:{kind}:{id}"
    # (services.vault.crypto). Never returned by any API.
    blob: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
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
    last_used_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    def __repr__(self) -> str:
        # The masked label only: a repr in a traceback must never show the blob.
        return f"<VaultItem {self.id} kind={self.kind} {self.masked}>"
