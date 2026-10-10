"""Declares the ``user_files`` table: the text Crawler extracted from a file a
user uploaded (web chat, Telegram or Slack), encrypted, never the file.

Why it exists: an uploaded document is read once, in the sandboxed worker,
and its sections are kept so files.read can page through it on later turns
without the original. ``content`` holds
``core.security.encrypt_credentials(json.dumps({"v": 1, "sections": [...]}))``
(AES-GCM under ENCRYPTION_KEY) and is loaded only when read (deferred).
``sha256`` (of the original bytes) exists only to deduplicate a re-upload.
A row expires 30 days after it was last read (``expires_at``), and account
deletion cascades. services.files.store is the only reader and writer, and
migration 0018_user_files mirrors these columns so ``create_all`` and the
migrated schema stay identical (tests/test_migrations.py).
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any, Optional

from sqlalchemy import (
    JSON,
    Boolean,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    LargeBinary,
    String,
    Uuid,
)
from sqlalchemy.orm import Mapped, mapped_column

from core.database import Base


def _now() -> datetime:
    return datetime.now(timezone.utc)


class UserFile(Base):
    __tablename__ = "user_files"
    __table_args__ = (
        # One row per distinct file per user: a re-upload refreshes it.
        Index("uq_user_files_user_sha256", "user_id", "sha256", unique=True),
        Index("ix_user_files_user_created", "user_id", "created_at"),
        # The expiry purge.
        Index("ix_user_files_expires_at", "expires_at"),
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid(), primary_key=True, default=uuid.uuid4)
    user_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(), ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )
    # "web" | "telegram" | "slack"
    source: Mapped[str] = mapped_column(String(16), nullable=False)
    # The display name (services.files.prompting.sanitize_display_name).
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    # The name the attachment note uses ("a PDF file" when PromptGuard
    # flags the real one).
    prompt_name: Mapped[str] = mapped_column(String(80), nullable=False)
    # The detected type, never the declared one.
    media_type: Mapped[str] = mapped_column(String(100), nullable=False)
    # pdf, docx, pptx, xlsx, csv, text, markdown, html, json or image.
    kind: Mapped[str] = mapped_column(String(16), nullable=False)
    size_bytes: Mapped[int] = mapped_column(Integer, nullable=False)
    sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    # Pages, slides or sheets; None for a file without pages.
    pages: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    sections_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    chars: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    ocr_pages: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    ocr_engine: Mapped[Optional[str]] = mapped_column(String(16), nullable=True)
    scanned_pages_unread: Mapped[Optional[list[Any]]] = mapped_column(JSON, nullable=True)
    # Warning codes only, never text.
    warnings: Mapped[Optional[list[Any]]] = mapped_column(JSON, nullable=True)
    truncated: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    content: Mapped[bytes] = mapped_column(LargeBinary, nullable=False, deferred=True)
    # The encrypted content's size (and, later, page images'): the quota.
    stored_bytes: Mapped[int] = mapped_column(Integer, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=_now)
    last_used_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=_now)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    def __repr__(self) -> str:
        return f"<UserFile id={self.id} kind={self.kind}>"
