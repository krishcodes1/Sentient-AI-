"""Declares the ``media_transcripts`` table: a user's cached transcript of a
video, lecture or podcast episode (timestamped passages), kept 14 days after
its last use.

Why it exists: reading a YouTube video through the AI provider costs tokens,
and a feed or caption file is a round trip, so follow-up questions and
"continue from 45:00" are answered from here instead. ``source_key`` is
``yt:<video id>`` or ``url:<sha256 of the normalised URL>``, so a private
feed's token is never stored; ``display_url`` keeps the path and only a query
with nothing credential-like in it. ``segments`` is the passages as
``[start_s, end_s, text]`` (times null for an untimed transcript) and
``covered`` the windows read so far. ``billed`` holds the provider seconds
each read took (``[epoch_s, seconds]``, at most 64), which the per-day cap
counts. The text is untrusted publisher content: it is only ever returned as
a tool result, never put in a prompt. services/tools/video/store.py is the
only reader and writer; migration 0024_media_transcripts mirrors these
columns, and account deletion cascades.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any, Optional

from sqlalchemy import JSON, DateTime, ForeignKey, Index, Integer, String, Uuid
from sqlalchemy.orm import Mapped, mapped_column

from core.database import Base


def _now() -> datetime:
    return datetime.now(timezone.utc)


class MediaTranscript(Base):
    __tablename__ = "media_transcripts"
    __table_args__ = (
        # One row per source, method and detail per user: a later read
        # merges into it.
        Index(
            "uq_media_transcripts_user_source",
            "user_id",
            "source_key",
            "method",
            "detail",
            unique=True,
        ),
        # Listing (newest used first) and the per-user LRU cap.
        Index("ix_media_transcripts_user_last_used", "user_id", "last_used_at"),
        # The expiry purge.
        Index("ix_media_transcripts_expires_at", "expires_at"),
        # The phase-2 job claim (pending rows past their lease).
        Index("ix_media_transcripts_status_claimed", "status", "claimed_until"),
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid(), primary_key=True, default=uuid.uuid4)
    user_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(), ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )
    source_key: Mapped[str] = mapped_column(String(80), nullable=False)
    # youtube | podcast | captions | page | media
    kind: Mapped[str] = mapped_column(String(12), nullable=False)
    # publisher_captions | provider_video | transcribed_audio
    method: Mapped[str] = mapped_column(String(24), nullable=False)
    # notes | verbatim
    detail: Mapped[str] = mapped_column(String(10), nullable=False)
    display_url: Mapped[str] = mapped_column(String(500), nullable=False)
    title: Mapped[Optional[str]] = mapped_column(String(200), nullable=True)
    author: Mapped[Optional[str]] = mapped_column(String(120), nullable=True)
    language: Mapped[Optional[str]] = mapped_column(String(16), nullable=True)
    duration_s: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    # "publisher" or the model id that read the video.
    engine: Mapped[str] = mapped_column(String(80), nullable=False)
    segments: Mapped[list[Any]] = mapped_column(JSON, nullable=False, default=list)
    covered: Mapped[list[Any]] = mapped_column(JSON, nullable=False, default=list)
    chars: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    billed: Mapped[list[Any]] = mapped_column(JSON, nullable=False, default=list)
    # ready | pending | running | failed (phase 1 writes ready only).
    status: Mapped[str] = mapped_column(String(12), nullable=False, default="ready")
    # Crawler's own short reason, never publisher text.
    error: Mapped[Optional[str]] = mapped_column(String(200), nullable=True)
    attempts: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    claimed_until: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=_now)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=_now)
    last_used_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=_now)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    def __repr__(self) -> str:
        return f"<MediaTranscript id={self.id} kind={self.kind} method={self.method}>"
