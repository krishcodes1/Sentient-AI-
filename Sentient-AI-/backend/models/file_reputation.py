"""Declares the file-reputation tables (security wave S10): the install-wide VirusTotal verdict
cache, each user's file checks, and the request log that keeps VirusTotal's per-key limits true
across restarts.

Why it exists: a VirusTotal answer about a fingerprint is the same for everyone, so it is cached
once (file_reputation_verdicts); each person's own history, and where their file's bytes can be
fetched again for an approved upload, is theirs (file_reputation_checks, cascading with the
user); and the public key's 4-a-minute / 500-a-day limits belong to the key, not to a process, so
every request is logged before it is made (file_reputation_calls). services.file_reputation.store
is the only reader and writer; migration 0032_file_reputation mirrors these columns.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import DateTime, ForeignKey, Index, Integer, LargeBinary, String, Uuid
from sqlalchemy.orm import Mapped, mapped_column

from core.database import Base


def _now() -> datetime:
    return datetime.now(timezone.utc)


class FileReputationVerdict(Base):
    __tablename__ = "file_reputation_verdicts"
    __table_args__ = (Index("ix_file_reputation_verdicts_expires_at", "expires_at"),)

    # Lowercase hex.
    sha256: Mapped[str] = mapped_column(String(64), primary_key=True)
    # malicious | suspicious | no_detections | unknown (strings checked in code).
    verdict: Mapped[str] = mapped_column(String(16), nullable=False)
    malicious: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    suspicious: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    harmless: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    undetected: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    engines: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    threat_label: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    file_type: Mapped[Optional[str]] = mapped_column(String(40), nullable=True)
    first_seen_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    analysed_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    # lookup | analysis (an upload's finished scan).
    origin: Mapped[str] = mapped_column(String(10), nullable=False)
    fetched_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    def __repr__(self) -> str:
        return f"<FileReputationVerdict {self.verdict} {self.malicious}/{self.engines}>"


class FileReputationCheck(Base):
    __tablename__ = "file_reputation_checks"
    __table_args__ = (
        Index("uq_file_reputation_checks_user_sha256", "user_id", "sha256", unique=True),
        Index("ix_file_reputation_checks_user_updated", "user_id", "updated_at"),
        Index("ix_file_reputation_checks_user_source_key", "user_id", "source_key"),
        Index("ix_file_reputation_checks_state_due", "state", "next_poll_at"),
        Index("ix_file_reputation_checks_expires_at", "expires_at"),
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid(), primary_key=True, default=uuid.uuid4)
    user_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(), ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )
    sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    # Sanitised display name, like user_files.name.
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    media_type: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    size_bytes: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    # page | web | telegram | slack | gmail | outlook | hash | scam
    source: Mapped[str] = mapped_column(String(16), nullable=False)
    # encrypt_credentials(json.dumps(...)): where the bytes can be fetched
    # again for an approved upload. Deferred: only that upload reads it, and
    # no route ever returns it.
    source_ref: Mapped[Optional[bytes]] = mapped_column(LargeBinary, nullable=True, deferred=True)
    # Mail rows only: a keyed HMAC of the message, read by the call check.
    source_key: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    # queued | checked | not_checked | upload_pending | analysing
    state: Mapped[str] = mapped_column(String(16), nullable=False)
    # explicit | automatic (the order of the queue).
    priority: Mapped[str] = mapped_column(String(10), nullable=False, default="automatic")
    verdict: Mapped[Optional[str]] = mapped_column(String(16), nullable=True)
    malicious: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    suspicious: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    engines: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    threat_label: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    reason: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)
    alerted_verdict: Mapped[Optional[str]] = mapped_column(String(16), nullable=True)
    action_id: Mapped[Optional[str]] = mapped_column(String(36), nullable=True)
    analysis_id: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    polls: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    next_poll_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    claimed_until: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    uploaded_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    checked_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=_now)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=_now)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    def __repr__(self) -> str:
        # Never the name or the source reference: they are the person's own.
        return f"<FileReputationCheck {self.id} {self.state} {self.verdict}>"


class FileReputationCall(Base):
    __tablename__ = "file_reputation_calls"
    __table_args__ = (
        Index("ix_file_reputation_calls_at", "at"),
        Index("ix_file_reputation_calls_user_at", "user_id", "at"),
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid(), primary_key=True, default=uuid.uuid4)
    # When the slot was reserved, which is before the request.
    at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    # lookup | upload | analysis
    kind: Mapped[str] = mapped_column(String(10), nullable=False)
    # explicit | automatic
    priority: Mapped[str] = mapped_column(String(10), nullable=False)
    # SET NULL, so the day's count survives a user's deletion.
    user_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        Uuid(), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )

    def __repr__(self) -> str:
        return f"<FileReputationCall {self.kind} {self.priority} at={self.at}>"
