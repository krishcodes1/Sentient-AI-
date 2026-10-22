"""Declares ``mail_scan_cursors`` (one row per connected Gmail or Outlook
account: where the scam check is in its inbox) and ``mail_scam_findings`` (one
row per new email the check flagged: why, the AI review, the alert and the
cards made for it).

Why it exists: the mail-scan sweeper (services/notifications/mail_scan.py)
claims due cursor rows with a conditional UPDATE of ``next_check_at``, and the
unique (connector_id, external_key) index is the guard that one email is never
flagged twice across workers and restarts. Mail that is not flagged leaves only
a 16-hex hash in the cursor's ``seen`` ring. Rows die with their user and their
connector (ON DELETE CASCADE). Statuses are plain strings validated in code.
Migration 0027_mail_security mirrors these columns (tests/test_migrations.py).
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
    String,
    Text,
    Uuid,
    false,
)
from sqlalchemy.orm import Mapped, mapped_column

from core.database import Base

KEY_CHARS = 64
REF_MAX_CHARS = 255
ERROR_MAX_CHARS = 200
NOTE_MAX_CHARS = 200
DOMAIN_MAX_CHARS = 253

PROVIDERS = ("gmail", "outlook")
# active: checked every few minutes; paused: the person paused it; error:
# stopped after 5 failed checks in a row (a reconnect or Resume restarts it).
CURSOR_STATUSES = ("active", "paused", "error")
# pending: flagged, waiting for review and alert; reviewing: claimed (lease);
# alerted: an alert was decided (delivered, held, or listed on the tab only);
# quiet: only weak signs from an authenticated sender and the AI review found
# none (mail_checks.may_go_quiet), so no alert; dismissed: the person said "not
# a scam"; expired: waited over a day while the switch was off, never alerted.
FINDING_STATUSES = ("pending", "reviewing", "alerted", "quiet", "dismissed", "expired")
VERDICTS = ("likely_scam", "suspicious", "no_signs", "unknown")
LEVELS = ("likely_scam", "suspicious")


def _now() -> datetime:
    return datetime.now(timezone.utc)


class MailScanCursor(Base):
    __tablename__ = "mail_scan_cursors"
    __table_args__ = (
        Index("ux_mail_scan_cursors_connector_id", "connector_id", unique=True),
        Index("ix_mail_scan_cursors_status_next_check_at", "status", "next_check_at"),
        Index("ix_mail_scan_cursors_user_id", "user_id"),
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid(), primary_key=True, default=uuid.uuid4)
    user_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(), ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )
    connector_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(), ForeignKey("connector_configs.id", ondelete="CASCADE"), nullable=False
    )
    provider: Mapped[str] = mapped_column(String(16), nullable=False)
    status: Mapped[str] = mapped_column(
        String(12), nullable=False, default="active", server_default="active"
    )
    # Opaque, made by the connector action ("g1:<historyId>", "o1:d:<deltatoken>");
    # NULL until the first (baseline) check.
    cursor: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    # Provider ids listed but not checked yet:
    # [{"id": <message id>, "tries": <failed reads so far>}], newest kept, at most 200
    # (review SEC-F7: an id that keeps failing is skipped after two tries).
    pending_ids: Mapped[Optional[list[Any]]] = mapped_column(JSON, nullable=True)
    # Ring of 16-hex hashes of checked messages (at most 500).
    seen: Mapped[Optional[list[str]]] = mapped_column(JSON, nullable=True)
    # The mailbox's own domain when the provider says (Gmail profile), for
    # "imitates your organisation"; consumer domains are never stored here.
    account_domain: Mapped[Optional[str]] = mapped_column(String(DOMAIN_MAX_CHARS), nullable=True)
    baseline_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    next_check_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_checked_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    consecutive_errors: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0, server_default="0"
    )
    # Always the sweeper's own sentence, never vendor text.
    last_error: Mapped[Optional[str]] = mapped_column(String(ERROR_MAX_CHARS), nullable=True)
    checked_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0, server_default="0")
    flagged_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0, server_default="0")
    # Listed but never checked (too many at once, or older than a day).
    skipped_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0, server_default="0")
    # The sweeper's own note ("Restarted on Oct 14: earlier mail was not checked.").
    note: Mapped[Optional[str]] = mapped_column(String(NOTE_MAX_CHARS), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=_now)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_now, onupdate=_now
    )

    def __repr__(self) -> str:
        return f"<MailScanCursor {self.provider} {self.status} connector={self.connector_id}>"


class MailScamFinding(Base):
    __tablename__ = "mail_scam_findings"
    __table_args__ = (
        Index(
            "ux_mail_scam_findings_connector_id_external_key",
            "connector_id",
            "external_key",
            unique=True,
        ),
        Index("ix_mail_scam_findings_status_detected_at", "status", "detected_at"),
        Index("ix_mail_scam_findings_user_id_detected_at", "user_id", "detected_at"),
        Index("ix_mail_scam_findings_user_id_reviewed_at", "user_id", "reviewed_at"),
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid(), primary_key=True, default=uuid.uuid4)
    user_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(), ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )
    connector_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(), ForeignKey("connector_configs.id", ondelete="CASCADE"), nullable=False
    )
    provider: Mapped[str] = mapped_column(String(16), nullable=False)
    # sha256 hex of "mail:<provider message id>".
    external_key: Mapped[str] = mapped_column(String(KEY_CHARS), nullable=False)
    message_ref: Mapped[str] = mapped_column(String(REF_MAX_CHARS), nullable=False)
    status: Mapped[str] = mapped_column(
        String(16), nullable=False, default="pending", server_default="pending"
    )
    verdict: Mapped[str] = mapped_column(
        String(16), nullable=False, default="unknown", server_default="unknown"
    )
    local_level: Mapped[str] = mapped_column(String(16), nullable=False)
    score: Mapped[int] = mapped_column(Integer, nullable=False)
    # [{"code": "sender_lookalike_brand", "weight": 3, "arg": "paypal.com"}] (at most 20).
    signals: Mapped[list[dict[str, Any]]] = mapped_column(JSON, nullable=False, default=list)
    # Display facts (untrusted, capped at 4 KB; mail_checks.display_facts).
    facts: Mapped[Optional[dict[str, Any]]] = mapped_column(JSON, nullable=True)
    # The excerpt the AI review reads; NULL once reviewed (or after 24 h).
    review_input: Mapped[Optional[dict[str, Any]]] = mapped_column(JSON, nullable=True)
    # {"verdict","reasons","advice","provider","model","input_tokens","output_tokens","cost_usd"}.
    review: Mapped[Optional[dict[str, Any]]] = mapped_column(JSON, nullable=True)
    review_note: Mapped[Optional[str]] = mapped_column(String(NOTE_MAX_CHARS), nullable=True)
    # Set whenever a provider was called (it counts toward the daily cap).
    reviewed_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    # Notes from S4/S10 ("Links were not checked against the link service this time.").
    check_notes: Mapped[Optional[list[str]]] = mapped_column(JSON, nullable=True)
    alert_delivered: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default=false()
    )
    alert_note: Mapped[Optional[str]] = mapped_column(String(NOTE_MAX_CHARS), nullable=True)
    alerted_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    # [{"action_id": "<uuid>", "kind": "move_to_spam"}]. Block sender is
    # deferred in this wave (owner decision 8a), so no other kind is written.
    card_ids: Mapped[Optional[list[dict[str, Any]]]] = mapped_column(JSON, nullable=True)
    dismissed_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    received_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    detected_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=_now)
    claimed_until: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    attempts: Mapped[int] = mapped_column(Integer, nullable=False, default=0, server_default="0")

    def __repr__(self) -> str:
        # Never the message reference or the facts: they come from the email.
        return f"<MailScamFinding {self.id} {self.status} {self.verdict}>"
