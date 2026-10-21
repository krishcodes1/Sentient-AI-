"""Declares the breach-monitor tables: ``breach_watch_addresses`` (an owner's
watched addresses, sealed, with each one's check schedule and health) and
``breach_watch_findings`` (the breaches already seen for each address, which is
how only new ones are alerted).

Why it exists: the weekly sweeper (services/notifications/breach_monitor.py)
claims due addresses by status/next_check_at with a conditional UPDATE, and the
unique (address_id, breach_name) index is the dedupe guard that keeps a breach
from being alerted twice. Addresses are AES-GCM sealed and looked up by an HMAC
digest, never stored or logged in plain text. services/breach/store.py is the
only reader and writer; migration 0029_breach_watch mirrors these columns, and
account deletion cascades. No enum types: source, status and error codes are
strings checked in code.
"""

from __future__ import annotations

import uuid
from datetime import date, datetime, timezone
from typing import Any, Optional

from sqlalchemy import (
    JSON,
    BigInteger,
    Boolean,
    Date,
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

ADDRESS_SOURCES = ("account", "added")  # the owner's sign-in address | typed in
ADDRESS_STATUSES = ("active", "paused", "error")
ERROR_CODE_MAX_CHARS = 24
BREACH_NAME_MAX_CHARS = 120
TITLE_MAX_CHARS = 160
DOMAIN_MAX_CHARS = 253


def _now() -> datetime:
    return datetime.now(timezone.utc)


class BreachWatchAddress(Base):
    __tablename__ = "breach_watch_addresses"
    __table_args__ = (
        # One row per address per owner; also the "already watched" check.
        Index("uq_breach_watch_addresses_user_digest", "user_id", "address_digest", unique=True),
        # The sweeper's only query: active and due, soonest first.
        Index("ix_breach_watch_addresses_status_next_check", "status", "next_check_at"),
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid(), primary_key=True, default=uuid.uuid4)
    user_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(), ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )
    source: Mapped[str] = mapped_column(String(8), nullable=False)  # account | added
    address_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    address_sealed: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    status: Mapped[str] = mapped_column(String(8), nullable=False, default="active")
    next_check_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_checked_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    # First successful lookup; NULL means the next answer is the baseline.
    baseline_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    breach_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0, server_default="0")
    consecutive_errors: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0, server_default="0"
    )
    # A fixed code (services/breach/messages.FAILURE_SENTENCES), never vendor text.
    last_error_code: Mapped[Optional[str]] = mapped_column(
        String(ERROR_CODE_MAX_CHARS), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=_now)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=_now)

    def __repr__(self) -> str:
        # Never the address: not even sealed bytes belong in a log line.
        return f"<BreachWatchAddress {self.id} {self.source} {self.status}>"


class BreachWatchFinding(Base):
    __tablename__ = "breach_watch_findings"
    __table_args__ = (
        # The seen list: each breach once per address (dedupe guard; IntegrityError caught).
        Index("uq_breach_watch_findings_address_name", "address_id", "breach_name", unique=True),
        # The tab's list, newest first, per owner.
        Index("ix_breach_watch_findings_user_seen", "user_id", "first_seen_at"),
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid(), primary_key=True, default=uuid.uuid4)
    address_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(), ForeignKey("breach_watch_addresses.id", ondelete="CASCADE"), nullable=False
    )
    user_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(), ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )
    # HIBP "Name".
    breach_name: Mapped[str] = mapped_column(String(BREACH_NAME_MAX_CHARS), nullable=False)
    title: Mapped[str] = mapped_column(String(TITLE_MAX_CHARS), nullable=False)
    domain: Mapped[Optional[str]] = mapped_column(String(DOMAIN_MAX_CHARS), nullable=True)
    breach_date: Mapped[Optional[date]] = mapped_column(Date, nullable=True)
    added_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    pwn_count: Mapped[Optional[int]] = mapped_column(BigInteger, nullable=True)
    data_classes: Mapped[list[Any]] = mapped_column(JSON, nullable=False, default=list)
    verified: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    sensitive: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    fabricated: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    spam_list: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    # True: found by the address's first lookup ("known before monitoring started").
    baseline: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    first_seen_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_now
    )
    # When the owner was told: a channel delivered it, or a Check now answer showed it.
    alerted_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    # The owner pressed "Mark as handled" (UI state only).
    acknowledged_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    def __repr__(self) -> str:
        return f"<BreachWatchFinding {self.id} address={self.address_id}>"
