"""Declares the ``known_recipients`` table (keyed fingerprints of the addresses and domains Crawler
has sent mail to for a user) and the ``organisation_domains`` table (the owner's list of the
install's own mail domains).

Why it exists: outbound message checks (security S1, services/security/outbound.py) tell the owner
when a message goes to someone Crawler has never sent to, or outside the organisation. Only HMACs
are kept (services/security/outbound_recipients.py), never an address. Migration
0026_known_recipients mirrors these columns (tests/test_migrations.py).
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import DateTime, ForeignKey, Index, Integer, String, Uuid
from sqlalchemy.orm import Mapped, mapped_column

from core.database import Base


class KnownRecipient(Base):
    __tablename__ = "known_recipients"
    __table_args__ = (
        # The lookup: has Crawler sent to this address (or domain) for this user?
        Index("uq_known_recipients_user_kind_value", "user_id", "kind", "value_hmac", unique=True),
        # Pruning, least recently sent first.
        Index("ix_known_recipients_user_last_sent", "user_id", "last_sent_at"),
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid(), primary_key=True, default=uuid.uuid4)
    user_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(), ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )
    # "address" | "domain" (checked in code, no enum type).
    kind: Mapped[str] = mapped_column(String(8), nullable=False)
    # Hex HMAC-SHA256 of the user id, the kind and the normalised value.
    value_hmac: Mapped[str] = mapped_column(String(64), nullable=False)
    # First 8 hex of sha256(hmac_key): rows made under another key are
    # ignored and pruned.
    key_id: Mapped[str] = mapped_column(String(8), nullable=False)
    first_sent_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_sent_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    send_count: Mapped[int] = mapped_column(Integer, nullable=False, default=1, server_default="1")

    def __repr__(self) -> str:
        # Never the fingerprint: it identifies a correspondent to anyone with the key.
        return f"<KnownRecipient {self.kind} user={self.user_id}>"


class OrganisationDomain(Base):
    __tablename__ = "organisation_domains"
    __table_args__ = (Index("uq_organisation_domains_domain", "domain", unique=True),)

    id: Mapped[uuid.UUID] = mapped_column(Uuid(), primary_key=True, default=uuid.uuid4)
    # Lower-case ASCII (IDNA A-label), validated by the route.
    domain: Mapped[str] = mapped_column(String(253), nullable=False)
    # Install policy outlives the account that added it.
    added_by: Mapped[Optional[uuid.UUID]] = mapped_column(
        Uuid(), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False
    )

    def __repr__(self) -> str:
        return f"<OrganisationDomain {self.domain!r}>"
