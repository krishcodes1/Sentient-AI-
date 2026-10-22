"""Declares the ``browser_site_rules`` table: the owner's install-wide site
rules for Crawler's browser and web reads (Blocked, Always ask, Trusted on a
host or a site with its subdomains) and the owner's overrides of the
built-in sensitive-site categories.

Why it exists: a rule is owner policy that is not a number, so it cannot
live in the capability settings. Only the owner creates, changes or deletes
rows (api/routes/security_site_rules.py); services/site_rules loads them
into an in-memory snapshot the browser guard reads on every navigation.
Values are validated in services/site_rules (not by database constraints,
which differ between SQLite and Postgres). Migration 0030_browser_site_rules
mirrors these columns (tests/test_migrations.py).
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import DateTime, ForeignKey, Index, String, Uuid
from sqlalchemy.orm import Mapped, mapped_column

from core.database import Base


def _now() -> datetime:
    return datetime.now(timezone.utc)


class BrowserSiteRule(Base):
    __tablename__ = "browser_site_rules"
    __table_args__ = (
        Index("ux_browser_site_rules_target", "target_type", "target", unique=True),
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid(), primary_key=True, default=uuid.uuid4)
    # "host" | "category" (services.site_rules.patterns.TARGET_TYPES).
    target_type: Mapped[str] = mapped_column(String(16), nullable=False)
    # "chase.com" | "*.chase.com" (ASCII, IDNA) | a category key ("banks").
    target: Mapped[str] = mapped_column(String(255), nullable=False)
    # "blocked" | "always_ask" | "trusted" (services.site_rules.patterns.KINDS).
    kind: Mapped[str] = mapped_column(String(16), nullable=False)
    created_by: Mapped[Optional[uuid.UUID]] = mapped_column(
        Uuid(), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    updated_by: Mapped[Optional[uuid.UUID]] = mapped_column(
        Uuid(), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_now, nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_now, onupdate=_now, nullable=False
    )

    def __repr__(self) -> str:
        return f"<BrowserSiteRule {self.target_type} {self.target!r} {self.kind}>"
