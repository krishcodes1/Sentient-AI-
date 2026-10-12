"""Declares the ``skill_states`` table: the owner's on/off switch for one bundled
skill (a reviewed ``SKILL.md`` playbook in backend/skills/), with the hash of
the text the owner saw when they set it.

Why it exists: bundled skills are on by default, and the owner can switch any
one off (or back on) from Settings → Skills (api/routes/skills.py). The
switch is install-wide, not per user, so the row is keyed by the skill's name;
no row means the bundled default (on). ``sha256`` records which version of the
skill the owner was looking at, and ``updated_by`` who changed it, kept as
NULL if that account is later deleted. Migration 0025_skill_states mirrors
these columns (tests/test_migrations.py).
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import Boolean, DateTime, ForeignKey, String, Uuid
from sqlalchemy.orm import Mapped, mapped_column

from core.database import Base

# A skill's name (its folder name, at most 64 characters) and a SHA-256 hex
# digest.
SKILL_NAME_MAX_CHARS = 64
SHA256_HEX_CHARS = 64


def _now() -> datetime:
    return datetime.now(timezone.utc)


class SkillState(Base):
    __tablename__ = "skill_states"

    name: Mapped[str] = mapped_column(String(SKILL_NAME_MAX_CHARS), primary_key=True)
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False)
    # The skill's hash when the owner set the switch (services/skills).
    sha256: Mapped[Optional[str]] = mapped_column(String(SHA256_HEX_CHARS), nullable=True)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_now, onupdate=_now
    )
    # The owner who set it; kept (as NULL) if that account is deleted.
    updated_by: Mapped[Optional[uuid.UUID]] = mapped_column(
        Uuid(), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )

    def __repr__(self) -> str:
        return f"<SkillState {self.name} enabled={self.enabled}>"
