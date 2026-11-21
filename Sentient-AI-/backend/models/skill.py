"""Declares the ``skills`` table: playbooks a user wrote to teach Crawler a
kind of task (a name, a one-line description and the instructions).

Why it exists: the Skills page (api/routes/skills.py) saves them, the agent
route lists each enabled skill's name and description in the system prompt
(services/skills.py), and ``skills.read`` hands the model the instructions
only when a task needs them. Each skill belongs to one user and dies with
them; a name is unique per user because the model reads a skill by name.
Lengths are checked in services/skills.py; migration 0036_skills mirrors
these columns.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from sqlalchemy import Boolean, DateTime, ForeignKey, Index, String, Text, Uuid, true
from sqlalchemy.orm import Mapped, mapped_column

from core.database import Base


def _now() -> datetime:
    return datetime.now(timezone.utc)


class Skill(Base):
    __tablename__ = "skills"
    __table_args__ = (Index("ix_skills_user_id_name", "user_id", "name", unique=True),)

    id: Mapped[uuid.UUID] = mapped_column(Uuid(), primary_key=True, default=uuid.uuid4)
    user_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(), ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )
    name: Mapped[str] = mapped_column(String(40), nullable=False)
    description: Mapped[str] = mapped_column(String(200), nullable=False)
    instructions: Mapped[str] = mapped_column(Text, nullable=False)
    enabled: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=True, server_default=true()
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_now
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_now, onupdate=_now
    )

    def __repr__(self) -> str:
        return f"<Skill {self.name!r}>"
