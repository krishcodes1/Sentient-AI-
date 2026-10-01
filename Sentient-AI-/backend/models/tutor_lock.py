"""Declares the ``tutor_locks`` table: the owner's locks that force tutor mode
on, either for one Canvas course (by id, code, name or aliases) or for a
whole account, applied to one account or to every account on the install.

Why it exists: a lock is owner policy that is not a number, so it cannot live
in the capability settings; it needs its own rows. Only the owner creates or
deletes them, from Settings → Permissions (api/routes/tutor.py); every turn
reads the rows that apply to its user (``user_id`` equal to theirs, or NULL
for every account) through services/tutor/service.py. The validation rules
(at least one course field, no generic or secret-shaped terms, at most 100
locks, no duplicates) live in services/tutor/locks.py rather than in database
constraints, which behave differently on SQLite and Postgres. Migration
0019_tutor_mode mirrors these columns so ``create_all`` and the migrated
schema stay identical (tests/test_migrations.py).
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import List, Optional

from sqlalchemy import JSON, DateTime, ForeignKey, String, Uuid
from sqlalchemy.orm import Mapped, mapped_column

from core.database import Base


class TutorLock(Base):
    __tablename__ = "tutor_locks"

    id: Mapped[uuid.UUID] = mapped_column(
        Uuid(),
        primary_key=True,
        default=uuid.uuid4,
    )
    # The account the lock applies to; NULL means every account. Deleted
    # with that account.
    user_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        Uuid(),
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=True,
        index=True,
    )
    # "course" | "account" (services.tutor.locks.SCOPES).
    scope: Mapped[str] = mapped_column(String(16), nullable=False)
    # Digits only (the number in the course's Canvas address).
    canvas_course_id: Mapped[Optional[str]] = mapped_column(String(20), nullable=True)
    course_code: Mapped[Optional[str]] = mapped_column(String(40), nullable=True)
    course_name: Mapped[Optional[str]] = mapped_column(String(120), nullable=True)
    # At most 5 other names for the course, each 3-60 characters.
    aliases: Mapped[Optional[List[str]]] = mapped_column(JSON, nullable=True)
    # Sanitised to [A-Za-z0-9 .&:()'/_-]: shown in replies and notices.
    label: Mapped[str] = mapped_column(String(40), nullable=False)
    # The owner who made it; kept (as NULL) if that account is deleted.
    created_by: Mapped[Optional[uuid.UUID]] = mapped_column(
        Uuid(),
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )

    def __repr__(self) -> str:
        return f"<TutorLock {self.scope} {self.label!r}>"
