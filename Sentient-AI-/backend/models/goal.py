"""Declares the goals tables: ``goals`` (what a user wants to reach, with where
things stand and a target date), ``goal_milestones`` (the ordered steps of one
goal) and ``goal_entries`` (the goal's progress log, one note per row).

Why it exists: a goal made in chat (the goals.* tools) and one made on the
Goals page obey the same rules (services/goals/store.py), and both need real
rows: the list is filtered by status, the steps keep their order and state,
and the log grows over months. A goal runs nothing by itself; ``check_in`` is
a preference shown to the user and the goals skill, it schedules nothing.
Every row belongs to one user and cascades away with that user (and a
milestone or note with its goal). Milestones are never deleted, only
``dropped`` (reversible), so a note keeps pointing at its milestone;
``goal_entries.milestone_id`` has no foreign key for the same reason.

Statuses, categories, states and sources are plain strings validated in code
(no Postgres enum types). The sizes and limits below are shared by the store
and the tests; migration 0026_goals mirrors these columns
(tests/test_migrations.py).
"""

from __future__ import annotations

import uuid
from datetime import date, datetime, timezone
from typing import Optional

from sqlalchemy import Date, DateTime, ForeignKey, Index, Integer, String, Text, Uuid
from sqlalchemy.orm import Mapped, mapped_column

from core.database import Base

# What a goal is about (display and filtering only).
GOAL_CATEGORIES = ("school", "career", "health", "money", "personal", "other")
# active and paused are "open": they count towards MAX_OPEN_GOALS and the
# duplicate-title rule; completed sets completed_at; archived is put away.
GOAL_STATUSES = ("active", "paused", "completed", "archived")
OPEN_STATUSES = ("active", "paused")
# How often the user wants to look at the goal: a preference, never a job.
CHECK_INS = ("none", "daily", "weekly")
# A milestone is never deleted: dropped takes it out of the progress count,
# and reopening brings it back.
MILESTONE_STATES = ("open", "done", "dropped")
# Who wrote a progress note: the user on the Goals page, or the agent's tool.
ENTRY_SOURCES = ("user", "agent")

# Column sizes (the store's limits are the same numbers).
TITLE_MAX_CHARS = 200
DESCRIPTION_MAX_CHARS = 1000
CURRENT_STATE_MAX_CHARS = 300
MILESTONE_TITLE_MAX_CHARS = 200
NOTE_MAX_CHARS = 500
CATEGORY_MAX_CHARS = 16
STATUS_MAX_CHARS = 12
CHECK_IN_MAX_CHARS = 12
STATE_MAX_CHARS = 8
SOURCE_MAX_CHARS = 8

# Per-user and per-goal limits. Hitting one is an error naming it; nothing is
# dropped silently.
MAX_GOALS_PER_USER = 50
MAX_OPEN_GOALS = 25
MAX_MILESTONES_PER_GOAL = 20
MAX_MILESTONES_PER_CALL = 12
MAX_ENTRIES_PER_GOAL = 500


def _now() -> datetime:
    return datetime.now(timezone.utc)


class Goal(Base):
    __tablename__ = "goals"
    __table_args__ = (
        # The list filtered by status, the open-goal cap and the
        # duplicate-title rule.
        Index("ix_goals_user_id_status", "user_id", "status"),
        # The per-user cap and the account export.
        Index("ix_goals_user_id_created_at", "user_id", "created_at"),
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid(), primary_key=True, default=uuid.uuid4)
    user_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(), ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )
    title: Mapped[str] = mapped_column(String(TITLE_MAX_CHARS), nullable=False)
    # At most DESCRIPTION_MAX_CHARS (checked in code; Text keeps the column
    # portable).
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    # One of GOAL_CATEGORIES.
    category: Mapped[str] = mapped_column(
        String(CATEGORY_MAX_CHARS), nullable=False, default="other", server_default="other"
    )
    # One of GOAL_STATUSES.
    status: Mapped[str] = mapped_column(
        String(STATUS_MAX_CHARS), nullable=False, default="active", server_default="active"
    )
    # One line: where things stand now.
    current_state: Mapped[Optional[str]] = mapped_column(
        String(CURRENT_STATE_MAX_CHARS), nullable=True
    )
    target_date: Mapped[Optional[date]] = mapped_column(Date, nullable=True)
    # One of CHECK_INS.
    check_in: Mapped[str] = mapped_column(
        String(CHECK_IN_MAX_CHARS), nullable=False, default="none", server_default="none"
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_now
    )
    # Moved by any change to the goal, its milestones or its log.
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_now, onupdate=_now
    )
    # Set when the status becomes completed, cleared when it leaves it.
    completed_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    def __repr__(self) -> str:
        return f"<Goal {self.id} status={self.status}>"


class GoalMilestone(Base):
    """One step of a goal. ``position`` orders a goal's milestones from 0
    with no gaps (they are never deleted). ``user_id`` repeats the goal's
    owner, so every lookup is scoped by user in one query."""

    __tablename__ = "goal_milestones"
    __table_args__ = (Index("ix_goal_milestones_goal_id_position", "goal_id", "position"),)

    id: Mapped[uuid.UUID] = mapped_column(Uuid(), primary_key=True, default=uuid.uuid4)
    goal_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(), ForeignKey("goals.id", ondelete="CASCADE"), nullable=False
    )
    user_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(), ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )
    title: Mapped[str] = mapped_column(String(MILESTONE_TITLE_MAX_CHARS), nullable=False)
    due_date: Mapped[Optional[date]] = mapped_column(Date, nullable=True)
    # One of MILESTONE_STATES.
    state: Mapped[str] = mapped_column(
        String(STATE_MAX_CHARS), nullable=False, default="open", server_default="open"
    )
    position: Mapped[int] = mapped_column(Integer, nullable=False)
    # Set when the state becomes done, cleared when it leaves it.
    done_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_now
    )

    def __repr__(self) -> str:
        return f"<GoalMilestone {self.id} goal={self.goal_id} state={self.state}>"


class GoalEntry(Base):
    """One progress note on a goal: the user's (Goals page) or the agent's
    (goals.log_progress). ``milestone_id`` is the milestone it is about, if
    any; no foreign key, so a note outlives what it points at."""

    __tablename__ = "goal_entries"
    __table_args__ = (Index("ix_goal_entries_goal_id_created_at", "goal_id", "created_at"),)

    id: Mapped[uuid.UUID] = mapped_column(Uuid(), primary_key=True, default=uuid.uuid4)
    goal_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(), ForeignKey("goals.id", ondelete="CASCADE"), nullable=False
    )
    user_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(), ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )
    note: Mapped[str] = mapped_column(String(NOTE_MAX_CHARS), nullable=False)
    # One of ENTRY_SOURCES.
    source: Mapped[str] = mapped_column(String(SOURCE_MAX_CHARS), nullable=False)
    milestone_id: Mapped[Optional[uuid.UUID]] = mapped_column(Uuid(), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_now
    )

    def __repr__(self) -> str:
        return f"<GoalEntry {self.id} goal={self.goal_id} source={self.source}>"
