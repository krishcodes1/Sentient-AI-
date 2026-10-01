"""Declares the study tables: ``study_decks`` (a user's flashcard decks),
``study_items`` (their cards and multiple-choice items, each with its own
spaced-repetition state), ``study_reviews`` (one row per graded review),
``study_quiz_attempts`` (a practice quiz and its answers) and
``study_settings`` (the user's review limits and the id of their "cards are
due" nudge).

Why it exists: the study.* tools, the model-free Telegram and Slack reviews
and the nudge renderer all read and write the same per-user store, and the
due-date queries need real indexed columns (a JSON blob per deck could not
answer "what is due now" without loading every card). Every row belongs to
one user and cascades away with that user; kinds, modes and statuses are
plain strings validated in code, so no Postgres enum type is needed.

The column sizes below are shared with the toolkit's limits
(services/study/items.py), so an item the tool accepted always fits; a test
holds them equal.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any, Optional

from sqlalchemy import (
    JSON,
    Boolean,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    SmallInteger,
    String,
    Text,
    Uuid,
)
from sqlalchemy.orm import Mapped, mapped_column

from core.database import Base

# Column sizes (the toolkit's limits are the same numbers).
DECK_TITLE_MAX_CHARS = 120
COURSE_MAX_CHARS = 80
SOURCE_KIND_MAX_CHARS = 24
SOURCE_REF_MAX_CHARS = 200
SOURCE_NOTE_MAX_CHARS = 120
ITEM_KIND_MAX_CHARS = 8
DIFFICULTY_MAX_CHARS = 8
CONTENT_HASH_CHARS = 64
REVIEW_MODE_MAX_CHARS = 8
CHANNEL_MAX_CHARS = 8
ATTEMPT_STATUS_MAX_CHARS = 12

# What an item is: a front/back card, or a multiple-choice question.
ITEM_KINDS = ("card", "choice")
# Where a graded review came from.
REVIEW_MODES = ("review", "quiz")
STUDY_CHANNELS = ("chat", "telegram", "slack")
# active: being answered; finished: scored; abandoned: left for over a day.
ATTEMPT_STATUSES = ("active", "finished", "abandoned")

# SM-2's starting ease (services/study/srs.py).
DEFAULT_EASE = 2.5
DEFAULT_NEW_PER_DAY = 20
DEFAULT_SESSION_SIZE = 20


def _now() -> datetime:
    return datetime.now(timezone.utc)


class StudyDeck(Base):
    __tablename__ = "study_decks"
    __table_args__ = (Index("ix_study_decks_user_id_created_at", "user_id", "created_at"),)

    id: Mapped[uuid.UUID] = mapped_column(Uuid(), primary_key=True, default=uuid.uuid4)
    user_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(), ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )
    title: Mapped[str] = mapped_column(String(DECK_TITLE_MAX_CHARS), nullable=False)
    course: Mapped[Optional[str]] = mapped_column(String(COURSE_MAX_CHARS), nullable=True)
    # notes, chat, file, knowledge_base, canvas, drive, onedrive, notion,
    # web or other: where the material came from (a label, never fetched).
    source_kind: Mapped[str] = mapped_column(
        String(SOURCE_KIND_MAX_CHARS), nullable=False, default="notes"
    )
    # A display label for the source ("Lecture 3 slides"); never fetched.
    source_ref: Mapped[Optional[str]] = mapped_column(String(SOURCE_REF_MAX_CHARS), nullable=True)
    # Whether /review, study.review and the nudge include this deck.
    in_reviews: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_now
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_now, onupdate=_now
    )
    last_studied_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    def __repr__(self) -> str:
        return f"<StudyDeck {self.id}>"


class StudyItem(Base):
    """One card or multiple-choice item with its SM-2 state. ``due_at`` NULL
    means new (never reviewed). ``user_id`` repeats the deck's owner, so the
    due queue is one indexed query per user."""

    __tablename__ = "study_items"
    __table_args__ = (
        Index("ix_study_items_user_id_due_at", "user_id", "due_at"),
        Index("ix_study_items_deck_id_position", "deck_id", "position"),
        # One item per front (and kind) per deck: saving the same material
        # twice adds nothing.
        Index("uq_study_items_deck_id_content_hash", "deck_id", "content_hash", unique=True),
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid(), primary_key=True, default=uuid.uuid4)
    deck_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(), ForeignKey("study_decks.id", ondelete="CASCADE"), nullable=False
    )
    user_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(), ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )
    kind: Mapped[str] = mapped_column(String(ITEM_KIND_MAX_CHARS), nullable=False)
    front: Mapped[str] = mapped_column(Text, nullable=False)
    back: Mapped[str] = mapped_column(Text, nullable=False)
    # choice items: 2-6 options and the 0-based index of the right one.
    choices: Mapped[Optional[list[str]]] = mapped_column(JSON, nullable=True)
    answer_index: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    explanation: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    # Aligned with ``choices``: why each wrong option is wrong (or null).
    choice_notes: Mapped[Optional[list[Any]]] = mapped_column(JSON, nullable=True)
    tags: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    difficulty: Mapped[Optional[str]] = mapped_column(String(DIFFICULTY_MAX_CHARS), nullable=True)
    source_note: Mapped[Optional[str]] = mapped_column(String(SOURCE_NOTE_MAX_CHARS), nullable=True)
    content_hash: Mapped[str] = mapped_column(String(CONTENT_HASH_CHARS), nullable=False)
    position: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    suspended: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    ease: Mapped[float] = mapped_column(Float, nullable=False, default=DEFAULT_EASE)
    interval_days: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    repetitions: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    lapses: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    due_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    last_reviewed_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_now
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_now, onupdate=_now
    )

    def __repr__(self) -> str:
        return f"<StudyItem {self.id} kind={self.kind}>"


class StudyReview(Base):
    """One graded review (1 again, 2 hard, 3 good, 4 easy). Ids and numbers
    only: never the card's text."""

    __tablename__ = "study_reviews"
    __table_args__ = (
        Index("ix_study_reviews_user_id_reviewed_at", "user_id", "reviewed_at"),
        Index("ix_study_reviews_item_id", "item_id"),
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid(), primary_key=True, default=uuid.uuid4)
    user_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(), ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )
    deck_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(), ForeignKey("study_decks.id", ondelete="CASCADE"), nullable=False
    )
    item_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(), ForeignKey("study_items.id", ondelete="CASCADE"), nullable=False
    )
    reviewed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_now
    )
    rating: Mapped[int] = mapped_column(SmallInteger, nullable=False)
    was_new: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    mode: Mapped[str] = mapped_column(String(REVIEW_MODE_MAX_CHARS), nullable=False)
    channel: Mapped[str] = mapped_column(String(CHANNEL_MAX_CHARS), nullable=False)
    interval_after_days: Mapped[float] = mapped_column(Float, nullable=False)
    ease_after: Mapped[float] = mapped_column(Float, nullable=False)

    def __repr__(self) -> str:
        return f"<StudyReview {self.id} rating={self.rating}>"


class StudyQuizAttempt(Base):
    """A practice quiz: the items picked (in order), the next position (the
    Telegram double-press guard) and the answers given. The answer key stays
    here, never in what the model is shown before it submits."""

    __tablename__ = "study_quiz_attempts"
    __table_args__ = (
        Index("ix_study_quiz_attempts_user_id_started_at", "user_id", "started_at"),
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid(), primary_key=True, default=uuid.uuid4)
    user_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(), ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )
    deck_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(), ForeignKey("study_decks.id", ondelete="CASCADE"), nullable=False
    )
    channel: Mapped[str] = mapped_column(String(CHANNEL_MAX_CHARS), nullable=False)
    item_ids: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    position: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    # [{item_id, choice (the shown position, or null), correct}].
    answers: Mapped[list[dict[str, Any]]] = mapped_column(JSON, nullable=False, default=list)
    total: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    answered: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    correct: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    status: Mapped[str] = mapped_column(
        String(ATTEMPT_STATUS_MAX_CHARS), nullable=False, default="active"
    )
    started_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_now
    )
    finished_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)

    def __repr__(self) -> str:
        return f"<StudyQuizAttempt {self.id} status={self.status}>"


class StudySettings(Base):
    """A user's review limits and the scheduled "cards are due" nudge (a
    scheduled_tasks row of kind nudge; its hour and days live there)."""

    __tablename__ = "study_settings"

    user_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(), ForeignKey("users.id", ondelete="CASCADE"), primary_key=True
    )
    new_per_day: Mapped[int] = mapped_column(
        SmallInteger, nullable=False, default=DEFAULT_NEW_PER_DAY
    )
    session_size: Mapped[int] = mapped_column(
        SmallInteger, nullable=False, default=DEFAULT_SESSION_SIZE
    )
    nudge_task_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        Uuid(), ForeignKey("scheduled_tasks.id", ondelete="SET NULL"), nullable=True
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_now, onupdate=_now
    )

    def __repr__(self) -> str:
        return f"<StudySettings {self.user_id}>"
