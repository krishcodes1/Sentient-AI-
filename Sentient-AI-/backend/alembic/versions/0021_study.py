"""Creates the study tables: ``study_decks``, ``study_items``, ``study_reviews``,
``study_quiz_attempts`` and ``study_settings``, each guarded against already
existing.

Why it exists: flashcards_quizzes (top10 wave 2) keeps each user's decks,
cards with their spaced-repetition state, graded reviews, practice quizzes and
review limits. Every user_id cascades on account delete; study_settings'
nudge_task_id points at the user's "cards are due" scheduled task and is set
to NULL when that task is deleted. Kinds, modes and statuses are plain
strings, so no Postgres enum type is created. The revision id was reserved
for this skill in the top10 chain (0017 to 0024), so its down_revision never
changes. Guarded like 0011-0018: an adopted legacy database is created from
model metadata (which already has the tables) before the upgrade runs.
Columns mirror models/study.py.

Revision ID: 0021_study
Revises: 0020_knowledge_base
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0021_study"
down_revision = "0020_knowledge_base"
branch_labels = None
depends_on = None

# Created in this order and dropped in reverse (children before parents).
_TABLES = ("study_decks", "study_items", "study_reviews", "study_quiz_attempts", "study_settings")


def _has_table(name: str) -> bool:
    return sa.inspect(op.get_bind()).has_table(name)


def _user_fk() -> sa.Column:
    return sa.Column(
        "user_id", sa.Uuid(), sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )


def _deck_fk() -> sa.Column:
    return sa.Column(
        "deck_id", sa.Uuid(), sa.ForeignKey("study_decks.id", ondelete="CASCADE"), nullable=False
    )


def upgrade() -> None:
    if not _has_table("study_decks"):
        op.create_table(
            "study_decks",
            sa.Column("id", sa.Uuid(), primary_key=True),
            _user_fk(),
            sa.Column("title", sa.String(120), nullable=False),
            sa.Column("course", sa.String(80), nullable=True),
            sa.Column("source_kind", sa.String(24), nullable=False),
            sa.Column("source_ref", sa.String(200), nullable=True),
            sa.Column("in_reviews", sa.Boolean(), nullable=False),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("last_studied_at", sa.DateTime(timezone=True), nullable=True),
        )
        op.create_index("ix_study_decks_user_id_created_at", "study_decks", ["user_id", "created_at"])

    if not _has_table("study_items"):
        op.create_table(
            "study_items",
            sa.Column("id", sa.Uuid(), primary_key=True),
            _deck_fk(),
            _user_fk(),
            sa.Column("kind", sa.String(8), nullable=False),
            sa.Column("front", sa.Text(), nullable=False),
            sa.Column("back", sa.Text(), nullable=False),
            sa.Column("choices", sa.JSON(), nullable=True),
            sa.Column("answer_index", sa.Integer(), nullable=True),
            sa.Column("explanation", sa.Text(), nullable=True),
            sa.Column("choice_notes", sa.JSON(), nullable=True),
            sa.Column("tags", sa.JSON(), nullable=False),
            sa.Column("difficulty", sa.String(8), nullable=True),
            sa.Column("source_note", sa.String(120), nullable=True),
            sa.Column("content_hash", sa.String(64), nullable=False),
            sa.Column("position", sa.Integer(), nullable=False),
            sa.Column("suspended", sa.Boolean(), nullable=False),
            sa.Column("ease", sa.Float(), nullable=False),
            sa.Column("interval_days", sa.Float(), nullable=False),
            sa.Column("repetitions", sa.Integer(), nullable=False),
            sa.Column("lapses", sa.Integer(), nullable=False),
            sa.Column("due_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("last_reviewed_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        )
        op.create_index("ix_study_items_user_id_due_at", "study_items", ["user_id", "due_at"])
        op.create_index("ix_study_items_deck_id_position", "study_items", ["deck_id", "position"])
        op.create_index(
            "uq_study_items_deck_id_content_hash", "study_items", ["deck_id", "content_hash"], unique=True
        )

    if not _has_table("study_reviews"):
        op.create_table(
            "study_reviews",
            sa.Column("id", sa.Uuid(), primary_key=True),
            _user_fk(),
            _deck_fk(),
            sa.Column(
                "item_id", sa.Uuid(), sa.ForeignKey("study_items.id", ondelete="CASCADE"), nullable=False
            ),
            sa.Column("reviewed_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("rating", sa.SmallInteger(), nullable=False),
            sa.Column("was_new", sa.Boolean(), nullable=False),
            sa.Column("mode", sa.String(8), nullable=False),
            sa.Column("channel", sa.String(8), nullable=False),
            sa.Column("interval_after_days", sa.Float(), nullable=False),
            sa.Column("ease_after", sa.Float(), nullable=False),
        )
        op.create_index("ix_study_reviews_user_id_reviewed_at", "study_reviews", ["user_id", "reviewed_at"])
        op.create_index("ix_study_reviews_item_id", "study_reviews", ["item_id"])

    if not _has_table("study_quiz_attempts"):
        op.create_table(
            "study_quiz_attempts",
            sa.Column("id", sa.Uuid(), primary_key=True),
            _user_fk(),
            _deck_fk(),
            sa.Column("channel", sa.String(8), nullable=False),
            sa.Column("item_ids", sa.JSON(), nullable=False),
            sa.Column("position", sa.Integer(), nullable=False),
            sa.Column("answers", sa.JSON(), nullable=False),
            sa.Column("total", sa.Integer(), nullable=False),
            sa.Column("answered", sa.Integer(), nullable=False),
            sa.Column("correct", sa.Integer(), nullable=False),
            sa.Column("status", sa.String(12), nullable=False),
            sa.Column("started_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
        )
        op.create_index(
            "ix_study_quiz_attempts_user_id_started_at", "study_quiz_attempts", ["user_id", "started_at"]
        )

    if not _has_table("study_settings"):
        op.create_table(
            "study_settings",
            sa.Column(
                "user_id",
                sa.Uuid(),
                sa.ForeignKey("users.id", ondelete="CASCADE"),
                primary_key=True,
            ),
            sa.Column("new_per_day", sa.SmallInteger(), nullable=False),
            sa.Column("session_size", sa.SmallInteger(), nullable=False),
            sa.Column(
                "nudge_task_id",
                sa.Uuid(),
                sa.ForeignKey("scheduled_tasks.id", ondelete="SET NULL"),
                nullable=True,
            ),
            sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        )


def downgrade() -> None:
    # Dropping a table drops its indexes with it.
    for table in reversed(_TABLES):
        if _has_table(table):
            op.drop_table(table)
