"""Creates the goals tables: ``goals``, ``goal_milestones`` and ``goal_entries``,
each guarded against already existing.

Why it exists: a user's goals (made in chat with the goals.* tools or on the
Goals page, both through services/goals/store.py) keep their ordered
milestones and a progress log that grows over months, so they need real rows
rather than a JSON blob. Every user_id cascades on account delete, and a
milestone or note cascades with its goal; goal_entries.milestone_id has no
foreign key, so a note outlives the milestone it points at. Categories,
statuses, check-in choices, milestone states and note sources are plain
strings validated in code, so no Postgres enum type is created. Follows
0025_skill_states. Guarded like 0021: an adopted legacy database is created
from model metadata (which already has the tables) before the upgrade runs.
Columns mirror models/goal.py.

Revision ID: 0026_goals
Revises: 0025_skill_states
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0026_goals"
down_revision = "0025_skill_states"
branch_labels = None
depends_on = None

# Created in this order and dropped in reverse (children before parents).
_TABLES = ("goals", "goal_milestones", "goal_entries")


def _has_table(name: str) -> bool:
    return sa.inspect(op.get_bind()).has_table(name)


def _user_fk() -> sa.Column:
    return sa.Column(
        "user_id", sa.Uuid(), sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )


def _goal_fk() -> sa.Column:
    return sa.Column(
        "goal_id", sa.Uuid(), sa.ForeignKey("goals.id", ondelete="CASCADE"), nullable=False
    )


def upgrade() -> None:
    if not _has_table("goals"):
        op.create_table(
            "goals",
            sa.Column("id", sa.Uuid(), primary_key=True),
            _user_fk(),
            sa.Column("title", sa.String(200), nullable=False),
            sa.Column("description", sa.Text(), nullable=True),
            sa.Column("category", sa.String(16), server_default="other", nullable=False),
            sa.Column("status", sa.String(12), server_default="active", nullable=False),
            sa.Column("current_state", sa.String(300), nullable=True),
            sa.Column("target_date", sa.Date(), nullable=True),
            sa.Column("check_in", sa.String(12), server_default="none", nullable=False),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        )
        op.create_index("ix_goals_user_id_status", "goals", ["user_id", "status"])
        op.create_index("ix_goals_user_id_created_at", "goals", ["user_id", "created_at"])

    if not _has_table("goal_milestones"):
        op.create_table(
            "goal_milestones",
            sa.Column("id", sa.Uuid(), primary_key=True),
            _goal_fk(),
            _user_fk(),
            sa.Column("title", sa.String(200), nullable=False),
            sa.Column("due_date", sa.Date(), nullable=True),
            sa.Column("state", sa.String(8), server_default="open", nullable=False),
            sa.Column("position", sa.Integer(), nullable=False),
            sa.Column("done_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        )
        op.create_index(
            "ix_goal_milestones_goal_id_position", "goal_milestones", ["goal_id", "position"]
        )

    if not _has_table("goal_entries"):
        op.create_table(
            "goal_entries",
            sa.Column("id", sa.Uuid(), primary_key=True),
            _goal_fk(),
            _user_fk(),
            sa.Column("note", sa.String(500), nullable=False),
            sa.Column("source", sa.String(8), nullable=False),
            # No foreign key: a note survives its milestone being dropped.
            sa.Column("milestone_id", sa.Uuid(), nullable=True),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        )
        op.create_index(
            "ix_goal_entries_goal_id_created_at", "goal_entries", ["goal_id", "created_at"]
        )


def downgrade() -> None:
    # Dropping a table drops its indexes with it.
    for table in reversed(_TABLES):
        if _has_table(table):
            op.drop_table(table)
