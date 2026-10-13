"""Adds tutor mode's storage: ``conversations.tutor_state`` (nullable JSON) and
the ``tutor_locks`` table, each guarded against already existing.

Why it exists: tutor mode is per conversation, so its state (the person's own
switch and the course lock that engaged in the chat) is a column on the
conversation, NULL meaning off, so existing rows need no backfill. The owner's
locks (a Canvas course or a whole account, for one account or for every
account) are rows of their own: ``user_id`` NULL means every account, and a
lock naming an account is deleted with it; ``created_by`` is kept as NULL when
that owner's account goes. Guarded like 0013 and 0015, because an adopted
legacy database is built from the model metadata (which already has both)
before the upgrade runs. Connects to ``models.conversation.Conversation
.tutor_state`` and ``models.tutor_lock.TutorLock``; talks to no external
service.

This revision id was reserved in the top10 chain (0017-0024) so parallel
branches never pick the same parent; its down_revision is fixed.

Revision ID: 0019_tutor_mode
Revises: 0018_user_files
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0019_tutor_mode"
down_revision = "0018_user_files"
branch_labels = None
depends_on = None

_CONVERSATIONS = "conversations"
_STATE_COLUMN = "tutor_state"
_LOCKS = "tutor_locks"
_LOCKS_USER_INDEX = "ix_tutor_locks_user_id"


def _has_column(table: str, column: str) -> bool:
    inspector = sa.inspect(op.get_bind())
    return column in {c["name"] for c in inspector.get_columns(table)}


def _has_table(name: str) -> bool:
    return sa.inspect(op.get_bind()).has_table(name)


def upgrade() -> None:
    if not _has_column(_CONVERSATIONS, _STATE_COLUMN):
        op.add_column(_CONVERSATIONS, sa.Column(_STATE_COLUMN, sa.JSON(), nullable=True))
    if not _has_table(_LOCKS):
        op.create_table(
            _LOCKS,
            sa.Column("id", sa.Uuid(), primary_key=True),
            sa.Column(
                "user_id",
                sa.Uuid(),
                sa.ForeignKey("users.id", ondelete="CASCADE"),
                nullable=True,
            ),
            sa.Column("scope", sa.String(16), nullable=False),
            sa.Column("canvas_course_id", sa.String(20), nullable=True),
            sa.Column("course_code", sa.String(40), nullable=True),
            sa.Column("course_name", sa.String(120), nullable=True),
            sa.Column("aliases", sa.JSON(), nullable=True),
            sa.Column("label", sa.String(40), nullable=False),
            sa.Column(
                "created_by",
                sa.Uuid(),
                sa.ForeignKey("users.id", ondelete="SET NULL"),
                nullable=True,
            ),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        )
        op.create_index(_LOCKS_USER_INDEX, _LOCKS, ["user_id"])


def downgrade() -> None:
    if _has_table(_LOCKS):
        op.drop_index(_LOCKS_USER_INDEX, table_name=_LOCKS)
        op.drop_table(_LOCKS)
    if _has_column(_CONVERSATIONS, _STATE_COLUMN):
        op.drop_column(_CONVERSATIONS, _STATE_COLUMN)
