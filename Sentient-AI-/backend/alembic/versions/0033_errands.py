"""Creates the ``errands`` table (errand runs): one background errand per row,
with its source, the owner's own words, its dates, status and the purchase card
it waits on, guarded against it already existing.

Why it exists: an errand is planned days or months ahead and outlives every
chat turn, so it needs a durable row the errand sweeper claims by status and
run date. Guarded like 0032: an adopted database built from model metadata
already has the table. Columns mirror models/errand.py; statuses are strings
checked in code, so there is no enum type to create or drop.

The first revision after the reserved security chain: it revises
0032_file_reputation, as alembic/README.md says the next one does.

Revision ID: 0033_errands
Revises: 0032_file_reputation
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0033_errands"
down_revision = "0032_file_reputation"
branch_labels = None
depends_on = None

_TABLE = "errands"
_INDEXES = (
    "ix_errands_status_run_on",
    "uq_errands_user_source_ref",
    "ix_errands_approval_action_id",
)


def _has_table(name: str) -> bool:
    return sa.inspect(op.get_bind()).has_table(name)


def upgrade() -> None:
    if _has_table(_TABLE):
        return
    op.create_table(
        _TABLE,
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column(
            "user_id",
            sa.Uuid(),
            sa.ForeignKey("users.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("source", sa.String(16), nullable=False),
        sa.Column("source_ref", sa.String(255), nullable=True),
        sa.Column("source_updated", sa.DateTime(timezone=True), nullable=True),
        sa.Column("title", sa.String(120), nullable=False),
        sa.Column("item", sa.String(500), nullable=False),
        sa.Column("link", sa.String(2048), nullable=True),
        sa.Column("needed_by", sa.Date(), nullable=True),
        sa.Column("run_on", sa.Date(), nullable=False),
        sa.Column("status", sa.String(20), nullable=False, server_default="planned"),
        sa.Column("attempts", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("last_message", sa.Text(), nullable=True),
        sa.Column("approval_action_id", sa.Uuid(), nullable=True),
        sa.Column(
            "conversation_id",
            sa.Uuid(),
            sa.ForeignKey("conversations.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_errands_status_run_on", _TABLE, ["status", "run_on"])
    op.create_index(
        "uq_errands_user_source_ref", _TABLE, ["user_id", "source", "source_ref"], unique=True
    )
    op.create_index("ix_errands_approval_action_id", _TABLE, ["approval_action_id"])


def downgrade() -> None:
    if not _has_table(_TABLE):
        return
    for index in _INDEXES:
        op.drop_index(index, table_name=_TABLE, if_exists=True)
    op.drop_table(_TABLE)
