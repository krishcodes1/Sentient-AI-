"""Creates the ``skills`` table (playbooks a user wrote for Crawler), guarded
against it already existing.

Why it exists: user skills (backlog C5). Guarded like 0031: an adopted
database built from model metadata already has the table. Columns mirror
models/skill.py.

Revision ID: 0036_skills
Revises: 0035_errand_fingerprint
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0036_skills"
down_revision = "0035_errand_fingerprint"
branch_labels = None
depends_on = None

_TABLE = "skills"


def _has_table() -> bool:
    return sa.inspect(op.get_bind()).has_table(_TABLE)


def upgrade() -> None:
    if _has_table():
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
        sa.Column("name", sa.String(40), nullable=False),
        sa.Column("description", sa.String(200), nullable=False),
        sa.Column("instructions", sa.Text(), nullable=False),
        sa.Column("enabled", sa.Boolean(), server_default=sa.true(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_skills_user_id_name", _TABLE, ["user_id", "name"], unique=True)


def downgrade() -> None:
    if _has_table():
        op.drop_index("ix_skills_user_id_name", table_name=_TABLE)
        op.drop_table(_TABLE)
