"""Creates the ``skill_states`` table (the owner's on/off switch for each bundled
skill), guarded against it already existing.

Why it exists: bundled skills (backend/skills/) are on by default, and the
owner can switch any one off, or back on, from Settings → Skills
(api/routes/skills.py). The switch is install-wide, so the table is keyed by
the skill's name; no row means the bundled default (on). It keeps the hash
of the text the owner saw and who set it, kept as NULL when that account is
deleted. The first revision after the reserved top10 chain (0017 to 0024).
Guarded like 0024: an adopted legacy database is created from model metadata
(which already has the table) before the upgrade runs. Columns mirror
models/skill_state.py. No enum types.

Revision ID: 0025_skill_states
Revises: 0024_media_transcripts
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0025_skill_states"
down_revision = "0024_media_transcripts"
branch_labels = None
depends_on = None

_TABLE = "skill_states"


def _has_table(name: str) -> bool:
    return sa.inspect(op.get_bind()).has_table(name)


def upgrade() -> None:
    if _has_table(_TABLE):
        return
    op.create_table(
        _TABLE,
        sa.Column("name", sa.String(64), primary_key=True),
        sa.Column("enabled", sa.Boolean(), nullable=False),
        sa.Column("sha256", sa.String(64), nullable=True),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column(
            "updated_by",
            sa.Uuid(),
            sa.ForeignKey("users.id", ondelete="SET NULL"),
            nullable=True,
        ),
    )


def downgrade() -> None:
    if _has_table(_TABLE):
        op.drop_table(_TABLE)
