"""Creates the ``media_transcripts`` table (a user's cached video, lecture and
podcast transcripts), guarded against it already existing.

Why it exists: video_transcripts keeps the timestamped passages it read so a
follow-up question or "continue from 45:00" costs no second provider call or
fetch. The revision id was reserved for this skill in the top10 chain (0017
to 0024), so its down_revision never changes. Guarded like 0011-0018: an
adopted legacy database is created from model metadata (which already has
the table) before the upgrade runs. Columns mirror
models/media_transcript.py. No enum types: kind, method, detail and status
are strings checked in code.

Revision ID: 0024_media_transcripts
Revises: 0023_permission_grants
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0024_media_transcripts"
down_revision = "0023_permission_grants"
branch_labels = None
depends_on = None

_TABLE = "media_transcripts"


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
        sa.Column("source_key", sa.String(80), nullable=False),
        sa.Column("kind", sa.String(12), nullable=False),
        sa.Column("method", sa.String(24), nullable=False),
        sa.Column("detail", sa.String(10), nullable=False),
        sa.Column("display_url", sa.String(500), nullable=False),
        sa.Column("title", sa.String(200), nullable=True),
        sa.Column("author", sa.String(120), nullable=True),
        sa.Column("language", sa.String(16), nullable=True),
        sa.Column("duration_s", sa.Integer(), nullable=True),
        sa.Column("engine", sa.String(80), nullable=False),
        sa.Column("segments", sa.JSON(), nullable=False),
        sa.Column("covered", sa.JSON(), nullable=False),
        sa.Column("chars", sa.Integer(), nullable=False),
        sa.Column("billed", sa.JSON(), nullable=False),
        sa.Column("status", sa.String(12), nullable=False),
        sa.Column("error", sa.String(200), nullable=True),
        sa.Column("attempts", sa.Integer(), nullable=False),
        sa.Column("claimed_until", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_used_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index(
        "uq_media_transcripts_user_source",
        _TABLE,
        ["user_id", "source_key", "method", "detail"],
        unique=True,
    )
    op.create_index("ix_media_transcripts_user_last_used", _TABLE, ["user_id", "last_used_at"])
    op.create_index("ix_media_transcripts_expires_at", _TABLE, ["expires_at"])
    op.create_index("ix_media_transcripts_status_claimed", _TABLE, ["status", "claimed_until"])


def downgrade() -> None:
    if _has_table(_TABLE):
        op.drop_index("ix_media_transcripts_status_claimed", table_name=_TABLE)
        op.drop_index("ix_media_transcripts_expires_at", table_name=_TABLE)
        op.drop_index("ix_media_transcripts_user_last_used", table_name=_TABLE)
        op.drop_index("uq_media_transcripts_user_source", table_name=_TABLE)
        op.drop_table(_TABLE)
