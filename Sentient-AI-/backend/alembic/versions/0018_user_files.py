"""Creates the ``user_files`` table (the encrypted text Crawler extracted from
a user's uploaded files), guarded against it already existing.

Why it exists: file_extraction keeps an upload's sections so files.read can
page through them on later turns; the original bytes are never stored. The
revision id was reserved for this skill in the top10 chain (0017 to 0024),
so its down_revision never changes. Guarded like 0011-0015: an adopted
legacy database is created from model metadata (which already has the
table) before the upgrade runs. Columns mirror models/user_file.py.
user_file_pages (page images for the "look at scanned pages" phase) is not
part of this revision: that phase ships later.

Revision ID: 0018_user_files
Revises: 0017_scheduled_tasks
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0018_user_files"
down_revision = "0017_scheduled_tasks"
branch_labels = None
depends_on = None

_TABLE = "user_files"


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
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("prompt_name", sa.String(80), nullable=False),
        sa.Column("media_type", sa.String(100), nullable=False),
        sa.Column("kind", sa.String(16), nullable=False),
        sa.Column("size_bytes", sa.Integer(), nullable=False),
        sa.Column("sha256", sa.String(64), nullable=False),
        sa.Column("pages", sa.Integer(), nullable=True),
        sa.Column("sections_count", sa.Integer(), nullable=False),
        sa.Column("chars", sa.Integer(), nullable=False),
        sa.Column("ocr_pages", sa.Integer(), nullable=False),
        sa.Column("ocr_engine", sa.String(16), nullable=True),
        sa.Column("scanned_pages_unread", sa.JSON(), nullable=True),
        sa.Column("warnings", sa.JSON(), nullable=True),
        sa.Column("truncated", sa.Boolean(), nullable=False),
        sa.Column("content", sa.LargeBinary(), nullable=False),
        sa.Column("stored_bytes", sa.Integer(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_used_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("uq_user_files_user_sha256", _TABLE, ["user_id", "sha256"], unique=True)
    op.create_index("ix_user_files_user_created", _TABLE, ["user_id", "created_at"])
    op.create_index("ix_user_files_expires_at", _TABLE, ["expires_at"])


def downgrade() -> None:
    if _has_table(_TABLE):
        op.drop_index("ix_user_files_expires_at", table_name=_TABLE)
        op.drop_index("ix_user_files_user_created", table_name=_TABLE)
        op.drop_index("uq_user_files_user_sha256", table_name=_TABLE)
        op.drop_table(_TABLE)
