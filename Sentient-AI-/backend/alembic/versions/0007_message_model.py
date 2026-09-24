"""Adds ``messages.llm_provider``, ``llm_model``, ``cache_read_tokens`` and
``cache_write_tokens``, each guarded against the column already existing.

Why it exists: Token counts cannot be priced without knowing which model
produced the turn and how much of the prompt was cached, so the usage summary
needs these recorded per row.

Record which provider/model produced each assistant message, and how
much of its prompt was served from or written to the prompt cache.

Token counts alone cannot be priced: the same thousand tokens cost two
orders of magnitude more on one model than another, and a user's Settings
choice changes over time. Likewise a cached input token bills at a
fraction of a fresh one, so the cache split is needed to price a turn.
All four columns are nullable — rows written before this revision never
recorded them, and inventing values would misprice those rows.

Column adds are guarded for the same reason as 0003, 0004 and 0006: an
adopted legacy database is created from model metadata (which already has
these columns) before the upgrade runs.

Revision ID: 0007_message_model
Revises: 0006_message_usage
"""

import sqlalchemy as sa
from alembic import op

revision = "0007_message_model"
down_revision = "0006_message_usage"
branch_labels = None
depends_on = None


def _has_column(table: str, column: str) -> bool:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    return column in {c["name"] for c in inspector.get_columns(table)}


def upgrade() -> None:
    if not _has_column("messages", "llm_provider"):
        op.add_column(
            "messages", sa.Column("llm_provider", sa.String(32), nullable=True)
        )
    if not _has_column("messages", "llm_model"):
        op.add_column(
            "messages", sa.Column("llm_model", sa.String(128), nullable=True)
        )
    if not _has_column("messages", "cache_read_tokens"):
        op.add_column(
            "messages", sa.Column("cache_read_tokens", sa.Integer(), nullable=True)
        )
    if not _has_column("messages", "cache_write_tokens"):
        op.add_column(
            "messages", sa.Column("cache_write_tokens", sa.Integer(), nullable=True)
        )


def downgrade() -> None:
    if _has_column("messages", "cache_write_tokens"):
        op.drop_column("messages", "cache_write_tokens")
    if _has_column("messages", "cache_read_tokens"):
        op.drop_column("messages", "cache_read_tokens")
    if _has_column("messages", "llm_model"):
        op.drop_column("messages", "llm_model")
    if _has_column("messages", "llm_provider"):
        op.drop_column("messages", "llm_provider")
