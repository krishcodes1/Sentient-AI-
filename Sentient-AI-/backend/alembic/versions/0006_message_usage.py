"""Per-message token accounting and image attachment metadata.

``input_tokens``/``output_tokens`` record what the provider billed for an
assistant turn, so cost per conversation is a SUM over ``messages`` rather
than a number that only ever existed in a log line. Both are nullable:
every row written before this revision has no usage to report, and zero
would be a lie rather than an absence.

``attachments`` holds metadata for images sent with a user message
(media type, byte size, digest) — never the bytes. See models/conversation.py
for why the blobs stay out of the row.

Column adds are guarded for the same reason as 0003 and 0004: an adopted
legacy database is created from model metadata (which already has these
columns) before the upgrade runs.

Revision ID: 0006_message_usage
Revises: 0005_reminders
"""

import sqlalchemy as sa
from alembic import op

revision = "0006_message_usage"
down_revision = "0005_reminders"
branch_labels = None
depends_on = None


def _has_column(table: str, column: str) -> bool:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    return column in {c["name"] for c in inspector.get_columns(table)}


def upgrade() -> None:
    if not _has_column("messages", "attachments"):
        op.add_column("messages", sa.Column("attachments", sa.JSON(), nullable=True))
    if not _has_column("messages", "input_tokens"):
        op.add_column("messages", sa.Column("input_tokens", sa.Integer(), nullable=True))
    if not _has_column("messages", "output_tokens"):
        op.add_column(
            "messages", sa.Column("output_tokens", sa.Integer(), nullable=True)
        )


def downgrade() -> None:
    if _has_column("messages", "output_tokens"):
        op.drop_column("messages", "output_tokens")
    if _has_column("messages", "input_tokens"):
        op.drop_column("messages", "input_tokens")
    if _has_column("messages", "attachments"):
        op.drop_column("messages", "attachments")
