"""Telegram approval linking columns on users.

``telegram_chat_id`` is the chat approvals are pushed to (NULL = feature
not linked for this user). ``telegram_link_code`` / ``telegram_link_
expires_at`` hold the short-lived one-time code that proves the person
tapping the bot's /start deep link is the logged-in Crawler AI user.

Column adds are guarded and the index uses ``if_not_exists`` for the same
reason as 0003: adopted legacy databases are created from model metadata
(which already includes these columns and the index) before the upgrade
runs.

Revision ID: 0004_telegram_link
Revises: 0003_hot_path_indexes
"""

import sqlalchemy as sa
from alembic import op

revision = "0004_telegram_link"
down_revision = "0003_hot_path_indexes"
branch_labels = None
depends_on = None


def _has_column(table: str, column: str) -> bool:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    return column in {c["name"] for c in inspector.get_columns(table)}


def upgrade() -> None:
    if not _has_column("users", "telegram_chat_id"):
        op.add_column(
            "users", sa.Column("telegram_chat_id", sa.BigInteger(), nullable=True)
        )
    if not _has_column("users", "telegram_link_code"):
        op.add_column(
            "users", sa.Column("telegram_link_code", sa.String(64), nullable=True)
        )
    if not _has_column("users", "telegram_link_expires_at"):
        op.add_column(
            "users",
            sa.Column(
                "telegram_link_expires_at", sa.DateTime(timezone=True), nullable=True
            ),
        )
    op.create_index(
        "ix_users_telegram_link_code",
        "users",
        ["telegram_link_code"],
        unique=True,
        if_not_exists=True,
    )


def downgrade() -> None:
    op.drop_index(
        "ix_users_telegram_link_code", table_name="users", if_exists=True
    )
    if _has_column("users", "telegram_link_expires_at"):
        op.drop_column("users", "telegram_link_expires_at")
    if _has_column("users", "telegram_link_code"):
        op.drop_column("users", "telegram_link_code")
    if _has_column("users", "telegram_chat_id"):
        op.drop_column("users", "telegram_chat_id")
