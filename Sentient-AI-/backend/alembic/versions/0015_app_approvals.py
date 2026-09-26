"""Creates the ``app_approvals`` table for weekly app approvals, guarded
against it already existing.

Why it exists: The owner can allow one app on this computer for 7 days from a
desktop.act approval card, for requests from one Telegram chat or one browser
(spec 2026-09-25-weekly-app-approvals). The row must outlive restarts and be
readable by every worker and the Telegram poller. Guarded for the same reason
as 0005-0010: an adopted legacy database is created from model metadata
(which already has the table) before the upgrade runs.

Numbered after the connectors branch's 0010-0014 (their migrations land
between this and 0010_vault_items); ``down_revision`` is set to main's head at
merge time.

Revision ID: 0015_app_approvals
Revises: 0010_vault_items
"""

import sqlalchemy as sa
from alembic import op

revision = "0015_app_approvals"
down_revision = "0010_vault_items"
branch_labels = None
depends_on = None

_TABLE = "app_approvals"
_INDEX = "ix_app_approvals_lookup"


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
        sa.Column("tool", sa.String(64), nullable=False),
        sa.Column("app_key", sa.String(100), nullable=False),
        sa.Column("app_name", sa.String(100), nullable=False),
        sa.Column("channel_kind", sa.String(16), nullable=False),
        sa.Column("channel_key", sa.String(128), nullable=False),
        sa.Column("granted_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_used_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("uses", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("source_action_id", sa.Uuid(), nullable=True),
    )
    op.create_index(_INDEX, _TABLE, ["user_id", "app_key", "channel_kind", "channel_key"])


def downgrade() -> None:
    if _has_table(_TABLE):
        op.drop_index(_INDEX, table_name=_TABLE)
        op.drop_table(_TABLE)
