"""Reminders the assistant can set on the user's behalf.

Guarded with inspector checks and ``if_not_exists`` for the same reason as
0003/0004: an adopted pre-Alembic database is built from model metadata
(which already contains this table) before it is stamped and upgraded.

Revision ID: 0005_reminders
Revises: 0004_telegram_link
"""

import sqlalchemy as sa
from alembic import op

revision = "0005_reminders"
down_revision = "0004_telegram_link"
branch_labels = None
depends_on = None


def _has_table(name: str) -> bool:
    return name in sa.inspect(op.get_bind()).get_table_names()


def upgrade() -> None:
    if not _has_table("reminders"):
        op.create_table(
            "reminders",
            sa.Column("id", sa.Uuid(), primary_key=True, nullable=False),
            sa.Column(
                "user_id",
                sa.Uuid(),
                sa.ForeignKey("users.id", ondelete="CASCADE"),
                nullable=False,
            ),
            sa.Column("title", sa.String(200), nullable=False),
            sa.Column("note", sa.Text(), nullable=True),
            sa.Column("due_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column(
                "status",
                sa.Enum(
                    "scheduled",
                    "delivered",
                    "cancelled",
                    name="reminder_status",
                ),
                server_default="scheduled",
                nullable=False,
            ),
            sa.Column(
                "source",
                sa.Enum("user", "agent", name="reminder_source"),
                server_default="user",
                nullable=False,
            ),
            sa.Column("delivered_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        )
    op.create_index(
        "ix_reminders_user_id", "reminders", ["user_id"], if_not_exists=True
    )
    op.create_index(
        "ix_reminders_status_due_at",
        "reminders",
        ["status", "due_at"],
        if_not_exists=True,
    )
    op.create_index(
        "ix_reminders_user_id_due_at",
        "reminders",
        ["user_id", "due_at"],
        if_not_exists=True,
    )


def downgrade() -> None:
    op.drop_index(
        "ix_reminders_user_id_due_at", table_name="reminders", if_exists=True
    )
    op.drop_index(
        "ix_reminders_status_due_at", table_name="reminders", if_exists=True
    )
    op.drop_index("ix_reminders_user_id", table_name="reminders", if_exists=True)
    op.drop_table("reminders")
    # Postgres keeps enum types after the table goes; SQLite has none.
    bind = op.get_bind()
    if bind.dialect.name == "postgresql":
        sa.Enum(name="reminder_status").drop(bind, checkfirst=True)
        sa.Enum(name="reminder_source").drop(bind, checkfirst=True)
