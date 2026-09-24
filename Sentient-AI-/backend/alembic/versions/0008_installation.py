"""One-row installation record for owner switches, provider and secrets.

The capability switches, the server-wide AI provider/model, the encrypted
provider keys and the encrypted Telegram bot token live in a single row
(id = 1) so a native install can be configured from the setup wizard
instead of a .env file. The row is seeded here so every reader can assume
it exists; the service still creates it on demand as a fallback.

The create is guarded for the same reason as 0005: an adopted legacy
database is built from model metadata (which already has this table)
before the upgrade runs. The seed is guarded separately, because that
adopted table exists but is empty.

The seed goes through a table construct rather than a raw string so the
boolean and JSON literals render correctly on both SQLite and Postgres.

Revision ID: 0008_installation
Revises: 0007_message_model
"""

from datetime import datetime, timezone

import sqlalchemy as sa
from alembic import op

revision = "0008_installation"
down_revision = "0007_message_model"
branch_labels = None
depends_on = None

_ROW_ID = 1


def _has_table(name: str) -> bool:
    return sa.inspect(op.get_bind()).has_table(name)


def upgrade() -> None:
    if not _has_table("installation"):
        op.create_table(
            "installation",
            sa.Column("id", sa.Integer(), primary_key=True, autoincrement=False),
            sa.Column("capabilities", sa.JSON(), nullable=False, server_default="{}"),
            sa.Column("llm_provider", sa.String(50), nullable=True),
            sa.Column("llm_model", sa.String(200), nullable=True),
            sa.Column("llm_api_keys", sa.LargeBinary(), nullable=True),
            sa.Column("telegram_bot_token", sa.LargeBinary(), nullable=True),
            sa.Column(
                "allow_registration",
                sa.Boolean(),
                nullable=False,
                server_default=sa.false(),
            ),
            sa.Column("setup_completed_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column(
                "updated_at",
                sa.DateTime(timezone=True),
                nullable=False,
                server_default=sa.func.now(),
            ),
            sa.Column("updated_by_user_id", sa.Uuid(), nullable=True),
        )

    installation = sa.table(
        "installation",
        sa.column("id", sa.Integer()),
        sa.column("capabilities", sa.JSON()),
        sa.column("allow_registration", sa.Boolean()),
        sa.column("updated_at", sa.DateTime(timezone=True)),
    )
    bind = op.get_bind()
    exists = bind.execute(
        sa.select(installation.c.id).where(installation.c.id == _ROW_ID)
    ).first()
    if exists is None:
        op.bulk_insert(
            installation,
            [
                {
                    "id": _ROW_ID,
                    "capabilities": {},
                    "allow_registration": False,
                    "updated_at": datetime.now(timezone.utc),
                }
            ],
        )


def downgrade() -> None:
    if _has_table("installation"):
        op.drop_table("installation")
