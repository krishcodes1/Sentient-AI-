"""Creates the ``vault_items`` table for the card vault and adds
``installation.capability_settings`` for per-capability owner settings,
both guarded against already existing.

Why it exists: The purchases capability (spec 2026-09-25 §2, §4) stores the
owner's card as a sealed blob whose key the database never holds, and its
spending caps as JSON on the installation row next to the switches. Both
changes are guarded for the same reason as 0005-0009: an adopted legacy
database is created from model metadata (which already has the table and
the column) before the upgrade runs.

Revision ID: 0010_vault_items
Revises: 0009_user_llm_nullable
"""

import sqlalchemy as sa
from alembic import op

revision = "0010_vault_items"
down_revision = "0009_user_llm_nullable"
branch_labels = None
depends_on = None

_TABLE = "vault_items"
_INDEX = "ix_vault_items_user_id_kind"
_SETTINGS = "capability_settings"


def _has_table(name: str) -> bool:
    return sa.inspect(op.get_bind()).has_table(name)


def _has_column(table: str, column: str) -> bool:
    inspector = sa.inspect(op.get_bind())
    return any(info["name"] == column for info in inspector.get_columns(table))


def upgrade() -> None:
    if not _has_table(_TABLE):
        op.create_table(
            _TABLE,
            sa.Column("id", sa.Uuid(), primary_key=True),
            sa.Column(
                "user_id",
                sa.Uuid(),
                sa.ForeignKey("users.id", ondelete="CASCADE"),
                nullable=False,
            ),
            sa.Column("kind", sa.String(16), nullable=False),
            sa.Column("label", sa.String(120), nullable=False),
            sa.Column("origins", sa.JSON(), nullable=False, server_default="[]"),
            sa.Column("masked", sa.String(64), nullable=False),
            sa.Column("blob", sa.LargeBinary(), nullable=False),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("last_used_at", sa.DateTime(timezone=True), nullable=True),
        )
        op.create_index(_INDEX, _TABLE, ["user_id", "kind"])

    if not _has_column("installation", _SETTINGS):
        op.add_column(
            "installation",
            sa.Column(_SETTINGS, sa.JSON(), nullable=False, server_default="{}"),
        )


def downgrade() -> None:
    if _has_column("installation", _SETTINGS):
        # SQLite cannot DROP COLUMN in place; the batch rebuilds the table
        # there and is a plain ALTER on Postgres.
        with op.batch_alter_table("installation") as batch:
            batch.drop_column(_SETTINGS)
    if _has_table(_TABLE):
        op.drop_index(_INDEX, table_name=_TABLE)
        op.drop_table(_TABLE)
