"""Adds permission tiers' schema: the ``permission_grants`` table (7-day
"Allow low-risk changes" grants, one connection each), the nullable JSON
column ``pending_actions.grant_offer``, and on Postgres the ``low_risk``
label of the ``permission_tier`` enum.

Why it exists: permission_tiers (top10 wave 2) grades every connector action
low, medium or high risk and adds the per-connection tier "Allow low-risk
changes" (``low_risk``) between ``auto_approve`` and ``user_confirm``. A card
for a LOW action can offer a grant for that account; the grant must outlive
restarts and be readable by every worker and channel. Grants cascade with
their user and their connector.

Postgres: ``ALTER TYPE permission_tier ADD VALUE IF NOT EXISTS 'low_risk'
AFTER 'auto_approve'`` runs inside an autocommit block (a new enum label
cannot be used in the transaction that adds it). SQLite needs nothing: sa.Enum
there is a VARCHAR sized to the longest label (12, "hard_blocked"), and
"low_risk" has 8 characters.

Guarded like 0015 and 0017 (inspector checks and ``if_not_exists``): an
adopted pre-Alembic database is built from the model metadata, which already
has the table and column, before it is stamped and upgraded.

Downgrade maps every ``low_risk`` tier (connector rows and account defaults)
to ``user_confirm``, the stricter neighbour, then drops the column and the
table. Postgres cannot drop an enum label, so ``low_risk`` stays in the type
(backend/alembic/README.md).

This is the revision reserved for permission_tiers: its id and down_revision
were fixed by the integration seams and never change.

Revision ID: 0023_permission_grants
Revises: 0022_event_triggers
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0023_permission_grants"
down_revision = "0022_event_triggers"
branch_labels = None
depends_on = None

_TABLE = "permission_grants"
_INDEX = "ix_permission_grants_lookup"


def _has_table(name: str) -> bool:
    return name in sa.inspect(op.get_bind()).get_table_names()


def _has_column(table: str, column: str) -> bool:
    return column in {c["name"] for c in sa.inspect(op.get_bind()).get_columns(table)}


def upgrade() -> None:
    if op.get_bind().dialect.name == "postgresql":
        with op.get_context().autocommit_block():
            op.execute(
                "ALTER TYPE permission_tier ADD VALUE IF NOT EXISTS 'low_risk' AFTER 'auto_approve'"
            )

    if not _has_table(_TABLE):
        op.create_table(
            _TABLE,
            sa.Column("id", sa.Uuid(), primary_key=True, nullable=False),
            sa.Column(
                "user_id",
                sa.Uuid(),
                sa.ForeignKey("users.id", ondelete="CASCADE"),
                nullable=False,
            ),
            sa.Column(
                "connector_id",
                sa.Uuid(),
                sa.ForeignKey("connector_configs.id", ondelete="CASCADE"),
                nullable=False,
            ),
            sa.Column("kind", sa.String(32), nullable=False),
            sa.Column("granted_from", sa.String(16), nullable=True),
            sa.Column("granted_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("last_used_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("uses", sa.Integer(), nullable=False, server_default="0"),
            sa.Column("source_action_id", sa.Uuid(), nullable=True),
        )
    op.create_index(_INDEX, _TABLE, ["user_id", "connector_id", "kind"], if_not_exists=True)

    if not _has_column("pending_actions", "grant_offer"):
        with op.batch_alter_table("pending_actions") as batch:
            batch.add_column(sa.Column("grant_offer", sa.JSON(), nullable=True))


def downgrade() -> None:
    # The stricter neighbour: nothing that asked before the downgrade stops
    # asking after it.
    op.execute(
        "UPDATE connector_configs SET permission_tier = 'user_confirm' "
        "WHERE permission_tier = 'low_risk'"
    )
    op.execute(
        "UPDATE users SET default_permission_tier = 'user_confirm' "
        "WHERE default_permission_tier = 'low_risk'"
    )
    if _has_column("pending_actions", "grant_offer"):
        with op.batch_alter_table("pending_actions") as batch:
            batch.drop_column("grant_offer")
    op.drop_index(_INDEX, table_name=_TABLE, if_exists=True)
    if _has_table(_TABLE):
        op.drop_table(_TABLE)
