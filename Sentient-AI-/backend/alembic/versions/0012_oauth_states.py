"""Creates the ``oauth_states`` table the OAuth broker keeps one row in per
connector sign-in flow, with its three indexes, each guarded against already
existing.

Why it exists: the provider's redirect back to /api/oauth/callback carries no
bearer token, so a stored row (keyed by the HMAC of the ``state`` value) is
what binds it to the user who started the flow. Connects to
``models.oauth_state.OAuthState`` and ``services/connectors/oauth.py``; talks
to no external service.

Guarded with inspector checks and ``if_not_exists`` like 0005: an adopted
pre-Alembic database is built from model metadata (which already contains
this table) before it is stamped and upgraded.

Revision ID: 0012_oauth_states
Revises: 0011_connector_type_string
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0012_oauth_states"
down_revision = "0011_connector_type_string"
branch_labels = None
depends_on = None

_TABLE = "oauth_states"


def _has_table(name: str) -> bool:
    return name in sa.inspect(op.get_bind()).get_table_names()


def upgrade() -> None:
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
            sa.Column("provider", sa.String(32), nullable=False),
            sa.Column("connector_type", sa.String(64), nullable=False),
            sa.Column("kind", sa.String(16), nullable=False),
            sa.Column("state_hash", sa.String(64), nullable=True),
            sa.Column("encrypted_secret", sa.LargeBinary(), nullable=True),
            sa.Column("requested_scopes", sa.JSON(), nullable=False),
            sa.Column("draft", sa.JSON(), nullable=False),
            sa.Column("device_info", sa.JSON(), nullable=True),
            sa.Column(
                "status",
                sa.String(16),
                server_default="pending",
                nullable=False,
            ),
            sa.Column("error", sa.String(255), nullable=True),
            sa.Column(
                "connector_id",
                sa.Uuid(),
                sa.ForeignKey("connector_configs.id", ondelete="SET NULL"),
                nullable=True,
            ),
            sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        )
    op.create_index(
        "ix_oauth_states_user_id", _TABLE, ["user_id"], if_not_exists=True
    )
    op.create_index(
        "ix_oauth_states_state_hash",
        _TABLE,
        ["state_hash"],
        unique=True,
        if_not_exists=True,
    )
    op.create_index(
        "ix_oauth_states_expires_at", _TABLE, ["expires_at"], if_not_exists=True
    )


def downgrade() -> None:
    op.drop_index("ix_oauth_states_expires_at", table_name=_TABLE, if_exists=True)
    op.drop_index("ix_oauth_states_state_hash", table_name=_TABLE, if_exists=True)
    op.drop_index("ix_oauth_states_user_id", table_name=_TABLE, if_exists=True)
    op.drop_table(_TABLE)
