"""Creates the ``mcp_tool_pins`` table (security S5: MCP tool-definition
pinning), guarded against it already existing.

Why it exists: mcp_pinning remembers a fingerprint of every MCP tool's raw
definition per connector and holds a changed or new tool until the owner
reviews it. Rows cascade with their user and their connector. The revision id
was reserved for S5 in the security chain (0025 to 0032), so its
down_revision never changes. Guarded like 0024: an adopted database built from
model metadata already has the table. Columns mirror models/mcp_tool_pin.py.
No enum types: status, review_kind and trusted_how are strings checked in
code.

Revision ID: 0028_mcp_tool_pins
Revises: 0027_mail_security
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0028_mcp_tool_pins"
down_revision = "0027_mail_security"
branch_labels = None
depends_on = None

_TABLE = "mcp_tool_pins"


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
        sa.Column(
            "connector_id",
            sa.Uuid(),
            sa.ForeignKey("connector_configs.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("name_key", sa.String(64), nullable=False),
        sa.Column("remote_name", sa.String(512), nullable=False),
        sa.Column("exposed_name", sa.String(64), nullable=False),
        sa.Column("status", sa.String(16), nullable=False),
        sa.Column("review_kind", sa.String(16), nullable=True),
        sa.Column("trusted_how", sa.String(16), nullable=True),
        sa.Column("approved_hash", sa.String(64), nullable=True),
        sa.Column("approved_definition", sa.JSON(), nullable=True),
        sa.Column("approved_hidden_chars", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("pending_hash", sa.String(64), nullable=True),
        sa.Column("pending_definition", sa.JSON(), nullable=True),
        sa.Column("pending_hidden_chars", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("change_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("notified_hash", sa.String(64), nullable=True),
        sa.Column("notified_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("first_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("approved_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("changed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("removed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index(
        "uq_mcp_tool_pins_connector_name", _TABLE, ["connector_id", "name_key"], unique=True
    )
    op.create_index("ix_mcp_tool_pins_connector_exposed", _TABLE, ["connector_id", "exposed_name"])
    op.create_index("ix_mcp_tool_pins_user_status", _TABLE, ["user_id", "status"])


def downgrade() -> None:
    if not _has_table(_TABLE):
        return
    op.drop_index("ix_mcp_tool_pins_user_status", table_name=_TABLE)
    op.drop_index("ix_mcp_tool_pins_connector_exposed", table_name=_TABLE)
    op.drop_index("uq_mcp_tool_pins_connector_name", table_name=_TABLE)
    op.drop_table(_TABLE)
