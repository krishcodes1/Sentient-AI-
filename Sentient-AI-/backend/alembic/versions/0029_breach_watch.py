"""Creates the breach-monitor tables ``breach_watch_addresses`` and
``breach_watch_findings`` (security S6), guarded against them already existing.

Why it exists: the weekly Have I Been Pwned sweeper needs each owner's watched
addresses (sealed, looked up by an HMAC digest) and the breaches already seen
per address, which is how only new ones are alerted. Both tables cascade with
their user, and findings with their address. The revision id was reserved for
S6 in the security chain (0025 to 0032), so its down_revision never changes.
Guarded like 0024: an adopted database built from model metadata already has
the tables. Columns mirror models/breach_watch.py. No enum types: source,
status and error codes are strings checked in code.

Revision ID: 0029_breach_watch
Revises: 0028_mcp_tool_pins
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0029_breach_watch"
down_revision = "0028_mcp_tool_pins"
branch_labels = None
depends_on = None

_ADDRESSES = "breach_watch_addresses"
_FINDINGS = "breach_watch_findings"


def _has_table(name: str) -> bool:
    return sa.inspect(op.get_bind()).has_table(name)


def upgrade() -> None:
    if not _has_table(_ADDRESSES):
        op.create_table(
            _ADDRESSES,
            sa.Column("id", sa.Uuid(), primary_key=True),
            sa.Column(
                "user_id",
                sa.Uuid(),
                sa.ForeignKey("users.id", ondelete="CASCADE"),
                nullable=False,
            ),
            sa.Column("source", sa.String(8), nullable=False),
            sa.Column("address_digest", sa.String(64), nullable=False),
            sa.Column("address_sealed", sa.LargeBinary(), nullable=False),
            sa.Column("status", sa.String(8), nullable=False),
            sa.Column("next_check_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("last_checked_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("baseline_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("breach_count", sa.Integer(), nullable=False, server_default="0"),
            sa.Column("consecutive_errors", sa.Integer(), nullable=False, server_default="0"),
            sa.Column("last_error_code", sa.String(24), nullable=True),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        )
        op.create_index(
            "uq_breach_watch_addresses_user_digest",
            _ADDRESSES,
            ["user_id", "address_digest"],
            unique=True,
        )
        op.create_index(
            "ix_breach_watch_addresses_status_next_check",
            _ADDRESSES,
            ["status", "next_check_at"],
        )
    if not _has_table(_FINDINGS):
        op.create_table(
            _FINDINGS,
            sa.Column("id", sa.Uuid(), primary_key=True),
            sa.Column(
                "address_id",
                sa.Uuid(),
                sa.ForeignKey("breach_watch_addresses.id", ondelete="CASCADE"),
                nullable=False,
            ),
            sa.Column(
                "user_id",
                sa.Uuid(),
                sa.ForeignKey("users.id", ondelete="CASCADE"),
                nullable=False,
            ),
            sa.Column("breach_name", sa.String(120), nullable=False),
            sa.Column("title", sa.String(160), nullable=False),
            sa.Column("domain", sa.String(253), nullable=True),
            sa.Column("breach_date", sa.Date(), nullable=True),
            sa.Column("added_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("pwn_count", sa.BigInteger(), nullable=True),
            sa.Column("data_classes", sa.JSON(), nullable=False),
            sa.Column("verified", sa.Boolean(), nullable=False),
            sa.Column("sensitive", sa.Boolean(), nullable=False),
            sa.Column("fabricated", sa.Boolean(), nullable=False),
            sa.Column("spam_list", sa.Boolean(), nullable=False),
            sa.Column("baseline", sa.Boolean(), nullable=False),
            sa.Column("first_seen_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("alerted_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("acknowledged_at", sa.DateTime(timezone=True), nullable=True),
        )
        op.create_index(
            "uq_breach_watch_findings_address_name",
            _FINDINGS,
            ["address_id", "breach_name"],
            unique=True,
        )
        op.create_index(
            "ix_breach_watch_findings_user_seen", _FINDINGS, ["user_id", "first_seen_at"]
        )


def downgrade() -> None:
    if _has_table(_FINDINGS):
        op.drop_index("ix_breach_watch_findings_user_seen", table_name=_FINDINGS)
        op.drop_index("uq_breach_watch_findings_address_name", table_name=_FINDINGS)
        op.drop_table(_FINDINGS)
    if _has_table(_ADDRESSES):
        op.drop_index("ix_breach_watch_addresses_status_next_check", table_name=_ADDRESSES)
        op.drop_index("uq_breach_watch_addresses_user_digest", table_name=_ADDRESSES)
        op.drop_table(_ADDRESSES)
