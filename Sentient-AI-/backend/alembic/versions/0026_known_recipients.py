"""Creates the ``known_recipients`` table (keyed fingerprints of the addresses
and domains Crawler has sent mail to, per user) and the ``organisation_domains``
table (the owner's list of the install's own mail domains), guarded against
them already existing.

Why it exists: outbound message checks (security S1) tell the owner when a
message goes to someone Crawler has never sent to, or outside the
organisation. Only HMACs are kept for recipients, never an address; the
organisation's domains are install policy every user may read.
``known_recipients`` cascades with its user; ``organisation_domains.added_by``
is set to NULL when that account is deleted (the policy outlives it). Guarded
like 0024: an adopted database built from model metadata already has both
tables. Columns mirror models/known_recipient.py. No enum types: ``kind`` is a
string checked in code.

This is the revision reserved for S1 (outbound_checks) in the security chain
(0025 to 0032): its id and down_revision were fixed up front and never change.

Revision ID: 0026_known_recipients
Revises: 0025_security_service_keys
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0026_known_recipients"
down_revision = "0025_security_service_keys"
branch_labels = None
depends_on = None

_RECIPIENTS = "known_recipients"
_DOMAINS = "organisation_domains"


def _has_table(name: str) -> bool:
    return sa.inspect(op.get_bind()).has_table(name)


def upgrade() -> None:
    if not _has_table(_RECIPIENTS):
        op.create_table(
            _RECIPIENTS,
            sa.Column("id", sa.Uuid(), primary_key=True),
            sa.Column(
                "user_id",
                sa.Uuid(),
                sa.ForeignKey("users.id", ondelete="CASCADE"),
                nullable=False,
            ),
            sa.Column("kind", sa.String(8), nullable=False),
            sa.Column("value_hmac", sa.String(64), nullable=False),
            sa.Column("key_id", sa.String(8), nullable=False),
            sa.Column("first_sent_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("last_sent_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("send_count", sa.Integer(), nullable=False, server_default="1"),
        )
        op.create_index(
            "uq_known_recipients_user_kind_value",
            _RECIPIENTS,
            ["user_id", "kind", "value_hmac"],
            unique=True,
        )
        op.create_index(
            "ix_known_recipients_user_last_sent", _RECIPIENTS, ["user_id", "last_sent_at"]
        )
    if not _has_table(_DOMAINS):
        op.create_table(
            _DOMAINS,
            sa.Column("id", sa.Uuid(), primary_key=True),
            sa.Column("domain", sa.String(253), nullable=False),
            sa.Column(
                "added_by",
                sa.Uuid(),
                sa.ForeignKey("users.id", ondelete="SET NULL"),
                nullable=True,
            ),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        )
        op.create_index("uq_organisation_domains_domain", _DOMAINS, ["domain"], unique=True)


def downgrade() -> None:
    if _has_table(_DOMAINS):
        op.drop_index("uq_organisation_domains_domain", table_name=_DOMAINS)
        op.drop_table(_DOMAINS)
    if _has_table(_RECIPIENTS):
        op.drop_index("ix_known_recipients_user_last_sent", table_name=_RECIPIENTS)
        op.drop_index("uq_known_recipients_user_kind_value", table_name=_RECIPIENTS)
        op.drop_table(_RECIPIENTS)
