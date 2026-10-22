"""Creates the file-reputation tables (security S10): the install-wide
VirusTotal verdict cache ``file_reputation_verdicts``, each user's file checks
``file_reputation_checks`` and the request log ``file_reputation_calls``,
guarded against them already existing.

Why it exists: a VirusTotal answer about a fingerprint is the same for
everyone, so it is cached once; each person's own history (and where their
file's bytes can be fetched again for an approved upload) cascades with that
person; and the public key's per-minute and per-day limits belong to the key,
not to a process, so every request is logged before it is made. The request
log keeps its rows when a user is deleted (``user_id`` set to NULL), so the
day's count survives. Guarded like 0024: an adopted database built from model
metadata already has the tables. Columns mirror models/file_reputation.py. No
server defaults and no enum types: states and verdicts are strings checked in
code.

This is the revision reserved for S10 (file_reputation) in the security chain
(0025 to 0032): its id and down_revision were fixed up front and never change.

Revision ID: 0032_file_reputation
Revises: 0031_tool_rules
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0032_file_reputation"
down_revision = "0031_tool_rules"
branch_labels = None
depends_on = None

_VERDICTS = "file_reputation_verdicts"
_CHECKS = "file_reputation_checks"
_CALLS = "file_reputation_calls"

_VERDICT_INDEXES = ("ix_file_reputation_verdicts_expires_at",)
_CHECK_INDEXES = (
    "uq_file_reputation_checks_user_sha256",
    "ix_file_reputation_checks_user_updated",
    "ix_file_reputation_checks_user_source_key",
    "ix_file_reputation_checks_state_due",
    "ix_file_reputation_checks_expires_at",
)
_CALL_INDEXES = ("ix_file_reputation_calls_at", "ix_file_reputation_calls_user_at")


def _has_table(name: str) -> bool:
    return sa.inspect(op.get_bind()).has_table(name)


def upgrade() -> None:
    if not _has_table(_VERDICTS):
        op.create_table(
            _VERDICTS,
            sa.Column("sha256", sa.String(64), primary_key=True),
            sa.Column("verdict", sa.String(16), nullable=False),
            sa.Column("malicious", sa.Integer(), nullable=False),
            sa.Column("suspicious", sa.Integer(), nullable=False),
            sa.Column("harmless", sa.Integer(), nullable=False),
            sa.Column("undetected", sa.Integer(), nullable=False),
            sa.Column("engines", sa.Integer(), nullable=False),
            sa.Column("threat_label", sa.String(64), nullable=True),
            sa.Column("file_type", sa.String(40), nullable=True),
            sa.Column("first_seen_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("analysed_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("origin", sa.String(10), nullable=False),
            sa.Column("fetched_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        )
        op.create_index("ix_file_reputation_verdicts_expires_at", _VERDICTS, ["expires_at"])
    if not _has_table(_CHECKS):
        op.create_table(
            _CHECKS,
            sa.Column("id", sa.Uuid(), primary_key=True),
            sa.Column(
                "user_id",
                sa.Uuid(),
                sa.ForeignKey("users.id", ondelete="CASCADE"),
                nullable=False,
            ),
            sa.Column("sha256", sa.String(64), nullable=False),
            sa.Column("name", sa.String(255), nullable=False),
            sa.Column("media_type", sa.String(100), nullable=True),
            sa.Column("size_bytes", sa.Integer(), nullable=True),
            sa.Column("source", sa.String(16), nullable=False),
            sa.Column("source_ref", sa.LargeBinary(), nullable=True),
            sa.Column("source_key", sa.String(64), nullable=True),
            sa.Column("state", sa.String(16), nullable=False),
            sa.Column("priority", sa.String(10), nullable=False),
            sa.Column("verdict", sa.String(16), nullable=True),
            sa.Column("malicious", sa.Integer(), nullable=True),
            sa.Column("suspicious", sa.Integer(), nullable=True),
            sa.Column("engines", sa.Integer(), nullable=True),
            sa.Column("threat_label", sa.String(64), nullable=True),
            sa.Column("reason", sa.String(32), nullable=True),
            sa.Column("alerted_verdict", sa.String(16), nullable=True),
            sa.Column("action_id", sa.String(36), nullable=True),
            sa.Column("analysis_id", sa.String(128), nullable=True),
            sa.Column("polls", sa.Integer(), nullable=False),
            sa.Column("next_poll_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("claimed_until", sa.DateTime(timezone=True), nullable=True),
            sa.Column("uploaded_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("checked_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        )
        op.create_index(
            "uq_file_reputation_checks_user_sha256", _CHECKS, ["user_id", "sha256"], unique=True
        )
        op.create_index(
            "ix_file_reputation_checks_user_updated", _CHECKS, ["user_id", "updated_at"]
        )
        op.create_index(
            "ix_file_reputation_checks_user_source_key", _CHECKS, ["user_id", "source_key"]
        )
        op.create_index("ix_file_reputation_checks_state_due", _CHECKS, ["state", "next_poll_at"])
        op.create_index("ix_file_reputation_checks_expires_at", _CHECKS, ["expires_at"])
    if not _has_table(_CALLS):
        op.create_table(
            _CALLS,
            sa.Column("id", sa.Uuid(), primary_key=True),
            sa.Column("at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("kind", sa.String(10), nullable=False),
            sa.Column("priority", sa.String(10), nullable=False),
            sa.Column(
                "user_id",
                sa.Uuid(),
                sa.ForeignKey("users.id", ondelete="SET NULL"),
                nullable=True,
            ),
        )
        op.create_index("ix_file_reputation_calls_at", _CALLS, ["at"])
        op.create_index("ix_file_reputation_calls_user_at", _CALLS, ["user_id", "at"])


def downgrade() -> None:
    # Reverse order, each table's indexes first, each step guarded.
    for table, indexes in (
        (_CALLS, _CALL_INDEXES),
        (_CHECKS, _CHECK_INDEXES),
        (_VERDICTS, _VERDICT_INDEXES),
    ):
        if not _has_table(table):
            continue
        for index in indexes:
            op.drop_index(index, table_name=table, if_exists=True)
        op.drop_table(table)
