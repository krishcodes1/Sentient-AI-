"""Creates the mail scam check's tables (security S2: automatic scam check on
new email), ``mail_scan_cursors`` and ``mail_scam_findings``, guarded against
them already existing.

Why it exists: the mail-scan sweeper keeps one cursor row per connected Gmail
or Outlook account (where the check is in that inbox) and one finding row per
new email it flagged (why, the AI review, the alert and the cards made for
it). The unique (connector_id, external_key) index is the guard that one email
is never flagged twice across workers and restarts. Both tables cascade with
their user and their connector. Guarded like 0022 (``_has_table`` and
``if_not_exists``): an adopted database built from model metadata already has
them. Columns mirror models/mail_security.py. No enum types: statuses,
verdicts and levels are strings checked in code.

This is the revision reserved for S2 (mail_scam_scan) in the security chain
(0025 to 0032): its id and down_revision were fixed up front and never change.

Revision ID: 0027_mail_security
Revises: 0026_known_recipients
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0027_mail_security"
down_revision = "0026_known_recipients"
branch_labels = None
depends_on = None

_CURSORS = "mail_scan_cursors"
_FINDINGS = "mail_scam_findings"


def _has_table(name: str) -> bool:
    return sa.inspect(op.get_bind()).has_table(name)


def upgrade() -> None:
    if not _has_table(_CURSORS):
        op.create_table(
            _CURSORS,
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
            sa.Column("provider", sa.String(16), nullable=False),
            sa.Column("status", sa.String(12), server_default="active", nullable=False),
            sa.Column("cursor", sa.Text(), nullable=True),
            sa.Column("pending_ids", sa.JSON(), nullable=True),
            sa.Column("seen", sa.JSON(), nullable=True),
            sa.Column("account_domain", sa.String(253), nullable=True),
            sa.Column("baseline_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("next_check_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("last_checked_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("consecutive_errors", sa.Integer(), server_default="0", nullable=False),
            sa.Column("last_error", sa.String(200), nullable=True),
            sa.Column("checked_count", sa.Integer(), server_default="0", nullable=False),
            sa.Column("flagged_count", sa.Integer(), server_default="0", nullable=False),
            sa.Column("skipped_count", sa.Integer(), server_default="0", nullable=False),
            sa.Column("note", sa.String(200), nullable=True),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        )
    op.create_index(
        "ux_mail_scan_cursors_connector_id",
        _CURSORS,
        ["connector_id"],
        unique=True,
        if_not_exists=True,
    )
    op.create_index(
        "ix_mail_scan_cursors_status_next_check_at",
        _CURSORS,
        ["status", "next_check_at"],
        if_not_exists=True,
    )
    op.create_index("ix_mail_scan_cursors_user_id", _CURSORS, ["user_id"], if_not_exists=True)

    if not _has_table(_FINDINGS):
        op.create_table(
            _FINDINGS,
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
            sa.Column("provider", sa.String(16), nullable=False),
            sa.Column("external_key", sa.String(64), nullable=False),
            sa.Column("message_ref", sa.String(255), nullable=False),
            sa.Column("status", sa.String(16), server_default="pending", nullable=False),
            sa.Column("verdict", sa.String(16), server_default="unknown", nullable=False),
            sa.Column("local_level", sa.String(16), nullable=False),
            sa.Column("score", sa.Integer(), nullable=False),
            sa.Column("signals", sa.JSON(), nullable=False),
            sa.Column("facts", sa.JSON(), nullable=True),
            sa.Column("review_input", sa.JSON(), nullable=True),
            sa.Column("review", sa.JSON(), nullable=True),
            sa.Column("review_note", sa.String(200), nullable=True),
            sa.Column("reviewed_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("check_notes", sa.JSON(), nullable=True),
            sa.Column(
                "alert_delivered", sa.Boolean(), server_default=sa.false(), nullable=False
            ),
            sa.Column("alert_note", sa.String(200), nullable=True),
            sa.Column("alerted_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("card_ids", sa.JSON(), nullable=True),
            sa.Column("dismissed_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("received_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("detected_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("claimed_until", sa.DateTime(timezone=True), nullable=True),
            sa.Column("attempts", sa.Integer(), server_default="0", nullable=False),
        )
    op.create_index(
        "ux_mail_scam_findings_connector_id_external_key",
        _FINDINGS,
        ["connector_id", "external_key"],
        unique=True,
        if_not_exists=True,
    )
    op.create_index(
        "ix_mail_scam_findings_status_detected_at",
        _FINDINGS,
        ["status", "detected_at"],
        if_not_exists=True,
    )
    op.create_index(
        "ix_mail_scam_findings_user_id_detected_at",
        _FINDINGS,
        ["user_id", "detected_at"],
        if_not_exists=True,
    )
    op.create_index(
        "ix_mail_scam_findings_user_id_reviewed_at",
        _FINDINGS,
        ["user_id", "reviewed_at"],
        if_not_exists=True,
    )


def downgrade() -> None:
    # Each table's indexes go with it.
    for name in (_FINDINGS, _CURSORS):
        if _has_table(name):
            op.drop_table(name)
