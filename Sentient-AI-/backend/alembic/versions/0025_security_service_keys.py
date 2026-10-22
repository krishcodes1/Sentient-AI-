"""Adds the security wave's two shared columns, guarded against them already
existing: ``installation.security_service_keys``, the encrypted owner keys for
outside security services (Google Safe Browsing / Web Risk, Have I Been Pwned,
VirusTotal), and the nullable JSON ``pending_actions.security_notes``, the
typed notes the call checks put on an approval card.

Why it exists: capability_settings holds whole numbers only and is sent to
every account, and llm_api_keys is listed as AI providers, so the security
wave's keys get their own AES-256-GCM column (one blob of {name: key}, like
llm_api_keys). A card's notes must survive a restart and be read the same way
by the database store, Telegram, Slack and the web, and ``pending_actions``
has no free JSON column, so the notes column is added here too (the scaffold's
A12 deviation; 0023 added ``pending_actions.grant_offer`` inside its skill's
revision the same way). Guarded like 0010 and 0023: an adopted database built
from model metadata already has both columns.

Downgrade drops both columns (notes on waiting cards are lost; the cards
stay). SQLite cannot drop a column in place, so each drop runs in a batch,
which rebuilds the table there.

This is the revision reserved for the security wave's shared key store
(security10, WAVE 0): its id and down_revision were fixed up front and never
change.

Revision ID: 0025_security_service_keys
Revises: 0024_media_transcripts
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0025_security_service_keys"
down_revision = "0024_media_transcripts"
branch_labels = None
depends_on = None

_KEYS_COLUMN = "security_service_keys"
_NOTES_COLUMN = "security_notes"


def _has_column(table: str, column: str) -> bool:
    return column in {c["name"] for c in sa.inspect(op.get_bind()).get_columns(table)}


def upgrade() -> None:
    if not _has_column("installation", _KEYS_COLUMN):
        op.add_column("installation", sa.Column(_KEYS_COLUMN, sa.LargeBinary(), nullable=True))
    if not _has_column("pending_actions", _NOTES_COLUMN):
        with op.batch_alter_table("pending_actions") as batch:
            batch.add_column(sa.Column(_NOTES_COLUMN, sa.JSON(), nullable=True))


def downgrade() -> None:
    if _has_column("pending_actions", _NOTES_COLUMN):
        with op.batch_alter_table("pending_actions") as batch:
            batch.drop_column(_NOTES_COLUMN)
    if _has_column("installation", _KEYS_COLUMN):
        with op.batch_alter_table("installation") as batch:
            batch.drop_column(_KEYS_COLUMN)
