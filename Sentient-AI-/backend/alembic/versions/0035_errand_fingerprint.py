"""Adds the nullable ``errands.source_fingerprint``, guarded against it already
existing: the hash of what a calendar errand's note said when it was last read.

Why it exists: Google Calendar gives an event no change time, so the calendar
finder tells a changed note by its fingerprint, which it kept only in memory.
After a restart a Google-only note edited while Crawler was down looked the
same as before and was never read again: the errand ran with the old item and
day. With the fingerprint on the row, a restart reads a note again only when it
differs. NULL for older rows and chat errands, so there is no backfill (the
finder fills it the next time it sees the note). Guarded like 0034: an adopted
database built from model metadata already has the column. A separate revision
rather than an edit of 0034_errand_details, which a database may already have
run.

Downgrade drops the column, in a batch (SQLite rebuilds the table).

Revision ID: 0035_errand_fingerprint
Revises: 0034_errand_details
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0035_errand_fingerprint"
down_revision = "0034_errand_details"
branch_labels = None
depends_on = None

_TABLE = "errands"
_COLUMN = "source_fingerprint"


def _present() -> bool:
    return _COLUMN in {c["name"] for c in sa.inspect(op.get_bind()).get_columns(_TABLE)}


def upgrade() -> None:
    if _present():
        return
    with op.batch_alter_table(_TABLE) as batch:
        batch.add_column(sa.Column(_COLUMN, sa.String(64), nullable=True))


def downgrade() -> None:
    if not _present():
        return
    with op.batch_alter_table(_TABLE) as batch:
        batch.drop_column(_COLUMN)
