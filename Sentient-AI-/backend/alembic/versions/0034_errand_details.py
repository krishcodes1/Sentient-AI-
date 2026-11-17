"""Adds two nullable columns to ``errands``, guarded against them already
existing: ``details`` (who the purchase is for and the rest of what the owner's
note asked) and ``event_day`` (a calendar errand's event day as the calendar
listed it).

Why it exists: messages about an errand name only its item, while the run
still reads who it is for and the notes, so those move out of ``item`` into
``details``. The calendar finder only takes a note as deleted while its day is
inside the window it read (30 days back, 180 ahead), so an errand needed long
after its note's day is not cancelled once the note drops out of that window;
that needs the event's day on the row. Both are NULL for older rows and chat
errands, so there is no backfill. Guarded like 0025: an adopted database built
from model metadata already has both columns. A separate revision rather than
an edit of 0033_errands, which a database may already have run.

Downgrade drops both columns. SQLite cannot drop a column in place, so the
drop runs in a batch, which rebuilds the table there.

Revision ID: 0034_errand_details
Revises: 0033_errands
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0034_errand_details"
down_revision = "0033_errands"
branch_labels = None
depends_on = None

_TABLE = "errands"
_COLUMNS: tuple[tuple[str, sa.types.TypeEngine], ...] = (
    ("details", sa.String(500)),
    ("event_day", sa.Date()),
)


def _columns() -> set[str]:
    return {c["name"] for c in sa.inspect(op.get_bind()).get_columns(_TABLE)}


def upgrade() -> None:
    missing = [(name, kind) for name, kind in _COLUMNS if name not in _columns()]
    if not missing:
        return
    with op.batch_alter_table(_TABLE) as batch:
        for name, kind in missing:
            batch.add_column(sa.Column(name, kind, nullable=True))


def downgrade() -> None:
    present = [name for name, _kind in _COLUMNS if name in _columns()]
    if not present:
        return
    with op.batch_alter_table(_TABLE) as batch:
        for name in present:
            batch.drop_column(name)
