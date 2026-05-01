"""audit chain (previous_hash + sequence)

Revision ID: 2026_05_01_0003_audit_chain
Revises: 0001_initial_baseline
Create Date: 2026-05-01 00:00:00.000000

Adds the ``previous_hash`` and ``sequence`` columns to ``audit_logs`` so
the SHA-256 audit chain can detect deletions and reorderings, plus a
composite ``(user_id, sequence)`` index used by ``AuditService``.

Existing rows are backfilled with a per-user monotonic ``sequence`` derived
from a window function over ``timestamp ASC``. ``previous_hash`` is left
NULL on legacy rows because those rows predate the chained-hash format
and would otherwise produce false-positive integrity failures.
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op


# revision identifiers, used by Alembic.
revision: str = "2026_05_01_0003_audit_chain"
down_revision: Union[str, None] = "0001_initial_baseline"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "audit_logs",
        sa.Column("previous_hash", sa.String(length=64), nullable=True),
    )
    op.add_column(
        "audit_logs",
        sa.Column("sequence", sa.Integer(), nullable=True),
    )
    op.create_index(
        "ix_audit_logs_sequence",
        "audit_logs",
        ["user_id", "sequence"],
        unique=False,
    )

    # Backfill ``sequence`` per-user using a window function. Postgres-only
    # (SQLite tests skip backfill — window functions in UPDATE FROM are not
    # universally supported and the test database is created fresh anyway).
    try:
        op.execute(
            """
            UPDATE audit_logs AS al
            SET sequence = sub.rn
            FROM (
                SELECT id,
                       (row_number() OVER (
                           PARTITION BY user_id
                           ORDER BY timestamp ASC
                       ) - 1) AS rn
                FROM audit_logs
            ) AS sub
            WHERE al.id = sub.id
            """
        )
    except Exception:
        # Dialects without window-function-in-UPDATE support (e.g. SQLite)
        # simply leave sequence NULL on legacy rows.
        pass


def downgrade() -> None:
    op.drop_index("ix_audit_logs_sequence", table_name="audit_logs")
    op.drop_column("audit_logs", "sequence")
    op.drop_column("audit_logs", "previous_hash")
