"""channel status / last_error / last_status_at

Revision ID: 2026_05_01_0004_channel_status
Revises: 0001_initial_baseline
Create Date: 2026-05-01 00:00:00.000000

Adds three columns to ``channels`` so we can persist the runtime state of
each messaging channel as observed by the OpenClaw sync layer:

- ``status`` — short enum-ish string (``connected`` / ``disconnected`` /
  ``error`` / ``connecting`` / ``unconfigured``). Defaults to
  ``unconfigured`` server-side so existing rows backfill cleanly.
- ``last_error`` — free-form text describing the most recent error.
- ``last_status_at`` — when ``status`` was last updated.

The ``down_revision`` is the baseline (``0001_initial_baseline``) per the
spec; this migration is parallel to ``2026_05_01_0003_audit_chain`` and
the deployer is expected to merge the heads when both have run.
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op


# revision identifiers, used by Alembic.
revision: str = "2026_05_01_0004_channel_status"
down_revision: Union[str, None] = "0001_initial_baseline"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "channels",
        sa.Column(
            "status",
            sa.String(length=20),
            nullable=True,
            server_default="unconfigured",
        ),
    )
    op.add_column(
        "channels",
        sa.Column("last_error", sa.Text(), nullable=True),
    )
    op.add_column(
        "channels",
        sa.Column(
            "last_status_at",
            sa.DateTime(timezone=True),
            nullable=True,
        ),
    )


def downgrade() -> None:
    op.drop_column("channels", "last_status_at")
    op.drop_column("channels", "last_error")
    op.drop_column("channels", "status")
