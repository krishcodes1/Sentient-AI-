"""Merge auth, audit-chain, and channel-status branches.

Revision ID: 2026_05_01_0005_merge
Revises: 2026_05_01_0002_auth, 2026_05_01_0003_audit_chain, 2026_05_01_0004_channel_status
Create Date: 2026-05-01

The Round 2 backend hardening produced three independent migrations that all
branch off the initial baseline. This empty merge migration unifies them so
``alembic upgrade head`` resolves to a single head.
"""

from typing import Sequence, Union

# revision identifiers, used by Alembic.
revision: str = "2026_05_01_0005_merge"
down_revision: Union[str, Sequence[str], None] = (
    "2026_05_01_0002_auth",
    "2026_05_01_0003_audit_chain",
    "2026_05_01_0004_channel_status",
)
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    pass


def downgrade() -> None:
    pass
