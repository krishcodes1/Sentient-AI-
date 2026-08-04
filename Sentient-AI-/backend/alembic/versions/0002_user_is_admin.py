"""Add users.is_admin, promoting the first account.

Revision ID: 0002_user_is_admin
Revises: 0001_baseline
Create Date: 2026-08-04

The `admin_only` permission tier existed in the UI and the models but had
no role to check against, so it silently meant "this connector is disabled
for everyone". This column gives it meaning.

The data step promotes the OLDEST account. On a self-hosted install the
first person to register is the person who deployed it, which is the same
rule new registrations follow (see api/routes/auth.py). A deployment with
no users yet promotes nobody and the first registration takes the role.
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0002_user_is_admin"
down_revision = "0001_baseline"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "users",
        sa.Column(
            "is_admin",
            sa.Boolean(),
            nullable=False,
            # sa.false(), matching the model. A plain "false" string renders
            # as the TEXT literal 'false' on SQLite, and every row backfilled
            # by this ADD COLUMN would read back as truthy — turning every
            # pre-existing account into an admin. sa.false() renders as
            # `false` on Postgres and `0` on SQLite.
            server_default=sa.false(),
        ),
    )
    # Promote the earliest account. Written as a correlated subquery rather
    # than ORDER BY + LIMIT so it runs unchanged on both Postgres and the
    # SQLite the test suite migrates.
    op.execute(
        """
        UPDATE users SET is_admin = true
        WHERE id = (SELECT id FROM users ORDER BY created_at ASC LIMIT 1)
        """
    )


def downgrade() -> None:
    op.drop_column("users", "is_admin")
