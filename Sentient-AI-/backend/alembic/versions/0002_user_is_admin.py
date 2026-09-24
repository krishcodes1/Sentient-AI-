"""Adds ``users.is_admin`` (default false, guarded against the column already
existing) and promotes the oldest account.

Why it exists: The ``admin_only`` permission tier had no role to check against
until this column existed; the inspector guard lets the revision run on both a
stamped pre-Alembic database and one already built by ``create_all``.

Add users.is_admin, promoting the first account.

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


def _has_is_admin() -> bool:
    """Whether the column is already there.

    This revision has to meet databases in two different states. One that
    predates Alembic gets stamped at the baseline and then arrives here
    needing the column. But a database built by the old create_all() from
    a recent checkout ALREADY has it, and is stamped at the baseline just
    the same — for that one, adding the column raises DuplicateColumn and,
    on Postgres, aborts the transaction so startup fails identically on
    every restart.
    """
    inspector = sa.inspect(op.get_bind())
    return any(c["name"] == "is_admin" for c in inspector.get_columns("users"))


def upgrade() -> None:
    if _has_is_admin():
        return

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
