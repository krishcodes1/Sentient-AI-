"""Adds the ``browser_site_rules`` table (security S7: site rules for
Crawler's browser), guarded against it already existing.

Why it exists: the owner's install-wide Blocked / Always ask / Trusted rules
and their overrides of the built-in sensitive-site categories are owner policy
that is not a number, so they get their own rows. Install policy outlives the
account that wrote it: ``created_by`` and ``updated_by`` are set to NULL when
that user is deleted. Guarded like 0023 (inspector checks and
``if_not_exists``): an adopted pre-Alembic database is built from the model
metadata before it is stamped and upgraded. Columns mirror
models/browser_site_rule.py. No enum types and no CHECK constraints: values
are checked in code.

This is the revision reserved for S7 (browser_site_rules) in the security
chain (0025 to 0032): its id and down_revision were fixed up front and never
change.

Revision ID: 0030_browser_site_rules
Revises: 0029_breach_watch
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0030_browser_site_rules"
down_revision = "0029_breach_watch"
branch_labels = None
depends_on = None

_TABLE = "browser_site_rules"
_INDEX = "ux_browser_site_rules_target"


def _has_table(name: str) -> bool:
    return name in sa.inspect(op.get_bind()).get_table_names()


def upgrade() -> None:
    if not _has_table(_TABLE):
        op.create_table(
            _TABLE,
            sa.Column("id", sa.Uuid(), primary_key=True, nullable=False),
            sa.Column("target_type", sa.String(16), nullable=False),
            sa.Column("target", sa.String(255), nullable=False),
            sa.Column("kind", sa.String(16), nullable=False),
            sa.Column(
                "created_by",
                sa.Uuid(),
                sa.ForeignKey("users.id", ondelete="SET NULL"),
                nullable=True,
            ),
            sa.Column(
                "updated_by",
                sa.Uuid(),
                sa.ForeignKey("users.id", ondelete="SET NULL"),
                nullable=True,
            ),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        )
    op.create_index(_INDEX, _TABLE, ["target_type", "target"], unique=True, if_not_exists=True)


def downgrade() -> None:
    op.drop_index(_INDEX, table_name=_TABLE, if_exists=True)
    if _has_table(_TABLE):
        op.drop_table(_TABLE)
