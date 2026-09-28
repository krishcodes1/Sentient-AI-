"""Joins the weekly app approvals revision (0015_app_approvals, on 0014)
with the page-watch merge (0015_merge_page_watches, also on 0014) into one
head. Changes no schema.

Why it exists: the two features were built in parallel from the same
parent, and a database may already have run either one. Both keep their
revision and parent, and ``alembic upgrade head`` reaches this head from
either line, or neither, with no manual step.

Revision ID: 0016_merge_app_approvals
Revises: 0015_merge_page_watches, 0015_app_approvals
"""

from __future__ import annotations

revision = "0016_merge_app_approvals"
down_revision = ("0015_merge_page_watches", "0015_app_approvals")
branch_labels = None
depends_on = None


def upgrade() -> None:
    pass


def downgrade() -> None:
    pass
