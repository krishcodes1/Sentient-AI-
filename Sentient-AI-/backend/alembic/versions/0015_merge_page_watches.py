"""Joins the page-watch revision (0011_page_watches, on 0009) with the
other line from 0009 (0010_vault_items, then the connectors migrations 0011
to 0014) into one head. Changes no schema.

Why it exists: 0011_page_watches was run on top of 0009 before those
migrations landed, so it keeps that parent (see its docstring).
A database that ran either line first, or neither, reaches this head with
``alembic upgrade head`` and no manual step.

Revision ID: 0015_merge_page_watches
Revises: 0014_slack_channel_links, 0011_page_watches
"""

from __future__ import annotations

revision = "0015_merge_page_watches"
down_revision = ("0014_slack_channel_links", "0011_page_watches")
branch_labels = None
depends_on = None


def upgrade() -> None:
    pass


def downgrade() -> None:
    pass
