"""Creates the ``tool_rules`` and ``tool_rule_builtins`` tables (the owner's
rules on tool-call arguments and the on/off state of each built-in rule),
guarded against them already existing.

Why it exists: S9 tool rules (security top 10). A rule is owner policy that is
not a number, so it cannot live in the capability settings; a built-in rule
with no row is on. Both tables are install-wide: ``created_by`` and
``changed_by`` are set to NULL when that user is deleted. The revision id was
reserved in the security chain (0025 to 0032), so its down_revision never
changes. Guarded like 0024: an adopted database built from model metadata
already has the tables. Columns mirror models/tool_rule.py. No enum types and
no CHECK constraints: values are validated in code.

Revision ID: 0031_tool_rules
Revises: 0030_browser_site_rules
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0031_tool_rules"
down_revision = "0030_browser_site_rules"
branch_labels = None
depends_on = None

_RULES = "tool_rules"
_BUILTINS = "tool_rule_builtins"


def _has_table(name: str) -> bool:
    return sa.inspect(op.get_bind()).has_table(name)


def upgrade() -> None:
    if not _has_table(_RULES):
        op.create_table(
            _RULES,
            sa.Column("id", sa.Uuid(), primary_key=True),
            sa.Column("name", sa.String(60), nullable=False),
            sa.Column("tool_pattern", sa.String(120), nullable=False),
            sa.Column("conditions", sa.JSON(), nullable=False),
            sa.Column(
                "created_by",
                sa.Uuid(),
                sa.ForeignKey("users.id", ondelete="SET NULL"),
                nullable=True,
            ),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        )
        op.create_index("ix_tool_rules_created_at", _RULES, ["created_at"])
    if not _has_table(_BUILTINS):
        op.create_table(
            _BUILTINS,
            sa.Column("key", sa.String(40), primary_key=True),
            sa.Column("enabled", sa.Boolean(), nullable=False),
            sa.Column(
                "changed_by",
                sa.Uuid(),
                sa.ForeignKey("users.id", ondelete="SET NULL"),
                nullable=True,
            ),
            sa.Column("changed_at", sa.DateTime(timezone=True), nullable=False),
        )


def downgrade() -> None:
    if _has_table(_BUILTINS):
        op.drop_table(_BUILTINS)
    if _has_table(_RULES):
        op.drop_index("ix_tool_rules_created_at", table_name=_RULES)
        op.drop_table(_RULES)
