"""Creates the ``slack_channel_links`` table (one row per Slack connector whose
DM channel has a link or a pending one-time code) with its user index and the
unique (team_id, slack_user_id) constraint, guarded against already existing.

Why it exists: the Slack DM chat channel serves only the Slack account linked
to a Crawler user's Slack connector. Connects to
``models.slack_link.SlackChannelLink``, ``services/notifications/slack.py`` and
``api/routes/slack.py``; talks to no external service.

Guarded like 0012: an adopted pre-Alembic database is built from model metadata
(which already contains this table) before it is stamped and upgraded.

Revision ID: 0014_slack_channel_links
Revises: 0013_conversation_loaded_tools
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0014_slack_channel_links"
down_revision = "0013_conversation_loaded_tools"
branch_labels = None
depends_on = None

_TABLE = "slack_channel_links"


def _has_table(name: str) -> bool:
    return name in sa.inspect(op.get_bind()).get_table_names()


def upgrade() -> None:
    if not _has_table(_TABLE):
        op.create_table(
            _TABLE,
            sa.Column(
                "connector_id",
                sa.Uuid(),
                sa.ForeignKey("connector_configs.id", ondelete="CASCADE"),
                primary_key=True,
                nullable=False,
            ),
            sa.Column(
                "user_id",
                sa.Uuid(),
                sa.ForeignKey("users.id", ondelete="CASCADE"),
                nullable=False,
            ),
            sa.Column("team_id", sa.String(32), nullable=True),
            sa.Column("slack_user_id", sa.String(32), nullable=True),
            sa.Column("link_code_hash", sa.String(64), nullable=True),
            sa.Column("link_expires_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("linked_at", sa.DateTime(timezone=True), nullable=True),
            sa.UniqueConstraint(
                "team_id", "slack_user_id", name="uq_slack_channel_links_team_user"
            ),
        )
    op.create_index(
        "ix_slack_channel_links_user_id", _TABLE, ["user_id"], if_not_exists=True
    )


def downgrade() -> None:
    op.drop_index("ix_slack_channel_links_user_id", table_name=_TABLE, if_exists=True)
    op.drop_table(_TABLE)
