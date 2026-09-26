"""Adds ``conversations.loaded_tools``, a nullable JSON list of tool names.

Why it exists: the model is offered at most 24 tools per request, and
``tools.find`` loads the others a conversation needs. The loaded names are
stored on the conversation so they stay offered on later turns instead of
being searched for again. Connects to ``models.conversation.Conversation``,
which the agent routes (api/routes/agent.py) read before a turn and update
after one that loaded something; talks to no external service.

Nullable with no server default: NULL means nothing loaded yet, so existing
rows need no backfill. The add is guarded like 0003 to 0009, because an
adopted legacy database is built from the model metadata (which already has
the column) before the upgrade runs.

Revision ID: 0013_conversation_loaded_tools
Revises: 0012_oauth_states
"""

import sqlalchemy as sa
from alembic import op

revision = "0013_conversation_loaded_tools"
down_revision = "0012_oauth_states"
branch_labels = None
depends_on = None

_TABLE = "conversations"
_COLUMN = "loaded_tools"


def _has_column(table: str, column: str) -> bool:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    return column in {c["name"] for c in inspector.get_columns(table)}


def upgrade() -> None:
    if not _has_column(_TABLE, _COLUMN):
        op.add_column(_TABLE, sa.Column(_COLUMN, sa.JSON(), nullable=True))


def downgrade() -> None:
    if _has_column(_TABLE, _COLUMN):
        op.drop_column(_TABLE, _COLUMN)
