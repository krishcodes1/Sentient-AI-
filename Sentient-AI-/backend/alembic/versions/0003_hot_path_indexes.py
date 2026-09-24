"""Composite indexes for the hot per-user query paths.

Every index targets a confirmed query shape: the audit chain-head lookup
(services/audit.py, runs on every audited tool event), audit listing
(api/routes/audit.py), conversation-detail message fetch (api/routes/
agent.py), the approvals poll (services/agent/approvals.py, hit every 20s
per open chat client), the conversation list, and the memory list.

``if_not_exists``/``if_exists`` throughout: an adopted legacy database is
built by ``Base.metadata.create_all`` — which already creates these indexes
from the models' ``__table_args__`` — before being stamped and upgraded, so
the migration must tolerate the indexes already existing (and vice versa on
downgrade).

Revision ID: 0003_hot_path_indexes
Revises: 0002_user_is_admin
"""

from alembic import op

revision = "0003_hot_path_indexes"
down_revision = "0002_user_is_admin"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Chain-head lookup on every audit append:
    # WHERE user_id = ? ORDER BY seq DESC NULLS LAST, timestamp DESC LIMIT 1
    op.create_index(
        "ix_audit_logs_user_id_seq",
        "audit_logs",
        ["user_id", "seq"],
        if_not_exists=True,
    )
    # Audit listing: WHERE user_id = ? ORDER BY timestamp DESC LIMIT/OFFSET
    op.create_index(
        "ix_audit_logs_user_id_timestamp",
        "audit_logs",
        ["user_id", "timestamp"],
        if_not_exists=True,
    )
    # Conversation detail / agent context:
    # WHERE conversation_id = ? ORDER BY created_at
    op.create_index(
        "ix_messages_conversation_id_created_at",
        "messages",
        ["conversation_id", "created_at"],
        if_not_exists=True,
    )
    # Approvals poll (every 20s per open chat):
    # WHERE user_id = ? AND status = 'pending'
    op.create_index(
        "ix_pending_actions_user_id_status",
        "pending_actions",
        ["user_id", "status"],
        if_not_exists=True,
    )
    # Conversation list: WHERE user_id = ? ORDER BY updated_at DESC
    op.create_index(
        "ix_conversations_user_id_updated_at",
        "conversations",
        ["user_id", "updated_at"],
        if_not_exists=True,
    )
    # Memory list: WHERE user_id = ? ORDER BY created_at DESC
    op.create_index(
        "ix_memories_user_id_created_at",
        "memories",
        ["user_id", "created_at"],
        if_not_exists=True,
    )


def downgrade() -> None:
    op.drop_index(
        "ix_memories_user_id_created_at", table_name="memories", if_exists=True
    )
    op.drop_index(
        "ix_conversations_user_id_updated_at",
        table_name="conversations",
        if_exists=True,
    )
    op.drop_index(
        "ix_pending_actions_user_id_status",
        table_name="pending_actions",
        if_exists=True,
    )
    op.drop_index(
        "ix_messages_conversation_id_created_at",
        table_name="messages",
        if_exists=True,
    )
    op.drop_index(
        "ix_audit_logs_user_id_timestamp", table_name="audit_logs", if_exists=True
    )
    op.drop_index(
        "ix_audit_logs_user_id_seq", table_name="audit_logs", if_exists=True
    )
