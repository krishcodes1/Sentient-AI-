"""initial baseline

Revision ID: 0001_initial_baseline
Revises:
Create Date: 2026-05-01 00:00:00.000000

Baseline migration that captures the entire current schema in one place,
replacing the previous ``Base.metadata.create_all()`` plus ad-hoc
``ALTER TABLE`` strings in ``core/database.py``.

For existing development databases, run ``alembic stamp head`` to mark this
revision as applied without re-running it. Fresh databases should run
``alembic upgrade head`` normally.

In addition to the existing tables, this revision adds:
- composite indexes flagged by the schema audit
- unique constraints that were previously only enforced in app code
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql


# revision identifiers, used by Alembic.
revision: str = "0001_initial_baseline"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # ── users ────────────────────────────────────────────────────────────────
    op.create_table(
        "users",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            primary_key=True,
            nullable=False,
        ),
        sa.Column("email", sa.String(length=320), nullable=False),
        sa.Column("name", sa.String(length=256), nullable=True),
        sa.Column("hashed_password", sa.String(length=128), nullable=False),
        sa.Column(
            "is_active",
            sa.Boolean(),
            nullable=False,
        ),
        sa.Column(
            "llm_provider",
            sa.String(length=32),
            server_default=sa.text("'openai'"),
            nullable=False,
        ),
        sa.Column(
            "llm_model",
            sa.String(length=128),
            server_default=sa.text("'gpt-4o'"),
            nullable=False,
        ),
        sa.Column("llm_api_key_enc", sa.LargeBinary(), nullable=True),
        sa.Column(
            "onboarding_completed",
            sa.Boolean(),
            server_default=sa.text("false"),
            nullable=False,
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            nullable=False,
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_users")),
        sa.UniqueConstraint("email", name=op.f("uq_users_email")),
    )
    op.create_index(op.f("ix_users_email"), "users", ["email"], unique=True)

    # ── conversations ───────────────────────────────────────────────────────
    op.create_table(
        "conversations",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            primary_key=True,
            nullable=False,
        ),
        sa.Column(
            "user_id",
            postgresql.UUID(as_uuid=True),
            nullable=False,
        ),
        sa.Column("title", sa.String(length=512), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ["user_id"],
            ["users.id"],
            ondelete="CASCADE",
            name=op.f("fk_conversations_user_id_users"),
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_conversations")),
    )
    op.create_index(
        op.f("ix_conversations_user_id"),
        "conversations",
        ["user_id"],
        unique=False,
    )
    # Composite index for "list a user's conversations newest-first".
    op.create_index(
        "ix_conversations_user_updated",
        "conversations",
        ["user_id", sa.text("updated_at DESC")],
        unique=False,
    )

    # ── messages ────────────────────────────────────────────────────────────
    message_role = postgresql.ENUM(
        "user",
        "assistant",
        "system",
        name="message_role",
        create_type=True,
    )
    message_role.create(op.get_bind(), checkfirst=True)

    op.create_table(
        "messages",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            primary_key=True,
            nullable=False,
        ),
        sa.Column(
            "conversation_id",
            postgresql.UUID(as_uuid=True),
            nullable=False,
        ),
        sa.Column(
            "role",
            postgresql.ENUM(
                "user",
                "assistant",
                "system",
                name="message_role",
                create_type=False,
            ),
            nullable=False,
        ),
        sa.Column("content", sa.Text(), nullable=False),
        sa.Column("tool_calls", postgresql.JSON(), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ["conversation_id"],
            ["conversations.id"],
            ondelete="CASCADE",
            name=op.f("fk_messages_conversation_id_conversations"),
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_messages")),
    )
    op.create_index(
        op.f("ix_messages_conversation_id"),
        "messages",
        ["conversation_id"],
        unique=False,
    )
    # Composite index for paged "messages in a conversation in order".
    op.create_index(
        "ix_messages_conversation_created",
        "messages",
        ["conversation_id", "created_at"],
        unique=False,
    )

    # ── audit_logs ──────────────────────────────────────────────────────────
    audit_status = postgresql.ENUM(
        "approved",
        "blocked",
        "pending",
        name="audit_status",
        create_type=True,
    )
    audit_status.create(op.get_bind(), checkfirst=True)

    op.create_table(
        "audit_logs",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            primary_key=True,
            nullable=False,
        ),
        sa.Column(
            "user_id",
            postgresql.UUID(as_uuid=True),
            nullable=False,
        ),
        sa.Column(
            "timestamp",
            sa.DateTime(timezone=True),
            nullable=False,
        ),
        sa.Column("connector_name", sa.String(length=255), nullable=False),
        sa.Column("action", sa.String(length=255), nullable=False),
        sa.Column("endpoint", sa.String(length=2048), nullable=False),
        sa.Column("scope_used", sa.String(length=512), nullable=False),
        sa.Column(
            "status",
            postgresql.ENUM(
                "approved",
                "blocked",
                "pending",
                name="audit_status",
                create_type=False,
            ),
            nullable=False,
        ),
        sa.Column("reasoning_chain", postgresql.JSON(), nullable=True),
        sa.Column("detection_method", sa.String(length=255), nullable=True),
        sa.Column("confidence_score", sa.Float(), nullable=True),
        sa.Column("request_data", postgresql.JSON(), nullable=True),
        sa.Column("response_summary", sa.Text(), nullable=True),
        sa.Column("integrity_hash", sa.String(length=64), nullable=False),
        sa.Column("request_id", sa.String(length=36), nullable=False),
        sa.ForeignKeyConstraint(
            ["user_id"],
            ["users.id"],
            ondelete="CASCADE",
            name=op.f("fk_audit_logs_user_id_users"),
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_audit_logs")),
    )
    op.create_index(
        op.f("ix_audit_logs_user_id"),
        "audit_logs",
        ["user_id"],
        unique=False,
    )
    op.create_index(
        op.f("ix_audit_logs_timestamp"),
        "audit_logs",
        ["timestamp"],
        unique=False,
    )
    op.create_index(
        op.f("ix_audit_logs_request_id"),
        "audit_logs",
        ["request_id"],
        unique=False,
    )
    # Composite index for "fetch a user's audit trail newest-first".
    op.create_index(
        "ix_audit_logs_user_timestamp",
        "audit_logs",
        ["user_id", sa.text("timestamp DESC")],
        unique=False,
    )

    # ── channels ────────────────────────────────────────────────────────────
    channel_type = postgresql.ENUM(
        "telegram",
        "discord",
        "slack",
        "whatsapp",
        "signal",
        "webchat",
        name="channel_type",
        create_type=True,
    )
    channel_type.create(op.get_bind(), checkfirst=True)

    op.create_table(
        "channels",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            primary_key=True,
            nullable=False,
        ),
        sa.Column(
            "user_id",
            postgresql.UUID(as_uuid=True),
            nullable=False,
        ),
        sa.Column(
            "channel_type",
            postgresql.ENUM(
                "telegram",
                "discord",
                "slack",
                "whatsapp",
                "signal",
                "webchat",
                name="channel_type",
                create_type=False,
            ),
            nullable=False,
        ),
        sa.Column("display_name", sa.String(length=255), nullable=False),
        sa.Column("is_enabled", sa.Boolean(), nullable=False),
        sa.Column("config_enc", sa.LargeBinary(), nullable=True),
        sa.Column("config_meta", postgresql.JSON(), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ["user_id"],
            ["users.id"],
            ondelete="CASCADE",
            name=op.f("fk_channels_user_id_users"),
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_channels")),
        sa.UniqueConstraint(
            "user_id",
            "channel_type",
            name="uq_channels_user_type",
        ),
    )
    op.create_index(
        op.f("ix_channels_user_id"),
        "channels",
        ["user_id"],
        unique=False,
    )

    # ── connector_configs ───────────────────────────────────────────────────
    connector_type = postgresql.ENUM(
        "canvas",
        "google_workspace",
        "robinhood",
        "custom",
        name="connector_type",
        create_type=True,
    )
    connector_type.create(op.get_bind(), checkfirst=True)

    auth_method = postgresql.ENUM(
        "oauth2",
        "api_key",
        "bearer_token",
        name="auth_method",
        create_type=True,
    )
    auth_method.create(op.get_bind(), checkfirst=True)

    permission_tier = postgresql.ENUM(
        "auto_approve",
        "user_confirm",
        "admin_only",
        "hard_blocked",
        name="permission_tier",
        create_type=True,
    )
    permission_tier.create(op.get_bind(), checkfirst=True)

    op.create_table(
        "connector_configs",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            primary_key=True,
            nullable=False,
        ),
        sa.Column(
            "user_id",
            postgresql.UUID(as_uuid=True),
            nullable=False,
        ),
        sa.Column(
            "connector_type",
            postgresql.ENUM(
                "canvas",
                "google_workspace",
                "robinhood",
                "custom",
                name="connector_type",
                create_type=False,
            ),
            nullable=False,
        ),
        sa.Column("display_name", sa.String(length=255), nullable=False),
        sa.Column("is_active", sa.Boolean(), nullable=False),
        sa.Column(
            "auth_method",
            postgresql.ENUM(
                "oauth2",
                "api_key",
                "bearer_token",
                name="auth_method",
                create_type=False,
            ),
            nullable=False,
        ),
        sa.Column("encrypted_credentials", sa.LargeBinary(), nullable=False),
        sa.Column("granted_scopes", postgresql.JSON(), nullable=False),
        sa.Column(
            "permission_tier",
            postgresql.ENUM(
                "auto_approve",
                "user_confirm",
                "admin_only",
                "hard_blocked",
                name="permission_tier",
                create_type=False,
            ),
            nullable=False,
        ),
        sa.Column("rate_limit_per_minute", sa.Integer(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ["user_id"],
            ["users.id"],
            ondelete="CASCADE",
            name=op.f("fk_connector_configs_user_id_users"),
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_connector_configs")),
        sa.UniqueConstraint(
            "user_id",
            "connector_type",
            name="uq_connectors_user_type",
        ),
    )
    op.create_index(
        op.f("ix_connector_configs_user_id"),
        "connector_configs",
        ["user_id"],
        unique=False,
    )


def downgrade() -> None:
    # Drop in reverse dependency order.
    op.drop_index(
        op.f("ix_connector_configs_user_id"),
        table_name="connector_configs",
    )
    op.drop_table("connector_configs")

    op.drop_index(op.f("ix_channels_user_id"), table_name="channels")
    op.drop_table("channels")

    op.drop_index("ix_audit_logs_user_timestamp", table_name="audit_logs")
    op.drop_index(op.f("ix_audit_logs_request_id"), table_name="audit_logs")
    op.drop_index(op.f("ix_audit_logs_timestamp"), table_name="audit_logs")
    op.drop_index(op.f("ix_audit_logs_user_id"), table_name="audit_logs")
    op.drop_table("audit_logs")

    op.drop_index("ix_messages_conversation_created", table_name="messages")
    op.drop_index(op.f("ix_messages_conversation_id"), table_name="messages")
    op.drop_table("messages")

    op.drop_index("ix_conversations_user_updated", table_name="conversations")
    op.drop_index(op.f("ix_conversations_user_id"), table_name="conversations")
    op.drop_table("conversations")

    op.drop_index(op.f("ix_users_email"), table_name="users")
    op.drop_table("users")

    # Drop enum types last — nothing references them now.
    bind = op.get_bind()
    for enum_name in (
        "permission_tier",
        "auth_method",
        "connector_type",
        "channel_type",
        "audit_status",
        "message_role",
    ):
        postgresql.ENUM(name=enum_name).drop(bind, checkfirst=True)
