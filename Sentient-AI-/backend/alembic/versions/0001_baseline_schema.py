"""Baseline schema.

Revision ID: 0001_baseline
Revises:
Create Date: 2026-08-04

===========================================================================
OPERATORS — READ THIS BEFORE UPGRADING AN EXISTING DEPLOYMENT
===========================================================================

This revision creates the schema that Crawler AI already runs today: it is
exactly what ``Base.metadata.create_all()`` plus every idempotent ALTER in
the old ``core.database.init_db`` migration list produced. It is a starting
point for migration history, not a change.

* Empty / brand-new database (no tables yet)::

      alembic upgrade head

* Existing database that already has this schema (any deployment that has
  booted the app before this revision landed) — DO NOT run ``upgrade``.
  Running it would fail on the first ``CREATE TABLE users``, and on
  Postgres that aborts the transaction, leaving the alembic_version table
  unwritten. Record the baseline as already applied instead::

      alembic stamp 0001_baseline

  That writes ``0001_baseline`` into ``alembic_version`` and touches
  nothing else. From then on ``alembic upgrade head`` applies only the
  revisions that come after it.

  Before stamping, confirm the live schema really matches this revision —
  in particular that ``init_db`` ran to completion at least once, since its
  ALTERs swallowed their own failures::

      \\d audit_logs   -- expect previous_hash, seq, and index ix_audit_logs_seq
      \\d users        -- expect name, default_permission_tier, rate_limit,
                       --        llm_provider, llm_model, memory_enabled, token_epoch
      \\d memories     -- expect source, source_conversation_id
      \\d pending_actions  -- expect risk_note
      SELECT unnest(enum_range(NULL::connector_type));  -- expect 'mcp' present

  Anything missing must be added by hand (the statements are in this
  file's ``upgrade()``) BEFORE stamping — stamping asserts the schema is
  already correct, it does not check.

Known drift on long-lived deployments: ``memories.source`` is created here
as the ``memory_source`` enum, but an old database that gained the column
via ``init_db``'s ``ADD COLUMN ... VARCHAR(16)`` will hold a varchar. Both
store the same values and the app is indifferent; a follow-up revision can
convert it with ``ALTER TABLE memories ALTER COLUMN source TYPE
memory_source USING source::memory_source``.

===========================================================================
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0001_baseline"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


# Named enum types, declared once so upgrade() and downgrade() cannot drift.
# On Postgres these become real ENUM types (created with the first table
# that uses them); on SQLite SQLAlchemy renders them as VARCHAR + CHECK,
# which is what lets this revision run in CI without a Postgres service.
AUDIT_STATUS = sa.Enum("approved", "blocked", "pending", name="audit_status")
CONNECTOR_TYPE = sa.Enum(
    "canvas",
    "google_workspace",
    "robinhood",
    # Added to live databases by init_db's ALTER TYPE ... ADD VALUE, which
    # appended it last. A fresh create_all() puts it here, in declaration
    # order. Only the sort order of the type differs; nothing reads it.
    "mcp",
    "custom",
    name="connector_type",
)
AUTH_METHOD = sa.Enum("oauth2", "api_key", "bearer_token", name="auth_method")
PERMISSION_TIER = sa.Enum(
    "auto_approve",
    "user_confirm",
    "admin_only",
    "hard_blocked",
    name="permission_tier",
)
MESSAGE_ROLE = sa.Enum("user", "assistant", "system", name="message_role")
MEMORY_CATEGORY = sa.Enum(
    "profile", "preference", "project", "fact", name="memory_category"
)
MEMORY_SOURCE = sa.Enum("user", "agent", name="memory_source")
PENDING_ACTION_STATUS = sa.Enum(
    "pending", "approved", "denied", "expired", name="pending_action_status"
)

_ENUMS = (
    AUDIT_STATUS,
    CONNECTOR_TYPE,
    AUTH_METHOD,
    PERMISSION_TIER,
    MESSAGE_ROLE,
    MEMORY_CATEGORY,
    MEMORY_SOURCE,
    PENDING_ACTION_STATUS,
)


def upgrade() -> None:
    op.create_table(
        "users",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("email", sa.String(length=320), nullable=False),
        sa.Column("name", sa.String(length=255), nullable=True),
        sa.Column("hashed_password", sa.String(length=128), nullable=False),
        sa.Column("is_active", sa.Boolean(), nullable=False),
        # server_default on the columns that were retrofitted by init_db:
        # rows written by an older app binary (or by hand) must backfill to
        # the same value the ADD COLUMN ... DEFAULT gave them.
        sa.Column(
            "token_epoch", sa.Integer(), server_default="0", nullable=False
        ),
        sa.Column(
            "default_permission_tier",
            sa.String(length=32),
            server_default="user_confirm",
            nullable=False,
        ),
        sa.Column("rate_limit", sa.Integer(), server_default="60", nullable=False),
        sa.Column(
            "llm_provider",
            sa.String(length=32),
            server_default="anthropic",
            nullable=False,
        ),
        sa.Column(
            "llm_model",
            sa.String(length=128),
            server_default="claude-sonnet-4-20250514",
            nullable=False,
        ),
        sa.Column(
            "memory_enabled", sa.Boolean(), server_default="true", nullable=False
        ),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    # Unique + indexed on the model, which SQLAlchemy expresses as a single
    # unique index (not a separate UNIQUE constraint).
    op.create_index("ix_users_email", "users", ["email"], unique=True)

    op.create_table(
        "audit_logs",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("user_id", sa.Uuid(), nullable=False),
        sa.Column("timestamp", sa.DateTime(timezone=True), nullable=False),
        # Per-user hash-chain order key. Nullable: rows written before the
        # column existed carry no seq and the verifier orders them first.
        sa.Column("seq", sa.BigInteger(), nullable=True),
        sa.Column("connector_name", sa.String(length=255), nullable=False),
        sa.Column("action", sa.String(length=255), nullable=False),
        sa.Column("endpoint", sa.String(length=2048), nullable=False),
        sa.Column("scope_used", sa.String(length=512), nullable=False),
        sa.Column("status", AUDIT_STATUS, nullable=False),
        sa.Column("reasoning_chain", sa.JSON(), nullable=True),
        sa.Column("detection_method", sa.String(length=255), nullable=True),
        sa.Column("confidence_score", sa.Float(), nullable=True),
        sa.Column("request_data", sa.JSON(), nullable=True),
        sa.Column("response_summary", sa.Text(), nullable=True),
        sa.Column("integrity_hash", sa.String(length=64), nullable=False),
        sa.Column("previous_hash", sa.String(length=64), nullable=True),
        sa.Column("request_id", sa.String(length=36), nullable=False),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_audit_logs_user_id", "audit_logs", ["user_id"])
    op.create_index("ix_audit_logs_timestamp", "audit_logs", ["timestamp"])
    op.create_index("ix_audit_logs_request_id", "audit_logs", ["request_id"])
    # Every audit append looks up the chain head by seq; without this index
    # that is a full scan of the user's history.
    op.create_index("ix_audit_logs_seq", "audit_logs", ["seq"])

    op.create_table(
        "connector_configs",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("user_id", sa.Uuid(), nullable=False),
        sa.Column("connector_type", CONNECTOR_TYPE, nullable=False),
        sa.Column("display_name", sa.String(length=255), nullable=False),
        sa.Column("is_active", sa.Boolean(), nullable=False),
        sa.Column("auth_method", AUTH_METHOD, nullable=False),
        sa.Column("encrypted_credentials", sa.LargeBinary(), nullable=False),
        sa.Column("granted_scopes", sa.JSON(), nullable=False),
        sa.Column("permission_tier", PERMISSION_TIER, nullable=False),
        sa.Column("rate_limit_per_minute", sa.Integer(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_connector_configs_user_id", "connector_configs", ["user_id"])

    op.create_table(
        "conversations",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("user_id", sa.Uuid(), nullable=False),
        sa.Column("title", sa.String(length=512), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_conversations_user_id", "conversations", ["user_id"])

    op.create_table(
        "memories",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("user_id", sa.Uuid(), nullable=False),
        sa.Column("content", sa.Text(), nullable=False),
        sa.Column("category", MEMORY_CATEGORY, nullable=False),
        sa.Column("source", MEMORY_SOURCE, nullable=False),
        # Provenance only — deliberately not a foreign key, so deleting a
        # conversation never cascades away the memory it produced.
        sa.Column("source_conversation_id", sa.Uuid(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_memories_user_id", "memories", ["user_id"])

    op.create_table(
        "messages",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("conversation_id", sa.Uuid(), nullable=False),
        sa.Column("role", MESSAGE_ROLE, nullable=False),
        sa.Column("content", sa.Text(), nullable=False),
        sa.Column("tool_calls", sa.JSON(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["conversation_id"], ["conversations.id"], ondelete="CASCADE"
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_messages_conversation_id", "messages", ["conversation_id"])

    op.create_table(
        "pending_actions",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("user_id", sa.Uuid(), nullable=False),
        sa.Column("conversation_id", sa.Uuid(), nullable=True),
        sa.Column("tool_name", sa.String(length=255), nullable=False),
        sa.Column("arguments", sa.JSON(), nullable=False),
        sa.Column("reason", sa.Text(), nullable=False),
        # Why this approval deserves a careful look (taint-gate warning).
        sa.Column("risk_note", sa.Text(), nullable=True),
        sa.Column("status", PENDING_ACTION_STATUS, nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("decided_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(
            ["conversation_id"], ["conversations.id"], ondelete="CASCADE"
        ),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_pending_actions_user_id", "pending_actions", ["user_id"])
    op.create_index("ix_pending_actions_status", "pending_actions", ["status"])


def downgrade() -> None:
    # Reverse dependency order: children before the tables they reference.
    op.drop_table("pending_actions")
    op.drop_table("messages")
    op.drop_table("memories")
    op.drop_table("conversations")
    op.drop_table("connector_configs")
    op.drop_table("audit_logs")
    op.drop_table("users")

    # DROP TABLE leaves Postgres ENUM types behind, so a later re-upgrade
    # would fail on "type already exists". No-op on backends without native
    # enums (SQLite), where the types never existed as separate objects.
    bind = op.get_bind()
    for enum in _ENUMS:
        enum.drop(bind, checkfirst=True)
