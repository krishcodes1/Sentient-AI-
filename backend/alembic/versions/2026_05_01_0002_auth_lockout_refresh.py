"""auth lockout, refresh sessions, password reset, email verification

Revision ID: 2026_05_01_0002_auth
Revises: 0001_initial_baseline
Create Date: 2026-05-01 00:00:01.000000

P0 security hardening:
- Add lockout / verification / reset columns to ``users``
- Add ``auth_sessions`` table for server-side refresh-token rotation
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql


# revision identifiers, used by Alembic.
revision: str = "2026_05_01_0002_auth"
down_revision: Union[str, None] = "0001_initial_baseline"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # ── users: lockout + verification + reset columns ───────────────────────
    op.add_column(
        "users",
        sa.Column(
            "failed_login_count",
            sa.Integer(),
            nullable=False,
            server_default=sa.text("0"),
        ),
    )
    op.add_column(
        "users",
        sa.Column("lockout_until", sa.DateTime(timezone=True), nullable=True),
    )
    op.add_column(
        "users",
        sa.Column("email_verified_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.add_column(
        "users",
        sa.Column("password_reset_token_hash", sa.String(length=64), nullable=True),
    )
    op.add_column(
        "users",
        sa.Column(
            "password_reset_expires_at",
            sa.DateTime(timezone=True),
            nullable=True,
        ),
    )
    op.add_column(
        "users",
        sa.Column("verification_token_hash", sa.String(length=64), nullable=True),
    )
    op.add_column(
        "users",
        sa.Column(
            "verification_expires_at",
            sa.DateTime(timezone=True),
            nullable=True,
        ),
    )
    op.create_index(
        "ix_users_password_reset_token_hash",
        "users",
        ["password_reset_token_hash"],
    )
    op.create_index(
        "ix_users_verification_token_hash",
        "users",
        ["verification_token_hash"],
    )

    # ── auth_sessions ───────────────────────────────────────────────────────
    op.create_table(
        "auth_sessions",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column(
            "user_id",
            postgresql.UUID(as_uuid=True),
            nullable=False,
        ),
        sa.Column("refresh_token_hash", sa.String(length=64), nullable=False),
        sa.Column("user_agent", sa.String(length=255), nullable=True),
        sa.Column("ip_address", sa.String(length=45), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(
            ["user_id"],
            ["users.id"],
            ondelete="CASCADE",
            name=op.f("fk_auth_sessions_user_id_users"),
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_auth_sessions")),
        sa.UniqueConstraint(
            "refresh_token_hash",
            name=op.f("uq_auth_sessions_refresh_token_hash"),
        ),
    )
    op.create_index(
        "ix_auth_sessions_user_id",
        "auth_sessions",
        ["user_id"],
        unique=False,
    )
    op.create_index(
        "ix_auth_sessions_refresh_token_hash",
        "auth_sessions",
        ["refresh_token_hash"],
        unique=True,
    )


def downgrade() -> None:
    # Drop in reverse dependency order.
    op.drop_index(
        "ix_auth_sessions_refresh_token_hash",
        table_name="auth_sessions",
    )
    op.drop_index("ix_auth_sessions_user_id", table_name="auth_sessions")
    op.drop_table("auth_sessions")

    op.drop_index("ix_users_verification_token_hash", table_name="users")
    op.drop_index("ix_users_password_reset_token_hash", table_name="users")
    op.drop_column("users", "verification_expires_at")
    op.drop_column("users", "verification_token_hash")
    op.drop_column("users", "password_reset_expires_at")
    op.drop_column("users", "password_reset_token_hash")
    op.drop_column("users", "email_verified_at")
    op.drop_column("users", "lockout_until")
    op.drop_column("users", "failed_login_count")
