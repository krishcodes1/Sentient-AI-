"""Adds the scheduler's tables and columns: ``scheduled_tasks`` (prompts the
owner approved to run on a recurrence, the daily briefing, feature nudges),
``automation_runs`` (one row per unattended run or skipped occurrence), and
the nullable columns ``users.timezone``, ``conversations.origin`` and
``pending_actions.origin``.

Why it exists: scheduler_briefing (top10 wave 1) sweeps due tasks and records
every occurrence; the unique (task_id, scheduled_for) index on
automation_runs is what keeps two workers, or a restart, from running one
occurrence twice. The origin columns tie a conversation and an approval card
to the unattended job that made them, so approving such a card runs that one
call and never resumes a model turn.

Guarded like 0011 (inspector checks and ``if_not_exists``): an adopted
pre-Alembic database is built from the model metadata, which already has
these, before it is stamped and upgraded. Statuses and kinds are plain
strings, so no Postgres enum type is created. The columns are added and
dropped through ``batch_alter_table`` with a ``_has_column`` guard.

This is the revision reserved for scheduler_briefing: its id and
down_revision were fixed by the integration seams and never change.

Revision ID: 0017_scheduled_tasks
Revises: 0016_merge_app_approvals
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0017_scheduled_tasks"
down_revision = "0016_merge_app_approvals"
branch_labels = None
depends_on = None

# (table, column) pairs this revision adds to existing tables.
_COLUMNS = (
    ("users", "timezone"),
    ("conversations", "origin"),
    ("pending_actions", "origin"),
)


def _has_table(name: str) -> bool:
    return name in sa.inspect(op.get_bind()).get_table_names()


def _has_column(table: str, column: str) -> bool:
    return column in {c["name"] for c in sa.inspect(op.get_bind()).get_columns(table)}


def upgrade() -> None:
    if not _has_table("scheduled_tasks"):
        op.create_table(
            "scheduled_tasks",
            sa.Column("id", sa.Uuid(), primary_key=True, nullable=False),
            sa.Column(
                "user_id",
                sa.Uuid(),
                sa.ForeignKey("users.id", ondelete="CASCADE"),
                nullable=False,
            ),
            sa.Column("kind", sa.String(16), nullable=False),
            sa.Column("label", sa.String(80), nullable=False),
            sa.Column("prompt", sa.Text(), nullable=True),
            sa.Column("options", sa.JSON(), nullable=False),
            sa.Column("recurrence", sa.JSON(), nullable=False),
            sa.Column("timezone", sa.String(64), nullable=False),
            sa.Column("channels", sa.JSON(), nullable=False),
            sa.Column("status", sa.String(12), server_default="active", nullable=False),
            sa.Column("next_run_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("last_run_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("last_status", sa.String(24), nullable=True),
            sa.Column("last_error", sa.String(200), nullable=True),
            sa.Column("consecutive_errors", sa.Integer(), server_default="0", nullable=False),
            sa.Column(
                "conversation_id",
                sa.Uuid(),
                sa.ForeignKey("conversations.id", ondelete="SET NULL"),
                nullable=True,
            ),
            sa.Column("source", sa.String(8), nullable=False),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        )
    op.create_index(
        "ix_scheduled_tasks_status_next_run_at",
        "scheduled_tasks",
        ["status", "next_run_at"],
        if_not_exists=True,
    )
    op.create_index(
        "ix_scheduled_tasks_user_id_label",
        "scheduled_tasks",
        ["user_id", "label"],
        unique=True,
        if_not_exists=True,
    )

    if not _has_table("automation_runs"):
        op.create_table(
            "automation_runs",
            sa.Column("id", sa.Uuid(), primary_key=True, nullable=False),
            sa.Column(
                "user_id",
                sa.Uuid(),
                sa.ForeignKey("users.id", ondelete="CASCADE"),
                nullable=False,
            ),
            sa.Column("origin", sa.String(64), nullable=False),
            sa.Column(
                "task_id",
                sa.Uuid(),
                sa.ForeignKey("scheduled_tasks.id", ondelete="CASCADE"),
                nullable=True,
            ),
            sa.Column("scheduled_for", sa.DateTime(timezone=True), nullable=True),
            sa.Column("trigger", sa.String(8), nullable=False),
            sa.Column("status", sa.String(24), nullable=False),
            sa.Column("started_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("input_tokens", sa.Integer(), nullable=False),
            sa.Column("output_tokens", sa.Integer(), nullable=False),
            sa.Column("cost_usd", sa.Float(), nullable=False),
            sa.Column("delivered", sa.JSON(), nullable=True),
            sa.Column("error", sa.String(200), nullable=True),
            sa.Column(
                "message_id",
                sa.Uuid(),
                sa.ForeignKey("messages.id", ondelete="SET NULL"),
                nullable=True,
            ),
        )
    op.create_index(
        "ix_automation_runs_task_id_scheduled_for",
        "automation_runs",
        ["task_id", "scheduled_for"],
        unique=True,
        if_not_exists=True,
    )
    op.create_index(
        "ix_automation_runs_user_id_started_at",
        "automation_runs",
        ["user_id", "started_at"],
        if_not_exists=True,
    )

    for table, column in _COLUMNS:
        if not _has_column(table, column):
            with op.batch_alter_table(table) as batch:
                batch.add_column(sa.Column(column, sa.String(64), nullable=True))


def downgrade() -> None:
    for table, column in reversed(_COLUMNS):
        if _has_column(table, column):
            with op.batch_alter_table(table) as batch:
                batch.drop_column(column)

    op.drop_index(
        "ix_automation_runs_user_id_started_at", table_name="automation_runs", if_exists=True
    )
    op.drop_index(
        "ix_automation_runs_task_id_scheduled_for", table_name="automation_runs", if_exists=True
    )
    if _has_table("automation_runs"):
        op.drop_table("automation_runs")
    op.drop_index(
        "ix_scheduled_tasks_user_id_label", table_name="scheduled_tasks", if_exists=True
    )
    op.drop_index(
        "ix_scheduled_tasks_status_next_run_at", table_name="scheduled_tasks", if_exists=True
    )
    if _has_table("scheduled_tasks"):
        op.drop_table("scheduled_tasks")
