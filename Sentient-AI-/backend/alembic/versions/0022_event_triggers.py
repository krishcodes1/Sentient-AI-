"""Adds the event-trigger tables: ``event_triggers`` (owner-approved rules "when
X happens in a connected app, tell me, or run this task", each pinned to one
connector row) and ``trigger_events`` (the new items each check found, queued
until they are sent or run).

Why it exists: event_triggers (top10 wave 2) polls connected apps with a
model-free sweeper; the unique (trigger_id, external_key) index is the guard
that one item never fires twice across workers and restarts, and the unique
(user_id, fingerprint) index refuses the same rule twice. A trigger dies with
its user and with its connector row (ON DELETE CASCADE); its conversation is
kept (SET NULL).

Guarded like 0011 and 0017 (inspector checks and ``if_not_exists``): an
adopted pre-Alembic database is built from the model metadata, which already
has these, before it is stamped and upgraded. Statuses, sources and modes are
plain strings, so no Postgres enum type is created.

This is the revision reserved for event_triggers: its id and down_revision
were fixed by the integration seams and never change.

Revision ID: 0022_event_triggers
Revises: 0021_study
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0022_event_triggers"
down_revision = "0021_study"
branch_labels = None
depends_on = None


def _has_table(name: str) -> bool:
    return name in sa.inspect(op.get_bind()).get_table_names()


def upgrade() -> None:
    if not _has_table("event_triggers"):
        op.create_table(
            "event_triggers",
            sa.Column("id", sa.Uuid(), primary_key=True, nullable=False),
            sa.Column(
                "user_id",
                sa.Uuid(),
                sa.ForeignKey("users.id", ondelete="CASCADE"),
                nullable=False,
            ),
            sa.Column("label", sa.String(80), nullable=False),
            sa.Column("source", sa.String(40), nullable=False),
            sa.Column(
                "connector_id",
                sa.Uuid(),
                sa.ForeignKey("connector_configs.id", ondelete="CASCADE"),
                nullable=True,
            ),
            sa.Column("filters", sa.JSON(), nullable=False),
            sa.Column("fingerprint", sa.String(64), nullable=False),
            sa.Column("mode", sa.String(16), server_default="notify", nullable=False),
            sa.Column("prompt", sa.Text(), nullable=True),
            sa.Column("allow_writes", sa.Boolean(), server_default=sa.false(), nullable=False),
            sa.Column("interval_minutes", sa.Integer(), nullable=False),
            sa.Column("max_runs_per_day", sa.Integer(), server_default="6", nullable=False),
            sa.Column("runs_day", sa.Date(), nullable=True),
            sa.Column("runs_today", sa.Integer(), server_default="0", nullable=False),
            sa.Column("status", sa.String(12), server_default="active", nullable=False),
            sa.Column("cursor", sa.JSON(), nullable=True),
            sa.Column("baseline_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("next_check_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("last_checked_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("last_fired_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("consecutive_errors", sa.Integer(), server_default="0", nullable=False),
            sa.Column("last_error", sa.String(200), nullable=True),
            sa.Column(
                "conversation_id",
                sa.Uuid(),
                sa.ForeignKey("conversations.id", ondelete="SET NULL"),
                nullable=True,
            ),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        )
    op.create_index(
        "ix_event_triggers_status_next_check_at",
        "event_triggers",
        ["status", "next_check_at"],
        if_not_exists=True,
    )
    op.create_index(
        "ix_event_triggers_user_id_created_at",
        "event_triggers",
        ["user_id", "created_at"],
        if_not_exists=True,
    )
    op.create_index(
        "ix_event_triggers_user_id_fingerprint",
        "event_triggers",
        ["user_id", "fingerprint"],
        unique=True,
        if_not_exists=True,
    )

    if not _has_table("trigger_events"):
        op.create_table(
            "trigger_events",
            sa.Column("id", sa.Uuid(), primary_key=True, nullable=False),
            sa.Column(
                "trigger_id",
                sa.Uuid(),
                sa.ForeignKey("event_triggers.id", ondelete="CASCADE"),
                nullable=False,
            ),
            sa.Column(
                "user_id",
                sa.Uuid(),
                sa.ForeignKey("users.id", ondelete="CASCADE"),
                nullable=False,
            ),
            sa.Column("external_key", sa.String(64), nullable=False),
            sa.Column("status", sa.String(16), server_default="pending", nullable=False),
            sa.Column("facts", sa.JSON(), nullable=True),
            sa.Column("batch_id", sa.Uuid(), nullable=True),
            sa.Column("claimed_until", sa.DateTime(timezone=True), nullable=True),
            sa.Column("detected_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("handled_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("note", sa.String(200), nullable=True),
        )
    op.create_index(
        "ix_trigger_events_trigger_id_external_key",
        "trigger_events",
        ["trigger_id", "external_key"],
        unique=True,
        if_not_exists=True,
    )
    op.create_index(
        "ix_trigger_events_status_detected_at",
        "trigger_events",
        ["status", "detected_at"],
        if_not_exists=True,
    )
    op.create_index(
        "ix_trigger_events_user_id_detected_at",
        "trigger_events",
        ["user_id", "detected_at"],
        if_not_exists=True,
    )


def downgrade() -> None:
    op.drop_index(
        "ix_trigger_events_user_id_detected_at", table_name="trigger_events", if_exists=True
    )
    op.drop_index(
        "ix_trigger_events_status_detected_at", table_name="trigger_events", if_exists=True
    )
    op.drop_index(
        "ix_trigger_events_trigger_id_external_key", table_name="trigger_events", if_exists=True
    )
    if _has_table("trigger_events"):
        op.drop_table("trigger_events")
    op.drop_index(
        "ix_event_triggers_user_id_fingerprint", table_name="event_triggers", if_exists=True
    )
    op.drop_index(
        "ix_event_triggers_user_id_created_at", table_name="event_triggers", if_exists=True
    )
    op.drop_index(
        "ix_event_triggers_status_next_check_at", table_name="event_triggers", if_exists=True
    )
    if _has_table("event_triggers"):
        op.drop_table("event_triggers")
