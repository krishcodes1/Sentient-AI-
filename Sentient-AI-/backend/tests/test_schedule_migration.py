"""Tests for migration 0017_scheduled_tasks: upgrading creates the two tables,
their indexes (the unique occurrence index among them) and the three origin /
time zone columns; the unique index refuses a second row for one occurrence;
downgrading to 0016 removes exactly what it added and upgrading again works.

Why it exists: test_migrations.py proves the head schema matches the models;
this pins the revision itself, including its downgrade, on a throwaway
SQLite file (Postgres runs the same through the CI job's TEST_DATABASE_URL).
"""

from __future__ import annotations

from pathlib import Path

import pytest
import sqlalchemy as sa
from alembic import command
from alembic.config import Config

BACKEND_DIR = Path(__file__).resolve().parents[1]


def _config(db_path: Path) -> Config:
    config = Config(str(BACKEND_DIR / "alembic.ini"))
    config.set_main_option("script_location", str(BACKEND_DIR / "alembic"))
    config.attributes["sqlalchemy_url"] = f"sqlite+aiosqlite:///{db_path}"
    config.attributes["configure_logger"] = False
    return config


def _inspect(db_path: Path):
    engine = sa.create_engine(f"sqlite:///{db_path}")
    try:
        inspector = sa.inspect(engine)
        tables = set(inspector.get_table_names())
        columns = {t: {c["name"] for c in inspector.get_columns(t)} for t in tables}
        indexes = {
            t: {i["name"]: bool(i.get("unique")) for i in inspector.get_indexes(t)} for t in tables
        }
    finally:
        engine.dispose()
    return tables, columns, indexes


def test_upgrade_adds_the_tables_indexes_and_columns_and_downgrade_removes_them(tmp_path):
    db_path = tmp_path / "sched.db"
    config = _config(db_path)
    command.upgrade(config, "0017_scheduled_tasks")
    tables, columns, indexes = _inspect(db_path)
    assert {"scheduled_tasks", "automation_runs"} <= tables
    assert indexes["scheduled_tasks"] == {
        "ix_scheduled_tasks_status_next_run_at": False,
        "ix_scheduled_tasks_user_id_label": True,
    }
    assert indexes["automation_runs"] == {
        "ix_automation_runs_task_id_scheduled_for": True,
        "ix_automation_runs_user_id_started_at": False,
    }
    assert "timezone" in columns["users"]
    assert "origin" in columns["conversations"] and "origin" in columns["pending_actions"]

    command.downgrade(config, "0016_merge_app_approvals")
    tables, columns, _indexes = _inspect(db_path)
    assert not {"scheduled_tasks", "automation_runs"} & tables
    assert "timezone" not in columns["users"]
    assert "origin" not in columns["conversations"] and "origin" not in columns["pending_actions"]

    command.upgrade(config, "head")
    tables, _columns, _indexes = _inspect(db_path)
    assert {"scheduled_tasks", "automation_runs"} <= tables


def test_the_occurrence_index_refuses_a_second_row(tmp_path):
    db_path = tmp_path / "unique.db"
    command.upgrade(_config(db_path), "head")
    engine = sa.create_engine(f"sqlite:///{db_path}")
    try:
        with engine.begin() as conn:
            conn.execute(
                sa.text(
                    "INSERT INTO users (id, email, hashed_password, is_active, created_at, updated_at) "
                    "VALUES ('u1', 'm@example.com', 'x', 1, '2026-01-01', '2026-01-01')"
                )
            )
            conn.execute(
                sa.text(
                    "INSERT INTO scheduled_tasks (id, user_id, kind, label, options, recurrence, timezone, "
                    "channels, status, next_run_at, consecutive_errors, source, created_at, updated_at) "
                    "VALUES ('t1', 'u1', 'prompt', 'x', '{}', '{}', 'UTC', '[]', 'active', "
                    "'2026-01-01', 0, 'agent', '2026-01-01', '2026-01-01')"
                )
            )
        insert = sa.text(
            "INSERT INTO automation_runs (id, user_id, origin, task_id, scheduled_for, trigger, status, "
            "started_at, input_tokens, output_tokens, cost_usd) VALUES (:id, 'u1', 'schedule:t1', 't1', "
            "'2026-01-02 08:00:00', 'schedule', 'running', '2026-01-02', 0, 0, 0)"
        )
        with engine.begin() as conn:
            conn.execute(insert, {"id": "r1"})
        with pytest.raises(sa.exc.IntegrityError):
            with engine.begin() as conn:
                conn.execute(insert, {"id": "r2"})
    finally:
        engine.dispose()


def test_the_revision_keeps_its_reserved_place():
    source = (BACKEND_DIR / "alembic" / "versions" / "0017_scheduled_tasks.py").read_text(encoding="utf-8")
    assert 'revision = "0017_scheduled_tasks"' in source
    assert 'down_revision = "0016_merge_app_approvals"' in source
    assert "sa.Enum(" not in source  # statuses are strings: no Postgres enum type
