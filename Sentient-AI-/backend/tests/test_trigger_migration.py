"""Tests for migration 0022_event_triggers: upgrading creates the two tables and
their indexes (the dedupe and duplicate-rule indexes unique), the dedupe index
refuses a second event with the same key, deleting a connector row takes its
triggers and their events with it, deleting a user takes everything, the
conversation is only unlinked, downgrading to 0021 removes exactly what it
added, and an adopted database built from the models (create_all, stamp,
upgrade) is left as it is.

Why it exists: test_migrations.py proves the head schema matches the models;
this pins the revision itself on a throwaway SQLite file (Postgres runs the
same through the CI job's TEST_DATABASE_URL).
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
        indexes = {t: {i["name"]: bool(i.get("unique")) for i in inspector.get_indexes(t)} for t in tables}
        fks = {
            t: {(fk["referred_table"], (fk.get("options") or {}).get("ondelete")) for fk in inspector.get_foreign_keys(t)}
            for t in tables
        }
    finally:
        engine.dispose()
    return tables, indexes, fks


def test_upgrade_adds_the_tables_and_downgrade_removes_them(tmp_path):
    db_path = tmp_path / "triggers.db"
    config = _config(db_path)
    command.upgrade(config, "0022_event_triggers")
    tables, indexes, fks = _inspect(db_path)
    assert {"event_triggers", "trigger_events"} <= tables
    assert indexes["event_triggers"] == {
        "ix_event_triggers_status_next_check_at": False,
        "ix_event_triggers_user_id_created_at": False,
        "ix_event_triggers_user_id_fingerprint": True,
    }
    assert indexes["trigger_events"] == {
        "ix_trigger_events_trigger_id_external_key": True,
        "ix_trigger_events_status_detected_at": False,
        "ix_trigger_events_user_id_detected_at": False,
    }
    assert fks["event_triggers"] == {
        ("users", "CASCADE"),
        ("connector_configs", "CASCADE"),
        ("conversations", "SET NULL"),
    }
    assert fks["trigger_events"] == {("event_triggers", "CASCADE"), ("users", "CASCADE")}
    command.downgrade(config, "0021_study")
    tables, _indexes, _fks = _inspect(db_path)
    assert not {"event_triggers", "trigger_events"} & tables
    command.upgrade(config, "head")
    tables, _indexes, _fks = _inspect(db_path)
    assert {"event_triggers", "trigger_events"} <= tables


def _seed(engine) -> None:
    with engine.begin() as conn:
        conn.execute(sa.text("PRAGMA foreign_keys=ON"))
        conn.execute(
            sa.text(
                "INSERT INTO users (id, email, hashed_password, is_active, created_at, updated_at) "
                "VALUES ('u1', 'm@example.com', 'x', 1, '2026-01-01', '2026-01-01')"
            )
        )
        conn.execute(
            sa.text(
                "INSERT INTO connector_configs (id, user_id, connector_type, display_name, is_active, auth_method, "
                "encrypted_credentials, granted_scopes, permission_tier, rate_limit_per_minute, created_at, updated_at) "
                "VALUES ('c1', 'u1', 'google_workspace', 'School', 1, 'bearer_token', x'00', '[]', 'user_confirm', 30, "
                "'2026-01-01', '2026-01-01')"
            )
        )
        conn.execute(
            sa.text(
                "INSERT INTO event_triggers (id, user_id, label, source, connector_id, filters, fingerprint, mode, "
                "allow_writes, interval_minutes, max_runs_per_day, runs_today, status, next_check_at, "
                "consecutive_errors, created_at, updated_at) VALUES ('t1', 'u1', 'Prof', 'email.new', 'c1', '{}', "
                "'f1', 'notify', 0, 15, 6, 0, 'active', '2026-01-01', 0, '2026-01-01', '2026-01-01')"
            )
        )


_EVENT = sa.text(
    "INSERT INTO trigger_events (id, trigger_id, user_id, external_key, status, detected_at) "
    "VALUES (:id, 't1', 'u1', :key, 'pending', '2026-01-02')"
)


def test_the_dedupe_index_refuses_a_second_event_and_a_connector_delete_cascades(tmp_path):
    db_path = tmp_path / "unique.db"
    command.upgrade(_config(db_path), "head")
    engine = sa.create_engine(f"sqlite:///{db_path}")
    try:
        _seed(engine)
        with engine.begin() as conn:
            conn.execute(_EVENT, {"id": "e1", "key": "k" * 64})
        with pytest.raises(sa.exc.IntegrityError):
            with engine.begin() as conn:
                conn.execute(_EVENT, {"id": "e2", "key": "k" * 64})
        with pytest.raises(sa.exc.IntegrityError):
            with engine.begin() as conn:
                conn.execute(
                    sa.text(
                        "INSERT INTO event_triggers (id, user_id, label, source, filters, fingerprint, mode, "
                        "allow_writes, interval_minutes, max_runs_per_day, runs_today, status, next_check_at, "
                        "consecutive_errors, created_at, updated_at) VALUES ('t2', 'u1', 'Again', 'email.new', "
                        "'{}', 'f1', 'notify', 0, 15, 6, 0, 'active', '2026-01-01', 0, '2026-01-01', '2026-01-01')"
                    )
                )
        with engine.begin() as conn:
            conn.execute(sa.text("PRAGMA foreign_keys=ON"))
            conn.execute(sa.text("DELETE FROM connector_configs WHERE id = 'c1'"))
        with engine.begin() as conn:
            assert conn.execute(sa.text("SELECT count(*) FROM event_triggers")).scalar_one() == 0
            assert conn.execute(sa.text("SELECT count(*) FROM trigger_events")).scalar_one() == 0
    finally:
        engine.dispose()


def test_an_adopted_database_keeps_its_tables(tmp_path):
    import models  # noqa: F401 - registers every model
    from core.database import Base

    db_path = tmp_path / "adopted.db"
    engine = sa.create_engine(f"sqlite:///{db_path}")
    try:
        Base.metadata.create_all(engine)
    finally:
        engine.dispose()
    config = _config(db_path)
    command.stamp(config, "0021_study")
    command.upgrade(config, "head")
    tables, indexes, _fks = _inspect(db_path)
    assert {"event_triggers", "trigger_events"} <= tables
    assert indexes["trigger_events"]["ix_trigger_events_trigger_id_external_key"] is True


def test_the_revision_keeps_its_reserved_place():
    source = (BACKEND_DIR / "alembic" / "versions" / "0022_event_triggers.py").read_text(encoding="utf-8")
    assert 'revision = "0022_event_triggers"' in source
    assert 'down_revision = "0021_study"' in source
    assert "sa.Enum(" not in source  # statuses are strings: no Postgres enum type
