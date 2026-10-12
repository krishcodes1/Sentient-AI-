"""Tests for migration 0025_skill_states: upgrading creates the table keyed by
the skill's name with its owner foreign key set to NULL on delete, deleting
that owner keeps the switch, downgrading to 0024 removes exactly what it
added, an adopted database built from the models (create_all, stamp,
upgrade) is left as it is, and the revision follows the reserved chain with
no enum type.

Why it exists: test_migrations.py proves the head schema matches the models;
this pins the revision itself on a throwaway SQLite file (Postgres runs the
same through the CI job's TEST_DATABASE_URL).
"""

from __future__ import annotations

from pathlib import Path

import sqlalchemy as sa
from alembic import command
from alembic.script import ScriptDirectory

from tests.test_page_watch_migration import _config, _inspect

REVISION = "0025_skill_states"
PARENT = "0024_media_transcripts"
BACKEND_DIR = Path(__file__).resolve().parents[1]


def test_the_revision_follows_the_reserved_chain_with_no_enum_type():
    script = ScriptDirectory.from_config(_config(Path("unused.db")))
    assert script.get_revision(REVISION).down_revision == PARENT
    source = (BACKEND_DIR / "alembic" / "versions" / f"{REVISION}.py").read_text(encoding="utf-8")
    assert f'revision = "{REVISION}"' in source
    assert f'down_revision = "{PARENT}"' in source
    assert "sa.Enum(" not in source


def test_upgrade_creates_the_table_and_downgrade_removes_only_it(tmp_path):
    db_path = tmp_path / "skills.db"
    config = _config(db_path)
    command.upgrade(config, REVISION)
    engine, inspector = _inspect(db_path)
    try:
        assert "skill_states" in inspector.get_table_names()
        columns = {c["name"]: c for c in inspector.get_columns("skill_states")}
        assert set(columns) == {"name", "enabled", "sha256", "updated_at", "updated_by"}
        assert not columns["enabled"]["nullable"] and columns["sha256"]["nullable"]
        assert inspector.get_pk_constraint("skill_states")["constrained_columns"] == ["name"]
        (fk,) = inspector.get_foreign_keys("skill_states")
        assert fk["referred_table"] == "users" and fk["constrained_columns"] == ["updated_by"]
        assert fk["options"].get("ondelete") == "SET NULL"
    finally:
        engine.dispose()
    command.downgrade(config, PARENT)
    engine, inspector = _inspect(db_path)
    try:
        tables = set(inspector.get_table_names())
        assert "skill_states" not in tables and "media_transcripts" in tables
    finally:
        engine.dispose()
    command.upgrade(config, "head")
    engine, inspector = _inspect(db_path)
    try:
        assert "skill_states" in inspector.get_table_names()
    finally:
        engine.dispose()


def test_deleting_the_owner_keeps_the_switch(tmp_path):
    db_path = tmp_path / "owner.db"
    command.upgrade(_config(db_path), "head")
    engine = sa.create_engine(f"sqlite:///{db_path}")
    try:
        with engine.begin() as conn:
            conn.execute(sa.text("PRAGMA foreign_keys=ON"))
            conn.execute(
                sa.text(
                    "INSERT INTO users (id, email, hashed_password, is_active, created_at, "
                    "updated_at) VALUES ('u1', 'owner@example.com', 'x', 1, '2026-01-01', "
                    "'2026-01-01')"
                )
            )
            conn.execute(
                sa.text(
                    "INSERT INTO skill_states (name, enabled, sha256, updated_at, updated_by) "
                    "VALUES ('goals', 0, :sha, '2026-01-02', 'u1')"
                ),
                {"sha": "a" * 64},
            )
        with engine.begin() as conn:
            conn.execute(sa.text("PRAGMA foreign_keys=ON"))
            conn.execute(sa.text("DELETE FROM users WHERE id = 'u1'"))
        with engine.begin() as conn:
            row = conn.execute(
                sa.text("SELECT enabled, updated_by FROM skill_states WHERE name = 'goals'")
            ).one()
        assert row == (0, None)
    finally:
        engine.dispose()


def test_an_adopted_database_keeps_its_table(tmp_path):
    import models  # noqa: F401 - registers every model
    from core.database import Base

    db_path = tmp_path / "adopted.db"
    engine = sa.create_engine(f"sqlite:///{db_path}")
    try:
        Base.metadata.create_all(engine)
    finally:
        engine.dispose()
    config = _config(db_path)
    command.stamp(config, PARENT)
    command.upgrade(config, "head")
    engine, inspector = _inspect(db_path)
    try:
        assert "skill_states" in inspector.get_table_names()
        (fk,) = inspector.get_foreign_keys("skill_states")
        assert fk["options"].get("ondelete") == "SET NULL"
    finally:
        engine.dispose()
