"""Tests for migration 0026_goals: upgrading creates the three goals tables with
their server defaults, indexes and cascading foreign keys (a note's
milestone_id has none), deleting a user or a goal takes its rows with it,
downgrading to 0025 removes exactly what it added, an adopted database built
from the models (create_all, stamp, upgrade) is left as it is, and the
revision follows 0025_skill_states with no enum type.

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

REVISION = "0026_goals"
PARENT = "0025_skill_states"
TABLES = ("goals", "goal_milestones", "goal_entries")
BACKEND_DIR = Path(__file__).resolve().parents[1]


def _fks(inspector, table: str) -> set[tuple[str, str, str | None]]:
    return {
        (fk["constrained_columns"][0], fk["referred_table"], fk["options"].get("ondelete"))
        for fk in inspector.get_foreign_keys(table)
    }


def _indexes(inspector, table: str) -> dict[str, tuple[str, ...]]:
    return {ix["name"]: tuple(ix["column_names"]) for ix in inspector.get_indexes(table)}


def test_the_revision_follows_skill_states_with_no_enum_type():
    script = ScriptDirectory.from_config(_config(Path("unused.db")))
    assert script.get_revision(REVISION).down_revision == PARENT
    source = (BACKEND_DIR / "alembic" / "versions" / f"{REVISION}.py").read_text(encoding="utf-8")
    assert f'revision = "{REVISION}"' in source
    assert f'down_revision = "{PARENT}"' in source
    assert "sa.Enum(" not in source


def test_upgrade_creates_the_tables_and_downgrade_removes_only_them(tmp_path):
    db_path = tmp_path / "goals.db"
    config = _config(db_path)
    command.upgrade(config, REVISION)
    engine, inspector = _inspect(db_path)
    try:
        assert set(TABLES) <= set(inspector.get_table_names())
        goals = {c["name"]: c for c in inspector.get_columns("goals")}
        assert set(goals) == {
            "id",
            "user_id",
            "title",
            "description",
            "category",
            "status",
            "current_state",
            "target_date",
            "check_in",
            "created_at",
            "updated_at",
            "completed_at",
        }
        defaults = {name: str(goals[name]["default"]).strip("'\"") for name in goals}
        assert (defaults["category"], defaults["status"], defaults["check_in"]) == (
            "other",
            "active",
            "none",
        )
        assert goals["description"]["nullable"] and not goals["title"]["nullable"]
        assert _indexes(inspector, "goals") == {
            "ix_goals_user_id_status": ("user_id", "status"),
            "ix_goals_user_id_created_at": ("user_id", "created_at"),
        }
        assert _fks(inspector, "goals") == {("user_id", "users", "CASCADE")}

        milestones = {c["name"]: c for c in inspector.get_columns("goal_milestones")}
        assert str(milestones["state"]["default"]).strip("'\"") == "open"
        assert _indexes(inspector, "goal_milestones") == {
            "ix_goal_milestones_goal_id_position": ("goal_id", "position")
        }
        assert _fks(inspector, "goal_milestones") == {
            ("goal_id", "goals", "CASCADE"),
            ("user_id", "users", "CASCADE"),
        }

        entries = {c["name"]: c for c in inspector.get_columns("goal_entries")}
        assert entries["source"]["default"] is None and entries["milestone_id"]["nullable"]
        assert _indexes(inspector, "goal_entries") == {
            "ix_goal_entries_goal_id_created_at": ("goal_id", "created_at")
        }
        # milestone_id has no foreign key: a note outlives its milestone.
        assert _fks(inspector, "goal_entries") == {
            ("goal_id", "goals", "CASCADE"),
            ("user_id", "users", "CASCADE"),
        }
    finally:
        engine.dispose()
    command.downgrade(config, PARENT)
    engine, inspector = _inspect(db_path)
    try:
        tables = set(inspector.get_table_names())
        assert not tables & set(TABLES)
        assert "skill_states" in tables and "media_transcripts" in tables
    finally:
        engine.dispose()
    command.upgrade(config, "head")
    engine, inspector = _inspect(db_path)
    try:
        assert set(TABLES) <= set(inspector.get_table_names())
    finally:
        engine.dispose()


def test_a_users_and_a_goals_rows_cascade(tmp_path):
    db_path = tmp_path / "cascade.db"
    command.upgrade(_config(db_path), "head")
    engine = sa.create_engine(f"sqlite:///{db_path}")
    stamp = "'2026-10-12'"
    try:
        with engine.begin() as conn:
            conn.execute(sa.text("PRAGMA foreign_keys=ON"))
            conn.execute(
                sa.text(
                    "INSERT INTO users (id, email, hashed_password, is_active, created_at, "
                    "updated_at) VALUES ('u1', 'goals@example.com', 'x', 1, '2026-01-01', "
                    "'2026-01-01')"
                )
            )
            for goal in ("g1", "g2"):
                # The server defaults fill category, status and check_in.
                conn.execute(
                    sa.text(
                        "INSERT INTO goals (id, user_id, title, created_at, updated_at) "
                        f"VALUES ('{goal}', 'u1', 'Run a 5k', {stamp}, {stamp})"
                    )
                )
                conn.execute(
                    sa.text(
                        "INSERT INTO goal_milestones (id, goal_id, user_id, title, position, "
                        f"created_at) VALUES ('m-{goal}', '{goal}', 'u1', 'Week one', 0, {stamp})"
                    )
                )
                conn.execute(
                    sa.text(
                        "INSERT INTO goal_entries (id, goal_id, user_id, note, source, "
                        f"milestone_id, created_at) VALUES ('e-{goal}', '{goal}', 'u1', "
                        f"'Ran 2k', 'user', 'm-{goal}', {stamp})"
                    )
                )
        with engine.begin() as conn:
            row = conn.execute(
                sa.text("SELECT category, status, check_in FROM goals WHERE id = 'g1'")
            ).one()
            assert tuple(row) == ("other", "active", "none")
            state = conn.execute(
                sa.text("SELECT state FROM goal_milestones WHERE id = 'm-g1'")
            ).scalar_one()
            assert state == "open"
        with engine.begin() as conn:
            conn.execute(sa.text("PRAGMA foreign_keys=ON"))
            conn.execute(sa.text("DELETE FROM goals WHERE id = 'g1'"))
        with engine.begin() as conn:
            for table in ("goal_milestones", "goal_entries"):
                left = conn.execute(sa.text(f"SELECT goal_id FROM {table}")).scalars().all()
                assert left == ["g2"], table
            conn.execute(sa.text("PRAGMA foreign_keys=ON"))
            conn.execute(sa.text("DELETE FROM users WHERE id = 'u1'"))
        with engine.begin() as conn:
            for table in TABLES:
                count = conn.execute(sa.text(f"SELECT COUNT(*) FROM {table}")).scalar_one()
                assert count == 0, table
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
    command.stamp(config, PARENT)
    command.upgrade(config, "head")
    engine, inspector = _inspect(db_path)
    try:
        assert set(TABLES) <= set(inspector.get_table_names())
        assert ("goal_id", "goals", "CASCADE") in _fks(inspector, "goal_entries")
        assert "ix_goals_user_id_status" in _indexes(inspector, "goals")
    finally:
        engine.dispose()
