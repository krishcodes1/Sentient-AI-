"""Tests for migration 0011_page_watches on SQLite: upgrading from 0009 creates
the table with its columns, indexes and cascading foreign key, downgrading to
0009 removes exactly that table and keeps every row elsewhere, the round trip
repeats cleanly, and an adopted database built from the models upgrades
without trying to create the table twice.

Why it exists: test_migrations.py proves the head schema matches the models;
this pins the one revision page watch adds, including the way back, so a
failed rollout can be reverted without touching anyone's other data.
"""

from __future__ import annotations

from pathlib import Path

import sqlalchemy as sa
from alembic import command
from alembic.config import Config
from alembic.script import ScriptDirectory

BACKEND_DIR = Path(__file__).resolve().parents[1]


def _config(db_path: Path) -> Config:
    config = Config(str(BACKEND_DIR / "alembic.ini"))
    config.set_main_option("script_location", str(BACKEND_DIR / "alembic"))
    config.attributes["sqlalchemy_url"] = f"sqlite+aiosqlite:///{db_path}"
    config.attributes["configure_logger"] = False
    return config


def _inspect(db_path: Path):
    engine = sa.create_engine(f"sqlite:///{db_path}")
    return engine, sa.inspect(engine)


def _version(db_path: Path) -> str:
    engine = sa.create_engine(f"sqlite:///{db_path}")
    try:
        with engine.connect() as conn:
            return conn.execute(sa.text("SELECT version_num FROM alembic_version")).scalar_one()
    finally:
        engine.dispose()


def test_0011_follows_0009():
    # Its place in the chain, for good: databases already ran it on top of
    # 0009, so re-parenting it onto feat/purchases' 0010_vault_items would
    # make Alembic skip 0010 on them. When 0010 lands, a merge revision joins
    # the two (see the revision's docstring); test_migrations.py checks
    # there is one head.
    script = ScriptDirectory.from_config(_config(Path("unused.db")))
    revision = script.get_revision("0011_page_watches")
    assert revision is not None
    assert revision.down_revision == "0009_user_llm_nullable"


def test_upgrade_creates_the_table_and_downgrade_removes_only_it(tmp_path):
    db_path = tmp_path / "page_watch.db"
    config = _config(db_path)
    command.upgrade(config, "0009_user_llm_nullable")

    engine = sa.create_engine(f"sqlite:///{db_path}")
    try:
        before = set(sa.inspect(engine).get_table_names())
        assert "page_watches" not in before
        with engine.begin() as conn:
            conn.execute(
                sa.text(
                    "INSERT INTO users (id, email, hashed_password, is_active, created_at, "
                    "updated_at) VALUES ('11111111111111111111111111111111', "
                    "'keep@example.com', 'x', 1, '2026-01-01 00:00:00', '2026-01-01 00:00:00')"
                )
            )
    finally:
        engine.dispose()

    command.upgrade(config, "0011_page_watches")
    assert _version(db_path) == "0011_page_watches"
    engine, inspector = _inspect(db_path)
    try:
        assert set(inspector.get_table_names()) == before | {"page_watches"}
        columns = {c["name"]: c for c in inspector.get_columns("page_watches")}
        assert set(columns) == {
            "id",
            "user_id",
            "url",
            "label",
            "interval_minutes",
            "last_hash",
            "last_excerpt",
            "last_checked_at",
            "next_check_at",
            "last_changed_at",
            "status",
            "consecutive_errors",
            "last_error",
            "created_at",
        }
        for required in (
            "id",
            "user_id",
            "url",
            "label",
            "interval_minutes",
            "next_check_at",
            "status",
            "consecutive_errors",
            "created_at",
        ):
            assert columns[required]["nullable"] is False, required
        indexes = {
            i["name"]: (tuple(i["column_names"]), bool(i["unique"]))
            for i in inspector.get_indexes("page_watches")
        }
        assert indexes == {
            "ix_page_watches_status_next_check_at": (("status", "next_check_at"), False),
            "ix_page_watches_user_id_url": (("user_id", "url"), True),
        }
        fks = inspector.get_foreign_keys("page_watches")
        assert [
            (fk["referred_table"], (fk.get("options") or {}).get("ondelete")) for fk in fks
        ] == [("users", "CASCADE")]
        with engine.begin() as conn:
            conn.execute(
                sa.text(
                    "INSERT INTO page_watches (id, user_id, url, label, interval_minutes, "
                    "next_check_at, created_at) VALUES ('22222222222222222222222222222222', "
                    "'11111111111111111111111111111111', 'https://example.com/', 'Example', 60, "
                    "'2026-09-25 12:00:00', '2026-09-25 12:00:00')"
                )
            )
            row = conn.execute(sa.text("SELECT status, consecutive_errors FROM page_watches")).one()
            # The server defaults a raw insert relies on.
            assert tuple(row) == ("active", 0)
    finally:
        engine.dispose()

    command.downgrade(config, "0009_user_llm_nullable")
    assert _version(db_path) == "0009_user_llm_nullable"
    engine, inspector = _inspect(db_path)
    try:
        assert set(inspector.get_table_names()) == before
        with engine.connect() as conn:
            assert (
                conn.execute(sa.text("SELECT email FROM users")).scalar_one() == "keep@example.com"
            )
    finally:
        engine.dispose()

    # And back up again: the downgrade left nothing behind in the way.
    command.upgrade(config, "head")
    engine, inspector = _inspect(db_path)
    try:
        assert "page_watches" in inspector.get_table_names()
    finally:
        engine.dispose()


def test_an_adopted_database_upgrades_through_0011(tmp_path):
    """A database built from the models already has page_watches; stamped at
    0009, the upgrade must not try to create it again."""
    import models  # noqa: F401 - registers every model
    from core.database import Base

    db_path = tmp_path / "adopted.db"
    engine = sa.create_engine(f"sqlite:///{db_path}")
    try:
        Base.metadata.create_all(engine)
    finally:
        engine.dispose()
    config = _config(db_path)
    command.stamp(config, "0009_user_llm_nullable")
    command.upgrade(config, "0011_page_watches")
    assert _version(db_path) == "0011_page_watches"
    engine, inspector = _inspect(db_path)
    try:
        names = {i["name"] for i in inspector.get_indexes("page_watches")}
        assert names == {"ix_page_watches_status_next_check_at", "ix_page_watches_user_id_url"}
    finally:
        engine.dispose()
