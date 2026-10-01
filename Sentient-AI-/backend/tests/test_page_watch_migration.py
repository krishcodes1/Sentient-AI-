"""Tests for migration 0011_page_watches and its merge 0015_merge_page_watches on
SQLite: upgrading from 0014 creates the table with its columns, indexes and
cascading foreign key, downgrading the page-watch line removes exactly that
table and keeps every row elsewhere, the round trip repeats cleanly, a
database that ran 0011_page_watches before the connectors migrations reaches
head with no manual step, and an adopted database built from the models
upgrades without trying to create the table twice.

Why it exists: test_migrations.py proves the head schema matches the models;
this pins the one revision page watch adds, including the way back, so a
failed rollout can be reverted without touching anyone's other data, and
keeps the databases that already ran it bootable.
"""

from __future__ import annotations

import pytest

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


PAGE_WATCH_MERGE = "0015_merge_page_watches"
# Joins the page-watch merge and 0015_app_approvals into one line.
APP_APPROVALS_MERGE = "0016_merge_app_approvals"
# The single head: the last of the revisions reserved on top of that merge
# (0017-0024, tests/test_integration_seams.py).
HEAD = "0024_media_transcripts"


def _versions(db_path: Path) -> list[str]:
    engine = sa.create_engine(f"sqlite:///{db_path}")
    try:
        with engine.connect() as conn:
            rows = conn.execute(sa.text("SELECT version_num FROM alembic_version")).scalars()
            return sorted(rows)
    finally:
        engine.dispose()


def test_0011_keeps_its_parent_and_the_merge_is_the_only_head():
    # Databases already ran 0011_page_watches on top of 0009, so it keeps
    # that parent; the merge joins it with the line through 0014.
    script = ScriptDirectory.from_config(_config(Path("unused.db")))
    revision = script.get_revision("0011_page_watches")
    assert revision is not None
    assert revision.down_revision == "0009_user_llm_nullable"
    merge = script.get_revision(PAGE_WATCH_MERGE)
    assert merge is not None
    assert merge.down_revision == ("0014_slack_channel_links", "0011_page_watches")
    joined = script.get_revision(APP_APPROVALS_MERGE)
    assert joined is not None
    assert joined.down_revision == (PAGE_WATCH_MERGE, "0015_app_approvals")
    assert script.get_heads() == [HEAD]


@pytest.mark.parametrize("first", [PAGE_WATCH_MERGE, "0015_app_approvals"])
def test_either_0015_line_run_first_reaches_the_single_head(tmp_path, first):
    # Page watch and weekly app approvals were built in parallel on 0014; a
    # database that ran either one first still reaches head with no manual step.
    db_path = tmp_path / "either.db"
    config = _config(db_path)
    command.upgrade(config, first)
    command.upgrade(config, "head")
    assert _versions(db_path) == [HEAD]


def test_upgrade_creates_the_table_and_downgrade_removes_only_it(tmp_path):
    db_path = tmp_path / "page_watch.db"
    config = _config(db_path)
    command.upgrade(config, "0014_slack_channel_links")

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

    command.upgrade(config, PAGE_WATCH_MERGE)
    assert _versions(db_path) == [PAGE_WATCH_MERGE]
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

    # Undo the merge, then the page-watch line only.
    command.downgrade(config, "0014_slack_channel_links")
    assert _versions(db_path) == ["0011_page_watches", "0014_slack_channel_links"]
    command.downgrade(config, "0011_page_watches@-1")
    assert _versions(db_path) == ["0014_slack_channel_links"]
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


def test_a_database_that_ran_0011_first_reaches_head(tmp_path):
    """The owner's database ran 0011_page_watches on top of 0009 before the
    vault and connectors migrations existed. ``upgrade head`` (init_db and
    the container's start command run it) must bring it level with no
    manual step and keep its watches."""
    db_path = tmp_path / "ran_0011.db"
    config = _config(db_path)
    command.upgrade(config, "0011_page_watches")
    assert _versions(db_path) == ["0011_page_watches"]
    engine = sa.create_engine(f"sqlite:///{db_path}")
    try:
        tables = set(sa.inspect(engine).get_table_names())
        assert "page_watches" in tables and "vault_items" not in tables
        with engine.begin() as conn:
            conn.execute(
                sa.text(
                    "INSERT INTO users (id, email, hashed_password, is_active, created_at, "
                    "updated_at) VALUES ('11111111111111111111111111111111', "
                    "'keep@example.com', 'x', 1, '2026-01-01 00:00:00', '2026-01-01 00:00:00')"
                )
            )
            conn.execute(
                sa.text(
                    "INSERT INTO page_watches (id, user_id, url, label, interval_minutes, "
                    "next_check_at, created_at) VALUES ('22222222222222222222222222222222', "
                    "'11111111111111111111111111111111', 'https://example.com/', 'Example', 60, "
                    "'2026-09-25 12:00:00', '2026-09-25 12:00:00')"
                )
            )
    finally:
        engine.dispose()

    command.upgrade(config, "head")
    assert _versions(db_path) == [HEAD]
    engine, inspector = _inspect(db_path)
    try:
        assert {"page_watches", "vault_items", "slack_channel_links"} <= set(
            inspector.get_table_names()
        )
        with engine.connect() as conn:
            assert conn.execute(sa.text("SELECT label FROM page_watches")).scalar_one() == "Example"
    finally:
        engine.dispose()


def test_an_adopted_database_upgrades_to_head(tmp_path):
    """A database built from the models already has page_watches; stamped at
    0014, the upgrade must not try to create it again."""
    import models  # noqa: F401 - registers every model
    from core.database import Base

    db_path = tmp_path / "adopted.db"
    engine = sa.create_engine(f"sqlite:///{db_path}")
    try:
        Base.metadata.create_all(engine)
    finally:
        engine.dispose()
    config = _config(db_path)
    command.stamp(config, "0014_slack_channel_links")
    command.upgrade(config, "head")
    assert _versions(db_path) == [HEAD]
    engine, inspector = _inspect(db_path)
    try:
        names = {i["name"] for i in inspector.get_indexes("page_watches")}
        assert names == {"ix_page_watches_status_next_check_at", "ix_page_watches_user_id_url"}
    finally:
        engine.dispose()
