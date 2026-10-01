"""Tests for migration 0018_user_files on SQLite: upgrading creates the
user_files table with its unique dedupe index, the listing index and the
expiry index and a cascading owner key; downgrading to 0017 removes only it;
and a database whose table already exists (an adopted one) upgrades cleanly.

Why it exists: the revision id was reserved in the top10 chain, so it must
keep its parent, and its schema must match the model (tests/test_migrations.py
compares the whole head against create_all; this pins the revision itself).
"""

from __future__ import annotations

from pathlib import Path

import sqlalchemy as sa
from alembic import command
from alembic.script import ScriptDirectory

from tests.test_page_watch_migration import _config, _inspect

REVISION = "0018_user_files"


def test_the_revision_keeps_its_reserved_parent():
    script = ScriptDirectory.from_config(_config(Path("unused.db")))
    assert script.get_revision(REVISION).down_revision == "0017_scheduled_tasks"


def test_upgrade_creates_user_files_and_downgrade_removes_only_it(tmp_path):
    db_path = tmp_path / "files.db"
    config = _config(db_path)
    command.upgrade(config, REVISION)
    engine, inspector = _inspect(db_path)
    try:
        assert "user_files" in inspector.get_table_names()
        indexes = {i["name"]: (tuple(i["column_names"]), bool(i["unique"])) for i in inspector.get_indexes("user_files")}
        assert indexes["uq_user_files_user_sha256"] == (("user_id", "sha256"), True)
        assert indexes["ix_user_files_user_created"] == (("user_id", "created_at"), False)
        assert indexes["ix_user_files_expires_at"] == (("expires_at",), False)
        (fk,) = inspector.get_foreign_keys("user_files")
        assert fk["referred_table"] == "users" and fk["options"].get("ondelete") == "CASCADE"
        columns = {c["name"] for c in inspector.get_columns("user_files")}
        assert {"content", "sha256", "expires_at", "scanned_pages_unread", "warnings"} <= columns
    finally:
        engine.dispose()

    command.downgrade(config, "0017_scheduled_tasks")
    engine, inspector = _inspect(db_path)
    try:
        tables = set(inspector.get_table_names())
        assert "user_files" not in tables and "users" in tables
    finally:
        engine.dispose()
    command.upgrade(config, "head")


def test_an_existing_table_is_left_alone(tmp_path):
    db_path = tmp_path / "adopted.db"
    config = _config(db_path)
    command.upgrade(config, "0017_scheduled_tasks")
    engine = sa.create_engine(f"sqlite:///{db_path}")
    try:
        with engine.begin() as conn:
            conn.execute(sa.text("CREATE TABLE user_files (id CHAR(32) PRIMARY KEY)"))
    finally:
        engine.dispose()
    command.upgrade(config, REVISION)
    engine, inspector = _inspect(db_path)
    try:
        # The adopted table is untouched (no column added, no index made)
        # and the revision is still recorded as applied.
        assert [c["name"] for c in inspector.get_columns("user_files")] == ["id"]
        assert inspector.get_indexes("user_files") == []
        with engine.connect() as conn:
            stamped = conn.execute(sa.text("SELECT version_num FROM alembic_version")).scalars().all()
        assert stamped == [REVISION]
    finally:
        engine.dispose()
