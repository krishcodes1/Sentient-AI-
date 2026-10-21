"""Tests for migration 0032_file_reputation on SQLite: they prove it creates the three
file-reputation tables with every column of models/file_reputation.py, their indexes (the one
unique index per person and file included) and their foreign keys (checks cascade with their
user, the request log keeps its rows with the user id set to NULL), and that downgrading to
0031_tool_rules removes exactly those three tables.

Why it exists: the request log must survive a user's deletion so the day's count stays true,
a person's history must go with them, and a migration that drifted from the model would only
fail on a real upgrade (scaffold B8; the pattern of tests/test_video_store.py).
"""

from __future__ import annotations

from pathlib import Path

import sqlalchemy as sa
from alembic import command
from alembic.script import ScriptDirectory

from models.file_reputation import FileReputationCall, FileReputationCheck, FileReputationVerdict
from tests.test_page_watch_migration import _config, _inspect

REVISION = "0032_file_reputation"
PARENT = "0031_tool_rules"
TABLES = {
    "file_reputation_verdicts": FileReputationVerdict,
    "file_reputation_checks": FileReputationCheck,
    "file_reputation_calls": FileReputationCall,
}


def _indexes(inspector: sa.Inspector, table: str) -> dict[str, tuple[tuple[str, ...], bool]]:
    return {
        index["name"]: (tuple(index["column_names"]), bool(index["unique"]))
        for index in inspector.get_indexes(table)
    }


def test_0032_creates_the_three_tables_with_their_indexes_and_downgrades_cleanly(tmp_path):
    script = ScriptDirectory.from_config(_config(Path("unused.db")))
    assert script.get_revision(REVISION).down_revision == PARENT

    db_path = tmp_path / "file_reputation.db"
    config = _config(db_path)
    command.upgrade(config, REVISION)
    engine, inspector = _inspect(db_path)
    try:
        for table, model in TABLES.items():
            columns = {c["name"]: c for c in inspector.get_columns(table)}
            assert set(columns) == {c.name for c in model.__table__.columns}, table
            for column in model.__table__.columns:
                assert columns[column.name]["nullable"] == column.nullable or column.primary_key, (
                    table,
                    column.name,
                )
        assert inspector.get_pk_constraint("file_reputation_verdicts")["constrained_columns"] == ["sha256"]
        assert _indexes(inspector, "file_reputation_verdicts") == {
            "ix_file_reputation_verdicts_expires_at": (("expires_at",), False)
        }
        assert _indexes(inspector, "file_reputation_checks") == {
            "uq_file_reputation_checks_user_sha256": (("user_id", "sha256"), True),
            "ix_file_reputation_checks_user_updated": (("user_id", "updated_at"), False),
            "ix_file_reputation_checks_user_source_key": (("user_id", "source_key"), False),
            "ix_file_reputation_checks_state_due": (("state", "next_poll_at"), False),
            "ix_file_reputation_checks_expires_at": (("expires_at",), False),
        }
        assert _indexes(inspector, "file_reputation_calls") == {
            "ix_file_reputation_calls_at": (("at",), False),
            "ix_file_reputation_calls_user_at": (("user_id", "at"), False),
        }
        (checks_fk,) = inspector.get_foreign_keys("file_reputation_checks")
        assert checks_fk["referred_table"] == "users" and checks_fk["options"].get("ondelete") == "CASCADE"
        (calls_fk,) = inspector.get_foreign_keys("file_reputation_calls")
        assert calls_fk["referred_table"] == "users" and calls_fk["options"].get("ondelete") == "SET NULL"
        assert inspector.get_foreign_keys("file_reputation_verdicts") == []
    finally:
        engine.dispose()

    command.downgrade(config, PARENT)
    engine, inspector = _inspect(db_path)
    try:
        tables = set(inspector.get_table_names())
        assert not tables & set(TABLES)
        assert {"users", "user_files", "tool_rules"} <= tables
    finally:
        engine.dispose()
    command.upgrade(config, "head")
    engine, inspector = _inspect(db_path)
    try:
        assert set(TABLES) <= set(inspector.get_table_names())
    finally:
        engine.dispose()
