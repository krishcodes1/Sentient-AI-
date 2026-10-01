"""Tests for migration 0019_tutor_mode: it adds the nullable
``conversations.tutor_state`` column (existing rows read as off) and the
``tutor_locks`` table with its user index, a lock naming an account deleted
with it and ``created_by`` kept as NULL; both adds are guarded, so a database
that already has them (an adopted one built from the models) upgrades
cleanly; and the downgrade removes both.

Why it exists: the schema-parity tests in test_migrations.py compare the head
with the models, but not what this one revision does to a database that is
mid-chain or already has the column, which is how installs actually upgrade.
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import command

from tests.test_migrations import _alembic_config, _snapshot


def _url(tmp_path, name: str) -> tuple[str, str]:
    path = tmp_path / name
    return f"sqlite+aiosqlite:///{path}", f"sqlite:///{path}"


def test_upgrade_adds_the_column_and_the_table_and_downgrade_removes_them(tmp_path):
    async_url, sync_url = _url(tmp_path, "tutor.db")
    config = _alembic_config(async_url)
    command.upgrade(config, "0018_user_files")
    engine = sa.create_engine(sync_url)
    try:
        with engine.begin() as conn:
            conn.execute(
                sa.text(
                    "INSERT INTO users (id, email, hashed_password, is_active, is_admin, "
                    "created_at, updated_at, default_permission_tier, rate_limit, memory_enabled, token_epoch) "
                    "VALUES ('00000000000000000000000000000001', 'a@example.com', 'x', 1, 0, "
                    "'2026-09-30', '2026-09-30', 'user_confirm', 20, 1, 0)"
                )
            )
            conn.execute(
                sa.text(
                    "INSERT INTO conversations (id, user_id, title, created_at, updated_at) VALUES "
                    "('00000000000000000000000000000002', '00000000000000000000000000000001', 't', "
                    "'2026-09-30', '2026-09-30')"
                )
            )
    finally:
        engine.dispose()

    command.upgrade(config, "0019_tutor_mode")
    snapshot = _snapshot(sync_url)
    assert snapshot["conversations"]["columns"]["tutor_state"][:2] == ("JSON", True)
    locks = snapshot["tutor_locks"]
    assert set(locks["columns"]) == {
        "id",
        "user_id",
        "scope",
        "canvas_course_id",
        "course_code",
        "course_name",
        "aliases",
        "label",
        "created_by",
        "created_at",
    }
    assert locks["columns"]["user_id"][1] is True  # NULL: every account
    assert locks["columns"]["label"][1] is False
    assert locks["indexes"]["ix_tutor_locks_user_id"] == (("user_id",), False)
    assert (("user_id",), "users", ("id",), "CASCADE") in locks["foreign_keys"]
    assert (("created_by",), "users", ("id",), "SET NULL") in locks["foreign_keys"]
    engine = sa.create_engine(sync_url)
    try:
        with engine.connect() as conn:
            assert conn.execute(sa.text("SELECT tutor_state FROM conversations")).scalar_one() is None
    finally:
        engine.dispose()

    command.downgrade(config, "0018_user_files")
    snapshot = _snapshot(sync_url)
    assert "tutor_locks" not in snapshot
    assert "tutor_state" not in snapshot["conversations"]["columns"]
    assert set(snapshot["conversations"]["columns"]) >= {"id", "title", "loaded_tools"}


def test_the_adds_are_guarded(tmp_path):
    async_url, sync_url = _url(tmp_path, "adopted.db")
    config = _alembic_config(async_url)
    command.upgrade(config, "0018_user_files")
    engine = sa.create_engine(sync_url)
    try:
        with engine.begin() as conn:
            conn.execute(sa.text("ALTER TABLE conversations ADD COLUMN tutor_state JSON"))
    finally:
        engine.dispose()
    command.upgrade(config, "0019_tutor_mode")  # the column is there already: no error
    command.upgrade(config, "head")
    assert "tutor_locks" in _snapshot(sync_url)
