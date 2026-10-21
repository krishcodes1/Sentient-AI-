"""Tests for migration 0030_browser_site_rules: it creates the
``browser_site_rules`` table with the columns the model declares, the
unique index on (target_type, target) and the two ``users`` foreign keys
that keep a rule (SET NULL) when its author's account is deleted; a
database that already has the table (an adopted one built from the models)
upgrades cleanly; and the downgrade removes the index and the table.

Why it exists: the schema-parity tests compare the head with the models,
not what this one revision does to a database mid-chain, which is how
installs upgrade. Runs on a throwaway SQLite file; no network.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import sqlalchemy as sa
from alembic import command
from alembic.config import Config

BACKEND_DIR = Path(__file__).resolve().parents[1]
BEFORE = "0029_breach_watch"
REVISION = "0030_browser_site_rules"


def _config(async_url: str) -> Config:
    config = Config(str(BACKEND_DIR / "alembic.ini"))
    config.set_main_option("script_location", str(BACKEND_DIR / "alembic"))
    config.attributes["sqlalchemy_url"] = async_url
    config.attributes["configure_logger"] = False
    return config


def _urls(tmp_path: Path, name: str) -> tuple[str, str]:
    path = tmp_path / name
    return f"sqlite+aiosqlite:///{path}", f"sqlite:///{path}"


def _table(sync_url: str) -> dict[str, Any]:
    engine = sa.create_engine(sync_url)
    try:
        inspector = sa.inspect(engine)
        if "browser_site_rules" not in inspector.get_table_names():
            return {}
        return {
            "columns": {
                column["name"]: (str(column["type"]), bool(column["nullable"]))
                for column in inspector.get_columns("browser_site_rules")
            },
            "primary_key": tuple(inspector.get_pk_constraint("browser_site_rules")["constrained_columns"]),
            "indexes": {
                index["name"]: (tuple(index["column_names"]), bool(index.get("unique")))
                for index in inspector.get_indexes("browser_site_rules")
            },
            "foreign_keys": {
                (tuple(fk["constrained_columns"]), fk["referred_table"], (fk.get("options") or {}).get("ondelete"))
                for fk in inspector.get_foreign_keys("browser_site_rules")
            },
        }
    finally:
        engine.dispose()


def test_0030_creates_the_table_and_its_unique_target_index(tmp_path):
    async_url, sync_url = _urls(tmp_path, "site_rules.db")
    config = _config(async_url)
    command.upgrade(config, BEFORE)
    assert _table(sync_url) == {}
    command.upgrade(config, REVISION)
    table = _table(sync_url)
    assert table["columns"] == {
        "id": ("CHAR(32)", False),
        "target_type": ("VARCHAR(16)", False),
        "target": ("VARCHAR(255)", False),
        "kind": ("VARCHAR(16)", False),
        "created_by": ("CHAR(32)", True),
        "updated_by": ("CHAR(32)", True),
        "created_at": ("DATETIME", False),
        "updated_at": ("DATETIME", False),
    }
    assert table["primary_key"] == ("id",)
    assert table["indexes"] == {"ux_browser_site_rules_target": (("target_type", "target"), True)}
    assert table["foreign_keys"] == {
        (("created_by",), "users", "SET NULL"),
        (("updated_by",), "users", "SET NULL"),
    }
    # The unique index refuses a second row for the same target.
    engine = sa.create_engine(sync_url)
    try:
        insert = sa.text(
            "INSERT INTO browser_site_rules (id, target_type, target, kind, created_at, updated_at) "
            "VALUES (:id, 'host', '*.example-casino.com', 'blocked', '2026-10-21', '2026-10-21')"
        )
        with engine.begin() as conn:
            conn.execute(insert, {"id": "00000000000000000000000000000001"})
        duplicate_refused = False
        try:
            with engine.begin() as conn:
                conn.execute(insert, {"id": "00000000000000000000000000000002"})
        except sa.exc.IntegrityError:
            duplicate_refused = True
        assert duplicate_refused
    finally:
        engine.dispose()


def test_0030_upgrades_a_database_that_already_has_the_table(tmp_path):
    # An adopted pre-Alembic database is built from the model metadata
    # before it is stamped and upgraded: the guarded create must not fail.
    async_url, sync_url = _urls(tmp_path, "adopted.db")
    config = _config(async_url)
    command.upgrade(config, BEFORE)
    engine = sa.create_engine(sync_url)
    try:
        with engine.begin() as conn:
            conn.execute(
                sa.text(
                    "CREATE TABLE browser_site_rules (id CHAR(32) PRIMARY KEY, target_type VARCHAR(16) "
                    "NOT NULL, target VARCHAR(255) NOT NULL, kind VARCHAR(16) NOT NULL, created_by "
                    "CHAR(32), updated_by CHAR(32), created_at DATETIME NOT NULL, updated_at DATETIME "
                    "NOT NULL)"
                )
            )
    finally:
        engine.dispose()
    command.upgrade(config, REVISION)
    assert _table(sync_url)["indexes"] == {
        "ux_browser_site_rules_target": (("target_type", "target"), True)
    }


def test_0030_downgrade_drops_them(tmp_path):
    async_url, sync_url = _urls(tmp_path, "downgrade.db")
    config = _config(async_url)
    command.upgrade(config, REVISION)
    assert _table(sync_url)
    command.downgrade(config, BEFORE)
    assert _table(sync_url) == {}
    # And it upgrades again from there.
    command.upgrade(config, REVISION)
    assert "ux_browser_site_rules_target" in _table(sync_url)["indexes"]
