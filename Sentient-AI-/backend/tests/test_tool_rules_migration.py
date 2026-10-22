"""Tests for migration 0031_tool_rules (security S9, tool rules): upgrading creates
``tool_rules`` (with its ``ix_tool_rules_created_at`` index for the oldest-first listing) and
``tool_rule_builtins``, both with foreign keys to ``users`` that set the author to NULL when the
account is deleted, so a rule outlives the account that made it; the revision is a no-op on an
adopted database that already has the tables; and downgrading to 0030_browser_site_rules drops
exactly these two tables, after which the chain upgrades to head again.

Why it exists: tests/test_migrations.py proves the head schema matches the models; this pins
the revision itself on a throwaway SQLite file. A cascading delete here would silently remove
the owner's rules (and with them the cards they raise) when an account is removed, which is the
one thing the SET NULL foreign keys exist to prevent.
"""

from __future__ import annotations

from pathlib import Path

import sqlalchemy as sa
from alembic import command
from alembic.config import Config

BACKEND_DIR = Path(__file__).resolve().parents[1]

REVISION = "0031_tool_rules"
PARENT = "0030_browser_site_rules"
TABLES = {"tool_rules", "tool_rule_builtins"}


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
        columns = {
            t: {c["name"]: bool(c["nullable"]) for c in inspector.get_columns(t)}
            for t in tables & TABLES
        }
        indexes = {
            t: {i["name"]: (tuple(i["column_names"]), bool(i.get("unique"))) for i in inspector.get_indexes(t)}
            for t in tables & TABLES
        }
        fks = {
            t: {
                (
                    fk["referred_table"],
                    tuple(fk["constrained_columns"]),
                    (fk.get("options") or {}).get("ondelete"),
                )
                for fk in inspector.get_foreign_keys(t)
            }
            for t in tables & TABLES
        }
        primary_keys = {t: tuple(inspector.get_pk_constraint(t)["constrained_columns"]) for t in tables & TABLES}
    finally:
        engine.dispose()
    return tables, columns, indexes, fks, primary_keys


def _seed(engine) -> None:
    """One user, one rule and one built-in switch (raw SQL: the ORM models describe head, not
    the revision under test)."""
    with engine.begin() as conn:
        conn.execute(sa.text("PRAGMA foreign_keys=ON"))
        conn.execute(
            sa.text(
                "INSERT INTO users (id, email, hashed_password, is_active, created_at, updated_at) "
                "VALUES ('u1', 'owner@example.com', 'x', 1, '2026-01-01', '2026-01-01')"
            )
        )
        conn.execute(
            sa.text(
                "INSERT INTO tool_rules (id, name, tool_pattern, conditions, created_by, created_at) "
                "VALUES ('r1', 'Large refunds', 'mcp.stripe.*', "
                "'[{\"arg\": \"amount\", \"op\": \"number_gt\", \"value\": 500}]', 'u1', '2026-10-14')"
            )
        )
        conn.execute(
            sa.text(
                "INSERT INTO tool_rule_builtins (key, enabled, changed_by, changed_at) "
                "VALUES ('many_recipients', 0, 'u1', '2026-10-14')"
            )
        )


def _rows(engine) -> tuple[list[tuple], list[tuple]]:
    with engine.connect() as conn:
        rules = [tuple(r) for r in conn.execute(sa.text("SELECT id, name, created_by FROM tool_rules"))]
        builtins = [
            tuple(r) for r in conn.execute(sa.text("SELECT key, enabled, changed_by FROM tool_rule_builtins"))
        ]
    return rules, builtins


def test_0031_creates_both_tables_with_their_columns_index_and_set_null_foreign_keys(tmp_path):
    db_path = tmp_path / "tool_rules.db"
    config = _config(db_path)
    command.upgrade(config, PARENT)
    assert not TABLES & _inspect(db_path)[0]

    command.upgrade(config, REVISION)
    tables, columns, indexes, fks, primary_keys = _inspect(db_path)
    assert TABLES <= tables
    assert columns["tool_rules"] == {
        "id": False,
        "name": False,
        "tool_pattern": False,
        "conditions": False,
        "created_by": True,
        "created_at": False,
    }
    assert columns["tool_rule_builtins"] == {
        "key": False,
        "enabled": False,
        "changed_by": True,
        "changed_at": False,
    }
    assert primary_keys == {"tool_rules": ("id",), "tool_rule_builtins": ("key",)}
    assert indexes["tool_rules"] == {"ix_tool_rules_created_at": (("created_at",), False)}
    assert indexes["tool_rule_builtins"] == {}
    assert fks == {
        "tool_rules": {("users", ("created_by",), "SET NULL")},
        "tool_rule_builtins": {("users", ("changed_by",), "SET NULL")},
    }

    engine = sa.create_engine(f"sqlite:///{db_path}")
    try:
        _seed(engine)
        # Deleting the account keeps the rule and the switch, with the author cleared.
        with engine.begin() as conn:
            conn.execute(sa.text("PRAGMA foreign_keys=ON"))
            conn.execute(sa.text("DELETE FROM users WHERE id = 'u1'"))
        assert _rows(engine) == ([("r1", "Large refunds", None)], [("many_recipients", 0, None)])
    finally:
        engine.dispose()


def test_0031_upgrade_is_a_no_op_when_the_tables_already_exist(tmp_path):
    # An adopted database built from model metadata already has both tables.
    import models  # noqa: F401 (registers every model)
    from models.tool_rule import ToolRule, ToolRuleBuiltin

    db_path = tmp_path / "adopted.db"
    config = _config(db_path)
    command.upgrade(config, PARENT)
    engine = sa.create_engine(f"sqlite:///{db_path}")
    try:
        ToolRule.__table__.create(engine)
        ToolRuleBuiltin.__table__.create(engine)
        _seed(engine)
    finally:
        engine.dispose()
    before = _inspect(db_path)

    command.upgrade(config, REVISION)

    assert _inspect(db_path) == before
    engine = sa.create_engine(f"sqlite:///{db_path}")
    try:
        # Nothing was dropped or recreated.
        assert _rows(engine) == ([("r1", "Large refunds", "u1")], [("many_recipients", 0, "u1")])
    finally:
        engine.dispose()


def test_0031_downgrade_drops_both_tables(tmp_path):
    db_path = tmp_path / "round_trip.db"
    config = _config(db_path)
    command.upgrade(config, "head")
    assert TABLES <= _inspect(db_path)[0]

    command.downgrade(config, PARENT)
    tables = _inspect(db_path)[0]
    assert not TABLES & tables
    # Only S9's tables went: the revision below keeps its own, and so do users.
    assert {"browser_site_rules", "users"} <= tables

    command.upgrade(config, "head")
    tables, _columns, indexes, _fks, _pks = _inspect(db_path)
    assert TABLES <= tables
    assert indexes["tool_rules"] == {"ix_tool_rules_created_at": (("created_at",), False)}


def test_0031_keeps_its_reserved_parent_and_uses_no_enum_type():
    source = (BACKEND_DIR / "alembic" / "versions" / f"{REVISION}.py").read_text(encoding="utf-8")
    assert f'revision = "{REVISION}"' in source
    assert f'down_revision = "{PARENT}"' in source
    assert "sa.Enum(" not in source
