"""Tests for migration 0029_breach_watch (security S6, the breach monitor):
upgrading creates ``breach_watch_addresses`` and ``breach_watch_findings`` with
their indexes (one row per address per owner, each breach once per address)
and foreign keys that cascade with the user and, for findings, the address;
the server defaults fill the counters; deleting a user or an address takes its
rows with it; downgrading to 0028_mcp_tool_pins removes exactly the two tables
before upgrading again; the revision is a no-op when an adopted database
already has the tables; and it keeps its reserved parent and uses no enum.

Why it exists: tests/test_migrations.py proves the head schema matches the
models; this pins the revision itself on a throwaway SQLite file, including
the unique (address_id, breach_name) index that is the breach monitor's dedupe
guard: without it a breach could be alerted twice across workers and restarts.
"""

from __future__ import annotations

from pathlib import Path

import pytest
import sqlalchemy as sa
from alembic import command
from alembic.config import Config

BACKEND_DIR = Path(__file__).resolve().parents[1]

REVISION = "0029_breach_watch"
PARENT = "0028_mcp_tool_pins"
TABLES = {"breach_watch_addresses", "breach_watch_findings"}


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
        indexes = {
            t: {
                i["name"]: (tuple(i["column_names"]), bool(i.get("unique")))
                for i in inspector.get_indexes(t)
            }
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
        columns = {t: {c["name"] for c in inspector.get_columns(t)} for t in tables & TABLES}
    finally:
        engine.dispose()
    return tables, indexes, fks, columns


_ADDRESS = sa.text(
    "INSERT INTO breach_watch_addresses (id, user_id, source, address_digest, address_sealed, "
    "status, next_check_at, created_at, updated_at) VALUES (:id, 'u1', 'account', :digest, x'00', "
    "'active', '2026-10-14', '2026-10-14', '2026-10-14')"
)
_FINDING = sa.text(
    "INSERT INTO breach_watch_findings (id, address_id, user_id, breach_name, title, data_classes, "
    "verified, sensitive, fabricated, spam_list, baseline, first_seen_at) VALUES (:id, 'a1', 'u1', "
    ":name, 'Adobe', '[]', 1, 0, 0, 0, 1, '2026-10-14')"
)


def _seed(engine) -> None:
    """One user, one watched address and one finding (raw SQL: the ORM models describe
    head, not the revision under test)."""
    with engine.begin() as conn:
        conn.execute(sa.text("PRAGMA foreign_keys=ON"))
        conn.execute(
            sa.text(
                "INSERT INTO users (id, email, hashed_password, is_active, created_at, updated_at) "
                "VALUES ('u1', 'kash@example.com', 'x', 1, '2026-01-01', '2026-01-01')"
            )
        )
        conn.execute(_ADDRESS, {"id": "a1", "digest": "d" * 64})
        conn.execute(_FINDING, {"id": "f1", "name": "Adobe"})


def _counts(engine) -> tuple[int, int]:
    with engine.connect() as conn:
        addresses = conn.execute(
            sa.text("SELECT count(*) FROM breach_watch_addresses")
        ).scalar_one()
        findings = conn.execute(sa.text("SELECT count(*) FROM breach_watch_findings")).scalar_one()
    return addresses, findings


def test_0029_creates_both_tables_with_their_indexes_and_cascades_and_downgrades_cleanly(tmp_path):
    db_path = tmp_path / "breach.db"
    config = _config(db_path)
    command.upgrade(config, REVISION)
    tables, indexes, fks, columns = _inspect(db_path)
    assert TABLES <= tables
    assert indexes["breach_watch_addresses"] == {
        "uq_breach_watch_addresses_user_digest": (("user_id", "address_digest"), True),
        "ix_breach_watch_addresses_status_next_check": (("status", "next_check_at"), False),
    }
    assert indexes["breach_watch_findings"] == {
        "uq_breach_watch_findings_address_name": (("address_id", "breach_name"), True),
        "ix_breach_watch_findings_user_seen": (("user_id", "first_seen_at"), False),
    }
    assert fks["breach_watch_addresses"] == {("users", ("user_id",), "CASCADE")}
    assert fks["breach_watch_findings"] == {
        ("users", ("user_id",), "CASCADE"),
        ("breach_watch_addresses", ("address_id",), "CASCADE"),
    }
    # Never a plain-text address column, never a key.
    assert "address_sealed" in columns["breach_watch_addresses"]
    for table_columns in columns.values():
        assert not {"address", "email", "api_key", "hibp_api_key"} & table_columns

    engine = sa.create_engine(f"sqlite:///{db_path}")
    try:
        _seed(engine)
        with engine.connect() as conn:
            counters = conn.execute(
                sa.text("SELECT breach_count, consecutive_errors FROM breach_watch_addresses")
            ).one()
        assert tuple(counters) == (0, 0)
        # The seen list's dedupe guard and the one-row-per-address guard.
        with pytest.raises(sa.exc.IntegrityError):
            with engine.begin() as conn:
                conn.execute(_FINDING, {"id": "f2", "name": "Adobe"})
        with pytest.raises(sa.exc.IntegrityError):
            with engine.begin() as conn:
                conn.execute(_ADDRESS, {"id": "a2", "digest": "d" * 64})
        with engine.begin() as conn:
            conn.execute(_FINDING, {"id": "f3", "name": "Linked"})
        assert _counts(engine) == (1, 2)
        # Removing the address takes its findings; removing the user takes everything.
        with engine.begin() as conn:
            conn.execute(sa.text("PRAGMA foreign_keys=ON"))
            conn.execute(sa.text("DELETE FROM breach_watch_addresses WHERE id = 'a1'"))
        assert _counts(engine) == (0, 0)
        with engine.begin() as conn:
            conn.execute(sa.text("PRAGMA foreign_keys=ON"))
            conn.execute(_ADDRESS, {"id": "a1", "digest": "e" * 64})
            conn.execute(_FINDING, {"id": "f4", "name": "Adobe"})
        assert _counts(engine) == (1, 1)
        with engine.begin() as conn:
            conn.execute(sa.text("PRAGMA foreign_keys=ON"))
            conn.execute(sa.text("DELETE FROM users WHERE id = 'u1'"))
        assert _counts(engine) == (0, 0)
    finally:
        engine.dispose()

    command.downgrade(config, PARENT)
    tables, _indexes, _fks, _columns = _inspect(db_path)
    assert not TABLES & tables
    # Only S6's tables went: the revision below it keeps its own.
    assert {"mcp_tool_pins", "users"} <= tables
    command.upgrade(config, "head")
    tables, indexes, _fks, _columns = _inspect(db_path)
    assert TABLES <= tables
    assert indexes["breach_watch_findings"]["uq_breach_watch_findings_address_name"][1]


def test_0029_is_a_no_op_when_the_tables_already_exist(tmp_path):
    # An adopted database built from model metadata already has both tables.
    import models  # noqa: F401 (registers every model)
    from models.breach_watch import BreachWatchAddress, BreachWatchFinding

    db_path = tmp_path / "adopted.db"
    config = _config(db_path)
    command.upgrade(config, PARENT)
    engine = sa.create_engine(f"sqlite:///{db_path}")
    try:
        BreachWatchAddress.__table__.create(engine)
        BreachWatchFinding.__table__.create(engine)
        _seed(engine)
    finally:
        engine.dispose()
    before = _inspect(db_path)

    command.upgrade(config, REVISION)

    after = _inspect(db_path)
    assert after == before
    engine = sa.create_engine(f"sqlite:///{db_path}")
    try:
        assert _counts(engine) == (1, 1)  # nothing was dropped or recreated
    finally:
        engine.dispose()


def test_0029_keeps_its_reserved_parent_and_uses_no_enum_type():
    source = (BACKEND_DIR / "alembic" / "versions" / f"{REVISION}.py").read_text(encoding="utf-8")
    assert f'revision = "{REVISION}"' in source
    assert f'down_revision = "{PARENT}"' in source
    assert "sa.Enum(" not in source
