"""Tests for migration and model consistency: the schema `alembic upgrade head`
builds matches the schema `Base.metadata.create_all()` expects, that there is a
single migration head, and that Postgres-only behavior like native ENUM types
and cascading deletes is correct.

Why it exists: A model changed without a matching Alembic revision would
otherwise only surface as a broken production deploy instead of failing here.

Migrations have to stay honest.

The schema `alembic upgrade head` builds and the schema the ORM expects are
two independent descriptions of the same thing, and nothing keeps them in
sync except discipline. These tests build a database each way — one by
running every migration, one by `Base.metadata.create_all()` — and compare
what the database actually ended up with. A model changed without a
matching revision fails here instead of at 3am on a production deploy.

Everything runs on a throwaway SQLite file so CI needs no Postgres.
Behaviour that only exists on Postgres (native ENUM types) is checked in a
separate test that skips unless TEST_DATABASE_URL points at one.
"""

from __future__ import annotations

import asyncio
import os
import uuid
from pathlib import Path
from typing import Any

import pytest
import sqlalchemy as sa
from alembic import command
from alembic.config import Config

BACKEND_DIR = Path(__file__).resolve().parents[1]

TEST_DATABASE_URL = os.environ.get("TEST_DATABASE_URL", "")

# Columns that used to be bolted on by core.database.init_db's inline ALTER
# list. They are the ones most likely to be dropped from a hand-written
# baseline, and the ones whose absence breaks the app in ways a smoke test
# does not catch (the audit chain, the settings page, approval risk notes).
RETROFITTED_COLUMNS = {
    "audit_logs": {"previous_hash", "seq"},
    "users": {
        "name",
        "default_permission_tier",
        "rate_limit",
        "llm_provider",
        "llm_model",
        "memory_enabled",
        "token_epoch",
    },
    "memories": {"source", "source_conversation_id"},
    "pending_actions": {"risk_note"},
}


def _alembic_config(url: str) -> Config:
    """Alembic Config pointed at a specific database.

    Paths are absolute because pytest's working directory is not guaranteed
    to be backend/, and `configure_logger` is off so env.py's fileConfig()
    never tears down the logging the test session is already using.
    """
    config = Config(str(BACKEND_DIR / "alembic.ini"))
    config.set_main_option("script_location", str(BACKEND_DIR / "alembic"))
    config.attributes["sqlalchemy_url"] = url
    config.attributes["configure_logger"] = False
    return config


def _snapshot(sync_url: str) -> dict[str, Any]:
    """Reflect a database into a comparable structure.

    Indexes, primary keys and foreign keys are included alongside columns:
    a baseline that gets every column right but loses an index or an
    ON DELETE CASCADE is still a production incident, just a slower one.
    """
    engine = sa.create_engine(sync_url)
    try:
        inspector = sa.inspect(engine)
        snapshot: dict[str, Any] = {}
        for table in inspector.get_table_names():
            # Alembic's own bookkeeping; only the migrated database has it.
            if table == "alembic_version":
                continue
            snapshot[table] = {
                "columns": {
                    column["name"]: (
                        str(column["type"]),
                        bool(column["nullable"]),
                        column.get("default"),
                    )
                    for column in inspector.get_columns(table)
                },
                "primary_key": tuple(
                    inspector.get_pk_constraint(table)["constrained_columns"]
                ),
                "indexes": {
                    index["name"]: (
                        tuple(index["column_names"]),
                        bool(index.get("unique")),
                    )
                    for index in inspector.get_indexes(table)
                },
                "foreign_keys": {
                    (
                        tuple(fk["constrained_columns"]),
                        fk["referred_table"],
                        tuple(fk["referred_columns"]),
                        (fk.get("options") or {}).get("ondelete"),
                    )
                    for fk in inspector.get_foreign_keys(table)
                },
            }
        return snapshot
    finally:
        engine.dispose()


@pytest.fixture(scope="module")
def migrated(tmp_path_factory) -> dict[str, Any]:
    """Schema produced by `alembic upgrade head`."""
    db_path = tmp_path_factory.mktemp("alembic") / "migrated.db"
    command.upgrade(_alembic_config(f"sqlite+aiosqlite:///{db_path}"), "head")
    return _snapshot(f"sqlite:///{db_path}")


@pytest.fixture(scope="module")
def created(tmp_path_factory) -> dict[str, Any]:
    """Schema produced by Base.metadata.create_all() — what the ORM expects."""
    import models  # noqa: F401 — registers every model on Base.metadata
    from core.database import Base

    db_path = tmp_path_factory.mktemp("create_all") / "metadata.db"
    engine = sa.create_engine(f"sqlite:///{db_path}")
    try:
        Base.metadata.create_all(engine)
    finally:
        engine.dispose()
    return _snapshot(f"sqlite:///{db_path}")


# ---------------------------------------------------------------------------
# Migrated schema == ORM schema
# ---------------------------------------------------------------------------


def test_same_tables(migrated, created):
    assert set(migrated) == set(created)


def test_tables_are_not_empty(created):
    """Guards the comparison itself: two empty snapshots also compare equal."""
    assert {
        "users",
        "conversations",
        "messages",
        "connector_configs",
        "audit_logs",
        "memories",
        "pending_actions",
    } <= set(created)


@pytest.mark.parametrize(
    "aspect", ["columns", "primary_key", "indexes", "foreign_keys"]
)
def test_schema_aspect_matches(migrated, created, aspect):
    """Compare one aspect at a time so a failure names what actually drifted."""
    for table in sorted(created):
        assert migrated[table][aspect] == created[table][aspect], (
            f"{table}.{aspect} differs between 'alembic upgrade head' and "
            f"Base.metadata.create_all()"
        )


# ---------------------------------------------------------------------------
# The columns the old inline-ALTER list used to add
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("table", sorted(RETROFITTED_COLUMNS))
def test_retrofitted_columns_survive_the_baseline(migrated, table):
    missing = RETROFITTED_COLUMNS[table] - set(migrated[table]["columns"])
    assert not missing, f"baseline is missing {table} columns: {sorted(missing)}"


def test_audit_seq_index_exists(migrated):
    """Appending an audit row looks up the chain head by seq; without this
    index that is a full scan of the user's history on every tool call."""
    assert migrated["audit_logs"]["indexes"]["ix_audit_logs_seq"] == (("seq",), False)


def test_users_email_index_is_unique(migrated):
    assert migrated["users"]["indexes"]["ix_users_email"] == (("email",), True)


def test_user_owned_rows_cascade_on_delete(migrated):
    """Deleting a user must not strand their audit logs, conversations,
    connectors, memories or parked approvals."""
    for table in (
        "audit_logs",
        "connector_configs",
        "conversations",
        "memories",
        "pending_actions",
    ):
        cascades = {
            fk[3]
            for fk in migrated[table]["foreign_keys"]
            if fk[1] == "users"
        }
        assert cascades == {"CASCADE"}, f"{table}.user_id is missing ON DELETE CASCADE"


# ---------------------------------------------------------------------------
# Migration mechanics
# ---------------------------------------------------------------------------


def test_single_head():
    """Two heads mean a merge is missing and `upgrade head` is ambiguous."""
    from alembic.script import ScriptDirectory

    script = ScriptDirectory.from_config(_alembic_config("sqlite://"))
    assert len(script.get_heads()) == 1


def test_head_is_recorded(tmp_path):
    """`alembic current` must report the head after an upgrade — otherwise a
    later `upgrade` would try to replay the baseline over a live schema."""
    from alembic.script import ScriptDirectory

    db_path = tmp_path / "stamped.db"
    config = _alembic_config(f"sqlite+aiosqlite:///{db_path}")
    command.upgrade(config, "head")

    engine = sa.create_engine(f"sqlite:///{db_path}")
    try:
        with engine.connect() as conn:
            recorded = conn.execute(
                sa.text("SELECT version_num FROM alembic_version")
            ).scalars().all()
    finally:
        engine.dispose()

    assert recorded == list(ScriptDirectory.from_config(config).get_heads())


def test_stamp_does_not_touch_an_existing_schema(tmp_path):
    """The documented adoption path for existing deployments: build the
    schema the way the app does today, `stamp` the baseline, and end up
    with a versioned database whose tables were never re-created."""
    import models  # noqa: F401
    from core.database import Base

    db_path = tmp_path / "legacy.db"
    engine = sa.create_engine(f"sqlite:///{db_path}")
    try:
        Base.metadata.create_all(engine)
        with engine.begin() as conn:
            conn.execute(
                sa.text(
                    "INSERT INTO users (id, email, hashed_password, is_active, "
                    "created_at, updated_at) VALUES "
                    "('abc', 'legacy@example.com', 'x', 1, "
                    "'2026-01-01 00:00:00', '2026-01-01 00:00:00')"
                )
            )
    finally:
        engine.dispose()

    command.stamp(_alembic_config(f"sqlite+aiosqlite:///{db_path}"), "0001_baseline")

    engine = sa.create_engine(f"sqlite:///{db_path}")
    try:
        with engine.connect() as conn:
            assert conn.execute(
                sa.text("SELECT version_num FROM alembic_version")
            ).scalar_one() == "0001_baseline"
            # The pre-existing row is still there: stamping recorded history,
            # it did not rebuild anything.
            assert conn.execute(
                sa.text("SELECT email FROM users")
            ).scalar_one() == "legacy@example.com"
    finally:
        engine.dispose()


def test_downgrade_removes_every_table(tmp_path):
    """An un-revertable migration is an outage with no exit."""
    db_path = tmp_path / "roundtrip.db"
    config = _alembic_config(f"sqlite+aiosqlite:///{db_path}")
    command.upgrade(config, "head")
    command.downgrade(config, "base")

    engine = sa.create_engine(f"sqlite:///{db_path}")
    try:
        remaining = set(sa.inspect(engine).get_table_names()) - {"alembic_version"}
    finally:
        engine.dispose()
    assert remaining == set()


def test_no_pending_autogenerate_diff(tmp_path):
    """A model added without a migration shows up as a pending operation.

    This is the check that keeps the two schemas converged going forward:
    test_schema_aspect_matches compares what exists, this one asks alembic
    whether anything is *missing*.
    """
    import models  # noqa: F401
    from alembic.autogenerate import compare_metadata
    from alembic.runtime.migration import MigrationContext

    from core.database import Base

    db_path = tmp_path / "diff.db"
    command.upgrade(_alembic_config(f"sqlite+aiosqlite:///{db_path}"), "head")

    engine = sa.create_engine(f"sqlite:///{db_path}")
    try:
        with engine.connect() as conn:
            context = MigrationContext.configure(conn, opts={"compare_type": True})
            diff = compare_metadata(context, Base.metadata)
    finally:
        engine.dispose()

    assert diff == [], f"models and migrations have diverged: {diff}"


# ---------------------------------------------------------------------------
# Postgres-only: native ENUM types
# ---------------------------------------------------------------------------


@pytest.mark.skipif(
    "postgresql" not in TEST_DATABASE_URL,
    reason=(
        "native ENUM types exist only on Postgres; SQLite renders sa.Enum as "
        "VARCHAR. Set TEST_DATABASE_URL to an asyncpg URL (the backend-postgres "
        "CI job does) to exercise this."
    ),
)
def test_postgres_enum_types_match_the_models():
    """`mcp` reached live databases through `ALTER TYPE ... ADD VALUE`; a
    baseline that creates connector_type without it would let a fresh
    deployment reject every MCP connector the app can create.

    Runs against a throwaway database so it cannot disturb the shared test
    schema the rest of the suite uses.
    """
    from sqlalchemy.engine import make_url
    from sqlalchemy.ext.asyncio import create_async_engine

    from models.connector import AuthMethod, ConnectorType, PermissionTier

    admin_url = make_url(TEST_DATABASE_URL)
    scratch = f"migration_check_{uuid.uuid4().hex[:12]}"
    scratch_url = admin_url.set(database=scratch)

    async def _run(statement: str) -> None:
        engine = create_async_engine(admin_url, isolation_level="AUTOCOMMIT")
        try:
            async with engine.connect() as conn:
                await conn.execute(sa.text(statement))
        finally:
            await engine.dispose()

    try:
        asyncio.run(_run(f'CREATE DATABASE "{scratch}"'))
    except Exception as exc:  # no CREATEDB privilege, etc.
        pytest.skip(f"cannot provision a throwaway database: {exc}")

    try:
        command.upgrade(
            _alembic_config(scratch_url.render_as_string(hide_password=False)), "head"
        )

        async def _enum_labels() -> dict[str, list[str]]:
            engine = create_async_engine(scratch_url)
            try:
                async with engine.connect() as conn:
                    rows = await conn.execute(
                        sa.text(
                            "SELECT t.typname, e.enumlabel FROM pg_type t "
                            "JOIN pg_enum e ON e.enumtypid = t.oid "
                            "ORDER BY t.typname, e.enumsortorder"
                        )
                    )
                    labels: dict[str, list[str]] = {}
                    for typname, label in rows.all():
                        labels.setdefault(typname, []).append(label)
                    return labels
            finally:
                await engine.dispose()

        labels = asyncio.run(_enum_labels())

        assert "mcp" in labels["connector_type"]
        assert set(labels["connector_type"]) == {t.value for t in ConnectorType}
        assert set(labels["auth_method"]) == {m.value for m in AuthMethod}
        assert set(labels["permission_tier"]) == {t.value for t in PermissionTier}
    finally:
        try:
            asyncio.run(_run(f'DROP DATABASE IF EXISTS "{scratch}" WITH (FORCE)'))
        except Exception:
            # A leaked scratch database is noise in CI, not a test failure.
            pass
