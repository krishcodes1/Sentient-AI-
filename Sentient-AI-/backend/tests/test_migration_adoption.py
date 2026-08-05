"""Adopting a database that predates Alembic.

Migrations landed after this app had already been run, so real databases
exist with the full schema and no ``alembic_version`` row. ``upgrade head``
on one of those starts at the baseline and dies on ``CREATE TABLE users``;
on Postgres that aborts the transaction, so it fails the same way on every
restart and the app never serves a request. From the outside that looks
like the whole product returning "Internal Server Error", which is exactly
what it did.

Requiring the operator to know to run ``alembic stamp`` first is not a fix
— nothing warns them until it is already down — so startup detects and
adopts the database itself. These tests cover the three states a database
can be in when the app boots.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, inspect, text

BACKEND_DIR = Path(__file__).resolve().parent.parent


def _config(url: str) -> Config:
    """Alembic drives the app's async engine, so it needs the async driver
    even though the reflection helpers below use the sync one."""
    config = Config(str(BACKEND_DIR / "alembic.ini"))
    config.set_main_option("script_location", str(BACKEND_DIR / "alembic"))
    config.attributes["sqlalchemy_url"] = url.replace(
        "sqlite://", "sqlite+aiosqlite://", 1
    )
    config.attributes["configure_logger"] = False
    return config


def _create_all_database(path: Path) -> str:
    """A database built the way the app used to build one: create_all, no
    migration history."""
    import models  # noqa: F401 — registers every model
    from core.database import Base

    url = f"sqlite:///{path}"
    engine = create_engine(url)
    Base.metadata.create_all(engine)
    engine.dispose()
    return url


def _tables(url: str) -> set[str]:
    engine = create_engine(url)
    try:
        return set(inspect(engine).get_table_names())
    finally:
        engine.dispose()


def _columns(url: str, table: str) -> set[str]:
    engine = create_engine(url)
    try:
        return {c["name"] for c in inspect(engine).get_columns(table)}
    finally:
        engine.dispose()


# ---------------------------------------------------------------------------
# Detection
# ---------------------------------------------------------------------------


def test_detects_a_database_that_predates_alembic(tmp_path):
    from core.database import _needs_baseline_stamp

    url = _create_all_database(tmp_path / "legacy.db")
    engine = create_engine(url)
    try:
        with engine.connect() as conn:
            assert _needs_baseline_stamp(conn) is True
    finally:
        engine.dispose()


def test_does_not_stamp_an_empty_database(tmp_path):
    """A fresh install must run the migrations, not skip past them."""
    from core.database import _needs_baseline_stamp

    engine = create_engine(f"sqlite:///{tmp_path / 'empty.db'}")
    try:
        with engine.connect() as conn:
            assert _needs_baseline_stamp(conn) is False
    finally:
        engine.dispose()


def test_does_not_stamp_a_database_alembic_already_manages(tmp_path):
    from core.database import _needs_baseline_stamp

    url = f"sqlite:///{tmp_path / 'managed.db'}"
    command.upgrade(_config(url), "head")

    engine = create_engine(url)
    try:
        with engine.connect() as conn:
            assert _needs_baseline_stamp(conn) is False
    finally:
        engine.dispose()


# ---------------------------------------------------------------------------
# Adoption end to end
# ---------------------------------------------------------------------------


def test_stamping_then_upgrading_adopts_a_legacy_database(tmp_path):
    """The path a real pre-Alembic database takes on the next boot."""
    db = tmp_path / "adopt.db"
    url = _create_all_database(db)

    # Simulate the genuinely-old shape: no is_admin yet.
    engine = create_engine(url)
    with engine.begin() as conn:
        conn.execute(text("ALTER TABLE users DROP COLUMN is_admin"))
    engine.dispose()
    assert "is_admin" not in _columns(url, "users")

    command.stamp(_config(url), "0001_baseline")
    command.upgrade(_config(url), "head")

    assert "is_admin" in _columns(url, "users")
    assert "alembic_version" in _tables(url)


def test_adoption_is_idempotent_when_the_schema_is_already_current(tmp_path):
    """The other real shape: a database created by create_all from a recent
    checkout, so it has every column AND no migration history. Adding a
    column that is already there raises DuplicateColumn and, on Postgres,
    poisons the transaction — so the revision has to tolerate it."""
    url = _create_all_database(tmp_path / "current.db")
    assert "is_admin" in _columns(url, "users")

    command.stamp(_config(url), "0001_baseline")
    command.upgrade(_config(url), "head")  # must not raise

    assert "is_admin" in _columns(url, "users")


def test_upgrade_twice_is_a_no_op(tmp_path):
    url = f"sqlite:///{tmp_path / 'twice.db'}"
    command.upgrade(_config(url), "head")
    command.upgrade(_config(url), "head")  # must not raise

    assert "users" in _tables(url)


def test_existing_rows_survive_adoption(tmp_path):
    """Adoption must never be destructive — it is running against the only
    copy of someone's data."""
    import uuid

    db = tmp_path / "data.db"
    url = _create_all_database(db)

    engine = create_engine(url)
    with engine.begin() as conn:
        conn.execute(text("ALTER TABLE users DROP COLUMN is_admin"))
        conn.execute(
            text(
                "INSERT INTO users (id, email, hashed_password, is_active,"
                " token_epoch, default_permission_tier, rate_limit,"
                " llm_provider, llm_model, memory_enabled, created_at,"
                " updated_at) VALUES (:i, :e, 'hash', 1, 0, 'user_confirm',"
                " 60, 'anthropic', 'm', 1, '2026-01-01', '2026-01-01')"
            ),
            {"i": str(uuid.uuid4()), "e": "keeper@example.com"},
        )
    engine.dispose()

    command.stamp(_config(url), "0001_baseline")
    command.upgrade(_config(url), "head")

    engine = create_engine(url)
    try:
        with engine.connect() as conn:
            rows = conn.execute(text("SELECT email FROM users")).fetchall()
    finally:
        engine.dispose()
    assert [r[0] for r in rows] == ["keeper@example.com"]


@pytest.mark.parametrize("revision", ["0001_baseline", "head"])
def test_downgrade_still_works_after_adoption(tmp_path, revision):
    """A stamped database must still be a normal Alembic database."""
    url = _create_all_database(tmp_path / f"down-{revision}.db")
    command.stamp(_config(url), "0001_baseline")
    command.upgrade(_config(url), "head")

    command.downgrade(_config(url), "base")
    assert "users" not in _tables(url)


# ---------------------------------------------------------------------------
# The real startup path
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_init_db_adopts_a_legacy_database_without_operator_action(
    tmp_path, monkeypatch
):
    """The regression this whole module exists for.

    Startup itself must adopt a pre-Alembic database. If it only *upgrades*,
    the baseline runs against a schema that already exists and every boot
    fails the same way — the app comes up with no database and answers
    "Internal Server Error" to everything, with nothing in the UI pointing
    at the cause.
    """
    from sqlalchemy.ext.asyncio import create_async_engine

    import core.database as database

    db = tmp_path / "startup.db"
    sync_url = _create_all_database(db)
    async_url = f"sqlite+aiosqlite:///{db}"

    engine = create_async_engine(async_url)
    monkeypatch.setattr(database, "engine", engine)
    monkeypatch.setattr(database.settings, "DATABASE_URL", async_url)

    assert "alembic_version" not in _tables(sync_url)
    try:
        await database.init_db(retries=1)
    finally:
        await engine.dispose()

    assert "alembic_version" in _tables(sync_url), (
        "startup left the database unmanaged; the next boot repeats the "
        "failure instead of adopting it"
    )


@pytest.mark.asyncio
async def test_init_db_still_builds_a_fresh_database(tmp_path, monkeypatch):
    """Adoption must not short-circuit a genuine first install."""
    from sqlalchemy.ext.asyncio import create_async_engine

    import core.database as database

    db = tmp_path / "fresh.db"
    async_url = f"sqlite+aiosqlite:///{db}"
    engine = create_async_engine(async_url)
    monkeypatch.setattr(database, "engine", engine)
    monkeypatch.setattr(database.settings, "DATABASE_URL", async_url)

    try:
        await database.init_db(retries=1)
    finally:
        await engine.dispose()

    tables = _tables(f"sqlite:///{db}")
    assert {"users", "conversations", "audit_logs", "alembic_version"} <= tables
