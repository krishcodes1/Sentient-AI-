"""Alembic entry point that runs migrations through the app's own async engine
and settings.

Why it exists: Alembic needs a script that supplies the database URL and
``Base.metadata``; using ``core.config.settings`` and importing ``models`` here
means a migration can never target a different database than the API, and
autogenerate sees every table.

Alembic environment for the Crawler AI backend.

The application runs on an async engine (asyncpg), so migrations connect
through that same stack instead of maintaining a second sync-driver URL:
one URL, one driver, one place credentials live. The URL is read from
``core.config.settings`` — the very object the app uses — so a migration
can never target a different database than the one the API will open.

Every model module is imported here so ``Base.metadata`` is complete;
autogenerate compares against whatever is registered at import time, and a
model that nobody imported silently becomes a table nobody migrates.
"""

from __future__ import annotations

import asyncio
import sys
from logging.config import fileConfig
from pathlib import Path

from alembic import context
from sqlalchemy import pool
from sqlalchemy.engine import Connection
from sqlalchemy.ext.asyncio import create_async_engine

# `alembic upgrade head` is normally run from backend/, but the migration
# regression test drives alembic programmatically from pytest's cwd. Putting
# backend/ on sys.path from this file's own location makes `core` and
# `models` importable regardless of how alembic was invoked.
BACKEND_DIR = Path(__file__).resolve().parents[1]
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

import models  # noqa: E402,F401 — registers every model on Base.metadata
from core.config import settings  # noqa: E402
from core.database import Base  # noqa: E402

config = context.config

# Programmatic callers own their own logging; only the CLI wants alembic to
# install handlers. `disable_existing_loggers=False` keeps structlog's
# configuration intact either way.
if config.config_file_name is not None and config.attributes.get(
    "configure_logger", True
):
    fileConfig(config.config_file_name, disable_existing_loggers=False)

target_metadata = Base.metadata


def _database_url() -> str:
    """Resolve the database to migrate.

    Precedence: a URL injected programmatically (the test suite points
    migrations at a throwaway SQLite file), then an explicit operator
    override in alembic.ini, then the application setting. Production always
    falls through to the last one, so credentials stay in the environment.
    """
    return (
        config.attributes.get("sqlalchemy_url")
        or config.get_main_option("sqlalchemy.url")
        or settings.DATABASE_URL
    )


def run_migrations_offline() -> None:
    """Emit SQL to stdout instead of executing it (``alembic upgrade --sql``).

    Useful when a DBA has to review or hand-apply the change set.
    """
    context.configure(
        url=_database_url(),
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        compare_type=True,
    )

    with context.begin_transaction():
        context.run_migrations()


def _run_migrations(connection: Connection) -> None:
    """Body of an online run, executed on a sync-style connection."""
    context.configure(
        connection=connection,
        target_metadata=target_metadata,
        # Column type drift (VARCHAR(32) -> VARCHAR(64)) is exactly the kind
        # of change the old inline-ALTER list could never express, so let
        # autogenerate see it.
        compare_type=True,
    )

    with context.begin_transaction():
        context.run_migrations()


async def _run_async_migrations() -> None:
    connectable = create_async_engine(_database_url(), poolclass=pool.NullPool)
    try:
        async with connectable.connect() as connection:
            await connection.run_sync(_run_migrations)
    finally:
        await connectable.dispose()


def run_migrations_online() -> None:
    """Open the async engine and run migrations against a live connection.

    Alembic's entry point is synchronous, so ``asyncio.run`` owns the loop
    for the duration. Callers already inside a running loop must therefore
    invoke the alembic command API from a worker thread.
    """
    asyncio.run(_run_async_migrations())


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
