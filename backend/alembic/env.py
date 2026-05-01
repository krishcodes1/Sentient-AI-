"""Alembic environment for SentientAI.

The application uses ``sqlalchemy.ext.asyncio.create_async_engine``,
so the online migration path runs inside ``asyncio.run`` and uses
``connection.run_sync`` to bridge the sync Alembic API.

The database URL is read from the ``DATABASE_URL`` environment variable,
falling back to ``core.config.settings`` for development convenience.
"""

from __future__ import annotations

import asyncio
import os
import sys
from logging.config import fileConfig
from pathlib import Path

from sqlalchemy import pool
from sqlalchemy.engine import Connection
from sqlalchemy.ext.asyncio import async_engine_from_config

from alembic import context

# ──────────────────────────────────────────────────────────────────────────────
# Make the project importable so ``core``/``models`` resolve the same way
# they do at runtime, regardless of where ``alembic`` is invoked from.
# ──────────────────────────────────────────────────────────────────────────────
BACKEND_DIR = Path(__file__).resolve().parent.parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from core.config import settings  # noqa: E402
from core.database import Base  # noqa: E402
import models  # noqa: F401, E402  -- side-effect: register all tables on Base.metadata


# ──────────────────────────────────────────────────────────────────────────────
# Alembic Config
# ──────────────────────────────────────────────────────────────────────────────
config = context.config

# Set up loggers from alembic.ini, but only if the file actually defines them.
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

# Resolve the database URL: env var wins, then pydantic-settings default.
database_url = os.environ.get("DATABASE_URL") or settings.DATABASE_URL
config.set_main_option("sqlalchemy.url", database_url)

target_metadata = Base.metadata


# ──────────────────────────────────────────────────────────────────────────────
# Offline migrations — emit SQL without a live connection.
# ──────────────────────────────────────────────────────────────────────────────
def run_migrations_offline() -> None:
    """Run migrations in 'offline' mode.

    Configures the context with just a URL (no Engine), so calls to
    ``context.execute()`` emit the given string to the script output.
    """
    url = config.get_main_option("sqlalchemy.url")
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        compare_type=True,
        compare_server_default=True,
    )

    with context.begin_transaction():
        context.run_migrations()


# ──────────────────────────────────────────────────────────────────────────────
# Online migrations — async-aware.
# ──────────────────────────────────────────────────────────────────────────────
def do_run_migrations(connection: Connection) -> None:
    """Bridge sync Alembic API onto an async connection via ``run_sync``."""
    context.configure(
        connection=connection,
        target_metadata=target_metadata,
        compare_type=True,
        compare_server_default=True,
    )

    with context.begin_transaction():
        context.run_migrations()


async def run_async_migrations() -> None:
    """Create an async engine and run migrations in a transactional context."""
    connectable = async_engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )

    async with connectable.connect() as connection:
        await connection.run_sync(do_run_migrations)

    await connectable.dispose()


def run_migrations_online() -> None:
    """Entry point for online migrations — schedules the async runner."""
    asyncio.run(run_async_migrations())


# ──────────────────────────────────────────────────────────────────────────────
# Dispatch
# ──────────────────────────────────────────────────────────────────────────────
if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
