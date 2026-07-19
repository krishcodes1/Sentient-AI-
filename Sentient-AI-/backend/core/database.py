from __future__ import annotations

import asyncio
from collections.abc import AsyncGenerator

import structlog
from sqlalchemy.ext.asyncio import (
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.orm import DeclarativeBase

from core.config import settings

logger = structlog.get_logger(__name__)

engine = create_async_engine(
    settings.DATABASE_URL,
    echo=(settings.ENVIRONMENT == "development"),
    pool_size=20,
    max_overflow=10,
    pool_pre_ping=True,
    pool_recycle=300,
)

async_session = async_sessionmaker(
    bind=engine,
    class_=AsyncSession,
    expire_on_commit=False,
)


class Base(DeclarativeBase):
    """Declarative base for all ORM models."""


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """FastAPI dependency that yields an async database session."""
    async with async_session() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise


async def init_db(retries: int = 10, delay: float = 2.0) -> None:
    """Create all tables that don't yet exist, and run inline additive
    migrations (development convenience; production should use Alembic).

    Retries while the database is still coming up. Postgres' ``pg_isready``
    healthcheck can report ready a moment before it accepts password-
    authenticated TCP connections, so a fresh ``docker compose up`` would
    otherwise lose the race and start the API without a database on first boot.
    """
    from sqlalchemy import text

    # SQLAlchemy's create_all() only creates new tables, it does not add
    # columns to existing ones. ``ADD COLUMN IF NOT EXISTS`` is idempotent on
    # Postgres so this is safe to run on every startup. NOT NULL columns
    # include a DEFAULT so existing rows backfill cleanly.
    migrations = [
        "ALTER TABLE audit_logs ADD COLUMN IF NOT EXISTS previous_hash VARCHAR(64)",
        # New connector kind for MCP servers (PG 12+ allows ADD VALUE in a
        # transaction as long as the value isn't used in the same one).
        "ALTER TYPE connector_type ADD VALUE IF NOT EXISTS 'mcp'",
        "ALTER TABLE users ADD COLUMN IF NOT EXISTS name VARCHAR(255)",
        "ALTER TABLE users ADD COLUMN IF NOT EXISTS default_permission_tier VARCHAR(32) NOT NULL DEFAULT 'user_confirm'",
        "ALTER TABLE users ADD COLUMN IF NOT EXISTS rate_limit INTEGER NOT NULL DEFAULT 60",
        "ALTER TABLE users ADD COLUMN IF NOT EXISTS llm_provider VARCHAR(32) NOT NULL DEFAULT 'anthropic'",
        "ALTER TABLE users ADD COLUMN IF NOT EXISTS llm_model VARCHAR(128) NOT NULL DEFAULT 'claude-sonnet-4-20250514'",
    ]

    # Accounts still on the historical hardcoded provider default never chose
    # it (choosing in Settings had no effect until per-user providers were
    # wired), so move them to the provider this server actually runs. Values
    # come from admin config; validate anyway since they are inlined into SQL.
    import re

    from core.config import settings

    if (settings.LLM_PROVIDER, settings.LLM_MODEL) != (
        "anthropic",
        "claude-sonnet-4-20250514",
    ) and all(
        re.fullmatch(r"[A-Za-z0-9._:-]+", v)
        for v in (settings.LLM_PROVIDER, settings.LLM_MODEL)
    ):
        migrations.append(
            "UPDATE users SET "
            f"llm_provider = '{settings.LLM_PROVIDER}', "
            f"llm_model = '{settings.LLM_MODEL}' "
            "WHERE llm_provider = 'anthropic' "
            "AND llm_model = 'claude-sonnet-4-20250514'"
        )

    last_exc: Exception | None = None
    for attempt in range(1, retries + 1):
        try:
            async with engine.begin() as conn:
                await conn.run_sync(Base.metadata.create_all)
            # The additive migrations use Postgres-specific syntax. Each one
            # runs in its own transaction and failures are tolerated: on a
            # fresh database (any backend) create_all already produced the
            # current schema, so a failed ALTER means there is nothing to do.
            for statement in migrations:
                try:
                    async with engine.begin() as conn:
                        await conn.execute(text(statement))
                except Exception as exc:
                    logger.debug(
                        "inline_migration_skipped",
                        statement=statement,
                        error=str(exc),
                    )
            if attempt > 1:
                logger.info("database_ready_after_retry", attempts=attempt)
            return
        except Exception as exc:  # retry on any connection/auth error
            last_exc = exc
            logger.warning(
                "database_not_ready",
                attempt=attempt,
                max_attempts=retries,
                error=str(exc),
            )
            if attempt < retries:
                await asyncio.sleep(delay)

    # Exhausted all retries — re-raise so the lifespan handler can log and
    # decide whether to start in degraded (no-database) mode.
    assert last_exc is not None
    raise last_exc
