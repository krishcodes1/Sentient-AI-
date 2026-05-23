from __future__ import annotations

from collections.abc import AsyncGenerator

from sqlalchemy.ext.asyncio import (
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.orm import DeclarativeBase

from core.config import settings

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


async def init_db() -> None:
    """Create all tables that don't yet exist, and run inline additive
    migrations (development convenience; production should use Alembic).
    """
    from sqlalchemy import text

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

        # SQLAlchemy's create_all() only creates new tables, it does
        # not add columns to existing ones. ``ADD COLUMN IF NOT EXISTS``
        # is idempotent on Postgres so this is safe to run on every
        # startup. NOT NULL columns include a DEFAULT so existing rows
        # backfill cleanly.
        migrations = [
            "ALTER TABLE audit_logs ADD COLUMN IF NOT EXISTS previous_hash VARCHAR(64)",
            "ALTER TABLE users ADD COLUMN IF NOT EXISTS name VARCHAR(255)",
            "ALTER TABLE users ADD COLUMN IF NOT EXISTS default_permission_tier VARCHAR(32) NOT NULL DEFAULT 'user_confirm'",
            "ALTER TABLE users ADD COLUMN IF NOT EXISTS rate_limit INTEGER NOT NULL DEFAULT 60",
            "ALTER TABLE users ADD COLUMN IF NOT EXISTS llm_provider VARCHAR(32) NOT NULL DEFAULT 'anthropic'",
            "ALTER TABLE users ADD COLUMN IF NOT EXISTS llm_model VARCHAR(128) NOT NULL DEFAULT 'claude-sonnet-4-20250514'",
        ]
        for statement in migrations:
            await conn.execute(text(statement))
