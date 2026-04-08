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
    """Create tables and migrate missing columns for development convenience."""
    from sqlalchemy import text

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

        # Add columns that may be missing on an existing users table.
        # Each is wrapped in a try/except so it's safe to re-run.
        migrations = [
            "ALTER TABLE users ADD COLUMN IF NOT EXISTS name VARCHAR(256)",
            "ALTER TABLE users ADD COLUMN IF NOT EXISTS llm_provider VARCHAR(32) NOT NULL DEFAULT 'openai'",
            "ALTER TABLE users ADD COLUMN IF NOT EXISTS llm_model VARCHAR(128) NOT NULL DEFAULT 'gpt-4o'",
            "ALTER TABLE users ADD COLUMN IF NOT EXISTS llm_api_key_enc BYTEA",
            "ALTER TABLE users ADD COLUMN IF NOT EXISTS onboarding_completed BOOLEAN NOT NULL DEFAULT false",
        ]
        for stmt in migrations:
            try:
                await conn.execute(text(stmt))
            except Exception:
                pass
