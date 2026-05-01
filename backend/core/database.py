from __future__ import annotations

import os
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
    pool_size=10,
    max_overflow=20,
    pool_pre_ping=True,
    pool_recycle=1800,
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
    """Deprecated stub — schema is managed by Alembic.

    Schema creation/migration used to live here as ``Base.metadata.create_all``
    plus ad-hoc ``ALTER TABLE`` strings. That has been replaced by Alembic.

    Run ``alembic upgrade head`` (or ``./scripts/migrate.sh``) to apply
    pending migrations. In development you can also set ``AUTO_MIGRATE=true``
    to have ``main.py`` invoke the upgrade on startup.
    """
    if os.environ.get("ENVIRONMENT", settings.ENVIRONMENT) != "development":
        raise RuntimeError(
            "init_db is deprecated; use 'alembic upgrade head'"
        )
    raise RuntimeError(
        "init_db is deprecated; use 'alembic upgrade head'"
    )
