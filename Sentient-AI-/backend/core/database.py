from __future__ import annotations

import asyncio
from collections.abc import AsyncGenerator
from pathlib import Path
from typing import TYPE_CHECKING, Any, Optional

import structlog
from sqlalchemy.ext.asyncio import (
    AsyncConnection,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.orm import DeclarativeBase

from core.config import settings

if TYPE_CHECKING:
    from alembic.config import Config

logger = structlog.get_logger(__name__)

# The first revision. A database that predates Alembic is stamped with
# this so `upgrade head` applies only what came after it.
_BASELINE_REVISION = "0001_baseline"

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


def _alembic_config() -> "Config":
    from alembic.config import Config

    cfg = Config(str(Path(__file__).resolve().parents[1] / "alembic.ini"))
    # The .ini's script_location is relative to the backend directory; make
    # it absolute so migrations work regardless of the process's cwd.
    cfg.set_main_option(
        "script_location",
        str(Path(__file__).resolve().parents[1] / "alembic"),
    )
    # The app's configured database, never a second URL that could drift.
    cfg.attributes["sqlalchemy_url"] = settings.DATABASE_URL
    cfg.attributes["configure_logger"] = False
    return cfg


def _needs_baseline_stamp(sync_connection: Any) -> bool:
    """True when this database predates Alembic and must be stamped first.

    A database created before migrations existed already has every table
    but no ``alembic_version`` row, so ``upgrade head`` starts at the
    baseline and immediately fails on ``CREATE TABLE users``. On Postgres
    that aborts the transaction, so it fails identically on every restart
    and the app never serves a request — which is the whole database
    silently unavailable, from the operator's point of view.

    Requiring a human to run ``alembic stamp`` first is a footgun: nothing
    warns you until the app is down. The condition is trivially
    detectable, so detect it.
    """
    from sqlalchemy import inspect

    inspector = inspect(sync_connection)
    tables = set(inspector.get_table_names())
    if "alembic_version" in tables:
        return False
    # "users" is the anchor: it exists in the baseline and in every
    # pre-Alembic database. An empty database is a fresh install and must
    # run the migrations normally, not be stamped past them.
    return "users" in tables


def _run_alembic_upgrade() -> None:
    """Bring the database to the latest revision.

    Synchronous on purpose: alembic's entry point owns an event loop of its
    own (env.py calls asyncio.run), so this must never be awaited directly
    from the running loop — callers use asyncio.to_thread.
    """
    from alembic import command

    cfg = _alembic_config()
    command.upgrade(cfg, "head")


def _stamp_baseline() -> None:
    """Record the baseline as already applied, without running it."""
    from alembic import command

    command.stamp(_alembic_config(), _BASELINE_REVISION)


# The provider/model every account was created with before the server's own
# configuration was consulted (the old column server default).
_LEGACY_LLM_PAIR = ("anthropic", "claude-sonnet-4-20250514")


async def backfill_user_llm_defaults(
    conn: AsyncConnection, provider: Optional[str], model: Optional[str]
) -> None:
    """Turn inherited provider/model pairs into NULL ("follow the install").

    Accounts used to be stamped at registration with the provider/model the
    server ran that day, so a row that still holds the server's CURRENT
    default pair almost always inherited it rather than chose it. Setting
    it to NULL lets the account follow the install from now on — including
    a provider the owner configures later through the setup wizard, which
    a stamped row would never have reached.

    Rows still on the historical hardcoded default are included only when
    their ``updated_at`` equals ``created_at``: that account never touched
    Settings, so it never chose the pair (anyone who did may have picked it
    on purpose).

    Values are bound parameters, never inlined into the SQL. Comparison is
    case- and whitespace-insensitive on the provider, whitespace-insensitive
    on the model. Idempotent; ``updated_at`` is left alone, because this is
    not the user changing anything.
    """
    from sqlalchemy import text

    provider = (provider or "").strip().lower()
    model = (model or "").strip()
    if provider and model:
        await conn.execute(
            text(
                "UPDATE users SET llm_provider = NULL, llm_model = NULL "
                "WHERE LOWER(TRIM(llm_provider)) = :provider "
                "AND TRIM(llm_model) = :model"
            ),
            {"provider": provider, "model": model},
        )
    await conn.execute(
        text(
            "UPDATE users SET llm_provider = NULL, llm_model = NULL "
            "WHERE llm_provider = :provider AND llm_model = :model "
            "AND updated_at = created_at"
        ),
        {"provider": _LEGACY_LLM_PAIR[0], "model": _LEGACY_LLM_PAIR[1]},
    )


async def init_db(retries: int = 10, delay: float = 2.0) -> None:
    """Wait for the database, migrate it to head, then apply data fixes.

    Schema is owned entirely by Alembic (backend/alembic/versions). Running
    the upgrade here keeps a single-worker deployment and a bare
    ``uvicorn main:app`` dev run working with no extra step; the container
    CMD also runs it before the server starts, which is the path that
    matters for a multi-worker deploy (two workers racing the same
    migration is the thing to avoid — see alembic/README.md).

    Retries while the database is still coming up. Postgres' ``pg_isready``
    healthcheck can report ready a moment before it accepts password-
    authenticated TCP connections, so a fresh ``docker compose up`` would
    otherwise lose the race and start the API without a database on first boot.
    """
    from sqlalchemy import text

    last_exc: Exception | None = None
    for attempt in range(1, retries + 1):
        try:
            # Connectivity probe first, so a database that is still booting
            # is retried here rather than surfacing as a migration failure.
            # The same connection adopts a pre-Alembic database, which has
            # to happen before any upgrade is attempted.
            async with engine.begin() as conn:
                await conn.execute(text("SELECT 1"))
                needs_stamp = await conn.run_sync(_needs_baseline_stamp)

            if needs_stamp:
                logger.info("database_predates_alembic_stamping_baseline")
                await asyncio.to_thread(_stamp_baseline)

            # Alembic owns the schema. Run in a worker thread: the alembic
            # env drives its own event loop, which cannot be started from
            # inside this one.
            await asyncio.to_thread(_run_alembic_upgrade)
            logger.info("database_schema_at_head")

            # Data fix, after the schema allows NULL (0009): accounts that
            # merely inherited the server's provider/model follow the
            # install default instead. It stays here rather than in the
            # migration because the target pair is runtime configuration,
            # not static DDL (an offline `alembic upgrade --sql` would bake
            # in whatever environment generated the script).
            async with engine.begin() as conn:
                await backfill_user_llm_defaults(
                    conn, settings.LLM_PROVIDER, settings.LLM_MODEL
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
