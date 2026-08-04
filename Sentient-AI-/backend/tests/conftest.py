"""Test setup. Sets dummy env vars before any project modules import,
because core.config.Settings is instantiated at import time and requires
SECRET_KEY and ENCRYPTION_KEY.

Also provides the shared integration harness: an in-memory SQLite
database (the models use portable column types), a session factory, an
httpx client wired to the FastAPI app with the DB dependency overridden,
and helpers to mint users + JWTs.
"""

from __future__ import annotations

import base64
import os
import secrets
import uuid

os.environ.setdefault("SECRET_KEY", secrets.token_urlsafe(48))
os.environ.setdefault(
    "ENCRYPTION_KEY",
    base64.urlsafe_b64encode(os.urandom(32)).decode("utf-8"),
)
# Use an asyncpg URL (driver ships in requirements.txt). Engine creation
# is lazy so this never actually connects during import; it just lets
# modules that import core.database load without needing the aiosqlite
# driver.
os.environ.setdefault(
    "DATABASE_URL",
    "postgresql+asyncpg://test:test@localhost:5432/test",
)
os.environ.setdefault("REDIS_URL", "redis://localhost:6379/0")
os.environ.setdefault("LLM_PROVIDER", "anthropic")
os.environ.setdefault("LLM_MODEL", "claude-sonnet-4-6")
# Lets AgentRuntime construct its provider in tests; never used for real
# calls (tests patch the provider with fakes).
os.environ.setdefault("ANTHROPIC_API_KEY", "test-key-not-real")
# The developer's local .env may restrict these (they are real Settings
# fields now); env vars outrank the .env file, so tests always see an
# unrestricted host list and the stock password policy.
os.environ["ALLOWED_HOSTS"] = '["*"]'
os.environ["PASSWORD_MIN_LENGTH"] = "8"
os.environ["ALLOW_REGISTRATION"] = "true"

import httpx  # noqa: E402
import pytest_asyncio  # noqa: E402
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine  # noqa: E402
from sqlalchemy.pool import StaticPool  # noqa: E402


@pytest_asyncio.fixture
async def session_factory():
    """Test database with all tables created.

    Defaults to in-memory SQLite. Set TEST_DATABASE_URL to an asyncpg URL
    to run the suite against real Postgres (the backend-postgres CI job
    does) — otherwise Postgres-only behavior would first execute in
    production. Each test gets a freshly created schema; Postgres runs
    drop_all around it for isolation.
    """
    import models  # noqa: F401 — registers every model on Base.metadata
    from core.database import Base

    test_url = os.environ.get("TEST_DATABASE_URL", "")
    if test_url:
        engine = create_async_engine(test_url)
    else:
        engine = create_async_engine(
            "sqlite+aiosqlite://",
            connect_args={"check_same_thread": False},
            poolclass=StaticPool,
        )
    async with engine.begin() as conn:
        if test_url:
            # Clean slate even after an aborted previous run.
            await conn.run_sync(Base.metadata.drop_all)
        await conn.run_sync(Base.metadata.create_all)

    factory = async_sessionmaker(bind=engine, expire_on_commit=False)
    yield factory
    if test_url:
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.drop_all)
    await engine.dispose()


@pytest_asyncio.fixture
async def client(session_factory):
    """httpx client against the real app with get_db overridden.

    Each client gets a unique X-Forwarded-For so the in-memory rate
    limiter buckets never bleed between tests.
    """
    from core.database import get_db
    from main import app

    async def _override_get_db():
        async with session_factory() as session:
            try:
                yield session
                await session.commit()
            except Exception:
                await session.rollback()
                raise

    app.dependency_overrides[get_db] = _override_get_db

    # Give each client a unique *peer* IP (the ASGI scope's client host), so
    # rate-limit buckets never bleed between tests regardless of the
    # TRUSTED_PROXIES setting. Relying on X-Forwarded-For for isolation only
    # works when the peer is a trusted proxy; a distinct peer is faithful to
    # "these are different external clients" and independent of that config.
    fake_ip = f"198.51.100.{uuid.uuid4().int % 254 + 1}"
    transport = httpx.ASGITransport(app=app, client=(fake_ip, 54321))
    async with httpx.AsyncClient(
        transport=transport,
        base_url="http://testserver",
        headers={"X-Forwarded-For": fake_ip},
    ) as http_client:
        yield http_client

    app.dependency_overrides.clear()


async def make_user(session_factory, email: str = "user@example.com"):
    """Create a user directly in the DB and return (user, bearer_token)."""
    from core.security import create_access_token, hash_password
    from models.user import User

    async with session_factory() as session:
        user = User(email=email, hashed_password=hash_password("password-123"))
        session.add(user)
        await session.flush()
        await session.refresh(user)
        await session.commit()

    token = create_access_token({"sub": str(user.id), "email": user.email})
    return user, token


def auth_headers(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}
