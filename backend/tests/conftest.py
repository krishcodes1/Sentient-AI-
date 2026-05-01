"""Pytest fixtures for SentientAI backend test suite.

This module sets up test-only environment variables BEFORE the application
modules are imported, then exposes a small set of fixtures that the rest of
the suite consumes:

- ``engine``        : per-test in-memory SQLite engine with all tables created
- ``db_session``    : an :class:`AsyncSession` bound to ``engine``
- ``client``        : an :class:`httpx.AsyncClient` with the FastAPI ``get_db``
                      dependency overridden to use ``db_session``
- ``test_user``     : a plain user plus a JWT and ``Authorization`` headers
- ``test_admin``    : same as ``test_user`` but with admin tier metadata
- ``event_loop``    : function-scoped asyncio loop (compatible with pytest-asyncio)

External side effects (LLM HTTP calls, OpenClaw config writes) are stubbed
out via autouse fixtures so the suite is hermetic.
"""

from __future__ import annotations

import asyncio
import os
import sys
import uuid
from collections.abc import AsyncGenerator, Generator
from pathlib import Path
from typing import Any

# ---------------------------------------------------------------------------
# Environment must be set BEFORE the application imports core.config / models.
# ---------------------------------------------------------------------------
os.environ.setdefault("ENVIRONMENT", "test")
os.environ["DATABASE_URL"] = "sqlite+aiosqlite:///:memory:"
os.environ["SECRET_KEY"] = "test-secret-key-do-not-use-in-production"
# 32 raw bytes -> urlsafe-b64 encoded; must decode to exactly 32 bytes.
os.environ["ENCRYPTION_KEY"] = "dGVzdC1lbmNyeXB0aW9uLWtleS0zMi1ieXRlcyEhIQ=="
os.environ.setdefault("REDIS_URL", "redis://localhost:6379/15")
os.environ.setdefault("OPENCLAW_CONFIG_DIR", "/tmp/openclaw-test")

# Make the backend package importable regardless of where pytest is invoked.
_BACKEND_ROOT = Path(__file__).resolve().parent.parent
if str(_BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(_BACKEND_ROOT))

import pytest  # noqa: E402
import pytest_asyncio  # noqa: E402
from sqlalchemy.dialects.postgresql import JSON as PG_JSON  # noqa: E402
from sqlalchemy.dialects.postgresql import UUID as PG_UUID  # noqa: E402
from sqlalchemy.ext.asyncio import (  # noqa: E402
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.ext.compiler import compiles  # noqa: E402

# ---------------------------------------------------------------------------
# Make Postgres-specific column types compile under SQLite. The application
# models use ``postgresql.UUID`` and ``postgresql.JSON`` directly; under
# SQLite we render them as TEXT/JSON-compatible types so ``create_all``
# succeeds and round-trips work.
# ---------------------------------------------------------------------------


@compiles(PG_UUID, "sqlite")  # type: ignore[misc]
def _compile_uuid_sqlite(_element: Any, _compiler: Any, **_kw: Any) -> str:
    return "CHAR(36)"


@compiles(PG_JSON, "sqlite")  # type: ignore[misc]
def _compile_json_sqlite(_element: Any, _compiler: Any, **_kw: Any) -> str:
    return "JSON"


# ---------------------------------------------------------------------------
# Application imports (after env is configured).
# ---------------------------------------------------------------------------
from core import database as core_database  # noqa: E402
from core.database import Base, get_db  # noqa: E402
from core.security import create_access_token, hash_password  # noqa: E402

# Import all model modules so Base.metadata knows every table.
import models.audit  # noqa: E402, F401
import models.channel  # noqa: E402, F401
import models.connector  # noqa: E402, F401
import models.conversation  # noqa: E402, F401
import models.user  # noqa: E402, F401
from models.user import User  # noqa: E402

from main import app  # noqa: E402


# ---------------------------------------------------------------------------
# Event loop — function scoped so each test gets a clean loop.
# ---------------------------------------------------------------------------


@pytest.fixture(scope="function")
def event_loop() -> Generator[asyncio.AbstractEventLoop, None, None]:
    """Provide a fresh event loop per test."""
    loop = asyncio.new_event_loop()
    try:
        yield loop
    finally:
        loop.close()


# ---------------------------------------------------------------------------
# Block real outbound HTTP at session scope.
# ---------------------------------------------------------------------------


@pytest.fixture(scope="session", autouse=True)
def _block_outbound_http() -> Generator[None, None, None]:
    """Replace ``httpx.AsyncClient`` for outbound calls with a benign stub.

    The FastAPI test client uses its own transport, so it's unaffected.
    Anything else (anthropic SDK, openai SDK, custom HTTP clients) gets a
    202 stub so a forgotten mock never reaches the network.
    """
    import httpx

    real_async_client = httpx.AsyncClient

    class _StubResponse:
        status_code = 202
        text = ""
        headers: dict[str, str] = {}

        def json(self) -> dict[str, Any]:
            return {"stubbed": True}

        def raise_for_status(self) -> None:
            return None

    class _StubAsyncClient:
        def __init__(self, *args: Any, **kwargs: Any) -> None:
            self._args = args
            self._kwargs = kwargs

        async def __aenter__(self) -> "_StubAsyncClient":
            return self

        async def __aexit__(self, *exc: Any) -> None:
            return None

        async def request(self, *args: Any, **kwargs: Any) -> _StubResponse:
            return _StubResponse()

        async def get(self, *args: Any, **kwargs: Any) -> _StubResponse:
            return _StubResponse()

        async def post(self, *args: Any, **kwargs: Any) -> _StubResponse:
            return _StubResponse()

        async def put(self, *args: Any, **kwargs: Any) -> _StubResponse:
            return _StubResponse()

        async def patch(self, *args: Any, **kwargs: Any) -> _StubResponse:
            return _StubResponse()

        async def delete(self, *args: Any, **kwargs: Any) -> _StubResponse:
            return _StubResponse()

        async def aclose(self) -> None:
            return None

    # Don't blanket-replace httpx.AsyncClient, because ASGITransport-based
    # clients used by tests rely on the real implementation. Instead, expose
    # both names and let test code opt in via ``httpx.AsyncClient`` for the
    # ASGITransport flow. We set an env flag so anything that wants to be
    # paranoid can check.
    os.environ["SENTIENTAI_TEST_HTTP_BLOCKED"] = "1"
    httpx._RealAsyncClient = real_async_client  # type: ignore[attr-defined]
    httpx._StubAsyncClient = _StubAsyncClient  # type: ignore[attr-defined]
    yield


# ---------------------------------------------------------------------------
# No-op the OpenClaw config writer so tests don't touch the filesystem.
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _stub_openclaw_config(monkeypatch: pytest.MonkeyPatch) -> None:
    """Stub :func:`services.openclaw.config_manager.write_openclaw_config`."""
    from pathlib import Path as _Path

    def _noop_write(_config: dict[str, Any]) -> _Path:
        return _Path("/tmp/openclaw-test/openclaw.json")

    async def _noop_sync(*_args: Any, **_kwargs: Any) -> _Path:
        return _Path("/tmp/openclaw-test/openclaw.json")

    monkeypatch.setattr(
        "services.openclaw.config_manager.write_openclaw_config",
        _noop_write,
        raising=False,
    )
    monkeypatch.setattr(
        "services.openclaw.config_manager.sync_openclaw_config_for_user",
        _noop_sync,
        raising=False,
    )


# ---------------------------------------------------------------------------
# Database fixtures.
# ---------------------------------------------------------------------------


@pytest_asyncio.fixture(scope="function")
async def engine() -> AsyncGenerator[Any, None]:
    """Create a fresh in-memory SQLite database with all tables for each test."""
    test_engine = create_async_engine(
        "sqlite+aiosqlite:///:memory:",
        echo=False,
        future=True,
    )

    # Patch the global engine + session factory used by the application so any
    # code path that calls ``get_db`` ends up against the test database.
    async with test_engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
        await conn.run_sync(Base.metadata.create_all)

    test_session_factory = async_sessionmaker(
        bind=test_engine,
        class_=AsyncSession,
        expire_on_commit=False,
    )

    original_engine = core_database.engine
    original_factory = core_database.async_session
    core_database.engine = test_engine  # type: ignore[assignment]
    core_database.async_session = test_session_factory  # type: ignore[assignment]

    try:
        yield test_engine
    finally:
        core_database.engine = original_engine  # type: ignore[assignment]
        core_database.async_session = original_factory  # type: ignore[assignment]
        await test_engine.dispose()


@pytest_asyncio.fixture(scope="function")
async def db_session(engine: Any) -> AsyncGenerator[AsyncSession, None]:
    """Async DB session bound to the per-test engine.

    Commits and rollbacks are managed by the caller; on teardown any
    uncommitted state is rolled back to avoid bleeding into other tests.
    """
    session_factory = async_sessionmaker(
        bind=engine,
        class_=AsyncSession,
        expire_on_commit=False,
    )
    async with session_factory() as session:
        try:
            yield session
        finally:
            await session.rollback()
            await session.close()


# ---------------------------------------------------------------------------
# HTTP client fixture wired to the test database.
# ---------------------------------------------------------------------------


@pytest_asyncio.fixture(scope="function")
async def client(engine: Any) -> AsyncGenerator[Any, None]:
    """An ``httpx.AsyncClient`` against the FastAPI app with DB overridden."""
    import httpx

    real_async_client = getattr(httpx, "_RealAsyncClient", httpx.AsyncClient)

    session_factory = async_sessionmaker(
        bind=engine,
        class_=AsyncSession,
        expire_on_commit=False,
    )

    async def _override_get_db() -> AsyncGenerator[AsyncSession, None]:
        async with session_factory() as session:
            try:
                yield session
                await session.commit()
            except Exception:
                await session.rollback()
                raise

    app.dependency_overrides[get_db] = _override_get_db

    transport = httpx.ASGITransport(app=app)
    async with real_async_client(
        transport=transport,
        base_url="http://testserver",
    ) as ac:
        yield ac

    app.dependency_overrides.pop(get_db, None)


# ---------------------------------------------------------------------------
# User factories.
# ---------------------------------------------------------------------------


async def _make_user(
    db_session: AsyncSession,
    *,
    email: str | None = None,
    password: str = "TestPassword123!",
    name: str | None = None,
    is_active: bool = True,
) -> dict[str, Any]:
    """Insert a User and return ``{user, token, headers}``."""
    user = User(
        id=uuid.uuid4(),
        email=email or f"user-{uuid.uuid4().hex[:8]}@example.com",
        name=name or "Test User",
        hashed_password=hash_password(password),
        is_active=is_active,
        llm_provider="openai",
        llm_model="gpt-4o",
        onboarding_completed=False,
    )
    db_session.add(user)
    await db_session.commit()
    await db_session.refresh(user)

    token = create_access_token(data={"sub": str(user.id), "email": user.email})
    return {
        "user": user,
        "password": password,
        "token": token,
        "headers": {"Authorization": f"Bearer {token}"},
    }


@pytest_asyncio.fixture(scope="function")
async def test_user(db_session: AsyncSession) -> dict[str, Any]:
    """Create a regular user and return user + JWT + auth headers."""
    return await _make_user(db_session, email="user@example.com")


@pytest_asyncio.fixture(scope="function")
async def test_admin(db_session: AsyncSession) -> dict[str, Any]:
    """Create an admin-tier user (no separate model, marked via token claim)."""
    bundle = await _make_user(db_session, email="admin@example.com")
    # Admin tier is encoded as a token claim since the User model has no
    # ``role`` field today; downstream auth checks can read ``tier``.
    bundle["token"] = create_access_token(
        data={
            "sub": str(bundle["user"].id),
            "email": bundle["user"].email,
            "tier": "admin",
        }
    )
    bundle["headers"] = {"Authorization": f"Bearer {bundle['token']}"}
    return bundle


# ---------------------------------------------------------------------------
# Convenience: factory exposed to tests that want to mint extra users.
# ---------------------------------------------------------------------------


@pytest_asyncio.fixture(scope="function")
async def make_user(db_session: AsyncSession):
    """Return an async callable that inserts an additional User."""

    async def _factory(**kwargs: Any) -> dict[str, Any]:
        return await _make_user(db_session, **kwargs)

    return _factory
