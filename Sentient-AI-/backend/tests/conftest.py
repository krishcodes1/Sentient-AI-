"""Tests for the shared pytest fixtures: the required env vars are set before any
project module imports settings, and that the in-memory database, HTTP client,
and user/JWT helpers every other test module relies on are built correctly.

Why it exists: Guards against a fixture regression breaking every test file at
once, and keeps the SECRET_KEY, ENCRYPTION_KEY, and DATABASE_URL setup used
across the whole suite in one place.

Connects to: the FastAPI app, an in-memory SQLite database (or Postgres
via TEST_DATABASE_URL) and the auth helpers.
Used by: pytest, for every test module; telegram_dm builds a realistic
private Telegram message for the bot tests.

Test setup. Sets dummy env vars before any project modules import,
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
# The runtime's default settings source resolves this key when a turn needs
# a provider; never used for real calls (tests install fakes with
# use_provider below).
os.environ.setdefault("ANTHROPIC_API_KEY", "test-key-not-real")
# The developer's local .env may restrict these (they are real Settings
# fields now); env vars outrank the .env file, so tests always see an
# unrestricted host list and the stock password policy.
os.environ["ALLOWED_HOSTS"] = '["*"]'
os.environ["PASSWORD_MIN_LENGTH"] = "8"
os.environ["ALLOW_REGISTRATION"] = "true"

import httpx  # noqa: E402
import pytest  # noqa: E402
import pytest_asyncio  # noqa: E402
from sqlalchemy import event  # noqa: E402
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine  # noqa: E402
from sqlalchemy.pool import StaticPool  # noqa: E402


@pytest.fixture(autouse=True)
def _no_real_computer_backend(monkeypatch):
    """No test drives or loads the real desktop. ``select_backend`` is the
    only way to the Mac or Windows backend (wire_services builds the
    toolkit with it, and the computer_control report asks it whether the
    backend imports), so every test gets an unavailable stand-in unless it
    injects its own fake. Tests of select_backend itself import it by name
    and are unaffected."""
    from services.tools.computer import backend as computer_backend

    monkeypatch.setattr(
        computer_backend,
        "select_backend",
        lambda _platform_name: computer_backend.UnavailableBackend(
            "Tests never use a real computer backend."
        ),
    )


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

        # SQLite ignores foreign keys unless asked. Production is Postgres,
        # where ON DELETE CASCADE is enforced and the ORM relies on it
        # (passive_deletes=True); without this pragma the SQLite suite
        # would silently pass on cascade behavior that Postgres enforces.
        @event.listens_for(engine.sync_engine, "connect")
        def _enable_sqlite_fks(dbapi_connection, _record):
            cursor = dbapi_connection.cursor()
            cursor.execute("PRAGMA foreign_keys=ON")
            cursor.close()
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


def telegram_dm(
    chat_id: int, text: str, *, sender_id: int | None = None, chat_type: str = "private"
) -> dict:
    """A Telegram ``message`` the way the Bot API delivers one: a person
    (``from``) writing in a chat. In a private chat the chat id IS the
    sender's user id; pass ``sender_id``/``chat_type`` to build anything
    else (someone else in a group, a mismatched sender, ...)."""
    sender = chat_id if sender_id is None else sender_id
    return {
        "message_id": 1,
        "from": {"id": sender, "is_bot": False, "first_name": "Test"},
        "chat": {"id": chat_id, "type": chat_type},
        "text": text,
    }


def _source_defaults_now(source) -> tuple[str, str]:
    """``await source.llm_defaults()`` from synchronous code.

    The runtime helpers that call use_provider are sync and run inside the
    test's event loop, so the coroutine cannot be handed to the loop. Every
    in-memory source (the environment one, the fakes tests pass) returns
    without suspending, so one step of the coroutine yields its value. A
    source that really awaits I/O cannot be read this way; the caller must
    pass the pair instead.
    """
    coro = source.llm_defaults()
    try:
        coro.send(None)
    except StopIteration as done:
        return done.value
    coro.close()
    raise RuntimeError(
        "the runtime's settings source suspends in llm_defaults(); pass "
        "pair=(provider, model) to use_provider explicitly"
    )


def use_provider(runtime, provider, pair: tuple[str, str] | None = None) -> None:
    """Make ``provider`` the LLM a runtime uses on its source's default
    (provider, model) pair — what a turn by an account that follows the
    install (NULL provider, the default for every test account) resolves to.

    The pair comes from the runtime's OWN settings source, so a runtime
    built with a custom source is seeded on that source's default, not on
    the environment's. Pass ``pair`` to seed a specific pair instead.

    The runtime builds providers lazily from its settings source and caches
    them per pair, so tests seed that cache where they used to overwrite
    the eagerly built ``runtime._provider``. Call again to swap it.
    """
    provider_name, model = pair if pair is not None else _source_defaults_now(
        runtime._source
    )
    runtime._provider_cache[
        ((provider_name or "").strip().lower(), (model or "").strip())
    ] = provider


# ── browser harness (contracts §8) ────────────────────────────────────────


@pytest.fixture
def fakesite(monkeypatch):
    """The fake site on a free 127.0.0.1 port, with the loopback toggle set
    for the duration of the test (never in production code paths)."""
    from tests.fakesite import FakeSite

    monkeypatch.setenv("CRAWLER_ALLOW_LOOPBACK_FOR_TESTS", "1")
    site = FakeSite().start()
    try:
        yield site
    finally:
        site.stop()


@pytest.fixture
def loopback_resolver():
    """A guard resolver that maps every host to 127.0.0.1: the fake site's
    address, and what a DNS-rebinding attacker would love to return."""
    return lambda host: ["127.0.0.1"]


@pytest_asyncio.fixture
async def page():
    """One headless Chromium page; skipped where the browser is absent."""
    playwright_api = pytest.importorskip("playwright.async_api")
    async with playwright_api.async_playwright() as playwright:
        try:
            browser = await playwright.chromium.launch(headless=True)
        except playwright_api.Error as exc:
            pytest.skip(f"headless Chromium unavailable: {str(exc).splitlines()[0]}")
        context = await browser.new_context(viewport={"width": 1280, "height": 800})
        page = await context.new_page()
        try:
            yield page
        finally:
            await browser.close()
