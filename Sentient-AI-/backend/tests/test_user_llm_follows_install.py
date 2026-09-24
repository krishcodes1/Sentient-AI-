"""Tests for the per-user provider/model "follow the install default" contract:
new accounts start with a NULL provider that tracks the install default, that
pinning then clearing a provider returns to following the install, and that the
startup backfill converts only inherited legacy rows.

Why it exists: Accounts used to be stamped with whatever provider ran at
registration time, so a key the owner later saved for a different provider
never reached them; NULL is now the steady state and this guards the backfill
from ever touching a row the user deliberately pinned.

A per-user provider of NULL means "follow this Crawler's default".

Accounts used to be stamped with whatever provider/model the server ran
when they registered, so a key the owner later saved for a different
provider (the setup wizard's whole point) never reached them: their row
still named the old provider and every turn failed. NULL is now the
steady state — new accounts get it, the startup backfill turns inherited
rows into it, and the Settings page offers it as "Use this Crawler's
default".
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
import sqlalchemy as sa
from alembic import command
from alembic.config import Config
from sqlalchemy import select

from tests.conftest import auth_headers, make_user

BACKEND_DIR = Path(__file__).resolve().parents[1]

LEGACY_PAIR = ("anthropic", "claude-sonnet-4-20250514")


# ---------------------------------------------------------------------------
# Model defaults and /auth/me
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_new_accounts_follow_the_install(client, session_factory):
    user, _ = await make_user(session_factory, "fresh@example.com")
    assert user.llm_provider is None and user.llm_model is None

    await client.post(
        "/api/auth/register",
        json={"email": "registered@example.com", "password": "password-123"},
    )
    login = await client.post(
        "/api/auth/login",
        json={"email": "registered@example.com", "password": "password-123"},
    )
    me = await client.get(
        "/api/auth/me", headers=auth_headers(login.json()["access_token"])
    )
    assert me.status_code == 200
    assert me.json()["llm_provider"] is None
    assert me.json()["llm_model"] is None


# ---------------------------------------------------------------------------
# PATCH /auth/settings
# ---------------------------------------------------------------------------


async def _patch(client, token, payload):
    return await client.patch(
        "/api/auth/settings", json=payload, headers=auth_headers(token)
    )


@pytest.mark.asyncio
async def test_settings_pin_then_return_to_the_install_default(client, session_factory):
    _, token = await make_user(session_factory, "pinner@example.com")

    pinned = await _patch(client, token, {"llm_provider": "OpenAI", "llm_model": "gpt-4o"})
    assert pinned.status_code == 200
    assert (pinned.json()["llm_provider"], pinned.json()["llm_model"]) == ("openai", "gpt-4o")

    back = await _patch(client, token, {"llm_provider": None, "llm_model": None})
    assert back.status_code == 200
    assert back.json()["llm_provider"] is None and back.json()["llm_model"] is None

    me = await client.get("/api/auth/me", headers=auth_headers(token))
    assert me.json()["llm_provider"] is None and me.json()["llm_model"] is None


@pytest.mark.asyncio
async def test_null_provider_alone_also_clears_the_model(client, session_factory):
    """A model without a provider means nothing (the runtime ignores it), so
    following the install clears both."""
    _, token = await make_user(session_factory, "half@example.com")
    await _patch(client, token, {"llm_provider": "openai", "llm_model": "gpt-4o"})

    response = await _patch(client, token, {"llm_provider": None})
    assert response.status_code == 200
    assert response.json()["llm_model"] is None


@pytest.mark.asyncio
async def test_omitted_fields_are_left_alone(client, session_factory):
    """Omitting a field is not the same as sending null: saving the rate
    limit must not silently reset the account's provider."""
    _, token = await make_user(session_factory, "omit@example.com")
    await _patch(client, token, {"llm_provider": "openai", "llm_model": "gpt-4o"})

    response = await _patch(client, token, {"rate_limit": 90})
    assert response.status_code == 200
    assert (response.json()["llm_provider"], response.json()["llm_model"]) == (
        "openai",
        "gpt-4o",
    )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "payload",
    [
        # A provider with no model on an account that follows the install.
        {"llm_provider": "openai"},
        # A pinned provider with its model removed.
        {"llm_provider": "openai", "llm_model": None},
        # A model alone, with no provider to pair it with.
        {"llm_model": "gpt-4o"},
    ],
)
async def test_a_pinned_provider_needs_a_model(client, session_factory, payload):
    user, token = await make_user(session_factory, "nomodel@example.com")
    response = await _patch(client, token, payload)
    assert response.status_code == 422
    me = await client.get("/api/auth/me", headers=auth_headers(token))
    assert (me.json()["llm_provider"], me.json()["llm_model"]) == (None, None)


@pytest.mark.asyncio
async def test_unrelated_saves_never_trip_the_pair_check(client, session_factory):
    """An account left with a provider but no model (by hand, or an older
    build) can still save its other settings."""
    user, token = await make_user(session_factory, "odd-row@example.com")
    from sqlalchemy import update

    from models.user import User

    async with session_factory() as session:
        await session.execute(
            update(User).where(User.id == user.id).values(llm_provider="openai")
        )
        await session.commit()
    response = await _patch(client, token, {"memory_enabled": False})
    assert response.status_code == 200


@pytest.mark.asyncio
async def test_unknown_provider_is_still_rejected(client, session_factory):
    _, token = await make_user(session_factory, "unknown@example.com")
    response = await _patch(client, token, {"llm_provider": "skynet", "llm_model": "t-800"})
    assert response.status_code == 422


# ---------------------------------------------------------------------------
# Startup backfill
# ---------------------------------------------------------------------------


async def _insert_user(session, email, provider, model, *, touched=False, drift=None):
    """``touched``: edited a day after registration. ``drift``: an untouched
    row whose two timestamps still differ by a hair — what the ORM writes,
    since created_at and updated_at each call datetime.now() on insert."""
    from models.user import User

    created = datetime(2026, 1, 1, tzinfo=timezone.utc)
    if touched:
        updated = created + timedelta(days=1)
    elif drift is not None:
        updated = created + drift
    else:
        updated = created
    user = User(
        email=email,
        hashed_password="x",
        llm_provider=provider,
        llm_model=model,
        created_at=created,
        updated_at=updated,
    )
    session.add(user)
    await session.flush()
    return user.id


@pytest.mark.asyncio
async def test_backfill_turns_inherited_pairs_into_follow_the_install(session_factory):
    from core.database import backfill_user_llm_defaults
    from models.user import User

    async with session_factory() as session:
        inherited = await _insert_user(
            session, "inherited@example.com", "gemini", "gemini-2.5-flash"
        )
        inherited_drift = await _insert_user(
            session,
            "inherited-drift@example.com",
            "gemini",
            "gemini-2.5-flash",
            drift=timedelta(microseconds=7),
        )
        # Pinned the server's own pair in Settings on purpose: it runs on
        # every boot, so it must never reset a deliberate choice.
        pinned_default = await _insert_user(
            session, "pinned-default@example.com", "gemini", "gemini-2.5-flash", touched=True
        )
        mixed_case = await _insert_user(
            session, "mixed@example.com", "Gemini", "gemini-2.5-flash"
        )
        pinned = await _insert_user(session, "pinned@example.com", "openai", "gpt-4o")
        same_provider_other_model = await _insert_user(
            session, "other-model@example.com", "gemini", "gemini-2.5-pro"
        )
        legacy_untouched = await _insert_user(session, "legacy@example.com", *LEGACY_PAIR)
        legacy_chosen = await _insert_user(
            session, "legacy-chosen@example.com", *LEGACY_PAIR, touched=True
        )
        await session.commit()

    async with session_factory() as session:
        conn = await session.connection()
        await backfill_user_llm_defaults(conn, " Gemini ", " gemini-2.5-flash ")
        await session.commit()

    async with session_factory() as session:
        rows = {
            u.id: (u.llm_provider, u.llm_model)
            for u in (await session.execute(select(User))).scalars()
        }

    assert rows[inherited] == (None, None)
    assert rows[inherited_drift] == (None, None)
    assert rows[pinned_default] == ("gemini", "gemini-2.5-flash")
    assert rows[mixed_case] == (None, None)
    assert rows[pinned] == ("openai", "gpt-4o")
    assert rows[same_provider_other_model] == ("gemini", "gemini-2.5-pro")
    # The historical hardcoded default, never touched since registration:
    # the account never chose it, so it follows the install too.
    assert rows[legacy_untouched] == (None, None)
    # Someone who opened Settings since then may have chosen it on purpose.
    assert rows[legacy_chosen] == LEGACY_PAIR


@pytest.mark.asyncio
async def test_backfill_leaves_a_user_who_saved_settings_alone_on_every_boot(
    client, session_factory
):
    """The real path: a user saves the env-default pair on the Settings
    page (updated_at moves on), and the backfill that runs at every boot
    must not reset it to "follow the install"."""
    from core.config import settings as app_settings
    from core.database import backfill_user_llm_defaults
    from models.user import User

    user, token = await make_user(session_factory, "keeps-it@example.com")
    provider, model = app_settings.LLM_PROVIDER, app_settings.LLM_MODEL
    async with session_factory() as session:
        row = await session.get(User, user.id)
        # Registered yesterday and never edited since.
        row.created_at = row.created_at - timedelta(days=1)
        row.updated_at = row.created_at
        await session.commit()

    saved = await _patch(client, token, {"llm_provider": provider, "llm_model": model})
    assert saved.status_code == 200, saved.text

    for _ in range(2):  # two restarts
        async with session_factory() as session:
            await backfill_user_llm_defaults(await session.connection(), provider, model)
            await session.commit()

    async with session_factory() as session:
        row = await session.get(User, user.id)
    assert row.updated_at.replace(tzinfo=timezone.utc) > row.created_at.replace(
        tzinfo=timezone.utc
    )
    assert (row.llm_provider, row.llm_model) == (provider, model)


@pytest.mark.asyncio
async def test_backfill_catches_an_account_the_orm_just_created(session_factory):
    """Accounts created by the ORM get created_at and updated_at from two
    separate datetime.now() calls, so "never edited" cannot mean exactly
    equal timestamps."""
    from core.config import settings as app_settings
    from core.database import backfill_user_llm_defaults
    from models.user import User

    provider, model = app_settings.LLM_PROVIDER, app_settings.LLM_MODEL
    ids = []
    async with session_factory() as session:
        for i in range(20):
            user = User(
                email=f"fresh-{i}@example.com",
                hashed_password="x",
                llm_provider=provider,
                llm_model=model,
            )
            session.add(user)
            await session.flush()
            ids.append(user.id)
        await session.commit()

    async with session_factory() as session:
        await backfill_user_llm_defaults(await session.connection(), provider, model)
        await session.commit()

    async with session_factory() as session:
        rows = (await session.execute(select(User).where(User.id.in_(ids)))).scalars().all()
    assert {(u.llm_provider, u.llm_model) for u in rows} == {(None, None)}


@pytest.mark.asyncio
async def test_backfill_is_idempotent_and_leaves_timestamps_alone(session_factory):
    from core.database import backfill_user_llm_defaults
    from models.user import User

    async with session_factory() as session:
        user_id = await _insert_user(session, "twice@example.com", "groq", "llama")
        await session.commit()

    for _ in range(2):
        async with session_factory() as session:
            await backfill_user_llm_defaults(await session.connection(), "groq", "llama")
            await session.commit()

    async with session_factory() as session:
        user = await session.get(User, user_id)
    assert (user.llm_provider, user.llm_model) == (None, None)
    assert user.updated_at.replace(tzinfo=timezone.utc) == datetime(
        2026, 1, 1, tzinfo=timezone.utc
    )


@pytest.mark.asyncio
async def test_backfill_with_no_server_default_touches_only_legacy_rows(session_factory):
    from core.database import backfill_user_llm_defaults
    from models.user import User

    async with session_factory() as session:
        user_id = await _insert_user(session, "blank@example.com", "openai", "gpt-4o")
        await session.commit()
    async with session_factory() as session:
        await backfill_user_llm_defaults(await session.connection(), "", "")
        await session.commit()
    async with session_factory() as session:
        user = await session.get(User, user_id)
    assert (user.llm_provider, user.llm_model) == ("openai", "gpt-4o")


# ---------------------------------------------------------------------------
# Migration 0009
# ---------------------------------------------------------------------------


def _alembic_config(url: str) -> Config:
    config = Config(str(BACKEND_DIR / "alembic.ini"))
    config.set_main_option("script_location", str(BACKEND_DIR / "alembic"))
    config.attributes["sqlalchemy_url"] = url
    config.attributes["configure_logger"] = False
    return config


def _user_columns(sync_url: str) -> dict[str, dict]:
    engine = sa.create_engine(sync_url)
    try:
        return {c["name"]: c for c in sa.inspect(engine).get_columns("users")}
    finally:
        engine.dispose()


def test_migration_makes_the_pair_nullable_and_back(tmp_path):
    db_path = tmp_path / "nullable.db"
    config = _alembic_config(f"sqlite+aiosqlite:///{db_path}")
    sync_url = f"sqlite:///{db_path}"

    command.upgrade(config, "0008_installation")
    before = _user_columns(sync_url)
    assert before["llm_provider"]["nullable"] is False

    engine = sa.create_engine(sync_url)
    try:
        with engine.begin() as conn:
            conn.execute(
                sa.text(
                    "INSERT INTO users (id, email, hashed_password, is_active, "
                    "created_at, updated_at) VALUES ('u1', 'kept@example.com', 'x', 1, "
                    "'2026-01-01 00:00:00', '2026-01-01 00:00:00')"
                )
            )
    finally:
        engine.dispose()

    command.upgrade(config, "head")
    after = _user_columns(sync_url)
    assert after["llm_provider"]["nullable"] is True
    assert after["llm_model"]["nullable"] is True
    # No server default: a row written without a provider follows the
    # install rather than silently pinning the historical default.
    assert after["llm_provider"]["default"] is None
    assert after["llm_model"]["default"] is None

    engine = sa.create_engine(sync_url)
    try:
        with engine.begin() as conn:
            # The pre-existing account survived the rebuild with its values.
            assert conn.execute(
                sa.text("SELECT email, llm_provider FROM users")
            ).one() == ("kept@example.com", "anthropic")
            conn.execute(sa.text("UPDATE users SET llm_provider = NULL, llm_model = NULL"))
    finally:
        engine.dispose()

    # Going back restores NOT NULL, so NULLs are filled with the old default
    # first instead of failing the downgrade.
    command.downgrade(config, "0008_installation")
    reverted = _user_columns(sync_url)
    assert reverted["llm_provider"]["nullable"] is False
    engine = sa.create_engine(sync_url)
    try:
        with engine.connect() as conn:
            assert conn.execute(
                sa.text("SELECT llm_provider, llm_model FROM users")
            ).one() == LEGACY_PAIR
    finally:
        engine.dispose()


@pytest.mark.asyncio
async def test_init_db_migrates_and_backfills_inherited_accounts(tmp_path, monkeypatch):
    """The real startup path: a database at 0008 whose accounts were stamped
    with the server's pair comes up at head with those accounts following
    the install, while a deliberate pick survives."""
    import asyncio

    from sqlalchemy.ext.asyncio import create_async_engine

    import core.database as database

    db = tmp_path / "startup.db"
    sync_url = f"sqlite:///{db}"
    async_url = f"sqlite+aiosqlite:///{db}"
    await asyncio.to_thread(command.upgrade, _alembic_config(async_url), "0008_installation")

    engine = sa.create_engine(sync_url)
    try:
        with engine.begin() as conn:
            for user_id, provider, model, updated_at in (
                # Never edited since registration: follows the install.
                ("inherited", "gemini", "gemini-2.5-flash", "2026-01-01 00:00:00"),
                # Saved Settings since, with the server's own pair: kept.
                ("chosen", "gemini", "gemini-2.5-flash", "2026-02-01 00:00:00"),
                ("pinned", "openai", "gpt-4o", "2026-02-01 00:00:00"),
            ):
                conn.execute(
                    sa.text(
                        "INSERT INTO users (id, email, hashed_password, is_active, "
                        "llm_provider, llm_model, created_at, updated_at) VALUES "
                        "(:id, :email, 'x', 1, :provider, :model, "
                        "'2026-01-01 00:00:00', :updated_at)"
                    ),
                    {
                        "id": user_id,
                        "email": f"{user_id}@example.com",
                        "provider": provider,
                        "model": model,
                        "updated_at": updated_at,
                    },
                )
    finally:
        engine.dispose()

    async_engine = create_async_engine(async_url)
    monkeypatch.setattr(database, "engine", async_engine)
    monkeypatch.setattr(database.settings, "DATABASE_URL", async_url)
    monkeypatch.setattr(database.settings, "LLM_PROVIDER", "gemini")
    monkeypatch.setattr(database.settings, "LLM_MODEL", "gemini-2.5-flash")
    try:
        await database.init_db(retries=1)
    finally:
        await async_engine.dispose()

    engine = sa.create_engine(sync_url)
    try:
        with engine.connect() as conn:
            rows = {
                r[0]: (r[1], r[2])
                for r in conn.execute(
                    sa.text("SELECT id, llm_provider, llm_model FROM users")
                )
            }
    finally:
        engine.dispose()
    assert rows == {
        "inherited": (None, None),
        "chosen": ("gemini", "gemini-2.5-flash"),
        "pinned": ("openai", "gpt-4o"),
    }


def test_migration_is_a_no_op_on_an_adopted_database(tmp_path):
    """A legacy database built from today's metadata already has nullable
    columns when it is stamped and upgraded; 0009 must not fail on it."""
    import models  # noqa: F401
    from core.database import Base

    db_path = tmp_path / "adopted.db"
    engine = sa.create_engine(f"sqlite:///{db_path}")
    try:
        Base.metadata.create_all(engine)
    finally:
        engine.dispose()
    config = _alembic_config(f"sqlite+aiosqlite:///{db_path}")
    command.stamp(config, "0001_baseline")
    command.upgrade(config, "head")
    assert _user_columns(f"sqlite:///{db_path}")["llm_provider"]["nullable"] is True
