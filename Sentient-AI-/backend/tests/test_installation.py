from __future__ import annotations

from pathlib import Path

import pytest
import sqlalchemy as sa
from alembic import command
from alembic.config import Config
from sqlalchemy import select

from core.config import settings
from models.audit import AuditLog
from services.installation import InstallationService
from tests.conftest import make_user

BACKEND_DIR = Path(__file__).resolve().parents[1]


@pytest.mark.asyncio
async def test_capabilities_default_then_patch_and_audit(session_factory, monkeypatch):
    svc = InstallationService(session_factory)
    caps = await svc.capabilities()
    assert caps["screen"] is False and caps["web_browsing"] is True

    user, _token = await make_user(session_factory, "owner@example.com")
    statuses = await svc.set_capabilities({"screen": True, "reminders": False}, actor_id=user.id)
    by = {s.key: s for s in statuses}
    assert by["reminders"].enabled is False
    assert (await svc.capabilities())["screen"] is True

    async with session_factory() as s:
        # AuditLog has no created_at; seq is its per-user append order.
        row = (await s.execute(select(AuditLog).order_by(AuditLog.seq.desc()))).scalars().first()
    assert row.connector_name == "installation" and row.action == "capabilities_updated"


@pytest.mark.asyncio
async def test_unknown_capability_key_is_rejected(session_factory):
    svc = InstallationService(session_factory)
    user, _ = await make_user(session_factory, "o@example.com")
    with pytest.raises(ValueError):
        await svc.set_capabilities({"nope": True}, actor_id=user.id)


@pytest.mark.asyncio
async def test_api_key_env_wins_over_db(session_factory, monkeypatch):
    svc = InstallationService(session_factory)
    user, _ = await make_user(session_factory, "o@example.com")
    monkeypatch.setattr(settings, "GEMINI_API_KEY", "", raising=False)
    await svc.set_llm("gemini", "gemini-2.5-flash", "db-key", actor_id=user.id)
    assert await svc.llm_api_key("gemini") == "db-key"
    monkeypatch.setattr(settings, "GEMINI_API_KEY", "env-key", raising=False)
    svc.invalidate()
    assert await svc.llm_api_key("gemini") == "env-key"
    assert await svc.llm_defaults() == ("gemini", "gemini-2.5-flash")
    assert await svc.provider_configured() is True


@pytest.mark.asyncio
async def test_secrets_are_encrypted_at_rest(session_factory, monkeypatch):
    from models.installation import Installation

    # A developer .env may carry a real bot token, which would (correctly)
    # win over the stored one; this test is about the stored one.
    monkeypatch.setattr(settings, "TELEGRAM_BOT_TOKEN", "", raising=False)
    svc = InstallationService(session_factory)
    user, _ = await make_user(session_factory, "o@example.com")
    await svc.set_llm("openai", "gpt-4o-mini", "sk-secret-value", actor_id=user.id)
    await svc.set_telegram_token("123456:ABCDEFghijklmnopqrstuvwxyz0123456789", actor_id=user.id)
    async with session_factory() as s:
        row = (await s.execute(select(Installation))).scalar_one()
    assert b"sk-secret-value" not in (row.llm_api_keys or b"")
    assert b"123456:" not in (row.telegram_bot_token or b"")
    assert await svc.telegram_token() == "123456:ABCDEFghijklmnopqrstuvwxyz0123456789"


@pytest.mark.asyncio
async def test_ollama_needs_no_key(session_factory):
    svc = InstallationService(session_factory)
    user, _ = await make_user(session_factory, "o@example.com")
    await svc.set_llm("ollama", "llama3.2", None, actor_id=user.id)
    assert await svc.llm_api_key("ollama") == ""
    assert await svc.provider_configured() is True


@pytest.mark.asyncio
async def test_needs_setup_and_completion(session_factory, monkeypatch):
    svc = InstallationService(session_factory)
    monkeypatch.setattr(settings, "ALLOW_REGISTRATION", True, raising=False)
    assert await svc.needs_setup() is True
    assert await svc.registration_allowed() is True  # env applies before setup
    user, _ = await make_user(session_factory, "o@example.com")
    assert await svc.needs_setup() is True  # owner exists but wizard not finished
    await svc.mark_setup_complete(allow_registration=False, actor_id=user.id)
    assert await svc.needs_setup() is False
    assert await svc.registration_allowed() is False  # stored switch applies after


@pytest.mark.asyncio
async def test_legacy_install_is_stamped_when_env_key_present(session_factory, monkeypatch):
    svc = InstallationService(session_factory)
    await make_user(session_factory, "o@example.com")
    monkeypatch.setattr(settings, "LLM_PROVIDER", "gemini", raising=False)
    monkeypatch.setattr(settings, "GEMINI_API_KEY", "env-key", raising=False)
    assert await svc.stamp_setup_if_legacy() is True
    assert await svc.needs_setup() is False
    assert await svc.stamp_setup_if_legacy() is False  # idempotent


@pytest.mark.asyncio
async def test_on_change_fires_with_topic(session_factory):
    svc = InstallationService(session_factory)
    user, _ = await make_user(session_factory, "o@example.com")
    seen: list[str] = []

    async def cb(topic: str) -> None:
        seen.append(topic)

    svc.on_change(cb)
    await svc.set_capabilities({"screen": True}, actor_id=user.id)
    await svc.set_telegram_token(None, actor_id=user.id)
    assert seen == ["capabilities", "telegram"]


# ---------------------------------------------------------------------------
# Migration 0008
# ---------------------------------------------------------------------------


def _alembic_config(db_path) -> Config:
    config = Config(str(BACKEND_DIR / "alembic.ini"))
    config.set_main_option("script_location", str(BACKEND_DIR / "alembic"))
    config.attributes["sqlalchemy_url"] = f"sqlite+aiosqlite:///{db_path}"
    config.attributes["configure_logger"] = False
    return config


def _tables(db_path) -> set[str]:
    engine = sa.create_engine(f"sqlite:///{db_path}")
    try:
        return set(sa.inspect(engine).get_table_names())
    finally:
        engine.dispose()


def _installation_rows(db_path) -> list[tuple]:
    engine = sa.create_engine(f"sqlite:///{db_path}")
    try:
        with engine.connect() as conn:
            return [
                tuple(r)
                for r in conn.execute(
                    sa.text(
                        "SELECT id, capabilities, allow_registration, setup_completed_at "
                        "FROM installation"
                    )
                )
            ]
    finally:
        engine.dispose()


def test_migration_0008_creates_the_seeded_row_and_downgrade_drops_it(tmp_path):
    db_path = tmp_path / "installation.db"
    config = _alembic_config(db_path)

    command.upgrade(config, "0007_message_model")
    assert "installation" not in _tables(db_path)

    command.upgrade(config, "0008_installation")
    assert "installation" in _tables(db_path)
    rows = _installation_rows(db_path)
    assert len(rows) == 1
    row_id, capabilities, allow_registration, setup_completed_at = rows[0]
    assert row_id == 1
    assert capabilities == "{}"
    assert not allow_registration  # registration is closed until the owner opens it
    assert setup_completed_at is None

    command.downgrade(config, "0007_message_model")
    assert "installation" not in _tables(db_path)


def test_migration_0008_tolerates_an_adopted_table_and_seeds_once(tmp_path):
    """The adoption path: a pre-Alembic database built from model metadata
    already has the (empty) table. The guard skips the create, the seed
    still lands, and re-running the seed never duplicates the row."""
    import models  # noqa: F401 — registers every model on Base.metadata
    from core.database import Base

    db_path = tmp_path / "adopted.db"
    engine = sa.create_engine(f"sqlite:///{db_path}")
    try:
        Base.metadata.create_all(engine)
    finally:
        engine.dispose()
    assert _installation_rows(db_path) == []

    config = _alembic_config(db_path)
    command.stamp(config, "0007_message_model")
    command.upgrade(config, "head")
    assert [r[0] for r in _installation_rows(db_path)] == [1]

    command.downgrade(config, "0007_message_model")
    command.upgrade(config, "head")
    assert [r[0] for r in _installation_rows(db_path)] == [1]
