"""Tests for the installation service: owner-set values and env-sourced defaults
resolve with the documented precedence, secrets are encrypted at rest and never
appear in an audit row, on-change listeners fire correctly, setup and
registration-lock state transitions follow the documented rules, and migration
0008 seeds and upgrades the installation row correctly.

Why it exists: This service is the single source of truth for provider keys,
capability switches, and the setup and registration lock, so a precedence bug
or a secret leaking into an audit row here would compromise every account on
the install.
"""

from __future__ import annotations

import asyncio
import base64
import contextlib
import json
import os
import uuid
from pathlib import Path

import pytest
import sqlalchemy as sa
from alembic import command
from alembic.config import Config
from sqlalchemy import select
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

import services.installation as installation_module
from core.config import PROVIDER_KEY_FIELDS, settings
from models.audit import AuditLog, AuditStatus
from models.installation import INSTALLATION_ROW_ID, Installation
from services.installation import InstallationService
from tests.conftest import make_user

BACKEND_DIR = Path(__file__).resolve().parents[1]

# Secrets that the audit sanitiser's value patterns would NOT redact on
# their own, so a leak into an audit row cannot be hidden by redaction.
LLM_SECRET = "anthropic-secret-VALUE-0001"
BOT_SECRET = "987654:telegram-secret-VALUE-0002"


@pytest.fixture(autouse=True)
def _pinned_env(monkeypatch):
    """A developer .env (or conftest's ANTHROPIC_API_KEY) must not decide
    these tests: every provider key and the bot token start empty, and the
    env defaults are fixed so the owner-first and env-first rules are
    proven against known values."""
    for attr in PROVIDER_KEY_FIELDS.values():
        monkeypatch.setattr(settings, attr, "", raising=False)
    monkeypatch.setattr(settings, "LLM_PROVIDER", "anthropic", raising=False)
    monkeypatch.setattr(settings, "LLM_MODEL", "claude-sonnet-5", raising=False)
    monkeypatch.setattr(settings, "TELEGRAM_BOT_TOKEN", "", raising=False)
    monkeypatch.setattr(settings, "ALLOW_REGISTRATION", True, raising=False)


async def _row(session_factory) -> Installation:
    async with session_factory() as s:
        return (await s.execute(select(Installation))).scalar_one()


async def _audit_rows(session_factory) -> list[AuditLog]:
    async with session_factory() as s:
        return list((await s.execute(select(AuditLog).order_by(AuditLog.seq))).scalars())


def _other_encryption_key() -> str:
    return base64.urlsafe_b64encode(os.urandom(32)).decode("utf-8")


def _registration_env(value: bool | None):
    """A copy of the (pinned) settings with ALLOW_REGISTRATION set to
    *value* in the environment, or absent from it when *value* is None.

    conftest exports ALLOW_REGISTRATION=true, so the shared settings always
    count it as explicitly set; pydantic-settings records every field read
    from the environment or .env in model_fields_set, and a copy lets a
    test take it back out."""
    if value is None:
        config = settings.model_copy()
        config.__pydantic_fields_set__.discard("ALLOW_REGISTRATION")
        return config
    return settings.model_copy(update={"ALLOW_REGISTRATION": value})


def test_settings_record_an_env_sourced_field_as_explicit(tmp_path, monkeypatch):
    """The lock rests on pydantic-settings marking values it read from the
    environment or the .env file as set, and leaving defaults unmarked."""
    from core.config import Settings

    monkeypatch.delenv("ALLOW_REGISTRATION", raising=False)
    monkeypatch.chdir(tmp_path)  # no .env here
    assert "ALLOW_REGISTRATION" not in Settings().model_fields_set

    (tmp_path / ".env").write_text("ALLOW_REGISTRATION=false\n", encoding="utf-8")
    from_dotenv = Settings()
    assert "ALLOW_REGISTRATION" in from_dotenv.model_fields_set
    assert from_dotenv.ALLOW_REGISTRATION is False

    (tmp_path / ".env").unlink()
    monkeypatch.setenv("ALLOW_REGISTRATION", "true")
    assert "ALLOW_REGISTRATION" in Settings().model_fields_set


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
    await svc.set_llm("gemini", "gemini-2.5-flash", "db-key", actor_id=user.id)
    assert await svc.llm_api_key("gemini") == "db-key"
    monkeypatch.setattr(settings, "GEMINI_API_KEY", "env-key", raising=False)
    svc.invalidate()
    assert await svc.llm_api_key("gemini") == "env-key"
    assert await svc.llm_defaults() == ("gemini", "gemini-2.5-flash")
    assert await svc.provider_configured() is True


@pytest.mark.asyncio
async def test_secrets_are_encrypted_at_rest(session_factory):
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
async def test_needs_setup_and_completion(session_factory):
    svc = InstallationService(session_factory)
    assert await svc.needs_setup() is True
    # The first account comes from /setup/owner, never open sign-up.
    assert await svc.registration_allowed() is False
    user, _ = await make_user(session_factory, "o@example.com")
    assert await svc.needs_setup() is True  # owner exists but wizard not finished
    assert await svc.registration_allowed() is False  # closed until the wizard ends
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


@pytest.mark.asyncio
async def test_setup_and_llm_topics_fire(session_factory):
    svc = InstallationService(session_factory)
    user, _ = await make_user(session_factory, "o@example.com")
    seen: list[str] = []

    async def cb(topic: str) -> None:
        seen.append(topic)

    svc.on_change(cb)
    await svc.set_llm("openai", "gpt-4o-mini", "sk-x", actor_id=user.id)
    await svc.mark_setup_complete(allow_registration=False, actor_id=user.id)
    assert seen == ["llm", "setup"]


@pytest.mark.asyncio
async def test_a_raising_listener_does_not_break_the_save(session_factory):
    svc = InstallationService(session_factory)
    user, _ = await make_user(session_factory, "o@example.com")
    seen: list[str] = []

    async def broken(_topic: str) -> None:
        raise RuntimeError(f"listener failed for {BOT_SECRET}")

    async def healthy(topic: str) -> None:
        seen.append(topic)

    svc.on_change(broken)
    svc.on_change(healthy)
    await svc.set_capabilities({"screen": True}, actor_id=user.id)  # does not raise
    svc.invalidate()
    assert (await svc.capabilities())["screen"] is True
    assert seen == ["capabilities"]  # a later listener still hears it


# ---------------------------------------------------------------------------
# Audit rows: written in the same transaction as the change
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_every_write_is_audited_with_its_endpoint_scope_and_payload(session_factory):
    svc = InstallationService(session_factory)
    user, _ = await make_user(session_factory, "o@example.com")
    await svc.set_capabilities({"screen": True}, actor_id=user.id)
    await svc.set_llm("openai", "gpt-4o-mini", "sk-x", actor_id=user.id)
    await svc.set_telegram_token(BOT_SECRET, actor_id=user.id)
    await svc.mark_setup_complete(allow_registration=False, actor_id=user.id)
    await svc.clear_stored_secrets(actor_id=user.id)

    rows = await _audit_rows(session_factory)
    got = [
        (r.action, r.endpoint, r.scope_used, r.status, r.request_data, r.connector_name, r.user_id)
        for r in rows
    ]
    approved = AuditStatus.approved
    assert got == [
        (
            "capabilities_updated",
            "/api/capabilities",
            "admin",
            approved,
            {"changes": {"screen": True}},
            "installation",
            user.id,
        ),
        (
            "provider_updated",
            "/api/setup/provider",
            "admin",
            approved,
            {"provider": "openai", "model": "gpt-4o-mini", "key_stored": True},
            "installation",
            user.id,
        ),
        (
            "telegram_updated",
            "/api/setup/telegram",
            "admin",
            approved,
            {"configured": True},
            "installation",
            user.id,
        ),
        (
            "setup_completed",
            "/api/setup/complete",
            "admin",
            approved,
            {"allow_registration": False},
            "installation",
            user.id,
        ),
        (
            "installation_secrets_cleared",
            "/api/setup/secrets",
            "admin",
            approved,
            {"provider_keys_cleared": True, "telegram_cleared": True},
            "installation",
            user.id,
        ),
    ]


@pytest.mark.asyncio
async def test_no_audit_row_carries_a_secret(session_factory):
    svc = InstallationService(session_factory)
    user, _ = await make_user(session_factory, "o@example.com")
    await svc.set_llm("anthropic", "claude-sonnet-5", LLM_SECRET, actor_id=user.id)
    await svc.set_llm("anthropic", "claude-sonnet-5", f"  {LLM_SECRET}  ", actor_id=user.id)
    await svc.set_telegram_token(BOT_SECRET, actor_id=user.id)
    await svc.set_telegram_token(f" {BOT_SECRET} ", actor_id=user.id)

    rows = await _audit_rows(session_factory)
    assert len(rows) == 4
    for row in rows:
        dumped = json.dumps(
            {c.name: getattr(row, c.name) for c in AuditLog.__table__.columns}, default=str
        )
        assert LLM_SECRET not in dumped
        assert BOT_SECRET not in dumped
        assert "987654" not in dumped


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "operation", ["capabilities", "llm", "telegram", "setup", "clear", "registration"]
)
async def test_a_failed_audit_write_rolls_the_change_back(session_factory, monkeypatch, operation):
    svc = InstallationService(session_factory)
    user, _ = await make_user(session_factory, "o@example.com")
    await svc.set_llm("openai", "gpt-4o-mini", "sk-kept", actor_id=user.id)
    await svc.set_telegram_token(BOT_SECRET, actor_id=user.id)
    before = await _row(session_factory)
    audits_before = len(await _audit_rows(session_factory))

    seen: list[str] = []

    async def cb(topic: str) -> None:
        seen.append(topic)

    svc.on_change(cb)

    async def audit_down(*_args, **_kwargs):
        raise RuntimeError("audit store unavailable")

    monkeypatch.setattr(installation_module, "append_audit_log", audit_down)
    calls = {
        "capabilities": lambda: svc.set_capabilities({"screen": True}, actor_id=user.id),
        "llm": lambda: svc.set_llm("gemini", "gemini-2.5-flash", "g-key", actor_id=user.id),
        "telegram": lambda: svc.set_telegram_token(None, actor_id=user.id),
        "setup": lambda: svc.mark_setup_complete(allow_registration=True, actor_id=user.id),
        "clear": lambda: svc.clear_stored_secrets(actor_id=user.id),
        "registration": lambda: svc.set_registration(True, actor_id=user.id),
    }
    with pytest.raises(RuntimeError, match="audit store unavailable"):
        await calls[operation]()

    after = await _row(session_factory)
    assert after.capabilities == before.capabilities
    assert (after.llm_provider, after.llm_model) == ("openai", "gpt-4o-mini")
    assert after.llm_api_keys == before.llm_api_keys
    assert after.telegram_bot_token == before.telegram_bot_token
    assert after.setup_completed_at is None
    assert after.allow_registration is False
    assert seen == []  # nothing changed, so no listener hears about it
    assert len(await _audit_rows(session_factory)) == audits_before

    svc.invalidate()
    assert (await svc.capabilities())["screen"] is False
    assert await svc.llm_api_key("openai") == "sk-kept"
    assert await svc.telegram_token() == BOT_SECRET
    assert await svc.setup_completed() is False


# ---------------------------------------------------------------------------
# Snapshot cache
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_a_load_that_raced_an_invalidate_is_not_cached(session_factory):
    """A reader that started its query before a writer committed must not
    cache what it read: the writer's invalidate() happened in between, so
    that result may predate the write."""
    after_session: list = []

    def racing_factory():
        @contextlib.asynccontextmanager
        async def cm():
            async with session_factory() as s:
                yield s
            if after_session:
                after_session.pop()()

        return cm()

    svc = InstallationService(racing_factory)
    after_session.append(svc.invalidate)  # a writer commits mid-read
    assert (await svc.capabilities())["screen"] is False

    async with session_factory() as s:  # the committed change
        row = await s.get(Installation, INSTALLATION_ROW_ID)
        row.capabilities = {"screen": True}
        await s.commit()
    # Not served from a cache filled by the raced read.
    assert (await svc.capabilities())["screen"] is True

    # Control: an unraced read IS cached (within the TTL), so the result
    # above is the generation guard at work, not a missing cache.
    async with session_factory() as s:
        row = await s.get(Installation, INSTALLATION_ROW_ID)
        row.capabilities = {"screen": False}
        await s.commit()
    assert (await svc.capabilities())["screen"] is True


@pytest.mark.asyncio
async def test_report_is_built_once_per_cache_period(session_factory, monkeypatch):
    """Every gated tool call asks for the owner's statuses; the environment
    facts (filesystem stats, browsers.json) are gathered once per cache
    period, not per call, and a change rebuilds them."""
    from services import capabilities as registry

    real = registry.default_context
    calls: list[bool] = []

    def counting_context(**kwargs):
        calls.append(True)
        return real(**kwargs)

    monkeypatch.setattr(registry, "default_context", counting_context)
    svc = InstallationService(session_factory)

    first = await svc.enabled_keys()
    for _ in range(20):
        assert await svc.enabled_keys() == first
    statuses = await svc.capability_statuses()
    report = await svc.report()
    assert len(calls) == 1
    assert set(statuses) == {s.key for s in report}
    assert first == frozenset(k for k, s in statuses.items() if s.effective == "on")
    # The cached index is read-only: a gate caller cannot corrupt it.
    with pytest.raises(TypeError):
        statuses["screen"] = statuses["web_browsing"]  # type: ignore[index]

    svc.invalidate()
    await svc.enabled_keys()
    assert len(calls) == 2

    # A switch change rebuilds the report and the gates see it at once.
    user, _ = await make_user(session_factory, "cache-owner@example.com")
    await svc.set_capabilities({"web_browsing": False}, actor_id=user.id)
    assert "web_browsing" not in await svc.enabled_keys()
    assert (await svc.capability_statuses())["web_browsing"].effective == "off"

    # Past the TTL the report is rebuilt.
    count = len(calls)
    monkeypatch.setattr(InstallationService, "CACHE_TTL_S", 0.0)
    await svc.enabled_keys()
    assert len(calls) == count + 1


@pytest.mark.asyncio
async def test_a_report_that_raced_an_invalidate_is_not_cached(session_factory, monkeypatch):
    from services import capabilities as registry

    svc = InstallationService(session_factory)
    real = registry.default_context

    def racing_context(**kwargs):
        svc.invalidate()  # a write committed while the report was built
        return real(**kwargs)

    monkeypatch.setattr(registry, "default_context", racing_context)
    await svc.enabled_keys()
    monkeypatch.setattr(registry, "default_context", real)
    assert svc._report_view is None


@pytest.mark.asyncio
async def test_snapshot_repr_hides_secrets(session_factory):
    svc = InstallationService(session_factory)
    user, _ = await make_user(session_factory, "o@example.com")
    await svc.set_llm("anthropic", "claude-sonnet-5", LLM_SECRET, actor_id=user.id)
    await svc.set_telegram_token(BOT_SECRET, actor_id=user.id)
    snap = await svc._load()
    assert snap.llm_api_keys == {"anthropic": LLM_SECRET}
    assert LLM_SECRET not in repr(snap)
    assert BOT_SECRET not in repr(snap)


# ---------------------------------------------------------------------------
# Provider: owner-first defaults, env-first keys, input normalisation
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_provider_not_configured_without_any_key(session_factory):
    svc = InstallationService(session_factory)
    assert await svc.llm_defaults() == ("anthropic", "claude-sonnet-5")
    assert await svc.llm_api_key("anthropic") is None
    assert await svc.provider_configured() is False


@pytest.mark.asyncio
async def test_owner_choice_beats_the_env_default_provider(session_factory):
    svc = InstallationService(session_factory)
    user, _ = await make_user(session_factory, "o@example.com")
    assert await svc.llm_defaults() == ("anthropic", "claude-sonnet-5")  # env
    await svc.set_llm("openai", "gpt-4o-mini", "sk-owner", actor_id=user.id)
    assert await svc.llm_defaults() == ("openai", "gpt-4o-mini")  # stored wins
    assert await svc.provider_configured() is True
    assert await svc.stored_provider_keys() == {"openai"}


@pytest.mark.asyncio
async def test_set_llm_normalises_its_inputs(session_factory):
    svc = InstallationService(session_factory)
    user, _ = await make_user(session_factory, "o@example.com")
    await svc.set_llm("  OpenAI ", "  gpt-4o-mini  ", "  sk-padded  ", actor_id=user.id)
    assert await svc.llm_defaults() == ("openai", "gpt-4o-mini")
    assert await svc.llm_api_key("openai") == "sk-padded"

    # A blank key is no key: the stored one is kept and the audit says so.
    await svc.set_llm("openai", "gpt-4o", "   ", actor_id=user.id)
    assert await svc.llm_api_key("openai") == "sk-padded"
    rows = await _audit_rows(session_factory)
    assert [r.request_data for r in rows] == [
        {"provider": "openai", "model": "gpt-4o-mini", "key_stored": True},
        {"provider": "openai", "model": "gpt-4o", "key_stored": False},
    ]


@pytest.mark.asyncio
@pytest.mark.parametrize("model", ["", "   ", None])
async def test_set_llm_rejects_an_empty_model(session_factory, model):
    svc = InstallationService(session_factory)
    user, _ = await make_user(session_factory, "o@example.com")
    with pytest.raises(ValueError):
        await svc.set_llm("openai", model, "sk-x", actor_id=user.id)
    assert await svc.llm_defaults() == ("anthropic", "claude-sonnet-5")  # env, untouched
    assert await svc.stored_provider_keys() == set()
    assert await _audit_rows(session_factory) == []


@pytest.mark.asyncio
async def test_unknown_provider_error_does_not_echo_the_input(session_factory):
    svc = InstallationService(session_factory)
    user, _ = await make_user(session_factory, "o@example.com")
    pasted = "sk-ant-pasted-into-the-wrong-field"
    with pytest.raises(ValueError) as excinfo:
        await svc.set_llm(pasted, "m", None, actor_id=user.id)
    assert str(excinfo.value) == "Unknown provider"
    assert pasted not in str(excinfo.value)


@pytest.mark.asyncio
async def test_set_telegram_token_normalises_its_input(session_factory):
    svc = InstallationService(session_factory)
    user, _ = await make_user(session_factory, "o@example.com")
    await svc.set_telegram_token(f"  {BOT_SECRET}  ", actor_id=user.id)
    assert await svc.telegram_token() == BOT_SECRET
    await svc.set_telegram_token("   ", actor_id=user.id)  # blank clears
    assert await svc.telegram_token() is None
    assert (await _row(session_factory)).telegram_bot_token is None
    rows = await _audit_rows(session_factory)
    assert [r.request_data for r in rows] == [{"configured": True}, {"configured": False}]


@pytest.mark.asyncio
@pytest.mark.parametrize("value", ["yes", 1, 0, None, "false"])
async def test_set_capabilities_rejects_non_bool_values(session_factory, value):
    svc = InstallationService(session_factory)
    user, _ = await make_user(session_factory, "o@example.com")
    with pytest.raises(ValueError):
        await svc.set_capabilities({"screen": value}, actor_id=user.id)
    assert (await svc.capabilities())["screen"] is False
    assert await _audit_rows(session_factory) == []


# ---------------------------------------------------------------------------
# Undecryptable secrets (ENCRYPTION_KEY changed or lost)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_undecryptable_secrets_are_reported_and_never_overwritten(
    session_factory, monkeypatch
):
    svc = InstallationService(session_factory)
    user, _ = await make_user(session_factory, "o@example.com")
    await svc.set_llm("openai", "gpt-4o-mini", "sk-old", actor_id=user.id)
    await svc.set_telegram_token(BOT_SECRET, actor_id=user.id)
    assert await svc.secrets_unreadable() is False
    before = await _row(session_factory)
    original_key = settings.ENCRYPTION_KEY

    monkeypatch.setattr(settings, "ENCRYPTION_KEY", _other_encryption_key())
    svc.invalidate()
    assert await svc.secrets_unreadable() is True
    assert await svc.llm_api_key("openai") is None
    assert await svc.telegram_token() is None
    assert await svc.stored_provider_keys() == set()

    with pytest.raises(RuntimeError, match="cannot be decrypted with the current ENCRYPTION_KEY"):
        await svc.set_llm("anthropic", "claude-sonnet-5", "sk-new", actor_id=user.id)
    with pytest.raises(RuntimeError, match="cannot be decrypted"):
        await svc.set_llm("ollama", "llama3.2", None, actor_id=user.id)
    after = await _row(session_factory)
    assert after.llm_api_keys == before.llm_api_keys  # byte-for-byte intact
    assert (after.llm_provider, after.llm_model) == ("openai", "gpt-4o-mini")

    # Restoring the key brings every secret back.
    monkeypatch.setattr(settings, "ENCRYPTION_KEY", original_key)
    svc.invalidate()
    assert await svc.secrets_unreadable() is False
    assert await svc.llm_api_key("openai") == "sk-old"
    assert await svc.telegram_token() == BOT_SECRET


@pytest.mark.asyncio
async def test_clear_stored_secrets_is_the_escape_hatch(session_factory, monkeypatch):
    svc = InstallationService(session_factory)
    user, _ = await make_user(session_factory, "o@example.com")
    await svc.set_llm("openai", "gpt-4o-mini", "sk-old", actor_id=user.id)
    await svc.set_telegram_token(BOT_SECRET, actor_id=user.id)
    monkeypatch.setattr(settings, "ENCRYPTION_KEY", _other_encryption_key())
    svc.invalidate()
    seen: list[str] = []

    async def cb(topic: str) -> None:
        seen.append(topic)

    svc.on_change(cb)
    await svc.clear_stored_secrets(actor_id=user.id)
    row = await _row(session_factory)
    assert row.llm_api_keys is None and row.telegram_bot_token is None
    assert await svc.secrets_unreadable() is False
    assert seen == ["llm", "telegram"]

    # With the unreadable blob gone, the wizard can save a key again.
    await svc.set_llm("anthropic", "claude-sonnet-5", "sk-new", actor_id=user.id)
    assert await svc.llm_api_key("anthropic") == "sk-new"


@pytest.mark.asyncio
async def test_undecryptable_warning_is_logged_once_per_blob(session_factory, monkeypatch):
    class _Recorder:
        def __init__(self) -> None:
            self.events: list[tuple[str, str]] = []

        def warning(self, event: str, **_kw) -> None:
            self.events.append(("warning", event))

        def info(self, event: str, **_kw) -> None:
            self.events.append(("info", event))

    recorder = _Recorder()
    monkeypatch.setattr(installation_module, "logger", recorder)
    svc = InstallationService(session_factory)
    user, _ = await make_user(session_factory, "o@example.com")
    await svc.set_llm("openai", "gpt-4o-mini", "sk-old", actor_id=user.id)
    await svc.set_telegram_token(BOT_SECRET, actor_id=user.id)
    monkeypatch.setattr(settings, "ENCRYPTION_KEY", _other_encryption_key())

    for _ in range(3):
        svc.invalidate()
        await svc.llm_api_key("openai")
        await svc.telegram_token()
    warnings = [e for level, e in recorder.events if level == "warning"]
    assert warnings.count("installation_keys_undecryptable") == 1
    assert warnings.count("installation_token_undecryptable") == 1


# ---------------------------------------------------------------------------
# Registration
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("env_value", "locked"), [(None, False), (True, False), (False, True)]
)
def test_only_an_explicit_false_locks_registration(session_factory, env_value, locked):
    svc = InstallationService(session_factory, config=_registration_env(env_value))
    assert svc.registration_env_locked() is locked


def test_a_config_without_a_fields_record_is_read_as_explicit(session_factory):
    """A plain stand-in config (no pydantic model_fields_set) that carries
    ALLOW_REGISTRATION=False still locks: never read a lock as open."""
    from types import SimpleNamespace

    locked = SimpleNamespace(ALLOW_REGISTRATION=False)
    assert InstallationService(session_factory, config=locked).registration_env_locked()
    unset = SimpleNamespace()
    assert not InstallationService(session_factory, config=unset).registration_env_locked()


@pytest.mark.asyncio
@pytest.mark.parametrize("env_value", [None, True, False])
async def test_registration_is_closed_before_any_user(session_factory, env_value):
    """Zero users: the first account comes from /setup/owner only, whatever
    the environment says."""
    svc = InstallationService(session_factory, config=_registration_env(env_value))
    assert await svc.registration_allowed() is False


@pytest.mark.asyncio
@pytest.mark.parametrize("env_value", [None, True])
async def test_registration_is_closed_between_owner_and_wizard_completion(
    session_factory, env_value
):
    svc = InstallationService(session_factory, config=_registration_env(env_value))
    user, _ = await make_user(session_factory, "owner@example.com")
    # Even a switch stored before completion does not open it early.
    await svc.set_registration(True, actor_id=user.id)
    assert await svc.registration_allowed() is False


@pytest.mark.asyncio
@pytest.mark.parametrize("env_value", [None, True])
@pytest.mark.parametrize("stored", [True, False])
async def test_registration_follows_the_stored_switch_after_setup(
    session_factory, env_value, stored
):
    """Unset or explicitly true, the environment does not decide: the
    owner's stored switch does."""
    svc = InstallationService(session_factory, config=_registration_env(env_value))
    user, _ = await make_user(session_factory, "o@example.com")
    await svc.mark_setup_complete(allow_registration=stored, actor_id=user.id)
    assert await svc.registration_allowed() is stored


@pytest.mark.asyncio
async def test_explicit_false_locks_registration_whatever_the_switch_says(session_factory):
    open_svc = InstallationService(session_factory, config=_registration_env(None))
    user, _ = await make_user(session_factory, "o@example.com")
    await open_svc.mark_setup_complete(allow_registration=True, actor_id=user.id)
    assert await open_svc.registration_allowed() is True

    locked_svc = InstallationService(session_factory, config=_registration_env(False))
    assert await locked_svc.registration_allowed() is False
    assert (await _row(session_factory)).allow_registration is True  # switch untouched


@pytest.mark.asyncio
async def test_completing_setup_under_the_lock_stores_the_switch_closed(session_factory):
    """Asking to open registration while the environment locks it must not
    leave an open switch behind for the day the lock is removed."""
    svc = InstallationService(session_factory, config=_registration_env(False))
    user, _ = await make_user(session_factory, "o@example.com")
    await svc.mark_setup_complete(allow_registration=True, actor_id=user.id)
    assert (await _row(session_factory)).allow_registration is False
    rows = await _audit_rows(session_factory)
    assert rows[-1].action == "setup_completed"
    assert rows[-1].request_data == {"allow_registration": False}


@pytest.mark.asyncio
@pytest.mark.parametrize("env_value", [None, True])
async def test_set_registration_stores_and_audits_the_switch(session_factory, env_value):
    svc = InstallationService(session_factory, config=_registration_env(env_value))
    user, _ = await make_user(session_factory, "o@example.com")
    await svc.mark_setup_complete(allow_registration=False, actor_id=user.id)
    seen: list[str] = []

    async def cb(topic: str) -> None:
        seen.append(topic)

    svc.on_change(cb)
    await svc.set_registration(True, actor_id=user.id)
    assert await svc.registration_allowed() is True
    await svc.set_registration(False, actor_id=user.id)
    assert await svc.registration_allowed() is False
    assert seen == ["registration", "registration"]

    rows = [r for r in await _audit_rows(session_factory) if r.action == "registration_updated"]
    assert [
        (r.request_data, r.endpoint, r.connector_name, r.scope_used, r.status) for r in rows
    ] == [
        (
            {"allow_registration": True},
            "/api/setup/registration",
            "installation",
            "admin",
            AuditStatus.approved,
        ),
        (
            {"allow_registration": False},
            "/api/setup/registration",
            "installation",
            "admin",
            AuditStatus.approved,
        ),
    ]


@pytest.mark.asyncio
async def test_set_registration_is_refused_under_the_lock(session_factory):
    svc = InstallationService(session_factory, config=_registration_env(False))
    user, _ = await make_user(session_factory, "o@example.com")
    assert await svc.setup_completed() is False  # reading creates the row
    audits_before = len(await _audit_rows(session_factory))
    with pytest.raises(installation_module.RegistrationLocked):
        await svc.set_registration(True, actor_id=user.id)
    assert (await _row(session_factory)).allow_registration is False
    assert len(await _audit_rows(session_factory)) == audits_before


@pytest.mark.asyncio
async def test_set_registration_takes_a_real_boolean(session_factory):
    svc = InstallationService(session_factory, config=_registration_env(None))
    user, _ = await make_user(session_factory, "o@example.com")
    with pytest.raises(ValueError):
        await svc.set_registration("yes", actor_id=user.id)  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# Legacy stamp (installs that predate the wizard)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("env_value", "stored"),
    [
        # Unset: an upgraded install is never left open by accident.
        (None, False),
        # The operator said so in .env: carried into the switch.
        (True, True),
        (False, False),
    ],
)
async def test_legacy_stamp_seeds_the_registration_switch(
    session_factory, monkeypatch, env_value, stored
):
    monkeypatch.setattr(settings, "ANTHROPIC_API_KEY", "env-key", raising=False)
    svc = InstallationService(session_factory, config=_registration_env(env_value))
    await make_user(session_factory, "o@example.com")
    assert await svc.stamp_setup_if_legacy() is True
    assert await svc.needs_setup() is False
    assert (await _row(session_factory)).allow_registration is stored
    assert await svc.registration_allowed() is stored


@pytest.mark.asyncio
async def test_legacy_stamp_for_an_env_ollama_install(session_factory, monkeypatch):
    monkeypatch.setattr(settings, "LLM_PROVIDER", "ollama", raising=False)
    svc = InstallationService(session_factory)
    await make_user(session_factory, "o@example.com")
    assert await svc.stamp_setup_if_legacy() is True


@pytest.mark.asyncio
async def test_mid_wizard_owner_with_a_db_key_is_not_stamped(session_factory):
    """An owner who saved a provider in the wizard and quit must resume
    the wizard after a restart, not be waved past it."""
    svc = InstallationService(session_factory)
    user, _ = await make_user(session_factory, "o@example.com")
    await svc.set_llm("anthropic", "claude-sonnet-5", "db-key", actor_id=user.id)
    assert await svc.provider_configured() is True
    assert await svc.stamp_setup_if_legacy() is False
    assert await svc.needs_setup() is True


@pytest.mark.asyncio
async def test_mid_wizard_owner_is_not_stamped_even_with_an_env_key(session_factory, monkeypatch):
    monkeypatch.setattr(settings, "ANTHROPIC_API_KEY", "env-key", raising=False)
    svc = InstallationService(session_factory)
    user, _ = await make_user(session_factory, "o@example.com")
    await svc.set_llm("openai", "gpt-4o-mini", "db-key", actor_id=user.id)
    assert await svc.stamp_setup_if_legacy() is False
    assert await svc.needs_setup() is True


@pytest.mark.asyncio
async def test_no_users_is_not_stamped(session_factory, monkeypatch):
    monkeypatch.setattr(settings, "ANTHROPIC_API_KEY", "env-key", raising=False)
    svc = InstallationService(session_factory)
    assert await svc.stamp_setup_if_legacy() is False
    assert await svc.setup_completed() is False


@pytest.mark.asyncio
async def test_users_without_any_key_are_not_stamped(session_factory):
    svc = InstallationService(session_factory)
    await make_user(session_factory, "o@example.com")
    assert await svc.stamp_setup_if_legacy() is False
    assert await svc.needs_setup() is True


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


def test_migration_0008_upgrades_a_database_that_already_has_users(tmp_path, monkeypatch):
    """An existing deployment: users exist when 0008 lands. The seeded row
    leaves setup incomplete and registration closed; the startup stamp then
    carries an env-configured install past the wizard."""
    db_path = tmp_path / "with_users.db"
    config = _alembic_config(db_path)
    command.upgrade(config, "0007_message_model")

    engine = sa.create_engine(f"sqlite:///{db_path}")
    try:
        with engine.begin() as conn:
            conn.execute(
                sa.text(
                    "INSERT INTO users (id, email, hashed_password, is_active, "
                    "created_at, updated_at) VALUES "
                    "(:id, 'legacy@example.com', 'x', 1, "
                    "'2026-01-01 00:00:00', '2026-01-01 00:00:00')"
                ),
                {"id": uuid.uuid4().hex},
            )
    finally:
        engine.dispose()

    command.upgrade(config, "0008_installation")
    rows = _installation_rows(db_path)
    assert len(rows) == 1
    _row_id, capabilities, allow_registration, setup_completed_at = rows[0]
    assert capabilities == "{}" and not allow_registration and setup_completed_at is None

    engine = sa.create_engine(f"sqlite:///{db_path}")
    try:
        with engine.connect() as conn:
            emails = conn.execute(sa.text("SELECT email FROM users")).scalars().all()
    finally:
        engine.dispose()
    assert emails == ["legacy@example.com"]

    # The service maps every installation column at head (0010 added
    # capability_settings); startup runs `upgrade head` before any service
    # call, so the stamp below runs against head too.
    command.upgrade(config, "head")

    monkeypatch.setattr(settings, "ANTHROPIC_API_KEY", "env-key", raising=False)

    async def _stamp() -> tuple[bool, bool, bool, bool]:
        async_engine = create_async_engine(f"sqlite+aiosqlite:///{db_path}")
        try:
            svc = InstallationService(async_sessionmaker(async_engine, expire_on_commit=False))
            before = await svc.needs_setup()
            stamped = await svc.stamp_setup_if_legacy()
            return before, stamped, await svc.needs_setup(), await svc.registration_allowed()
        finally:
            await async_engine.dispose()

    needed_before, stamped, needs_setup, registration = asyncio.run(_stamp())
    assert needed_before is True
    assert stamped is True
    assert needs_setup is False
    # conftest exports ALLOW_REGISTRATION=true, an explicit value, so the
    # stamp carries it into the row.
    assert registration is True
