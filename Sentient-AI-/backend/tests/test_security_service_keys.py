"""Tests for the owner key store of the security wave (InstallationService's
service keys, the report's ``service_keys`` fact and the key registry in
services/reputation/keys.py): they prove a saved key is encrypted at rest and
never in a repr, an audit row or a log line; the environment's key wins and
counts without a stored one; the report fact follows a save or a removal
without a restart; a blob that no longer decrypts reads as no keys, is never
overwritten and is reported, while an environment key keeps working;
clearing the stored secrets discards the blob and says so only when there was
one; and the registry has one row per configured service whose lazy tester
refuses while the skill's module does not exist.

Why it exists: three skills (link reputation, breach monitor, file
reputation) send data to a third party only with the owner's own key
(decisions 2). If this store leaked a key, overwrote a blob it cannot read,
or reported a key that is not there, a check would run without consent or
the owner would lose their keys. Keys here are built by concatenation so no
scanner sees a literal one.
"""

from __future__ import annotations

import base64
import json
import os
import sys
import types
import uuid

import pytest
from sqlalchemy import select

from core.config import SERVICE_KEY_FIELDS, settings
from core.security import decrypt_credentials, sanitize_for_logging
from models.audit import AuditLog
from models.installation import Installation
from services import capabilities as registry
from services.capabilities.base import ReportContext
from services.installation import UNREADABLE_SERVICE_KEYS_MESSAGE, InstallationService
from services.reputation import keys as key_registry
from services.reputation.keys import KeyTestResult, service_key_specs, spec_for
from tests.conftest import make_user

GOOGLE_KEY = "AIza" + "FAKEfake" * 4 + "000"
OTHER_GOOGLE_KEY = "AIza" + "OTHERkey" * 4 + "111"
HIBP_KEY = "a" * 32
VIRUSTOTAL_KEY = "b" * 64


@pytest.fixture(autouse=True)
def _no_env_service_keys(monkeypatch):
    """A developer .env must not decide these tests: every service key starts
    unset in the environment."""
    for attr in SERVICE_KEY_FIELDS.values():
        monkeypatch.setattr(settings, attr, None, raising=False)


async def _row(session_factory) -> Installation:
    async with session_factory() as s:
        return (await s.execute(select(Installation))).scalar_one()


async def _audit_rows(session_factory) -> list[AuditLog]:
    async with session_factory() as s:
        return list((await s.execute(select(AuditLog).order_by(AuditLog.seq))).scalars())


def _other_encryption_key() -> str:
    return base64.urlsafe_b64encode(os.urandom(32)).decode("utf-8")


# ── storage ──────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_a_saved_service_key_is_encrypted_at_rest_and_only_names_with_a_key_are_stored(
    session_factory,
):
    svc = InstallationService(session_factory)
    user, _ = await make_user(session_factory, "owner@example.com")
    await svc.set_service_key("safe_browsing", GOOGLE_KEY, actor_id=user.id)
    await svc.set_service_key("virustotal", f"  {VIRUSTOTAL_KEY}  ", actor_id=user.id)

    row = await _row(session_factory)
    assert row.security_service_keys is not None
    assert GOOGLE_KEY.encode() not in bytes(row.security_service_keys)
    assert json.loads(decrypt_credentials(row.security_service_keys)) == {
        "safe_browsing": GOOGLE_KEY,
        "virustotal": VIRUSTOTAL_KEY,  # stripped
    }
    assert await svc.service_key("safe_browsing") == GOOGLE_KEY
    assert await svc.service_key("web_risk") is None

    # Removing the last key leaves no blob at all.
    await svc.set_service_key("safe_browsing", None, actor_id=user.id)
    await svc.set_service_key("virustotal", "   ", actor_id=user.id)
    assert (await _row(session_factory)).security_service_keys is None
    assert await svc.configured_service_keys() == frozenset()


@pytest.mark.asyncio
async def test_the_environment_key_wins_and_counts_without_a_stored_one(
    session_factory, monkeypatch
):
    svc = InstallationService(session_factory)
    user, _ = await make_user(session_factory, "owner@example.com")
    await svc.set_service_key("web_risk", GOOGLE_KEY, actor_id=user.id)
    monkeypatch.setattr(settings, "WEB_RISK_API_KEY", f" {OTHER_GOOGLE_KEY} ", raising=False)
    monkeypatch.setattr(settings, "HIBP_API_KEY", HIBP_KEY, raising=False)
    svc.invalidate()

    assert await svc.service_key("web_risk") == OTHER_GOOGLE_KEY
    assert await svc.service_key("hibp") == HIBP_KEY
    assert await svc.configured_service_keys() == frozenset({"web_risk", "hibp"})
    assert await svc.service_key_status() == {
        "safe_browsing": {"key_from_env": False, "key_stored": False},
        "web_risk": {"key_from_env": True, "key_stored": True},
        "hibp": {"key_from_env": True, "key_stored": False},
        "virustotal": {"key_from_env": False, "key_stored": False},
    }
    # An empty or blank environment value is no key.
    monkeypatch.setattr(settings, "HIBP_API_KEY", "  ", raising=False)
    assert await svc.service_key("hibp") is None


@pytest.mark.asyncio
async def test_service_key_status_lists_every_service_in_order_with_booleans_only(
    session_factory,
):
    svc = InstallationService(session_factory)
    user, _ = await make_user(session_factory, "owner@example.com")
    await svc.set_service_key("hibp", HIBP_KEY, actor_id=user.id)
    status = await svc.service_key_status()
    assert list(status) == list(SERVICE_KEY_FIELDS)
    assert status["hibp"] == {"key_from_env": False, "key_stored": True}
    for flags in status.values():
        assert all(isinstance(value, bool) for value in flags.values())
    assert HIBP_KEY not in json.dumps(status)


@pytest.mark.asyncio
async def test_an_unknown_service_is_refused_without_echoing_the_name(session_factory):
    svc = InstallationService(session_factory)
    user, _ = await make_user(session_factory, "owner@example.com")
    pasted = "AIza-pasted-into-the-name"
    with pytest.raises(ValueError) as refused:
        await svc.set_service_key(pasted, GOOGLE_KEY, actor_id=user.id)
    assert str(refused.value) == "Unknown service"
    assert await svc.service_key(pasted) is None
    assert await svc.service_key("") is None
    assert await _audit_rows(session_factory) == []


@pytest.mark.asyncio
async def test_every_write_is_audited_as_service_key_updated_with_booleans_and_no_key(
    session_factory,
):
    svc = InstallationService(session_factory)
    user, _ = await make_user(session_factory, "owner@example.com")
    await svc.set_service_key("safe_browsing", GOOGLE_KEY, actor_id=user.id)
    await svc.set_service_key("safe_browsing", None, actor_id=user.id)
    rows = await _audit_rows(session_factory)
    assert [
        (r.action, r.endpoint, r.scope_used, r.connector_name, r.request_data) for r in rows
    ] == [
        (
            "service_key_updated",
            "/api/security/keys/safe_browsing",
            "admin",
            "installation",
            {"service": "safe_browsing", "key_stored": True},
        ),
        (
            "service_key_updated",
            "/api/security/keys/safe_browsing",
            "admin",
            "installation",
            {"service": "safe_browsing", "key_stored": False},
        ),
    ]
    for row in rows:
        columns = {c.name: getattr(row, c.name) for c in AuditLog.__table__.columns}
        assert GOOGLE_KEY not in json.dumps(columns, default=str)


# ── the report fact ─────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_the_report_fact_follows_a_save_and_a_removal_without_a_restart(session_factory):
    svc = InstallationService(session_factory)
    user, _ = await make_user(session_factory, "owner@example.com")
    topics: list[str] = []

    async def listener(topic: str) -> None:
        topics.append(topic)

    svc.on_change(listener)
    assert (await svc.context()).service_keys == frozenset()

    await svc.set_service_key("hibp", HIBP_KEY, actor_id=user.id)
    assert (await svc.context()).service_keys == frozenset({"hibp"})
    await svc.set_service_key("hibp", None, actor_id=user.id)
    assert (await svc.context()).service_keys == frozenset()
    assert topics == ["capabilities", "capabilities"]


@pytest.mark.asyncio
async def test_a_saved_key_unblocks_only_the_capability_that_uses_it(session_factory):
    svc = InstallationService(session_factory)
    user, _ = await make_user(session_factory, "owner@example.com")

    async def effective() -> dict[str, str]:
        statuses = await svc.capability_statuses()
        return {key: statuses[key].effective for key in ("link_reputation", "breach_monitor")}

    # On by default, blocked until a key exists, with the reason the owner reads.
    assert await effective() == {"link_reputation": "blocked", "breach_monitor": "blocked"}
    statuses = await svc.capability_statuses()
    assert "Security → Service keys" in statuses["link_reputation"].reason
    assert "Have I Been Pwned key" in statuses["breach_monitor"].reason

    # A VirusTotal key unblocks neither; Web Risk unblocks link reputation only.
    await svc.set_service_key("virustotal", VIRUSTOTAL_KEY, actor_id=user.id)
    assert await effective() == {"link_reputation": "blocked", "breach_monitor": "blocked"}
    await svc.set_service_key("web_risk", GOOGLE_KEY, actor_id=user.id)
    assert await effective() == {"link_reputation": "on", "breach_monitor": "blocked"}
    await svc.set_service_key("hibp", HIBP_KEY, actor_id=user.id)
    assert await effective() == {"link_reputation": "on", "breach_monitor": "on"}
    await svc.set_service_key("web_risk", None, actor_id=user.id)
    assert await effective() == {"link_reputation": "blocked", "breach_monitor": "on"}


def test_the_report_context_carries_service_keys_and_stays_hashable():
    ctx = registry.default_context(service_keys=frozenset({"web_risk"}))
    assert ctx.service_keys == frozenset({"web_risk"})
    assert registry.default_context().service_keys == frozenset()
    # Part of the probe-cache key: it must hash, and two equal facts are one key.
    plain = ReportContext(
        in_container=False,
        platform="linux",
        telegram_configured=False,
        browser_installed=False,
        service_keys=frozenset({"hibp"}),
    )
    same = ReportContext(
        in_container=False,
        platform="linux",
        telegram_configured=False,
        browser_installed=False,
        service_keys=frozenset({"hibp"}),
    )
    assert hash(plain) == hash(same) and {plain: 1}[same] == 1


# ── unreadable and cleared ──────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_an_unreadable_blob_reads_as_no_keys_is_never_overwritten_and_is_reported(
    session_factory, monkeypatch
):
    svc = InstallationService(session_factory)
    user, _ = await make_user(session_factory, "owner@example.com")
    await svc.set_service_key("virustotal", VIRUSTOTAL_KEY, actor_id=user.id)
    before = bytes((await _row(session_factory)).security_service_keys)
    original_key = settings.ENCRYPTION_KEY

    monkeypatch.setattr(settings, "ENCRYPTION_KEY", _other_encryption_key())
    svc.invalidate()
    assert await svc.service_keys_unreadable() is True
    assert await svc.secrets_unreadable() is True
    assert await svc.service_key("virustotal") is None
    assert await svc.configured_service_keys() == frozenset()
    assert (await svc.service_key_status())["virustotal"]["key_stored"] is False

    for attempt in (VIRUSTOTAL_KEY, None):
        with pytest.raises(RuntimeError) as refused:
            await svc.set_service_key("virustotal", attempt, actor_id=user.id)
        assert str(refused.value) == UNREADABLE_SERVICE_KEYS_MESSAGE
    assert bytes((await _row(session_factory)).security_service_keys) == before

    # An environment key keeps working while the stored blob cannot be read.
    monkeypatch.setattr(settings, "VIRUSTOTAL_API_KEY", "c" * 64, raising=False)
    assert await svc.service_key("virustotal") == "c" * 64
    monkeypatch.setattr(settings, "VIRUSTOTAL_API_KEY", None, raising=False)

    # Restoring the encryption key brings the stored key back.
    monkeypatch.setattr(settings, "ENCRYPTION_KEY", original_key)
    svc.invalidate()
    assert await svc.service_keys_unreadable() is False
    assert await svc.service_key("virustotal") == VIRUSTOTAL_KEY


@pytest.mark.asyncio
async def test_clearing_secrets_discards_the_service_keys_and_names_them_only_when_there_were_some(
    session_factory, monkeypatch
):
    svc = InstallationService(session_factory)
    user, _ = await make_user(session_factory, "owner@example.com")
    topics: list[str] = []

    async def listener(topic: str) -> None:
        topics.append(topic)

    svc.on_change(listener)
    # Nothing stored: the payload is exactly today's, and nothing is heard.
    await svc.clear_stored_secrets(actor_id=user.id)
    assert (await _audit_rows(session_factory))[-1].request_data == {
        "provider_keys_cleared": False,
        "telegram_cleared": False,
    }
    assert topics == []

    await svc.set_service_key("safe_browsing", GOOGLE_KEY, actor_id=user.id)
    monkeypatch.setattr(settings, "ENCRYPTION_KEY", _other_encryption_key())
    svc.invalidate()
    topics.clear()
    await svc.clear_stored_secrets(actor_id=user.id)
    assert (await _row(session_factory)).security_service_keys is None
    assert (await _audit_rows(session_factory))[-1].request_data == {
        "provider_keys_cleared": False,
        "telegram_cleared": False,
        "service_keys_cleared": True,
    }
    assert topics == ["capabilities"]
    assert await svc.secrets_unreadable() is False


@pytest.mark.asyncio
async def test_the_undecryptable_service_keys_warning_names_its_own_blob_once(
    session_factory, monkeypatch
):
    import services.installation as installation_module

    svc = InstallationService(session_factory)
    user, _ = await make_user(session_factory, "owner@example.com")
    await svc.set_service_key("hibp", HIBP_KEY, actor_id=user.id)
    events: list[tuple[str, dict]] = []

    class _Logger:
        def warning(self, event: str, **fields) -> None:
            events.append((event, fields))

    monkeypatch.setattr(installation_module, "logger", _Logger())
    monkeypatch.setattr(settings, "ENCRYPTION_KEY", _other_encryption_key())
    for _ in range(3):
        svc.invalidate()
        await svc.service_keys_unreadable()
    assert [event for event, _fields in events] == ["installation_service_keys_undecryptable"]
    assert HIBP_KEY not in json.dumps(events)


@pytest.mark.asyncio
async def test_the_snapshot_repr_never_shows_a_service_key(session_factory):
    svc = InstallationService(session_factory)
    user, _ = await make_user(session_factory, "owner@example.com")
    await svc.set_service_key("hibp", HIBP_KEY, actor_id=user.id)
    snap = await svc._load()
    assert snap.service_keys == {"hibp": HIBP_KEY}
    assert HIBP_KEY not in repr(snap)


# ── log masking ──────────────────────────────────────────────────────────────


def test_the_log_sanitiser_masks_every_service_key_name_and_header():
    data = {
        "X-Goog-Api-Key": GOOGLE_KEY,
        "x_goog_api_key": GOOGLE_KEY,
        "hibp-api-key": HIBP_KEY,
        "HIBP_API_KEY": HIBP_KEY,
        "x-apikey": VIRUSTOTAL_KEY,
        "x_apikey": VIRUSTOTAL_KEY,
        "service_key": GOOGLE_KEY,
        "security_service_keys": GOOGLE_KEY,
        "SAFE_BROWSING_API_KEY": GOOGLE_KEY,
        "web_risk_api_key": GOOGLE_KEY,
        "virustotal_api_key": VIRUSTOTAL_KEY,
        "service": "safe_browsing",
    }
    masked = sanitize_for_logging(data)
    assert masked.pop("service") == "safe_browsing"
    assert set(masked.values()) == {"***"}


# ── the key registry ────────────────────────────────────────────────────────


def test_the_key_registry_has_one_row_per_configured_service_in_order():
    specs = service_key_specs()
    assert [spec.name for spec in specs] == list(SERVICE_KEY_FIELDS)
    assert [spec.label for spec in specs] == [
        "Google Safe Browsing",
        "Google Web Risk",
        "Have I Been Pwned",
        "VirusTotal",
    ]
    for spec in specs:
        assert spec_for(spec.name) is spec
        assert spec.used_for and spec.note and spec.key_hint and spec.format_message
        assert spec.console_url.startswith("https://")
    assert spec_for("google") is None and spec_for("") is None


@pytest.mark.parametrize(
    "name,good,bad",
    [
        ("safe_browsing", GOOGLE_KEY, ["AIza" + "x" * 34, "BIza" + "x" * 35, GOOGLE_KEY + "!"]),
        ("web_risk", OTHER_GOOGLE_KEY, ["AIza" + "x" * 36, "AIza" + "x" * 34 + " "]),
        ("hibp", HIBP_KEY, ["a" * 31, "g" * 32, "a" * 33]),
        ("virustotal", VIRUSTOTAL_KEY, ["b" * 63, "z" * 64, "b" * 65]),
    ],
)
def test_each_key_pattern_accepts_its_documented_shape_and_refuses_others(name, good, bad):
    spec = spec_for(name)
    assert spec is not None
    assert spec.key_pattern.fullmatch(good)
    assert spec.key_pattern.fullmatch(good.upper() if name in ("hibp", "virustotal") else good)
    for key in bad:
        assert not spec.key_pattern.fullmatch(key), key
        assert key not in spec.format_message


@pytest.mark.asyncio
async def test_a_tester_whose_skill_module_does_not_exist_refuses_with_its_own_sentence():
    tester = key_registry._lazy_tester(
        "services.reputation.not_built_yet_" + uuid.uuid4().hex,
        "test_key",
        not_built="Example keys cannot be checked yet.",
    )
    result = await tester(GOOGLE_KEY)
    assert result == KeyTestResult(False, "Example keys cannot be checked yet.")
    # A whole missing skill package counts the same.
    tester = key_registry._lazy_tester(
        "services.not_a_skill_" + uuid.uuid4().hex + ".client",
        "check_key",
        not_built="Example keys cannot be checked yet.",
    )
    assert (await tester(HIBP_KEY)).ok is False


@pytest.mark.asyncio
async def test_a_built_tester_is_imported_lazily_and_called_with_its_leading_arguments(
    monkeypatch,
):
    calls: list[tuple] = []

    async def check(service: str, key: str) -> KeyTestResult:
        calls.append((service, key))
        return KeyTestResult(True, "Google accepted the key.")

    name = "services.reputation.fake_links_" + uuid.uuid4().hex
    module = types.ModuleType(name)
    module.check = check  # type: ignore[attr-defined]
    tester = key_registry._lazy_tester(name, "check", leading=("web_risk",), not_built="no")
    monkeypatch.setitem(sys.modules, name, module)
    assert await tester(GOOGLE_KEY) == KeyTestResult(True, "Google accepted the key.")
    assert calls == [("web_risk", GOOGLE_KEY)]


@pytest.mark.asyncio
async def test_a_broken_import_inside_a_built_tester_module_is_raised_not_hidden(monkeypatch):
    import importlib

    name = "services.reputation.broken_" + uuid.uuid4().hex
    real_import = importlib.import_module

    def fake_import(module: str, *args, **kwargs):
        if module == name:
            raise ModuleNotFoundError("No module named 'some_dependency'", name="some_dependency")
        return real_import(module, *args, **kwargs)

    monkeypatch.setattr(key_registry.importlib, "import_module", fake_import)
    tester = key_registry._lazy_tester(name, "check", not_built="no")
    with pytest.raises(ModuleNotFoundError):
        await tester(GOOGLE_KEY)
