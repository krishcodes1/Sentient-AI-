"""Tests for the "breach_monitor" capability (services/capabilities/breach_monitor.py):
they prove it is a policy switch that is on by default, claims no tool and has
no settings; that it reads blocked, with the plain fix, until a Have I Been Pwned
key is configured (stored or in the environment) while the owner's switch stays
on, which is what the keyless password check reads; that an HIBP key in the
environment makes it available and opens the sweeper's capability gate; and
that the <permissions> line names the owner's switch when it is off and the
missing key when it is blocked.

Why it exists: nothing may be sent to Have I Been Pwned without the owner's own
key (decisions.md item 2), and the password check must keep working without one
unless the owner turned breach checks off. The report is the one place both
facts come from. The wiring test proves main.wire_services hangs the real
service on app.state with the owner's gate, the owner's key and the shared
owner sender, and kicks it on every "capabilities" change only.
"""

from __future__ import annotations

import pytest

from core.config import SERVICE_KEY_FIELDS, settings
from services import capabilities as registry
from services.capabilities import breach_monitor
from services.capabilities.base import ReportContext
from services.capabilities.prompt import render_permissions_block
from services.installation import InstallationService
from services.notifications.sweeper import capability_gate
from tests.conftest import make_user

HIBP_KEY = "0123456789abcdef" * 2  # built, never a literal key (scaffold C6)
BLOCKED_REASON = (
    "Breach checks use your own Have I Been Pwned key, and none is saved yet. "
    "Add one in Security → Service keys."
)


@pytest.fixture(autouse=True)
def _no_env_service_keys(monkeypatch):
    """A developer .env must not decide these tests: every service key starts unset."""
    for attr in SERVICE_KEY_FIELDS.values():
        monkeypatch.setattr(settings, attr, None, raising=False)


def _status(*, switch_on: bool = True, service_keys: frozenset[str] = frozenset()):
    ctx = ReportContext(
        in_container=False,
        platform="win32",
        telegram_configured=True,
        browser_installed=True,
        service_keys=service_keys,
    )
    switches = {key: registry.get(key).default_enabled for key in registry.keys()}
    switches["breach_monitor"] = switch_on
    return registry.statuses_by_key(registry.report(switches, ctx, use_cache=False))[
        "breach_monitor"
    ]


def test_breach_monitor_is_a_policy_switch_on_by_default_that_claims_no_tool():
    cap = registry.get("breach_monitor")
    assert cap is breach_monitor.CAPABILITY
    assert cap.label == "Watch my email addresses for data breaches"
    assert cap.tools == () and cap.default_enabled is True and cap.risk == "low"
    assert registry.settings_defaults("breach_monitor") == {}
    for name in ("breach.check", "hibp.lookup", "security.breach"):
        found = registry.capability_for_tool(name)
        assert found is None or found.key != "breach_monitor"
    # In the security block, in skill order (A25).
    keys = registry.keys()
    assert (
        keys.index("mcp_pinning") < keys.index("breach_monitor") < keys.index("browser_site_rules")
    )


def test_breach_monitor_is_blocked_with_a_plain_fix_until_an_hibp_key_is_configured():
    blocked = _status()
    assert blocked.effective == "blocked"
    assert blocked.reason == BLOCKED_REASON
    # The owner's switch is still on: the keyless password check reads this, not effective.
    assert blocked.enabled is True and blocked.available is False

    other_keys = _status(service_keys=frozenset({"safe_browsing", "virustotal"}))
    assert other_keys.effective == "blocked"

    on = _status(service_keys=frozenset({"hibp"}))
    assert on.effective == "on" and on.enabled is True and on.available is True

    off = _status(switch_on=False, service_keys=frozenset({"hibp"}))
    assert off.effective == "off" and off.enabled is False


@pytest.mark.asyncio
async def test_an_hibp_key_in_the_environment_makes_breach_monitor_available(
    session_factory, monkeypatch
):
    svc = InstallationService(session_factory)
    gate = capability_gate(svc, "breach_monitor")
    statuses = await svc.capability_statuses()
    assert statuses["breach_monitor"].effective == "blocked"
    assert await gate() is False

    monkeypatch.setattr(settings, "HIBP_API_KEY", HIBP_KEY, raising=False)
    fresh = InstallationService(session_factory)
    assert await fresh.service_key("hibp") == HIBP_KEY
    statuses = await fresh.capability_statuses()
    assert statuses["breach_monitor"].effective == "on"
    assert await capability_gate(fresh, "breach_monitor")() is True


def test_the_permissions_block_line_for_breach_monitor_names_the_owner_switch():
    blocked = render_permissions_block([_status()])
    assert blocked.splitlines()[1] == (
        f"- Watch my email addresses for data breaches: blocked. {BLOCKED_REASON}"
    )
    off = render_permissions_block([_status(switch_on=False)])
    assert off.splitlines()[1] == (
        "- Watch my email addresses for data breaches: off. Breach monitoring is off. "
        "The owner can turn on 'Watch my email addresses for data breaches' in Settings "
        "→ Permissions; it needs their own Have I Been Pwned key."
    )
    on = render_permissions_block([_status(service_keys=frozenset({"hibp"}))])
    assert on.splitlines()[1] == "- Watch my email addresses for data breaches: on"


@pytest.mark.asyncio
async def test_wire_services_hangs_the_breach_monitor_on_app_state_with_the_owners_gate(
    session_factory, monkeypatch
):
    from main import app, wire_services
    from services.notifications.breach_monitor import BreachMonitorService
    from services.scheduler import commands as schedule_commands
    from tests.test_telegram_manager import FakeService

    monkeypatch.setattr(settings, "TELEGRAM_BOT_TOKEN", "", raising=False)
    saved = dict(app.state._state)
    await wire_services(app, session_factory, telegram_service_factory=FakeService)
    try:
        service = app.state.breach_monitor
        assert isinstance(service, BreachMonitorService)
        # Alerts go through the one shared owner sender (A34), nowhere else.
        assert service.send is app.state.owner_send
        # The gate is the owner's report: closed without a key (blocked), so nothing runs.
        assert await service._is_enabled() is False
        assert await service._key() is None
        assert await service.sweep_once() == 0

        # An HIBP key in the environment opens the gate and is the key the service reads.
        monkeypatch.setattr(settings, "HIBP_API_KEY", HIBP_KEY, raising=False)
        app.state.installation.invalidate()
        assert await service._is_enabled() is True
        assert await service._key() == HIBP_KEY

        # The owner's switch closes it again, with the key still there.
        kicks: list[str] = []
        monkeypatch.setattr(service, "kick", lambda: kicks.append("kick"))
        owner, _ = await make_user(session_factory, email="wiring-owner@example.com")
        await app.state.installation.set_capabilities({"breach_monitor": False}, actor_id=owner.id)
        assert await service._is_enabled() is False
        # A "capabilities" change (a key saved or removed, a switch flipped) kicks one sweep;
        # other topics do not.
        assert kicks == ["kick"]
        await app.state.installation._changed("telegram")
        assert kicks == ["kick"]
    finally:
        schedule_commands.configure(None)
        await app.state.telegram_manager.stop()
        await app.state.slack_manager.stop()
        app.state._state.clear()
        app.state._state.update(saved)
