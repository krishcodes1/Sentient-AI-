"""Tests for how scheduled tasks are declared and wired: the "scheduled_tasks"
capability (off by default, always available, its own refusal sentence and
budgets), the schedule tool family (every change on a card under every
account default, READ auto, EXECUTE and FINANCIAL blocked), the prompt line,
the list budget, progress lines, reserved names, length-only audit of the
prompt, the per-capability settings message, and main.wire_services building
the runner, the toolkit and the sweeper gated on the owner's switch.

Why it exists: the capability recipe (services/capabilities/README.md) is
what keeps a new family from being offered, run or audited differently from
the rest; these pin each step for this one.
"""

from __future__ import annotations

import pytest

from services import capabilities as registry
from services.agent.permissions import ActionCategory, PermissionEngine, PermissionTier
from services.agent.runtime import RESULT_CHAR_BUDGETS, SECURITY_SYSTEM_PROMPT
from services.agent.tool_registry import (
    _BUILTIN_STANCE,
    _BUILTIN_STARTER_TOOLS,
    BUILTIN_CONNECTOR_TYPES,
    CONNECTOR_CATALOG,
    ConnectorSpec,
    build_tools,
)
from tests.conftest import make_user


def test_the_capability():
    cap = registry.get("scheduled_tasks")
    assert cap.label == "Scheduled tasks and daily briefing"
    assert cap.tools == ("schedule.",) and cap.default_enabled is False and cap.risk == "medium"
    assert cap.when_denied == (
        "Scheduled tasks are off. The owner can turn on 'Scheduled tasks and daily "
        "briefing' in Settings → Permissions."
    )
    assert cap.description.startswith("Run prompts you approve on a schedule")
    assert cap.availability(registry.default_context()).available is True
    assert registry.settings_defaults("scheduled_tasks") == {
        "run_cap_cents": 5,
        "day_cap_cents": 25,
        "runs_per_day": 24,
    }
    for name in ("schedule.create", "schedule.briefing", "schedule.list", "schedule.pause", "schedule.delete"):
        assert registry.capability_for_tool(name) is cap


def test_the_family_is_offered_only_when_on_and_every_change_is_a_card():
    off = build_tools([], user_default_tier="auto_approve")
    assert not [t for t in off if t.name.startswith("schedule.")]
    on = {
        t.name: t
        for t in build_tools(
            [ConnectorSpec("canvas")],
            user_default_tier="auto_approve",
            enabled_capabilities=frozenset({"scheduled_tasks"}),
        )
    }
    assert on["schedule.list"].permission_tier == "auto"
    for name in ("schedule.create", "schedule.briefing", "schedule.pause", "schedule.delete"):
        assert on[name].permission_tier == "approval", name
    assert on["schedule.create"].starter and on["schedule.briefing"].starter
    assert {"schedule.create", "schedule.briefing"} <= _BUILTIN_STARTER_TOOLS
    assert "schedule" in BUILTIN_CONNECTOR_TYPES and _BUILTIN_STANCE["schedule"] == "user_confirm"
    specs = {s.action: s for s in CONNECTOR_CATALOG["schedule"]}
    assert specs["delete"].category == ActionCategory.DELETE
    assert all(specs[a].always_confirm for a in ("create", "briefing", "pause", "delete"))


def test_the_policy_rows():
    engine = PermissionEngine()
    tiers = {
        category: engine.check_permission(connector_type="schedule", action="x", scope=category).tier
        for category in ActionCategory
    }
    assert tiers[ActionCategory.READ] == PermissionTier.AUTO_APPROVE
    assert tiers[ActionCategory.WRITE] == PermissionTier.USER_CONFIRM
    assert tiers[ActionCategory.DELETE] == PermissionTier.USER_CONFIRM
    assert tiers[ActionCategory.EXECUTE] == PermissionTier.HARD_BLOCKED
    assert tiers[ActionCategory.FINANCIAL] == PermissionTier.HARD_BLOCKED


def test_prompt_line_budgets_phrases_names_and_undo_companions():
    from services.agent.context_manager import UNDO_COMPANIONS
    from services.connectors.registry import RESERVED_KEYS
    from services.notifications import progress

    assert "schedule.create / schedule.briefing; if the tool says the time\n  zone is unknown, ask the user." in SECURITY_SYSTEM_PROMPT
    assert SECURITY_SYSTEM_PROMPT.index("watch.create") < SECURITY_SYSTEM_PROMPT.index("schedule.create") < SECURITY_SYSTEM_PROMPT.index("</capabilities>")
    assert RESULT_CHAR_BUDGETS["schedule.list"] == 8000
    assert progress._TOOL_PHRASES["schedule.list"].endswith("…")
    assert "schedule" in RESERVED_KEYS
    assert UNDO_COMPANIONS["schedule.create"] == ("schedule.list", "schedule.delete")
    assert UNDO_COMPANIONS["schedule.briefing"] == ("schedule.list", "schedule.delete")


def test_the_prompt_and_topic_are_audited_as_their_length():
    from services.audit import redact_tool_arguments

    assert redact_tool_arguments("schedule.create", {"prompt": "secret plan", "label": "L"}) == {
        "prompt": "<11 characters>",
        "label": "L",
    }
    assert redact_tool_arguments("schedule.briefing", {"topic": "AI"})["topic"] == "<2 characters>"


@pytest.mark.asyncio
async def test_out_of_bounds_settings_are_worded_per_capability(session_factory):
    from services.installation import InstallationService

    owner, _ = await make_user(session_factory, "bounds@example.com")
    service = InstallationService(session_factory)
    with pytest.raises(ValueError, match="Enter a whole number from 1 to 10,000."):
        await service.set_capability_settings("scheduled_tasks", {"run_cap_cents": 0}, actor_id=owner.id)
    with pytest.raises(ValueError, match=r"Caps must be between \$1 and \$10,000."):
        await service.set_capability_settings("purchases", {"per_day_cap_usd": 0}, actor_id=owner.id)
    saved = await service.set_capability_settings("scheduled_tasks", {"runs_per_day": 6}, actor_id=owner.id)
    assert saved == {"run_cap_cents": 5, "day_cap_cents": 25, "runs_per_day": 6}


def test_the_install_default_zone_reads_crawler_timezone(monkeypatch):
    from core.config import Settings

    monkeypatch.setenv("CRAWLER_TIMEZONE", "America/Chicago")
    assert Settings().DEFAULT_TIMEZONE == "America/Chicago"
    monkeypatch.delenv("CRAWLER_TIMEZONE")
    assert Settings(_env_file=None).DEFAULT_TIMEZONE is None


@pytest.mark.asyncio
async def test_wire_services_builds_the_runner_the_toolkit_and_the_gated_sweeper(session_factory, monkeypatch):
    from core.config import settings
    from main import app, wire_services
    from services.automation.turns import UnattendedTurnRunner
    from services.notifications.schedules import ScheduleService
    from services.scheduler import commands as schedule_commands
    from services.tools.schedule import ScheduleToolkit
    from tests.test_telegram_manager import FakeService

    monkeypatch.setattr(settings, "TELEGRAM_BOT_TOKEN", "", raising=False)
    saved = dict(app.state._state)
    await wire_services(app, session_factory, telegram_service_factory=FakeService)
    try:
        assert isinstance(app.state.unattended_runner, UnattendedTurnRunner)
        assert isinstance(app.state.schedule_toolkit, ScheduleToolkit)
        sweeper = app.state.schedules
        assert isinstance(sweeper, ScheduleService) and sweeper.runner is app.state.unattended_runner
        assert set(sweeper.senders) == {"telegram", "slack"}
        assert schedule_commands.current().service is sweeper
        # Off by default: the gate is closed.
        assert await sweeper._gate_on("prompt", {}) is False
        owner, _ = await make_user(session_factory, "wire-sched@example.com")
        await app.state.installation.set_capabilities({"scheduled_tasks": True}, actor_id=owner.id)
        await app.state.slack_manager.wait_idle()
        assert await sweeper._gate_on("prompt", {}) is True
    finally:
        schedule_commands.configure(None)
        await app.state.telegram_manager.stop()
        await app.state.slack_manager.stop()
        app.state._state.clear()
        app.state._state.update(saved)
