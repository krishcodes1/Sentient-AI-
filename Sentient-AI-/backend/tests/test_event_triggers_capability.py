"""Tests for how app-event triggers are declared and wired: the two
capabilities ("event_triggers": off by default, available only with Telegram
or Slack to deliver; "trigger_runs": off by default, high risk, gating an
argument and blocked while "event_triggers" is off), the family's offer
(every change a card under every account default, reads auto), the
/api/triggers routes (owner-scoped, audited, a foreign id is a 404), and
main.wire_services building the sweeper, the toolkit and the page-watch hook.

Why it exists: the capability recipe (services/capabilities/README.md) is what
keeps a new family from being offered, run or audited differently from the
rest; these pin each step for this one.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

import pytest
from sqlalchemy import select

from services import capabilities as registry
from services.agent.tool_registry import ConnectorSpec, build_tools
from services.capabilities.base import ReportContext
from tests.conftest import auth_headers, make_user

NOW = datetime(2026, 9, 30, 12, 0, tzinfo=timezone.utc)


def ctx(**facts) -> ReportContext:
    return ReportContext(in_container=True, platform="linux", telegram_configured=True, browser_installed=False, **facts)


def test_event_triggers_needs_a_chat_channel_to_deliver():
    cap = registry.get("event_triggers")
    assert cap.label == "Tell me when something happens in my apps"
    assert cap.tools == ("triggers.",) and cap.default_enabled is False and cap.risk == "medium"
    assert cap.description.startswith("Check your connected apps on a schedule")
    assert cap.when_denied == (
        "App triggers are turned off. The owner can turn on 'Tell me when something happens "
        "in my apps' in Settings → Permissions."
    )
    assert cap.availability(ctx(telegram_enabled=True)).available is True
    assert cap.availability(ctx(slack_configured=True)).available is True
    none = cap.availability(ctx())
    assert none.available is False and none.reason.startswith("Trigger alerts go out over Telegram or Slack")
    for name in ("triggers.create", "triggers.list", "triggers.history", "triggers.update", "triggers.delete"):
        assert registry.capability_for_tool(name) is cap


def test_trigger_runs_gates_an_argument_and_needs_event_triggers():
    cap = registry.get("trigger_runs")
    assert cap.label == "Run a task when something happens in my apps"
    assert cap.tools == () and cap.default_enabled is False and cap.risk == "high"
    assert cap.requires == ("event_triggers",)
    assert cap.when_denied.startswith("Running tasks from triggers is off.")
    statuses = {s.key: s for s in registry.report({"trigger_runs": True}, ctx(telegram_enabled=True))}
    assert statuses["trigger_runs"].effective == "blocked"
    both = registry.enabled_keys({"trigger_runs": True, "event_triggers": True}, ctx(telegram_enabled=True))
    assert {"trigger_runs", "event_triggers"} <= both
    assert "trigger_runs" not in registry.enabled_keys({"trigger_runs": True, "event_triggers": True}, ctx())


def test_the_family_is_offered_only_when_on_and_every_change_is_a_card():
    off = build_tools([], user_default_tier="auto_approve")
    assert not [t for t in off if t.name.startswith("triggers.")]
    on = {
        t.name: t
        for t in build_tools(
            [ConnectorSpec("canvas")],
            user_default_tier="auto_approve",
            enabled_capabilities=frozenset({"event_triggers"}),
        )
    }
    assert on["triggers.list"].permission_tier == "auto" and on["triggers.history"].permission_tier == "auto"
    for name in ("triggers.create", "triggers.update", "triggers.delete"):
        assert on[name].permission_tier == "approval", name
    assert on["triggers.create"].starter


def test_the_readme_describes_a_capability_that_gates_an_argument():
    from pathlib import Path

    readme = (Path(__file__).resolve().parents[1] / "services" / "capabilities" / "README.md").read_text(encoding="utf-8")
    assert "## A capability that gates an argument" in readme


# -- the REST routes ---------------------------------------------------------------------


@pytest.fixture
def wired(session_factory):
    from main import app
    from services.tools.triggers import TriggerToolkit

    saved = getattr(app.state, "trigger_toolkit", None)
    app.state.trigger_toolkit = TriggerToolkit(session_factory, clock=lambda: NOW)
    yield app.state.trigger_toolkit
    app.state.trigger_toolkit = saved


async def add_trigger(session_factory, user, label="Canvas posts") -> str:
    from models.event_trigger import EventTrigger

    trigger_id = uuid.uuid4()
    async with session_factory() as session:
        session.add(
            EventTrigger(
                id=trigger_id,
                user_id=user.id,
                label=label,
                source="canvas.announcement",
                filters={},
                fingerprint=uuid.uuid4().hex,
                mode="notify",
                interval_minutes=60,
                status="error",
                consecutive_errors=5,
                last_error="The app did not answer in time.",
                next_check_at=NOW,
                created_at=NOW,
                updated_at=NOW,
            )
        )
        await session.commit()
    return str(trigger_id)


@pytest.mark.asyncio
async def test_the_routes_list_pause_resume_and_delete_only_the_owners(client, session_factory, wired):
    from models.audit import AuditLog

    owner, token = await make_user(session_factory, "routes-owner@example.com")
    other, other_token = await make_user(session_factory, "routes-other@example.com")
    trigger_id = await add_trigger(session_factory, owner)
    headers, strange = auth_headers(token), auth_headers(other_token)

    listed = await client.get("/api/triggers", headers=headers)
    assert listed.status_code == 200 and listed.json()["count"] == 1
    assert listed.json()["triggers"][0]["last_error"] == "The app did not answer in time."
    assert (await client.get("/api/triggers", headers=strange)).json()["count"] == 0

    assert (await client.patch(f"/api/triggers/{trigger_id}", json={"paused": True}, headers=strange)).status_code == 404
    assert (await client.delete(f"/api/triggers/{trigger_id}", headers=strange)).status_code == 404
    assert (await client.patch(f"/api/triggers/{uuid.uuid4()}", json={"paused": True}, headers=headers)).status_code == 404

    resumed = await client.patch(f"/api/triggers/{trigger_id}", json={"paused": False}, headers=headers)
    assert resumed.status_code == 200 and resumed.json()["status"] == "active"
    paused = await client.patch(f"/api/triggers/{trigger_id}", json={"paused": True}, headers=headers)
    assert paused.json()["status"] == "paused"
    assert (await client.delete(f"/api/triggers/{trigger_id}", headers=headers)).status_code == 204
    assert (await client.get("/api/triggers", headers=headers)).json()["count"] == 0
    assert (await client.get("/api/triggers")).status_code == 401

    async with session_factory() as session:
        rows = list(
            (
                await session.execute(
                    select(AuditLog).where(AuditLog.connector_name == "triggers").order_by(AuditLog.seq)
                )
            )
            .scalars()
            .all()
        )
    assert [r.action for r in rows] == ["trigger_resumed", "trigger_paused", "trigger_deleted"]
    assert all(r.request_data == {"trigger_id": trigger_id, "source": "web"} for r in rows)
    assert all(str(r.user_id) == str(owner.id) for r in rows)
    del other


@pytest.mark.asyncio
async def test_without_the_toolkit_the_routes_say_so(client, session_factory):
    from main import app

    saved = getattr(app.state, "trigger_toolkit", None)
    app.state.trigger_toolkit = None
    try:
        _user, token = await make_user(session_factory, "routes-none@example.com")
        assert (await client.get("/api/triggers", headers=auth_headers(token))).status_code == 503
    finally:
        app.state.trigger_toolkit = saved


# -- wiring --------------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_wire_services_builds_the_sweeper_the_toolkit_and_the_page_hook(session_factory, monkeypatch):
    from core.config import settings
    from main import app, wire_services
    from services.notifications.event_triggers import TriggerService
    from services.scheduler import commands as schedule_commands
    from services.triggers import commands as trigger_commands
    from tests.test_telegram_manager import FakeService

    monkeypatch.setattr(settings, "TELEGRAM_BOT_TOKEN", "", raising=False)
    saved = dict(app.state._state)
    await wire_services(app, session_factory, telegram_service_factory=FakeService)
    try:
        sweeper = app.state.triggers
        assert isinstance(sweeper, TriggerService)
        assert sweeper.runner is app.state.unattended_runner and sweeper.executor is app.state.tool_executor
        assert app.state.trigger_toolkit is app.state.tool_executor.triggers_toolkit
        assert app.state.trigger_toolkit._runner_ready() is True
        assert app.state.page_watches.on_change == sweeper.enqueue_page_change
        assert trigger_commands.current().toolkit is app.state.trigger_toolkit
        # Off by default: the gates are closed.
        assert await sweeper._on() is False and await sweeper._runs_on() is False
    finally:
        schedule_commands.configure(None)
        trigger_commands.configure(None)
        await app.state.telegram_manager.stop()
        await app.state.slack_manager.stop()
        app.state._state.clear()
        app.state._state.update(saved)
