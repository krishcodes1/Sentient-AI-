"""Tests for /api/schedules: each task belongs to its user (another user's id
is a 404), creating a task and running one now are refused with 409 while the
owner's switch is off (listing, pausing and deleting still work), validation
is the toolkit's own (a tool a scheduled run may not use is a 422), the time
zone can be read and saved (a path or a directory of zones is refused), run
now is rate-limited, and every change is audited without the prompt.

Why it exists: these routes change what runs on the user's behalf with no
approval card, so ownership, the switch and the rules must hold exactly as
they do for the chat tools. The app is driven over httpx with in-memory
SQLite and a fake runner; no network, no model.
"""

from __future__ import annotations

import json
import uuid

import pytest
from sqlalchemy import select

from services.automation.runner import BudgetState, UnattendedOutcome
from services.notifications.schedules import ScheduleService
from services.tools.schedule import ScheduleToolkit
from tests.conftest import auth_headers, make_user

BODY = {
    "label": "Canvas summary",
    "prompt": "Summarise my Canvas due items, including the words OKAPI-77.",
    "freq": "weekdays",
    "time": "08:00",
    "tools": ["canvas.get_upcoming"],
    "timezone": "America/New_York",
}


class Installation:
    def __init__(self, on: bool):
        self.on = on

    async def enabled_keys(self):
        return frozenset({"scheduled_tasks"}) if self.on else frozenset()


class Runner:
    def __init__(self):
        self.requests = []

    async def run(self, request):
        self.requests.append(request)
        return UnattendedOutcome(status="ok", reply="done", run_id=request.run_id)

    async def budget_left(self, user_id, *, exclude_run_id=None):
        return BudgetState(usd_left=1.0, runs_left=10)


@pytest.fixture
def wired(session_factory):
    from main import app

    saved = {k: getattr(app.state, k, None) for k in ("schedule_toolkit", "schedules", "installation")}
    runner = Runner()
    installation = Installation(on=True)

    async def enabled():
        return await installation.enabled_keys()

    app.state.schedule_toolkit = ScheduleToolkit(session_factory, default_timezone=lambda: None)
    app.state.schedules = ScheduleService(session_factory, runner=runner, enabled_keys=enabled, delivery_pause_s=0)
    app.state.installation = installation
    yield installation, runner, app.state.schedules
    for key, value in saved.items():
        setattr(app.state, key, value)


async def account(session_factory, email):
    user, token = await make_user(session_factory, email)
    return user, auth_headers(token)


@pytest.mark.asyncio
async def test_create_list_pause_delete(client, session_factory, wired):
    _user, headers = await account(session_factory, "api-crud@example.com")
    assert (await client.get("/api/schedules", headers=headers)).json()["tasks"] == []
    made = await client.post("/api/schedules", json=BODY, headers=headers)
    assert made.status_code == 201, made.text
    task_id = made.json()["task_id"]
    listed = (await client.get("/api/schedules", headers=headers)).json()
    assert [t["id"] for t in listed["tasks"]] == [task_id] and listed["tasks"][0]["schedule"] == "Weekdays at 08:00"
    paused = await client.patch(f"/api/schedules/{task_id}", json={"paused": True}, headers=headers)
    assert paused.status_code == 200 and paused.json()["status"] == "paused"
    resumed = await client.patch(f"/api/schedules/{task_id}", json={"paused": False}, headers=headers)
    assert resumed.json()["status"] == "active"
    assert (await client.delete(f"/api/schedules/{task_id}", headers=headers)).status_code == 204
    assert (await client.delete(f"/api/schedules/{task_id}", headers=headers)).status_code == 404


@pytest.mark.asyncio
async def test_another_users_task_is_not_found(client, session_factory, wired):
    _owner, owner_headers = await account(session_factory, "api-owner@example.com")
    _other, other_headers = await account(session_factory, "api-other@example.com")
    task_id = (await client.post("/api/schedules", json=BODY, headers=owner_headers)).json()["task_id"]
    assert (await client.patch(f"/api/schedules/{task_id}", json={"paused": True}, headers=other_headers)).status_code == 404
    assert (await client.delete(f"/api/schedules/{task_id}", headers=other_headers)).status_code == 404
    assert (await client.post(f"/api/schedules/{task_id}/run", headers=other_headers)).status_code == 404
    assert (await client.get("/api/schedules", headers=other_headers)).json()["tasks"] == []
    assert (await client.get("/api/schedules", headers=owner_headers)).json()["tasks"][0]["status"] == "active"


@pytest.mark.asyncio
async def test_create_and_run_are_refused_while_the_switch_is_off(client, session_factory, wired):
    installation, runner, _service = wired
    _user, headers = await account(session_factory, "api-off@example.com")
    task_id = (await client.post("/api/schedules", json=BODY, headers=headers)).json()["task_id"]
    installation.on = False
    refused = await client.post("/api/schedules", json={**BODY, "label": "Other"}, headers=headers)
    assert refused.status_code == 409 and "Scheduled tasks are off" in refused.json()["detail"]
    assert (await client.post(f"/api/schedules/{task_id}/run", headers=headers)).status_code == 409
    # Cleaning up still works.
    assert (await client.patch(f"/api/schedules/{task_id}", json={"paused": True}, headers=headers)).status_code == 200
    assert (await client.delete(f"/api/schedules/{task_id}", headers=headers)).status_code == 204
    assert runner.requests == []


@pytest.mark.asyncio
async def test_validation_is_the_toolkits(client, session_factory, wired):
    _user, headers = await account(session_factory, "api-rules@example.com")
    bad_tool = await client.post("/api/schedules", json={**BODY, "tools": ["desktop.act"]}, headers=headers)
    assert bad_tool.status_code == 422 and bad_tool.json()["detail"]["rule"] == "tool_not_allowed"
    no_zone = await client.post("/api/schedules", json={**BODY, "timezone": None}, headers=headers)
    assert no_zone.status_code == 422 and no_zone.json()["detail"]["rule"] == "timezone_required"
    first = await client.post("/api/schedules", json=BODY, headers=headers)
    assert first.status_code == 201
    assert (await client.post("/api/schedules", json=BODY, headers=headers)).status_code == 409
    briefing = await client.post("/api/schedules", json={"kind": "briefing", "timezone": "UTC"}, headers=headers)
    assert briefing.status_code == 201 and briefing.json()["label"] == "Daily briefing"


@pytest.mark.asyncio
async def test_run_now_starts_a_run_and_is_rate_limited(client, session_factory, wired):
    _installation, runner, service = wired
    _user, headers = await account(session_factory, "api-run@example.com")
    task_id = (await client.post("/api/schedules", json=BODY, headers=headers)).json()["task_id"]
    started = await client.post(f"/api/schedules/{task_id}/run", headers=headers)
    assert started.status_code == 202 and started.json()["started"] is True
    await service.wait_idle()
    assert len(runner.requests) == 1
    assert (await client.post(f"/api/schedules/{task_id}/run", headers=headers)).status_code == 429


@pytest.mark.asyncio
async def test_the_time_zone_can_be_read_and_saved(client, session_factory, wired):
    _user, headers = await account(session_factory, "api-zone@example.com")
    assert (await client.get("/api/schedules/timezone", headers=headers)).json() == {"timezone": None}
    for bad in ("../etc", "America", "Mars/Olympus"):
        assert (await client.put("/api/schedules/timezone", json={"timezone": bad}, headers=headers)).status_code == 422
    saved = await client.put("/api/schedules/timezone", json={"timezone": "Europe/London"}, headers=headers)
    assert saved.json() == {"timezone": "Europe/London"}
    assert (await client.get("/api/schedules/timezone", headers=headers)).json() == {"timezone": "Europe/London"}


@pytest.mark.asyncio
async def test_changes_are_audited_without_the_prompt(client, session_factory, wired):
    from models.audit import AuditLog

    user, headers = await account(session_factory, "api-audit@example.com")
    task_id = (await client.post("/api/schedules", json=BODY, headers=headers)).json()["task_id"]
    await client.patch(f"/api/schedules/{task_id}", json={"paused": True}, headers=headers)
    await client.delete(f"/api/schedules/{task_id}", headers=headers)
    async with session_factory() as session:
        rows = list(
            (
                await session.execute(
                    select(AuditLog).where(AuditLog.user_id == user.id, AuditLog.connector_name == "schedule")
                )
            )
            .scalars()
            .all()
        )
    assert [r.action for r in rows] == ["create", "pause", "delete"]
    assert "OKAPI-77" not in json.dumps([r.request_data for r in rows])


@pytest.mark.asyncio
async def test_the_browser_zone_is_stored_from_the_header(client, session_factory):
    from main import app
    from models.user import User

    user, headers = await account(session_factory, "api-header@example.com")
    conversation = await client.post("/api/agent/conversations", json={"title": "t"}, headers=headers)
    conversation_id = conversation.json()["id"]

    class Runtime:
        async def chat(self, **kwargs):
            from services.agent.runtime import AgentResponse

            return AgentResponse(content="hi", provider="anthropic", model="claude-sonnet-4-6")

    saved = getattr(app.state, "agent_runtime", None)
    app.state.agent_runtime = Runtime()
    try:
        for zone, expected in (("../etc", None), ("America/Denver", "America/Denver")):
            resp = await client.post(
                f"/api/agent/conversations/{conversation_id}/messages",
                json={"content": "hello"},
                headers={**headers, "X-Crawler-Timezone": zone},
            )
            assert resp.status_code == 201, resp.text
            async with session_factory() as session:
                assert (await session.get(User, user.id)).timezone == expected
    finally:
        app.state.agent_runtime = saved
    assert uuid.UUID(conversation_id)
