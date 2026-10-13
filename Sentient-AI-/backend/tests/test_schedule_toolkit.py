"""Tests for the schedule.* toolkit and its approval-card hooks: tasks belong to
their owner, the 10-task and one-briefing limits hold, the time zone comes
from the call, then the user, then CRAWLER_TIMEZONE (else the model is told to
ask), a secret in the prompt is refused, only tools an unattended run may use
are accepted (never the desktop, the browser, memories, watches, schedules,
system, MCP or a screenshot; never a DELETE; at most 3 writes), and the card
names the zone, the tools and the channels.

Why it exists: every scheduled task runs later with nobody watching, so what
the card shows and what gets stored must be exactly what the rules allow. An
in-memory SQLite database and a fixed clock; no network, no model.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

import pytest
from sqlalchemy import select

from services.tools import schedule as schedule_mod
from services.tools.schedule import (
    BRIEFING_LABEL,
    LIST_ROWS_CHARS,
    MAX_TASKS_PER_USER,
    ScheduleToolkit,
)
from tests.conftest import make_user

NOW = datetime(2026, 9, 29, 12, 0, tzinfo=timezone.utc)  # Tue 08:00 in New York


def toolkit(session_factory, default_zone=None) -> ScheduleToolkit:
    return ScheduleToolkit(session_factory, clock=lambda: NOW, default_timezone=lambda: default_zone)


def create_args(**overrides):
    args = {
        "label": "Canvas summary",
        "prompt": "Summarise what is due on Canvas this week.",
        "freq": "weekdays",
        "time": "08:00",
        "tools": ["canvas.get_upcoming"],
        "timezone": "America/New_York",
    }
    args.update(overrides)
    return {k: v for k, v in args.items() if v is not None}


async def rows(session_factory, user_id):
    from models.scheduled_task import ScheduledTask

    async with session_factory() as session:
        return list(
            (await session.execute(select(ScheduledTask).where(ScheduledTask.user_id == user_id)))
            .scalars()
            .all()
        )


# ── create ────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_create_saves_the_task_and_the_first_run(session_factory):
    user, _ = await make_user(session_factory, "create@example.com")
    result = await toolkit(session_factory).execute("create", create_args(), str(user.id))
    assert result["ok"] is True
    assert result["schedule"] == "Weekdays at 08:00"
    assert result["next_run_local"] == "Wed 2026-09-30 08:00"  # 08:00 today has just passed
    [row] = await rows(session_factory, user.id)
    assert (row.kind, row.label, row.timezone, row.status, row.source) == (
        "prompt",
        "Canvas summary",
        "America/New_York",
        "active",
        "agent",
    )
    assert row.options == {"tools": ["canvas.get_upcoming"], "write_tools": []}
    assert row.channels == ["telegram", "slack"]


@pytest.mark.asyncio
async def test_a_user_id_argument_is_ignored_and_rows_stay_with_the_caller(session_factory):
    owner, _ = await make_user(session_factory, "owner@example.com")
    other, _ = await make_user(session_factory, "other@example.com")
    kit = toolkit(session_factory)
    result = await kit.execute("create", {**create_args(), "user_id": str(other.id)}, str(owner.id))
    assert result["ok"] is True
    assert len(await rows(session_factory, owner.id)) == 1
    assert await rows(session_factory, other.id) == []
    # The other user sees nothing and cannot touch it.
    assert (await kit.execute("list", {}, str(other.id)))["tasks"] == []
    for action, params in (
        ("pause", {"task_id": result["task_id"], "paused": True}),
        ("delete", {"task_id": result["task_id"]}),
    ):
        refused = await kit.execute(action, params, str(other.id))
        assert refused["ok"] is False and refused.get("not_found") is True
    assert (await rows(session_factory, owner.id))[0].status == "active"


@pytest.mark.asyncio
async def test_the_zone_comes_from_the_call_then_the_user_then_the_install(session_factory):
    from models.user import User

    user, _ = await make_user(session_factory, "zones@example.com")
    uid = str(user.id)
    # No zone anywhere: the model is told to ask.
    refused = await toolkit(session_factory).execute("create", create_args(timezone=None), uid)
    assert refused["rule"] == "timezone_required" and "Ask the user" in refused["error"]
    # The install default applies.
    made = await toolkit(session_factory, "Europe/London").execute(
        "create", create_args(label="A", timezone=None), uid
    )
    assert made["timezone"] == "Europe/London"
    # The call's zone wins, and is saved as the user's since they had none.
    made = await toolkit(session_factory, "Europe/London").execute(
        "create", create_args(label="B", timezone="America/Chicago"), uid
    )
    assert made["timezone"] == "America/Chicago"
    async with session_factory() as session:
        assert (await session.get(User, user.id)).timezone == "America/Chicago"
    # The user's zone beats the install's; a later call's zone does not
    # replace a saved one.
    made = await toolkit(session_factory, "Europe/London").execute(
        "create", create_args(label="C", timezone=None), uid
    )
    assert made["timezone"] == "America/Chicago"
    await toolkit(session_factory).execute("create", create_args(label="D", timezone="Asia/Tokyo"), uid)
    async with session_factory() as session:
        assert (await session.get(User, user.id)).timezone == "America/Chicago"


@pytest.mark.asyncio
async def test_an_invalid_zone_is_refused(session_factory):
    user, _ = await make_user(session_factory, "badzone@example.com")
    for zone in ("../etc", "America", "Mars/Olympus"):
        refused = await toolkit(session_factory).execute(
            "create", create_args(timezone=zone), str(user.id)
        )
        assert refused["ok"] is False and refused["rule"] == "invalid_arguments"


@pytest.mark.asyncio
async def test_a_prompt_with_a_secret_is_refused(session_factory):
    user, _ = await make_user(session_factory, "secret@example.com")
    refused = await toolkit(session_factory).execute(
        "create",
        create_args(prompt="Log in with password: hunter2hunter2 and check grades"),
        str(user.id),
    )
    assert refused["rule"] == "secret" and refused["refused"] is True
    assert await rows(session_factory, user.id) == []


@pytest.mark.parametrize(
    "tools",
    [
        ["desktop.screenshot"],
        ["desktop.observe"],
        ["browser.read"],
        ["schedule.list"],
        ["watch.list"],
        ["system.capabilities"],
        ["web.screenshot"],
        ["mcp.notes.search"],
        ["tools.find"],
        ["reminders.create"],  # a write listed as a read
        ["nosuch.tool"],
    ],
)
@pytest.mark.asyncio
async def test_tools_an_unattended_run_may_not_use_are_refused(session_factory, tools):
    user, _ = await make_user(session_factory, f"tools-{uuid.uuid4().hex[:6]}@example.com")
    refused = await toolkit(session_factory).execute("create", create_args(tools=tools), str(user.id))
    assert refused["ok"] is False and refused["rule"] == "tool_not_allowed"


@pytest.mark.parametrize("writes", [["memory.remember"], ["watch.create"], ["canvas.get_upcoming"]])
@pytest.mark.asyncio
async def test_write_tools_must_be_allowed_writes(session_factory, writes):
    user, _ = await make_user(session_factory, f"w-{uuid.uuid4().hex[:6]}@example.com")
    refused = await toolkit(session_factory).execute(
        "create", create_args(write_tools=writes), str(user.id)
    )
    assert refused["rule"] == "tool_not_allowed"


def test_every_delete_execute_and_financial_action_is_refused():
    from services.agent.permissions import ActionCategory
    from services.agent.tool_registry import CONNECTOR_CATALOG
    from services.automation.fence import classify_tool

    checked = 0
    for family, specs in CONNECTOR_CATALOG.items():
        for spec in specs:
            if spec.category in (ActionCategory.DELETE, ActionCategory.EXECUTE, ActionCategory.FINANCIAL):
                assert classify_tool(f"{family}.{spec.action}") is None, f"{family}.{spec.action}"
                checked += 1
    assert checked > 0


@pytest.mark.asyncio
async def test_reads_and_up_to_three_writes_are_accepted(session_factory):
    user, _ = await make_user(session_factory, "ok-tools@example.com")
    kit = toolkit(session_factory)
    made = await kit.execute(
        "create",
        create_args(
            tools=["canvas.get_upcoming", "web.search", "google_workspace.get_events"],
            write_tools=["reminders.create", "google_workspace.send_email"],
        ),
        str(user.id),
    )
    assert made["ok"] is True
    too_many = await kit.execute(
        "create",
        create_args(
            label="Too many",
            write_tools=[
                "reminders.create",
                "reminders.cancel",
                "google_workspace.send_email",
                "google_workspace.create_event",
            ],
        ),
        str(user.id),
    )
    assert too_many["ok"] is False and "at most 3" in too_many["error"]
    nine = [f"t{i}" for i in range(9)]
    assert "at most 8" in (await kit.execute("create", create_args(label="N", tools=nine), str(user.id)))["error"]


@pytest.mark.asyncio
async def test_the_ten_task_limit_and_duplicate_labels(session_factory):
    user, _ = await make_user(session_factory, "limit@example.com")
    kit = toolkit(session_factory)
    for i in range(MAX_TASKS_PER_USER):
        assert (await kit.execute("create", create_args(label=f"Task {i}"), str(user.id)))["ok"]
    over = await kit.execute("create", create_args(label="One more"), str(user.id))
    assert over["rule"] == "task_limit" and over["refused"] is True
    dup = await kit.execute("create", create_args(label="Task 3"), str(user.id))
    assert dup["ok"] is False


@pytest.mark.asyncio
async def test_a_once_task_in_the_past_is_refused(session_factory):
    user, _ = await make_user(session_factory, "once@example.com")
    kit = toolkit(session_factory)
    past = await kit.execute("create", create_args(freq="once", date="2026-09-28"), str(user.id))
    assert "already passed" in past["error"]
    earlier_today = await kit.execute(
        "create", create_args(freq="once", date="2026-09-29", time="07:00"), str(user.id)
    )
    assert "already passed" in earlier_today["error"]
    later_today = await kit.execute(
        "create", create_args(freq="once", date="2026-09-29", time="09:00"), str(user.id)
    )
    assert later_today["ok"] is True and later_today["next_run_local"] == "Tue 2026-09-29 09:00"


# ── the briefing ─────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_one_briefing_per_user_and_a_second_call_changes_it(session_factory):
    user, _ = await make_user(session_factory, "brief@example.com")
    kit = toolkit(session_factory, "America/New_York")
    first = await kit.execute("briefing", {}, str(user.id))
    assert first["ok"] and first["label"] == BRIEFING_LABEL and first["schedule"] == "Every day at 07:30"
    [row] = await rows(session_factory, user.id)
    assert row.options == {"sections": ["canvas", "calendar"], "topic": None, "summary": False}
    second = await kit.execute(
        "briefing",
        {"freq": "weekdays", "time": "06:45", "sections": ["email", "canvas"], "topic": "AI rules", "summary": True},
        str(user.id),
    )
    assert second["task_id"] == first["task_id"] and second.get("updated") is True
    [row] = await rows(session_factory, user.id)
    assert row.options == {"sections": ["canvas", "email"], "topic": "AI rules", "summary": True}
    assert row.recurrence == {"freq": "weekdays", "time": "06:45"}


@pytest.mark.asyncio
async def test_briefing_arguments_are_checked(session_factory):
    user, _ = await make_user(session_factory, "brief-args@example.com")
    kit = toolkit(session_factory, "UTC")
    for params in (
        {"freq": "monthly"},
        {"sections": ["weather"]},
        {"topic": "x" * 121},
        {"summary": "yes"},
        {"channels": ["email"]},
        {"prompt": "hi"},
    ):
        assert (await kit.execute("briefing", params, str(user.id)))["ok"] is False, params


# ── list, pause, delete ─────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_list_cuts_prompts_and_caps_its_rows(session_factory, monkeypatch):
    user, _ = await make_user(session_factory, "list@example.com")
    kit = toolkit(session_factory)
    await kit.execute("create", create_args(prompt="p" * 1500), str(user.id))
    listed = await kit.execute("list", {}, str(user.id))
    [row] = listed["tasks"]
    assert len(row["prompt"]) == 200 and row["prompt_truncated"] is True
    assert row["next_run_local"] == "Wed 2026-09-30 08:00" and row["schedule"] == "Weekdays at 08:00"
    assert listed["timezone"] == "America/New_York"
    for i in range(5):
        await kit.execute("create", create_args(label=f"L{i}", prompt="q" * 1500), str(user.id))
    monkeypatch.setattr(schedule_mod, "LIST_ROWS_CHARS", 900)
    capped = await kit.execute("list", {}, str(user.id))
    assert capped["count"] == 6 and capped["shown"] < 6 and "note" in capped
    assert LIST_ROWS_CHARS == 7000


@pytest.mark.asyncio
async def test_pause_and_resume_recompute_the_next_run_and_reset_errors(session_factory):
    from models.scheduled_task import ScheduledTask

    user, _ = await make_user(session_factory, "pause@example.com")
    clock = {"now": NOW}
    kit = ScheduleToolkit(session_factory, clock=lambda: clock["now"], default_timezone=lambda: None)
    made = await kit.execute("create", create_args(), str(user.id))
    async with session_factory() as session:
        row = await session.get(ScheduledTask, uuid.UUID(made["task_id"]))
        row.status, row.consecutive_errors = "error", 5
        await session.commit()
    clock["now"] = datetime(2026, 10, 2, 13, 0, tzinfo=timezone.utc)
    resumed = await kit.execute("pause", {"task_id": made["task_id"], "paused": False}, str(user.id))
    # Friday 09:00 in New York: the next weekday 08:00 is Monday.
    assert resumed["status"] == "active" and resumed["next_run_local"] == "Mon 2026-10-05 08:00"
    [row] = await rows(session_factory, user.id)
    assert row.consecutive_errors == 0
    assert (await kit.set_paused(user.id, made["task_id"], True))["status"] == "paused"


@pytest.mark.asyncio
async def test_delete_removes_the_task_and_keeps_its_conversation(session_factory):
    from models.conversation import Conversation
    from models.scheduled_task import ScheduledTask

    user, _ = await make_user(session_factory, "delete@example.com")
    kit = toolkit(session_factory)
    made = await kit.execute("create", create_args(), str(user.id))
    conversation_id = uuid.uuid4()
    async with session_factory() as session:
        session.add(Conversation(id=conversation_id, user_id=user.id, title="Scheduled: Canvas summary"))
        await session.flush()
        row = await session.get(ScheduledTask, uuid.UUID(made["task_id"]))
        row.conversation_id = conversation_id
        await session.commit()
    deleted = await kit.execute("delete", {"task_id": made["task_id"]}, str(user.id))
    assert deleted["deleted"] is True
    assert await rows(session_factory, user.id) == []
    async with session_factory() as session:
        assert await session.get(Conversation, conversation_id) is not None


# ── the card hooks ───────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_precheck_bind_and_the_card_sentence(session_factory):
    user, _ = await make_user(session_factory, "card@example.com")
    kit = toolkit(session_factory, "America/New_York")
    args = create_args(timezone=None, channels=["telegram", "slack"])
    assert await kit.precheck("create", args, str(user.id)) is None
    bound = await kit.bind("create", args, str(user.id))
    assert bound["timezone"] == "America/New_York"
    assert kit.describe("create", bound, str(user.id)) == (
        'Run "Canvas summary" every weekday at 08:00 (America/New_York) and send the result '
        "to Telegram and Slack. Reads with: canvas.get_upcoming. Asks you first before: "
        "nothing. Full prompt below."
    )
    web_only = kit.describe("create", {**bound, "channels": [], "write_tools": ["reminders.create"]}, str(user.id))
    assert "keep the result in the web app" in web_only and "Asks you first before: reminders.create" in web_only
    refused = await kit.precheck("create", create_args(tools=["desktop.act"]), str(user.id))
    assert refused["rule"] == "tool_not_allowed"


@pytest.mark.asyncio
async def test_the_briefing_card_says_change_when_one_exists(session_factory):
    user, _ = await make_user(session_factory, "brief-card@example.com")
    kit = toolkit(session_factory, "America/New_York")
    args = {"freq": "weekdays", "sections": ["canvas", "calendar", "email"], "topic": "AI rules", "summary": True}
    bound = await kit.bind("briefing", args, str(user.id))
    first = kit.describe("briefing", bound, str(user.id))
    assert first.startswith("Send you a briefing every weekday at 07:30 (America/New_York) on Telegram and Slack")
    assert "sender and subject only" in first and 'news on "AI rules"' in first
    assert first.endswith("Built from read-only lookups; a short AI overview uses your AI provider.")
    await kit.execute("briefing", bound, str(user.id))
    again = kit.describe("briefing", await kit.bind("briefing", args, str(user.id)), str(user.id))
    assert again.startswith("Change your daily briefing: send it every weekday")


@pytest.mark.asyncio
async def test_pause_and_delete_cards_name_the_task(session_factory):
    user, _ = await make_user(session_factory, "names@example.com")
    kit = toolkit(session_factory)
    made = await kit.execute("create", create_args(), str(user.id))
    params = {"task_id": made["task_id"]}
    await kit.bind("delete", params, str(user.id))
    assert kit.describe("delete", params, str(user.id)) == (
        'Delete the scheduled task "Canvas summary". Its conversation is kept.'
    )
    assert (await kit.precheck("delete", {"task_id": str(uuid.uuid4())}, str(user.id)))["not_found"]
    assert (await kit.precheck("pause", {"task_id": made["task_id"]}, str(user.id)))["ok"] is False


def test_model_and_toolkit_sizes_agree():
    from models import scheduled_task as model

    assert model.LABEL_MAX_CHARS == schedule_mod.LABEL_MAX_CHARS
    assert model.PROMPT_MAX_CHARS == schedule_mod.PROMPT_MAX_CHARS
    assert model.ERROR_MAX_CHARS == schedule_mod.ERROR_MAX_CHARS


@pytest.mark.asyncio
async def test_without_a_database_every_action_fails_closed():
    kit = ScheduleToolkit(None)
    for action, params in (("create", create_args()), ("list", {}), ("delete", {"task_id": str(uuid.uuid4())})):
        result = await kit.execute(action, params, str(uuid.uuid4()))
        assert result["ok"] is False
    assert (await kit.execute("launch", {}, str(uuid.uuid4())))["ok"] is False


# ── the executor's hooks ─────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_the_executor_routes_the_card_hooks_to_the_toolkit(session_factory):
    from services import capabilities as registry
    from services.agent.runtime import PrecheckRefusal
    from services.agent.tool_registry import SCHEDULE_RULE_POLICY, ConnectorToolExecutor

    user, _ = await make_user(session_factory, "executor@example.com")
    kit = toolkit(session_factory, "America/New_York")
    statuses = registry.statuses_by_key(
        registry.report({"scheduled_tasks": True}, registry.default_context())
    )

    async def gate():
        return statuses

    executor = ConnectorToolExecutor(session_factory=session_factory, schedule_toolkit=kit, capability_gate=gate)
    uid = str(user.id)
    refusal = await executor.precheck_approval("schedule.create", create_args(tools=["browser.read"]), uid)
    assert isinstance(refusal, PrecheckRefusal)
    assert refusal.policy == SCHEDULE_RULE_POLICY and refusal.rule == "tool_not_allowed"
    assert await executor.precheck_approval("schedule.create", create_args(timezone=None), uid) is None
    bound = await executor.approval_arguments_async("schedule.create", create_args(timezone=None), uid, task_id="t")
    assert bound["timezone"] == "America/New_York"
    assert executor.describe_approval("schedule.create", bound, uid).startswith('Run "Canvas summary"')
    # Unapproved, a change is refused at dispatch; a list runs.
    unapproved = await executor.execute("schedule.create", bound, uid)
    assert unapproved.get("requires_approval") is True
    assert (await executor.execute("schedule.create", bound, uid, approved=True))["ok"] is True
    assert (await executor.execute("schedule.list", {}, uid))["count"] == 1
