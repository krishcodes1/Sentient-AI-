"""Tests for the built-in reminder tools: `now`, `create`, `list`, and `cancel`
are wired correctly into the tool catalog, the permission engine, and the
executor, and that a reminder is only ever visible to or cancellable by its own
creator.

Why it exists: Guards the identity boundary so a reminder tool never lists or
cancels another user's reminder, and that the always-on clock tool works even
without a database.

Built-in reminder tools: the clock, create/list/cancel, and their wiring
into the catalog, the permission engine and the executor.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import select

from models.reminder import Reminder, ReminderSource, ReminderStatus
from services.agent.permissions import ActionCategory, PermissionEngine, PermissionTier
from services.agent.tool_registry import (
    ConnectorToolExecutor,
    RuntimePermissionAdapter,
    build_tools,
)
from services.tools.reminders import ReminderToolkit
from tests.conftest import make_user

REMINDER_TOOLS = {"reminders.now", "reminders.create", "reminders.list", "reminders.cancel"}


async def _rows(session_factory) -> list[Reminder]:
    async with session_factory() as session:
        return list((await session.execute(select(Reminder))).scalars().all())


# ---------------------------------------------------------------------------
# now
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_now_returns_a_parseable_clock(session_factory):
    result = await ReminderToolkit(session_factory).execute("now", {}, str(uuid.uuid4()))

    assert result["ok"] is True
    now_utc = datetime.fromisoformat(result["now_utc"])
    now_local = datetime.fromisoformat(result["now_local"])
    assert now_utc.utcoffset() == timedelta(0)
    assert now_local.utcoffset() is not None  # carries the server's offset
    assert abs((now_utc - datetime.now(timezone.utc)).total_seconds()) < 5
    assert now_utc == now_local  # same instant, two renderings
    assert result["weekday"] == now_local.strftime("%A")
    assert result["timezone"]


@pytest.mark.asyncio
async def test_now_works_without_a_database():
    result = await ReminderToolkit(None).execute("now", {}, "anyone")
    assert result["ok"] is True


# ---------------------------------------------------------------------------
# create
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_create_with_delay_persists_an_agent_row_for_the_caller(session_factory):
    user, _ = await make_user(session_factory, email="rt-owner@example.com")
    toolkit = ReminderToolkit(session_factory)

    result = await toolkit.execute(
        "create", {"title": "Submit the report", "delay_minutes": 90}, str(user.id)
    )

    assert result["ok"] is True
    assert result["title"] == "Submit the report"
    assert result["due_in_minutes"] == 90
    due = datetime.fromisoformat(result["due_at"])
    assert abs((due - (datetime.now(timezone.utc) + timedelta(minutes=90))).total_seconds()) < 5

    (row,) = await _rows(session_factory)
    assert str(row.id) == result["reminder_id"]
    assert row.user_id == user.id
    assert row.source is ReminderSource.agent
    assert row.status is ReminderStatus.scheduled
    assert row.title == "Submit the report"


@pytest.mark.asyncio
async def test_create_with_due_at_reads_naive_as_utc_and_keeps_offsets(session_factory):
    user, _ = await make_user(session_factory, email="rt-tz@example.com")
    toolkit = ReminderToolkit(session_factory)
    target = (datetime.now(timezone.utc) + timedelta(days=1)).replace(microsecond=0)

    naive = await toolkit.execute(
        "create",
        {"title": "naive", "due_at": target.replace(tzinfo=None).isoformat()},
        str(user.id),
    )
    offset = await toolkit.execute(
        "create",
        {
            "title": "offset",
            "note": "with a note",
            "due_at": target.astimezone(timezone(timedelta(hours=-4))).isoformat(),
        },
        str(user.id),
    )

    assert naive["ok"] is True and offset["ok"] is True
    assert datetime.fromisoformat(naive["due_at"]) == target
    assert datetime.fromisoformat(offset["due_at"]) == target


@pytest.mark.asyncio
async def test_create_rejects_a_past_due_at(session_factory):
    user, _ = await make_user(session_factory, email="rt-past@example.com")
    past = datetime.now(timezone.utc) - timedelta(minutes=5)

    result = await ReminderToolkit(session_factory).execute(
        "create", {"title": "too late", "due_at": past.isoformat()}, str(user.id)
    )

    assert result["ok"] is False
    assert "past" in result["error"]
    assert "reminders.now" in result["error"]
    assert await _rows(session_factory) == []


@pytest.mark.asyncio
async def test_create_rejects_bad_timing_arguments(session_factory):
    user, _ = await make_user(session_factory, email="rt-args@example.com")
    toolkit = ReminderToolkit(session_factory)
    soon = (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat()

    neither = await toolkit.execute("create", {"title": "x"}, str(user.id))
    both = await toolkit.execute(
        "create", {"title": "x", "due_at": soon, "delay_minutes": 5}, str(user.id)
    )
    far = await toolkit.execute(
        "create",
        {"title": "x", "due_at": (datetime.now(timezone.utc) + timedelta(days=4000)).isoformat()},
        str(user.id),
    )
    garbage = await toolkit.execute(
        "create", {"title": "x", "due_at": "next tuesday"}, str(user.id)
    )
    zero = await toolkit.execute("create", {"title": "x", "delay_minutes": 0}, str(user.id))
    huge = await toolkit.execute(
        "create", {"title": "x", "delay_minutes": 525601}, str(user.id)
    )
    unknown_arg = await toolkit.execute(
        "create", {"title": "x", "delay_minutes": 5, "priority": "high"}, str(user.id)
    )

    for result in (neither, both, far, garbage, zero, huge, unknown_arg):
        assert result["ok"] is False, result
    assert "exactly one" in neither["error"]
    assert "ISO-8601" in garbage["error"]
    assert await _rows(session_factory) == []


@pytest.mark.asyncio
async def test_create_validates_title_and_note(session_factory):
    user, _ = await make_user(session_factory, email="rt-text@example.com")
    toolkit = ReminderToolkit(session_factory)

    empty = await toolkit.execute("create", {"title": "   ", "delay_minutes": 5}, str(user.id))
    long_title = await toolkit.execute(
        "create", {"title": "t" * 201, "delay_minutes": 5}, str(user.id)
    )
    long_note = await toolkit.execute(
        "create", {"title": "ok", "note": "n" * 2001, "delay_minutes": 5}, str(user.id)
    )
    nul = await toolkit.execute(
        "create", {"title": "bad\x00byte", "delay_minutes": 5}, str(user.id)
    )

    for result in (empty, long_title, long_note, nul):
        assert result["ok"] is False, result
    assert await _rows(session_factory) == []


@pytest.mark.asyncio
async def test_create_without_a_database_fails_closed():
    result = await ReminderToolkit(None).execute(
        "create", {"title": "x", "delay_minutes": 5}, str(uuid.uuid4())
    )
    assert result["ok"] is False
    assert "not configured" in result["error"]


# ---------------------------------------------------------------------------
# list / cancel
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_list_shows_only_the_callers_scheduled_reminders_soonest_first(session_factory):
    owner, _ = await make_user(session_factory, email="rt-list@example.com")
    other, _ = await make_user(session_factory, email="rt-list-other@example.com")
    toolkit = ReminderToolkit(session_factory)

    later = await toolkit.execute("create", {"title": "later", "delay_minutes": 120}, str(owner.id))
    sooner = await toolkit.execute("create", {"title": "sooner", "delay_minutes": 30}, str(owner.id))
    await toolkit.execute("create", {"title": "not yours", "delay_minutes": 10}, str(other.id))
    cancelled = await toolkit.execute("create", {"title": "gone", "delay_minutes": 60}, str(owner.id))
    await toolkit.execute("cancel", {"reminder_id": cancelled["reminder_id"]}, str(owner.id))

    result = await toolkit.execute("list", {}, str(owner.id))

    assert result["ok"] is True
    assert result["count"] == 2
    assert [r["id"] for r in result["reminders"]] == [sooner["reminder_id"], later["reminder_id"]]
    assert [r["title"] for r in result["reminders"]] == ["sooner", "later"]
    assert result["reminders"][0]["due_in_minutes"] == 30
    assert datetime.fromisoformat(result["reminders"][0]["due_at"]).utcoffset() == timedelta(0)


@pytest.mark.asyncio
async def test_cancel_by_another_user_is_refused_as_not_found(session_factory):
    owner, _ = await make_user(session_factory, email="rt-cancel-owner@example.com")
    intruder, _ = await make_user(session_factory, email="rt-cancel-intruder@example.com")
    toolkit = ReminderToolkit(session_factory)
    created = await toolkit.execute(
        "create", {"title": "mine", "delay_minutes": 15}, str(owner.id)
    )

    result = await toolkit.execute(
        "cancel", {"reminder_id": created["reminder_id"]}, str(intruder.id)
    )

    assert result["ok"] is False
    assert result["not_found"] is True
    (row,) = await _rows(session_factory)
    assert row.status is ReminderStatus.scheduled

    # An unknown or malformed id reads the same way, so the tool never
    # confirms that someone else's reminder exists.
    missing = await toolkit.execute(
        "cancel", {"reminder_id": str(uuid.uuid4())}, str(intruder.id)
    )
    malformed = await toolkit.execute("cancel", {"reminder_id": "nope"}, str(intruder.id))
    assert missing == result and malformed == result


@pytest.mark.asyncio
async def test_cancel_by_owner_works_and_keeps_the_row(session_factory):
    owner, _ = await make_user(session_factory, email="rt-cancel@example.com")
    toolkit = ReminderToolkit(session_factory)
    created = await toolkit.execute(
        "create", {"title": "mine", "delay_minutes": 15}, str(owner.id)
    )

    result = await toolkit.execute(
        "cancel", {"reminder_id": created["reminder_id"]}, str(owner.id)
    )

    assert result == {
        "ok": True,
        "reminder_id": created["reminder_id"],
        "title": "mine",
        "status": "cancelled",
    }
    (row,) = await _rows(session_factory)
    assert row.status is ReminderStatus.cancelled
    # Cancelling again is a no-op, not an error: a retried tool call must
    # not read as a failure to the model.
    again = await toolkit.execute(
        "cancel", {"reminder_id": created["reminder_id"]}, str(owner.id)
    )
    assert again["ok"] is True


# ---------------------------------------------------------------------------
# Wiring: catalog, permission engine, executor
# ---------------------------------------------------------------------------


def test_catalog_offers_reminder_tools_to_a_user_with_no_connectors():
    tools = {t.name: t for t in build_tools([])}

    assert REMINDER_TOOLS <= set(tools)
    # Every reminder action runs unattended under the default account tier.
    assert {tools[name].permission_tier for name in REMINDER_TOOLS} == {"auto"}
    assert tools["reminders.create"].connector_type == "reminders"
    assert set(tools["reminders.create"].parameters["required"]) == {"title"}
    assert set(tools["reminders.create"].parameters["properties"]) == {
        "title", "note", "due_at", "delay_minutes",
    }
    assert tools["reminders.cancel"].parameters["required"] == ["reminder_id"]
    # The time-taking tools tell the model to read the clock first.
    assert "reminders.now" in tools["reminders.create"].description
    assert "FIRST" in tools["reminders.now"].description


def test_reminder_tools_are_still_floored_by_the_account_default():
    assert not any(
        t.name in REMINDER_TOOLS for t in build_tools([], user_default_tier="admin_only")
    )


def test_permission_engine_auto_approves_reminder_reads_and_writes():
    engine = PermissionEngine()
    for action, category in (("now", ActionCategory.READ), ("create", ActionCategory.WRITE)):
        decision = engine.check_permission("reminders", action, category)
        assert decision.tier == PermissionTier.AUTO_APPROVE
        assert decision.allowed is True
        assert decision.requires_approval is False
    for category in (ActionCategory.DELETE, ActionCategory.EXECUTE, ActionCategory.FINANCIAL):
        decision = engine.check_permission("reminders", "purge", category)
        assert decision.tier == PermissionTier.HARD_BLOCKED
        assert decision.allowed is False


@pytest.mark.asyncio
async def test_runtime_adapter_approves_reminder_create_without_an_approval_card():
    adapter = RuntimePermissionAdapter()
    assert await adapter.check("u", "reminders.create", {"title": "x"}) == "approved"
    assert await adapter.check("u", "reminders.cancel", {"reminder_id": "x"}) == "approved"
    assert await adapter.get_policy_name("u", "reminders.create") == "reminders:write"


@pytest.mark.asyncio
async def test_executor_dispatches_reminders_under_the_callers_identity(session_factory):
    user, _ = await make_user(session_factory, email="rt-exec@example.com")
    executor = ConnectorToolExecutor(session_factory=session_factory)

    # A user_id smuggled through the arguments is ignored: the executor's
    # caller is the owner, full stop.
    created = await executor.execute(
        "reminders.create",
        {"title": "From chat", "delay_minutes": 45, "user_id": str(uuid.uuid4())},
        str(user.id),
    )
    assert created["ok"] is True
    (row,) = await _rows(session_factory)
    assert row.user_id == user.id
    assert row.source is ReminderSource.agent

    listed = await executor.execute("reminders.list", {}, str(user.id))
    assert [r["id"] for r in listed["reminders"]] == [created["reminder_id"]]

    cancelled = await executor.execute(
        "reminders.cancel", {"reminder_id": created["reminder_id"]}, str(user.id)
    )
    assert cancelled["ok"] is True


@pytest.mark.asyncio
async def test_executor_without_a_database_tells_time_but_will_not_write():
    executor = ConnectorToolExecutor()
    assert (await executor.execute("reminders.now", {}, "u"))["ok"] is True
    refused = await executor.execute(
        "reminders.create", {"title": "x", "delay_minutes": 5}, str(uuid.uuid4())
    )
    assert refused["ok"] is False
    unknown = await executor.execute("reminders.purge", {}, "u")
    assert unknown["ok"] is False
