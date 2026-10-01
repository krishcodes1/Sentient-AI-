"""Tests for reminders.now with the user's saved time zone: when
``users.timezone`` is set, the clock also reports the user's zone and local
time (a container's own zone is UTC); when it is not, or cannot be read, the
answer is exactly what it always was.

Why it exists: every "tomorrow at 9am" the model computes starts here, and a
scheduled task's times are the user's local ones. In-memory SQLite.
"""

from __future__ import annotations

import pytest

from services.tools.reminders import ReminderToolkit
from tests.conftest import make_user

_BASE_KEYS = {"ok", "now_utc", "now_local", "timezone", "weekday"}


@pytest.mark.asyncio
async def test_the_users_zone_and_local_time_are_added_when_saved(session_factory):
    from models.user import User

    user, _ = await make_user(session_factory, "now-zone@example.com")
    async with session_factory() as session:
        (await session.get(User, user.id)).timezone = "Asia/Kolkata"
        await session.commit()
    result = await ReminderToolkit(session_factory).execute("now", {}, str(user.id))
    assert result["user_timezone"] == "Asia/Kolkata"
    assert result["now_user_local"].endswith("+05:30")
    assert set(result) == _BASE_KEYS | {"user_timezone", "now_user_local", "user_weekday"}


@pytest.mark.asyncio
async def test_the_answer_is_unchanged_without_a_saved_zone(session_factory):
    user, _ = await make_user(session_factory, "now-plain@example.com")
    assert set(await ReminderToolkit(session_factory).execute("now", {}, str(user.id))) == _BASE_KEYS
    assert set(await ReminderToolkit(None).execute("now", {}, str(user.id))) == _BASE_KEYS
    assert set(await ReminderToolkit(session_factory).execute("now", {}, "not-a-uuid")) == _BASE_KEYS


@pytest.mark.asyncio
async def test_a_bad_stored_zone_or_a_broken_database_still_tells_the_time(session_factory):
    from models.user import User

    user, _ = await make_user(session_factory, "now-bad@example.com")
    async with session_factory() as session:
        (await session.get(User, user.id)).timezone = "Nowhere/Land"
        await session.commit()
    assert set(await ReminderToolkit(session_factory).execute("now", {}, str(user.id))) == _BASE_KEYS

    def broken():
        raise RuntimeError("database down")

    result = await ReminderToolkit(broken).execute("now", {}, str(user.id))
    assert result["ok"] is True and set(result) == _BASE_KEYS
