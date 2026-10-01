"""Tests for the owner's schedule keywords in a Slack DM: "schedules" lists the
account's tasks, "schedules pause|resume|run N" acts on one, "briefing" sends
the briefing now, "timezone" shows or saves the zone; they are tried after
stop, pending and new, other text still goes to the chat, and a message from
anyone but the linked Slack user is never answered.

Why it exists: Slack has no buttons here, so these keywords are how the owner
pauses a task from their phone; each must act only on the channel's own
account. The Slack API is a recorder; the database is in-memory SQLite.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from typing import Any

import pytest

from services.scheduler import commands as schedule_commands
from services.tools.schedule import ScheduleToolkit
from tests.conftest import make_user

TEAM, LINKED, STRANGER, DM = "T0TEAM001", "U0LINKED1", "U0OTHER01", "D0DM00001"
NOW = datetime(2026, 9, 29, 12, 0, tzinfo=timezone.utc)


class FakeService:
    def __init__(self):
        self.runs: list[tuple[str, str]] = []

    async def run_now(self, user_id, task_id):
        self.runs.append((str(user_id), str(task_id)))
        return {"ok": True, "started": True}


class Ticking:
    def __init__(self):
        self.ticks = 0

    def __call__(self):
        self.ticks += 1
        return NOW + timedelta(seconds=self.ticks)


@pytest.fixture
def backend(session_factory):
    kit = ScheduleToolkit(session_factory, clock=Ticking(), default_timezone=lambda: "UTC")
    service = FakeService()
    schedule_commands.configure(schedule_commands.ScheduleBackend(toolkit=kit, service=service, session_factory=session_factory))
    yield kit, service
    schedule_commands.configure(None)


def slack(user_id: str):
    from services.connectors.slack import SlackConnector
    from services.notifications import slack as slack_mod

    connector = SlackConnector.from_credentials({"bot_token": "xoxb-x", "app_token": "xapp-x"})
    channel = slack_mod.SlackChannel(
        connector_id="11111111-1111-1111-1111-111111111111",
        user_id=user_id,
        bot_token="xoxb-x",
        app_token="xapp-x",
        session_factory=lambda: None,
        connector=connector,
    )
    channel.team_id, channel.bot_user_id = TEAM, "U0BOT0001"
    link = SimpleNamespace(team_id=TEAM, slack_user_id=LINKED, link_code_hash=None, link_expires_at=None)

    async def load_link():
        return link

    posted: list[str] = []
    chats: list[str] = []

    async def post_text(where, text):
        posted.append(text)
        return {}

    channel._load_link = load_link  # type: ignore[method-assign]
    channel._post_text = post_text  # type: ignore[method-assign]
    channel._handle_chat = lambda where, text: chats.append(text)  # type: ignore[method-assign]
    return channel, posted, chats


def dm(text: str, n: int, sender: str = LINKED) -> dict[str, Any]:
    return {
        "type": "event_callback",
        "team_id": TEAM,
        "event_id": f"Ev{n:08d}",
        "event": {"type": "message", "channel": DM, "user": sender, "text": text, "ts": f"{n}.000100", "channel_type": "im"},
    }


async def say(channel, text, n, sender=LINKED):
    await channel._on_events_api(dm(text, n, sender))
    await channel.wait_idle()


@pytest.mark.asyncio
async def test_keywords_come_after_the_builtins_and_other_text_goes_to_chat(session_factory, backend):
    user, _ = await make_user(session_factory, "slack-order@example.com")
    channel, _posted, chats = slack(str(user.id))
    names = [h.__name__ for h in channel._text_handlers]
    # The built-ins first; other skills' keywords (files, tutor) may sit
    # around the scheduler's three, which stay together and in order.
    assert names[:3] == ["_keyword_stop", "_keyword_pending", "_keyword_new"]
    start = names.index("_keyword_schedules")
    assert start >= 3
    assert names[start : start + 3] == ["_keyword_schedules", "_keyword_briefing", "_keyword_timezone"]
    await say(channel, "schedules are hard", 1)
    await say(channel, "what is my timezone offset today", 2)
    assert chats == ["schedules are hard", "what is my timezone offset today"]
    await channel._connector.close()


@pytest.mark.asyncio
async def test_list_pause_resume_and_run(session_factory, backend):
    kit, fake = backend
    user, _ = await make_user(session_factory, "slack-list@example.com")
    made = await kit.execute(
        "create", {"label": "Canvas summary", "prompt": "Summarise Canvas.", "freq": "daily", "time": "08:00"}, str(user.id)
    )
    channel, posted, _chats = slack(str(user.id))
    await say(channel, "schedules", 1)
    assert "1. Canvas summary — Every day at 08:00 (UTC)" in posted[-1]
    assert 'Reply "schedules run 2"' in posted[-1]
    await say(channel, "schedules pause 1", 2)
    assert posted[-1].startswith("Paused")
    assert (await kit.list(str(user.id)))["tasks"][0]["status"] == "paused"
    await say(channel, "Schedules Resume 1", 3)
    assert (await kit.list(str(user.id)))["tasks"][0]["status"] == "active"
    await say(channel, "schedules run 1", 4)
    assert fake.runs == [(str(user.id), made["task_id"])]
    await channel._connector.close()


@pytest.mark.asyncio
async def test_a_stranger_is_never_answered(session_factory, backend):
    kit, fake = backend
    user, _ = await make_user(session_factory, "slack-stranger@example.com")
    await kit.execute("briefing", {}, str(user.id))
    channel, posted, chats = slack(str(user.id))
    await say(channel, "schedules pause 1", 1, sender=STRANGER)
    await say(channel, "briefing", 2, sender=STRANGER)
    assert posted == [] and chats == [] and fake.runs == []
    assert (await kit.list(str(user.id)))["tasks"][0]["status"] == "active"
    await channel._connector.close()


@pytest.mark.asyncio
async def test_briefing_and_timezone(session_factory, backend):
    from models.user import User

    kit, fake = backend
    user, _ = await make_user(session_factory, "slack-brief@example.com")
    channel, posted, _chats = slack(str(user.id))
    await say(channel, "briefing", 1)
    assert "no daily briefing yet" in posted[-1]
    made = await kit.execute("briefing", {}, str(user.id))
    await say(channel, "briefing", 2)
    assert fake.runs == [(str(user.id), made["task_id"])]
    await say(channel, "timezone", 3)
    assert posted[-1].startswith("No time zone saved yet")
    await say(channel, "timezone Asia/Tokyo", 4)
    assert posted[-1].startswith("Saved: Asia/Tokyo.")
    async with session_factory() as session:
        assert (await session.get(User, user.id)).timezone == "Asia/Tokyo"
    await channel._connector.close()
