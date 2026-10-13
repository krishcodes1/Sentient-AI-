"""Tests for the owner's schedule commands on Telegram: /schedules lists the
account's tasks with Run now, Pause and Resume buttons, the text fallbacks
("/schedules pause 2") do the same, /briefing sends the briefing now or says
how to set one up, /timezone shows or saves a zone, /help names the three, and
a button press from anyone but the linked account's own chat, or naming
someone else's task, changes nothing.

Why it exists: these commands change what runs on the owner's behalf without
an approval card, so the A1 link check and per-user scoping must hold for
every one. The Bot API is a recorder; the database is in-memory SQLite.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

import pytest

from services.scheduler import commands as schedule_commands
from services.tools.schedule import ScheduleToolkit
from tests.conftest import make_user, telegram_dm

NOW = datetime(2026, 9, 29, 12, 0, tzinfo=timezone.utc)
LINKED, STRANGER = 8101, 8102


class FakeService:
    def __init__(self):
        self.runs: list[tuple[str, str]] = []

    async def run_now(self, user_id, task_id):
        self.runs.append((str(user_id), str(task_id)))
        return {"ok": True, "started": True, "task_id": str(task_id)}


class Ticking:
    """NOW, one second later on every read: tasks made one after another
    list in that order."""

    def __init__(self):
        self.ticks = 0

    def __call__(self):
        self.ticks += 1
        return NOW + timedelta(seconds=self.ticks)


@pytest.fixture
def backend(session_factory):
    kit = ScheduleToolkit(session_factory, clock=Ticking(), default_timezone=lambda: "America/New_York")
    service = FakeService()
    schedule_commands.configure(schedule_commands.ScheduleBackend(toolkit=kit, service=service, session_factory=session_factory))
    yield kit, service
    schedule_commands.configure(None)


def telegram(user_id: str):
    from services.notifications.telegram import TelegramService

    service = TelegramService(token="123:fake-token", session_factory=lambda: None)
    sent: list[tuple[str, dict[str, Any]]] = []

    async def api(method: str, **params: Any) -> Any:
        sent.append((method, params))
        return {}

    async def user_for_chat(chat_id: Any):
        return user_id if chat_id == LINKED else None

    service._api = api  # type: ignore[method-assign]
    service._user_for_chat = user_for_chat  # type: ignore[method-assign]
    return service, sent


def press(data: str, chat_id: int, sender: int | None = None) -> dict[str, Any]:
    return {
        "id": "press",
        "data": data,
        "from": {"id": sender if sender is not None else chat_id, "is_bot": False},
        "message": {"message_id": 3, "chat": {"id": chat_id, "type": "private"}},
    }


async def two_tasks(kit, user):
    a = await kit.execute(
        "create",
        {"label": "Canvas summary", "prompt": "Summarise Canvas.", "freq": "weekdays", "time": "08:00"},
        str(user.id),
    )
    b = await kit.execute("briefing", {}, str(user.id))
    return a["task_id"], b["task_id"]


def texts(sent):
    return [p.get("text", "") for m, p in sent if m == "sendMessage"]


@pytest.mark.asyncio
async def test_the_three_commands_are_registered_and_in_help(backend):
    service, sent = telegram("u")
    assert {"/schedules", "/briefing", "/timezone"} <= set(service._commands)
    assert {"scn:", "scp:", "scr:"} <= set(service._callback_routes)
    await service._handle_help(LINKED)
    help_text = texts(sent)[-1]
    for word in ("/schedules", "/briefing", "/timezone"):
        assert word in help_text
    assert help_text.rstrip().endswith("/help — this message")
    await service._client.aclose()


@pytest.mark.asyncio
async def test_schedules_lists_with_buttons(session_factory, backend):
    kit, _service = backend
    user, _ = await make_user(session_factory, "tg-list@example.com")
    first, second = await two_tasks(kit, user)
    service, sent = telegram(str(user.id))
    await service._handle_message(telegram_dm(LINKED, "/schedules"))
    [(method, params)] = sent
    assert "1. Canvas summary — Weekdays at 08:00 (America/New_York)" in params["text"]
    assert "2. Daily briefing — Every day at 07:30" in params["text"]
    buttons = [b["callback_data"] for row in params["reply_markup"]["inline_keyboard"] for b in row]
    assert buttons == [f"scn:{first}", f"scp:{first}", f"scn:{second}", f"scp:{second}"]
    assert all(len(b) <= 64 for b in buttons)
    await service._client.aclose()


@pytest.mark.asyncio
async def test_text_fallbacks_pause_resume_and_run(session_factory, backend):
    kit, fake = backend
    user, _ = await make_user(session_factory, "tg-text@example.com")
    first, _second = await two_tasks(kit, user)
    service, sent = telegram(str(user.id))
    await service._handle_message(telegram_dm(LINKED, "/schedules pause 1"))
    assert texts(sent)[-1].startswith("Paused “Canvas summary”")
    assert (await kit.list(str(user.id)))["tasks"][0]["status"] == "paused"
    await service._handle_message(telegram_dm(LINKED, "/schedules resume 1"))
    assert texts(sent)[-1].startswith("Resumed “Canvas summary”")
    await service._handle_message(telegram_dm(LINKED, "/schedules run 1"))
    assert fake.runs == [(str(user.id), first)]
    await service._handle_message(telegram_dm(LINKED, "/schedules pause 9"))
    assert texts(sent)[-1].startswith("No such task")
    await service._client.aclose()


@pytest.mark.asyncio
async def test_buttons_work_only_from_the_linked_owners_chat(session_factory, backend):
    kit, fake = backend
    user, _ = await make_user(session_factory, "tg-buttons@example.com")
    first, _second = await two_tasks(kit, user)
    service, sent = telegram(str(user.id))
    # From an unlinked chat, and from someone else pressing in the owner's chat.
    await service._handle_callback(press(f"scp:{first}", STRANGER))
    await service._handle_callback(press(f"scp:{first}", LINKED, sender=4242))
    answers = [p["text"] for m, p in sent if m == "answerCallbackQuery"]
    assert answers == ["This chat is not linked to a Crawler AI account."] * 2
    assert (await kit.list(str(user.id)))["tasks"][0]["status"] == "active"
    # The owner's own press works.
    await service._handle_callback(press(f"scp:{first}", LINKED))
    assert (await kit.list(str(user.id)))["tasks"][0]["status"] == "paused"
    await service._handle_callback(press(f"scr:{first}", LINKED))
    await service._handle_callback(press(f"scn:{first}", LINKED))
    assert (await kit.list(str(user.id)))["tasks"][0]["status"] == "active"
    assert fake.runs == [(str(user.id), first)]
    await service._client.aclose()


@pytest.mark.asyncio
async def test_a_button_naming_someone_elses_task_changes_nothing(session_factory, backend):
    kit, fake = backend
    owner, _ = await make_user(session_factory, "tg-owner@example.com")
    intruder, _ = await make_user(session_factory, "tg-intruder@example.com")
    first, _second = await two_tasks(kit, owner)
    service, sent = telegram(str(intruder.id))
    await service._handle_callback(press(f"scp:{first}", LINKED))
    await service._handle_callback(press(f"scn:{first}", LINKED))
    assert (await kit.list(str(owner.id)))["tasks"][0]["status"] == "active"
    assert fake.runs == []
    assert all("No such task" in t for t in texts(sent))
    await service._client.aclose()


@pytest.mark.asyncio
async def test_briefing_runs_or_explains(session_factory, backend):
    kit, fake = backend
    user, _ = await make_user(session_factory, "tg-brief@example.com")
    service, sent = telegram(str(user.id))
    await service._handle_message(telegram_dm(LINKED, "/briefing"))
    assert "no daily briefing yet" in texts(sent)[-1]
    _first, second = await two_tasks(kit, user)
    await service._handle_message(telegram_dm(LINKED, "/briefing"))
    assert fake.runs == [(str(user.id), second)]
    await service._client.aclose()


@pytest.mark.asyncio
async def test_timezone_shows_saves_and_refuses_bad_names(session_factory, backend):
    from models.user import User

    user, _ = await make_user(session_factory, "tg-zone@example.com")
    service, sent = telegram(str(user.id))
    await service._handle_message(telegram_dm(LINKED, "/timezone"))
    assert texts(sent)[-1].startswith("No time zone saved yet")
    await service._handle_message(telegram_dm(LINKED, "/timezone ../etc"))
    assert "not a time zone" in texts(sent)[-1]
    await service._handle_message(telegram_dm(LINKED, "/timezone America/Chicago"))
    assert texts(sent)[-1].startswith("Saved: America/Chicago.")
    async with session_factory() as session:
        assert (await session.get(User, user.id)).timezone == "America/Chicago"
    await service._handle_message(telegram_dm(LINKED, "/timezone"))
    assert texts(sent)[-1].startswith("Your time zone: America/Chicago.")
    # An unlinked chat gets no answer at all.
    before = len(sent)
    await service._handle_message(telegram_dm(STRANGER, "/timezone Europe/London"))
    assert len(sent) == before
    await service._client.aclose()


@pytest.mark.asyncio
async def test_without_a_backend_the_commands_say_so(session_factory):
    schedule_commands.configure(None)
    service, sent = telegram("u")
    await service._handle_message(telegram_dm(LINKED, "/schedules"))
    assert texts(sent)[-1] == "Scheduled tasks are not available right now."
    await service._client.aclose()
