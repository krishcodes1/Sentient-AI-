"""Tests for the owner's trigger commands in chat (services/triggers/commands.py):
Telegram's /triggers lists the account's triggers with Pause and Resume
buttons, the text fallbacks ("/triggers pause 2", "resume 2", "delete 2" then
"delete 2 yes") do the same, a press from anyone but the linked account's own
chat or naming someone else's trigger changes nothing, /help names the
command, every change is audited with ids only; Slack's "triggers" keywords
match, come after the ones registered before, and other text still goes to
the chat.

Why it exists: these commands change what watches the owner's apps without an
approval card, so the link check and per-user scoping must hold for every one.
The Bot API and the Slack API are recorders; the database is in-memory SQLite.
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from typing import Any

import pytest
from sqlalchemy import select

from services.tools.triggers import TriggerToolkit
from services.triggers import commands as trigger_commands
from tests.conftest import make_user, telegram_dm

NOW = datetime(2026, 9, 30, 12, 0, tzinfo=timezone.utc)
LINKED, STRANGER = 8201, 8202
TEAM, SLACK_LINKED, SLACK_STRANGER, DM = "T0TEAM001", "U0LINKED1", "U0OTHER01", "D0DM00001"


@pytest.fixture
def backend(session_factory):
    kit = TriggerToolkit(session_factory, clock=lambda: NOW)
    trigger_commands.configure(trigger_commands.TriggerBackend(toolkit=kit, session_factory=session_factory))
    yield kit
    trigger_commands.configure(None)


async def add_trigger(session_factory, user, label, *, status="active", mode="notify", created=0) -> str:
    from models.event_trigger import EventTrigger

    trigger_id = uuid.uuid4()
    async with session_factory() as session:
        session.add(
            EventTrigger(
                id=trigger_id,
                user_id=user.id,
                label=label,
                source="canvas.announcement" if mode == "notify" else "email.new",
                filters={},
                fingerprint=uuid.uuid4().hex,
                mode=mode,
                prompt="Summarise it" if mode == "run_task" else None,
                interval_minutes=60,
                status=status,
                next_check_at=NOW,
                created_at=NOW + timedelta(seconds=created),
                updated_at=NOW,
            )
        )
        await session.commit()
    return str(trigger_id)


async def status_of(session_factory, trigger_id):
    from models.event_trigger import EventTrigger

    async with session_factory() as session:
        row = await session.get(EventTrigger, uuid.UUID(trigger_id))
        return None if row is None else row.status


async def audits(session_factory):
    from models.audit import AuditLog

    async with session_factory() as session:
        return list(
            (await session.execute(select(AuditLog).where(AuditLog.connector_name == "triggers"))).scalars().all()
        )


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


def texts(sent):
    return [p.get("text", "") for m, p in sent if m == "sendMessage"]


# -- Telegram ---------------------------------------------------------------------


@pytest.mark.asyncio
async def test_triggers_is_registered_with_its_buttons_and_in_help(backend):
    service, sent = telegram("u")
    assert "/triggers" in service._commands and {"tgp:", "tgr:"} <= set(service._callback_routes)
    await service._handle_help(LINKED)
    help_text = texts(sent)[-1]
    assert "/triggers — your app triggers" in help_text
    assert help_text.rstrip().endswith("/help — this message")
    await service._client.aclose()


@pytest.mark.asyncio
async def test_the_list_has_numbers_details_and_a_button_per_trigger(session_factory, backend):
    user, _ = await make_user(session_factory, "tg-trig-list@example.com")
    first = await add_trigger(session_factory, user, "Canvas posts")
    second = await add_trigger(session_factory, user, "Prof mail", status="paused", mode="run_task", created=1)
    service, sent = telegram(str(user.id))
    await service._handle_message(telegram_dm(LINKED, "/triggers"))
    [(method, params)] = sent
    assert "1. Canvas posts — a new Canvas announcement, messages you" in params["text"]
    assert "2. Prof mail — a new email, runs a task · paused" in params["text"]
    assert "runs today 0/6" in params["text"]
    buttons = [b["callback_data"] for row in params["reply_markup"]["inline_keyboard"] for b in row]
    assert buttons == [f"tgp:{first}", f"tgr:{second}"]
    assert all(len(b) <= 64 for b in buttons)
    await service._client.aclose()


@pytest.mark.asyncio
async def test_last_fired_shows_in_the_users_own_time_zone(session_factory, backend):
    from models.event_trigger import EventTrigger
    from models.user import User

    user, _ = await make_user(session_factory, "tg-trig-fired@example.com")
    trigger_id = await add_trigger(session_factory, user, "Canvas posts")
    async with session_factory() as session:
        (await session.get(User, user.id)).timezone = "America/New_York"
        (await session.get(EventTrigger, uuid.UUID(trigger_id))).last_fired_at = NOW
        await session.commit()
    service, sent = telegram(str(user.id))
    await service._handle_message(telegram_dm(LINKED, "/triggers"))
    [(_method, params)] = sent
    # 12:00 UTC is 08:00 in New York (EDT); never the raw ISO string.
    assert "last fired Wed Sep 30 08:00" in params["text"]
    assert "2026-09-30T" not in params["text"]
    await service._client.aclose()
    # Without a saved zone, this computer's zone (never a UTC ISO string).
    assert "T12:00" not in trigger_commands.list_text(
        [{"label": "x", "source": "email.new", "mode": "notify", "status": "active", "last_fired_at": "2026-09-30T12:00:00Z"}],
        how="",
    )


@pytest.mark.asyncio
async def test_text_fallbacks_pause_resume_and_delete_with_a_yes(session_factory, backend):
    user, _ = await make_user(session_factory, "tg-trig-text@example.com")
    first = await add_trigger(session_factory, user, "Canvas posts")
    service, sent = telegram(str(user.id))
    await service._handle_message(telegram_dm(LINKED, "/triggers pause 1"))
    assert texts(sent)[-1].startswith("Paused “Canvas posts”")
    assert await status_of(session_factory, first) == "paused"
    await service._handle_message(telegram_dm(LINKED, "/triggers resume 1"))
    assert texts(sent)[-1].startswith("Resumed “Canvas posts”")
    assert await status_of(session_factory, first) == "active"
    await service._handle_message(telegram_dm(LINKED, "/triggers delete 1"))
    assert texts(sent)[-1] == "Delete “Canvas posts” and its queued events? Send /triggers delete 1 yes to confirm."
    assert await status_of(session_factory, first) == "active"
    await service._handle_message(telegram_dm(LINKED, "/triggers delete 1 yes"))
    assert texts(sent)[-1].startswith("Deleted “Canvas posts”")
    assert await status_of(session_factory, first) is None
    await service._handle_message(telegram_dm(LINKED, "/triggers pause 9"))
    assert texts(sent)[-1].startswith("No such trigger")
    rows = await audits(session_factory)
    assert [(r.action, r.endpoint) for r in rows] == [
        ("trigger_paused", "telegram:/triggers"),
        ("trigger_resumed", "telegram:/triggers"),
        ("trigger_deleted", "telegram:/triggers"),
    ]
    assert all(set(r.request_data) == {"trigger_id"} for r in rows)
    assert "Canvas posts" not in json.dumps([r.request_data for r in rows])
    await service._client.aclose()


@pytest.mark.asyncio
async def test_buttons_work_only_from_the_linked_owners_chat(session_factory, backend):
    user, _ = await make_user(session_factory, "tg-trig-btn@example.com")
    first = await add_trigger(session_factory, user, "Canvas posts")
    service, sent = telegram(str(user.id))
    await service._handle_callback(press(f"tgp:{first}", STRANGER))
    await service._handle_callback(press(f"tgp:{first}", LINKED, sender=4242))
    answers = [p["text"] for m, p in sent if m == "answerCallbackQuery"]
    assert answers == ["This chat is not linked to a Crawler AI account."] * 2
    assert await status_of(session_factory, first) == "active"
    await service._handle_callback(press(f"tgp:{first}", LINKED))
    assert await status_of(session_factory, first) == "paused"
    await service._handle_callback(press(f"tgr:{first}", LINKED))
    assert await status_of(session_factory, first) == "active"
    await service._client.aclose()


@pytest.mark.asyncio
async def test_a_button_naming_someone_elses_trigger_changes_nothing(session_factory, backend):
    owner, _ = await make_user(session_factory, "tg-trig-owner@example.com")
    intruder, _ = await make_user(session_factory, "tg-trig-intruder@example.com")
    first = await add_trigger(session_factory, owner, "Canvas posts")
    service, sent = telegram(str(intruder.id))
    await service._handle_callback(press(f"tgp:{first}", LINKED))
    await service._handle_message(telegram_dm(LINKED, f"/triggers delete {first} yes"))
    assert await status_of(session_factory, first) == "active"
    assert all("No such trigger" in t for t in texts(sent))
    await service._client.aclose()


@pytest.mark.asyncio
async def test_without_a_backend_the_command_says_so(session_factory):
    trigger_commands.configure(None)
    service, sent = telegram("u")
    await service._handle_message(telegram_dm(LINKED, "/triggers"))
    assert texts(sent)[-1] == "Triggers are not available right now."
    await service._client.aclose()


@pytest.mark.asyncio
async def test_no_triggers_says_how_to_make_one(session_factory, backend):
    user, _ = await make_user(session_factory, "tg-trig-none@example.com")
    service, sent = telegram(str(user.id))
    await service._handle_message(telegram_dm(LINKED, "/triggers"))
    assert texts(sent)[-1].startswith("You have no triggers yet.")
    await service._client.aclose()


# -- Slack ----------------------------------------------------------------------------


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
    link = SimpleNamespace(team_id=TEAM, slack_user_id=SLACK_LINKED, link_code_hash=None, link_expires_at=None)

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


def dm(text: str, n: int, sender: str = SLACK_LINKED) -> dict[str, Any]:
    return {
        "type": "event_callback",
        "team_id": TEAM,
        "event_id": f"Ev{n:08d}",
        "event": {"type": "message", "channel": DM, "user": sender, "text": text, "ts": f"{n}.000100", "channel_type": "im"},
    }


async def say(channel, text, n, sender=SLACK_LINKED):
    await channel._on_events_api(dm(text, n, sender))
    await channel.wait_idle()


@pytest.mark.asyncio
async def test_slack_keywords_list_pause_resume_and_delete(session_factory, backend):
    user, _ = await make_user(session_factory, "slack-trig@example.com")
    first = await add_trigger(session_factory, user, "Canvas posts")
    channel, posted, chats = slack(str(user.id))
    names = [h.__name__ for h in channel._text_handlers]
    # After the built-ins and the scheduler's keywords; a later skill's
    # keywords (grants) may follow it.
    assert names.index("_keyword_triggers") > names.index("_keyword_timezone")
    await say(channel, "triggers", 1)
    assert "1. Canvas posts — a new Canvas announcement" in posted[-1] and 'Reply "triggers pause 2"' in posted[-1]
    await say(channel, "Triggers Pause 1", 2)
    assert posted[-1].startswith("Paused") and await status_of(session_factory, first) == "paused"
    await say(channel, "triggers resume 1", 3)
    assert await status_of(session_factory, first) == "active"
    await say(channel, "triggers delete 1", 4)
    assert posted[-1].endswith('Send "triggers delete 1 yes" to confirm.')
    await say(channel, "triggers delete 1 yes", 5)
    assert await status_of(session_factory, first) is None
    await say(channel, "triggers are neat", 6)
    assert chats == ["triggers are neat"]
    assert [r.endpoint for r in await audits(session_factory)] == ["slack:triggers"] * 3
    await channel._connector.close()


@pytest.mark.asyncio
async def test_a_slack_stranger_is_never_answered(session_factory, backend):
    user, _ = await make_user(session_factory, "slack-trig-stranger@example.com")
    first = await add_trigger(session_factory, user, "Canvas posts")
    channel, posted, chats = slack(str(user.id))
    await say(channel, "triggers pause 1", 1, sender=SLACK_STRANGER)
    assert posted == [] and chats == []
    assert await status_of(session_factory, first) == "active"
    await channel._connector.close()
