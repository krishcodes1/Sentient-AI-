"""Tests for weekly app approvals: which apps can be allowed, the channel an
approval is tied to, and both stores (in memory and the ``app_approvals``
table): allow, renew, find, expiry, revoke.

Why it exists: an approval lets desktop acts run with no card for a week, so
what it covers must be exactly one app, one channel and seven days, and a
browser, a mail or chat app or a store must never be on the list (spec
2026-09-25-weekly-app-approvals §3). The runtime and channel tests build on
these; here nothing runs a turn.
"""

from __future__ import annotations

import hashlib
import uuid
from datetime import datetime, timedelta, timezone

import pytest
import pytest_asyncio

from services.agent.app_approvals import (
    WEEK,
    Channel,
    DbAppApprovalStore,
    InMemoryAppApprovalStore,
    target_app,
    weekly_app_for,
)
from services.tools.computer import rules
from services.tools.computer.toolkit import CARD_KEY

T0 = datetime(2026, 9, 25, 12, 0, tzinfo=timezone.utc)
TG = Channel.telegram(9101)
DEVICE = "3f2b9c3e-6a4d-4f1e-9d7a-2b8c1e5f0a7d"
WEB = Channel.web(DEVICE)


class Clock:
    def __init__(self, now: datetime = T0) -> None:
        self.now = now

    def __call__(self) -> datetime:
        return self.now


# ── which apps ───────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    ("name", "display"),
    [
        ("Calendar", "Calendar"),
        ("calendar", "Calendar"),
        ("/Applications/Calendar.app", "Calendar"),
        ("iCal", "Calendar"),
        ("Reminders", "Reminders"),
        ("Notes", "Notes"),
        ("Contacts", "Contacts"),
        ("Microsoft Sticky Notes", "Sticky Notes"),
        ("CalculatorApp.exe", "Calculator"),
        ("Notepad", "Notepad"),
        ("Microsoft Photos", "Photos"),
        ("Clock", "Clock"),
    ],
)
def test_everyday_local_apps_can_be_allowed_for_a_week(name, display):
    assert rules.weekly_app(name) == display


@pytest.mark.parametrize(
    "name",
    [
        # browsers: an unattended click could place an order
        "Safari",
        "Google Chrome",
        "Microsoft Edge",
        "Firefox",
        "Arc",
        # mail, messages and chat: an unattended click could send something
        "Mail",
        "Messages",
        "Microsoft Outlook",
        "Slack",
        "Telegram",
        "WhatsApp",
        # stores, files, automation
        "App Store",
        "Music",
        "TV",
        "Books",
        "Finder",
        "File Explorer",
        "Shortcuts",
        # blocked apps nothing can approve
        "Terminal",
        "1Password",
        "System Settings",
        "Crawler AI",
        # near misses: the whole name only
        "Calendar Helper",
        "com.example.calendar",
        "Notes Pro",
        "",
    ],
)
def test_nothing_else_can_be_allowed_for_a_week(name):
    assert rules.weekly_app(name) is None


def test_the_list_names_no_browser_mail_chat_or_store():
    for display in rules.WEEKLY_APPS:
        assert rules.blocked_app(display) is None
    assert not {"Safari", "Mail", "Messages", "App Store", "Music", "TV", "Books"} & set(
        rules.WEEKLY_APPS
    )


def test_the_target_app_is_the_named_app_or_the_bound_screens():
    assert target_app("desktop.act", {"action": "open_app", "app": "Calendar"}) == "Calendar"
    assert target_app("desktop.act", {"action": "focus_window", "app": " Notes "}) == "Notes"
    bound = {"action": "click", "ref": "d4", CARD_KEY: {"app": "Calendar", "outline": "ab"}}
    assert target_app("desktop.act", bound) == "Calendar"
    # An act that is not bound names no app: it gets a card.
    assert target_app("desktop.act", {"action": "click", "ref": "d4"}) is None
    # open_app names its app; the screen it was made from does not count.
    moved = {"action": "open_app", "app": "Safari", CARD_KEY: {"app": "Calendar", "outline": ""}}
    assert target_app("desktop.act", moved) == "Safari"
    assert target_app("browser.act", {"action": "click", "app": "Calendar"}) is None


def test_weekly_app_for_is_desktop_act_on_the_list_only():
    bound = {"action": "type", "text": "x", CARD_KEY: {"app": "Calendar", "outline": "ab"}}
    assert weekly_app_for("desktop.act", bound) == "Calendar"
    assert (
        weekly_app_for("desktop.act", {**bound, CARD_KEY: {"app": "Mail", "outline": ""}}) is None
    )
    assert weekly_app_for("desktop.observe", bound) is None
    assert weekly_app_for("desktop.act", "not a mapping") is None


# ── channels ─────────────────────────────────────────────────────────────────


def test_a_web_channel_stores_only_the_hash_of_the_device_id():
    assert WEB is not None
    assert WEB.kind == "web"
    assert WEB.key == hashlib.sha256(DEVICE.encode()).hexdigest()
    assert DEVICE not in WEB.key


@pytest.mark.parametrize(
    "bad",
    [None, "", "short", "x" * 101, "has spaces in it ok", "ünïcödé-ünïcödé-ü", 12345678901234567],
)
def test_a_missing_or_malformed_device_id_is_no_channel(bad):
    assert Channel.web(bad) is None


def test_a_telegram_channel_is_the_chat_id():
    assert TG == Channel("telegram", "9101")


# ── the stores ───────────────────────────────────────────────────────────────


@pytest_asyncio.fixture(params=["memory", "db"])
async def store_and_clock(request, session_factory):
    clock = Clock()
    if request.param == "memory":
        yield InMemoryAppApprovalStore(now=clock), clock, None
    else:
        from models.user import User

        async with session_factory() as session:
            user = User(email=f"{uuid.uuid4().hex}@example.com", hashed_password="x")
            session.add(user)
            await session.commit()
        yield DbAppApprovalStore(session_factory, now=clock), clock, str(user.id)


def _user(owner):
    return owner or str(uuid.uuid4())


@pytest.mark.asyncio
async def test_an_approval_holds_for_its_app_and_channel_for_seven_days(store_and_clock):
    store, clock, owner = store_and_clock
    uid = _user(owner)
    made = await store.allow(
        user_id=uid, app="Calendar", channel=TG, source_action_id=str(uuid.uuid4())
    )
    assert made.expires_at == T0 + WEEK
    assert made.app == "Calendar" and made.channel_kind == "telegram"

    found = await store.find(user_id=uid, app="Calendar", channel=TG)
    assert found is not None and found.id == made.id
    # Another app, another channel, another user: nothing.
    assert await store.find(user_id=uid, app="Notes", channel=TG) is None
    assert await store.find(user_id=uid, app="Calendar", channel=WEB) is None
    assert await store.find(user_id=uid, app="Calendar", channel=Channel.telegram(42)) is None
    assert await store.find(user_id=str(uuid.uuid4()), app="Calendar", channel=TG) is None

    clock.now = T0 + WEEK - timedelta(seconds=1)
    assert await store.find(user_id=uid, app="Calendar", channel=TG) is not None
    clock.now = T0 + WEEK
    assert await store.find(user_id=uid, app="Calendar", channel=TG) is None
    assert await store.list_active(uid) == []


@pytest.mark.asyncio
async def test_allowing_again_renews_the_week_instead_of_adding_a_row(store_and_clock):
    store, clock, owner = store_and_clock
    uid = _user(owner)
    first = await store.allow(user_id=uid, app="Calendar", channel=TG)
    clock.now = T0 + timedelta(days=5)
    again = await store.allow(user_id=uid, app="Calendar", channel=TG)
    assert again.id == first.id
    assert again.expires_at == T0 + timedelta(days=12)
    assert [a.id for a in await store.list_active(uid)] == [first.id]
    # The same app from the browser is a second, separate approval.
    await store.allow(user_id=uid, app="Calendar", channel=WEB)
    assert len(await store.list_active(uid)) == 2


@pytest.mark.asyncio
async def test_revoking_ends_one_approval_and_only_the_owners(store_and_clock):
    store, _, owner = store_and_clock
    uid = _user(owner)
    cal = await store.allow(user_id=uid, app="Calendar", channel=TG)
    notes = await store.allow(user_id=uid, app="Notes", channel=TG)

    assert await store.revoke(user_id=str(uuid.uuid4()), approval_id=cal.id) is None
    revoked = await store.revoke(user_id=uid, approval_id=cal.id)
    assert revoked is not None and revoked.app == "Calendar"
    assert await store.revoke(user_id=uid, approval_id=cal.id) is None  # once
    assert await store.revoke(user_id=uid, approval_id="not-a-uuid") is None
    assert await store.find(user_id=uid, app="Calendar", channel=TG) is None
    assert [a.id for a in await store.list_active(uid)] == [notes.id]


@pytest.mark.asyncio
async def test_revoking_a_channel_ends_every_approval_given_from_it(store_and_clock):
    store, _, owner = store_and_clock
    uid = _user(owner)
    await store.allow(user_id=uid, app="Calendar", channel=TG)
    await store.allow(user_id=uid, app="Notes", channel=TG)
    web = await store.allow(user_id=uid, app="Calendar", channel=WEB)
    assert await store.revoke_channel(user_id=uid, kind="telegram") == 2
    assert [a.id for a in await store.list_active(uid)] == [web.id]


@pytest.mark.asyncio
async def test_uses_are_counted(store_and_clock):
    store, clock, owner = store_and_clock
    uid = _user(owner)
    made = await store.allow(user_id=uid, app="Calendar", channel=TG)
    clock.now = T0 + timedelta(hours=1)
    await store.record_use(made.id)
    [live] = await store.list_active(uid)
    assert live.last_used_at == T0 + timedelta(hours=1)
