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
    SITE_TOOL,
    SITE_TTL,
    TOOL,
    WEEK,
    Channel,
    DbAppApprovalStore,
    InMemoryAppApprovalStore,
    errand_covers,
    may_run_errand,
    may_run_site,
    may_run_weekly,
    site_covers,
    site_for,
    site_key,
    target_app,
    weekly_app_for,
    weekly_arguments,
    weekly_covers,
)
from services.tools.computer import rules
from services.tools.computer.toolkit import CARD_KEY, WEEKLY_MARK

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
        # text editors: their Save sheet writes any file (~/.zshrc, Startup)
        "TextEdit",
        "Notepad",
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


def _click(role: str, name: str, action: str = "click") -> dict:
    screen = {"app": "Calendar", "outline": "ab", "target": {"role": role, "name": name}}
    return {"action": action, "ref": "d4", CARD_KEY: screen}


@pytest.mark.parametrize(
    "arguments",
    [
        {"action": "scroll", "direction": "down"},
        {"action": "open_app", "app": "Calendar"},
        {"action": "focus_window", "app": "Calendar"},
        {"action": "key", "keys": "pagedown"},
        {"action": "key", "keys": "cmd+right"},
        _click("cell", "September 15"),
        _click("button", "Next month"),
        _click("button", "Today"),
        _click("radio button", "Week"),
        _click("row", "Dentist 10:00", action="double_click"),
    ],
)
def test_a_weekly_approval_covers_looking_around(arguments):
    assert weekly_covers(arguments) is True


@pytest.mark.parametrize(
    "arguments",
    [
        # typing, and keys that confirm, save or open
        {"action": "type", "text": "Jordan", "ref": "d4"},
        {"action": "key", "keys": "enter"},
        {"action": "key", "keys": "cmd+s"},
        {"action": "key", "keys": "cmd+shift+s"},
        {"action": "key", "keys": "ctrl+right"},
        # controls that answer, send, share, delete or save
        _click("button", "Decline"),
        _click("button", "Send"),
        _click("button", "Add Invitees"),
        _click("menu item", "Share"),
        _click("cell", "Delete event"),
        _click("button", "Save"),
        # anything not known to only show something
        _click("button", "Done"),
        _click("link", "Join meeting"),
        _click("checkbox", "Completed"),
        # a click with no element behind it
        {"action": "click", "x": 10, "y": 10, CARD_KEY: {"app": "Calendar", "outline": "ab"}},
        {"action": "click", "ref": "d4", CARD_KEY: {"app": "Calendar", "outline": "ab"}},
        {"action": "click", "ref": "d4"},
        "not a mapping",
    ],
)
def test_a_weekly_approval_never_covers_typing_or_a_consequential_control(arguments):
    assert weekly_covers(arguments) is False


# Security wave: the call checks' "would this run without a card" test for an
# unbound act (services.agent.app_approvals.may_run_weekly, scaffold A29).
@pytest.mark.parametrize(
    ("arguments", "may_run"),
    [
        ({"action": "scroll", "direction": "down"}, True),
        ({"action": "open_app", "app": "Calendar"}, True),
        ({"action": "focus_window", "app": "Calendar"}, True),
        ({"action": "key", "keys": "pagedown"}, True),
        ({"action": "key", "keys": "cmd+right"}, True),
        ({"action": "click", "ref": "d4"}, True),
        ({"action": "double_click", "ref": "d4"}, True),
        ({"action": "type", "text": "Jordan", "ref": "d4"}, False),
        ({"action": "key", "keys": "enter"}, False),
        ({"action": "key", "keys": "not a combo +"}, False),
        ({"action": "click", "x": 10, "y": 10}, False),
        ({"action": "click", "ref": 4}, False),
        ("not a mapping", False),
        (None, False),
    ],
)
def test_may_run_weekly_accepts_every_shape_weekly_covers_can_and_never_type(arguments, may_run):
    assert may_run_weekly(arguments) is may_run
    # A superset of weekly_covers: whatever it refuses, weekly_covers refuses
    # too, bound or not (so a call it calls carded can never run unasked).
    if not may_run:
        assert weekly_covers(arguments) is False
        if isinstance(arguments, dict):
            bound = {**arguments, CARD_KEY: {"app": "Calendar", "target": {"role": "cell", "name": "15"}}}
            assert weekly_covers(bound) is False


def test_a_weekly_run_is_marked_on_its_screen():
    bound = _click("cell", "September 15")
    marked = weekly_arguments(bound)
    assert marked[CARD_KEY] == {**bound[CARD_KEY], WEEKLY_MARK: True}
    assert WEEKLY_MARK not in bound[CARD_KEY]


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


# ── site approvals (browser.act on one website, for a short while) ──────────────────────


@pytest.mark.parametrize(
    ("host", "key"),
    [
        ("tickets.fandango.com", "tickets.fandango.com"),
        ("WWW.Fandango.COM", "www.fandango.com"),
        ("xn--bcher-kva.example", "xn--bcher-kva.example"),
        ("localhost", None),  # a public site has a dot
        ("fandango.com.", None),
        ("fan dango.com", None),
        ("fandango.com/path", None),
        ("https://fandango.com", None),
        ("-bad.example", None),
        ("a" * 101 + ".com", None),
        ("", None),
        (None, None),
    ],
)
def test_a_site_is_keyed_by_its_exact_host(host, key):
    assert site_key(host) == key


@pytest.mark.asyncio
async def test_a_site_approval_holds_for_its_exact_host_and_channel_for_one_hour(store_and_clock):
    """Every browser.act had its own card and every card ended the turn, so a
    booking took a tap per click. A site approval lets the acts that only
    click around on ONE host run for an hour, from the chat or browser that
    gave it. The host is matched exactly: a look-alike, a sibling subdomain
    or two hosts that differ only in where the dots are never share one."""
    store, clock, owner = store_and_clock
    uid = _user(owner)
    made = await store.allow(
        user_id=uid, app="tickets.fandango.com", channel=TG, tool=SITE_TOOL,
        source_action_id=str(uuid.uuid4()),
    )
    assert made.tool == SITE_TOOL and made.app == "tickets.fandango.com"
    assert made.expires_at == T0 + SITE_TTL == T0 + timedelta(hours=1)

    async def held(host, channel=TG, tool=SITE_TOOL, user=uid):
        return await store.find(user_id=user, app=host, channel=channel, tool=tool)

    assert (await held("tickets.fandango.com")).id == made.id
    assert (await held("Tickets.Fandango.com")).id == made.id
    for other in ("www.fandango.com", "fandango.com", "ticketsfandango.com", "tickets.fandango.co",
                  "tickets.fandango.com.evil.example", "t.icketsfandango.com"):
        assert await held(other) is None, other
    assert await held("tickets.fandango.com", channel=WEB) is None
    assert await held("tickets.fandango.com", user=str(uuid.uuid4())) is None
    # A site approval is not an app approval, and the other way round.
    assert await held("tickets.fandango.com", tool=TOOL) is None
    calendar = await store.allow(user_id=uid, app="Calendar", channel=TG)
    assert calendar.tool == TOOL and calendar.expires_at == T0 + WEEK
    assert await store.find(user_id=uid, app="Calendar", channel=TG, tool=SITE_TOOL) is None

    # The owner sees and can end both kinds in one list.
    assert {(a.tool, a.app) for a in await store.list_active(uid)} == {
        (SITE_TOOL, "tickets.fandango.com"),
        (TOOL, "Calendar"),
    }
    clock.now = T0 + SITE_TTL - timedelta(seconds=1)
    assert await held("tickets.fandango.com") is not None
    clock.now = T0 + SITE_TTL
    assert await held("tickets.fandango.com") is None
    assert [a.app for a in await store.list_active(uid)] == ["Calendar"]


@pytest.mark.asyncio
async def test_allowing_a_site_again_renews_the_hour_and_dots_never_collide(store_and_clock):
    store, clock, owner = store_and_clock
    uid = _user(owner)
    first = await store.allow(user_id=uid, app="a.bc.example", channel=TG, tool=SITE_TOOL)
    other = await store.allow(user_id=uid, app="ab.c.example", channel=TG, tool=SITE_TOOL)
    assert other.id != first.id
    clock.now = T0 + timedelta(minutes=50)
    again = await store.allow(user_id=uid, app="a.bc.example", channel=TG, tool=SITE_TOOL)
    assert again.id == first.id and again.expires_at == T0 + timedelta(minutes=110)
    assert await store.revoke(user_id=uid, approval_id=first.id) is not None
    assert await store.find(user_id=uid, app="a.bc.example", channel=TG, tool=SITE_TOOL) is None
    assert await store.find(user_id=uid, app="ab.c.example", channel=TG, tool=SITE_TOOL) is not None


@pytest.mark.asyncio
async def test_a_host_that_is_no_site_is_never_allowed(store_and_clock):
    store, _, owner = store_and_clock
    uid = _user(owner)
    with pytest.raises(ValueError):
        await store.allow(user_id=uid, app="not a host", channel=TG, tool=SITE_TOOL)
    assert await store.find(user_id=uid, app="not a host", channel=TG, tool=SITE_TOOL) is None
    assert await store.list_active(uid) == []


def _act(action="click", page=None, **arguments):
    """A browser.act card's arguments as the toolkit binds them: the call's
    own plus ``_page`` (the page the card was made from; ``quiet`` is the
    toolkit's own judgment of the live page and target)."""
    bound = {"origin": "https://tickets.fandango.com", "address": "a1", "outline": "o1", "scheme": "https",
             "picture": "p1", "quiet": True, "target": {"role": "button", "name": "Seat F7, available"}}
    bound.update(page or {})
    return {"action": action, **arguments, "_page": bound}


@pytest.mark.parametrize(
    "arguments",
    [
        _act("click", ref="e7"),
        _act("select", ref="e7", value="2"),
        _act("check", ref="e7"),
        _act("press", key="Tab"),
        _act("press", key="ArrowDown"),
        _act("press", key="Escape"),
    ],
)
def test_a_site_approval_covers_clicking_around(arguments):
    assert site_for(SITE_TOOL, arguments) == "tickets.fandango.com"
    assert may_run_site(arguments) and site_covers(arguments)


@pytest.mark.parametrize(
    "arguments",
    [
        _act("fill", ref="e7", text="me@example.com"),  # typing always asks
        _act("fill_form", fields=[{"ref": "e7", "text": "x"}]),
        _act("submit", ref="e7"),  # sending a form always asks
        _act("press", key="Enter"),  # Enter can send a form
        _act("click"),  # no ref: nothing the toolkit judged
        _act("click", ref="e7", page={"quiet": False}),  # the toolkit said this one is not quiet
        _act("click", ref="e7", page={"quiet": None}),
        _act("click", ref="e7", page={"quiet": "yes"}),  # only the toolkit's own True counts
        # The card carries a money warning: a person looks at that one.
        _act("click", ref="e7", page={"money": {"order_total": True, "saved_payment": True}}),
        _act("click", ref="e7", page={"scheme": "http", "origin": "http://tickets.fandango.com"}),
        _act("click", ref="e7", page={"origin": "https://localhost"}),
        _act("click", ref="e7", page={"origin": "not a url"}),
        # Another port is another origin; an address is no site.
        _act("click", ref="e7", page={"origin": "https://tickets.fandango.com:8443"}),
        _act("click", ref="e7", page={"origin": "https://tickets.fandango.com:notaport"}),
        _act("click", ref="e7", page={"origin": "https://192.168.1.1"}),
        # The target's own name: a script button sends no form, so its words
        # are all that tell "Cancel booking" from "Next".
        *[
            _act("click", ref="e7", page={"target": {"role": "button", "name": name}})
            for name in (
                "Cancel booking", "Delete account", "Post", "Send", "Unsubscribe", "Transfer tickets",
                "Accept invitation", "Confirm reservation", "Log out", "Sign out", "Share", "Decline",
                "Book now", "Reserve", "Place order", "Check out", "Apply", "Join", "Follow", "Report",
                "Remove from cart", "Save changes", "Submit", "Pay $12.00", "Leave group", "Empty cart",
            )
        ],
        _act("check", ref="e7", page={"target": {"role": "checkbox", "name": "I agree to the Terms of Service"}}),
        # No name to judge, or one of the wrong shape, keeps the card.
        _act("click", ref="e7", page={"target": {"role": "button", "name": ""}}),
        _act("click", ref="e7", page={"target": {"role": "button", "name": "  "}}),
        _act("click", ref="e7", page={"target": {"role": "button", "name": 7}}),
        _act("click", ref="e7", page={"target": "Seat F7"}),
        _act("click", ref="e7", page={"target": None}),
        _act("click", ref="e7", page={"target": {"role": "button", "name": "x" * 201}}),
        {"action": "click", "ref": "e7"},  # unbound
        {"action": "click", "ref": "e7", "_page": "junk"},
        None,
    ],
)
def test_a_site_approval_never_covers_typing_sending_or_anything_the_card_warns_about(arguments):
    assert not site_covers(arguments)


def test_site_for_is_browser_act_on_an_https_page_only():
    bound = _act("fill", ref="e7", text="x")
    # Any browser.act card on the site names the site (the button is offered
    # by what the card is, see site_covers); other tools never do.
    assert site_for(SITE_TOOL, bound) == "tickets.fandango.com"
    assert site_for("desktop.act", bound) is None
    assert site_for("browser.read", bound) is None
    assert site_for("browser.checkout", bound) is None
    assert site_for(SITE_TOOL, _act(page={"origin": "https://WWW.Fandango.com:443"})) == "www.fandango.com"
    # Only https's own port: another port is another origin.
    assert site_for(SITE_TOOL, _act(page={"origin": "https://www.fandango.com:8443"})) is None
    assert site_for(SITE_TOOL, _act(page={"origin": "https://www.fandango.com:99999"})) is None
    assert site_for(SITE_TOOL, _act(page={"origin": "https://user:pw@evil.example@fandango.com"})) is None


@pytest.mark.parametrize(
    ("arguments", "may_run"),
    [
        ({"action": "click", "ref": "e7"}, True),
        ({"action": "select", "ref": "e7", "value": "2"}, True),
        ({"action": "check", "ref": "e7"}, True),
        ({"action": "press", "key": "Tab"}, True),
        ({"action": "press", "key": "Enter"}, False),
        ({"action": "fill", "ref": "e7", "text": "x"}, False),
        ({"action": "fill_form", "fields": []}, False),
        ({"action": "submit", "ref": "e7"}, False),
        ({"action": "click"}, False),
        ("junk", False),
    ],
)
def test_may_run_site_accepts_every_shape_site_covers_can_and_never_typing(arguments, may_run):
    assert may_run_site(arguments) is may_run


@pytest.mark.parametrize(
    "name",
    ["Seat F7, available", "Next", "Continue", "7:45 PM", "Show more", "Select 2 tickets", "Standard", "Go to slide 2",
     "Thursday, November 12", "Add to cart", "Back", "Close", "Dolby Cinema format"],
)
def test_a_site_approval_covers_a_control_whose_name_only_moves_or_picks(name):
    assert site_covers(_act("click", ref="e7", page={"target": {"role": "button", "name": name}}))


@pytest.mark.parametrize("host", ["192.168.1.1", "1.1.1.1", "127.0.0.1", "10.1", "0x7f.1", "2130706433.1"])
def test_an_address_is_never_a_site(host):
    from services.agent.app_approvals import site_key

    assert site_key(host) is None
    assert site_for(SITE_TOOL, _act(page={"origin": f"https://{host}"})) is None


def test_only_the_toolkit_writes_the_page_key():
    from services.agent.app_approvals import carries_page

    assert carries_page({"action": "click", "ref": "e7", "_page": {}})
    assert not carries_page({"action": "click", "ref": "e7"}) and not carries_page(None)


# ── website errands (the "Ask before every website step" switch off) ──────


def _errand(action="click", page=None, **arguments):
    """A browser.act card's arguments as the toolkit binds them for an
    errand step: ``errand`` is its own judgment of the live page, ``target``
    the control's words and ``fields`` the kinds of the fields typed into."""
    bound = {"origin": "https://www.amazon.com", "address": "a1", "outline": "o1", "scheme": "https",
             "picture": "p1", "quiet": False, "errand": True, "target": {"name": "Add to Cart"}}
    if action in ("fill", "fill_form"):
        bound.pop("target")
        bound["fields"] = ["search"] * (len(arguments.get("fields") or ()) or 1)
    bound.update(page or {})
    return {"action": action, **arguments, "_page": bound}


@pytest.mark.parametrize(
    "arguments",
    [
        _errand("click", ref="e7"),
        *[
            _errand("click", ref="e7", page={"target": {"name": name}})
            for name in (
                "Add to Cart", "Proceed to checkout", "Continue", "Next", "7:15 PM", "Accept cookies",
                "Reject all cookies", "Cancel", "OK", "Close", "Back", "See more", "Show all", "View cart",
                "Select size M", "Update cart", "Increase quantity", "Apply filters", "Add to order list",
            )
        ],
        # A plain link is followed by GET: its words are navigation.
        _errand("click", ref="e7", page={"target": {"name": "Order online", "plain_link": True}}),
        _errand("click", ref="e7", page={"target": {"name": "", "plain_link": True}}),
        _errand("select", ref="e7", value="2", page={"target": {"name": "Quantity | 2 | 2"}}),
        _errand("check", ref="e7", page={"target": {"name": "Gift wrap"}}),
        _errand("fill", ref="e2", text="chain lube"),
        _errand("fill_form", fields=[{"ref": "e2", "text": "x"}, {"ref": "e3", "text": "94110"}],
                page={"fields": ["quantity", "zip"]}),
        _errand("fill", ref="e2", text="SAVE10", page={"fields": ["promo"]}),
        _errand("submit", ref="e2", page={"target": {"name": "Go"}}),
        _errand("press", key="Enter", page={"target": {"name": ""}}),  # a search form with no button
        *[_errand("press", key=key, page={"target": None}) for key in ("Tab", "Escape", "ArrowDown", "ArrowUp")],
        # Short names a person presses to move on, by their whole name only.
        *[
            _errand("click", ref="e7", page={"target": {"name": name}})
            for name in (
                "Dismiss", "Got it", "Accept all", "Accept all cookies", "Reject all", "Maybe later",
                "Apply 10% coupon", "Order summary", "Clear filters", "Save for later", "More like this",
            )
        ],
        # Judged by the words a person reads, not the control's name attribute
        # (Amazon's input is name="submit.add-to-cart").
        _errand("click", ref="e7", page={"target": {
            "name": "Add to Cart | Add to Shopping Cart | submit.add-to-cart",
            "words": "Add to Cart | Add to Shopping Cart",
        }}),
        # A cookie banner's own Agree or OK, inside a region about cookies.
        *[
            _errand("click", ref="e7", page={"target": {"name": name, "consent": True}})
            for name in ("Agree and close", "I agree", "Accept", "OK", "Allow all", "Accept our cookie policy", "Yes")
        ],
        # A brand that starts with a word on the list.
        _errand("check", ref="e7", page={"target": {"name": "Finish Line (23)"}}),
        # A wallet button elsewhere on the page, or a link worded like a
        # purchase: the card would warn, but the page shows nothing to pay.
        _errand("click", ref="e7", page={"money": {
            "amount": "", "order_total": False, "saved_payment": False, "wallet": True, "unread": False,
        }}),
        *[
            _errand("click", ref="e7", page={"target": {"name": name, "plain_link": True}})
            for name in ("Sign in", "Cancellation policy", "Cancel", "Order online", "7:15 PM")
        ],
        _errand("click", ref="e7", page={
            "target": {"name": "All showtimes", "plain_link": True},
            "money": {"amount": "", "order_total": False, "saved_payment": False, "wallet": False, "unread": False},
        }),
    ],
)
def test_an_errand_step_the_toolkit_judged_on_the_live_page_runs_without_a_card(arguments):
    assert may_run_errand(arguments) and errand_covers(arguments)


@pytest.mark.parametrize(
    "arguments",
    [
        # Only the toolkit's own True counts.
        *[_errand("click", ref="e7", page={"errand": value}) for value in (False, None, "yes", 1)],
        # The card warns about money the page shows: a person looks at it.
        _errand("click", ref="e7", page={"money": {"order_total": True}}),
        *[
            _errand("click", ref="e7", page={"money": {
                "amount": "", "order_total": False, "saved_payment": False, "wallet": True, "unread": False,
                **shown,
            }})
            for shown in ({"saved_payment": True}, {"amount": "$9.99"}, {"unread": True})
        ],
        _errand("click", ref="e7", page={"money": {"wallet": True}}),  # a fact missing counts as shown
        # Not one public https host.
        _errand("click", ref="e7", page={"scheme": "http", "origin": "http://www.amazon.com"}),
        _errand("click", ref="e7", page={"origin": "https://192.168.1.1"}),
        _errand("click", ref="e7", page={"origin": "https://localhost"}),
        _errand("click", ref="e7", page={"origin": "https://www.amazon.com:8443"}),
        # Words that commit the person, whatever the toolkit said.
        *[
            _errand("click", ref="e7", page={"target": {"name": name}})
            for name in (
                "Place your order", "Buy Now", "Pay", "Post comment", "Send", "Delete", "Cancel subscription",
                "Cancel my order", "Sign up", "Register", "Create account", "Join", "Subscribe", "Unsubscribe",
                "Submit", "Confirm", "Book", "Reserve", "RSVP", "Donate", "Tip", "Place bid", "Vote",
                "Remove from account", "Close account", "Deactivate", "Revoke", "Block", "Report", "Transfer",
                "Withdraw", "Refund", "Redeem", "Claim", "I agree", "Accept terms", "Accept the agreement",
                "Log out", "Sign out", "Empty cart", "Clear", "Share", "Reply", "Write a review", "Rate",
                "Follow", "Like", "Apply", "Save", "Reorder", "Order",
            )
        ],
        # Cancelling, signing, granting, connecting and the social sends,
        # by their stems ("Finish Cancellation" is Netflix's last button).
        *[
            _errand("click", ref="e7", page={"target": {"name": name}})
            for name in (
                "Finish Cancellation", "Continue to cancel", "Yes, cancel", "Cancel my plan now",
                "End membership", "Pause membership", "Stop subscription", "Turn off auto-renew", "Opt out",
                "Adopt and Sign", "Sign", "Sign document", "Allow", "Authorize", "Authorise app",
                "Grant access", "Accept", "Connect", "Add friend", "Repost", "Retweet", "Upvote", "Enroll",
                "Enrol now", "Remove", "Remove card", "Install", "Activate", "Disable two-factor authentication",
                "Decline", "Leave group", "Trash", "Reject", "Drop course", "Merge", "Message seller",
                "Call now", "Email me", "Cancel | Cancel subscription",
            )
        ],
        # The same stems with a prefix, and outcomes the list once missed.
        *[
            _errand("click", ref="e7", page={"target": {"name": name}})
            for name in (
                "Unsend", "Unblock", "Unpublish", "Unlike", "Downvote", "Dislike", "Disconnect", "Reactivate",
                "Resubscribe", "Rebook", "Rejoin", "Re-subscribe", "Restart membership", "Resume membership",
                "Switch to annual billing", "Switch plan", "Get Premium", "Sell", "Request",
                "Turn off two-factor authentication", "Turn on auto-pay", "Make profile public",
                "Make my account private", "Start a return", "Finish", "End my benefits", "Yes",
            )
        ],
        # Words beside the ones a person reads still count when they are
        # all the toolkit wrote; the words it read win when it wrote both.
        _errand("click", ref="e7", page={"target": {"name": "Add to cart", "words": "Delete"}}),
        _errand("click", ref="e7", page={"target": {"name": "Add to cart", "words": 7}}),
        # Consent and assent on a tick.
        *[
            _errand("check", ref="e7", page={"target": {"name": name}})
            for name in (
                "I agree to the Terms of Service", "Subscribe to our newsletter",
                "I have read and understood the Terms and Conditions",
                "I consent to the processing of my personal data",
                "I acknowledge the non-refundable cancellation policy",
                "Keep me subscribed to marketing emails", "Opt in to offers", "I confirm I am over 18",
            )
        ],
        # Agreeing outside a region about cookies, or more than agreeing in one.
        _errand("click", ref="e7", page={"target": {"name": "Agree and close"}}),
        _errand("click", ref="e7", page={"target": {"name": "Agree and close", "consent": "yes"}}),
        _errand("click", ref="e7", page={"target": {"name": "Accept and subscribe", "consent": True}}),
        _errand("click", ref="e7", page={"target": {"name": "Allow | Allow Acme to read your mail",
                                                     "consent": True}}),
        # A one-click link does these by GET alone.
        *[
            _errand("click", ref="e7", page={"target": {"name": name, "plain_link": True}})
            for name in (
                "Unsubscribe", "Sign out", "Delete this listing", "Confirm my email", "Cancel my order",
                "Decline", "Leave group", "Accept", "Accept invitation", "Remove", "Cancel membership",
                "Finish Cancellation", "Authorize", "Grant access", "Connect", "Add friend", "Opt out",
                "End membership", "Enroll", "Install", "Activate account", "Disable alerts", "Retweet",
                "Upvote", "Disconnect", "Reactivate account", "Uninstall",
            )
        ],
        # A link worded like a purchase: a page's script can make it place
        # the order (a single-page app's delegated click handler).
        *[
            _errand("click", ref="e7", page={"target": {"name": name, "plain_link": True}})
            for name in ("Place order", "Buy now", "Book now", "Reserve a table", "Pay now")
        ],
        _errand("click", ref="e7", page={"target": {"name": "7:15 PM", "words": "Buy now", "plain_link": True}}),
        # No words to judge, or words of the wrong shape.
        _errand("click", ref="e7", page={"target": {"name": ""}}),
        _errand("click", ref="e7", page={"target": {"name": "  "}}),
        _errand("click", ref="e7", page={"target": {"name": 7}}),
        _errand("click", ref="e7", page={"target": "Add to Cart"}),
        _errand("click", ref="e7", page={"target": None}),
        _errand("click", ref="e7", page={"target": {"name": "x" * 201}}),
        _errand("submit", ref="e2", page={"target": None}),
        _errand("press", key="Enter", page={"target": None}),
        # A field the toolkit did not class as an errand field, or a count that differs.
        _errand("fill", ref="e2", text="Ada", page={"fields": [""]}),
        _errand("fill", ref="e2", text="Ada", page={"fields": ["name"]}),
        _errand("fill", ref="e2", text="Ada", page={"fields": []}),
        _errand("fill", ref="e2", text="Ada", page={"fields": "search"}),
        _errand("fill", ref="e2", text="Ada", page={"fields": None}),
        _errand("fill_form", fields=[{"ref": "e2", "text": "x"}, {"ref": "e3", "text": "y"}],
                page={"fields": ["search"]}),
        # Shapes no errand step has.
        _errand("click"),
        _errand("fill_form", fields=[]),
        _errand("press", key="Space"),
        {"action": "click", "ref": "e7"},  # unbound
        {"action": "click", "ref": "e7", "_page": "junk"},
        None,
    ],
)
def test_an_errand_never_covers_an_outcome_or_anything_the_toolkit_did_not_judge(arguments):
    assert not errand_covers(arguments)


@pytest.mark.parametrize(
    ("arguments", "may_run"),
    [
        ({"action": "click", "ref": "e7"}, True),
        ({"action": "select", "ref": "e7", "value": "2"}, True),
        ({"action": "check", "ref": "e7"}, True),
        ({"action": "fill", "ref": "e7", "text": "x"}, True),
        ({"action": "fill_form", "fields": [{"ref": "e7", "text": "x"}]}, True),
        ({"action": "submit", "ref": "e7"}, True),
        ({"action": "press", "key": "Enter"}, True),
        ({"action": "press", "key": "Tab"}, True),
        ({"action": "press", "key": "Space"}, False),
        ({"action": "fill_form", "fields": []}, False),
        ({"action": "fill"}, False),
        ({"action": "click"}, False),
        ("junk", False),
    ],
)
def test_may_run_errand_accepts_every_shape_errand_covers_can(arguments, may_run):
    assert may_run_errand(arguments) is may_run


@pytest.mark.parametrize(
    ("words", "cart"),
    [
        ("Add to Cart | Add to Shopping Cart", True),
        ("Add to bag", True),
        ("Update cart", True),
        ("Proceed to checkout", True),
        ("Increase quantity", True),
        ("Decrease the quantity of Chain lube", True),
        ("Increase", True),  # a quantity stepper's whole name
        ("+", True),
        ("Qty", True),
        ("Increase credit limit", False),
        ("Increase my monthly donation", False),
        ("Increase seats", False),
        ("Decrease font size", False),
        ("Continue", False),
        ("", False),
    ],
)
def test_only_cart_words_and_a_quantity_steppers_own_name_are_cart_words(words, cart):
    from services.agent.app_approvals import cart_words

    assert cart_words(words) is cart


def test_a_step_run_without_asking_is_marked_unasked_on_its_page_and_nothing_else_changes():
    from services.agent.app_approvals import UNASKED_MARK, unasked_arguments

    bound = _errand("click", ref="e7")
    marked = unasked_arguments(bound)
    assert marked["_page"][UNASKED_MARK] is True
    assert {**marked["_page"], UNASKED_MARK: None} == {**bound["_page"], UNASKED_MARK: None}
    assert UNASKED_MARK not in bound["_page"]  # the card's own copy is left as it was
    assert errand_covers(marked)
