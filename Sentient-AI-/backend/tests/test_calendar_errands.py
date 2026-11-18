"""Tests for the calendar finder (services/errands/): the Mac Calendar app's
osascript output is parsed safely, Google Calendar is paged, only the owner's
own notes are read, a word check and one model call per new or changed note
find what to buy, and each note becomes one planned errand with one message,
planned again when edited and cancelled when deleted; the errand sweeper then
starts it once on its day.

Why it exists: the owner's goal is "Crawler checks my calendar every day, sees
'order this perfume for my girlfriend' and orders it in one approval". Reading
someone's calendar and spending model calls on it daily must cost nothing for
notes already read, never act on other people's events, never cancel an
errand because a read failed, and tell the owner exactly once per plan. The
real ErrandService runs on the test database; the calendar, the model and the
errand runner are stubs (nothing runs osascript or calls a model).

Connects to: services/errands/calendar.py, services/errands/finder.py,
services/automation/errands.py, services/capabilities/calendar_errands.py.
"""

from __future__ import annotations

import asyncio
import json
from datetime import date, datetime, timedelta, timezone
from typing import Any

import pytest
import pytest_asyncio

from models.errand import Errand
from models.user import User
from services import capabilities
from services.agent.runtime import OnceResult
from services.automation.errands import ErrandService
from services.automation.runner import UnattendedOutcome
from services.errands.calendar import (
    RS,
    TRAILER,
    US,
    CalendarEvent,
    SourceRead,
    google_event,
    parse_mac_output,
    read_google_calendar,
)
from services.errands.finder import (
    STARTUP_DELAY,
    CalendarErrandFinder,
    is_candidate,
    planned_notice,
    read_answer,
)
from services.scheduler.briefing import Account
from tests.conftest import make_user

NOW = datetime(2026, 11, 13, 17, 0, tzinfo=timezone.utc)
TODAY = date(2026, 11, 13)
DAY = date(2026, 12, 20)
TITLE = "Order perfume for Anna"
LINK = "https://perfume.example.com/chanel-no-5"
NOTE = f"Chanel No 5 Eau de Parfum 50 ml, her favourite \U0001f381\n{LINK}"
ITEM = "Chanel No 5 Eau de Parfum 50 ml"
ANSWER = json.dumps(
    {
        "is_errand": True,
        "item": ITEM,
        "link": LINK,
        "needed_by": "",
        "for_whom": "Anna",
        "quantity": 1,
        "notes": "",
    }
)
NO = json.dumps({"is_errand": False, "item": "", "link": "", "needed_by": ""})


def _event(**overrides: Any) -> CalendarEvent:
    fields: dict[str, Any] = {
        "ref": "evt-1",
        "title": TITLE,
        "notes": NOTE,
        "url": "",
        "day": DAY,
        "shared": False,
        "updated": datetime(2026, 11, 1, 9, 0, tzinfo=timezone.utc),
    }
    fields.update(overrides)
    return CalendarEvent(**fields)


def _record(*fields: str) -> str:
    return US.join(fields) + RS


# ── the Mac's Calendar app ─────────────────────────────────────────────────────


def test_the_mac_calendar_output_is_parsed_with_separators_newlines_and_emoji_in_notes():
    # The script turns RS and US inside a field into spaces, so a note that
    # had them reads with spaces and never splits a record.
    note = "Chanel No 5 x y\nsecond line \U0001f381 https://shop.example.com/p?a=1"
    output = (
        _record("uid-1", "Gift \U0001f381 for Anna", "2026-12-20 9:5:7", note, "", "1", "0",
                "2026-11-1 8:0:0", "")
        + _record("uid-2", "Team sync", "2026-12-21 0:0:0", "", "https://meet.example.com", "1",
                  "3", "", "")
        + _record(TRAILER, "0")
        + "\n"
    )
    read = parse_mac_output(output, TODAY)
    assert read.status == "ok" and read.complete
    first, second = read.events
    assert (first.ref, first.title, first.notes, first.day) == (
        "uid-1", "Gift \U0001f381 for Anna", note, date(2026, 12, 20)
    )
    assert first.updated == datetime(2026, 11, 1, 8, 0).astimezone()
    assert not first.shared
    assert second.shared and second.updated is None and second.url == "https://meet.example.com"


def test_a_cut_short_or_partial_mac_read_is_never_complete():
    good = _record("uid-1", TITLE, "2026-12-20 9:0:0", NOTE, "", "1", "0", "", "")
    assert not parse_mac_output(good).complete  # no trailer: cut short
    assert not parse_mac_output(good + _record(TRAILER, "1")).complete  # the script said so
    broken = _record("uid-2", "only three", "fields")
    read = parse_mac_output(good + broken + _record(TRAILER, "0"))
    assert not read.complete and [e.ref for e in read.events] == ["uid-1"]


def test_events_with_other_people_or_on_calendars_the_owner_cannot_write_to_are_shared():
    def one(writable: str, guests: str) -> CalendarEvent:
        output = _record("u", TITLE, "2026-12-20 9:0:0", NOTE, "", writable, guests, "", "")
        return parse_mac_output(output + _record(TRAILER, "0")).events[0]

    assert not one("1", "0").shared
    assert one("0", "0").shared  # a subscription, holidays, birthdays
    assert one("1", "2").shared  # other people are on it
    assert one("1", "?").shared  # it could not be told


# ── Google Calendar ────────────────────────────────────────────────────────────


class FakeReader:
    def __init__(self, *pages: list[dict[str, Any]]) -> None:
        self.pages = list(pages)
        self.calls: list[tuple[str, dict[str, Any]]] = []

    async def read(self, user_id, name, arguments, run_id):
        self.calls.append((name, dict(arguments)))
        return {"ok": True, "result": self.pages.pop(0)}, None


def _google(n: int, **extra: Any) -> dict[str, Any]:
    start = datetime(2026, 11, 20, tzinfo=timezone.utc) + timedelta(hours=n)
    return {"id": f"g{n}", "summary": f"Event {n}", "start": {"dateTime": start.isoformat()},
            "creator_self": True, **extra}


@pytest.mark.asyncio
async def test_google_events_are_paged_and_only_the_owners_own_events_are_not_shared():
    first = [_google(n) for n in range(50)]
    second = [
        _google(49),
        _google(50, organizer="unknownorganizer@calendar.google.com"),
        _google(51, attendees=[{"email": "sam@example.com"}]),
        _google(52, status="cancelled"),
        # Someone else's event on the owner's calendar: they did not make
        # it, even when the owner's calendar makes them its organizer (a
        # delegate writing on it).
        _google(53, creator_self=False),
        _google(54, creator_self=False, organizer_self=True, iCalUID="abc-uid"),
    ]
    reader = FakeReader(first, second)
    accounts = [Account("google_workspace", "c1", "")]
    read = await read_google_calendar(reader, "u1", accounts, NOW, NOW + timedelta(days=180))
    assert read.status == "ok" and read.complete
    assert len(read.events) == 54 and {e.source for e in read.events} == {"google"}
    assert reader.calls[1][0] == "google_workspace.get_events"
    assert reader.calls[1][1]["time_min"] == first[-1]["start"]["dateTime"]
    shared = {e.ref for e in read.events if e.shared}
    assert shared == {"g50@google.com", "g51@google.com", "g53@google.com", "abc-uid"}
    # The iCalendar uid names the event when Google gives one.
    assert "abc-uid" in {e.ref for e in read.events}
    assert google_event({"id": "x", "start": {"date": "2026-12-20"}}).day == DAY
    nothing = await read_google_calendar(reader, "u1", [], NOW, NOW)
    assert nothing.status == "unavailable"


# ── finding what a note asks for ───────────────────────────────────────────────


def test_the_word_check_picks_buying_notes_in_any_case_and_skips_the_rest():
    for title in ("ORDER perfume", "buy flowers", "Gift for mom", "pick up a cake",
                  "Renew passport", "refill meds", "Get Anna a present", "Purchase tickets"):
        assert is_candidate(_event(title=title, notes="")), title
    for title in ("Team presentation", "Dentist", "Forget it", "Reorganize desk"):
        assert not is_candidate(_event(title=title, notes="")), title
    assert is_candidate(_event(title="Anna's birthday", notes="buy the perfume"))


def test_a_valid_answer_becomes_what_to_buy_with_the_event_day_as_its_date():
    verdict, found = read_answer(ANSWER, _event(), TODAY)
    assert verdict == "errand" and found is not None
    assert (found.item, found.link, found.needed_by, found.for_whom) == (ITEM, LINK, DAY, "Anna")
    assert (found.short_item, found.details) == (ITEM, "for Anna")
    fenced = f"```json\n{ANSWER}\n```"
    assert read_answer(fenced, _event(), TODAY)[0] == "errand"
    assert read_answer(NO, _event(), TODAY) == ("no", None)


def test_a_link_that_is_not_in_the_note_is_dropped():
    invented = json.loads(ANSWER) | {"link": "https://evil.example.net/buy"}
    _verdict, found = read_answer(json.dumps(invented), _event(), TODAY)
    assert found is not None and found.link is None
    _verdict, kept = read_answer(json.dumps(invented), _event(url="https://evil.example.net/buy"),
                                 TODAY)
    assert kept is not None and kept.link == "https://evil.example.net/buy"


def test_anything_but_the_strict_answer_is_unreadable():
    base = json.loads(ANSWER)
    for bad in (
        "not json at all",
        "{broken",
        json.dumps([base]),
        json.dumps(base | {"is_errand": "yes"}),
        json.dumps(base | {"item": ""}),
        json.dumps(base | {"item": 42}),
        json.dumps(base | {"quantity": 0}),
        json.dumps(base | {"quantity": True}),
        json.dumps(base | {"quantity": "2"}),
        json.dumps(base | {"needed_by": 20261220}),
    ):
        assert read_answer(bad, _event(), TODAY) == ("unreadable", None), bad


def test_a_date_in_the_past_or_far_ahead_falls_back_to_the_event_day():
    base = json.loads(ANSWER)
    for needed in ("2020-01-01", "2030-01-01", "next friday"):
        found = read_answer(json.dumps(base | {"needed_by": needed}), _event(), TODAY)[1]
        assert found is not None and found.needed_by == DAY, needed
    found = read_answer(json.dumps(base | {"needed_by": "2026-12-01", "quantity": 2}), _event(),
                        TODAY)[1]
    assert found is not None and found.needed_by == date(2026, 12, 1)
    assert found.short_item == f"2 x {ITEM}"


def test_the_planned_notice_says_what_when_and_by_when_in_plain_words():
    text = planned_notice(ITEM, TITLE, date(2026, 12, 13), DAY, TODAY)
    assert text == (
        f"From your calendar: I'll order {ITEM} on Sunday, December 13 so it arrives by "
        f"Sunday, December 20 ({TITLE}). I'll only ask you once, to approve the payment. "
        "Send /errands to see or cancel it."
    )
    soon = planned_notice(ITEM, TITLE, TODAY, date(2027, 1, 2), TODAY)
    assert "I'll order" in soon and " today so it arrives by Saturday, January 2, 2027" in soon
    assert "—" not in text + soon and "–" not in text + soon


# ── planning: the finder on the test database ──────────────────────────────────


class StubRuntime:
    """The runtime's one-shot call: answers in order, records each call."""

    def __init__(self, *answers: str, input_tokens: int = 500) -> None:
        self.answers = list(answers)
        self.calls: list[dict[str, Any]] = []
        self.input_tokens = input_tokens

    def untrusted_data_message(self, name, data, closing):
        return {"role": "user", "content": json.dumps({"name": name, "data": data})}

    async def complete_once(self, messages, *, llm_provider, llm_model, system):
        self.calls.append({"messages": messages, "system": system})
        return OnceResult(
            text=self.answers.pop(0) if self.answers else NO,
            usage={"input_tokens": self.input_tokens, "output_tokens": 60},
            provider="gemini",
            model="gemini-2.5-flash",
        )


class Calendar:
    """The Mac source: the events it holds now, read whole unless told."""

    def __init__(self, *events: CalendarEvent) -> None:
        self.events = list(events)
        self.status = "ok"
        self.complete = True
        self.reads = 0

    async def __call__(self, back_days: int, ahead_days: int) -> SourceRead:
        self.reads += 1
        if self.status != "ok":
            return SourceRead(self.status)
        return SourceRead("ok", tuple(self.events), self.complete)


class Rig:
    def __init__(self, session_factory, owner_id: str, calendar: Calendar, runtime: StubRuntime,
                 *, runner: Any = None, cap_cents: int = 10) -> None:
        self.session_factory, self.owner_id = session_factory, owner_id
        self.calendar, self.runtime = calendar, runtime
        self.sent: list[str] = []
        self.now = NOW

        async def send(_user_id, text):
            self.sent.append(text)
            return True

        async def keys():
            return frozenset({"errand_runs", "calendar_errands"})

        async def no_settings():
            return {}

        async def settings():
            return {"day_cap_cents": cap_cents}

        self.errands = ErrandService(
            session_factory, runner=runner, send=send, enabled_keys=keys, settings=no_settings,
            clock=lambda: self.now,
        )
        self.finder = CalendarErrandFinder(
            session_factory, errands=self.errands, runtime=lambda: self.runtime, send=send,
            settings=settings, mac=calendar, clock=lambda: self.now,
        )

    async def rows(self) -> list[Errand]:
        from sqlalchemy import select

        async with self.session_factory() as session:
            return list((await session.execute(select(Errand))).scalars())


@pytest_asyncio.fixture
async def owner(session_factory):
    user, _ = await make_user(session_factory, "owner@example.com")
    async with session_factory() as session:
        row = await session.get(User, user.id)
        row.is_admin = True
        await session.commit()
    return str(user.id)


@pytest.mark.asyncio
async def test_a_calendar_note_becomes_one_planned_errand_and_one_message(session_factory, owner):
    rig = Rig(session_factory, owner, Calendar(_event()), StubRuntime(ANSWER))
    assert await rig.finder.scan_once() == 1
    [row] = await rig.rows()
    assert (row.source, row.source_ref, row.title, row.item, row.details, row.link) == (
        "calendar", "evt-1", TITLE, ITEM, "for Anna", LINK
    )
    assert row.event_day == DAY
    # Seven lead days before the day, so it arrives in time.
    assert (row.needed_by, row.run_on, row.status) == (DAY, date(2026, 12, 13), "planned")
    assert rig.sent == [planned_notice(ITEM, TITLE, date(2026, 12, 13), DAY, TODAY)]
    # The note reached the model only as data, with the strict-JSON prompt.
    [call] = rig.runtime.calls
    assert '"notes":' in call["messages"][0]["content"] and "JSON object" in call["system"]


@pytest.mark.asyncio
async def test_an_unchanged_note_is_not_read_again_even_after_a_restart(session_factory, owner):
    calendar = Calendar(_event(), _event(ref="evt-2", title="Buy milk", notes=""))
    rig = Rig(session_factory, owner, calendar, StubRuntime(ANSWER, NO))
    await rig.finder.scan_once()
    assert len(rig.runtime.calls) == 2
    await rig.finder.scan_once()
    assert len(rig.runtime.calls) == 2 and len(rig.sent) == 1
    # A new process: the errand's own change time says the note is as it was.
    restarted = Rig(session_factory, owner, calendar, StubRuntime(NO))
    await restarted.finder.scan_once()
    [call] = restarted.runtime.calls
    assert "Buy milk" in call["messages"][0]["content"]
    assert restarted.sent == [] and len(await rig.rows()) == 1


@pytest.mark.asyncio
async def test_an_edited_note_plans_the_errand_again_and_says_so(session_factory, owner):
    calendar = Calendar(_event())
    edited = json.loads(ANSWER) | {"item": "Chanel No 5, 100 ml", "needed_by": "2026-12-10"}
    rig = Rig(session_factory, owner, calendar, StubRuntime(ANSWER, json.dumps(edited)))
    await rig.finder.scan_once()
    calendar.events = [_event(notes="Chanel No 5, 100 ml, by Dec 10",
                              updated=datetime(2026, 11, 12, tzinfo=timezone.utc))]
    assert await rig.finder.scan_once() == 1
    [row] = await rig.rows()
    assert (row.item, row.details, row.needed_by, row.run_on) == (
        "Chanel No 5, 100 ml", "for Anna", date(2026, 12, 10), date(2026, 12, 3)
    )
    assert len(rig.sent) == 2 and "Chanel No 5, 100 ml on Thursday, December 3" in rig.sent[1]


@pytest.mark.asyncio
async def test_a_deleted_note_cancels_its_planned_errand_but_a_failed_read_cancels_nothing(
    session_factory, owner
):
    calendar = Calendar(_event())
    rig = Rig(session_factory, owner, calendar, StubRuntime(ANSWER))
    await rig.finder.scan_once()
    calendar.events = []
    for status, complete in (("failed", True), ("denied", True), ("ok", False)):
        calendar.status, calendar.complete = status, complete
        await rig.finder.scan_once()
        assert [r.status for r in await rig.rows()] == ["planned"], status
    calendar.status, calendar.complete = "ok", True
    await rig.finder.scan_once()
    assert [r.status for r in await rig.rows()] == ["cancelled"]
    assert rig.sent[-1] == (
        f'From your calendar: your note "{TITLE}" was removed or no longer asks me to buy '
        f"anything, so I won't order {ITEM}."
    )


@pytest.mark.asyncio
async def test_a_note_that_no_longer_asks_to_buy_anything_cancels_its_errand(
    session_factory, owner
):
    calendar = Calendar(_event())
    rig = Rig(session_factory, owner, calendar, StubRuntime(ANSWER, NO))
    await rig.finder.scan_once()
    later = datetime(2026, 11, 12, tzinfo=timezone.utc)
    calendar.events = [_event(notes="Anna said she has it already, order nothing", updated=later)]
    await rig.finder.scan_once()
    assert [r.status for r in await rig.rows()] == ["cancelled"]


@pytest.mark.asyncio
async def test_notes_shared_with_others_on_past_days_or_without_buying_words_are_never_read(
    session_factory, owner
):
    calendar = Calendar(
        _event(ref="shared", shared=True),
        _event(ref="past", day=TODAY - timedelta(days=2)),
        _event(ref="plain", title="Dentist", notes="bring the card"),
    )
    rig = Rig(session_factory, owner, calendar, StubRuntime(ANSWER))
    assert await rig.finder.scan_once() == 0
    assert rig.runtime.calls == [] and await rig.rows() == [] and rig.sent == []


@pytest.mark.asyncio
async def test_a_note_due_within_the_lead_days_is_ordered_today(session_factory, owner):
    soon = TODAY + timedelta(days=3)
    rig = Rig(session_factory, owner, Calendar(_event(day=soon)), StubRuntime(ANSWER))
    await rig.finder.scan_once()
    [row] = await rig.rows()
    assert row.run_on == TODAY and row.needed_by == soon
    assert f"I'll order {ITEM} today so it arrives by Monday, November 16" in rig.sent[0]


@pytest.mark.asyncio
async def test_the_same_note_from_both_calendars_is_one_errand(session_factory, owner):
    calendar = Calendar(_event(), _event(ref="g1@google.com", updated=None))
    rig = Rig(session_factory, owner, calendar, StubRuntime(ANSWER, ANSWER))
    await rig.finder.scan_once()
    assert len(rig.runtime.calls) == 1 and len(await rig.rows()) == 1
    # Another day only the Google copy is read: still one errand.
    calendar.events = [_event(ref="g1@google.com", updated=None)]
    await rig.finder.scan_once()
    assert len(await rig.rows()) == 1 and len(rig.sent) == 1


@pytest.mark.asyncio
async def test_the_daily_budget_stops_model_calls_until_tomorrow(session_factory, owner):
    calendar = Calendar(_event(), _event(ref="evt-2", title="Buy flowers", notes=""))
    rig = Rig(session_factory, owner, calendar, StubRuntime(input_tokens=1_000_000), cap_cents=10)
    await rig.finder.scan_once()
    assert len(rig.runtime.calls) == 1  # 30 cents spent: the second waits
    await rig.finder.scan_once()
    assert len(rig.runtime.calls) == 1
    rig.now = NOW + timedelta(days=1)
    await rig.finder.scan_once()
    assert len(rig.runtime.calls) == 2


@pytest.mark.asyncio
async def test_the_owner_is_told_once_when_the_calendar_app_is_not_allowed(
    session_factory, owner
):
    calendar = Calendar()
    calendar.status = "denied"
    rig = Rig(session_factory, owner, calendar, StubRuntime())
    await rig.finder.scan_once()
    await rig.finder.scan_once()
    [told] = rig.sent
    assert "Privacy & Security, then Automation" in told and "Calendar" in told


@pytest.mark.asyncio
async def test_the_scan_waits_a_few_minutes_after_startup_then_runs_once_a_day(
    session_factory, owner
):
    calendar = Calendar()
    rig = Rig(session_factory, owner, calendar, StubRuntime())
    assert await rig.finder._tick() == 0 and calendar.reads == 0
    rig.now = NOW + STARTUP_DELAY
    await rig.finder._tick()
    rig.now += timedelta(hours=2)
    await rig.finder._tick()
    assert calendar.reads == 1
    rig.now += timedelta(days=1)
    await rig.finder._tick()
    assert calendar.reads == 2


class HeldRunner:
    def __init__(self) -> None:
        self.requests: list[Any] = []
        self.gate = asyncio.Event()

    async def run(self, request):
        self.requests.append(request)
        await self.gate.wait()
        return UnattendedOutcome(status="ok")


@pytest.mark.asyncio
async def test_the_errand_sweeper_starts_a_calendar_errand_once_on_its_day(
    session_factory, owner
):
    runner = HeldRunner()
    rig = Rig(session_factory, owner, Calendar(_event()), StubRuntime(ANSWER), runner=runner)
    await rig.finder.scan_once()
    assert await rig.errands.sweep_once() == 0  # not its day yet
    rig.now = datetime(2026, 12, 13, 17, 0, tzinfo=timezone.utc)
    assert await rig.errands.sweep_once() == 1
    assert await rig.errands.sweep_once() == 0
    runner.gate.set()
    await rig.errands.wait_idle()
    [request] = runner.requests
    [row] = await rig.rows()
    assert request.origin == f"errand:{row.id}" and request.writes == ("browser.checkout",)
    assert ITEM in request.prompt and LINK in request.prompt


def test_the_switch_is_off_by_default_and_needs_background_errands():
    cap = capabilities.get("calendar_errands")
    assert cap.default_enabled is False and cap.tools == ()
    assert cap.requires == ("errand_runs",)
    assert capabilities.settings_defaults("calendar_errands") == {"day_cap_cents": 10}
    for text in (cap.label, cap.description, cap.when_denied):
        assert "—" not in text and "–" not in text


@pytest.mark.asyncio
async def test_the_app_wires_the_finder_and_it_reads_nothing_while_its_switch_is_off(
    session_factory, monkeypatch
):
    from core.config import settings
    from main import app, wire_services
    from tests.test_telegram_manager import FakeService

    monkeypatch.setattr(settings, "TELEGRAM_BOT_TOKEN", "", raising=False)
    saved = dict(app.state._state)
    await wire_services(app, session_factory, telegram_service_factory=FakeService)
    try:
        finder = app.state.calendar_errands
        assert isinstance(finder, CalendarErrandFinder)
        calendar = Calendar(_event())
        finder._mac, finder._born = calendar, NOW - timedelta(days=1)
        assert await finder._loop.run_once() == 0 and calendar.reads == 0
    finally:
        await app.state.telegram_manager.stop()
        await app.state.slack_manager.stop()
        app.state._state.clear()
        app.state._state.update(saved)


@pytest.mark.asyncio
async def test_the_calendar_app_is_read_in_one_osascript_call_and_a_refusal_reads_as_denied(
    tmp_path, monkeypatch
):
    import sys

    from services.errands import calendar as source

    body = tmp_path / "fake_osascript.py"
    body.write_text(
        "import os, sys, time\n"
        "mode = os.environ['FAKE_OSASCRIPT']\n"
        "if mode == 'ok':\n"
        "    assert sys.argv[1] == '-e' and sys.argv[3:] == ['30', '180'], sys.argv\n"
        f"    sys.stdout.write({_record('u1', TITLE, '2026-12-20 9:0:0', NOTE, '', '1', '0', '', '')!r}"
        f" + {_record(TRAILER, '0')!r} + '\\n')\n"
        "elif mode == 'denied':\n"
        "    sys.stderr.write('Not authorized to send Apple events to Calendar. (-1743)')\n"
        "    sys.exit(1)\n"
        "else:\n"
        "    time.sleep(30)\n"
    )
    # A shell wrapper: a shebang cannot hold a path with spaces in it.
    fake = tmp_path / "osascript"
    fake.write_text(f'#!/bin/sh\nexec "{sys.executable}" "{body}" "$@"\n')
    fake.chmod(0o755)
    monkeypatch.setattr(source, "OSASCRIPT", str(fake))
    monkeypatch.setattr(source.sys, "platform", "darwin")
    monkeypatch.setenv("FAKE_OSASCRIPT", "ok")
    read = await source.read_mac_calendar(30, 180)
    assert read.status == "ok" and read.complete and [e.ref for e in read.events] == ["u1"]
    monkeypatch.setenv("FAKE_OSASCRIPT", "denied")
    assert (await source.read_mac_calendar(30, 180)).status == "denied"
    monkeypatch.setenv("FAKE_OSASCRIPT", "slow")
    monkeypatch.setattr(source, "OSASCRIPT_TIMEOUT_S", 1.0)
    assert (await source.read_mac_calendar(30, 180)).status == "failed"
    monkeypatch.setattr(source.sys, "platform", "linux")
    assert (await source.read_mac_calendar(30, 180)).status == "unavailable"


# ── review fixes ──────────────────────────────────────────────────────────────


async def _set(rig: Rig, **values: Any) -> None:
    from sqlalchemy import update

    async with rig.session_factory() as session:
        await session.execute(update(Errand).values(**values))
        await session.commit()


class GoogleReader:
    """A connected Google calendar that always answers *items* (or fails)."""

    def __init__(self, items: list[dict[str, Any]] | None) -> None:
        self.items = items

    async def read(self, user_id, name, arguments, run_id):
        if self.items is None:
            return None, "couldn't read it"
        return {"ok": True, "result": list(self.items)}, None


def _with_google(rig: Rig, reader: GoogleReader) -> None:
    rig.finder._reader = reader

    async def accounts(_uid):
        return [Account("google_workspace", "c1", "")]

    rig.finder._accounts = accounts


def _own_google(**fields: Any) -> dict[str, Any]:
    return {"summary": TITLE, "description": NOTE, "start": {"date": DAY.isoformat()},
            "creator_self": True, **fields}


@pytest.mark.asyncio
async def test_an_errand_needed_long_after_its_note_is_kept_once_the_note_leaves_the_window(
    session_factory, owner
):
    far = (TODAY + timedelta(days=80)).isoformat()
    calendar = Calendar(_event(day=TODAY))
    rig = Rig(session_factory, owner, calendar, StubRuntime(json.dumps(json.loads(ANSWER)
                                                                      | {"needed_by": far})))
    await rig.finder.scan_once()
    # A month on, the calendar no longer lists the note's day (30 days back).
    rig.now = NOW + timedelta(days=31)
    calendar.events = []
    await rig.finder.scan_once()
    [row] = await rig.rows()
    assert row.status == "planned" and row.event_day == TODAY and len(rig.sent) == 1


@pytest.mark.asyncio
async def test_a_source_that_never_listed_a_note_does_not_keep_its_deletion_from_counting(
    session_factory, owner
):
    calendar = Calendar(_event())
    rig = Rig(session_factory, owner, calendar, StubRuntime(ANSWER))
    _with_google(rig, GoogleReader(None))  # connected, but its read fails
    await rig.finder.scan_once()
    calendar.events = []
    await rig.finder.scan_once()
    assert [r.status for r in await rig.rows()] == ["cancelled"]


@pytest.mark.asyncio
async def test_a_deleted_note_is_not_kept_by_a_shared_or_past_event_with_its_title(
    session_factory, owner
):
    calendar = Calendar(_event())
    rig = Rig(session_factory, owner, calendar, StubRuntime(ANSWER))
    await rig.finder.scan_once()
    calendar.events = [
        _event(ref="old", day=TODAY - timedelta(days=20)),
        _event(ref="invite", shared=True),
    ]
    await rig.finder.scan_once()
    assert [r.status for r in await rig.rows()] == ["cancelled"]


@pytest.mark.asyncio
async def test_a_failed_or_possibly_bought_errand_is_never_planned_again_from_the_calendar(
    session_factory, owner
):
    from services.automation import errands

    calendar = Calendar(_event())
    rig = Rig(session_factory, owner, calendar, StubRuntime(ANSWER))
    await rig.finder.scan_once()
    for status in ("unsure", "failed"):
        await _set(rig, status=status, attempts=1,
                   last_message=errands._UNSURE.format(title=TITLE, site="x"))
        # A new process, a newer change time and new words.
        edited = json.loads(ANSWER) | {"item": "Chanel No 5, 100 ml"}
        calendar.events = [_event(notes="100 ml now", updated=datetime(2026, 11, 12, 1,
                                                                       tzinfo=timezone.utc))]
        restarted = Rig(session_factory, owner, calendar, StubRuntime(json.dumps(edited)))
        await restarted.finder.scan_once()
        [row] = await rig.rows()
        assert (row.status, row.attempts, row.item) == (status, 1, ITEM), status
        assert restarted.sent == [] and restarted.runtime.calls == []


@pytest.mark.asyncio
async def test_a_copy_with_no_change_time_never_plans_an_errand_again_with_the_same_words(
    session_factory, owner
):
    calendar = Calendar(_event(ref="g1@google.com", url=LINK))
    rig = Rig(session_factory, owner, calendar, StubRuntime(ANSWER, ANSWER))
    _with_google(rig, GoogleReader([_own_google(id="g1")]))
    await rig.finder.scan_once()
    [row] = await rig.rows()
    stamp = row.source_updated
    await _set(rig, attempts=2)
    # The Mac read fails one day: the Google copy (no change time, another
    # fingerprint) is read, and the same words leave the errand as it was.
    rig.now += timedelta(days=1)
    calendar.status = "failed"
    await rig.finder.scan_once()
    [row] = await rig.rows()
    assert (row.status, row.attempts, row.source_updated) == ("planned", 2, stamp)
    assert len(rig.sent) == 1


@pytest.mark.asyncio
async def test_a_note_moved_on_one_calendar_while_the_other_copy_lags_stays_one_errand(
    session_factory, owner
):
    calendar = Calendar(_event(ref="4F3C-UID"))
    reader = GoogleReader([_own_google(id="abc", iCalUID="4F3C-UID")])
    edited = json.loads(ANSWER) | {"needed_by": "2026-12-10"}
    rig = Rig(session_factory, owner, calendar,
              StubRuntime(ANSWER, json.dumps(edited), json.dumps(edited)))
    _with_google(rig, reader)
    await rig.finder.scan_once()
    # Moved to Dec 10 on the phone: Google has it, the Mac has not synced.
    reader.items = [_own_google(id="abc", iCalUID="4F3C-UID", start={"date": "2026-12-10"})]
    rig.now += timedelta(days=1)
    await rig.finder.scan_once()
    # Then the Mac copy syncs too.
    calendar.events = [_event(ref="4F3C-UID", day=date(2026, 12, 10),
                              updated=datetime(2026, 11, 14, tzinfo=timezone.utc))]
    rig.now += timedelta(days=1)
    await rig.finder.scan_once()
    [row] = await rig.rows()
    assert (row.status, row.needed_by, row.run_on) == ("planned", date(2026, 12, 10),
                                                       date(2026, 12, 3))


@pytest.mark.asyncio
async def test_two_notes_on_different_days_for_the_same_item_are_two_errands_and_two_messages(
    session_factory, owner
):
    mom = _event(ref="evt-mom", title="Order gift card for Mom", day=DAY - timedelta(days=15),
                 notes="Amazon gift card $50")
    anna = _event(ref="evt-anna", title="Order gift card for Anna", day=DAY,
                  notes="Amazon gift card $50")
    answer = json.dumps(json.loads(ANSWER) | {"item": "Amazon gift card $50", "link": ""})
    rig = Rig(session_factory, owner, Calendar(mom, anna), StubRuntime(answer, answer))

    assert await rig.finder.scan_once() == 2

    rows = await rig.rows()
    assert sorted((r.source_ref, r.needed_by) for r in rows) == [
        ("evt-anna", DAY), ("evt-mom", DAY - timedelta(days=15))
    ]
    assert len(rig.sent) == 2


@pytest.mark.asyncio
async def test_a_google_only_note_edited_while_crawler_was_down_is_read_again(
    session_factory, owner
):
    bigger = "Chanel No 5 Eau de Parfum 100 ml"
    runtime = StubRuntime(ANSWER, json.dumps(json.loads(ANSWER) | {"item": bigger}))
    rig = Rig(session_factory, owner, Calendar(), runtime)
    reader = GoogleReader([_own_google(id="g1", iCalUID="g1@google.com")])
    _with_google(rig, reader)
    await rig.finder.scan_once()
    # A new process; the owner changed the note meanwhile.
    restarted = Rig(session_factory, owner, Calendar(), runtime)
    _with_google(restarted, reader)
    reader.items = [_own_google(id="g1", iCalUID="g1@google.com",
                                description=f"{bigger}, her favourite\n{LINK}")]
    await restarted.finder.scan_once()
    [row] = await rig.rows()
    assert row.item == bigger and len(runtime.calls) == 2
    # Unchanged after yet another restart: not read again.
    again = Rig(session_factory, owner, Calendar(), runtime)
    _with_google(again, reader)
    await again.finder.scan_once()
    assert len(runtime.calls) == 2


@pytest.mark.asyncio
async def test_an_errand_planned_before_its_day_was_kept_gets_it_and_is_cancelled_when_deleted(
    session_factory, owner
):
    event = _event()
    calendar = Calendar(event)
    rig = Rig(session_factory, owner, calendar, StubRuntime(ANSWER))
    await rig.errands.create(
        owner, source="calendar", title=TITLE, item=ITEM, link=LINK, needed_by=DAY,
        source_ref=event.ref, source_updated=event.updated,
    )
    await rig.finder.scan_once()
    [row] = await rig.rows()
    assert row.event_day == DAY and rig.runtime.calls == []
    calendar.events = []
    rig.now += timedelta(days=1)
    await rig.finder.scan_once()
    assert [r.status for r in await rig.rows()] == ["cancelled"]


@pytest.mark.asyncio
async def test_deleting_a_note_cancels_its_errand_whatever_open_state_it_is_in(
    session_factory, owner
):
    for status in ("awaiting_approval", "waiting"):
        calendar = Calendar(_event(ref=f"evt-{status}"))
        rig = Rig(session_factory, owner, calendar, StubRuntime(ANSWER))
        await rig.finder.scan_once()
        await _set(rig, status=status)
        calendar.events = []
        await rig.finder.scan_once()
        assert {r.status for r in await rig.rows()} == {"cancelled"}, status
        assert "was removed" in rig.sent[-1]


@pytest.mark.asyncio
async def test_calendar_errands_do_not_start_while_the_calendar_switch_is_off(
    session_factory, owner
):
    runner = HeldRunner()
    rig = Rig(session_factory, owner, Calendar(_event()), StubRuntime(ANSWER), runner=runner)
    await rig.finder.scan_once()
    rig.now = datetime(2026, 12, 13, 17, 0, tzinfo=timezone.utc)

    async def only_errands():
        return frozenset({"errand_runs"})

    rig.errands._enabled_keys = only_errands
    assert await rig.errands.sweep_once() == 0 and runner.requests == []


def test_a_link_is_kept_only_when_it_is_one_of_the_notes_own_links_whole():
    note = _event(notes="Chanel No 5 https://www.chanel.com.au/no5-50ml, thanks", url="")
    base = json.loads(ANSWER)
    cut = read_answer(json.dumps(base | {"link": "https://www.chanel.com"}), note, TODAY)[1]
    whole = read_answer(json.dumps(base | {"link": "https://www.chanel.com.au/no5-50ml"}), note,
                        TODAY)[1]
    assert cut is not None and cut.link is None
    assert whole is not None and whole.link == "https://www.chanel.com.au/no5-50ml"


@pytest.mark.asyncio
async def test_a_note_any_copy_marks_as_someone_elses_is_never_planned(session_factory, owner):
    calendar = Calendar(_event(ref="gm1@google.com", title="Pick up order 4471",
                               notes="Buy the gift card"))
    rig = Rig(session_factory, owner, calendar, StubRuntime(ANSWER))
    gmail = _own_google(id="gm1", summary="Pick up order 4471", description="Buy the gift card",
                        organizer="unknownorganizer@calendar.google.com")
    _with_google(rig, GoogleReader([gmail]))
    await rig.finder.scan_once()
    assert await rig.rows() == [] and rig.runtime.calls == []


@pytest.mark.asyncio
async def test_a_recurring_note_is_one_errand_for_its_next_occurrence_on_either_calendar(
    session_factory, owner
):
    answer = json.dumps({"is_errand": True, "item": "roses", "link": "", "needed_by": "",
                         "for_whom": "Anna", "quantity": 1, "notes": ""})
    weekly = [
        _own_google(id=f"base_{DAY + timedelta(days=7 * w):%Y%m%d}", summary="Buy flowers",
                    description="roses", start={"date": (DAY + timedelta(days=7 * w)).isoformat()})
        for w in range(6)
    ]
    rig = Rig(session_factory, owner, Calendar(), StubRuntime(answer, answer))
    _with_google(rig, GoogleReader(weekly))
    await rig.finder.scan_once()
    [row] = await rig.rows()
    assert (row.source_ref, row.needed_by, len(rig.sent)) == ("base@google.com", DAY, 1)
    # The Mac lists a series on its first day (here 10 days ago): it is read
    # as its next occurrence too.
    first = TODAY - timedelta(days=10)
    output = _record("mac-series", "Buy flowers", f"{first} 9:0:0", "roses", "", "1", "0", "",
                     "FREQ=WEEKLY;INTERVAL=1") + _record(TRAILER, "0")
    [series] = parse_mac_output(output, TODAY).events
    assert (series.day, series.window_day) == (TODAY + timedelta(days=4), first)


def test_a_series_next_occurrence_follows_its_rule_and_its_end():
    from services.errands.calendar import next_occurrence

    first = date(2026, 1, 31)
    assert next_occurrence(first, "FREQ=MONTHLY", TODAY) == date(2026, 12, 31)
    assert next_occurrence(date(2026, 11, 1), "FREQ=WEEKLY;INTERVAL=2", TODAY) == date(2026, 11, 15)
    assert next_occurrence(date(2026, 11, 1), "FREQ=DAILY;COUNT=5", TODAY) is None
    assert next_occurrence(date(2026, 11, 1), "FREQ=DAILY;UNTIL=20261110T000000Z", TODAY) is None
    assert next_occurrence(date(2024, 2, 29), "FREQ=YEARLY", TODAY) == date(2028, 2, 29)
    assert next_occurrence(first, "FREQ=HOURLY", TODAY) is None


@pytest.mark.asyncio
async def test_the_daily_cap_on_reading_notes_holds_across_restarts(session_factory, owner):
    calendar = Calendar(_event(ref="a", title="Get coffee with Sam", notes=""),
                        _event(ref="b", title="Get the car washed", notes=""))
    calls = 0
    for _ in range(3):
        rig = Rig(session_factory, owner, calendar, StubRuntime(input_tokens=1_000_000),
                  cap_cents=10)
        await rig.finder.scan_once()
        calls += len(rig.runtime.calls)
    assert calls == 1


@pytest.mark.asyncio
async def test_an_answer_without_usage_still_counts_against_the_cap(session_factory, owner):
    from services.errands.finder import MIN_CALL_USD

    class NoUsage(StubRuntime):
        async def complete_once(self, messages, *, llm_provider, llm_model, system):
            once = await super().complete_once(messages, llm_provider=llm_provider,
                                               llm_model=llm_model, system=system)
            return OnceResult(text=once.text, usage={}, provider=once.provider, model=once.model)

    events = [_event(ref=f"n{i}", title=f"Get thing {i}", notes="") for i in range(10)]
    rig = Rig(session_factory, owner, Calendar(*events), NoUsage(), cap_cents=1)
    await rig.finder.scan_once()
    assert len(rig.runtime.calls) == round(0.01 / MIN_CALL_USD) < len(events)


@pytest.mark.asyncio
async def test_the_cancel_notice_names_only_the_item(session_factory, owner):
    answer = json.dumps(json.loads(ANSWER) | {"notes": "her old address on Elm St, gift wrap"})
    calendar = Calendar(_event())
    rig = Rig(session_factory, owner, calendar, StubRuntime(answer))
    await rig.finder.scan_once()
    [row] = await rig.rows()
    assert row.details == "for Anna, her old address on Elm St, gift wrap"
    calendar.events = []
    await rig.finder.scan_once()
    assert "Elm St" not in rig.sent[-1] and "Anna," not in rig.sent[-1]


@pytest.mark.asyncio
async def test_google_paging_after_an_all_day_event_keeps_that_mornings_events_east_of_utc():
    tz = timezone(timedelta(hours=5, minutes=30))

    def timed(i: int, start: datetime) -> dict[str, Any]:
        return {"id": f"t{i}", "summary": f"E{i}", "start": {"dateTime": start.isoformat()},
                "_s": start, "_e": start + timedelta(hours=1)}

    events = [timed(i, datetime(2026, 12, 1, 9, tzinfo=tz) + timedelta(hours=i))
              for i in range(49)]
    events.append({"id": "ad", "summary": "Holiday", "start": {"date": "2026-12-20"},
                   "_s": datetime(2026, 12, 20, tzinfo=tz), "_e": datetime(2026, 12, 21, tzinfo=tz)})
    events.append(timed(99, datetime(2026, 12, 20, 1, 0, tzinfo=tz)))

    class Google:
        async def read(self, user_id, name, arguments, run_id):
            lo = datetime.fromisoformat(arguments["time_min"].replace("Z", "+00:00"))
            hi = datetime.fromisoformat(arguments["time_max"])
            hits = sorted((e for e in events if e["_e"] > lo and e["_s"] < hi),
                          key=lambda e: (e["_s"], "dateTime" in e["start"]))[:50]
            return {"ok": True, "result": [
                {k: v for k, v in e.items() if not k.startswith("_")} for e in hits]}, None

    start = datetime(2026, 11, 13, tzinfo=tz)
    read = await read_google_calendar(Google(), "u", [Account("google_workspace", "c", "")],
                                      start, start + timedelta(days=180))
    assert "t99@google.com" in {e.ref for e in read.events}


def test_a_ref_longer_than_the_errand_row_keeps_is_cut_to_fit():
    output = _record("x" * 300, TITLE, "2026-12-20 9:0:0", NOTE, "", "1", "0", "", "")
    [event] = parse_mac_output(output + _record(TRAILER, "0"), TODAY).events
    assert len(event.ref) == 255
    assert len(google_event({"id": "y" * 300, "start": {"date": "2026-12-20"}}).ref) == 255
