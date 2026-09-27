"""Tests for the Microsoft 365 connector's calendar, OneDrive, To Do and
contacts actions: exact requests, output shaping, confirmation before any
request, argument validation and the OneDrive download redirect.

Why it exists: these actions create events that invite people, upload and
share files and delete tasks, so each request and each refusal is pinned.
It exercises ``services/connectors/microsoft_api/calendar.py``, ``drive.py``
and ``todo.py`` through ``httpx.MockTransport`` only (no network, no real
credentials), reusing the helpers in ``tests/connectors/test_microsoft.py``.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any, Callable

import httpx
import pytest

import core.network_security as netsec
from services.agent.permissions import ActionCategory
from services.connectors.base import ConnectorError, UserConfirmationRequired
from services.connectors.microsoft_api import calendar as calendar_module
from tests.connectors.test_microsoft import PUBLIC_IP, TOKEN, body_of, make_connector, ok

# find_meeting_times skips the past; the calendar tests use October 2026
# windows, so the clock is pinned before them unless a test moves it.
_PINNED_NOW = datetime(2026, 9, 1, tzinfo=timezone.utc)


@pytest.fixture(autouse=True)
def pinned_clock(monkeypatch) -> Callable[[datetime], None]:
    """Pins ``calendar._utc_now``; call the fixture value to move the clock."""

    def move(moment: datetime) -> None:
        monkeypatch.setattr(calendar_module, "_utc_now", lambda: moment)

    move(_PINNED_NOW)
    return move


@pytest.fixture
def no_dns(monkeypatch):
    """Policy checks decide on the allowlist alone; no DNS lookups."""
    monkeypatch.setattr(
        netsec,
        "check_ssrf",
        lambda url: netsec.SSRFCheckResult(safe=True, resolved_ip=PUBLIC_IP, resolved_ips=(PUBLIC_IP,)),
    )


# ---------------------------------------------------------------------------
# Calendar
# ---------------------------------------------------------------------------

_EVENT = {
    "id": "e1",
    "subject": "Standup",
    "start": {"dateTime": "2026-10-01T09:00:00.0000000", "timeZone": "UTC"},
    "end": {"dateTime": "2026-10-01T09:15:00.0000000", "timeZone": "UTC"},
    "location": {"displayName": "Room 1"},
    "organizer": {"emailAddress": {"name": "Ann", "address": "ann@contoso.com"}},
    "isAllDay": False,
    "showAs": "busy",
    "responseStatus": {"response": "accepted"},
    "onlineMeeting": {"joinUrl": "https://teams.microsoft.com/l/x"},
    "webLink": "https://outlook.office365.com/x",
    "body": {"content": "should not be returned"},
}


@pytest.mark.asyncio
async def test_list_events_uses_calendar_view_with_a_utc_window():
    connector, seen = make_connector(ok({"value": [_EVENT]}))
    result = await connector.list_events(start="2026-10-01T00:00:00+02:00", end="2026-10-03", limit=5)

    (request,) = seen
    assert request.method == "GET"
    assert request.url.path == "/v1.0/me/calendarView"
    params = request.url.params
    assert params["startDateTime"] == "2026-09-30T22:00:00Z"
    assert params["endDateTime"] == "2026-10-03T00:00:00Z"
    assert params["$top"] == "5"
    assert params["$orderby"] == "start/dateTime"
    assert "body" not in params["$select"]
    assert result == [
        {
            "id": "e1",
            "subject": "Standup",
            "start": "2026-10-01T09:00:00.0000000 (UTC)",
            "end": "2026-10-01T09:15:00.0000000 (UTC)",
            "all_day": False,
            "location": "Room 1",
            "organizer": "Ann <ann@contoso.com>",
            "show_as": "busy",
            "response": "accepted",
            "online_meeting_url": "https://teams.microsoft.com/l/x",
            "web_link": "https://outlook.office365.com/x",
        }
    ]


@pytest.mark.asyncio
async def test_list_events_defaults_to_seven_days_and_scopes_to_a_calendar():
    connector, seen = make_connector(ok({"value": []}))
    await connector.list_events(start="2026-10-01T00:00:00Z", calendar_id="cal/1")
    assert seen[0].url.raw_path.startswith(b"/v1.0/me/calendars/cal%2F1/calendarView?")
    assert seen[0].url.params["endDateTime"] == "2026-10-08T00:00:00Z"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("kwargs", "message"),
    [
        ({"start": "tomorrow"}, "ISO 8601"),
        ({"start": "2026-10-02", "end": "2026-10-01"}, "after 'start'"),
        ({"start": "2026-01-01", "end": "2028-01-01"}, "too long"),
        ({"start": 5}, "ISO 8601"),
    ],
)
async def test_list_events_validates_the_window_before_any_request(kwargs, message):
    connector, seen = make_connector(ok({"value": []}))
    with pytest.raises(ConnectorError, match=message):
        await connector.list_events(**kwargs)
    assert seen == []


def _slot(start: str, end: str, status: str, zone: str = "UTC", **extra: Any) -> dict[str, Any]:
    """A calendarView event or getSchedule item in Graph's wire format."""
    return {
        "start": {"dateTime": f"{start}.0000000", "timeZone": zone},
        "end": {"dateTime": f"{end}.0000000", "timeZone": zone},
        **extra,
        "status": status,
        "showAs": status,
    }


def _schedule(address: str, items: list[dict[str, Any]], **extra: Any) -> dict[str, Any]:
    return {"scheduleId": address, "availabilityView": "0", "scheduleItems": items, **extra}


def _free_busy_graph(
    own: list[dict[str, Any]], schedules: list[dict[str, Any]] | None = None
) -> Callable[[httpx.Request], httpx.Response]:
    """Answers the calendar view (own events) and getSchedule (attendees)."""

    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "GET" and request.url.path == "/v1.0/me/calendarView":
            return httpx.Response(200, json={"value": own})
        if request.method == "POST" and request.url.path == "/v1.0/me/calendar/getSchedule":
            return httpx.Response(200, json={"value": schedules or []})
        return httpx.Response(404, json={"error": {"code": "UnexpectedRequest"}})

    return handler


_WORK_WEEK = ["monday", "tuesday", "wednesday", "thursday", "friday"]


@pytest.mark.asyncio
async def test_find_meeting_times_intersects_own_calendar_and_get_schedule():
    own = [
        _slot("2026-10-01T09:00:00", "2026-10-01T10:00:00", "busy"),
        _slot("2026-10-01T10:00:00", "2026-10-01T11:00:00", "free"),
        _slot("2026-10-01T11:00:00", "2026-10-01T12:00:00", "busy", isCancelled=True),
    ]
    bob = _schedule(
        "bob@contoso.com",
        [
            _slot("2026-10-01T12:00:00", "2026-10-01T13:00:00", "Busy"),
            # Overlaps the busy item above and runs past it.
            _slot("2026-10-01T12:30:00", "2026-10-01T14:00:00", "busy"),
            _slot("2026-10-01T13:00:00", "2026-10-01T13:30:00", "tentative"),
            _slot("2026-10-01T15:00:00", "2026-10-01T16:00:00", "oof"),
            _slot("2026-10-01T16:00:00", "2026-10-01T17:00:00", "workingElsewhere"),
        ],
    )
    # An address outside the organisation: Graph answers with an error
    # object, whose text must never be relayed.
    carol = {
        "scheduleId": "carol@fabrikam.com",
        "error": {"message": f"Not found {TOKEN}", "responseCode": "ErrorMailRecipientNotFound"},
    }
    connector, seen = make_connector(_free_busy_graph(own, [bob, carol]))
    result = await connector.find_meeting_times(
        "2026-10-01T08:00:00Z", "2026-10-01T18:00:00Z",
        attendees=["Bob@contoso.com", "carol@fabrikam.com"], duration_minutes=60, limit=10,
    )

    view, schedule = seen
    assert view.method == "GET" and view.url.host == "graph.microsoft.com"
    assert view.url.path == "/v1.0/me/calendarView"
    assert view.url.params["startDateTime"] == "2026-10-01T08:00:00Z"
    assert view.url.params["endDateTime"] == "2026-10-01T18:00:00Z"
    assert view.url.params["$top"] == "200"
    assert view.url.params["$select"] == "showAs,start,end,isCancelled"
    assert view.headers["prefer"] == 'outlook.timezone="UTC"'
    assert schedule.method == "POST"
    assert schedule.url.raw_path == b"/v1.0/me/calendar/getSchedule"
    assert schedule.headers["prefer"] == 'outlook.timezone="UTC"'
    assert body_of(schedule) == {
        "schedules": ["Bob@contoso.com", "carol@fabrikam.com"],
        "startTime": {"dateTime": "2026-10-01T08:00:00", "timeZone": "UTC"},
        "endTime": {"dateTime": "2026-10-01T18:00:00", "timeZone": "UTC"},
        "availabilityViewInterval": 1440,
    }
    # Busy: own 09-10, Bob 12-14 (busy, overlapping busy, tentative) and
    # 15-16 (oof). Free, workingElsewhere and cancelled time stays open;
    # the two-hour gaps give a second start one meeting length later.
    assert result == {
        "items": [
            {"start": "2026-10-01T08:00:00Z", "end": "2026-10-01T09:00:00Z", "free_until": "2026-10-01T09:00:00Z"},
            {"start": "2026-10-01T10:00:00Z", "end": "2026-10-01T11:00:00Z", "free_until": "2026-10-01T12:00:00Z"},
            {"start": "2026-10-01T11:00:00Z", "end": "2026-10-01T12:00:00Z", "free_until": "2026-10-01T12:00:00Z"},
            {"start": "2026-10-01T14:00:00Z", "end": "2026-10-01T15:00:00Z", "free_until": "2026-10-01T15:00:00Z"},
            {"start": "2026-10-01T16:00:00Z", "end": "2026-10-01T17:00:00Z", "free_until": "2026-10-01T18:00:00Z"},
            {"start": "2026-10-01T17:00:00Z", "end": "2026-10-01T18:00:00Z", "free_until": "2026-10-01T18:00:00Z"},
        ],
        "count": 6,
        "empty_reason": None,
        "unknown_availability": ["carol@fabrikam.com"],
        "working_hours_from": [],
    }
    assert TOKEN not in repr(result) and "Not found" not in repr(result)


@pytest.mark.asyncio
async def test_find_meeting_times_honours_known_working_hours_only():
    # Thursday 1 October 2026; Pacific daylight time is UTC-7, so 09:00 to
    # 17:00 in Seattle is 16:00 to 00:00 UTC.
    pacific = {"daysOfWeek": _WORK_WEEK, "startTime": "09:00:00.0000000",
               "endTime": "17:00:00.0000000", "timeZone": {"name": "Pacific Standard Time"}}
    custom = {"daysOfWeek": _WORK_WEEK, "startTime": "08:00:00.0000000",
              "endTime": "09:00:00.0000000",
              "timeZone": {"@odata.type": "#microsoft.graph.customTimeZone", "bias": 480,
                           "name": "Customized Time Zone"}}
    schedules = [
        _schedule("bob@contoso.com", [], workingHours=pacific),
        # A zone that cannot be resolved: the hours are not applied.
        _schedule("dan@contoso.com", [], workingHours=custom),
        # Working hours absent altogether.
        _schedule("eve@contoso.com", [_slot("2026-10-01T20:00:00", "2026-10-01T21:00:00", "busy")]),
    ]
    connector, _ = make_connector(_free_busy_graph([], schedules))
    result = await connector.find_meeting_times(
        "2026-10-01T12:00:00Z", "2026-10-02T12:00:00Z",
        attendees=["bob@contoso.com", "dan@contoso.com", "eve@contoso.com"],
    )
    # Default limit 5: both free periods first, then more starts inside
    # them in turn (30 minutes apart), listed in time order.
    assert result["items"] == [
        {"start": "2026-10-01T16:00:00Z", "end": "2026-10-01T16:30:00Z", "free_until": "2026-10-01T20:00:00Z"},
        {"start": "2026-10-01T16:30:00Z", "end": "2026-10-01T17:00:00Z", "free_until": "2026-10-01T20:00:00Z"},
        {"start": "2026-10-01T17:00:00Z", "end": "2026-10-01T17:30:00Z", "free_until": "2026-10-01T20:00:00Z"},
        {"start": "2026-10-01T21:00:00Z", "end": "2026-10-01T21:30:00Z", "free_until": "2026-10-02T00:00:00Z"},
        {"start": "2026-10-01T21:30:00Z", "end": "2026-10-01T22:00:00Z", "free_until": "2026-10-02T00:00:00Z"},
    ]
    assert result["working_hours_from"] == ["bob@contoso.com"]
    assert result["unknown_availability"] == []


@pytest.mark.asyncio
async def test_find_meeting_times_rounds_starts_and_skips_short_gaps():
    own = [_slot("2026-10-01T09:00:00", "2026-10-01T09:20:00", "busy")]
    connector, seen = make_connector(_free_busy_graph(own))
    result = await connector.find_meeting_times(
        "2026-10-01T08:07:00Z", "2026-10-01T10:00:00Z", duration_minutes=45
    )
    # No attendees: only the user's calendar is read, no getSchedule call.
    assert [request.url.path for request in seen] == ["/v1.0/me/calendarView"]
    # 08:07 rounds to 08:15 and 08:15 plus 45 minutes fits before 09:00;
    # 09:20 rounds to 09:30 and 09:30 plus 45 minutes does not fit.
    assert result["items"] == [
        {"start": "2026-10-01T08:15:00Z", "end": "2026-10-01T09:00:00Z", "free_until": "2026-10-01T09:00:00Z"}
    ]


@pytest.mark.asyncio
async def test_find_meeting_times_reports_when_no_slot_is_found():
    own = [_slot("2026-10-01T00:00:00", "2026-10-03T00:00:00", "oof")]
    schedules = [_schedule("bob@contoso.com", [_slot("2026-10-01T09:00:00", "2026-10-01T10:00:00", "busy")])]
    connector, _ = make_connector(_free_busy_graph(own, schedules))
    result = await connector.find_meeting_times("2026-10-01", "2026-10-02", attendees=["bob@contoso.com"])
    assert result == {
        "items": [],
        "count": 0,
        "empty_reason": "No common free time of 30 minutes in the window.",
        "unknown_availability": [],
        "working_hours_from": [],
    }


@pytest.mark.asyncio
async def test_find_meeting_times_marks_unusable_schedules_unknown():
    unreadable = _schedule("bob@contoso.com", [{"status": "busy", "start": {"dateTime": "soon"}, "end": {}}])
    no_items = {"scheduleId": "dan@contoso.com", "availabilityView": "000"}
    connector, _ = make_connector(_free_busy_graph([], [unreadable, no_items]))
    result = await connector.find_meeting_times(
        "2026-10-01T08:00:00Z", "2026-10-01T09:00:00Z",
        # eve is missing from the response altogether.
        attendees=["bob@contoso.com", "dan@contoso.com", "eve@contoso.com"],
    )
    assert result["unknown_availability"] == ["bob@contoso.com", "dan@contoso.com", "eve@contoso.com"]
    # The free hour holds two 30-minute starts.
    assert [item["start"] for item in result["items"]] == ["2026-10-01T08:00:00Z", "2026-10-01T08:30:00Z"]


def _schedule_without_value(request: httpx.Request) -> httpx.Response:
    return httpx.Response(200, json={"value": []} if request.method == "GET" else {"oops": True})


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "handler",
    [
        # getSchedule without a value list.
        _schedule_without_value,
        # A blocking own event whose times cannot be read.
        _free_busy_graph([{"showAs": "busy", "start": {"dateTime": "later"}, "end": None}]),
    ],
)
async def test_find_meeting_times_refuses_malformed_answers(handler):
    connector, _ = make_connector(handler)
    with pytest.raises(ConnectorError, match="Malformed response"):
        await connector.find_meeting_times(
            "2026-10-01T08:00:00Z", "2026-10-01T09:00:00Z", attendees=["bob@contoso.com"]
        )


@pytest.mark.asyncio
async def test_find_meeting_times_refuses_a_window_with_too_many_events():
    page = [_slot("2026-10-01T08:00:00", "2026-10-01T08:05:00", "free")] * 200
    calls = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        link = f"https://graph.microsoft.com/v1.0/me/calendarView?%24skiptoken=p{calls['n']}"
        return httpx.Response(200, json={"value": page, "@odata.nextLink": link})

    connector, seen = make_connector(handler)
    with pytest.raises(ConnectorError, match="Could not read the whole calendar"):
        await connector.find_meeting_times("2026-10-01", "2026-10-02")
    # 1000 events read and a next link still pending: refused, not followed.
    assert len(seen) == 5 and all(request.method == "GET" for request in seen)


_VIEW_URL = "https://graph.microsoft.com/v1.0/me/calendarView"
# The user's 08:00 to 18:00 busy block that a missed page would hide.
_ALL_DAY_BUSY = _slot("2026-10-01T08:00:00", "2026-10-01T18:00:00", "busy")
_FILLER = _slot("2026-10-01T07:00:00", "2026-10-01T07:05:00", "free")


def _paged_calendar(pages: int, busy_on: int, link: Callable[[int], str]) -> Callable[[httpx.Request], httpx.Response]:
    """A calendar view that ignores $top: 10 events per page, *pages*
    pages, the busy block on page *busy_on*; ``link(n)`` is page n's next
    link (none on the last page)."""

    def handler(request: httpx.Request) -> httpx.Response:
        if request.method != "GET" or request.url.path != "/v1.0/me/calendarView":
            return httpx.Response(404, json={"error": {"code": "UnexpectedRequest"}})
        number = 1 if "p" not in request.url.params else int(request.url.params["p"])
        value = [_FILLER] * 9 + [_ALL_DAY_BUSY if number == busy_on else _FILLER]
        body: dict[str, Any] = {"value": value}
        if number < pages:
            body["@odata.nextLink"] = link(number)
        return httpx.Response(200, json=body)

    return handler


@pytest.mark.asyncio
async def test_find_meeting_times_follows_every_small_page_of_the_calendar():
    connector, seen = make_connector(_paged_calendar(7, 6, lambda n: f"{_VIEW_URL}?p={n + 1}"))
    result = await connector.find_meeting_times("2026-10-01T08:00:00Z", "2026-10-01T18:00:00Z")
    # All seven pages are read, the next ones through the link as given.
    assert len(seen) == 7
    assert [request.url.params.get("p") for request in seen[1:]] == ["2", "3", "4", "5", "6", "7"]
    assert all(request.headers["prefer"] == 'outlook.timezone="UTC"' for request in seen)
    # The busy block on page 6 is honoured: no slot is offered.
    assert result["items"] == [] and result["count"] == 0


@pytest.mark.asyncio
async def test_find_meeting_times_refuses_a_calendar_past_the_page_cap():
    connector, seen = make_connector(_paged_calendar(100, 99, lambda n: f"{_VIEW_URL}?p={n + 1}"))
    with pytest.raises(ConnectorError, match="Could not read the whole calendar"):
        await connector.find_meeting_times("2026-10-01T08:00:00Z", "2026-10-01T18:00:00Z")
    assert len(seen) == calendar_module._MAX_OWN_PAGES


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "link",
    [
        # Another collection form of the same calendar: refused by
        # _next_page_url, so the rest of the calendar cannot be read.
        "https://graph.microsoft.com/v1.0/users('user-test-id')/calendarView?p=2",
        # Off the Graph host.
        "https://graph.example.com/v1.0/me/calendarView?p=2",
        # Not a string at all.
        12345,
    ],
)
async def test_find_meeting_times_refuses_when_a_next_link_is_refused(link):
    connector, seen = make_connector(_paged_calendar(2, 2, lambda n: link))
    with pytest.raises(ConnectorError, match="Could not read the whole calendar"):
        await connector.find_meeting_times("2026-10-01T08:00:00Z", "2026-10-01T18:00:00Z")
    assert len(seen) == 1


@pytest.mark.asyncio
async def test_find_meeting_times_refuses_a_repeated_next_link():
    # Page 2 hands back the link that led to it: a loop, not the end.
    connector, seen = make_connector(_paged_calendar(10, 9, lambda n: f"{_VIEW_URL}?p=2"))
    with pytest.raises(ConnectorError, match="Could not read the whole calendar"):
        await connector.find_meeting_times("2026-10-01T08:00:00Z", "2026-10-01T18:00:00Z")
    assert len(seen) == 2


@pytest.mark.asyncio
async def test_find_meeting_times_malformed_later_page_is_refused():
    def handler(request: httpx.Request) -> httpx.Response:
        if "p" in request.url.params:
            return httpx.Response(200, json={"value": "nope"})
        return httpx.Response(200, json={"value": [], "@odata.nextLink": f"{_VIEW_URL}?p=2"})

    connector, seen = make_connector(handler)
    with pytest.raises(ConnectorError, match="Malformed response"):
        await connector.find_meeting_times("2026-10-01T08:00:00Z", "2026-10-01T18:00:00Z")
    assert len(seen) == 2


@pytest.mark.asyncio
async def test_find_meeting_times_skips_the_past_part_of_the_window(pinned_clock):
    pinned_clock(datetime(2026, 10, 1, 10, 7, 30, tzinfo=timezone.utc))
    schedules = [_schedule("bob@contoso.com", [])]
    connector, seen = make_connector(_free_busy_graph([], schedules))
    result = await connector.find_meeting_times(
        "2026-10-01T08:00:00Z", "2026-10-01T12:00:00Z", attendees=["bob@contoso.com"],
        duration_minutes=60, limit=2,
    )
    view, schedule = seen
    # Only the rest of the window is read, and no slot starts in the past.
    assert view.url.params["startDateTime"] == "2026-10-01T10:07:30Z"
    assert body_of(schedule)["startTime"] == {"dateTime": "2026-10-01T10:07:30", "timeZone": "UTC"}
    assert result["items"] == [
        {"start": "2026-10-01T10:15:00Z", "end": "2026-10-01T11:15:00Z", "free_until": "2026-10-01T12:00:00Z"},
    ]


@pytest.mark.asyncio
async def test_find_meeting_times_window_already_over_makes_no_request(pinned_clock):
    pinned_clock(datetime(2026, 10, 2, tzinfo=timezone.utc))
    connector, seen = make_connector(_free_busy_graph([]))
    result = await connector.find_meeting_times("2026-10-01T08:00:00Z", "2026-10-01T12:00:00Z")
    assert seen == []
    assert result["items"] == [] and result["empty_reason"] == "The window is already over."


@pytest.mark.asyncio
async def test_find_meeting_times_gives_several_slots_in_one_long_gap():
    connector, _ = make_connector(_free_busy_graph([]))
    result = await connector.find_meeting_times(
        "2026-10-01T09:05:00Z", "2026-10-08T09:00:00Z", duration_minutes=50, limit=4
    )
    # A free week is one gap: four starts on quarter hours, an hour apart
    # (50 minutes rounded up to the next quarter hour).
    assert result["count"] == 4
    assert [item["start"] for item in result["items"]] == [
        "2026-10-01T09:15:00Z", "2026-10-01T10:15:00Z", "2026-10-01T11:15:00Z", "2026-10-01T12:15:00Z",
    ]
    assert {item["free_until"] for item in result["items"]} == {"2026-10-08T09:00:00Z"}


@pytest.mark.parametrize(
    ("minutes", "spacing"),
    [(5, 30), (20, 30), (30, 30), (45, 45), (50, 60), (61, 75), (1440, 1440)],
)
def test_slot_spacing_is_at_least_half_an_hour_on_quarter_hours(minutes, spacing):
    assert calendar_module._slot_spacing(timedelta(minutes=minutes)) == timedelta(minutes=spacing)


def test_slots_take_every_gap_before_a_second_start_in_any():
    day = datetime(2026, 10, 1, tzinfo=timezone.utc)
    gaps = [
        (day + timedelta(hours=8), day + timedelta(hours=12)),
        (day + timedelta(hours=14), day + timedelta(hours=14, minutes=30)),
        (day + timedelta(hours=16), day + timedelta(hours=18)),
    ]
    slots = calendar_module._slots(gaps, timedelta(minutes=30), 4)
    assert [slot["start"] for slot in slots] == [
        "2026-10-01T08:00:00Z", "2026-10-01T08:30:00Z", "2026-10-01T14:00:00Z", "2026-10-01T16:00:00Z",
    ]
    assert calendar_module._slots(gaps, timedelta(minutes=30), 0) == []
    assert calendar_module._slots([], timedelta(minutes=30), 5) == []


def test_find_meeting_times_needs_only_calendars_read():
    from services.connectors.microsoft import DEFINITION

    spec = next(spec for spec in DEFINITION.actions if spec.action == "find_meeting_times")
    assert spec.required_scope == "calendar.read" and spec.category == ActionCategory.READ
    oauth = DEFINITION.auth.oauth
    assert oauth is not None and "calendar.availability" not in oauth.scope_map
    provider_scopes = oauth.provider_scopes(DEFINITION.scopes()["read"])
    assert "Calendars.Read" in provider_scopes
    assert not any("Shared" in scope for scope in provider_scopes)


@pytest.mark.asyncio
async def test_find_meeting_times_validates_before_any_request():
    connector, seen = make_connector(ok({}))
    for kwargs, message in (
        ({"duration_minutes": 2}, "between 5 and 1440"),
        ({"duration_minutes": "30"}, "whole number"),
        ({"attendees": ["nope"]}, "invalid email"),
    ):
        with pytest.raises(ConnectorError, match=message):
            await connector.find_meeting_times("2026-10-01", "2026-10-02", **kwargs)
    with pytest.raises(ConnectorError, match="at most 62 days"):
        await connector.find_meeting_times("2026-10-01", "2027-10-02")
    assert seen == []


@pytest.mark.asyncio
async def test_list_calendars_shapes_entries():
    item = {"id": "c1", "name": "Calendar", "canEdit": True, "isDefaultCalendar": True,
            "owner": {"name": "Ann", "address": "ann@contoso.com"}}
    connector, seen = make_connector(ok({"value": [item]}))
    assert await connector.list_calendars() == [
        {"id": "c1", "name": "Calendar", "is_default": True, "can_edit": True, "owner": "ann@contoso.com"}
    ]
    assert seen[0].url.path == "/v1.0/me/calendars"


_CAL_WRITES = [
    ("create_event", lambda c, **k: c.create_event("Sync", "2026-10-01T09:00:00", "2026-10-01T09:30:00", **k)),
    ("update_event", lambda c, **k: c.update_event("e1", subject="New", **k)),
    ("respond_to_invite", lambda c, **k: c.respond_to_invite("e1", "accept", **k)),
    ("delete_event", lambda c, **k: c.delete_event("e1", **k)),
]


@pytest.mark.asyncio
@pytest.mark.parametrize(("action", "call"), _CAL_WRITES)
async def test_calendar_writes_require_confirmation_before_any_request(action, call):
    connector, seen = make_connector(ok(_EVENT))
    with pytest.raises(UserConfirmationRequired) as exc:
        await call(connector)
    assert exc.value.action == action
    assert seen == []
    result = await call(connector, user_confirmed=True)
    assert len(seen) == 1 and isinstance(result, dict)


@pytest.mark.asyncio
async def test_delete_event_confirmation_names_the_attendee_cancellation():
    connector, seen = make_connector(ok(_EVENT))
    with pytest.raises(UserConfirmationRequired) as exc:
        await connector.delete_event("e1")
    assert "e1" in exc.value.details
    assert "attendees, they are sent a cancellation" in exc.value.details
    assert seen == []


@pytest.mark.asyncio
async def test_create_event_body_and_invitation_warning():
    connector, seen = make_connector(ok(_EVENT, 201))
    with pytest.raises(UserConfirmationRequired) as exc:
        await connector.create_event(
            "Sync", "2026-10-01T09:00:00", "2026-10-01T09:30:00",
            time_zone="Europe/London", attendees=["bob@contoso.com"],
        )
    assert "send an invitation to bob@contoso.com" in exc.value.details

    await connector.create_event(
        "Sync", "2026-10-01T09:00:00", "2026-10-01T10:00:00Z",
        time_zone="Europe/London", attendees=["bob@contoso.com"], location="Room 2",
        body="Agenda", calendar_id="c1", user_confirmed=True,
    )
    (request,) = seen
    assert request.method == "POST"
    assert request.url.raw_path == b"/v1.0/me/calendars/c1/events"
    assert body_of(request) == {
        "subject": "Sync",
        "start": {"dateTime": "2026-10-01T09:00:00", "timeZone": "Europe/London"},
        "end": {"dateTime": "2026-10-01T10:00:00", "timeZone": "UTC"},
        "attendees": [{"type": "required", "emailAddress": {"address": "bob@contoso.com"}}],
        "location": {"displayName": "Room 2"},
        "body": {"contentType": "Text", "content": "Agenda"},
    }


@pytest.mark.asyncio
async def test_create_event_validates_arguments():
    connector, seen = make_connector(ok(_EVENT))
    with pytest.raises(ConnectorError, match="time-zone name"):
        await connector.create_event("S", "2026-10-01T09:00", "2026-10-01T10:00", time_zone="Bad;Zone")
    with pytest.raises(ConnectorError, match="ISO 8601"):
        await connector.create_event("S", "9am", "2026-10-01T10:00")
    assert seen == []


@pytest.mark.asyncio
async def test_update_respond_and_delete_event_requests():
    connector, seen = make_connector(lambda r: httpx.Response(202 if r.method == "POST" else 200, json=_EVENT))
    await connector.update_event("e/1", start="2026-10-01T10:00:00", location="", user_confirmed=True)
    await connector.respond_to_invite("e1", "Tentative", comment="maybe", send_response=False, user_confirmed=True)
    await connector.delete_event("e1", user_confirmed=True)
    assert [(r.method, r.url.raw_path) for r in seen] == [
        ("PATCH", b"/v1.0/me/events/e%2F1"),
        ("POST", b"/v1.0/me/events/e1/tentativelyAccept"),
        ("DELETE", b"/v1.0/me/events/e1"),
    ]
    assert body_of(seen[0]) == {
        "start": {"dateTime": "2026-10-01T10:00:00", "timeZone": "UTC"},
        "location": {"displayName": ""},
    }
    assert body_of(seen[1]) == {"sendResponse": False, "comment": "maybe"}


@pytest.mark.asyncio
async def test_update_event_needs_a_change_and_respond_needs_a_valid_answer():
    connector, seen = make_connector(ok(_EVENT))
    with pytest.raises(ConnectorError, match="Nothing to update"):
        await connector.update_event("e1", user_confirmed=True)
    with pytest.raises(ConnectorError, match="accept, tentative, decline"):
        await connector.respond_to_invite("e1", "maybe", user_confirmed=True)
    with pytest.raises(ConnectorError, match="required"):
        await connector.respond_to_invite("e1", None, user_confirmed=True)
    assert seen == []


# ---------------------------------------------------------------------------
# OneDrive
# ---------------------------------------------------------------------------

_FILE = {
    "id": "f1",
    "name": "notes.md",
    "size": 11,
    "file": {"mimeType": "text/markdown", "hashes": {"sha1Hash": "x"}},
    "lastModifiedDateTime": "2026-09-20T10:00:00Z",
    "webUrl": "https://onedrive.live.com/x",
    "parentReference": {"id": "root-id", "driveId": "d1"},
    "@microsoft.graph.downloadUrl": "https://public.files.1drv.com/secret",
}
_FOLDER = {"id": "d9", "name": "Docs", "folder": {"childCount": 4}, "webUrl": "https://x/d"}


@pytest.mark.asyncio
async def test_search_files_puts_an_encoded_odata_literal_in_the_path():
    connector, seen = make_connector(ok({"value": [_FILE, _FOLDER]}))
    result = await connector.search_files("it's q2/plan?#", limit=2)
    (request,) = seen
    assert request.url.raw_path.startswith(
        b"/v1.0/me/drive/root/search(q='it''s%20q2%2Fplan%3F%23')?"
    )
    assert request.url.params["$top"] == "2"
    assert result[0] == {
        "id": "f1",
        "name": "notes.md",
        "is_folder": False,
        "size": 11,
        "modified": "2026-09-20T10:00:00Z",
        "web_url": "https://onedrive.live.com/x",
        "parent_id": "root-id",
        "mime_type": "text/markdown",
    }
    assert result[1]["is_folder"] is True and result[1]["child_count"] == 4
    assert "downloadUrl" not in str(result)


@pytest.mark.asyncio
async def test_list_folder_root_and_by_id():
    connector, seen = make_connector(ok({"value": [_FILE]}))
    await connector.list_folder()
    await connector.list_folder(folder_id="d/9", limit=1)
    assert seen[0].url.path == "/v1.0/me/drive/root/children"
    assert seen[1].url.raw_path.startswith(b"/v1.0/me/drive/items/d%2F9/children?")
    assert seen[1].url.params["$top"] == "1"


def _download_handler(meta: dict[str, Any], content: bytes = b"# Notes\nhi") -> Any:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.host == "graph.microsoft.com" and request.url.path.endswith("/content"):
            return httpx.Response(
                302,
                headers={"Location": "https://contoso-my.sharepoint.com/personal/ann/_layouts/15/download.aspx?tempauth=abc"},
            )
        if request.url.host == "graph.microsoft.com":
            return httpx.Response(200, json=meta)
        return httpx.Response(200, content=content)

    return handler


@pytest.mark.asyncio
async def test_get_file_text_checks_metadata_then_follows_the_download_without_token(no_dns):
    connector, seen = make_connector(_download_handler(_FILE), hooked=True)
    result = await connector.get_file_text("f1")

    assert [(r.method, r.url.host, r.url.path) for r in seen] == [
        ("GET", "graph.microsoft.com", "/v1.0/me/drive/items/f1"),
        ("GET", "graph.microsoft.com", "/v1.0/me/drive/items/f1/content"),
        ("GET", "contoso-my.sharepoint.com", "/personal/ann/_layouts/15/download.aspx"),
    ]
    assert seen[1].headers["Authorization"] == f"Bearer {TOKEN}"
    assert "authorization" not in seen[2].headers
    assert result["text"] == "# Notes\nhi"
    assert result["truncated"] is False
    assert result["name"] == "notes.md"
    await connector.close()


@pytest.mark.asyncio
async def test_get_file_text_redirect_to_an_off_list_host_is_refused(no_dns):
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/content"):
            return httpx.Response(302, headers={"Location": "https://attacker.example.com/steal"})
        return httpx.Response(200, json=_FILE)

    connector, seen = make_connector(handler, hooked=True)
    with pytest.raises(ConnectorError, match="blocked by network policy"):
        await connector.get_file_text("f1")
    assert all(r.url.host == "graph.microsoft.com" for r in seen)
    await connector.close()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("meta", "message"),
    [
        (_FOLDER, "is a folder"),
        ({**_FILE, "name": "deck.pptx", "file": {"mimeType": "application/vnd.ms-powerpoint"}}, "not a plain-text file"),
        ({**_FILE, "size": 9_000_000}, "too large"),
    ],
)
async def test_get_file_text_refuses_before_downloading(meta, message):
    connector, seen = make_connector(_download_handler(meta))
    with pytest.raises(ConnectorError, match=message):
        await connector.get_file_text("f1")
    assert len(seen) == 1


@pytest.mark.asyncio
async def test_get_file_text_caps_long_files(no_dns):
    connector, _ = make_connector(_download_handler(_FILE, content=b"z" * 50_000), hooked=True)
    result = await connector.get_file_text("f1")
    assert result["truncated"] is True and len(result["text"]) == 20_000
    assert "web_url" in result["hint"]
    await connector.close()


_DRIVE_WRITES = [
    ("upload_file", lambda c, **k: c.upload_file("a.txt", "hello", **k)),
    ("create_folder", lambda c, **k: c.create_folder("Reports", **k)),
    ("move_file", lambda c, **k: c.move_file("f1", "d9", **k)),
    ("create_share_link", lambda c, **k: c.create_share_link("f1", **k)),
    ("delete_file", lambda c, **k: c.delete_file("f1", **k)),
]


@pytest.mark.asyncio
@pytest.mark.parametrize(("action", "call"), _DRIVE_WRITES)
async def test_drive_writes_require_confirmation_before_any_request(action, call):
    connector, seen = make_connector(ok(_FILE))
    with pytest.raises(UserConfirmationRequired) as exc:
        await call(connector)
    assert exc.value.action == action
    assert seen == []
    await call(connector, user_confirmed=True)
    assert len(seen) == 1


@pytest.mark.asyncio
async def test_upload_file_puts_text_with_conflict_behaviour():
    connector, seen = make_connector(ok(_FILE, 201))
    await connector.upload_file("my notes.txt", "héllo", user_confirmed=True)
    await connector.upload_file("a.txt", "x", folder_id="d9", overwrite=True, user_confirmed=True)

    first, second = seen
    assert first.method == "PUT"
    assert first.url.raw_path == (
        b"/v1.0/me/drive/root:/my%20notes.txt:/content?%40microsoft.graph.conflictBehavior=fail"
    )
    assert first.content == "héllo".encode()
    assert first.headers["Content-Type"].startswith("text/plain")
    assert second.url.raw_path.startswith(b"/v1.0/me/drive/items/d9:/a.txt:/content?")
    assert second.url.params["@microsoft.graph.conflictBehavior"] == "replace"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("kwargs", "message"),
    [
        ({"name": "../x.txt", "content": "a"}, "not a valid OneDrive name"),
        ({"name": "a:b.txt", "content": "a"}, "not a valid OneDrive name"),
        ({"name": "ok.txt", "content": b"bytes"}, "string of text"),
        ({"name": "ok.txt", "content": "x" * 1_000_001}, "too large"),
        ({"name": "ok.txt", "content": "a", "overwrite": "yes"}, "true or false"),
    ],
)
async def test_upload_file_validates_before_any_request(kwargs, message):
    connector, seen = make_connector(ok(_FILE))
    with pytest.raises(ConnectorError, match=message):
        await connector.upload_file(**kwargs, user_confirmed=True)
    assert seen == []


@pytest.mark.asyncio
async def test_folder_move_share_and_delete_requests():
    link = {"link": {"webUrl": "https://1drv.ms/x", "type": "view", "scope": "anonymous"}}
    connector, seen = make_connector(
        lambda r: httpx.Response(204) if r.method == "DELETE" else httpx.Response(200, json=link if r.url.path.endswith("createLink") else _FILE)
    )
    await connector.create_folder("Reports", parent_folder_id="d9", user_confirmed=True)
    await connector.move_file("f1", "d9", new_name="n.md", user_confirmed=True)
    with pytest.raises(UserConfirmationRequired) as exc:
        await connector.create_share_link("f1", scope="anonymous")
    assert "anyone who has the link" in exc.value.details
    shared = await connector.create_share_link("f1", scope="anonymous", user_confirmed=True)
    deleted = await connector.delete_file("f1", user_confirmed=True)

    assert [(r.method, r.url.raw_path) for r in seen] == [
        ("POST", b"/v1.0/me/drive/items/d9/children"),
        ("PATCH", b"/v1.0/me/drive/items/f1"),
        ("POST", b"/v1.0/me/drive/items/f1/createLink"),
        ("DELETE", b"/v1.0/me/drive/items/f1"),
    ]
    assert body_of(seen[0]) == {"name": "Reports", "folder": {}, "@microsoft.graph.conflictBehavior": "fail"}
    assert body_of(seen[1]) == {"parentReference": {"id": "d9"}, "name": "n.md"}
    assert body_of(seen[2]) == {"type": "view", "scope": "anonymous"}
    assert shared == {"item_id": "f1", "link": "https://1drv.ms/x", "type": "view", "scope": "anonymous"}
    assert deleted == {"deleted": True, "id": "f1"}


@pytest.mark.asyncio
async def test_share_link_defaults_to_an_organization_view_link():
    connector, seen = make_connector(ok({"link": {}}))
    result = await connector.create_share_link("f1", user_confirmed=True)
    assert body_of(seen[0]) == {"type": "view", "scope": "organization"}
    assert result["link"] is None and result["scope"] == "organization"
    with pytest.raises(ConnectorError, match="link_type"):
        await connector.create_share_link("f1", link_type="owner", user_confirmed=True)


# ---------------------------------------------------------------------------
# To Do
# ---------------------------------------------------------------------------

_TASK = {
    "id": "t1",
    "title": "Pay invoice",
    "status": "notStarted",
    "importance": "high",
    "dueDateTime": {"dateTime": "2026-10-05T00:00:00.0000000", "timeZone": "UTC"},
    "body": {"content": "n" * 900, "contentType": "text"},
    "linkedResources": [{"webUrl": "https://x"}],
}


@pytest.mark.asyncio
async def test_list_task_lists_and_tasks():
    lists = {"value": [{"id": "l1", "displayName": "Tasks", "isOwner": True, "wellknownListName": "defaultList"}]}
    connector, seen = make_connector(
        lambda r: httpx.Response(200, json=lists if r.url.path.endswith("/lists") else {"value": [_TASK]})
    )
    assert await connector.list_task_lists() == [
        {"id": "l1", "name": "Tasks", "is_owner": True, "well_known_name": "defaultList"}
    ]
    tasks = await connector.list_tasks("l/1")
    await connector.list_tasks("l1", status="completed", limit=2)
    await connector.list_tasks("l1", status="all")

    assert seen[0].url.raw_path == b"/v1.0/me/todo/lists"
    assert seen[1].url.raw_path.startswith(b"/v1.0/me/todo/lists/l%2F1/tasks?")
    assert seen[1].url.params["$filter"] == "status ne 'completed'"
    assert seen[2].url.params["$filter"] == "status eq 'completed'"
    assert seen[2].url.params["$top"] == "2"
    assert "$filter" not in seen[3].url.params
    assert tasks[0]["title"] == "Pay invoice"
    assert tasks[0]["due"] == "2026-10-05T00:00:00.0000000 (UTC)"
    assert len(tasks[0]["note"]) == 500 and tasks[0]["note_truncated"] is True
    assert "linkedResources" not in str(tasks)


_TODO_WRITES = [
    ("create_task", lambda c, **k: c.create_task("l1", "Call Bob", **k)),
    ("update_task", lambda c, **k: c.update_task("l1", "t1", title="New", **k)),
    ("complete_task", lambda c, **k: c.complete_task("l1", "t1", **k)),
    ("delete_task", lambda c, **k: c.delete_task("l1", "t1", **k)),
]


@pytest.mark.asyncio
@pytest.mark.parametrize(("action", "call"), _TODO_WRITES)
async def test_todo_writes_require_confirmation_before_any_request(action, call):
    connector, seen = make_connector(ok(_TASK))
    with pytest.raises(UserConfirmationRequired) as exc:
        await call(connector)
    assert exc.value.action == action
    assert seen == []
    await call(connector, user_confirmed=True)
    assert len(seen) == 1


@pytest.mark.asyncio
async def test_todo_write_requests():
    connector, seen = make_connector(lambda r: httpx.Response(204) if r.method == "DELETE" else httpx.Response(200, json=_TASK))
    await connector.create_task("l1", "Call Bob", note="re: lease", due_date="2026-10-05", importance="HIGH", user_confirmed=True)
    await connector.update_task("l1", "t1", due_date="2026-10-06", user_confirmed=True)
    await connector.complete_task("l1", "t1", user_confirmed=True)
    await connector.delete_task("l1", "t/1", user_confirmed=True)
    assert [(r.method, r.url.raw_path) for r in seen] == [
        ("POST", b"/v1.0/me/todo/lists/l1/tasks"),
        ("PATCH", b"/v1.0/me/todo/lists/l1/tasks/t1"),
        ("PATCH", b"/v1.0/me/todo/lists/l1/tasks/t1"),
        ("DELETE", b"/v1.0/me/todo/lists/l1/tasks/t%2F1"),
    ]
    assert body_of(seen[0]) == {
        "title": "Call Bob",
        "body": {"content": "re: lease", "contentType": "text"},
        "dueDateTime": {"dateTime": "2026-10-05T00:00:00", "timeZone": "UTC"},
        "importance": "high",
    }
    assert body_of(seen[1]) == {"dueDateTime": {"dateTime": "2026-10-06T00:00:00", "timeZone": "UTC"}}
    assert body_of(seen[2]) == {"status": "completed"}


@pytest.mark.asyncio
async def test_todo_validation():
    connector, seen = make_connector(ok(_TASK))
    with pytest.raises(ConnectorError, match="Nothing to update"):
        await connector.update_task("l1", "t1", user_confirmed=True)
    with pytest.raises(ConnectorError, match="date like"):
        await connector.create_task("l1", "x", due_date="next week", user_confirmed=True)
    with pytest.raises(ConnectorError, match="importance"):
        await connector.create_task("l1", "x", importance="urgent", user_confirmed=True)
    with pytest.raises(ConnectorError, match="list_id"):
        await connector.list_tasks("")
    assert seen == []


# ---------------------------------------------------------------------------
# Contacts
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_search_contacts_by_name_prefix_and_by_exact_email():
    contact = {
        "id": "c1",
        "displayName": "Bob O'Neil",
        "emailAddresses": [{"name": "Bob", "address": "bob@contoso.com"}, "junk"],
        "businessPhones": ["+1 555 0100"],
        "mobilePhone": "+1 555 0199",
        "companyName": "Contoso",
        "jobTitle": "PM",
        "homeAddress": {"street": "private"},
    }
    connector, seen = make_connector(ok({"value": [contact]}))
    result = await connector.search_contacts("O'Ne")
    await connector.search_contacts("bob@contoso.com", limit=1)

    assert seen[0].url.path == "/v1.0/me/contacts"
    assert seen[0].url.params["$filter"] == (
        "startswith(displayName,'O''Ne') or startswith(givenName,'O''Ne') or startswith(surname,'O''Ne')"
    )
    assert seen[1].url.params["$filter"] == "emailAddresses/any(a:a/address eq 'bob@contoso.com')"
    assert seen[1].url.params["$top"] == "1"
    assert result == [
        {
            "id": "c1",
            "name": "Bob O'Neil",
            "emails": ["bob@contoso.com"],
            "phones": ["+1 555 0199", "+1 555 0100"],
            "company": "Contoso",
            "job_title": "PM",
        }
    ]
