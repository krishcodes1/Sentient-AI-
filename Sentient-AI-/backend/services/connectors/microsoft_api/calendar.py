"""Outlook calendar actions of the Microsoft 365 connector: list events in a
time window, find meeting times, list calendars, create, update, respond to
and delete events.

Why it exists: spec section 5.5 (Calendar row). ``services/connectors/microsoft.py``
mixes ``CalendarActions`` into ``MicrosoftConnector`` and lists
``CALENDAR_ACTIONS`` in its ``DEFINITION``.
Talks to Microsoft Graph ``/v1.0/me/calendarView``, ``/me/calendars``,
``/me/events`` and ``/me/calendar/getSchedule``. Depends on ``common.py``
(validation, shaping, paging), ``services/connectors/base.py`` and
``services/connectors/definition.py``.
"""

from __future__ import annotations

import re
from datetime import datetime, time, timedelta, timezone, tzinfo
from functools import lru_cache
from typing import Any, Optional
from urllib.parse import urlparse
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from services.agent.permissions import ActionCategory

from ..base import ConnectorError, UserConfirmationRequired, path_segment
from ..definition import ToolSpec, _schema
from ..shaping import clamp_limit
from .common import (
    MAX_LONG_TEXT,
    ME,
    GraphBase,
    address_of,
    choice,
    email_list,
    graph_time,
    json_object,
    malformed,
    optional_bool,
    optional_id,
    optional_text,
    parse_moment,
    recipients,
    require_id,
    require_text,
    sub,
    text_of,
    utc_iso,
    when_of,
)
from .common import time_zone as parse_time_zone

_DEFAULT_WINDOW = timedelta(days=7)
_MAX_WINDOW = timedelta(days=366)
_MAX_MEETING_WINDOW = timedelta(days=62)
_EVENT_FIELDS = (
    "id,subject,start,end,location,organizer,isAllDay,showAs,responseStatus,"
    "webLink,isOnlineMeeting,onlineMeeting"
)
_RESPONSES = ("accept", "tentative", "decline")
_RESPONSE_VERBS = {"accept": "accept", "tentative": "tentativelyAccept", "decline": "decline"}

# find_meeting_times: free/busy statuses that block a slot. "free" and
# "workingElsewhere" leave the person available; "unknown" is treated as
# busy so a slot is never offered on a guess.
_BLOCKING_STATUSES = frozenset({"busy", "oof", "tentative", "unknown"})
# Times come back in UTC because every free/busy request asks for it.
_PREFER_UTC = {"Prefer": 'outlook.timezone="UTC"'}
# The user's own calendar is read in pages of this size, up to the caps.
# Free time is only worked out from the whole calendar: a window whose
# events cannot all be read (too many events or pages, a next link that is
# refused or repeats) is refused, never guessed.
_OWN_EVENTS_PAGE = 200
_MAX_OWN_EVENTS = 1000
# Graph may ignore $top and send small pages, so the page cap is well above
# _MAX_OWN_EVENTS / _OWN_EVENTS_PAGE.
_MAX_OWN_PAGES = 20
_OWN_CALENDAR_PATH = "/calendarView"
_INCOMPLETE_CALENDAR = "Could not read the whole calendar for this window. Use a shorter window."
# A schedule with more entries than this is reported as unknown.
_MAX_SCHEDULE_ITEMS = 5000
# Suggested starts are rounded up to the next quarter hour.
_SLOT_STEP = timedelta(minutes=15)
# Inside one long free gap, further suggestions are at least this far apart
# (or one meeting length, if longer), on quarter-hour boundaries.
_MIN_SLOT_SPACING = timedelta(minutes=30)
_EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)
_FRACTION_RE = re.compile(r"(\.\d{1,6})\d*$")
_CLOCK_RE = re.compile(r"^(\d{2}):(\d{2})(?::(\d{2}))?")
_WEEKDAYS = ("monday", "tuesday", "wednesday", "thursday", "friday", "saturday", "sunday")
_UTC_NAMES = frozenset(
    {"utc", "etc/utc", "coordinated universal time", "tzone://microsoft/utc", "z"}
)
# Windows time-zone names Graph uses for working hours, mapped to IANA
# names (the CLDR windowsZones primary zone). A name missing here is tried
# as an IANA name; if that fails too, that person's working hours are not
# applied (their free/busy still is).
_WINDOWS_ZONES = {
    "gmt standard time": "Europe/London",
    "greenwich standard time": "Atlantic/Reykjavik",
    "w. europe standard time": "Europe/Berlin",
    "romance standard time": "Europe/Paris",
    "central europe standard time": "Europe/Budapest",
    "central european standard time": "Europe/Warsaw",
    "e. europe standard time": "Europe/Chisinau",
    "fle standard time": "Europe/Kiev",
    "gtb standard time": "Europe/Bucharest",
    "russian standard time": "Europe/Moscow",
    "turkey standard time": "Europe/Istanbul",
    "israel standard time": "Asia/Jerusalem",
    "egypt standard time": "Africa/Cairo",
    "south africa standard time": "Africa/Johannesburg",
    "arabian standard time": "Asia/Dubai",
    "pakistan standard time": "Asia/Karachi",
    "india standard time": "Asia/Kolkata",
    "bangladesh standard time": "Asia/Dhaka",
    "se asia standard time": "Asia/Bangkok",
    "singapore standard time": "Asia/Singapore",
    "china standard time": "Asia/Shanghai",
    "taipei standard time": "Asia/Taipei",
    "tokyo standard time": "Asia/Tokyo",
    "korea standard time": "Asia/Seoul",
    "w. australia standard time": "Australia/Perth",
    "e. australia standard time": "Australia/Brisbane",
    "aus eastern standard time": "Australia/Sydney",
    "new zealand standard time": "Pacific/Auckland",
    "hawaiian standard time": "Pacific/Honolulu",
    "alaskan standard time": "America/Anchorage",
    "pacific standard time": "America/Los_Angeles",
    "us mountain standard time": "America/Phoenix",
    "mountain standard time": "America/Denver",
    "central standard time": "America/Chicago",
    "canada central standard time": "America/Regina",
    "central america standard time": "America/Guatemala",
    "eastern standard time": "America/New_York",
    "atlantic standard time": "America/Halifax",
    "e. south america standard time": "America/Sao_Paulo",
}

Interval = tuple[datetime, datetime]

_EVENT_ID = {"type": "string", "description": "Event id from list_events", "required": True}
_ADDRESSES = {"type": "array", "items": {"type": "string"}}
_WALL_TIME = (
    "ISO 8601 date-time, e.g. 2026-10-01T09:00:00 (read in time_zone), or with an offset/Z"
)

CALENDAR_ACTIONS: tuple[ToolSpec, ...] = (
    ToolSpec(
        "list_events",
        "List Outlook calendar events between two times (default: the next 7 days), recurring events expanded.",
        ActionCategory.READ,
        _schema(
            start={"type": "string", "description": "Window start, ISO 8601 (default now, UTC if no offset)"},
            end={"type": "string", "description": "Window end, ISO 8601 (default start + 7 days)"},
            calendar_id={"type": "string", "description": "Calendar id from list_calendars (default: main calendar)"},
            limit={"type": "integer", "description": "How many (default 10, max 50)"},
        ),
        required_scope="calendar.read",
        starter=True,
    ),
    ToolSpec(
        "find_meeting_times",
        (
            "Suggest meeting times in a window when the user and the attendees are all free "
            "(busy, tentative and out-of-office time count as busy; attendees' working hours "
            "are respected when known). The user's own working hours are NOT applied, so give "
            "a window inside the user's working day. Time already past is skipped. "
            "Attendee free/busy needs a work or school account."
        ),
        ActionCategory.READ,
        _schema(
            attendees={**_ADDRESSES, "description": "Attendee email addresses (empty: only the user)"},
            start={"type": "string", "description": "Earliest time, ISO 8601", "required": True},
            end={"type": "string", "description": "Latest time, ISO 8601 (at most 62 days after start)", "required": True},
            duration_minutes={"type": "integer", "description": "Meeting length in minutes (default 30)"},
            limit={"type": "integer", "description": "How many suggestions (default 5, max 20)"},
        ),
        required_scope="calendar.read",
    ),
    ToolSpec(
        "list_calendars",
        "List the user's Outlook calendars (id, name, whether it is the default and editable).",
        ActionCategory.READ,
        _schema(limit={"type": "integer", "description": "How many (default 10, max 50)"}),
        required_scope="calendar.read",
    ),
    ToolSpec(
        "create_event",
        "Create an Outlook calendar event. Listing attendees sends them an invitation.",
        ActionCategory.WRITE,
        _schema(
            subject={"type": "string", "required": True},
            start={"type": "string", "description": _WALL_TIME, "required": True},
            end={"type": "string", "description": _WALL_TIME, "required": True},
            time_zone={"type": "string", "description": "e.g. UTC (default), Europe/London, Pacific Standard Time"},
            attendees={**_ADDRESSES, "description": "Attendee email addresses (they get an invitation)"},
            location={"type": "string"},
            body={"type": "string", "description": "Plain-text description"},
            calendar_id={"type": "string", "description": "Calendar id (default: main calendar)"},
        ),
        required_scope="calendar.write",
    ),
    ToolSpec(
        "update_event",
        "Change the subject, time, location or description of an Outlook event. Attendees are notified of changes.",
        ActionCategory.WRITE,
        _schema(
            event_id=_EVENT_ID,
            subject={"type": "string"},
            start={"type": "string", "description": _WALL_TIME},
            end={"type": "string", "description": _WALL_TIME},
            time_zone={"type": "string", "description": "Zone for start/end (default UTC)"},
            location={"type": "string"},
            body={"type": "string", "description": "Plain-text description"},
        ),
        required_scope="calendar.write",
    ),
    ToolSpec(
        "respond_to_invite",
        "Accept, tentatively accept or decline an Outlook meeting invitation.",
        ActionCategory.WRITE,
        _schema(
            event_id=_EVENT_ID,
            response={"type": "string", "enum": list(_RESPONSES), "required": True},
            comment={"type": "string", "description": "Optional note to the organizer"},
            send_response={"type": "boolean", "description": "Notify the organizer (default true)"},
        ),
        required_scope="calendar.write",
    ),
    ToolSpec(
        "delete_event",
        "Delete an Outlook calendar event. Always asks the user first.",
        ActionCategory.DELETE,
        _schema(event_id=_EVENT_ID),
        required_scope="calendar.write",
        always_confirm=True,
    ),
)


def _event_summary(event: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": text_of(event.get("id")),
        "subject": text_of(event.get("subject")),
        "start": when_of(event.get("start")),
        "end": when_of(event.get("end")),
        "all_day": event.get("isAllDay") is True,
        "location": text_of(sub(event, "location").get("displayName")),
        "organizer": address_of(event.get("organizer")),
        "show_as": text_of(event.get("showAs"), 32),
        "response": text_of(sub(event, "responseStatus").get("response"), 32),
        "online_meeting_url": text_of(sub(event, "onlineMeeting").get("joinUrl"), 2048),
        "web_link": text_of(event.get("webLink"), 2048),
    }


def _window(start: Any, end: Any, *, maximum: timedelta) -> tuple[datetime, datetime]:
    begin = parse_moment(start, "start") if start not in (None, "") else datetime.now(timezone.utc)
    finish = parse_moment(end, "end") if end not in (None, "") else begin + _DEFAULT_WINDOW
    if finish <= begin:
        raise ConnectorError("'end' must be after 'start'.")
    if finish - begin > maximum:
        raise ConnectorError(f"The time window is too long (at most {maximum.days} days).")
    return begin, finish


def _duration(value: Any) -> timedelta:
    """The meeting length from whole minutes, 5 to 1440 (default 30)."""
    if value is None:
        minutes = 30
    elif isinstance(value, int) and not isinstance(value, bool):
        minutes = value
    else:
        raise ConnectorError("'duration_minutes' must be a whole number of minutes.")
    if not 5 <= minutes <= 1440:
        raise ConnectorError("'duration_minutes' must be between 5 and 1440.")
    return timedelta(minutes=minutes)


# -- find_meeting_times: free/busy arithmetic --------------------------------


@lru_cache(maxsize=64)
def _resolve_zone(name: str) -> Optional[tzinfo]:
    """A tzinfo for a Graph time-zone name (UTC aliases, the common Windows
    names, or an IANA name), else ``None``."""
    key = name.strip()
    if key.lower() in _UTC_NAMES:
        return timezone.utc
    iana = _WINDOWS_ZONES.get(key.lower(), key)
    try:
        return ZoneInfo(iana)
    except (ZoneInfoNotFoundError, ValueError, OSError):
        return None


def _graph_moment(value: Any) -> Optional[datetime]:
    """An aware UTC datetime from a Graph ``dateTimeTimeZone``, else ``None``.

    Graph writes seven fractional digits (``12:00:00.0000000``); they are
    cut to the six Python reads. A value with no zone is read as UTC.
    """
    if not isinstance(value, dict):
        return None
    text = value.get("dateTime")
    if not isinstance(text, str) or not text.strip() or len(text) > 64:
        return None
    try:
        moment = datetime.fromisoformat(_FRACTION_RE.sub(r"\1", text.strip()))
    except ValueError:
        return None
    if moment.tzinfo is None:
        zone_name = value.get("timeZone")
        zone = _resolve_zone(zone_name) if isinstance(zone_name, str) and zone_name.strip() else timezone.utc
        if zone is None:
            return None
        moment = moment.replace(tzinfo=zone)
    return moment.astimezone(timezone.utc)


def _busy_interval(item: Any, status_key: str) -> tuple[bool, Optional[Interval]]:
    """``(readable, interval)`` for one calendar entry: the interval is set
    only when the entry blocks time; ``readable`` is False when a blocking
    entry has times that cannot be read (the whole schedule is then unknown)."""
    if not isinstance(item, dict) or item.get("isCancelled") is True:
        return True, None
    status = item.get(status_key)
    if not isinstance(status, str) or status.lower() not in _BLOCKING_STATUSES:
        return True, None
    start, end = _graph_moment(item.get("start")), _graph_moment(item.get("end"))
    if start is None or end is None:
        return False, None
    return True, ((start, end) if end > start else None)


def _busy_intervals(items: list[Any], status_key: str) -> Optional[list[Interval]]:
    """The blocking intervals of *items*, or ``None`` if one is unreadable."""
    intervals: list[Interval] = []
    for item in items:
        readable, interval = _busy_interval(item, status_key)
        if not readable:
            return None
        if interval is not None:
            intervals.append(interval)
    return intervals


def _schedule_busy_time(info: Optional[dict[str, Any]]) -> Optional[list[Interval]]:
    """An attendee's blocking intervals from one ``scheduleInformation``, or
    ``None`` when Graph returned no usable free/busy for them (missing,
    an ``error`` object, no item list, too many items, unreadable times).
    The error text itself is never used."""
    if not isinstance(info, dict) or info.get("error"):
        return None
    items = info.get("scheduleItems")
    if not isinstance(items, list) or len(items) > _MAX_SCHEDULE_ITEMS:
        return None
    return _busy_intervals(items, "status")


def _clock(value: Any) -> Optional[time]:
    """``08:00:00.0000000`` -> 08:00, else ``None``."""
    match = _CLOCK_RE.match(value) if isinstance(value, str) else None
    if match is None:
        return None
    hour, minute, second = int(match.group(1)), int(match.group(2)), int(match.group(3) or 0)
    if hour > 23 or minute > 59 or second > 59:
        return None
    return time(hour, minute, second)


def _outside_working_hours(hours: Any, begin: datetime, finish: datetime) -> Optional[list[Interval]]:
    """The parts of the window outside a person's working hours, or ``None``
    when the working hours are absent or cannot be read (not applied)."""
    if not isinstance(hours, dict):
        return None
    raw_days = hours.get("daysOfWeek")
    days = {
        _WEEKDAYS.index(day.lower())
        for day in (raw_days if isinstance(raw_days, list) else [])
        if isinstance(day, str) and day.lower() in _WEEKDAYS
    }
    opens, closes = _clock(hours.get("startTime")), _clock(hours.get("endTime"))
    zone_name = sub(hours, "timeZone").get("name")
    zone = _resolve_zone(zone_name) if isinstance(zone_name, str) and zone_name.strip() else None
    if not days or opens is None or closes is None or opens == closes or zone is None:
        return None
    working: list[Interval] = []
    day = begin.astimezone(zone).date() - timedelta(days=1)
    last = finish.astimezone(zone).date()
    while day <= last:
        if day.weekday() in days:
            start = datetime.combine(day, opens, tzinfo=zone)
            # Hours that end at or before they start run past midnight.
            end_day = day if closes > opens else day + timedelta(days=1)
            end = datetime.combine(end_day, closes, tzinfo=zone)
            working.append((start.astimezone(timezone.utc), end.astimezone(timezone.utc)))
        day += timedelta(days=1)
    # The gaps between working periods are the time outside them.
    return _free_gaps(begin, finish, working)


def _free_gaps(begin: datetime, finish: datetime, busy: list[Interval]) -> list[Interval]:
    """The parts of [begin, finish) not covered by any *busy* interval."""
    gaps: list[Interval] = []
    cursor = begin
    for start, end in sorted(busy):
        if start >= finish:
            break
        if end <= cursor:
            continue
        if start > cursor:
            gaps.append((cursor, start))
        cursor = max(cursor, end)
        if cursor >= finish:
            return gaps
    if cursor < finish:
        gaps.append((cursor, finish))
    return gaps


def _utc_now() -> datetime:
    """The current time (a seam so tests can pin the clock)."""
    return datetime.now(timezone.utc)


def _round_up(moment: datetime) -> datetime:
    remainder = (moment - _EPOCH) % _SLOT_STEP
    return moment + (_SLOT_STEP - remainder) if remainder else moment


def _slot_spacing(length: timedelta) -> timedelta:
    """Distance between suggestions inside one gap: the meeting length or
    30 minutes, whichever is longer, rounded up to a quarter hour."""
    spacing = max(length, _MIN_SLOT_SPACING)
    remainder = spacing % _SLOT_STEP
    return spacing + (_SLOT_STEP - remainder) if remainder else spacing


def _gap_starts(gap: Interval, length: timedelta, spacing: timedelta, limit: int) -> list[datetime]:
    """Up to *limit* quarter-hour meeting starts that fit inside *gap*."""
    gap_start, gap_end = gap
    starts: list[datetime] = []
    start = _round_up(gap_start)
    while start + length <= gap_end and len(starts) < limit:
        starts.append(start)
        start += spacing
    return starts


def _slots(gaps: list[Interval], length: timedelta, limit: int) -> list[dict[str, Any]]:
    """Up to *limit* suggestions in time order: each has a quarter-hour
    start, the meeting end, and how long everyone stays free.

    Every gap long enough first gives its earliest start; further starts
    inside long gaps (``_slot_spacing`` apart) are then taken round-robin,
    so a free day still yields several candidates while separate free
    periods are all represented.
    """
    if limit <= 0:
        return []
    spacing = _slot_spacing(length)
    per_gap = [
        (starts, gap_end)
        for (gap_start, gap_end) in gaps
        if (starts := _gap_starts((gap_start, gap_end), length, spacing, limit))
    ]
    chosen: list[tuple[datetime, datetime]] = []
    depth = 0
    while len(chosen) < limit and per_gap:
        per_gap = [(starts, gap_end) for starts, gap_end in per_gap if depth < len(starts)]
        for starts, gap_end in per_gap:
            chosen.append((starts[depth], gap_end))
            if len(chosen) >= limit:
                break
        depth += 1
    return [
        {"start": utc_iso(start), "end": utc_iso(start + length), "free_until": utc_iso(gap_end)}
        for start, gap_end in sorted(chosen)
    ]


def _meeting_result(
    suggestions: list[dict[str, Any]],
    length: timedelta,
    unknown: list[str],
    working_hours_from: list[str],
    *,
    reason: Optional[str] = None,
) -> dict[str, Any]:
    """The ``find_meeting_times`` payload; ``empty_reason`` explains an
    empty list (*reason*, or no common free time of that length)."""
    minutes = int(length.total_seconds() // 60)
    if suggestions:
        empty_reason = None
    else:
        empty_reason = reason or f"No common free time of {minutes} minutes in the window."
    return {
        "items": suggestions,
        "count": len(suggestions),
        "empty_reason": empty_reason,
        "unknown_availability": unknown,
        "working_hours_from": working_hours_from,
    }


def _event_path(event_id: str) -> str:
    return f"/events/{path_segment(event_id)}"


class CalendarActions(GraphBase):
    """Outlook calendar action coroutines (mixed into ``MicrosoftConnector``)."""

    # -- READ -------------------------------------------------------------

    async def list_events(
        self,
        start: Any = None,
        end: Any = None,
        calendar_id: Any = None,
        limit: Any = None,
    ) -> list[dict[str, Any]]:
        begin, finish = _window(start, end, maximum=_MAX_WINDOW)
        calendar = optional_id(calendar_id, "calendar_id")
        top = clamp_limit(limit)
        path = f"/calendars/{path_segment(calendar)}/calendarView" if calendar else "/calendarView"
        params = {
            "startDateTime": utc_iso(begin),
            "endDateTime": utc_iso(finish),
            "$top": top,
            "$select": _EVENT_FIELDS,
            "$orderby": "start/dateTime",
        }
        items = await self._graph_list(path, params, limit=top)
        return [_event_summary(item) for item in items]

    async def find_meeting_times(
        self,
        start: Any,
        end: Any,
        attendees: Any = None,
        duration_minutes: Any = None,
        limit: Any = None,
    ) -> dict[str, Any]:
        """Common free slots of the requested length inside the window.

        The user's own busy time comes from their calendar view and the
        attendees' from ``getSchedule``; both need only Calendars.Read.
        Busy, tentative, out-of-office and unknown time blocks a slot. An
        attendee whose free/busy Graph cannot return (an outside address,
        say) is listed under ``unknown_availability`` and left out. The
        part of the window already past is skipped; the user's own working
        hours are not known here and are not applied.
        """
        if start in (None, "") or end in (None, ""):
            raise ConnectorError("'start' and 'end' are required.")
        begin, finish = _window(start, end, maximum=_MAX_MEETING_WINDOW)
        people = email_list(attendees, "attendees", required=False)
        length = _duration(duration_minutes)
        candidates = clamp_limit(limit, default=5, maximum=20)
        # A meeting cannot start in the past: only the rest of the window counts.
        begin = max(begin, _utc_now())
        if begin >= finish:
            return _meeting_result([], length, [], [], reason="The window is already over.")

        busy = await self._own_busy_time(begin, finish)
        unknown: list[str] = []
        working_hours_from: list[str] = []
        if people:
            schedules = await self._schedules(people, begin, finish)
            for address in people:
                info = schedules.get(address.lower())
                intervals = _schedule_busy_time(info)
                if intervals is None:
                    unknown.append(address)
                    continue
                busy.extend(intervals)
                outside = _outside_working_hours(sub(info, "workingHours"), begin, finish)
                if outside is not None:
                    busy.extend(outside)
                    working_hours_from.append(address)

        suggestions = _slots(_free_gaps(begin, finish, busy), length, candidates)
        return _meeting_result(suggestions, length, unknown, working_hours_from)

    async def _own_busy_time(self, begin: datetime, finish: datetime) -> list[Interval]:
        """The user's blocking events in the window (UTC), from calendarView.

        Pages are followed explicitly (not through ``collect_pages``, which
        stops quietly) because a missed page would turn busy time into a
        suggested slot. The whole calendar is read or ``ConnectorError`` is
        raised: a next link still pending at the page or event cap, a next
        link ``_next_page_url`` refuses, or one that repeats.
        """
        params: Optional[dict[str, Any]] = {
            "startDateTime": utc_iso(begin),
            "endDateTime": utc_iso(finish),
            "$top": _OWN_EVENTS_PAGE,
            "$select": "showAs,start,end,isCancelled",
        }
        url = f"{ME}{_OWN_CALENDAR_PATH}"
        collection_path = urlparse(url).path
        events: list[Any] = []
        followed: set[str] = set()
        for _ in range(_MAX_OWN_PAGES):
            body = json_object(await self._request_json("GET", url, params=params, headers=_PREFER_UTC))
            page = body.get("value")
            if not isinstance(page, list):
                raise malformed()
            events.extend(page)
            link = body.get("@odata.nextLink")
            if link is None or link == "":
                break
            next_url = self._next_page_url(link, collection_path)
            if len(events) >= _MAX_OWN_EVENTS or next_url is None or next_url in followed:
                raise ConnectorError(_INCOMPLETE_CALENDAR)
            followed.add(next_url)
            url, params = next_url, None
        else:
            # The page cap was reached with a next link still pending.
            raise ConnectorError(_INCOMPLETE_CALENDAR)
        intervals = _busy_intervals(events, "showAs")
        if intervals is None:
            raise malformed()
        return intervals

    async def _schedules(
        self, people: list[str], begin: datetime, finish: datetime
    ) -> dict[str, dict[str, Any]]:
        """``getSchedule`` results keyed by lower-cased address."""
        payload = {
            "schedules": people,
            "startTime": {"dateTime": utc_iso(begin)[:-1], "timeZone": "UTC"},
            "endTime": {"dateTime": utc_iso(finish)[:-1], "timeZone": "UTC"},
            # The per-slot availabilityView string is not used; the widest
            # interval keeps it short.
            "availabilityViewInterval": 1440,
        }
        result = await self._graph_object(
            "POST", "/calendar/getSchedule", json=payload, headers=_PREFER_UTC
        )
        value = result.get("value")
        if not isinstance(value, list):
            raise malformed()
        found: dict[str, dict[str, Any]] = {}
        for info in value:
            schedule_id = info.get("scheduleId") if isinstance(info, dict) else None
            if isinstance(schedule_id, str) and schedule_id.strip():
                found.setdefault(schedule_id.strip().lower(), info)
        return found

    async def list_calendars(self, limit: Any = None) -> list[dict[str, Any]]:
        top = clamp_limit(limit)
        params = {"$top": top, "$select": "id,name,canEdit,isDefaultCalendar,owner"}
        items = await self._graph_list("/calendars", params, limit=top)
        return [
            {
                "id": text_of(item.get("id")),
                "name": text_of(item.get("name")),
                "is_default": item.get("isDefaultCalendar") is True,
                "can_edit": item.get("canEdit") is True,
                "owner": text_of(sub(item, "owner").get("address"), 320),
            }
            for item in items
        ]

    # -- WRITE ------------------------------------------------------------

    async def create_event(
        self,
        subject: Any,
        start: Any,
        end: Any,
        time_zone: Any = None,
        attendees: Any = None,
        location: Any = None,
        body: Any = None,
        calendar_id: Any = None,
        *,
        user_confirmed: bool = False,
    ) -> dict[str, Any]:
        title = require_text(subject, "subject", max_chars=255)
        zone = parse_time_zone(time_zone)
        start_at = graph_time(start, "start", zone)
        end_at = graph_time(end, "end", zone)
        people = email_list(attendees, "attendees", required=False)
        place = optional_text(location, "location", max_chars=255)
        notes = optional_text(body, "body", max_chars=MAX_LONG_TEXT)
        calendar = optional_id(calendar_id, "calendar_id")
        if not user_confirmed:
            invite = f" and send an invitation to {', '.join(people)}" if people else ""
            raise UserConfirmationRequired(
                action="create_event",
                details=(
                    f"Create the Outlook event '{title}' from {start_at['dateTime']} to "
                    f"{end_at['dateTime']} ({start_at['timeZone']}){invite}."
                ),
            )
        payload: dict[str, Any] = {"subject": title, "start": start_at, "end": end_at}
        if people:
            payload["attendees"] = [{"type": "required", **entry} for entry in recipients(people)]
        if place:
            payload["location"] = {"displayName": place}
        if notes:
            payload["body"] = {"contentType": "Text", "content": notes}
        path = f"/calendars/{path_segment(calendar)}/events" if calendar else "/events"
        created = await self._graph_object("POST", path, json=payload)
        return _event_summary(created)

    async def update_event(
        self,
        event_id: Any,
        subject: Any = None,
        start: Any = None,
        end: Any = None,
        time_zone: Any = None,
        location: Any = None,
        body: Any = None,
        *,
        user_confirmed: bool = False,
    ) -> dict[str, Any]:
        eid = require_id(event_id, "event_id")
        zone = parse_time_zone(time_zone)
        changes: dict[str, Any] = {}
        if subject is not None:
            changes["subject"] = require_text(subject, "subject", max_chars=255)
        if start not in (None, ""):
            changes["start"] = graph_time(start, "start", zone)
        if end not in (None, ""):
            changes["end"] = graph_time(end, "end", zone)
        if location is not None:
            changes["location"] = {"displayName": optional_text(location, "location", max_chars=255) or ""}
        if body is not None:
            changes["body"] = {
                "contentType": "Text",
                "content": optional_text(body, "body", max_chars=MAX_LONG_TEXT) or "",
            }
        if not changes:
            raise ConnectorError("Nothing to update: give at least one of subject, start, end, location, body.")
        if not user_confirmed:
            raise UserConfirmationRequired(
                action="update_event",
                details=(
                    f"Change {', '.join(sorted(changes))} of Outlook event {eid}; "
                    "attendees are notified of the change."
                ),
            )
        updated = await self._graph_object("PATCH", _event_path(eid), json=changes)
        return _event_summary(updated)

    async def respond_to_invite(
        self,
        event_id: Any,
        response: Any,
        comment: Any = None,
        send_response: Any = None,
        *,
        user_confirmed: bool = False,
    ) -> dict[str, Any]:
        eid = require_id(event_id, "event_id")
        if response is None:
            raise ConnectorError("'response' is required: accept, tentative or decline.")
        answer = choice(response, "response", _RESPONSES, default="accept")
        note = optional_text(comment, "comment", max_chars=MAX_LONG_TEXT)
        notify = optional_bool(send_response, "send_response", default=True)
        if not user_confirmed:
            told = " and tell the organizer" if notify else ""
            raise UserConfirmationRequired(
                action="respond_to_invite",
                details=f"Answer '{answer}' to the Outlook invitation {eid}{told}.",
            )
        payload: dict[str, Any] = {"sendResponse": notify}
        if note:
            payload["comment"] = note
        await self._graph("POST", f"{_event_path(eid)}/{_RESPONSE_VERBS[answer]}", json=payload)
        return {"event_id": eid, "response": answer, "organizer_notified": notify}

    # -- DELETE -----------------------------------------------------------

    async def delete_event(self, event_id: Any, *, user_confirmed: bool = False) -> dict[str, Any]:
        eid = require_id(event_id, "event_id")
        if not user_confirmed:
            raise UserConfirmationRequired(
                action="delete_event",
                # Graph cancels the meeting for everyone when its organizer
                # deletes it, so the card must say so.
                details=(
                    f"Delete Outlook calendar event {eid}. If you organized it and it "
                    "has attendees, they are sent a cancellation."
                ),
            )
        await self._graph_response("DELETE", _event_path(eid))
        return {"deleted": True, "id": eid}
