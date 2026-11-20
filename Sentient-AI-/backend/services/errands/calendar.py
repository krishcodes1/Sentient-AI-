"""Reads the owner's own calendar notes for the calendar finder: the Mac's
Calendar app through one osascript call, and Google Calendar through the
connector's get_events when the owner connected one.

Why it exists: the owner's errands start as notes on their own calendar
("order this perfume for my girlfriend", with a name and a link). This
install may have no Google sign-in, but the Mac's Calendar app already syncs
the owner's accounts, so it is read directly with AppleScript (no new
dependency; macOS asks the owner for the Automation permission the first
time). Both sources come back as ``CalendarEvent`` rows with a ``shared``
flag: an event with other people on it, or on a calendar the owner cannot
write to (subscriptions, holidays, birthdays, suggestions), or on Google one
the owner did not create (``creator_self``: Google marks the owner organizer
of every event on their own calendar, so a delegate's event there would
pass on that alone), is someone else's words, never an errand. A known
limit on the Mac: the Calendar app says who can write a calendar, not who
wrote an event, so an event someone else put on a shared calendar the owner
can write to (and with nobody invited) reads as the owner's own there. Read
the event's creator through EventKit if that ever matters.
Both name an event by its iCalendar uid (Google's ``iCalUID``, which
Calendar.app shows as the event's uid), so the two copies of one note, and
every occurrence of a recurring one, share a ``ref``; a Mac recurring series
is read as its next occurrence (``next_occurrence``), like Google's. A read
says whether it saw the whole window (``complete``), so a failed or
cut-short read never reads as "the event was deleted".

The osascript output is parsed, never evaluated: records end with ASCII 30,
fields with ASCII 31, both removed from every field by the script, and a
trailer record proves the output was not cut short. Logs carry counts and
statuses only, never a note.

Connects to: services/errands/finder.py (the only caller),
services/scheduler/briefing.py (``BriefingReader``, the gated and audited
read the Google source goes through), services/connectors/google_api/
calendar.py (get_events and its event shape).
"""

from __future__ import annotations

import asyncio
import calendar as month_days
import hashlib
import re
import sys
import uuid
from dataclasses import dataclass
from datetime import date, datetime, timedelta
from typing import Any, Mapping, Optional, Sequence

import structlog

logger = structlog.get_logger(__name__)

# Absolute, so a PATH entry ahead of /usr/bin can never stand in for it.
OSASCRIPT = "/usr/bin/osascript"
OSASCRIPT_TIMEOUT_S = 120.0
RS, US = "\x1e", "\x1f"
TRAILER = "CRAWLER-END"
# The Apple event errors that mean the owner has not allowed Crawler to
# control Calendar (errAEEventNotPermitted, errAEEventWouldRequireUserConsent).
_DENIED_MARKS = (b"-1743", b"-1744")
# get_events returns at most this many events a call (google_api/calendar.py
# MAX_EVENTS * EVENT_PAGES); a full page means there may be more.
GOOGLE_PAGE = 200
GOOGLE_MAX_PAGES = 5
_NOTE_CHARS = 4000
# An errand row keeps at most this much of a ref (models/errand.py).
REF_CHARS = 255
# A Google occurrence id without its iCalUID: "<series id>_20261220" or
# "<series id>_20261220T090000Z".
_OCCURRENCE_RE = re.compile(r"_\d{8}(?:T\d{6}Z?)?$")
_FREQS = {"DAILY", "WEEKLY", "MONTHLY", "YEARLY"}
_MAX_OCCURRENCES = 1000

# One call per scan: every event that starts in the window, from every
# calendar, with the fields the finder needs. Only a calendar the owner can
# write to makes the read partial when it cannot be read (Birthdays and
# subscriptions are never errands). Calendar is quit again when it was not
# running, so a daily scan leaves no window open on the owner's Mac. A
# recurring series comes back once, on its first day, with its rule.
# ponytail: a series whose first day is before the window is not listed (the
# app's query filters on that day), so on the Mac alone it never becomes an
# errand and its errand is never judged deleted; Google lists every
# occurrence. Query series by rule as well if that matters.
MAC_SCRIPT = """
on run argv
	set backDays to (item 1 of argv) as integer
	set aheadDays to (item 2 of argv) as integer
	set RS to character id 30
	set US to character id 31
	set d0 to current date
	set time of d0 to 0
	set d1 to d0 + aheadDays * days
	set d0 to d0 - backDays * days
	set partial to "0"
	set out to {}
	set wasRunning to application "Calendar" is running
	tell application "Calendar"
		with timeout of 100 seconds
			repeat with c in calendars
				set canWrite to "0"
				try
					if writable of c then set canWrite to "1"
				end try
				try
					set found to (every event of c whose start date is greater than or equal to d0 and start date is less than d1)
				on error
					set found to {}
					if canWrite is "1" then set partial to "1"
				end try
				repeat with e in found
					try
						set guests to "?"
						try
							set guests to (count of attendees of e) as text
						end try
						set rec to ""
					try
						set rec to my clean(recurrence of e)
					end try
					set end of out to my clean(uid of e) & US & my clean(summary of e) & US & my stamp(start date of e) & US & my clean(description of e) & US & my clean(url of e) & US & canWrite & US & guests & US & my stamp(stamp date of e) & US & rec & RS
					on error
						if canWrite is "1" then set partial to "1"
					end try
				end repeat
			end repeat
		end timeout
	end tell
	if not wasRunning then
		try
			tell application "Calendar" to quit
		end try
	end if
	set end of out to "CRAWLER-END" & US & partial & RS
	set AppleScript's text item delimiters to ""
	return out as text
end run

on clean(t)
	if t is missing value then return ""
	set t to t as text
	set AppleScript's text item delimiters to {character id 30, character id 31}
	set parts to text items of t
	set AppleScript's text item delimiters to " "
	set t to parts as text
	set AppleScript's text item delimiters to ""
	return t
end clean

on stamp(d)
	try
		return ((year of d) as text) & "-" & ((month of d as integer) as text) & "-" & ((day of d) as text) & " " & ((hours of d) as text) & ":" & ((minutes of d) as text) & ":" & ((seconds of d) as text)
	on error
		return ""
	end try
end stamp
"""


@dataclass(frozen=True)
class CalendarEvent:
    """One calendar event as the finder sees it. ``ref`` is its iCalendar
    uid (Google's ``iCalUID``, else "<series id>@google.com"), the same for
    both copies of a note and for every occurrence of a series; ``day`` the
    local date of the occurrence it is read as; ``listed`` the day the
    source listed it on when that differs (a Mac recurring series' first
    day, which the Calendar app's window filters on); ``updated`` when it
    last changed (None when the source does not say); ``source`` "mac" or
    "google"."""

    ref: str
    title: str
    notes: str
    url: str
    day: date
    shared: bool
    updated: Optional[datetime] = None
    source: str = "mac"
    listed: Optional[date] = None

    @property
    def window_day(self) -> date:
        """The day the source's read window matched this event on."""
        return self.listed or self.day

    @property
    def fingerprint(self) -> str:
        """What the event says, hashed: a changed note is a new fingerprint."""
        text = US.join((self.title, self.notes, self.url, self.day.isoformat()))
        return hashlib.sha256(text.encode("utf-8", "replace")).hexdigest()

    @property
    def text(self) -> str:
        """Everything the owner wrote on it (a link must appear here)."""
        return "\n".join(p for p in (self.title, self.notes, self.url) if p)


@dataclass(frozen=True)
class SourceRead:
    """One source's read. ``status``: "ok", "unavailable" (not on this
    computer or not connected), "denied" (the owner has not allowed it) or
    "failed". ``complete``: every event in the window was read."""

    status: str
    events: tuple[CalendarEvent, ...] = ()
    complete: bool = False


def _moment(text: str) -> Optional[datetime]:
    """A "Y-M-D H:M:S" local time from the script (no locale involved)."""
    try:
        day, clock = text.strip().split(" ")
        year, month, mday = (int(p) for p in day.split("-"))
        hour, minute, second = (int(p) for p in clock.split(":"))
        return datetime(year, month, mday, hour, minute, second)
    except ValueError:
        return None


def _add_months(first: date, months: int) -> Optional[date]:
    """*first* moved *months* ahead, None when that month has no such day."""
    year, month = divmod(first.month - 1 + months, 12)
    year += first.year
    if first.day > month_days.monthrange(year, month + 1)[1]:
        return None
    return first.replace(year=year, month=month + 1)


def next_occurrence(first: date, rule: str, today: date) -> Optional[date]:
    """The first day on or after *today* that a series starting on *first*
    falls on, from its RRULE ("FREQ=WEEKLY;INTERVAL=2;UNTIL=20271231T..."),
    or None when the series ended before today or the rule is not one of
    daily, weekly, monthly or yearly."""
    # ponytail: FREQ, INTERVAL, COUNT and UNTIL only; BYDAY and the like
    # are read as the series' own cadence from its first day.
    parts = dict(p.split("=", 1) for p in rule.upper().replace("RRULE:", "").split(";") if "=" in p)
    raw_until = parts.get("UNTIL", "")
    try:
        freq, interval = parts.get("FREQ", ""), int(parts.get("INTERVAL") or 1)
        count = int(parts["COUNT"]) if "COUNT" in parts else None
        until = (
            date(int(raw_until[:4]), int(raw_until[4:6]), int(raw_until[6:8]))
            if raw_until
            else None
        )
    except ValueError:
        return None
    if freq not in _FREQS or interval < 1:
        return None
    for n in range(_MAX_OCCURRENCES):
        if count is not None and n >= count:
            return None
        step = n * interval
        if freq == "DAILY":
            day: Optional[date] = first + timedelta(days=step)
        elif freq == "WEEKLY":
            day = first + timedelta(weeks=step)
        else:
            day = _add_months(first, step * (12 if freq == "YEARLY" else 1))
        if day is None:
            continue
        if until is not None and day > until:
            return None
        if day >= today:
            return day
    return None


def parse_mac_output(output: str, today: Optional[date] = None) -> SourceRead:
    """The events in one osascript output. Incomplete when the trailer is
    missing (the output was cut short), the script said a calendar or an
    event could not be read, or a record does not have its nine fields. A
    recurring series (listed on its first day) is read as its next
    occurrence from *today* (the local date)."""
    today = today or date.today()
    records = output.split(RS)
    trailer = next((r.strip() for r in reversed(records) if r.strip()), "")
    complete = trailer == f"{TRAILER}{US}0"
    events: list[CalendarEvent] = []
    for record in records:
        if not record.strip() or record.strip().startswith(TRAILER):
            continue
        fields = record.split(US)
        start = _moment(fields[2]) if len(fields) == 9 else None
        if start is None or not fields[0].strip():
            complete = False
            continue
        uid, title, _, notes, url, writable, guests, stamp, rule = fields
        changed = _moment(stamp)
        first = start.date()
        day = (next_occurrence(first, rule, today) or first) if rule.strip() else first
        events.append(
            CalendarEvent(
                ref=uid.strip()[:REF_CHARS],
                title=" ".join(title.split()),
                notes=notes.strip()[:_NOTE_CHARS],
                url=url.strip(),
                day=day,
                # Someone else's words: other people on it (or unknown), or a
                # calendar the owner cannot write to.
                shared=writable != "1" or guests.strip() != "0",
                # The script's times are local; astimezone reads them so.
                updated=changed.astimezone() if changed is not None else None,
                source="mac",
                listed=first if day != first else None,
            )
        )
    return SourceRead("ok", tuple(events), complete)


async def read_mac_calendar(back_days: int, ahead_days: int) -> SourceRead:
    """The Mac's Calendar app, from *back_days* before today to *ahead_days*
    after, in one osascript call under a timeout. "unavailable" off macOS,
    "denied" when the owner has not allowed Crawler to control Calendar."""
    if sys.platform != "darwin":
        logger.info("mac_calendar_unavailable", reason="not_macos")
        return SourceRead("unavailable")
    try:
        proc = await asyncio.create_subprocess_exec(
            OSASCRIPT,
            "-e",
            MAC_SCRIPT,
            str(int(back_days)),
            str(int(ahead_days)),
            stdin=asyncio.subprocess.DEVNULL,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
    except OSError as exc:
        logger.warning("mac_calendar_unavailable", error_type=type(exc).__name__)
        return SourceRead("unavailable")
    try:
        out, err = await asyncio.wait_for(proc.communicate(), timeout=OSASCRIPT_TIMEOUT_S)
    except asyncio.TimeoutError:
        logger.warning("mac_calendar_timed_out")
        return SourceRead("failed")
    finally:
        if proc.returncode is None:
            proc.kill()
            await proc.wait()
    if proc.returncode != 0:
        # The error text can quote an event, so only its kind is logged.
        denied = any(mark in err for mark in _DENIED_MARKS)
        logger.warning("mac_calendar_read_failed", denied=denied, code=proc.returncode)
        return SourceRead("denied" if denied else "failed")
    read = parse_mac_output(out.decode("utf-8", "replace"))
    logger.info("mac_calendar_read", events=len(read.events), complete=read.complete)
    return read


def google_event(raw: Any) -> Optional[CalendarEvent]:
    """One get_events row as a CalendarEvent; None for a cancelled event or
    one without an id or a start. Its ref is its ``iCalUID`` (one for every
    occurrence of a series, and the uid Calendar.app shows), else its series
    id. Shared unless the owner created it (``creator_self``; being its
    organizer is not enough, since every event on the owner's calendar
    has them as organizer) and nobody else is on it; Gmail's own events
    ("unknownorganizer@calendar.google.com") always are."""
    if not isinstance(raw, Mapping) or raw.get("status") == "cancelled":
        return None
    event_id, start = raw.get("id"), raw.get("start")
    when = start.get("date") or start.get("dateTime") if isinstance(start, Mapping) else None
    if not isinstance(event_id, str) or not event_id or not isinstance(when, str):
        return None
    try:
        day = date.fromisoformat(when[:10])
    except ValueError:
        return None
    uid = raw.get("iCalUID")
    ref = uid if isinstance(uid, str) and uid else f"{_OCCURRENCE_RE.sub('', event_id)}@google.com"
    organizer = str(raw.get("organizer") or "").lower()
    mine = raw.get("creator_self") is True
    return CalendarEvent(
        ref=ref[:REF_CHARS],
        title=" ".join(str(raw.get("summary") or "").split()),
        notes=str(raw.get("description") or "").strip()[:_NOTE_CHARS],
        url="",
        day=day,
        shared=(
            not mine or bool(raw.get("attendees")) or organizer.endswith("calendar.google.com")
        ),
        source="google",
    )


def _next_min(raw: Any) -> Optional[str]:
    """Where the next page starts: the last event's start (pages overlap a
    little; events are told apart by id). An all-day event starts a day
    early: Google matches timeMin against an event's end, so midnight UTC
    would skip that local morning's short events east of UTC."""
    start = raw.get("start") if isinstance(raw, Mapping) else None
    if not isinstance(start, Mapping):
        return None
    if isinstance(start.get("dateTime"), str):
        return str(start["dateTime"])
    if isinstance(start.get("date"), str):
        try:
            day = date.fromisoformat(start["date"]) - timedelta(days=1)
        except ValueError:
            return None
        return f"{day.isoformat()}T00:00:00Z"
    return None


async def read_google_calendar(
    reader: Any, user_id: str, accounts: Sequence[Any], start: datetime, end: datetime
) -> SourceRead:
    """Every connected Google account's primary calendar from *start* to
    *end*, a page of 200 at a time, through the briefing's gated and audited
    read. "unavailable" when no Google account is connected."""
    from services.scheduler.briefing import _items, tool_name

    mine = [a for a in accounts if a.connector_type == "google_workspace"]
    if reader is None or not mine:
        return SourceRead("unavailable")
    events: list[CalendarEvent] = []
    complete = True
    run_id = str(uuid.uuid4())
    for account in mine:
        name = tool_name(account, "get_events", accounts)
        seen: set[str] = set()
        time_min: Optional[str] = start.isoformat()
        for _page in range(GOOGLE_MAX_PAGES):
            arguments = {"time_min": time_min, "time_max": end.isoformat()}
            result, _reason = await reader.read(user_id, name, arguments, run_id)
            if result is None:
                logger.warning("google_calendar_read_failed")
                return SourceRead("failed")
            items = _items(result, "items", "events")
            fresh = [i for i in items if isinstance(i, Mapping) and i.get("id") not in seen]
            seen.update(str(i.get("id")) for i in fresh)
            events.extend(e for e in map(google_event, fresh) if e is not None)
            if len(items) < GOOGLE_PAGE:
                break
            time_min = _next_min(items[-1])
            if not fresh or time_min is None:
                complete = False
                break
        else:
            complete = False
    logger.info("google_calendar_read", events=len(events), complete=complete)
    return SourceRead("ok", tuple(events), complete)
