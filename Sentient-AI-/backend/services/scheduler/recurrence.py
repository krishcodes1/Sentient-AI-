"""Parses a scheduled task's recurrence (once, daily, weekdays, weekly or
monthly at a local HH:MM), finds its next occurrence in a time zone, and says
it in plain words.

Why it exists: the toolkit validates a new task with it, the sweeper moves a
claimed task to its next run with it, and cards, lists and chat commands
describe it with it, so all three agree. Standard library only (zoneinfo):
no croniter, no APScheduler.

Daylight saving time, decided once here:
- A local time that does not exist that day (inside a spring-forward gap,
  e.g. 02:30 on 2026-03-08 in New York) runs after the gap, shifted by its
  length (03:30 EDT): ``fold=0`` gives the offset before the transition.
- A local time that happens twice (inside the autumn fold, e.g. 01:30 on
  2026-11-01 in New York) runs once, at its first occurrence (EDT). The
  next occurrence is always found on a later local date, so the repeat is
  never scheduled.
"""

from __future__ import annotations

import calendar
import re
from dataclasses import dataclass
from datetime import date, datetime, time, timedelta, timezone
from typing import Any, Mapping, Optional
from zoneinfo import ZoneInfo

FREQS = ("once", "daily", "weekdays", "weekly", "monthly")
DAY_NAMES = ("mon", "tue", "wed", "thu", "fri", "sat", "sun")
_LONG_DAY_NAMES = ("Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday")
_SHORT_DAY_NAMES = ("Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun")
# Fixed English month names (calendar.month_abbr follows the process locale).
_MONTH_NAMES = ("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec")
# A once task's date may be at most this far ahead.
ONCE_HORIZON_DAYS = 365
# How many local dates next_after looks at before giving up. Every rule but
# a once has a match within 31 days; a once lies within the horizon.
_SEARCH_DAYS = ONCE_HORIZON_DAYS + 40
_TIME_RE = re.compile(r"([01]?\d|2[0-3]):([0-5]\d)")
_DATE_RE = re.compile(r"\d{4}-\d{2}-\d{2}")
_RECURRENCE_KEYS = frozenset({"freq", "time", "days", "day_of_month", "date"})


@dataclass(frozen=True)
class Recurrence:
    """One validated rule. ``days`` are weekday numbers (0 = Monday, weekly
    only); ``day_of_month`` is 1-31 or -1 for the last day (monthly only;
    29-31 run on the last day of a shorter month); ``on_date`` is the local
    date of a once task."""

    freq: str
    hour: int
    minute: int
    days: tuple[int, ...] = ()
    day_of_month: Optional[int] = None
    on_date: Optional[date] = None

    @property
    def time(self) -> str:
        return f"{self.hour:02d}:{self.minute:02d}"

    def to_dict(self) -> dict[str, Any]:
        """The JSON stored in ``scheduled_tasks.recurrence`` (and shown on
        cards): only the keys this frequency uses."""
        out: dict[str, Any] = {"freq": self.freq, "time": self.time}
        if self.freq == "weekly":
            out["days"] = [DAY_NAMES[d] for d in self.days]
        if self.freq == "monthly":
            out["day_of_month"] = self.day_of_month
        if self.freq == "once" and self.on_date is not None:
            out["date"] = self.on_date.isoformat()
        return out


def _parse_time(value: Any) -> tuple[Optional[tuple[int, int]], Optional[str]]:
    if not isinstance(value, str) or not _TIME_RE.fullmatch(value.strip()):
        return None, "'time' must be a 24-hour local time as HH:MM, e.g. '08:00' or '18:30'."
    hour, minute = value.strip().split(":")
    return (int(hour), int(minute)), None


def _parse_days(value: Any) -> tuple[Optional[tuple[int, ...]], Optional[str]]:
    items = [value] if isinstance(value, str) else value
    if not isinstance(items, (list, tuple)) or not items:
        return None, "'days' must list weekdays as mon, tue, wed, thu, fri, sat or sun."
    found: set[int] = set()
    for item in items:
        name = item.strip().lower()[:3] if isinstance(item, str) else ""
        if name not in DAY_NAMES:
            return None, "'days' must list weekdays as mon, tue, wed, thu, fri, sat or sun."
        found.add(DAY_NAMES.index(name))
    return tuple(sorted(found)), None


def _parse_day_of_month(value: Any) -> tuple[Optional[int], Optional[str]]:
    if isinstance(value, bool) or not isinstance(value, int):
        if isinstance(value, float) and value.is_integer():
            value = int(value)
        else:
            return None, "'day_of_month' must be a whole number from 1 to 31, or -1 for the last day."
    if value == -1 or 1 <= value <= 31:
        return value, None
    return None, "'day_of_month' must be a whole number from 1 to 31, or -1 for the last day."


def _parse_date(value: Any, today: Optional[date]) -> tuple[Optional[date], Optional[str]]:
    if not isinstance(value, str) or not _DATE_RE.fullmatch(value.strip()):
        return None, "'date' must be a local date as YYYY-MM-DD."
    try:
        parsed = date.fromisoformat(value.strip())
    except ValueError:
        return None, "'date' must be a real date as YYYY-MM-DD."
    if today is None:
        return parsed, None
    if parsed < today:
        return None, "That date has already passed."
    if parsed > today + timedelta(days=ONCE_HORIZON_DAYS):
        return None, f"A one-time task must be within {ONCE_HORIZON_DAYS} days."
    return parsed, None


def parse_recurrence(
    params: Mapping[str, Any], *, today: Optional[date] = None, check_date: bool = True
) -> tuple[Optional[Recurrence], Optional[str]]:
    """``(rule, None)`` for valid recurrence arguments, else ``(None, error)``.

    Reads ``freq``, ``time``, ``days`` (weekly), ``day_of_month`` (monthly)
    and ``date`` (once) and ignores other keys. ``today`` is the local date
    a once date is checked against (default: the server's today); a date
    before it or more than ONCE_HORIZON_DAYS after it is refused. With
    ``check_date`` False (a stored row) the date is only parsed."""
    freq = params.get("freq")
    if not isinstance(freq, str) or freq.strip().lower() not in FREQS:
        return None, "'freq' must be one of: once, daily, weekdays, weekly, monthly."
    freq = freq.strip().lower()
    clock, err = _parse_time(params.get("time"))
    if err or clock is None:
        return None, err
    hour, minute = clock

    days_value = params.get("days")
    has_days = days_value not in (None, [], ())
    if freq == "weekly":
        days, err = _parse_days(days_value) if has_days else (None, "A weekly task needs 'days', e.g. ['mon', 'wed'].")
        if err or days is None:
            return None, err
    elif has_days:
        return None, "'days' is only for a weekly task."
    else:
        days = ()

    dom_value = params.get("day_of_month")
    day_of_month: Optional[int] = None
    if freq == "monthly":
        if dom_value is None:
            return None, "A monthly task needs 'day_of_month' (1-31, or -1 for the last day)."
        day_of_month, err = _parse_day_of_month(dom_value)
        if err:
            return None, err
    elif dom_value is not None:
        return None, "'day_of_month' is only for a monthly task."

    date_value = params.get("date")
    on_date: Optional[date] = None
    if freq == "once":
        if date_value is None:
            return None, "A one-time task needs 'date' as YYYY-MM-DD."
        on_date, err = _parse_date(date_value, (today or date.today()) if check_date else None)
        if err:
            return None, err
    elif date_value is not None:
        return None, "'date' is only for a one-time task (freq 'once')."

    return (
        Recurrence(
            freq=freq,
            hour=hour,
            minute=minute,
            days=days,
            day_of_month=day_of_month,
            on_date=on_date,
        ),
        None,
    )


def recurrence_from_stored(stored: Any) -> Optional[Recurrence]:
    """The rule a stored row holds, or None when it is not a valid one (a
    corrupted row is never run). A once date is not checked against today
    here: a stored once task may be due today."""
    if not isinstance(stored, Mapping):
        return None
    params = {k: v for k, v in stored.items() if k in _RECURRENCE_KEYS}
    rule, _err = parse_recurrence(params, check_date=False)
    return rule


def _last_day(year: int, month: int) -> int:
    return calendar.monthrange(year, month)[1]


def _matches(rule: Recurrence, day: date) -> bool:
    if rule.freq == "once":
        return day == rule.on_date
    if rule.freq == "daily":
        return True
    if rule.freq == "weekdays":
        return day.weekday() < 5
    if rule.freq == "weekly":
        return day.weekday() in rule.days
    if rule.freq == "monthly" and rule.day_of_month is not None:
        last = _last_day(day.year, day.month)
        wanted = last if rule.day_of_month == -1 else min(rule.day_of_month, last)
        return day.day == wanted
    return False


def local_instant(day: date, hour: int, minute: int, tz: ZoneInfo) -> datetime:
    """The UTC instant of *hour*:*minute* on local *day* in *tz*. A time in
    a spring gap lands after it; a time in an autumn fold is its first
    occurrence (``fold=0`` in both cases, see the module docstring)."""
    local = datetime.combine(day, time(hour, minute)).replace(tzinfo=tz, fold=0)
    return local.astimezone(timezone.utc)


def next_after(rule: Recurrence, tz: ZoneInfo, after_utc: datetime) -> Optional[datetime]:
    """The first occurrence of *rule* in *tz* strictly after *after_utc*, as
    an aware UTC datetime; None when there is none (a once task whose time
    has passed)."""
    if after_utc.tzinfo is None:
        after_utc = after_utc.replace(tzinfo=timezone.utc)
    start = after_utc.astimezone(tz).date() - timedelta(days=1)
    for offset in range(_SEARCH_DAYS):
        day = start + timedelta(days=offset)
        if rule.freq == "once" and rule.on_date is not None and day > rule.on_date:
            return None
        if not _matches(rule, day):
            continue
        instant = local_instant(day, rule.hour, rule.minute, tz)
        if instant > after_utc:
            return instant
    return None


def _join(words: list[str]) -> str:
    if len(words) <= 1:
        return "".join(words)
    return ", ".join(words[:-1]) + " and " + words[-1]


def clock(hour: int, minute: int) -> str:
    """A time of day as people in the US read it: "8:00 AM", "12:30 PM".
    Cards, lists and chat commands show times this way; a task's stored
    rule keeps its 24-hour "HH:MM"."""
    try:
        hour, minute = int(hour) % 24, int(minute) % 60
    except (TypeError, ValueError):
        return ""
    return f"{hour % 12 or 12}:{minute:02d} {'AM' if hour < 12 else 'PM'}"


def ordinal(number: int) -> str:
    """1st, 2nd, 3rd, 4th, 11th, 12th, 13th, 21st... Never raises: what is
    not a whole number comes back as its own text."""
    if isinstance(number, bool) or not isinstance(number, int):
        return str(number)
    if 10 <= number % 100 <= 20:
        suffix = "th"
    else:
        suffix = {1: "st", 2: "nd", 3: "rd"}.get(number % 10, "th")
    return f"{number}{suffix}"


def every_words(minutes: Any) -> str:
    """How often something repeats, as a card says it: "every 90 minutes",
    "every hour", "every 2 hours", "every day", "every week". Used for page
    watches and triggers too, so every card counts time the same way."""
    if isinstance(minutes, bool) or not isinstance(minutes, int) or minutes <= 0:
        return "regularly"
    for size, unit in ((10080, "week"), (1440, "day"), (60, "hour"), (1, "minute")):
        if minutes % size == 0:
            count = minutes // size
            return f"every {unit}" if count == 1 else f"every {count} {unit}s"
    return "regularly"


def day_words(day: date, *, long: bool = False) -> str:
    """A date with its weekday, month and year: "Tue, Oct 20, 2026" (or
    "Tuesday, Oct 20, 2026" inside a sentence). Never the ISO form."""
    names = _LONG_DAY_NAMES if long else _SHORT_DAY_NAMES
    return f"{names[day.weekday()]}, {_MONTH_NAMES[day.month - 1]} {day.day}, {day.year}"


def phrase(rule: Recurrence) -> str:
    """The rule as the middle of a sentence: "every weekday at 8:00 AM",
    "on the 15th of every month at 9:00 AM", "once on Tuesday, Oct 20,
    2026 at 2:30 PM"."""
    at = f"at {clock(rule.hour, rule.minute)}"
    if rule.freq == "daily":
        return f"every day {at}"
    if rule.freq == "weekdays":
        return f"every weekday {at}"
    if rule.freq == "weekly":
        return f"every {_join([_LONG_DAY_NAMES[d] for d in rule.days])} {at}"
    if rule.freq == "monthly":
        if rule.day_of_month == -1:
            return f"on the last day of every month {at}"
        return f"on the {ordinal(rule.day_of_month or 1)} of every month {at}"
    if rule.freq == "once" and rule.on_date is not None:
        return f"once on {day_words(rule.on_date, long=True)} {at}"
    return at


def describe(rule: Recurrence) -> str:
    """The rule in a few words for lists (schedule.list, the schedules page,
    /schedules in Telegram and Slack): "Weekdays at 8:00 AM", "Mon and Wed
    at 6:00 PM", "The 15th of each month at 9:00 AM", "Once on Fri, Oct 2,
    2026 at 6:00 AM"."""
    at = f"at {clock(rule.hour, rule.minute)}"
    if rule.freq == "daily":
        return f"Every day {at}"
    if rule.freq == "weekdays":
        return f"Weekdays {at}"
    if rule.freq == "weekly":
        return f"{_join([_SHORT_DAY_NAMES[d] for d in rule.days])} {at}"
    if rule.freq == "monthly":
        if rule.day_of_month == -1:
            return f"Last day of the month {at}"
        return f"The {ordinal(rule.day_of_month or 1)} of each month {at}"
    if rule.freq == "once" and rule.on_date is not None:
        return f"Once on {day_words(rule.on_date)} {at}"
    return at[:1].upper() + at[1:]


def local_label(instant: Optional[datetime], tz: ZoneInfo) -> Optional[str]:
    """An instant as the owner reads it in *tz*: "Tue 2026-09-29 08:00"."""
    if instant is None:
        return None
    if instant.tzinfo is None:
        instant = instant.replace(tzinfo=timezone.utc)
    local = instant.astimezone(tz)
    return f"{_SHORT_DAY_NAMES[local.weekday()]} {local:%Y-%m-%d %H:%M}"


def short_when(instant: datetime, tz: ZoneInfo) -> str:
    """The delivery header's time: "Tue 08:00"."""
    if instant.tzinfo is None:
        instant = instant.replace(tzinfo=timezone.utc)
    local = instant.astimezone(tz)
    return f"{_SHORT_DAY_NAMES[local.weekday()]} {local:%H:%M}"
