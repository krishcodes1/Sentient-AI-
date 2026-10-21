"""Plain words for every action Crawler can ask the owner to approve: the
approval card's first sentence, a short verb phrase for reply notes, the app's
everyday name, a label for each detail on the card and plain words for a few
fixed values.

Why it exists: approval cards and reply notes used to read like developer
logs ("Why: Tool 'system.install_capability' requires explicit user
approval", "Arguments: {...}", "Blocked by security policy: desktop.act").
The person reading them is not a developer, so every action that can stop
for an OK gets its words here, in one table, following
docs/bot-message-style.md:

- ``approval_sentence``: one plain sentence (two at most), verb first, built
  only from the call's own arguments ("Send an email to priya@acme.com from
  your Gmail"). It is the card's first line and the phone's notification
  preview. It never names a tool, never shows JSON, braces or dashes, and
  never invents a name it was not given: with only a message id it says
  "an email". Long free text (a subject, a title, text to type) may be
  clipped inside the sentence to about ``CLIP_CHARS`` characters with "…",
  because the card's details below always show it in full (spec F3).
  Recipients, amounts, links and paths are never clipped.
- ``short_phrase``: a lower-case verb phrase with no final period for reply
  notes ("I need your OK before I send an email", "Your safety settings
  didn't let me click or type in an app on your computer").
- ``app_name``: the app or place in everyday words ("Gmail", "OneDrive",
  "your computer", a tidied MCP server name).
- ``field_label``: the everyday label of one argument key ("To", "Starts",
  "Email ID"), per tool first, then shared, then a humanized fallback.
- ``field_value``: plain words for a known fixed value ("speech_to_text" is
  "Voice notes", "tentative" is "Maybe"), or None to show the value as is.

Tools that already state their card from facts (desktop.act, browser.act,
browser.checkout, memory.remember, watch, files, schedule, knowledge,
study.delete, triggers) keep their own describers; their sentences here are
the fallback for when a describer has nothing to say.

Pure module: standard library only, no I/O, no lookups and no imports from
services.agent, services.notifications or services.tools, so any layer can
use it. Every public function accepts anything (None, wrong types, odd
mappings) and never raises; the worst case is a plain generic sentence.
"""

from __future__ import annotations

import math
import re
from dataclasses import dataclass, field
from datetime import date, datetime
from typing import Any, Callable, Mapping, Optional

# How long free text (a subject, a title, text to type) may run inside a
# sentence before it is clipped with "…". The card's details show it whole.
CLIP_CHARS = 80

# The sentence when nothing better can be said (no usable tool name).
GENERIC_SENTENCE = "Take a step that needs your OK"
# The reply-note phrase for the same case.
GENERIC_PHRASE = "do that step"

# What the prompt guard stops is filed under two pseudo tool names
# (services/agent/runtime.py): "input" for the person's own message and
# "output" for my reply. They name no app, so they get their own phrase
# ("I didn't act on your message."). The reply the guard writes already
# explains the stop, so the chat channels' reply notes skip them
# (services/notifications/cards.turn_notes).
GUARD_PHRASES = {"input": "act on your message", "output": "send my reply"}

# Control characters, line and paragraph separators and the bidirectional
# overrides that could make a value look like a different line or reorder
# its text; each becomes a space before whitespace is collapsed.
_INVISIBLE_RE = re.compile(
    r"[\x00-\x1f\x7f-\x9f\u200e\u200f\u2028\u2029\u202a-\u202e\u2066-\u2069]"
)
# camelCase and PascalCase word boundaries ("searchNotes", "getHTMLPage").
_CAMEL_RE = re.compile(r"(?<=[a-z0-9])(?=[A-Z])|(?<=[A-Z])(?=[A-Z][a-z])")
_WORD_SPLIT_RE = re.compile(r"[\s_\-./:]+")
# Slack ids: channels (C, G, Z), direct messages (D) and people (U, W).
_SLACK_CHANNEL_ID_RE = re.compile(r"^[CGZ][A-Z0-9]{6,}$")
_SLACK_DM_ID_RE = re.compile(r"^D[A-Z0-9]{6,}$")
_SLACK_USER_ID_RE = re.compile(r"^[UW][A-Z0-9]{6,}$")
# A Gmail user label id ("Label_12"), as list_labels returns it.
_GMAIL_USER_LABEL_RE = re.compile(r"^Label_\d+$")
# An opaque folder id rather than a folder name (Outlook ids are long base64).
_OPAQUE_ID_RE = re.compile(r"^[A-Za-z0-9+/=_-]{32,}$")
_CLOCK_RE = re.compile(r"^(\d{1,2}):(\d{2})(?::\d{2})?$")

_MONTHS = ("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec")
_WEEKDAYS = ("Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun")
_DAY_NAMES = {
    "mon": "Monday",
    "tue": "Tuesday",
    "wed": "Wednesday",
    "thu": "Thursday",
    "fri": "Friday",
    "sat": "Saturday",
    "sun": "Sunday",
}

# Words kept in capitals, and brand spellings, when a key or a server name
# is turned into words.
_ACRONYMS = {
    "ai",
    "api",
    "csv",
    "db",
    "html",
    "id",
    "ip",
    "json",
    "mcp",
    "ocr",
    "pdf",
    "sms",
    "sql",
    "ui",
    "uri",
    "utc",
    "aws",
    "gcp",
    "crm",
    "rss",
    "ssh",
    "vpn",
}
_BRANDS = {
    "github": "GitHub",
    "gitlab": "GitLab",
    "youtube": "YouTube",
    "openai": "OpenAI",
    "hubspot": "HubSpot",
    "clickup": "ClickUp",
    "onedrive": "OneDrive",
    "sharepoint": "SharePoint",
    "linkedin": "LinkedIn",
    "paypal": "PayPal",
    "postgresql": "PostgreSQL",
    "mysql": "MySQL",
    "imessage": "iMessage",
    "icloud": "iCloud",
    "whatsapp": "WhatsApp",
}


# ---------------------------------------------------------------------------
# Small text helpers
# ---------------------------------------------------------------------------


def _one_line(text: str) -> str:
    """Text on one line: invisible and control characters become spaces and
    every run of whitespace becomes a single space."""
    return " ".join(_INVISIBLE_RE.sub(" ", text).split())


def _scalar_text(value: Any) -> str:
    """A string or a number as one tidy line; "" for anything else
    (None, booleans, lists, mappings, NaN)."""
    if isinstance(value, str):
        return _one_line(value)
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return ""
    try:
        if isinstance(value, float):
            if not math.isfinite(value):
                return ""
            return str(int(value)) if value.is_integer() else f"{value:g}"
        return str(value)
    except (ValueError, OverflowError):  # an int too long to print
        return ""


def _clip(text: str, limit: int = CLIP_CHARS) -> str:
    """Free text cut to about *limit* characters at a word, ending in "…"."""
    if len(text) <= limit:
        return text
    cut = text[: limit - 1]
    space = cut.rfind(" ")
    if space >= limit // 2:
        cut = cut[:space]
    return cut.rstrip(" ,;:.") + "…"


def _quote(text: str, limit: int = CLIP_CHARS) -> str:
    """Free text in straight quotes, clipped."""
    return f'"{_clip(text, limit)}"'


def _quote_whole(text: str) -> str:
    """A name or path in straight quotes, never clipped."""
    return f'"{text}"'


def _and(items: list[str]) -> str:
    """ "a", "a and b", "a, b and c"."""
    kept = [item for item in items if item]
    if len(kept) <= 1:
        return kept[0] if kept else ""
    return ", ".join(kept[:-1]) + " and " + kept[-1]


def _or(items: list[str]) -> str:
    kept = [item for item in items if item]
    if len(kept) <= 1:
        return kept[0] if kept else ""
    return ", ".join(kept[:-1]) + " or " + kept[-1]


def _count(n: int, singular: str, plural: Optional[str] = None) -> str:
    return f"{n} {singular if n == 1 else (plural or singular + 's')}"


def _sentences(*parts: str) -> str:
    """One sentence as is (no final period, like a card title), or several
    joined, each ending with a period."""
    kept = [part.strip() for part in parts if part and part.strip()]
    if len(kept) <= 1:
        return kept[0] if kept else ""
    return " ".join(part if part.endswith((".", "?", "!")) else part + "." for part in kept)


def _words(text: str) -> list[str]:
    """The words of an identifier: snake_case, kebab-case, dotted and
    camelCase all split; leading underscores and empty parts dropped."""
    return [word for word in _WORD_SPLIT_RE.split(_CAMEL_RE.sub(" ", text)) if word]


def _humanize(text: str) -> str:
    """An identifier as lower-case words, acronyms in capitals:
    "create_issue" is "create issue", "getHTMLPage" is "get HTML page"."""
    out = []
    for word in _words(text):
        lower = word.lower()
        if lower in _ACRONYMS:
            out.append(lower.upper())
        elif lower in _BRANDS:
            out.append(_BRANDS[lower])
        else:
            out.append(lower)
    return " ".join(out)


def _title_words(text: str) -> str:
    """An identifier as a name: every word capitalized ("brave_search" is
    "Brave Search", "github_mcp" is "GitHub MCP")."""
    out = []
    for word in _words(text):
        lower = word.lower()
        if lower in _BRANDS:
            out.append(_BRANDS[lower])
        elif lower in _ACRONYMS:
            out.append(lower.upper())
        else:
            out.append(word[:1].upper() + word[1:])
    return " ".join(out)


def _sentence_case(text: str) -> str:
    return text[:1].upper() + text[1:] if text else text


def _every(minutes: Optional[float]) -> str:
    """ "every 30 minutes", "every hour", "every 2 days"; "" when unknown."""
    span = _span(minutes)
    if not span:
        return ""
    return "every " + (span[2:] if span.startswith("1 ") else span)


def _span(minutes: Optional[float]) -> str:
    """ "30 minutes", "1 hour", "2 days", "1 week"; "" when unknown."""
    if minutes is None or minutes <= 0 or minutes > 10_000_000:
        return ""
    whole = int(minutes)
    if whole != minutes:
        return ""
    for size, unit in ((10080, "week"), (1440, "day"), (60, "hour")):
        if whole % size == 0:
            return _count(whole // size, unit)
    return _count(whole, "minute")


def _ordinal(n: int) -> str:
    """1 is "1st", 22 is "22nd", 13 is "13th"."""
    suffix = "th" if 10 <= n % 100 <= 20 else {1: "st", 2: "nd", 3: "rd"}.get(n % 10, "th")
    return f"{n}{suffix}"


def _money(amount: float) -> str:
    return f"${amount:,.2f}"


# ---------------------------------------------------------------------------
# Dates and times
# ---------------------------------------------------------------------------


def _clock(hour: int, minute: int) -> str:
    suffix = "AM" if hour < 12 else "PM"
    return f"{hour % 12 or 12}:{minute:02d} {suffix}"


def _day_text(day: date) -> str:
    return f"{_WEEKDAYS[day.weekday()]}, {_MONTHS[day.month - 1]} {day.day}, {day.year}"


def _zone_words(zone: str) -> str:
    """A time zone in everyday words: "America/New_York" is "New York
    time", "UTC" stays "UTC", "Pacific Standard Time" stays as it is."""
    text = _one_line(zone)
    if not text:
        return ""
    if text.upper() in {"UTC", "GMT", "Z", "ETC/UTC", "ETC/GMT", "ETC/ZULU", "ZULU"}:
        return "UTC"
    if "/" in text:
        city = text.rsplit("/", 1)[-1].replace("_", " ").strip()
        return f"{city} time" if city else ""
    return _clip(text.replace("_", " "), 40)


def _parse_moment(text: str) -> Optional[date]:
    """An ISO 8601 date or date-time, or None."""
    value = text.strip()
    if not value:
        return None
    try:
        if len(value) == 10:
            return date.fromisoformat(value)
        if value[-1:] in ("Z", "z"):
            value = value[:-1] + "+00:00"
        return datetime.fromisoformat(value)
    except (ValueError, TypeError, OverflowError):
        return None


# A whole ISO 8601 date or date-time, to the second, with an optional UTC
# offset. Anything else (fractions of a second, text around it) is left
# for a card to show exactly as written.
_ISO_MOMENT = re.compile(r"\d{4}-\d{2}-\d{2}(?:[T ]\d{2}:\d{2}(?::\d{2})?(?:[+-]\d{2}:\d{2}|[Zz])?)?")


def exact_moment(value: Any) -> Optional[str]:
    """An ISO 8601 date or date-time in everyday words with nothing lost,
    for an approval card's details: "2026-10-16T10:00:00-04:00" is "Fri,
    Oct 16, 2026 at 10:00 AM (UTC-4)". It keeps the wall time as written,
    its seconds when they are not zero and its offset from UTC ("UTC" for
    zero, nothing for a time without one), so it names the same moment.
    None for anything that is not exactly such a value. Never raises."""
    if not isinstance(value, str) or not _ISO_MOMENT.fullmatch(value):
        return None
    parsed = _parse_moment(value)
    if parsed is None:
        return None
    if not isinstance(parsed, datetime):
        return _day_text(parsed)
    clock = _clock(parsed.hour, parsed.minute)
    if parsed.second:
        clock = clock.replace(" ", f":{parsed.second:02d} ", 1)
    shown = f"{_day_text(parsed.date())} at {clock}"
    offset = parsed.utcoffset()
    if offset is None:
        return shown
    minutes = int(offset.total_seconds() // 60)
    if minutes == 0:
        return f"{shown} UTC"
    hours, rest = divmod(abs(minutes), 60)
    sign = "+" if minutes > 0 else "-"
    return f"{shown} (UTC{sign}{hours}{f':{rest:02d}' if rest else ''})"


def _moment(value: Any, zone: str = "", default_zone: str = "") -> str:
    """A date or time in everyday words ("Fri, Sep 25, 2026 at 10:00 AM").

    Takes an ISO string or a Google-style ``{"dateTime" | "date",
    "timeZone"}`` mapping. The wall time is shown as written (never
    converted); a named zone, a UTC time or *default_zone* (the zone a
    naive time is read in) is added. Text that is not a date comes back
    clipped as it is; "" when there is nothing.
    """
    if isinstance(value, Mapping):
        inner = _Args(value)
        raw = inner.raw("dateTime") or inner.raw("date")
        return _moment(raw, zone or inner.text("timeZone"), default_zone)
    text = _scalar_text(value)
    if not text:
        return ""
    parsed = _parse_moment(text)
    if parsed is None:
        return _clip(text)
    if not isinstance(parsed, datetime):
        return _day_text(parsed)
    shown = f"{_day_text(parsed.date())} at {_clock(parsed.hour, parsed.minute)}"
    named = _zone_words(zone)
    if named:
        return f"{shown} {named}"
    offset = parsed.utcoffset()
    if offset is not None:
        return f"{shown} UTC" if offset.total_seconds() == 0 else shown
    fallback = _zone_words(default_zone)
    return f"{shown} {fallback}" if fallback else shown


def _unix_moment(value: Any) -> str:
    """Unix seconds as this computer's local date and time; "" if unusable."""
    if isinstance(value, bool) or not isinstance(value, (int, float, str)):
        return ""
    try:
        moment = datetime.fromtimestamp(float(value))
    except (ValueError, OverflowError, OSError, TypeError):
        return ""
    return f"{_day_text(moment.date())} at {_clock(moment.hour, moment.minute)}"


def _time_of_day(value: str) -> str:
    """ "07:30" is "7:30 AM"; other text comes back clipped as it is."""
    match = _CLOCK_RE.match(value)
    if not match:
        return _clip(value, 20)
    hour, minute = int(match.group(1)), int(match.group(2))
    if hour > 23 or minute > 59:
        return _clip(value, 20)
    return _clock(hour, minute)


# ---------------------------------------------------------------------------
# Safe argument access
# ---------------------------------------------------------------------------


class _Args:
    """Read-only access to a call's arguments that never raises: anything
    that is not a mapping reads as empty, and a value of the wrong type
    reads as missing."""

    __slots__ = ("_raw",)

    def __init__(self, arguments: Any) -> None:
        self._raw: Mapping[Any, Any] = arguments if isinstance(arguments, Mapping) else {}

    def raw(self, key: str) -> Any:
        try:
            return self._raw.get(key)
        except Exception:
            return None

    def text(self, key: str) -> str:
        return _scalar_text(self.raw(key))

    def flag(self, key: str) -> Optional[bool]:
        value = self.raw(key)
        return value if isinstance(value, bool) else None

    def number(self, key: str) -> Optional[float]:
        value = self.raw(key)
        if isinstance(value, bool):
            return None
        if isinstance(value, str):
            try:
                value = float(value.strip().lstrip("$").replace(",", ""))
            except ValueError:
                return None
        if isinstance(value, (int, float)):
            try:
                number = float(value)
            except OverflowError:
                return None
            return number if math.isfinite(number) else None
        return None

    def texts(self, key: str) -> list[str]:
        """A list of strings (or one string) as tidy, non-empty items."""
        value = self.raw(key)
        if isinstance(value, (list, tuple)):
            return [item for item in (_scalar_text(v) for v in value) if item]
        item = _scalar_text(value)
        return [item] if item else []

    def size(self, key: str) -> Optional[int]:
        value = self.raw(key)
        return len(value) if isinstance(value, (list, tuple)) else None

    def mapping(self, key: str) -> _Args:
        return _Args(self.raw(key))

    def has(self, key: str) -> bool:
        """Whether the key carries a value (empty text, lists and mappings
        and None count as not given)."""
        value = self.raw(key)
        if value is None:
            return False
        if isinstance(value, str):
            return bool(value.strip())
        if isinstance(value, (list, tuple, dict)):
            return bool(value)
        return True

    def given(self, key: str) -> bool:
        """Whether the key is present at all, even with an empty value."""
        try:
            return key in self._raw
        except Exception:
            return False

    def keys(self) -> list[str]:
        try:
            return [key for key in self._raw.keys() if isinstance(key, str)]
        except Exception:
            return []


def _people(value: Any) -> list[str]:
    """Recipients or guests: strings, or mappings carrying an email or a
    name (Google attendees are ``{"email": ...}``)."""
    items = value if isinstance(value, (list, tuple)) else [value]
    out = []
    for item in items:
        if isinstance(item, Mapping):
            entry = _Args(item)
            text = (
                entry.text("email")
                or entry.text("address")
                or entry.text("name")
                or entry.text("displayName")
            )
            if not text:
                text = _Args(entry.raw("emailAddress")).text("address")
        else:
            text = _scalar_text(item)
        if text:
            out.append(text)
    return out


def _nouns(args: _Args, changes: tuple[tuple[tuple[str, ...], str], ...]) -> list[str]:
    """The plain nouns of the fields a call changes, in a fixed order and
    without repeats ("title", "time", "place")."""
    out: list[str] = []
    for keys, noun in changes:
        if noun not in out and any(args.has(key) for key in keys):
            out.append(noun)
    return out


# ---------------------------------------------------------------------------
# Built-in tools
# ---------------------------------------------------------------------------


# The add-ons system.install_capability can install, keyed by their
# services/tools/system.py ALLOWLIST name: the plain name for the card's
# details and the sentence. The sizes mirror each Installable.size_hint
# ("~150-300 MB download"); tests/test_action_text.py fails when they drift.
_ADDONS: dict[str, tuple[str, tuple[str, ...]]] = {
    "browser": (
        "Web browser",
        (
            "Install the web browser add-on so I can open websites, click around and take "
            "pictures of pages for you",
            "It's a one-time download of about 150 to 300 MB",
        ),
    ),
    "speech_to_text": (
        "Voice notes",
        (
            "Install the voice notes add-on so I can turn your Telegram voice notes into text "
            "on this computer",
            "It's a one-time download of about 250 MB, and your recordings never leave this "
            "computer",
        ),
    ),
}


def _s_install(a: _Args) -> str:
    name = a.text("name")
    addon = _ADDONS.get(name)
    if addon is not None:
        return _sentences(*addon[1])
    words = _clip(_humanize(name), 40)
    return (
        f"Install the {words} add-on on this computer"
        if words
        else "Install an add-on on this computer"
    )


_ON_COMPUTER = "in an app on your computer"


def _key_words(keys: str) -> str:
    """ "cmd+s" is "Cmd+S", "enter" is "Enter"."""
    return "+".join(part[:1].upper() + part[1:] for part in keys.split("+") if part) or keys


def _s_desktop_act(a: _Args) -> str:
    action = a.text("action").lower()
    app = _clip(a.text("app"), 40)
    if action in ("click", "double_click"):
        verb = "Click" if action == "click" else "Double-click"
        if not a.has("ref") and (a.has("x") or a.has("y")):
            return f"{verb} a spot on your screen"
        return f"{verb} an item {_ON_COMPUTER}"
    if action == "type":
        text = a.text("text")
        return f"Type {_quote(text)} {_ON_COMPUTER}" if text else f"Type {_ON_COMPUTER}"
    if action == "key":
        keys = _clip(a.text("keys"), 40)
        return f"Press {_key_words(keys)} {_ON_COMPUTER}" if keys else f"Press keys {_ON_COMPUTER}"
    if action == "scroll":
        direction = a.text("direction").lower()
        way = f" {direction}" if direction in ("up", "down") else ""
        return f"Scroll{way} {_ON_COMPUTER}"
    if action == "open_app":
        return f"Open {app} on your computer" if app else "Open an app on your computer"
    if action == "focus_window":
        return (
            f"Switch to {app} on your computer"
            if app
            else "Switch to another window on your computer"
        )
    return f"Click or type {_ON_COMPUTER}"


def _s_browser_act(a: _Args) -> str:
    action = a.text("action").lower()
    if action == "fill":
        text = a.text("text")
        return (
            f"Type {_quote(text)} into a field on a web page"
            if text
            else "Type into a field on a web page"
        )
    if action == "fill_form":
        count = a.size("fields")
        return (
            f"Fill in {_count(count, 'field')} on a web page"
            if count
            else "Fill in a form on a web page"
        )
    if action == "select":
        value = a.text("value")
        return (
            f"Pick {_quote(value)} in a list on a web page"
            if value
            else "Pick an option on a web page"
        )
    if action == "check":
        return "Tick a box on a web page"
    if action == "click":
        return "Click a button or link on a web page"
    if action == "press":
        key = _clip(a.text("key"), 20)
        return f"Press {key} on a web page" if key else "Press a key on a web page"
    if action == "submit":
        return "Send a form on a web page"
    return "Fill in or click on a web page"


def _s_checkout(a: _Args) -> str:
    merchant = a.text("merchant")
    amount = a.number("amount")
    note = a.text("note")
    where = merchant or "a website"
    first = (
        f"Pay {_money(amount)} to {where}" if amount is not None else f"Make a purchase on {where}"
    )
    return f"{first} for {_quote(note)}" if note else first


def _s_remember(a: _Args) -> str:
    content = a.text("content")
    return (
        f"Remember this about you: {_quote(content)}" if content else "Remember something about you"
    )


def _s_watch_create(a: _Args) -> str:
    url, label = a.text("url"), a.text("label")
    if label and url:
        page = f"{_quote(label)} ({url})"
    else:
        page = url or (_quote(label) if label else "a web page")
    every = _every(a.number("interval_minutes"))
    when = f" {every}" if every else ""
    return f"Check {page}{when} and message you when it changes"


def _s_files_forget(a: _Args) -> str:
    return _sentences(
        "Forget an uploaded file and delete the text I pulled from it",
        "Your original file isn't touched",
    )


def _schedule_when(a: _Args) -> str:
    """ "every weekday at 8:00 AM (New York time)" from a schedule's
    freq, time, days, day_of_month, date and timezone."""
    freq = a.text("freq").lower()
    time_text = a.text("time")
    at = f" at {_time_of_day(time_text)}" if time_text else ""
    days = [_DAY_NAMES.get(day.lower()[:3], _clip(day, 20)) for day in a.texts("days")]
    if freq == "once":
        on = _moment(a.raw("date"))
        when = f"once on {on}{at}" if on else f"once{at}"
    elif freq == "daily":
        when = f"every day{at}"
    elif freq == "weekdays":
        when = f"every weekday{at}"
    elif freq == "weekly":
        when = f"every {_and(days)}{at}" if days else f"every week{at}"
    elif freq == "monthly":
        day = a.number("day_of_month")
        if day == -1:
            when = f"on the last day of every month{at}"
        elif day is not None and 1 <= day <= 31 and day == int(day):
            when = f"on the {_ordinal(int(day))} of every month{at}"
        else:
            when = f"every month{at}"
    else:
        when = at.strip()
    zone = _zone_words(a.text("timezone"))
    return f"{when} ({zone})" if when and zone and at else when


_CHANNEL_WORDS = {"telegram": "Telegram", "slack": "Slack", "web": "the web app"}


def _channels(a: _Args) -> str:
    names = []
    for channel in a.texts("channels"):
        word = _CHANNEL_WORDS.get(channel.lower(), _clip(channel, 20))
        if word not in names:
            names.append(word)
    return _and(names)


def _s_schedule_create(a: _Args) -> str:
    label = a.text("label")
    what = f"the scheduled task {_quote(label)}" if label else "a scheduled task"
    when = _schedule_when(a)
    first = f"Set up {what} to run {when}" if when else f"Set up {what}"
    channels = _channels(a)
    return f"{first} and send you the result on {channels}" if channels else first


_SECTION_WORDS = {
    "canvas": "what's due on Canvas",
    "calendar": "today's calendar",
    "email": "important unread email",
}


def _s_schedule_briefing(a: _Args) -> str:
    when = _schedule_when(a)
    sections = [_SECTION_WORDS.get(s.lower(), _clip(s, 30)) for s in a.texts("sections")]
    topic = a.text("topic")
    first = f"Send you a briefing {when}" if when else "Send you a regular briefing"
    if sections:
        first += f" with {_and(sections)}"
    if topic:
        first += (
            f", plus news about {_quote(topic)}"
            if sections
            else f" with news about {_quote(topic)}"
        )
    channels = _channels(a)
    return f"{first} on {channels}" if channels else first


def _s_schedule_pause(a: _Args) -> str:
    paused = a.flag("paused")
    if paused is True:
        return _sentences("Pause a scheduled task", "It won't run until you turn it back on")
    if paused is False:
        return "Turn a scheduled task back on"
    return "Pause or resume a scheduled task"


_KNOWLEDGE_SOURCES = {
    "google_workspace": "Google Drive",
    "microsoft": "OneDrive",
    "canvas": "Canvas",
    "notion": "Notion",
}


def _s_knowledge_add(a: _Args) -> str:
    sources = []
    url = a.text("url")
    if url:
        sources.append(f"the web page {url}")
    ids = a.texts("ids")
    if ids:
        family = a.text("connector").split("__", 1)[0].lower()
        where = _KNOWLEDGE_SOURCES.get(family, "a connected app")
        sources.append(f"{_count(len(ids), 'item')} from {where}")
    file_ids = a.texts("file_ids")
    if file_ids:
        sources.append(_count(len(file_ids), "uploaded file"))
    if a.has("text"):
        title = a.text("title")
        sources.append(f"a note called {_quote(title)}" if title else "a note")
    collection = a.text("collection")
    what = _and(sources) or "something"
    under = f" under {_quote(collection)}" if collection else ""
    return f"Save {what} to your saved documents{under}"


def _s_knowledge_remove(a: _Args) -> str:
    collection = a.text("collection")
    if a.has("document_id"):
        under = f" under {_quote(collection)}" if collection else ""
        return f"Delete a document from your saved documents{under}"
    if collection:
        return f"Delete everything saved under {_quote(collection)} in your saved documents"
    return "Delete from your saved documents"


def _s_study_save(a: _Args) -> str:
    count = a.size("items")
    cards = _count(count, "flashcard") if count else "flashcards"
    title = a.text("title")
    if a.has("deck_id"):
        return f"Save {cards} to one of your decks"
    if title:
        return f"Save {cards} to a new deck called {_quote(title)}"
    return f"Save {cards} to a new deck"


def _s_study_edit(a: _Args) -> str:
    return "Change a flashcard" if a.has("item_id") else "Change a flashcard deck"


def _s_study_delete(a: _Args) -> str:
    count = a.size("item_ids")
    if count:
        first = f"Delete {_count(count, 'flashcard')} and their review history"
    else:
        first = "Delete a flashcard deck and its review history"
    return _sentences(first, "This can't be undone")


_RATING_WORDS = {"again": "Again", "hard": "Hard", "good": "Good", "easy": "Easy"}


def _s_study_review(a: _Args) -> str:
    action = a.text("action").lower()
    if action == "grade":
        rating = _RATING_WORDS.get(a.text("rating").lower())
        return (
            f"Record your flashcard answer as {_quote(rating)}"
            if rating
            else "Record a flashcard answer"
        )
    if action == "skip":
        return "Skip a flashcard"
    if action == "next":
        return "Show your next flashcard"
    return "Record a flashcard answer"


def _s_study_quiz(a: _Args) -> str:
    action = a.text("action").lower()
    return {
        "start": "Start a practice quiz",
        "reveal": "Show a practice quiz question",
        "submit": "Grade your practice quiz answers",
        "finish": "Finish your practice quiz",
    }.get(action, "Start or grade a practice quiz")


_TRIGGER_EVENTS = {
    "email.new": "a new email arrives",
    "canvas.announcement": "a new Canvas announcement is posted",
    "canvas.assignment": "a new Canvas assignment is posted",
    "canvas.grade": "a new grade is posted on Canvas",
    "calendar.starting_soon": "an event is about to start",
    "files.new_in_folder": "a new file lands in a folder",
    "page.changed": "a watched page changes",
}


def _trigger_when(a: _Args) -> str:
    source = a.text("source").lower()
    if source == "calendar.starting_soon":
        lead = _span(a.number("lead_minutes"))
        return f"{lead} before each event starts" if lead else "whenever an event is about to start"
    event = _TRIGGER_EVENTS.get(source, "something new happens")
    if source == "email.new":
        senders = a.texts("senders")
        if senders:
            event += f" from {_or(senders)}"
        subject = a.text("subject_contains")
        if subject:
            event += f" with {_quote(subject, 60)} in the subject"
    return f"whenever {event}"


def _s_triggers_create(a: _Args) -> str:
    when = _trigger_when(a)
    if a.text("mode").lower() == "run_task":
        prompt = a.text("prompt")
        action = f"run the task {_quote(prompt)} {when}" if prompt else f"run a task for you {when}"
    else:
        action = f"message you {when}"
    label = a.text("label")
    first = f"Set up {_quote(label)} to {action}" if label else _sentence_case(action)
    second = "It may suggest changes, but it asks you first" if a.flag("allow_writes") else ""
    return _sentences(first, second)


def _s_triggers_update(a: _Args) -> str:
    paused = a.flag("paused")
    if paused is True:
        return _sentences("Pause a trigger", "Nothing is checked or sent until you turn it back on")
    if paused is False:
        return "Turn a trigger back on"
    label = a.text("label")
    first = f"Change a trigger and rename it {_quote(label)}" if label else "Change a trigger"
    second = "It may suggest changes, but it asks you first" if a.flag("allow_writes") else ""
    return _sentences(first, second)


def _s_reminder_create(a: _Args) -> str:
    title = a.text("title")
    first = f"Remind you about {_quote(title)}" if title else "Set a reminder for you"
    when = _moment(a.raw("due_at"))
    if when:
        return f"{first} on {when}"
    later = _span(a.number("delay_minutes"))
    return f"{first} in {later}" if later else first


# ---------------------------------------------------------------------------
# Canvas
# ---------------------------------------------------------------------------


def _s_canvas_submit(a: _Args) -> str:
    data = a.mapping("submission_data")
    kind = data.text("submission_type").lower()
    url = data.text("url")
    if kind == "online_url" or (url and not kind):
        return (
            f"Hand in an assignment on Canvas with the link {url}"
            if url
            else "Hand in a link for an assignment on Canvas"
        )
    if kind == "online_text_entry":
        return "Hand in an assignment on Canvas as text"
    if kind == "online_upload":
        return "Hand in an assignment on Canvas as a file upload"
    return "Hand in an assignment on Canvas"


# ---------------------------------------------------------------------------
# Google Workspace
# ---------------------------------------------------------------------------


def _s_gmail_send(a: _Args) -> str:
    to = _and(a.texts("to"))
    return f"Send an email to {to} from your Gmail" if to else "Send an email from your Gmail"


def _s_gmail_reply(a: _Args) -> str:
    if a.flag("reply_all"):
        return "Reply to everyone on an email in your Gmail"
    return "Reply to an email in your Gmail"


def _s_gmail_forward(a: _Args) -> str:
    to = _and(a.texts("to"))
    first = (
        f"Forward an email from your Gmail to {to}" if to else "Forward an email from your Gmail"
    )
    return _sentences(first, "Attachments aren't included")


def _s_gmail_draft(a: _Args) -> str:
    to = _and(a.texts("to"))
    subject = a.text("subject")
    if to:
        first = f"Save a draft email to {to} in your Gmail"
    elif subject:
        first = f"Save a draft email {_quote(subject)} in your Gmail"
    else:
        first = "Save a draft email in your Gmail"
    return _sentences(first, "Nothing is sent")


_GMAIL_ADD = {
    "UNREAD": "mark it unread",
    "STARRED": "star it",
    "INBOX": "move it back to the inbox",
    "IMPORTANT": "mark it important",
    "TRASH": "move it to the trash",
    "SPAM": "mark it as spam",
}
_GMAIL_REMOVE = {
    "UNREAD": "mark it read",
    "STARRED": "unstar it",
    "INBOX": "archive it",
    "IMPORTANT": "mark it not important",
    "TRASH": "take it out of the trash",
    "SPAM": "take it out of spam",
}
_GMAIL_TABS = {
    "CATEGORY_PERSONAL": "Primary",
    "CATEGORY_SOCIAL": "Social",
    "CATEGORY_PROMOTIONS": "Promotions",
    "CATEGORY_UPDATES": "Updates",
    "CATEGORY_FORUMS": "Forums",
}


def _label_changes(labels: list[str], adding: bool) -> list[str]:
    """Plain words for one direction of a Gmail label change."""
    words = []
    own = 0
    system = _GMAIL_ADD if adding else _GMAIL_REMOVE
    for label in labels:
        upper = label.upper()
        if upper in system:
            words.append(system[upper])
        elif upper in _GMAIL_TABS:
            tab = _GMAIL_TABS[upper]
            words.append(f"move it to the {tab} tab" if adding else f"take it out of the {tab} tab")
        elif _GMAIL_USER_LABEL_RE.match(label):
            own += 1
        else:
            name = _quote(label, 40)
            words.append(f"add the label {name}" if adding else f"remove the label {name}")
    if own:
        what = "one of your labels" if own == 1 else f"{own} of your labels"
        words.append(f"add {what}" if adding else f"remove {what}")
    return words


def _s_gmail_labels(a: _Args) -> str:
    changes = _label_changes(a.texts("add_label_ids"), True) + _label_changes(
        a.texts("remove_label_ids"), False
    )
    unique = list(dict.fromkeys(changes))
    if not unique:
        return "Change labels on an email in your Gmail"
    return f"Change an email in your Gmail: {_and(unique)}"


def _s_gmail_trash(a: _Args) -> str:
    return _sentences(
        "Move an email to the trash in your Gmail", "Gmail deletes it for good after 30 days"
    )


def _s_gcal_create(a: _Args) -> str:
    event = a.mapping("event_data")
    title = event.text("summary")
    first = (
        f"Add {_quote(title)} to your Google Calendar"
        if title
        else "Add an event to your Google Calendar"
    )
    when = _moment(event.raw("start"))
    if when:
        first += f" on {when}"
    guests = _people(event.raw("attendees"))
    if guests:
        first += f" and invite {_and(guests)}"
    return first


_EVENT_CHANGES = (
    (("summary", "subject"), "title"),
    (("start", "end", "time_zone"), "time"),
    (("location",), "place"),
    (("description", "body"), "notes"),
    (("attendees",), "guest list"),
)


def _s_gcal_update(a: _Args) -> str:
    nouns = _nouns(a, _EVENT_CHANGES)
    first = (
        f"Change the {_and(nouns)} of an event in your Google Calendar"
        if nouns
        else "Change an event in your Google Calendar"
    )
    notify = a.has("attendees") and a.flag("notify_attendees") is not False
    return _sentences(first, "The guests get an email about it" if notify else "")


_GOOGLE_ANSWERS = {"accepted": "Accept", "declined": "Decline", "tentative": "Say maybe to"}


def _s_gcal_respond(a: _Args) -> str:
    verb = _GOOGLE_ANSWERS.get(a.text("response").lower())
    first = (
        f"{verb} an invitation in your Google Calendar"
        if verb
        else "Answer an invitation in your Google Calendar"
    )
    return _sentences(first, "The organizer will see your answer")


def _s_gcal_delete(a: _Args) -> str:
    second = "" if a.flag("notify_attendees") is False else "Any guests get a cancellation email"
    return _sentences("Delete an event from your Google Calendar", second)


def _s_drive_upload(a: _Args) -> str:
    name = a.text("name")
    return (
        f"Save a new file {_quote_whole(name)} to your Google Drive"
        if name
        else "Save a new file to your Google Drive"
    )


def _s_drive_folder(a: _Args) -> str:
    name = a.text("name")
    return (
        f"Make a new folder {_quote_whole(name)} in your Google Drive"
        if name
        else "Make a new folder in your Google Drive"
    )


def _s_drive_move(a: _Args) -> str:
    return "Move a file to another folder in your Google Drive"


def _s_drive_rename(a: _Args) -> str:
    name = a.text("name")
    return (
        f"Rename a file in your Google Drive to {_quote_whole(name)}"
        if name
        else "Rename a file in your Google Drive"
    )


_DRIVE_ROLES = {"reader": "view", "commenter": "comment on", "writer": "edit"}


def _s_drive_share(a: _Args) -> str:
    email = _and(a.texts("email"))
    if not email:
        return "Share a file from your Google Drive"
    first = f"Share a file from your Google Drive with {email}"
    role = _DRIVE_ROLES.get(a.text("role").lower())
    if role:
        first += f" so they can {role} it"
    second = "" if a.flag("notify") is False else "They get an email about it"
    return _sentences(first, second)


def _s_drive_trash(a: _Args) -> str:
    return _sentences(
        "Move a file to the trash in your Google Drive", "Drive deletes it for good after 30 days"
    )


def _s_docs_create(a: _Args) -> str:
    title = a.text("title")
    return f"Create a new Google Doc called {_quote(title)}" if title else "Create a new Google Doc"


def _s_docs_append(a: _Args) -> str:
    return "Add text to the end of a Google Doc"


def _s_docs_replace(a: _Args) -> str:
    find = a.text("find")
    replace_raw = a.raw("replace_with")
    replacement = a.text("replace_with")
    if find and replacement:
        return f"Change every {_quote(find, 60)} to {_quote(replacement, 60)} in a Google Doc"
    if find and isinstance(replace_raw, str):
        return f"Delete every {_quote(find, 60)} in a Google Doc"
    return "Replace text in a Google Doc"


def _s_sheets_update(a: _Args) -> str:
    cells = a.text("a1_range")
    return (
        f"Change the cells in {cells} of a Google Sheet"
        if cells
        else "Change cells in a Google Sheet"
    )


def _s_sheets_append(a: _Args) -> str:
    count = a.size("values")
    rows = _count(count, "row") if count else "rows"
    cells = a.text("a1_range")
    after = f" after the data in {cells}" if cells else ""
    return f"Add {rows} to a Google Sheet{after}"


def _s_sheets_tab(a: _Args) -> str:
    title = a.text("title")
    return (
        f"Add a new tab called {_quote(title)} to a Google Sheet"
        if title
        else "Add a new tab to a Google Sheet"
    )


def _s_sheets_clear(a: _Args) -> str:
    cells = a.text("a1_range")
    first = (
        f"Erase the cells in {cells} of a Google Sheet"
        if cells
        else "Erase cells in a Google Sheet"
    )
    return _sentences(first, "The formatting stays")


def _s_contact_create(a: _Args) -> str:
    name = _clip(" ".join(part for part in (a.text("given_name"), a.text("family_name")) if part))
    who = name or a.text("email")
    return (
        f"Add {who} to your Google Contacts" if who else "Add a new contact to your Google Contacts"
    )


_CONTACT_CHANGES = (
    (("given_name", "family_name"), "name"),
    (("email",), "email"),
    (("phone",), "phone number"),
    (("organization",), "company"),
    (("notes",), "notes"),
)


def _s_contact_update(a: _Args) -> str:
    nouns = _nouns(a, _CONTACT_CHANGES)
    if nouns:
        return f"Change the {_and(nouns)} of a contact in your Google Contacts"
    return "Change a contact in your Google Contacts"


def _s_contact_delete(a: _Args) -> str:
    return "Delete a contact from your Google Contacts"


# ---------------------------------------------------------------------------
# Robinhood
# ---------------------------------------------------------------------------


def _s_rh_portfolio(a: _Args) -> str:
    return _sentences(
        "Look at your Robinhood crypto portfolio", "This only reads it, nothing is bought or sold"
    )


def _s_rh_prices(a: _Args) -> str:
    coins = _and([_clip(symbol, 20) for symbol in a.texts("symbols")])
    first = f"Check Robinhood prices for {coins}" if coins else "Check crypto prices on Robinhood"
    return _sentences(first, "This only reads prices")


def _s_rh_holdings(a: _Args) -> str:
    return _sentences(
        "Look at the crypto you hold on Robinhood", "This only reads it, nothing is bought or sold"
    )


def _s_rh_trade(a: _Args) -> str:
    side = a.text("side").lower()
    symbol = _clip(a.text("symbol"), 20) or "crypto"
    verb = {"buy": "Buy", "sell": "Sell"}.get(side, "Buy or sell")
    return f"{verb} {symbol} on Robinhood"


# ---------------------------------------------------------------------------
# Slack
# ---------------------------------------------------------------------------


def _slack_name(value: str) -> str:
    """A channel's "#name" when the value is a name; "" for an id."""
    name = value.lstrip("#").strip()
    if not name or _SLACK_CHANNEL_ID_RE.match(name) or _SLACK_DM_ID_RE.match(name):
        return ""
    return f"#{name}"


def _slack_where(a: _Args) -> str:
    """ "in #general on Slack", "in a Slack channel" or "in a private Slack
    chat" (a direct-message id), from the channel argument."""
    value = a.text("channel")
    name = _slack_name(value)
    if name:
        return f"in {name} on Slack"
    if _SLACK_DM_ID_RE.match(value.lstrip("#")):
        return "in a private Slack chat"
    return "in a Slack channel"


def _emoji_words(name: str) -> str:
    """ ":palm_tree:" is "palm tree"."""
    return _clip(" ".join(_WORD_SPLIT_RE.split(name.strip(":"))).strip(), 30)


def _s_slack_post(a: _Args) -> str:
    return f"Post a message {_slack_where(a)}"


def _s_slack_reply(a: _Args) -> str:
    first = f"Reply in a thread {_slack_where(a)}"
    return (
        f"{first}, and show the reply in the channel too"
        if a.flag("also_send_to_channel")
        else first
    )


def _s_slack_react(a: _Args) -> str:
    emoji = _emoji_words(a.text("name"))
    where = _slack_where(a)
    return (
        f"React with the {emoji} emoji to a message {where}"
        if emoji
        else f"React to a message {where}"
    )


def _s_slack_upload(a: _Args) -> str:
    filename = a.text("filename")
    where = _slack_where(a)
    return (
        f"Share the file {_quote_whole(filename)} {where}" if filename else f"Share a file {where}"
    )


def _s_slack_status(a: _Args) -> str:
    text = a.text("text")
    emoji = _emoji_words(a.text("emoji"))
    if not text and not emoji:
        return "Clear your Slack status"
    first = (
        f"Set your Slack status to {_quote(text)}"
        if text
        else f"Set your Slack status to the {emoji} emoji"
    )
    lasting = _span(a.number("expires_in_minutes"))
    return f"{first} for {lasting}" if lasting else first


def _s_slack_create(a: _Args) -> str:
    name = a.text("name").lstrip("#").strip()
    kind = "private" if a.flag("is_private") else "public"
    return (
        f"Create a new {kind} Slack channel #{name}"
        if name
        else f"Create a new {kind} Slack channel"
    )


def _s_slack_invite(a: _Args) -> str:
    users = a.texts("users")
    named = [user for user in users if not _SLACK_USER_ID_RE.match(user.lstrip("@"))]
    unnamed = len(users) - len(named)
    if named and unnamed:
        who = f"{_and(named)} and {_count(unnamed, 'other person', 'other people')}"
    elif named:
        who = _and(named)
    elif unnamed:
        who = _count(unnamed, "person", "people")
    else:
        who = "people"
    channel = _slack_name(a.text("channel"))
    return f"Invite {who} to {channel} on Slack" if channel else f"Invite {who} to a Slack channel"


def _s_slack_schedule(a: _Args) -> str:
    first = f"Schedule a message {_slack_where(a)}"
    when = _unix_moment(a.raw("post_at"))
    return f"{first} for {when}" if when else first


def _s_slack_delete(a: _Args) -> str:
    return _sentences(f"Delete a message {_slack_where(a)}", "This can't be undone")


def _s_slack_archive(a: _Args) -> str:
    name = _slack_name(a.text("channel"))
    return f"Archive the Slack channel {name}" if name else "Archive a Slack channel"


# ---------------------------------------------------------------------------
# Microsoft
# ---------------------------------------------------------------------------


def _s_ms_send(a: _Args) -> str:
    to = _and(a.texts("to"))
    first = f"Send an email to {to} from your Outlook" if to else "Send an email from your Outlook"
    cc, bcc = _and(a.texts("cc")), _and(a.texts("bcc"))
    if cc:
        first += f", with a copy to {cc}"
    if bcc:
        first += f" and a hidden copy to {bcc}" if cc else f", with a hidden copy to {bcc}"
    return first


def _s_ms_reply(a: _Args) -> str:
    if a.flag("reply_all"):
        return "Reply to everyone on an email in your Outlook"
    return "Reply to an email in your Outlook"


def _s_ms_forward(a: _Args) -> str:
    to = _and(a.texts("to"))
    return (
        f"Forward an email from your Outlook to {to}"
        if to
        else "Forward an email from your Outlook"
    )


def _s_ms_draft(a: _Args) -> str:
    to = _and(a.texts("to"))
    subject = a.text("subject")
    if to:
        first = f"Save a draft email to {to} in your Outlook"
    elif subject:
        first = f"Save a draft email {_quote(subject)} in your Outlook"
    else:
        first = "Save a draft email in your Outlook"
    return _sentences(first, "Nothing is sent")


_OUTLOOK_FOLDERS = {
    "inbox": "Inbox",
    "sentitems": "Sent Items",
    "drafts": "Drafts",
    "archive": "Archive",
    "deleteditems": "Deleted Items",
    "junkemail": "Junk Email",
    "outbox": "Outbox",
    "recoverableitemsdeletions": "Recoverable Items",
}


def _s_ms_move(a: _Args) -> str:
    folder = a.text("destination_folder")
    known = _OUTLOOK_FOLDERS.get(folder.lower())
    if known:
        return f"Move an email in your Outlook to the {known} folder"
    if folder and not _OPAQUE_ID_RE.match(folder):
        return f"Move an email in your Outlook to the folder {_quote(folder, 40)}"
    return "Move an email in your Outlook to another folder"


def _s_ms_flag(a: _Args) -> str:
    status = a.text("status")
    if status == "complete":
        return "Mark an email's flag as done in your Outlook"
    if status == "notFlagged":
        return "Remove the flag from an email in your Outlook"
    return "Flag an email in your Outlook for follow up"


def _s_ms_delete_mail(a: _Args) -> str:
    return "Delete an email from your Outlook"


def _s_ms_event_create(a: _Args) -> str:
    subject = a.text("subject")
    first = (
        f"Add {_quote(subject)} to your Outlook calendar"
        if subject
        else "Add an event to your Outlook calendar"
    )
    # A start without an offset is read in time_zone, which defaults to UTC.
    when = _moment(a.raw("start"), a.text("time_zone"), "UTC")
    if when:
        first += f" on {when}"
    guests = _people(a.raw("attendees"))
    if guests:
        first += f" and invite {_and(guests)}"
    return first


def _s_ms_event_update(a: _Args) -> str:
    nouns = _nouns(a, _EVENT_CHANGES)
    if nouns:
        return f"Change the {_and(nouns)} of an event in your Outlook calendar"
    return "Change an event in your Outlook calendar"


_OUTLOOK_ANSWERS = {"accept": "Accept", "decline": "Decline", "tentative": "Say maybe to"}


def _s_ms_respond(a: _Args) -> str:
    verb = _OUTLOOK_ANSWERS.get(a.text("response").lower())
    first = (
        f"{verb} a meeting invitation in your Outlook"
        if verb
        else "Answer a meeting invitation in your Outlook"
    )
    if a.flag("send_response") is False:
        return _sentences(first, "The organizer isn't told")
    return _sentences(first, "The organizer will see your answer")


def _s_ms_event_delete(a: _Args) -> str:
    return "Delete an event from your Outlook calendar"


def _s_onedrive_upload(a: _Args) -> str:
    name = a.text("name")
    first = (
        f"Save a file {_quote_whole(name)} to your OneDrive"
        if name
        else "Save a file to your OneDrive"
    )
    return f"{first}, replacing any file with the same name" if a.flag("overwrite") else first


def _s_onedrive_folder(a: _Args) -> str:
    name = a.text("name")
    return (
        f"Make a new folder {_quote_whole(name)} in your OneDrive"
        if name
        else "Make a new folder in your OneDrive"
    )


def _s_onedrive_move(a: _Args) -> str:
    new_name = a.text("new_name")
    if a.has("destination_folder_id"):
        first = "Move a file or folder in your OneDrive to another folder"
        return f"{first} and rename it {_quote_whole(new_name)}" if new_name else first
    if new_name:
        return f"Rename a file or folder in your OneDrive to {_quote_whole(new_name)}"
    return "Move a file or folder in your OneDrive"


def _s_onedrive_link(a: _Args) -> str:
    who = (
        "anyone who has it"
        if a.text("scope").lower() == "anonymous"
        else "people in your organization"
    )
    can = "edit" if a.text("link_type").lower() == "edit" else "view"
    return f"Make a link that lets {who} {can} a file or folder in your OneDrive"


def _s_onedrive_delete(a: _Args) -> str:
    return _sentences("Delete a file or folder from your OneDrive", "It goes to the recycle bin")


def _s_todo_create(a: _Args) -> str:
    title = a.text("title")
    first = (
        f"Add the task {_quote(title)} to Microsoft To Do"
        if title
        else "Add a task to Microsoft To Do"
    )
    due = _moment(a.raw("due_date"))
    if due:
        first += f", due {due}"
    if a.text("importance").lower() == "high":
        first += ", marked important"
    return first


_TASK_CHANGES = (
    (("title",), "title"),
    (("note",), "note"),
    (("due_date",), "due date"),
    (("importance",), "importance"),
)


def _s_todo_update(a: _Args) -> str:
    nouns = _nouns(a, _TASK_CHANGES)
    if nouns:
        return f"Change the {_and(nouns)} of a task in Microsoft To Do"
    return "Change a task in Microsoft To Do"


def _s_todo_complete(a: _Args) -> str:
    return "Mark a task as done in Microsoft To Do"


def _s_todo_delete(a: _Args) -> str:
    return "Delete a task from Microsoft To Do"


# ---------------------------------------------------------------------------
# GitHub
# ---------------------------------------------------------------------------


def _repo(a: _Args) -> str:
    """ "octo/site on GitHub", or "a GitHub repository" when not given."""
    owner, repo = a.text("owner"), a.text("repo")
    if owner and repo:
        return f"{owner}/{repo} on GitHub"
    if repo:
        return f"{repo} on GitHub"
    return "a GitHub repository"


def _number(a: _Args) -> str:
    number = a.text("number")
    return f"#{number.lstrip('#')}" if number else ""


def _s_gh_create_repo(a: _Args) -> str:
    kind = "public" if a.flag("private") is False else "private"
    name = a.text("name")
    first = (
        f"Create a new {kind} GitHub repository {_quote_whole(name)}"
        if name
        else f"Create a new {kind} GitHub repository"
    )
    org = a.text("org")
    return f"{first} in {org}" if org else first


def _s_gh_create_branch(a: _Args) -> str:
    branch = a.text("branch")
    first = (
        f"Create the branch {_quote_whole(branch)} in {_repo(a)}"
        if branch
        else f"Create a branch in {_repo(a)}"
    )
    start = a.text("from_ref")
    return f"{first}, starting from {start}" if start else first


def _s_gh_put_file(a: _Args) -> str:
    path = a.text("path")
    first = f"Save the file {path} to {_repo(a)}" if path else f"Save a file to {_repo(a)}"
    branch = a.text("branch")
    return f"{first} on the branch {_quote_whole(branch)}" if branch else first


def _s_gh_delete_branch(a: _Args) -> str:
    branch = a.text("branch")
    return (
        f"Delete the branch {_quote_whole(branch)} from {_repo(a)}"
        if branch
        else f"Delete a branch from {_repo(a)}"
    )


def _s_gh_create_issue(a: _Args) -> str:
    title = a.text("title")
    first = f"Open an issue in {_repo(a)}"
    return f"{first}: {_quote(title)}" if title else first


def _s_gh_comment(a: _Args) -> str:
    number = _number(a)
    target = f"{number} in {_repo(a)}" if number else f"an issue or pull request in {_repo(a)}"
    return f"Post a comment under your name on {target}"


def _s_gh_update_issue(a: _Args) -> str:
    number = _number(a)
    issue = f"issue {number}" if number else "an issue"
    state = a.text("state").lower()
    reason = a.text("state_reason").lower()
    if state == "closed":
        how = {"completed": " as done", "not_planned": " as not planned"}.get(reason, "")
        return f"Close {issue} in {_repo(a)}{how}"
    if state == "open":
        return f"Reopen {issue} in {_repo(a)}"
    return f"Change {issue} in {_repo(a)}"


def _s_gh_create_pr(a: _Args) -> str:
    kind = "a draft pull request" if a.flag("draft") else "a pull request"
    first = f"Open {kind} in {_repo(a)}"
    head, base = a.text("head"), a.text("base")
    if head and base:
        first += f" to merge {head} into {base}"
    title = a.text("title")
    return f"{first}: {_quote(title)}" if title else first


def _s_gh_review(a: _Args) -> str:
    number = _number(a)
    pr = f"pull request {number}" if number else "a pull request"
    verb = {
        "approve": "Approve",
        "request_changes": "Ask for changes on",
        "comment": "Comment on",
    }.get(a.text("event").lower(), "Review")
    return f"{verb} {pr} in {_repo(a)} under your name"


def _s_gh_reviewers(a: _Args) -> str:
    people = a.texts("reviewers")
    teams = [f"the {team} team" for team in a.texts("team_reviewers")]
    who = _and(people + teams) or "people"
    number = _number(a)
    pr = f"pull request {number}" if number else "a pull request"
    return f"Ask {who} to review {pr} in {_repo(a)}"


def _s_gh_merge(a: _Args) -> str:
    number = _number(a)
    pr = f"pull request {number}" if number else "a pull request"
    how = {"squash": " as one combined commit", "rebase": " by rebasing it"}.get(
        a.text("merge_method").lower(), ""
    )
    return f"Merge {pr} in {_repo(a)}{how}"


def _s_gh_rerun(a: _Args) -> str:
    return f"Run the failed steps of an automated workflow in {_repo(a)} again"


def _s_gh_dispatch(a: _Args) -> str:
    workflow = a.text("workflow")
    first = (
        f"Start the workflow {_quote_whole(workflow)} in {_repo(a)}"
        if workflow
        else f"Start a workflow in {_repo(a)}"
    )
    ref = a.text("ref")
    return f"{first} on {ref}" if ref else first


def _s_gh_cancel(a: _Args) -> str:
    return f"Stop a running workflow in {_repo(a)}"


def _s_gh_notification(a: _Args) -> str:
    return "Mark a GitHub notification as read"


def _s_gh_create_release(a: _Args) -> str:
    tag = a.text("tag_name")
    first = (
        f"Create a draft release {tag} in {_repo(a)}"
        if tag
        else f"Create a draft release in {_repo(a)}"
    )
    return _sentences(first, "Nobody else sees it until you publish it")


def _s_gh_publish(a: _Args) -> str:
    return _sentences(
        f"Publish a draft release in {_repo(a)}",
        "It becomes public and people watching it are told",
    )


def _s_gh_gist(a: _Args) -> str:
    filename = a.text("filename")
    what = f"snippet {_quote_whole(filename)}" if filename else "snippet"
    if a.flag("public"):
        return f"Post a public {what} on GitHub Gist"
    return _sentences(
        f"Post a secret {what} on GitHub Gist", "Only people with the link can see it"
    )


# ---------------------------------------------------------------------------
# Notion
# ---------------------------------------------------------------------------


def _s_notion_create(a: _Args) -> str:
    title = a.text("title")
    return f"Create a Notion page called {_quote(title)}" if title else "Create a Notion page"


def _s_notion_append(a: _Args) -> str:
    return "Add content to a Notion page"


def _property_names(a: _Args) -> list[str]:
    return [
        _clip(_one_line(name), 40) for name in a.mapping("properties").keys() if _one_line(name)
    ]


def _s_notion_properties(a: _Args) -> str:
    names = _property_names(a)
    if names:
        return f"Change {_and(names)} on a Notion page"
    return "Change fields on a Notion page"


def _s_notion_row(a: _Args) -> str:
    props = a.mapping("properties")
    for key in ("Name", "Title", "name", "title"):
        title = props.text(key)
        if title:
            return f"Add {_quote(title)} as a row in a Notion database"
    return "Add a row to a Notion database"


def _s_notion_block(a: _Args) -> str:
    checked = a.flag("checked")
    if checked is not None and not a.has("text"):
        return "Tick a to-do on a Notion page" if checked else "Untick a to-do on a Notion page"
    return "Change one part of a Notion page"


def _s_notion_comment(a: _Args) -> str:
    if a.has("discussion_id"):
        return "Reply to a comment on a Notion page"
    return _sentences(
        "Post a comment on a Notion page", "Everyone who can open the page will see it"
    )


def _s_notion_archive(a: _Args) -> str:
    return "Move a Notion page and everything inside it to Notion's trash"


def _s_notion_delete_block(a: _Args) -> str:
    return _sentences("Delete one part of a Notion page", "It goes to Notion's trash")


# ---------------------------------------------------------------------------
# The table
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class _Entry:
    """One tool's words. ``sentence`` builds the card sentence from the
    arguments (None: the phrase, capitalized, is the sentence); ``app``
    overrides the family's app name; ``labels`` overrides shared labels."""

    phrase: str
    sentence: Optional[Callable[[_Args], str]] = None
    app: Optional[str] = None
    labels: Mapping[str, str] = field(default_factory=dict)


# The app or place of each tool family, in everyday words.
_FAMILY_APPS: dict[str, str] = {
    "system": "your computer",
    "desktop": "your computer",
    "browser": "the web browser",
    "web": "the web",
    "memory": "your saved memories",
    "watch": "your page watches",
    "files": "your uploaded files",
    "schedule": "your scheduled tasks",
    "knowledge": "your saved documents",
    "study": "your flashcards",
    "triggers": "your triggers",
    "reminders": "your reminders",
    "tutor": "tutor mode",
    "video": "video transcripts",
    "tools": "Crawler",
    "security": "Crawler's safety checks",
    "canvas": "Canvas",
    "google_workspace": "your Google account",
    "microsoft": "your Microsoft account",
    "github": "GitHub",
    "notion": "Notion",
    "slack": "Slack",
    "robinhood": "Robinhood",
    "mcp": "a connected app",
}

_GMAIL, _GCAL, _DRIVE, _DOCS, _SHEETS, _CONTACTS = (
    "Gmail",
    "Google Calendar",
    "Google Drive",
    "Google Docs",
    "Google Sheets",
    "Google Contacts",
)
_OUTLOOK, _ONEDRIVE, _TODO = "Outlook", "OneDrive", "Microsoft To Do"

_EMAIL_REF = {"message_id": "Email ID"}
_GH = {"owner": "Owner", "repo": "Repository"}
_SCHEDULE_LABELS = {
    "label": "Name",
    "prompt": "What to do each time",
    "freq": "How often",
    "time": "Time",
    "days": "Days",
    "day_of_month": "Day of the month",
    "date": "Date",
    "tools": "Can look at",
    "write_tools": "Asks you before",
    "timezone": "Time zone",
    "channels": "Send to",
    "sections": "Includes",
    "topic": "News topic",
    "summary": "Short summary at the top",
}
_TRIGGER_LABELS = {
    "trigger_id": "Trigger ID",
    "label": "Name",
    "source": "When",
    "account": "Account",
    "folder": "Folder",
    "watch_id": "Page watch ID",
    "mode": "Then",
    "senders": "From",
    "subject_contains": "Subject includes",
    "course_ids": "Course IDs",
    "show_score": "Include the score",
    "lead_minutes": "Minutes before",
    "prompt": "Task to run",
    "allow_writes": "Can suggest changes",
    "interval_minutes": "Check every",
    "max_runs_per_day": "Most runs a day",
    "paused": "Paused",
}

_TOOLS: dict[str, _Entry] = {
    # -- This computer and Crawler's own features --------------------------
    "system.install_capability": _Entry("install an add-on", _s_install, labels={"name": "Add-on"}),
    "system.capabilities": _Entry("check what this computer can do"),
    "desktop.act": _Entry(
        "click or type in an app on your computer",
        _s_desktop_act,
        labels={
            "action": "Action",
            "ref": "On-screen item",
            "x": "Screen position across",
            "y": "Screen position down",
            "text": "Text to type",
            "keys": "Keys",
            "direction": "Direction",
            "app": "App",
            "index": "Window number",
            "_screen": "Screen",
        },
    ),
    "desktop.observe": _Entry("look at the apps on your screen"),
    "desktop.screenshot": _Entry("take a picture of your screen"),
    "browser.act": _Entry(
        "fill in or click on a web page",
        _s_browser_act,
        labels={
            "action": "Action",
            "ref": "Page item",
            "text": "Text to type",
            "fields": "Fields to fill",
            "value": "Option to pick",
            "key": "Key",
            "_page": "Page",
        },
    ),
    "browser.checkout": _Entry(
        "pay for something on a website",
        _s_checkout,
        labels={
            "merchant": "Store",
            "amount": "Expected total",
            "note": "What you're buying",
            "_checkout": "Checkout",
        },
    ),
    "browser.read": _Entry("open a web page in the browser", labels={"url": "Link"}),
    "web.search": _Entry("search the web", labels={"query": "Search for"}),
    "web.fetch_page": _Entry("read a web page"),
    "web.research": _Entry("read several web pages", labels={"query": "Search for"}),
    "web.screenshot": _Entry("take a picture of a web page"),
    "memory.remember": _Entry(
        "remember something about you",
        _s_remember,
        labels={"content": "What I'll remember", "category": "Kind"},
    ),
    "watch.create": _Entry(
        "start watching a web page",
        _s_watch_create,
        labels={"url": "Page", "label": "Name", "interval_minutes": "Check every"},
    ),
    "watch.delete": _Entry(
        "stop watching a web page",
        lambda a: "Stop watching a web page for changes",
        labels={"watch_id": "Page watch ID"},
    ),
    "watch.list": _Entry("check your page watches"),
    "files.forget": _Entry(
        "forget an uploaded file", _s_files_forget, labels={"file_id": "File ID"}
    ),
    "files.read": _Entry("read an uploaded file"),
    "files.list": _Entry("list your uploaded files"),
    "schedule.create": _Entry(
        "set up a scheduled task", _s_schedule_create, labels=_SCHEDULE_LABELS
    ),
    "schedule.briefing": _Entry(
        "set up a regular briefing", _s_schedule_briefing, labels=_SCHEDULE_LABELS
    ),
    "schedule.pause": _Entry(
        "pause or resume a scheduled task",
        _s_schedule_pause,
        labels={"task_id": "Task ID", "paused": "Paused"},
    ),
    "schedule.delete": _Entry(
        "delete a scheduled task",
        lambda a: "Delete a scheduled task",
        labels={"task_id": "Task ID"},
    ),
    "schedule.list": _Entry("check your scheduled tasks"),
    "knowledge.add": _Entry(
        "save something to your documents",
        _s_knowledge_add,
        labels={
            "collection": "Save under",
            "url": "Web page",
            "connector": "From app",
            "ids": "Item IDs",
            "file_ids": "Uploaded file IDs",
            "text": "Note",
            "title": "Note title",
            "_knowledge": "Saved documents",
        },
    ),
    "knowledge.remove": _Entry(
        "delete saved documents",
        _s_knowledge_remove,
        labels={
            "document_id": "Document ID",
            "collection": "Saved under",
            "_knowledge": "Saved documents",
        },
    ),
    "knowledge.search": _Entry("search your saved documents"),
    "knowledge.read": _Entry("read a saved document"),
    "knowledge.list": _Entry("list your saved documents"),
    "study.save": _Entry(
        "save flashcards",
        _s_study_save,
        labels={
            "deck_id": "Deck ID",
            "title": "New deck name",
            "course": "Course",
            "source_kind": "Made from",
            "source_ref": "Source",
            "items": "Cards",
        },
    ),
    "study.edit": _Entry(
        "change a flashcard deck",
        _s_study_edit,
        labels={"deck_id": "Deck ID", "item_id": "Card ID", "in_reviews": "Include in reviews"},
    ),
    "study.delete": _Entry(
        "delete flashcards",
        _s_study_delete,
        labels={"deck_id": "Deck ID", "item_ids": "Card IDs", "_deck": "Deck"},
    ),
    "study.review": _Entry(
        "record a flashcard answer",
        _s_study_review,
        labels={"item_id": "Card ID", "rating": "Your answer", "deck_id": "Deck ID"},
    ),
    "study.quiz": _Entry(
        "start or grade a practice quiz",
        _s_study_quiz,
        labels={"attempt_id": "Quiz ID", "item_id": "Question ID", "deck_id": "Deck ID"},
    ),
    "study.settings": _Entry(
        "change your study reminder and limits",
        lambda a: "Change your study reminder and daily limits",
        labels={
            "reminder": "Daily reminder",
            "hour": "Reminder hour",
            "new_per_day": "New cards a day",
            "session_size": "Cards per session",
        },
    ),
    "study.decks": _Entry("look at your flashcards"),
    "study.progress": _Entry("check your study progress"),
    "study.export": _Entry("export a flashcard deck"),
    "triggers.create": _Entry(
        "set up a trigger",
        _s_triggers_create,
        labels={**_TRIGGER_LABELS, "_account": "Account", "_trigger": "Trigger"},
    ),
    "triggers.update": _Entry(
        "change a trigger",
        _s_triggers_update,
        labels={**_TRIGGER_LABELS, "label": "New name", "_trigger": "Trigger"},
    ),
    "triggers.delete": _Entry(
        "delete a trigger",
        lambda a: "Delete a trigger and anything it was about to send",
        labels={"trigger_id": "Trigger ID", "_trigger": "Trigger"},
    ),
    "triggers.list": _Entry("check your triggers"),
    "triggers.history": _Entry("check your triggers"),
    "reminders.create": _Entry(
        "set a reminder",
        _s_reminder_create,
        labels={
            "title": "Reminder",
            "note": "Details",
            "due_at": "When",
            "delay_minutes": "In minutes",
        },
    ),
    "reminders.cancel": _Entry(
        "cancel a reminder",
        lambda a: "Cancel one of your reminders",
        labels={"reminder_id": "Reminder ID"},
    ),
    "reminders.list": _Entry("check your reminders"),
    "reminders.now": _Entry("check the time"),
    "tutor.start": _Entry("switch to tutor mode"),
    "video.transcript": _Entry("get a video's transcript"),
    "video.list": _Entry("list your saved transcripts"),
    "tools.find": _Entry("look up what I can do"),
    # Security wave (security10): the safety checks' own actions (S3, S10).
    # An upload card's sentence comes from the file reputation toolkit's
    # describer (it names the file and what VirusTotal does with it).
    "security.check_scam": _Entry("check a message or link for signs of a scam"),
    "security.check_file": _Entry("check a file with VirusTotal"),
    "security.upload_to_virustotal": _Entry(
        "send a file to VirusTotal to be scanned",
        labels={"sha256": "File fingerprint", "file_name": "File"},
    ),
    # -- Canvas ---------------------------------------------------------------
    "canvas.submit_assignment": _Entry(
        "hand in an assignment",
        _s_canvas_submit,
        labels={
            "course_id": "Course ID",
            "assignment_id": "Assignment ID",
            "submission_data": "Submission",
            "submission_type": "Type",
            "submission_data.submission_type": "Type",
            "submission_data.body": "Text",
            "submission_data.url": "Link",
            "submission_data.file_ids": "File IDs",
        },
    ),
    "canvas.get_courses": _Entry("check your Canvas courses"),
    "canvas.get_assignments": _Entry("check your Canvas assignments"),
    "canvas.get_upcoming": _Entry("check what's due on Canvas"),
    "canvas.get_grades": _Entry("check your Canvas grades"),
    "canvas.grade_whatif": _Entry("work out a grade on Canvas"),
    "canvas.get_calendar_events": _Entry("check your Canvas calendar"),
    "canvas.get_submissions": _Entry("check your Canvas submissions"),
    "canvas.get_announcements": _Entry("check Canvas announcements"),
    "canvas.get_recent_grades": _Entry("check your recent Canvas grades"),
    "canvas.list_files": _Entry("look through Canvas course files"),
    "canvas.get_file_text": _Entry("read a Canvas course file"),
    # -- Gmail ----------------------------------------------------------------
    "google_workspace.send_email": _Entry("send an email", _s_gmail_send, _GMAIL),
    "google_workspace.reply": _Entry(
        "reply to an email",
        _s_gmail_reply,
        _GMAIL,
        {
            **_EMAIL_REF,
            "message_id": "Replying to email ID",
            "body": "Your reply",
            "reply_all": "Reply to everyone",
        },
    ),
    "google_workspace.forward": _Entry(
        "forward an email",
        _s_gmail_forward,
        _GMAIL,
        {"message_id": "Email ID", "note": "Your note"},
    ),
    "google_workspace.create_draft": _Entry("save an email draft", _s_gmail_draft, _GMAIL),
    "google_workspace.send_draft": _Entry(
        "send an email draft",
        lambda a: "Send a saved draft email from your Gmail",
        _GMAIL,
        {"draft_id": "Draft ID"},
    ),
    "google_workspace.modify_labels": _Entry(
        "change labels on an email",
        _s_gmail_labels,
        _GMAIL,
        {**_EMAIL_REF, "add_label_ids": "Add labels", "remove_label_ids": "Remove labels"},
    ),
    "google_workspace.trash_message": _Entry(
        "move an email to the trash", _s_gmail_trash, _GMAIL, _EMAIL_REF
    ),
    "google_workspace.get_messages": _Entry("check your email", app=_GMAIL),
    "google_workspace.get_message": _Entry("read an email", app=_GMAIL),
    "google_workspace.search_emails": _Entry("search your email", app=_GMAIL),
    "google_workspace.get_thread": _Entry("read an email conversation", app=_GMAIL),
    "google_workspace.list_labels": _Entry("list your email labels", app=_GMAIL),
    "google_workspace.get_attachment_text": _Entry("read an email attachment", app=_GMAIL),
    # Security wave (security10): the mail checks' reads (S1, S2, S10).
    "google_workspace.get_draft": _Entry("read an email draft", app=_GMAIL),
    "google_workspace.get_attachment_hash": _Entry("check an email attachment", app=_GMAIL),
    "google_workspace.list_new_message_ids": _Entry("check for new email", app=_GMAIL),
    "google_workspace.get_message_security": _Entry(
        "check where an email came from", app=_GMAIL
    ),
    # -- Google Calendar --------------------------------------------------------
    "google_workspace.create_event": _Entry(
        "add a calendar event",
        _s_gcal_create,
        _GCAL,
        {
            "event_data": "Event",
            "event_data.summary": "Title",
            "event_data.start": "Starts",
            "event_data.end": "Ends",
            "event_data.location": "Place",
            "event_data.description": "Notes",
            "event_data.attendees": "Guests",
            "event_data.recurrence": "Repeats",
            "event_data.reminders": "Reminders",
            "summary": "Title",
            "description": "Notes",
            "attendees": "Guests",
            "recurrence": "Repeats",
        },
    ),
    "google_workspace.update_event": _Entry(
        "change a calendar event",
        _s_gcal_update,
        _GCAL,
        {
            "event_id": "Event ID",
            "calendar_id": "Calendar",
            "summary": "New title",
            "description": "New notes",
            "location": "New place",
            "start": "New start",
            "end": "New end",
            "attendees": "Guests",
            "notify_attendees": "Email the guests",
        },
    ),
    "google_workspace.respond_to_invite": _Entry(
        "answer a calendar invitation",
        _s_gcal_respond,
        _GCAL,
        {"event_id": "Event ID", "response": "Your answer", "calendar_id": "Calendar"},
    ),
    "google_workspace.delete_event": _Entry(
        "delete a calendar event",
        _s_gcal_delete,
        _GCAL,
        {"event_id": "Event ID", "calendar_id": "Calendar", "notify_attendees": "Email the guests"},
    ),
    "google_workspace.get_events": _Entry("check your calendar", app=_GCAL),
    "google_workspace.check_availability": _Entry("check when you're free", app=_GCAL),
    "google_workspace.list_calendars": _Entry("list your calendars", app=_GCAL),
    # -- Google Drive -------------------------------------------------------------
    "google_workspace.upload_file": _Entry(
        "save a new file",
        _s_drive_upload,
        _DRIVE,
        {
            "name": "File name",
            "content": "What's in the file",
            "mime_type": "File type",
            "folder_id": "Folder ID",
        },
    ),
    "google_workspace.create_folder": _Entry(
        "make a new folder",
        _s_drive_folder,
        _DRIVE,
        {"name": "Folder name", "parent_id": "Inside folder ID"},
    ),
    "google_workspace.move_file": _Entry(
        "move a file",
        _s_drive_move,
        _DRIVE,
        {"folder_id": "Move to folder ID"},
    ),
    "google_workspace.rename_file": _Entry(
        "rename a file", _s_drive_rename, _DRIVE, {"name": "New name"}
    ),
    "google_workspace.share_file": _Entry(
        "share a file",
        _s_drive_share,
        _DRIVE,
        {"email": "Share with", "role": "They can", "notify": "Email them"},
    ),
    "google_workspace.trash_file": _Entry("move a file to the trash", _s_drive_trash, _DRIVE),
    "google_workspace.search_files": _Entry("search your files", app=_DRIVE),
    "google_workspace.get_file_text": _Entry("read a file", app=_DRIVE),
    "google_workspace.list_folder": _Entry("look in a folder", app=_DRIVE),
    # -- Google Docs and Sheets -------------------------------------------------------
    "google_workspace.create_document": _Entry(
        "create a document", _s_docs_create, _DOCS, {"text": "Starting text"}
    ),
    "google_workspace.append_text": _Entry(
        "add text to a document", _s_docs_append, _DOCS, {"text": "Text to add"}
    ),
    "google_workspace.replace_text": _Entry(
        "replace text in a document",
        _s_docs_replace,
        _DOCS,
        {"find": "Find", "replace_with": "Replace with", "match_case": "Match capital letters"},
    ),
    "google_workspace.get_document": _Entry("read a document", app=_DOCS),
    "google_workspace.update_values": _Entry(
        "change cells in a spreadsheet",
        _s_sheets_update,
        _SHEETS,
        {"values": "New values", "parse_input": "Read values as typed"},
    ),
    "google_workspace.append_rows": _Entry(
        "add rows to a spreadsheet",
        _s_sheets_append,
        _SHEETS,
        {"values": "Rows to add", "parse_input": "Read values as typed"},
    ),
    "google_workspace.add_sheet": _Entry(
        "add a tab to a spreadsheet", _s_sheets_tab, _SHEETS, {"title": "Tab name"}
    ),
    "google_workspace.clear_range": _Entry(
        "erase cells in a spreadsheet", _s_sheets_clear, _SHEETS
    ),
    "google_workspace.get_values": _Entry("read a spreadsheet", app=_SHEETS),
    "google_workspace.get_metadata": _Entry("look at a spreadsheet's tabs", app=_SHEETS),
    # -- Google Contacts --------------------------------------------------------------
    "google_workspace.create_contact": _Entry("add a contact", _s_contact_create, _CONTACTS),
    "google_workspace.update_contact": _Entry(
        "change a contact",
        _s_contact_update,
        _CONTACTS,
        {"email": "Main email", "phone": "Main phone"},
    ),
    "google_workspace.delete_contact": _Entry("delete a contact", _s_contact_delete, _CONTACTS),
    "google_workspace.search_contacts": _Entry("search your contacts", app=_CONTACTS),
    "google_workspace.get_contact": _Entry("look up a contact", app=_CONTACTS),
    # -- Robinhood ----------------------------------------------------------------------
    "robinhood.get_crypto_portfolio": _Entry("look at your crypto portfolio", _s_rh_portfolio),
    "robinhood.get_crypto_prices": _Entry(
        "check crypto prices", _s_rh_prices, labels={"symbols": "Coins"}
    ),
    "robinhood.get_crypto_holdings": _Entry("look at the crypto you hold", _s_rh_holdings),
    "robinhood.execute_trade": _Entry(
        "buy or sell crypto", _s_rh_trade, labels={"symbol": "Coin", "side": "Buy or sell"}
    ),
    # -- Slack ----------------------------------------------------------------------------
    "slack.post_message": _Entry(
        "post a message in a channel", _s_slack_post, labels={"text": "Message"}
    ),
    "slack.reply_in_thread": _Entry(
        "reply in a thread",
        _s_slack_reply,
        labels={
            "text": "Reply",
            "thread_ts": "Thread",
            "also_send_to_channel": "Also post in the channel",
        },
    ),
    "slack.add_reaction": _Entry(
        "add an emoji reaction", _s_slack_react, labels={"ts": "Message", "name": "Emoji"}
    ),
    "slack.upload_file": _Entry(
        "share a file in a channel",
        _s_slack_upload,
        labels={"content": "What's in the file", "thread_ts": "In thread"},
    ),
    "slack.set_status": _Entry(
        "change your status",
        _s_slack_status,
        labels={"text": "Status", "emoji": "Emoji", "expires_in_minutes": "Clear after minutes"},
    ),
    "slack.create_channel": _Entry(
        "create a channel",
        _s_slack_create,
        labels={"name": "Channel name", "is_private": "Private"},
    ),
    "slack.invite_to_channel": _Entry("invite people to a channel", _s_slack_invite),
    "slack.schedule_message": _Entry(
        "schedule a message",
        _s_slack_schedule,
        labels={"text": "Message", "post_at": "Send at", "thread_ts": "In thread"},
    ),
    "slack.delete_message": _Entry("delete a message", _s_slack_delete, labels={"ts": "Message"}),
    "slack.archive_channel": _Entry("archive a channel", _s_slack_archive),
    "slack.list_channels": _Entry("list your Slack channels"),
    "slack.get_history": _Entry("read a Slack channel"),
    "slack.get_thread": _Entry("read a Slack thread"),
    "slack.search_messages": _Entry("search your Slack messages"),
    "slack.list_users": _Entry("list the people in your Slack"),
    "slack.get_user": _Entry("look up a person on Slack"),
    "slack.get_file_info": _Entry("look at a file shared on Slack"),
    # -- Outlook mail ----------------------------------------------------------------
    "microsoft.send_mail": _Entry(
        "send an email", _s_ms_send, _OUTLOOK, {"bcc": "Bcc (hidden copy)"}
    ),
    "microsoft.reply": _Entry(
        "reply to an email",
        _s_ms_reply,
        _OUTLOOK,
        {
            "message_id": "Replying to email ID",
            "comment": "Your reply",
            "reply_all": "Reply to everyone",
        },
    ),
    "microsoft.forward": _Entry(
        "forward an email", _s_ms_forward, _OUTLOOK, {**_EMAIL_REF, "comment": "Your note"}
    ),
    "microsoft.create_draft": _Entry("save an email draft", _s_ms_draft, _OUTLOOK),
    "microsoft.move_message": _Entry(
        "move an email to another folder",
        _s_ms_move,
        _OUTLOOK,
        {**_EMAIL_REF, "destination_folder": "Move to folder"},
    ),
    "microsoft.flag_message": _Entry(
        "flag an email", _s_ms_flag, _OUTLOOK, {**_EMAIL_REF, "status": "Flag"}
    ),
    "microsoft.delete_message": _Entry("delete an email", _s_ms_delete_mail, _OUTLOOK, _EMAIL_REF),
    "microsoft.list_messages": _Entry("check your email", app=_OUTLOOK),
    "microsoft.search_messages": _Entry("search your email", app=_OUTLOOK),
    "microsoft.get_message": _Entry("read an email", app=_OUTLOOK),
    "microsoft.get_attachment_text": _Entry("read an email attachment", app=_OUTLOOK),
    # Security wave (security10): the mail checks' reads (S2, S10).
    "microsoft.get_attachment_hash": _Entry("check an email attachment", app=_OUTLOOK),
    "microsoft.list_new_message_ids": _Entry("check for new email", app=_OUTLOOK),
    "microsoft.get_message_security": _Entry("check where an email came from", app=_OUTLOOK),
    "microsoft.list_folders": _Entry("list your email folders", app=_OUTLOOK),
    "microsoft.search_contacts": _Entry("search your contacts", app=_OUTLOOK),
    # -- Outlook calendar --------------------------------------------------------------
    "microsoft.create_event": _Entry(
        "add a calendar event",
        _s_ms_event_create,
        _OUTLOOK,
        {"subject": "Title", "body": "Notes", "attendees": "Guests", "calendar_id": "Calendar ID"},
    ),
    "microsoft.update_event": _Entry(
        "change a calendar event",
        _s_ms_event_update,
        _OUTLOOK,
        {
            "subject": "New title",
            "start": "New start",
            "end": "New end",
            "location": "New place",
            "body": "New notes",
        },
    ),
    "microsoft.respond_to_invite": _Entry(
        "answer a meeting invitation",
        _s_ms_respond,
        _OUTLOOK,
        {
            "response": "Your answer",
            "comment": "Note to the organizer",
            "send_response": "Tell the organizer",
        },
    ),
    "microsoft.delete_event": _Entry("delete a calendar event", _s_ms_event_delete, _OUTLOOK),
    "microsoft.list_events": _Entry("check your calendar", app=_OUTLOOK),
    "microsoft.find_meeting_times": _Entry("find a time to meet", app=_OUTLOOK),
    "microsoft.list_calendars": _Entry("list your calendars", app=_OUTLOOK),
    # -- OneDrive --------------------------------------------------------------------
    "microsoft.upload_file": _Entry(
        "save a new file",
        _s_onedrive_upload,
        _ONEDRIVE,
        {
            "name": "File name",
            "content": "What's in the file",
            "overwrite": "Replace a file with the same name",
        },
    ),
    "microsoft.create_folder": _Entry(
        "make a new folder",
        _s_onedrive_folder,
        _ONEDRIVE,
        {"name": "Folder name", "parent_folder_id": "Inside folder ID"},
    ),
    "microsoft.move_file": _Entry(
        "move a file",
        _s_onedrive_move,
        _ONEDRIVE,
        {"item_id": "File or folder ID", "destination_folder_id": "Move to folder ID"},
    ),
    "microsoft.create_share_link": _Entry(
        "make a sharing link",
        _s_onedrive_link,
        _ONEDRIVE,
        {
            "item_id": "File or folder ID",
            "link_type": "Link lets people",
            "scope": "Who can use it",
        },
    ),
    "microsoft.delete_file": _Entry(
        "delete a file", _s_onedrive_delete, _ONEDRIVE, {"item_id": "File or folder ID"}
    ),
    "microsoft.search_files": _Entry("search your files", app=_ONEDRIVE),
    "microsoft.get_file_text": _Entry("read a file", app=_ONEDRIVE),
    "microsoft.list_folder": _Entry("look in a folder", app=_ONEDRIVE),
    # -- Microsoft To Do ---------------------------------------------------------------
    "microsoft.create_task": _Entry("add a task", _s_todo_create, _TODO, {"title": "Task"}),
    "microsoft.update_task": _Entry(
        "change a task",
        _s_todo_update,
        _TODO,
        {"title": "New title", "note": "New note", "due_date": "New due date"},
    ),
    "microsoft.complete_task": _Entry("mark a task as done", _s_todo_complete, _TODO),
    "microsoft.delete_task": _Entry("delete a task", _s_todo_delete, _TODO),
    "microsoft.list_task_lists": _Entry("list your task lists", app=_TODO),
    "microsoft.list_tasks": _Entry("check your tasks", app=_TODO),
    # -- GitHub ------------------------------------------------------------------------
    "github.create_repo": _Entry(
        "create a repository",
        _s_gh_create_repo,
        labels={"org": "Organization", "auto_init": "Start with a README file"},
    ),
    "github.create_branch": _Entry(
        "create a branch",
        _s_gh_create_branch,
        labels={**_GH, "branch": "New branch", "from_ref": "Start from"},
    ),
    "github.put_file": _Entry(
        "save a file to a repository",
        _s_gh_put_file,
        labels={
            **_GH,
            "content": "New file contents",
            "message": "Change note",
            "sha": "Version being replaced",
        },
    ),
    "github.delete_branch": _Entry("delete a branch", _s_gh_delete_branch, labels=_GH),
    "github.create_issue": _Entry(
        "open an issue", _s_gh_create_issue, labels={**_GH, "assignees": "Assign to"}
    ),
    "github.comment": _Entry(
        "post a comment",
        _s_gh_comment,
        labels={**_GH, "number": "Issue or pull request", "body": "Comment"},
    ),
    "github.update_issue": _Entry(
        "change an issue",
        _s_gh_update_issue,
        labels={
            **_GH,
            "number": "Issue",
            "title": "New title",
            "body": "New description",
            "state_reason": "Reason",
            "labels": "Labels (replaces all)",
            "assignees": "Assigned to (replaces all)",
        },
    ),
    "github.create_pr": _Entry(
        "open a pull request",
        _s_gh_create_pr,
        labels={**_GH, "head": "Changes from", "base": "Merge into"},
    ),
    "github.review_pr": _Entry(
        "review a pull request",
        _s_gh_review,
        labels={**_GH, "number": "Pull request", "event": "Your review", "body": "Review"},
    ),
    "github.request_reviewers": _Entry(
        "ask for a review",
        _s_gh_reviewers,
        labels={**_GH, "number": "Pull request", "reviewers": "People", "team_reviewers": "Teams"},
    ),
    "github.merge_pr": _Entry(
        "merge a pull request",
        _s_gh_merge,
        labels={
            **_GH,
            "number": "Pull request",
            "merge_method": "How to merge",
            "sha": "Only if the latest commit is",
        },
    ),
    "github.rerun_failed_jobs": _Entry(
        "rerun failed workflow steps", _s_gh_rerun, labels={**_GH, "run_id": "Run ID"}
    ),
    "github.dispatch_workflow": _Entry(
        "start a workflow",
        _s_gh_dispatch,
        labels={**_GH, "workflow": "Workflow", "ref": "Branch or tag", "inputs": "Settings"},
    ),
    "github.cancel_run": _Entry(
        "stop a running workflow", _s_gh_cancel, labels={**_GH, "run_id": "Run ID"}
    ),
    "github.mark_notification_read": _Entry(
        "mark a notification as read", _s_gh_notification, labels={"thread_id": "Notification ID"}
    ),
    "github.create_release": _Entry(
        "create a draft release",
        _s_gh_create_release,
        labels={
            **_GH,
            "tag_name": "Version",
            "name": "Title",
            "body": "Release notes",
            "target_commitish": "From branch or commit",
            "prerelease": "Pre-release",
            "generate_release_notes": "Let GitHub write the notes",
        },
    ),
    "github.publish_release": _Entry(
        "publish a release", _s_gh_publish, labels={**_GH, "release_id": "Release ID"}
    ),
    "github.create_gist": _Entry("post a snippet", _s_gh_gist, labels={"content": "Contents"}),
    "github.list_repos": _Entry("list your GitHub repositories"),
    "github.get_repo": _Entry("look at a GitHub repository"),
    "github.get_file": _Entry("read a file on GitHub"),
    "github.list_tree": _Entry("list a repository's files"),
    "github.search_code": _Entry("search code on GitHub"),
    "github.list_branches": _Entry("list branches"),
    "github.list_commits": _Entry("list recent commits"),
    "github.compare": _Entry("compare two branches"),
    "github.list_issues": _Entry("list GitHub issues"),
    "github.get_issue": _Entry("read a GitHub issue"),
    "github.search_issues": _Entry("search GitHub issues"),
    "github.list_comments": _Entry("read comments on GitHub"),
    "github.list_prs": _Entry("list GitHub pull requests"),
    "github.get_pr": _Entry("read a GitHub pull request"),
    "github.get_pr_diff": _Entry("read a pull request's changes"),
    "github.get_pr_checks": _Entry("check a pull request's test results"),
    "github.list_reviews": _Entry("read reviews"),
    "github.list_runs": _Entry("list workflow runs"),
    "github.get_run": _Entry("look at a workflow run"),
    "github.get_failed_logs": _Entry("read the logs of a failed run"),
    "github.list_notifications": _Entry("check your GitHub notifications"),
    "github.list_releases": _Entry("list releases"),
    "github.get_release": _Entry("read a release"),
    # -- Notion ------------------------------------------------------------------------
    "notion.create_page": _Entry(
        "create a page",
        _s_notion_create,
        labels={"parent_page_id": "Inside page ID", "content": "Page content"},
    ),
    "notion.append_blocks": _Entry(
        "add to a page",
        _s_notion_append,
        labels={
            "block_id": "Page or block ID",
            "markdown": "Content to add",
            "after": "After block ID",
        },
    ),
    "notion.update_page_properties": _Entry("change fields on a page", _s_notion_properties),
    "notion.create_database_row": _Entry(
        "add a row to a database", _s_notion_row, labels={"content": "Page content"}
    ),
    "notion.update_block": _Entry(
        "change part of a page", _s_notion_block, labels={"text": "New text", "checked": "Ticked"}
    ),
    "notion.add_comment": _Entry(
        "post a comment",
        _s_notion_comment,
        labels={"text": "Comment", "discussion_id": "Discussion ID"},
    ),
    "notion.archive_page": _Entry("move a page to the trash", _s_notion_archive),
    "notion.delete_block": _Entry("delete part of a page", _s_notion_delete_block),
    "notion.search": _Entry("search Notion"),
    "notion.get_page": _Entry("read a Notion page"),
    "notion.get_block_children": _Entry("read a Notion page"),
    "notion.query_database": _Entry("look through a Notion database"),
    "notion.get_database": _Entry("look at a Notion database"),
    "notion.list_comments": _Entry("read comments in Notion"),
    "notion.list_users": _Entry("list the people in your Notion"),
}


# Labels every tool shares, used when the tool has no label of its own.
_SHARED_LABELS: dict[str, str] = {
    "to": "To",
    "cc": "Cc",
    "bcc": "Bcc",
    "subject": "Subject",
    "body": "Message",
    "text": "Text",
    "content": "Content",
    "url": "Link",
    "path": "File",
    "name": "Name",
    "title": "Title",
    "start": "Starts",
    "end": "Ends",
    "message_id": "Email ID",
    "file_id": "File ID",
    "file_ids": "File IDs",
    "draft_id": "Draft ID",
    "thread_id": "Thread ID",
    "note": "Note",
    "notes": "Notes",
    "comment": "Comment",
    "description": "Description",
    "location": "Place",
    "attendees": "Guests",
    "email": "Email",
    "phone": "Phone",
    "query": "Search for",
    "label": "Name",
    "labels": "Labels",
    "prompt": "Instructions",
    "channel": "Channel",
    "users": "People",
    "event_id": "Event ID",
    "calendar_id": "Calendar",
    "folder_id": "Folder ID",
    "parent_id": "Inside folder ID",
    "item_id": "Item ID",
    "document_id": "Document ID",
    "spreadsheet_id": "Spreadsheet ID",
    "a1_range": "Cells",
    "values": "Values",
    "owner": "Owner",
    "repo": "Repository",
    "branch": "Branch",
    "number": "Number",
    "time_zone": "Time zone",
    "timezone": "Time zone",
    "timeZone": "Time zone",
    "dateTime": "Date and time",
    "date": "Date",
    "time": "Time",
    "due_date": "Due",
    "due_at": "When",
    "importance": "Importance",
    "list_id": "List ID",
    "task_id": "Task ID",
    "page_id": "Page ID",
    "block_id": "Block ID",
    "database_id": "Database ID",
    "properties": "Fields",
    "channels": "Send to",
    "days": "Days",
    "freq": "How often",
    "interval_minutes": "Check every",
    "reply_all": "Reply to everyone",
    "notify": "Email them",
    "notify_attendees": "Email the guests",
    "given_name": "First name",
    "family_name": "Last name",
    "organization": "Company",
    "resource_name": "Contact ID",
    "filename": "File name",
    "mime_type": "File type",
    "private": "Private",
    "public": "Public",
    "draft": "Draft",
    "state": "Status",
    "assignees": "Assignees",
    "amount": "Amount",
    "symbols": "Coins",
    "course_id": "Course ID",
    "assignment_id": "Assignment ID",
    "deck_id": "Deck ID",
    "displayName": "Name",
    "responseStatus": "Answer",
    "_account": "Account",
}


# Plain words for fixed values (enums) that would otherwise show as code
# words on a card. Keyed by tool, then argument key (the last part of a
# dotted key), then value. Shared values follow.
_SCHEDULE_VALUES = {
    "freq": {
        "once": "Once",
        "daily": "Every day",
        "weekdays": "Weekdays",
        "weekly": "Every week",
        "monthly": "Every month",
    },
    "days": dict(_DAY_NAMES),
    "sections": {
        "canvas": "What's due on Canvas",
        "calendar": "Today's calendar",
        "email": "Important unread email",
    },
}
_TRIGGER_VALUES = {
    "source": {
        "email.new": "A new email arrives",
        "canvas.announcement": "A new Canvas announcement",
        "canvas.assignment": "A new Canvas assignment",
        "canvas.grade": "A new grade on Canvas",
        "calendar.starting_soon": "An event is about to start",
        "files.new_in_folder": "A new file lands in a folder",
        "page.changed": "A watched page changes",
    },
    "mode": {"notify": "Message you", "run_task": "Run a task"},
}
_VALUE_WORDS: dict[str, dict[str, dict[str, str]]] = {
    "system.install_capability": {"name": {name: addon[0] for name, addon in _ADDONS.items()}},
    "desktop.act": {
        "action": {
            "click": "Click",
            "double_click": "Double-click",
            "type": "Type",
            "key": "Press keys",
            "scroll": "Scroll",
            "open_app": "Open an app",
            "focus_window": "Switch to a window",
        },
        "direction": {"up": "Up", "down": "Down"},
    },
    "browser.act": {
        "action": {
            "fill": "Type into a field",
            "fill_form": "Fill in a form",
            "select": "Pick an option",
            "check": "Tick a box",
            "click": "Click",
            "press": "Press a key",
            "submit": "Send a form",
        },
    },
    "memory.remember": {
        "category": {
            "profile": "About you",
            "preference": "How you like things",
            "project": "Ongoing work",
            "fact": "Other",
        },
    },
    "schedule.create": _SCHEDULE_VALUES,
    "schedule.briefing": _SCHEDULE_VALUES,
    "triggers.create": _TRIGGER_VALUES,
    "triggers.update": _TRIGGER_VALUES,
    "study.save": {
        "source_kind": {
            "notes": "Notes",
            "chat": "Chat",
            "file": "A file",
            "knowledge_base": "Saved documents",
            "canvas": "Canvas",
            "drive": "Google Drive",
            "onedrive": "OneDrive",
            "notion": "Notion",
            "web": "The web",
            "other": "Other",
        },
    },
    "study.review": {
        "action": {"next": "Next card", "grade": "Record an answer", "skip": "Skip"},
        "rating": dict(_RATING_WORDS),
    },
    "study.quiz": {
        "action": {
            "start": "Start",
            "reveal": "Show a question",
            "submit": "Grade answers",
            "finish": "Finish",
        },
    },
    "canvas.submit_assignment": {
        "submission_type": {
            "online_text_entry": "Text",
            "online_url": "Link",
            "online_upload": "File upload",
        },
    },
    "google_workspace.respond_to_invite": {
        "response": {"accepted": "Yes", "declined": "No", "tentative": "Maybe"},
    },
    "google_workspace.share_file": {
        "role": {"reader": "View", "commenter": "Comment", "writer": "Edit"},
    },
    "google_workspace.upload_file": {
        "mime_type": {
            "text/plain": "Text",
            "text/csv": "Spreadsheet (CSV)",
            "text/markdown": "Text (Markdown)",
            "text/html": "Web page (HTML)",
            "application/json": "Data file",
        },
    },
    "google_workspace.modify_labels": {
        "add_label_ids": {
            **{key: key.capitalize() for key in _GMAIL_ADD},
            **{key: f"{tab} tab" for key, tab in _GMAIL_TABS.items()},
        },
        "remove_label_ids": {
            **{key: key.capitalize() for key in _GMAIL_REMOVE},
            **{key: f"{tab} tab" for key, tab in _GMAIL_TABS.items()},
        },
    },
    "microsoft.flag_message": {
        "status": {"flagged": "Flagged", "complete": "Done", "notFlagged": "No flag"},
    },
    "microsoft.move_message": {"destination_folder": dict(_OUTLOOK_FOLDERS)},
    "microsoft.respond_to_invite": {
        "response": {"accept": "Yes", "tentative": "Maybe", "decline": "No"},
    },
    "microsoft.create_share_link": {
        "link_type": {"view": "View only", "edit": "Edit"},
        "scope": {
            "organization": "People in your organization",
            "anonymous": "Anyone with the link",
        },
    },
    "microsoft.create_task": {"importance": {"low": "Low", "normal": "Normal", "high": "High"}},
    "microsoft.update_task": {"importance": {"low": "Low", "normal": "Normal", "high": "High"}},
    "github.update_issue": {
        "state": {"open": "Open", "closed": "Closed"},
        "state_reason": {"completed": "Done", "not_planned": "Won't do", "reopened": "Reopened"},
    },
    "github.review_pr": {
        "event": {
            "approve": "Approve",
            "request_changes": "Ask for changes",
            "comment": "Comment only",
        },
    },
    "github.merge_pr": {
        "merge_method": {
            "merge": "Merge commit",
            "squash": "One combined commit",
            "rebase": "Rebase",
        },
    },
    "robinhood.execute_trade": {"side": {"buy": "Buy", "sell": "Sell"}},
}
_SHARED_VALUES: dict[str, dict[str, str]] = {
    "channels": {"telegram": "Telegram", "slack": "Slack", "web": "Web app"},
}


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def _parts(tool_name: Any) -> tuple[str, str, str]:
    """``(family, action, key)`` of a tool name. A second connection of one
    type ("canvas__1f2e3d4c.get_courses") reads as its type; an MCP tool
    ("mcp.<server>.<tool>") gives family "mcp", the server as action and
    the full name as key."""
    if not isinstance(tool_name, str):
        return "", "", ""
    name = _one_line(tool_name)
    family, _, action = name.partition(".")
    family = family.split("__", 1)[0].lower()
    if family == "mcp":
        server, _, tool = action.partition(".")
        return "mcp", server, f"mcp.{server}.{tool}"
    return family, action, f"{family}.{action}"


def _mcp_parts(tool_name: str) -> tuple[str, str]:
    """``(server name, humanized tool)`` of an MCP tool name."""
    _, _, rest = _one_line(tool_name).partition(".")
    server, _, tool = rest.partition(".")
    return _clip(_title_words(server), 40), _clip(_humanize(tool), 60)


def app_name(tool_name: str) -> str:
    """The app or place a tool works in, in everyday words.

    Google and Microsoft name the product per action ("Gmail", "Google
    Calendar", "OneDrive", "Microsoft To Do"), falling back to "your Google
    account" or "your Microsoft account". An MCP tool gives its server's
    name tidied up ("brave_search" is "Brave Search"); an unknown family its
    own name in words. Never raises; "an app" when nothing is known.
    """
    try:
        family, _, key = _parts(tool_name)
        if family == "mcp":
            server, _ = _mcp_parts(tool_name)
            return server or _FAMILY_APPS["mcp"]
        entry = _TOOLS.get(key)
        if entry is not None and entry.app:
            return entry.app
        if family in _FAMILY_APPS:
            return _FAMILY_APPS[family]
        words = _clip(_title_words(family), 40)
        if words:
            return words
    except Exception:
        pass
    return "an app"


def short_phrase(tool_name: str) -> str:
    """A lower-case verb phrase for reply notes, with no final period
    ("send an email", "install an add-on", "change labels on an email").

    It reads after "I" or "let me" ("I need your OK before I send an
    email"). A tool not in the table gives "use <app>" ("use Linear" for an
    MCP tool); no usable name gives "do that step". The prompt guard's two
    pseudo names (GUARD_PHRASES) get their own phrase. Never raises.
    """
    try:
        if isinstance(tool_name, str) and tool_name in GUARD_PHRASES:
            return GUARD_PHRASES[tool_name]
        family, _, key = _parts(tool_name)
        entry = _TOOLS.get(key)
        if entry is not None:
            return entry.phrase
        if family:
            return f"use {app_name(tool_name)}"
    except Exception:
        pass
    return GENERIC_PHRASE


def _generic_sentence(tool_name: Any) -> str:
    """ "Use <app> to <humanized action>" for a tool not in the table."""
    family, action, _ = _parts(tool_name)
    if not family:
        return GENERIC_SENTENCE
    if family == "mcp":
        server, tool = _mcp_parts(tool_name)
        server = server or _FAMILY_APPS["mcp"]
        return f"Use {server} to {tool}" if tool else f"Use {server}"
    app = app_name(tool_name)
    words = _clip(_humanize(action), 60)
    return f"Use {app} to {words}" if words else f"Use {app}"


def approval_sentence(tool_name: str, arguments: Optional[Mapping[str, Any]]) -> str:
    """One plain sentence (two at most) saying what the call will do, verb
    first, built only from its arguments.

    Examples: "Send an email to priya@acme.com from your Gmail", "Install
    the web browser add-on so I can open websites, click around and take
    pictures of pages for you. It's a one-time download of about 150 to
    300 MB.", "Use Linear to create issue" (an MCP tool). A single sentence
    has no final period, like a card title; two are each closed.

    Only the arguments are read: no lookups and no I/O, so a name that is
    not in them is never invented ("an email", "a Slack channel"). Free
    text such as a subject is clipped to about ``CLIP_CHARS`` characters;
    recipients, amounts, links and paths are shown whole. The result is
    always one line and never names the tool. Never raises: a tool not in
    the table, odd arguments or a failing builder give a generic sentence.
    """
    try:
        _, _, key = _parts(tool_name)
        entry = _TOOLS.get(key)
        if entry is not None:
            if entry.sentence is not None:
                text = _one_line(entry.sentence(_Args(arguments)))
                if text:
                    return text
            return _sentence_case(entry.phrase)
        return _generic_sentence(tool_name)
    except Exception:
        try:
            return _generic_sentence(tool_name)
        except Exception:
            return GENERIC_SENTENCE


def _key_parts(key: Any) -> list[str]:
    """The non-numeric parts of a dotted key ("attendees.0.email" gives
    ["attendees", "email"])."""
    text = key if isinstance(key, str) else _scalar_text(key)
    return [part for part in _one_line(text).split(".") if part and not part.isdigit()]


def _humanized_label(key: str) -> str:
    """A key as a sentence-case label: "max_results" is "Max results",
    "event_id" is "Event ID", "callback_url" is "Callback link"."""
    out = []
    for word in _words(key):
        lower = word.lower()
        if lower == "id":
            out.append("ID")
        elif lower == "ids":
            out.append("IDs")
        elif lower in ("url", "uri"):
            out.append("link")
        elif lower in ("urls", "uris"):
            out.append("links")
        elif lower in _ACRONYMS or (word.isupper() and len(word) > 1):
            out.append(lower.upper())
        elif lower in _BRANDS:
            out.append(_BRANDS[lower])
        else:
            out.append(lower)
    return _sentence_case(" ".join(out))


def field_label(tool_name: str, key: str) -> str:
    """The everyday label of one argument key, in sentence case and with no
    colon ("To", "Starts", "Email ID", "Add-on").

    Looked up in the tool's own labels, then the shared ones, then made
    from the key itself ("max_results" is "Max results", "_account" is
    "Account"). A dotted key ("event_data.start") is tried whole first,
    then by its last part. Never raises; "Detail" when nothing is left.
    """
    try:
        parts = _key_parts(key)
        if not parts:
            return "Detail"
        _, _, tool_key = _parts(tool_name)
        entry = _TOOLS.get(tool_key)
        own = entry.labels if entry is not None else {}
        whole, last = ".".join(parts), parts[-1]
        for table, candidate in (
            (own, whole),
            (own, last),
            (_SHARED_LABELS, whole),
            (_SHARED_LABELS, last),
        ):
            label = table.get(candidate)
            if label:
                return label
        return _clip(_humanized_label(last), 60) or "Detail"
    except Exception:
        return "Detail"


def field_value(tool_name: str, key: str, value: Any) -> Optional[str]:
    """Plain words for a known fixed value of one argument ("speech_to_text"
    on system.install_capability is "Voice notes", "tentative" on a Google
    invitation is "Maybe"), or None when the value has none and should be
    shown as it is. For a list, call it once per item. Never raises.
    """
    try:
        if not isinstance(value, str):
            return None
        parts = _key_parts(key)
        if not parts:
            return None
        _, _, tool_key = _parts(tool_name)
        last = parts[-1]
        table = _VALUE_WORDS.get(tool_key, {}).get(last) or _SHARED_VALUES.get(last) or {}
        text = value.strip()
        return table.get(text) or table.get(text.lower())
    except Exception:
        return None


def known_tools() -> tuple[str, ...]:
    """Every tool name this module has its own words for, sorted."""
    return tuple(sorted(_TOOLS))
