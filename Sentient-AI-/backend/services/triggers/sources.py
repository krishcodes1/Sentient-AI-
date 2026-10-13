"""The trigger sources: what each one polls (which connector action of which
connector type), which filters and intervals it takes, the Gmail query it
compiles to, and the adapters that turn a connector's answer into new items.

Why it exists: a trigger reads its own pinned connector row through the tool
executor (``executor.execute`` with the slugged tool name, ``approved=False``,
the row's user), so scopes, rate limits, token refresh, the network policy and
error sanitising all apply exactly as for a chat's read. Everything read is
untrusted: filters are re-checked in code on the parsed values (a display-name
spoof of an allowed sender fails), mail in Sent, Drafts, Spam or Trash is
skipped, items become capped facts (services/triggers/facts.py), and the first
check only records a baseline, so only newer items ever fire. Dedupe is a
hashed external id per item, kept in the trigger's cursor as a ring of up to
200 short keys (and, behind it, the unique index on trigger_events).
"""

from __future__ import annotations

import re
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Awaitable, Callable, Mapping, Optional, Protocol, Sequence

from services.triggers import facts as shape

SOURCES: tuple[str, ...] = (
    "email.new",
    "canvas.announcement",
    "canvas.assignment",
    "canvas.grade",
    "calendar.starting_soon",
    "files.new_in_folder",
    "page.changed",
)
# Sources the sweeper polls; page.changed is pushed by the page-watch sweeper.
POLLED_SOURCES: tuple[str, ...] = tuple(s for s in SOURCES if s != "page.changed")

MAX_SENDERS = 10
MAX_COURSE_IDS = 20
SUBJECT_MAX_CHARS = 100
LEAD_MINUTES = (5, 120, 15)
SEEN_RING = 200
# Seconds a mail query reaches back before the watermark, so mail that
# arrived while a check ran is not missed (the seen ring drops repeats).
OVERLAP_SECONDS = 300
GMAIL_MAX_RESULTS = 10
LIST_LIMIT = 25
FILTERS_MAX_BYTES = 2048

# Gmail labels whose mail never fires a trigger (a trigger must not fire on
# its own drafts, on sent mail or on spam).
SKIP_LABELS = frozenset({"SENT", "DRAFT", "SPAM", "TRASH"})
# Outlook folders a trigger may not watch, for the same reason.
SKIP_FOLDERS = frozenset({"sentitems", "drafts", "junkemail", "deleteditems", "outbox"})

_ADDRESS_RE = re.compile(r"^[a-z0-9.!#$%&'*+/=?^_`{|}~-]{1,64}@[a-z0-9-]+(?:\.[a-z0-9-]+)*\.[a-z]{2,24}$")
_DOMAIN_RE = re.compile(r"^@[a-z0-9-]+(?:\.[a-z0-9-]+)*\.[a-z]{2,24}$")
_FOLDER_RE = re.compile(r"^[A-Za-z0-9_\-!.=+]{1,200}$")
_COURSE_RE = re.compile(r"^[0-9]{1,20}$")


@dataclass(frozen=True)
class SourceSpec:
    """One source: a phrase for the card, the (connector type, action) it
    polls per supported type, the filters it takes, and its interval
    (min, max, default) in minutes; ``fixed_interval`` when it has one."""

    source: str
    phrase: str
    reads: tuple[tuple[str, str], ...]
    filters: frozenset[str]
    interval: Optional[tuple[int, int, int]] = None
    fixed_interval: Optional[int] = None

    @property
    def connector_types(self) -> tuple[str, ...]:
        return tuple(t for t, _a in self.reads)

    def action_for(self, connector_type: str) -> Optional[str]:
        return next((a for t, a in self.reads if t == connector_type), None)


SPECS: dict[str, SourceSpec] = {
    "email.new": SourceSpec(
        "email.new",
        "a new email",
        (("google_workspace", "get_messages"), ("microsoft", "list_messages")),
        frozenset({"senders", "subject_contains", "folder"}),
        interval=(5, 1440, 15),
    ),
    "canvas.announcement": SourceSpec(
        "canvas.announcement",
        "a new Canvas announcement",
        (("canvas", "get_announcements"),),
        frozenset({"course_ids"}),
        interval=(30, 1440, 60),
    ),
    "canvas.assignment": SourceSpec(
        "canvas.assignment",
        "a new Canvas assignment",
        (("canvas", "get_upcoming"),),
        frozenset({"course_ids"}),
        interval=(30, 1440, 60),
    ),
    "canvas.grade": SourceSpec(
        "canvas.grade",
        "a new Canvas grade",
        (("canvas", "get_recent_grades"),),
        frozenset({"course_ids", "show_score"}),
        interval=(30, 1440, 60),
    ),
    "calendar.starting_soon": SourceSpec(
        "calendar.starting_soon",
        "a calendar event about to start",
        (("google_workspace", "get_events"), ("microsoft", "list_events")),
        frozenset({"lead_minutes"}),
        fixed_interval=5,
    ),
    "files.new_in_folder": SourceSpec(
        "files.new_in_folder",
        "a new file in a folder",
        (("google_workspace", "list_folder"), ("microsoft", "list_folder")),
        frozenset({"folder"}),
        interval=(15, 1440, 60),
    ),
    "page.changed": SourceSpec(
        "page.changed",
        "a watched page changing",
        (),
        frozenset({"watch_id"}),
    ),
}

FILTER_KEYS: frozenset[str] = frozenset().union(*(s.filters for s in SPECS.values()))

APP_NAMES = {"google_workspace": "Google", "microsoft": "Microsoft 365", "canvas": "Canvas"}


def source_app(source: str, connector_type: Optional[str]) -> str:
    """"Gmail", "Outlook", "Canvas", "Google Calendar"... for sentences."""
    if connector_type == "google_workspace":
        return {
            "email.new": "Gmail",
            "calendar.starting_soon": "Google Calendar",
            "files.new_in_folder": "Google Drive",
        }.get(source, "Google")
    if connector_type == "microsoft":
        return {
            "email.new": "Outlook",
            "calendar.starting_soon": "the Outlook calendar",
            "files.new_in_folder": "OneDrive",
        }.get(source, "Microsoft 365")
    if connector_type == "canvas":
        return "Canvas"
    return "your page watch"


# -- Filters and intervals ------------------------------------------------------------


def _error(message: str) -> tuple[None, str]:
    return None, message


def _string_list(value: Any, name: str) -> tuple[Optional[list[str]], Optional[str]]:
    items = [value] if isinstance(value, str) else value
    if not isinstance(items, (list, tuple)) or not all(isinstance(i, (str, int)) and not isinstance(i, bool) for i in items):
        return None, f"'{name}' must be a list."
    return list(dict.fromkeys(str(i).strip() for i in items if str(i).strip())), None


def validate_filters(source: str, params: Mapping[str, Any]) -> tuple[Optional[dict[str, Any]], Optional[str]]:
    """The canonical filters for *source* from a call's arguments, or why
    they are invalid. Only the filters the source takes are accepted; the
    ones with a default get it."""
    spec = SPECS.get(source)
    if spec is None:
        return _error(f"Unknown source {source!r}.")
    given = {k for k in FILTER_KEYS if params.get(k) is not None}
    extra = sorted(given - spec.filters)
    if extra:
        return _error(
            f"{', '.join(repr(k) for k in extra)} cannot be used with source {source}; "
            f"it takes {', '.join(sorted(spec.filters)) or 'no filters'}."
        )
    filters: dict[str, Any] = {}
    if "senders" in spec.filters and params.get("senders") is not None:
        senders, err = _string_list(params.get("senders"), "senders")
        if err or senders is None:
            return _error(err or "Invalid senders.")
        lowered = list(dict.fromkeys(s.lower() for s in senders))
        if len(lowered) > MAX_SENDERS:
            return _error(f"'senders' may list at most {MAX_SENDERS} addresses or @domains.")
        for entry in lowered:
            if not (_ADDRESS_RE.match(entry) or _DOMAIN_RE.match(entry)):
                return _error(
                    f"{entry!r} is not an email address or an @domain (e.g. smith@univ.edu or @univ.edu)."
                )
        if lowered:
            filters["senders"] = lowered
    if "subject_contains" in spec.filters and params.get("subject_contains") is not None:
        subject = params.get("subject_contains")
        if not isinstance(subject, str) or not subject.strip():
            return _error("'subject_contains' must be a short piece of text.")
        subject = " ".join(subject.split())
        if len(subject) > SUBJECT_MAX_CHARS:
            return _error(f"'subject_contains' is too long (max {SUBJECT_MAX_CHARS} characters).")
        if any(not c.isprintable() or c in '"\\' for c in subject):
            return _error("'subject_contains' must be plain text without quotes or backslashes.")
        filters["subject_contains"] = subject
    if "folder" in spec.filters and params.get("folder") is not None:
        folder = params.get("folder")
        if not isinstance(folder, str) or not _FOLDER_RE.match(folder.strip()):
            return _error("'folder' must be a folder id (or root for a drive's top folder).")
        folder = folder.strip()
        if source == "email.new" and folder.lower() in SKIP_FOLDERS:
            return _error("A trigger cannot watch Sent, Drafts, Junk, Outbox or Deleted mail.")
        filters["folder"] = folder
    if source == "files.new_in_folder" and "folder" not in filters:
        return _error("'folder' is required: the folder's id from list_folder, or root.")
    if "course_ids" in spec.filters and params.get("course_ids") is not None:
        courses, err = _string_list(params.get("course_ids"), "course_ids")
        if err or courses is None:
            return _error(err or "Invalid course_ids.")
        if len(courses) > MAX_COURSE_IDS:
            return _error(f"'course_ids' may list at most {MAX_COURSE_IDS} courses.")
        if any(not _COURSE_RE.match(c) for c in courses):
            return _error("'course_ids' must be numeric Canvas course ids from canvas.get_courses.")
        if courses:
            filters["course_ids"] = courses
    if "show_score" in spec.filters:
        show = params.get("show_score", False)
        if show is None:
            show = False
        if not isinstance(show, bool):
            return _error("'show_score' must be true or false.")
        filters["show_score"] = show
    if "lead_minutes" in spec.filters:
        lead = params.get("lead_minutes", LEAD_MINUTES[2])
        if lead is None:
            lead = LEAD_MINUTES[2]
        if isinstance(lead, bool) or not isinstance(lead, int) or not LEAD_MINUTES[0] <= lead <= LEAD_MINUTES[1]:
            return _error(f"'lead_minutes' must be a whole number from {LEAD_MINUTES[0]} to {LEAD_MINUTES[1]}.")
        filters["lead_minutes"] = lead
    if "watch_id" in spec.filters:
        watch = params.get("watch_id")
        try:
            filters["watch_id"] = str(uuid.UUID(str(watch)))
        except (TypeError, ValueError):
            return _error("'watch_id' is required: a page watch id from watch.list.")
    import json

    if len(json.dumps(filters, ensure_ascii=False).encode("utf-8")) > FILTERS_MAX_BYTES:
        return _error("The filters are too long.")
    return filters, None


def check_filters_for(source: str, connector_type: str, filters: Mapping[str, Any]) -> Optional[str]:
    """Filters that make sense only for one connector type: an email
    folder is Outlook's (Gmail uses labels)."""
    if source == "email.new" and filters.get("folder") and connector_type != "microsoft":
        return "'folder' applies to Outlook mail only; Gmail triggers watch the inbox."
    return None


def interval_for(source: str, value: Any) -> tuple[Optional[int], Optional[str]]:
    """The check interval in minutes for *source*, or why *value* is not
    allowed. page.changed has none (the page watch decides): 0."""
    spec = SPECS[source]
    if spec.fixed_interval is not None:
        if value is not None and value != spec.fixed_interval:
            return None, f"{source} triggers check every {spec.fixed_interval} minutes; leave interval_minutes out."
        return spec.fixed_interval, None
    if spec.interval is None:
        if value is not None:
            return None, "A page-change trigger fires when its page watch sees a change; leave interval_minutes out."
        return 0, None
    low, high, default = spec.interval
    if value is None:
        return default, None
    if isinstance(value, bool) or not isinstance(value, int) or not low <= value <= high:
        return None, f"'interval_minutes' for {source} must be a whole number from {low} to {high}."
    return value, None


def gmail_query(filters: Mapping[str, Any], since: datetime) -> str:
    """'(from:(a OR b) subject:"x") after:<epoch-300>': the senders and the
    subject (both validated to hold no quote or operator), newer than the
    watermark less the overlap."""
    parts: list[str] = []
    senders = list(filters.get("senders") or [])
    if senders:
        parts.append("from:(" + " OR ".join(senders) + ")")
    subject = filters.get("subject_contains")
    if subject:
        parts.append(f'subject:"{subject}"')
    after = int(since.timestamp()) - OVERLAP_SECONDS
    head = f"({' '.join(parts)}) " if parts else ""
    return f"{head}after:{after}"


# -- Checking -----------------------------------------------------------------------


class SourceError(Exception):
    """A check that could not read its app. The message is the sweeper's
    own sentence (never the connector's or the vendor's text)."""


@dataclass(frozen=True)
class Item:
    """One item a source sees now: its external id (unhashed), its facts
    and, when known, when it happened (older than the trigger: never
    fires)."""

    ident: str
    facts: dict[str, Any]
    at: Optional[datetime] = None


@dataclass(frozen=True)
class CheckTarget:
    """What a check needs from its trigger row, read when it was claimed."""

    trigger_id: str
    user_id: str
    source: str
    connector_type: Optional[str]
    connector_id: Optional[str]
    filters: Mapping[str, Any]
    label: str
    cursor: Optional[Mapping[str, Any]] = None
    baseline_at: Optional[datetime] = None


@dataclass
class CheckOutcome:
    """New items to queue (at most ``max_items``, oldest first), how many
    more were found, the new cursor, and whether this was the baseline."""

    items: list[tuple[str, Item]] = field(default_factory=list)
    more: int = 0
    cursor: dict[str, Any] = field(default_factory=dict)
    baseline: bool = False


Call = Callable[[str, dict[str, Any]], Awaitable[dict[str, Any]]]


class TriggerSource(Protocol):
    source: str
    connector_type: str
    action: str

    async def fetch(self, call: Call, target: CheckTarget, since: datetime, now: datetime) -> list[Item]: ...


def tool_name(connector_type: str, connector_id: str, action: str) -> str:
    """The slugged name that pins a call to one connector row."""
    from services.agent.tool_registry import connector_slug

    return f"{connector_type}__{connector_slug(str(connector_id))}.{action}"


def _app_error(result: Any, app: str) -> str:
    """A fixed sentence for a failed read (never the connector's text)."""
    text = str(result.get("error") or "") if isinstance(result, Mapping) else ""
    if isinstance(result, Mapping) and result.get("capability"):
        return f"A setting this trigger needs is turned off, so {app} could not be read."
    if text.startswith("No active"):
        return f"The {app} account this trigger reads was turned off or removed."
    if "Scope '" in text or "granted" in text:
        return f"The {app} account no longer allows what this trigger reads."
    if "reconnect" in text.lower() or "sign-in" in text.lower() or "HTTP 401" in text:
        return f"The {app} sign-in needs to be renewed in Connectors."
    if "rate limit" in text.lower():
        return f"{app} asked Crawler to slow down."
    return f"Crawler could not read {app}."


def make_call(executor: Any, target: CheckTarget) -> Call:
    """The adapter's way to its app: one executor call on the pinned row,
    as the row's user, never approved; a failed result raises SourceError."""
    app = source_app(target.source, target.connector_type)

    async def call(action: str, arguments: dict[str, Any]) -> dict[str, Any]:
        if not target.connector_type or not target.connector_id:
            raise SourceError("This trigger has no connected account.")
        result = await executor.execute(
            tool_name(target.connector_type, target.connector_id, action),
            dict(arguments),
            target.user_id,
            approved=False,
        )
        if not isinstance(result, Mapping) or result.get("ok") is not True:
            raise SourceError(_app_error(result, app))
        data = result.get("result")
        return dict(data) if isinstance(data, Mapping) else {}

    return call


def _rows(data: Mapping[str, Any]) -> list[Mapping[str, Any]]:
    items = data.get("items")
    return [row for row in items if isinstance(row, Mapping)] if isinstance(items, list) else []


def _courses(target: CheckTarget) -> set[str]:
    return {str(c) for c in target.filters.get("course_ids") or []}


class EmailGmail:
    source, connector_type, action = "email.new", "google_workspace", "get_messages"

    async def fetch(self, call: Call, target: CheckTarget, since: datetime, now: datetime) -> list[Item]:
        data = await call(
            self.action,
            {"query": gmail_query(target.filters, since), "max_results": GMAIL_MAX_RESULTS},
        )
        return _mail_items(_rows(data), target, labels=True)


class EmailOutlook:
    source, connector_type, action = "email.new", "microsoft", "list_messages"

    async def fetch(self, call: Call, target: CheckTarget, since: datetime, now: datetime) -> list[Item]:
        args: dict[str, Any] = {"limit": LIST_LIMIT}
        if target.filters.get("folder"):
            args["folder"] = target.filters["folder"]
        data = await call(self.action, args)
        floor = since - timedelta(seconds=OVERLAP_SECONDS)
        fresh = []
        for row in _rows(data):
            received = shape.parse_time(row.get("received"))
            if received is not None and received < floor:
                continue
            fresh.append(row)
        return _mail_items(fresh, target, labels=False)


def _mail_items(rows: Sequence[Mapping[str, Any]], target: CheckTarget, *, labels: bool) -> list[Item]:
    senders = list(target.filters.get("senders") or [])
    subject_filter = str(target.filters.get("subject_contains") or "").lower()
    items: list[Item] = []
    for row in rows:
        ident = row.get("id")
        if not isinstance(ident, str) or not ident:
            continue
        if labels:
            row_labels = row.get("label_ids")
            if isinstance(row_labels, list) and SKIP_LABELS & {str(x).upper() for x in row_labels}:
                continue
        # The allowlist again, on the parsed address: the query matched a
        # From header, and a display name can spell any address.
        if not shape.sender_allowed(shape.sender_address(row.get("from")), senders):
            continue
        subject = _subject if isinstance((_subject := row.get("subject")), str) else ""
        if subject_filter and subject_filter not in subject.lower():
            continue
        facts = shape.email_facts(row, preview_key="snippet" if labels else "preview")
        at = shape.parse_time(row.get("received")) if not labels else _mail_date(row.get("date"))
        items.append(Item(ident=f"mail:{ident}", facts=facts, at=at))
    return items


def _mail_date(value: Any) -> Optional[datetime]:
    if not isinstance(value, str) or not value.strip():
        return None
    from email.utils import parsedate_to_datetime

    try:
        parsed = parsedate_to_datetime(value)
    except (TypeError, ValueError, IndexError):
        return None
    if parsed is None:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


class CanvasAnnouncement:
    source, connector_type, action = "canvas.announcement", "canvas", "get_announcements"

    async def fetch(self, call: Call, target: CheckTarget, since: datetime, now: datetime) -> list[Item]:
        courses = _courses(target)
        args: dict[str, Any] = {"days": 7}
        if len(courses) == 1:
            args["course_id"] = next(iter(courses))
        items = []
        for row in _rows(await call(self.action, args)):
            ident = row.get("id")
            if ident is None or isinstance(ident, bool):
                continue
            if courses and str(row.get("course_id") or "") not in courses:
                continue
            items.append(
                Item(
                    ident=f"announcement:{ident}",
                    facts=shape.announcement_facts(row),
                    at=shape.parse_time(row.get("posted_at")),
                )
            )
        return items


class CanvasAssignment:
    """A diff over canvas.get_upcoming: a due item (not missing or late)
    the trigger has not seen before is a new assignment."""

    source, connector_type, action = "canvas.assignment", "canvas", "get_upcoming"
    _KINDS = frozenset({"assignment", "quiz", "discussion"})

    async def fetch(self, call: Call, target: CheckTarget, since: datetime, now: datetime) -> list[Item]:
        courses = _courses(target)
        items = []
        for row in _rows(await call(self.action, {"days": 30})):
            if row.get("type") not in self._KINDS or row.get("missing") or row.get("late"):
                continue
            url = _url if isinstance((_url := row.get("html_url")), str) else ""
            if courses and shape.canvas_course_id(url) not in courses:
                continue
            ident = url or f"{row.get('course')}|{row.get('title')}"
            if not ident.strip("|"):
                continue
            items.append(Item(ident=f"assignment:{ident}", facts=shape.assignment_facts(row)))
        return items


class CanvasGrade:
    source, connector_type, action = "canvas.grade", "canvas", "get_recent_grades"

    async def fetch(self, call: Call, target: CheckTarget, since: datetime, now: datetime) -> list[Item]:
        courses = _courses(target)
        args: dict[str, Any] = {"days": 7}
        if len(courses) == 1:
            args["course_id"] = next(iter(courses))
        items = []
        for row in _rows(await call(self.action, args)):
            ident = row.get("id")
            if ident is None or isinstance(ident, bool):
                continue
            if courses and str(row.get("course_id") or "") not in courses:
                continue
            graded = row.get("graded_at")
            items.append(
                Item(
                    ident=f"grade:{ident}:{graded}",
                    facts=shape.grade_facts(row),
                    at=shape.parse_time(graded),
                )
            )
        return items


class _CalendarSoon:
    source = "calendar.starting_soon"
    connector_type = ""
    action = ""

    def _window(self, target: CheckTarget, now: datetime) -> tuple[datetime, datetime]:
        lead = int(target.filters.get("lead_minutes") or LEAD_MINUTES[2])
        return now, now + timedelta(minutes=lead)

    @staticmethod
    def _item(ident: Any, start: Optional[datetime], window: tuple[datetime, datetime], **fields: Any) -> Optional[Item]:
        # Once per occurrence, only before it starts, only within the lead.
        if not isinstance(ident, str) or not ident or start is None:
            return None
        if not window[0] <= start <= window[1]:
            return None
        return Item(ident=f"event:{ident}@{shape.iso(start)}", facts=shape.event_facts(start=start, **fields))


class CalendarSoonGoogle(_CalendarSoon):
    connector_type, action = "google_workspace", "get_events"

    async def fetch(self, call: Call, target: CheckTarget, since: datetime, now: datetime) -> list[Item]:
        window = self._window(target, now)
        data = await call(self.action, {"time_min": shape.iso(window[0]), "time_max": shape.iso(window[1])})
        items = []
        for row in _rows(data):
            if row.get("status") == "cancelled":
                continue
            start_field = _start_field if isinstance((_start_field := row.get("start")), Mapping) else {}
            end_field = _end_field if isinstance((_end_field := row.get("end")), Mapping) else {}
            # An all-day event has a date and no dateTime: nothing starts.
            start = shape.parse_time(start_field.get("dateTime"))
            item = self._item(
                row.get("id"),
                start,
                window,
                title=row.get("summary"),
                end=end_field.get("dateTime"),
                location=row.get("location"),
            )
            if item is not None:
                items.append(item)
        return items


class CalendarSoonOutlook(_CalendarSoon):
    connector_type, action = "microsoft", "list_events"

    async def fetch(self, call: Call, target: CheckTarget, since: datetime, now: datetime) -> list[Item]:
        window = self._window(target, now)
        data = await call(
            self.action,
            {"start": shape.iso(window[0]), "end": shape.iso(window[1]), "limit": LIST_LIMIT},
        )
        items = []
        for row in _rows(data):
            if row.get("all_day") is True:
                continue
            item = self._item(
                row.get("id"),
                shape.parse_time(row.get("start")),
                window,
                title=row.get("subject"),
                end=row.get("end"),
                location=row.get("location"),
            )
            if item is not None:
                items.append(item)
        return items


class FilesDrive:
    source, connector_type, action = "files.new_in_folder", "google_workspace", "list_folder"
    _FOLDER_MIME = "application/vnd.google-apps.folder"

    async def fetch(self, call: Call, target: CheckTarget, since: datetime, now: datetime) -> list[Item]:
        folder = str(target.filters.get("folder") or "root")
        data = await call(self.action, {"folder_id": folder, "limit": LIST_LIMIT, "newest_first": True})
        items = []
        for row in _rows(data):
            ident = row.get("id")
            if not isinstance(ident, str) or not ident or row.get("mime_type") == self._FOLDER_MIME:
                continue
            items.append(
                Item(
                    ident=f"file:{ident}",
                    facts=shape.file_facts(name=row.get("name"), modified=row.get("modified"), link=row.get("link")),
                )
            )
        return items


class FilesOneDrive:
    source, connector_type, action = "files.new_in_folder", "microsoft", "list_folder"

    async def fetch(self, call: Call, target: CheckTarget, since: datetime, now: datetime) -> list[Item]:
        folder = str(target.filters.get("folder") or "root")
        args: dict[str, Any] = {"limit": LIST_LIMIT, "newest_first": True}
        if folder.lower() != "root":
            args["folder_id"] = folder
        items = []
        for row in _rows(await call(self.action, args)):
            ident = row.get("id")
            if not isinstance(ident, str) or not ident or row.get("is_folder") is True:
                continue
            items.append(
                Item(
                    ident=f"file:{ident}",
                    facts=shape.file_facts(name=row.get("name"), modified=row.get("modified"), link=row.get("web_url")),
                )
            )
        return items


class PageChanged:
    """Pushed, never polled: the page-watch sweeper reports a change
    (TriggerService.enqueue_page_change); nothing is fetched here."""

    source, connector_type, action = "page.changed", "", ""

    async def fetch(self, call: Call, target: CheckTarget, since: datetime, now: datetime) -> list[Item]:
        return []


ADAPTERS: dict[tuple[str, str], TriggerSource] = {
    (a.source, a.connector_type): a
    for a in (
        EmailGmail(),
        EmailOutlook(),
        CanvasAnnouncement(),
        CanvasAssignment(),
        CanvasGrade(),
        CalendarSoonGoogle(),
        CalendarSoonOutlook(),
        FilesDrive(),
        FilesOneDrive(),
        PageChanged(),
    )
}


def adapter_for(source: str, connector_type: Optional[str]) -> Optional[TriggerSource]:
    return ADAPTERS.get((source, connector_type or ""))


async def run_check(
    adapter: TriggerSource,
    call: Call,
    target: CheckTarget,
    now: datetime,
    *,
    max_items: int = shape.MAX_ITEMS_PER_BATCH,
) -> CheckOutcome:
    """One check: fetch what the source shows now, keep only items not seen
    before (and not older than the trigger), and advance the cursor. The
    first check (no baseline yet) only records what is there. Keys of
    everything visible now stay in the ring, so an item that stays listed
    never fires twice however many new ones pass."""
    cursor = target.cursor if isinstance(target.cursor, Mapping) else {}
    seen = [k for k in (cursor.get("seen") or []) if isinstance(k, str)]
    baseline = target.baseline_at is None
    watermark = shape.parse_time(cursor.get("watermark")) or target.baseline_at or now
    since = now if baseline else min(watermark, now)
    found = await adapter.fetch(call, target, since, now)
    known = set(seen)
    visible: list[str] = []
    fresh: list[tuple[str, Item]] = []
    floor = (target.baseline_at - timedelta(seconds=OVERLAP_SECONDS)) if target.baseline_at else None
    for item in found:
        key = shape.external_key(target.source, item.ident)
        short = key[:16]
        if short in visible:
            continue
        visible.append(short)
        if short in known or baseline:
            continue
        if floor is not None and item.at is not None and item.at < floor:
            continue
        fresh.append((key, item))
    ring = [k for k in seen if k not in set(visible)] + visible
    new_cursor = {"watermark": shape.iso(now), "seen": ring[-SEEN_RING:]}
    kept = fresh[:max_items]
    return CheckOutcome(items=kept, more=len(fresh) - len(kept), cursor=new_cursor, baseline=baseline)


def read_actions(connector_type: str) -> tuple[str, ...]:
    """Every READ action of *connector_type* an unattended run may use
    (canonical names), for a task run's reads."""
    from services.agent.tool_registry import CONNECTOR_CATALOG
    from services.automation.fence import classify_tool

    return tuple(
        f"{connector_type}.{spec.action}"
        for spec in CONNECTOR_CATALOG.get(connector_type, [])
        if classify_tool(f"{connector_type}.{spec.action}") == "read"
    )


def write_actions(connector_type: str) -> tuple[str, ...]:
    """Every WRITE action of *connector_type* an unattended run may propose
    (never a DELETE, EXECUTE or FINANCIAL one)."""
    from services.agent.tool_registry import CONNECTOR_CATALOG
    from services.automation.fence import classify_tool

    return tuple(
        f"{connector_type}.{spec.action}"
        for spec in CONNECTOR_CATALOG.get(connector_type, [])
        if classify_tool(f"{connector_type}.{spec.action}") == "write"
    )


def required_scope(source: str, connector_type: str) -> Optional[str]:
    """The scope the source's read needs on the row, from the catalog."""
    from services.agent.tool_registry import resolve_tool

    action = SPECS[source].action_for(connector_type)
    if action is None:
        return None
    resolved = resolve_tool(f"{connector_type}.{action}")
    return resolved.spec.required_scope if resolved is not None else None
