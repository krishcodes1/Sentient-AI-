"""Shapes Canvas planner items and missing submissions into the compact
"what's due" rows that ``canvas.get_upcoming`` returns.

Why it exists: Answering "what's due this week" took get_courses plus one
get_assignments call per course, and the runtime cuts each of those results
to about 2000 characters, so due items fell silently out of the middle of a
long course. Two account-wide Canvas reads cover the same ground: the
planner (everything with a date in a window, with the user's submission
state) and the missing-submissions list. This module turns them into one
bounded answer. Each row is a few short fields, the list is capped by rows
and by the characters the model is shown, and the counts always cover
everything found, so a cut list says it was cut. It only shapes data and
reads the clock through ``_now`` (a seam for tests); the requests are made
by ``CanvasConnector.get_upcoming``.

Everything read here is untrusted Canvas content. Titles and course names
become one line of printable text, a link is kept only when it points into
the user's own Canvas instance, and nothing here decides an action.
"""

from __future__ import annotations

import json
import math
import re
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from .base import ConnectorError, PromptGuard, path_segment

DEFAULT_DAYS = 7
MAX_DAYS = 30
# Late and missing flags need past items too: the planner is read from this
# many days back, and a past item is kept only when it is late or missing.
# (The missing-submissions list has no window; it covers every active
# course's missing work, however old.)
LATE_LOOKBACK_DAYS = 14
MAX_ROWS = 50
# The rows' compact JSON, measured after the connector's own PromptGuard
# pass, stays under this. A typical row is 230 to 280 characters, so 50 of
# them fit; rows with the longest titles and links stop sooner. With the
# counts and the executor's envelope the whole result fits
# RESULT_CHAR_BUDGETS["canvas.get_upcoming"] (services/agent/runtime.py),
# so the runtime never cuts it in the middle.
MAX_ITEMS_CHARS = 14_000
TITLE_CHARS = 120
COURSE_CHARS = 60
URL_CHARS = 200

# Planner item types, as the short labels the rows carry. Events and
# announcements have a date but nothing is due; canvas.get_calendar_events
# covers events. A type Canvas adds later is still listed, as "other".
_KINDS: dict[str, str] = {
    "assignment": "assignment",
    "sub_assignment": "assignment",
    "quiz": "quiz",
    "discussion_topic": "discussion",
    "wiki_page": "page",
    "planner_note": "todo",
    "assessment_request": "peer_review",
}
_NOT_DUE = frozenset({"calendar_event", "announcement"})

# Where a Canvas item lives under /courses/:id/, for a row whose own link
# is missing or points off the instance.
_LINK_SEGMENTS: dict[str, str] = {
    "assignment": "assignments",
    "quiz": "quizzes",
    "discussion_topic": "discussion_topics",
}

# Printable characters that still render as nothing; with every
# non-printable character they are dropped from titles, because the runtime
# re-spells invisible characters as \uXXXX (six characters each) and hidden
# text is how an injected instruction hides from the person reading along.
_BLANK_LOOKING = frozenset("\u034f\u115f\u1160\u17b4\u17b5\u3164\uffa0")

_ID_RE = re.compile(r"[0-9]{1,20}")

_DAYS_ERROR = f"days must be a whole number of days from 1 to {MAX_DAYS}."


def _now() -> datetime:
    return datetime.now(timezone.utc)


@dataclass(frozen=True)
class Window:
    """The period one call covers, all in UTC and to the second."""

    now: datetime
    until: datetime
    late_since: datetime
    days: int


def parse_days(value: Any) -> int:
    """``days`` as the model sent it, clamped to 1..MAX_DAYS.

    A missing value means the default; a number past either end is pulled
    in (the result reports the days it used); anything that is not a whole
    number is refused rather than guessed at.
    """
    if value is None:
        return DEFAULT_DAYS
    if isinstance(value, bool):
        raise ConnectorError(_DAYS_ERROR)
    if isinstance(value, str):
        try:
            value = int(value.strip())
        except ValueError:
            raise ConnectorError(_DAYS_ERROR)
    if isinstance(value, float):
        if not math.isfinite(value) or not value.is_integer():
            raise ConnectorError(_DAYS_ERROR)
        value = int(value)
    if not isinstance(value, int):
        raise ConnectorError(_DAYS_ERROR)
    return max(1, min(MAX_DAYS, value))


def window_for(days: Any, *, now: Optional[datetime] = None) -> Window:
    start = (now or _now()).astimezone(timezone.utc).replace(microsecond=0)
    span = parse_days(days)
    return Window(
        now=start,
        until=start + timedelta(days=span),
        late_since=start - timedelta(days=LATE_LOOKBACK_DAYS),
        days=span,
    )


def iso(moment: Optional[datetime]) -> Optional[str]:
    """``2026-09-26T03:59:00Z``: UTC, to the second."""
    if moment is None:
        return None
    return moment.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


@dataclass
class _Item:
    key: tuple[str, ...]
    due: Optional[datetime]
    course: str
    title: str
    kind: str
    points: Optional[float]
    submitted: bool
    missing: bool
    late: bool
    url: Optional[str]

    def row(self) -> dict[str, Any]:
        return {
            "course": self.course,
            "title": self.title,
            "type": self.kind,
            "due_at": iso(self.due),
            "points_possible": self.points,
            "submitted": self.submitted,
            "missing": self.missing,
            "late": self.late,
            "html_url": self.url,
        }


def summarize(planner: Any, missing: Any, *, window: Window, base_url: str) -> dict[str, Any]:
    """One bounded what's-due answer from the two Canvas lists.

    Rows are ordered by what the question is about: work due in the window
    (soonest first), then missing work, then late work (both most recent
    first). ``counts`` and ``total`` cover every row found, before the
    ``MAX_ROWS`` and ``MAX_ITEMS_CHARS`` caps; ``truncated`` says whether
    any were left out.
    """
    if not isinstance(planner, list) or not isinstance(missing, list):
        # A dict here is an error body or a changed API. Reporting "nothing
        # due" on it would be a confident wrong answer; refuse instead.
        raise ConnectorError("Canvas returned an unexpected response for the due-items lists.")

    found: dict[tuple[str, ...], _Item] = {}
    for index, raw in enumerate(planner):
        _merge(found, _from_planner(raw, index, window, base_url))
    for index, raw in enumerate(missing):
        _merge(found, _from_missing(raw, index, base_url))

    upcoming: list[_Item] = []
    missing_items: list[_Item] = []
    late_items: list[_Item] = []
    for item in found.values():
        if item.missing:
            missing_items.append(item)
        elif item.late:
            late_items.append(item)
        elif item.due is None or window.now <= item.due <= window.until:
            upcoming.append(item)
        # Anything else is past and on time (or not submittable): not due.

    far = datetime.max.replace(tzinfo=timezone.utc)
    upcoming.sort(key=lambda i: (i.due or far, i.course, i.title))
    for past in (missing_items, late_items):
        past.sort(key=lambda i: (i.due is None, -(i.due or far).timestamp(), i.course, i.title))
    ordered = upcoming + missing_items + late_items

    items: list[dict[str, Any]] = []
    used = 2  # the list's brackets
    for item in ordered[:MAX_ROWS]:
        row = item.row()
        size = _shown_chars(row) + 1  # and its comma
        if used + size > MAX_ITEMS_CHARS:
            break
        items.append(row)
        used += size

    return {
        "as_of": iso(window.now),
        "until": iso(window.until),
        "days": window.days,
        "late_since": iso(window.late_since),
        "counts": {
            "upcoming": len(upcoming),
            "missing": len(missing_items),
            "late": len(late_items),
        },
        "total": len(ordered),
        "count": len(items),
        "truncated": len(items) < len(ordered),
        "items": items,
    }


def _from_planner(raw: Any, index: int, window: Window, base_url: str) -> Optional[_Item]:
    if not isinstance(raw, dict):
        return None
    ptype = raw.get("plannable_type")
    if not isinstance(ptype, str) or ptype in _NOT_DUE:
        return None
    plannable = raw.get("plannable")
    if not isinstance(plannable, dict):
        plannable = {}
    state = raw.get("submissions")
    if not isinstance(state, dict):
        state = {}  # Canvas sends false for items with nothing to submit
    if state.get("excused") is True:
        return None  # excused work is not due

    # plannable_date is the date the planner files the item under, with
    # the user's own due-date override applied; the rest are fallbacks.
    due = (
        _parse_time(raw.get("plannable_date"))
        or _parse_time(plannable.get("due_at"))
        or _parse_time(plannable.get("todo_date"))
    )
    if due is not None and not window.late_since <= due <= window.until:
        return None  # outside what was asked for, whatever Canvas sent

    course_id = raw.get("course_id")
    plannable_id = raw.get("plannable_id", plannable.get("id"))
    assignment_id = plannable_id if ptype == "assignment" else plannable.get("assignment_id")
    key = _assignment_key(assignment_id) or (
        "planner",
        ptype,
        _ident(plannable_id) or f"#{index}",
    )
    course = raw.get("context_name") if raw.get("context_type") != "User" else ""
    return _Item(
        key=key,
        due=due,
        course=_text(course, COURSE_CHARS),
        title=_text(plannable.get("title") or plannable.get("name"), TITLE_CHARS) or "(untitled)",
        kind=_KINDS.get(ptype, "other"),
        points=_points(plannable.get("points_possible")),
        submitted=state.get("submitted") is True,
        missing=state.get("missing") is True,
        late=state.get("late") is True,
        url=_link(raw.get("html_url"), base_url)
        or _course_link(base_url, course_id, ptype, plannable_id),
    )


def _from_missing(raw: Any, index: int, base_url: str) -> Optional[_Item]:
    if not isinstance(raw, dict):
        return None
    course = raw.get("course")
    if not isinstance(course, dict):
        course = {}
    types = raw.get("submission_types")
    if not isinstance(types, list):
        types = []
    if "online_quiz" in types or raw.get("is_quiz_assignment") is True:
        kind = "quiz"
    elif "discussion_topic" in types:
        kind = "discussion"
    else:
        kind = "assignment"
    assignment_id = raw.get("id")
    course_id = raw.get("course_id", course.get("id"))
    return _Item(
        key=_assignment_key(assignment_id) or ("missing", f"#{index}"),
        due=_parse_time(raw.get("due_at")),
        course=_text(course.get("name"), COURSE_CHARS),
        title=_text(raw.get("name"), TITLE_CHARS) or "(untitled)",
        kind=kind,
        points=_points(raw.get("points_possible")),
        submitted=False,
        missing=True,
        late=False,
        url=_link(raw.get("html_url"), base_url)
        or _course_link(base_url, course_id, "assignment", assignment_id),
    )


def _merge(found: dict[tuple[str, ...], _Item], item: Optional[_Item]) -> None:
    """One row per assignment: the planner and the missing list both name
    a missing assignment, and its flags are the union of what each says."""
    if item is None:
        return
    existing = found.get(item.key)
    if existing is None:
        found[item.key] = item
        return
    existing.missing = existing.missing or item.missing
    existing.late = existing.late or item.late
    existing.submitted = existing.submitted or item.submitted
    existing.course = existing.course or item.course
    existing.url = existing.url or item.url
    if existing.due is None:
        existing.due = item.due
    if existing.points is None:
        existing.points = item.points


def _assignment_key(assignment_id: Any) -> Optional[tuple[str, ...]]:
    # Assignment ids are unique across a Canvas instance, so the id alone
    # matches a planner item to its missing-submissions entry.
    ident = _ident(assignment_id)
    return ("assignment", ident) if ident else None


def _ident(value: Any) -> Optional[str]:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return str(value) if value >= 0 else None
    if isinstance(value, str) and _ID_RE.fullmatch(value):
        return value
    return None


def _shown_chars(row: dict[str, Any]) -> int:
    """The row's size as the model is shown it: after the connector's
    PromptGuard pass (a redaction can lengthen text), as compact JSON with
    non-ASCII kept, the way the runtime serializes results."""
    shown, _ = PromptGuard.scan(row)
    return len(json.dumps(shown, ensure_ascii=False, separators=(",", ":")))


def _text(value: Any, limit: int) -> str:
    if not isinstance(value, str):
        return ""
    cleaned = "".join(c if c.isprintable() and c not in _BLANK_LOOKING else " " for c in value)
    cleaned = " ".join(cleaned.split())
    if len(cleaned) > limit:
        cleaned = cleaned[: limit - 1].rstrip() + "…"
    return cleaned


def _parse_time(value: Any) -> Optional[datetime]:
    if not isinstance(value, str) or not value.strip() or len(value) > 40:
        return None
    try:
        parsed = datetime.fromisoformat(value.strip())
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _points(value: Any) -> Optional[float]:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    if not math.isfinite(value):
        return None
    if float(value).is_integer():
        return int(value)
    return round(float(value), 2)


def _link(value: Any, base_url: str) -> Optional[str]:
    """A link into the user's Canvas instance, or None.

    Planner links are relative ("/courses/1/assignments/2"); missing
    submissions carry absolute ones. Either way the row only ever links
    into ``base_url``: a link is content from the server and a row is not
    the place for one that leads anywhere else.
    """
    if not isinstance(value, str):
        return None
    value = value.strip()
    if not value or len(value) > URL_CHARS:
        return None
    if any(c.isspace() or not c.isprintable() for c in value):
        return None
    if value.startswith("/") and not value.startswith("//"):
        url = f"{base_url}{value}"
    elif value.lower().startswith(f"{base_url.lower()}/"):
        url = value
    else:
        return None
    return url if len(url) <= URL_CHARS else None


def _course_link(base_url: str, course_id: Any, ptype: str, item_id: Any) -> Optional[str]:
    segment = _LINK_SEGMENTS.get(ptype)
    course = _ident(course_id)
    item = _ident(item_id)
    if segment is None or course is None or item is None:
        return None
    url = f"{base_url}/courses/{path_segment(course)}/{segment}/{path_segment(item)}"
    return url if len(url) <= URL_CHARS else None
