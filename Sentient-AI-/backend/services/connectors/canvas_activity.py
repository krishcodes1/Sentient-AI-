"""Shapes Canvas announcements and recently graded submissions into the compact
rows that ``canvas.get_announcements`` and ``canvas.get_recent_grades`` return.

Why it exists: the announcement and grade triggers (services/triggers) and the
model both need "what is new on Canvas" without Canvas's raw objects, which
carry kilobytes of HTML, rubric data and ids. Each row keeps a few short
fields; announcement HTML becomes plain text (the stdlib reader in
services/tools/html_text.py), capped at 1500 characters and passed through
the connector's PromptGuard; a link is kept only when it points into the
user's own Canvas instance. The list is capped by rows and by the characters
the model is shown. It only shapes data and reads the clock through ``_now``
(a seam for tests); the requests are made by ``CanvasConnector``.

Everything read here is untrusted Canvas content (anyone who can post in a
course writes an announcement), and nothing here decides an action.
"""

from __future__ import annotations

import json
import math
import re
from datetime import datetime, timedelta, timezone
from typing import Any, Mapping, Optional

from .base import ConnectorError, PromptGuard
from .canvas_upcoming import parse_days

MAX_COURSES = 20
MAX_GRADE_COURSES = 12
PER_PAGE = 50
MAX_ROWS = 50
# The rows' compact JSON, as the model is shown it, stays under this, so
# the result fits RESULT_CHAR_BUDGETS for these tools (the default budget
# otherwise cuts a list in the middle).
MAX_ITEMS_CHARS = 14_000
TITLE_CHARS = 200
AUTHOR_CHARS = 80
COURSE_CHARS = 80
TEXT_CHARS = 1500
URL_CHARS = 300

_ID_RE = re.compile(r"^[0-9]{1,20}$")
_CONTEXT_RE = re.compile(r"^course_([0-9]{1,20})$")
_BLANK_LOOKING = frozenset("͏ᅟᅠ឴឵ㅤﾠ")
_COURSE_ID_ERROR = "course_id must be a numeric Canvas course id from canvas.get_courses."


def _now() -> datetime:
    return datetime.now(timezone.utc)


def iso(moment: datetime) -> str:
    return moment.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def since(days: Any, *, now: Optional[datetime] = None) -> tuple[int, datetime]:
    """(days used, the start of the window): ``days`` 1-30, default 7."""
    span = parse_days(days)
    start = (now or _now()).astimezone(timezone.utc).replace(microsecond=0)
    return span, start - timedelta(days=span)


def parse_course_id(value: Any) -> Optional[str]:
    """A course id argument as a plain numeric string, None when absent;
    anything else is refused before any request."""
    if value is None or (isinstance(value, str) and not value.strip()):
        return None
    if isinstance(value, bool):
        raise ConnectorError(_COURSE_ID_ERROR)
    text = str(value).strip()
    if not _ID_RE.match(text):
        raise ConnectorError(_COURSE_ID_ERROR)
    return text


def _ident(value: Any) -> Optional[str]:
    if isinstance(value, bool):
        return None
    if isinstance(value, int) and value >= 0:
        return str(value)
    if isinstance(value, str) and _ID_RE.match(value):
        return value
    return None


def _line(value: Any, limit: int) -> str:
    if not isinstance(value, str):
        return ""
    cleaned = "".join(c if c.isprintable() and c not in _BLANK_LOOKING else " " for c in value)
    cleaned = " ".join(cleaned.split())
    if len(cleaned) > limit:
        cleaned = cleaned[: limit - 1].rstrip() + "…"
    return cleaned


def html_to_text(html: Any, limit: int = TEXT_CHARS) -> str:
    """Announcement HTML as capped plain text, PromptGuard-sanitised."""
    if not isinstance(html, str) or not html.strip():
        return ""
    from services.tools.html_text import extract_readable_text

    _title, text = extract_readable_text(html[:200_000])
    lines = []
    for line in text.split("\n"):
        kept = "".join(c if c.isprintable() and c not in _BLANK_LOOKING else " " for c in line)
        kept = " ".join(kept.split())
        if kept:
            lines.append(kept)
    joined = "\n".join(lines)
    if len(joined) > limit:
        joined = joined[: limit - 1].rstrip() + "…"
    cleaned, _ = PromptGuard.scan(joined)
    return cleaned


def _time(value: Any) -> Optional[str]:
    if not isinstance(value, str) or not value.strip() or len(value) > 40:
        return None
    try:
        parsed = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return iso(parsed)


def _number(value: Any) -> Optional[float]:
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value):
        return None
    return int(value) if float(value).is_integer() else round(float(value), 2)


def link(value: Any, base_url: str) -> Optional[str]:
    """A link into the user's Canvas instance, or None (relative Canvas
    paths are made absolute on the instance)."""
    if not isinstance(value, str):
        return None
    value = value.strip()
    if not value or len(value) > URL_CHARS or any(c.isspace() or not c.isprintable() for c in value):
        return None
    if value.startswith("/") and not value.startswith("//"):
        url = f"{base_url}{value}"
    elif value.lower().startswith(f"{base_url.lower()}/"):
        url = value
    else:
        return None
    return url if len(url) <= URL_CHARS else None


def _shown_chars(row: Mapping[str, Any]) -> int:
    shown, _ = PromptGuard.scan(dict(row))
    return len(json.dumps(shown, ensure_ascii=False, separators=(",", ":")))


def _capped(rows: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], bool]:
    kept: list[dict[str, Any]] = []
    used = 2
    for row in rows[:MAX_ROWS]:
        size = _shown_chars(row) + 1
        if used + size > MAX_ITEMS_CHARS:
            break
        kept.append(row)
        used += size
    return kept, len(kept) < len(rows)


def course_names(courses: Any) -> dict[str, str]:
    """{course id: name} from canvas.get_courses rows (at most MAX_COURSES)."""
    names: dict[str, str] = {}
    if not isinstance(courses, list):
        return names
    for course in courses:
        if not isinstance(course, dict):
            continue
        ident = _ident(course.get("id"))
        if ident is None or ident in names:
            continue
        names[ident] = _line(course.get("name") or course.get("course_code"), COURSE_CHARS)
        if len(names) >= MAX_COURSES:
            break
    return names


def announcements(raw: Any, *, names: Mapping[str, str], base_url: str, days: int) -> dict[str, Any]:
    """The announcements answer: newest first, capped."""
    if not isinstance(raw, list):
        raise ConnectorError("Canvas returned an unexpected response for announcements.")
    rows: list[tuple[str, dict[str, Any]]] = []
    for item in raw:
        if not isinstance(item, dict):
            continue
        ident = _ident(item.get("id"))
        if ident is None:
            continue
        match = _CONTEXT_RE.match(str(item.get("context_code") or ""))
        course_id = match.group(1) if match else None
        author = _author if isinstance((_author := item.get("author")), dict) else {}
        posted = _time(item.get("posted_at")) or _time(item.get("delayed_post_at")) or ""
        rows.append(
            (
                posted,
                {
                    "id": ident,
                    "course": names.get(course_id or "", ""),
                    "course_id": course_id,
                    "title": _line(item.get("title"), TITLE_CHARS) or "(untitled)",
                    "posted_at": posted or None,
                    "author": _line(author.get("display_name") or item.get("user_name"), AUTHOR_CHARS),
                    "text": html_to_text(item.get("message")),
                    "html_url": link(item.get("html_url"), base_url),
                },
            )
        )
    rows.sort(key=lambda pair: pair[0], reverse=True)
    items, truncated = _capped([row for _posted, row in rows])
    return {"days": days, "total": len(rows), "count": len(items), "truncated": truncated, "items": items}


def grade_rows(course_id: str, course_name: str, raw: Any, *, base_url: str) -> list[dict[str, Any]]:
    """One course's graded submissions (the caller's own) as rows."""
    if not isinstance(raw, list):
        raise ConnectorError("Canvas returned an unexpected response for submissions.")
    rows: list[dict[str, Any]] = []
    for item in raw:
        if not isinstance(item, dict):
            continue
        ident = _ident(item.get("id"))
        graded = _time(item.get("graded_at"))
        if ident is None or graded is None or item.get("workflow_state") not in (None, "graded"):
            continue
        assignment = _assignment if isinstance((_assignment := item.get("assignment")), dict) else {}
        grade = item.get("grade")
        rows.append(
            {
                "id": ident,
                "assignment": _line(assignment.get("name"), TITLE_CHARS) or "(untitled)",
                "course": course_name,
                "course_id": course_id,
                "graded_at": graded,
                "score": _number(item.get("score")),
                "grade": _line(str(grade), 24) if grade is not None else None,
                "points_possible": _number(assignment.get("points_possible")),
                "html_url": link(assignment.get("html_url"), base_url),
            }
        )
    return rows


def grades(rows: list[dict[str, Any]], *, days: int, courses: int) -> dict[str, Any]:
    """The recent-grades answer: newest first, capped."""
    ordered = sorted(rows, key=lambda row: row.get("graded_at") or "", reverse=True)
    items, truncated = _capped(ordered)
    return {
        "days": days,
        "courses_checked": courses,
        "total": len(ordered),
        "count": len(items),
        "truncated": truncated,
        "items": items,
    }
