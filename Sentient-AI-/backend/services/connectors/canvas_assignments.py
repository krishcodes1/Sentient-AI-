"""Shapes Canvas assignments, submissions and calendar events into the compact
rows that ``canvas.get_assignments``, ``canvas.get_submissions`` and
``canvas.get_calendar_events`` return.

Why it exists: these three reads used to hand Canvas's raw objects to the
model. Every assignment object carries ``secure_params``, a signed token whose
payload repeats the assignment's description; the runtime's prompt guard
decoded it, found words such as "system" or "token" in ordinary coursework and
replaced the whole result, so the assistant could never read an assignment.
The raw objects are also many times the result budget, and they carry things
the model has no use for: launch data for external tools, rubrics, and file
links with a download token in them. Each row here copies a few named fields
and nothing else, a list is capped by rows and by the characters the model is
shown and says when it was cut, and one assignment's description is turned
from HTML into capped plain text. It only shapes data and reads the clock
through ``_now`` (a seam for tests); the requests are made by
``CanvasConnector``.

Connects to: ``canvas_activity`` for the row helpers and the list caps (the
ones announcements and recent grades use), ``canvas_upcoming`` for the title
length, ``shaping`` for the text cap.

Everything read here is untrusted Canvas content (a teacher writes an
assignment and an event, a student writes a submission), and nothing here
decides an action.
"""

from __future__ import annotations

import sys
from datetime import datetime, timezone
from operator import itemgetter
from typing import Any, Optional

from .base import ConnectorError
from .canvas_activity import (
    COURSE_CHARS,
    HTML_READ_CHARS,
    _capped,
    _ident,
    _line,
    _number,
    _shown_chars,
    _time,
    html_to_text,
    iso,
    link,
)
from .canvas_upcoming import TITLE_CHARS
from .shaping import cap_text

# One assignment's description, as plain text. It is the one long field, so
# it has two limits: its own length, and its length as the model is shown it
# (quotes, backslashes and line breaks are two characters each there). With
# the other fields and the executor's envelope, the second keeps one
# assignment inside the 16000 characters these reads are sized for, as the
# list cap in canvas_activity keeps a full list (the entries these three
# tools need in RESULT_CHAR_BUDGETS, services/agent/runtime.py; raise both
# together), so the runtime never cuts the middle out of either.
DESCRIPTION_CHARS = 8000
DESCRIPTION_SHOWN_CHARS = 12_000
# Canvas has about a dozen submission types and an assignment allows a few.
MAX_SUBMISSION_TYPES = 8
SUBMISSION_TYPE_CHARS = 30
LOCATION_CHARS = 120
STATE_CHARS = 24


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _envelope(rows: list[dict[str, Any]]) -> dict[str, Any]:
    """What every list here answers with: ``total`` counts the rows found,
    ``count`` the rows listed, and ``truncated`` says whether any were left
    out by the row and character caps."""
    items, truncated = _capped(rows)
    return {"count": len(items), "total": len(rows), "truncated": truncated, "items": items}


def _row(raw: Any, base_url: str) -> Optional[dict[str, Any]]:
    """One assignment as the fields a student asks about, or None when the
    entry is not an assignment with an id.

    Only the keys named here are copied, so secure_params, the LTI ids, an
    external tool's launch data and the rubric never come through. The
    student's own state is listed when Canvas sent their submission, as the
    three flags canvas.get_upcoming uses. The score is left out on purpose:
    this read needs only the assignments scope, and scores sit behind the
    grades and submissions scopes.
    """
    if not isinstance(raw, dict) or (ident := _ident(raw.get("id"))) is None:
        return None
    types = raw.get("submission_types")
    row: dict[str, Any] = {
        "id": ident,
        "name": _line(raw.get("name"), TITLE_CHARS) or "(untitled)",
        "due_at": _time(raw.get("due_at")),
        "points_possible": _number(raw.get("points_possible")),
        "submission_types": [
            _line(kind, SUBMISSION_TYPE_CHARS)
            for kind in (types[:MAX_SUBMISSION_TYPES] if isinstance(types, list) else [])
            if isinstance(kind, str)
        ],
        "html_url": link(raw.get("html_url"), base_url),
        "locked": raw.get("locked_for_user") is True,
    }
    submission = raw.get("submission")
    if isinstance(submission, dict):
        row["submitted"] = _time(submission.get("submitted_at")) is not None
        row["missing"] = submission.get("missing") is True
        row["late"] = submission.get("late") is True
    return row


def rows(raw: Any, *, base_url: str) -> dict[str, Any]:
    """A course's assignments in the order a student asks about them: work
    still due (soonest first), then work with no due date, then past work
    (latest first).

    Canvas lists a course oldest first. Cut at the end of that order, a
    course with more assignments than fit would lose this week's work and
    keep the first week's; in this order the rows left out are the oldest.
    """
    if not isinstance(raw, list):
        # A dict here is an error body or a changed API. "No assignments"
        # would be a confident wrong answer; refuse instead.
        raise ConnectorError("Canvas returned an unexpected response for assignments.")
    shaped = [row for row in (_row(item, base_url) for item in raw) if row is not None]
    # A known limit: no paging or search past the cap (about 48 rows of ordinary
    # length); add a search argument (Canvas's search_term) when a long
    # course needs its oldest work.
    # A row's due_at is always "YYYY-MM-DDTHH:MM:SSZ", so text order is time order.
    now, due_at = iso(_now()), itemgetter("due_at")
    due = sorted((row for row in shaped if row["due_at"] and row["due_at"] >= now), key=due_at)
    undated = [row for row in shaped if not row["due_at"]]
    past = sorted(
        (row for row in shaped if row["due_at"] and row["due_at"] < now), key=due_at, reverse=True
    )
    return _envelope(due + undated + past)


def detail(raw: Any, *, base_url: str) -> dict[str, Any]:
    """One assignment: its row plus the description as plain text.

    The description is the teacher's HTML read as text (tags, scripts,
    styles and comments gone), cut to ``DESCRIPTION_CHARS``; ``truncated``
    says whether any of it was left out.
    """
    row = _row(raw, base_url)
    if row is None:
        raise ConnectorError("Canvas returned an unexpected response for the assignment.")
    # sys.maxsize: the helper's own cut of the text never happens, so the
    # cut below is the only cut of the text. The helper reads only the first
    # HTML_READ_CHARS of the HTML, though (a pasted inline image can be
    # longer than that), and what it never read counts as left out too.
    html = raw.get("description")
    text, truncated = cap_text(html_to_text(html, sys.maxsize), DESCRIPTION_CHARS)
    truncated = truncated or (isinstance(html, str) and len(html) > HTML_READ_CHARS)
    # Shortened further until it fits as shown: a description that is mostly
    # quotes or line breaks is up to twice its length there.
    while _shown_chars({"description": text}) > DESCRIPTION_SHOWN_CHARS:
        text, truncated = text[: len(text) * 9 // 10], True
    return {**row, "description": text, "truncated": truncated}


def submissions(raw: Any) -> dict[str, Any]:
    """An assignment's submissions as rows: when the work was handed in,
    where it stands and what it scored. A student's token lists their own.

    The submitted text, the comments and the files stay behind: a file's
    link carries a download token, and none of it is needed to say whether
    the work was handed in and how it was graded.
    """
    if not isinstance(raw, list):
        raise ConnectorError("Canvas returned an unexpected response for submissions.")
    shaped: list[dict[str, Any]] = []
    for item in raw:
        if not isinstance(item, dict):
            continue
        grade = item.get("grade")
        shaped.append(
            {
                "user_id": _ident(item.get("user_id")),
                "attempt": _number(item.get("attempt")),
                "submitted_at": _time(item.get("submitted_at")),
                "workflow_state": _line(item.get("workflow_state"), STATE_CHARS) or None,
                "missing": item.get("missing") is True,
                "late": item.get("late") is True,
                "excused": item.get("excused") is True,
                "score": _number(item.get("score")),
                "grade": _line(str(grade), STATE_CHARS) if grade is not None else None,
                "graded_at": _time(item.get("graded_at")),
            }
        )
    return _envelope(shaped)


def calendar_events(raw: Any, *, base_url: str) -> dict[str, Any]:
    """Calendar events as rows: what, when, where, whose calendar, a link.

    The description stays behind, and so does the whole assignment object
    (secure_params included) that Canvas embeds in an assignment's event.
    """
    if not isinstance(raw, list):
        raise ConnectorError("Canvas returned an unexpected response for calendar events.")
    return _envelope(
        [
            {
                "title": _line(item.get("title"), TITLE_CHARS) or "(untitled)",
                "start_at": _time(item.get("start_at")),
                "end_at": _time(item.get("end_at")),
                "all_day": item.get("all_day") is True,
                "location": _line(item.get("location_name"), LOCATION_CHARS),
                "calendar": _line(item.get("context_name"), COURSE_CHARS),
                "html_url": link(item.get("html_url"), base_url),
            }
            for item in raw
            if isinstance(item, dict)
        ]
    )
