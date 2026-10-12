"""The goals store: every rule a goal obeys (its arguments, sizes, limits, the
duplicate-title rule, screening, milestone states and progress) and the JSON
shapes a goal is shown in, as async functions over an ``AsyncSession``.

Why it exists: a goal made in chat (the goals.* tools, services/tools/goals.py)
and one made on the Goals page (api/routes/goals.py) must obey identical
rules, so both call these functions and nothing else writes the goals tables:
- every lookup is scoped to the caller's user id; another user's goal, or an
  id that is not one, reads as not found;
- unknown arguments are refused, never ignored;
- every free-text field (title, description, current_state, milestone titles,
  notes) is cleaned and screened before it is stored: text the prompt guard
  grades unsafe is refused, and so is anything the shared secret detector
  flags under the MEMORY policy; a guard or detector error refuses too (fail
  closed);
- a second active or paused goal with the same title (folded case and
  spaces) is refused with the existing goal's id;
- the limits (models/goal.py) are errors that name the limit; nothing is
  dropped silently;
- milestones are never deleted, only dropped and reopened, so their
  positions stay 0..n-1 with no gaps;
- an error never repeats the user's text (only field names, ids and
  numbers), so it is safe to show, log and audit.
The functions flush and never commit: the caller owns the transaction (the
toolkit commits its own session, a route's ``get_db`` the request's). A
create, an update and a progress note take a per-user lock before their
first read, so two of one user's writers never pass the same check at once. A
refusal is a ``GoalError`` carrying its rule and the HTTP status a route
answers with.
"""

from __future__ import annotations

import re
import unicodedata
import uuid
from dataclasses import dataclass
from datetime import date, datetime, timezone
from typing import Any, Iterable, Mapping, Optional, Sequence

import structlog
from sqlalchemy import delete, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from models.goal import (
    CHECK_INS,
    CURRENT_STATE_MAX_CHARS,
    DESCRIPTION_MAX_CHARS,
    ENTRY_SOURCES,
    GOAL_CATEGORIES,
    GOAL_STATUSES,
    MAX_ENTRIES_PER_GOAL,
    MAX_GOALS_PER_USER,
    MAX_MILESTONES_PER_CALL,
    MAX_MILESTONES_PER_GOAL,
    MAX_OPEN_GOALS,
    MILESTONE_TITLE_MAX_CHARS,
    NOTE_MAX_CHARS,
    OPEN_STATUSES,
    TITLE_MAX_CHARS,
    Goal,
    GoalEntry,
    GoalMilestone,
)
from services.agent.prompt_guard import _INVISIBLE_CHARS, PromptGuard
from services.security.policies import MEMORY
from services.security.redact import DETECTOR_ERROR_LABEL, first_finding
from services.skills.prompt import VARIATION_SELECTORS

logger = structlog.get_logger(__name__)

# The fields each operation takes (the toolkit adds goal_id; a route takes
# the goal id from its path). Anything else is refused.
MILESTONE_KEYS = frozenset({"title", "due_date"})
CREATE_KEYS = frozenset(
    {
        "title",
        "description",
        "category",
        "target_date",
        "current_state",
        "check_in",
        "milestones",
    }
)
UPDATE_KEYS = frozenset(
    {
        "title",
        "description",
        "category",
        "status",
        "current_state",
        "target_date",
        "clear_target_date",
        "check_in",
        "add_milestones",
        "complete_milestones",
        "reopen_milestones",
        "drop_milestones",
    }
)
PROGRESS_KEYS = frozenset({"note", "milestone_id"})
ALLOWED_KEYS: Mapping[str, frozenset[str]] = {
    "create": CREATE_KEYS,
    "update": UPDATE_KEYS,
    "log_progress": PROGRESS_KEYS,
}

# What list_goals filters by: one status, or every goal.
LIST_STATUSES = (*GOAL_STATUSES, "all")
# How many progress notes get_goal returns by default (newest first), and at
# most.
DEFAULT_ENTRIES = 10
MAX_ENTRIES_SHOWN = 100
# The dates a goal or milestone may name.
MIN_DATE = date(2000, 1, 1)
MAX_DATE = date(2100, 12, 31)

NOT_FOUND_MESSAGE = "Goal not found."

# The first key of the per-user goal-writer lock (_lock_owner): "GOAL".
_WRITER_LOCK_CLASS = int.from_bytes(b"GOAL", "big")

# The other line and paragraph ends: vertical tab, form feed, the file,
# group, record and unit separators, next line (NEL) and the Unicode line
# and paragraph separators. Each becomes a newline before the controls are
# removed, so a multi-line field keeps the break and a one-line field a
# space; otherwise "Week 1: run 2k<U+2028>Week 2" is stored as "2kWeek 2".
_LINE_END = re.compile(r"[\x0b\x0c\x1c-\x1f\x85\u2028\u2029]")
# C0 and C1 controls other than tab and newline.
_CONTROL = re.compile(r"[\x01-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f]")
# A run of variation selectors (services.skills.prompt.VARIATION_SELECTORS).
# They render as nothing after a visible character and 256 of them encode
# any byte, so a run can hide a whole sentence. As in the skills scanner,
# only a single U+FE0F right after a visible character (an emoji's
# presentation) is kept.
_SELECTOR_RUN = re.compile(f"(?:{VARIATION_SELECTORS.pattern})+")
_EMOJI_PRESENTATION = "\N{VARIATION SELECTOR-16}"
# Every Unicode space separator but the plain space (no-break, Ogham, the
# en/em quads and spaces through the thin and hair space, narrow no-break,
# medium mathematical, ideographic). Each is a real gap between words, so it
# becomes a plain space before the invisible characters (whose list holds
# U+2000-U+200A) are removed; otherwise "Run a<thin space>5k" is stored as
# "Run a5k". U+180E is no longer a space and is still removed.
_SPACE_LIKE = re.compile(r"[\u00a0\u1680\u2000-\u200a\u202f\u205f\u3000]")
_BLANK_RUN = re.compile(r"\n{3,}")
_DATE = re.compile(r"\d{4}-\d{2}-\d{2}")
_FIELD_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,23}")

# One shared, stateless scanner.
_GUARD = PromptGuard()


# -- errors -----------------------------------------------------------------


class GoalError(Exception):
    """A goal operation refused. ``rule`` names why (a toolkit result carries
    it) and ``status`` is the HTTP status a route answers with. The message
    never repeats the user's text."""

    status: int = 422
    rule: str = "invalid_arguments"

    def __init__(self, message: str, *, rule: Optional[str] = None) -> None:
        super().__init__(message)
        self.message = message
        if rule is not None:
            self.rule = rule


class GoalNotFound(GoalError):
    """No such goal for this user (another user's goal reads the same)."""

    status = 404
    rule = "not_found"

    def __init__(self, message: str = NOT_FOUND_MESSAGE) -> None:
        super().__init__(message)


class GoalConflict(GoalError):
    """A rule about what is already stored: ``duplicate`` (``existing_id``
    is the open goal with the same title) or ``limit``."""

    status = 409
    rule = "limit"

    def __init__(
        self, message: str, *, rule: str = "limit", existing_id: Optional[str] = None
    ) -> None:
        super().__init__(message, rule=rule)
        self.existing_id = existing_id


class GoalInvalid(GoalError):
    """Arguments that cannot be stored: ``invalid_arguments``, or screened
    text (``unsafe_text``, ``secret``)."""

    status = 422
    rule = "invalid_arguments"


# -- small helpers ----------------------------------------------------------


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _utc(value: Optional[datetime]) -> Optional[datetime]:
    # SQLite hands back naive datetimes; every value written here is UTC.
    if value is None:
        return None
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _iso(value: Optional[datetime]) -> Optional[str]:
    utc = _utc(value)
    return utc.isoformat() if utc is not None else None


def _day(value: Optional[date]) -> Optional[str]:
    return value.isoformat() if value is not None else None


def as_uuid(value: Any) -> Optional[uuid.UUID]:
    """*value* as a UUID, or None when it is not one."""
    if isinstance(value, uuid.UUID):
        return value
    if not isinstance(value, str):
        return None
    try:
        return uuid.UUID(value.strip())
    except ValueError:
        return None


def normalized_title(title: str) -> str:
    """What the duplicate rule compares: the title with its case folded and
    its whitespace collapsed (NFKC first, so look-alike forms compare
    equal), and with no variation selectors, which render as nothing (a
    title stored before they were cleaned may hold some)."""
    plain = VARIATION_SELECTORS.sub("", title)
    return " ".join(unicodedata.normalize("NFKC", plain).casefold().split())


def _owner(user_id: Any) -> uuid.UUID:
    key = as_uuid(user_id if isinstance(user_id, uuid.UUID) else str(user_id))
    if key is None:
        raise GoalInvalid("Goals need a signed-in user.")
    return key


def _source(source: Any) -> str:
    if source not in ENTRY_SOURCES:
        raise GoalInvalid(f"'source' must be one of: {', '.join(ENTRY_SOURCES)}.")
    return str(source)


def _fields(data: Any, allowed: frozenset[str], what: str) -> dict[str, Any]:
    """*data* as a dict, refusing any field outside *allowed*. Only short
    plain field names are repeated in the error."""
    if not isinstance(data, Mapping):
        raise GoalInvalid(f"The fields for {what} must be an object.")
    unknown = sorted(str(k) for k in data if k not in allowed)
    if unknown:
        shown = [k for k in unknown if _FIELD_NAME.fullmatch(k)][:4]
        raise GoalInvalid(
            f"Unknown field(s) for {what}" + (f": {', '.join(shown)}." if shown else ".")
        )
    return dict(data)


# -- text: cleaning and screening -------------------------------------------


def _screen(text: str, field: str) -> None:
    """Refuse *text* the prompt guard grades unsafe (``unsafe_text``) or
    that holds a password, key, token, card, bank or ID number (``secret``,
    policy MEMORY). A guard or detector error refuses (fail closed). Both
    read the text without its variation selectors: _clean keeps an emoji's
    U+FE0F, and one after every letter would otherwise hide the words from
    both while the page still shows them."""
    text = VARIATION_SELECTORS.sub("", text)
    try:
        safe = _GUARD.scan(text).is_safe
    except Exception:  # noqa: BLE001 - a scan that fails refuses (fail closed)
        raise GoalInvalid(
            f"Crawler could not check '{field}'; nothing was saved.", rule="unsafe_text"
        ) from None
    if not safe:
        raise GoalInvalid(
            f"'{field}' looks like instructions aimed at an AI assistant, so nothing was saved. "
            "A goal holds plain words about what the user wants to do.",
            rule="unsafe_text",
        )
    secret = first_finding(text, MEMORY)
    if secret is not None:
        if secret.label == DETECTOR_ERROR_LABEL:
            raise GoalInvalid(
                f"Crawler could not check '{field}' for secrets; nothing was saved.", rule="secret"
            )
        raise GoalInvalid(
            f"'{field}' looks like a password, key, token, card, bank or ID number. Crawler "
            "never saves passwords, keys, card, bank or ID numbers in a goal; nothing was saved.",
            rule="secret",
        )


def _selectors_kept(match: re.Match[str]) -> str:
    start = match.start()
    if match.group() == _EMOJI_PRESENTATION and start > 0 and not match.string[start - 1].isspace():
        return match.group()
    return ""


def _clean(
    value: Any, field: str, max_chars: int, *, required: bool = False, multiline: bool = False
) -> Optional[str]:
    """The text to store, cleaned and screened, or None for a blank optional
    field. Space characters become plain spaces, invisible characters,
    controls and variation selectors (but an emoji's single U+FE0F) are
    removed, a NUL is refused, line ends are normalised, and one-line fields
    are collapsed to one line."""
    if value is None or (isinstance(value, str) and not value.strip()):
        if required:
            raise GoalInvalid(f"'{field}' is required.")
        return None
    if not isinstance(value, str):
        raise GoalInvalid(f"'{field}' must be text.")
    if "\x00" in value:
        raise GoalInvalid(f"'{field}' contains a null character.")
    text = _INVISIBLE_CHARS.sub("", _SPACE_LIKE.sub(" ", value))
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    text = _CONTROL.sub("", _LINE_END.sub("\n", text))
    text = _SELECTOR_RUN.sub(_selectors_kept, text)
    if multiline:
        text = "\n".join(line.rstrip() for line in text.split("\n"))
        text = _BLANK_RUN.sub("\n\n", text).strip()
    else:
        text = " ".join(text.split())
    if not text:
        if required:
            raise GoalInvalid(f"'{field}' is required.")
        return None
    if len(text) > max_chars:
        raise GoalInvalid(f"'{field}' is too long ({len(text)} characters; max {max_chars}).")
    _screen(text, field)
    return text


# A goal's free-text fields: (most characters, may hold several lines).
_GOAL_TEXT = {
    "title": (TITLE_MAX_CHARS, False),
    "description": (DESCRIPTION_MAX_CHARS, True),
    "current_state": (CURRENT_STATE_MAX_CHARS, False),
}


def _goal_text(values: Mapping[str, Any], field: str, *, required: bool = False) -> Optional[str]:
    max_chars, multiline = _GOAL_TEXT[field]
    return _clean(values.get(field), field, max_chars, required=required, multiline=multiline)


# -- other values -----------------------------------------------------------


def _choice(value: Any, field: str, allowed: Sequence[str]) -> str:
    if not isinstance(value, str) or value.strip().lower() not in allowed:
        raise GoalInvalid(f"'{field}' must be one of: {', '.join(allowed)}.")
    return value.strip().lower()


def _date(value: Any, field: str) -> date:
    """A date given as ``YYYY-MM-DD`` (or a date, from a route's model)."""
    if isinstance(value, date) and not isinstance(value, datetime):
        day = value
    elif isinstance(value, str) and _DATE.fullmatch(value.strip()):
        try:
            day = date.fromisoformat(value.strip())
        except ValueError:
            raise GoalInvalid(f"'{field}' is not a real date (YYYY-MM-DD).") from None
    else:
        raise GoalInvalid(f"'{field}' must be a date as YYYY-MM-DD.")
    if not MIN_DATE <= day <= MAX_DATE:
        raise GoalInvalid(f"'{field}' must be from {MIN_DATE} to {MAX_DATE}.")
    return day


def _flag(value: Any, field: str) -> bool:
    if value is None:
        return False
    if not isinstance(value, bool):
        raise GoalInvalid(f"'{field}' must be true or false.")
    return value


@dataclass(frozen=True)
class _MilestoneDraft:
    """A milestone that passed every check, ready to store."""

    title: str
    due_date: Optional[date]


def _milestone_drafts(value: Any, field: str) -> list[_MilestoneDraft]:
    """Validated milestones: a list of ``{title, due_date?}`` (a plain
    string is a title), at most MAX_MILESTONES_PER_CALL."""
    if value is None:
        return []
    if not isinstance(value, list):
        raise GoalInvalid(f"'{field}' must be a list of milestones ({{title, due_date?}}).")
    if len(value) > MAX_MILESTONES_PER_CALL:
        raise GoalInvalid(
            f"At most {MAX_MILESTONES_PER_CALL} milestones per call ('{field}' has "
            f"{len(value)}); add the rest with another update."
        )
    drafts: list[_MilestoneDraft] = []
    for index, raw in enumerate(value):
        name = f"{field}[{index}]"
        item = {"title": raw} if isinstance(raw, str) else raw
        item = _fields(item, MILESTONE_KEYS, f"{name} (a milestone)")
        title = _clean(
            item.get("title"), f"{name}.title", MILESTONE_TITLE_MAX_CHARS, required=True
        )
        due = item.get("due_date")
        drafts.append(
            _MilestoneDraft(
                title=str(title),
                due_date=_date(due, f"{name}.due_date") if due is not None else None,
            )
        )
    return drafts


def _milestone_ids(value: Any, field: str) -> list[uuid.UUID]:
    """Milestone ids, de-duplicated (one id may be given as a string)."""
    if value is None:
        return []
    items = [value] if isinstance(value, str) else value
    if not isinstance(items, (list, tuple)) or len(items) > MAX_MILESTONES_PER_GOAL:
        raise GoalInvalid(
            f"'{field}' must be a list of at most {MAX_MILESTONES_PER_GOAL} milestone ids."
        )
    ids: list[uuid.UUID] = []
    for item in items:
        key = as_uuid(item)
        if key is None:
            raise GoalInvalid(f"'{field}' holds an id that is not valid.")
        if key not in ids:
            ids.append(key)
    return ids


# -- the JSON shapes --------------------------------------------------------


def progress_of(milestones: Iterable[GoalMilestone]) -> dict[str, int]:
    """``{done, total}``: dropped milestones are not counted."""
    states = [m.state for m in milestones]
    return {
        "done": sum(1 for s in states if s == "done"),
        "total": sum(1 for s in states if s != "dropped"),
    }


def serialize_goal(goal: Goal, progress: Optional[Mapping[str, int]] = None) -> dict[str, Any]:
    """The Goal shape the tools and the Goals page show."""
    counts = progress or {}
    return {
        "id": str(goal.id),
        "title": goal.title,
        "description": goal.description,
        "category": goal.category,
        "status": goal.status,
        "current_state": goal.current_state,
        "target_date": _day(goal.target_date),
        "check_in": goal.check_in,
        "created_at": _iso(goal.created_at),
        "updated_at": _iso(goal.updated_at),
        "completed_at": _iso(goal.completed_at),
        "progress": {"done": int(counts.get("done", 0)), "total": int(counts.get("total", 0))},
    }


def serialize_milestone(milestone: GoalMilestone) -> dict[str, Any]:
    return {
        "id": str(milestone.id),
        "title": milestone.title,
        "due_date": _day(milestone.due_date),
        "state": milestone.state,
        "position": int(milestone.position),
        "done_at": _iso(milestone.done_at),
    }


def serialize_entry(entry: GoalEntry) -> dict[str, Any]:
    return {
        "id": str(entry.id),
        "note": entry.note,
        "source": entry.source,
        "milestone_id": str(entry.milestone_id) if entry.milestone_id is not None else None,
        "created_at": _iso(entry.created_at),
    }


# -- queries ----------------------------------------------------------------


def _owner_lock_keys(owner: uuid.UUID) -> tuple[int, int]:
    """The two int4 keys of *owner*'s goal-writer lock: "GOAL" and the
    first four bytes of the user's id (a rare clash only serialises two
    users' writes)."""
    return _WRITER_LOCK_CLASS, int.from_bytes(owner.bytes[:4], "big", signed=True)


async def _lock_owner(session: AsyncSession, owner: uuid.UUID) -> None:
    """Hold *owner*'s goal-writer lock until the caller's transaction ends,
    so two writers for one user (the Goals page and a chat turn, two tabs)
    run one after the other: the duplicate-title rule, the limits and the
    milestone positions are read and then written, and without it both
    writers pass the same check. Taken before the first read.

    A PostgreSQL advisory transaction lock, not a lock on the users row:
    services/audit.append_audit_log holds an in-process per-user lock while
    it waits for that row (FOR NO KEY UPDATE), and a route writes its audit
    row after the store in the same transaction, so a route holding the row
    here would wait on that in-process lock while its holder waited on the
    row, a cycle PostgreSQL cannot see. The goal, milestone and note rows
    the store inserts do hold the users row FOR KEY SHARE until commit
    (their foreign key); FOR NO KEY UPDATE does not conflict with that, so
    another writer's audit row never waits on this transaction (with FOR
    UPDATE it did, and both hung). Nothing that holds an audit lock waits
    for this one. SQLite has no such lock and serialises writers anyway."""
    if session.get_bind().dialect.name != "postgresql":
        return
    await session.execute(select(func.pg_advisory_xact_lock(*_owner_lock_keys(owner))))


async def _owned_goal(session: AsyncSession, owner: uuid.UUID, goal_id: Any) -> Goal:
    key = as_uuid(goal_id)
    if key is None:
        raise GoalNotFound()
    goal = (
        await session.execute(select(Goal).where(Goal.id == key, Goal.user_id == owner))
    ).scalar_one_or_none()
    if goal is None:
        raise GoalNotFound()
    return goal


async def _milestones_of(
    session: AsyncSession, owner: uuid.UUID, goal_id: uuid.UUID
) -> list[GoalMilestone]:
    return list(
        (
            await session.execute(
                select(GoalMilestone)
                .where(GoalMilestone.goal_id == goal_id, GoalMilestone.user_id == owner)
                .order_by(GoalMilestone.position, GoalMilestone.created_at, GoalMilestone.id)
            )
        ).scalars()
    )


async def _entries_of(
    session: AsyncSession, owner: uuid.UUID, goal_id: uuid.UUID, limit: int
) -> list[GoalEntry]:
    if limit <= 0:
        return []
    return list(
        (
            await session.execute(
                select(GoalEntry)
                .where(GoalEntry.goal_id == goal_id, GoalEntry.user_id == owner)
                .order_by(GoalEntry.created_at.desc(), GoalEntry.id.desc())
                .limit(limit)
            )
        ).scalars()
    )


async def _count(session: AsyncSession, model: Any, *conditions: Any) -> int:
    query = select(func.count()).select_from(model).where(*conditions)
    return int((await session.execute(query)).scalar_one())


async def _progress_by_goal(
    session: AsyncSession, owner: uuid.UUID, goal_ids: Sequence[uuid.UUID]
) -> dict[uuid.UUID, dict[str, int]]:
    """``{goal_id: {done, total}}`` for *goal_ids*, in one grouped query."""
    progress: dict[uuid.UUID, dict[str, int]] = {}
    if not goal_ids:
        return progress
    rows = (
        await session.execute(
            select(GoalMilestone.goal_id, GoalMilestone.state, func.count())
            .where(GoalMilestone.user_id == owner, GoalMilestone.goal_id.in_(list(goal_ids)))
            .group_by(GoalMilestone.goal_id, GoalMilestone.state)
        )
    ).all()
    for goal_id, state, count in rows:
        counts = progress.setdefault(goal_id, {"done": 0, "total": 0})
        if state == "done":
            counts["done"] += int(count)
        if state != "dropped":
            counts["total"] += int(count)
    return progress


async def _detail(
    session: AsyncSession, owner: uuid.UUID, goal: Goal, entries_limit: int
) -> dict[str, Any]:
    milestones = await _milestones_of(session, owner, goal.id)
    entries = await _entries_of(session, owner, goal.id, entries_limit)
    return {
        **serialize_goal(goal, progress_of(milestones)),
        "milestones": [serialize_milestone(m) for m in milestones],
        "entries": [serialize_entry(e) for e in entries],
    }


async def _refuse_duplicate(
    session: AsyncSession, owner: uuid.UUID, title: str, *, exclude: Optional[uuid.UUID] = None
) -> None:
    """Refuse a second active or paused goal with the same normalised
    title; the error carries the existing goal's id."""
    wanted = normalized_title(title)
    rows = (
        await session.execute(
            select(Goal.id, Goal.title).where(
                Goal.user_id == owner, Goal.status.in_(OPEN_STATUSES)
            )
        )
    ).all()
    for goal_id, existing in rows:
        if goal_id != exclude and normalized_title(existing) == wanted:
            raise GoalConflict(
                f"An active or paused goal with this title already exists (goal_id {goal_id}). "
                "Update that goal instead of making a second one.",
                rule="duplicate",
                existing_id=str(goal_id),
            )


async def _refuse_over_limit(
    session: AsyncSession, owner: uuid.UUID, *, new_goal: bool, opening: bool
) -> None:
    """Refuse a goal past MAX_GOALS_PER_USER (a new one) or past
    MAX_OPEN_GOALS (one that becomes active or paused)."""
    if new_goal:
        total = await _count(session, Goal, Goal.user_id == owner)
        if total >= MAX_GOALS_PER_USER:
            raise GoalConflict(
                f"You already have {total} goals, the most allowed ({MAX_GOALS_PER_USER} goals "
                "per user). Delete one you no longer need first."
            )
    if opening:
        open_goals = await _count(
            session, Goal, Goal.user_id == owner, Goal.status.in_(OPEN_STATUSES)
        )
        if open_goals >= MAX_OPEN_GOALS:
            raise GoalConflict(
                f"You already have {open_goals} active or paused goals, the most allowed "
                f"({MAX_OPEN_GOALS} open goals). Complete or archive one first."
            )


# -- operations -------------------------------------------------------------


async def create_goal(
    session: AsyncSession, user_id: Any, data: Mapping[str, Any], *, source: str
) -> dict[str, Any]:
    """Store a new active goal (CREATE_KEYS) with its first milestones and
    return it as a GoalDetail. *source* is who asked (``user`` or
    ``agent``)."""
    owner = _owner(user_id)
    _source(source)
    values = _fields(data, CREATE_KEYS, "a new goal")
    title = str(_goal_text(values, "title", required=True))
    description = _goal_text(values, "description")
    current_state = _goal_text(values, "current_state")
    category = _choice(values.get("category") or "other", "category", GOAL_CATEGORIES)
    check_in = _choice(values.get("check_in") or "none", "check_in", CHECK_INS)
    target = values.get("target_date")
    target = _date(target, "target_date") if target is not None else None
    drafts = _milestone_drafts(values.get("milestones"), "milestones")
    await _lock_owner(session, owner)
    await _refuse_duplicate(session, owner, title)
    await _refuse_over_limit(session, owner, new_goal=True, opening=True)
    now = _utcnow()
    goal = Goal(
        id=uuid.uuid4(),
        user_id=owner,
        title=title,
        description=description,
        category=category,
        status="active",
        current_state=current_state,
        target_date=target,
        check_in=check_in,
        created_at=now,
        updated_at=now,
        completed_at=None,
    )
    session.add(goal)
    # The goal row first: its milestones point at it.
    await session.flush()
    milestones = [
        GoalMilestone(
            id=uuid.uuid4(),
            goal_id=goal.id,
            user_id=owner,
            title=draft.title,
            due_date=draft.due_date,
            state="open",
            position=position,
            done_at=None,
            created_at=now,
        )
        for position, draft in enumerate(drafts)
    ]
    session.add_all(milestones)
    await session.flush()
    logger.info("goal_created", goal_id=str(goal.id), milestones=len(milestones), source=source)
    return {
        **serialize_goal(goal, progress_of(milestones)),
        "milestones": [serialize_milestone(m) for m in milestones],
        "entries": [],
    }


async def list_goals(
    session: AsyncSession, user_id: Any, *, status: str = "active", category: Optional[str] = None
) -> list[dict[str, Any]]:
    """The user's goals with *status* (or ``all``), optionally of one
    *category*, as Goal summaries, the most recently updated first."""
    owner = _owner(user_id)
    wanted = _choice(status if status is not None else "active", "status", LIST_STATUSES)
    kind = _choice(category, "category", GOAL_CATEGORIES) if category is not None else None
    query = select(Goal).where(Goal.user_id == owner)
    if wanted != "all":
        query = query.where(Goal.status == wanted)
    if kind is not None:
        query = query.where(Goal.category == kind)
    query = query.order_by(Goal.updated_at.desc(), Goal.created_at.desc(), Goal.id)
    goals = list((await session.execute(query)).scalars())
    progress = await _progress_by_goal(session, owner, [g.id for g in goals])
    return [serialize_goal(g, progress.get(g.id)) for g in goals]


async def get_goal(
    session: AsyncSession, user_id: Any, goal_id: Any, *, entries_limit: int = DEFAULT_ENTRIES
) -> dict[str, Any]:
    """One goal as a GoalDetail: its milestones in order and its last
    *entries_limit* progress notes, newest first."""
    owner = _owner(user_id)
    _check_entries_limit(entries_limit)
    goal = await _owned_goal(session, owner, goal_id)
    return await _detail(session, owner, goal, entries_limit)


def _check_entries_limit(entries_limit: Any) -> None:
    if (
        isinstance(entries_limit, bool)
        or not isinstance(entries_limit, int)
        or not 0 <= entries_limit <= MAX_ENTRIES_SHOWN
    ):
        raise GoalInvalid(f"'entries_limit' must be a whole number from 0 to {MAX_ENTRIES_SHOWN}.")


async def update_goal(
    session: AsyncSession,
    user_id: Any,
    goal_id: Any,
    data: Mapping[str, Any],
    *,
    entries_limit: int = DEFAULT_ENTRIES,
) -> dict[str, Any]:
    """Change a goal (UPDATE_KEYS) and return it as a GoalDetail with its
    last *entries_limit* progress notes, as get_goal does (the Goals page
    shows the same notes it read, the goals.update tool the default).

    A field left out or given as null is not changed; an empty
    ``description`` or ``current_state`` clears it, and ``clear_target_date``
    clears the target date. Milestones are added, completed, reopened or
    dropped, never deleted. Status ``completed`` sets ``completed_at``, and
    leaving it clears it. Every argument is checked before anything is
    changed, so a refusal changes nothing."""
    owner = _owner(user_id)
    _check_entries_limit(entries_limit)
    values = _fields(data, UPDATE_KEYS, "a goal update")
    changes: dict[str, Any] = {}
    for field in _GOAL_TEXT:
        if values.get(field) is not None:
            # The title is required; the others are cleared by an empty string.
            changes[field] = _goal_text(values, field, required=field == "title")
    if values.get("category") is not None:
        changes["category"] = _choice(values["category"], "category", GOAL_CATEGORIES)
    if values.get("check_in") is not None:
        changes["check_in"] = _choice(values["check_in"], "check_in", CHECK_INS)
    new_status = (
        _choice(values["status"], "status", GOAL_STATUSES)
        if values.get("status") is not None
        else None
    )
    clear_target = _flag(values.get("clear_target_date"), "clear_target_date")
    if clear_target and values.get("target_date") is not None:
        raise GoalInvalid("Give target_date or clear_target_date, not both.")
    if clear_target:
        changes["target_date"] = None
    elif values.get("target_date") is not None:
        changes["target_date"] = _date(values["target_date"], "target_date")
    adds = _milestone_drafts(values.get("add_milestones"), "add_milestones")
    moves = {
        "done": _milestone_ids(values.get("complete_milestones"), "complete_milestones"),
        "open": _milestone_ids(values.get("reopen_milestones"), "reopen_milestones"),
        "dropped": _milestone_ids(values.get("drop_milestones"), "drop_milestones"),
    }
    named = [key for ids in moves.values() for key in ids]
    if len(named) != len(set(named)):
        raise GoalInvalid(
            "A milestone id appears in more than one of complete_milestones, "
            "reopen_milestones and drop_milestones."
        )
    if not changes and new_status is None and not adds and not named:
        raise GoalInvalid(
            "Nothing to change: give the fields to change, a status, or milestones to add, "
            "complete, reopen or drop."
        )

    await _lock_owner(session, owner)
    goal = await _owned_goal(session, owner, goal_id)
    milestones = await _milestones_of(session, owner, goal.id)
    by_id = {m.id: m for m in milestones}
    for field, state in (
        ("complete_milestones", "done"),
        ("reopen_milestones", "open"),
        ("drop_milestones", "dropped"),
    ):
        if any(key not in by_id for key in moves[state]):
            raise GoalInvalid(f"'{field}' names a milestone that is not in this goal.")
    if len(milestones) + len(adds) > MAX_MILESTONES_PER_GOAL:
        raise GoalConflict(
            f"A goal holds at most {MAX_MILESTONES_PER_GOAL} milestones, dropped ones included "
            f"(they are kept); this one has {len(milestones)}. Reopen a dropped milestone "
            "instead, or start a new goal."
        )
    final_status = new_status or goal.status
    reopening = final_status in OPEN_STATUSES and goal.status not in OPEN_STATUSES
    title = changes.get("title")
    renaming = title is not None and normalized_title(title) != normalized_title(goal.title)
    if final_status in OPEN_STATUSES and (reopening or renaming):
        await _refuse_duplicate(session, owner, title or goal.title, exclude=goal.id)
    if reopening:
        await _refuse_over_limit(session, owner, new_goal=False, opening=True)

    # Every check passed: apply.
    now = _utcnow()
    changed: list[str] = []
    for column, value in changes.items():
        if getattr(goal, column) != value:
            setattr(goal, column, value)
            changed.append(column)
    if new_status is not None and new_status != goal.status:
        if new_status == "completed":
            goal.completed_at = now
        elif goal.status == "completed":
            goal.completed_at = None
        goal.status = new_status
        changed.append("status")
    moved = 0
    for state, ids in moves.items():
        for key in ids:
            milestone = by_id[key]
            if milestone.state == state:
                continue
            milestone.state = state
            milestone.done_at = now if state == "done" else None
            moved += 1
    added = [
        GoalMilestone(
            id=uuid.uuid4(),
            goal_id=goal.id,
            user_id=owner,
            title=draft.title,
            due_date=draft.due_date,
            state="open",
            position=len(milestones) + offset,
            done_at=None,
            created_at=now,
        )
        for offset, draft in enumerate(adds)
    ]
    session.add_all(added)
    if changed or moved or added:
        goal.updated_at = now
    await session.flush()
    logger.info(
        "goal_updated",
        goal_id=str(goal.id),
        changed=sorted(changed),
        milestones_added=len(added),
        milestones_moved=moved,
    )
    return await _detail(session, owner, goal, entries_limit)


async def log_progress(
    session: AsyncSession,
    user_id: Any,
    goal_id: Any,
    note: str,
    *,
    milestone_id: Optional[str] = None,
    source: str,
) -> dict[str, Any]:
    """Add a progress note to a goal (optionally about one of its
    milestones) and return it as a GoalEntry."""
    owner = _owner(user_id)
    _source(source)
    text = str(_clean(note, "note", NOTE_MAX_CHARS, required=True, multiline=True))
    milestone_key: Optional[uuid.UUID] = None
    if milestone_id is not None and milestone_id != "":
        milestone_key = as_uuid(milestone_id)
        if milestone_key is None:
            raise GoalInvalid("'milestone_id' is not a valid id.")
    await _lock_owner(session, owner)
    goal = await _owned_goal(session, owner, goal_id)
    if milestone_key is not None:
        found = await _count(
            session,
            GoalMilestone,
            GoalMilestone.id == milestone_key,
            GoalMilestone.goal_id == goal.id,
            GoalMilestone.user_id == owner,
        )
        if not found:
            raise GoalInvalid("'milestone_id' is not a milestone of this goal.")
    entries = await _count(
        session, GoalEntry, GoalEntry.goal_id == goal.id, GoalEntry.user_id == owner
    )
    if entries >= MAX_ENTRIES_PER_GOAL:
        raise GoalConflict(
            f"This goal already has {entries} progress notes, the most allowed "
            f"({MAX_ENTRIES_PER_GOAL} per goal). Start a new goal to keep logging."
        )
    now = _utcnow()
    entry = GoalEntry(
        id=uuid.uuid4(),
        goal_id=goal.id,
        user_id=owner,
        note=text,
        source=source,
        milestone_id=milestone_key,
        created_at=now,
    )
    session.add(entry)
    goal.updated_at = now
    await session.flush()
    logger.info("goal_progress_logged", goal_id=str(goal.id), source=source)
    return serialize_entry(entry)


async def goal_facts(session: AsyncSession, user_id: Any, goal_id: Any) -> dict[str, Any]:
    """What a delete card states, read from the database: ``{goal_id,
    title, milestones, entries}`` (every milestone, dropped ones included,
    and every progress note)."""
    owner = _owner(user_id)
    goal = await _owned_goal(session, owner, goal_id)
    return {
        "goal_id": str(goal.id),
        "title": goal.title,
        "milestones": await _count(
            session, GoalMilestone, GoalMilestone.goal_id == goal.id, GoalMilestone.user_id == owner
        ),
        "entries": await _count(
            session, GoalEntry, GoalEntry.goal_id == goal.id, GoalEntry.user_id == owner
        ),
    }


async def delete_goal(session: AsyncSession, user_id: Any, goal_id: Any) -> dict[str, Any]:
    """Delete a goal with its milestones and progress notes; returns
    ``{goal_id, milestones, entries}`` (how many of each went)."""
    facts = await goal_facts(session, user_id, goal_id)
    owner = _owner(user_id)
    key = uuid.UUID(facts["goal_id"])
    # Children first: SQLite enforces the cascade only with its pragma on.
    await session.execute(
        delete(GoalEntry).where(GoalEntry.goal_id == key, GoalEntry.user_id == owner)
    )
    await session.execute(
        delete(GoalMilestone).where(GoalMilestone.goal_id == key, GoalMilestone.user_id == owner)
    )
    await session.execute(delete(Goal).where(Goal.id == key, Goal.user_id == owner))
    await session.flush()
    deleted = {k: facts[k] for k in ("goal_id", "milestones", "entries")}
    logger.info("goal_deleted", **deleted)
    return deleted


__all__ = [
    "ALLOWED_KEYS",
    "CREATE_KEYS",
    "DEFAULT_ENTRIES",
    "LIST_STATUSES",
    "MAX_ENTRIES_SHOWN",
    "MILESTONE_KEYS",
    "PROGRESS_KEYS",
    "UPDATE_KEYS",
    "GoalConflict",
    "GoalError",
    "GoalInvalid",
    "GoalNotFound",
    "as_uuid",
    "create_goal",
    "delete_goal",
    "get_goal",
    "goal_facts",
    "list_goals",
    "log_progress",
    "normalized_title",
    "progress_of",
    "serialize_entry",
    "serialize_goal",
    "serialize_milestone",
    "update_goal",
]
