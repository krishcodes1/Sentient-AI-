"""Implements the schedule.* built-in tools (create a scheduled prompt, set up
or change the daily briefing, list, pause or resume, delete) and the same
operations for the owner's REST routes, chat commands and features' nudges.

Why it exists: every way a scheduled task is made or changed goes through one
set of rules, so a task the agent proposes on a card, one the owner makes
from the web and a feature's nudge are held to the same limits:
- ownership: ``user_id`` is the caller's identity as the executor (or the
  route) knows it, never a tool argument; a foreign or unknown id reads as
  "not found";
- the prompt is the owner's own words: 1-2000 characters, never a secret
  (``looks_like_secret``), never copied from a tool result (the runtime's
  taint gate refuses that before any card, ``prompt_is_tainted``);
- tools: at most 8 reads and 3 writes, each one an unattended run may be
  given at all (services/automation/fence.py); writes only ever become cards;
- time: a real recurrence and a real IANA zone, resolved from the call, then
  the user's saved zone, then CRAWLER_TIMEZONE, else the model is told to ask;
- limits: 10 tasks per user (nudges excluded), one daily briefing per user.

The approval card's hooks live here too: ``precheck`` (the rules, before any
card), ``bind`` (the resolved zone written into the card's arguments) and
``describe`` (the card's sentence, from facts). Tool errors are results.
"""

from __future__ import annotations

import json
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Mapping, Optional
from zoneinfo import ZoneInfo

import structlog
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError, SQLAlchemyError

from services.agent.prompt_guard import _INVISIBLE_CHARS
from services.scheduler.recurrence import (
    ONCE_HORIZON_DAYS,
    Recurrence,
    describe,
    local_label,
    next_after,
    parse_recurrence,
    phrase,
    recurrence_from_stored,
)
from services.scheduler.timezones import parse_zone

logger = structlog.get_logger(__name__)

# The scheduled_tasks columns are these sizes (models/scheduled_task.py).
LABEL_MAX_CHARS = 80
PROMPT_MAX_CHARS = 2000
ERROR_MAX_CHARS = 200
TOPIC_MAX_CHARS = 120
MAX_TASKS_PER_USER = 10
MAX_READ_TOOLS = 8
MAX_WRITE_TOOLS = 3
# schedule.list keeps its rows, as the model is shown them, within this many
# characters, so RESULT_CHAR_BUDGETS["schedule.list"] (8000, runtime.py)
# holds the whole list; raise both together.
LIST_ROWS_CHARS = 7000
PROMPT_PREVIEW_CHARS = 200
BRIEFING_LABEL = "Daily briefing"
CHANNELS = ("telegram", "slack")
SECTIONS = ("canvas", "calendar", "email")
DEFAULT_SECTIONS = ("canvas", "calendar")
BRIEFING_FREQS = ("daily", "weekdays", "weekly")
BRIEFING_DEFAULT_TIME = "07:30"

# The policy a schedule.* call refused before its card is filed under, and
# the rule for a prompt copied from tool results.
SCHEDULE_RULE_POLICY = "schedule_rule"
TAINTED_PROMPT_RULE = "tainted_prompt"
TAINTED_PROMPT_ERROR = (
    "Not set up: this task's text was copied from a tool result (an email, a page "
    "or a file). Write the task in your own words, or ask the user to."
)
TIMEZONE_REQUIRED_ERROR = (
    "The user's time zone is unknown. Ask the user which time zone they are in "
    "(an IANA name such as America/New_York) and call again with 'timezone'."
)
_PROMPT_TOOLS = frozenset({"schedule.create", "schedule.briefing"})
# Rules that are a refusal the owner should see as blocked (not the
# model's own mistake, which it fixes by calling again).
_REFUSAL_RULES = frozenset({"secret", "tool_not_allowed", "task_limit"})

_CREATE_KEYS = frozenset(
    {
        "label",
        "prompt",
        "freq",
        "time",
        "days",
        "day_of_month",
        "date",
        "tools",
        "write_tools",
        "timezone",
        "channels",
    }
)
_BRIEFING_KEYS = frozenset(
    {"freq", "time", "days", "sections", "topic", "summary", "timezone", "channels"}
)
_RECURRENCE_KEYS = ("freq", "time", "days", "day_of_month", "date")
_LINE_SEPARATORS = (chr(0x2028), chr(0x2029))
_SECTION_WORDS = {
    "canvas": "Canvas due items",
    "calendar": "today's calendar",
    "email": "unread important email (sender and subject only)",
}
_CHANNEL_NAMES = {"telegram": "Telegram", "slack": "Slack"}


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _utc(value: datetime) -> datetime:
    # SQLite hands back naive datetimes; every value written here is UTC.
    return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value


def _error(message: str, *, rule: str = "invalid_arguments", **extra: Any) -> dict[str, Any]:
    result: dict[str, Any] = {"ok": False, "error": message, "rule": rule, **extra}
    if rule in _REFUSAL_RULES:
        result["refused"] = True
    return result


def _not_found() -> dict[str, Any]:
    return _error("Scheduled task not found. Call schedule.list for the ids.", not_found=True)


def _shown_chars(value: Any) -> int:
    text = json.dumps(value, ensure_ascii=False, separators=(",", ":"), default=str)
    return len(_INVISIBLE_CHARS.sub(lambda m: json.dumps(m.group())[1:-1], text))


def _default_timezone() -> Optional[str]:
    from core.config import settings

    return getattr(settings, "DEFAULT_TIMEZONE", None)


def prompt_is_tainted(canonical: str, arguments: Mapping[str, Any], taint: Any) -> bool:
    """Whether a schedule.create / schedule.briefing call's own text (the
    prompt, the news topic) was copied from untrusted tool results. Only
    those fields are checked: a zone name or a tool name that also appears
    in a result is not a copied task."""
    if canonical not in _PROMPT_TOOLS or not isinstance(arguments, Mapping):
        return False
    own_text = {k: arguments.get(k) for k in ("prompt", "topic") if isinstance(arguments.get(k), str)}
    return bool(own_text) and taint.taint_reason(own_text) is not None


# -- Argument rules ------------------------------------------------------------


def clean_label(value: Any) -> tuple[Optional[str], Optional[str]]:
    if not isinstance(value, str) or not value.strip():
        return None, "A short 'label' is required: what the task is, e.g. 'Canvas summary'."
    if any(ord(ch) < 32 or 0x7F <= ord(ch) < 0xA0 or ch in _LINE_SEPARATORS for ch in value):
        return None, "The label must be one line with no control characters."
    label = " ".join(value.split())
    if len(label) > LABEL_MAX_CHARS:
        return None, f"The label is too long ({len(label)} chars; max {LABEL_MAX_CHARS})."
    return label, None


def _clean_prompt(value: Any) -> tuple[Optional[str], Optional[str], str]:
    """(prompt, error, rule)."""
    from services.tools.memory import looks_like_secret

    if not isinstance(value, str) or not value.strip():
        return None, "A 'prompt' is required: what to do each run, in the user's own words.", "invalid_arguments"
    if "\x00" in value:
        return None, "The prompt must not contain null bytes.", "invalid_arguments"
    prompt = value.strip()
    if len(prompt) > PROMPT_MAX_CHARS:
        return None, f"The prompt is too long ({len(prompt)} chars; max {PROMPT_MAX_CHARS}).", "invalid_arguments"
    if looks_like_secret(prompt):
        return (
            None,
            "The prompt looks like it holds a password, key, token or card number. "
            "Scheduled tasks never store secrets; write it without one.",
            "secret",
        )
    return prompt, None, ""


def _clean_topic(value: Any) -> tuple[Optional[str], Optional[str], str]:
    from services.tools.memory import looks_like_secret

    if value is None or (isinstance(value, str) and not value.strip()):
        return None, None, ""
    if not isinstance(value, str) or any(ord(ch) < 32 for ch in value):
        return None, "'topic' must be one line of text.", "invalid_arguments"
    topic = " ".join(value.split())
    if len(topic) > TOPIC_MAX_CHARS:
        return None, f"'topic' is too long ({len(topic)} chars; max {TOPIC_MAX_CHARS}).", "invalid_arguments"
    if looks_like_secret(topic):
        return None, "The topic looks like it holds a secret; write it without one.", "secret"
    return topic, None, ""


def _string_list(value: Any, name: str) -> tuple[Optional[list[str]], Optional[str]]:
    if value is None:
        return [], None
    items = [value] if isinstance(value, str) else value
    if not isinstance(items, (list, tuple)) or not all(isinstance(i, str) for i in items):
        return None, f"'{name}' must be a list of names."
    return list(dict.fromkeys(i.strip() for i in items if i.strip())), None


def _clean_tools(
    value: Any, name: str, kind: str, limit: int
) -> tuple[Optional[list[str]], Optional[str], str]:
    from services.automation.fence import canonical_name, classify_tool

    names, err = _string_list(value, name)
    if err or names is None:
        return None, err, "invalid_arguments"
    canonical = list(dict.fromkeys(canonical_name(n) for n in names))
    if len(canonical) > limit:
        return None, f"'{name}' may list at most {limit} tools.", "invalid_arguments"
    for tool in canonical:
        found = classify_tool(tool)
        if found != kind:
            what = "read" if kind == "read" else "change something (a write)"
            return (
                None,
                f"'{tool}' cannot be used by a scheduled task in '{name}': scheduled runs may "
                f"only use tools that {what}, and never tools that act on this computer, "
                "in a browser, on memories, watches, schedules or skills, or that delete, "
                "run or pay.",
                "tool_not_allowed",
            )
    return canonical, None, ""


def _clean_channels(value: Any) -> tuple[Optional[list[str]], Optional[str]]:
    if value is None:
        return list(CHANNELS), None
    names, err = _string_list(value, "channels")
    if err or names is None:
        return None, err
    lowered = [n.lower() for n in names]
    if any(n not in CHANNELS for n in lowered):
        return None, "'channels' may only list telegram and slack (the web app always gets the result)."
    return [c for c in CHANNELS if c in lowered], None


def _clean_sections(value: Any) -> tuple[Optional[list[str]], Optional[str]]:
    if value is None:
        return list(DEFAULT_SECTIONS), None
    names, err = _string_list(value, "sections")
    if err or names is None:
        return None, err
    lowered = [n.lower() for n in names]
    if not lowered or any(n not in SECTIONS for n in lowered):
        return None, "'sections' must list one or more of canvas, calendar and email."
    return [s for s in SECTIONS if s in lowered], None


def _clean_zone_arg(value: Any) -> tuple[Optional[str], Optional[str]]:
    if value is None or (isinstance(value, str) and not value.strip()):
        return None, None
    zone, err = parse_zone(value)
    if zone is None:
        return None, err
    return str(value).strip(), None


@dataclass
class TaskSpec:
    """A new or changed task, validated except for what needs the zone."""

    kind: str
    label: str
    rule: Recurrence
    channels: list[str]
    prompt: Optional[str] = None
    options: dict[str, Any] = field(default_factory=dict)
    zone_arg: Optional[str] = None


def validate_create(params: Mapping[str, Any]) -> tuple[Optional[TaskSpec], Optional[dict[str, Any]]]:
    """The schedule.create rules that need no database: ``(spec, None)`` or
    ``(None, error result)``."""
    unknown = sorted(set(params) - _CREATE_KEYS)
    if unknown:
        return None, _error(f"Unknown argument(s) for schedule.create: {', '.join(unknown)}.")
    label, err = clean_label(params.get("label"))
    if err or label is None:
        return None, _error(err or "Invalid label.")
    prompt, err, rule = _clean_prompt(params.get("prompt"))
    if err or prompt is None:
        return None, _error(err or "Invalid prompt.", rule=rule or "invalid_arguments")
    recurrence, err = parse_recurrence(
        {k: params.get(k) for k in _RECURRENCE_KEYS}, check_date=False
    )
    if err or recurrence is None:
        return None, _error(err or "Invalid schedule.")
    reads, err, rule = _clean_tools(params.get("tools"), "tools", "read", MAX_READ_TOOLS)
    if err or reads is None:
        return None, _error(err or "Invalid tools.", rule=rule)
    writes, err, rule = _clean_tools(params.get("write_tools"), "write_tools", "write", MAX_WRITE_TOOLS)
    if err or writes is None:
        return None, _error(err or "Invalid write_tools.", rule=rule)
    channels, err = _clean_channels(params.get("channels"))
    if err or channels is None:
        return None, _error(err or "Invalid channels.")
    zone_arg, err = _clean_zone_arg(params.get("timezone"))
    if err:
        return None, _error(err)
    return (
        TaskSpec(
            kind="prompt",
            label=label,
            rule=recurrence,
            channels=channels,
            prompt=prompt,
            options={"tools": reads, "write_tools": writes},
            zone_arg=zone_arg,
        ),
        None,
    )


def validate_briefing(params: Mapping[str, Any]) -> tuple[Optional[TaskSpec], Optional[dict[str, Any]]]:
    """The schedule.briefing rules that need no database."""
    unknown = sorted(set(params) - _BRIEFING_KEYS)
    if unknown:
        return None, _error(f"Unknown argument(s) for schedule.briefing: {', '.join(unknown)}.")
    freq = params.get("freq") or "daily"
    if not isinstance(freq, str) or freq.strip().lower() not in BRIEFING_FREQS:
        return None, _error("A briefing's 'freq' must be daily, weekdays or weekly.")
    recurrence, err = parse_recurrence(
        {
            "freq": freq,
            "time": params.get("time") or BRIEFING_DEFAULT_TIME,
            "days": params.get("days"),
        },
        check_date=False,
    )
    if err or recurrence is None:
        return None, _error(err or "Invalid schedule.")
    sections, err = _clean_sections(params.get("sections"))
    if err or sections is None:
        return None, _error(err or "Invalid sections.")
    topic, err, rule = _clean_topic(params.get("topic"))
    if err:
        return None, _error(err, rule=rule or "invalid_arguments")
    summary = params.get("summary", False)
    if not isinstance(summary, bool):
        return None, _error("'summary' must be true or false.")
    channels, err = _clean_channels(params.get("channels"))
    if err or channels is None:
        return None, _error(err or "Invalid channels.")
    zone_arg, err = _clean_zone_arg(params.get("timezone"))
    if err:
        return None, _error(err)
    return (
        TaskSpec(
            kind="briefing",
            label=BRIEFING_LABEL,
            rule=recurrence,
            channels=channels,
            options={"sections": sections, "topic": topic, "summary": summary},
            zone_arg=zone_arg,
        ),
        None,
    )


def first_run(rule: Recurrence, tz: ZoneInfo, now: datetime) -> tuple[Optional[datetime], Optional[str]]:
    """The first run of a new task, or why there is none: a once task whose
    date or time is past, or beyond the horizon, in the task's own zone."""
    if rule.freq == "once" and rule.on_date is not None:
        today = now.astimezone(tz).date()
        if rule.on_date < today:
            return None, "That date has already passed."
        if rule.on_date > today + timedelta(days=ONCE_HORIZON_DAYS):
            return None, f"A one-time task must be within {ONCE_HORIZON_DAYS} days."
    nxt = next_after(rule, tz, now)
    if nxt is None:
        return None, "That time has already passed; pick a later time or date."
    return nxt, None


def _join(words: list[str]) -> str:
    if len(words) <= 1:
        return "".join(words)
    return ", ".join(words[:-1]) + " and " + words[-1]


def channel_words(channels: Any) -> str:
    names = [_CHANNEL_NAMES[c] for c in CHANNELS if isinstance(channels, (list, tuple)) and c in channels]
    return _join(names)


@dataclass
class Plan:
    """A validated task with its zone resolved and its first run found."""

    spec: TaskSpec
    zone_name: str
    tz: ZoneInfo
    next_run: datetime
    existing_id: Optional[uuid.UUID] = None
    save_user_zone: Optional[str] = None


class ScheduleToolkit:
    """Executes the ``schedule.*`` actions for one caller, and the same
    operations for the owner's routes and commands.

    ``session_factory`` is the application's; without one every action is
    refused (fail closed). ``clock`` and ``default_timezone`` are test seams
    (the latter defaults to CRAWLER_TIMEZONE from the settings)."""

    def __init__(
        self,
        session_factory: Optional[Callable[[], Any]] = None,
        *,
        clock: Callable[[], datetime] = _utcnow,
        default_timezone: Callable[[], Optional[str]] = _default_timezone,
    ) -> None:
        self._session_factory = session_factory
        self._clock = clock
        self._default_timezone = default_timezone
        # What the last card bind learned, for the sync card sentence:
        # whether this user's briefing already exists, and the label of a
        # task a pause or delete names. Per user, overwritten by each bind.
        self._briefing_exists: dict[str, bool] = {}
        self._task_labels: dict[tuple[str, str], str] = {}

    # -- Dispatch ------------------------------------------------------------

    async def execute(self, action: str, params: dict[str, Any], user_id: str) -> dict[str, Any]:
        """Run one ``schedule.*`` action as *user_id* (the executor's).
        Unknown actions and arguments fail closed."""
        params = {k: v for k, v in (params or {}).items() if k != "user_id"}
        try:
            if action == "create":
                return await self.create(user_id, params)
            if action == "briefing":
                return await self.briefing(user_id, params)
            if action == "list":
                if params:
                    return _error("schedule.list takes no arguments.")
                return await self.list(user_id)
            if action == "pause":
                return await self.pause(user_id, params)
            if action == "delete":
                return await self.delete(user_id, params)
            return _error(f"Unknown schedule action '{action}'.")
        except SQLAlchemyError as exc:
            logger.error("schedule_tool_db_error", action=action, error_type=type(exc).__name__)
            return _error("Scheduled task storage is unavailable; try again shortly.", rule="storage")
        except Exception as exc:  # noqa: BLE001 - a tool failure is a result
            logger.error("schedule_tool_unexpected_error", action=action, error_type=type(exc).__name__)
            return _error(f"Scheduled task action failed: {type(exc).__name__}", rule="storage")

    # -- Helpers -------------------------------------------------------------

    def _owner(self, user_id: Any) -> Optional[uuid.UUID]:
        try:
            return uuid.UUID(str(user_id))
        except (TypeError, ValueError):
            return None

    def _ready(self, user_id: Any) -> tuple[Optional[uuid.UUID], Optional[dict[str, Any]]]:
        if self._session_factory is None:
            return None, _error("Scheduled tasks are not configured (no database).", rule="storage")
        owner = self._owner(user_id)
        if owner is None:
            return None, _error("Scheduled tasks need a signed-in user.", rule="storage")
        return owner, None

    async def _user_zone(self, session: Any, owner: uuid.UUID) -> Optional[str]:
        from models.user import User

        return (
            await session.execute(select(User.timezone).where(User.id == owner))
        ).scalar_one_or_none()

    async def plan(
        self, user_id: Any, spec: TaskSpec
    ) -> tuple[Optional[Plan], Optional[dict[str, Any]]]:
        """Resolve the zone (the call's, the user's, CRAWLER_TIMEZONE), find
        the first run, and check the per-user limits and the label."""
        from models.scheduled_task import ScheduledTask

        owner, refusal = self._ready(user_id)
        if refusal is not None or owner is None:
            return None, refusal
        assert self._session_factory is not None
        async with self._session_factory() as session:
            user_zone = await self._user_zone(session, owner)
            zone_name: Optional[str] = spec.zone_arg
            if zone_name is None:
                for candidate in (user_zone, self._default_timezone()):
                    if candidate and parse_zone(candidate)[0] is not None:
                        zone_name = candidate
                        break
            if zone_name is None:
                return None, _error(TIMEZONE_REQUIRED_ERROR, rule="timezone_required")
            tz, err = parse_zone(zone_name)
            if tz is None:
                return None, _error(err or TIMEZONE_REQUIRED_ERROR, rule="timezone_required")
            existing = (
                await session.execute(
                    select(ScheduledTask.id, ScheduledTask.kind).where(
                        ScheduledTask.user_id == owner, ScheduledTask.label == spec.label
                    )
                )
            ).first()
            existing_id: Optional[uuid.UUID] = None
            if existing is not None:
                if spec.kind != "briefing" or existing.kind != "briefing":
                    return None, _error(
                        f'You already have a scheduled task called "{spec.label}". '
                        "Pick another label, or delete that one first.",
                        duplicate=True,
                    )
                existing_id = existing.id
            else:
                count = (
                    await session.execute(
                        select(func.count())
                        .select_from(ScheduledTask)
                        .where(ScheduledTask.user_id == owner, ScheduledTask.kind != "nudge")
                    )
                ).scalar_one()
                if count >= MAX_TASKS_PER_USER:
                    return None, _error(
                        f"You already have {MAX_TASKS_PER_USER} scheduled tasks, the most "
                        "allowed. Delete one first (schedule.list shows them).",
                        rule="task_limit",
                    )
        next_run, err = first_run(spec.rule, tz, self._clock())
        if next_run is None:
            return None, _error(err or "That schedule never runs.")
        return (
            Plan(
                spec=spec,
                zone_name=zone_name,
                tz=tz,
                next_run=next_run,
                existing_id=existing_id,
                save_user_zone=spec.zone_arg if not user_zone and spec.zone_arg else None,
            ),
            None,
        )

    # -- Approval card hooks -------------------------------------------------

    async def precheck(self, action: str, params: dict[str, Any], user_id: str) -> Optional[dict[str, Any]]:
        """The result a call would get even once approved, when that is
        knowable now (reading the database, touching nothing); None to ask
        for approval as usual."""
        params = dict(params or {})
        if action in ("create", "briefing"):
            spec, refusal = (validate_create if action == "create" else validate_briefing)(params)
            if refusal is not None or spec is None:
                return refusal
            _plan, refusal = await self.plan(user_id, spec)
            return refusal
        if action in ("pause", "delete"):
            _task, refusal = await self._find_for_change(user_id, action, params)
            return refusal
        return None

    async def bind(self, action: str, params: dict[str, Any], user_id: str) -> dict[str, Any]:
        """The arguments the card stores and the approved call runs with:
        for create and briefing, the resolved ``timezone`` written in, so
        the card shows the zone and the owner approves exactly it."""
        params = dict(params or {})
        if action in ("create", "briefing"):
            spec, refusal = (validate_create if action == "create" else validate_briefing)(params)
            if spec is None or refusal is not None:
                return params
            plan, _refusal = await self.plan(user_id, spec)
            if plan is None:
                return params
            if action == "briefing":
                self._briefing_exists[str(user_id)] = plan.existing_id is not None
            return {**params, "timezone": plan.zone_name}
        if action in ("pause", "delete"):
            task, _refusal = await self._find_for_change(user_id, action, params)
            if task is not None:
                if len(self._task_labels) > 1024:
                    self._task_labels.clear()
                self._task_labels[(str(user_id), str(task.id))] = task.label
        return params

    def describe(self, action: str, params: Mapping[str, Any], user_id: str) -> Optional[str]:
        """The approval card's sentence, from the (bound) arguments; None
        when they do not make a valid call."""
        params = dict(params or {})
        zone = params.get("timezone") if isinstance(params.get("timezone"), str) else "your time zone"
        if action == "create":
            spec, refusal = validate_create(params)
            if spec is None or refusal is not None:
                return None
            where = channel_words(spec.channels)
            send = (
                f"send the result to {where}" if where else "keep the result in the web app"
            )
            reads = ", ".join(spec.options.get("tools") or []) or "no tools"
            writes = ", ".join(spec.options.get("write_tools") or []) or "nothing"
            return (
                f'Run "{spec.label}" {phrase(spec.rule)} ({zone}) and {send}. '
                f"Reads with: {reads}. Asks you first before: {writes}. Full prompt below."
            )
        if action == "briefing":
            spec, refusal = validate_briefing(params)
            if spec is None or refusal is not None:
                return None
            head = (
                "Change your daily briefing: send it"
                if self._briefing_exists.get(str(user_id))
                else "Send you a briefing"
            )
            where = channel_words(spec.channels)
            parts = [_SECTION_WORDS[s] for s in spec.options.get("sections") or []]
            if spec.options.get("topic"):
                parts.append(f'news on "{spec.options["topic"]}"')
            overview = (
                "; a short AI overview uses your AI provider" if spec.options.get("summary") else ""
            )
            return (
                f"{head} {phrase(spec.rule)} ({zone})"
                + (f" on {where}" if where else " in the web app")
                + f" with {_join(parts)}. Built from read-only lookups{overview}."
            )
        if action in ("pause", "delete"):
            task_id = params.get("task_id")
            try:
                task_key = str(uuid.UUID(str(task_id)))
            except (TypeError, ValueError):
                return None
            label = self._task_labels.get((str(user_id), task_key))
            name = f'"{label}"' if label else f"task {task_id}"
            if action == "delete":
                return f"Delete the scheduled task {name}. Its conversation is kept."
            if params.get("paused") is True:
                return f"Pause the scheduled task {name}; it does not run until you resume it."
            return (
                f"Resume the scheduled task {name}; its next run is counted from now "
                "(missed runs are not made up)."
            )
        return None

    # -- Actions -------------------------------------------------------------

    async def create(
        self, user_id: str, params: dict[str, Any], *, source: str = "agent"
    ) -> dict[str, Any]:
        """Save a scheduled prompt for the caller."""
        spec, refusal = validate_create(params)
        if spec is None or refusal is not None:
            return refusal or _error("Invalid task.")
        return await self._save(user_id, spec, source=source)

    async def briefing(
        self, user_id: str, params: dict[str, Any], *, source: str = "agent"
    ) -> dict[str, Any]:
        """Set up the caller's daily briefing, or change the one they have."""
        spec, refusal = validate_briefing(params)
        if spec is None or refusal is not None:
            return refusal or _error("Invalid briefing.")
        return await self._save(user_id, spec, source=source)

    async def _save(self, user_id: str, spec: TaskSpec, *, source: str) -> dict[str, Any]:
        from models.scheduled_task import ScheduledTask
        from models.user import User

        plan, refusal = await self.plan(user_id, spec)
        if plan is None or refusal is not None:
            return refusal or _error("Invalid task.")
        owner = self._owner(user_id)
        assert owner is not None and self._session_factory is not None
        now = self._clock()
        async with self._session_factory() as session:
            if plan.existing_id is not None:
                row = await session.get(ScheduledTask, plan.existing_id)
                if row is None or row.user_id != owner:
                    return _not_found()
                row.recurrence = spec.rule.to_dict()
                row.options = dict(spec.options)
                row.timezone = plan.zone_name
                row.channels = list(spec.channels)
                row.status = "active"
                row.consecutive_errors = 0
                row.last_error = None
                row.next_run_at = plan.next_run
                row.updated_at = now
                task_id = row.id
                changed = True
            else:
                task_id = uuid.uuid4()
                session.add(
                    ScheduledTask(
                        id=task_id,
                        user_id=owner,
                        kind=spec.kind,
                        label=spec.label,
                        prompt=spec.prompt,
                        options=dict(spec.options),
                        recurrence=spec.rule.to_dict(),
                        timezone=plan.zone_name,
                        channels=list(spec.channels),
                        status="active",
                        next_run_at=plan.next_run,
                        consecutive_errors=0,
                        source=source if source in ("agent", "user", "feature") else "agent",
                        created_at=now,
                        updated_at=now,
                    )
                )
                changed = False
            if plan.save_user_zone:
                user = await session.get(User, owner)
                if user is not None and not user.timezone:
                    user.timezone = plan.save_user_zone
            try:
                await session.commit()
            except IntegrityError:
                await session.rollback()
                return _error(
                    f'You already have a scheduled task called "{spec.label}".', duplicate=True
                )
        result: dict[str, Any] = {
            "ok": True,
            "task_id": str(task_id),
            "kind": spec.kind,
            "label": spec.label,
            "schedule": describe(spec.rule),
            "timezone": plan.zone_name,
            "next_run_local": local_label(plan.next_run, plan.tz),
            "channels": list(spec.channels),
            "status": "active",
        }
        if changed:
            result["updated"] = True
        return result

    async def list(self, user_id: str) -> dict[str, Any]:
        """The caller's tasks (nudges included), oldest first."""
        from models.scheduled_task import ScheduledTask

        owner, refusal = self._ready(user_id)
        if refusal is not None or owner is None:
            return refusal or _error("Scheduled tasks need a signed-in user.")
        assert self._session_factory is not None
        async with self._session_factory() as session:
            rows = (
                (
                    await session.execute(
                        select(ScheduledTask)
                        .where(ScheduledTask.user_id == owner)
                        .order_by(ScheduledTask.created_at, ScheduledTask.id)
                    )
                )
                .scalars()
                .all()
            )
            user_zone = await self._user_zone(session, owner)
        tasks: list[dict[str, Any]] = []
        used = 0
        for row in rows:
            item = task_row(row)
            size = _shown_chars(item) + 1
            if used + size > LIST_ROWS_CHARS:
                break
            tasks.append(item)
            used += size
        result: dict[str, Any] = {
            "ok": True,
            "timezone": user_zone,
            "count": len(rows),
            "tasks": tasks,
        }
        if len(tasks) < len(rows):
            result["shown"] = len(tasks)
            result["note"] = f"Only the oldest {len(tasks)} of {len(rows)} tasks fit in this list."
        return result

    async def _find_for_change(
        self, user_id: Any, action: str, params: Mapping[str, Any]
    ) -> tuple[Optional[Any], Optional[dict[str, Any]]]:
        """The caller's task a pause or delete names, or the refusal."""
        from models.scheduled_task import ScheduledTask

        allowed = {"task_id", "paused"} if action == "pause" else {"task_id"}
        extra = sorted(set(params) - allowed)
        if extra:
            return None, _error(f"schedule.{action} takes only {', '.join(sorted(allowed))}.")
        if action == "pause" and not isinstance(params.get("paused"), bool):
            return None, _error("'paused' must be true (pause) or false (resume).")
        owner, refusal = self._ready(user_id)
        if refusal is not None or owner is None:
            return None, refusal
        try:
            target = uuid.UUID(str(params.get("task_id")))
        except (TypeError, ValueError):
            return None, _not_found()
        assert self._session_factory is not None
        async with self._session_factory() as session:
            row = (
                await session.execute(
                    select(ScheduledTask).where(
                        ScheduledTask.id == target, ScheduledTask.user_id == owner
                    )
                )
            ).scalar_one_or_none()
        if row is None:
            return None, _not_found()
        return row, None

    async def pause(self, user_id: str, params: dict[str, Any]) -> dict[str, Any]:
        """Pause or resume one of the caller's tasks."""
        task, refusal = await self._find_for_change(user_id, "pause", params)
        if task is None or refusal is not None:
            return refusal or _not_found()
        return await self.set_paused(user_id, task.id, bool(params["paused"]))

    async def set_paused(self, user_id: Any, task_id: Any, paused: bool) -> dict[str, Any]:
        """Pause, or resume with the next run counted from now and the
        error count reset (a task stopped after errors resumes the same
        way). The owner's own routes and commands call this directly."""
        from models.scheduled_task import ScheduledTask

        owner, refusal = self._ready(user_id)
        if refusal is not None or owner is None:
            return refusal or _not_found()
        try:
            target = uuid.UUID(str(task_id))
        except (TypeError, ValueError):
            return _not_found()
        assert self._session_factory is not None
        now = self._clock()
        async with self._session_factory() as session:
            row = (
                await session.execute(
                    select(ScheduledTask).where(
                        ScheduledTask.id == target, ScheduledTask.user_id == owner
                    )
                )
            ).scalar_one_or_none()
            if row is None:
                return _not_found()
            if row.status == "done":
                return _error("That one-time task has already run; set up a new one instead.")
            if paused:
                row.status = "paused"
            else:
                rule = recurrence_from_stored(row.recurrence)
                tz, _err = parse_zone(row.timezone)
                nxt = next_after(rule, tz, now) if rule is not None and tz is not None else None
                if nxt is None:
                    return _error("That task has no future run left to resume.")
                row.status = "active"
                row.consecutive_errors = 0
                row.last_error = None
                row.next_run_at = nxt
            row.updated_at = now
            label, status, zone = row.label, row.status, row.timezone
            next_run = row.next_run_at
            await session.commit()
        tz, _err = parse_zone(zone)
        result: dict[str, Any] = {"ok": True, "task_id": str(target), "label": label, "status": status}
        if status == "active" and tz is not None:
            result["next_run_local"] = local_label(_utc(next_run), tz)
        return result

    async def delete(self, user_id: str, params: dict[str, Any]) -> dict[str, Any]:
        task, refusal = await self._find_for_change(user_id, "delete", params)
        if task is None or refusal is not None:
            return refusal or _not_found()
        return await self.delete_task(user_id, task.id)

    async def delete_task(self, user_id: Any, task_id: Any) -> dict[str, Any]:
        """Delete one of the caller's tasks and its run history; its
        conversation is kept."""
        from models.scheduled_task import ScheduledTask

        owner, refusal = self._ready(user_id)
        if refusal is not None or owner is None:
            return refusal or _not_found()
        try:
            target = uuid.UUID(str(task_id))
        except (TypeError, ValueError):
            return _not_found()
        assert self._session_factory is not None
        async with self._session_factory() as session:
            row = (
                await session.execute(
                    select(ScheduledTask).where(
                        ScheduledTask.id == target, ScheduledTask.user_id == owner
                    )
                )
            ).scalar_one_or_none()
            if row is None:
                return _not_found()
            label = row.label
            await session.delete(row)
            await session.commit()
        return {"ok": True, "task_id": str(target), "label": label, "deleted": True}


def task_row(row: Any) -> dict[str, Any]:
    """One task as schedule.list, the REST list and the chat commands show
    it: schedule and times in the task's zone, the prompt cut to 200
    characters, never the conversation's text."""
    rule = recurrence_from_stored(row.recurrence)
    tz, _err = parse_zone(row.timezone)
    item: dict[str, Any] = {
        "id": str(row.id),
        "kind": row.kind,
        "label": row.label,
        "schedule": describe(rule) if rule is not None else "unreadable schedule",
        "timezone": row.timezone,
        "status": row.status,
        "next_run_local": (
            local_label(_utc(row.next_run_at), tz)
            if row.status == "active" and tz is not None and row.next_run_at is not None
            else None
        ),
        "last_run_local": (
            local_label(_utc(row.last_run_at), tz) if tz is not None and row.last_run_at else None
        ),
        "last_status": row.last_status,
        "channels": list(row.channels or []),
    }
    options = row.options if isinstance(row.options, dict) else {}
    if row.kind == "prompt":
        prompt = row.prompt or ""
        item["tools"] = list(options.get("tools") or [])
        item["write_tools"] = list(options.get("write_tools") or [])
        item["prompt"] = prompt[:PROMPT_PREVIEW_CHARS]
        item["prompt_truncated"] = len(prompt) > PROMPT_PREVIEW_CHARS
    elif row.kind == "briefing":
        item["sections"] = list(options.get("sections") or [])
        item["topic"] = options.get("topic")
        item["summary"] = bool(options.get("summary"))
    elif row.kind == "nudge":
        item["renderer"] = options.get("renderer")
    if row.consecutive_errors:
        item["consecutive_errors"] = row.consecutive_errors
    if row.last_error:
        item["last_error"] = row.last_error[:100]
    return item
