"""Implements the goals.* built-in tools: create a goal with its first
milestones, list and read goals, update them (fields, status, milestones),
log progress notes, and delete a goal (behind a card).

Why it exists: the agent keeps the user's goals in the same store the Goals
page uses, so every rule lives in services/goals/store.py and this toolkit only
adapts it to tool calls:
- ownership: ``user_id`` is the executor's, never a tool argument (one in the
  arguments is dropped); another user's goal reads as "not found";
- unknown arguments fail closed, and every free-text field is cleaned and
  screened by the store (prompt guard and secret detector) before it is
  stored; a refusal never repeats the text;
- only goals.delete needs a card: its sentence comes from the database facts
  the async bind adds under ``_goal`` (a model-supplied ``_goal`` is refused
  before any card, an unbound delete never runs, and a goal that changed
  after its card was made is not deleted);
- every result stays within the budget the runtime gives the tool
  (RESULT_CHAR_BUDGETS in services/agent/runtime.py holds the numbers below
  plus 2000 of headroom; raise both together).
Tool errors are results (``{"ok": False, "error": ...}``), never exceptions.
"""

from __future__ import annotations

import uuid
from typing import Any, Callable, Mapping, Optional

import structlog
from sqlalchemy.exc import SQLAlchemyError

from models.goal import TITLE_MAX_CHARS
from services.goals import store as goal_store
from services.goals.store import GoalConflict, GoalError, GoalNotFound, as_uuid
from services.tools.text_budget import shown_length

logger = structlog.get_logger(__name__)

# The policy a goals.* call refused before its card is filed under
# (services/agent/runtime.py _BIND_REFUSAL_POLICIES names it too).
GOALS_RULE_POLICY = "goals_rule"
# The reserved argument the async bind adds to a delete card: the goal's
# facts read from the database. Never taken from the model.
GOAL_CARD_KEY = "_goal"

# Result sizes as the model is shown them (the whole result, measured by
# text_budget.shown_length). The budgets in runtime.py RESULT_CHAR_BUDGETS
# are these numbers plus 2000 of headroom (as study's): goals.list,
# goals.get, and goals.create / goals.update; raise both together.
# goals.log_progress and goals.delete fit the default 2000.
MAX_LIST_RESULT_CHARS = 16000
MAX_GET_RESULT_CHARS = 20000
MAX_WRITE_RESULT_CHARS = 10000
# Room kept in a list result for its keys and the "more did not fit" note.
_LIST_ROOM_CHARS = 400
# How much of a description a list row shows (goals.get shows it whole).
LIST_DESCRIPTION_CHARS = 160
# What an oversized goal is cut to, step by step, until it fits.
CUT_DESCRIPTION_CHARS = 200
CUT_MILESTONE_TITLE_CHARS = 60
CUT_LINE_CHARS = 120

_KEYS = {
    "create": goal_store.CREATE_KEYS,
    "list": frozenset({"status", "category"}),
    "get": frozenset({"goal_id"}),
    "update": goal_store.UPDATE_KEYS | {"goal_id"},
    "log_progress": goal_store.PROGRESS_KEYS | {"goal_id"},
    "delete": frozenset({"goal_id"}),
}
# What a delete card's facts must still be when the approved call runs.
_FACT_KEYS = ("goal_id", "title", "milestones", "entries")
# Rules that are a refusal the owner should see as blocked. Anything else is
# the call's own error, which the model fixes; a ``refused`` result under any
# other rule would be shown on every channel as a security block.
_REFUSAL_RULES = frozenset({"reserved_argument"})

STORAGE_ERROR = "Goal storage is unavailable; try again shortly."
TRIMMED_NOTE = (
    "Some of this goal was shortened to fit (older progress notes first); the Goals page "
    "shows it whole."
)
GOAL_CHANGED_ERROR = (
    "This goal changed after its card was made (its title, milestones or progress notes), "
    "so nothing was deleted. Ask again so a new card shows it as it is now."
)


def _error(message: str, *, rule: str = "invalid_arguments", **extra: Any) -> dict[str, Any]:
    result: dict[str, Any] = {"ok": False, "error": message, "rule": rule, **extra}
    if rule in _REFUSAL_RULES:
        result["refused"] = True
    return result


def _not_found() -> dict[str, Any]:
    return _error("Goal not found. Call goals.list for the ids.", rule="not_found", not_found=True)


def _refusal(exc: GoalError) -> dict[str, Any]:
    """A store refusal as a tool result (its message never holds the
    user's text)."""
    if isinstance(exc, GoalNotFound):
        return _not_found()
    extra: dict[str, Any] = {}
    if isinstance(exc, GoalConflict) and exc.existing_id:
        extra["existing_goal_id"] = exc.existing_id
    return _error(exc.message, rule=exc.rule, **extra)


def _cut(text: Optional[str], limit: int) -> Optional[str]:
    if text is None:
        return None
    return text if len(text) <= limit else text[: limit - 1] + "…"


def _unknown(action: str, params: Mapping[str, Any]) -> Optional[dict[str, Any]]:
    unknown = sorted(str(k) for k in params if k not in _KEYS[action])
    if not unknown:
        return None
    shown = [k for k in unknown if k.replace("_", "").isalnum() and len(k) <= 24][:4]
    return _error(
        f"Unknown argument(s) for goals.{action}" + (f": {', '.join(shown)}." if shown else ".")
    )


def _goal_id(params: Mapping[str, Any]) -> tuple[Optional[uuid.UUID], Optional[str]]:
    value = params.get("goal_id")
    if value is None or value == "":
        return None, "'goal_id' is required. Call goals.list for the ids."
    key = as_uuid(value)
    if key is None:
        return None, "'goal_id' is not a valid id. Call goals.list for the ids."
    return key, None


def _count(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0


def _list_rows(goals: list[dict[str, Any]], budget: int) -> list[dict[str, Any]]:
    """Goal summaries (descriptions shortened) in order, as many as fit in
    *budget* shown characters."""
    rows: list[dict[str, Any]] = []
    used = 2
    for goal in goals:
        row = {**goal, "description": _cut(goal.get("description"), LIST_DESCRIPTION_CHARS)}
        size = shown_length(row) + 2
        if used + size > budget:
            break
        rows.append(row)
        used += size
    return rows


def _fitted(result: dict[str, Any], budget: int) -> dict[str, Any]:
    """*result* (``{ok, goal}``) within *budget* shown characters: the
    oldest progress notes go first, then the description, the milestone
    titles and the title and current state are shortened, each step only
    while it is still too big."""
    if shown_length(result) <= budget:
        return result
    goal = dict(result["goal"])
    fitted = {**result, "goal": goal, "trimmed": True, "note": TRIMMED_NOTE}
    entries = list(goal.get("entries") or [])
    while entries and shown_length(fitted) > budget:
        entries.pop()
        goal["entries"] = list(entries)
    if shown_length(fitted) > budget:
        goal["description"] = _cut(goal.get("description"), CUT_DESCRIPTION_CHARS)
    if shown_length(fitted) > budget:
        goal["milestones"] = [
            {**m, "title": _cut(m.get("title"), CUT_MILESTONE_TITLE_CHARS)}
            for m in goal.get("milestones") or []
        ]
    if shown_length(fitted) > budget:
        goal["title"] = _cut(goal.get("title"), CUT_LINE_CHARS)
        goal["current_state"] = _cut(goal.get("current_state"), CUT_LINE_CHARS)
    return fitted


class GoalsToolkit:
    """Executes the ``goals.*`` actions for one caller.

    ``session_factory`` is the application's; without one every action is
    refused (fail closed). Construction does no I/O."""

    def __init__(self, session_factory: Optional[Callable[[], Any]] = None) -> None:
        self._session_factory = session_factory

    # -- dispatch ------------------------------------------------------------

    async def execute(self, action: str, params: dict[str, Any], user_id: str) -> dict[str, Any]:
        """Run one ``goals.*`` action as *user_id* (the executor's). Unknown
        actions and arguments fail closed."""
        raw = params if isinstance(params, Mapping) else {}
        params = {k: v for k, v in raw.items() if k != "user_id"}
        if action not in _KEYS:
            return _error(f"Unknown goals action '{action}'.")
        if action != "delete" or GOAL_CARD_KEY not in params:
            unknown = _unknown(action, params)
            if unknown is not None:
                return unknown
        if self._session_factory is None:
            return _error("Goals are not configured (no database).", rule="storage")
        owner = as_uuid(str(user_id))
        if owner is None:
            return _error("Goals need a signed-in user.", rule="storage")
        try:
            handler = getattr(self, f"_{action}")
            result: dict[str, Any] = await handler(owner, params)
            return result
        except GoalError as exc:
            return _refusal(exc)
        except SQLAlchemyError as exc:
            logger.error("goals_tool_db_error", action=action, error_type=type(exc).__name__)
            return _error(STORAGE_ERROR, rule="storage")
        except Exception as exc:  # noqa: BLE001 - a tool failure is a result
            logger.error(
                "goals_tool_unexpected_error", action=action, error_type=type(exc).__name__
            )
            return _error(f"Goal action failed: {type(exc).__name__}", rule="storage")

    def _session(self) -> Any:
        assert self._session_factory is not None
        return self._session_factory()

    # -- create, list, get ---------------------------------------------------

    async def _create(self, owner: uuid.UUID, params: dict[str, Any]) -> dict[str, Any]:
        async with self._session() as session:
            goal = await goal_store.create_goal(session, owner, params, source="agent")
            await session.commit()
        return _fitted({"ok": True, "goal": goal}, MAX_WRITE_RESULT_CHARS)

    async def _list(self, owner: uuid.UUID, params: dict[str, Any]) -> dict[str, Any]:
        status = params.get("status")
        async with self._session() as session:
            goals = await goal_store.list_goals(
                session,
                owner,
                status=status if status is not None else "active",
                category=params.get("category"),
            )
        rows = _list_rows(goals, MAX_LIST_RESULT_CHARS - _LIST_ROOM_CHARS)
        result: dict[str, Any] = {"ok": True, "goals": rows, "count": len(goals)}
        if len(rows) < len(goals):
            result["shown"] = len(rows)
            result["note"] = (
                f"{len(goals) - len(rows)} more goals did not fit; narrow the list with status "
                "or category."
            )
        return result

    async def _get(self, owner: uuid.UUID, params: dict[str, Any]) -> dict[str, Any]:
        key, err = _goal_id(params)
        if err or key is None:
            return _error(err or "Invalid goal_id.")
        async with self._session() as session:
            goal = await goal_store.get_goal(
                session, owner, key, entries_limit=goal_store.DEFAULT_ENTRIES
            )
        return _fitted({"ok": True, "goal": goal}, MAX_GET_RESULT_CHARS)

    # -- update, log_progress --------------------------------------------------

    async def _update(self, owner: uuid.UUID, params: dict[str, Any]) -> dict[str, Any]:
        key, err = _goal_id(params)
        if err or key is None:
            return _error(err or "Invalid goal_id.")
        data = {k: v for k, v in params.items() if k != "goal_id"}
        async with self._session() as session:
            goal = await goal_store.update_goal(
                session, owner, key, data, entries_limit=goal_store.DEFAULT_ENTRIES
            )
            await session.commit()
        return _fitted({"ok": True, "goal": goal}, MAX_WRITE_RESULT_CHARS)

    async def _log_progress(self, owner: uuid.UUID, params: dict[str, Any]) -> dict[str, Any]:
        key, err = _goal_id(params)
        if err or key is None:
            return _error(err or "Invalid goal_id.")
        note = params.get("note")
        if not isinstance(note, str):
            return _error("'note' must be text." if note is not None else "'note' is required.")
        async with self._session() as session:
            entry = await goal_store.log_progress(
                session, owner, key, note, milestone_id=params.get("milestone_id"), source="agent"
            )
            await session.commit()
        return {"ok": True, "entry": entry}

    # -- delete (behind a card) ------------------------------------------------

    async def precheck(
        self, action: str, params: Mapping[str, Any], user_id: str
    ) -> Optional[dict[str, Any]]:
        """The refusal a goals.* call meets before any card, with no
        database: a ``_goal`` it brought itself, and for goals.delete an
        unknown argument or a malformed id. None otherwise."""
        raw = params if isinstance(params, Mapping) else {}
        args = {k: v for k, v in raw.items() if k != "user_id"}
        if GOAL_CARD_KEY in args:
            return _error(
                f"'{GOAL_CARD_KEY}' is set by Crawler, never given: the card's facts are read "
                "from the database.",
                rule="reserved_argument",
            )
        if action != "delete":
            return None
        unknown = _unknown("delete", args)
        if unknown is not None:
            return unknown
        _key, err = _goal_id(args)
        if err:
            return _error(err)
        return None

    async def bind(self, action: str, params: Mapping[str, Any], user_id: str) -> dict[str, Any]:
        """A delete card's arguments: the call's own plus ``_goal`` (the
        goal's id and title and how many milestones and progress notes it
        has, read now). A goal that is not the user's is refused instead (no
        card)."""
        raw = params if isinstance(params, Mapping) else {}
        args = {k: v for k, v in raw.items() if k != "user_id"}
        if action != "delete":
            return args
        refusal = await self.precheck(action, args, user_id)
        if refusal is not None:
            return {**refusal, "refused": True}
        key, _err = _goal_id(args)
        owner = as_uuid(str(user_id))
        # Not found is the call's own error (rule invalid_arguments, which
        # the runtime never shows as a security block), as study.delete's is.
        not_found = {
            **_error("Goal not found. Call goals.list for the ids.", not_found=True),
            "refused": True,
        }
        if owner is None or key is None or self._session_factory is None:
            return not_found
        try:
            async with self._session() as session:
                facts = await goal_store.goal_facts(session, owner, key)
        except GoalNotFound:
            return not_found
        except GoalError as exc:
            return {**_refusal(exc), "refused": True}
        except Exception as exc:  # noqa: BLE001 - no card when the facts cannot be read
            logger.error("goals_bind_failed", error_type=type(exc).__name__)
            return {**_error(STORAGE_ERROR, rule="storage"), "refused": True}
        return {**args, GOAL_CARD_KEY: facts}

    def describe(self, action: str, params: Mapping[str, Any]) -> Optional[str]:
        """The delete card's sentence, from the bound facts only; None
        without them (the runtime then uses its generic reason)."""
        if action != "delete":
            return None
        facts = params.get(GOAL_CARD_KEY) if isinstance(params, Mapping) else None
        if not isinstance(facts, Mapping):
            return None
        title = facts.get("title")
        milestones, entries = facts.get("milestones"), facts.get("entries")
        if not isinstance(title, str) or not _count(milestones) or not _count(entries):
            return None
        shown = _cut(" ".join(title.split()), TITLE_MAX_CHARS)
        return (
            f'Delete the goal "{shown}" with {milestones} '
            f'milestone{"" if milestones == 1 else "s"} and {entries} '
            f'progress note{"" if entries == 1 else "s"}.'
        )

    async def _delete(self, owner: uuid.UUID, params: dict[str, Any]) -> dict[str, Any]:
        """Runs only approved (the executor's confirm set). The card's
        ``_goal`` must be there and still true: a delete no bind checked,
        or of a goal that changed since its card was made, is refused."""
        facts = params.get(GOAL_CARD_KEY)
        if not isinstance(facts, Mapping):
            return _error(
                "This delete was not checked before approval; ask for it again.", rule="unbound"
            )
        args = {k: v for k, v in params.items() if k != GOAL_CARD_KEY}
        unknown = _unknown("delete", args)
        if unknown is not None:
            return unknown
        key, err = _goal_id(args)
        if err or key is None:
            return _error(err or "Invalid goal_id.")
        async with self._session() as session:
            current = await goal_store.goal_facts(session, owner, key)
            if any(current.get(k) != facts.get(k) for k in _FACT_KEYS):
                return _error(GOAL_CHANGED_ERROR, rule="goal_changed")
            deleted = await goal_store.delete_goal(session, owner, key)
            await session.commit()
        return {"ok": True, "deleted": deleted}
