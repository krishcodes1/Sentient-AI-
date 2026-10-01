"""Implements the study.* built-in tools: save flashcards and multiple-choice
items to decks, list and edit them, delete them (behind a card), review them
on an SM-2 schedule, run practice quizzes graded in code, report progress,
set review limits and the daily "cards are due" nudge, and mint one-time
Anki/CSV download links.

Why it exists: the agent turns the user's material into stored decks, and
everything about them runs through one set of rules:
- ownership: ``user_id`` is the executor's, never a tool argument (one in the
  arguments is dropped); another user's deck, item or quiz reads as "not
  found";
- items are validated and screened before they are stored
  (services/study/items.py) and a rejection never repeats the text;
- a quiz never shows its answers before they are submitted; choice items are
  graded here, in code, and the answer key stays in the database;
- only study.delete needs a card: its sentence comes from the database facts
  the async bind adds under ``_deck`` (a model-supplied ``_deck`` is refused
  before any card, and an unbound delete never runs);
- every list stays within the result budget the runtime gives the tool
  (RESULT_CHAR_BUDGETS in services/agent/runtime.py; raise both together).
Tool errors are results (``{"ok": False, "error": ...}``), never exceptions.
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from typing import Any, Callable, Mapping, Optional

import structlog
from sqlalchemy import select
from sqlalchemy.exc import SQLAlchemyError

from services.agent.prompt_guard import _INVISIBLE_CHARS
from services.study import engine as study_engine
from services.study import items as item_rules
from services.study import srs
from services.study.engine import StudyEngine, as_uuid, shuffled_order
from services.study.export import EXPORT_TOKENS, FORMATS, ExportTokens, safe_filename
from services.study.nudges import LABEL as NUDGE_LABEL
from services.study.nudges import RENDERER as NUDGE_RENDERER
from services.study.render import LETTERS

logger = structlog.get_logger(__name__)

# The policy a study.* call refused before its card is filed under
# (services/agent/runtime.py _BIND_REFUSAL_POLICIES names it too).
STUDY_RULE_POLICY = "study_rule"
# The reserved argument the async bind adds to a delete card: the deck's
# facts read from the database. Never taken from the model.
DECK_CARD_KEY = "_deck"
EXPORT_PATH = "/api/study/export"

# Result sizes as the model is shown them. The budgets in runtime.py are
# these plus room for the keys: study.decks 14000, study.review 12000,
# study.quiz 16000, study.progress 6000.
DECKS_ROWS_CHARS = 12000
REVIEW_ROWS_CHARS = 10000
QUIZ_ROWS_CHARS = 14000
PREVIEW_CHARS = 200
DECKS_DEFAULT_LIMIT = 20
DECKS_MAX_LIMIT = 50
DECKS_FULL_MAX_LIMIT = 10
REVIEW_NEXT_MAX = 3
QUIZ_DEFAULT_COUNT = 10
DELETE_MAX_ITEMS = 50
NEW_PER_DAY_RANGE = (0, 100)
SESSION_SIZE_RANGE = (5, 50)
DEFAULT_NUDGE_HOUR = 18
WEEKDAYS = ("mon", "tue", "wed", "thu", "fri", "sat", "sun")
NUDGE_CHANNELS = ("telegram", "slack")

TIMEZONE_REQUIRED_ERROR = (
    "The user's time zone is unknown. Ask which time zone they are in (an IANA name "
    "such as America/New_York) and call study.settings again with 'timezone'."
)

_KEYS = {
    "save": frozenset({"deck_id", "title", "course", "source_kind", "source_ref", "items"}),
    "decks": frozenset({"deck_id", "offset", "limit", "tag", "full"}),
    "edit": frozenset(
        {
            "deck_id",
            "item_id",
            "title",
            "course",
            "in_reviews",
            "front",
            "back",
            "choices",
            "answer",
            "explanation",
            "choice_notes",
            "tags",
            "difficulty",
            "suspended",
            "reset_progress",
        }
    ),
    "delete": frozenset({"deck_id", "item_ids"}),
    "review": frozenset({"action", "deck_id", "count", "item_id", "rating"}),
    "quiz": frozenset(
        {"action", "deck_id", "count", "tag", "difficulty", "attempt_id", "item_id", "answers", "offset"}
    ),
    "progress": frozenset({"deck_id", "course"}),
    "settings": frozenset({"reminder", "hour", "days", "new_per_day", "session_size", "timezone"}),
    "export": frozenset({"deck_id", "format"}),
}
_ITEM_EDIT_FIELDS = ("front", "back", "choices", "answer", "explanation", "choice_notes", "tags", "difficulty")
_DECK_EDIT_FIELDS = ("title", "course", "in_reviews")
# Rules that are a refusal the owner should see as blocked.
_REFUSAL_RULES = frozenset({"reserved_argument"})


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _error(message: str, *, rule: str = "invalid_arguments", **extra: Any) -> dict[str, Any]:
    result: dict[str, Any] = {"ok": False, "error": message, "rule": rule, **extra}
    if rule in _REFUSAL_RULES:
        result["refused"] = True
    return result


def _deck_not_found() -> dict[str, Any]:
    return _error("Deck not found. Call study.decks for the ids.", not_found=True)


def _shown_chars(value: Any) -> int:
    """*value*'s size as the runtime shows it to the model."""
    text = json.dumps(value, ensure_ascii=False, separators=(",", ":"), default=str)
    return len(_INVISIBLE_CHARS.sub(lambda m: json.dumps(m.group())[1:-1], text))


def _cut(text: Optional[str], limit: int) -> Optional[str]:
    if text is None:
        return None
    return text if len(text) <= limit else text[: limit - 1] + "…"


def _iso(value: Optional[datetime]) -> Optional[str]:
    utc = study_engine._utc(value)
    return utc.isoformat(timespec="minutes") if utc is not None else None


def _unknown(action: str, params: Mapping[str, Any]) -> Optional[dict[str, Any]]:
    unknown = sorted(str(k) for k in params if k not in _KEYS[action])
    if not unknown:
        return None
    shown = [k for k in unknown if k.replace("_", "").isalnum() and len(k) <= 24][:4]
    return _error(f"Unknown argument(s) for study.{action}" + (f": {', '.join(shown)}." if shown else "."))


def _int(value: Any, name: str, low: int, high: int, default: Optional[int] = None) -> tuple[Optional[int], Optional[str]]:
    if value is None:
        return default, None
    whole = isinstance(value, int) or (isinstance(value, float) and value.is_integer())
    if isinstance(value, bool) or not whole:
        return None, f"'{name}' must be a whole number from {low} to {high}."
    number = int(value)
    if not low <= number <= high:
        return None, f"'{name}' must be from {low} to {high}."
    return number, None


def _bool(value: Any, name: str) -> tuple[Optional[bool], Optional[str]]:
    if value is None:
        return None, None
    if not isinstance(value, bool):
        return None, f"'{name}' must be true or false."
    return value, None


def _id(value: Any, name: str, *, required: bool = True) -> tuple[Optional[uuid.UUID], Optional[str]]:
    if value is None or value == "":
        return None, (f"'{name}' is required." if required else None)
    key = as_uuid(value)
    if key is None:
        return None, f"'{name}' is not a valid id."
    return key, None


def _shown_choices(item: Any, seed: str) -> tuple[list[str], list[int]]:
    """An item's choices in the order shown (seeded), and ``order[shown] =
    stored index``."""
    choices = list(item.choices or [])
    order = shuffled_order(seed, item.id, len(choices))
    return [choices[i] for i in order], order


def _letter_of(index: Optional[int]) -> str:
    return LETTERS[index] if index is not None and 0 <= index < len(LETTERS) else "?"


def _choice_index(value: Any, count: int) -> Optional[int]:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value if 0 <= value < count else None
    if isinstance(value, str):
        text = value.strip().rstrip(")").strip()
        if len(text) == 1 and text.upper() in LETTERS[:count]:
            return LETTERS.index(text.upper())
        if text.isdecimal() and 0 <= int(text) < count:
            return int(text)
    return None


class StudyToolkit:
    """Executes the ``study.*`` actions for one caller.

    ``session_factory`` is the application's; without one every action is
    refused (fail closed). ``exports`` holds the one-time download tokens
    (the process's own by default, shared with the download route);
    ``nudges`` is the schedule service (``app.state.schedules``) the daily
    reminder is scheduled through, wired by main.py (``use_nudges``);
    ``clock`` and ``default_timezone`` are test seams."""

    def __init__(
        self,
        session_factory: Optional[Callable[[], Any]] = None,
        *,
        clock: Callable[[], datetime] = _utcnow,
        exports: Optional[ExportTokens] = None,
        nudges: Optional[Any] = None,
        default_timezone: Callable[[], Optional[str]] = study_engine.default_timezone,
    ) -> None:
        self._session_factory = session_factory
        self.engine = StudyEngine(session_factory, clock=clock, default_timezone=default_timezone)
        # "is not None": an empty token store has no length, so it is falsy.
        self.exports = exports if exports is not None else EXPORT_TOKENS
        self._nudges = nudges

    def use_nudges(self, scheduler: Any) -> None:
        """Wire the NudgeScheduler (main.py, once the schedule service exists)."""
        self._nudges = scheduler

    # -- dispatch ------------------------------------------------------------

    async def execute(self, action: str, params: dict[str, Any], user_id: str) -> dict[str, Any]:
        """Run one ``study.*`` action as *user_id* (the executor's). Unknown
        actions and arguments fail closed."""
        params = {k: v for k, v in (params or {}).items() if k != "user_id"}
        if action not in _KEYS:
            return _error(f"Unknown study action '{action}'.")
        if action != "delete" or DECK_CARD_KEY not in params:
            unknown = _unknown(action, params)
            if unknown is not None:
                return unknown
        if self._session_factory is None:
            return _error("Flashcards are not configured (no database).", rule="storage")
        owner = as_uuid(str(user_id))
        if owner is None:
            return _error("Flashcards need a signed-in user.", rule="storage")
        try:
            handler = getattr(self, f"_{action}")
            result: dict[str, Any] = await handler(owner, params)
            return result
        except SQLAlchemyError as exc:
            logger.error("study_tool_db_error", action=action, error_type=type(exc).__name__)
            return _error("Flashcard storage is unavailable; try again shortly.", rule="storage")
        except Exception as exc:  # noqa: BLE001 - a tool failure is a result
            logger.error("study_tool_unexpected_error", action=action, error_type=type(exc).__name__)
            return _error(f"Flashcard action failed: {type(exc).__name__}", rule="storage")

    # -- save ----------------------------------------------------------------

    async def _save(self, owner: uuid.UUID, params: dict[str, Any]) -> dict[str, Any]:
        deck_id, err = _id(params.get("deck_id"), "deck_id", required=False)
        if err:
            return _error(err)
        title_given = params.get("title") is not None
        if deck_id is not None and title_given:
            return _error("Give deck_id to add to a deck, or title to start a new one, not both.")
        if deck_id is None and not title_given:
            return _error("Give a 'title' for a new deck, or the 'deck_id' of one to add to.")
        new_deck: Optional[dict[str, Any]] = None
        if deck_id is None:
            title, err = item_rules.clean_label(
                params.get("title"), name="title", max_chars=item_rules.TITLE_MAX_CHARS, required=True
            )
            if err or title is None:
                return _error(err or "Invalid title.")
            course, err = item_rules.clean_label(
                params.get("course"), name="course", max_chars=item_rules.COURSE_MAX, required=False
            )
            if err:
                return _error(err)
            kind = params.get("source_kind") or "notes"
            if not isinstance(kind, str) or kind.strip().lower() not in item_rules.SOURCE_KINDS:
                return _error(f"'source_kind' must be one of {', '.join(item_rules.SOURCE_KINDS)}.")
            ref, err = item_rules.clean_label(
                params.get("source_ref"), name="source_ref", max_chars=item_rules.SOURCE_REF_MAX, required=False
            )
            if err:
                return _error(err)
            new_deck = {"title": title, "course": course, "source_kind": kind.strip().lower(), "source_ref": ref}
        elif any(params.get(k) is not None for k in ("course", "source_kind", "source_ref")):
            return _error("course, source_kind and source_ref describe a new deck; change a deck with study.edit.")
        raw_items = params.get("items")
        if not isinstance(raw_items, list) or not raw_items:
            return _error(f"'items' must be a list of 1-{item_rules.MAX_ITEMS_PER_CALL} items.")
        if len(raw_items) > item_rules.MAX_ITEMS_PER_CALL:
            return _error(
                f"At most {item_rules.MAX_ITEMS_PER_CALL} items per call; save the rest with another "
                "call using the deck_id this one returns."
            )
        chars = item_rules.raw_chars(raw_items)
        if chars > item_rules.MAX_CALL_CHARS:
            return _error(
                f"These items hold {chars} characters; at most {item_rules.MAX_CALL_CHARS} per call. "
                "Split them over several calls."
            )
        drafts: list[tuple[int, item_rules.ItemDraft]] = []
        rejected: list[dict[str, Any]] = []
        for index, raw in enumerate(raw_items):
            draft, reason = item_rules.validate_item(raw)
            if draft is None:
                rejected.append({"index": index, "reason": reason or "invalid item"})
            else:
                drafts.append((index, draft))
        if not drafts:
            return _error("No item could be saved; fix them and call again.", rejected=rejected)
        saved = await self.engine.save_items(
            owner,
            deck_id=deck_id,
            new_deck=new_deck,
            drafts=drafts,
            max_decks=item_rules.MAX_DECKS_PER_USER,
            max_items_per_user=item_rules.MAX_ITEMS_PER_USER,
            max_items_per_deck=item_rules.MAX_ITEMS_PER_DECK,
        )
        if not saved.get("ok"):
            reason = saved.get("reason")
            if reason == study_engine.NOT_FOUND:
                return _deck_not_found()
            if reason == "deck_limit":
                return _error(
                    f"You already have {item_rules.MAX_DECKS_PER_USER} decks, the most allowed. "
                    "Add to an existing deck or delete one first.",
                    rule="limit",
                )
            if reason == "deck_item_limit":
                return _error(
                    f"A deck holds at most {item_rules.MAX_ITEMS_PER_DECK} items (this one has "
                    f"{saved.get('in_deck', 0)}). Start a new deck for the rest.",
                    rule="limit",
                )
            if reason == "user_item_limit":
                return _error(
                    f"You already have close to {item_rules.MAX_ITEMS_PER_USER} items, the most allowed.",
                    rule="limit",
                )
            if reason == "nothing_to_add":
                return _error("Every item repeats another in this call; nothing was saved.", rejected=rejected)
            return _error("The items could not be saved.")
        logger.info(
            "study_items_saved",
            deck_id=saved["deck_id"],
            added=saved["added"],
            skipped=saved["skipped_duplicates"],
            rejected=len(rejected),
        )
        return {
            "ok": True,
            "deck_id": saved["deck_id"],
            "title": saved["title"],
            "created": saved["created"],
            "added": saved["added"],
            "skipped_duplicates": saved["skipped_duplicates"],
            "rejected": rejected,
            "deck_items": saved["deck_items"],
            "added_ids": saved["added_ids"],
            "next": "Show the user 3 of the saved items and offer to fix any.",
        }

    # -- decks ---------------------------------------------------------------

    async def _decks(self, owner: uuid.UUID, params: dict[str, Any]) -> dict[str, Any]:
        deck_id, err = _id(params.get("deck_id"), "deck_id", required=False)
        if err:
            return _error(err)
        full, err = _bool(params.get("full"), "full")
        if err:
            return _error(err)
        high = DECKS_FULL_MAX_LIMIT if full else DECKS_MAX_LIMIT
        limit, err = _int(params.get("limit"), "limit", 1, high, min(DECKS_DEFAULT_LIMIT, high))
        if err or limit is None:
            return _error(err or "Invalid limit.")
        offset, err = _int(params.get("offset"), "offset", 0, 100000, 0)
        if err or offset is None:
            return _error(err or "Invalid offset.")
        tag = params.get("tag")
        if tag is not None:
            tags, err = item_rules.clean_tags([tag])
            if err or not tags:
                return _error(err or "Invalid tag.")
            tag = tags[0]
            if deck_id is None:
                return _error("'tag' filters one deck's items: give its deck_id too.")
        if deck_id is None:
            decks, stats = await self.engine.list_decks(owner)
            rows: list[dict[str, Any]] = []
            for number, deck in enumerate(decks, start=1):
                s = stats.get(deck.id, {})
                reviews = int(s.get("reviews_30d", 0))
                rows.append(
                    {
                        "n": number,
                        "deck_id": str(deck.id),
                        "title": deck.title,
                        "course": deck.course,
                        "items": int(s.get("items", 0)),
                        "due_now": int(s.get("due_now", 0)),
                        "new": int(s.get("new", 0)),
                        "in_reviews": bool(deck.in_reviews),
                        "last_studied": _iso(deck.last_studied_at),
                        "accuracy_30d": round(int(s.get("correct_30d", 0)) / reviews, 2) if reviews else None,
                    }
                )
            page, next_offset = self._page(rows, offset, limit, DECKS_ROWS_CHARS)
            result: dict[str, Any] = {"ok": True, "decks": page, "total": len(rows)}
            if next_offset is not None:
                result["next_offset"] = next_offset
            return result
        found = await self.engine.deck_items(owner, deck_id, tag=tag)
        if found is None:
            return _deck_not_found()
        deck, items = found
        item_rows = [self._item_row(i, full=bool(full)) for i in items]
        page, next_offset = self._page(item_rows, offset, limit, DECKS_ROWS_CHARS)
        result = {
            "ok": True,
            "deck": {"deck_id": str(deck.id), "title": deck.title, "course": deck.course, "in_reviews": deck.in_reviews},
            "items": page,
            "total": len(item_rows),
        }
        if next_offset is not None:
            result["next_offset"] = next_offset
        return result

    @staticmethod
    def _item_row(item: Any, *, full: bool) -> dict[str, Any]:
        limit = 100000 if full else PREVIEW_CHARS
        row: dict[str, Any] = {
            "item_id": str(item.id),
            "kind": item.kind,
            "front": _cut(item.front, limit),
            "back": _cut(item.back, limit),
            "tags": list(item.tags or []),
            "due": _iso(item.due_at) or "new",
        }
        if item.suspended:
            row["suspended"] = True
        if item.difficulty:
            row["difficulty"] = item.difficulty
        if full:
            if item.kind == "choice":
                row["choices"] = list(item.choices or [])
                row["answer"] = item.answer_index
                if item.choice_notes:
                    row["choice_notes"] = list(item.choice_notes)
            if item.explanation:
                row["explanation"] = item.explanation
            if item.source_note:
                row["source_note"] = item.source_note
        return row

    @staticmethod
    def _page(rows: list[dict[str, Any]], offset: int, limit: int, budget: int) -> tuple[list[dict[str, Any]], Optional[int]]:
        """Rows from *offset*, at most *limit*, within *budget* shown
        characters; the next offset when some are left."""
        page: list[dict[str, Any]] = []
        used = 2
        for index in range(offset, min(len(rows), offset + limit)):
            size = _shown_chars(rows[index]) + 1
            if page and used + size > budget:
                return page, index
            page.append(rows[index])
            used += size
        end = offset + len(page)
        return page, (end if end < len(rows) else None)

    # -- edit ----------------------------------------------------------------

    async def _edit(self, owner: uuid.UUID, params: dict[str, Any]) -> dict[str, Any]:
        deck_id, err = _id(params.get("deck_id"), "deck_id", required=False)
        if err:
            return _error(err)
        item_id, err = _id(params.get("item_id"), "item_id", required=False)
        if err:
            return _error(err)
        if (deck_id is None) == (item_id is None):
            return _error("Give exactly one of deck_id (to change a deck) or item_id (to change an item).")
        reset, err = _bool(params.get("reset_progress"), "reset_progress")
        if err:
            return _error(err)
        if deck_id is not None:
            if any(params.get(k) is not None for k in (*_ITEM_EDIT_FIELDS, "suspended")):
                return _error("Those fields change an item: give its item_id instead of deck_id.")
            values: dict[str, Any] = {}
            if params.get("title") is not None:
                title, err = item_rules.clean_label(
                    params.get("title"), name="title", max_chars=item_rules.TITLE_MAX_CHARS, required=True
                )
                if err:
                    return _error(err)
                values["title"] = title
            if "course" in params:
                course, err = item_rules.clean_label(
                    params.get("course"), name="course", max_chars=item_rules.COURSE_MAX, required=False
                )
                if err:
                    return _error(err)
                values["course"] = course
            in_reviews, err = _bool(params.get("in_reviews"), "in_reviews")
            if err:
                return _error(err)
            if in_reviews is not None:
                values["in_reviews"] = in_reviews
            if not values and not reset:
                return _error("Nothing to change: give title, course, in_reviews or reset_progress.")
            done = await self.engine.edit_deck(owner, deck_id, values, reset_progress=bool(reset))
            if not done.get("ok"):
                return _deck_not_found()
            return {"ok": True, "deck_id": done["deck_id"], "changed": sorted(values) + (["progress"] if reset else [])}
        if any(params.get(k) is not None for k in _DECK_EDIT_FIELDS):
            return _error("title, course and in_reviews change a deck: give its deck_id instead of item_id.")
        suspended, err = _bool(params.get("suspended"), "suspended")
        if err:
            return _error(err)
        content = {k: params[k] for k in _ITEM_EDIT_FIELDS if k in params}
        if not content and suspended is None and not reset:
            return _error("Nothing to change: give the fields to change, suspended or reset_progress.")
        draft: Optional[item_rules.ItemDraft] = None
        if content:
            async with self.engine.session() as session:
                item = await self.engine.item(session, owner, item_id)
            if item is None:
                return _error("Item not found. Call study.decks with its deck_id for the ids.", not_found=True)
            merged = {**item_rules.draft_of(item), **content}
            if "answer" in content and item.kind == "choice" and "back" not in content:
                merged.pop("back", None)  # a choice's back follows its right answer
            draft, reason = item_rules.validate_item(merged)
            if draft is None:
                return _error(f"Not changed: the item {reason}.")
        values = {"suspended": suspended} if suspended is not None else {}
        done = await self.engine.edit_item(owner, item_id, draft, values, reset_progress=bool(reset))
        if not done.get("ok"):
            if done.get("reason") == "duplicate":
                return _error("Another item in this deck already has that front.")
            return _error("Item not found. Call study.decks with its deck_id for the ids.", not_found=True)
        changed = sorted(content) + (["suspended"] if suspended is not None else []) + (["progress"] if reset else [])
        return {"ok": True, "item_id": done["item_id"], "deck_id": done["deck_id"], "changed": changed}

    # -- delete (behind a card) ------------------------------------------------

    def _delete_args(self, params: Mapping[str, Any]) -> tuple[Optional[uuid.UUID], Optional[list[uuid.UUID]], Optional[str]]:
        deck_id, err = _id(params.get("deck_id"), "deck_id")
        if err or deck_id is None:
            return None, None, err
        raw = params.get("item_ids")
        if raw is None:
            return deck_id, None, None
        if not isinstance(raw, list) or not 1 <= len(raw) <= DELETE_MAX_ITEMS:
            return None, None, f"'item_ids' must list 1-{DELETE_MAX_ITEMS} item ids (omit it to delete the deck)."
        ids: list[uuid.UUID] = []
        for value in raw:
            key = as_uuid(value)
            if key is None:
                return None, None, "'item_ids' holds an id that is not valid."
            if key not in ids:
                ids.append(key)
        return deck_id, ids, None

    def precheck(self, action: str, params: Mapping[str, Any]) -> Optional[dict[str, Any]]:
        """The refusal a study.delete meets before any card, with no
        database: a ``_deck`` it brought itself, an unknown argument, a
        malformed id. None otherwise (and for every other action)."""
        if action != "delete":
            return None
        if DECK_CARD_KEY in params:
            return _error(
                "study.delete takes deck_id and item_ids; the card's facts are read from the "
                "database by Crawler, never given.",
                rule="reserved_argument",
            )
        unknown = _unknown("delete", params)
        if unknown is not None:
            return unknown
        _deck, _items, err = self._delete_args(params)
        if err:
            return _error(err)
        return None

    async def bind(self, action: str, params: dict[str, Any], user_id: str) -> dict[str, Any]:
        """A delete card's arguments: the call's own plus ``_deck`` (the
        deck's title and how many items and reviews it has, read now). A
        deck or item that is not the user's is refused instead (no card)."""
        if action != "delete":
            return params
        refusal = self.precheck(action, params)
        if refusal is not None:
            return {**refusal, "refused": True}
        owner = as_uuid(str(user_id))
        deck_id, item_ids, _err = self._delete_args(params)
        facts = await self.engine.deck_facts(owner, deck_id) if owner is not None and self._session_factory else None
        if facts is None or owner is None:
            return {**_deck_not_found(), "refused": True}
        if item_ids:
            count = await self.engine.items_in_deck(owner, deck_id, item_ids)
            if count != len(item_ids):
                return {
                    **_error("Some of those items are not in that deck. Call study.decks with its deck_id."),
                    "refused": True,
                }
            facts = {**facts, "delete_items": len(item_ids)}
        return {**params, DECK_CARD_KEY: facts}

    def describe(self, action: str, params: Mapping[str, Any]) -> Optional[str]:
        """The delete card's sentence, from the bound facts; None without
        them (the runtime then uses its generic reason)."""
        if action != "delete":
            return None
        facts = params.get(DECK_CARD_KEY)
        if not isinstance(facts, Mapping) or not isinstance(facts.get("title"), str):
            return None
        title = _cut(" ".join(str(facts["title"]).split()), item_rules.TITLE_MAX_CHARS)
        count = facts.get("delete_items")
        if isinstance(count, int) and count > 0:
            noun = "item" if count == 1 else "items"
            return f'Delete {count} {noun} (and their review history) from the deck "{title}". This cannot be undone.'
        items, reviews = int(facts.get("items") or 0), int(facts.get("reviews") or 0)
        return (
            f'Delete the deck "{title}" ({items} item{"" if items == 1 else "s"}, '
            f'{reviews} review{"" if reviews == 1 else "s"}). This cannot be undone.'
        )

    async def _delete(self, owner: uuid.UUID, params: dict[str, Any]) -> dict[str, Any]:
        """Runs only approved (the executor's confirm set). The card's
        ``_deck`` must be there: a delete no bind checked is refused."""
        if not isinstance(params.get(DECK_CARD_KEY), Mapping):
            return _error(
                "This delete was not checked before approval; ask for it again.", rule="unbound"
            )
        args = {k: v for k, v in params.items() if k != DECK_CARD_KEY}
        unknown = _unknown("delete", args)
        if unknown is not None:
            return unknown
        deck_id, item_ids, err = self._delete_args(args)
        if err:
            return _error(err)
        done = await self.engine.delete(owner, deck_id, item_ids)
        if not done.get("ok"):
            return _deck_not_found()
        logger.info(
            "study_deleted", deck_id=str(deck_id), whole_deck=bool(done.get("deleted_deck")), items=done.get("deleted_items")
        )
        return {
            "ok": True,
            "deck_id": str(deck_id),
            "deleted_deck": bool(done.get("deleted_deck")),
            "deleted_items": int(done.get("deleted_items") or 0),
        }

    # -- review --------------------------------------------------------------

    def _review_row(self, item: Any, titles: Mapping[Any, str], now: datetime) -> dict[str, Any]:
        seed = f"review:{item.repetitions}:{item.lapses}"
        row: dict[str, Any] = {
            "item_id": str(item.id),
            "deck": titles.get(item.deck_id),
            "kind": item.kind,
            "front": item.front,
            "back": item.back,
            "new": item.last_reviewed_at is None,
        }
        if item.kind == "choice" and item.choices:
            shown, order = _shown_choices(item, seed)
            row["choices"] = [f"{LETTERS[i]}) {c}" for i, c in enumerate(shown)]
            if item.answer_index is not None and item.answer_index in order:
                row["answer"] = LETTERS[order.index(item.answer_index)]
        if item.explanation:
            row["explanation"] = item.explanation
        if item.tags:
            row["tags"] = list(item.tags)
        intervals = srs.previews(study_engine.card_state(item), now)
        row["grades"] = {name: srs.short_interval(delta) for name, delta in intervals.items()}
        return row

    async def _next_rows(
        self, owner: uuid.UUID, count: int, deck_id: Optional[uuid.UUID]
    ) -> dict[str, Any]:
        queue = await self.engine.queue(owner, limit=count, deck_id=deck_id)
        now = self.engine.now()
        rows: list[dict[str, Any]] = []
        used = 0
        for item in queue["items"]:
            row = self._review_row(item, queue["titles"], now)
            size = _shown_chars(row)
            if rows and used + size > REVIEW_ROWS_CHARS:
                break
            rows.append(row)
            used += size
        return {
            "items": rows,
            "due_now": queue["due"],
            "new_available_today": queue["new_available"],
        }

    async def _review(self, owner: uuid.UUID, params: dict[str, Any]) -> dict[str, Any]:
        action = params.get("action")
        deck_id, err = _id(params.get("deck_id"), "deck_id", required=False)
        if err:
            return _error(err)
        if deck_id is not None:
            async with self.engine.session() as session:
                if await self.engine.deck(session, owner, deck_id) is None:
                    return _deck_not_found()
        if action == "next":
            count, err = _int(params.get("count"), "count", 1, REVIEW_NEXT_MAX, 1)
            if err or count is None:
                return _error(err or "Invalid count.")
            found = await self._next_rows(owner, count, deck_id)
            result: dict[str, Any] = {"ok": True, **found}
            if not found["items"]:
                result["note"] = "Nothing is due now. study.progress shows what comes next."
            else:
                result["how"] = (
                    "Show the front (and any choices); after the user answers, show the back and "
                    "grade it with study.review action=grade, the item_id and a rating."
                )
            return result
        if action not in ("grade", "skip"):
            return _error("'action' must be next, grade or skip.")
        item_id, err = _id(params.get("item_id"), "item_id")
        if err or item_id is None:
            return _error(err or "item_id is required.")
        if action == "skip":
            if not await self.engine.skip(owner, item_id):
                return _error("That card is not due now (or not found); nothing was skipped.", not_due=True)
            nxt = await self._next_rows(owner, 1, deck_id)
            return {"ok": True, "item_id": str(item_id), "skipped_for_minutes": study_engine.SKIP_MINUTES, "next": nxt["items"][:1], "due_now": nxt["due_now"]}
        rating = srs.rating_name(params.get("rating"))
        if rating is None:
            return _error("'rating' must be again, hard, good or easy.")
        graded = await self.engine.grade(owner, item_id, rating, mode="review", channel="chat")
        if not graded.ok:
            if graded.reason == study_engine.NOT_FOUND:
                return _error("Item not found.", not_found=True)
            return _error("That card is not due now (already graded?); nothing changed.", already_answered=True)
        nxt = await self._next_rows(owner, 1, deck_id)
        return {
            "ok": True,
            "item_id": str(item_id),
            "rating": rating,
            "next_due": _iso(graded.due_at),
            "interval": srs.long_interval(graded.interval),
            "next": nxt["items"][:1],
            "due_now": nxt["due_now"],
            "new_available_today": nxt["new_available_today"],
        }

    # -- quiz ----------------------------------------------------------------

    @staticmethod
    def _question(attempt_id: Any, number: int, item: Any) -> dict[str, Any]:
        row: dict[str, Any] = {"n": number, "item_id": str(item.id), "kind": item.kind, "question": item.front}
        if item.kind == "choice" and item.choices:
            shown, _order = _shown_choices(item, str(attempt_id))
            row["choices"] = [f"{LETTERS[i]}) {c}" for i, c in enumerate(shown)]
        else:
            row["answer_with"] = "reveal, then submit correct true/false"
        return row

    async def _quiz(self, owner: uuid.UUID, params: dict[str, Any]) -> dict[str, Any]:
        action = params.get("action")
        if action == "start":
            return await self._quiz_start(owner, params)
        if action not in ("reveal", "submit", "finish"):
            return _error("'action' must be start, reveal, submit or finish.")
        attempt_id, err = _id(params.get("attempt_id"), "attempt_id")
        if err or attempt_id is None:
            return _error(err or "attempt_id is required.")
        if action == "finish":
            return await self._quiz_finish(owner, attempt_id)
        found = await self.engine.attempt(owner, attempt_id)
        if found is None:
            return _error("Quiz not found. Start one with study.quiz action=start.", not_found=True)
        attempt, items, _deck = found
        if attempt.status != "active":
            return _error(f"This quiz is {attempt.status}. Start a new one.")
        answered = {str(a.get("item_id")) for a in attempt.answers or []}
        if action == "reveal":
            item_id, err = _id(params.get("item_id"), "item_id")
            if err:
                return _error(err)
            item = next((i for i in items if i.id == item_id), None)
            if item is None:
                return _error("That item is not in this quiz.", not_found=True)
            if item.kind == "choice":
                return _error("A choice item is graded when you submit the user's choice; nothing to reveal.")
            if str(item.id) in answered:
                return _error("That question is already answered.")
            result: dict[str, Any] = {"ok": True, "item_id": str(item.id), "answer": item.back}
            if item.explanation:
                result["explanation"] = item.explanation
            result["next"] = "Compare with the user's answer, then submit correct true or false."
            return result
        return await self._quiz_submit(owner, attempt, items, answered, params.get("answers"))

    async def _quiz_start(self, owner: uuid.UUID, params: dict[str, Any]) -> dict[str, Any]:
        offset, err = _int(params.get("offset"), "offset", 0, study_engine.QUIZ_MAX_ITEMS, None)
        if err:
            return _error(err)
        if params.get("attempt_id") is not None:
            # The rest of an existing quiz's questions (no new attempt).
            attempt_id, err = _id(params.get("attempt_id"), "attempt_id")
            if err:
                return _error(err)
            found = await self.engine.attempt(owner, attempt_id)
            if found is None:
                return _error("Quiz not found.", not_found=True)
            attempt, items, deck = found
            return self._questions_page(attempt, items, deck, offset or 0)
        deck_id, err = _id(params.get("deck_id"), "deck_id")
        if err or deck_id is None:
            return _error(err or "deck_id is required.")
        count, err = _int(params.get("count"), "count", 1, study_engine.QUIZ_MAX_ITEMS, QUIZ_DEFAULT_COUNT)
        if err or count is None:
            return _error(err or "Invalid count.")
        tag = None
        if params.get("tag") is not None:
            tags, err = item_rules.clean_tags([params.get("tag")])
            if err or not tags:
                return _error(err or "Invalid tag.")
            tag = tags[0]
        difficulty = params.get("difficulty")
        if difficulty is not None and (not isinstance(difficulty, str) or difficulty.lower() not in item_rules.DIFFICULTIES):
            return _error("'difficulty' must be easy, medium or hard.")
        started = await self.engine.quiz_start(
            owner, deck_id, count=count, channel="chat", tag=tag, difficulty=difficulty.lower() if isinstance(difficulty, str) else None
        )
        if not started.get("ok"):
            if started.get("reason") == study_engine.NOT_FOUND:
                return _deck_not_found()
            return _error("No items in that deck match; nothing to quiz on.")
        logger.info("study_quiz_started", attempt_id=str(started["attempt"].id), items=len(started["items"]))
        return self._questions_page(started["attempt"], started["items"], started["deck"], 0)

    def _questions_page(self, attempt: Any, items: list[Any], deck: Any, offset: int) -> dict[str, Any]:
        rows = [self._question(attempt.id, n, item) for n, item in enumerate(items, start=1)]
        page, next_offset = self._page(rows, offset, len(rows), QUIZ_ROWS_CHARS)
        result: dict[str, Any] = {
            "ok": True,
            "attempt_id": str(attempt.id),
            "deck": deck.title,
            "total": len(rows),
            "questions": page,
            "how": (
                "Ask one question at a time and do not reveal answers. Submit the user's choice "
                "(0-based as shown, or the letter) with study.quiz action=submit; for a question "
                "without choices, reveal it first and submit correct true or false."
            ),
        }
        if next_offset is not None:
            result["next_offset"] = next_offset
            result["more"] = "Call study.quiz action=start with this attempt_id and offset for the rest."
        return result

    async def _quiz_submit(
        self,
        owner: uuid.UUID,
        attempt: Any,
        items: list[Any],
        answered: set[str],
        raw: Any,
    ) -> dict[str, Any]:
        if not isinstance(raw, list) or not 1 <= len(raw) <= study_engine.QUIZ_MAX_ITEMS:
            return _error(f"'answers' must list 1-{study_engine.QUIZ_MAX_ITEMS} answers.")
        by_id = {str(i.id): i for i in items}
        results: list[dict[str, Any]] = []
        shown: list[dict[str, Any]] = []
        seen: set[str] = set()
        for entry in raw:
            if not isinstance(entry, Mapping):
                return _error("Each answer is {item_id, choice} or {item_id, correct}.")
            key = as_uuid(entry.get("item_id"))
            item = by_id.get(str(key)) if key is not None else None
            if item is None:
                return _error("An answer names an item that is not in this quiz.", not_found=True)
            item_key = str(item.id)
            if item_key in answered or item_key in seen:
                shown.append({"item_id": item_key, "already_answered": True})
                continue
            seen.add(item_key)
            if item.kind == "choice" and item.choices:
                shown_choices, order = _shown_choices(item, str(attempt.id))
                picked = _choice_index(entry.get("choice"), len(order))
                if picked is None:
                    return _error("A choice answer needs 'choice': the 0-based index as shown, or the letter.")
                stored = order[picked]
                right = item.answer_index if item.answer_index is not None else -1
                correct = stored == right
                row: dict[str, Any] = {
                    "item_id": item_key,
                    "correct": correct,
                    "picked": f"{LETTERS[picked]}) {shown_choices[picked]}",
                    "right_answer": (
                        f"{_letter_of(order.index(right))}) {item.choices[right]}" if right in order else item.back
                    ),
                }
                notes = list(item.choice_notes or [])
                if not correct and stored < len(notes) and notes[stored]:
                    row["why_wrong"] = notes[stored]
                results.append({"item_id": item_key, "choice": picked, "correct": correct})
            else:
                judged = entry.get("correct")
                if not isinstance(judged, bool):
                    return _error("An answer to a question without choices needs 'correct': true or false.")
                correct = judged
                row = {"item_id": item_key, "correct": correct, "right_answer": item.back}
                results.append({"item_id": item_key, "choice": None, "correct": correct})
            if item.explanation:
                row["explanation"] = item.explanation
            shown.append(row)
        if results and not await self.engine.record_answers(owner, attempt, results):
            return _error("This quiz changed meanwhile (answered elsewhere?); nothing was recorded.")
        # Keep the reply within the budget: past it, only whether each was right.
        used = 0
        trimmed: list[dict[str, Any]] = []
        for row in shown:
            size = _shown_chars(row)
            if trimmed and used + size > QUIZ_ROWS_CHARS:
                row = {k: row[k] for k in ("item_id", "correct", "already_answered") if k in row}
                size = _shown_chars(row)
            trimmed.append(row)
            used += size
        return {
            "ok": True,
            "attempt_id": str(attempt.id),
            "results": trimmed,
            "answered": attempt.answered,
            "correct": attempt.correct,
            "total": attempt.total,
            "note": "A wrong answer makes that card due now for review; a right one leaves its schedule alone.",
        }

    async def _quiz_finish(self, owner: uuid.UUID, attempt_id: uuid.UUID) -> dict[str, Any]:
        found = await self.engine.attempt(owner, attempt_id)
        if found is None:
            return _error("Quiz not found.", not_found=True)
        _attempt, items, deck = found
        attempt = await self.engine.quiz_finish(owner, attempt_id)
        if attempt is None:
            return _error("Quiz not found.", not_found=True)
        return self.quiz_summary(attempt, items, deck.title)

    @staticmethod
    def quiz_summary(attempt: Any, items: list[Any], deck_title: str) -> dict[str, Any]:
        return {"ok": True, **study_engine.quiz_summary(attempt, items, deck_title)}

    # -- progress --------------------------------------------------------------

    async def _progress(self, owner: uuid.UUID, params: dict[str, Any]) -> dict[str, Any]:
        deck_id, err = _id(params.get("deck_id"), "deck_id", required=False)
        if err:
            return _error(err)
        course = params.get("course")
        if course is not None and (not isinstance(course, str) or not course.strip()):
            return _error("'course' must be text, e.g. 'BIO 101'.")
        deck_ids: Optional[list[uuid.UUID]] = None
        decks, stats = await self.engine.list_decks(owner)
        if deck_id is not None:
            if all(d.id != deck_id for d in decks):
                return _deck_not_found()
            deck_ids = [deck_id]
        elif isinstance(course, str):
            wanted = " ".join(course.split()).casefold()
            deck_ids = [d.id for d in decks if d.course and " ".join(d.course.split()).casefold() == wanted]
            if not deck_ids:
                return _error("No deck has that course. study.decks lists each deck's course.", not_found=True)
        report = await self.engine.progress(owner, deck_ids=deck_ids)
        scope = [d for d in decks if deck_ids is None or d.id in deck_ids]
        suggestions: list[str] = []
        busiest = sorted(scope, key=lambda d: -int(stats.get(d.id, {}).get("due_now", 0)))
        for deck in busiest[:2]:
            due = int(stats.get(deck.id, {}).get("due_now", 0))
            if due:
                suggestions.append(f"{due} due now in {_cut(deck.title, 60)}")
        for tag in report["weakest_tags"][:1]:
            suggestions.append(f"{round(100 * tag['accuracy'])}% on tag {tag['name']}: quiz it")
        return {"ok": True, **report, "decks": len(scope), "suggestions": suggestions[:3]}

    # -- settings -------------------------------------------------------------

    async def _linked(self, owner: uuid.UUID) -> bool:
        from models.slack_link import SlackChannelLink
        from models.user import User

        async with self.engine.session() as session:
            chat = (await session.execute(select(User.telegram_chat_id).where(User.id == owner))).scalar_one_or_none()
            if chat is not None:
                return True
            slack = (
                await session.execute(
                    select(SlackChannelLink.connector_id).where(
                        SlackChannelLink.user_id == owner, SlackChannelLink.slack_user_id.is_not(None)
                    )
                )
            ).first()
            return slack is not None

    async def _nudge_info(self, owner: uuid.UUID, task_id: Optional[uuid.UUID]) -> Optional[dict[str, Any]]:
        """The user's reminder as scheduled (on, recurrence, zone,
        channels), or None when there is none."""
        if task_id is None:
            return None
        from models.scheduled_task import ScheduledTask

        async with self.engine.session() as session:
            task = await session.get(ScheduledTask, task_id)
            if task is None or task.user_id != owner:
                return None
            return {
                "on": task.status == "active",
                "recurrence": dict(task.recurrence or {}),
                "timezone": task.timezone,
                "channels": list(task.channels or []),
            }

    async def _settings(self, owner: uuid.UUID, params: dict[str, Any]) -> dict[str, Any]:
        if not params:
            current = await self.engine.settings(owner)
            return {
                "ok": True,
                "new_per_day": current.new_per_day,
                "session_size": current.session_size,
                "reminder": await self._nudge_info(owner, current.nudge_task_id),
            }
        reminder, err = _bool(params.get("reminder"), "reminder")
        if err:
            return _error(err)
        hour, err = _int(params.get("hour"), "hour", 0, 23)
        if err:
            return _error(err)
        new_per_day, err = _int(params.get("new_per_day"), "new_per_day", *NEW_PER_DAY_RANGE)
        if err:
            return _error(err)
        session_size, err = _int(params.get("session_size"), "session_size", *SESSION_SIZE_RANGE)
        if err:
            return _error(err)
        days = params.get("days")
        if days is not None:
            if not isinstance(days, list) or not days or not all(
                isinstance(d, str) and d.strip().lower()[:3] in WEEKDAYS for d in days
            ):
                return _error(f"'days' must list weekdays: {', '.join(WEEKDAYS)}.")
            days = [d for d in WEEKDAYS if d in {x.strip().lower()[:3] for x in days}]
        zone = params.get("timezone")
        if zone is not None:
            from services.scheduler.timezones import parse_zone

            parsed, zone_err = parse_zone(zone)
            if parsed is None:
                return _error(zone_err or "Unknown time zone.")
            zone = str(zone).strip()
        current = await self.engine.settings(owner)
        wants_reminder = reminder is True or (
            reminder is None and (hour is not None or days is not None or zone is not None)
        )
        if wants_reminder and reminder is None and current.nudge_task_id is None:
            return _error("hour, days and timezone set the daily reminder: send reminder=true with them.")
        result: dict[str, Any] = {"ok": True}
        fields: dict[str, Any] = {}
        if new_per_day is not None:
            fields["new_per_day"] = new_per_day
        if session_size is not None:
            fields["session_size"] = session_size
        if wants_reminder:
            if self._nudges is None:
                return _error("Reminders are not available right now; try again shortly.", rule="storage")
            existing = await self._nudge_info(owner, current.nudge_task_id)
            if existing is not None:
                # Keep what this call does not change.
                stored = existing.get("recurrence") or {}
                if hour is None and isinstance(stored.get("time"), str) and stored["time"][:2].isdecimal():
                    hour = int(stored["time"][:2])
                if days is None and stored.get("freq") == "weekly" and isinstance(stored.get("days"), list):
                    days = [d for d in WEEKDAYS if d in stored["days"]]
            recurrence: dict[str, Any] = {"freq": "weekly" if days and len(days) < 7 else "daily"}
            recurrence["time"] = f"{DEFAULT_NUDGE_HOUR if hour is None else hour:02d}:00"
            if recurrence["freq"] == "weekly":
                recurrence["days"] = days
            try:
                task_id = await self._nudges.upsert_nudge(
                    str(owner),
                    renderer=NUDGE_RENDERER,
                    label=NUDGE_LABEL,
                    recurrence=recurrence,
                    timezone=zone,
                    channels=NUDGE_CHANNELS,
                )
            except ValueError as exc:
                if str(exc) == "timezone_required":
                    return _error(TIMEZONE_REQUIRED_ERROR, rule="timezone_required")
                return _error(str(exc)[:300])
            fields["nudge_task_id"] = as_uuid(str(task_id))
            info = await self._nudge_info(owner, fields["nudge_task_id"])
            result["reminder"] = info or {"on": True, "recurrence": recurrence, "timezone": zone}
            if not await self._linked(owner):
                result["warning"] = (
                    "No Telegram chat or Slack DM is linked, so the reminder has nowhere to go yet. "
                    "Link one in Settings (Telegram) or on the Slack connector."
                )
        elif reminder is False:
            if self._nudges is not None:
                await self._nudges.cancel_nudge(str(owner), renderer=NUDGE_RENDERER)
            fields["nudge_task_id"] = None
            result["reminder"] = {"on": False}
        saved = await self.engine.save_settings(owner, **fields)
        result["new_per_day"] = saved.new_per_day
        result["session_size"] = saved.session_size
        return result

    # -- export ----------------------------------------------------------------

    async def _export(self, owner: uuid.UUID, params: dict[str, Any]) -> dict[str, Any]:
        deck_id, err = _id(params.get("deck_id"), "deck_id")
        if err or deck_id is None:
            return _error(err or "deck_id is required.")
        fmt = params.get("format") or "anki"
        if not isinstance(fmt, str) or fmt.strip().lower() not in FORMATS:
            return _error("'format' must be anki or csv.")
        fmt = fmt.strip().lower()
        found = await self.engine.deck_items(owner, deck_id)
        if found is None:
            return _deck_not_found()
        deck, items = found
        if not items:
            return _error("That deck has no items to export.")
        token = self.exports.mint(owner, deck.id, fmt)
        logger.info("study_export_link_minted", deck_id=str(deck.id), format=fmt, items=len(items))
        return {
            "ok": True,
            "url": f"{EXPORT_PATH}?t={token}",
            "filename": safe_filename(deck.title, fmt),
            "format": fmt,
            "items": len(items),
            "expires_in_minutes": self.exports.ttl_minutes,
            "note": (
                "Give the user this link as a Markdown link. It works once, for 10 minutes. "
                "On Telegram the user can send /export <deck number> instead."
            ),
        }
