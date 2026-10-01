"""Validates, cleans and screens flashcards and multiple-choice items before they
are stored, and fingerprints them for de-duplication.

Why it exists: items are written from material the user did not write (a
course PDF, a web page, a Canvas file), and they are later shown on Telegram
and Slack and read back to the model. So every item is held to the same rules
whichever tool saves or edits it:
- sizes fit the columns (models/study.py) and one chat message (3500 chars);
- invisible and tag characters are stripped, a NUL is refused;
- text PromptGuard flags as instructions aimed at an AI is refused;
- keys, card numbers and ID numbers are refused (services.security, policy
  TOOL_ARGS: "A token is a unit of text" is fine, "sk-..." is not);
- a rejection says why in a fixed sentence and never repeats the text.
Items are fingerprinted by kind and normalised front, so saving the same
material twice adds nothing.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from typing import Any, Mapping, Optional

from models.study import (
    COURSE_MAX_CHARS,
    DECK_TITLE_MAX_CHARS,
    DIFFICULTY_MAX_CHARS,
    SOURCE_NOTE_MAX_CHARS,
    SOURCE_REF_MAX_CHARS,
)
from services.agent.prompt_guard import _INVISIBLE_CHARS, PromptGuard
from services.security.policies import TOOL_ARGS
from services.security.redact import contains
from services.study import render

# Toolkit limits. The ones that are column sizes are the model's numbers
# (a test holds them equal); the rest are per item, per call and per user.
TITLE_MAX_CHARS = DECK_TITLE_MAX_CHARS
COURSE_MAX = COURSE_MAX_CHARS
SOURCE_REF_MAX = SOURCE_REF_MAX_CHARS
SOURCE_NOTE_MAX = SOURCE_NOTE_MAX_CHARS
DIFFICULTY_MAX = DIFFICULTY_MAX_CHARS
FRONT_MAX_CHARS = 600
BACK_MAX_CHARS = 1500
CHOICE_MAX_CHARS = 300
MIN_CHOICES = 2
MAX_CHOICES = 6
EXPLANATION_MAX_CHARS = 1200
CHOICE_NOTE_MAX_CHARS = 200
MAX_TAGS = 6
TAG_MAX_CHARS = 40
RENDER_MAX_CHARS = render.RENDER_MAX_CHARS
MAX_ITEMS_PER_CALL = 40
MAX_CALL_CHARS = 60000
MAX_DECKS_PER_USER = 200
MAX_ITEMS_PER_USER = 20000
MAX_ITEMS_PER_DECK = 1000

ITEM_KINDS = ("card", "choice")
DIFFICULTIES = ("easy", "medium", "hard")
SOURCE_KINDS = (
    "notes",
    "chat",
    "file",
    "knowledge_base",
    "canvas",
    "drive",
    "onedrive",
    "notion",
    "web",
    "other",
)
ITEM_FIELDS = frozenset(
    {
        "kind",
        "front",
        "back",
        "choices",
        "answer",
        "explanation",
        "choice_notes",
        "tags",
        "difficulty",
        "source_note",
    }
)

# The fixed reasons a rejected item is reported with (never its text).
REASON_INSTRUCTIONS = "looks like instructions aimed at an AI assistant"
REASON_SECRET = "looks like it holds a key, card number or ID number (items never store those)"
REASON_TOO_LONG_TO_SHOW = f"too long to show in one message (max {RENDER_MAX_CHARS} characters in all)"

# C0 and C1 controls other than tab and newline, and the Unicode line and
# paragraph separators.
_CONTROL = re.compile(r"[\x01-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f  ]")
_BLANK_RUN = re.compile(r"\n{3,}")
_FIELD_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,23}")

_guard = PromptGuard()


@dataclass(frozen=True)
class ItemDraft:
    """A validated, cleaned item, ready to store."""

    kind: str
    front: str
    back: str
    choices: Optional[tuple[str, ...]]
    answer_index: Optional[int]
    explanation: Optional[str]
    choice_notes: Optional[tuple[Optional[str], ...]]
    tags: tuple[str, ...]
    difficulty: Optional[str]
    source_note: Optional[str]

    @property
    def content_hash(self) -> str:
        return content_hash(self.kind, self.front)

    def text_parts(self) -> list[str]:
        parts = [self.front, self.back, *(self.choices or ()), self.explanation or ""]
        parts += [n for n in (self.choice_notes or ()) if n]
        parts += [*self.tags, self.source_note or ""]
        return [p for p in parts if p]


def content_hash(kind: str, front: str) -> str:
    """The de-duplication key: sha256 of the kind and the front, folded to
    lower case with its whitespace collapsed."""
    normal = " ".join(str(front).casefold().split())
    return hashlib.sha256(f"{kind}\x1f{normal}".encode("utf-8")).hexdigest()


def clean_text(
    value: Any, *, name: str, max_chars: int, required: bool = True, multiline: bool = True
) -> tuple[Optional[str], Optional[str]]:
    """``(text, None)`` or ``(None, reason)``. Invisible characters and
    controls are removed, a NUL is refused, line ends are normalised, and
    one-line fields are collapsed to one line. None (or blank) is ``(None,
    None)`` when not *required*."""
    if value is None or (isinstance(value, str) and not value.strip()):
        return (None, f"'{name}' is required") if required else (None, None)
    if not isinstance(value, str):
        return None, f"'{name}' must be text"
    if "\x00" in value:
        return None, f"'{name}' contains a null character"
    text = _INVISIBLE_CHARS.sub("", value).replace("\r\n", "\n").replace("\r", "\n")
    text = _CONTROL.sub("", text)
    if multiline:
        text = "\n".join(line.rstrip() for line in text.split("\n"))
        text = _BLANK_RUN.sub("\n\n", text).strip()
    else:
        text = " ".join(text.split())
    if not text:
        return (None, f"'{name}' is required") if required else (None, None)
    if len(text) > max_chars:
        return None, f"'{name}' is too long ({len(text)} characters; max {max_chars})"
    return text, None


def screen_text(text: str) -> Optional[str]:
    """The reason *text* may not be stored, or None: instructions aimed at
    an AI, or a key, card or ID number."""
    if not text:
        return None
    if contains(text, TOOL_ARGS):
        return REASON_SECRET
    try:
        if not _guard.scan(text).is_safe:
            return REASON_INSTRUCTIONS
    except Exception:  # noqa: BLE001 - a scan that fails refuses (fail closed)
        return REASON_INSTRUCTIONS
    return None


def clean_label(value: Any, *, name: str, max_chars: int, required: bool) -> tuple[Optional[str], Optional[str]]:
    """A one-line label (a deck title, a course, a source): cleaned and
    screened like an item."""
    text, reason = clean_text(value, name=name, max_chars=max_chars, required=required, multiline=False)
    if reason or text is None:
        return None, reason
    refusal = screen_text(text)
    if refusal:
        return None, f"'{name}' {refusal}"
    return text, None


def clean_tags(value: Any) -> tuple[Optional[tuple[str, ...]], Optional[str]]:
    """Tags lower-cased, without a leading '#', whitespace collapsed,
    de-duplicated; at most MAX_TAGS of at most TAG_MAX_CHARS each."""
    if value is None:
        return (), None
    items = [value] if isinstance(value, str) else value
    if not isinstance(items, (list, tuple)) or not all(isinstance(t, str) for t in items):
        return None, "'tags' must be a list of short words"
    tags: list[str] = []
    for raw in items:
        text, reason = clean_text(raw, name="tag", max_chars=TAG_MAX_CHARS * 4, required=False, multiline=False)
        if reason:
            return None, reason
        tag = (text or "").lstrip("#").strip().lower()
        if not tag:
            continue
        if len(tag) > TAG_MAX_CHARS:
            return None, f"a tag is too long (max {TAG_MAX_CHARS} characters)"
        if tag not in tags:
            tags.append(tag)
    if len(tags) > MAX_TAGS:
        return None, f"at most {MAX_TAGS} tags"
    return tuple(tags), None


def _answer_index(value: Any, count: int) -> Optional[int]:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value if 0 <= value < count else None
    if isinstance(value, str):
        text = value.strip()
        if len(text) == 1 and text.upper() in render.LETTERS[:count]:
            return render.LETTERS.index(text.upper())
        if text.isdecimal() and 0 <= int(text) < count:
            return int(text)
    return None


def _unknown_fields(raw: Mapping[str, Any]) -> Optional[str]:
    unknown = [str(k) for k in raw if k not in ITEM_FIELDS]
    if not unknown:
        return None
    shown = [k for k in unknown if _FIELD_NAME.fullmatch(k)][:3]
    names = f" ({', '.join(shown)})" if shown else ""
    return f"unknown field(s){names}; an item takes {', '.join(sorted(ITEM_FIELDS))}"


def raw_chars(items: Any) -> int:
    """The characters of text in a save call's items, counted before any
    cleaning (the per-call cap)."""
    total = 0

    def walk(value: Any, depth: int = 0) -> None:
        nonlocal total
        if depth > 4:
            return
        if isinstance(value, str):
            total += len(value)
        elif isinstance(value, Mapping):
            for v in value.values():
                walk(v, depth + 1)
        elif isinstance(value, (list, tuple)):
            for v in value:
                walk(v, depth + 1)

    walk(items)
    return total


def validate_item(raw: Any) -> tuple[Optional[ItemDraft], Optional[str]]:
    """``(draft, None)`` for an item that may be stored, else ``(None,
    reason)``: every size, shape and screening rule above."""
    if not isinstance(raw, Mapping):
        return None, "an item must be an object with 'front' and 'back' (or 'choices' and 'answer')"
    unknown = _unknown_fields(raw)
    if unknown:
        return None, unknown
    kind = raw.get("kind") or "card"
    if not isinstance(kind, str) or kind.strip().lower() not in ITEM_KINDS:
        return None, "'kind' must be card or choice"
    kind = kind.strip().lower()
    front, reason = clean_text(raw.get("front"), name="front", max_chars=FRONT_MAX_CHARS)
    if reason or front is None:
        return None, reason
    choices: Optional[tuple[str, ...]] = None
    answer_index: Optional[int] = None
    notes: Optional[tuple[Optional[str], ...]] = None
    if kind == "card":
        if raw.get("choices") is not None or raw.get("answer") is not None:
            return None, "a card has no 'choices' or 'answer' (use kind 'choice' for multiple choice)"
        if raw.get("choice_notes") is not None:
            return None, "'choice_notes' belong to a choice item"
        back, reason = clean_text(raw.get("back"), name="back", max_chars=BACK_MAX_CHARS)
        if reason or back is None:
            return None, reason
    else:
        values = raw.get("choices")
        if not isinstance(values, (list, tuple)) or not MIN_CHOICES <= len(values) <= MAX_CHOICES:
            return None, f"a choice item needs {MIN_CHOICES}-{MAX_CHOICES} 'choices'"
        cleaned: list[str] = []
        for value in values:
            text, reason = clean_text(value, name="choice", max_chars=CHOICE_MAX_CHARS, multiline=False)
            if reason or text is None:
                return None, reason
            cleaned.append(text)
        if len({c.casefold() for c in cleaned}) != len(cleaned):
            return None, "two choices are the same"
        choices = tuple(cleaned)
        answer_index = _answer_index(raw.get("answer"), len(choices))
        if answer_index is None:
            return None, f"'answer' must be the 0-based index of the right choice (0-{len(choices) - 1})"
        back_value = raw.get("back")
        if back_value is None or (isinstance(back_value, str) and not back_value.strip()):
            back = choices[answer_index]
        else:
            back, reason = clean_text(back_value, name="back", max_chars=BACK_MAX_CHARS)
            if reason or back is None:
                return None, reason
        raw_notes = raw.get("choice_notes")
        if raw_notes is not None:
            if not isinstance(raw_notes, (list, tuple)) or len(raw_notes) != len(choices):
                return None, "'choice_notes' must have one entry per choice (null for the right one)"
            note_list: list[Optional[str]] = []
            for note in raw_notes:
                text, reason = clean_text(
                    note, name="choice note", max_chars=CHOICE_NOTE_MAX_CHARS, required=False
                )
                if reason:
                    return None, reason
                note_list.append(text)
            notes = tuple(note_list)
    explanation, reason = clean_text(
        raw.get("explanation"), name="explanation", max_chars=EXPLANATION_MAX_CHARS, required=False
    )
    if reason:
        return None, reason
    tags, reason = clean_tags(raw.get("tags"))
    if reason or tags is None:
        return None, reason
    difficulty = raw.get("difficulty")
    if difficulty is not None:
        if not isinstance(difficulty, str) or difficulty.strip().lower() not in DIFFICULTIES:
            return None, "'difficulty' must be easy, medium or hard"
        difficulty = difficulty.strip().lower()
    source_note, reason = clean_text(
        raw.get("source_note"), name="source_note", max_chars=SOURCE_NOTE_MAX, required=False, multiline=False
    )
    if reason:
        return None, reason
    draft = ItemDraft(
        kind=kind,
        front=front,
        back=back,
        choices=choices,
        answer_index=answer_index,
        explanation=explanation,
        choice_notes=notes,
        tags=tags,
        difficulty=difficulty,
        source_note=source_note,
    )
    refusal = screen_text("\n".join(draft.text_parts()))
    if refusal:
        return None, refusal
    shown = render.full_text(
        draft.front, draft.back, draft.choices, draft.answer_index, draft.explanation,
        draft.choice_notes, draft.source_note,
    )
    if len(shown) > RENDER_MAX_CHARS:
        return None, REASON_TOO_LONG_TO_SHOW
    return draft, None


def draft_of(item: Any) -> dict[str, Any]:
    """A stored item as the raw fields validate_item takes (for edits)."""
    raw: dict[str, Any] = {"kind": item.kind, "front": item.front}
    if item.kind == "choice":
        raw["choices"] = list(item.choices or [])
        raw["answer"] = item.answer_index
        raw["back"] = item.back
        if item.choice_notes is not None:
            raw["choice_notes"] = list(item.choice_notes)
    else:
        raw["back"] = item.back
    for name in ("explanation", "difficulty", "source_note"):
        if getattr(item, name) is not None:
            raw[name] = getattr(item, name)
    raw["tags"] = list(item.tags or [])
    return raw
