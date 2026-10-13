"""The owner's tutor locks as values: matching one against what a chat says
(the course code, name or an alias) and does (a Canvas ``course_id``, a
``/courses/<id>/`` URL), validating a new one, and sanitising its label.

Why it exists: a lock must engage deterministically and only for the course
it names. "MATH 221", "math-221" and "MATH221" are the same course, while
"MATH2210" and "aftermath" are not, and a lock on a generic word ("math",
"homework") would lock every chat that used it, so those are refused when
the owner creates the lock. Only the student's own message and the model's
tool arguments engage a lock; tool results never do, so fetched content
cannot lock (or unlock) anything.

Connects to: services/tutor/policy.py (canonical tool names and the URL
rule), services/agent/prompt_guard.py and services/tools/memory.py (the
screens every lock term passes, imported at call time), and
services/tutor/service.py, which turns ``TutorLock`` rows into these values.
"""

from __future__ import annotations

import functools
import re
import unicodedata
from dataclasses import dataclass, field
from typing import Any, Callable, Iterable, Mapping, Optional, Sequence

from services.tutor.policy import canonical_name, course_id_in_url, is_url_tool

SCOPE_COURSE = "course"
SCOPE_ACCOUNT = "account"
SCOPES: tuple[str, ...] = (SCOPE_COURSE, SCOPE_ACCOUNT)

# How a course lock engaged in a conversation (TutorState.lock.matched_by).
MATCHED_BY_TEXT = "text"
MATCHED_BY_TOOL_ARGS = "tool_args"
MATCHED_BY_URL = "url"
MATCHED_BY: frozenset[str] = frozenset({MATCHED_BY_TEXT, MATCHED_BY_TOOL_ARGS, MATCHED_BY_URL})

MAX_LOCKS = 100
MAX_ALIASES = 5
ALIAS_MIN_CHARS = 3
ALIAS_MAX_CHARS = 60
CODE_MAX_CHARS = 40
NAME_MAX_CHARS = 120
COURSE_ID_MAX_DIGITS = 20
LABEL_MAX_CHARS = 40
# A term with no digit must be at least this long: "calc" or "art" would
# match far too many chats that are not about the course.
SHORT_TERM_CHARS = 5
# Words that name no course in particular.
GENERIC_TERMS: frozenset[str] = frozenset(
    {"math", "english", "class", "course", "homework", "lab"}
)
# Only the start of a very long message is searched for a course.
TEXT_SCAN_CHARS = 20_000

# Label characters shown in notices and replies (which later enter the
# chat's history): letters, digits and a little punctuation, nothing that
# could open a tag or start a new line.
_LABEL_DISALLOWED = re.compile(r"[^A-Za-z0-9 .&:()'/_-]")
_WHITESPACE = re.compile(r"\s+")
_CONTROL = re.compile(r"[\x00-\x1f\x7f-\x9f​-‏ -‮⁠-⁤﻿]")
_COURSE_ID = re.compile(r"\d{1,%d}" % COURSE_ID_MAX_DIGITS)
# Runs of letters, or of digits: "MATH-221" and "math 221" both give
# ("math", "221").
_TOKEN = re.compile(r"[^\W\d_]+|\d+")


class LockValidationError(ValueError):
    """A lock the owner asked for that cannot be saved; the message says why
    in words the Settings page shows as is (it never repeats a term)."""


def sanitize_label(value: Any) -> str:
    """*value* as a lock label: whitespace collapsed, only
    ``[A-Za-z0-9 .&:()'/_-]`` kept, at most 40 characters."""
    text = value if isinstance(value, str) else ""
    text = _WHITESPACE.sub(" ", text)
    text = _LABEL_DISALLOWED.sub("", text)
    text = re.sub(r" {2,}", " ", text).strip()
    return text[:LABEL_MAX_CHARS].strip()


def _fold(text: str) -> str:
    return unicodedata.normalize("NFKC", text).casefold()


def term_tokens(term: str) -> tuple[str, ...]:
    """The letter and digit runs of *term*, case-folded."""
    return tuple(_TOKEN.findall(_fold(term)))


@functools.lru_cache(maxsize=1024)
def _pattern_for(tokens: tuple[str, ...]) -> re.Pattern[str]:
    """A search for *tokens* in folded text: up to three separators between
    runs ("math - 221"), and no letter or digit on either side, so "math221"
    matches "MATH 221" while "math2210" and "aftermath 221" do not."""
    body = r"[\W_]{0,3}".join(re.escape(token) for token in tokens)
    return re.compile(r"(?<![^\W_])" + body + r"(?![^\W_])")


def _clean_text(value: Any, limit: int) -> Optional[str]:
    """A typed field as stored: control characters gone, whitespace
    collapsed and trimmed; None when empty. Raises for a non-string."""
    if value is None:
        return None
    if not isinstance(value, str):
        raise LockValidationError("Course fields must be text.")
    text = _CONTROL.sub("", value)
    text = _WHITESPACE.sub(" ", text).strip()
    if not text:
        return None
    if len(text) > limit:
        raise LockValidationError(f"{{field}} can be at most {limit} characters.")
    return text


def _course_id(value: Any) -> Optional[str]:
    """A Canvas course id as digits, from a tool argument or a typed field;
    None when it is not one."""
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        value = str(value)
    if not isinstance(value, str):
        return None
    text = value.strip()
    return text if _COURSE_ID.fullmatch(text) else None


@dataclass(frozen=True)
class CourseLock:
    """One lock that applies to the user a turn runs for.

    ``user_id`` None means it applies to every account. A course lock
    (``scope == "course"``) names its course by Canvas id, code, name
    and/or aliases; an account lock (``scope == "account"``) names none.
    """

    lock_id: str
    scope: str
    label: str
    user_id: Optional[str] = None
    canvas_course_id: Optional[str] = None
    course_code: Optional[str] = None
    course_name: Optional[str] = None
    aliases: tuple[str, ...] = field(default_factory=tuple)

    @classmethod
    def from_row(cls, row: Any) -> "CourseLock":
        """A ``TutorLock`` row (or anything with its attributes) as a value.
        Malformed aliases are dropped rather than trusted."""
        raw_aliases = getattr(row, "aliases", None)
        aliases = tuple(
            a for a in (raw_aliases if isinstance(raw_aliases, list) else []) if isinstance(a, str) and a.strip()
        )
        user_id = getattr(row, "user_id", None)
        return cls(
            lock_id=str(row.id),
            scope=str(getattr(row, "scope", "") or ""),
            label=sanitize_label(getattr(row, "label", "")),
            user_id=str(user_id) if user_id is not None else None,
            canvas_course_id=_course_id(getattr(row, "canvas_course_id", None)),
            course_code=getattr(row, "course_code", None) or None,
            course_name=getattr(row, "course_name", None) or None,
            aliases=aliases,
        )

    @property
    def is_course(self) -> bool:
        return self.scope == SCOPE_COURSE

    @property
    def is_account(self) -> bool:
        return self.scope == SCOPE_ACCOUNT

    def applies_to(self, user_id: str) -> bool:
        return self.user_id is None or self.user_id == str(user_id)

    @property
    def terms(self) -> tuple[str, ...]:
        """The words a message can name the course by."""
        return tuple(t for t in (self.course_code, self.course_name, *self.aliases) if t)

    def matches_text(self, folded: str) -> bool:
        """Whether *folded* (case-folded message text) names this course."""
        if not self.is_course:
            return False
        for term in self.terms:
            tokens = term_tokens(term)
            if tokens and _pattern_for(tokens).search(folded):
                return True
        return False

    def matches_course_id(self, value: Any) -> bool:
        course_id = _course_id(value)
        return self.is_course and course_id is not None and course_id == self.canvas_course_id


def match_text(locks: Iterable[CourseLock], text: Any) -> Optional[CourseLock]:
    """The first course lock whose course *text* names, or None."""
    if not isinstance(text, str) or not text.strip():
        return None
    folded = _fold(text[:TEXT_SCAN_CHARS])
    for lock in locks:
        if lock.matches_text(folded):
            return lock
    return None


def match_call(
    locks: Iterable[CourseLock], tool_name: Any, arguments: Any
) -> Optional[tuple[CourseLock, str]]:
    """The course lock a tool call's own arguments touch, with how: a
    Canvas call's ``course_id`` (``tool_args``), or ``/courses/<id>/`` in the
    ``url`` of a page-opening call (``url``). Never a result."""
    if not isinstance(arguments, Mapping):
        return None
    course_locks = [lock for lock in locks if lock.is_course and lock.canvas_course_id]
    if not course_locks:
        return None
    canonical = canonical_name(tool_name)
    if canonical.startswith("canvas.") and "course_id" in arguments:
        for lock in course_locks:
            if lock.matches_course_id(arguments.get("course_id")):
                return lock, MATCHED_BY_TOOL_ARGS
    if is_url_tool(canonical):
        course_id = course_id_in_url(arguments.get("url"))
        if course_id is not None:
            for lock in course_locks:
                if lock.matches_course_id(course_id):
                    return lock, MATCHED_BY_URL
    return None


# ---------------------------------------------------------------------------
# Create-time validation
# ---------------------------------------------------------------------------


def screen_term(term: str) -> bool:
    """True when *term* is safe to keep as a lock term: no secret-shaped
    value (an owner pasting a token by mistake) and nothing the prompt
    guard reads as instructions. A screen that fails refuses the term."""
    from services.agent.prompt_guard import PromptGuard
    from services.tools.memory import looks_like_secret

    try:
        if looks_like_secret(term):
            return False
        return bool(PromptGuard().scan(term).is_safe)
    except Exception:
        return False


@dataclass(frozen=True)
class LockDraft:
    """A validated lock, ready to be stored as a ``TutorLock`` row."""

    scope: str
    user_id: Optional[str]
    canvas_course_id: Optional[str]
    course_code: Optional[str]
    course_name: Optional[str]
    aliases: tuple[str, ...]
    label: str


def _field(value: Any, limit: int, name: str) -> Optional[str]:
    try:
        return _clean_text(value, limit)
    except LockValidationError as exc:
        raise LockValidationError(str(exc).replace("{field}", name)) from None


def _check_term(term: str, what: str, screen: Callable[[str], bool]) -> None:
    tokens = term_tokens(term)
    if not tokens:
        raise LockValidationError(f"{what} needs letters or digits.")
    if " ".join(tokens) in GENERIC_TERMS:
        raise LockValidationError(
            f"{what} is too general: it would lock chats that only mention it. "
            "Use the course code (like MATH 221) or its full name."
        )
    if len(term) < SHORT_TERM_CHARS and not any(token.isdigit() for token in tokens):
        raise LockValidationError(
            f"{what} is too short to match safely. Use at least {SHORT_TERM_CHARS} "
            "characters, a course number, or the Canvas course id."
        )
    if not screen(term):
        raise LockValidationError(
            f"{what} looks like instructions or a secret, so it can't be used."
        )


def _same_course(a: CourseLock, b: LockDraft) -> bool:
    def norm(value: Optional[str]) -> str:
        return " ".join(term_tokens(value)) if value else ""

    return (
        (a.canvas_course_id or "") == (b.canvas_course_id or "")
        and norm(a.course_code) == norm(b.course_code)
        and norm(a.course_name) == norm(b.course_name)
    )


def course_label(
    course_code: Optional[str], course_name: Optional[str], canvas_course_id: Optional[str]
) -> str:
    """A course lock's label: the code, else the name, else "course <id>",
    each sanitised (``sanitize_label``)."""
    for candidate in (course_code, course_name):
        label = sanitize_label(candidate)
        if label:
            return label
    if canvas_course_id:
        return sanitize_label(f"course {canvas_course_id}")
    return "a course"


def account_label(user_id: Optional[str]) -> str:
    return "every account" if user_id is None else "this account"


def validate_lock(
    *,
    scope: Any,
    user_id: Optional[str],
    canvas_course_id: Any = None,
    course_code: Any = None,
    course_name: Any = None,
    aliases: Any = None,
    existing: Sequence[CourseLock] = (),
    screen: Callable[[str], bool] = screen_term,
) -> LockDraft:
    """Check one lock the owner asked for against every rule, and return it
    as stored. Raises ``LockValidationError`` with the reason.

    ``user_id`` is the account it applies to (None: every account) and
    ``existing`` every lock on the install (the cap and duplicates)."""
    if scope not in SCOPES:
        raise LockValidationError("Choose a course lock or a whole-account lock.")
    if len(existing) >= MAX_LOCKS:
        raise LockValidationError(
            f"This install already has {MAX_LOCKS} tutor locks, the most it can hold. "
            "Remove one first."
        )
    course_id_text = _field(canvas_course_id, COURSE_ID_MAX_DIGITS, "The Canvas course id")
    code = _field(course_code, CODE_MAX_CHARS, "The course code")
    name = _field(course_name, NAME_MAX_CHARS, "The course name")
    if aliases is None:
        alias_values: list[Any] = []
    elif isinstance(aliases, (list, tuple)):
        alias_values = list(aliases)
    else:
        raise LockValidationError("Aliases must be a list of names.")

    if scope == SCOPE_ACCOUNT:
        if course_id_text or code or name or any(
            isinstance(a, str) and a.strip() for a in alias_values
        ):
            raise LockValidationError("A whole-account lock takes no course.")
        draft = LockDraft(SCOPE_ACCOUNT, user_id, None, None, None, (), account_label(user_id))
        if any(lock.is_account and lock.user_id == user_id for lock in existing):
            raise LockValidationError("That lock already exists.")
        return draft

    course_id: Optional[str] = None
    if course_id_text is not None:
        course_id = _course_id(course_id_text)
        if course_id is None:
            raise LockValidationError(
                "The Canvas course id is the number in the course's address (…/courses/12345)."
            )
    if not (course_id or code or name):
        raise LockValidationError(
            "A course lock needs the Canvas course id, the course code or the course name."
        )
    if len(alias_values) > MAX_ALIASES:
        raise LockValidationError(f"A lock can have at most {MAX_ALIASES} aliases.")
    cleaned_aliases: list[str] = []
    seen: set[str] = set()
    for value in alias_values:
        alias = _field(value, ALIAS_MAX_CHARS, "An alias")
        if alias is None:
            continue
        if len(alias) < ALIAS_MIN_CHARS:
            raise LockValidationError(f"An alias needs at least {ALIAS_MIN_CHARS} characters.")
        key = " ".join(term_tokens(alias))
        if key in seen:
            continue
        seen.add(key)
        cleaned_aliases.append(alias)

    if code is not None:
        _check_term(code, "The course code", screen)
    if name is not None:
        _check_term(name, "The course name", screen)
    for alias in cleaned_aliases:
        _check_term(alias, "An alias", screen)

    draft = LockDraft(
        scope=SCOPE_COURSE,
        user_id=user_id,
        canvas_course_id=course_id,
        course_code=code,
        course_name=name,
        aliases=tuple(cleaned_aliases),
        label=course_label(code, name, course_id),
    )
    if any(
        lock.is_course and lock.user_id == user_id and _same_course(lock, draft)
        for lock in existing
    ):
        raise LockValidationError("That lock already exists.")
    return draft
