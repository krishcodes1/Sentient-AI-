"""The grammar of an owner's tool rule and its validation: a name, a lower-case glob over canonical
tool names, and up to five argument conditions (equals, not_equals, contains, a bounded regular
expression, in_list, domain_in, domain_not_in, number_gt, number_lt). Also the plain-English
summary of a rule, the audit digest, and which catalog tools a glob covers.

Why it exists: a rule is owner policy that every turn evaluates, so what can be saved is decided
here once, with a reason the Security page shows exactly as sent (RuleValidationError). The limits
keep evaluation cheap and safe: at most 50 rules of 5 conditions, values of at most 200
characters, lists of at most 50 items, and regular expressions that are short, have no
back-references or look-arounds, never repeat a group that holds a repeat or an alternation,
use at most one open-ended repeat, repeat nothing more than 50 times, whose backtracking choices
stay within a budget (MAX_BACKTRACK_CHOICES, MAX_BOUNDED_CHOICES: the first five checks alone
admitted "a?" twenty times, which took about a minute on 4,000 characters), and whose
estimated worst-case search steps stay within MAX_SEARCH_STEPS (choices alone admitted
".*a{50}b", about a second, and ".*(?:a{50}){50}b", about twenty). A rule name can never hold
"@" or a link, and nothing that looks like a key, password, card, bank or ID number can be
saved (the secret guard's own detector).

Connects to: engine.py (the rule types), values.py (domains, numbers, normalised text), texts.py
(every reason and phrase), services.security.redact.argument_findings with the TOOL_ARGS policy,
and services.agent.tool_registry (the catalog; imported lazily, it imports every connector).
Used by: store.py (rows read back), the routes (create, preview, catalog) and the engine (each
stored pattern is compiled through compile_regex, so a pattern that fails today's checks asks).
"""

from __future__ import annotations

import functools
import hashlib
import importlib
import json
import math
import re
from dataclasses import dataclass
from datetime import datetime
from fnmatch import fnmatchcase
from typing import Any, Iterator, Mapping, Optional, Sequence

from services.security.policies import TOOL_ARGS
from services.security.redact import argument_findings
from services.security.tool_rules import texts, values
from services.security.tool_rules.builtins import BUILTINS
from services.security.tool_rules.engine import (
    REGEX_TEXT_CAP,
    Condition,
    Op,
    OwnerRule,
    is_runtime_tool,
)

MAX_RULES = 50
MAX_CONDITIONS = 5
MAX_LIST_ITEMS = 50
MAX_VALUE_CHARS = 200
MAX_REGEX_CHARS = 100
MAX_BOUNDED_REPEAT = 50
MAX_TOOL_CHARS = 120
MAX_NAME_CHARS = 60
MIN_NAME_CHARS = 3
# REGEX_TEXT_CAP lives in engine.py (it applies it); re-exported here with the other limits.
# A pattern's backtracking choices multiply: an open-ended repeat counts as REGEX_TEXT_CAP
# choices, a bounded one as (max - min + 1), an optional group as one more than what it holds,
# and alternatives add up. With an open-ended repeat the product may not exceed REGEX_TEXT_CAP
# (so nothing else in the pattern may add a choice); without one it may not exceed
# MAX_BOUNDED_CHOICES.
MAX_BACKTRACK_CHOICES = REGEX_TEXT_CAP
MAX_BOUNDED_CHOICES = 1000
# Choices alone miss the work each one repeats: ".*a{50}b" has one choice per position, but at
# each it matches fifty characters before failing (about a second on 4,000 "a"s). So the
# worst-case steps of one search over a REGEX_TEXT_CAP-character value are estimated too (every
# start, every way, every character a fixed repeat or literal matches; see _search_steps) and
# may not exceed five times REGEX_TEXT_CAP squared. "a.*c" is about one n squared; the slowest
# accepted shapes (seven "\w{50}" after a "\w{0,50}", with or without capturing groups) took
# 0.1-0.3 s of CPU on 4,000 hostile characters on an idle dev machine and up to about 0.6 s while
# it was busy with other work. A search cannot be interrupted once started (it holds the
# interpreter, and with it the event loop), so this bound, not the engine's time budget, is
# what limits one search.
MAX_SEARCH_STEPS = 5 * REGEX_TEXT_CAP * REGEX_TEXT_CAP
# The matcher runs a repeat of one character (".*", "\w{0,50}", "(?:x)+") in a tight loop, but a
# repeat of anything longer ("(?:ab)+", "(?:\w\w){12}") through its general repeat machinery,
# which costs several times as much per character: "(?:\w\w){0,25}(?:\w\w){0,25}(?:\w\w){12}!"
# took 0.7 s at 0.9 of MAX_SEARCH_STEPS when every step was costed alike. So each step inside
# such a repeat counts this many times. Capturing groups cost even more per character (and
# turn a one-character repeat into the general one), so a pattern is compiled with every group
# made non-capturing (back-references are refused, so nothing ever reads a capture).
GENERAL_REPEAT_WEIGHT = 4.0

OPS: tuple[Op, ...] = (
    "equals",
    "not_equals",
    "contains",
    "regex",
    "in_list",
    "domain_in",
    "domain_not_in",
    "number_gt",
    "number_lt",
)
OP_LABELS: Mapping[Op, str] = {
    "equals": "is",
    "not_equals": "is not",
    "contains": "contains",
    "regex": "matches pattern",
    "in_list": "is one of",
    "domain_in": "has an address or link at",
    "domain_not_in": "has an address or link outside",
    "number_gt": "is more than",
    "number_lt": "is less than",
}
# What the page's value input is for each operator: "text" | "list" | "number" | "pattern".
OP_VALUE_KINDS: Mapping[Op, str] = {
    "equals": "text",
    "not_equals": "text",
    "contains": "text",
    "regex": "pattern",
    "in_list": "list",
    "domain_in": "list",
    "domain_not_in": "list",
    "number_gt": "number",
    "number_lt": "number",
}
LIMITS: Mapping[str, int] = {
    "max_rules": MAX_RULES,
    "max_conditions": MAX_CONDITIONS,
    "max_list_items": MAX_LIST_ITEMS,
    "max_value_chars": MAX_VALUE_CHARS,
    "max_regex_chars": MAX_REGEX_CHARS,
    "regex_text_cap": REGEX_TEXT_CAP,
}

_NAME_CHARS = re.compile(r"[A-Za-z0-9 .,&:()'/_-]+")
# A name may not read as a link or a host name: it is shown on Telegram and Slack (which turn
# hosts into links) and written to audit rows.
_NAME_LINKISH = re.compile(r"://|\bwww\.|[A-Za-z0-9-]\.[A-Za-z]{2,}\b")
_TOOL_CHARS = re.compile(r"[a-z0-9_.*?-]+")
_ARG = re.compile(r"\*|[A-Za-z0-9_]{1,40}(?:\.[A-Za-z0-9_]{1,40}){0,3}")
_OP_ECHO = re.compile(r"[a-z_]{1,20}")
_MCP_PREFIX = "mcp."


class RuleValidationError(ValueError):
    """A rule the owner may not save; str(exc) is the plain reason the page shows as is."""


@dataclass(frozen=True)
class RuleDraft:
    """A validated, normalised rule ready to store."""

    name: str
    tool: str
    conditions: tuple[Condition, ...]


# ---------------------------------------------------------------------------
# Regular expressions
# ---------------------------------------------------------------------------


def _sre_modules() -> tuple[Any, Any]:
    """The interpreter's private regex parser and its constants (re._parser, re._constants on
    3.11+). Imported by name so a Python without them refuses patterns instead of failing."""
    try:
        parser = importlib.import_module("re._parser")
        constants = importlib.import_module("re._constants")
    except ImportError as exc:
        raise RuleValidationError(texts.PATTERNS_UNAVAILABLE) from exc
    return parser, constants


# One character each. (CATEGORY, RANGE, NEGATE and CHARSET normally sit inside IN.)
_CHAR_OPS = frozenset(
    {"LITERAL", "NOT_LITERAL", "ANY", "IN", "CATEGORY", "RANGE", "NEGATE", "CHARSET"}
)
_REFUSED_OPS = frozenset(
    {
        "GROUPREF",
        "GROUPREF_EXISTS",
        "GROUPREF_IGNORE",
        "GROUPREF_UNI_IGNORE",
        "GROUPREF_LOC_IGNORE",
        "ASSERT",
        "ASSERT_NOT",
    }
)
_REPEAT_OPS = frozenset({"MAX_REPEAT", "MIN_REPEAT", "POSSESSIVE_REPEAT"})


class _Shape:
    def __init__(self, maxrepeat: Any) -> None:
        self.maxrepeat = maxrepeat
        self.open_repeats = 0


@dataclass(frozen=True)
class _Unit:
    """One step of a pattern flattened for costing.

    ``"char"`` matches one character (``key`` is the literal, None for a class or ``.``);
    ``"at"`` is a zero-width check (``^``, ``$``, ``\\b``); ``"choice"`` is a bounded variable
    repeat, an optional group or an alternation, with the number of ways it can match and the
    steps it takes to try them all once; ``"open"`` is the one open-ended repeat, with the steps
    it spends per character it consumes."""

    kind: str
    key: Optional[str] = None
    ways: int = 1
    steps: float = 1.0


_CHAR_UNIT = _Unit("char")
_AT_UNIT = _Unit("at")


def _general(body: list[_Unit]) -> list[_Unit]:
    """*body* as the matcher's general repeat runs it: unless it is one character (a tight
    loop), every unit's steps count GENERAL_REPEAT_WEIGHT times."""
    if len(body) == 1 and body[0].kind == "char":
        return body
    return [
        _Unit(unit.kind, key=unit.key, ways=unit.ways, steps=unit.steps * GENERAL_REPEAT_WEIGHT)
        for unit in body
    ]


def _units(items: Any, shape: _Shape, *, repeating: bool) -> list[_Unit]:
    """A parsed sequence flattened into units (groups opened, fixed repeats written out),
    refusing what the safety check does not allow. *repeating* is True inside a group that
    repeats more than once, where no repeat and no alternation may appear (S9 §4.3: "a repeat
    inside a repeat")."""
    out: list[_Unit] = []
    for op, av in items:
        name = str(op)
        if name == "LITERAL":
            out.append(_Unit("char", key=chr(av)))
        elif name in _CHAR_OPS:
            out.append(_CHAR_UNIT)
        elif name == "AT":
            out.append(_AT_UNIT)
        elif name in _REFUSED_OPS:
            raise RuleValidationError(texts.PATTERN_LOOKAROUND)
        elif name == "SUBPATTERN":
            out.extend(_units(av[-1], shape, repeating=repeating))
        elif name == "ATOMIC_GROUP":
            out.extend(_units(av, shape, repeating=repeating))
        elif name == "BRANCH":
            if repeating:
                raise RuleValidationError(texts.PATTERN_NESTED)
            ways, steps = 0, 0.0
            for branch in av[1]:
                branch_ways, branch_steps = _sequence_cost(_units(branch, shape, repeating=False))
                ways += branch_ways
                steps += branch_steps
            out.append(_Unit("choice", ways=ways, steps=steps))
        elif name in _REPEAT_OPS:
            low, high, inner = av
            if low == high and high <= 1:
                # {1} and {0} are no repeat at all: the group as written (or nothing).
                body = _general(_units(inner, shape, repeating=repeating))
                out.extend(body * high)
                continue
            if repeating:
                raise RuleValidationError(texts.PATTERN_NESTED)
            open_ended = high == shape.maxrepeat
            if open_ended:
                shape.open_repeats += 1
                if shape.open_repeats > 1:
                    raise RuleValidationError(texts.PATTERN_OPEN_REPEATS)
            elif high > MAX_BOUNDED_REPEAT:
                raise RuleValidationError(texts.PATTERN_BIG_REPEAT)
            body = _general(_units(inner, shape, repeating=open_ended or high > 1))
            body_steps_once = sum(unit.steps for unit in body)
            if open_ended:
                # The body is plain characters and checks (nothing inside may repeat or branch):
                # consuming the text costs its steps per character.
                chars = sum(1 for unit in body if unit.kind == "char")
                out.append(
                    _Unit(
                        "open",
                        ways=REGEX_TEXT_CAP,
                        steps=max(1.0, body_steps_once) / max(1, chars),
                    )
                )
            elif high <= 1:
                # optional: taken (in each of its own ways) or skipped
                body_ways, body_steps = _sequence_cost(body)
                out.append(_Unit("choice", ways=body_ways + 1, steps=body_steps))
            elif low == high:
                out.extend(body * high)  # a fixed repeat costs every character it matches
            else:
                out.append(_Unit("choice", ways=high - low + 1, steps=high * body_steps_once))
        else:
            raise RuleValidationError(texts.PATTERN_UNSUPPORTED)
    return out


def _compatible(first: Optional[str], second: Optional[str]) -> bool:
    """Whether one text character could match both units (case-insensitively). A class, and
    anything outside ASCII (Unicode case folding has its own equivalences), counts as matching
    anything."""
    if first is None or second is None or not (first.isascii() and second.isascii()):
        return True
    return first.lower() == second.lower()


def _tail_cost(tail: Sequence[_Unit]) -> float:
    """Steps per text position, amortised over the whole text, of trying the plain *tail* that
    follows the open-ended repeat at every position it backtracks to.

    A try at one position costs one step, plus one for each character of the tail that matched
    before the first mismatch, plus its zero-width checks. Two places where the first k
    characters of the tail both match must be at least d_k apart, where d_k is the smallest
    shift of those k characters onto themselves that one text could satisfy (k when there is
    none), so at most n/d_k + 1 places get past character k. Hence the steps per position are at
    most 1 + #checks + the sum of 1/d_k: about 3.5 for a word like "invoice", but 51 for
    "a{50}b" or "\\w{50}", whose every place can match 50 characters before failing. Stops
    adding once the total is past what any accepted pattern could use. A unit inside a general
    repeat (_general) counts its own weight wherever this counts one step."""
    chars = [unit for unit in tail if unit.kind == "char"]
    keys = [unit.key for unit in chars]
    cost = (chars[0].steps if chars else 1.0) + sum(
        unit.steps for unit in tail if unit.kind != "char"
    )
    ceiling = MAX_SEARCH_STEPS / (REGEX_TEXT_CAP * REGEX_TEXT_CAP) + 1
    shift = 1
    for k in range(1, len(keys)):  # the first k characters match; the (k+1)th is tried
        while shift < k and not all(
            _compatible(keys[i], keys[i + shift]) for i in range(k - shift)
        ):
            shift += 1
        cost += chars[k].steps / shift + 1.0 / REGEX_TEXT_CAP
        if cost > ceiling:
            break
    return cost


def _sequence_cost(units: Sequence[_Unit]) -> tuple[int, float]:
    """(the ways *units* can match from one start, the steps to try every way from one start).

    Every way of what comes before a unit tries that unit afresh, so a unit's steps count once
    per way of everything before it. An open-ended repeat consumes up to REGEX_TEXT_CAP
    characters and backtracks to each of them; the plain tail after it is costed per position
    (_tail_cost). Refuses once the ways pass MAX_BACKTRACK_CHOICES."""
    ways = 1
    steps = 0.0
    for index, unit in enumerate(units):
        if unit.kind == "open":
            tail = units[index + 1 :]
            if all(u.kind in ("char", "at") for u in tail):
                steps += ways * REGEX_TEXT_CAP * (unit.steps + _tail_cost(tail))
                ways *= unit.ways
                if ways > MAX_BACKTRACK_CHOICES:
                    raise RuleValidationError(texts.PATTERN_TOO_SLOW)
                return ways, steps
            steps += ways * REGEX_TEXT_CAP * unit.steps
        else:
            steps += ways * unit.steps
        ways *= unit.ways
        if ways > MAX_BACKTRACK_CHOICES:
            raise RuleValidationError(texts.PATTERN_TOO_SLOW)
    return ways, steps


def _search_steps(units: Sequence[_Unit]) -> float:
    """The worst-case steps of one search over a REGEX_TEXT_CAP-character value: every start
    position tries the pattern. With the open-ended repeat at the top level and only plain
    characters after it, the starts share the text: consuming costs about n²/2 in all, and the
    tail's tries about n² times its per-position cost less a half."""
    n = float(REGEX_TEXT_CAP)
    for index, unit in enumerate(units):
        if unit.kind != "open":
            continue
        tail = units[index + 1 :]
        if not all(u.kind in ("char", "at") for u in tail):
            break
        prefix_ways, prefix_steps = _sequence_cost(units[:index])
        if prefix_ways != 1:
            break
        return n * (prefix_steps + 1) + n * n * (unit.steps / 2 + _tail_cost(tail) - 0.5)
    return n * _sequence_cost(units)[1]


def _without_captures(pattern: str) -> str:
    """*pattern* with every capturing group written as a non-capturing one: "(" becomes "(?:"
    and "(?P<name>" becomes "(?:". Escapes and character classes are copied as they are. One
    pass over the text; compile_regex checks with the parser that the result is the same
    pattern apart from the groups, so an odd spelling this misreads is refused, never changed."""
    out: list[str] = []
    index, size = 0, len(pattern)
    while index < size:
        char = pattern[index]
        if char == "\\":
            out.append(pattern[index : index + 2])
            index += 2
        elif char == "[":
            # A class runs to the first "]" that is not its first character (after an optional
            # "^"); escapes inside it are skipped whole.
            end = index + 1
            if end < size and pattern[end] == "^":
                end += 1
            if end < size and pattern[end] == "]":
                end += 1
            while end < size and pattern[end] != "]":
                end += 2 if pattern[end] == "\\" else 1
            out.append(pattern[index : end + 1])
            index = end + 1
        elif char == "(" and pattern.startswith("(?P<", index):
            close = pattern.find(">", index)
            if close < 0:
                return pattern
            out.append("(?:")
            index = close + 1
        elif char == "(" and not pattern.startswith("(?", index):
            out.append("(?:")
            index += 1
        else:
            out.append(char)
            index += 1
    return "".join(out)


def _items(parser: Any, data: Any) -> Iterator[Any]:
    """The items of one parsed sequence, a group without flag changes spliced in where it
    stands (a plain group only brackets; the parser itself drops a non-capturing one under a
    repeat, and keeps a capturing one)."""
    for op, av in data:
        if str(op) == "SUBPATTERN":
            _group, add_flags, del_flags, inner = av
            if not add_flags and not del_flags:
                yield from _items(parser, inner.data)
                continue
            yield ("SUBPATTERN", add_flags, del_flags, _tree(parser, inner))
        else:
            yield (str(op), _tree(parser, av))


def _tree(parser: Any, value: Any) -> Any:
    """A parsed pattern as nested tuples that compare equal for the same pattern, with group
    numbers and plain brackets left out (so a pattern and its capture-free twin compare
    equal)."""
    if isinstance(value, parser.SubPattern):
        return ("seq", tuple(_items(parser, value.data)))
    if isinstance(value, (list, tuple)):
        return tuple(_tree(parser, item) for item in value)
    if value is None or type(value) in (int, str, bool):
        return value
    return str(value)  # the parser's named opcode constants, by name


def _has_capture(value: Any, parser: Any) -> bool:
    if isinstance(value, parser.SubPattern):
        return any(_has_capture(item, parser) for item in value.data)
    if isinstance(value, tuple) and len(value) == 2 and str(value[0]) == "SUBPATTERN":
        return value[1][0] is not None or _has_capture(value[1][3], parser)
    if isinstance(value, (list, tuple)):
        return any(_has_capture(item, parser) for item in value)
    return False


def _parse(parser: Any, pattern: str) -> Any:
    try:
        return parser.parse(pattern, re.IGNORECASE)
    except (re.error, OverflowError, RecursionError, ValueError) as exc:
        raise RuleValidationError(texts.PATTERN_INVALID) from exc


def pattern_search_steps(pattern: str) -> float:
    """The worst-case search steps compile_regex estimates for *pattern* (RuleValidationError
    when it is refused for another reason first). For tests and the spec doc's figures."""
    parser, constants = _sre_modules()
    parsed = _parse(parser, pattern)
    return _search_steps(_units(list(parsed), _Shape(constants.MAXREPEAT), repeating=False))


@functools.lru_cache(maxsize=512)
def compile_regex(pattern: str) -> re.Pattern[str]:
    """A compiled, case-insensitive pattern that passed the safety check, or RuleValidationError.

    What is compiled is the capture-free twin of *pattern* (_without_captures): the parser must
    read it as the same pattern apart from the groups, and with no capturing group left, else
    the pattern is refused. A match means the same either way, since nothing reads a capture."""
    if not isinstance(pattern, str) or not 1 <= len(pattern) <= MAX_REGEX_CHARS:
        raise RuleValidationError(texts.PATTERN_LENGTH)
    parser, constants = _sre_modules()
    parsed = _parse(parser, pattern)
    shape = _Shape(constants.MAXREPEAT)
    units = _units(list(parsed), shape, repeating=False)
    choices, _ = _sequence_cost(units)
    if choices > (MAX_BACKTRACK_CHOICES if shape.open_repeats else MAX_BOUNDED_CHOICES):
        raise RuleValidationError(texts.PATTERN_TOO_SLOW)
    if _search_steps(units) > MAX_SEARCH_STEPS:
        raise RuleValidationError(texts.PATTERN_TOO_SLOW)
    plain = _without_captures(pattern)
    twin = _parse(parser, plain)
    if _has_capture(twin, parser) or _tree(parser, twin) != _tree(parser, parsed):
        raise RuleValidationError(texts.PATTERN_UNSUPPORTED)
    try:
        return re.compile(plain, re.IGNORECASE)
    except (re.error, OverflowError, RecursionError, ValueError) as exc:
        raise RuleValidationError(texts.PATTERN_INVALID) from exc


# ---------------------------------------------------------------------------
# Tool patterns and the catalog
# ---------------------------------------------------------------------------


@functools.lru_cache(maxsize=1)
def _catalog_rows() -> tuple[tuple[str, str, tuple[str, ...]], ...]:
    # Deferred: tool_registry imports the runtime and every connector. The catalog is built once
    # at import time there and never changes afterwards, so it is read once here.
    from services.agent.tool_registry import CONNECTOR_CATALOG, RUNTIME_BUILTIN_TYPES

    rows: list[tuple[str, str, tuple[str, ...]]] = []
    for connector_type, specs in CONNECTOR_CATALOG.items():
        if connector_type in RUNTIME_BUILTIN_TYPES:
            continue
        for spec in specs:
            properties = (
                spec.parameters.get("properties") if isinstance(spec.parameters, dict) else None
            )
            args = (
                tuple(
                    sorted(
                        key
                        for key in properties
                        if isinstance(key, str) and key and not key.startswith("_")
                    )
                )
                if isinstance(properties, dict)
                else ()
            )
            category = getattr(spec.category, "value", str(spec.category))
            rows.append((f"{connector_type}.{spec.action}", str(category), args))
    return tuple(sorted(rows))


def catalog() -> list[tuple[str, str, list[str]]]:
    """Every tool a rule can cover: (canonical name, category, argument names), sorted. The
    runtime's own tools (tools.find, tutor.*) are not in it."""
    return [(name, category, list(args)) for name, category, args in _catalog_rows()]


@functools.lru_cache(maxsize=1)
def _runtime_tool_names() -> tuple[str, ...]:
    from services.agent.tool_registry import CONNECTOR_CATALOG, RUNTIME_BUILTIN_TYPES

    return tuple(
        f"{connector_type}.{spec.action}"
        for connector_type in sorted(RUNTIME_BUILTIN_TYPES)
        for spec in CONNECTOR_CATALOG.get(connector_type, ())
    )


def _glob_match(pattern: str, name: str) -> bool:
    return fnmatchcase(name.lower(), pattern)


def can_match_prefix(pattern: str, prefix: str) -> bool:
    """Whether the glob (only ``*`` and ``?`` are special) can match some name starting with
    *prefix*: a small automaton run over the prefix."""

    def closure(states: set[int]) -> set[int]:
        out = set(states)
        stack = list(states)
        while stack:
            position = stack.pop()
            if position < len(pattern) and pattern[position] == "*" and position + 1 not in out:
                out.add(position + 1)
                stack.append(position + 1)
        return out

    states = closure({0})
    for char in prefix:
        moved: set[int] = set()
        for position in states:
            if position >= len(pattern):
                continue
            token = pattern[position]
            if token == "*":
                moved.add(position)
            elif token == "?" or token == char:
                moved.add(position + 1)
        states = closure(moved)
        if not states:
            return False
    return True


def matching_tools(tool: str) -> tuple[list[tuple[str, str]], bool]:
    """(catalog tools the glob matches as (name, category), whether it can match MCP tools)."""
    pattern = tool.strip().lower()
    matches = [
        (name, category) for name, category, _ in _catalog_rows() if _glob_match(pattern, name)
    ]
    return matches, can_match_prefix(pattern, _MCP_PREFIX)


def validate_tool_pattern(tool: Any) -> str:
    """The lower-case glob, or RuleValidationError (bad characters, too long, runtime-only)."""
    if not isinstance(tool, str) or not tool.strip():
        raise RuleValidationError(texts.TOOL_MISSING)
    pattern = tool.strip().lower()
    if len(pattern) > MAX_TOOL_CHARS:
        raise RuleValidationError(texts.TOOL_TOO_LONG)
    if not _TOOL_CHARS.fullmatch(pattern):
        raise RuleValidationError(texts.TOOL_CHARSET)
    namespace = pattern.partition(".")[0]
    if "*" not in namespace and "?" not in namespace and is_runtime_tool(namespace + "."):
        raise RuleValidationError(texts.TOOL_RUNTIME_ONLY)
    matches, can_mcp = matching_tools(pattern)
    if not matches and not can_mcp:
        runtime_hits = [name for name in _runtime_tool_names() if _glob_match(pattern, name)]
        if runtime_hits:
            raise RuleValidationError(texts.TOOL_RUNTIME_ONLY)
    return pattern


# ---------------------------------------------------------------------------
# Conditions
# ---------------------------------------------------------------------------


def _number(value: Any) -> Optional[float]:
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        number = float(value)
        return number if math.isfinite(number) else None
    if isinstance(value, str):
        return values.parse_number(value)
    return None


def _text(value: Any) -> Optional[str]:
    """A stripped text value of 1..MAX_VALUE_CHARS, else None (too long raises)."""
    if not isinstance(value, str):
        return None
    stripped = value.strip()
    if len(stripped) > MAX_VALUE_CHARS:
        raise RuleValidationError(texts.VALUE_TOO_LONG)
    return stripped or None


def _list_items(value: Any, op: Op) -> list[Any]:
    label = OP_LABELS[op]
    if isinstance(value, str) and op in ("domain_in", "domain_not_in"):
        value = [part for part in re.split(r"[,\s]+", value) if part]
    if not isinstance(value, (list, tuple)):
        raise RuleValidationError(texts.needs_values(label))
    items = list(value)
    if len(items) > MAX_LIST_ITEMS:
        raise RuleValidationError(texts.needs_values(label))
    return items


def _echo_safe(text: str) -> bool:
    """Whether a refused value may be repeated back: short, printable and not secret-shaped."""
    if len(text) > 60 or not text.isprintable():
        return False
    try:
        return not argument_findings({"value": text}, TOOL_ARGS)
    except Exception:  # noqa: BLE001 - when in doubt, do not echo
        return False


def _domain(item: Any) -> str:
    if not isinstance(item, str):
        raise RuleValidationError(texts.NOT_A_DOMAIN_GENERIC)
    raw = item.strip()
    if len(raw) > MAX_VALUE_CHARS:
        raise RuleValidationError(texts.VALUE_TOO_LONG)
    lowered = raw.lower().rstrip(".")
    encoded = None
    if lowered and not any(ch in lowered for ch in "*@/:\\ \t?#[]"):
        encoded = values.idna_domain(lowered)
    if encoded is None or not values.is_hostname(encoded):
        raise RuleValidationError(
            texts.not_a_domain(raw) if raw and _echo_safe(raw) else texts.NOT_A_DOMAIN_GENERIC
        )
    return encoded


def _condition(item: Any) -> Condition:
    if not isinstance(item, Mapping) or not {"arg", "op"} <= set(item) or "value" not in item:
        raise RuleValidationError(texts.CONDITION_SHAPE)
    arg, op, value = item.get("arg"), item.get("op"), item.get("value")
    if not isinstance(arg, str) or not _ARG.fullmatch(arg.strip()):
        raise RuleValidationError(texts.ARG_INVALID)
    arg = arg.strip()
    if any(part.startswith("_") for part in arg.split(".")):
        raise RuleValidationError(texts.ARG_RESERVED)
    if not isinstance(op, str) or op not in OP_LABELS:
        raise RuleValidationError(texts.OP_UNKNOWN)
    op_name: Op = op  # type: ignore[assignment]
    label = OP_LABELS[op_name]
    if op_name in ("equals", "not_equals"):
        number = _number(value) if not isinstance(value, str) else None
        if number is not None:
            return Condition(arg, op_name, number)
        text = _text(value)
        if text is None:
            raise RuleValidationError(texts.needs_text(label, number_ok=True))
        return Condition(arg, op_name, text)
    if op_name == "contains":
        text = _text(value)
        if text is None or not values.simple_form(text):
            raise RuleValidationError(texts.needs_text(label, number_ok=False))
        return Condition(arg, op_name, text)
    if op_name == "regex":
        if not isinstance(value, str) or not 1 <= len(value) <= MAX_REGEX_CHARS:
            raise RuleValidationError(texts.PATTERN_LENGTH)
        compile_regex(value)
        return Condition(arg, op_name, value)
    if op_name == "in_list":
        items: list[str] = []
        for raw in _list_items(value, op_name):
            number = _number(raw) if not isinstance(raw, str) else None
            entry = texts.format_number(number) if number is not None else _text(raw)
            if entry is not None and entry not in items:
                items.append(entry)
        if not items:
            raise RuleValidationError(texts.needs_values(label))
        return Condition(arg, op_name, tuple(items))
    if op_name in ("domain_in", "domain_not_in"):
        domains: list[str] = []
        for raw in _list_items(value, op_name):
            if isinstance(raw, str) and not raw.strip():
                continue
            domain = _domain(raw)
            if domain not in domains:
                domains.append(domain)
        if not domains:
            raise RuleValidationError(texts.needs_values(label))
        return Condition(arg, op_name, tuple(domains))
    number = _number(value)
    if number is None:
        raise RuleValidationError(texts.needs_number(label))
    return Condition(arg, op_name, number)


def validate_conditions(conditions: Any) -> tuple[Condition, ...]:
    """The normalised conditions, or RuleValidationError with the first reason."""
    if conditions is None:
        return ()
    if not isinstance(conditions, (list, tuple)):
        raise RuleValidationError(texts.CONDITIONS_NOT_LIST)
    if len(conditions) > MAX_CONDITIONS:
        raise RuleValidationError(texts.TOO_MANY_CONDITIONS)
    return tuple(_condition(item) for item in conditions)


# ---------------------------------------------------------------------------
# Whole rules
# ---------------------------------------------------------------------------


def _name(name: Any) -> str:
    if not isinstance(name, str):
        raise RuleValidationError(texts.NAME_INVALID)
    cleaned = " ".join(name.split())
    if (
        not MIN_NAME_CHARS <= len(cleaned) <= MAX_NAME_CHARS
        or not _NAME_CHARS.fullmatch(cleaned)
        or _NAME_LINKISH.search(cleaned)
    ):
        raise RuleValidationError(texts.NAME_INVALID)
    return cleaned


def _secret_shaped(name: Any, tool: Any, conditions: Any) -> bool:
    """Whether anything in the submitted rule looks like a key, password, card, bank or ID
    number. Each condition is read as ``{arg: value}``, so "password is Tr0ub4dor&3" counts as
    a stated password."""
    probe: list[Any] = [{"name": name}, {"tool": tool}]
    if isinstance(conditions, (list, tuple)):
        for item in conditions:
            if isinstance(item, Mapping):
                arg = item.get("arg")
                probe.append({str(arg) if isinstance(arg, str) else "value": item.get("value")})
    try:
        return bool(argument_findings(probe, TOOL_ARGS))
    except Exception:  # noqa: BLE001 - a detector failure refuses (fail closed)
        return True


def _value_key(value: str | float | tuple[str, ...]) -> Any:
    if isinstance(value, tuple):
        return tuple(sorted(values.simple_form(v) for v in value))
    if isinstance(value, str):
        return values.simple_form(value)
    return float(value)


def _identity(tool: str, conditions: Sequence[Condition]) -> Any:
    return (
        tool,
        tuple(sorted((c.arg, c.op, repr(_value_key(c.value))) for c in conditions)),
    )


def validate_rule(
    name: Any, tool: Any, conditions: Any, *, existing: Sequence[OwnerRule]
) -> RuleDraft:
    """The normalised rule, or RuleValidationError with the reason (never quoting a refused value)."""
    if len(existing) >= MAX_RULES:
        raise RuleValidationError(texts.TOO_MANY_RULES)
    if _secret_shaped(name, tool, conditions):
        raise RuleValidationError(texts.SECRET_VALUE)
    clean_name = _name(name)
    taken = {r.name.casefold() for r in existing} | {b.text.name.casefold() for b in BUILTINS}
    if clean_name.casefold() in taken:
        raise RuleValidationError(texts.NAME_TAKEN)
    pattern = validate_tool_pattern(tool)
    clean_conditions = validate_conditions(conditions)
    identity = _identity(pattern, clean_conditions)
    for rule in existing:
        if _identity(rule.tool, rule.conditions) == identity:
            raise RuleValidationError(texts.identical_rule(rule.name))
    return RuleDraft(name=clean_name, tool=pattern, conditions=clean_conditions)


def validate_draft(tool: Any, conditions: Any) -> RuleDraft:
    """A rule without its name, checked as validate_rule checks it (nothing secret-shaped, the
    tool pattern, every condition) but not against the saved rules: what the page's preview
    needs. The draft's name is empty."""
    if _secret_shaped("", tool, conditions):
        raise RuleValidationError(texts.SECRET_VALUE)
    return RuleDraft(
        name="", tool=validate_tool_pattern(tool), conditions=validate_conditions(conditions)
    )


def stored_name(name: Any) -> str:
    """A stored rule's name as cards, notices and the page show it: the name when today's check
    still accepts it (so it never holds "@" or a link), else a fixed placeholder."""
    try:
        return _name(name)
    except RuleValidationError:
        return texts.UNREADABLE_RULE_NAME


def owner_rule_from_stored(
    *,
    rule_id: Any,
    name: str,
    tool: str,
    conditions: Any,
    created_at: datetime,
    created_by: Optional[Any] = None,
) -> OwnerRule:
    """An OwnerRule from a stored row, its pattern and conditions re-checked with today's
    validator; RuleValidationError for a row that no longer passes (the store decides how to
    fail closed)."""
    return OwnerRule(
        id=str(rule_id),
        name=name,
        tool=validate_tool_pattern(tool),
        conditions=validate_conditions(conditions),
        created_at=created_at,
        created_by=str(created_by) if created_by is not None else None,
    )


def unreadable_rule(
    *,
    rule_id: Any,
    name: Any,
    tool: Any,
    created_at: datetime,
    created_by: Optional[Any] = None,
) -> OwnerRule:
    """The OwnerRule for a stored row today's validator refuses: its glob as stored (any
    string is safe to match; a missing one covers every tool), no conditions, and
    ``unreadable`` set, so every write the glob covers asks (engine.evaluate)."""
    glob = tool.strip().lower() if isinstance(tool, str) and tool.strip() else "*"
    return OwnerRule(
        id=str(rule_id),
        name=stored_name(name),
        tool=glob[:MAX_TOOL_CHARS],
        conditions=(),
        created_at=created_at,
        created_by=str(created_by) if created_by is not None else None,
        unreadable=True,
    )


# ---------------------------------------------------------------------------
# Output: JSON, summaries, digests, operator list
# ---------------------------------------------------------------------------


def condition_json(condition: Condition) -> dict[str, Any]:
    """{"arg", "op", "value"} with whole numbers as ints and lists as lists."""
    value: Any = condition.value
    if isinstance(value, tuple):
        value = list(value)
    elif isinstance(value, float) and value == int(value) and abs(value) < 1e15:
        value = int(value)
    return {"arg": condition.arg, "op": condition.op, "value": value}


def conditions_json(conditions: Sequence[Condition]) -> list[dict[str, Any]]:
    return [condition_json(c) for c in conditions]


def summarize(tool: str, conditions: Sequence[Condition]) -> str:
    """'Ask before <tool> when "amount" is more than 500 and ...' (the owner's words only)."""
    phrases = [
        texts.condition_phrase(c.arg, c.op, c.value, list_limit=texts.SUMMARY_LIST_LIMIT)
        for c in conditions
    ]
    return texts.rule_summary(tool, phrases)


def rule_digest(draft: RuleDraft | OwnerRule) -> str:
    """16 hex chars of sha256 over the canonical rule JSON, for audit rows (values never logged)."""
    canonical = json.dumps(
        {"name": draft.name, "tool": draft.tool, "conditions": conditions_json(draft.conditions)},
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:16]


def audit_fields(rule: RuleDraft | OwnerRule, *, rule_id: str) -> dict[str, Any]:
    """The request_data of a tool_rule_created / tool_rule_deleted row: id, name, tool pattern,
    argument and operator names and the digest; never a condition value."""
    return {
        "rule_id": rule_id,
        "name": rule.name,
        "tool": rule.tool,
        "args": [c.arg for c in rule.conditions],
        "ops": [c.op for c in rule.conditions],
        "digest": rule_digest(rule),
    }


def operator_options() -> list[dict[str, str]]:
    """The operators in page order: [{"op", "label", "value"}]."""
    return [{"op": op, "label": OP_LABELS[op], "value": OP_VALUE_KINDS[op]} for op in OPS]


__all__ = [
    "GENERAL_REPEAT_WEIGHT",
    "LIMITS",
    "MAX_BACKTRACK_CHOICES",
    "MAX_BOUNDED_CHOICES",
    "MAX_BOUNDED_REPEAT",
    "MAX_CONDITIONS",
    "MAX_LIST_ITEMS",
    "MAX_REGEX_CHARS",
    "MAX_RULES",
    "MAX_SEARCH_STEPS",
    "MAX_TOOL_CHARS",
    "MAX_VALUE_CHARS",
    "OPS",
    "OP_LABELS",
    "OP_VALUE_KINDS",
    "REGEX_TEXT_CAP",
    "RuleDraft",
    "RuleValidationError",
    "audit_fields",
    "can_match_prefix",
    "catalog",
    "compile_regex",
    "condition_json",
    "conditions_json",
    "matching_tools",
    "operator_options",
    "owner_rule_from_stored",
    "pattern_search_steps",
    "rule_digest",
    "stored_name",
    "summarize",
    "unreadable_rule",
    "validate_conditions",
    "validate_draft",
    "validate_rule",
    "validate_tool_pattern",
]
