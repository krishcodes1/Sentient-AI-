"""Decides which tool rules one call breaks: the four built-in rules (B1-B4, builtins.py) and the
owner's own rules (a tool glob plus up to five argument conditions that must all hold). Pure: no
I/O, no clock beyond an injected one, nothing stored between calls.

Why it exists: decisions.md item 3 (Progent-style rules on tool arguments). A broken rule only ever
turns a call into an approval card that names the rule; it never blocks a call and never lets one
skip a card. The evaluator therefore fails toward asking everywhere: a rule whose evaluation
raises counts as broken, an unreadable rule store makes every write ask, a value too long for a
pattern counts as a match, and a pattern check that runs out of its time budget counts as broken.

Connects to: builtins.py (B1-B4), values.py (leaf selection, normalised text, addresses, links,
numbers), texts.py (note wording), grammar.py (compile_regex, imported lazily: grammar imports
the types below). The rule glob is matched against the canonical tool name (no per-account slug),
lower-cased, with fnmatch.
Used by: check.py (the S9 call check, every stage) and the routes' preview; tests call it directly.
"""

from __future__ import annotations

import functools
import re
import time
from dataclasses import dataclass, field
from datetime import datetime
from fnmatch import fnmatchcase
from typing import Any, Callable, Literal, Mapping, Optional, Sequence

from services.agent.permissions import ActionCategory
from services.security.tool_rules import builtins as _builtins
from services.security.tool_rules import texts, values

Op = Literal[
    "equals",
    "not_equals",
    "contains",
    "regex",
    "in_list",
    "domain_in",
    "domain_not_in",
    "number_gt",
    "number_lt",
]

BUILTIN_PREFIX = "builtin:"
OWNER_PREFIX = "owner:"
UNAVAILABLE_RULE_ID = "tool_rules:unavailable"

# A string leaf longer than this (after normalisation) counts as a pattern match: Crawler asks
# rather than skip the check. Mirrors grammar.REGEX_TEXT_CAP (grammar imports this module).
REGEX_TEXT_CAP = 4000
# At most this much normalised text is searched for one pattern condition; more counts as a
# match. Each search is bounded by the pattern checks in grammar.compile_regex.
REGEX_TOTAL_CAP = 4 * REGEX_TEXT_CAP
# Time one evaluation may spend in pattern searches. A search is never started after it runs
# out; the rule that needed it counts as broken (asks), with the "could not check" note.
REGEX_BUDGET_S = 0.25

_WRITE_CATEGORIES = frozenset(
    {
        ActionCategory.WRITE,
        ActionCategory.DELETE,
        ActionCategory.EXECUTE,
        ActionCategory.FINANCIAL,
    }
)


@dataclass(frozen=True)
class Condition:
    """One argument test of an owner rule: the argument path, the operator and its value."""

    arg: str  # "to", "fields.text", or "*" (any argument)
    op: Op
    value: str | float | tuple[str, ...]


@dataclass(frozen=True)
class OwnerRule:
    """One stored owner rule, already validated (grammar.validate_rule).

    ``unreadable`` marks a stored row that today's validator refuses (a grammar change, a hand
    edit): its conditions are not trusted, so every write its tool glob covers asks, with the
    "could not check" note (the store keeps the row's glob; ``conditions`` is empty)."""

    id: str
    name: str
    tool: str  # lower-case glob
    conditions: tuple[Condition, ...]
    created_at: datetime
    created_by: Optional[str] = None
    unreadable: bool = False


@dataclass(frozen=True)
class RuleSnapshot:
    """What one turn (or one dispatch) checks against: the owner's rules (oldest first), the
    built-ins the owner turned off, and whether the store could be read at all."""

    owner_rules: tuple[OwnerRule, ...] = ()
    builtins_off: frozenset[str] = frozenset()
    error: bool = False  # store unreadable: built-ins all on + ask before writes


@dataclass(frozen=True)
class CallView:
    """The facts about one call a rule may read. ``recipients`` and ``shares_content`` come from
    the tool's ``spec.outbound`` declaration (scaffold A5); ``call_view`` reads them."""

    canonical: str  # canonical_tool_name(tool_name)
    arguments: Mapping[str, Any]
    category: Optional[ActionCategory]  # resolve_tool(...).spec.category; None for MCP
    is_mcp: bool
    recipients: tuple[str, ...] = ()  # spec.outbound.recipients: argument paths with addresses
    shares_content: bool = False  # spec.outbound.shares_content: forward, share, invite


@dataclass(frozen=True)
class TurnView:
    """What only a turn knows: what Crawler read (untrusted) and what the person wrote."""

    untrusted: Callable[[str], bool]  # an email/URL/host Crawler read this turn or earlier
    owner_addresses: frozenset[str]  # Address.key of every address in the person's messages
    owner_hosts: frozenset[str]  # hosts and domains in the person's own messages


@dataclass(frozen=True)
class RuleHit:
    """One broken rule, ready for the card: a stable id for audit, the display name, and the
    note text (names arguments, never quotes their values)."""

    rule_id: str  # "builtin:many_recipients" | "owner:<uuid>" | "tool_rules:unavailable"
    name: str
    source: Literal["built_in", "owner", "system"]
    note: str


def call_view(
    canonical: str,
    arguments: Any,
    *,
    spec: Any = None,
    is_mcp: bool = False,
) -> CallView:
    """The CallView for a call: category and outbound declaration read from *spec* (a ToolSpec,
    or None for an MCP tool or an unknown name). A non-mapping argument value reads as no
    arguments."""
    outbound = getattr(spec, "outbound", None) if spec is not None else None
    recipients = tuple(getattr(outbound, "recipients", ()) or ()) if outbound is not None else ()
    shares = bool(getattr(outbound, "shares_content", False)) if outbound is not None else False
    category = getattr(spec, "category", None) if spec is not None else None
    return CallView(
        canonical=canonical,
        arguments=arguments if isinstance(arguments, Mapping) else {},
        category=category if isinstance(category, ActionCategory) else None,
        is_mcp=is_mcp,
        recipients=recipients,
        shares_content=shares and bool(recipients),
    )


@functools.lru_cache(maxsize=1)
def _runtime_types() -> frozenset[str]:
    # Deferred: tool_registry imports the runtime and every connector, and this module must stay
    # importable on its own.
    from services.agent.tool_registry import RUNTIME_BUILTIN_TYPES

    return frozenset(RUNTIME_BUILTIN_TYPES)


def is_runtime_tool(canonical: str) -> bool:
    """True for a tool the runtime answers itself (tools.find, tutor.*)."""
    return canonical.lower().partition(".")[0] in _runtime_types()


def applies_to(canonical: str) -> bool:
    """False for calls the runtime answers itself (tools.find, tutor.*), which no rule may park."""
    return bool(canonical) and not is_runtime_tool(canonical)


def is_write(call: CallView) -> bool:
    """WRITE, DELETE, EXECUTE or FINANCIAL, or any MCP tool (its category is unknown); a non-MCP
    tool with no known category counts as a write too (fail closed)."""
    if call.is_mcp or call.category is None:
        return True
    return call.category in _WRITE_CATEGORIES


def tool_matches(pattern: str, canonical: str) -> bool:
    """Whether a rule's lower-case glob covers the canonical tool name."""
    return fnmatchcase(canonical.lower(), pattern)


# ---------------------------------------------------------------------------
# Conditions
# ---------------------------------------------------------------------------


class _RegexBudgetSpent(RuntimeError):
    """This evaluation's pattern-search time ran out; the rule that needed it asks."""


@dataclass
class _Context:
    """Per-evaluation state: normalised forms of each leaf string (computed once) and the
    pattern-search budget."""

    deadline: float
    clock: Callable[[], float]
    simple: dict[str, str] = field(default_factory=dict)
    scan: dict[str, str] = field(default_factory=dict)

    def simple_form(self, text: str) -> str:
        form = self.simple.get(text)
        if form is None:
            form = self.simple[text] = values.simple_form(text)
        return form

    def scan_form(self, text: str) -> str:
        form = self.scan.get(text)
        if form is None:
            form = self.scan[text] = values.scan_form(text)
        return form

    def search(self, pattern: re.Pattern[str], text: str) -> bool:
        if self.clock() > self.deadline:
            raise _RegexBudgetSpent
        return pattern.search(text) is not None


def _new_context(budget_s: float = REGEX_BUDGET_S, clock: Callable[[], float] = time.perf_counter) -> _Context:
    return _Context(deadline=clock() + budget_s, clock=clock)


@functools.lru_cache(maxsize=512)
def _compiled(pattern: str) -> re.Pattern[str]:
    from services.security.tool_rules.grammar import compile_regex

    return compile_regex(pattern)


def _equal(leaf: Any, target: str | float, ctx: _Context, *, look_alikes: bool) -> bool:
    """A leaf equals a target: numerically when both read as numbers, else by simple_form (and,
    with *look_alikes*, by scan_form too, so a homoglyph spelling still counts as equal)."""
    target_number = values.parse_number(target)
    if target_number is not None:
        leaf_number = values.parse_number(leaf)
        if leaf_number is not None:
            return leaf_number == target_number
    text = values.leaf_text(leaf)
    if text is None:
        return False
    wanted = target if isinstance(target, str) else texts.format_number(target)
    if ctx.simple_form(text) == ctx.simple_form(wanted):
        return True
    return look_alikes and ctx.scan_form(text) == ctx.scan_form(wanted)


def _domains_of(leaf: Any) -> tuple[list[str], bool]:
    """(the domains of the addresses and link hosts in one leaf, whether the leaf holds something
    that cannot be placed: a non-blank value with nothing recognisable in it, or an "@" that no
    readable address accounts for). Every host a reader may take from a link counts (the
    browser's and urllib's, values.Link.hosts)."""
    text = values.leaf_text(leaf)
    if text is None:
        return [], False
    addresses, unread = values.address_scan(text)
    found = [a.domain for a in addresses]
    found.extend(values.hosts_in(text))
    if not found:
        host = values.whole_host(text)
        if host:
            found.append(host)
    return found, (not found and bool(text.strip())) or unread > 0


def _regex_holds(pattern: re.Pattern[str], leaves: Sequence[Any], ctx: _Context) -> bool:
    searched = 0
    for leaf in leaves:
        text = values.leaf_text(leaf)
        if text is None:
            continue
        simple = ctx.simple_form(text)
        scan = ctx.scan_form(text)
        forms = (simple,) if scan == simple else (simple, scan)
        for form in forms:
            if len(form) > REGEX_TEXT_CAP:
                return True  # too long to search safely: ask rather than skip the check
            searched += len(form)
            if searched > REGEX_TOTAL_CAP:
                return True
            if ctx.search(pattern, form):
                return True
    return False


def _holds(condition: Condition, arguments: Mapping[str, Any], ctx: _Context) -> bool:
    leaves = values.select(arguments, condition.arg)
    if not leaves:
        return False  # an absent argument never satisfies a condition
    op, value = condition.op, condition.value
    if op == "equals":
        assert not isinstance(value, tuple)
        return any(_equal(leaf, value, ctx, look_alikes=True) for leaf in leaves)
    if op == "not_equals":
        assert not isinstance(value, tuple)
        return any(not _equal(leaf, value, ctx, look_alikes=False) for leaf in leaves)
    if op == "in_list":
        options = value if isinstance(value, tuple) else (str(value),)
        return any(_equal(leaf, o, ctx, look_alikes=True) for leaf in leaves for o in options)
    if op == "contains":
        needle = str(value)
        simple_needle, scan_needle = ctx.simple_form(needle), ctx.scan_form(needle)
        for leaf in leaves:
            text = values.leaf_text(leaf)
            if text is None:
                continue
            if simple_needle and simple_needle in ctx.simple_form(text):
                return True
            if scan_needle and scan_needle in ctx.scan_form(text):
                return True
        return False
    if op == "regex":
        return _regex_holds(_compiled(str(value)), leaves, ctx)
    if op in ("domain_in", "domain_not_in"):
        wanted = frozenset(value) if isinstance(value, tuple) else frozenset({str(value)})
        named = condition.arg != "*"
        for leaf in leaves:
            domains, unrecognised = _domains_of(leaf)
            if op == "domain_in":
                if any(values.in_domains(d, wanted) for d in domains):
                    return True
            else:
                if any(not values.in_domains(d, wanted) for d in domains):
                    return True
                if named and unrecognised:
                    return True  # an address argument with no readable address: fail closed
        return False
    if op in ("number_gt", "number_lt"):
        threshold = float(value) if not isinstance(value, tuple) else None
        if threshold is None:
            return False
        for leaf in leaves:
            number = values.parse_number(leaf)
            if number is None:
                continue
            if (op == "number_gt" and number > threshold) or (
                op == "number_lt" and number < threshold
            ):
                return True
        return False
    raise ValueError(f"unknown operator {op!r}")


def condition_holds(
    condition: Condition,
    arguments: Mapping[str, Any],
    *,
    regex_budget_s: float = REGEX_BUDGET_S,
    clock: Callable[[], float] = time.perf_counter,
) -> bool:
    """Whether one condition holds for these arguments (raises when it cannot be checked)."""
    return _holds(condition, arguments, _new_context(regex_budget_s, clock))


def condition_phrases(conditions: Sequence[Condition], *, list_limit: int) -> list[str]:
    return [
        texts.condition_phrase(c.arg, c.op, c.value, list_limit=list_limit) for c in conditions
    ]


# ---------------------------------------------------------------------------
# Evaluation
# ---------------------------------------------------------------------------


def evaluate(
    call: CallView,
    snapshot: RuleSnapshot,
    *,
    turn: Optional[TurnView],
    org_domains: Optional[frozenset[str]],
    regex_budget_s: float = REGEX_BUDGET_S,
    clock: Callable[[], float] = time.perf_counter,
) -> tuple[RuleHit, ...]:
    """Every rule this call breaks, built-ins first (B1-B4) then owner rules oldest first. A
    rule that needs the turn (B1, B4) is skipped when turn is None; a rule whose evaluation
    raises counts as broken (fail closed). Pure: no I/O.

    ``org_domains``: the calling person's organisation domains for B3; an empty set means no
    organisation is known (B3 stays quiet), None means they could not be read (B3 asks for
    every share). With ``snapshot.error`` every write gets the "rules unavailable" hit first and
    every built-in counts as on."""
    if not applies_to(call.canonical):
        return ()
    write = is_write(call)
    hits: list[RuleHit] = []
    if snapshot.error and write:
        hits.append(
            RuleHit(
                rule_id=UNAVAILABLE_RULE_ID,
                name=texts.UNAVAILABLE_NAME,
                source="system",
                note=texts.UNAVAILABLE_NOTE,
            )
        )
    if write:
        for rule in _builtins.BUILTINS:
            if rule.key in snapshot.builtins_off and not snapshot.error:
                continue
            if rule.needs_turn and turn is None:
                continue
            try:
                note = rule.check(call, turn, org_domains)
            except Exception:  # noqa: BLE001 - a rule that cannot be checked asks
                note = texts.rule_failed_note(rule.text.name, owner=False)
            if note:
                hits.append(
                    RuleHit(
                        rule_id=BUILTIN_PREFIX + rule.key,
                        name=rule.text.name,
                        source="built_in",
                        note=note,
                    )
                )
    ctx = _new_context(regex_budget_s, clock)
    for owner_rule in snapshot.owner_rules:
        try:
            if not tool_matches(owner_rule.tool, call.canonical):
                continue
            if owner_rule.unreadable:
                # Its conditions cannot be trusted: a write asks, a read goes on (as with an
                # unreadable store).
                if not write:
                    continue
                raise ValueError("stored rule no longer valid")
            if not all(_holds(c, call.arguments, ctx) for c in owner_rule.conditions):
                continue
            owner_note = texts.owner_rule_note(
                owner_rule.name,
                condition_phrases(owner_rule.conditions, list_limit=texts.NOTE_LIST_LIMIT),
            )
        except Exception:  # noqa: BLE001 - includes a spent pattern budget: the rule asks
            owner_note = texts.rule_failed_note(owner_rule.name, owner=True)
        hits.append(
            RuleHit(
                rule_id=OWNER_PREFIX + str(owner_rule.id),
                name=owner_rule.name,
                source="owner",
                note=owner_note,
            )
        )
    unique: dict[str, RuleHit] = {}
    for hit in hits:
        unique.setdefault(hit.rule_id, hit)
    return tuple(unique.values())


def rule_ids(hits: Sequence[RuleHit]) -> str:
    """The hit ids joined by "," for audit rows ("builtin:untrusted_recipient,owner:7c0e...")."""
    return ",".join(dict.fromkeys(h.rule_id for h in hits))


__all__ = [
    "BUILTIN_PREFIX",
    "CallView",
    "Condition",
    "OWNER_PREFIX",
    "Op",
    "OwnerRule",
    "REGEX_BUDGET_S",
    "REGEX_TEXT_CAP",
    "REGEX_TOTAL_CAP",
    "RuleHit",
    "RuleSnapshot",
    "TurnView",
    "UNAVAILABLE_RULE_ID",
    "applies_to",
    "call_view",
    "condition_holds",
    "condition_phrases",
    "evaluate",
    "is_runtime_tool",
    "is_write",
    "rule_ids",
    "tool_matches",
]
