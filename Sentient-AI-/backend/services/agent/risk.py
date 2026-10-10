"""Grades every connector action low, medium or high risk, in code, from the
action's ToolSpec and the arguments actually sent.

Why it exists: standing consent (the auto_approve tier, the "Allow low-risk
changes" tier and 7-day low-risk grants) must never cover a send, a delete, a
share or an invitation. The grade decides that, so it is computed only here:
from the catalog (category, always_confirm and the three declarative fields
``risk``, ``risk_check`` and ``ref_args`` on services/connectors/definition.py
ToolSpec) and the call's arguments. The model never grades anything, and a
reason never quotes an argument value, so nothing here needs redacting.

Rules:
- READ is LOW. DELETE, EXECUTE, FINANCIAL and always_confirm are HIGH. A WRITE
  is MEDIUM unless its spec declares ``risk="low"``.
- An argument the schema does not list, or one of the wrong type (or outside
  its enum), makes the call at least MEDIUM.
- ``risk_check`` can only raise the grade; one that raises grades HIGH.
- Built-in, MCP and unknown tools are HIGH: only a registry connector's action
  is ever eligible for standing consent.

Connects to: services/agent/tool_registry.py (the offer label, the executor's
re-grade of the arguments it sends), services/agent/runtime.py (the per-call
standing-consent decision), services/connectors/registry.py (validation of the
declarations and the Connectors page payload) and the connector modules
(their ``risk_check`` rules use the builders below). It imports only
services.agent.permissions at module level; the registry and tool registry
are imported inside the functions that need them.
"""

from __future__ import annotations

import enum
from collections import Counter
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Callable, Iterable, Mapping, Optional

from services.agent.permissions import ActionCategory

if TYPE_CHECKING:
    from services.connectors.definition import RiskCheck, ToolSpec


class Risk(str, enum.Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


_ORDER: dict[Risk, int] = {Risk.LOW: 0, Risk.MEDIUM: 1, Risk.HIGH: 2}

# Most low-risk changes (low_risk tier or grant) one turn may make without a
# card; the next one asks. A constant in v1, not an owner setting.
LOW_RISK_MAX_PER_TURN = 10
# Longest ToolSpec.low_risk_note the registry accepts.
LOW_RISK_NOTE_MAX_CHARS = 80
# The owner's install-wide switch for low-risk runs and grants
# (services/capabilities/low_risk_actions.py).
LOW_RISK_SWITCH = "low_risk_actions"

# Why a call got its grade. Fixed text: a reason goes on audit rows and on
# cards, so it never carries an argument value.
REASON_READ = "it only reads"
REASON_DELETE = "it deletes something"
REASON_EXECUTE = "it runs something on the service"
REASON_FINANCIAL = "it moves money"
REASON_ALWAYS_CONFIRM = "it sends, shares or speaks for you"
REASON_WRITE = "it changes something in the account"
REASON_LOW = "it is a small change you can undo"
REASON_NOT_OBJECT = "its arguments are not an object"
REASON_UNEXPECTED_ARGUMENT = "it has an argument this action does not take"
REASON_WRONG_TYPE = "it has an argument of the wrong kind"
REASON_CHECK_FAILED = "it could not be graded"
REASON_NOT_CONNECTOR = "it is not an action of a connected account"

# risk_check levels a connector may answer with. "low" is accepted and never
# lowers anything (a check only escalates).
_CHECK_LEVELS: dict[str, Risk] = {"low": Risk.LOW, "medium": Risk.MEDIUM, "high": Risk.HIGH}

_JSON_TYPES: dict[str, Callable[[Any], bool]] = {
    "string": lambda v: isinstance(v, str),
    "integer": lambda v: isinstance(v, int) and not isinstance(v, bool),
    "number": lambda v: isinstance(v, (int, float)) and not isinstance(v, bool),
    "boolean": lambda v: isinstance(v, bool),
    "array": lambda v: isinstance(v, list),
    "object": lambda v: isinstance(v, dict),
}


@dataclass(frozen=True)
class RiskGrade:
    """A call's grade and the fixed reason for it."""

    risk: Risk
    reason: str

    @property
    def is_low(self) -> bool:
        return self.risk is Risk.LOW

    @property
    def is_high(self) -> bool:
        return self.risk is Risk.HIGH


def _higher(current: RiskGrade, level: Risk, reason: str) -> RiskGrade:
    """*current*, or the escalation when it is higher: a grade only rises."""
    return RiskGrade(level, reason) if _ORDER[level] > _ORDER[current.risk] else current


def low_risk_eligible(spec: Optional["ToolSpec"]) -> bool:
    """Whether *spec* may ever run under the low-risk tier or a grant: a
    WRITE that declares ``risk="low"`` and does not always confirm."""
    return (
        spec is not None
        and spec.category == ActionCategory.WRITE
        and spec.risk == Risk.LOW.value
        and not spec.always_confirm
    )


def _base_grade(spec: "ToolSpec") -> RiskGrade:
    category = spec.category
    if category == ActionCategory.FINANCIAL:
        return RiskGrade(Risk.HIGH, REASON_FINANCIAL)
    if category == ActionCategory.DELETE:
        return RiskGrade(Risk.HIGH, REASON_DELETE)
    if category == ActionCategory.EXECUTE:
        return RiskGrade(Risk.HIGH, REASON_EXECUTE)
    if spec.always_confirm:
        return RiskGrade(Risk.HIGH, REASON_ALWAYS_CONFIRM)
    if category == ActionCategory.READ:
        return RiskGrade(Risk.LOW, REASON_READ)
    if low_risk_eligible(spec):
        return RiskGrade(Risk.LOW, REASON_LOW)
    return RiskGrade(Risk.MEDIUM, REASON_WRITE)


def _argument_grade(spec: "ToolSpec", arguments: Mapping[str, Any]) -> Optional[tuple[Risk, str]]:
    """MEDIUM when an argument is outside the schema, of the wrong type or
    outside its enum; None when every argument is one the action takes."""
    schema = spec.parameters or {}
    properties = schema.get("properties") if isinstance(schema, Mapping) else None
    properties = properties if isinstance(properties, Mapping) else {}
    for name, value in arguments.items():
        prop = properties.get(name)
        if not isinstance(prop, Mapping):
            return Risk.MEDIUM, REASON_UNEXPECTED_ARGUMENT
        if value is None:
            # An optional argument sent as null: the action's default.
            continue
        check = _JSON_TYPES.get(str(prop.get("type", "")))
        if check is not None and not check(value):
            return Risk.MEDIUM, REASON_WRONG_TYPE
        allowed = prop.get("enum")
        if isinstance(allowed, (list, tuple)) and value not in allowed:
            return Risk.MEDIUM, REASON_WRONG_TYPE
    return None


def grade_spec(spec: Optional["ToolSpec"], arguments: Any) -> RiskGrade:
    """The grade of one call to *spec* with *arguments*.

    The base grade comes from the spec; the arguments and the spec's
    ``risk_check`` can only raise it. None (no spec) is HIGH."""
    if spec is None:
        return RiskGrade(Risk.HIGH, REASON_NOT_CONNECTOR)
    grade = _base_grade(spec)
    if not isinstance(arguments, Mapping):
        return _higher(grade, Risk.MEDIUM, REASON_NOT_OBJECT)
    shape = _argument_grade(spec, arguments)
    if shape is not None:
        grade = _higher(grade, *shape)
    if spec.risk_check is not None:
        try:
            answer = spec.risk_check(arguments)
        except Exception:
            # A check that cannot decide never lets the call through.
            return RiskGrade(Risk.HIGH, REASON_CHECK_FAILED)
        if answer is not None:
            try:
                level, reason = answer
                escalated = _CHECK_LEVELS[str(getattr(level, "value", level))]
            except (TypeError, ValueError, KeyError):
                return RiskGrade(Risk.HIGH, REASON_CHECK_FAILED)
            grade = _higher(grade, escalated, str(reason) or REASON_WRITE)
    return grade


def grade_tool(tool_name: Any, arguments: Any) -> RiskGrade:
    """The grade of a call by its tool name (either spelling of a two-account
    name). Anything that is not a registry connector's action (a built-in, an
    MCP tool, an unknown name) is HIGH, so it is never eligible for standing
    consent."""
    from services.agent.tool_registry import resolve_tool
    from services.connectors import registry as connector_registry

    resolved = resolve_tool(tool_name) if isinstance(tool_name, str) else None
    if resolved is None or not connector_registry.is_registered(resolved.connector_type):
        return RiskGrade(Risk.HIGH, REASON_NOT_CONNECTOR)
    return grade_spec(resolved.spec, arguments)


def ref_args_of(tool_name: Any) -> tuple[str, ...]:
    """The ``ref_args`` of a registry connector's LOW-eligible action, else ()."""
    from services.agent.tool_registry import resolve_tool
    from services.connectors import registry as connector_registry

    resolved = resolve_tool(tool_name) if isinstance(tool_name, str) else None
    if resolved is None or not connector_registry.is_registered(resolved.connector_type):
        return ()
    return tuple(resolved.spec.ref_args) if low_risk_eligible(resolved.spec) else ()


# ---------------------------------------------------------------------------
# Declarations: validation and the Connectors page
# ---------------------------------------------------------------------------


def spec_problems(spec: "ToolSpec") -> list[str]:
    """What is wrong with one action's risk declarations, as registry lines
    (services/connectors/registry.py validate_registry)."""
    name = spec.action
    problems: list[str] = []
    properties = (spec.parameters or {}).get("properties", {})
    properties = properties if isinstance(properties, Mapping) else {}
    if spec.risk is not None and spec.risk != Risk.LOW.value:
        problems.append(f"action '{name}': risk may only be 'low' (or left unset)")
    if spec.risk == Risk.LOW.value:
        if spec.category != ActionCategory.WRITE:
            problems.append(f"action '{name}': only a WRITE may declare risk='low'")
        if spec.always_confirm:
            problems.append(f"action '{name}': an always_confirm action may not declare risk='low'")
        note = spec.low_risk_note.strip()
        if not note:
            problems.append(f"action '{name}': risk='low' needs a low_risk_note")
        elif len(spec.low_risk_note) > LOW_RISK_NOTE_MAX_CHARS:
            problems.append(
                f"action '{name}': low_risk_note is over {LOW_RISK_NOTE_MAX_CHARS} characters"
            )
    elif spec.low_risk_note:
        problems.append(f"action '{name}': low_risk_note is only for risk='low' actions")
    if spec.ref_args and not low_risk_eligible(spec):
        problems.append(f"action '{name}': ref_args are only for risk='low' actions")
    if len(set(spec.ref_args)) != len(spec.ref_args):
        problems.append(f"action '{name}': ref_args name an argument twice")
    for arg in spec.ref_args:
        if arg not in properties:
            problems.append(f"action '{name}': ref_arg '{arg}' is not a parameter")
    if spec.risk_check is not None and not callable(spec.risk_check):
        problems.append(f"action '{name}': risk_check must be callable")
    return problems


def low_risk_notes_for_tool(tool_name: Any) -> list[str]:
    """The low-risk notes of the connector a tool belongs to (for a grant
    card's line: what the grant would allow on that account)."""
    from services.agent.tool_registry import resolve_tool
    from services.connectors import registry as connector_registry

    resolved = resolve_tool(tool_name) if isinstance(tool_name, str) else None
    definition = (
        connector_registry.get_definition(resolved.connector_type) if resolved is not None else None
    )
    if definition is None:
        return []
    return [entry["note"] for entry in low_risk_notes(definition.actions)]


def low_risk_notes(actions: Iterable["ToolSpec"]) -> list[dict[str, str]]:
    """``[{"action", "note"}]`` for a connector's LOW-eligible actions, in
    declaration order (GET /api/connectors/types)."""
    return [
        {"action": spec.action, "note": spec.low_risk_note}
        for spec in actions
        if low_risk_eligible(spec)
    ]


# ---------------------------------------------------------------------------
# Escalate-only rule builders for ToolSpec.risk_check
# ---------------------------------------------------------------------------


def when_given(argument: str, level: str, reason: str) -> "RiskCheck":
    """Escalate when *argument* is sent with a value (not None, "" or [])."""

    def check(arguments: Mapping[str, Any]) -> Optional[tuple[str, str]]:
        value = arguments.get(argument)
        if value is None or value == "" or value == [] or value == {}:
            return None
        return level, reason

    return check


def unless_value(argument: str, allowed: Iterable[Any], level: str, reason: str) -> "RiskCheck":
    """Escalate when *argument* is sent and is not one of *allowed* (strings
    compared without case or surrounding space). Absent or None passes."""
    allowed_values = frozenset(_folded(v) for v in allowed)

    def check(arguments: Mapping[str, Any]) -> Optional[tuple[str, str]]:
        value = arguments.get(argument)
        if value is None or _folded(value) in allowed_values:
            return None
        return level, reason

    return check


def when_value(argument: str, matches: Callable[[Any], bool], level: str, reason: str) -> "RiskCheck":
    """Escalate when *argument* is sent and *matches* it."""

    def check(arguments: Mapping[str, Any]) -> Optional[tuple[str, str]]:
        value = arguments.get(argument)
        return (level, reason) if value is not None and matches(value) else None

    return check


def all_of(*checks: "RiskCheck") -> "RiskCheck":
    """Every check; the highest escalation wins (HIGH before MEDIUM)."""

    def check(arguments: Mapping[str, Any]) -> Optional[tuple[str, str]]:
        found: Optional[tuple[str, str]] = None
        for each in checks:
            answer = each(arguments)
            if answer is None:
                continue
            if found is None or _ORDER[_CHECK_LEVELS[answer[0]]] > _ORDER[_CHECK_LEVELS[found[0]]]:
                found = answer
        return found

    return check


def _folded(value: Any) -> Any:
    return value.strip().lower() if isinstance(value, str) else value


# ---------------------------------------------------------------------------
# What people read
# ---------------------------------------------------------------------------


def card_note(grade: RiskGrade) -> str:
    """The plain sentence a card carries when standing consent did not cover
    a call because of its grade."""
    return (
        f"Asking first because {grade.reason}: your standing permission for this "
        "account does not cover that."
    )


def ran_without_asking_line(runs: Iterable[tuple[str, str]]) -> str:
    """The reply line for low-risk changes a turn made with no card, built
    from facts only (tool names and account labels, never model text):
    "Done without asking (low-risk changes you allowed): 3 × google_workspace.
    modify_labels on School Gmail." Empty when nothing ran."""
    counts: Counter[tuple[str, str]] = Counter(runs)
    if not counts:
        return ""
    parts = [
        f"{count} × {tool}" + (f" on {account}" if account else "")
        for (tool, account), count in counts.items()
    ]
    return "Done without asking (low-risk changes you allowed): " + "; ".join(parts) + "."
