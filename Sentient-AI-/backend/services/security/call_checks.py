"""The pre-dispatch call checks: one ordered pipeline that every tool call passes
through in the agent turn, again when a person approves its card, and once more
as a fail-closed backstop in the executor. The checks are the security wave's
tool rules (S9), MCP tool pins (S5), browser site rules (S7), outbound message
checks (S1) and file reputation (S10), always in that order.

Why it exists: five skills each need a word on a tool call before it runs, at
the same three moments. One pipeline with one set of types (``CallFacts`` in,
``Allow``/``Note``/``Escalate``/``Refuse`` out) means the runtime and the
executor have one place to ask, one fail-closed rule for a check that breaks,
and one shape for the notes a card shows. A check can add notes for the card,
turn a call that would run without a card into a card (escalate), or refuse it
before any card. Nothing here can let a call skip a card.

Local only, like the rest of this package: no network, no model. The checks
themselves are injected by main.py (``standard_pipeline``); built without them
the pipeline is empty and costs one ``bool()`` per call. Logs and audit rows
carry check names, kinds, counts and exception type names only, never an
argument value or a note's text.

Connects to: services/agent/runtime.py (the turn and approve stages,
``park_card``), services/agent/tool_registry.py (the executor backstop),
services/agent/approvals.py and services/notifications/cards.py (notes on
approval cards), main.py (``standard_pipeline``).
"""

from __future__ import annotations

import asyncio
import re
import unicodedata
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import (
    TYPE_CHECKING,
    Any,
    Awaitable,
    Callable,
    Literal,
    Mapping,
    Optional,
    Protocol,
    Sequence,
    Union,
    cast,
)

import structlog

if TYPE_CHECKING:
    # Never at runtime: tool_registry imports the runtime, which imports this
    # module, so these are read lazily where a value is needed.
    from services.agent.permissions import ActionCategory
    from services.agent.runtime import PrecheckRefusal
    from services.connectors.definition import ToolSpec

logger = structlog.get_logger(__name__)

Stage = Literal["turn", "approve", "execute"]
Severity = Literal["high", "warn", "info"]
SEVERITIES: tuple[Severity, ...] = ("high", "warn", "info")
STAGES: frozenset[str] = frozenset({"turn", "approve", "execute"})

# The production order: S9 tool rules, S5 MCP pins, S7 site rules, S1 outbound
# message checks, S10 file reputation. Owner rules come first so a rule that
# names a tool is never hidden behind another check's refusal.
CHECK_ORDER: tuple[str, ...] = ("tool_rules", "mcp_pin", "site_rules", "outbound", "file_reputation")
# The pipeline's own failures (a bug in it): their check name and policy.
PIPELINE_CHECK = "call_check"
CHECK_FAILED_RULE = "call_check_failed"
CALL_CHECK_NAMES: frozenset[str] = frozenset({*CHECK_ORDER, PIPELINE_CHECK})

# What one card may carry: at most eight notes of one line each, and an
# escalation sentence that keeps the card's reason readable on a phone.
MAX_NOTES = 8
NOTE_TEXT_CHARS = 300
REASON_CHARS = 400
# A turn-stage check may read (S1 looks up recipients and links), so it gets
# at least this long; the approve and execute stages are backstops on a call
# a person or standing consent already let through, and must stay quick.
TURN_TIMEOUT_FLOOR_S = 10.0
BACKSTOP_TIMEOUT_S = 5.0

# Fixed texts: a check's exception can quote anything, so none of it is shown.
CHECK_FAILED_NOTE = "A safety check could not run, so Crawler is asking before this step."
CHECK_FAILED_REASON = "A safety check could not run."
CHECK_FAILED_REFUSAL = "A safety check could not run, so this was not done. Try again in a moment."
DEFAULT_EXECUTE_ESCALATION = "This needs the owner's approval first; nothing was run."
# A call whose arguments are not a JSON object (a model can send a list, and
# dict() turns a list of pairs into real arguments): no check can read it and
# S1's floor cannot clean it, so it is refused under the pipeline's own name
# before any card or dispatch (fail closed).
ARGUMENTS_NOT_OBJECT_RULE = "arguments_not_object"
ARGUMENTS_NOT_OBJECT_REFUSAL = "Tool arguments must be a JSON object."

# The note kinds the pipeline itself adds (every other kind is a skill's).
CHECK_FAILED_KIND = "check_failed"
MORE_NOTES_KIND = "more_notes"

# Built-in families the runtime answers itself during a turn (tools.find,
# tutor.*): a check that breaks on one must never turn it into a card. The
# same set as services.agent.tool_registry.RUNTIME_BUILTIN_TYPES, kept here
# because this module may not import the registry (a test holds them equal).
RUNTIME_ANSWERED_TYPES: frozenset[str] = frozenset({"tools", "tutor"})

_KIND_RE = re.compile(r"[a-z][a-z0-9_]{0,39}")
# Old severity words some specs used, mapped to the one vocabulary (A3). Any
# other unknown word reads as "warn": toward caution, never "info", so a
# misspelling can never switch off the rule that a warning card offers no
# standing consent.
_SEVERITY_ALIASES: Mapping[str, Severity] = {
    "warning": "warn",
    "medium": "warn",
    "danger": "high",
    "critical": "high",
}
# Line breaks a note's text may carry become spaces before anything else, so
# two words never run together when the controls are removed.
_LINE_BREAKS = str.maketrans({"\t": " ", "\r": " ", "\n": " ", " ": " ", " ": " "})


def _clean_note_text(text: str) -> str:
    """*text* as one plain line a card can show: line breaks as spaces, every
    control and format character removed (bidi controls, zero-width
    characters, U+FEFF, tag characters: a note can quote an address an
    attacker wrote), whitespace runs as one space, at most NOTE_TEXT_CHARS."""
    spaced = text.translate(_LINE_BREAKS)
    visible = "".join(ch for ch in spaced if unicodedata.category(ch) not in ("Cc", "Cf"))
    line = " ".join(visible.split())
    if len(line) > NOTE_TEXT_CHARS:
        line = line[: NOTE_TEXT_CHARS - 1].rstrip() + "…"
    return line


def _severity_of(value: Any, kind: str) -> Severity:
    word = value.strip().lower() if isinstance(value, str) else ""
    if word in SEVERITIES:
        return cast(Severity, word)
    alias = _SEVERITY_ALIASES.get(word)
    if alias is not None:
        return alias
    logger.warning("security_note_severity_unknown", kind=kind)
    return "warn"


@dataclass(frozen=True)
class SecurityNote:
    """One line an approval card shows about a call: what a check noticed.

    ``kind`` names it for code and audit rows (``recipient_first_time``);
    ``severity`` is "high", "warn" or "info"; ``text`` is one line of at most
    NOTE_TEXT_CHARS that names hosts or addresses at most, never message
    text and never model text."""

    kind: str
    severity: Severity
    text: str

    def to_dict(self) -> dict[str, str]:
        return {"kind": self.kind, "severity": self.severity, "text": self.text}

    @classmethod
    def from_value(cls, value: Any) -> Optional["SecurityNote"]:
        """A stored or caller-given note, normalised; None for anything that
        is not a note (no kind of the right shape, no text).

        Severity goes through ``_SEVERITY_ALIASES`` ("warning" and "medium"
        read as "warn", "danger" and "critical" as "high"); any other unknown
        value reads as "warn" with one ``security_note_severity_unknown`` log
        line. The text loses its line breaks, control and format characters
        and extra whitespace, and is capped at NOTE_TEXT_CHARS."""
        kind: Any
        severity: Any
        text: Any
        if isinstance(value, SecurityNote):
            kind, severity, text = value.kind, value.severity, value.text
        elif isinstance(value, Mapping):
            kind, severity, text = value.get("kind"), value.get("severity"), value.get("text")
        else:
            return None
        if not isinstance(kind, str) or not _KIND_RE.fullmatch(kind):
            return None
        if not isinstance(text, str):
            return None
        line = _clean_note_text(text)
        if not line:
            return None
        return cls(kind=kind, severity=_severity_of(severity, kind), text=line)


def _normalised(values: Any) -> list[SecurityNote]:
    """Every note in *values* (a list or tuple of notes or note dicts),
    normalised, bad items dropped, the same (kind, text) kept once."""
    if not isinstance(values, (list, tuple)):
        return []
    out: list[SecurityNote] = []
    seen: set[tuple[str, str]] = set()
    for item in values:
        note = SecurityNote.from_value(item)
        if note is None or (note.kind, note.text) in seen:
            continue
        seen.add((note.kind, note.text))
        out.append(note)
    return out


def notes_from(value: Any, *, limit: int = MAX_NOTES) -> list[dict[str, str]]:
    """Validated note dicts from a stored column or a caller (bad items
    dropped, repeats kept once, at most *limit*). Anything that is not a list
    of notes (NULL, a corrupt row) gives no notes."""
    return [note.to_dict() for note in _normalised(value)[: max(0, limit)]]


def has_warnings(notes: Any) -> bool:
    """Whether *notes* (stored dicts or ``SecurityNote`` objects) hold any
    note of severity high or warn. Such a card offers no standing consent:
    neither "Allow for 7 days" nor "Allow low-risk changes" (A18)."""
    return any(note.severity in ("high", "warn") for note in _normalised(notes))


@dataclass
class TurnFacts:
    """What a turn-stage check may read about the turn a call came from.

    ``messages`` is the turn's message list as the model saw it this round;
    ``taint`` is the turn's ``TaintTracker``; ``trusted_text`` an unattended
    run's own approved prompt ("" otherwise); ``scratch`` per-turn state each
    check keeps under its own name (shared by every call of the turn, so a
    check reads its switch or snapshot once per turn)."""

    messages: Sequence[Mapping[str, Any]]
    taint: Any
    trusted_text: str = ""
    unattended: bool = False
    conversation_id: Optional[str] = None
    scratch: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class CallFacts:
    """One tool call as every check sees it, at one stage.

    ``arguments`` are the model's (placeholders restored) at the turn stage,
    the stored card arguments at approve (reserved "_" keys included), and the
    dispatched arguments at execute. ``turn`` is set only inside a turn: at
    stage "turn" it is None in ``AgentRuntime.park_card``, and a check then
    behaves as at "execute" for anything that needs the turn, and never
    raises because of it."""

    stage: Stage
    user_id: str
    tool_name: str  # as called (may carry "__<slug>")
    canonical: str  # canonical_tool_name(tool_name): "google_workspace.send_email"
    arguments: Mapping[str, Any]
    spec: Optional["ToolSpec"] = None  # None for MCP tools and unknown names
    is_mcp: bool = False
    person_approved: bool = False  # approve: True; execute: approved and no standing consent
    runs_without_card: bool = False  # turn: would run unasked (A29); execute: not person_approved
    will_card: bool = False  # turn: the call goes to a card before any escalation
    unattended: bool = False
    task_id: Optional[str] = None
    approval: Optional[str] = None  # execute: the standing-consent kind ("tier", "low_risk", ...)
    origin: Optional[str] = None  # park_card's origin ("mailcheck:<id>", "file_check:<id>")
    turn: Optional[TurnFacts] = None

    @property
    def approved(self) -> bool:
        """``person_approved`` under the name S7 uses."""
        return self.person_approved

    @property
    def category(self) -> Optional["ActionCategory"]:
        return self.spec.category if self.spec is not None else None

    @property
    def is_read(self) -> bool:
        """A non-MCP READ (built-in reads included)."""
        from services.agent.permissions import ActionCategory

        return not self.is_mcp and self.category == ActionCategory.READ


@dataclass(frozen=True)
class Allow:
    """Nothing to add: the call goes on as it would have."""


@dataclass(frozen=True)
class Note:
    """Notes for the call's card; the call goes on as it would have."""

    notes: tuple[SecurityNote, ...]


@dataclass(frozen=True)
class Escalate:
    """The call must not run without a card. ``reason`` is one sentence
    appended to the card's reason (A19). ``rule`` names rule ids for audit
    rows ("builtin:many_recipients,owner:<uuid>"). ``refusal_text`` is what
    the executor answers for an unapproved call (A20). ``names_rule``: True
    when the sentence names a rule and so always goes on the card (S9);
    False when it only explains why an auto-run call now asks, and goes on
    the card only when the call really would have run without one (A29)."""

    notes: tuple[SecurityNote, ...]
    reason: str
    rule: str = ""
    refusal_text: str = ""
    names_rule: bool = False


@dataclass(frozen=True)
class Refuse:
    """The call is refused before any card. ``message`` is fixed text the
    model and the owner read. ``audit_event`` names an extra row the
    pipeline writes with ``audit_facts`` (kinds, counts, keyed hashes only)."""

    rule: str
    message: str
    policy: Optional[str] = None  # defaults to the check's policy
    audit_event: Optional[str] = None
    audit_facts: Optional[Mapping[str, Any]] = None


Verdict = Union[Allow, Note, Escalate, Refuse]
ALLOW = Allow()


class CallCheck(Protocol):
    """One check of the pipeline. ``applies_to`` is cheap and does no I/O;
    ``check`` never rewrites arguments, never raises on purpose, and refuses
    only for its own rules."""

    name: str  # one of CHECK_ORDER
    policy: str  # recorded on refusal and escalation rows (A28)
    stages: frozenset[str]
    timeout_s: float

    def applies_to(self, call: CallFacts) -> bool: ...

    async def check(self, call: CallFacts) -> Verdict: ...


@dataclass(frozen=True)
class Escalation:
    """One check's escalation, as the runtime files it."""

    check: str
    policy: str
    reason: str
    rule: str
    refusal_text: str
    names_rule: bool = False


@dataclass(frozen=True)
class Refusal:
    """The check that refused a call, and what the model and owner read."""

    check: str
    policy: str
    rule: str
    message: str

    def result(self) -> dict[str, Any]:
        """What the model is shown as the call's result, and what the
        executor answers (``call_check_refusal`` recognises it)."""
        return {
            "ok": False,
            "refused": True,
            "call_check": self.check,
            "policy": self.policy,
            "rule": self.rule,
            "error": self.message,
        }

    def precheck(self) -> "PrecheckRefusal":
        """The runtime's ``PrecheckRefusal`` for this refusal, filed like any
        rule refusing a call before its card."""
        from services.agent.runtime import PrecheckRefusal

        return PrecheckRefusal(
            reason=self.message, policy=self.policy, result=self.result(), rule=self.rule
        )


def arguments_not_object() -> Refusal:
    """The refusal of a call whose arguments are not a JSON object, in the
    pipeline's own name. The runtime files it before any card (a turn, an
    approval, ``park_card``) and the executor answers it before its backstop,
    so ``call_check_refusal`` reads it as a block, never as a call that ran."""
    return Refusal(
        check=PIPELINE_CHECK,
        policy=PIPELINE_CHECK,
        rule=ARGUMENTS_NOT_OBJECT_RULE,
        message=ARGUMENTS_NOT_OBJECT_REFUSAL,
    )


def _unique(values: Sequence[str]) -> list[str]:
    return [value for value in dict.fromkeys(values) if value]


def _join_capped(sentences: Sequence[str], limit: int) -> str:
    """*sentences* joined by one space, whole sentences only while they fit
    in *limit* characters; a first sentence longer than that is cut."""
    out = ""
    for sentence in sentences:
        joined = f"{out} {sentence}" if out else sentence
        if len(joined) <= limit:
            out = joined
        elif not out:
            return sentence[: limit - 1].rstrip() + "…"
        else:
            break
    return out


@dataclass(frozen=True)
class CheckOutcome:
    """What the pipeline found for one call at one stage."""

    notes: tuple[SecurityNote, ...] = ()
    escalations: tuple[Escalation, ...] = ()
    refusal: Optional[Refusal] = None
    failed: tuple[str, ...] = ()  # checks that raised or timed out

    @property
    def escalated(self) -> bool:
        return bool(self.escalations)

    @property
    def warns(self) -> bool:
        """Any high or warn note: the card offers no standing consent (A18)."""
        return has_warnings(self.notes)

    def reason_suffix(self, *, auto_run: bool) -> str:
        """The escalation sentences a card's reason gains (A19): every
        sentence that names a rule, plus the ones that only explain why an
        auto-run call now asks when *auto_run* (the call really would have
        run without a card, A29). Each sentence once, joined by one space,
        at most REASON_CHARS."""
        sentences = [
            e.reason.strip() for e in self.escalations if e.names_rule or auto_run
        ]
        return _join_capped(_unique(sentences), REASON_CHARS)

    def rule(self) -> str:
        """The escalations' rule ids, joined by ","."""
        return ",".join(_unique([e.rule for e in self.escalations]))

    def note_dicts(self) -> list[dict[str, str]]:
        return [note.to_dict() for note in self.notes]

    def note_kinds(self) -> list[str]:
        return [note.kind for note in self.notes]

    def audit_fields(self) -> dict[str, Any]:
        """What a ``tool_pending_approval`` row adds: the escalations' rule
        ids and the notes' kinds, each only when there is one (never a
        note's text)."""
        fields: dict[str, Any] = {}
        rule = self.rule()
        if rule:
            fields["rule"] = rule
        kinds = self.note_kinds()
        if kinds:
            fields["note_kinds"] = kinds
        return fields

    def execute_result(self) -> Optional[dict[str, Any]]:
        """The executor's answer when the backstop stops a call: the
        refusal's result; for an escalation, a ``requires_approval`` answer
        naming the check, its policy and rule, and its fixed text (A20);
        None when the call may be dispatched."""
        if self.refusal is not None:
            return self.refusal.result()
        if not self.escalations:
            return None
        first = self.escalations[0]
        return {
            "ok": False,
            "requires_approval": True,
            "call_check": first.check,
            "policy": first.policy,
            "rule": self.rule() or first.rule,
            "error": first.refusal_text or DEFAULT_EXECUTE_ESCALATION,
        }


EMPTY_OUTCOME = CheckOutcome()
AuditSink = Callable[[dict[str, Any]], Awaitable[None]]


class _BadVerdict(Exception):
    """A check answered something that is not a verdict (a bug): handled
    like a check that raised."""


def _runtime_answered(canonical: str) -> bool:
    return canonical.partition(".")[0] in RUNTIME_ANSWERED_TYPES


def _ordered_notes(notes: Sequence[SecurityNote]) -> tuple[SecurityNote, ...]:
    """*notes* without repeats, ordered by severity (high, warn, info) and
    then by the order the checks gave them, capped at MAX_NOTES; when more
    were dropped, the last kept note says how many."""
    unique = _normalised(list(notes))
    rank = {severity: index for index, severity in enumerate(SEVERITIES)}
    unique.sort(key=lambda note: rank[note.severity])  # stable: check order holds
    if len(unique) <= MAX_NOTES:
        return tuple(unique)
    hidden = len(unique) - (MAX_NOTES - 1)
    more = SecurityNote(MORE_NOTES_KIND, "info", f"and {hidden} more security notes")
    return (*unique[: MAX_NOTES - 1], more)


@dataclass
class _Run:
    """What one run gathers before it becomes a ``CheckOutcome``."""

    notes: list[SecurityNote] = field(default_factory=list)
    escalations: list[Escalation] = field(default_factory=list)
    refusal: Optional[Refusal] = None
    failed: list[str] = field(default_factory=list)

    def outcome(self) -> CheckOutcome:
        if not (self.notes or self.escalations or self.refusal or self.failed):
            return EMPTY_OUTCOME
        return CheckOutcome(
            notes=_ordered_notes(self.notes),
            escalations=tuple(self.escalations),
            refusal=self.refusal,
            failed=tuple(self.failed),
        )


class CallCheckPipeline:
    """The checks, in CHECK_ORDER, and how one call is run through them
    (``run``). Empty unless main.py (or a test) gives it checks."""

    def __init__(self, checks: Sequence[CallCheck] = (), *, audit: Optional[AuditSink] = None) -> None:
        """Raises ValueError for a check named outside CHECK_ORDER, a
        duplicate, or checks out of CHECK_ORDER's order: the order is the
        contract every skill codes against."""
        names = [getattr(check, "name", None) for check in checks]
        for name in names:
            if name not in CHECK_ORDER:
                raise ValueError(f"unknown call check {name!r}; the order is {CHECK_ORDER}")
        if len(set(names)) != len(names):
            raise ValueError(f"a call check is listed twice: {names}")
        positions = [CHECK_ORDER.index(str(name)) for name in names]
        if positions != sorted(positions):
            raise ValueError(f"call checks out of order: {names}; the order is {CHECK_ORDER}")
        self._checks: tuple[CallCheck, ...] = tuple(checks)
        self._audit = audit

    @property
    def names(self) -> tuple[str, ...]:
        return tuple(check.name for check in self._checks)

    def __bool__(self) -> bool:
        return bool(self._checks)

    async def run(self, call: CallFacts) -> CheckOutcome:
        """Run *call* through every check that covers its stage and applies
        to it, in order. Never raises: a check that raises or times out is
        handled by stage (see ``_failed``), and so is a bug in the pipeline
        itself, as a failure of ``call_check``."""
        if not self._checks:
            return EMPTY_OUTCOME
        gathered = _Run()
        try:
            for check in self._checks:
                if call.stage not in check.stages:
                    continue
                try:
                    applies = bool(check.applies_to(call))
                except Exception as exc:
                    # Cheap and pure by contract; one that breaks is asked anyway.
                    logger.warning(
                        "call_check_applies_failed",
                        check=check.name,
                        stage=call.stage,
                        error_type=type(exc).__name__,
                    )
                    applies = True
                if not applies:
                    continue
                timeout = (
                    max(float(check.timeout_s), TURN_TIMEOUT_FLOOR_S)
                    if call.stage == "turn"
                    else BACKSTOP_TIMEOUT_S
                )
                try:
                    verdict = await asyncio.wait_for(check.check(call), timeout)
                    if not isinstance(verdict, (Allow, Note, Escalate, Refuse)):
                        raise _BadVerdict(type(verdict).__name__)
                except Exception as exc:
                    if self._failed(gathered, call, check.name, check.policy, exc):
                        break
                    continue
                if await self._apply(gathered, call, check, verdict):
                    break
        except Exception as exc:  # a bug in the pipeline itself
            # A refusal already found stands; otherwise the bug is handled
            # like a check that broke, under the pipeline's own name.
            if gathered.refusal is None:
                self._failed(gathered, call, PIPELINE_CHECK, PIPELINE_CHECK, exc)
        return gathered.outcome()

    def _failed(
        self, gathered: _Run, call: CallFacts, name: str, policy: str, exc: Exception
    ) -> bool:
        """Handle a check that raised or timed out; True when the run stops.

        - turn: a READ or a call the runtime answers itself goes on with
          nothing added (a stalled check must never turn a page read into a
          card); a call that would run without a card is escalated with the
          fixed reason and a warn note; any other gets the note only.
        - approve: refused (a person just approved; fail closed).
        - execute: a non-MCP READ goes on (internal reads keep working);
          anything else is refused."""
        logger.warning(
            "call_check_failed", check=name, stage=call.stage, error_type=type(exc).__name__
        )
        gathered.failed.append(name)
        if call.stage == "turn":
            if call.is_read or _runtime_answered(call.canonical):
                return False
            gathered.notes.append(SecurityNote(CHECK_FAILED_KIND, "warn", CHECK_FAILED_NOTE))
            if call.runs_without_card:
                gathered.escalations.append(
                    Escalation(
                        check=name,
                        policy=policy,
                        reason=CHECK_FAILED_REASON,
                        rule=CHECK_FAILED_RULE,
                        refusal_text="",
                        names_rule=False,
                    )
                )
            return False
        if call.stage == "execute" and call.is_read:
            return False
        gathered.refusal = Refusal(name, PIPELINE_CHECK, CHECK_FAILED_RULE, CHECK_FAILED_REFUSAL)
        return True

    async def _apply(
        self, gathered: _Run, call: CallFacts, check: CallCheck, verdict: Verdict
    ) -> bool:
        """Fold one verdict into *gathered*; True when the run stops (a
        refusal). Notes count only at the turn stage; an escalation counts at
        the turn stage, and at execute for a call no person approved."""
        if isinstance(verdict, Allow):
            return False
        if isinstance(verdict, Note):
            if call.stage == "turn":
                gathered.notes.extend(_as_notes(verdict.notes))
            return False
        if isinstance(verdict, Escalate):
            if call.stage == "approve" or (call.stage == "execute" and call.person_approved):
                return False
            if call.stage == "turn":
                gathered.notes.extend(_as_notes(verdict.notes))
            gathered.escalations.append(
                Escalation(
                    check=check.name,
                    policy=check.policy,
                    reason=verdict.reason,
                    rule=verdict.rule,
                    refusal_text=verdict.refusal_text,
                    names_rule=verdict.names_rule,
                )
            )
            return False
        refusal = Refusal(
            check=check.name,
            policy=verdict.policy or check.policy,
            rule=verdict.rule,
            message=verdict.message,
        )
        gathered.refusal = refusal
        if verdict.audit_event:
            await self._write_refusal_row(call, refusal, verdict)
        return True

    async def _write_refusal_row(self, call: CallFacts, refusal: Refusal, verdict: Refuse) -> None:
        """The refusing check's own audit row (S7's site_rule_blocked): best
        effort, logged by type; the refusal stands either way."""
        if self._audit is None:
            return
        try:
            await self._audit(
                {
                    "event": verdict.audit_event,
                    "user_id": call.user_id,
                    "tool": call.canonical,
                    "policy": refusal.policy,
                    "rule": refusal.rule,
                    "arguments": dict(verdict.audit_facts or {}),
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                }
            )
        except Exception as exc:
            logger.error(
                "audit_write_failed_call_check",
                check=refusal.check,
                error_type=type(exc).__name__,
            )


def _as_notes(values: Any) -> list[SecurityNote]:
    """A verdict's notes, normalised (a check may give note dicts)."""
    if isinstance(values, (SecurityNote, Mapping)):
        values = [values]
    return _normalised(list(values) if isinstance(values, (list, tuple)) else [])


def standard_pipeline(
    *,
    tool_rules: Optional[CallCheck] = None,
    mcp_pin: Optional[CallCheck] = None,
    site_rules: Optional[CallCheck] = None,
    outbound: Optional[CallCheck] = None,
    file_reputation: Optional[CallCheck] = None,
    audit: Optional[AuditSink] = None,
) -> CallCheckPipeline:
    """The production pipeline in CHECK_ORDER, leaving out the checks given
    as None (main.py builds it once and hands the same object to the runtime
    and the executor)."""
    checks = [
        check
        for check in (tool_rules, mcp_pin, site_rules, outbound, file_reputation)
        if check is not None
    ]
    return CallCheckPipeline(checks, audit=audit)


def call_check_refusal(result: Any) -> Optional[tuple[str, str, str]]:
    """``(reason, policy, rule)`` when *result* is the executor's backstop
    refusing a call or asking for a card first (``Refusal.result`` or
    ``CheckOutcome.execute_result``), else None. The runtime files it as a
    ``tool_blocked`` row, as it files a capability refusal."""
    if not isinstance(result, Mapping) or result.get("ok") is not False:
        return None
    if result.get("call_check") not in CALL_CHECK_NAMES:
        return None
    if result.get("refused") is not True and result.get("requires_approval") is not True:
        return None
    reason = result.get("error")
    policy = result.get("policy")
    rule = result.get("rule")
    return (
        reason if isinstance(reason, str) and reason else CHECK_FAILED_REFUSAL,
        policy if isinstance(policy, str) and policy else PIPELINE_CHECK,
        rule if isinstance(rule, str) else "",
    )
