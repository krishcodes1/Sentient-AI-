"""Outbound message checks (security S1): the hidden-character floor the
executor applies to every write, and the call check that looks at an outgoing
message's recipients and links before its card.

Why it exists: a prompt injection that gets a message sent can hide text a
reader never sees (tag characters, bidi overrides) or send it somewhere the
owner never meant. The floor (``OutboundFloor``) cleans what can be cleaned at
the card and again at dispatch, so no card shows text the owner cannot see and
nothing hidden reaches another person; the check (``OutboundCheck``, slot 4 of
services/security/call_checks.py) puts the facts on the card (first time
Crawler sends there, outside the organisation, a look-alike address, who a
reply or a draft really goes to, links that can carry data out), and turns a
flagged call that would have run without a card into a card. Nothing is
rewritten except the hidden-character floor, and S1 never removes a card.

What it decides, by stage (S1 design 4.4, scaffold D1/D2):
- every stage: a recipient address that hides characters is refused before
  any card (stripping it would silently change who receives the mail);
- turn: the floor note, then (switch on) kept invisibles, S1's own link
  findings, S4's link lookup of ``scheme://host/`` only, and the recipient
  facts (at most two READs through the executor, one history SELECT); the
  whole check is bounded at 9 s and an unfinished part says "not checked";
- approve: pure; only the refusal counts (a person just approved);
- execute: pure; a call no person approved is escalated when the floor
  removed something or a link finding is local and certain.

Privacy: notes name hosts and addresses only (addresses through
``note_address``), never message text; logs and audit rows carry kinds,
counts and exception type names only. The sent-to history keeps keyed
fingerprints (services/security/outbound_store.py).

Connects to: services/agent/tool_registry.py (the executor's floor, its binds
and its send hooks), services/security/call_checks.py (the check),
services/security/outbound_text.py and outbound_recipients.py (the pure
parts), services/security/outbound_store.py (history, organisation domains,
sign-in addresses), services/security/link_checks.py (S4's ``LinkChecker``),
main.py (wiring).
"""

from __future__ import annotations

import asyncio
import re
import time
from collections import OrderedDict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from types import MappingProxyType
from typing import (
    TYPE_CHECKING,
    Any,
    Awaitable,
    Callable,
    Iterable,
    Mapping,
    Optional,
    Sequence,
)

import structlog

from services.security import link_checks
from services.security.call_checks import (
    ALLOW,
    NOTE_TEXT_CHARS,
    CallFacts,
    Escalate,
    Note,
    Refuse,
    SecurityNote,
    Verdict,
)
from services.security.outbound_recipients import (
    OrgView,
    Recipient,
    address_concern,
    classify,
    normalize_address,
    note_address,
    org_view,
    parse_recipients,
)
from services.security.outbound_text import (
    SCAN_LINK_LIMIT,
    STRIP_KINDS,
    ExfilFinding,
    FoundLink,
    clean_safe_subset,
    clean_text,
    exfil_findings,
    find_links,
    hidden_count,
    hides_characters_in_address,
    origin_only,
)

if TYPE_CHECKING:
    from services.connectors.definition import ToolSpec
    from services.security.outbound_store import (
        KnownRecipientStore,
        OrganisationDomainStore,
        UserEmails,
    )

logger = structlog.get_logger(__name__)

CHECK_NAME = "outbound"
OUTBOUND_RULE_POLICY = "outbound_rule"
HIDDEN_IN_RECIPIENT_RULE = "hidden_characters_in_recipient"
# Arguments the floor cannot clean (nested past MAX_ARGUMENT_DEPTH, or two
# names that differ only by hidden characters): refused, fail closed.
UNCHECKABLE_RULE = "arguments_not_checkable"
CLEANED_EVENT = "outbound_cleaned"
ESCALATE_REASON = (
    "Crawler would have done this without asking, but its outgoing-message check "
    "found something to look at."
)
# What the executor answers when its backstop stops a call no person approved
# (scaffold A20).
EXECUTE_REFUSAL = (
    "Crawler's outgoing-message check found something to look at, so this needs the "
    "owner's approval first; nothing was sent."
)
# The READs S1 makes through the executor, by connector type (pinned to the
# call's own row by reusing its namespace, e.g.
# "google_workspace__1a2b3c4d.get_draft"). One constant: a rename is one edit.
MAIL_FACTS_ACTION: Mapping[str, str] = {
    "google_workspace": "get_message_security",
    "microsoft": "get_message_security",
}
DRAFT_ACTION: Mapping[str, str] = {"google_workspace": "get_draft"}
SENT_PROBE: Mapping[str, tuple[str, dict[str, Any]]] = {
    "google_workspace": ("get_messages", {"query": "in:sent", "max_results": 1}),
    "microsoft": ("list_messages", {"folder": "sentitems", "limit": 1}),
}

# Content arguments that hold a file's bytes as text: one byte order mark at
# position 0 is part of the file, not smuggling (S1 design 4.5).
FILE_CONTENT_PATHS: Mapping[str, frozenset[str]] = {
    "slack.upload_file": frozenset({"content"}),
    "github.put_file": frozenset({"content"}),
    "github.create_gist": frozenset({"content"}),
}
# Sends whose connector result already names who it went to (gmail.py's reply
# returns "to" and "cc"), so no READ is needed before them.
_RESULT_NAMES_RECIPIENTS = frozenset({"google_workspace.reply"})

# Caps (S1 design 4.4 A7, 4.8).
MAX_S1_NOTES = 6
ADDRESSES_PER_NOTE = 5
RECIPIENTS_LOOKED_AT = 50
LINK_NOTES = 3
LINKS_LOOKED_AT = 50
LINKS_FOR_LOOKUP = 20
# Time limits, in seconds. The check bounds itself below its own timeout_s so
# a part that did not finish can still say "not checked".
CHECK_TIMEOUT_S = 9.0
CHECK_BUDGET_S = 8.5
READ_TIMEOUT_S = 6.0
PROBE_TIMEOUT_S = 4.0
HISTORY_TIMEOUT_S = 3.0
LINKS_TIMEOUT_S = 4.0
SEND_READ_TIMEOUT_S = 4.0
# In-memory caches (S1 design 4.8).
ACCOUNT_FOUND_S = 12 * 3600.0
ACCOUNT_MISSING_S = 3600.0
ACCOUNT_CACHE_SIZE = 1000
FACTS_TTL_S = 600.0
FACTS_CACHE_SIZE = 200
# Arguments nested deeper than this are refused by the floor (fail closed):
# no real tool takes them, and a walk must never blow the stack.
MAX_ARGUMENT_DEPTH = 64

_FIELD_NAME_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_.\-]{0,63}")
_GENERIC_FIELD = "argument"
_MCP_FIELD = "arguments"

_SEVERITY_RANK = {"high": 0, "warn": 1, "info": 2}
# Within one severity: hidden characters, then links, then recipients.
_HIDDEN, _LINKS, _RECIPIENTS = 0, 1, 2

_KIND_WORDS: Mapping[str, tuple[str, str]] = {
    "tag": ("tag character", "tag characters"),
    "bidi": ("text-direction control", "text-direction controls"),
    "zero_width_run": ("zero-width character", "zero-width characters"),
    "extra_variation": ("variation selector", "variation selectors"),
}

# Why a READ did not answer, as a note says it.
_WHY_NO_SCOPE = "this account does not allow reading mail"
_WHY_TIMEOUT = "reading it took too long"
_WHY_SETTING = "a setting it needs is turned off"
_WHY_ACCOUNT = "the account was turned off or removed"
_WHY_SIGN_IN = "the sign-in needs to be renewed in Connectors"
_WHY_OTHER = "the mail service did not answer"
_WHY_NOT_FOUND = "it is no longer there"
_WHY_GONE_MESSAGE = "the original message is no longer there"

# The rule each provider applies to a reply (gmail.py _REPLY_TARGET; Graph
# picks server-side for Outlook).
_GMAIL_REPLY_RULE = (
    "Gmail will send it to the original's Reply-To address, or its From address if it has "
    "none (for mail you sent, to its original To recipients)"
)
_OUTLOOK_REPLY_RULE = "Outlook will send it to the original's sender, or its Reply-To address"


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _plural(count: int, one: str, many: str) -> str:
    return f"{count} {one if count == 1 else many}"


def _joined(items: Sequence[str]) -> str:
    """ "a", "a and b", "a, b and c"."""
    if len(items) <= 1:
        return "".join(items)
    return ", ".join(items[:-1]) + " and " + items[-1]


def _canonical(tool_name: str) -> str:
    from services.agent.runtime import canonical_tool_name

    return canonical_tool_name(tool_name)


def _is_mcp(tool_name: str) -> bool:
    from services.mcp.integration import is_mcp_tool

    return is_mcp_tool(tool_name)


def _is_read(spec: Optional["ToolSpec"]) -> bool:
    from services.connectors.definition import ActionCategory

    return spec is not None and spec.category == ActionCategory.READ


def _spec_of(tool_name: str) -> Optional["ToolSpec"]:
    from services.agent.tool_registry import resolve_tool

    resolved = resolve_tool(tool_name)
    return resolved.spec if resolved is not None else None


# ---------------------------------------------------------------------------
# Which fields leave the account
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class OutboundFields:
    """Which arguments of one call leave the account (from ``ToolSpec.outbound``,
    or every string leaf of an MCP call, floor only)."""

    content: tuple[str, ...]
    recipients: tuple[str, ...]
    resolve: Optional[str]  # "reply" | "draft"
    delivers: bool  # False for a draft (saved, not sent)
    history: bool  # record recipients after a successful send
    every_string: bool = False  # MCP: every string leaf, floor only


_MCP_FIELDS = OutboundFields(
    content=(), recipients=(), resolve=None, delivers=True, history=False, every_string=True
)


def outbound_fields(tool_name: str, spec: Optional["ToolSpec"]) -> Optional[OutboundFields]:
    """The call's outbound fields: ``ToolSpec.outbound`` as declared, every
    string leaf for an MCP tool (``every_string``), None otherwise."""
    if _is_mcp(tool_name):
        return _MCP_FIELDS
    out = spec.outbound if spec is not None else None
    if out is None:
        return None
    return OutboundFields(
        content=tuple(out.content),
        recipients=tuple(out.recipients),
        resolve=out.resolve,
        delivers=bool(out.delivers),
        history=bool(out.history),
    )


def _under(path: str, roots: Iterable[str]) -> Optional[str]:
    """The declared path *path* is (or lies under), or None."""
    for root in roots:
        if path == root or path.startswith(root + "."):
            return root
    return None


def _values_at(arguments: Mapping[str, Any], path: str) -> list[Any]:
    """Every value at dotted *path* (a list on the way is read element by
    element, as a path naming a list covers what is inside it)."""
    current: list[Any] = [arguments]
    for segment in path.split("."):
        found: list[Any] = []
        for value in current:
            items = value if isinstance(value, (list, tuple)) else [value]
            for item in items:
                if isinstance(item, Mapping) and segment in item:
                    found.append(item[segment])
        current = found
        if not current:
            break
    return current


def _refusal_text(path: str) -> str:
    field_name = path.rsplit(".", 1)[-1]
    return (
        f"Refused: the '{field_name}' address contains hidden characters, which can make an "
        "address look like a different one. Write the address again in plain text; nothing "
        "was sent."
    )


def _refusal(path: str) -> dict[str, Any]:
    """The floor's refusal, in the call-check shape (scaffold A22), so the
    runtime files it as tool_blocked under outbound_rule."""
    return {
        "ok": False,
        "refused": True,
        "call_check": CHECK_NAME,
        "policy": OUTBOUND_RULE_POLICY,
        "rule": HIDDEN_IN_RECIPIENT_RULE,
        "error": _refusal_text(path),
    }


# ---------------------------------------------------------------------------
# The floor
# ---------------------------------------------------------------------------


class _Unclean(ValueError):
    """Arguments the floor cannot clean: nested deeper than
    MAX_ARGUMENT_DEPTH, or with two names that are the same once their hidden
    characters are removed. The call is refused (fail closed)."""


@dataclass
class _Scan:
    """One pass of the floor over a call's arguments."""

    arguments: Mapping[str, Any]
    removed: dict[str, int] = field(default_factory=dict)
    fields: list[str] = field(default_factory=list)
    kept: dict[str, int] = field(default_factory=dict)
    # (field, cleaned text) of every string the full rules cleaned (declared
    # content and MCP leaves): what the link checks read.
    content: list[tuple[str, str]] = field(default_factory=list)
    hiding: Optional[str] = None  # the recipient path that hides characters


class _Walker:
    """Rebuilds a call's arguments with every string leaf cleaned by the rule
    its path calls for, copying only what changed."""

    def __init__(
        self,
        scan: _Scan,
        *,
        every_string: bool,
        content: Sequence[str],
        recipients: Sequence[str],
        file_paths: frozenset[str],
        known_keys: Optional[frozenset[str]],
    ) -> None:
        self.scan = scan
        self.every_string = every_string
        self.content = content
        self.recipients = recipients
        self.file_paths = file_paths
        self.known_keys = known_keys

    def _label(self, path: str, declared: Optional[str]) -> str:
        if self.every_string:
            return _MCP_FIELD
        if declared is not None:
            return declared
        top = path.split(".", 1)[0]
        if self.known_keys is not None and top in self.known_keys and _FIELD_NAME_RE.fullmatch(top):
            return top
        return _GENERIC_FIELD

    def _string(self, value: str, path: str) -> str:
        declared = _under(path, self.content)
        if self.every_string or declared is not None:
            result = clean_text(value, file_content=declared in self.file_paths)
            label = self._label(path, declared)
            if result.kept:
                self.scan.kept[label] = self.scan.kept.get(label, 0) + result.kept
            self.scan.content.append((label, result.text))
        elif _under(path, self.recipients) is not None:
            return value  # refused instead when it hides anything (_Floor)
        else:
            result = clean_safe_subset(value)
        if not result.removed:
            return value
        for kind, count in result.removed.items():
            self.scan.removed[kind] = self.scan.removed.get(kind, 0) + count
        label = self._label(path, declared)
        if label not in self.scan.fields:
            self.scan.fields.append(label)
        return result.text

    def _key(self, key: Any, path: str) -> Any:
        """An argument name without tag characters and bidi controls: a name
        reaches an MCP server, a card and a nested object (Notion properties,
        calendar fields) as text too, and a name with hidden characters must
        not slip past the declared paths."""
        if not isinstance(key, str):
            return key
        result = clean_safe_subset(key)
        if not result.removed:
            return key
        for kind, count in result.removed.items():
            self.scan.removed[kind] = self.scan.removed.get(kind, 0) + count
        child = f"{path}.{result.text}" if path else result.text
        label = self._label(child, _under(child, self.content))
        if label not in self.scan.fields:
            self.scan.fields.append(label)
        return result.text

    def mapping(
        self, value: Mapping[Any, Any], path: str, depth: int, *, skip_reserved: bool
    ) -> Any:
        out: dict[Any, Any] = {}
        changed = False
        for key, item in value.items():
            if skip_reserved and isinstance(key, str) and key.startswith("_"):
                # Reserved keys are set by binds, never sent as text: a
                # connector method refuses an argument it does not take.
                out[key] = item
                continue
            name = self._key(key, path)
            if name is not key:
                if name in value or name in out:
                    raise _Unclean(
                        "two argument names are the same without their hidden characters"
                    )
                changed = True
            child = f"{path}.{name}" if path else str(name)
            new = self.walk(item, child, depth + 1)
            changed = changed or new is not item
            out[name] = new
        return out if changed else value

    def walk(self, value: Any, path: str, depth: int) -> Any:
        if depth > MAX_ARGUMENT_DEPTH:
            raise _Unclean("arguments nested too deeply")
        if isinstance(value, str):
            return self._string(value, path)
        if isinstance(value, Mapping):
            return self.mapping(value, path, depth, skip_reserved=False)
        if isinstance(value, (list, tuple)):
            items = [self.walk(item, path, depth + 1) for item in value]
            if all(new is old for new, old in zip(items, value, strict=True)):
                return value
            return items if isinstance(value, list) else tuple(items)
        return value


def _scan(
    tool_name: str,
    spec: Optional["ToolSpec"],
    arguments: Mapping[str, Any],
    *,
    is_mcp: Optional[bool] = None,
) -> _Scan:
    """The floor over one call: full rules on declared content and MCP string
    leaves, the always-safe subset on every other string leaf of a non-READ
    call (reserved "_" keys skipped), and the recipient refusal. A READ is
    untouched."""
    mcp = _is_mcp(tool_name) if is_mcp is None else is_mcp
    scan = _Scan(arguments=arguments)
    if not mcp and _is_read(spec):
        return scan
    fields = _MCP_FIELDS if mcp else outbound_fields(tool_name, spec)
    content = fields.content if fields is not None else ()
    recipients = fields.recipients if fields is not None else ()
    properties = (spec.parameters or {}).get("properties") if spec is not None else None
    walker = _Walker(
        scan,
        every_string=mcp,
        content=content,
        recipients=recipients,
        file_paths=FILE_CONTENT_PATHS.get(_canonical(tool_name), frozenset()),
        known_keys=frozenset(properties) if isinstance(properties, Mapping) else None,
    )
    # An MCP server gets every key as sent, so for MCP no "_" key is skipped.
    scan.arguments = walker.mapping(arguments, "", 0, skip_reserved=not mcp)
    # Recipients are read where they will be sent from: after the names are
    # cleaned, so a recipient argument whose own name hides characters is
    # still checked (the walk never changes a recipient's value).
    for path in recipients:
        if hides_characters_in_address(
            _values_at(scan.arguments, path)
        ) or hides_characters_in_address(_values_at(arguments, path)):
            scan.hiding = path
            break
    return scan


@dataclass(frozen=True)
class CleanedCall:
    """A call's arguments after the floor. ``arguments`` is the SAME mapping
    when nothing changed; ``removed`` counts what was taken out by kind;
    ``fields`` names the argument paths that changed; ``refusal`` is set when
    the call must not be sent (a recipient that hides characters)."""

    arguments: Mapping[str, Any]
    removed: Mapping[str, int]
    fields: tuple[str, ...]
    refusal: Optional[dict[str, Any]]


@dataclass(frozen=True)
class SendTicket:
    """The recipients of an approved send whose result names none (a Gmail
    draft sent, an Outlook reply), resolved just before it is sent."""

    recipients: tuple[Recipient, ...]


class OutboundFloor:
    """The hidden-character floor: no I/O, no switch. The executor's default.

    Declared outbound fields and every MCP string leaf get the full rules
    (services/security/outbound_text.clean_text); every other string leaf of
    a non-READ call, built-ins and own-storage writes included, gets the
    always-safe subset (tag characters and bidi controls, scaffold A35); a
    READ is untouched; a recipient that hides characters is refused. The
    async hooks do nothing here: ``OutboundService`` adds them."""

    def clean_call(
        self, tool_name: str, spec: Optional["ToolSpec"], arguments: Mapping[str, Any]
    ) -> CleanedCall:
        """The call's arguments after the floor. Raises on arguments nested
        deeper than MAX_ARGUMENT_DEPTH (the executor then sends nothing)."""
        scan = _scan(tool_name, spec, arguments)
        if scan.hiding is not None:
            return CleanedCall(
                arguments=arguments, removed={}, fields=(), refusal=_refusal(scan.hiding)
            )
        return CleanedCall(
            arguments=scan.arguments,
            removed=MappingProxyType(dict(scan.removed)),
            fields=tuple(scan.fields),
            refusal=None,
        )

    def card_arguments(self, tool_name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        """The arguments a card stores, cleaned (resolved from the name),
        never a refusal: the call check refused before any card, and the
        executor refuses again at dispatch. The same dict when nothing
        changed. A clean that breaks leaves the card as it was (the dispatch
        fails closed on its own)."""
        if not isinstance(arguments, Mapping):
            return arguments
        try:
            scan = _scan(tool_name, None if _is_mcp(tool_name) else _spec_of(tool_name), arguments)
        except Exception as exc:
            logger.warning("outbound_card_clean_failed", error_type=type(exc).__name__)
            return arguments
        return arguments if scan.arguments is arguments else dict(scan.arguments)

    async def note_cleaned(
        self, user_id: str, tool_name: str, cleaned: CleanedCall, *, approved: bool
    ) -> None:
        """Audit what the floor removed at dispatch. The bare floor: nothing."""
        return None

    async def before_send(
        self,
        executor: Any,
        user_id: str,
        tool_name: str,
        spec: Optional["ToolSpec"],
        arguments: Mapping[str, Any],
    ) -> Optional[SendTicket]:
        """Resolve the recipients of an approved send whose result will not
        name them. The bare floor: None."""
        return None

    async def after_send(
        self,
        user_id: str,
        tool_name: str,
        spec: Optional["ToolSpec"],
        arguments: Mapping[str, Any],
        result: Mapping[str, Any],
        ticket: Optional[SendTicket],
    ) -> None:
        """Record a successful send's recipients in the sent-to history. The
        bare floor: nothing."""
        return None


# ---------------------------------------------------------------------------
# Reading mail facts through the executor
# ---------------------------------------------------------------------------


def _failure_why(result: Any) -> str:
    """A fixed reason for a READ that did not answer (never the connector's
    text: it can quote anything). The scope test mirrors
    triggers/sources.py:_app_error."""
    if not isinstance(result, Mapping):
        return _WHY_OTHER
    if result.get("capability"):
        return _WHY_SETTING
    text = str(result.get("error") or "")
    if "Scope '" in text or "granted" in text or "scope" in text.lower():
        return _WHY_NO_SCOPE
    if text.startswith("No active"):
        return _WHY_ACCOUNT
    lowered = text.lower()
    if "reconnect" in lowered or "sign-in" in lowered or "http 401" in lowered:
        return _WHY_SIGN_IN
    if "not found" in lowered or "http 404" in lowered:
        return _WHY_NOT_FOUND
    return _WHY_OTHER


async def _read(
    executor: Any, name: str, arguments: Mapping[str, Any], user_id: str, timeout_s: float
) -> tuple[Any, str]:
    """One internal READ (approved=False, the triggers/sources.py pattern):
    ``(data, "")``, or ``(None, why)``."""
    execute = getattr(executor, "execute", None)
    if execute is None:
        return None, _WHY_OTHER
    try:
        result = await asyncio.wait_for(
            execute(name, dict(arguments), user_id, approved=False), timeout_s
        )
    except TimeoutError:
        return None, _WHY_TIMEOUT
    except Exception as exc:
        logger.warning("outbound_read_failed", error_type=type(exc).__name__)
        return None, _WHY_OTHER
    if not isinstance(result, Mapping) or result.get("ok") is not True:
        return None, _failure_why(result)
    return result.get("result"), ""


def _strings(value: Any) -> list[str]:
    if isinstance(value, str):
        return [value] if value.strip() else []
    if isinstance(value, (list, tuple)):
        return [item for item in value if isinstance(item, str) and item.strip()]
    return []


def _sender_address(facts: Mapping[str, Any]) -> str:
    sender = facts.get("from")
    if isinstance(sender, Mapping):
        address = sender.get("address")
        return address if isinstance(address, str) else ""
    return sender if isinstance(sender, str) else ""


def _true(value: Any) -> bool:
    return value is True or (isinstance(value, str) and value.strip().lower() == "true")


@dataclass(frozen=True)
class _ReplyTargets:
    primary: tuple[str, ...]  # raw addresses as the original wrote them
    copies: tuple[str, ...]
    sent_by_me: bool


def _reply_targets(facts: Mapping[str, Any], reply_all: bool, own: set[str]) -> _ReplyTargets:
    """Who a reply goes to, mirroring gmail.py's reply: for mail you sent,
    the original's To; otherwise its Reply-To, or From when it has none;
    reply-all adds To and Cc minus the mailbox and the primary."""
    sent = facts.get("sent_by_me") is True
    to, cc = _strings(facts.get("to")), _strings(facts.get("cc"))
    if sent:
        primary = to
    else:
        sender = _sender_address(facts)
        primary = _strings(facts.get("reply_to")) or ([sender] if sender else [])
    copies: list[str] = []
    if reply_all:
        skip = {normalize_address(a) for a in primary} | own
        for address in [*to, *cc]:
            normalised = normalize_address(address)
            if normalised is not None and normalised not in skip:
                skip.add(normalised)
                copies.append(address)
    return _ReplyTargets(tuple(primary), tuple(copies), sent)


def _reply_to_elsewhere(facts: Mapping[str, Any]) -> tuple[list[Recipient], str]:
    """The Reply-To recipients on a domain the sender is not on, and the
    sender's domain (google_api/mime.reply_to_elsewhere on the facts)."""
    if facts.get("sent_by_me") is True:
        return [], ""
    senders = parse_recipients(_sender_address(facts))
    if not senders:
        return [], ""
    domains = {r.domain for r in senders}
    elsewhere = [
        r for r in parse_recipients(_strings(facts.get("reply_to"))) if r.domain not in domains
    ]
    return elsewhere, senders[0].domain


# ---------------------------------------------------------------------------
# The service: the floor plus the audit row and the sent-to history
# ---------------------------------------------------------------------------


class OutboundService(OutboundFloor):
    """The floor plus the ``outbound_cleaned`` audit row and the sent-to
    history (main.py wires it into the executor and hangs it on
    ``app.state.outbound`` for the Security tab's routes)."""

    def __init__(
        self,
        *,
        known: "KnownRecipientStore",
        audit: Optional[Callable[[dict[str, Any]], Awaitable[None]]] = None,
    ) -> None:
        self._known = known
        self._audit = audit

    @property
    def known(self) -> "KnownRecipientStore":
        """The sent-to history this service records into."""
        return self._known

    async def note_cleaned(
        self, user_id: str, tool_name: str, cleaned: CleanedCall, *, approved: bool
    ) -> None:
        """One ``outbound_cleaned`` row when the executor removed characters
        before a dispatch (no card, a failed bind, MCP): counts by kind and
        the argument names, never text. Nothing when nothing was removed."""
        if not cleaned.removed or self._audit is None:
            return
        row = {
            "event": CLEANED_EVENT,
            "user_id": user_id,
            "tool": _canonical(tool_name),
            "arguments": {
                "removed": {kind: int(cleaned.removed.get(kind, 0)) for kind in STRIP_KINDS},
                "fields": list(cleaned.fields),
                "after_approval": bool(approved),
            },
            "timestamp": _utcnow().isoformat(),
        }
        try:
            await self._audit(row)
        except Exception as exc:  # the cleaned call goes ahead either way
            logger.error("audit_write_failed_outbound_cleaned", error_type=type(exc).__name__)

    async def before_send(
        self,
        executor: Any,
        user_id: str,
        tool_name: str,
        spec: Optional["ToolSpec"],
        arguments: Mapping[str, Any],
    ) -> Optional[SendTicket]:
        """For an approved send that records history, resolves recipients
        through a READ and whose result names nobody (a Gmail draft sent, an
        Outlook reply): one READ (4 s), best effort, None on any failure (a
        Gmail draft is gone after drafts/send)."""
        out = spec.outbound if spec is not None else None
        if out is None or not out.history or out.resolve is None:
            return None
        canonical = _canonical(tool_name)
        if canonical in _RESULT_NAMES_RECIPIENTS:
            return None
        connector_type = canonical.partition(".")[0]
        namespace = tool_name.rpartition(".")[0]
        if out.resolve == "draft":
            action = DRAFT_ACTION.get(connector_type)
            draft_id = arguments.get("draft_id")
            if action is None or not isinstance(draft_id, str):
                return None
            data, why = await _read(
                executor,
                f"{namespace}.{action}",
                {"draft_id": draft_id},
                user_id,
                SEND_READ_TIMEOUT_S,
            )
            if why or not isinstance(data, Mapping):
                return None
            found = parse_recipients([data.get("to"), data.get("cc"), data.get("bcc")])
            return SendTicket(tuple(found)) if found else None
        action = MAIL_FACTS_ACTION.get(connector_type)
        message_id = arguments.get("message_id")
        if action is None or not isinstance(message_id, str):
            return None
        data, why = await _read(
            executor,
            f"{namespace}.{action}",
            {"message_id": message_id},
            user_id,
            SEND_READ_TIMEOUT_S,
        )
        if why or not isinstance(data, Mapping) or data.get("gone") is True:
            return None
        raw_mailbox = data.get("mailbox")
        mailbox = normalize_address(raw_mailbox) if isinstance(raw_mailbox, str) else None
        targets = _reply_targets(
            data, _true(arguments.get("reply_all")), {mailbox} if mailbox else set()
        )
        found = parse_recipients([*targets.primary, *targets.copies])
        return SendTicket(tuple(found)) if found else None

    async def after_send(
        self,
        user_id: str,
        tool_name: str,
        spec: Optional["ToolSpec"],
        arguments: Mapping[str, Any],
        result: Mapping[str, Any],
        ticket: Optional[SendTicket],
    ) -> None:
        """Record a successful, approved send's recipients (the declared
        recipient arguments, a Gmail reply's result "to"/"cc", or the
        ticket). Never raises and never changes the result: failures log
        ``outbound_record_failed`` with the exception type only."""
        out = spec.outbound if spec is not None else None
        if out is None or not out.history:
            return
        try:
            recipients: list[Recipient] = []
            for path in out.recipients:
                recipients.extend(parse_recipients(_values_at(arguments, path)))
            if out.resolve is not None:
                data = result.get("result") if isinstance(result, Mapping) else None
                named = (
                    parse_recipients([data.get("to"), data.get("cc")])
                    if isinstance(data, Mapping)
                    else []
                )
                if named:
                    recipients.extend(named)
                elif ticket is not None:
                    recipients.extend(ticket.recipients)
            unique: dict[str, Recipient] = {}
            for recipient in recipients:
                unique.setdefault(recipient.address, recipient)
            if unique:
                await self._known.record(user_id, list(unique.values()))
        except Exception as exc:
            logger.warning("outbound_record_failed", error_type=type(exc).__name__)


# ---------------------------------------------------------------------------
# The call check
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class _Draft:
    """One note before ordering: its group (hidden, links, recipients)."""

    group: int
    note: SecurityNote


def _note(group: int, kind: str, severity: str, text: str) -> _Draft:
    if len(text) > NOTE_TEXT_CHARS:
        text = text[: NOTE_TEXT_CHARS - 1].rstrip() + "…"
    made = SecurityNote.from_value({"kind": kind, "severity": severity, "text": text})
    assert made is not None  # fixed kinds and non-empty texts
    return _Draft(group, made)


def _ordered(drafts: Sequence[_Draft]) -> tuple[SecurityNote, ...]:
    """High, then warn, then info; within a severity hidden characters, then
    links, then recipients; the same (kind, text) once; at most MAX_S1_NOTES."""
    ranked = sorted(
        enumerate(drafts),
        key=lambda item: (_SEVERITY_RANK[item[1].note.severity], item[1].group, item[0]),
    )
    out: list[SecurityNote] = []
    seen: set[tuple[str, str]] = set()
    for _, draft in ranked:
        key = (draft.note.kind, draft.note.text)
        if key in seen:
            continue
        seen.add(key)
        out.append(draft.note)
        if len(out) >= MAX_S1_NOTES:
            break
    return tuple(out)


def _address_list(recipients: Sequence[Recipient]) -> str:
    """At most ADDRESSES_PER_NOTE addresses as notes show them, then "and N more"."""
    shown = [note_address(r) for r in recipients[:ADDRESSES_PER_NOTE]]
    rest = len(recipients) - len(shown)
    return ", ".join(shown) + (f" and {rest} more" if rest > 0 else "")


def _by_domain(groups: Mapping[str, Sequence[Recipient]]) -> str:
    """ "acme.com (ann@acme.com)" or "acme.com (ann@acme.com), beta.example (bo@beta.example)":
    at most ADDRESSES_PER_NOTE addresses in all, then "and N more"."""
    parts: list[str] = []
    shown = 0
    total = sum(len(group) for group in groups.values())
    for domain, group in groups.items():
        room = ADDRESSES_PER_NOTE - shown
        if room <= 0:
            break
        taken = [note_address(r) for r in group[:room]]
        shown += len(taken)
        parts.append(f"{domain} ({', '.join(taken)})")
    rest = total - shown
    return ", ".join(parts) + (f" and {rest} more" if rest > 0 else "")


def _removed_note(scan: _Scan) -> Optional[_Draft]:
    total = sum(scan.removed.values())
    if not total:
        return None
    labels = scan.fields[:3]
    more = len(scan.fields) - len(labels)
    where = (
        _joined(labels)
        if not more
        else f"{', '.join(labels)} and {_plural(more, 'more field', 'more fields')}"
    )
    parts = [
        _plural(scan.removed[kind], *_KIND_WORDS[kind])
        for kind in STRIP_KINDS
        if scan.removed.get(kind)
    ]
    return _note(
        _HIDDEN,
        "hidden_characters_removed",
        "warn",
        f"Removed {_plural(total, 'hidden character', 'hidden characters')} from {where or 'the message'} "
        f"({', '.join(parts)}): text a reader would not see.",
    )


def _kept_note(scan: _Scan) -> Optional[_Draft]:
    total = sum(scan.kept.values())
    if not total:
        return None
    labels = list(scan.kept)[:3]
    verb = "contains" if len(labels) == 1 else "contain"
    return _note(
        _HIDDEN,
        "invisible_characters_kept",
        "info",
        f"The {_joined(labels)} {verb} "
        f"{_plural(total, 'invisible formatting character', 'invisible formatting characters')} "
        "(zero-width spaces). They were left in; they usually come from copied web text.",
    )


@dataclass
class _LinkFacts:
    """What the links of some text show without any network."""

    notes: list[_Draft] = field(default_factory=list)
    origins: list[str] = field(default_factory=list)  # scheme://host/ for S4's lookup
    others: list[str] = field(default_factory=list)  # non-web links: local checks only
    certain: bool = False  # an exfil finding, a text mismatch or a high local signal


def _exfil_text(finding: ExfilFinding) -> str:
    if finding.kind == "remote_image":
        return (
            f"The message shows an image from {finding.host}. Opening the message loads it, "
            "which tells that site the message was read and can carry data in the image address."
        )
    return (
        f"A link to {finding.host} carries a long coded value ({finding.size} characters). "
        "Links like this can carry your data to that site."
    )


class OutboundCheck:
    """The call check (slot 4 of the pre-dispatch pipeline): the floor's
    refusal and note at every stage, and at the turn stage the recipient and
    link facts that make the card worth reading (S1 design 4.4).

    Collaborators are injected by main.py: the executor (READs), the
    sent-to history, the organisation's domain list, the users' sign-in
    addresses, S4's ``LinkChecker`` (the local-only one when absent) and the
    owner's switch (a read error counts as on)."""

    name = CHECK_NAME
    policy = OUTBOUND_RULE_POLICY
    stages: frozenset[str] = frozenset({"turn", "approve", "execute"})
    # The pipeline gives a turn-stage check at least 10 s; S1 bounds itself
    # at CHECK_BUDGET_S inside that.
    timeout_s = CHECK_TIMEOUT_S

    def __init__(
        self,
        *,
        executor: Any,
        known: Optional["KnownRecipientStore"],
        org_domains: Optional["OrganisationDomainStore"],
        users: Optional["UserEmails"],
        links: Optional[link_checks.LinkChecker] = None,
        enabled: Optional[Callable[[], Awaitable[bool]]] = None,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._executor = executor
        self._known = known
        self._org_domains = org_domains
        self._users = users
        self._links: link_checks.LinkChecker = (
            links if links is not None else link_checks.LocalOnlyLinkChecker()
        )
        self._enabled = enabled
        self._clock = clock
        # (user, namespace) -> (expires, account address or None): learned
        # from the sent folder, in memory only (S1 deviation 7).
        self._accounts: OrderedDict[tuple[str, str], tuple[float, Optional[str]]] = OrderedDict()
        # (user, namespace, message id) -> (expires, facts): one READ when the
        # model proposes the same reply again.
        self._facts: OrderedDict[tuple[str, str, str], tuple[float, Mapping[str, Any]]] = (
            OrderedDict()
        )

    # -- the pipeline's contract ----------------------------------------------

    def applies_to(self, call: CallFacts) -> bool:
        """Every MCP call and every non-READ call with a spec (no I/O)."""
        if call.is_mcp:
            return True
        return call.spec is not None and not _is_read(call.spec)

    async def check(self, call: CallFacts) -> Verdict:
        if not self.applies_to(call):
            return ALLOW
        arguments = call.arguments if isinstance(call.arguments, Mapping) else {}
        try:
            scan = _scan(call.tool_name, call.spec, arguments, is_mcp=call.is_mcp)
        except _Unclean:
            return Refuse(
                rule=UNCHECKABLE_RULE,
                message=(
                    "Refused: Crawler could not check these arguments for hidden characters (they "
                    "are nested too deeply, or two names differ only by hidden characters). Write "
                    "them again plainly; nothing was sent."
                ),
                policy=OUTBOUND_RULE_POLICY,
            )
        if scan.hiding is not None:
            return Refuse(
                rule=HIDDEN_IN_RECIPIENT_RULE,
                message=_refusal_text(scan.hiding),
                policy=OUTBOUND_RULE_POLICY,
            )
        if call.stage == "approve":
            return ALLOW
        fields = _MCP_FIELDS if call.is_mcp else outbound_fields(call.tool_name, call.spec)
        if call.stage == "execute":
            return await self._execute_stage(call, fields, scan)

        drafts: list[_Draft] = []
        removed = _removed_note(scan)
        if removed is not None:
            drafts.append(removed)
        if fields is None or fields.every_string:
            # Floor only (MCP, or a write that declares no outbound fields).
            return await self._verdict(call, drafts)
        if not await self._is_enabled():
            return Note(_ordered(drafts)) if drafts else ALLOW
        # The facts are read from the arguments as they will be sent (cleaned
        # values and names), never from what the model wrote.
        drafts.extend(await self._turn(call, fields, scan.arguments, scan))
        return await self._verdict(call, drafts, enabled=True)

    # -- verdicts ---------------------------------------------------------------

    async def _is_enabled(self) -> bool:
        if self._enabled is None:
            return True
        try:
            return bool(await self._enabled())
        except Exception as exc:  # the hide_personal_details rule: unreadable counts as on
            logger.warning("outbound_switch_unreadable", error_type=type(exc).__name__)
            return True

    async def _verdict(
        self, call: CallFacts, drafts: Sequence[_Draft], *, enabled: Optional[bool] = None
    ) -> Verdict:
        notes = _ordered(drafts)
        if not notes:
            return ALLOW
        warns = any(n.severity in ("high", "warn") for n in notes)
        if call.runs_without_card and warns:
            if enabled is None:
                enabled = await self._is_enabled()
            if enabled:
                return Escalate(
                    notes, ESCALATE_REASON, refusal_text=EXECUTE_REFUSAL, names_rule=False
                )
        return Note(notes)

    async def _execute_stage(
        self, call: CallFacts, fields: Optional[OutboundFields], scan: _Scan
    ) -> Verdict:
        """Pure: a call no person approved is escalated (the executor answers
        requires_approval) when the floor removed something or a link finding
        is certain without any network; notes are not kept at this stage."""
        if not call.runs_without_card:
            return ALLOW
        certain = bool(scan.removed)
        if not certain and fields is not None and not fields.every_string:
            certain = self._link_facts(scan.content).certain
        if not certain or not await self._is_enabled():
            return ALLOW
        return Escalate((), ESCALATE_REASON, refusal_text=EXECUTE_REFUSAL, names_rule=False)

    # -- the turn stage -----------------------------------------------------------

    async def _turn(
        self,
        call: CallFacts,
        fields: OutboundFields,
        arguments: Mapping[str, Any],
        scan: _Scan,
    ) -> list[_Draft]:
        loop = asyncio.get_running_loop()
        deadline = loop.time() + CHECK_BUDGET_S
        drafts: list[_Draft] = []
        kept = _kept_note(scan)
        if kept is not None:
            drafts.append(kept)
        facts = self._link_facts(scan.content)
        drafts.extend(facts.notes)

        links_task: Optional[asyncio.Task[list[_Draft]]] = None
        if facts.origins or facts.others:
            links_task = asyncio.create_task(self._reputation(facts.origins, facts.others))
        recipients_task = asyncio.create_task(self._recipients(call, fields, arguments))
        tasks: set[asyncio.Task[Any]] = {recipients_task}
        if links_task is not None:
            tasks.add(links_task)
        try:
            _done, pending = await asyncio.wait(tasks, timeout=max(0.0, deadline - loop.time()))
        except BaseException:
            for task in tasks:
                task.cancel()
            raise
        for task in pending:
            task.cancel()

        if links_task is not None:
            drafts.extend(self._finished_links(links_task))
        if recipients_task in pending:
            drafts.append(self._recipients_not_finished(call, fields))
        else:
            try:
                recipient_drafts, draft_texts = recipients_task.result()
            except Exception as exc:
                logger.warning(
                    "outbound_check_failed", part="recipients", error_type=type(exc).__name__
                )
                drafts.append(self._recipients_not_finished(call, fields))
            else:
                drafts.extend(recipient_drafts)
                if draft_texts:
                    drafts.extend(await self._draft_links(draft_texts, deadline))
        return drafts

    @staticmethod
    def _links_not_finished() -> _Draft:
        return _note(
            _LINKS,
            "link_not_checked",
            "info",
            "Links in this message were not checked (the check did not finish in time).",
        )

    def _finished_links(self, task: "asyncio.Task[list[_Draft]]") -> list[_Draft]:
        if not task.done() or task.cancelled():
            return [self._links_not_finished()]
        try:
            return task.result()
        except Exception as exc:
            if not isinstance(exc, TimeoutError):
                logger.warning("outbound_check_failed", part="links", error_type=type(exc).__name__)
            return [self._links_not_finished()]

    def _recipients_not_finished(self, call: CallFacts, fields: OutboundFields) -> _Draft:
        if fields.resolve is not None:
            reply_all = (
                _true(call.arguments.get("reply_all"))
                if isinstance(call.arguments, Mapping)
                else False
            )
            return self._not_checked(call, fields.resolve, _WHY_TIMEOUT, reply_all=reply_all)
        return _note(
            _RECIPIENTS,
            "recipient_history_not_checked",
            "info",
            "Crawler could not read its sent-to history in time, so it cannot say whether these "
            "recipients are new.",
        )

    async def _draft_links(self, texts: list[tuple[str, str]], deadline: float) -> list[_Draft]:
        """The links of a saved draft: S1's own findings, then S4's lookup in
        what is left of the budget."""
        facts = self._link_facts(texts)
        drafts = list(facts.notes)
        if facts.origins or facts.others:
            remaining = deadline - asyncio.get_running_loop().time()
            try:
                drafts.extend(
                    await asyncio.wait_for(
                        self._reputation(facts.origins, facts.others), max(0.0, remaining)
                    )
                )
            except Exception as exc:
                if not isinstance(exc, TimeoutError):
                    logger.warning(
                        "outbound_check_failed", part="links", error_type=type(exc).__name__
                    )
                drafts.append(self._links_not_finished())
        return drafts

    # -- links ----------------------------------------------------------------------

    def _link_facts(self, texts: Sequence[tuple[str, str]]) -> _LinkFacts:
        """S1's own link findings (remote images, coded values), link text
        that names another site (S4's check_local), the high local signals,
        and what may go to S4: ``scheme://host/`` only."""
        facts = _LinkFacts()
        every: list[FoundLink] = []
        for _, text in texts:
            if len(every) >= SCAN_LINK_LIMIT:
                break
            every.extend(find_links(text, limit=SCAN_LINK_LIMIT - len(every)))
        if not every:
            return facts
        first: list[FoundLink] = []
        seen: set[FoundLink] = set()
        for link in every:
            if link not in seen:
                seen.add(link)
                first.append(link)
                if len(first) >= LINKS_LOOKED_AT:
                    break
        own: list[_Draft] = []
        for finding in exfil_findings(every):
            own.append(_note(_LINKS, finding.kind, "warn", _exfil_text(finding)))
        mismatches: set[str] = set()
        for link in first:
            origin = origin_only(link.url)
            target = origin or link.url
            if origin is not None:
                if origin not in facts.origins and len(facts.origins) < LINKS_FOR_LOOKUP:
                    facts.origins.append(origin)
            elif link.url not in facts.others and len(facts.others) < LINKS_FOR_LOOKUP:
                facts.others.append(link.url)
            try:
                report = self._links.check_local(target, text=link.text)
            except Exception as exc:
                logger.warning("outbound_link_check_failed", error_type=type(exc).__name__)
                continue
            for signal in report.signals:
                if signal.code == "text_mismatch" and link.text:
                    if signal.text not in mismatches:
                        mismatches.add(signal.text)
                        own.append(
                            _note(_LINKS, "link_text_mismatch", signal.severity, signal.text)
                        )
                    facts.certain = True
                elif signal.severity == "high":
                    facts.certain = True
        if own:
            facts.certain = True
        ranked = sorted(own, key=lambda d: _SEVERITY_RANK[d.note.severity])
        facts.notes = ranked[:LINK_NOTES]
        rest = ranked[LINK_NOTES:]
        if rest:
            facts.notes.append(
                _note(
                    _LINKS,
                    rest[0].note.kind,
                    "warn",
                    f"And {_plural(len(rest), 'more link was', 'more links were')} flagged.",
                )
            )
        return facts

    async def _reputation(self, origins: Sequence[str], others: Sequence[str]) -> list[_Draft]:
        """S4's lookup of ``scheme://host/`` only, plus local reports of
        non-web links, in S4's wording (never "safe")."""
        reports: list[link_checks.LinkReport] = []
        if origins:
            reports.extend(
                await asyncio.wait_for(
                    self._links.check(
                        list(origins), purpose="outbound", network=True, timeout_s=LINKS_TIMEOUT_S
                    ),
                    LINKS_TIMEOUT_S + 0.5,
                )
            )
        for url in others:
            try:
                reports.append(self._links.check_local(url))
            except Exception as exc:
                logger.warning("outbound_link_check_failed", error_type=type(exc).__name__)
        drafts: list[_Draft] = []
        for item in link_checks.security_notes(reports, limit=LINK_NOTES):
            made = SecurityNote.from_value(item)
            if made is not None:
                drafts.append(_Draft(_LINKS, made))
        return drafts

    # -- recipients -------------------------------------------------------------------

    def _not_checked(self, call: CallFacts, resolve: str, why: str, *, reply_all: bool) -> _Draft:
        connector_type = call.canonical.partition(".")[0]
        if resolve == "draft":
            text = (
                f"Crawler could not read the draft, so it cannot say who it goes to ({why}). "
                "Open it in Gmail to check its recipients before you approve."
            )
        else:
            rule = _OUTLOOK_REPLY_RULE if connector_type == "microsoft" else _GMAIL_REPLY_RULE
            if reply_all:
                rule += ", plus everyone else on it"
            text = (
                "Crawler could not read the original message, so it cannot say who this reply "
                f"goes to ({why}). {rule}."
            )
        return _note(_RECIPIENTS, "recipients_not_checked", "warn", text)

    async def _account_address(self, call: CallFacts, namespace: str) -> Optional[str]:
        """The connector's own address, learned from its sent folder (one
        READ, 4 s), cached 12 h when found and 1 h when not."""
        connector_type = call.canonical.partition(".")[0]
        probe = SENT_PROBE.get(connector_type)
        if probe is None:
            return None
        key = (call.user_id, namespace)
        now = self._clock()
        cached = self._accounts.get(key)
        if cached is not None and now < cached[0]:
            self._accounts.move_to_end(key)
            return cached[1]
        action, arguments = probe
        data, why = await _read(
            self._executor, f"{namespace}.{action}", arguments, call.user_id, PROBE_TIMEOUT_S
        )
        address: Optional[str] = None
        if not why:
            rows = data.get("items") if isinstance(data, Mapping) else data
            if isinstance(rows, list) and rows and isinstance(rows[0], Mapping):
                found = parse_recipients(rows[0].get("from"))
                address = found[0].address if found else None
        self._accounts[key] = (now + (ACCOUNT_FOUND_S if address else ACCOUNT_MISSING_S), address)
        self._accounts.move_to_end(key)
        while len(self._accounts) > ACCOUNT_CACHE_SIZE:
            self._accounts.popitem(last=False)
        return address

    async def _mail_facts(
        self, call: CallFacts, namespace: str, message_id: str
    ) -> tuple[Optional[Mapping[str, Any]], str]:
        """The original message's facts (S2's get_message_security, scaffold
        A7), cached 10 min; ``(None, why)`` when they could not be read."""
        connector_type = call.canonical.partition(".")[0]
        action = MAIL_FACTS_ACTION.get(connector_type)
        if action is None:
            return None, _WHY_OTHER
        key = (call.user_id, namespace, message_id)
        now = self._clock()
        cached = self._facts.get(key)
        if cached is not None and now < cached[0]:
            self._facts.move_to_end(key)
            return cached[1], ""
        data, why = await _read(
            self._executor,
            f"{namespace}.{action}",
            {"message_id": message_id},
            call.user_id,
            READ_TIMEOUT_S,
        )
        if why:
            return None, why
        if not isinstance(data, Mapping):
            return None, _WHY_OTHER
        if data.get("gone") is True:
            return None, _WHY_GONE_MESSAGE
        self._facts[key] = (now + FACTS_TTL_S, data)
        self._facts.move_to_end(key)
        while len(self._facts) > FACTS_CACHE_SIZE:
            self._facts.popitem(last=False)
        return data, ""

    async def _recipients(
        self, call: CallFacts, fields: OutboundFields, arguments: Mapping[str, Any]
    ) -> tuple[list[_Draft], list[tuple[str, str]]]:
        """The recipient notes, and a saved draft's subject and body (for
        the link checks). Explicit recipients from the declared paths;
        replies and drafts resolved through one READ."""
        drafts: list[_Draft] = []
        draft_texts: list[tuple[str, str]] = []
        recipients: list[Recipient] = []
        for path in fields.recipients:
            recipients.extend(parse_recipients(_values_at(arguments, path)))
        namespace = call.tool_name.rpartition(".")[0]
        connector_type = call.canonical.partition(".")[0]
        mailbox: Optional[str] = None

        if fields.resolve == "reply":
            reply_all = _true(arguments.get("reply_all"))
            message_id = arguments.get("message_id")
            facts: Optional[Mapping[str, Any]] = None
            why = _WHY_OTHER
            if isinstance(message_id, str) and message_id.strip():
                facts, why = await self._mail_facts(call, namespace, message_id.strip())
            if facts is None:
                drafts.append(self._not_checked(call, "reply", why, reply_all=reply_all))
            else:
                raw_mailbox = facts.get("mailbox")
                mailbox = normalize_address(raw_mailbox) if isinstance(raw_mailbox, str) else None
                if mailbox is None:
                    mailbox = await self._account_address(call, namespace)
                targets = _reply_targets(facts, reply_all, {mailbox} if mailbox else set())
                drafts.extend(self._hidden_in_resolved([*targets.primary, *targets.copies]))
                primary = parse_recipients(list(targets.primary))
                copies = parse_recipients(list(targets.copies))
                recipients.extend([*primary, *copies])
                drafts.append(self._resolved_note(connector_type, "reply", primary, copies, []))
                elsewhere, sender_domain = _reply_to_elsewhere(facts)
                if elsewhere:
                    drafts.append(
                        _note(
                            _RECIPIENTS,
                            "reply_to_elsewhere",
                            "warn",
                            f"The original message asks for replies to {_address_list(elsewhere)}, "
                            f"a different domain from its sender ({sender_domain}).",
                        )
                    )
        elif fields.resolve == "draft":
            action = DRAFT_ACTION.get(connector_type)
            draft_id = arguments.get("draft_id")
            data: Any = None
            why = _WHY_OTHER
            if action is not None and isinstance(draft_id, str) and draft_id.strip():
                data, why = await _read(
                    self._executor,
                    f"{namespace}.{action}",
                    {"draft_id": draft_id.strip()},
                    call.user_id,
                    READ_TIMEOUT_S,
                )
                if not why and not isinstance(data, Mapping):
                    why = _WHY_OTHER
            if why or not isinstance(data, Mapping):
                drafts.append(self._not_checked(call, "draft", why or _WHY_OTHER, reply_all=False))
            else:
                raw = {key: _strings(data.get(key)) for key in ("to", "cc", "bcc")}
                drafts.extend(self._hidden_in_resolved([*raw["to"], *raw["cc"], *raw["bcc"]]))
                to, cc, bcc = (parse_recipients(raw[key]) for key in ("to", "cc", "bcc"))
                recipients.extend([*to, *cc, *bcc])
                drafts.append(self._resolved_note(connector_type, "draft", to, cc, bcc))
                raw_subject, raw_body = data.get("subject"), data.get("body")
                subject = raw_subject if isinstance(raw_subject, str) else ""
                body = raw_body if isinstance(raw_body, str) else ""
                hidden = hidden_count(subject) + hidden_count(body)
                if hidden:
                    drafts.append(
                        _note(
                            _HIDDEN,
                            "hidden_characters_in_draft",
                            "warn",
                            f"The draft contains {_plural(hidden, 'hidden character', 'hidden characters')}. "
                            "Crawler cannot clean a saved draft; open it in Gmail if you are unsure.",
                        )
                    )
                draft_texts = [
                    ("subject", clean_text(subject).text),
                    ("body", clean_text(body).text),
                ]

        unique: dict[str, Recipient] = {}
        for recipient in recipients:
            unique.setdefault(recipient.address, recipient)
        if unique:
            drafts.extend(
                await self._recipient_notes(call, fields, list(unique.values()), mailbox, namespace)
            )
        return drafts, draft_texts

    def _hidden_in_resolved(self, raw: Sequence[str]) -> list[_Draft]:
        """Recipients read from a message or a draft are someone else's words
        (a Reply-To): one that hides characters is flagged high, shown
        normalised (review SEC-F9)."""
        hiding = [value for value in raw if hides_characters_in_address(value)]
        if not hiding:
            return []
        found = parse_recipients(hiding)
        who = _address_list(found) if found else "An address"
        verb = "has" if len(found) <= 1 else "have"
        return [
            _note(
                _RECIPIENTS,
                "recipient_unusual_characters",
                "high",
                f"{who} {verb} characters a reader cannot see in the address, so it may not be "
                "the address it looks like.",
            )
        ]

    def _resolved_note(
        self,
        connector_type: str,
        resolve: str,
        to: Sequence[Recipient],
        cc: Sequence[Recipient],
        bcc: Sequence[Recipient],
    ) -> _Draft:
        if resolve == "draft" and not (to or cc or bcc):
            return _note(
                _RECIPIENTS, "recipients_resolved", "info", "This draft names no recipients."
            )
        extra = []
        if cc:
            extra.append(f"cc: {_address_list(cc)}")
        if bcc:
            extra.append(f"bcc: {_address_list(bcc)}")
        tail = f" ({'; '.join(extra)})" if extra else ""
        main = _address_list(to) if to else "nobody"
        if resolve == "draft":
            text = f"This draft goes to: {main}{tail}."
        elif connector_type == "microsoft":
            text = f"Outlook picks who this reply goes to; from the original it should be: {main}{tail}."
        else:
            text = f"This reply goes to: {main}{tail}."
        return _note(_RECIPIENTS, "recipients_resolved", "info", text)

    async def _org(
        self, call: CallFacts, mailbox: Optional[str], namespace: str
    ) -> tuple[OrgView, bool]:
        """The user's organisation as far as it is known, and whether the
        owner's domain list could be read (when it could not, nothing is
        called "outside": better no note than a wrong one)."""
        own: list[str] = []
        try:
            if self._users is not None:
                email = await self._users.email(call.user_id)
                if email:
                    own.append(email)
        except Exception as exc:
            logger.warning("outbound_user_email_unreadable", error_type=type(exc).__name__)
        account = mailbox
        if account is None:
            try:
                account = await self._account_address(call, namespace)
            except Exception as exc:
                logger.warning("outbound_account_probe_failed", error_type=type(exc).__name__)
        if account:
            own.append(account)
        rows: list[str] = []
        try:
            if self._org_domains is not None:
                rows = [row.domain for row in await self._org_domains.domains()]
        except Exception as exc:
            logger.warning("outbound_org_domains_unreadable", error_type=type(exc).__name__)
            return org_view(own), False
        return org_view(own, rows), True

    async def _recipient_notes(
        self,
        call: CallFacts,
        fields: OutboundFields,
        recipients: Sequence[Recipient],
        mailbox: Optional[str],
        namespace: str,
    ) -> list[_Draft]:
        org, listed = await self._org(call, mailbox, namespace)
        others = [r for r in recipients if classify(r, org) != "self"][:RECIPIENTS_LOOKED_AT]
        if not others:
            return []
        drafts: list[_Draft] = []

        # Look-alikes and unusual letters, grouped by what they imitate or read as.
        lookalikes: dict[tuple[str, str], list[Recipient]] = {}
        unusual: dict[str, list[Recipient]] = {}
        international: list[Recipient] = []
        for recipient in others:
            concern = address_concern(recipient, org)
            if concern is None:
                continue
            if concern.kind == "lookalike":
                lookalikes.setdefault((concern.severity, concern.reference), []).append(recipient)
            elif concern.severity == "high":
                unusual.setdefault(concern.reading or recipient.domain, []).append(recipient)
            else:
                international.append(recipient)
        for (severity, reference), group in lookalikes.items():
            if len(group) == 1:
                text = f"{_address_list(group)} looks like {reference} but is a different address."
            else:
                text = f"{_address_list(group)} look like {reference} but are different addresses."
            drafts.append(_note(_RECIPIENTS, "recipient_lookalike", severity, text))
        for reading, group in unusual.items():
            if len(group) == 1:
                text = f"{_address_list(group)} uses look-alike letters: it reads as {reading}."
            else:
                text = f"{_address_list(group)} use look-alike letters: they read as {reading}."
            drafts.append(_note(_RECIPIENTS, "recipient_unusual_characters", "high", text))
        if international:
            verb = "uses" if len(international) == 1 else "use"
            drafts.append(
                _note(
                    _RECIPIENTS,
                    "recipient_unusual_characters",
                    "info",
                    f"{_address_list(international)} {verb} non-Latin letters.",
                )
            )

        # First time Crawler sends there (the history fails open with a note).
        known = None
        try:
            if self._known is None:
                raise LookupError("no history store")
            known = await asyncio.wait_for(
                self._known.known(call.user_id, others), HISTORY_TIMEOUT_S
            )
        except Exception as exc:
            if not isinstance(exc, TimeoutError):
                logger.warning("outbound_history_unreadable", error_type=type(exc).__name__)
            drafts.append(
                _note(
                    _RECIPIENTS,
                    "recipient_history_not_checked",
                    "info",
                    "Crawler could not read its sent-to history, so it cannot say whether these "
                    "recipients are new.",
                )
            )
        if known is not None:
            new_domain_warn: dict[str, list[Recipient]] = {}
            new_domain_info: dict[str, list[Recipient]] = {}
            new_address: list[Recipient] = []
            for recipient in others:
                if recipient.address in known.addresses:
                    continue
                if recipient.domain in known.domains:
                    new_address.append(recipient)
                    continue
                inside = classify(recipient, org) == "inside"
                target = new_domain_warn if (fields.delivers and not inside) else new_domain_info
                target.setdefault(recipient.domain, []).append(recipient)
            for severity, groups in (("warn", new_domain_warn), ("info", new_domain_info)):
                if groups:
                    drafts.append(
                        _note(
                            _RECIPIENTS,
                            "recipient_first_time",
                            severity,
                            f"First time Crawler sends to anyone at {_by_domain(groups)}.",
                        )
                    )
            if new_address:
                drafts.append(
                    _note(
                        _RECIPIENTS,
                        "recipient_first_time",
                        "info",
                        f"First time Crawler sends to {_address_list(new_address)}.",
                    )
                )

        if org.domains and listed:
            outside = [r for r in others if classify(r, org) == "outside"]
            if outside:
                drafts.append(
                    _note(
                        _RECIPIENTS,
                        "recipient_outside_organisation",
                        "info",
                        f"Outside your organisation ({org.label}): {_address_list(outside)}.",
                    )
                )
        return drafts
