"""Connector tool registry and executor.

Turns a user's active connectors into runtime ``Tool`` objects, bridges
the runtime's permission seam to the real permission engine, and
dispatches approved tool calls to the connectors.

Three pieces plug into the agent runtime:

- ``build_tools(...)`` produces the ``Tool`` list the route passes to
  ``runtime.chat``. Hard-blocked actions and actions outside the
  connector's granted scopes are omitted so the LLM is never offered a
  tool it can't use.
- ``RuntimePermissionAdapter`` implements the runtime's expected
  ``check / get_block_reason / get_policy_name`` interface by delegating
  to ``services.agent.permissions.PermissionEngine``. Injected into the
  runtime singleton.
- ``ConnectorToolExecutor`` resolves a namespaced tool name, loads the
  user's connector config, decrypts credentials, enforces scopes and
  rate limits, and dispatches through the real connector classes (which
  in turn enforce the deny-by-default network policy and sanitize their
  responses).

Tool names are namespaced ``<connector_type>.<action>`` (e.g.
``canvas.get_assignments``). The connector_type segment is the
``ConnectorType`` enum value (canvas / google_workspace / robinhood),
NOT the connector class's category property ("lms"/"email"/"finance").
When a user has two active connectors of the same type the segment
carries a per-row slug as well — see ``build_tools``.

``web``, ``reminders`` and ``system`` are built-in types rather than
connectors: they hold no credentials and have no connector row, so every
user is offered them. Reminders are owner-scoped, so the executor hands
the toolkit the caller's identity rather than anything in the tool
arguments. ``system`` installs optional software onto the host from a
fixed allowlist; its install action is the one built-in that always goes
through the approval card, and the executor refuses it unapproved.
``desktop`` reads this computer's display and is off by default.

Every built-in tool belongs to a capability (``services/capabilities``)
the owner can switch off, except the few in ``ALWAYS_ON_TOOLS``. That
switch is enforced three times, always by the canonical ``type.action``
name: ``build_tools`` offers a tool only when its capability is on, the
permission adapter blocks it before anything runs, and the executor
refuses it at dispatch as the backstop. The adapter and the executor read
the owner's report (``capability_gate``) and tell the cases apart: off
(the owner's switch; ``capability_off``), blocked (switched on but not
usable here, e.g. not installed or no OS permission;
``capability_blocked``, with the reason and fix), and a gate that could
not answer (``capability_gate_error``: refused, fail closed).
"""

from __future__ import annotations

import hashlib
import json
import uuid as uuid_module
from collections import OrderedDict
from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable, Iterable, Literal, Mapping, Optional

import structlog

from services.agent.permissions import (
    ActionCategory,
    PermissionEngine,
    PermissionTier,
    UserTier,
    is_hard_blocked_action,
)
from services.agent.runtime import (
    CAPABILITY_BLOCKED_POLICY,
    CAPABILITY_GATE_ERROR_POLICY,
    CAPABILITY_GATE_ERROR_REASON,
    CAPABILITY_OFF_POLICY,
    Tool,
)
from services.capabilities.base import Capability, CapabilityStatus
from services.tools.desktop import DesktopToolkit
from services.tools.reminders import ReminderToolkit
from services.tools.system import ALLOWLIST as SYSTEM_CAPABILITIES
from services.tools.system import SystemToolkit
from services.tools.web import WebToolkit

logger = structlog.get_logger(__name__)


_EMPTY_SCHEMA: dict[str, Any] = {"type": "object", "properties": {}, "required": []}


# ---------------------------------------------------------------------------
# Static action catalog
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ToolSpec:
    """Declarative description of one connector action.

    ``policy_key`` is the connector_type string the permission engine is
    keyed by, which for Google differs per action (gmail vs
    google_calendar). It defaults to the owning connector_type.

    ``required_scope`` is the connector scope a user must have granted for
    this action to be offered and executed. ``None`` means the action has
    no scope gate beyond its permission tier.
    """

    action: str
    description: str
    category: ActionCategory
    parameters: dict[str, Any] = field(default_factory=dict)
    policy_key: Optional[str] = None
    required_scope: Optional[str] = None


def _schema(**props: dict[str, Any]) -> dict[str, Any]:
    """Build a minimal JSON-schema object for tool parameters."""
    required = [k for k, v in props.items() if v.get("required")]
    return {
        "type": "object",
        "properties": {
            k: {key: val for key, val in v.items() if key != "required"}
            for k, v in props.items()
        },
        "required": required,
    }


# Keyed by ConnectorType enum value.
CONNECTOR_CATALOG: dict[str, list[ToolSpec]] = {
    "canvas": [
        ToolSpec(
            "get_courses",
            "List the user's active Canvas courses.",
            ActionCategory.READ,
            required_scope="courses.read",
        ),
        ToolSpec(
            "get_assignments",
            "List assignments for a Canvas course.",
            ActionCategory.READ,
            _schema(course_id={"type": "string", "description": "Canvas course id", "required": True}),
            required_scope="assignments.read",
        ),
        ToolSpec(
            "get_grades",
            "Get the user's grades for a Canvas course.",
            ActionCategory.READ,
            _schema(course_id={"type": "string", "description": "Canvas course id", "required": True}),
            required_scope="grades.read",
        ),
        ToolSpec(
            "get_calendar_events",
            "List upcoming Canvas calendar events.",
            ActionCategory.READ,
            required_scope="calendar.read",
        ),
        ToolSpec(
            "get_submissions",
            "List submissions for a Canvas assignment.",
            ActionCategory.READ,
            _schema(
                course_id={"type": "string", "required": True},
                assignment_id={"type": "string", "required": True},
            ),
            required_scope="submissions.read",
        ),
        ToolSpec(
            "submit_assignment",
            "Submit work to a Canvas assignment.",
            ActionCategory.WRITE,
            _schema(
                course_id={"type": "string", "required": True},
                assignment_id={"type": "string", "required": True},
                submission_data={"type": "object", "required": True},
            ),
            required_scope="submissions.write",
        ),
    ],
    "google_workspace": [
        ToolSpec(
            "get_messages",
            "List recent Gmail messages, optionally filtered by query.",
            ActionCategory.READ,
            _schema(query={"type": "string"}, max_results={"type": "integer"}),
            policy_key="gmail",
            required_scope="gmail.read",
        ),
        ToolSpec(
            "get_message",
            "Fetch a single Gmail message by id.",
            ActionCategory.READ,
            _schema(message_id={"type": "string", "required": True}),
            policy_key="gmail",
            required_scope="gmail.read",
        ),
        ToolSpec(
            "search_emails",
            "Search Gmail messages with a query string.",
            ActionCategory.READ,
            _schema(query={"type": "string", "required": True}),
            policy_key="gmail",
            required_scope="gmail.read",
        ),
        ToolSpec(
            "send_email",
            "Send an email via Gmail.",
            ActionCategory.WRITE,
            _schema(
                to={"type": "string", "required": True},
                subject={"type": "string", "required": True},
                body={"type": "string", "required": True},
            ),
            policy_key="gmail",
            required_scope="gmail.send",
        ),
        ToolSpec(
            "get_events",
            "List upcoming Google Calendar events.",
            ActionCategory.READ,
            _schema(time_min={"type": "string"}, time_max={"type": "string"}),
            policy_key="google_calendar",
            required_scope="calendar.read",
        ),
        ToolSpec(
            "check_availability",
            "Check Google Calendar availability for a time range.",
            ActionCategory.READ,
            _schema(time_min={"type": "string"}, time_max={"type": "string"}),
            policy_key="google_calendar",
            required_scope="calendar.read",
        ),
        ToolSpec(
            "create_event",
            "Create a Google Calendar event.",
            ActionCategory.WRITE,
            _schema(
                event_data={
                    "type": "object",
                    "description": "Google Calendar event resource (summary, start, end, ...)",
                    "required": True,
                },
            ),
            policy_key="google_calendar",
            required_scope="calendar.write",
        ),
    ],
    "robinhood": [
        ToolSpec(
            "get_crypto_portfolio",
            "View the Robinhood crypto portfolio (read-only).",
            ActionCategory.READ,
            required_scope="crypto.read",
        ),
        ToolSpec(
            "get_crypto_prices",
            "Get current prices for crypto symbols (read-only).",
            ActionCategory.READ,
            _schema(symbols={"type": "array", "items": {"type": "string"}, "required": True}),
            required_scope="crypto.read",
        ),
        ToolSpec(
            "get_crypto_holdings",
            "View current crypto holdings (read-only).",
            ActionCategory.READ,
            required_scope="crypto.read",
        ),
        ToolSpec(
            "execute_trade",
            "Execute a crypto trade. Permanently blocked by platform policy.",
            ActionCategory.FINANCIAL,
            _schema(symbol={"type": "string", "required": True}, side={"type": "string", "required": True}),
            required_scope="crypto.trade",
        ),
    ],
    # Built-in: no credentials, no connector row, no scopes to grant, so
    # every action here is deliberately scope-free. Read-only by
    # construction — the permission engine hard-blocks every other
    # category for "web" so a future non-READ entry cannot be reached
    # even if it were added here by mistake.
    "web": [
        ToolSpec(
            "search",
            "Search the public web and return titles, URLs and snippets. "
            "Use this to find pages; use web.fetch_page to read one.",
            ActionCategory.READ,
            _schema(
                query={"type": "string", "description": "Search terms", "required": True},
                max_results={
                    "type": "integer",
                    "description": "How many results to return (1-10, default 5)",
                },
            ),
        ),
        ToolSpec(
            "fetch_page",
            "Fetch a public web page and return its readable text. The text is "
            "truncated; raise max_chars only when the answer was cut off.",
            ActionCategory.READ,
            _schema(
                url={"type": "string", "description": "Absolute http(s) URL", "required": True},
                max_chars={
                    "type": "integer",
                    "description": "Character budget for the extracted text (default 4000)",
                },
            ),
        ),
        ToolSpec(
            "screenshot",
            "Capture a screenshot of a public web page as an image data URL. "
            "Prefer image_format 'jpeg' for full pages: a PNG of one often "
            "exceeds the inline size limit and comes back without the image.",
            ActionCategory.READ,
            _schema(
                url={"type": "string", "description": "Absolute http(s) URL", "required": True},
                full_page={
                    "type": "boolean",
                    "description": "Capture the whole scrollable page instead of the viewport",
                },
                image_format={
                    "type": "string",
                    "enum": ["png", "jpeg"],
                    "description": "Image encoding (default png)",
                },
            ),
        ),
    ],
    # Built-in: reminders the agent sets for the user, delivered by the
    # sweeper over whatever channel they linked. Scope-free like web.
    # ``cancel`` is a WRITE (a status flip that keeps the row), not a
    # DELETE — the permission engine hard-blocks DELETE for this type, so
    # a genuinely destructive action could not be added here by mistake.
    # ``now`` exists because a model cannot know today's date or the
    # server's UTC offset; every description that takes a time says to
    # call it first, otherwise "tomorrow at 9am" lands on a guessed day.
    "reminders": [
        ToolSpec(
            "now",
            "Current date/time: UTC, server-local with UTC offset, and "
            "weekday. Call this FIRST whenever the user gives a relative "
            "or clock time ('tomorrow at 9am', 'in 2 hours') before "
            "computing due_at.",
            ActionCategory.READ,
        ),
        ToolSpec(
            "create",
            "Set a reminder that is delivered to the user at a future "
            "time. Give exactly one of due_at or delay_minutes. For a "
            "relative or clock time, call reminders.now first and compute "
            "due_at from it.",
            ActionCategory.WRITE,
            _schema(
                title={
                    "type": "string",
                    "description": "What to remind the user about (1-200 chars)",
                    "required": True,
                },
                note={
                    "type": "string",
                    "description": "Optional detail shown with the reminder (max 2000 chars)",
                },
                due_at={
                    "type": "string",
                    "description": (
                        "ISO-8601 time with UTC offset, e.g. 2026-09-24T09:00:00-04:00 "
                        "(naive = UTC). Use reminders.now for today's date and offset."
                    ),
                },
                delay_minutes={
                    "type": "integer",
                    "description": "Minutes from now (1-525600), instead of due_at",
                },
            ),
        ),
        ToolSpec(
            "list",
            "List the user's scheduled reminders, soonest first (max 20).",
            ActionCategory.READ,
        ),
        ToolSpec(
            "cancel",
            "Cancel one of the user's scheduled reminders by id (from "
            "reminders.list or reminders.create).",
            ActionCategory.WRITE,
            _schema(
                reminder_id={"type": "string", "description": "Reminder id", "required": True},
            ),
        ),
    ],
    # Built-in: the capability installer. The model may only *name* an
    # entry of ``services.tools.system.ALLOWLIST``; every command that
    # runs is spelled out there, so the schema's enum is the whole of what
    # the model can ask for. ``install_capability`` is a WRITE the policy
    # routes through the approval card and the executor refuses
    # unapproved; DELETE/EXECUTE/FINANCIAL are hard-blocked for the type,
    # so nothing that uninstalls or runs arbitrary commands could be added
    # here by mistake. The descriptions carry the "ask, then install"
    # rule because the system prompt only tells the model to say what is
    # missing; this is how it learns there is a sanctioned way to fix it.
    "system": [
        ToolSpec(
            "capabilities",
            "List the optional capabilities this installation can add (e.g. "
            "'browser', which web.screenshot needs) and whether each is "
            "installed right now, and the owner's permission switches (what "
            "is on, off or blocked and why).",
            ActionCategory.READ,
        ),
        ToolSpec(
            "install_capability",
            "Install one optional capability by name, from a fixed allowlist. "
            "If a tool reports a missing capability (e.g. web.screenshot says "
            "the browser is not installed), call this with its name; the user "
            "will be asked to approve the install first, so tell them what it "
            "is for and wait for the result. Only the listed names work: this "
            "cannot install arbitrary packages.",
            ActionCategory.WRITE,
            _schema(
                name={
                    "type": "string",
                    "enum": sorted(SYSTEM_CAPABILITIES),
                    "description": "Capability name, e.g. 'browser'",
                    "required": True,
                },
            ),
        ),
    ],
    # Built-in, capability "screen" (off by default): the owner turns it on
    # in Settings → Permissions. Reads the display; never types or clicks.
    "desktop": [
        ToolSpec(
            "screenshot",
            "Take a picture of what is currently on this computer's screen "
            "(the real desktop, not a web page). Use when the user asks what "
            "they are looking at or to send them a screenshot of the computer.",
            ActionCategory.READ,
            _schema(display={"type": "integer", "description": "Display index, 0 = main"}),
        ),
    ],
}

# Types offered to every user with no connector row and no credentials.
BUILTIN_CONNECTOR_TYPES: tuple[str, ...] = ("web", "reminders", "system", "desktop")

# The tier each built-in stands in for the connector row it does not
# have. web and reminders run unattended by policy, so an account whose
# default is auto_approve changes nothing for them. system is different:
# standing consent for emails and calendar entries is not consent to put
# new software on the machine, so its install action keeps the approval
# card under every account default rather than being downgraded to auto.
_BUILTIN_STANCE: dict[str, str] = {
    "web": "auto_approve",
    "reminders": "auto_approve",
    "system": "user_confirm",
    # Reads are auto by policy, so this changes nothing for the one action
    # there is; the capability switch (off by default) is the real gate.
    "desktop": "user_confirm",
}


def connector_scopes(connector_type: str) -> dict[str, list[str]]:
    """Return the catalog's scopes for a connector, grouped by risk.

    ``read`` scopes only expose data; ``write`` scopes let the agent change
    things (each write action still goes through the approval flow).
    """
    specs = CONNECTOR_CATALOG.get(connector_type, [])
    read: set[str] = set()
    write: set[str] = set()
    for spec in specs:
        if not spec.required_scope or spec.category == ActionCategory.FINANCIAL:
            continue
        if spec.category == ActionCategory.READ:
            read.add(spec.required_scope)
        else:
            write.add(spec.required_scope)
    return {"read": sorted(read), "write": sorted(write)}


def default_read_scopes(connector_type: str) -> list[str]:
    """Least-privilege default: the connector's read-only scopes."""
    return connector_scopes(connector_type)["read"]


# ---------------------------------------------------------------------------
# Connector spec (DB-free, so the registry is unit-testable)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ConnectorSpec:
    """The slice of a ConnectorConfig the registry needs. Decoupled from
    the SQLAlchemy model so building tools requires no database.

    ``granted_scopes=None`` means "not specified" (legacy connectors):
    no scope filtering happens at offer time, and the executor falls back
    to read-only enforcement. An explicit tuple filters the offered tools.

    ``permission_tier`` is the user's per-connector approval policy
    (``auto_approve`` / ``user_confirm`` / ``admin_only``); it is combined
    with the user's account-level default via :func:`effective_tier`.

    ``connector_id`` is the row's primary key. It is what tells two
    active connectors of the same type apart, both in the tool name and
    at dispatch; without it a second row of a type the registry already
    saw cannot be addressed at all (see ``build_tools``).
    ``display_name`` is the account label shown to the model alongside
    the disambiguated name — a slug on its own says nothing about which
    of two accounts is being picked.
    """

    connector_type: str
    is_active: bool = True
    granted_scopes: Optional[tuple[str, ...]] = None
    permission_tier: str = "user_confirm"
    connector_id: Optional[str] = None
    display_name: Optional[str] = None


# Separator between a connector type and a per-row slug in a tool name.
# Double, because connector types themselves contain single underscores
# ("google_workspace") and the two must not be confusable.
_SLUG_SEPARATOR = "__"
_SLUG_HEX_LENGTH = 8


def connector_slug(connector_id: str) -> str:
    """Stable short handle for one connector row.

    Derived from the row id rather than from its position, so the name a
    tool is offered under does not change when an unrelated connector is
    added or removed, and so the executor can map a name back to a row by
    recomputing this.
    """
    return hashlib.blake2s(
        connector_id.encode("utf-8"), digest_size=_SLUG_HEX_LENGTH // 2
    ).hexdigest()


# Ordering used to combine the per-connector tier with the user's account
# default: the STRICTER of the two wins.
_TIER_STRICTNESS: dict[str, int] = {
    "auto_approve": 0,
    "user_confirm": 1,
    "admin_only": 2,
    "hard_blocked": 3,
}


def effective_tier(
    connector_tier: Optional[str], user_default_tier: Optional[str]
) -> str:
    """The effective approval tier: the stricter of the connector's own
    tier and the user's account-level ``default_permission_tier``.
    Unknown/missing values fall back to ``user_confirm``."""
    conn = (connector_tier or "user_confirm").lower()
    user = (user_default_tier or "user_confirm").lower()
    if conn not in _TIER_STRICTNESS:
        conn = "user_confirm"
    if user not in _TIER_STRICTNESS:
        user = "user_confirm"
    return conn if _TIER_STRICTNESS[conn] >= _TIER_STRICTNESS[user] else user


# ---------------------------------------------------------------------------
# Tool-name resolution
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ResolvedTool:
    connector_type: str
    action: str
    spec: ToolSpec
    # Which connector row the call names, when the user has more than one
    # of this type. None means "the only row of this type".
    slug: Optional[str] = None

    @property
    def policy_key(self) -> str:
        return self.spec.policy_key or self.connector_type


def resolve_tool(tool_name: str) -> Optional[ResolvedTool]:
    """Map a namespaced ``connector_type.action`` name back to its spec.

    Accepts both the plain ``canvas.get_courses`` form and the
    disambiguated ``canvas__1f2e3d4c.get_courses`` one. Permissions key
    off the connector type either way, so two rows of the same type can
    never resolve to different tiers.

    Returns None for malformed names, unknown connector/action, and a slug
    on a built-in type, so callers can fail safe (default-deny) rather
    than raise.
    """
    if "." not in tool_name:
        return None
    namespace, _, action = tool_name.partition(".")

    connector_type, slug = namespace, None
    if namespace not in CONNECTOR_CATALOG and _SLUG_SEPARATOR in namespace:
        connector_type, _, slug = namespace.rpartition(_SLUG_SEPARATOR)
        if len(slug) != _SLUG_HEX_LENGTH or not all(
            c in "0123456789abcdef" for c in slug
        ):
            return None
        if connector_type in BUILTIN_CONNECTOR_TYPES:
            # Built-ins have no connector rows, so nothing is ever offered
            # under a slug. Accepting one would hand the model a second
            # spelling (``desktop__deadbeef.screenshot``) that capability
            # lookups keyed on the plain name do not recognise.
            return None

    specs = CONNECTOR_CATALOG.get(connector_type)
    if not specs:
        return None
    for spec in specs:
        if spec.action == action:
            return ResolvedTool(connector_type, action, spec, slug)
    return None


def _default_enabled_capabilities() -> frozenset[str]:
    """The registry defaults: what an unwired gate treats as on, so a
    caller that forgets to pass the owner's set can never switch on an
    off-by-default capability (``screen``)."""
    from services import capabilities as capability_registry

    return frozenset(k for k, on in capability_registry.default_switches().items() if on)


def _capability_of(connector_type: str, action: str) -> Optional[Capability]:
    """The capability gating one built-in action, looked up by its
    canonical ``type.action`` name — never by whatever spelling the model
    used — so every gate agrees on which switch applies."""
    from services import capabilities as capability_registry

    return capability_registry.capability_for_tool(f"{connector_type}.{action}")


def capability_of_tool(tool_name: str) -> Optional[Capability]:
    """The capability gating *tool_name*: the name is resolved first and
    the capability looked up by its canonical ``type.action``. None for a
    name that does not resolve (MCP tools, unknown or slugged built-in
    spellings) and for a tool no capability gates."""
    resolved = resolve_tool(tool_name)
    if resolved is None:
        return None
    return _capability_of(resolved.connector_type, resolved.action)


# The owner's capability report indexed by key
# (InstallationService.capability_statuses). The adapter and the executor
# read it per call; the offer (build_tools) takes the enabled set instead.
CapabilityGate = Callable[[], Awaitable[Mapping[str, CapabilityStatus]]]

CapabilityState = Literal["off", "blocked", "error"]


@dataclass(frozen=True)
class _CapabilityRefusal:
    """Why a capability refuses a tool right now: what to tell the model
    and the user (``reason``) and what the audit row records (``policy``)."""

    state: CapabilityState
    reason: str
    policy: str


def _off(cap: Capability) -> _CapabilityRefusal:
    return _CapabilityRefusal("off", cap.when_denied, CAPABILITY_OFF_POLICY)


def _blocked_reason(status: CapabilityStatus) -> str:
    """Why a switched-on capability is unusable here, and how to fix it:
    the report's reason, its first fix step, and the Install button when
    there is something to install."""
    reason = status.reason or f"{status.label} is not available here."
    if status.fix_steps:
        reason += f" To fix: {status.fix_steps[0]}"
    if status.install:
        reason += " The owner can install it from Settings → Permissions."
    return reason


async def _gate_refusal(
    gate: Optional[CapabilityGate], cap: Capability
) -> Optional[_CapabilityRefusal]:
    """Why *cap* refuses its tools right now, or None when they may run.

    Unwired (``gate`` None), the registry defaults stand in, so an
    off-by-default capability stays refused. Anything short of a report
    saying ``on`` refuses: ``off`` and ``blocked`` as the report says, a
    report without this capability as off, and a gate that raises (or
    answers with something that is not a report) as a gate error — fail
    closed. Only the exception's type is logged: its message can quote a
    connection string.
    """
    if gate is None:
        return None if cap.default_enabled else _off(cap)
    try:
        status = (await gate()).get(cap.key)
        if status is None:
            # No entry for this capability in the report: treat as off,
            # same as an explicit "off" - never crash on a missing status.
            return _off(cap)
        if status.effective == "on":
            return None
        if status.effective == "blocked":
            return _CapabilityRefusal(
                "blocked", _blocked_reason(status), CAPABILITY_BLOCKED_POLICY
            )
        return _off(cap)
    except Exception as exc:
        logger.warning(
            "capability_gate_failed", capability=cap.key, error_type=type(exc).__name__
        )
        return _CapabilityRefusal(
            "error", CAPABILITY_GATE_ERROR_REASON, CAPABILITY_GATE_ERROR_POLICY
        )


# Map a PermissionDecision to the string the runtime's check() returns.
def _runtime_decision(allowed: bool, requires_approval: bool, tier: PermissionTier) -> str:
    if tier == PermissionTier.HARD_BLOCKED or (not allowed and not requires_approval):
        return "blocked"
    if requires_approval:
        return "requires_approval"
    return "approved"


def _scope_allows(spec: ToolSpec, granted_scopes: Optional[tuple[str, ...]]) -> bool:
    """Offer-time scope filter. ``None`` (unspecified) imposes no filter;
    an explicit grant list must contain the action's required scope."""
    if granted_scopes is None or not spec.required_scope:
        return True
    return spec.required_scope in granted_scopes


# ---------------------------------------------------------------------------
# Registry: build the tool list for a user's connectors
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class _Offer:
    """One namespace the tool list is built under, with its tier resolved."""

    namespace: str
    connector_type: str
    label: str
    tier: str
    granted_scopes: Optional[tuple[str, ...]] = None


def _account_label(display_name: Optional[str]) -> str:
    """Render a connector's display name for a tool description.

    The name is user-supplied text heading into the model's tool list,
    which is prompt surface: newlines and control characters are dropped
    so it cannot open what looks like a new instruction block, and the
    length is capped.
    """
    if not display_name:
        return ""
    cleaned = "".join(c if c.isprintable() else " " for c in display_name)
    return " ".join(cleaned.split())[:40]


def _offers_for(
    connectors: Iterable[ConnectorSpec],
    user_default_tier: str,
    is_admin: bool,
) -> list[_Offer]:
    """Resolve a user's connectors to the namespaces tools are built under.

    A single active row of a type keeps the plain ``canvas`` namespace.
    Two rows of one type would otherwise emit the same tool names twice:
    the model sees one entry, and whichever row the executor happened to
    load (the newest) is the only one that could ever run. So each row of
    a contested type gets its own ``canvas__<slug>`` namespace instead,
    plus its display name in the description.

    Disambiguation is decided before tier filtering, not after: a name
    must identify the row it was built from even when its sibling is
    filtered out, or the executor would fall back to "newest row" and
    dispatch the call to a connector the user never offered it.

    Rows of a contested type that carry no id cannot be told apart at
    all, so the whole type is dropped with a logged error rather than
    guessed at from row order.

    Output is sorted, not in input order, because the caller's query has
    no ORDER BY: the same set of connectors must always produce the same
    tool list.
    """
    by_type: dict[str, list[ConnectorSpec]] = {}
    for conn in connectors:
        if not conn.is_active:
            continue
        if conn.connector_type not in CONNECTOR_CATALOG:
            continue  # unknown connector type: skip safely
        by_type.setdefault(conn.connector_type, []).append(conn)

    offers: list[_Offer] = []
    for connector_type in sorted(by_type):
        rows = by_type[connector_type]
        if len(rows) == 1:
            namespaced = [(connector_type, rows[0], "")]
        else:
            identified = sorted(
                (row for row in rows if row.connector_id),
                key=lambda row: row.connector_id or "",
            )
            slugs = {connector_slug(row.connector_id or "") for row in identified}
            if len(identified) != len(rows) or len(slugs) != len(rows):
                logger.error(
                    "connector_rows_indistinguishable",
                    connector_type=connector_type,
                    rows=len(rows),
                    identified=len(identified),
                    slugs=len(slugs),
                )
                continue
            namespaced = [
                (
                    f"{connector_type}{_SLUG_SEPARATOR}"
                    f"{connector_slug(row.connector_id or '')}",
                    row,
                    _account_label(row.display_name),
                )
                for row in identified
            ]

        for namespace, conn, label in namespaced:
            tier = effective_tier(conn.permission_tier, user_default_tier)
            if tier == "hard_blocked":
                continue
            if tier == "admin_only" and not is_admin:
                # Only the deployment's admin may use an admin_only
                # connector; for anyone else it contributes no tools at
                # all. Gating here is what makes an approval-time admin
                # check unnecessary: a non-admin can never get such an
                # action parked for approval in the first place.
                continue
            offers.append(
                _Offer(namespace, connector_type, label, tier, conn.granted_scopes)
            )
    return offers


def build_tools(
    connectors: Iterable[ConnectorSpec],
    engine: Optional[PermissionEngine] = None,
    user_tier: UserTier = UserTier.STANDARD,
    user_default_tier: str = "user_confirm",
    is_admin: bool = False,
    *,
    include_builtins: bool = True,
    enabled_capabilities: Optional[frozenset[str]] = None,
) -> list[Tool]:
    """Produce the runtime ``Tool`` objects for a user's active connectors.

    ``enabled_capabilities`` is the owner's effective set (see
    services/capabilities); tools of any other capability are not offered.
    ``None`` means the registry defaults, so a caller that forgets the
    argument can never offer an off-by-default capability (``screen``).

    Built-in types (``web``, ``reminders``, ``system``, ``desktop``) are
    appended for every user: they hold no credentials, so there is no
    connector row to gate them on. They are still held to the user's
    account-level tier, which is a floor over everything the agent may do
    unattended. The account tier can only tighten what the static policy
    grants: an action the policy auto-approves (web reads, reminder
    writes) stays unattended under the default ``user_confirm``, exactly
    as connector reads do. The ``system`` install stays approval-gated
    even under an ``auto_approve`` account default (see
    ``_BUILTIN_STANCE``).

    Hard-blocked actions and actions outside the connector's granted
    scopes are omitted entirely so the LLM is never offered a tool it
    cannot use. The runtime still independently blocks them via the
    permission adapter, and the executor re-checks scopes at dispatch
    time (defense in depth).

    Per-connector permission tiers (combined with the user's account
    default — the stricter wins) shape the offer:

    - ``admin_only``: the connector is usable only by the deployment's
      admin. For anyone else it contributes no tools at all. For the admin,
      the static policy then applies as usual (including the actions the
      policy itself marks ADMIN_ONLY, which require their confirmation
      rather than being refused outright).
    - ``auto_approve``: actions the static policy would send to the
      approval flow are offered as ``auto`` instead — EXCEPT financial /
      hard-blocked actions, which remain absolutely blocked at every
      layer regardless of tier.
    - ``user_confirm`` (default): static policy applies unchanged —
      write-scope tools require explicit approval.
    """
    if enabled_capabilities is None:
        # No wiring supplied: fall back to the registry defaults so a caller
        # that forgets the argument can never switch on an off-by-default
        # capability (screen). Wired callers pass the owner's effective set.
        enabled_capabilities = _default_enabled_capabilities()
    engine = engine or PermissionEngine()
    # The static policy already distinguishes admins (ADMIN_ONLY actions
    # require their confirmation instead of being refused outright); it had
    # simply never been handed one.
    if is_admin:
        user_tier = UserTier.ADMIN
    offers = _offers_for(connectors, user_default_tier, is_admin)
    if include_builtins:
        configured = {offer.connector_type for offer in offers}
        for builtin in BUILTIN_CONNECTOR_TYPES:
            if builtin in configured:
                continue
            # No connector row means no per-connector tier, so the type's
            # own stance stands in for one and the user's account default
            # still floors it.
            tier = effective_tier(_BUILTIN_STANCE[builtin], user_default_tier)
            if tier == "hard_blocked" or (tier == "admin_only" and not is_admin):
                continue
            offers.append(_Offer(builtin, builtin, "", tier))

    tools: list[Tool] = []
    for offer in offers:
        for spec in CONNECTOR_CATALOG[offer.connector_type]:
            if not _scope_allows(spec, offer.granted_scopes):
                continue
            policy_key = spec.policy_key or offer.connector_type
            decision = engine.check_permission(
                connector_type=policy_key,
                action=spec.action,
                scope=spec.category,
                user_tier=user_tier,
            )
            # Omit any tool the runtime would block for this user, not just
            # hard-blocked ones. This keeps the offered tool list consistent
            # with RuntimePermissionAdapter.check: e.g. ADMIN_ONLY actions
            # resolve to "blocked" for a standard user and must not be
            # offered to the model only to be rejected at call time.
            runtime_decision = _runtime_decision(
                decision.allowed, decision.requires_approval, decision.tier
            )
            if runtime_decision == "blocked":
                continue
            # auto_approve tier downgrades approval-gated tools to auto —
            # never financial/hard-blocked ones (those are filtered above,
            # but the guard is kept for defense in depth).
            if (
                offer.tier == "auto_approve"
                and runtime_decision == "requires_approval"
                and spec.category != ActionCategory.FINANCIAL
                and not is_hard_blocked_action(spec.action)
            ):
                runtime_decision = "approved"
            cap = _capability_of(offer.connector_type, spec.action)
            if cap is not None and cap.key not in enabled_capabilities:
                continue
            tool_name = f"{offer.namespace}.{spec.action}"
            tools.append(
                Tool(
                    name=tool_name,
                    description=(
                        f"{spec.description} (account: {offer.label})"
                        if offer.label
                        else spec.description
                    ),
                    parameters=spec.parameters or dict(_EMPTY_SCHEMA),
                    connector_type=offer.connector_type,
                    permission_tier="auto" if runtime_decision == "approved" else "approval",
                )
            )
    return tools


# ---------------------------------------------------------------------------
# Runtime permission adapter
# ---------------------------------------------------------------------------


class RuntimePermissionAdapter:
    """Adapts the real PermissionEngine to the interface the AgentRuntime
    expects (``check`` / ``get_block_reason`` / ``get_policy_name``).

    The runtime calls these with ``(user_id, tool_name, arguments)``; we
    resolve the tool name to its policy key + category and delegate to the
    real engine. Unknown tools are denied (blocked), which is default-deny.

    A built-in tool whose capability refuses it (see ``capability_gate``,
    the owner's report; the registry defaults when unwired) is "blocked"
    here: policy ``capability_off`` when the owner switched it off,
    ``capability_blocked`` (with the reason and fix) when it is on but not
    usable here, and ``capability_gate_error`` when the report could not
    be read. Refusing at this seam rather than only in the executor means
    the runtime records ``tool_blocked`` before any ``tool_executing``
    intent row and shows the user a blocked card; the executor's own gate
    stays as the backstop.

    The runtime calls ``check``, then (when blocked) ``get_block_reason``
    and ``get_policy_name`` for the same tool. The reason and policy come
    from the decision ``check`` made, not a fresh one: the report can
    refresh in between, and the audit row must not pair a capability block
    with the engine's reason for an allowed call.
    """

    # Decisions kept for the reason/policy calls that follow a check. The
    # runtime makes those right after check(), so a small window suffices.
    _DECISION_MEMO_SIZE = 256

    def __init__(
        self,
        engine: Optional[PermissionEngine] = None,
        user_tier: UserTier = UserTier.STANDARD,
        capability_gate: Optional[CapabilityGate] = None,
    ) -> None:
        self._engine = engine or PermissionEngine()
        self._user_tier = user_tier
        self._capability_gate = capability_gate
        # (user_id, tool_name) -> (decision, reason, policy) of the last check.
        self._decisions: OrderedDict[tuple[str, str], tuple[str, str, str]] = OrderedDict()

    async def _decide(self, tool_name: str) -> tuple[str, str, str]:
        """(decision, reason, policy) for one call to *tool_name*."""
        from services.mcp.integration import classify_mcp_tool, is_mcp_tool

        if is_mcp_tool(tool_name):
            # Third-party MCP tools never auto-approve; financial-looking
            # names are blocked outright.
            mcp_decision = classify_mcp_tool(tool_name)
            if mcp_decision == "blocked":
                return (
                    "blocked",
                    "MCP tool name matches a financial pattern; money-moving "
                    "actions are permanently blocked.",
                    "mcp:financial-pattern",
                )
            return (
                mcp_decision,
                "MCP tools require explicit user approval.",
                "mcp:default-approval",
            )
        resolved = resolve_tool(tool_name)
        if resolved is None:
            # Default-deny unknown tools.
            return "blocked", f"Unknown tool '{tool_name}' is denied by default.", "default-deny"
        cap = _capability_of(resolved.connector_type, resolved.action)
        if cap is not None:
            refusal = await _gate_refusal(self._capability_gate, cap)
            if refusal is not None:
                return "blocked", refusal.reason, refusal.policy
        decision = self._engine.check_permission(
            connector_type=resolved.policy_key,
            action=resolved.action,
            scope=resolved.spec.category,
            user_tier=self._user_tier,
        )
        return (
            _runtime_decision(decision.allowed, decision.requires_approval, decision.tier),
            decision.reason,
            f"{resolved.policy_key}:{resolved.spec.category.value}",
        )

    def _remember(self, key: tuple[str, str], decision: tuple[str, str, str]) -> None:
        self._decisions[key] = decision
        self._decisions.move_to_end(key)
        while len(self._decisions) > self._DECISION_MEMO_SIZE:
            self._decisions.popitem(last=False)

    async def _last_decision(self, user_id: str, tool_name: str) -> tuple[str, str, str]:
        """The decision the last check() made for this call, or a fresh one
        (remembered, so the policy call that follows agrees with it)."""
        key = (user_id, tool_name)
        decision = self._decisions.get(key)
        if decision is None:
            decision = await self._decide(tool_name)
            self._remember(key, decision)
        return decision

    async def check(self, user_id: str, tool_name: str, arguments: dict[str, Any]) -> str:
        decision = await self._decide(tool_name)
        self._remember((user_id, tool_name), decision)
        return decision[0]

    async def get_block_reason(self, user_id: str, tool_name: str, arguments: dict[str, Any]) -> str:
        return (await self._last_decision(user_id, tool_name))[1]

    async def get_policy_name(self, user_id: str, tool_name: str) -> str:
        return (await self._last_decision(user_id, tool_name))[2]


# ---------------------------------------------------------------------------
# Connector tool executor
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class _Builtin:
    """How the executor dispatches one built-in tool family.

    ``call(action, params, user_id, approved)`` runs the action on the
    family's toolkit. ``allowed`` is every category the family may run at
    all (the policy hard-blocks the rest; a spec in another category
    reaching here means the catalog gained an action the policy was never
    written for). ``confirm`` is the subset that runs only with
    ``approved=True``, with ``confirm_note`` saying why in the refusal.
    """

    label: str
    call: Callable[[str, dict[str, Any], str, bool], Awaitable[dict[str, Any]]]
    allowed: frozenset[ActionCategory]
    confirm: frozenset[ActionCategory] = frozenset()
    confirm_note: str = "changes something"


class ConnectorToolExecutor:
    """Dispatches an approved tool call through the real connector stack.

    Per call: load the user's active connector config, enforce granted
    scopes and the per-connector rate limit, decrypt credentials,
    instantiate the connector (which arms the deny-by-default network
    policy), authenticate, execute, and return the sanitized result.

    Built-in tools (``web.*``, ``reminders.*``, ``system.*``,
    ``desktop.*``) run here too, but take none of that path. They are
    first checked against the owner's capability report
    (``capability_gate``; the registry defaults when unwired) and refused
    unless theirs is on; the refusal says whether it is off, blocked or
    the report could not be read. Beyond that they have no credentials to
    decrypt, no connector row to load and no scopes to check, so they dispatch
    straight to their toolkit. The reminder toolkit shares this
    executor's session factory and is handed the caller's ``user_id``,
    which is the only identity it will write under.

    ``approved=True`` means the call already passed the explicit user
    approval flow; it unlocks connector actions that demand per-call
    confirmation, and it is the only thing that lets a ``system`` write
    (installing software) run at all. The flag can never come from tool
    arguments — any LLM-supplied ``user_confirmed`` value is stripped
    before dispatch.

    Whatever comes back is data, never instruction: the runtime scans
    every tool result before it reaches the model, and fetched web pages
    in particular are hostile input. Nothing here may shortcut that.

    Constructed without a session factory the executor cannot load
    credentials and refuses to dispatch connector tools (fail closed);
    ``main.py`` wires it with the application session factory at startup.
    """

    def __init__(
        self,
        session_factory: Optional[Callable[[], Any]] = None,
        web_toolkit: Optional[WebToolkit] = None,
        reminder_toolkit: Optional[ReminderToolkit] = None,
        system_toolkit: Optional[SystemToolkit] = None,
        desktop_toolkit: Optional[DesktopToolkit] = None,
        capability_gate: Optional[CapabilityGate] = None,
    ) -> None:
        self._session_factory = session_factory
        web = web_toolkit or WebToolkit()
        reminders = reminder_toolkit or ReminderToolkit(session_factory)
        system = system_toolkit or SystemToolkit()
        desktop = desktop_toolkit or DesktopToolkit()
        read, write = ActionCategory.READ, ActionCategory.WRITE
        # One entry per built-in family (see services/capabilities/README.md).
        # Only the reminder toolkit is handed the caller's identity: it is
        # the only one that stores anything per user.
        self._builtins: dict[str, _Builtin] = {
            "web": _Builtin(
                "Web",
                lambda a, p, uid, ok: web.execute(a, p),
                frozenset({read}),
            ),
            "reminders": _Builtin(
                "Reminder",
                lambda a, p, uid, ok: reminders.execute(a, p, uid),
                frozenset({read, write}),
            ),
            # Installing software is never done on the model's say-so. The
            # runtime parks the call for the user and re-dispatches it with
            # approved=True once they say yes; anything else reaching here
            # unapproved is refused, the same contract a connector's
            # per-call confirmation uses.
            "system": _Builtin(
                "System",
                lambda a, p, uid, ok: system.execute(a, p),
                frozenset({read, write}),
                confirm=frozenset({write}),
                confirm_note="installs software on this machine",
            ),
            "desktop": _Builtin(
                "Desktop",
                lambda a, p, uid, ok: desktop.execute(a, p),
                frozenset({read}),
            ),
        }
        # Returns the owner's capability report by key. Unwired, the
        # registry defaults apply (see _gate_refusal), so an off-by-default
        # capability stays refused.
        self._capability_gate = capability_gate
        # Per connector-config sliding-window limiters. Persist across
        # calls (connector instances are per-call) within this process.
        self._limiters: dict[uuid_module.UUID, Any] = {}
        self._mcp_dispatcher: Optional[Any] = None

    def _get_mcp_dispatcher(self):
        if self._mcp_dispatcher is None:
            from services.mcp.integration import MCPConnectorLoader, MCPDispatcher

            self._mcp_dispatcher = MCPDispatcher(
                MCPConnectorLoader(self._session_factory)
            )
        return self._mcp_dispatcher

    async def execute(
        self,
        tool_name: str,
        arguments: dict[str, Any],
        user_id: str,
        approved: bool = False,
    ) -> dict[str, Any]:
        from services.mcp.integration import is_mcp_tool

        if is_mcp_tool(tool_name):
            if self._session_factory is None:
                return {
                    "ok": False,
                    "error": (
                        "Connector execution is not configured (no database "
                        "session factory); refusing to dispatch."
                    ),
                }
            return await self._get_mcp_dispatcher().execute(
                tool_name, dict(arguments), user_id
            )

        resolved = resolve_tool(tool_name)
        if resolved is None:
            return {"error": f"Unknown tool '{tool_name}'", "ok": False}
        if resolved.spec.category == ActionCategory.FINANCIAL:
            # Belt-and-suspenders: never execute a financial action even if
            # one somehow reaches the executor.
            return {
                "error": f"Action '{resolved.action}' is permanently blocked.",
                "ok": False,
            }

        # Confirmation status is decided by the approval flow, never by the
        # model. Strip any attempt to smuggle it through tool arguments.
        arguments = {k: v for k, v in arguments.items() if k != "user_confirmed"}

        cap = _capability_of(resolved.connector_type, resolved.action)
        refusal = await _gate_refusal(self._capability_gate, cap) if cap is not None else None
        if cap is not None and refusal is not None:
            # Second gate, independent of the offer: a tool whose capability
            # is off, blocked, or unreadable is refused even if the model
            # somehow names it. Looked up by the canonical name, so no
            # alternate spelling slips past. The runtime files this shape
            # as tool_blocked under the state's policy (_capability_refusal).
            logger.info(
                "tool_capability_refused",
                tool=tool_name,
                capability=cap.key,
                state=refusal.state,
                user_id=user_id,
            )
            return {
                "ok": False,
                "capability": cap.key,
                "state": refusal.state,
                "error": refusal.reason,
            }

        builtin = self._builtins.get(resolved.connector_type)
        if builtin is not None:
            category = resolved.spec.category
            if category not in builtin.allowed:
                return {
                    "ok": False,
                    "error": f"{builtin.label} action '{resolved.action}' is not permitted.",
                }
            if category in builtin.confirm and not approved:
                return {
                    "ok": False,
                    "requires_approval": True,
                    "error": (
                        f"Action requires user confirmation: "
                        f"{resolved.connector_type}.{resolved.action} "
                        f"{builtin.confirm_note} and runs only after the user "
                        "approves it."
                    ),
                }
            return await builtin.call(resolved.action, dict(arguments), user_id, approved)

        if self._session_factory is None:
            return {
                "ok": False,
                "error": (
                    "Connector execution is not configured (no database "
                    "session factory); refusing to dispatch."
                ),
            }

        config = await self._load_config(
            resolved.connector_type, user_id, resolved.slug
        )
        if config is None:
            return {
                "ok": False,
                "error": f"No active '{resolved.connector_type}' connector is configured.",
            }

        scope_error = self._check_scope(resolved, list(config["granted_scopes"] or []))
        if scope_error:
            return {"ok": False, "error": scope_error}

        # Dispatch-time tier enforcement. Offer-time filtering alone is not
        # enough: a model can emit a tool name it was never offered (via
        # hallucination or injected content), and the static permission
        # engine cannot see per-connector or per-user tiers. Re-resolve the
        # effective tier here so hard_blocked and admin_only hold at the
        # moment of execution — the same defense-in-depth the financial
        # block already has.
        tier = effective_tier(
            config.get("permission_tier"), config.get("user_default_tier")
        )
        if tier == "hard_blocked":
            return {
                "ok": False,
                "error": (
                    f"Connector '{resolved.connector_type}' is hard-blocked "
                    "by its permission tier."
                ),
            }
        if tier == "admin_only" and not config.get("user_is_admin"):
            return {
                "ok": False,
                "error": (
                    f"Connector '{resolved.connector_type}' is admin-only "
                    "and this account is not an administrator."
                ),
            }

        from services.connectors.base import (
            AuthenticationError,
            ConnectorError,
            HardBlockError,
            RateLimitExceededError,
            UserConfirmationRequired,
        )

        limiter_error = self._acquire_rate_limit(
            config["id"], config["rate_limit_per_minute"]
        )
        if limiter_error:
            return {"ok": False, "error": limiter_error}

        from services.connectors.factory import create_connector

        try:
            connector = create_connector(
                resolved.connector_type,
                config["credentials"],
                rate_limit=config["rate_limit_per_minute"],
            )
        except ConnectorError as exc:
            return {"ok": False, "error": str(exc)}

        try:
            await connector.authenticate(config["credentials"])
            try:
                response = await connector.execute(resolved.action, dict(arguments))
            except UserConfirmationRequired as exc:
                if not approved:
                    return {
                        "ok": False,
                        "requires_approval": True,
                        "error": f"Action requires user confirmation: {exc.details}",
                    }
                response = await connector.execute(
                    resolved.action, {**arguments, "user_confirmed": True}
                )
            return {
                "ok": True,
                "connector": resolved.connector_type,
                "action": resolved.action,
                "result": response.data,
                "sanitized": response.sanitized,
                "execution_time_ms": response.execution_time_ms,
            }
        except HardBlockError as exc:
            return {"ok": False, "error": str(exc)}
        except (AuthenticationError, RateLimitExceededError) as exc:
            return {"ok": False, "error": str(exc)}
        except ConnectorError as exc:
            return {"ok": False, "error": str(exc)}
        except Exception as exc:  # never leak a raw traceback into the chat
            logger.error(
                "connector_dispatch_unexpected_error",
                connector=resolved.connector_type,
                action=resolved.action,
                error=str(exc),
            )
            return {"ok": False, "error": f"Connector failure: {exc}"}
        finally:
            # Persist tokens the connector rotated during this call (e.g. a
            # Google refresh) before the instance is thrown away — even when
            # the API call itself failed, a newly minted token is valid and
            # saves the next call a round trip (or a dead connector).
            updater = getattr(connector, "updated_credentials", None)
            if callable(updater):
                try:
                    new_creds = updater(config["credentials"])
                    if new_creds:
                        await self._persist_credentials(config["id"], new_creds)
                except Exception as exc:
                    logger.warning(
                        "credential_persist_failed",
                        connector=resolved.connector_type,
                        error=str(exc),
                    )
            await connector.close()

    async def _persist_credentials(
        self, config_id: uuid_module.UUID, credentials: dict[str, Any]
    ) -> None:
        import json as json_module

        from sqlalchemy import update

        from core.security import encrypt_credentials
        from models.connector import ConnectorConfig

        async with self._session_factory() as session:
            await session.execute(
                update(ConnectorConfig)
                .where(ConnectorConfig.id == config_id)
                .values(
                    encrypted_credentials=encrypt_credentials(
                        json_module.dumps(credentials)
                    )
                )
            )
            await session.commit()

    # -- helpers ------------------------------------------------------------

    async def _load_config(
        self, connector_type: str, user_id: str, slug: Optional[str] = None
    ) -> Optional[dict[str, Any]]:
        """Fetch the named active connector config + decrypted credentials.

        *slug* is the per-row handle a disambiguated tool name carries
        (see ``build_tools``); it selects which of several active rows of
        one type the call meant. A name without one is only ever offered
        when the type has a single active row, so the newest row is the
        right answer for it — and a slug that matches nothing returns
        None rather than falling back to the newest, which would run the
        call against an account the user did not name.

        Returns a plain dict (not the ORM row) so the session can close
        before any network I/O happens.
        """
        import json as json_module

        from sqlalchemy import select

        from core.security import decrypt_credentials
        from models.connector import ConnectorConfig, ConnectorType
        from models.user import User

        try:
            user_uuid = uuid_module.UUID(user_id)
            type_enum = ConnectorType(connector_type)
        except ValueError:
            return None

        async with self._session_factory() as session:
            result = await session.execute(
                select(ConnectorConfig)
                .where(
                    ConnectorConfig.user_id == user_uuid,
                    ConnectorConfig.connector_type == type_enum,
                    ConnectorConfig.is_active.is_(True),
                )
                .order_by(ConnectorConfig.created_at.desc())
            )
            rows = list(result.scalars().all())
            if slug is None:
                config = rows[0] if rows else None
            else:
                config = next(
                    (row for row in rows if connector_slug(str(row.id)) == slug), None
                )
            if config is None:
                return None

            # The tier must be re-checked at dispatch time (not only at
            # tool-offer time), so load the pieces effective_tier needs.
            user_row = (
                await session.execute(select(User).where(User.id == user_uuid))
            ).scalar_one_or_none()
            raw_tier = getattr(config, "permission_tier", None)
            tier_fields = {
                # The column is an Enum; effective_tier() wants the string.
                "permission_tier": getattr(raw_tier, "value", raw_tier),
                "user_default_tier": getattr(
                    user_row, "default_permission_tier", None
                ),
                "user_is_admin": bool(getattr(user_row, "is_admin", False)),
            }

            try:
                credentials = json_module.loads(
                    decrypt_credentials(config.encrypted_credentials)
                )
            except Exception:
                logger.error(
                    "credential_decryption_failed",
                    connector_id=str(config.id),
                    connector_type=connector_type,
                )
                return {
                    "id": config.id,
                    "credentials": {},
                    "granted_scopes": config.granted_scopes,
                    "rate_limit_per_minute": config.rate_limit_per_minute,
                    **tier_fields,
                }

            return {
                "id": config.id,
                "credentials": credentials,
                "granted_scopes": config.granted_scopes,
                "rate_limit_per_minute": config.rate_limit_per_minute,
                **tier_fields,
            }

    @staticmethod
    def _check_scope(resolved: ResolvedTool, granted_scopes: list[str]) -> Optional[str]:
        """Dispatch-time scope enforcement (the authoritative check).

        Connectors saved without explicit scopes (legacy rows) fall back
        to read-only: READ actions run, anything else is refused until the
        user grants scopes on the connector.
        """
        required = resolved.spec.required_scope
        if not required:
            return None
        if not granted_scopes:
            if resolved.spec.category == ActionCategory.READ:
                return None
            return (
                f"Connector has no granted scopes; '{required}' is required "
                f"for '{resolved.action}'. Edit the connector to grant it."
            )
        if required not in granted_scopes:
            return (
                f"Scope '{required}' has not been granted on this connector "
                f"(granted: {', '.join(granted_scopes)})."
            )
        return None

    def _acquire_rate_limit(
        self, config_id: uuid_module.UUID, max_per_minute: int
    ) -> Optional[str]:
        from services.connectors.base import RateLimiter, RateLimitExceededError

        limiter = self._limiters.get(config_id)
        if limiter is None or limiter.max_calls != max_per_minute:
            limiter = RateLimiter(max_per_minute)
            self._limiters[config_id] = limiter
        try:
            limiter.acquire()
        except RateLimitExceededError as exc:
            return str(exc)
        return None
