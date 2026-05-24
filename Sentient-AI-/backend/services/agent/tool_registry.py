"""Connector tool registry and executor.

Turns a user's active connectors into runtime ``Tool`` objects, bridges
the runtime's permission seam to the real permission engine, and
dispatches approved tool calls to the connectors.

Three pieces plug into the agent runtime:

- ``build_tools(...)`` produces the ``Tool`` list the route passes to
  ``runtime.chat``. Hard-blocked actions are omitted so the LLM is never
  offered a tool it can't use.
- ``RuntimePermissionAdapter`` implements the runtime's expected
  ``check / get_block_reason / get_policy_name`` interface by delegating
  to ``services.agent.permissions.PermissionEngine``. Injected into the
  runtime singleton.
- ``ConnectorToolExecutor`` resolves a namespaced tool name and dispatches
  it. Real connector instantiation needs decrypted OAuth credentials, so
  for now it returns deterministic mock payloads through a clearly marked
  seam (``_dispatch``). Wiring real connectors is the follow-up.

Tool names are namespaced ``<connector_type>.<action>`` (e.g.
``canvas.get_assignments``). The connector_type segment is the
``ConnectorType`` enum value (canvas / google_workspace / robinhood),
NOT the connector class's category property ("lms"/"email"/"finance").
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Iterable, Optional

import structlog

from services.agent.permissions import (
    ActionCategory,
    PermissionEngine,
    PermissionTier,
    UserTier,
)
from services.agent.runtime import Tool

logger = structlog.get_logger(__name__)


# ---------------------------------------------------------------------------
# Static action catalog
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ToolSpec:
    """Declarative description of one connector action.

    ``policy_key`` is the connector_type string the permission engine is
    keyed by, which for Google differs per action (gmail vs
    google_calendar). It defaults to the owning connector_type.
    """

    action: str
    description: str
    category: ActionCategory
    parameters: dict[str, Any] = field(default_factory=dict)
    policy_key: Optional[str] = None


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
        ToolSpec("get_courses", "List the user's active Canvas courses.", ActionCategory.READ),
        ToolSpec(
            "get_assignments",
            "List assignments for a Canvas course.",
            ActionCategory.READ,
            _schema(course_id={"type": "string", "description": "Canvas course id", "required": True}),
        ),
        ToolSpec(
            "get_grades",
            "Get the user's grades for a Canvas course.",
            ActionCategory.READ,
            _schema(course_id={"type": "string", "description": "Canvas course id", "required": True}),
        ),
        ToolSpec("get_calendar_events", "List upcoming Canvas calendar events.", ActionCategory.READ),
        ToolSpec(
            "get_submissions",
            "List submissions for a Canvas assignment.",
            ActionCategory.READ,
            _schema(
                course_id={"type": "string", "required": True},
                assignment_id={"type": "string", "required": True},
            ),
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
        ),
    ],
    "google_workspace": [
        ToolSpec(
            "get_messages",
            "List recent Gmail messages, optionally filtered by query.",
            ActionCategory.READ,
            _schema(query={"type": "string"}, max_results={"type": "integer"}),
            policy_key="gmail",
        ),
        ToolSpec(
            "get_message",
            "Fetch a single Gmail message by id.",
            ActionCategory.READ,
            _schema(message_id={"type": "string", "required": True}),
            policy_key="gmail",
        ),
        ToolSpec(
            "search_emails",
            "Search Gmail messages with a query string.",
            ActionCategory.READ,
            _schema(query={"type": "string", "required": True}),
            policy_key="gmail",
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
        ),
        ToolSpec(
            "get_events",
            "List upcoming Google Calendar events.",
            ActionCategory.READ,
            policy_key="google_calendar",
        ),
        ToolSpec(
            "check_availability",
            "Check Google Calendar availability for a time range.",
            ActionCategory.READ,
            _schema(time_min={"type": "string"}, time_max={"type": "string"}),
            policy_key="google_calendar",
        ),
        ToolSpec(
            "create_event",
            "Create a Google Calendar event.",
            ActionCategory.WRITE,
            _schema(
                summary={"type": "string", "required": True},
                start={"type": "string", "required": True},
                end={"type": "string", "required": True},
            ),
            policy_key="google_calendar",
        ),
    ],
    "robinhood": [
        ToolSpec("get_crypto_portfolio", "View the Robinhood crypto portfolio (read-only).", ActionCategory.READ),
        ToolSpec(
            "get_crypto_prices",
            "Get current prices for crypto symbols (read-only).",
            ActionCategory.READ,
            _schema(symbols={"type": "array", "items": {"type": "string"}, "required": True}),
        ),
        ToolSpec("get_crypto_holdings", "View current crypto holdings (read-only).", ActionCategory.READ),
        ToolSpec(
            "execute_trade",
            "Execute a crypto trade. Permanently blocked by platform policy.",
            ActionCategory.FINANCIAL,
            _schema(symbol={"type": "string", "required": True}, side={"type": "string", "required": True}),
        ),
    ],
}


# ---------------------------------------------------------------------------
# Connector spec (DB-free, so the registry is unit-testable)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ConnectorSpec:
    """The slice of a ConnectorConfig the registry needs. Decoupled from
    the SQLAlchemy model so building tools requires no database."""

    connector_type: str
    is_active: bool = True


# ---------------------------------------------------------------------------
# Tool-name resolution
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ResolvedTool:
    connector_type: str
    action: str
    spec: ToolSpec

    @property
    def policy_key(self) -> str:
        return self.spec.policy_key or self.connector_type


def resolve_tool(tool_name: str) -> Optional[ResolvedTool]:
    """Map a namespaced ``connector_type.action`` name back to its spec.

    Returns None for malformed names or unknown connector/action, so
    callers can fail safe (default-deny) rather than raise.
    """
    if "." not in tool_name:
        return None
    connector_type, _, action = tool_name.partition(".")
    specs = CONNECTOR_CATALOG.get(connector_type)
    if not specs:
        return None
    for spec in specs:
        if spec.action == action:
            return ResolvedTool(connector_type, action, spec)
    return None


# Map a PermissionDecision to the string the runtime's check() returns.
def _runtime_decision(allowed: bool, requires_approval: bool, tier: PermissionTier) -> str:
    if tier == PermissionTier.HARD_BLOCKED or (not allowed and not requires_approval):
        return "blocked"
    if requires_approval:
        return "requires_approval"
    return "approved"


# ---------------------------------------------------------------------------
# Registry: build the tool list for a user's connectors
# ---------------------------------------------------------------------------


def build_tools(
    connectors: Iterable[ConnectorSpec],
    engine: Optional[PermissionEngine] = None,
    user_tier: UserTier = UserTier.STANDARD,
) -> list[Tool]:
    """Produce the runtime ``Tool`` objects for a user's active connectors.

    Hard-blocked actions are omitted entirely so the LLM is never offered
    a tool it cannot use. The runtime still independently blocks them via
    the permission adapter (defense in depth).
    """
    engine = engine or PermissionEngine()
    tools: list[Tool] = []
    for conn in connectors:
        if not conn.is_active:
            continue
        specs = CONNECTOR_CATALOG.get(conn.connector_type)
        if not specs:
            continue  # unknown connector type: skip safely
        for spec in specs:
            policy_key = spec.policy_key or conn.connector_type
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
            tools.append(
                Tool(
                    name=f"{conn.connector_type}.{spec.action}",
                    description=spec.description,
                    parameters=spec.parameters,
                    connector_type=conn.connector_type,
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
    """

    def __init__(
        self,
        engine: Optional[PermissionEngine] = None,
        user_tier: UserTier = UserTier.STANDARD,
    ) -> None:
        self._engine = engine or PermissionEngine()
        self._user_tier = user_tier

    async def check(self, user_id: str, tool_name: str, arguments: dict[str, Any]) -> str:
        resolved = resolve_tool(tool_name)
        if resolved is None:
            return "blocked"  # default-deny unknown tools
        decision = self._engine.check_permission(
            connector_type=resolved.policy_key,
            action=resolved.action,
            scope=resolved.spec.category,
            user_tier=self._user_tier,
        )
        return _runtime_decision(decision.allowed, decision.requires_approval, decision.tier)

    async def get_block_reason(self, user_id: str, tool_name: str, arguments: dict[str, Any]) -> str:
        resolved = resolve_tool(tool_name)
        if resolved is None:
            return f"Unknown tool '{tool_name}' is denied by default."
        decision = self._engine.check_permission(
            connector_type=resolved.policy_key,
            action=resolved.action,
            scope=resolved.spec.category,
            user_tier=self._user_tier,
        )
        return decision.reason

    async def get_policy_name(self, user_id: str, tool_name: str) -> str:
        resolved = resolve_tool(tool_name)
        if resolved is None:
            return "default-deny"
        return f"{resolved.policy_key}:{resolved.spec.category.value}"


# ---------------------------------------------------------------------------
# Connector tool executor
# ---------------------------------------------------------------------------


class ConnectorToolExecutor:
    """Dispatches an approved tool call to its connector.

    SEAM: real execution requires loading the user's encrypted credentials,
    decrypting them, instantiating the connector class, authenticating, and
    calling ``connector.execute(action, params)``. That path is not wired
    yet, so ``_dispatch`` returns a deterministic mock payload per action.
    Swap ``_dispatch`` for the real connector call to go live without
    touching the rest of the agent loop.
    """

    async def execute(self, tool_name: str, arguments: dict[str, Any], user_id: str) -> dict[str, Any]:
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
        return await self._dispatch(resolved, arguments, user_id)

    async def _dispatch(
        self, resolved: ResolvedTool, arguments: dict[str, Any], user_id: str
    ) -> dict[str, Any]:
        """Return a deterministic mock result. Replace with real connector
        instantiation + ``connector.execute`` when credential decryption is
        wired."""
        # Make the mock path obvious in server logs so a deployed instance
        # is never mistaken for real connector execution.
        logger.warning(
            "connector_executor_mock_mode",
            connector=resolved.connector_type,
            action=resolved.action,
        )
        return {
            "ok": True,
            "connector": resolved.connector_type,
            "action": resolved.action,
            "arguments": arguments,
            "result": f"[mock] {resolved.connector_type}.{resolved.action} executed",
            "note": "Mock result. Real connector dispatch pending credential wiring.",
        }
