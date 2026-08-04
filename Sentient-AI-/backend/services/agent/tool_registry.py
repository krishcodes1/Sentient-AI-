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
"""

from __future__ import annotations

import json
import uuid as uuid_module
from dataclasses import dataclass, field
from typing import Any, Callable, Iterable, Optional

import structlog

from services.agent.permissions import (
    ActionCategory,
    PermissionEngine,
    PermissionTier,
    UserTier,
    is_hard_blocked_action,
)
from services.agent.runtime import Tool

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
    """

    connector_type: str
    is_active: bool = True
    granted_scopes: Optional[tuple[str, ...]] = None
    permission_tier: str = "user_confirm"


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


def _scope_allows(spec: ToolSpec, granted_scopes: Optional[tuple[str, ...]]) -> bool:
    """Offer-time scope filter. ``None`` (unspecified) imposes no filter;
    an explicit grant list must contain the action's required scope."""
    if granted_scopes is None or not spec.required_scope:
        return True
    return spec.required_scope in granted_scopes


# ---------------------------------------------------------------------------
# Registry: build the tool list for a user's connectors
# ---------------------------------------------------------------------------


def build_tools(
    connectors: Iterable[ConnectorSpec],
    engine: Optional[PermissionEngine] = None,
    user_tier: UserTier = UserTier.STANDARD,
    user_default_tier: str = "user_confirm",
    is_admin: bool = False,
) -> list[Tool]:
    """Produce the runtime ``Tool`` objects for a user's active connectors.

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
    engine = engine or PermissionEngine()
    # The static policy already distinguishes admins (ADMIN_ONLY actions
    # require their confirmation instead of being refused outright); it had
    # simply never been handed one.
    if is_admin:
        user_tier = UserTier.ADMIN
    tools: list[Tool] = []
    for conn in connectors:
        if not conn.is_active:
            continue
        tier = effective_tier(conn.permission_tier, user_default_tier)
        if tier == "hard_blocked":
            continue
        if tier == "admin_only" and not is_admin:
            # Only the deployment's admin may use an admin_only connector;
            # for anyone else it contributes no tools at all. Gating here is
            # what makes an approval-time admin check unnecessary: a
            # non-admin can never get such an action parked for approval in
            # the first place.
            continue
        specs = CONNECTOR_CATALOG.get(conn.connector_type)
        if not specs:
            continue  # unknown connector type: skip safely
        for spec in specs:
            if not _scope_allows(spec, conn.granted_scopes):
                continue
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
            # auto_approve tier downgrades approval-gated tools to auto —
            # never financial/hard-blocked ones (those are filtered above,
            # but the guard is kept for defense in depth).
            if (
                tier == "auto_approve"
                and runtime_decision == "requires_approval"
                and spec.category != ActionCategory.FINANCIAL
                and not is_hard_blocked_action(spec.action)
            ):
                runtime_decision = "approved"
            tools.append(
                Tool(
                    name=f"{conn.connector_type}.{spec.action}",
                    description=spec.description,
                    parameters=spec.parameters or dict(_EMPTY_SCHEMA),
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
        from services.mcp.integration import classify_mcp_tool, is_mcp_tool

        if is_mcp_tool(tool_name):
            # Third-party MCP tools never auto-approve; financial-looking
            # names are blocked outright.
            return classify_mcp_tool(tool_name)
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
        from services.mcp.integration import classify_mcp_tool, is_mcp_tool

        if is_mcp_tool(tool_name):
            if classify_mcp_tool(tool_name) == "blocked":
                return (
                    "MCP tool name matches a financial pattern; money-moving "
                    "actions are permanently blocked."
                )
            return "MCP tools require explicit user approval."
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
        from services.mcp.integration import classify_mcp_tool, is_mcp_tool

        if is_mcp_tool(tool_name):
            return (
                "mcp:financial-pattern"
                if classify_mcp_tool(tool_name) == "blocked"
                else "mcp:default-approval"
            )
        resolved = resolve_tool(tool_name)
        if resolved is None:
            return "default-deny"
        return f"{resolved.policy_key}:{resolved.spec.category.value}"


# ---------------------------------------------------------------------------
# Connector tool executor
# ---------------------------------------------------------------------------


class ConnectorToolExecutor:
    """Dispatches an approved tool call through the real connector stack.

    Per call: load the user's active connector config, enforce granted
    scopes and the per-connector rate limit, decrypt credentials,
    instantiate the connector (which arms the deny-by-default network
    policy), authenticate, execute, and return the sanitized result.

    ``approved=True`` means the call already passed the explicit user
    approval flow; it unlocks connector actions that demand per-call
    confirmation. The flag can never come from tool arguments — any
    LLM-supplied ``user_confirmed`` value is stripped before dispatch.

    Constructed without a session factory the executor cannot load
    credentials and refuses to dispatch (fail closed); ``main.py`` wires
    it with the application session factory at startup.
    """

    def __init__(
        self,
        session_factory: Optional[Callable[[], Any]] = None,
    ) -> None:
        self._session_factory = session_factory
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

        if self._session_factory is None:
            return {
                "ok": False,
                "error": (
                    "Connector execution is not configured (no database "
                    "session factory); refusing to dispatch."
                ),
            }

        config = await self._load_config(resolved.connector_type, user_id)
        if config is None:
            return {
                "ok": False,
                "error": f"No active '{resolved.connector_type}' connector is configured.",
            }

        scope_error = self._check_scope(resolved, list(config["granted_scopes"] or []))
        if scope_error:
            return {"ok": False, "error": scope_error}

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
            await connector.close()

    # -- helpers ------------------------------------------------------------

    async def _load_config(
        self, connector_type: str, user_id: str
    ) -> Optional[dict[str, Any]]:
        """Fetch the newest active connector config + decrypted credentials.

        Returns a plain dict (not the ORM row) so the session can close
        before any network I/O happens.
        """
        import json as json_module

        from sqlalchemy import select

        from core.security import decrypt_credentials
        from models.connector import ConnectorConfig, ConnectorType

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
                .limit(1)
            )
            config = result.scalar_one_or_none()
            if config is None:
                return None

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
                }

            return {
                "id": config.id,
                "credentials": credentials,
                "granted_scopes": config.granted_scopes,
                "rate_limit_per_minute": config.rate_limit_per_minute,
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
