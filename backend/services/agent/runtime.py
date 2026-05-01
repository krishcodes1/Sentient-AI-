"""Agent runtime — orchestrates LLM calls, tool execution, permission
checks, prompt scanning, and audit logging.

This module wires the real ``PermissionEngine``, ``PromptGuard``, and
``AuditService`` into the agent loop. Stubs are no longer used.

NOTE (route-level fix needed): ``api/routes/agent.py:201-202`` currently
serializes raw provider exception text into the assistant message that is
persisted to the conversation DB. That can leak API keys / provider error
internals. The runtime here re-raises a sanitized ``LLMProviderError``
instead, but the route also needs to stop interpolating ``{exc}`` into the
user-visible content. (Route author owns that change; do not modify the
route file from this module.)
"""

from __future__ import annotations

import unicodedata
import uuid
from collections.abc import AsyncGenerator
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Optional

import structlog

from core.config import Settings
from services.agent.context_manager import ContextManager
from services.agent.providers import LLMResponse, ToolCall, create_provider, LLMProvider

# Real safety services
from services.agent.permissions import (
    PermissionEngine,
    PermissionDecision,
    PermissionTier,
    ActionCategory,
    UserTier,
)
from services.agent.prompt_guard import PromptGuard, ScanResult, ThreatLevel
from services.audit import AuditService
from models.audit import AuditStatus

# Map provider names to their API key config attribute
_PROVIDER_KEY_MAP = {
    "anthropic": "ANTHROPIC_API_KEY",
    "openai": "OPENAI_API_KEY",
    "gemini": "GEMINI_API_KEY",
    "grok": "GROK_API_KEY",
    "deepseek": "DEEPSEEK_API_KEY",
    "groq": "GROQ_API_KEY",
    "mistral": "MISTRAL_API_KEY",
}

logger = structlog.get_logger(__name__)


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------


class RuntimeError_(Exception):
    """Base runtime error."""


class PromptInjectionBlocked(Exception):
    """Raised when the prompt guard rejects user/connector content."""

    def __init__(self, reason: str, level: str = "high") -> None:
        self.reason = reason
        self.level = level
        super().__init__(f"Prompt injection blocked ({level}): {reason}")


class LLMProviderError(Exception):
    """Re-raised after a provider-level failure with a sanitized message.

    The original (potentially sensitive) provider error is logged
    server-side and never propagated to the client.
    """


class HardBlockedAction(Exception):
    """Action permanently blocked by security policy (e.g. financial)."""

    def __init__(self, action: str, reason: str) -> None:
        self.action = action
        self.reason = reason
        super().__init__(f"HARD_BLOCK: '{action}' - {reason}")


class AdminOnlyAction(Exception):
    """Action requires admin tier; current user is standard."""

    def __init__(self, action: str, reason: str) -> None:
        self.action = action
        self.reason = reason
        super().__init__(f"ADMIN_ONLY: '{action}' - {reason}")


class UserConfirmationRequired(Exception):
    """Action requires explicit user confirmation before execution.

    The runtime returns a ``confirmation_required`` response rather than
    raising in the normal flow; this exception exists for callers that
    need to surface the requirement upstream.
    """

    def __init__(self, action_id: str, action: str, summary: str) -> None:
        self.action_id = action_id
        self.action = action
        self.summary = summary
        super().__init__(f"USER_CONFIRM required for '{action}': {summary}")


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------


@dataclass()
class Tool:
    """Descriptor for a tool that the agent can invoke."""

    name: str
    description: str
    parameters: dict[str, Any]
    connector_type: str = ""
    permission_tier: str = "auto"  # auto | approval | blocked


@dataclass()
class PendingApproval:
    """An action that requires explicit user approval before execution."""

    action_id: str
    tool_name: str
    arguments: dict[str, Any]
    reason: str
    summary: str = ""
    params_redacted: dict[str, Any] = field(default_factory=dict)
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


@dataclass()
class BlockedAction:
    """An action that was blocked by security policy."""

    tool_name: str
    reason: str
    policy: str


@dataclass()
class AgentResponse:
    """Unified response returned by the agent runtime."""

    content: str
    tool_calls: list[dict[str, Any]] = field(default_factory=list)
    pending_approvals: list[PendingApproval] = field(default_factory=list)
    blocked_actions: list[BlockedAction] = field(default_factory=list)
    usage: dict[str, int] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


# Action-name keyword heuristic for inferring scope category.
_DELETE_KEYWORDS = ("delete", "remove", "destroy", "drop", "purge")
_WRITE_KEYWORDS = (
    "send", "create", "update", "post", "put", "patch", "submit",
    "write", "modify", "set", "add", "upload", "schedule", "edit",
)
_FINANCIAL_KEYWORDS = (
    "trade", "buy", "sell", "transfer", "withdraw", "deposit", "wire",
    "send_money", "place_order", "execute_trade", "market_order",
    "limit_order", "crypto_buy", "crypto_sell",
)


def _infer_action_scope(action: str) -> ActionCategory:
    """Infer the ``ActionCategory`` from an action name heuristically.

    Examples:
        canvas.list_courses     -> READ
        gmail.send              -> WRITE
        github.delete_repo      -> DELETE
        robinhood.place_order   -> FINANCIAL
    """
    action_lower = action.lower()
    bare = action_lower.rsplit(".", 1)[-1]

    if any(kw in bare for kw in _FINANCIAL_KEYWORDS):
        return ActionCategory.FINANCIAL
    if any(bare.startswith(kw) or kw in bare for kw in _DELETE_KEYWORDS):
        return ActionCategory.DELETE
    if any(bare.startswith(kw) or kw in bare for kw in _WRITE_KEYWORDS):
        return ActionCategory.WRITE
    return ActionCategory.READ


def _split_action(action_name: str) -> tuple[str, str]:
    """Split a dotted action name into ``(connector, action)``.

    ``canvas.list_courses`` -> ``("canvas", "list_courses")``.
    Bare actions (no dot) get an empty connector.
    """
    if "." in action_name:
        connector, _, action = action_name.partition(".")
        return connector, action
    return "", action_name


_REDACT_KEYS = {
    "token", "password", "passwd", "secret", "api_key", "api-key", "apikey",
    "authorization", "credential", "private_key", "client_secret",
    "session_id", "cookie", "bearer", "refresh_token",
}


def _redact_params(params: dict[str, Any]) -> dict[str, Any]:
    """Shallow-redact sensitive keys for confirmation responses."""
    redacted: dict[str, Any] = {}
    for k, v in params.items():
        if any(s in str(k).lower() for s in _REDACT_KEYS):
            redacted[k] = "***REDACTED***"
        elif isinstance(v, dict):
            redacted[k] = _redact_params(v)
        else:
            redacted[k] = v
    return redacted


def _scan_summary(result: ScanResult) -> str:
    """Build a one-line reason string from a ``ScanResult``."""
    if not result.detections:
        return "no detections"
    parts = [
        f"{d.pattern_name}({d.severity})" for d in result.detections[:3]
    ]
    return "; ".join(parts)


# ---------------------------------------------------------------------------
# Tool executor — dispatches approved tool calls to a connector
# ---------------------------------------------------------------------------


class ToolExecutor:
    """Real tool dispatcher.

    Routes ``connector.action`` style calls to the matching connector
    instance. Connectors are looked up via the connectors registry if it
    exists; otherwise we dispatch by the connector prefix and import on
    demand. Auth wiring (loading user-specific credentials) is the
    responsibility of a yet-to-be-built connector registry — until that
    lands, calls raise ``NotImplementedError`` so the contract is clear.
    """

    def __init__(self, registry: Optional[Any] = None) -> None:
        # TODO(round-2C): replace with the central connectors registry once
        # services/connectors/__init__.py exposes one.
        self._registry = registry

    async def execute(
        self,
        action_name: str,
        params: dict[str, Any],
        user_id: str,
    ) -> dict[str, Any]:
        """Dispatch an approved action to the right connector.

        ``action_name`` is dotted: ``canvas.get_courses``,
        ``google.send_email``, etc.
        """
        connector_key, action = _split_action(action_name)

        if self._registry is not None:
            # Preferred path once a registry is wired
            try:
                connector = self._registry.get(connector_key, user_id)
            except Exception as exc:  # pragma: no cover - registry not implemented
                raise NotImplementedError(
                    f"Tool executor for {action_name}: registry lookup failed: {exc}"
                ) from exc
            response = await connector.execute(action, params)
            return {
                "success": response.success,
                "data": response.data,
                "sanitized": response.sanitized,
                "execution_time_ms": response.execution_time_ms,
            }

        # No registry yet — leave a clear contract failure. The audit log is
        # written *before* this raise by the calling code, so blocked / failed
        # dispatch attempts are still tracked.
        raise NotImplementedError(
            f"Tool executor for {action_name}: connector registry not yet wired"
        )


# ---------------------------------------------------------------------------
# Audit shim — keeps the runtime callable when no DB session is available
# ---------------------------------------------------------------------------


class _AuditLogger:
    """Thin wrapper around ``services.audit.AuditService`` that degrades
    gracefully when no DB session is provided.

    This lets the runtime be instantiated outside a request scope (e.g. in
    unit tests) without needing a live DB. When a real ``AuditService`` is
    injected, every event is persisted with chain integrity. When not, the
    same payload is emitted via ``structlog`` for ops visibility.
    """

    def __init__(self, audit_service: Optional[AuditService] = None) -> None:
        self._service = audit_service

    async def log(
        self,
        *,
        user_id: str,
        action: str,
        status: AuditStatus | str,
        connector_name: str = "agent",
        endpoint: str = "agent.runtime",
        scope_used: str = "internal",
        reasoning: Optional[str] = None,
        params: Any = None,
        confidence_score: Optional[float] = None,
    ) -> None:
        # Normalize status
        if isinstance(status, str):
            try:
                status_enum = AuditStatus(status)
            except ValueError:
                status_enum = AuditStatus.ESCALATED
        else:
            status_enum = status

        payload = {
            "user_id": user_id,
            "action": action,
            "status": status_enum.value,
            "connector_name": connector_name,
            "endpoint": endpoint,
            "scope_used": scope_used,
            "reasoning": reasoning,
            "confidence_score": confidence_score,
        }

        if self._service is None:
            logger.info("audit_event", **payload)
            return

        try:
            await self._service.log_action(
                user_id=user_id,
                connector_name=connector_name,
                action=action,
                endpoint=endpoint,
                scope_used=scope_used,
                status=status_enum,
                reasoning_chain=reasoning,
                request_data=params,
                confidence_score=confidence_score,
            )
        except Exception as exc:  # pragma: no cover - audit must never break the request
            logger.error("audit_log_failed", error=str(exc), **payload)


# ---------------------------------------------------------------------------
# Runtime
# ---------------------------------------------------------------------------


class AgentRuntime:
    """Core agent loop — send messages to an LLM and handle tool calls with
    full security checks.
    """

    def __init__(
        self,
        config: Settings,
        *,
        permission_engine: Optional[PermissionEngine] = None,
        prompt_guard: Optional[PromptGuard] = None,
        audit_service: Optional[AuditService] = None,
        tool_executor: Optional[ToolExecutor] = None,
        provider: Optional[LLMProvider] = None,
    ):
        self._config = config

        if provider is not None:
            # Allow injecting a fake provider (used by the test suite).
            self._provider: LLMProvider = provider
        else:
            # Resolve the correct API key for the selected provider
            key_attr = _PROVIDER_KEY_MAP.get(config.LLM_PROVIDER)
            api_key = getattr(config, key_attr, None) if key_attr else None
            self._provider = create_provider(
                provider_name=config.LLM_PROVIDER,
                model=config.LLM_MODEL,
                api_key=api_key,
                base_url=config.OLLAMA_BASE_URL,
            )

        self._context_manager = ContextManager(model=config.LLM_MODEL)
        self._permissions = permission_engine or PermissionEngine()
        self._guard = prompt_guard or PromptGuard()
        self._audit = _AuditLogger(audit_service)
        self._executor = tool_executor or ToolExecutor()

        # In-memory store for pending approvals.
        # TODO(round-2C): migrate to Redis. Single-worker only as written —
        # multi-worker deployments will lose pending actions across workers.
        self._pending: dict[str, dict[str, Any]] = {}

    # ------------------------------------------------------------------
    # Tool schema helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _tools_to_schema(tools: list[Tool]) -> list[dict[str, Any]]:
        """Convert ``Tool`` dataclasses into the generic dict format the
        providers understand."""
        return [
            {
                "name": t.name,
                "description": t.description,
                "parameters": t.parameters,
            }
            for t in tools
        ]

    # ------------------------------------------------------------------
    # Prompt-guard helpers
    # ------------------------------------------------------------------

    async def _scan_text(
        self,
        text: str,
        *,
        user_id: str,
        source: str,
    ) -> ScanResult:
        """Run NFKC normalization and ``PromptGuard.scan`` on text.

        Logs the scan via the audit service. Raises
        ``PromptInjectionBlocked`` if the threat level is HIGH or above.

        ``source`` is one of ``"user_input"``, ``"connector_output"``, or
        ``"tool_args"`` — used as the audit reasoning prefix.
        """
        normalized = unicodedata.normalize("NFKC", text or "")
        result = self._guard.scan(normalized)

        threat = result.threat_level
        is_blocking = threat in (ThreatLevel.HIGH, ThreatLevel.CRITICAL)

        await self._audit.log(
            user_id=user_id,
            action="prompt.scan",
            status=AuditStatus.BLOCKED if is_blocking else AuditStatus.APPROVED,
            connector_name="prompt_guard",
            endpoint=source,
            scope_used=threat.value,
            reasoning=f"{source}: {_scan_summary(result)}",
            confidence_score=result.confidence,
        )

        if is_blocking:
            raise PromptInjectionBlocked(
                reason=_scan_summary(result),
                level=threat.value,
            )

        return result

    # ------------------------------------------------------------------
    # Permission helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _resolve_user_tier(user: Any) -> UserTier:
        """Pull the tier off a user-like object.

        Accepts a ``User`` model, a dict, or a string. Admin status is
        encoded in the JWT ``tier`` claim today (the User model has no
        ``is_admin`` column), so callers that want admin behavior must
        pass a dict-like object with ``is_admin=True`` or ``tier="admin"``.
        """
        if user is None:
            return UserTier.STANDARD
        if isinstance(user, str):
            return UserTier.STANDARD
        is_admin = False
        if hasattr(user, "is_admin"):
            is_admin = bool(getattr(user, "is_admin"))
        elif isinstance(user, dict):
            is_admin = bool(user.get("is_admin")) or user.get("tier") == "admin"
        return UserTier.ADMIN if is_admin else UserTier.STANDARD

    @staticmethod
    def _user_id(user: Any) -> str:
        if user is None:
            return ""
        if isinstance(user, str):
            return user
        if hasattr(user, "id"):
            return str(getattr(user, "id"))
        if isinstance(user, dict):
            return str(user.get("id") or user.get("user_id") or "")
        return str(user)

    async def _check_permission(
        self,
        *,
        user: Any,
        action_name: str,
        params: dict[str, Any],
    ) -> tuple[PermissionDecision, str, str, ActionCategory]:
        """Evaluate the permission for a tool call and audit-log the verdict."""
        connector, action = _split_action(action_name)
        scope = _infer_action_scope(action_name)
        tier = self._resolve_user_tier(user)

        decision = self._permissions.check_permission(
            connector_type=connector,
            action=action,
            scope=scope,
            user_tier=tier,
        )

        # Map the decision tier onto an audit status.
        if decision.tier == PermissionTier.HARD_BLOCKED:
            status = AuditStatus.BLOCKED
        elif decision.tier == PermissionTier.ADMIN_ONLY and tier != UserTier.ADMIN:
            status = AuditStatus.BLOCKED
        elif decision.tier == PermissionTier.USER_CONFIRM:
            status = AuditStatus.PENDING
        elif decision.tier == PermissionTier.AUTO_APPROVE:
            status = AuditStatus.APPROVED
        else:
            status = AuditStatus.PENDING

        await self._audit.log(
            user_id=self._user_id(user),
            action=f"tool.permission_check:{action_name}",
            status=status,
            connector_name=connector or "agent",
            endpoint=action_name,
            scope_used=scope.value,
            reasoning=decision.reason,
            params=params,
        )

        return decision, connector, action, scope

    # ------------------------------------------------------------------
    # Tool dispatch (with full safety pipeline)
    # ------------------------------------------------------------------

    async def _dispatch_tool(
        self,
        *,
        user: Any,
        action_name: str,
        params: dict[str, Any],
    ) -> dict[str, Any]:
        """Execute a tool via the executor and audit-log the outcome."""
        user_id = self._user_id(user)
        try:
            result = await self._executor.execute(action_name, params, user_id)
            await self._audit.log(
                user_id=user_id,
                action=f"tool.execute:{action_name}",
                status=AuditStatus.APPROVED,
                endpoint=action_name,
                scope_used="execute",
                reasoning="tool executed",
                params=params,
            )
            return result
        except NotImplementedError as exc:
            await self._audit.log(
                user_id=user_id,
                action=f"tool.execute:{action_name}",
                status=AuditStatus.ESCALATED,
                endpoint=action_name,
                scope_used="execute",
                reasoning=f"executor not implemented: {exc}",
                params=params,
            )
            raise
        except Exception as exc:
            await self._audit.log(
                user_id=user_id,
                action=f"tool.execute:{action_name}",
                status=AuditStatus.ESCALATED,
                endpoint=action_name,
                scope_used="execute",
                reasoning=f"executor error: {str(exc)[:300]}",
                params=params,
            )
            return {"error": "tool execution failed; see logs"}

    # ------------------------------------------------------------------
    # Provider call wrapper
    # ------------------------------------------------------------------

    async def _call_provider(
        self,
        *,
        user_id: str,
        messages: list[dict[str, Any]],
        tool_schemas: list[dict[str, Any]] | None,
    ) -> LLMResponse:
        """Wrap ``provider.complete`` with audit logging and error sanitization.

        Provider errors are logged server-side with the raw exception text and
        re-raised as a generic ``LLMProviderError`` so sensitive content (API
        keys, internal URLs, etc.) never reaches the caller's response body.
        """
        await self._audit.log(
            user_id=user_id,
            action="llm.request",
            status=AuditStatus.APPROVED,
            connector_name="llm",
            endpoint=self._config.LLM_PROVIDER,
            scope_used="provider_call",
            reasoning="dispatching to provider",
            params={
                "provider": self._config.LLM_PROVIDER,
                "model": self._config.LLM_MODEL,
                "msg_count": len(messages),
                "input_tokens_estimate": sum(
                    len(str(m.get("content", ""))) // 4 for m in messages
                ),
            },
        )

        try:
            llm_response = await self._provider.complete(
                messages=messages,
                tools=tool_schemas or None,
            )
        except Exception as exc:
            # Log the raw error server-side ONLY.
            logger.error(
                "llm_provider_error",
                user_id=user_id,
                provider=self._config.LLM_PROVIDER,
                model=self._config.LLM_MODEL,
                error=str(exc),
                error_type=type(exc).__name__,
            )
            await self._audit.log(
                user_id=user_id,
                action="llm.error",
                status=AuditStatus.ESCALATED,
                connector_name="llm",
                endpoint=self._config.LLM_PROVIDER,
                scope_used="provider_call",
                reasoning=str(exc)[:500],
            )
            # Re-raise a clean exception. The original ``exc`` text never
            # reaches the response body.
            raise LLMProviderError("provider failed; see logs") from None

        await self._audit.log(
            user_id=user_id,
            action="llm.response",
            status=AuditStatus.APPROVED,
            connector_name="llm",
            endpoint=self._config.LLM_PROVIDER,
            scope_used="provider_call",
            reasoning="provider returned response",
            params={
                "output_tokens": llm_response.usage.get("output_tokens", 0),
                "tool_calls": [
                    {"name": tc.name, "id": tc.id} for tc in llm_response.tool_calls
                ],
            },
        )

        return llm_response

    # ------------------------------------------------------------------
    # Main chat
    # ------------------------------------------------------------------

    async def chat(
        self,
        messages: list[dict[str, Any]],
        tools: list[Tool],
        user_id: str,
        *,
        user: Any = None,
    ) -> AgentResponse:
        """Process a conversation turn.

        ``user_id`` is the canonical identifier persisted in audit logs.
        ``user`` (optional) is a User-like object used for tier resolution.
        """
        if user is None:
            user = {"id": user_id, "is_admin": False}

        # 1. Scan the latest user message for prompt injection
        last_user_msg = next(
            (m["content"] for m in reversed(messages) if m.get("role") == "user"),
            "",
        )
        try:
            await self._scan_text(
                last_user_msg, user_id=user_id, source="user_input"
            )
        except PromptInjectionBlocked as exc:
            return AgentResponse(
                content="I'm unable to process that request due to a security policy.",
                blocked_actions=[
                    BlockedAction(
                        tool_name="input",
                        reason=exc.reason,
                        policy="prompt_guard",
                    )
                ],
            )

        # 2. Call the LLM (errors surface as LLMProviderError)
        tool_schemas = self._tools_to_schema(tools) if tools else []
        llm_response = await self._call_provider(
            user_id=user_id, messages=messages, tool_schemas=tool_schemas
        )

        # 3. If no tool calls, scan output and return
        if not llm_response.tool_calls:
            content = llm_response.content
            blocked: list[BlockedAction] = []
            try:
                await self._scan_text(
                    content, user_id=user_id, source="llm_output"
                )
            except PromptInjectionBlocked as exc:
                content = "Response redacted due to security policy."
                blocked.append(
                    BlockedAction(
                        tool_name="output",
                        reason=exc.reason,
                        policy="prompt_guard",
                    )
                )
            return AgentResponse(
                content=content,
                usage=llm_response.usage,
                blocked_actions=blocked,
            )

        # 4. Process each tool call
        tool_results: list[dict[str, Any]] = []
        pending_approvals: list[PendingApproval] = []
        blocked_actions: list[BlockedAction] = []

        tool_map = {t.name: t for t in tools}

        for tc in llm_response.tool_calls:
            tool_def = tool_map.get(tc.name)

            # 4a. Permission check
            decision, connector_key, action, _scope = await self._check_permission(
                user=user, action_name=tc.name, params=tc.arguments
            )

            # HARD_BLOCKED — never executable.
            if decision.tier == PermissionTier.HARD_BLOCKED:
                blocked_actions.append(
                    BlockedAction(
                        tool_name=tc.name,
                        reason=decision.reason,
                        policy="hard_blocked",
                    )
                )
                continue

            # ADMIN_ONLY — block standard users.
            tier = self._resolve_user_tier(user)
            if decision.tier == PermissionTier.ADMIN_ONLY and tier != UserTier.ADMIN:
                blocked_actions.append(
                    BlockedAction(
                        tool_name=tc.name,
                        reason=decision.reason,
                        policy="admin_only",
                    )
                )
                continue

            # USER_CONFIRM — defer execution until confirmed.
            if decision.requires_approval and decision.tier in (
                PermissionTier.USER_CONFIRM,
                PermissionTier.ADMIN_ONLY,
            ):
                action_id = str(uuid.uuid4())
                summary = f"{tc.name} on {connector_key or 'agent'}"
                approval = PendingApproval(
                    action_id=action_id,
                    tool_name=tc.name,
                    arguments=tc.arguments,
                    reason=decision.reason,
                    summary=summary,
                    params_redacted=_redact_params(tc.arguments or {}),
                )
                pending_approvals.append(approval)
                # Stash for later approval (single-worker; see TODO at top)
                self._pending[action_id] = {
                    "tool_call": tc,
                    "user_id": user_id,
                    "user": user,
                    "messages": messages,
                    "tools": tools,
                    "action_name": tc.name,
                }
                continue

            # 4b. Scan tool arguments for prompt injection
            try:
                await self._scan_text(
                    str(tc.arguments), user_id=user_id, source="tool_args"
                )
            except PromptInjectionBlocked as exc:
                blocked_actions.append(
                    BlockedAction(
                        tool_name=tc.name,
                        reason=exc.reason,
                        policy="prompt_guard",
                    )
                )
                continue

            # 4c. Execute the tool
            try:
                result = await self._dispatch_tool(
                    user=user, action_name=tc.name, params=tc.arguments
                )
            except NotImplementedError as exc:
                blocked_actions.append(
                    BlockedAction(
                        tool_name=tc.name,
                        reason=str(exc),
                        policy="not_implemented",
                    )
                )
                continue

            # 4d. Scan tool response (BEFORE feeding into next LLM turn)
            try:
                await self._scan_text(
                    str(result), user_id=user_id, source="connector_output"
                )
            except PromptInjectionBlocked as exc:
                result = {"redacted": True, "reason": exc.reason}

            tool_results.append(
                {
                    "tool_call_id": tc.id,
                    "name": tc.name,
                    "result": result,
                }
            )

        # 5. If we executed tools, do a follow-up LLM call with the results
        final_content = llm_response.content
        total_usage = dict(llm_response.usage)

        if tool_results:
            follow_up_messages = list(messages)
            follow_up_messages.append(
                {"role": "assistant", "content": llm_response.content}
            )
            for tr in tool_results:
                follow_up_messages.append(
                    {
                        "role": "tool",
                        "tool_call_id": tr["tool_call_id"],
                        "name": tr["name"],
                        "content": str(tr["result"]),
                    }
                )

            follow_up = await self._call_provider(
                user_id=user_id, messages=follow_up_messages, tool_schemas=None
            )
            final_content = follow_up.content
            for k, v in follow_up.usage.items():
                total_usage[k] = total_usage.get(k, 0) + v

        return AgentResponse(
            content=final_content,
            tool_calls=tool_results,
            pending_approvals=pending_approvals,
            blocked_actions=blocked_actions,
            usage=total_usage,
        )

    # ------------------------------------------------------------------
    # Streaming chat
    # ------------------------------------------------------------------

    async def stream_chat(
        self,
        messages: list[dict[str, Any]],
        tools: list[Tool],
        user_id: str,
        *,
        user: Any = None,
    ) -> AsyncGenerator[dict[str, Any], None]:
        """Streaming variant — yields dicts with ``type`` and ``data`` keys."""
        if user is None:
            user = {"id": user_id, "is_admin": False}

        # Scan input
        last_user_msg = next(
            (m["content"] for m in reversed(messages) if m.get("role") == "user"),
            "",
        )
        try:
            await self._scan_text(
                last_user_msg, user_id=user_id, source="user_input"
            )
        except PromptInjectionBlocked as exc:
            yield {
                "type": "error",
                "data": {"reason": exc.reason},
            }
            return

        # Non-streaming first to handle tool use correctly.
        tool_schemas = self._tools_to_schema(tools) if tools else []
        try:
            llm_response = await self._call_provider(
                user_id=user_id, messages=messages, tool_schemas=tool_schemas
            )
        except LLMProviderError as exc:
            yield {"type": "error", "data": {"reason": str(exc)}}
            return

        if not llm_response.tool_calls:
            for i in range(0, len(llm_response.content), 20):
                yield {
                    "type": "content_delta",
                    "data": {"text": llm_response.content[i : i + 20]},
                }
            yield {"type": "done", "data": {"usage": llm_response.usage}}
            return

        # Process tool calls (mirrors chat)
        tool_map = {t.name: t for t in tools}
        tool_results: list[dict[str, Any]] = []

        for tc in llm_response.tool_calls:
            decision, connector_key, _action, _scope = await self._check_permission(
                user=user, action_name=tc.name, params=tc.arguments
            )

            yield {
                "type": "tool_call",
                "data": {
                    "name": tc.name,
                    "arguments": _redact_params(tc.arguments or {}),
                    "permission": decision.tier.value,
                },
            }

            tier = self._resolve_user_tier(user)

            if decision.tier == PermissionTier.HARD_BLOCKED:
                yield {
                    "type": "error",
                    "data": {"tool": tc.name, "reason": decision.reason},
                }
                continue

            if decision.tier == PermissionTier.ADMIN_ONLY and tier != UserTier.ADMIN:
                yield {
                    "type": "error",
                    "data": {"tool": tc.name, "reason": decision.reason},
                }
                continue

            if decision.requires_approval:
                action_id = str(uuid.uuid4())
                self._pending[action_id] = {
                    "tool_call": tc,
                    "user_id": user_id,
                    "user": user,
                    "messages": messages,
                    "tools": tools,
                    "action_name": tc.name,
                }
                yield {
                    "type": "tool_call",
                    "data": {
                        "name": tc.name,
                        "pending_approval": True,
                        "action_id": action_id,
                    },
                }
                continue

            try:
                result = await self._dispatch_tool(
                    user=user, action_name=tc.name, params=tc.arguments
                )
            except NotImplementedError as exc:
                yield {"type": "error", "data": {"tool": tc.name, "reason": str(exc)}}
                continue

            try:
                await self._scan_text(
                    str(result), user_id=user_id, source="connector_output"
                )
            except PromptInjectionBlocked as exc:
                result = {"redacted": True, "reason": exc.reason}

            tool_results.append(
                {"tool_call_id": tc.id, "name": tc.name, "result": result}
            )
            yield {"type": "tool_result", "data": {"name": tc.name, "result": result}}

        if tool_results:
            follow_up_messages = list(messages)
            follow_up_messages.append(
                {"role": "assistant", "content": llm_response.content}
            )
            for tr in tool_results:
                follow_up_messages.append(
                    {
                        "role": "tool",
                        "tool_call_id": tr["tool_call_id"],
                        "name": tr["name"],
                        "content": str(tr["result"]),
                    }
                )

            try:
                async for chunk in self._provider.stream(follow_up_messages):
                    yield {"type": "content_delta", "data": {"text": chunk}}
            except Exception as exc:
                logger.error(
                    "llm_stream_error",
                    user_id=user_id,
                    error=str(exc),
                    error_type=type(exc).__name__,
                )
                yield {"type": "error", "data": {"reason": "provider failed; see logs"}}
                return

        yield {"type": "done", "data": {}}

    # ------------------------------------------------------------------
    # Confirm / cancel pending actions
    # ------------------------------------------------------------------

    async def confirm_pending(
        self,
        action_id: str,
        user: Any,
    ) -> dict[str, Any]:
        """Execute a previously-pending tool call after explicit confirmation.

        Re-checks the permission tier (in case the user's tier changed
        since the action was queued), audits the execution, and removes
        the entry from the pending store.
        """
        pending = self._pending.get(action_id)
        if not pending:
            return {"error": "Action not found or already processed"}

        # Ownership check
        owner_id = pending.get("user_id")
        if owner_id != self._user_id(user):
            await self._audit.log(
                user_id=self._user_id(user),
                action="tool.confirm_pending",
                status=AuditStatus.BLOCKED,
                reasoning=f"ownership mismatch on action {action_id}",
            )
            return {"error": "Unauthorized"}

        tc: ToolCall = pending["tool_call"]
        action_name = pending.get("action_name", tc.name)

        # Re-check permission — user tier may have changed.
        decision, _connector, _action, _scope = await self._check_permission(
            user=user, action_name=action_name, params=tc.arguments
        )

        tier = self._resolve_user_tier(user)
        if decision.tier == PermissionTier.HARD_BLOCKED:
            self._pending.pop(action_id, None)
            return {"error": decision.reason}
        if decision.tier == PermissionTier.ADMIN_ONLY and tier != UserTier.ADMIN:
            self._pending.pop(action_id, None)
            return {"error": decision.reason}

        # Execute
        try:
            result = await self._dispatch_tool(
                user=user, action_name=action_name, params=tc.arguments
            )
        except NotImplementedError as exc:
            self._pending.pop(action_id, None)
            return {"error": str(exc)}

        await self._audit.log(
            user_id=self._user_id(user),
            action="tool.execute_after_confirm",
            status=AuditStatus.APPROVED,
            endpoint=action_name,
            scope_used="execute",
            reasoning=f"user confirmed action {action_id}",
            params=tc.arguments,
        )

        self._pending.pop(action_id, None)
        return {"tool": tc.name, "result": result}

    async def cancel_pending(
        self,
        action_id: str,
        user: Any,
    ) -> dict[str, Any]:
        """Drop a pending action and audit-log the cancellation."""
        pending = self._pending.get(action_id)
        if not pending:
            return {"error": "Action not found or already processed"}

        if pending.get("user_id") != self._user_id(user):
            return {"error": "Unauthorized"}

        action_name = pending.get("action_name", "unknown")
        await self._audit.log(
            user_id=self._user_id(user),
            action="tool.cancel_pending",
            status=AuditStatus.BLOCKED,
            endpoint=action_name,
            scope_used="execute",
            reasoning="user cancelled",
        )

        self._pending.pop(action_id, None)
        return {"cancelled": action_id}

    # ------------------------------------------------------------------
    # Backward-compat alias used by older callers
    # ------------------------------------------------------------------

    async def approve_action(self, action_id: str, user_id: str) -> dict[str, Any]:
        """Compat shim — older callers pass ``user_id`` as a string."""
        return await self.confirm_pending(action_id, {"id": user_id})
