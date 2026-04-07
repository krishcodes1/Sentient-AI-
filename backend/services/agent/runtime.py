"""Agent runtime — orchestrates LLM calls, tool execution, permission
checks, prompt scanning, and audit logging.
"""

from __future__ import annotations

import uuid
from collections.abc import AsyncGenerator
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

import structlog

from core.config import Settings
from services.agent.context_manager import ContextManager
from services.agent.providers import LLMResponse, ToolCall, create_provider, LLMProvider

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
# Data classes
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class Tool:
    """Descriptor for a tool that the agent can invoke."""

    name: str
    description: str
    parameters: dict[str, Any]
    connector_type: str = ""
    permission_tier: str = "auto"  # auto | approval | blocked


@dataclass(slots=True)
class PendingApproval:
    """An action that requires explicit user approval before execution."""

    action_id: str
    tool_name: str
    arguments: dict[str, Any]
    reason: str
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


@dataclass(slots=True)
class BlockedAction:
    """An action that was blocked by security policy."""

    tool_name: str
    reason: str
    policy: str


@dataclass(slots=True)
class AgentResponse:
    """Unified response returned by the agent runtime."""

    content: str
    tool_calls: list[dict[str, Any]] = field(default_factory=list)
    pending_approvals: list[PendingApproval] = field(default_factory=list)
    blocked_actions: list[BlockedAction] = field(default_factory=list)
    usage: dict[str, int] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Stub service interfaces — real implementations live in their own modules.
# The runtime only depends on the protocol, so callers can inject fakes.
# ---------------------------------------------------------------------------


class PermissionEngine:
    """Evaluates whether a tool call is allowed for a given user."""

    async def check(
        self, user_id: str, tool_name: str, arguments: dict[str, Any]
    ) -> str:
        """Return ``'approved'``, ``'requires_approval'``, or ``'blocked'``."""
        return "approved"

    async def get_block_reason(
        self, user_id: str, tool_name: str, arguments: dict[str, Any]
    ) -> str:
        return "Action blocked by security policy"

    async def get_policy_name(
        self, user_id: str, tool_name: str
    ) -> str:
        return "default"


class PromptGuard:
    """Scans inbound and outbound content for prompt injection / data leaks."""

    async def scan_input(self, content: str, user_id: str) -> dict[str, Any]:
        """Return ``{'safe': True}`` or ``{'safe': False, 'reason': ...}``."""
        return {"safe": True}

    async def scan_output(self, content: str, user_id: str) -> dict[str, Any]:
        return {"safe": True}


class AuditService:
    """Persists audit log entries."""

    async def log(self, entry: dict[str, Any]) -> None:
        logger.info("audit_log", **entry)


class ToolExecutor:
    """Dispatches approved tool calls to the appropriate connector."""

    async def execute(
        self, tool_name: str, arguments: dict[str, Any], user_id: str
    ) -> dict[str, Any]:
        """Execute the tool and return its result payload."""
        return {"result": f"Tool '{tool_name}' executed successfully", "data": {}}


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
        permission_engine: PermissionEngine | None = None,
        prompt_guard: PromptGuard | None = None,
        audit_service: AuditService | None = None,
        tool_executor: ToolExecutor | None = None,
    ):
        self._config = config
        # Resolve the correct API key for the selected provider
        key_attr = _PROVIDER_KEY_MAP.get(config.LLM_PROVIDER)
        api_key = getattr(config, key_attr, None) if key_attr else None
        self._provider: LLMProvider = create_provider(
            provider_name=config.LLM_PROVIDER,
            model=config.LLM_MODEL,
            api_key=api_key,
            base_url=config.OLLAMA_BASE_URL,
        )
        self._context_manager = ContextManager(model=config.LLM_MODEL)
        self._permissions = permission_engine or PermissionEngine()
        self._guard = prompt_guard or PromptGuard()
        self._audit = audit_service or AuditService()
        self._executor = tool_executor or ToolExecutor()

        # In-memory store for pending approvals (production would use DB/Redis)
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
    # Main chat
    # ------------------------------------------------------------------

    async def chat(
        self,
        messages: list[dict[str, Any]],
        tools: list[Tool],
        user_id: str,
    ) -> AgentResponse:
        """Process a conversation turn.  If the LLM requests tool calls the
        runtime checks permissions, scans content, executes approved calls,
        and returns the aggregated result.
        """
        # 1. Scan the latest user message for prompt injection
        last_user_msg = next(
            (m["content"] for m in reversed(messages) if m.get("role") == "user"),
            "",
        )
        input_scan = await self._guard.scan_input(last_user_msg, user_id)
        if not input_scan.get("safe", True):
            await self._audit.log(
                {
                    "event": "input_blocked",
                    "user_id": user_id,
                    "reason": input_scan.get("reason", "prompt injection detected"),
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                }
            )
            return AgentResponse(
                content="I'm unable to process that request due to a security policy.",
                blocked_actions=[
                    BlockedAction(
                        tool_name="input",
                        reason=input_scan.get("reason", "prompt injection detected"),
                        policy="prompt_guard",
                    )
                ],
            )

        # 2. Call the LLM
        tool_schemas = self._tools_to_schema(tools) if tools else []
        llm_response: LLMResponse = await self._provider.complete(
            messages=messages,
            tools=tool_schemas or None,
        )

        # 3. If no tool calls, scan output and return
        if not llm_response.tool_calls:
            output_scan = await self._guard.scan_output(llm_response.content, user_id)
            content = llm_response.content
            blocked: list[BlockedAction] = []
            if not output_scan.get("safe", True):
                content = "Response redacted due to security policy."
                blocked.append(
                    BlockedAction(
                        tool_name="output",
                        reason=output_scan.get("reason", "data leak detected"),
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
            permission = await self._permissions.check(user_id, tc.name, tc.arguments)

            if permission == "blocked":
                reason = await self._permissions.get_block_reason(
                    user_id, tc.name, tc.arguments
                )
                policy = await self._permissions.get_policy_name(user_id, tc.name)
                blocked_actions.append(
                    BlockedAction(tool_name=tc.name, reason=reason, policy=policy)
                )
                await self._audit.log(
                    {
                        "event": "tool_blocked",
                        "user_id": user_id,
                        "tool": tc.name,
                        "reason": reason,
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                    }
                )
                continue

            if permission == "requires_approval":
                action_id = str(uuid.uuid4())
                approval = PendingApproval(
                    action_id=action_id,
                    tool_name=tc.name,
                    arguments=tc.arguments,
                    reason=f"Tool '{tc.name}' requires explicit user approval",
                )
                pending_approvals.append(approval)
                # Stash for later approval
                self._pending[action_id] = {
                    "tool_call": tc,
                    "user_id": user_id,
                    "messages": messages,
                    "tools": tools,
                }
                await self._audit.log(
                    {
                        "event": "tool_pending_approval",
                        "user_id": user_id,
                        "tool": tc.name,
                        "action_id": action_id,
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                    }
                )
                continue

            # 4b. Scan tool arguments
            arg_scan = await self._guard.scan_input(
                str(tc.arguments), user_id
            )
            if not arg_scan.get("safe", True):
                blocked_actions.append(
                    BlockedAction(
                        tool_name=tc.name,
                        reason=arg_scan.get("reason", "tool arguments flagged"),
                        policy="prompt_guard",
                    )
                )
                continue

            # 4c. Execute the tool
            try:
                result = await self._executor.execute(tc.name, tc.arguments, user_id)
            except Exception as exc:
                logger.error("tool_execution_error", tool=tc.name, error=str(exc))
                result = {"error": str(exc)}

            # 4d. Scan tool response
            result_scan = await self._guard.scan_output(str(result), user_id)
            if not result_scan.get("safe", True):
                result = {"redacted": True, "reason": result_scan.get("reason")}

            await self._audit.log(
                {
                    "event": "tool_executed",
                    "user_id": user_id,
                    "tool": tc.name,
                    "connector_type": tool_def.connector_type if tool_def else "",
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                }
            )

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
            # Append the assistant message with tool calls
            follow_up_messages.append(
                {"role": "assistant", "content": llm_response.content}
            )
            # Append each tool result
            for tr in tool_results:
                follow_up_messages.append(
                    {
                        "role": "tool",
                        "tool_call_id": tr["tool_call_id"],
                        "name": tr["name"],
                        "content": str(tr["result"]),
                    }
                )

            follow_up = await self._provider.complete(follow_up_messages)
            final_content = follow_up.content
            # Merge usage
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
    ) -> AsyncGenerator[dict[str, Any], None]:
        """Streaming variant — yields dicts with ``type`` and ``data`` keys.

        Event types:
        - ``content_delta``: incremental text chunk
        - ``tool_call``: the LLM wants to call a tool (includes permission status)
        - ``tool_result``: result of an executed tool
        - ``error``: something went wrong
        - ``done``: stream finished
        """
        # Scan input
        last_user_msg = next(
            (m["content"] for m in reversed(messages) if m.get("role") == "user"),
            "",
        )
        input_scan = await self._guard.scan_input(last_user_msg, user_id)
        if not input_scan.get("safe", True):
            yield {
                "type": "error",
                "data": {"reason": input_scan.get("reason", "blocked")},
            }
            return

        # First do a non-streaming call to handle tool use correctly
        # (streaming + tool use is complex; we stream the *final* response)
        tool_schemas = self._tools_to_schema(tools) if tools else []
        llm_response: LLMResponse = await self._provider.complete(
            messages=messages,
            tools=tool_schemas or None,
        )

        if not llm_response.tool_calls:
            # Stream the text content
            for i in range(0, len(llm_response.content), 20):
                yield {
                    "type": "content_delta",
                    "data": {"text": llm_response.content[i : i + 20]},
                }
            yield {"type": "done", "data": {"usage": llm_response.usage}}
            return

        # Process tool calls (same logic as chat)
        tool_map = {t.name: t for t in tools}
        tool_results: list[dict[str, Any]] = []

        for tc in llm_response.tool_calls:
            tool_def = tool_map.get(tc.name)
            permission = await self._permissions.check(user_id, tc.name, tc.arguments)

            yield {
                "type": "tool_call",
                "data": {
                    "name": tc.name,
                    "arguments": tc.arguments,
                    "permission": permission,
                },
            }

            if permission == "blocked":
                reason = await self._permissions.get_block_reason(
                    user_id, tc.name, tc.arguments
                )
                yield {
                    "type": "error",
                    "data": {"tool": tc.name, "reason": reason},
                }
                continue

            if permission == "requires_approval":
                action_id = str(uuid.uuid4())
                self._pending[action_id] = {
                    "tool_call": tc,
                    "user_id": user_id,
                    "messages": messages,
                    "tools": tools,
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
                result = await self._executor.execute(tc.name, tc.arguments, user_id)
            except Exception as exc:
                result = {"error": str(exc)}

            tool_results.append(
                {"tool_call_id": tc.id, "name": tc.name, "result": result}
            )
            yield {"type": "tool_result", "data": {"name": tc.name, "result": result}}

        # Follow-up streaming if we have tool results
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

            async for chunk in self._provider.stream(follow_up_messages):
                yield {"type": "content_delta", "data": {"text": chunk}}

        yield {"type": "done", "data": {}}

    # ------------------------------------------------------------------
    # Approve a pending action
    # ------------------------------------------------------------------

    async def approve_action(self, action_id: str, user_id: str) -> dict[str, Any]:
        """Execute a previously-pending tool call after user approval."""
        pending = self._pending.pop(action_id, None)
        if not pending:
            return {"error": "Action not found or already processed"}

        if pending["user_id"] != user_id:
            return {"error": "Unauthorized"}

        tc: ToolCall = pending["tool_call"]

        try:
            result = await self._executor.execute(tc.name, tc.arguments, user_id)
        except Exception as exc:
            result = {"error": str(exc)}

        await self._audit.log(
            {
                "event": "tool_approved_and_executed",
                "user_id": user_id,
                "tool": tc.name,
                "action_id": action_id,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }
        )

        return {"tool": tc.name, "result": result}
