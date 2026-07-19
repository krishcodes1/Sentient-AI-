"""Wires MCP servers into the agent's tool/permission/audit pipeline.

Users register an MCP server as a connector (``connector_type=mcp``)
whose encrypted credentials hold ``{"url": ..., "headers": {...}}``.
Discovered tools surface as ``mcp.<server-label>.<tool>``.

Trust model — MCP servers are third-party code, so the defaults are the
most conservative in the platform:

- Every MCP tool call requires explicit user approval (no auto-approve).
- Tools whose names match financial patterns are never offered and are
  blocked at every layer if requested anyway.
- Server URLs are SSRF-checked on every request (no private ranges).
- Tool results are sanitized like any connector response before they
  reach the LLM, and the runtime wraps them in the untrusted envelope.
"""

from __future__ import annotations

import re
import time
import uuid as uuid_module
from dataclasses import dataclass
from typing import Any, Callable, Optional

import structlog

from services.agent.runtime import Tool
from services.connectors.base import PromptGuard
from services.mcp.activity import mcp_activity
from services.mcp.client import HttpMCPTransport, MCPClient, MCPError, MCPToolInfo

logger = structlog.get_logger(__name__)

MCP_PREFIX = "mcp"

# Tool names that suggest money movement are refused outright — same
# posture as the connector catalog's FINANCIAL category.
_FINANCIAL_PATTERN = re.compile(
    r"(trade|buy|sell|transfer|withdraw|deposit|payment|\bpay\b|order|purchase|invest|wire)",
    re.IGNORECASE,
)

# -- Tool metadata sanitization ---------------------------------------------
#
# MCP servers are third-party code and their tools/list response is
# attacker-controlled. Descriptions and schemas are sanitized before
# they ever reach the LLM (tool-poisoning defense), and remote tool
# names are normalized to the provider-safe charset so one bad name
# cannot 400 an entire chat turn.

_MAX_DESCRIPTION_LEN = 500
_MAX_SCHEMA_STRING_LEN = 500
_MAX_SCHEMA_KEY_LEN = 100
_MAX_SCHEMA_DEPTH = 8

# Anthropic/OpenAI tool-name constraint is ^[a-zA-Z0-9_-]{1,64}$ (the
# dot separator in "mcp.<label>.<tool>" is a platform-wide convention
# shared with first-party tools); each component must stay in-charset.
_TOOL_NAME_INVALID_CHARS = re.compile(r"[^a-zA-Z0-9_-]+")
_MAX_TOOL_COMPONENT_LEN = 64
_MAX_FULL_NAME_LEN = 128


def slugify_label(display_name: str) -> str:
    """Stable, LLM-friendly server label derived from the display name."""
    slug = re.sub(r"[^a-z0-9]+", "_", display_name.lower()).strip("_")
    return slug or "server"


def sanitize_tool_name(name: str) -> str:
    """Deterministically normalize a remote tool name to the provider-safe
    charset ``[a-zA-Z0-9_-]``. Returns "" when nothing survives (the
    caller must then reject the tool at discovery)."""
    normalized = _TOOL_NAME_INVALID_CHARS.sub("_", str(name))
    normalized = re.sub(r"_{2,}", "_", normalized).strip("_")
    return normalized[:_MAX_TOOL_COMPONENT_LEN]


def sanitized_tool_entries(
    label: str, infos: list[MCPToolInfo]
) -> list[tuple[str, MCPToolInfo]]:
    """``[(exposed_component, info)]`` with deterministic, provider-safe,
    per-server-unique exposed names.

    Both the catalog (discovery) and the dispatcher (execution) derive
    names through this function, so a normalized exposed name always
    resolves back to the same remote tool. Unresolvable names (empty
    after normalization, or no room left in the length budget) are
    rejected here — at discovery — and logged.
    """
    # Full name is "mcp.<label>.<component>" and must fit the length cap.
    budget = _MAX_FULL_NAME_LEN - len(MCP_PREFIX) - 2 - len(label)
    budget = min(budget, _MAX_TOOL_COMPONENT_LEN)

    entries: list[tuple[str, MCPToolInfo]] = []
    used: set[str] = set()
    for info in infos:
        base = sanitize_tool_name(info.name)[: max(budget, 0)]
        if not base:
            logger.warning(
                "mcp_tool_name_unresolvable", server=label, tool=repr(info.name)
            )
            continue
        candidate = base
        suffix_n = 2
        while candidate in used:
            suffix = f"_{suffix_n}"
            candidate = base[: max(1, budget - len(suffix))] + suffix
            suffix_n += 1
        used.add(candidate)
        entries.append((candidate, info))
    return entries


def _sanitize_schema_value(value: Any, depth: int = 0) -> Any:
    """Recursively clean a tools/list ``inputSchema`` fragment.

    Strings are run through PromptGuard and length-capped, dict keys must
    be strings (and are cleaned too — injection can hide in field names),
    and non-JSON junk (arbitrary objects, absurd nesting) is dropped.
    """
    if depth > _MAX_SCHEMA_DEPTH:
        return None
    if isinstance(value, str):
        cleaned, _ = PromptGuard.scan(value)
        return cleaned[:_MAX_SCHEMA_STRING_LEN]
    if isinstance(value, bool) or isinstance(value, (int, float)) or value is None:
        return value
    if isinstance(value, list):
        out_list = []
        for item in value:
            cleaned_item = _sanitize_schema_value(item, depth + 1)
            if cleaned_item is None and item is not None:
                continue  # dropped junk
            out_list.append(cleaned_item)
        return out_list
    if isinstance(value, dict):
        out: dict[str, Any] = {}
        for key, item in value.items():
            if not isinstance(key, str):
                continue  # non-string junk key
            cleaned_key, _ = PromptGuard.scan(key)
            cleaned_item = _sanitize_schema_value(item, depth + 1)
            if cleaned_item is None and item is not None:
                continue  # dropped junk
            out[cleaned_key[:_MAX_SCHEMA_KEY_LEN]] = cleaned_item
        return out
    return None  # non-JSON junk (objects, bytes, ...)


def sanitize_tool_info(info: MCPToolInfo) -> MCPToolInfo:
    """Return a copy of *info* safe to expose to the LLM: description
    scanned for injection patterns and capped, schema cleaned of
    injection-shaped strings and non-JSON junk."""
    description, was_modified = PromptGuard.scan(str(info.description or ""))
    if was_modified:
        logger.warning("mcp_tool_description_sanitized", tool=info.name)
    description = description[:_MAX_DESCRIPTION_LEN]

    schema = _sanitize_schema_value(info.input_schema)
    if not isinstance(schema, dict) or not schema:
        schema = {"type": "object", "properties": {}}

    return MCPToolInfo(
        name=info.name, description=description, input_schema=schema
    )


def is_mcp_tool(tool_name: str) -> bool:
    return tool_name.startswith(f"{MCP_PREFIX}.")


def split_mcp_tool(tool_name: str) -> Optional[tuple[str, str]]:
    """``mcp.<label>.<tool>`` -> ``(label, tool)``; None when malformed."""
    parts = tool_name.split(".", 2)
    if len(parts) != 3 or parts[0] != MCP_PREFIX or not parts[1] or not parts[2]:
        return None
    return parts[1], parts[2]


def classify_mcp_tool(tool_name: str) -> str:
    """Permission decision for an MCP tool: financial-looking names are
    blocked, everything else requires explicit user approval."""
    if _FINANCIAL_PATTERN.search(tool_name):
        return "blocked"
    return "requires_approval"


@dataclass(frozen=True)
class McpServerRef:
    """Decrypted view of one registered MCP server."""

    connector_id: uuid_module.UUID
    label: str
    url: str
    headers: dict[str, str]
    rate_limit_per_minute: int


def default_client_factory(ref: McpServerRef) -> MCPClient:
    return MCPClient(HttpMCPTransport(ref.url, headers=ref.headers))


class MCPConnectorLoader:
    """Loads and decrypts the user's active MCP server connectors."""

    def __init__(self, session_factory: Callable[[], Any]) -> None:
        self._session_factory = session_factory

    async def load_for_user(self, user_id: str) -> list[McpServerRef]:
        import json

        from sqlalchemy import select

        from core.security import decrypt_credentials
        from models.connector import ConnectorConfig, ConnectorType

        try:
            user_uuid = uuid_module.UUID(user_id)
        except ValueError:
            return []

        refs: list[McpServerRef] = []
        async with self._session_factory() as session:
            result = await session.execute(
                select(ConnectorConfig).where(
                    ConnectorConfig.user_id == user_uuid,
                    ConnectorConfig.connector_type == ConnectorType.mcp,
                    ConnectorConfig.is_active.is_(True),
                )
            )
            for row in result.scalars().all():
                try:
                    credentials = json.loads(
                        decrypt_credentials(row.encrypted_credentials)
                    )
                except Exception:
                    logger.error(
                        "mcp_credential_decryption_failed",
                        connector_id=str(row.id),
                    )
                    continue
                url = str(credentials.get("url", "")).strip()
                if not url:
                    continue
                refs.append(
                    McpServerRef(
                        connector_id=row.id,
                        label=slugify_label(row.display_name),
                        url=url,
                        headers=dict(credentials.get("headers") or {}),
                        rate_limit_per_minute=row.rate_limit_per_minute,
                    )
                )
        return refs

    async def find(self, user_id: str, label: str) -> Optional[McpServerRef]:
        for ref in await self.load_for_user(user_id):
            if ref.label == label:
                return ref
        return None


class MCPToolCatalog:
    """Discovers MCP tools for a user, with a short in-process cache so a
    chat turn does not hammer the server with tools/list calls."""

    def __init__(
        self,
        loader: MCPConnectorLoader,
        client_factory: Callable[[McpServerRef], MCPClient] = default_client_factory,
        ttl_seconds: float = 60.0,
    ) -> None:
        self._loader = loader
        self._client_factory = client_factory
        self._ttl = ttl_seconds
        self._cache: dict[uuid_module.UUID, tuple[float, list[MCPToolInfo]]] = {}

    async def _tools_for_server(self, ref: McpServerRef) -> list[MCPToolInfo]:
        cached = self._cache.get(ref.connector_id)
        now = time.monotonic()
        if cached and (now - cached[0]) < self._ttl:
            return cached[1]

        client = self._client_factory(ref)
        try:
            tools = await client.list_tools()
        except Exception as exc:
            mcp_activity.record_error(ref.connector_id, str(exc))
            raise
        finally:
            await client.close()
        # Sanitize BEFORE caching so poisoned metadata never sits in the
        # cache in raw form.
        tools = [sanitize_tool_info(t) for t in tools]
        self._cache[ref.connector_id] = (now, tools)
        mcp_activity.record_success(ref.connector_id)
        return tools

    async def tools_for_user(self, user_id: str) -> list[Tool]:
        """Runtime ``Tool`` objects for every reachable MCP server.

        A server that fails discovery is skipped (logged) rather than
        breaking the whole chat turn. Financial-looking tools are never
        offered.
        """
        out: list[Tool] = []
        for ref in await self._loader.load_for_user(user_id):
            try:
                infos = await self._tools_for_server(ref)
            except (MCPError, Exception) as exc:
                logger.warning(
                    "mcp_tool_discovery_failed", server=ref.label, error=str(exc)
                )
                continue
            for exposed_name, info in sanitized_tool_entries(ref.label, infos):
                full_name = f"{MCP_PREFIX}.{ref.label}.{exposed_name}"
                # Classify on both the exposed and the original remote name
                # so normalization can never launder a financial tool.
                if (
                    classify_mcp_tool(full_name) == "blocked"
                    or _FINANCIAL_PATTERN.search(info.name)
                ):
                    logger.info(
                        "mcp_tool_suppressed_financial",
                        server=ref.label,
                        tool=info.name,
                    )
                    continue
                out.append(
                    Tool(
                        name=full_name,
                        description=f"[MCP:{ref.label}] {info.description}".strip(),
                        parameters=info.input_schema
                        or {"type": "object", "properties": {}},
                        connector_type="mcp",
                        permission_tier="approval",
                    )
                )
        return out


class MCPDispatcher:
    """Executes an approved ``mcp.<label>.<tool>`` call.

    Enforces the connector's ``rate_limit_per_minute`` (sliding window,
    in-process, per server), resolves normalized exposed names back to
    the server's real tool names, and sanitizes output with the same
    PromptGuard used for first-party connectors before it returns to the
    runtime.
    """

    def __init__(
        self,
        loader: MCPConnectorLoader,
        client_factory: Callable[[McpServerRef], MCPClient] = default_client_factory,
    ) -> None:
        self._loader = loader
        self._client_factory = client_factory
        # connector_id -> RateLimiter (same in-process posture as the
        # executor's per-config limiters for first-party connectors).
        self._limiters: dict[uuid_module.UUID, Any] = {}

    def _acquire_rate_limit(self, ref: McpServerRef) -> Optional[str]:
        from services.connectors.base import RateLimiter, RateLimitExceededError

        limiter = self._limiters.get(ref.connector_id)
        if limiter is None or limiter.max_calls != ref.rate_limit_per_minute:
            limiter = RateLimiter(ref.rate_limit_per_minute)
            self._limiters[ref.connector_id] = limiter
        try:
            limiter.acquire()
        except RateLimitExceededError as exc:
            return str(exc)
        return None

    async def execute(
        self, tool_name: str, arguments: dict[str, Any], user_id: str
    ) -> dict[str, Any]:
        parts = split_mcp_tool(tool_name)
        if parts is None:
            return {"ok": False, "error": f"Malformed MCP tool name '{tool_name}'"}
        label, remote_tool = parts

        if classify_mcp_tool(tool_name) == "blocked":
            return {
                "ok": False,
                "error": (
                    f"MCP tool '{remote_tool}' looks like a financial action and "
                    "is permanently blocked by platform policy."
                ),
            }

        ref = await self._loader.find(user_id, label)
        if ref is None:
            return {
                "ok": False,
                "error": f"No active MCP server '{label}' is configured.",
            }

        limit_error = self._acquire_rate_limit(ref)
        if limit_error:
            return {"ok": False, "error": limit_error}

        client = self._client_factory(ref)
        try:
            # Resolve the exposed (normalized) name back to the server's
            # real tool name via the same deterministic mapping used at
            # discovery. Only advertised tools are callable.
            infos = await client.list_tools()
            remote_name: Optional[str] = None
            for exposed_name, info in sanitized_tool_entries(label, infos):
                if exposed_name == remote_tool:
                    remote_name = info.name
                    break
            if remote_name is None:
                mcp_activity.record_error(
                    ref.connector_id, f"tool '{remote_tool}' not advertised"
                )
                return {
                    "ok": False,
                    "error": (
                        f"MCP server '{label}' does not advertise a tool "
                        f"'{remote_tool}'."
                    ),
                }
            if _FINANCIAL_PATTERN.search(remote_name):
                return {
                    "ok": False,
                    "error": (
                        f"MCP tool '{remote_tool}' looks like a financial action "
                        "and is permanently blocked by platform policy."
                    ),
                }
            result = await client.call_tool(remote_name, dict(arguments))
        except MCPError as exc:
            mcp_activity.record_error(ref.connector_id, str(exc))
            return {"ok": False, "error": str(exc)}
        except Exception as exc:
            logger.error(
                "mcp_dispatch_unexpected_error",
                server=label,
                tool=remote_tool,
                error=str(exc),
            )
            mcp_activity.record_error(ref.connector_id, str(exc))
            return {"ok": False, "error": f"MCP call failed: {exc}"}
        finally:
            await client.close()

        mcp_activity.record_success(ref.connector_id)

        sanitized, was_modified = PromptGuard.scan(result.get("content"))
        if was_modified:
            logger.warning("mcp_content_sanitized", server=label, tool=remote_tool)
        return {
            "ok": result.get("ok", False),
            "connector": f"mcp:{label}",
            "action": remote_tool,
            "result": sanitized,
            "sanitized": was_modified,
        }
