"""Loads a user's MCP server connectors, discovers and sanitises their tools, and
dispatches approved calls through a pooled client.

Why it exists: MCP servers are third-party code, so the tool registry, the
agent route and the connector routes need one layer that applies the approval-
always, no-financial-tools and name-binding rules before a remote tool is
offered or run.

Wires MCP servers into the agent's tool/permission/audit pipeline.

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
- An exposed name is bound to one remote tool at discovery. A server
  cannot reorder or extend its catalog to make an already-approved name
  execute a different remote tool.
"""

from __future__ import annotations

import asyncio
import re
import time
import uuid as uuid_module
import weakref
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
#
# Applied to a run-on name only; see ``is_financial_action``.
_FINANCIAL_PATTERN = re.compile(
    r"(trade|buy|sell|transfer|withdraw|deposit|payment|\bpay\b|order|purchase|invest|wire)",
    re.IGNORECASE,
)

# The same vocabulary as tokens, with the inflections a tool name
# actually uses. Spelled out rather than stemmed so the blocklist stays
# auditable: every word here is one a reviewer can weigh.
_FINANCIAL_TOKENS: frozenset[str] = frozenset(
    {
        "trade", "trades", "trading", "traded",
        "buy", "buys", "buying", "bought",
        "sell", "sells", "selling", "sold",
        "transfer", "transfers", "transferring", "transferred",
        "withdraw", "withdraws", "withdrawing", "withdrawal", "withdrawals",
        "deposit", "deposits", "depositing", "deposited",
        "payment", "payments", "pay", "pays", "paying", "paid",
        "payout", "payouts",
        "order", "orders", "ordering", "ordered", "reorder", "reorders",
        "purchase", "purchases", "purchasing", "purchased",
        "invest", "invests", "investing", "invested",
        "investment", "investments",
        "wire", "wires", "wiring", "wired",
    }
)

_TOKEN_BOUNDARY = re.compile(r"[^A-Za-z0-9]+")
_CAMEL_BOUNDARY = re.compile(r"(?<=[a-z0-9])(?=[A-Z])")


def action_tokens(action: str) -> list[str]:
    """Split a tool's action name into lowercase words.

    Handles both conventions MCP servers use: ``execute_trade`` and
    ``executeTrade``.
    """
    words: list[str] = []
    for chunk in _TOKEN_BOUNDARY.split(action):
        if chunk:
            words.extend(w.lower() for w in _CAMEL_BOUNDARY.split(chunk) if w)
    return words


def is_financial_action(action: str) -> bool:
    """Whether *action* names a money-moving operation.

    Matching is on the words of the ACTION name alone. The old substring
    search ran over the whole ``mcp.<label>.<tool>`` string, so a server
    the user labelled "Banking Orders" had every one of its benign tools
    silently suppressed — and the user's only recourse was to guess that
    the server's own name was the problem.

    A name with no word boundaries at all ("executetrade") hides its
    words from tokenization, so that single case still gets the substring
    search: it is exactly the shape an evasive server would choose, and
    refusing it keeps the control at least as tight as before.
    """
    tokens = action_tokens(action)
    if any(token in _FINANCIAL_TOKENS for token in tokens):
        return True
    if len(tokens) <= 1:
        return bool(_FINANCIAL_PATTERN.search(action))
    return False


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

    Collision suffixes are assigned in a canonical order (sorted by the
    *remote* name), never in advertisement order. Order-dependent
    suffixing was a confused-deputy hole: a server advertising both
    "my tool" and "my_tool" got ``my_tool``/``my_tool_2`` at discovery
    and could swap which remote tool the approved ``my_tool`` executed
    simply by reversing its next tools/list. The returned list stays in
    advertisement order — only the name assignment is canonical — so a
    server still controls how its tools are presented, just not which
    remote tool an already-approved name means.
    """
    # Full name is "mcp.<label>.<component>" and must fit the length cap.
    budget = _MAX_FULL_NAME_LEN - len(MCP_PREFIX) - 2 - len(label)
    budget = min(budget, _MAX_TOOL_COMPONENT_LEN)

    resolvable: list[tuple[str, MCPToolInfo]] = []  # (base, info)
    for info in infos:
        base = sanitize_tool_name(info.name)[: max(budget, 0)]
        if not base:
            logger.warning(
                "mcp_tool_name_unresolvable", server=label, tool=repr(info.name)
            )
            continue
        resolvable.append((base, info))

    exposed: list[str] = [""] * len(resolvable)
    used: set[str] = set()
    # sorted() is stable, so duplicate remote names still fall back to
    # advertisement order — they are indistinguishable anyway.
    for index in sorted(
        range(len(resolvable)), key=lambda i: resolvable[i][1].name
    ):
        base = resolvable[index][0]
        candidate = base
        suffix_n = 2
        while candidate in used:
            suffix = f"_{suffix_n}"
            candidate = base[: max(1, budget - len(suffix))] + suffix
            suffix_n += 1
        used.add(candidate)
        exposed[index] = candidate

    return [(exposed[i], resolvable[i][1]) for i in range(len(resolvable))]


class MCPNameBindingRegistry:
    """Remembers which remote tool each exposed name meant at discovery.

    ``sanitized_tool_entries`` makes the mapping independent of the order
    a server advertises its tools in, but not of the *set*: a server that
    later adds a tool normalizing onto an already-approved exposed name
    would still steal it (add "my tool" after the user approved
    "my_tool"). Recording the binding when the tool list is shown to the
    user, and replaying it at execution, closes that: an approved name
    either runs the remote tool the user saw, or fails loudly.

    Bindings are STICKY: an exposed name keeps the remote tool it was
    first bound to, for the life of the process. Replacing the map on each
    discovery would reopen the hole it exists to close, because discovery
    re-runs on every chat send behind a 60s cache — a server only has to
    add the colliding tool and wait one TTL for the rebind to happen
    between the user seeing an action and approving it.

    A legitimate server that renames or drops a tool therefore does not
    get silent re-resolution either: the dispatcher refuses the stale
    binding rather than guessing, which is the safe direction. Re-adding
    the connector clears it.

    In-process only, like ``mcp_activity`` — after a restart the
    dispatcher falls back to the deterministic derivation.
    """

    def __init__(self) -> None:
        self._bindings: dict[uuid_module.UUID, dict[str, str]] = {}

    def record(
        self, connector_id: uuid_module.UUID, entries: list[tuple[str, MCPToolInfo]]
    ) -> None:
        bindings = self._bindings.setdefault(connector_id, {})
        for exposed, info in entries:
            existing = bindings.get(exposed)
            if existing is None:
                bindings[exposed] = info.name
            elif existing != info.name:
                # The server is now advertising a different remote tool
                # under a name the user may already have approved. Keep the
                # original binding and say so; the dispatcher will refuse
                # the call if the bound tool is genuinely gone.
                logger.warning(
                    "mcp_exposed_name_rebind_refused",
                    connector_id=str(connector_id),
                    exposed_name=exposed,
                    bound_remote=existing,
                    advertised_remote=info.name,
                )

    def resolve(
        self, connector_id: uuid_module.UUID, exposed_name: str
    ) -> Optional[str]:
        return self._bindings.get(connector_id, {}).get(exposed_name)

    def invalidate(self, connector_id: uuid_module.UUID) -> None:
        """Drop every binding for one connector."""
        self._bindings.pop(connector_id, None)

    def reset(self) -> None:
        """Clear all recorded bindings (test hygiene)."""
        self._bindings.clear()


# Process-wide singleton: the catalog writes it at discovery, the
# dispatcher reads it at execution (the two are constructed separately).
mcp_name_bindings = MCPNameBindingRegistry()

# Every live catalog, so a connector edit can drop its cached tool list
# as well as its name bindings. Weak so a discarded catalog is collected
# normally; the catalog is constructed per executor, not per request, so
# this set stays tiny.
_live_catalogs: "weakref.WeakSet[MCPToolCatalog]" = weakref.WeakSet()


def invalidate_mcp_connector(connector_id: uuid_module.UUID) -> None:
    """Forget everything cached about one MCP server.

    Bindings are deliberately sticky for the life of the process so a
    server cannot rebind an approved name behind the user's back. That
    protection is against the *server*, not the user: when the user
    themselves repoints or deletes the connector, the old bindings
    describe tools on a host that is no longer configured, and keeping
    them wedges those names — every call answered with "no longer
    advertises the tool approved as ..." until the process restarts.
    The routes call this on update and delete.
    """
    mcp_name_bindings.invalidate(connector_id)
    for catalog in list(_live_catalogs):
        catalog.forget(connector_id)


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
    blocked, everything else requires explicit user approval.

    Only the action component of a well-formed ``mcp.<label>.<tool>``
    name is classified — the label is the user's own server name and says
    nothing about what a tool does. A name that does not parse is judged
    whole, since there is no component to trust.
    """
    parts = split_mcp_tool(tool_name)
    action = parts[1] if parts else tool_name
    if is_financial_action(action):
        return "blocked"
    return "requires_approval"


@dataclass(frozen=True)
class McpServerRef:
    """Decrypted view of one registered MCP server.

    A row whose credentials cannot be used carries ``config_error``
    instead of being dropped. Dropping it made a misconfigured server
    indistinguishable from one that was never registered, so the user was
    told "no such server" about a server sitting right there in their
    connector list.
    """

    connector_id: uuid_module.UUID
    label: str
    url: str
    headers: dict[str, str]
    rate_limit_per_minute: int
    config_error: Optional[str] = None


class _PooledMCPClient(MCPClient):
    """An ``MCPClient`` owned by :class:`MCPClientPool`.

    Callers (catalog and dispatcher) follow a strict create → use →
    ``close()`` pattern. For a pooled client ``close()`` is a release,
    not a teardown: the MCP session (``Mcp-Session-Id`` + completed
    ``initialize`` handshake) and any kept-alive HTTP connection survive
    for the next call. Before pooling, every tool call paid a fresh
    TCP+TLS connect plus the two-round-trip handshake on top of the
    tools/list + tools/call it actually needed.

    Any protocol or transport error evicts this client from the pool and
    really closes it, so a wedged session (server restart, expired
    session id) lasts at most one failed call — the next call starts
    clean, exactly as it did before pooling.
    """

    def __init__(
        self, transport: Any, pool: "MCPClientPool", key: tuple
    ) -> None:
        super().__init__(transport)
        self._pool = pool
        self._pool_key = key

    async def close(self) -> None:  # release back to the pool
        return None

    async def force_close(self) -> None:
        await super().close()

    async def list_tools(self) -> list[MCPToolInfo]:
        try:
            return await super().list_tools()
        except Exception:
            await self._pool.discard(self._pool_key, self)
            raise

    async def call_tool(self, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        try:
            return await super().call_tool(name, arguments)
        except Exception:
            await self._pool.discard(self._pool_key, self)
            raise


class MCPClientPool:
    """One live MCP client per registered server, per event loop.

    Security semantics are unchanged by reuse: the SSRF check and DNS
    address pinning are a *per-request* httpx event hook on the transport
    (see ``HttpMCPTransport._check_ssrf``), so every request over a pooled
    client is still validated and pinned exactly as it was when each call
    built a throwaway client.

    The key includes the connector id, URL, and headers, so rotating a
    server's credentials or URL naturally stops hitting the old entry
    (which then ages out of the LRU and is closed). The event-loop id is
    in the key too because httpx clients bind to the loop that first uses
    them — an entry from a dead loop must never be handed to a new one.
    """

    def __init__(self, max_clients: int = 32) -> None:
        self._max = max_clients
        self._clients: dict[tuple, _PooledMCPClient] = {}
        # Fire-and-forget closes for LRU-evicted clients; referenced here
        # so the tasks are not garbage-collected mid-close.
        self._closing: set[asyncio.Task] = set()

    @staticmethod
    def _key(ref: McpServerRef) -> tuple:
        try:
            loop_id = id(asyncio.get_running_loop())
        except RuntimeError:
            loop_id = None
        return (
            loop_id,
            ref.connector_id,
            ref.url,
            tuple(sorted(ref.headers.items())),
        )

    def get(self, ref: McpServerRef) -> MCPClient:
        key = self._key(ref)
        client = self._clients.get(key)
        if client is not None:
            # Refresh LRU position (dicts preserve insertion order).
            del self._clients[key]
            self._clients[key] = client
            return client

        client = _PooledMCPClient(
            HttpMCPTransport(ref.url, headers=ref.headers), self, key
        )
        self._clients[key] = client
        while len(self._clients) > self._max:
            _, evicted = next(iter(self._clients.items()))
            self._retire(evicted)
        return client

    def _retire(self, client: _PooledMCPClient) -> None:
        self._clients.pop(client._pool_key, None)
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            return
        task = loop.create_task(client.force_close())
        self._closing.add(task)
        task.add_done_callback(self._closing.discard)

    async def discard(self, key: tuple, client: _PooledMCPClient) -> None:
        """Drop *client* (if it is still the pooled entry) and close it."""
        if self._clients.get(key) is client:
            del self._clients[key]
        await client.force_close()


_client_pool = MCPClientPool()


def default_client_factory(ref: McpServerRef) -> MCPClient:
    return _client_pool.get(ref)


class MCPConnectorLoader:
    """Loads and decrypts the user's active MCP server connectors."""

    def __init__(self, session_factory: Callable[[], Any]) -> None:
        self._session_factory = session_factory

    async def load_for_user(self, user_id: str) -> list[McpServerRef]:
        from sqlalchemy import select

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
                refs.append(self._ref_for_row(row))
        return refs

    @staticmethod
    def _ref_for_row(row: Any) -> McpServerRef:
        """Build a ref, recording why the row is unusable rather than
        raising. This runs on every chat send, so one connector with a
        malformed credential blob must not be able to fail the turn."""
        import json

        from core.security import decrypt_credentials
        from services.connectors.factory import coerce_header_map

        def broken(reason: str) -> McpServerRef:
            mcp_activity.record_error(row.id, reason)
            return McpServerRef(
                connector_id=row.id,
                label=slugify_label(row.display_name),
                url="",
                headers={},
                rate_limit_per_minute=row.rate_limit_per_minute,
                config_error=reason,
            )

        try:
            credentials = json.loads(decrypt_credentials(row.encrypted_credentials))
        except Exception:
            logger.error(
                "mcp_credential_decryption_failed", connector_id=str(row.id)
            )
            return broken(
                "stored credentials could not be read; re-enter them to fix"
            )
        if not isinstance(credentials, dict):
            return broken("stored credentials are not a JSON object")

        url = str(credentials.get("url", "")).strip()
        if not url:
            return broken("no server URL is configured")

        headers = coerce_header_map(credentials.get("headers"))
        if headers is None:
            logger.warning("mcp_headers_malformed", connector_id=str(row.id))
            return broken(
                "the 'headers' credential must be an object of "
                "header name -> value"
            )

        return McpServerRef(
            connector_id=row.id,
            label=slugify_label(row.display_name),
            url=url,
            headers=headers,
            rate_limit_per_minute=row.rate_limit_per_minute,
        )

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
        _live_catalogs.add(self)

    def forget(self, connector_id: uuid_module.UUID) -> None:
        """Drop the cached tool list for one server."""
        self._cache.pop(connector_id, None)

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
            if ref.config_error:
                logger.warning(
                    "mcp_server_misconfigured",
                    server=ref.label,
                    error=ref.config_error,
                )
                continue
            try:
                infos = await self._tools_for_server(ref)
            except (MCPError, Exception) as exc:
                logger.warning(
                    "mcp_tool_discovery_failed", server=ref.label, error=str(exc)
                )
                continue
            entries = sanitized_tool_entries(ref.label, infos)
            # Pin what each exposed name means *now*, before the user sees
            # (and approves) it — the dispatcher replays this instead of
            # re-deriving against a catalog the server may have mutated.
            mcp_name_bindings.record(ref.connector_id, entries)
            for exposed_name, info in entries:
                full_name = f"{MCP_PREFIX}.{ref.label}.{exposed_name}"
                # Classify on both the exposed and the original remote name
                # so normalization can never launder a financial tool.
                if (
                    classify_mcp_tool(full_name) == "blocked"
                    or is_financial_action(info.name)
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
    the server's real tool names — preferring the binding captured at
    discovery, which is what the user actually approved — and sanitizes
    output with the same PromptGuard used for first-party connectors
    before it returns to the runtime.
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
        if ref.config_error:
            return {
                "ok": False,
                "error": (
                    f"MCP server '{label}' is misconfigured: {ref.config_error}."
                ),
            }

        limit_error = self._acquire_rate_limit(ref)
        if limit_error:
            return {"ok": False, "error": limit_error}

        client = self._client_factory(ref)
        try:
            # Resolve the exposed (normalized) name back to the server's
            # real tool name. Only advertised tools are callable.
            infos = await client.list_tools()
            entries = sanitized_tool_entries(label, infos)
            advertised = {info.name for _, info in entries}

            remote_name = mcp_name_bindings.resolve(ref.connector_id, remote_tool)
            if remote_name is not None and remote_name not in advertised:
                # The tool the user approved is gone. Re-deriving here
                # would silently hand the approval to whichever remote
                # tool now owns the exposed name.
                mcp_activity.record_error(
                    ref.connector_id, f"tool '{remote_tool}' no longer advertised"
                )
                return {
                    "ok": False,
                    "error": (
                        f"MCP server '{label}' no longer advertises the tool "
                        f"approved as '{remote_tool}'."
                    ),
                }
            if remote_name is None:
                # No discovery in this process (restart, or dispatch
                # without a preceding tool listing): fall back to the
                # order-independent derivation.
                for exposed_name, info in entries:
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
            if is_financial_action(remote_name):
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

        sanitized, was_modified = PromptGuard.scan(result.get("content"))
        if was_modified:
            logger.warning("mcp_content_sanitized", server=label, tool=remote_tool)

        # A tool-level failure (``isError``) is still a failed call.
        # Recording it as a success gave /connectors/health a fresh
        # last_success for a server whose every call fails. The message is
        # the *sanitized* content: it is third-party text and the health
        # endpoint renders it back to the user.
        if result.get("ok"):
            mcp_activity.record_success(ref.connector_id)
        else:
            mcp_activity.record_error(
                ref.connector_id, str(sanitized) or "tool reported isError"
            )

        return {
            "ok": result.get("ok", False),
            "connector": f"mcp:{label}",
            "action": remote_tool,
            "result": sanitized,
            "sanitized": was_modified,
        }
