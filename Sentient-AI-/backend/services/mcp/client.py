"""Minimal MCP client (JSON-RPC 2.0 over Streamable HTTP).

Self-contained on purpose: the official ``mcp`` SDK is not a project
dependency, and the platform only needs three operations — initialize,
tools/list, and tools/call. The transport is a seam so tests (and a
future stdio implementation) can swap it out.

Security properties:
- Every outbound request URL is SSRF-checked (private/internal ranges
  refused), including redirect hops, via an httpx request hook.
- The addresses that check validated are *pinned*: the socket is opened
  to one of them instead of re-resolving the hostname, so a hostile DNS
  server cannot answer the check with a public address and the
  connection with 127.0.0.1 (see ``_PinnedResolutionBackend``).
- Responses are data, never trusted: callers sanitize tool output before
  it reaches the LLM (see ``MCPDispatcher``).
"""

from __future__ import annotations

import asyncio
import json
from dataclasses import dataclass, field
from typing import Any, Iterable, Optional, Protocol

import httpcore
import httpx
import structlog

logger = structlog.get_logger(__name__)

MCP_PROTOCOL_VERSION = "2025-03-26"

# (ascii host, port) -> addresses that passed the SSRF policy for it.
PinTable = dict[tuple[str, int], tuple[str, ...]]


class MCPError(Exception):
    """Raised for transport failures or JSON-RPC error responses."""


def _format_rpc_error(error: Any) -> str:
    """Render a JSON-RPC ``error`` member for an ``MCPError`` message.

    The member is attacker-controlled, so it may be an empty object, a
    bare string, or anything else — never assume the spec shape.
    """
    if isinstance(error, dict):
        return (
            f"MCP error {error.get('code', '?')}: {error.get('message', 'unknown')}"
        )
    return f"MCP error ?: {error}"


@dataclass(frozen=True)
class MCPToolInfo:
    """One tool advertised by an MCP server."""

    name: str
    description: str = ""
    input_schema: dict[str, Any] = field(default_factory=dict)


class MCPTransport(Protocol):
    async def request(self, method: str, params: dict[str, Any]) -> Any: ...

    async def notify(self, method: str, params: dict[str, Any]) -> None: ...

    async def close(self) -> None: ...


class _PinnedResolutionBackend(httpcore.AsyncNetworkBackend):
    """Socket layer that may only dial addresses already validated.

    Checking a URL and then handing the *hostname* to httpx leaves a
    DNS-rebinding TOCTOU: httpcore resolves the origin again inside
    ``connect_tcp``, and a hostile authoritative server answers the first
    lookup with a public address and the second with 127.0.0.1. httpx
    exposes no resolver seam, so the fix is to replace the connect-time
    lookup entirely — this backend dials the addresses the request hook
    recorded and never resolves anything itself. An origin with no entry
    is refused rather than resolved, so the failure mode is closed.

    TLS is deliberately untouched. httpcore derives the ``Host`` header,
    the TLS SNI, and the certificate hostname from the request origin,
    not from the argument to ``connect_tcp``, so connecting by IP costs
    nothing in certificate verification strictness.
    """

    def __init__(
        self,
        pins: PinTable,
        inner: Optional[httpcore.AsyncNetworkBackend] = None,
    ) -> None:
        self._pins = pins
        # AnyIOBackend is httpcore's default under both asyncio and trio
        # (its AutoBackend only swaps in the native-trio variant, which
        # this process never runs on). Injecting *inner* is the test seam
        # for the socket layer.
        self._inner = inner if inner is not None else httpcore.AnyIOBackend()

    async def connect_tcp(
        self,
        host: str,
        port: int,
        timeout: Optional[float] = None,
        local_address: Optional[str] = None,
        socket_options: Optional[Iterable[Any]] = None,
    ) -> httpcore.AsyncNetworkStream:
        addresses = self._pins.get((host.lower(), port))
        if not addresses:
            raise httpcore.ConnectError(
                f"No validated address is pinned for {host}:{port}; "
                "refusing to resolve it at connect time."
            )

        last_error: Optional[BaseException] = None
        for address in addresses:
            try:
                return await self._inner.connect_tcp(
                    address,
                    port,
                    timeout=timeout,
                    local_address=local_address,
                    socket_options=socket_options,
                )
            except (httpcore.ConnectError, httpcore.ConnectTimeout) as exc:
                # Every pinned address passed the policy, so falling
                # through to the next one cannot reach anywhere the first
                # one was not already allowed to reach. Without this, a
                # multi-record host with one dead record would fail even
                # though a healthy record was validated alongside it.
                last_error = exc
        if last_error is not None:
            raise last_error
        raise httpcore.ConnectError(f"No pinned address reachable for {host}:{port}")

    async def connect_unix_socket(
        self,
        path: str,
        timeout: Optional[float] = None,
        socket_options: Optional[Iterable[Any]] = None,
    ) -> httpcore.AsyncNetworkStream:
        # A unix socket has no address to validate and is by definition
        # local; MCP never uses one over this transport.
        raise httpcore.ConnectError(
            "Unix-socket connections are not permitted for MCP servers."
        )

    async def sleep(self, seconds: float) -> None:
        await self._inner.sleep(seconds)


class _PinnedHTTPTransport(httpx.AsyncHTTPTransport):
    """``httpx.AsyncHTTPTransport`` whose DNS is replaced by a pin table."""

    def __init__(
        self,
        pins: PinTable,
        network_backend: Optional[httpcore.AsyncNetworkBackend] = None,
        **kwargs: Any,
    ) -> None:
        super().__init__(**kwargs)
        # httpx builds the httpcore pool itself and forwards no
        # ``network_backend``, so swapping it afterwards is the only way
        # in. The pool hands this object to every connection it creates.
        if not hasattr(self._pool, "_network_backend"):
            # If a future httpx/httpcore renames this, a plain assignment
            # would quietly create a dead attribute and leave the real
            # resolver in place — the pin silently stops applying and the
            # rebinding window reopens with no signal. Fail loudly at
            # construction instead.
            raise MCPError(
                "Cannot pin MCP DNS resolution: this httpx build exposes no "
                "httpcore network backend to replace."
            )
        self._pool._network_backend = _PinnedResolutionBackend(pins, network_backend)


class HttpMCPTransport:
    """Streamable-HTTP transport: JSON-RPC requests POSTed to one URL.

    Handles plain JSON responses and single-response SSE bodies (servers
    may answer ``text/event-stream`` even for one-shot calls).
    """

    def __init__(
        self,
        url: str,
        headers: Optional[dict[str, str]] = None,
        timeout_s: float = 30.0,
        *,
        network_backend: Optional[httpcore.AsyncNetworkBackend] = None,
    ) -> None:
        self._url = url
        self._headers = dict(headers or {})
        self._timeout = timeout_s
        self._client: Optional[httpx.AsyncClient] = None
        self._next_id = 0
        self._session_id: Optional[str] = None
        self._network_backend = network_backend
        # Keyed by origin, and this transport only ever talks to one
        # origin (redirects are not followed), so the table holds a
        # single entry that every request overwrites with the resolution
        # its own check just validated. It cannot grow unbounded.
        self._pins: PinTable = {}

    async def _check_ssrf(self, request: httpx.Request) -> None:
        """Validate the destination and pin what was validated.

        Runs on every hop rather than once at construction: httpx fires
        request hooks inside its redirect loop, so a hop to a new host
        gets its own check and its own pin instead of inheriting the
        original host's clearance.
        """
        from core.network_security import check_ssrf

        # getaddrinfo is a blocking syscall and this hook runs on the event
        # loop, once per request and again per redirect hop. A slow or
        # unreachable resolver would stall every other request in the
        # worker — including in-flight SSE streams — so it goes to a thread.
        result = await asyncio.to_thread(check_ssrf, str(request.url))
        if not result.safe:
            raise MCPError(f"MCP request blocked (SSRF protection): {result.reason}")
        self._pin(request, result.resolved_ips)

    def _pin(self, request: httpx.Request, addresses: tuple[str, ...]) -> None:
        """Record the validated addresses for this request's origin.

        Keyed off ``raw_host`` (ASCII/punycode) and the scheme-defaulted
        port because that is exactly the origin httpcore will present to
        ``connect_tcp``; ``URL.host`` would hand back the decoded Unicode
        form for an IDN and the pin lookup would miss.

        Recording nothing is safe: ``_PinnedResolutionBackend`` refuses
        an unpinned origin instead of resolving it.
        """
        if not addresses:
            return
        from core.network_security import default_port_for_scheme

        host = request.url.raw_host.decode("ascii").lower()
        port = request.url.port or default_port_for_scheme(request.url.scheme)
        self._pins[(host, port)] = addresses

    def _get_client(self) -> httpx.AsyncClient:
        if self._client is None or self._client.is_closed:
            self._client = httpx.AsyncClient(
                timeout=httpx.Timeout(self._timeout),
                transport=_PinnedHTTPTransport(self._pins, self._network_backend),
                event_hooks={"request": [self._check_ssrf]},
            )
        return self._client

    def _build_headers(self) -> dict[str, str]:
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
            **self._headers,
        }
        if self._session_id:
            headers["Mcp-Session-Id"] = self._session_id
        return headers

    @staticmethod
    def _parse_sse(body: str, request_id: int) -> Any:
        """Extract the JSON-RPC response with *request_id* from an SSE body."""
        for raw_event in body.split("\n\n"):
            data_lines = [
                line[5:].strip()
                for line in raw_event.splitlines()
                if line.startswith("data:")
            ]
            if not data_lines:
                continue
            try:
                message = json.loads("\n".join(data_lines))
            except json.JSONDecodeError:
                continue
            if isinstance(message, dict) and message.get("id") == request_id:
                return message
        raise MCPError("No matching JSON-RPC response in SSE stream")

    async def _post(self, payload: dict[str, Any]) -> httpx.Response:
        client = self._get_client()
        try:
            response = await client.post(
                self._url, json=payload, headers=self._build_headers()
            )
        except MCPError:
            raise
        except httpx.HTTPError as exc:
            raise MCPError(f"MCP transport error: {exc}") from exc

        if session_id := response.headers.get("Mcp-Session-Id"):
            self._session_id = session_id
        return response

    async def request(self, method: str, params: dict[str, Any]) -> Any:
        self._next_id += 1
        request_id = self._next_id
        response = await self._post(
            {"jsonrpc": "2.0", "id": request_id, "method": method, "params": params}
        )
        if response.status_code >= 400:
            raise MCPError(
                f"MCP server returned HTTP {response.status_code} for '{method}'"
            )

        content_type = response.headers.get("content-type", "")
        if "text/event-stream" in content_type:
            message = self._parse_sse(response.text, request_id)
        else:
            try:
                message = response.json()
            except json.JSONDecodeError as exc:
                raise MCPError("MCP server returned invalid JSON") from exc

        if not isinstance(message, dict):
            raise MCPError("MCP server returned a non-object response")
        # JSON-RPC 2.0 requires exactly one of result/error. Neither (or a
        # present-but-empty error object) is a protocol violation, and it
        # must not read as success: `.get("result")` would hand back None,
        # which call_tool turns into an empty ok=True result and list_tools
        # into an empty catalog — the agent would treat a broken server as
        # a working one with nothing to say.
        if "error" in message and message["error"] is not None:
            raise MCPError(_format_rpc_error(message["error"]))
        if "result" not in message:
            raise MCPError(
                f"MCP server returned neither 'result' nor 'error' for '{method}'"
            )
        return message["result"]

    async def notify(self, method: str, params: dict[str, Any]) -> None:
        response = await self._post(
            {"jsonrpc": "2.0", "method": method, "params": params}
        )
        # A discarded response hides handshake failures: a rejected
        # notifications/initialized would still leave the client marked
        # initialized, and the real failure would resurface later as a
        # confusing tools/list error.
        if response.status_code >= 400:
            raise MCPError(
                f"MCP server returned HTTP {response.status_code} "
                f"for notification '{method}'"
            )
        # Servers that answer a notification with 200 + a JSON-RPC error
        # object instead of a 4xx have still refused it.
        if response.content:
            try:
                message = response.json()
            except (json.JSONDecodeError, UnicodeDecodeError):
                return
            if isinstance(message, dict) and message.get("error") is not None:
                raise MCPError(_format_rpc_error(message["error"]))

    async def close(self) -> None:
        if self._client and not self._client.is_closed:
            await self._client.aclose()
            self._client = None


class MCPClient:
    """High-level MCP operations over any transport."""

    def __init__(self, transport: MCPTransport) -> None:
        self._transport = transport
        self._initialized = False

    async def initialize(self) -> None:
        if self._initialized:
            return
        await self._transport.request(
            "initialize",
            {
                "protocolVersion": MCP_PROTOCOL_VERSION,
                "capabilities": {},
                "clientInfo": {"name": "sentientai", "version": "0.1.0"},
            },
        )
        await self._transport.notify("notifications/initialized", {})
        self._initialized = True

    async def list_tools(self) -> list[MCPToolInfo]:
        """Advertised tools, or ``MCPError`` if the payload is unusable.

        The payload is third-party data, so every shape assumption is a
        crash the caller cannot handle: a bare JSON array or a string
        entry used to escape as ``AttributeError`` and leak out of
        ``POST /connectors/{id}/test`` as "'str' object has no attribute
        'get'". Individually malformed entries are dropped, but a payload
        whose entries are *all* unusable raises rather than passing for a
        server that simply has no tools.
        """
        await self.initialize()
        result = await self._transport.request("tools/list", {})
        if not isinstance(result, dict):
            raise MCPError("MCP server returned a malformed tools/list result")
        raw_tools = result.get("tools", [])
        if not isinstance(raw_tools, list):
            raise MCPError("MCP server returned a malformed 'tools' list")

        tools: list[MCPToolInfo] = []
        for entry in raw_tools:
            if not isinstance(entry, dict):
                logger.warning("mcp_tool_entry_malformed", entry=repr(entry)[:200])
                continue
            name = entry.get("name")
            if not isinstance(name, str) or not name:
                continue
            schema = entry.get("inputSchema")
            tools.append(
                MCPToolInfo(
                    name=name,
                    description=str(entry.get("description", "")),
                    input_schema=schema
                    if isinstance(schema, dict)
                    else {"type": "object", "properties": {}},
                )
            )
        if raw_tools and not tools:
            raise MCPError("MCP server returned no usable entries in tools/list")
        return tools

    async def call_tool(self, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        await self.initialize()
        result = await self._transport.request(
            "tools/call", {"name": name, "arguments": arguments}
        )
        # Same reasoning as list_tools: a non-object result would otherwise
        # escape as AttributeError from a third-party server's payload.
        if not isinstance(result, dict):
            raise MCPError("MCP server returned a malformed tools/call result")
        content_blocks = result.get("content", [])
        text_parts = [
            block.get("text", "")
            for block in content_blocks
            if isinstance(block, dict) and block.get("type") == "text"
        ]
        return {
            "ok": not result.get("isError", False),
            "content": "\n".join(text_parts) if text_parts else content_blocks,
        }

    async def close(self) -> None:
        await self._transport.close()
