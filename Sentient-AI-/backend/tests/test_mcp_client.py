"""Protocol-level MCP tests: the HTTP transport's JSON-RPC framing, the
client handshake, catalog caching/isolation, dispatcher name resolution,
and the activity registry.

Complements ``tests/test_mcp.py`` (route- and policy-level coverage) by
driving the real ``HttpMCPTransport`` over ``httpx.MockTransport`` — the
wire bytes are asserted, but nothing leaves the process.
"""

from __future__ import annotations

import json
import uuid as uuid_module
from typing import Any, Optional

import httpx
import pytest

from services.mcp.activity import MCPActivityRegistry, mcp_activity
from services.mcp.client import (
    MCP_PROTOCOL_VERSION,
    HttpMCPTransport,
    MCPClient,
    MCPError,
    MCPToolInfo,
)
from services.mcp.integration import (
    MCPConnectorLoader,
    MCPDispatcher,
    MCPToolCatalog,
    mcp_name_bindings,
    sanitized_tool_entries,
)

MOCK_URL = "https://mcp.example.test/mcp"


# ---------------------------------------------------------------------------
# Harness
# ---------------------------------------------------------------------------


@pytest.fixture
def offline_ssrf(monkeypatch):
    """Keep the transport's SSRF hook wired up, but DNS-free.

    The real ``check_ssrf`` resolves hostnames, which would make these
    tests depend on the network. The stand-in preserves the hook's
    contract (``*.test`` reachable, everything else refused) so the hook
    is still exercised on every outbound request.
    """
    import core.network_security as netsec

    def fake_check_ssrf(url: str):
        host = httpx.URL(url).host
        if host.endswith(".test"):
            return netsec.SSRFCheckResult(safe=True, resolved_ip="203.0.113.10")
        return netsec.SSRFCheckResult(safe=False, reason="blocked by test policy")

    monkeypatch.setattr(netsec, "check_ssrf", fake_check_ssrf)


class RecordingHandler:
    """``httpx.MockTransport`` handler that records every JSON-RPC payload."""

    def __init__(self, responder) -> None:
        self._responder = responder
        self.payloads: list[dict[str, Any]] = []
        self.requests: list[httpx.Request] = []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        payload = json.loads(request.content) if request.content else {}
        self.payloads.append(payload)
        return self._responder(payload, request)

    @property
    def methods(self) -> list[str]:
        return [p.get("method") for p in self.payloads]


def _mock_http_transport(
    handler: RecordingHandler,
    *,
    url: str = MOCK_URL,
    headers: Optional[dict[str, str]] = None,
    timeout_s: float = 30.0,
) -> HttpMCPTransport:
    """A real ``HttpMCPTransport`` whose socket layer is a MockTransport.

    The pre-seeded client keeps the production request hook (SSRF) and
    timeout so only the network I/O is faked.
    """
    transport = HttpMCPTransport(
        url, headers=headers or {"X-Key": "secret"}, timeout_s=timeout_s
    )
    transport._client = httpx.AsyncClient(
        transport=httpx.MockTransport(handler),
        timeout=httpx.Timeout(timeout_s),
        event_hooks={"request": [transport._check_ssrf]},
    )
    return transport


def _rpc_result(payload: dict[str, Any], result: Any) -> httpx.Response:
    return httpx.Response(
        200, json={"jsonrpc": "2.0", "id": payload.get("id"), "result": result}
    )


def _default_responder(tools=None, call_result=None):
    """Responder implementing a well-behaved server for the three methods."""
    tools = tools if tools is not None else [{"name": "search_notes"}]
    call_result = call_result or {
        "content": [{"type": "text", "text": "ok"}],
        "isError": False,
    }

    def responder(payload: dict[str, Any], request: httpx.Request) -> httpx.Response:
        method = payload.get("method")
        if "id" not in payload:  # notification
            return httpx.Response(202)
        if method == "initialize":
            return _rpc_result(
                payload, {"protocolVersion": MCP_PROTOCOL_VERSION, "capabilities": {}}
            )
        if method == "tools/list":
            return _rpc_result(payload, {"tools": tools})
        if method == "tools/call":
            return _rpc_result(payload, call_result)
        return httpx.Response(404)

    return responder


class ScriptedTransport:
    """In-process MCP transport with per-method scripted failures."""

    def __init__(
        self,
        tools: Optional[list[dict[str, Any]]] = None,
        call_result: Optional[dict[str, Any]] = None,
        fail_with: Optional[dict[str, Exception]] = None,
        fail_times: Optional[dict[str, int]] = None,
    ) -> None:
        self.tools = list(tools or [{"name": "search_notes"}])
        self.call_result = (
            call_result
            if call_result is not None
            else {"content": [{"type": "text", "text": "ok"}], "isError": False}
        )
        self.fail_with = dict(fail_with or {})
        # method -> remaining failures; absent means "fail forever"
        self.fail_times = dict(fail_times or {})
        self.requests: list[tuple[str, dict[str, Any]]] = []
        self.notifications: list[tuple[str, dict[str, Any]]] = []
        self.closed = False

    async def request(self, method: str, params: dict[str, Any]) -> Any:
        self.requests.append((method, params))
        if method in self.fail_with:
            remaining = self.fail_times.get(method)
            if remaining is None or remaining > 0:
                if remaining is not None:
                    self.fail_times[method] = remaining - 1
                raise self.fail_with[method]
        if method == "initialize":
            return {"protocolVersion": MCP_PROTOCOL_VERSION, "capabilities": {}}
        if method == "tools/list":
            return {"tools": self.tools}
        if method == "tools/call":
            return self.call_result
        raise MCPError(f"unexpected method {method}")

    async def notify(self, method: str, params: dict[str, Any]) -> None:
        self.notifications.append((method, params))

    async def close(self) -> None:
        self.closed = True

    @property
    def methods(self) -> list[str]:
        return [m for m, _ in self.requests]


class FakeClock:
    """Stand-in for ``time`` so TTL tests never sleep."""

    def __init__(self, start: float = 1_000.0) -> None:
        self._now = start

    def monotonic(self) -> float:
        return self._now

    def advance(self, seconds: float) -> None:
        self._now += seconds


@pytest.fixture
def clean_activity():
    """The activity registry is a process-wide singleton; isolate it."""
    mcp_activity.reset()
    yield mcp_activity
    mcp_activity.reset()


@pytest.fixture
def clean_bindings():
    """Discovery-time exposed->remote bindings are a process-wide
    singleton too (the catalog and the dispatcher are built separately)."""
    mcp_name_bindings.reset()
    yield mcp_name_bindings
    mcp_name_bindings.reset()


async def _make_mcp_connector(
    session_factory,
    user_id,
    display_name: str = "Notes Server",
    rate_limit_per_minute: int = 30,
) -> uuid_module.UUID:
    from core.security import encrypt_credentials
    from models.connector import AuthMethod, ConnectorConfig, ConnectorType

    credentials = {"url": MOCK_URL, "headers": {"X-Key": "k"}}
    async with session_factory() as session:
        row = ConnectorConfig(
            user_id=user_id,
            connector_type=ConnectorType.mcp,
            display_name=display_name,
            auth_method=AuthMethod.bearer_token,
            encrypted_credentials=encrypt_credentials(json.dumps(credentials)),
            granted_scopes=[],
            rate_limit_per_minute=rate_limit_per_minute,
        )
        session.add(row)
        await session.flush()
        await session.commit()
    return row.id


# ---------------------------------------------------------------------------
# HttpMCPTransport: JSON-RPC framing over the wire
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_transport_sends_jsonrpc_envelope_and_increments_ids(offline_ssrf):
    handler = RecordingHandler(_default_responder())
    transport = _mock_http_transport(handler)
    try:
        first = await transport.request("tools/list", {})
        await transport.notify("notifications/initialized", {})
        await transport.request("tools/call", {"name": "search_notes", "arguments": {}})
    finally:
        await transport.close()

    assert first == {"tools": [{"name": "search_notes"}]}
    # Requests are numbered monotonically; notifications consume no id.
    assert [p.get("id") for p in handler.payloads] == [1, None, 2]
    assert all(p["jsonrpc"] == "2.0" for p in handler.payloads)
    assert "id" not in handler.payloads[1]

    sent = handler.requests[0]
    assert sent.headers["content-type"] == "application/json"
    assert "text/event-stream" in sent.headers["accept"]
    assert sent.headers["x-key"] == "secret"  # caller headers ride every request


@pytest.mark.asyncio
async def test_transport_surfaces_jsonrpc_error_instead_of_silent_success(offline_ssrf):
    def responder(payload, request):
        return httpx.Response(
            200,
            json={
                "jsonrpc": "2.0",
                "id": payload.get("id"),
                "error": {"code": -32601, "message": "Method not found"},
            },
        )

    handler = RecordingHandler(responder)
    transport = _mock_http_transport(handler)
    try:
        with pytest.raises(MCPError) as excinfo:
            await transport.request("tools/list", {})
    finally:
        await transport.close()

    assert "-32601" in str(excinfo.value)
    assert "Method not found" in str(excinfo.value)


@pytest.mark.asyncio
async def test_transport_rejects_non_json_and_non_object_bodies(offline_ssrf):
    """A proxy error page or a bare JSON array must not pass for a result."""

    def html_responder(payload, request):
        return httpx.Response(
            200, text="<html>gateway</html>", headers={"content-type": "text/html"}
        )

    transport = _mock_http_transport(RecordingHandler(html_responder))
    try:
        with pytest.raises(MCPError, match="invalid JSON"):
            await transport.request("tools/list", {})
    finally:
        await transport.close()

    def array_responder(payload, request):
        return httpx.Response(200, json=[1, 2, 3])

    transport = _mock_http_transport(RecordingHandler(array_responder))
    try:
        with pytest.raises(MCPError, match="non-object"):
            await transport.request("tools/list", {})
    finally:
        await transport.close()


@pytest.mark.asyncio
async def test_transport_raises_on_http_error_status(offline_ssrf):
    def responder(payload, request):
        return httpx.Response(503, text="upstream down")

    transport = _mock_http_transport(RecordingHandler(responder))
    try:
        with pytest.raises(MCPError) as excinfo:
            await transport.request("tools/call", {"name": "x", "arguments": {}})
    finally:
        await transport.close()

    assert "503" in str(excinfo.value)
    assert "tools/call" in str(excinfo.value)


@pytest.mark.asyncio
async def test_transport_timeout_surfaces_as_mcp_error(offline_ssrf):
    def responder(payload, request):
        raise httpx.ReadTimeout("read timed out", request=request)

    transport = _mock_http_transport(RecordingHandler(responder), timeout_s=0.25)
    try:
        with pytest.raises(MCPError, match="transport error"):
            await transport.request("tools/list", {})
    finally:
        await transport.close()

    # The configured budget is what the underlying client actually uses.
    plain = HttpMCPTransport(MOCK_URL, timeout_s=2.5)
    try:
        assert plain._get_client().timeout == httpx.Timeout(2.5)
    finally:
        await plain.close()


@pytest.mark.asyncio
async def test_transport_parses_single_response_sse_body(offline_ssrf):
    """Servers may answer a one-shot POST with ``text/event-stream``."""

    def responder(payload, request):
        message = {
            "jsonrpc": "2.0",
            "id": payload.get("id"),
            "result": {"tools": [{"name": "search_notes"}]},
        }
        body = (
            "event: message\n"
            f"data: {json.dumps(message)}\n"
            "\n"
            'data: {"jsonrpc": "2.0", "id": 999, "result": {"tools": []}}\n'
        )
        return httpx.Response(
            200, text=body, headers={"content-type": "text/event-stream"}
        )

    transport = _mock_http_transport(RecordingHandler(responder))
    try:
        result = await transport.request("tools/list", {})
    finally:
        await transport.close()

    # Matched on request id, not on stream position.
    assert result == {"tools": [{"name": "search_notes"}]}


@pytest.mark.asyncio
async def test_transport_replays_session_id_header(offline_ssrf):
    seen: list[Optional[str]] = []
    inner = _default_responder()

    def responder(payload, request):
        seen.append(request.headers.get("mcp-session-id"))
        response = inner(payload, request)
        response.headers["Mcp-Session-Id"] = "sess-abc"
        return response

    handler = RecordingHandler(responder)
    transport = _mock_http_transport(handler)
    try:
        await transport.request("initialize", {})
        await transport.notify("notifications/initialized", {})
        await transport.request("tools/list", {})
    finally:
        await transport.close()

    # First call has no session yet; every later call carries the one the
    # server assigned — including notifications.
    assert seen == [None, "sess-abc", "sess-abc"]


@pytest.mark.asyncio
async def test_transport_ssrf_hook_runs_before_the_wire(offline_ssrf):
    """The hook must fire even when a transport would happily answer."""
    handler = RecordingHandler(_default_responder())
    transport = _mock_http_transport(handler, url="http://10.0.0.5/mcp")
    try:
        with pytest.raises(MCPError, match="SSRF"):
            await transport.request("tools/list", {})
    finally:
        await transport.close()

    assert handler.payloads == []  # nothing reached the transport


# ---------------------------------------------------------------------------
# MCPClient: handshake ordering and result parsing
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_client_handshake_order_over_http(offline_ssrf):
    handler = RecordingHandler(_default_responder())
    client = MCPClient(_mock_http_transport(handler))
    try:
        tools = await client.list_tools()
        await client.call_tool("search_notes", {"q": "exam"})
    finally:
        await client.close()

    assert [t.name for t in tools] == ["search_notes"]
    # initialize -> notifications/initialized -> tools/list -> tools/call,
    # and the handshake is not repeated for the second operation.
    assert handler.methods == [
        "initialize",
        "notifications/initialized",
        "tools/list",
        "tools/call",
    ]
    assert handler.payloads[0]["params"]["protocolVersion"] == MCP_PROTOCOL_VERSION
    assert handler.payloads[0]["params"]["clientInfo"]["name"] == "sentientai"


@pytest.mark.asyncio
async def test_client_retries_handshake_after_a_failed_initialize():
    """A failed initialize must not leave the client wrongly 'initialized'."""
    transport = ScriptedTransport(
        fail_with={"initialize": MCPError("MCP error -32600: bad request")},
        fail_times={"initialize": 1},
    )
    client = MCPClient(transport)

    with pytest.raises(MCPError, match="-32600"):
        await client.list_tools()
    # tools/list is never attempted against an uninitialized session, and
    # the "initialized" notification is not sent for a failed handshake.
    assert transport.methods == ["initialize"]
    assert transport.notifications == []

    tools = await client.list_tools()
    assert [t.name for t in tools] == ["search_notes"]
    assert transport.methods == ["initialize", "initialize", "tools/list"]
    assert transport.notifications == [("notifications/initialized", {})]


@pytest.mark.asyncio
async def test_client_call_tool_reports_tool_level_errors():
    transport = ScriptedTransport(
        call_result={
            "content": [{"type": "text", "text": "no such note"}],
            "isError": True,
        }
    )
    client = MCPClient(transport)
    result = await client.call_tool("search_notes", {"q": "x"})

    # ``isError`` is a tool-level failure, not a transport failure: it must
    # come back as ok=False rather than raising.
    assert result == {"ok": False, "content": "no such note"}
    assert transport.requests[-1] == (
        "tools/call",
        {"name": "search_notes", "arguments": {"q": "x"}},
    )


@pytest.mark.asyncio
async def test_client_call_tool_passes_through_non_text_blocks():
    blocks = [{"type": "image", "data": "b64", "mimeType": "image/png"}]
    client = MCPClient(ScriptedTransport(call_result={"content": blocks}))
    result = await client.call_tool("render", {})

    assert result["ok"] is True
    assert result["content"] == blocks  # no text parts -> raw blocks survive


@pytest.mark.asyncio
async def test_client_list_tools_defaults_schema_and_rejects_junk():
    transport = ScriptedTransport(
        tools=[
            {"name": "no_schema", "description": "d"},
            {"name": "null_schema", "inputSchema": None},
            {"name": "", "description": "nameless"},
        ]
    )
    tools = await MCPClient(transport).list_tools()

    assert [t.name for t in tools] == ["no_schema", "null_schema"]
    empty_object = {"type": "object", "properties": {}}
    assert all(t.input_schema == empty_object for t in tools)

    # A tools/list payload that is not a list of objects must fail loudly
    # rather than yielding a plausible-looking empty catalog — and it must
    # fail as MCPError, the error type every caller handles. Leaking an
    # AttributeError from a third-party payload surfaced verbatim in
    # POST /connectors/{id}/test.
    with pytest.raises(MCPError):
        await MCPClient(ScriptedTransport(tools=["just a string"])).list_tools()


@pytest.mark.asyncio
async def test_client_list_tools_rejects_malformed_containers():
    """A non-dict result (e.g. the server answers with a JSON array) is a
    protocol violation, not an empty catalog."""

    class ArrayResultTransport(ScriptedTransport):
        async def request(self, method, params):
            await super().request(method, params)
            return [] if method == "tools/list" else {"capabilities": {}}

    with pytest.raises(MCPError, match="malformed"):
        await MCPClient(ArrayResultTransport()).list_tools()

    class StringToolsTransport(ScriptedTransport):
        async def request(self, method, params):
            result = await super().request(method, params)
            return {"tools": "search_notes"} if method == "tools/list" else result

    with pytest.raises(MCPError, match="malformed"):
        await MCPClient(StringToolsTransport()).list_tools()

    # One junk entry among usable ones is dropped, not fatal: a single bad
    # tool must not cost the user the rest of the server.
    tools = await MCPClient(
        ScriptedTransport(tools=["junk", {"name": "search_notes"}])
    ).list_tools()
    assert [t.name for t in tools] == ["search_notes"]


@pytest.mark.asyncio
async def test_client_rejects_response_with_neither_result_nor_error():
    """A JSON-RPC response carrying neither ``result`` nor a non-empty
    ``error`` violates the spec. It must not read as a successful empty
    call: the agent would take an empty catalog / empty tool answer from a
    broken server as the truth."""

    class ResultlessTransport(ScriptedTransport):
        async def request(self, method, params):
            await super().request(method, params)
            return None  # what the transport yields for {"jsonrpc","id"} only

    client = MCPClient(ResultlessTransport())
    with pytest.raises(MCPError, match="malformed"):
        await client.list_tools()
    with pytest.raises(MCPError, match="malformed"):
        await client.call_tool("anything", {})


@pytest.mark.asyncio
async def test_transport_rejects_resultless_and_empty_error_responses(offline_ssrf):
    """The same protocol violation, asserted at the wire layer where the
    ``result``/``error`` members are actually read."""

    def resultless(payload, request):
        return httpx.Response(200, json={"jsonrpc": "2.0", "id": payload.get("id")})

    transport = _mock_http_transport(RecordingHandler(resultless))
    try:
        with pytest.raises(MCPError, match="neither 'result' nor 'error'"):
            await transport.request("tools/list", {})
    finally:
        await transport.close()

    def empty_error(payload, request):
        return httpx.Response(
            200, json={"jsonrpc": "2.0", "id": payload.get("id"), "error": {}}
        )

    transport = _mock_http_transport(RecordingHandler(empty_error))
    try:
        # A falsy error object is still an error, not a missing one.
        with pytest.raises(MCPError, match="MCP error"):
            await transport.request("tools/call", {"name": "x", "arguments": {}})
    finally:
        await transport.close()

    # A null result IS a result: only a *missing* member is a violation.
    def null_result(payload, request):
        return httpx.Response(
            200, json={"jsonrpc": "2.0", "id": payload.get("id"), "result": None}
        )

    transport = _mock_http_transport(RecordingHandler(null_result))
    try:
        assert await transport.request("tools/list", {}) is None
    finally:
        await transport.close()


@pytest.mark.asyncio
async def test_transport_raises_when_a_notification_is_rejected(offline_ssrf):
    """A discarded notification response hid failed handshakes: the client
    marked itself initialized and the real failure resurfaced later as a
    confusing tools/list error."""

    def rejecting(payload, request):
        if "id" not in payload:
            return httpx.Response(400, text="session required")
        return _default_responder()(payload, request)

    handler = RecordingHandler(rejecting)
    client = MCPClient(_mock_http_transport(handler))
    try:
        with pytest.raises(MCPError, match="notifications/initialized"):
            await client.list_tools()
    finally:
        await client.close()

    # The handshake never completed, so tools/list is never attempted.
    assert handler.methods == ["initialize", "notifications/initialized"]

    def error_body(payload, request):
        if "id" not in payload:
            return httpx.Response(
                200, json={"jsonrpc": "2.0", "error": {"code": -32002, "message": "no session"}}
            )
        return _default_responder()(payload, request)

    handler = RecordingHandler(error_body)
    client = MCPClient(_mock_http_transport(handler))
    try:
        # A 200 carrying a JSON-RPC error is a refusal too.
        with pytest.raises(MCPError, match="-32002"):
            await client.list_tools()
    finally:
        await client.close()


# ---------------------------------------------------------------------------
# MCPToolCatalog: discovery cache and per-server isolation
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_catalog_caches_discovery_within_ttl(session_factory, monkeypatch):
    from tests.conftest import make_user

    user, _ = await make_user(session_factory)
    await _make_mcp_connector(session_factory, user.id)

    clock = FakeClock()
    monkeypatch.setattr("services.mcp.integration.time", clock)

    transport = ScriptedTransport()
    catalog = MCPToolCatalog(
        MCPConnectorLoader(session_factory),
        client_factory=lambda ref: MCPClient(transport),
        ttl_seconds=60.0,
    )

    assert len(await catalog.tools_for_user(str(user.id))) == 1
    clock.advance(59.0)
    assert len(await catalog.tools_for_user(str(user.id))) == 1

    # One chat turn must not re-hit the server for every discovery.
    assert transport.methods.count("tools/list") == 1


@pytest.mark.asyncio
async def test_catalog_rediscovers_after_ttl_expiry(session_factory, monkeypatch):
    from tests.conftest import make_user

    user, _ = await make_user(session_factory)
    await _make_mcp_connector(session_factory, user.id)

    clock = FakeClock()
    monkeypatch.setattr("services.mcp.integration.time", clock)

    transport = ScriptedTransport()
    catalog = MCPToolCatalog(
        MCPConnectorLoader(session_factory),
        client_factory=lambda ref: MCPClient(transport),
        ttl_seconds=60.0,
    )

    await catalog.tools_for_user(str(user.id))
    clock.advance(60.5)
    transport.tools = [{"name": "search_notes"}, {"name": "list_notebooks"}]
    tools = await catalog.tools_for_user(str(user.id))

    assert transport.methods.count("tools/list") == 2
    assert [t.name for t in tools] == [
        "mcp.notes_server.search_notes",
        "mcp.notes_server.list_notebooks",
    ]


@pytest.mark.asyncio
async def test_catalog_isolates_a_failing_server(session_factory, clean_activity):
    """One dead server must not cost the user their other servers' tools."""
    from tests.conftest import make_user

    user, _ = await make_user(session_factory)
    good_id = await _make_mcp_connector(session_factory, user.id, "Notes Server")
    dead_id = await _make_mcp_connector(session_factory, user.id, "Dead Server")

    healthy = ScriptedTransport(tools=[{"name": "search_notes"}])
    dead = ScriptedTransport(fail_with={"initialize": MCPError("connection refused")})

    def factory(ref):
        return MCPClient(healthy if ref.label == "notes_server" else dead)

    catalog = MCPToolCatalog(MCPConnectorLoader(session_factory), client_factory=factory)
    tools = await catalog.tools_for_user(str(user.id))

    assert [t.name for t in tools] == ["mcp.notes_server.search_notes"]
    assert clean_activity.get(good_id).last_success is not None
    assert "connection refused" in clean_activity.get(dead_id).last_error_message
    assert dead.closed is True  # the failed client is still cleaned up


@pytest.mark.asyncio
async def test_catalog_does_not_cache_failed_discovery(session_factory, monkeypatch):
    from tests.conftest import make_user

    user, _ = await make_user(session_factory)
    await _make_mcp_connector(session_factory, user.id)

    clock = FakeClock()
    monkeypatch.setattr("services.mcp.integration.time", clock)

    transport = ScriptedTransport(
        fail_with={"tools/list": MCPError("temporary outage")},
        fail_times={"tools/list": 1},
    )
    catalog = MCPToolCatalog(
        MCPConnectorLoader(session_factory),
        client_factory=lambda ref: MCPClient(transport),
    )

    assert await catalog.tools_for_user(str(user.id)) == []
    # No clock movement: a transient failure must not be cached as "this
    # server has no tools" for the rest of the TTL window.
    assert len(await catalog.tools_for_user(str(user.id))) == 1


@pytest.mark.asyncio
async def test_catalog_normalizes_and_dedupes_colliding_tool_names(session_factory):
    from tests.conftest import make_user

    user, _ = await make_user(session_factory)
    await _make_mcp_connector(session_factory, user.id)

    transport = ScriptedTransport(
        tools=[
            {"name": "search notes"},
            {"name": "search/notes"},  # normalizes onto the same name
            {"name": "???"},  # nothing survives normalization -> dropped
        ]
    )
    catalog = MCPToolCatalog(
        MCPConnectorLoader(session_factory),
        client_factory=lambda ref: MCPClient(transport),
    )
    names = [t.name for t in await catalog.tools_for_user(str(user.id))]

    assert names == [
        "mcp.notes_server.search_notes",
        "mcp.notes_server.search_notes_2",
    ]


def test_long_server_label_shrinks_the_tool_name_budget():
    """The exposed component shrinks so ``mcp.<label>.<tool>`` stays inside
    the provider's 128-char tool-name limit."""
    label = "l" * 100
    entries = sanitized_tool_entries(label, [MCPToolInfo(name="t" * 90)])

    exposed, info = entries[0]
    assert len(f"mcp.{label}.{exposed}") <= 128
    assert info.name == "t" * 90  # still resolves to the real remote name

    # No budget left at all -> the tool is rejected at discovery, never
    # exposed under a truncated (ambiguous) name.
    assert sanitized_tool_entries("x" * 130, [MCPToolInfo(name="tool")]) == []


# ---------------------------------------------------------------------------
# MCPDispatcher: resolution, result shape, error propagation
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_dispatcher_propagates_server_error(session_factory, clean_activity):
    from tests.conftest import make_user

    user, _ = await make_user(session_factory)
    connector_id = await _make_mcp_connector(session_factory, user.id)

    transport = ScriptedTransport(
        fail_with={"tools/call": MCPError("MCP error -32000: tool exploded")}
    )
    dispatcher = MCPDispatcher(
        MCPConnectorLoader(session_factory),
        client_factory=lambda ref: MCPClient(transport),
    )
    result = await dispatcher.execute(
        "mcp.notes_server.search_notes", {"q": "x"}, str(user.id)
    )

    assert result["ok"] is False
    assert "tool exploded" in result["error"]
    assert "tool exploded" in clean_activity.get(connector_id).last_error_message
    assert clean_activity.get(connector_id).last_success is None
    assert transport.closed is True


@pytest.mark.asyncio
async def test_dispatcher_surfaces_tool_level_is_error(session_factory):
    from tests.conftest import make_user

    user, _ = await make_user(session_factory)
    await _make_mcp_connector(session_factory, user.id)

    transport = ScriptedTransport(
        tools=[{"name": "Search Notes!"}],
        call_result={
            "content": [{"type": "text", "text": "note not found"}],
            "isError": True,
        },
    )
    dispatcher = MCPDispatcher(
        MCPConnectorLoader(session_factory),
        client_factory=lambda ref: MCPClient(transport),
    )
    result = await dispatcher.execute(
        "mcp.notes_server.Search_Notes", {"q": "x"}, str(user.id)
    )

    assert result == {
        "ok": False,
        "connector": "mcp:notes_server",
        # NOTE: "action" is the *exposed* name, not the remote name that
        # was actually called on the wire ("Search Notes!").
        "action": "Search_Notes",
        "result": "note not found",
        "sanitized": False,
    }


@pytest.mark.asyncio
async def test_dispatcher_rejects_malformed_tool_names(session_factory):
    from tests.conftest import make_user

    user, _ = await make_user(session_factory)
    await _make_mcp_connector(session_factory, user.id)

    transport = ScriptedTransport()
    dispatcher = MCPDispatcher(
        MCPConnectorLoader(session_factory),
        client_factory=lambda ref: MCPClient(transport),
    )

    for bad_name in ("mcp.notes_server", "mcp..search", "search_notes"):
        result = await dispatcher.execute(bad_name, {}, str(user.id))
        assert result["ok"] is False
        assert "Malformed" in result["error"]

    assert transport.requests == []  # never reaches a server


@pytest.mark.asyncio
async def test_dispatcher_contains_unexpected_client_exception(
    session_factory, clean_activity
):
    """A non-MCPError bug in the client path becomes a tool error, not a
    500 that kills the chat turn."""
    from tests.conftest import make_user

    user, _ = await make_user(session_factory)
    connector_id = await _make_mcp_connector(session_factory, user.id)

    transport = ScriptedTransport(fail_with={"tools/list": ValueError("kaboom")})
    dispatcher = MCPDispatcher(
        MCPConnectorLoader(session_factory),
        client_factory=lambda ref: MCPClient(transport),
    )
    result = await dispatcher.execute(
        "mcp.notes_server.search_notes", {}, str(user.id)
    )

    assert result["ok"] is False
    assert "kaboom" in result["error"]
    assert clean_activity.get(connector_id).last_error_message is not None
    assert transport.closed is True


def test_exposed_names_do_not_depend_on_advertisement_order():
    """The exposed -> remote mapping is a function of the *set* of remote
    names. Deriving collision suffixes from tools/list order let a server
    swap which remote tool an approved exposed name meant just by
    reordering its catalog."""
    remote_names = ["my tool", "my_tool", "my/tool", "ok", "My Tool"]
    infos = [MCPToolInfo(name=n) for n in remote_names]

    baseline = {
        exposed: info.name for exposed, info in sanitized_tool_entries("srv", infos)
    }
    assert len(baseline) == len(remote_names)  # every tool still reachable

    for rotation in range(1, len(remote_names)):
        shuffled = infos[rotation:] + infos[:rotation]
        mapping = {
            exposed: info.name
            for exposed, info in sanitized_tool_entries("srv", shuffled)
        }
        assert mapping == baseline

    # Presentation order still follows the server (only naming is canonical).
    assert [
        info.name for _, info in sanitized_tool_entries("srv", infos[::-1])
    ] == remote_names[::-1]


@pytest.mark.asyncio
async def test_dispatcher_name_resolution_survives_catalog_reordering(
    session_factory, clean_bindings
):
    """An approved exposed name must execute the remote tool the user saw,
    even if the server reorders its catalog between discovery and
    execution (a confused-deputy / approval-bypass path)."""
    from tests.conftest import make_user

    user, _ = await make_user(session_factory)
    await _make_mcp_connector(session_factory, user.id)

    transport = ScriptedTransport(tools=[{"name": "my tool"}, {"name": "my_tool"}])
    loader = MCPConnectorLoader(session_factory)
    factory = lambda ref: MCPClient(transport)  # noqa: E731

    catalog = MCPToolCatalog(loader, client_factory=factory)
    names = [t.name for t in await catalog.tools_for_user(str(user.id))]
    assert names == ["mcp.notes_server.my_tool", "mcp.notes_server.my_tool_2"]

    # Same server, catalog reordered on the next tools/list.
    transport.tools.reverse()
    dispatcher = MCPDispatcher(loader, client_factory=factory)
    result = await dispatcher.execute("mcp.notes_server.my_tool", {}, str(user.id))

    assert result["ok"] is True
    method, params = transport.requests[-1]
    assert method == "tools/call"
    # At discovery "my_tool" meant the remote tool "my tool"; it still does.
    assert params["name"] == "my tool"


@pytest.mark.asyncio
async def test_dispatcher_will_not_rebind_an_approved_name_to_a_new_tool(
    session_factory, clean_bindings
):
    """Order independence is not enough: a server can also *add* a tool
    that normalizes onto an already-approved exposed name. The binding
    captured at discovery wins."""
    from tests.conftest import make_user

    user, _ = await make_user(session_factory)
    await _make_mcp_connector(session_factory, user.id)

    transport = ScriptedTransport(tools=[{"name": "my_tool"}])
    loader = MCPConnectorLoader(session_factory)
    factory = lambda ref: MCPClient(transport)  # noqa: E731

    catalog = MCPToolCatalog(loader, client_factory=factory)
    assert [t.name for t in await catalog.tools_for_user(str(user.id))] == [
        "mcp.notes_server.my_tool"
    ]

    # The server now also advertises "my tool", which normalizes onto the
    # approved exposed name.
    transport.tools = [{"name": "my tool"}, {"name": "my_tool"}]
    dispatcher = MCPDispatcher(loader, client_factory=factory)
    result = await dispatcher.execute("mcp.notes_server.my_tool", {}, str(user.id))

    assert result["ok"] is True
    assert transport.requests[-1][1]["name"] == "my_tool"


@pytest.mark.asyncio
async def test_binding_survives_a_rediscovery_between_offer_and_approval(
    session_factory, clean_bindings
):
    """The production path re-runs discovery constantly.

    tools_for_user() is called on every chat send behind a 60s cache, so a
    turn that crosses the TTL between the agent proposing a tool call and
    the user approving it triggers another discovery. If recording replaced
    the binding map, that re-discovery would silently hand the approved
    exposed name to the tool the attacker just added — which is exactly the
    hole the binding exists to close.
    """
    from tests.conftest import make_user

    user, _ = await make_user(session_factory)
    await _make_mcp_connector(session_factory, user.id)

    transport = ScriptedTransport(tools=[{"name": "my_tool"}])
    loader = MCPConnectorLoader(session_factory)
    factory = lambda ref: MCPClient(transport)  # noqa: E731

    catalog = MCPToolCatalog(loader, client_factory=factory)
    assert [t.name for t in await catalog.tools_for_user(str(user.id))] == [
        "mcp.notes_server.my_tool"
    ]

    # Attacker adds the colliding tool, then a re-discovery happens before
    # the user decides (cache expiry — force it rather than sleeping).
    transport.tools = [{"name": "my tool"}, {"name": "my_tool"}]
    catalog._cache.clear()
    await catalog.tools_for_user(str(user.id))

    dispatcher = MCPDispatcher(loader, client_factory=factory)
    result = await dispatcher.execute("mcp.notes_server.my_tool", {}, str(user.id))

    assert result["ok"] is True
    assert transport.requests[-1][1]["name"] == "my_tool", (
        "a re-discovery rebound an already-approved exposed name to a "
        "different remote tool"
    )


@pytest.mark.asyncio
async def test_dispatcher_refuses_when_the_approved_tool_disappears(
    session_factory, clean_bindings, clean_activity
):
    """If the remote tool behind an approved name is gone, fail loudly —
    re-deriving would hand the approval to whatever now owns the name."""
    from tests.conftest import make_user

    user, _ = await make_user(session_factory)
    connector_id = await _make_mcp_connector(session_factory, user.id)

    transport = ScriptedTransport(tools=[{"name": "my tool"}])
    loader = MCPConnectorLoader(session_factory)
    factory = lambda ref: MCPClient(transport)  # noqa: E731

    catalog = MCPToolCatalog(loader, client_factory=factory)
    await catalog.tools_for_user(str(user.id))

    transport.tools = [{"name": "my_tool"}]  # the approved tool is gone
    dispatcher = MCPDispatcher(loader, client_factory=factory)
    result = await dispatcher.execute("mcp.notes_server.my_tool", {}, str(user.id))

    assert result["ok"] is False
    assert "no longer advertises" in result["error"]
    assert transport.methods.count("tools/call") == 0
    assert clean_activity.get(connector_id).last_error_message is not None


@pytest.mark.asyncio
async def test_dispatcher_records_tool_level_failure_as_unhealthy(
    session_factory, clean_activity
):
    """``isError`` results were recorded as successes, so /connectors/health
    showed a fresh last_success for a server whose every call fails."""
    from tests.conftest import make_user

    user, _ = await make_user(session_factory)
    connector_id = await _make_mcp_connector(session_factory, user.id)

    transport = ScriptedTransport(
        call_result={
            "content": [{"type": "text", "text": "upstream quota exceeded"}],
            "isError": True,
        }
    )
    dispatcher = MCPDispatcher(
        MCPConnectorLoader(session_factory),
        client_factory=lambda ref: MCPClient(transport),
    )
    result = await dispatcher.execute(
        "mcp.notes_server.search_notes", {}, str(user.id)
    )

    assert result["ok"] is False
    entry = clean_activity.get(connector_id)
    assert entry.last_success is None
    assert "upstream quota exceeded" in entry.last_error_message


# ---------------------------------------------------------------------------
# Activity registry
# ---------------------------------------------------------------------------


def test_activity_tracks_success_and_error_independently():
    registry = MCPActivityRegistry()
    connector_id = uuid_module.uuid4()

    assert registry.get(connector_id) is None  # never used -> no activity

    registry.record_success(connector_id)
    first_success = registry.get(connector_id).last_success
    assert first_success is not None
    assert registry.get(connector_id).last_error is None

    registry.record_error(connector_id, "boom")
    entry = registry.get(connector_id)
    # An error never erases the last known good call (and vice versa), so
    # the health endpoint can show both.
    assert entry.last_success == first_success
    assert entry.last_error is not None
    assert entry.last_error_message == "boom"

    registry.record_success(connector_id)
    assert registry.get(connector_id).last_error_message == "boom"
    assert registry.get(connector_id).last_success >= first_success


def test_activity_truncates_error_messages_and_resets():
    registry = MCPActivityRegistry()
    connector_id = uuid_module.uuid4()

    registry.record_error(connector_id, "x" * 5_000)
    assert len(registry.get(connector_id).last_error_message) == 500

    registry.reset()
    assert registry.get(connector_id) is None
