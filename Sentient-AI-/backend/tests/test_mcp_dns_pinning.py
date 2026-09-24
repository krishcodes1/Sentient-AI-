"""Tests for DNS-rebinding protection on the MCP HTTP transport: a hostname whose
resolution is entirely or partly private is refused, that the socket the
transport actually connects to is pinned to a validated address, and that a
rebind on a later request is still caught.

Why it exists: SSRF-checking a URL and then handing httpx the hostname is not a
control, since httpcore re-resolves DNS inside `connect_tcp`; these tests pin
the fix at the only place a rebind would actually show up, the address the
socket opens to.

DNS-rebinding (TOCTOU) coverage for the MCP HTTP transport.

SSRF-checking a URL and then handing the *hostname* to httpx is not a
control: httpcore resolves the origin again inside ``connect_tcp``, so a
hostile authoritative server can answer the check with a public address
and the connection with 127.0.0.1. These tests drive the real
``HttpMCPTransport`` with a fake resolver and a recording socket layer,
and assert on the address the socket was actually opened to — the only
place the rebind would show up.

Nothing leaves the process: ``socket.getaddrinfo`` is faked and the
httpcore network backend is an in-memory mock.
"""

from __future__ import annotations

import socket
from typing import Any, Iterable, Optional

import httpcore
import pytest

import core.network_security as netsec
from services.mcp.client import HttpMCPTransport, MCPError

# Genuinely globally-routable. RFC 5737 documentation ranges (203.0.113.x)
# are NOT routable, and the address policy refuses them like any other
# non-global address — a stand-in for "public" has to actually be public.
PUBLIC_IP = "93.184.216.34"
OTHER_PUBLIC_IP = "93.184.216.35"
PRIVATE_IP = "127.0.0.1"
INTERNAL_IP = "169.254.169.254"  # cloud metadata service

HOST = "mcp.example.test"
URL = f"https://{HOST}/mcp"


# ---------------------------------------------------------------------------
# Harness
# ---------------------------------------------------------------------------


class FakeResolver:
    """``socket.getaddrinfo`` stand-in returning a scripted answer per call.

    ``answers`` is a list of address lists: the first lookup gets the
    first list, the second the second, and so on (the last one repeats).
    That is the rebinding attack expressed as a fixture.
    """

    def __init__(self, answers: list[list[str]]) -> None:
        self._answers = answers
        self.calls = 0

    def __call__(self, host: str, port: int, *args: Any, **kwargs: Any) -> list[Any]:
        index = min(self.calls, len(self._answers) - 1)
        self.calls += 1
        return [
            (
                socket.AF_INET6 if ":" in ip else socket.AF_INET,
                socket.SOCK_STREAM,
                6,
                "",
                (ip, port),
            )
            for ip in self._answers[index]
        ]


class RecordingBackend(httpcore.AsyncNetworkBackend):
    """In-memory socket layer that records every address dialled."""

    def __init__(self, response: bytes) -> None:
        self._inner = httpcore.AsyncMockBackend([response])
        self.dialled: list[tuple[str, int]] = []

    async def connect_tcp(
        self,
        host: str,
        port: int,
        timeout: Optional[float] = None,
        local_address: Optional[str] = None,
        socket_options: Optional[Iterable[Any]] = None,
    ) -> httpcore.AsyncNetworkStream:
        self.dialled.append((host, port))
        return await self._inner.connect_tcp(host, port, timeout=timeout)

    async def sleep(self, seconds: float) -> None:
        return None


def _http_response(body: bytes) -> bytes:
    return (
        b"HTTP/1.1 200 OK\r\n"
        b"Content-Type: application/json\r\n"
        b"Content-Length: " + str(len(body)).encode() + b"\r\n"
        b"Connection: close\r\n"
        b"\r\n" + body
    )


JSONRPC_OK = _http_response(b'{"jsonrpc":"2.0","id":1,"result":{"tools":[]}}')


@pytest.fixture
def resolver(monkeypatch):
    """Install a scripted resolver; returns the factory for the test."""

    def install(*answers: list[str]) -> FakeResolver:
        fake = FakeResolver(list(answers))
        monkeypatch.setattr(socket, "getaddrinfo", fake)
        return fake

    return install


# ---------------------------------------------------------------------------
# The address policy applied to a whole resolution
# ---------------------------------------------------------------------------


def test_private_resolution_is_refused(resolver):
    """A hostname that resolves to a loopback address is not reachable."""
    resolver([PRIVATE_IP])

    result = netsec.check_ssrf(URL)

    assert result.safe is False
    assert result.resolved_ips == ()
    # Generic reason: the check must not confirm *which* internal address
    # the name pointed at.
    assert PRIVATE_IP not in (result.reason or "")


def test_one_private_record_among_public_ones_refuses_the_whole_host(resolver):
    """Multi-record hostnames pass only if every record passes.

    Accepting the host because *a* record is public is the rebinding bug
    in miniature: the validator looks at the public address and the connection
    lands on 127.0.0.1, with no DNS trickery required at all.
    """
    resolver([PUBLIC_IP, PRIVATE_IP])

    assert netsec.check_ssrf(URL).safe is False

    # ... and the same in the other record order, so this cannot pass by
    # accident of iteration order.
    resolver([INTERNAL_IP, PUBLIC_IP])
    assert netsec.check_ssrf(URL).safe is False


def test_public_resolution_returns_every_validated_address(resolver):
    resolver([PUBLIC_IP, OTHER_PUBLIC_IP])

    result = netsec.check_ssrf(URL)

    assert result.safe is True
    assert result.resolved_ips == (PUBLIC_IP, OTHER_PUBLIC_IP)


# ---------------------------------------------------------------------------
# The pin: what the socket is actually opened to
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_legitimate_public_host_works_end_to_end(resolver):
    """A public MCP server still round-trips, dialled by validated IP."""
    resolver([PUBLIC_IP])
    backend = RecordingBackend(JSONRPC_OK)
    transport = HttpMCPTransport(URL, network_backend=backend)

    try:
        result = await transport.request("tools/list", {})
    finally:
        await transport.close()

    assert result == {"tools": []}
    assert backend.dialled == [(PUBLIC_IP, 443)]


@pytest.mark.asyncio
async def test_rebind_between_validation_and_connect_cannot_reach_private(resolver):
    """The TOCTOU itself: the resolver flips to loopback after the check.

    Pre-fix, httpcore performed its own lookup at connect time and got
    the attacker's second answer. The pin means the second answer is
    never asked for, so the socket goes to the address that passed.
    """
    fake = resolver([PUBLIC_IP], [PRIVATE_IP])
    backend = RecordingBackend(JSONRPC_OK)
    transport = HttpMCPTransport(URL, network_backend=backend)

    try:
        await transport.request("tools/list", {})
    finally:
        await transport.close()

    assert backend.dialled == [(PUBLIC_IP, 443)]
    # The hostname must never reach the socket layer — being handed a name
    # instead of an address is exactly what re-opens the window.
    assert all(host != HOST for host, _ in backend.dialled)
    # And the poisoned second answer was never even requested.
    assert fake.calls == 1


@pytest.mark.asyncio
async def test_rebind_on_the_next_request_is_caught_by_that_request(resolver):
    """Each request re-validates and re-pins; a later flip is refused.

    A pin that outlived its check would let a server pass once and then
    hold the clearance forever.
    """
    resolver([PUBLIC_IP], [INTERNAL_IP])
    backend = RecordingBackend(JSONRPC_OK)
    transport = HttpMCPTransport(URL, network_backend=backend)

    try:
        await transport.request("tools/list", {})
        with pytest.raises(MCPError, match="SSRF"):
            await transport.request("tools/list", {})
    finally:
        await transport.close()

    assert backend.dialled == [(PUBLIC_IP, 443)]


@pytest.mark.asyncio
async def test_private_host_never_reaches_the_socket_layer(resolver):
    resolver([PRIVATE_IP])
    backend = RecordingBackend(JSONRPC_OK)
    transport = HttpMCPTransport(URL, network_backend=backend)

    try:
        with pytest.raises(MCPError, match="SSRF"):
            await transport.request("tools/list", {})
    finally:
        await transport.close()

    assert backend.dialled == []


@pytest.mark.asyncio
async def test_unpinned_origin_is_refused_instead_of_resolved(resolver):
    """Fail-closed: no pin means no connection, not a fresh lookup.

    Guards the invariant the whole design rests on. If the pin table is
    ever bypassed (a code path that skips the request hook, a future
    redirect hop that is not re-checked), the socket layer must refuse
    rather than quietly fall back to DNS.
    """
    from core.http_pinning import PinnedResolutionBackend

    inner = RecordingBackend(JSONRPC_OK)
    pinned = PinnedResolutionBackend({}, inner)

    with pytest.raises(httpcore.ConnectError, match="No validated address"):
        await pinned.connect_tcp(HOST, 443)

    assert inner.dialled == []


@pytest.mark.asyncio
async def test_pinned_backend_falls_over_to_the_next_validated_address():
    """A dead record must not take down a host whose other record is fine.

    Every pinned address already passed the policy, so trying the next
    one cannot reach anywhere the first was not allowed to reach.
    """
    from core.http_pinning import PinnedResolutionBackend

    class HalfDeadBackend(RecordingBackend):
        async def connect_tcp(self, host, port, **kwargs):
            self.dialled.append((host, port))
            if host == PUBLIC_IP:
                raise httpcore.ConnectError("connection refused")
            return await self._inner.connect_tcp(host, port)

    inner = HalfDeadBackend(JSONRPC_OK)
    pins = {(HOST, 443): (PUBLIC_IP, OTHER_PUBLIC_IP)}
    pinned = PinnedResolutionBackend(pins, inner)

    await pinned.connect_tcp(HOST, 443)

    assert inner.dialled == [(PUBLIC_IP, 443), (OTHER_PUBLIC_IP, 443)]


@pytest.mark.asyncio
async def test_unix_socket_connections_are_refused():
    """No address to validate, and always local."""
    from core.http_pinning import PinnedResolutionBackend

    pinned = PinnedResolutionBackend({}, RecordingBackend(JSONRPC_OK))

    with pytest.raises(httpcore.ConnectError, match="Unix-socket"):
        await pinned.connect_unix_socket("/tmp/mcp.sock")
