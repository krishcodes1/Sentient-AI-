"""The forward proxy Crawler's Chrome goes through: a host is resolved once
and judged by the guard's blocked ranges, and the connection is made to
the judged address, whether Chrome asks for a tunnel or sends a plain-http
request. Why: Chrome loads a walled page itself (guard ``proxied``), and a
redirect it follows unseen must still never reach a private address.
"""

from __future__ import annotations

import asyncio

import pytest

from services.tools.browser.egress_proxy import EgressProxy
from services.tools.browser.guard import LOOPBACK_TOGGLE, Guard


async def _echo_server(seen: list[bytes]) -> asyncio.base_events.Server:
    async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        data = await reader.read(65536)
        seen.append(data)
        writer.write(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
        await writer.drain()
        writer.close()

    return await asyncio.start_server(handle, "127.0.0.1", 0)


async def _ask(proxy: EgressProxy, head: bytes, then: bytes = b"") -> bytes:
    port = int(proxy.url.rsplit(":", 1)[1])
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    writer.write(head)
    await writer.drain()
    try:
        answer = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), 5)
    except asyncio.IncompleteReadError as closed:
        writer.close()
        return closed.partial  # refused: closed with no answer
    if then and answer.startswith(b"HTTP/1.1 200 Connection established"):
        writer.write(then)
        await writer.drain()
    answer += await asyncio.wait_for(reader.read(65536), 5)
    writer.close()
    return answer


@pytest.mark.asyncio
@pytest.mark.parametrize("answer", [["10.1.2.3"], ["93.184.216.34", "192.168.1.5"], ["169.254.169.254"], []])
async def test_a_host_that_resolves_to_a_private_address_is_closed_with_no_answer(monkeypatch, answer):
    monkeypatch.delenv(LOOPBACK_TOGGLE, raising=False)
    proxy = await EgressProxy(Guard(resolver=lambda _host: answer)).start()
    try:
        assert (await _ask(proxy, b"CONNECT router.example:443 HTTP/1.1\r\nHost: router.example:443\r\n\r\n")
                ) == b""
        assert (await _ask(proxy, b"GET http://router.example/admin HTTP/1.1\r\nHost: router.example\r\n\r\n")
                ) == b""
    finally:
        await proxy.close()


@pytest.mark.asyncio
async def test_loopback_and_private_literals_are_refused_without_the_test_toggle(monkeypatch):
    monkeypatch.delenv(LOOPBACK_TOGGLE, raising=False)
    proxy = await EgressProxy(Guard(resolver=lambda _host: ["127.0.0.1"])).start()
    try:
        for authority in ("127.0.0.1:8000", "[::1]:443", "10.0.0.1:80", "localhost:3000"):
            head = f"CONNECT {authority} HTTP/1.1\r\n\r\n".encode()
            assert (await _ask(proxy, head)) == b"", authority
        assert await _ask(proxy, b"GET ftp://x.example/ HTTP/1.1\r\n\r\n") == b""
    finally:
        await proxy.close()


@pytest.mark.asyncio
async def test_an_allowed_host_is_tunnelled_and_a_plain_http_request_goes_on_in_origin_form(monkeypatch):
    monkeypatch.setenv(LOOPBACK_TOGGLE, "1")
    seen: list[bytes] = []
    server = await _echo_server(seen)
    port = server.sockets[0].getsockname()[1]
    proxy = await EgressProxy(Guard()).start()
    try:
        tunnel = await _ask(proxy, f"CONNECT 127.0.0.1:{port} HTTP/1.1\r\n\r\n".encode(), b"hello")
        assert tunnel.startswith(b"HTTP/1.1 200 Connection established") and tunnel.endswith(b"ok")
        assert seen[-1] == b"hello"
        plain = await _ask(proxy, (
            f"GET http://127.0.0.1:{port}/a?b=1 HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n"
            "Proxy-Connection: keep-alive\r\nAccept: */*\r\n\r\n"
        ).encode())
        assert plain.endswith(b"ok")
        sent = seen[-1]
        assert sent.startswith(b"GET /a?b=1 HTTP/1.1\r\n") and b"Accept: */*" in sent
        assert b"Proxy-Connection" not in sent and b"Connection: close" in sent
    finally:
        await proxy.close()
        server.close()
