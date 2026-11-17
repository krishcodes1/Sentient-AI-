"""The forward proxy Crawler's Chrome is launched with: every connection it
makes (a CONNECT tunnel for https, an absolute-URL request for http) is to
a host resolved once here, every address judged by the egress guard's
blocked ranges (``Guard.checked_addresses``: private, loopback, link-local,
CGNAT...), and connected to the address that was judged, never resolved
again. Chrome's own TLS goes through the tunnel untouched.

Why: the guard fetches every top-level page itself so that each redirect
hop is judged (services/tools/browser/guard.py), and that fetch is not
Chrome on the wire. Sites whose bot manager walls a non-Chrome client
(AMC's Cloudflare answered 403, Amazon's search 503, while a plain Chrome
got 200) refused Crawler on its first page. For such a wall the guard lets
Chrome load the read-tier page itself (``EgressState.proxied``); a
redirect Chrome then follows unseen still cannot reach a private or local
address, since every connection comes through here. Path rules on those
hops (order steps, site rules, the link lookup) are not judged, so this
is done only for a short list of sites (guard ``_CHROME_LOADS_WALLS``):
see SECURITY.md.

Connects to: services/tools/browser/session.py (``playwright_launcher``
starts one per browser and stops it with the context).
"""

from __future__ import annotations

import asyncio
import ipaddress
from concurrent.futures import ThreadPoolExecutor
from typing import Optional
from urllib.parse import urlsplit

import structlog

from services.tools.browser.guard import _DEFAULT, Guard

logger = structlog.get_logger(__name__)

_HEAD_LIMIT = 64 * 1024
_HEAD_TIMEOUT_S = 15.0
_CONNECT_TIMEOUT_S = 10.0
_RESOLVE_TIMEOUT_S = 5.0
# The proxy's own lookups: a page that asks for many hosts whose name
# servers never answer must not hold up the app's shared worker threads.
_RESOLVERS = ThreadPoolExecutor(max_workers=8, thread_name_prefix="browser-proxy-dns")
_DROPPED_HEADERS = (b"proxy-connection", b"proxy-authorization", b"connection", b"keep-alive")


def _host_port(authority: str, default: int) -> Optional[tuple[str, int]]:
    """``host:port`` (an IPv6 literal in brackets) as (host, port), or None."""
    try:
        parts = urlsplit(f"//{authority}")
        host, port = parts.hostname, parts.port or default
    except ValueError:
        return None
    return (host, port) if host else None


class EgressProxy:
    """One proxy server on 127.0.0.1, judging with *guard*."""

    def __init__(self, guard: Guard = _DEFAULT) -> None:
        self._guard = guard
        self._server: Optional[asyncio.base_events.Server] = None
        self._tasks: set[asyncio.Task[None]] = set()

    @property
    def url(self) -> str:
        assert self._server is not None, "start() first"
        return f"http://127.0.0.1:{self._server.sockets[0].getsockname()[1]}"

    async def start(self) -> "EgressProxy":
        self._server = await asyncio.start_server(self._handle, "127.0.0.1", 0, limit=_HEAD_LIMIT)
        return self

    async def close(self) -> None:
        if self._server is not None:
            self._server.close()
            for task in list(self._tasks):
                task.cancel()
            await asyncio.gather(*self._tasks, return_exceptions=True)
            self._server = None

    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        task = asyncio.current_task()
        if task is not None:
            self._tasks.add(task)
        upstream: Optional[asyncio.StreamWriter] = None
        try:
            head = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), _HEAD_TIMEOUT_S)
            line, _, headers = head.partition(b"\r\n")
            method, _, rest = line.decode("latin-1").partition(" ")
            target, _, version = rest.partition(" ")
            if method == "CONNECT":
                where = _host_port(target, 443)
                first = b""
            else:
                parts = urlsplit(target)
                where = _host_port(parts.netloc, 80) if parts.scheme == "http" else None
                path = (parts.path or "/") + (f"?{parts.query}" if parts.query else "")
                kept = [h for h in headers.split(b"\r\n") if h and h.split(b":", 1)[0].strip().lower()
                        not in _DROPPED_HEADERS]
                first = b"\r\n".join(
                    [f"{method} {path} {version}".encode("latin-1"), *kept, b"Connection: close", b"", b""]
                )
            # A connection refused or not made is closed with no answer, so
            # Chrome reports the page as not loaded, as if nothing answered,
            # never a page the proxy wrote.
            if where is None or not version.startswith("HTTP/"):
                return
            host, port = where
            lookup = asyncio.get_running_loop().run_in_executor(_RESOLVERS, self._guard.checked_addresses, host)
            reason, addresses = await asyncio.wait_for(lookup, _RESOLVE_TIMEOUT_S)
            if reason is not None:
                logger.warning("browser_proxy_refused", host=host, reason=reason)
                return
            upstream_reader: Optional[asyncio.StreamReader] = None
            for address in addresses:
                try:
                    upstream_reader, upstream = await asyncio.wait_for(
                        asyncio.open_connection(str(ipaddress.ip_address(address)), port), _CONNECT_TIMEOUT_S
                    )
                    break
                except (OSError, asyncio.TimeoutError, ValueError):
                    continue
            if upstream_reader is None or upstream is None:
                return
            if method == "CONNECT":
                writer.write(b"HTTP/1.1 200 Connection established\r\n\r\n")
                await writer.drain()
            else:
                upstream.write(first)
            await asyncio.gather(_pipe(reader, upstream), _pipe(upstream_reader, writer))
        except (asyncio.IncompleteReadError, asyncio.LimitOverrunError, asyncio.TimeoutError, ConnectionError):
            pass
        except Exception as exc:  # noqa: BLE001 - one bad connection never takes the proxy down
            logger.warning("browser_proxy_failed", error_type=type(exc).__name__)
        finally:
            for stream in (upstream, writer):
                if stream is not None:
                    stream.close()
            if task is not None:
                self._tasks.discard(task)


async def _pipe(source: asyncio.StreamReader, sink: asyncio.StreamWriter) -> None:
    """Copy *source* to *sink* until either side ends."""
    try:
        while chunk := await source.read(65536):
            sink.write(chunk)
            await sink.drain()
    except (ConnectionError, OSError):
        pass
    finally:
        if sink.can_write_eof():
            try:
                sink.write_eof()
            except (OSError, RuntimeError):
                pass
