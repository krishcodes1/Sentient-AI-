"""Replaces httpx's connect-time DNS lookup with a table of addresses that
already passed the SSRF policy, and refuses any origin missing from that
table.

Why it exists: Checking a URL and then letting httpcore resolve the hostname
again would let a hostile DNS answer rebind the connection to a private
address; the MCP client and the web tools share this one transport so the
refusal behaviour cannot drift between them.

Connect-time DNS pinning for outbound HTTP.

``core.network_security`` decides whether a destination is reachable;
this module makes the socket land on what that decision looked at.
Validating a URL and then handing the *hostname* to httpx is not a
control on its own: httpcore resolves the origin again inside
``connect_tcp``, so a hostile authoritative server can answer the check
with a public address and the connection with 127.0.0.1.

httpx exposes no resolver seam, so the fix is to replace the
connect-time lookup entirely with a table of addresses that already
passed the policy. Every caller that reaches a user- or
content-supplied host (the MCP transport, the built-in web tools) shares
this one implementation: a second copy would drift from it the first
time the fallback or refusal behaviour changed, and it is the refusal
behaviour that is load-bearing.
"""

from __future__ import annotations

from typing import Any, Iterable, Optional

import httpcore
import httpx

# (ascii host, port) -> addresses that passed the policy for it.
PinTable = dict[tuple[str, int], tuple[str, ...]]


class PinningUnavailable(Exception):
    """Raised when the pin cannot be installed on an httpx transport.

    Deliberately not a connection error: it means the guarantee this
    module exists to provide is absent, so the caller must refuse rather
    than retry.
    """


class PinnedResolutionBackend(httpcore.AsyncNetworkBackend):
    """Socket layer that may only dial addresses already validated.

    An origin with no entry is refused rather than resolved, so the
    failure mode is closed: a code path that skips the request hook
    cannot fall back to DNS.

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
        # local; nothing that pins its egress has a use for one.
        raise httpcore.ConnectError("Unix-socket connections are not permitted.")

    async def sleep(self, seconds: float) -> None:
        await self._inner.sleep(seconds)


class PinnedHTTPTransport(httpx.AsyncHTTPTransport):
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
            raise PinningUnavailable(
                "Cannot pin DNS resolution: this httpx build exposes no "
                "httpcore network backend to replace."
            )
        self._pool._network_backend = PinnedResolutionBackend(pins, network_backend)


def pin_for_request(
    pins: PinTable, request: httpx.Request, addresses: tuple[str, ...]
) -> None:
    """Record *addresses* as the validated pin for *request*'s origin.

    Keyed off ``raw_host`` (ASCII/punycode) and the scheme-defaulted port
    because that is exactly the origin httpcore will present to
    ``connect_tcp``; ``URL.host`` would hand back the decoded Unicode
    form for an IDN and the pin lookup would miss.

    Recording nothing is safe: ``PinnedResolutionBackend`` refuses an
    unpinned origin instead of resolving it.
    """
    if not addresses:
        return
    from core.network_security import default_port_for_scheme

    host = request.url.raw_host.decode("ascii").lower()
    port = request.url.port or default_port_for_scheme(request.url.scheme)
    pins[(host, port)] = addresses
