"""Builds the httpx client the built-in tools use, with SSRF validation on every
hop and DNS-pinned connections.

Why it exists: Built-in tools reach hosts the user names, with no per-connector
allowlist; the web toolkit gets its client only from here so the policy in
core.network_security and the pinning in core.http_pinning apply once and are
never restated.

Egress guard for the built-in tools.

Built-in tools reach hosts the user names (or that a search result
points at), so they cannot rely on a per-connector allowlist the way
``services.connectors`` does. What they get instead is the same two
guarantees the MCP transport gives:

- Every request URL is validated by ``core.network_security.check_ssrf``
  before a socket is opened, and again on every redirect hop, because
  httpx fires request hooks inside its redirect loop.
- The addresses that validation looked at are *pinned* via
  ``core.http_pinning``: the connection is opened to one of them rather
  than re-resolving the hostname, so a hostile DNS server cannot answer
  the check with a public address and the connect with 127.0.0.1.

Neither the blocked ranges nor the pinning transport are restated here.
The policy lives in exactly one module and the socket layer in exactly
one other; a second copy of either would drift from the original the
first time a range or a fallback rule changed.
"""

from __future__ import annotations

import asyncio
from typing import Callable, Optional

import httpcore
import httpx
import structlog

from core.http_pinning import (
    PinnedHTTPTransport,
    PinningUnavailable,
    PinTable,
    pin_for_request,
)
from core.network_security import check_ssrf

logger = structlog.get_logger(__name__)

AddressResolver = Callable[[str], tuple[str, ...]]


class EgressBlocked(Exception):
    """Raised when a destination fails the network security policy.

    The message reaches the agent (and therefore the model), so it names
    the policy and never the internal address a hostname resolved to;
    ``check_ssrf`` keeps that detail server-side for the same reason.
    """


def validated_addresses(url: str) -> tuple[str, ...]:
    """Resolve *url*'s host once and return every address that passed.

    Thin translation of ``check_ssrf`` into the exception-raising shape a
    request hook needs. All records are judged, not just the first one: a
    name that answers with one public and one private address is a
    rebinding vector rather than a partial pass.

    The returned tuple is what the caller must connect to. Resolving
    again at connect time would reopen the window this closes.
    """
    result = check_ssrf(url)
    if not result.safe:
        logger.warning("web_tool_egress_blocked", url=url, reason=result.reason)
        raise EgressBlocked(
            result.reason
            or "That destination is not permitted by the network security policy."
        )
    return result.resolved_ips


def build_guarded_client(
    *,
    timeout_s: float = 20.0,
    headers: Optional[dict[str, str]] = None,
    resolver: AddressResolver = validated_addresses,
    transport: Optional[httpx.AsyncBaseTransport] = None,
    network_backend: Optional[httpcore.AsyncNetworkBackend] = None,
    follow_redirects: bool = True,
    max_redirects: int = 5,
    pins: Optional[PinTable] = None,
) -> httpx.AsyncClient:
    """An ``AsyncClient`` that validates and pins every hop it makes.

    *transport* is the seam tests use (``httpx.MockTransport``); the
    request hook still runs in front of it, so refusal behaviour is
    exercised with the real policy. Passing *pins* hands in the table the
    hook writes and the transport reads, which is how a test sees what a
    request was pinned to.
    """
    pins = {} if pins is None else pins

    async def _guard(request: httpx.Request) -> None:
        # getaddrinfo is a blocking syscall and this hook runs on the
        # event loop once per hop, so a slow resolver would stall every
        # other request in the worker.
        addresses = await asyncio.to_thread(resolver, str(request.url))
        pin_for_request(pins, request, tuple(addresses))

    if transport is None:
        try:
            transport = PinnedHTTPTransport(pins, network_backend)
        except PinningUnavailable as exc:
            # Without the pin the request is rebindable, so this is a
            # refusal rather than a degraded mode.
            raise EgressBlocked(str(exc)) from exc

    return httpx.AsyncClient(
        timeout=httpx.Timeout(timeout_s),
        headers=headers,
        follow_redirects=follow_redirects,
        max_redirects=max_redirects,
        transport=transport,
        event_hooks={"request": [_guard]},
    )
