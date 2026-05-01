"""Trusted-proxy middleware.

The downstream :class:`RateLimitMiddleware` (and any IP-based logic) reads
``request.client.host`` to identify a client. When the app is fronted by a
reverse proxy (Cloudflare, nginx, an L7 load balancer, ...), the *real*
client IP is sent in the ``X-Forwarded-For`` header. Trusting that header
unconditionally, however, lets any external caller spoof their IP.

This middleware only honours ``X-Forwarded-For`` when the *direct* TCP
peer (``request.client.host``) is in a configured allowlist of trusted
proxy networks (CIDRs). When trusted, it rewrites
``request.scope["client"]`` so downstream code transparently sees the
forwarded IP. When not trusted, the header is ignored.
"""

from __future__ import annotations

from ipaddress import ip_address, ip_network

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.types import ASGIApp


class TrustProxyMiddleware(BaseHTTPMiddleware):
    """Rewrite ``request.scope['client']`` based on a trusted XFF.

    Args:
        app: The ASGI app being wrapped.
        trusted_networks: Iterable of CIDR strings (e.g. ``"10.0.0.0/8"``)
            or single host strings (``"127.0.0.1"``) whose direct
            connections are allowed to send a trustworthy
            ``X-Forwarded-For`` header. Empty/None disables the feature
            entirely (XFF is ignored).
    """

    def __init__(
        self,
        app: ASGIApp,
        trusted_networks: list[str] | None = None,
    ) -> None:
        super().__init__(app)
        self.trusted = [ip_network(n, strict=False) for n in (trusted_networks or [])]

    async def dispatch(self, request, call_next):  # type: ignore[no-untyped-def]
        if not self.trusted:
            return await call_next(request)
        client = request.client
        if client is None:
            return await call_next(request)
        try:
            client_ip = ip_address(client.host)
        except ValueError:
            return await call_next(request)
        if any(client_ip in net for net in self.trusted):
            xff = request.headers.get("x-forwarded-for")
            if xff:
                first = xff.split(",")[0].strip()
                if first:
                    request.scope["client"] = (first, client.port or 0)
        return await call_next(request)
