"""
Security middleware stack for SentientAI FastAPI application.

Provides:
- SecurityHeadersMiddleware — defense-in-depth HTTP headers
- RateLimitMiddleware — in-memory per-IP rate limiting with TTL
- RequestIdMiddleware — unique request ID on every request/response
"""

from __future__ import annotations

import asyncio
import time
import uuid
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Callable

from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import JSONResponse, Response


# ------------------------------------------------------------------ #
# Security Headers
# ------------------------------------------------------------------ #

class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """
    Adds standard security headers to every response.
    """

    SECURITY_HEADERS = {
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY",
        "X-XSS-Protection": "1; mode=block",
        "Strict-Transport-Security": "max-age=63072000; includeSubDomains; preload",
        "Content-Security-Policy": (
            "default-src 'self'; "
            "script-src 'self'; "
            "style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data:; "
            "font-src 'self'; "
            "frame-ancestors 'none'; "
            "base-uri 'self'; "
            "form-action 'self'"
        ),
        "Referrer-Policy": "strict-origin-when-cross-origin",
        "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
        "Cache-Control": "no-store, no-cache, must-revalidate",
        "Pragma": "no-cache",
    }

    async def dispatch(
        self, request: Request, call_next: RequestResponseEndpoint
    ) -> Response:
        response = await call_next(request)
        for header, value in self.SECURITY_HEADERS.items():
            response.headers[header] = value
        return response


# ------------------------------------------------------------------ #
# Rate Limiter
# ------------------------------------------------------------------ #

@dataclass
class _RateBucket:
    """Tracks request timestamps for a single IP."""
    timestamps: list[float] = field(default_factory=list)


class RateLimitMiddleware(BaseHTTPMiddleware):
    """
    In-memory, per-IP rate limiter.

    Args:
        app: The ASGI application.
        max_requests: Maximum requests allowed within the window.
        window_seconds: Time window in seconds (default 60).
        cleanup_interval: How often to purge expired entries (seconds).
    """

    def __init__(
        self,
        app,
        max_requests: int = 100,
        window_seconds: int = 60,
        cleanup_interval: int = 300,
    ) -> None:
        super().__init__(app)
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self.cleanup_interval = cleanup_interval
        self._buckets: dict[str, _RateBucket] = defaultdict(_RateBucket)
        self._lock = asyncio.Lock()
        self._last_cleanup = time.monotonic()

    def _get_client_ip(self, request: Request) -> str:
        """Extract client IP, respecting X-Forwarded-For behind a reverse proxy."""
        forwarded = request.headers.get("x-forwarded-for")
        if forwarded:
            return forwarded.split(",")[0].strip()
        return request.client.host if request.client else "unknown"

    async def _cleanup_expired(self, now: float) -> None:
        """Remove entries older than the window to prevent memory growth."""
        if now - self._last_cleanup < self.cleanup_interval:
            return
        self._last_cleanup = now
        cutoff = now - self.window_seconds
        expired_keys = []
        for ip, bucket in self._buckets.items():
            bucket.timestamps = [t for t in bucket.timestamps if t > cutoff]
            if not bucket.timestamps:
                expired_keys.append(ip)
        for key in expired_keys:
            del self._buckets[key]

    async def dispatch(
        self, request: Request, call_next: RequestResponseEndpoint
    ) -> Response:
        client_ip = self._get_client_ip(request)
        now = time.monotonic()

        async with self._lock:
            await self._cleanup_expired(now)

            bucket = self._buckets[client_ip]
            cutoff = now - self.window_seconds
            bucket.timestamps = [t for t in bucket.timestamps if t > cutoff]

            if len(bucket.timestamps) >= self.max_requests:
                retry_after = int(self.window_seconds - (now - bucket.timestamps[0])) + 1
                return JSONResponse(
                    status_code=429,
                    content={
                        "detail": "Rate limit exceeded. Please try again later.",
                        "retry_after": retry_after,
                    },
                    headers={"Retry-After": str(retry_after)},
                )

            bucket.timestamps.append(now)

        return await call_next(request)


# ------------------------------------------------------------------ #
# Request ID
# ------------------------------------------------------------------ #

class RequestIdMiddleware(BaseHTTPMiddleware):
    """
    Ensures every request/response carries a unique X-Request-ID header.

    If the incoming request already has the header, it is preserved;
    otherwise a new UUID4 is generated.
    """

    HEADER_NAME = "X-Request-ID"

    async def dispatch(
        self, request: Request, call_next: RequestResponseEndpoint
    ) -> Response:
        request_id = request.headers.get(self.HEADER_NAME) or str(uuid.uuid4())

        # Attach to request state so downstream code can access it
        request.state.request_id = request_id

        response = await call_next(request)
        response.headers[self.HEADER_NAME] = request_id
        return response
