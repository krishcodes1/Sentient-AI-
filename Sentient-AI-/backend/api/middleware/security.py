"""
Security middleware stack for SentientAI FastAPI application.

Provides:
- SecurityHeadersMiddleware — defense-in-depth HTTP headers
- RateLimitMiddleware — per-IP rate limiting. Uses a Redis fixed-window
  counter (shared across workers) when REDIS_URL is reachable, and falls
  back automatically to the original in-memory sliding-window limiter
  whenever Redis is unavailable — a Redis outage never takes the API down.
- RequestIdMiddleware — unique request ID on every request/response
"""

from __future__ import annotations

import asyncio
import time
import uuid
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Callable

import structlog
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

try:  # pragma: no cover — exercised implicitly by the fallback path
    import redis.asyncio as _aioredis
except ImportError:  # redis is in requirements.txt; guard anyway
    _aioredis = None

logger = structlog.get_logger(__name__)


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

    # Swagger / ReDoc paths that need relaxed CSP
    _DOCS_PATHS = {"/docs", "/docs/", "/redoc", "/redoc/", "/openapi.json"}

    async def dispatch(
        self, request: Request, call_next: RequestResponseEndpoint
    ) -> Response:
        response = await call_next(request)
        for header, value in self.SECURITY_HEADERS.items():
            response.headers[header] = value
        # Swagger UI and ReDoc require inline scripts/styles + CDN resources
        if request.url.path in self._DOCS_PATHS:
            response.headers["Content-Security-Policy"] = (
                "default-src 'self'; "
                "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
                "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
                "img-src 'self' data: https://fastapi.tiangolo.com; "
                "font-src 'self' https://cdn.jsdelivr.net; "
                "frame-ancestors 'none'"
            )
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
    Per-IP rate limiter: Redis-backed when available, in-memory otherwise.

    When REDIS_URL is reachable, counting uses a Redis fixed-window counter
    (INCR + EXPIRE), so limits are shared across processes/workers. If Redis
    is unreachable at startup or errors mid-flight, the request is counted by
    the in-memory sliding-window limiter instead and Redis is retried after
    a cooldown — availability of the API never depends on Redis.

    Args:
        app: The ASGI application.
        max_requests: Maximum requests allowed within the window.
        window_seconds: Time window in seconds (default 60).
        cleanup_interval: How often to purge expired entries (seconds).
        auth_max_requests: Stricter limit for credential endpoints.
        redis_url: Redis connection URL. Defaults to settings.REDIS_URL;
            pass an empty string to force the in-memory limiter.
    """

    # Credential endpoints get a separate, much smaller bucket so login
    # brute-forcing is throttled long before the general API limit.
    AUTH_PATHS = ("/api/auth/login", "/api/auth/register")

    # After a Redis failure, wait this long before trying to reconnect.
    REDIS_RETRY_SECONDS = 30.0
    REDIS_KEY_PREFIX = "sentientai:ratelimit"

    def __init__(
        self,
        app,
        max_requests: int = 100,
        window_seconds: int = 60,
        cleanup_interval: int = 300,
        auth_max_requests: int = 10,
        redis_url: str | None = None,
    ) -> None:
        super().__init__(app)
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self.cleanup_interval = cleanup_interval
        self.auth_max_requests = auth_max_requests
        self._buckets: dict[str, _RateBucket] = defaultdict(_RateBucket)
        self._lock = asyncio.Lock()
        self._last_cleanup = time.monotonic()

        if redis_url is None:
            try:
                from core.config import settings

                redis_url = settings.REDIS_URL
            except Exception:  # settings unavailable — in-memory only
                redis_url = None
        self.redis_url = redis_url or None
        self._redis = None
        self._redis_down_until = 0.0
        self._redis_was_down = False

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

    # ── Redis backend (fixed-window counter) ────────────────────────── #

    async def _get_redis(self):
        """Return a live Redis client, or None if Redis is unavailable.

        Reconnection after a failure is attempted at most once per
        REDIS_RETRY_SECONDS so a down Redis adds no per-request latency.
        """
        if _aioredis is None or not self.redis_url:
            return None
        if self._redis is not None:
            return self._redis
        now = time.monotonic()
        if now < self._redis_down_until:
            return None
        try:
            client = _aioredis.from_url(
                self.redis_url,
                socket_connect_timeout=1.0,
                socket_timeout=1.0,
            )
            await client.ping()
        except Exception as exc:
            await self._mark_redis_down(exc)
            return None
        self._redis = client
        if self._redis_was_down:
            self._redis_was_down = False
            logger.info("rate_limiter_redis_recovered")
        else:
            logger.info("rate_limiter_redis_connected")
        return client

    async def _mark_redis_down(self, exc: Exception) -> None:
        """Drop the Redis client and back off before reconnecting."""
        self._redis_down_until = time.monotonic() + self.REDIS_RETRY_SECONDS
        client, self._redis = self._redis, None
        if client is not None:
            try:
                await client.aclose()
            except Exception:
                pass
        if not self._redis_was_down:
            self._redis_was_down = True
            # Deliberately not logging the URL — it may embed credentials.
            logger.warning(
                "rate_limiter_redis_unavailable_using_memory", error=str(exc)
            )

    async def _check_redis(self, bucket_key: str, limit: int):
        """Count this request in Redis.

        Returns (allowed, retry_after), or None if Redis is unavailable and
        the caller should fall back to the in-memory limiter.
        """
        client = await self._get_redis()
        if client is None:
            return None
        now = time.time()
        window_id = int(now // self.window_seconds)
        key = f"{self.REDIS_KEY_PREFIX}:{bucket_key}:{window_id}"
        try:
            async with client.pipeline(transaction=True) as pipe:
                pipe.incr(key)
                pipe.expire(key, self.window_seconds * 2)
                count, _ = await pipe.execute()
        except Exception as exc:
            await self._mark_redis_down(exc)
            return None
        if int(count) > limit:
            window_end = (window_id + 1) * self.window_seconds
            retry_after = max(1, int(window_end - now) + 1)
            return False, retry_after
        return True, 0

    # ── In-memory backend (sliding window) ──────────────────────────── #

    async def _check_memory(self, bucket_key: str, limit: int):
        """Count this request in the in-memory sliding window."""
        now = time.monotonic()
        async with self._lock:
            await self._cleanup_expired(now)

            bucket = self._buckets[bucket_key]
            cutoff = now - self.window_seconds
            bucket.timestamps = [t for t in bucket.timestamps if t > cutoff]

            if len(bucket.timestamps) >= limit:
                retry_after = (
                    int(self.window_seconds - (now - bucket.timestamps[0])) + 1
                )
                return False, retry_after

            bucket.timestamps.append(now)
            return True, 0

    async def dispatch(
        self, request: Request, call_next: RequestResponseEndpoint
    ) -> Response:
        client_ip = self._get_client_ip(request)

        is_auth_path = request.url.path in self.AUTH_PATHS
        bucket_key = f"{client_ip}:auth" if is_auth_path else client_ip
        limit = self.auth_max_requests if is_auth_path else self.max_requests

        verdict = await self._check_redis(bucket_key, limit)
        if verdict is None:
            verdict = await self._check_memory(bucket_key, limit)
        allowed, retry_after = verdict

        if not allowed:
            return JSONResponse(
                status_code=429,
                content={
                    "detail": "Rate limit exceeded. Please try again later.",
                    "retry_after": retry_after,
                },
                headers={"Retry-After": str(retry_after)},
            )

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
