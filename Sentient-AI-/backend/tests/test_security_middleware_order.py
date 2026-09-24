"""Tests for security-middleware ordering around the rate limiter: a 429 response
from the rate limiter still carries the standard security headers and a
correlation request id.

Why it exists: The rate limiter short-circuits the stack and was added outside
the header and request-id layers, so the one response class an attacker can
provoke on demand shipped with no CSP and no way to trace the burst.

Throttled responses go through the same hardening as every other one.

The rate limiter short-circuits: once a bucket is full it returns a 429
itself and nothing further in the stack runs. It was added outside the
header and request-id layers, so those never saw the response — which
meant the one class of response an attacker can provoke on demand was
served with no CSP, no frame-ancestors, and no correlation id to trace the
burst by. Ordering is the whole fix, so these tests pin the ordering
rather than the header values.
"""

from __future__ import annotations

import httpx
import pytest

from api.middleware.security import (
    RateLimitMiddleware,
    RequestIdMiddleware,
    SecurityHeadersMiddleware,
)


def _stack() -> list[type]:
    """Middleware classes, outermost first."""
    from main import app

    return [m.cls for m in app.user_middleware]


def test_rate_limiter_sits_inside_the_hardening_layers():
    stack = _stack()
    for wrapper in (SecurityHeadersMiddleware, RequestIdMiddleware):
        assert stack.index(wrapper) < stack.index(RateLimitMiddleware), (
            f"{wrapper.__name__} must wrap RateLimitMiddleware, or a 429 "
            "short-circuits past it"
        )


@pytest.mark.asyncio
async def test_throttled_response_carries_security_headers_and_a_request_id(
    session_factory,
):
    from core.database import get_db
    from main import app

    async def _override_get_db():
        async with session_factory() as session:
            yield session

    app.dependency_overrides[get_db] = _override_get_db
    # A peer outside the range conftest hands other clients: this test
    # deliberately exhausts its bucket, and the limiter's state is
    # process-wide for the whole session.
    transport = httpx.ASGITransport(app=app, client=("192.0.2.77", 54321))
    try:
        async with httpx.AsyncClient(
            transport=transport, base_url="http://testserver"
        ) as client:
            # Burst the credential bucket (AUTH_RATE_LIMIT_PER_MINUTE) with
            # requests that cannot succeed anyway.
            throttled = None
            for _ in range(40):
                resp = await client.post(
                    "/api/auth/login",
                    json={"email": "burst@example.com", "password": "x"},
                )
                if resp.status_code == 429:
                    throttled = resp
                    break
    finally:
        app.dependency_overrides.pop(get_db, None)

    assert throttled is not None, "the auth rate limit never engaged"
    assert throttled.headers["X-Frame-Options"] == "DENY"
    assert throttled.headers["X-Content-Type-Options"] == "nosniff"
    assert "frame-ancestors 'none'" in throttled.headers["Content-Security-Policy"]
    assert throttled.headers["X-Request-ID"]
    # The limiter's own contract still holds through the added layers.
    assert throttled.headers["Retry-After"]
