"""Request ID middleware.

Generates (or honours) a per-request ``X-Request-ID`` header, binds it
to the structlog context for the duration of the request, and stores it
in a :class:`contextvars.ContextVar` so background tasks running on the
same task chain can read it. Also writes ``request.state.request_id`` so
legacy code that reads the value off the FastAPI request state keeps
working.
"""

from __future__ import annotations

import uuid
from contextvars import ContextVar

import structlog
from starlette.middleware.base import BaseHTTPMiddleware

REQUEST_ID: ContextVar[str | None] = ContextVar("request_id", default=None)
HEADER = "X-Request-ID"


class RequestIDMiddleware(BaseHTTPMiddleware):
    """Attach a request id to every request/response and the log context."""

    async def dispatch(self, request, call_next):  # type: ignore[no-untyped-def]
        rid = request.headers.get(HEADER) or uuid.uuid4().hex
        token = REQUEST_ID.set(rid)
        # Make the id readable from request.state for code that reads it
        # off the request (e.g. the global exception handler).
        request.state.request_id = rid
        structlog.contextvars.bind_contextvars(
            request_id=rid,
            path=request.url.path,
            method=request.method,
        )
        try:
            response = await call_next(request)
        finally:
            structlog.contextvars.clear_contextvars()
            REQUEST_ID.reset(token)
        response.headers[HEADER] = rid
        return response
