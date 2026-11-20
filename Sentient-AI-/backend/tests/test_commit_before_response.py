"""Tests that a route's database commit runs before its response is sent.

Why it exists: get_db commits when the route's dependencies close. At FastAPI's
default request scope that happens after the response has gone out, so a commit
that failed (dropped connection, constraint, serialization) left the client
holding a 2xx for a write that was never saved. Routes now take
``Depends(get_db, scope="function")``; only the two streaming routes keep
request scope.

Connects to: core.database.get_db, services.auth.get_current_user(_streaming),
and every route in main.app.
"""

from __future__ import annotations

import uuid

import httpx
import pytest
from fastapi.routing import APIRoute, iter_route_contexts
from sqlalchemy import select
from sqlalchemy.exc import OperationalError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from core import database
from tests.conftest import auth_headers, make_user

# The routes whose StreamingResponse uses the session after the handler returns.
_STREAMING_ROUTES = {
    "/api/agent/conversations/{conversation_id}/messages/stream",
    "/api/auth/export",
}


def _get_db_scopes(dependant) -> set[str]:
    """Every scope get_db is requested at anywhere under ``dependant``."""
    scopes: set[str] = set()
    for sub in dependant.dependencies:
        if sub.call is database.get_db:
            scopes.add(sub.scope or "request")
        scopes |= _get_db_scopes(sub)
    return scopes


def test_routes_share_one_session_committed_before_the_response():
    """One scope per route means one cached session for the route and its
    get_current_user; function scope means it commits before the response."""
    from main import app

    checked = set()
    # FastAPI 0.141 keeps included routers nested; this walks them with prefixes.
    for route in iter_route_contexts(app.routes):
        if not isinstance(route.original_route, APIRoute):
            continue
        scopes = _get_db_scopes(route.dependant)
        if not scopes:
            continue
        expected = {"request"} if route.path in _STREAMING_ROUTES else {"function"}
        assert scopes == expected, f"{route.methods} {route.path} gets get_db at {scopes}"
        checked.add(route.path)
    assert _STREAMING_ROUTES <= checked
    assert len(checked) > 50  # the walk reached the included routers


@pytest.mark.asyncio
async def test_failed_commit_answers_500_and_saves_nothing(session_factory, monkeypatch):
    """The real get_db, with a commit that fails as a dropped connection would:
    the client gets the error, not the 201 it used to get first."""
    from main import app
    from models.memory import Memory

    user, token = await make_user(session_factory, email="commit-fails@example.com")

    class _CommitFails(AsyncSession):
        async def commit(self) -> None:
            raise OperationalError("COMMIT", None, ConnectionError("connection dropped"))

    monkeypatch.setattr(
        database,
        "async_session",
        async_sessionmaker(
            bind=session_factory.kw["bind"], class_=_CommitFails, expire_on_commit=False
        ),
    )
    h = uuid.uuid4().hex
    peer = f"2001:db8::{h[0:4]}:{h[4:8]}:{h[8:12]}:{h[12:16]}"
    # raise_app_exceptions=False: return what the client actually received.
    transport = httpx.ASGITransport(app=app, raise_app_exceptions=False, client=(peer, 54321))
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        resp = await client.post(
            "/api/memories/",
            json={"content": "Prefers tea over coffee"},
            headers={**auth_headers(token), "X-Forwarded-For": peer},
        )

    assert resp.status_code == 500
    async with session_factory() as session:
        saved = await session.execute(select(Memory).where(Memory.user_id == user.id))
        assert saved.first() is None
