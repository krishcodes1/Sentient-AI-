"""Tests for route-level security: every route requires authentication, a user can
never reach another user's conversation or connector, and the forgeable direct
audit-write endpoint has been removed.

Why it exists: Guards the baseline authorization and cross-user isolation every
route depends on, plus the removal of an endpoint that let a caller write
arbitrary audit rows.

Route-level security tests: authentication required everywhere,
cross-user isolation (anti-IDOR), and the removal of the forgeable
audit-write endpoint.
"""

from __future__ import annotations

import re
import uuid

import pytest

from tests.conftest import auth_headers, make_user


SOME_ID = str(uuid.uuid4())

# Every data route must reject unauthenticated callers. HTTPBearer yields
# 403 for a missing header and our validation yields 401 for a bad token;
# both mean "no access without credentials".
PROTECTED_ROUTES = [
    ("GET", "/api/agent/conversations"),
    ("POST", "/api/agent/conversations"),
    ("GET", f"/api/agent/conversations/{SOME_ID}"),
    ("POST", f"/api/agent/conversations/{SOME_ID}/messages"),
    ("GET", "/api/agent/approvals"),
    ("POST", f"/api/agent/approvals/{SOME_ID}"),
    ("GET", "/api/connectors/"),
    ("POST", "/api/connectors/"),
    ("GET", "/api/connectors/health"),
    ("GET", "/api/connectors/types"),
    ("GET", f"/api/connectors/{SOME_ID}"),
    ("PATCH", f"/api/connectors/{SOME_ID}"),
    ("DELETE", f"/api/connectors/{SOME_ID}"),
    ("POST", f"/api/connectors/{SOME_ID}/test"),
    ("POST", f"/api/connectors/{SOME_ID}/slack/link"),
    ("GET", f"/api/connectors/{SOME_ID}/slack/link"),
    ("DELETE", f"/api/connectors/{SOME_ID}/slack/link"),
    ("POST", "/api/oauth/google/start"),
    ("POST", "/api/oauth/google/device"),
    ("GET", f"/api/oauth/google/status?flow={SOME_ID}"),
    ("GET", "/api/audit/"),
    ("GET", f"/api/audit/{SOME_ID}"),
    ("GET", f"/api/audit/{SOME_ID}/verify"),
    # top10:flashcards_quizzes: the signed-in deck download (the one-time
    # link route answers 404 to anything but a live token instead).
    ("GET", f"/api/study/decks/{SOME_ID}/export"),
    # top10:scheduler_briefing: scheduled tasks create and run unattended
    # agent turns.
    ("GET", "/api/schedules"),
    ("POST", "/api/schedules"),
    ("PATCH", f"/api/schedules/{SOME_ID}"),
    ("DELETE", f"/api/schedules/{SOME_ID}"),
    ("POST", f"/api/schedules/{SOME_ID}/run"),
    ("GET", "/api/schedules/timezone"),
    ("PUT", "/api/schedules/timezone"),
    # top10:event_triggers
    ("GET", "/api/triggers"),
    ("PATCH", f"/api/triggers/{SOME_ID}"),
    ("DELETE", f"/api/triggers/{SOME_ID}"),
]

# The /api routes that answer without a signed-in user, each on purpose.
# Every other /api route must refuse a caller with no credentials (the walk
# below), so a new route that forgets Depends(get_current_user) fails here.
PUBLIC_ROUTES: set[tuple[str, str]] = {
    ("GET", "/api/health"),
    # Signing in and (when the owner opened it) registering.
    ("POST", "/api/auth/register"),
    ("POST", "/api/auth/login"),
    # The provider sends the browser back here; the flow's state is checked.
    ("GET", "/api/oauth/callback/{provider}"),
    # The first-run wizard: its status, and the owner step (409 as soon as
    # any account exists).
    ("GET", "/api/setup/status"),
    ("POST", "/api/setup/owner"),
    # top10:flashcards_quizzes: the one-time deck download link; anything
    # but a live token is a 404.
    ("GET", "/api/study/export"),
}


def _api_routes() -> list[tuple[str, str]]:
    """(method, path) of every /api route the app serves, included routers
    and all (FastAPI 0.14x keeps an included router as one entry)."""
    from fastapi.routing import APIRoute

    from main import app

    found: list[tuple[str, str]] = []

    def walk(routes, prefix: str) -> None:
        for route in routes:
            if isinstance(route, APIRoute):
                for method in sorted(route.methods - {"HEAD", "OPTIONS"}):
                    found.append((method, prefix + route.path))
            elif hasattr(route, "original_router"):
                walk(route.original_router.routes, prefix + route.include_context.prefix)

    walk(app.routes, "")
    return [(m, p) for m, p in found if p.startswith("/api/")]


def _concrete(path: str) -> str:
    return re.sub(r"\{[^}]+\}", SOME_ID, path)


def test_the_route_walk_sees_the_whole_api():
    from main import app

    routes = set(_api_routes())
    # Everything the OpenAPI schema lists is walked (and more: routes left
    # out of the schema, such as the one-time study download).
    documented = {
        (method.upper(), path)
        for path, operations in app.openapi()["paths"].items()
        for method in operations
        if path.startswith("/api/")
    }
    assert documented <= routes, documented - routes
    assert ("GET", "/api/schedules") in routes and ("GET", "/api/health") in routes


async def _anonymous_request(method: str, path: str) -> int:
    """One request with no credentials from a peer of its own (so the
    per-IP rate limit never answers 429 in place of the route)."""
    import httpx

    from main import app

    h = uuid.uuid4().hex
    peer = f"2001:db8::{h[0:4]}:{h[4:8]}:{h[8:12]}:{h[12:16]}"
    transport = httpx.ASGITransport(app=app, client=(peer, 54321))
    async with httpx.AsyncClient(
        transport=transport, base_url="http://testserver", headers={"X-Forwarded-For": peer}
    ) as anonymous:
        return (await anonymous.request(method, path, json={})).status_code


@pytest.mark.asyncio
async def test_every_api_route_refuses_a_caller_without_credentials(client):
    # ``client`` wires the test database into the app for these requests.
    allowed = []
    for method, path in _api_routes():
        if (method, path) in PUBLIC_ROUTES:
            continue
        status = await _anonymous_request(method, _concrete(path))
        if status not in (401, 403):
            allowed.append(f"{method} {path} -> {status}")
    assert allowed == [], "\n".join(allowed)


def test_every_public_route_exists():
    routes = set(_api_routes())
    assert PUBLIC_ROUTES <= routes, PUBLIC_ROUTES - routes


@pytest.mark.asyncio
@pytest.mark.parametrize("method,path", PROTECTED_ROUTES)
async def test_routes_reject_unauthenticated(client, method, path):
    response = await client.request(method, path, json={})
    assert response.status_code in (401, 403), (
        f"{method} {path} returned {response.status_code} without credentials"
    )


@pytest.mark.asyncio
async def test_routes_reject_garbage_token(client):
    response = await client.get(
        "/api/agent/conversations", headers=auth_headers("not-a-jwt")
    )
    assert response.status_code == 401


@pytest.mark.asyncio
async def test_audit_write_endpoint_removed(client, session_factory):
    """POST /api/audit/ allowed anyone to forge validly-chained audit rows.
    It must not exist; audit writes are server-side only."""
    _, token = await make_user(session_factory)
    response = await client.post(
        "/api/audit/",
        headers=auth_headers(token),
        json={"connector_name": "x", "action": "y"},
    )
    assert response.status_code == 405


# ---------------------------------------------------------------------------
# Cross-user isolation
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_conversations_are_scoped_to_token_user(client, session_factory):
    _, token_a = await make_user(session_factory, "a@example.com")
    _, token_b = await make_user(session_factory, "b@example.com")

    created = await client.post(
        "/api/agent/conversations",
        headers=auth_headers(token_a),
        json={"title": "A's private chat"},
    )
    assert created.status_code == 201
    conversation_id = created.json()["id"]

    # B cannot read it by id (404 — existence is not leaked)
    response = await client.get(
        f"/api/agent/conversations/{conversation_id}", headers=auth_headers(token_b)
    )
    assert response.status_code == 404

    # B's listing does not include it
    listing = await client.get(
        "/api/agent/conversations", headers=auth_headers(token_b)
    )
    assert listing.status_code == 200
    assert listing.json() == []

    # A still sees it
    listing_a = await client.get(
        "/api/agent/conversations", headers=auth_headers(token_a)
    )
    assert [c["id"] for c in listing_a.json()] == [conversation_id]


@pytest.mark.asyncio
async def test_send_message_to_foreign_conversation_404(client, session_factory):
    from api.routes import agent as agent_routes
    from main import app
    from services.agent.runtime import AgentResponse

    class FakeRuntime:
        async def chat(self, messages, tools, user_id, conversation_id=None, **kwargs):
            return AgentResponse(content="ok")

    app.dependency_overrides[agent_routes.get_runtime] = lambda: FakeRuntime()
    try:
        _, token_a = await make_user(session_factory, "a@example.com")
        _, token_b = await make_user(session_factory, "b@example.com")

        created = await client.post(
            "/api/agent/conversations",
            headers=auth_headers(token_a),
            json={"title": "A's chat"},
        )
        conversation_id = created.json()["id"]

        response = await client.post(
            f"/api/agent/conversations/{conversation_id}/messages",
            headers=auth_headers(token_b),
            json={"content": "let me in"},
        )
        assert response.status_code == 404

        # The owner can post fine.
        ok = await client.post(
            f"/api/agent/conversations/{conversation_id}/messages",
            headers=auth_headers(token_a),
            json={"content": "hello"},
        )
        assert ok.status_code == 201
        assert ok.json()["assistant_message"]["content"] == "ok"
    finally:
        app.dependency_overrides.pop(agent_routes.get_runtime, None)


@pytest.mark.asyncio
async def test_connectors_are_scoped_to_token_user(client, session_factory):
    _, token_a = await make_user(session_factory, "a@example.com")
    _, token_b = await make_user(session_factory, "b@example.com")

    created = await client.post(
        "/api/connectors/",
        headers=auth_headers(token_a),
        json={
            "connector_type": "canvas",
            "display_name": "School Canvas",
            "auth_method": "bearer_token",
            "credentials": {
                "base_url": "https://school.instructure.com",
                "access_token": "tok",
            },
        },
    )
    assert created.status_code == 201
    connector_id = created.json()["id"]

    # B cannot read, modify, or delete A's connector.
    assert (
        await client.get(
            f"/api/connectors/{connector_id}", headers=auth_headers(token_b)
        )
    ).status_code == 404
    assert (
        await client.patch(
            f"/api/connectors/{connector_id}",
            headers=auth_headers(token_b),
            json={"permission_tier": "auto_approve"},
        )
    ).status_code == 404
    assert (
        await client.delete(
            f"/api/connectors/{connector_id}", headers=auth_headers(token_b)
        )
    ).status_code == 404

    listing_b = await client.get("/api/connectors/", headers=auth_headers(token_b))
    assert listing_b.json() == []

    # Owner still has full access.
    assert (
        await client.get(
            f"/api/connectors/{connector_id}", headers=auth_headers(token_a)
        )
    ).status_code == 200


@pytest.mark.asyncio
async def test_connector_created_without_scopes_defaults_to_read_only(
    client, session_factory
):
    _, token = await make_user(session_factory)
    created = await client.post(
        "/api/connectors/",
        headers=auth_headers(token),
        json={
            "connector_type": "canvas",
            "display_name": "School Canvas",
            "auth_method": "bearer_token",
            "credentials": {
                "base_url": "https://school.instructure.com",
                "access_token": "tok",
            },
        },
    )
    assert created.status_code == 201
    scopes = created.json()["granted_scopes"]
    assert "courses.read" in scopes
    assert all(not s.endswith(".write") for s in scopes), scopes


@pytest.mark.asyncio
async def test_connector_create_validates_credentials(client, session_factory):
    _, token = await make_user(session_factory)
    response = await client.post(
        "/api/connectors/",
        headers=auth_headers(token),
        json={
            "connector_type": "canvas",
            "display_name": "Broken Canvas",
            "auth_method": "bearer_token",
            "credentials": {"access_token": "tok"},  # missing base_url
        },
    )
    assert response.status_code == 422
    assert "base_url" in response.json()["detail"]


async def _create_canvas_connector(client, token):
    response = await client.post(
        "/api/connectors/",
        headers=auth_headers(token),
        json={
            "connector_type": "canvas",
            "display_name": "Canvas",
            "auth_method": "bearer_token",
            "credentials": {
                "base_url": "https://school.instructure.com",
                "access_token": "tok",
            },
        },
    )
    assert response.status_code == 201
    return response.json()["id"]


@pytest.mark.asyncio
async def test_connector_update_validates_credentials(client, session_factory):
    """PATCH stored whatever it was given. A blob the connector can never
    use then failed at tool-call time, far from the edit that caused it."""
    _, token = await make_user(session_factory)
    connector_id = await _create_canvas_connector(client, token)

    broken = await client.patch(
        f"/api/connectors/{connector_id}",
        headers=auth_headers(token),
        json={"credentials": {"access_token": "tok"}},  # missing base_url
    )
    assert broken.status_code == 422
    assert "base_url" in broken.json()["detail"]

    scheme = await client.patch(
        f"/api/connectors/{connector_id}",
        headers=auth_headers(token),
        json={
            "credentials": {
                "base_url": "school.instructure.com",
                "access_token": "tok",
            }
        },
    )
    assert scheme.status_code == 422
    assert "http" in scheme.json()["detail"]

    ok = await client.patch(
        f"/api/connectors/{connector_id}",
        headers=auth_headers(token),
        json={
            "credentials": {
                "base_url": "https://canvas.myschool.edu",
                "access_token": "tok2",
            }
        },
    )
    assert ok.status_code == 200


@pytest.mark.asyncio
async def test_connector_update_rejects_non_object_mcp_headers(
    client, session_factory
):
    _, token = await make_user(session_factory)
    created = await client.post(
        "/api/connectors/",
        headers=auth_headers(token),
        json={
            "connector_type": "mcp",
            "display_name": "Notes Server",
            "auth_method": "bearer_token",
            "credentials": {"url": "https://mcp.example.com/mcp"},
        },
    )
    assert created.status_code == 201

    response = await client.patch(
        f"/api/connectors/{created.json()['id']}",
        headers=auth_headers(token),
        json={
            "credentials": {
                "url": "https://mcp.example.com/mcp",
                "headers": "Bearer token",
            }
        },
    )
    assert response.status_code == 422
    assert "headers" in response.json()["detail"]


@pytest.mark.asyncio
async def test_connector_create_rejects_non_object_mcp_headers(
    client, session_factory
):
    _, token = await make_user(session_factory)
    response = await client.post(
        "/api/connectors/",
        headers=auth_headers(token),
        json={
            "connector_type": "mcp",
            "display_name": "Notes Server",
            "auth_method": "bearer_token",
            "credentials": {
                "url": "https://mcp.example.com/mcp",
                "headers": "Bearer token",
            },
        },
    )
    assert response.status_code == 422
    assert "headers" in response.json()["detail"]


@pytest.mark.asyncio
async def test_audit_logs_scoped_and_verifiable(client, session_factory):
    from models.audit import AuditStatus
    from services.audit import append_audit_log

    user_a, token_a = await make_user(session_factory, "a@example.com")
    user_b, token_b = await make_user(session_factory, "b@example.com")

    async with session_factory() as session:
        row_a = await append_audit_log(
            session,
            user_id=user_a.id,
            connector_name="canvas",
            action="get_courses",
            endpoint="agent.tool_executed",
            scope_used="courses.read",
            status=AuditStatus.approved,
        )
        row_b = await append_audit_log(
            session,
            user_id=user_b.id,
            connector_name="gmail",
            action="send_email",
            endpoint="agent.tool_executed",
            scope_used="gmail.send",
            status=AuditStatus.pending,
        )
        await session.commit()
        row_a_id, row_b_id = str(row_a.id), str(row_b.id)

    listing = await client.get("/api/audit/", headers=auth_headers(token_a))
    assert listing.status_code == 200
    assert [row["id"] for row in listing.json()] == [row_a_id]

    # A cannot fetch or verify B's row.
    assert (
        await client.get(f"/api/audit/{row_b_id}", headers=auth_headers(token_a))
    ).status_code == 404
    assert (
        await client.get(
            f"/api/audit/{row_b_id}/verify", headers=auth_headers(token_a)
        )
    ).status_code == 404

    # A's own row verifies as untampered.
    verify = await client.get(
        f"/api/audit/{row_a_id}/verify", headers=auth_headers(token_a)
    )
    assert verify.status_code == 200
    # ``legacy`` distinguishes a row verified by the keyed HMAC from one that
    # only matched the pre-upgrade unkeyed digest; a freshly written row is
    # keyed, so it must be False.
    assert verify.json() == {"id": row_a_id, "valid": True, "legacy": False}
