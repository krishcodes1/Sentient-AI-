"""Route-level security tests: authentication required everywhere,
cross-user isolation (anti-IDOR), and the removal of the forgeable
audit-write endpoint.
"""

from __future__ import annotations

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
    ("GET", f"/api/connectors/{SOME_ID}"),
    ("PATCH", f"/api/connectors/{SOME_ID}"),
    ("DELETE", f"/api/connectors/{SOME_ID}"),
    ("POST", f"/api/connectors/{SOME_ID}/test"),
    ("GET", "/api/audit/"),
    ("GET", f"/api/audit/{SOME_ID}"),
    ("GET", f"/api/audit/{SOME_ID}/verify"),
]


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
