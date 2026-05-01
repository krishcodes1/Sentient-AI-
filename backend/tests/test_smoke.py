"""End-to-end smoke test: register -> login -> conversation lifecycle."""

from __future__ import annotations

import pytest


@pytest.mark.asyncio
async def test_smoke_full_user_flow(client) -> None:
    """A user can register, log in, create a conversation, and list it."""
    # 1. Register.
    register = await client.post(
        "/api/auth/register",
        json={
            "email": "smoke@example.com",
            "password": "SmokeTest123!",
            "name": "Smoke Tester",
        },
    )
    assert register.status_code == 201
    register_body = register.json()
    register_token = register_body["access_token"]
    assert register_token

    # 2. Log in (independent token).
    login = await client.post(
        "/api/auth/login",
        json={"email": "smoke@example.com", "password": "SmokeTest123!"},
    )
    assert login.status_code == 200
    login_body = login.json()
    auth_headers = {"Authorization": f"Bearer {login_body['access_token']}"}

    # 3. /me confirms identity.
    me = await client.get("/api/auth/me", headers=auth_headers)
    assert me.status_code == 200
    assert me.json()["email"] == "smoke@example.com"

    # 4. Create a conversation.
    create = await client.post(
        "/api/agent/conversations",
        headers=auth_headers,
        json={"title": "Smoke conversation"},
    )
    assert create.status_code == 201
    convo = create.json()
    assert convo["title"] == "Smoke conversation"
    convo_id = convo["id"]

    # 5. List conversations.
    listing = await client.get("/api/agent/conversations", headers=auth_headers)
    assert listing.status_code == 200
    items = listing.json()
    assert any(item["id"] == convo_id for item in items)

    # 6. Fetch the single conversation back.
    fetched = await client.get(
        f"/api/agent/conversations/{convo_id}",
        headers=auth_headers,
    )
    assert fetched.status_code == 200
    assert fetched.json()["id"] == convo_id


@pytest.mark.asyncio
async def test_smoke_unauthenticated_conversation_create_blocked(client) -> None:
    """Creating a conversation without a token must be rejected."""
    response = await client.post(
        "/api/agent/conversations",
        json={"title": "Should fail"},
    )
    assert response.status_code in (401, 403)
