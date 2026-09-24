"""Tests for the account data export endpoint: the export stays valid JSON across
streamed batches, covers every account record, and never includes connector
credentials.

Why it exists: The export is hand-assembled and streamed rather than serialized
from a model, so a batching bug or a credential leak into the one field that is
encrypted at rest would otherwise go unnoticed.

Account data export.

The export is streamed and assembled by hand rather than serialized from a
model, so the two things worth pinning are that it stays valid JSON across
batch boundaries and that it never carries connector credentials — the one
piece of an account's data that is encrypted at rest precisely so it does
not end up in a file.
"""

from __future__ import annotations

import json

import pytest

from tests.conftest import auth_headers

_SECRET = "super-secret-canvas-token-do-not-export"


async def _account(client, email: str = "exporter@example.com"):
    await client.post(
        "/api/auth/register",
        json={"email": email, "password": "password-123", "name": "Exporter"},
    )
    login = await client.post(
        "/api/auth/login", json={"email": email, "password": "password-123"}
    )
    return auth_headers(login.json()["access_token"])


async def _seed(client, headers, session_factory, *, messages: int = 3):
    conv = await client.post(
        "/api/agent/conversations", json={"title": "Exported thread"}, headers=headers
    )
    conv_id = conv.json()["id"]

    # Written straight to the database: posting to the agent endpoint would
    # need a live LLM provider, and this test is about the export, not the
    # chat path.
    import uuid as _uuid

    from models.conversation import Message, MessageRole

    async with session_factory() as session:
        for i in range(messages):
            session.add(
                Message(
                    conversation_id=_uuid.UUID(conv_id),
                    role=MessageRole.user,
                    content=f"message {i}",
                )
            )
            session.add(
                Message(
                    conversation_id=_uuid.UUID(conv_id),
                    role=MessageRole.assistant,
                    content=f"reply {i}",
                )
            )
        await session.commit()
    await client.post(
        "/api/memories/",
        json={"content": "exported memory", "category": "fact"},
        headers=headers,
    )
    await client.post(
        "/api/connectors/",
        json={
            "connector_type": "canvas",
            "display_name": "Exported Canvas",
            "auth_method": "bearer_token",
            "credentials": {
                "base_url": "https://canvas.example.edu",
                "access_token": _SECRET,
            },
            "granted_scopes": ["courses.read"],
            "permission_tier": "user_confirm",
        },
        headers=headers,
    )
    return conv_id


@pytest.mark.asyncio
async def test_export_requires_authentication(client):
    resp = await client.get("/api/auth/export")
    assert resp.status_code in (401, 403)


@pytest.mark.asyncio
async def test_export_is_valid_json_and_contains_the_account(client, session_factory):
    headers = await _account(client)
    await _seed(client, headers, session_factory)

    resp = await client.get("/api/auth/export", headers=headers)
    assert resp.status_code == 200
    assert resp.headers["content-type"].startswith("application/json")
    assert "attachment" in resp.headers.get("content-disposition", "")

    data = json.loads(resp.text)  # would raise on malformed streamed JSON
    assert data["account"]["email"] == "exporter@example.com"
    assert data["exported_at"]
    assert {"conversations", "memories", "connectors", "audit_logs"} <= set(data)


@pytest.mark.asyncio
async def test_export_includes_transcripts_memories_and_connectors(client, session_factory):
    headers = await _account(client, "full@example.com")
    await _seed(client, headers, session_factory, messages=3)

    data = json.loads((await client.get("/api/auth/export", headers=headers)).text)

    assert len(data["conversations"]) == 1
    conversation = data["conversations"][0]
    assert conversation["title"] == "Exported thread"
    contents = [m["content"] for m in conversation["messages"]]
    for i in range(3):
        assert f"message {i}" in contents
    assert [m["content"] for m in data["memories"]] == ["exported memory"]
    assert data["connectors"][0]["display_name"] == "Exported Canvas"
    assert data["connectors"][0]["granted_scopes"] == ["courses.read"]


@pytest.mark.asyncio
async def test_export_never_contains_connector_credentials(client, session_factory):
    headers = await _account(client, "nosecrets@example.com")
    await _seed(client, headers, session_factory)

    resp = await client.get("/api/auth/export", headers=headers)

    # Checked against the raw payload, not the parsed object: a credential
    # leaking through any nested field is still a leak.
    assert _SECRET not in resp.text
    assert "credentials" not in resp.text
    assert "access_token" not in resp.text
    assert "hashed_password" not in resp.text


@pytest.mark.asyncio
async def test_export_is_scoped_to_the_requesting_account(client, session_factory):
    owner = await _account(client, "owner@example.com")
    await _seed(client, owner, session_factory)
    other = await _account(client, "other@example.com")

    data = json.loads((await client.get("/api/auth/export", headers=other)).text)

    assert data["account"]["email"] == "other@example.com"
    assert data["conversations"] == []
    assert data["memories"] == []
    assert data["connectors"] == []
    assert "Exported thread" not in json.dumps(data)


@pytest.mark.asyncio
@pytest.mark.parametrize("batch_size", [1, 2, 3, 5])
async def test_export_streams_correctly_across_batch_boundaries(
    client, session_factory, monkeypatch, batch_size
):
    """The paging loops concatenate JSON by hand, so an off-by-one at a
    batch edge would produce a syntactically broken document. Several batch
    sizes are used so boundaries land at different points in the row set,
    including one that divides the row count exactly."""
    from api.routes import auth as auth_routes

    headers = await _account(client, f"batched{batch_size}@example.com")
    await _seed(client, headers, session_factory, messages=7)
    monkeypatch.setattr(auth_routes, "_EXPORT_BATCH_SIZE", batch_size)

    resp = await client.get("/api/auth/export", headers=headers)

    data = json.loads(resp.text)  # raises if a boundary broke the document
    messages = data["conversations"][0]["messages"]
    assert len(messages) == 14  # 7 user + 7 assistant
    assert [m["content"] for m in messages if m["role"] == "user"] == [
        f"message {i}" for i in range(7)
    ]
    assert len(data["memories"]) == 1


@pytest.mark.asyncio
async def test_export_with_an_empty_account_is_still_valid_json(client):
    headers = await _account(client, "empty@example.com")

    data = json.loads((await client.get("/api/auth/export", headers=headers)).text)

    assert data["conversations"] == []
    assert data["memories"] == []
    assert data["connectors"] == []
    # Registering and logging in are themselves audited, so a brand-new
    # account is not auditless — it holds exactly those account events and
    # no agent activity.
    assert {row["action"] for row in data["audit_logs"]} <= {
        "account_created",
        "login",
    }
