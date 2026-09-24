"""Hot-path query-efficiency regression tests.

``get_current_user`` runs on every authenticated request. When the User
relationships were lazy="selectin", authenticating additionally SELECTed
every audit row, connector, conversation, and memory the user owned — and
through Conversation.messages, every message they had ever sent. The cost
grew with account age on every single request, which is exactly the shape
of a bug that passes testing and dies in production.

These tests count the SQL actually emitted, so a future change back to
eager loading fails here instead of quietly degrading production.
"""

from __future__ import annotations

import uuid
from contextlib import contextmanager
from datetime import datetime, timezone

import pytest
from sqlalchemy import event, select

from models.audit import AuditLog, AuditStatus
from models.conversation import Conversation, Message, MessageRole
from models.memory import Memory, MemoryCategory, MemorySource
from tests.conftest import auth_headers


def _audit_row(user_id, action: str) -> AuditLog:
    return AuditLog(
        user_id=user_id,
        timestamp=datetime.now(timezone.utc),
        connector_name="canvas",
        action=action,
        endpoint="/api/v1/courses",
        scope_used="courses.read",
        status=AuditStatus.approved,
        integrity_hash="0" * 64,
        request_id=str(uuid.uuid4()),
    )


def _memory_row(user_id, content: str) -> Memory:
    return Memory(
        user_id=user_id,
        content=content,
        category=MemoryCategory.fact,
        source=MemorySource.user,
    )


@contextmanager
def count_queries(engine):
    """Record every SQL statement executed on *engine* within the block."""
    statements: list[str] = []

    def _before_cursor_execute(_conn, _cursor, statement, *_args):
        statements.append(statement)

    event.listen(engine.sync_engine, "before_cursor_execute", _before_cursor_execute)
    try:
        yield statements
    finally:
        event.remove(
            engine.sync_engine, "before_cursor_execute", _before_cursor_execute
        )


async def _user_with_history(session_factory, email: str, *, rows: int):
    """Create a user carrying a realistic amount of accumulated history."""
    from core.security import create_access_token, hash_password
    from models.user import User

    async with session_factory() as session:
        user = User(email=email, hashed_password=hash_password("password-123"))
        session.add(user)
        await session.flush()

        conversation = Conversation(user_id=user.id, title="History")
        session.add(conversation)
        await session.flush()

        for i in range(rows):
            session.add(_audit_row(user.id, f"action-{i}"))
            session.add(
                Message(
                    conversation_id=conversation.id,
                    role=MessageRole.user,
                    content=f"message-{i}",
                )
            )
            session.add(_memory_row(user.id, f"memory-{i}"))
        await session.commit()
        user_id = user.id

    token = create_access_token(
        {"sub": str(user_id), "email": email, "epoch": 0}
    )
    return user_id, token


@pytest.mark.asyncio
async def test_authentication_does_not_load_user_history(session_factory):
    """Authenticating must cost one SELECT regardless of account history."""
    from services.auth import get_current_user

    _user_id, token = await _user_with_history(
        session_factory, "hot-path@example.com", rows=25
    )

    class _Credentials:
        credentials = token

    engine = session_factory.kw["bind"]
    async with session_factory() as session:
        with count_queries(engine) as statements:
            user = await get_current_user(_Credentials(), session)

    assert user.email == "hot-path@example.com"
    selects = [s for s in statements if s.lstrip().upper().startswith("SELECT")]
    assert len(selects) == 1, (
        "authentication should issue exactly one SELECT (the user row); "
        f"got {len(selects)}:\n" + "\n".join(selects)
    )
    joined = " ".join(selects).lower()
    for table in ("audit_logs", "messages", "memories", "connectors"):
        assert table not in joined, f"authentication loaded {table}"


@pytest.mark.asyncio
async def test_listing_conversations_does_not_load_messages(
    client, session_factory
):
    """The sidebar list has no message data in its response model, so it
    must not pay to load transcripts."""
    resp = await client.post(
        "/api/auth/register",
        json={"email": "lister@example.com", "password": "password-123"},
    )
    assert resp.status_code == 201
    login = await client.post(
        "/api/auth/login",
        json={"email": "lister@example.com", "password": "password-123"},
    )
    headers = auth_headers(login.json()["access_token"])

    conv = await client.post(
        "/api/agent/conversations", json={"title": "C"}, headers=headers
    )
    conv_id = conv.json()["id"]
    async with session_factory() as session:
        for i in range(10):
            session.add(
                Message(
                    conversation_id=uuid.UUID(conv_id),
                    role=MessageRole.user,
                    content=f"m{i}",
                )
            )
        await session.commit()

    engine = session_factory.kw["bind"]
    with count_queries(engine) as statements:
        listing = await client.get("/api/agent/conversations", headers=headers)
    assert listing.status_code == 200

    assert not any(
        "FROM messages" in s or "from messages" in s for s in statements
    ), "listing conversations loaded message rows:\n" + "\n".join(statements)


@pytest.mark.asyncio
async def test_conversation_detail_still_returns_messages(client):
    """The efficiency work must not cost the detail endpoint its transcript."""
    await client.post(
        "/api/auth/register",
        json={"email": "detail@example.com", "password": "password-123"},
    )
    login = await client.post(
        "/api/auth/login",
        json={"email": "detail@example.com", "password": "password-123"},
    )
    headers = auth_headers(login.json()["access_token"])

    conv = await client.post(
        "/api/agent/conversations", json={"title": "D"}, headers=headers
    )
    conv_id = conv.json()["id"]

    detail = await client.get(
        f"/api/agent/conversations/{conv_id}", headers=headers
    )
    assert detail.status_code == 200
    assert "messages" in detail.json()


@pytest.mark.asyncio
async def test_account_deletion_cascades_to_all_owned_rows(
    client, session_factory
):
    """Deleting an account must remove its data via the database's ON
    DELETE CASCADE — the ORM no longer loads these rows to do it itself
    (passive_deletes=True), so this verifies the database really does."""
    # The first account owns the install and may not delete itself, so the
    # account under test is the second one.
    await client.post(
        "/api/auth/register",
        json={"email": "owner@example.com", "password": "password-123"},
    )
    await client.post(
        "/api/auth/register",
        json={"email": "deleter@example.com", "password": "password-123"},
    )
    login = await client.post(
        "/api/auth/login",
        json={"email": "deleter@example.com", "password": "password-123"},
    )
    headers = auth_headers(login.json()["access_token"])

    conv = await client.post(
        "/api/agent/conversations", json={"title": "Doomed"}, headers=headers
    )
    conv_id = uuid.UUID(conv.json()["id"])
    me = await client.get("/api/auth/me", headers=headers)
    user_id = uuid.UUID(me.json()["id"])

    async with session_factory() as session:
        session.add(
            Message(
                conversation_id=conv_id,
                role=MessageRole.user,
                content="goodbye",
            )
        )
        session.add(_memory_row(user_id, "remember me"))
        session.add(_audit_row(user_id, "something"))
        await session.commit()

    # Destroying an account re-authenticates: a bearer token alone is not
    # evidence the holder owns it. httpx needs the explicit request form
    # because DELETE bodies are not supported by the shorthand.
    resp = await client.request(
        "DELETE",
        "/api/auth/account",
        headers=headers,
        json={"current_password": "password-123"},
    )
    assert resp.status_code == 204

    async with session_factory() as session:
        for model, column in (
            (Conversation, Conversation.user_id),
            (Memory, Memory.user_id),
            (AuditLog, AuditLog.user_id),
        ):
            rows = await session.execute(select(model).where(column == user_id))
            assert rows.scalars().all() == [], f"{model.__name__} rows survived"
        messages = await session.execute(
            select(Message).where(Message.conversation_id == conv_id)
        )
        assert messages.scalars().all() == [], "messages survived"
