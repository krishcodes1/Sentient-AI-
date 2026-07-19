"""Conversation lifecycle + per-user settings route tests.

Covers the audit fixes:

- PATCH /agent/conversations/{id} (rename, owner-scoped, 1-200 chars)
- DELETE /agent/conversations/{id} (owner-scoped, cascades messages, 204)
- Conversation.updated_at bumps whenever a message is persisted, so
  newest-first ordering reflects real activity.
- Per-user rate_limit enforcement on send_message (429).
- Per-user llm_provider/llm_model: an unconfigured provider yields a
  clear 502 via ProviderError.
- Resume-after-approval: deciding an approval persists an assistant
  Message into the originating conversation (approve AND deny), bumps
  updated_at, and keeps returning the result in the response.
"""

from __future__ import annotations

import uuid

import pytest
from sqlalchemy import select

from tests.conftest import auth_headers, make_user


async def _set_user_fields(session_factory, user_id, **fields):
    from models.user import User

    async with session_factory() as session:
        row = await session.get(User, user_id)
        for key, value in fields.items():
            setattr(row, key, value)
        await session.commit()


def _fake_runtime_override():
    from services.agent.runtime import AgentResponse

    class FakeRuntime:
        async def chat(self, messages, tools, user_id, conversation_id=None, **kwargs):
            return AgentResponse(content="ok")

    return lambda: FakeRuntime()


class RecordingExecutor:
    def __init__(self, result=None):
        self.calls = []
        self._result = result if result is not None else {"ok": True, "result": "sent"}

    async def execute(self, tool_name, arguments, user_id, approved=False):
        self.calls.append({"tool": tool_name, "approved": approved})
        return self._result


class RecordingAudit:
    def __init__(self):
        self.entries = []

    async def log(self, entry):
        self.entries.append(entry)


def _real_runtime(session_factory, executor=None):
    from core.config import settings
    from services.agent.approvals import DbApprovalStore
    from services.agent.runtime import AgentRuntime
    from services.agent.tool_registry import RuntimePermissionAdapter

    executor = executor or RecordingExecutor()
    return (
        AgentRuntime(
            config=settings,
            permission_engine=RuntimePermissionAdapter(),
            tool_executor=executor,
            audit_service=RecordingAudit(),
            approval_store=DbApprovalStore(session_factory=session_factory),
        ),
        executor,
    )


# ---------------------------------------------------------------------------
# PATCH /conversations/{id}
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_lifecycle_routes_require_auth(client):
    some_id = str(uuid.uuid4())
    patched = await client.patch(
        f"/api/agent/conversations/{some_id}", json={"title": "x"}
    )
    assert patched.status_code in (401, 403)
    deleted = await client.delete(f"/api/agent/conversations/{some_id}")
    assert deleted.status_code in (401, 403)


@pytest.mark.asyncio
async def test_rename_conversation(client, session_factory):
    _, token = await make_user(session_factory)
    created = await client.post(
        "/api/agent/conversations",
        headers=auth_headers(token),
        json={"title": "Original"},
    )
    conv = created.json()

    renamed = await client.patch(
        f"/api/agent/conversations/{conv['id']}",
        headers=auth_headers(token),
        json={"title": "  Renamed chat  "},
    )
    assert renamed.status_code == 200
    body = renamed.json()
    assert body["title"] == "Renamed chat"  # stripped
    assert body["updated_at"] >= conv["updated_at"]

    fetched = await client.get(
        f"/api/agent/conversations/{conv['id']}", headers=auth_headers(token)
    )
    assert fetched.json()["title"] == "Renamed chat"


@pytest.mark.asyncio
async def test_rename_conversation_validates_title(client, session_factory):
    _, token = await make_user(session_factory)
    created = await client.post(
        "/api/agent/conversations", headers=auth_headers(token), json={}
    )
    conv_id = created.json()["id"]

    # Empty and whitespace-only titles are rejected.
    assert (
        await client.patch(
            f"/api/agent/conversations/{conv_id}",
            headers=auth_headers(token),
            json={"title": ""},
        )
    ).status_code == 422
    assert (
        await client.patch(
            f"/api/agent/conversations/{conv_id}",
            headers=auth_headers(token),
            json={"title": "   "},
        )
    ).status_code == 422
    # Over 200 chars is rejected.
    assert (
        await client.patch(
            f"/api/agent/conversations/{conv_id}",
            headers=auth_headers(token),
            json={"title": "x" * 201},
        )
    ).status_code == 422


@pytest.mark.asyncio
async def test_rename_foreign_conversation_404(client, session_factory):
    _, token_a = await make_user(session_factory, "a@example.com")
    _, token_b = await make_user(session_factory, "b@example.com")
    created = await client.post(
        "/api/agent/conversations", headers=auth_headers(token_a), json={}
    )
    conv_id = created.json()["id"]

    response = await client.patch(
        f"/api/agent/conversations/{conv_id}",
        headers=auth_headers(token_b),
        json={"title": "hijacked"},
    )
    assert response.status_code == 404


# ---------------------------------------------------------------------------
# DELETE /conversations/{id}
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_delete_conversation_cascades_messages(client, session_factory):
    from api.routes import agent as agent_routes
    from main import app
    from models.conversation import Message

    app.dependency_overrides[agent_routes.get_runtime] = _fake_runtime_override()
    try:
        _, token = await make_user(session_factory)
        created = await client.post(
            "/api/agent/conversations", headers=auth_headers(token), json={}
        )
        conv_id = created.json()["id"]

        sent = await client.post(
            f"/api/agent/conversations/{conv_id}/messages",
            headers=auth_headers(token),
            json={"content": "hello"},
        )
        assert sent.status_code == 201

        deleted = await client.delete(
            f"/api/agent/conversations/{conv_id}", headers=auth_headers(token)
        )
        assert deleted.status_code == 204

        assert (
            await client.get(
                f"/api/agent/conversations/{conv_id}", headers=auth_headers(token)
            )
        ).status_code == 404

        async with session_factory() as session:
            rows = await session.execute(
                select(Message).where(Message.conversation_id == uuid.UUID(conv_id))
            )
            assert rows.scalars().all() == []
    finally:
        app.dependency_overrides.pop(agent_routes.get_runtime, None)


@pytest.mark.asyncio
async def test_delete_foreign_conversation_404(client, session_factory):
    _, token_a = await make_user(session_factory, "a@example.com")
    _, token_b = await make_user(session_factory, "b@example.com")
    created = await client.post(
        "/api/agent/conversations", headers=auth_headers(token_a), json={}
    )
    conv_id = created.json()["id"]

    assert (
        await client.delete(
            f"/api/agent/conversations/{conv_id}", headers=auth_headers(token_b)
        )
    ).status_code == 404
    # Still there for the owner.
    assert (
        await client.get(
            f"/api/agent/conversations/{conv_id}", headers=auth_headers(token_a)
        )
    ).status_code == 200


# ---------------------------------------------------------------------------
# updated_at reflects activity
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_sending_a_message_bumps_updated_at_and_reorders_list(
    client, session_factory
):
    from api.routes import agent as agent_routes
    from main import app

    app.dependency_overrides[agent_routes.get_runtime] = _fake_runtime_override()
    try:
        _, token = await make_user(session_factory)
        first = (
            await client.post(
                "/api/agent/conversations",
                headers=auth_headers(token),
                json={"title": "older"},
            )
        ).json()
        second = (
            await client.post(
                "/api/agent/conversations",
                headers=auth_headers(token),
                json={"title": "newer"},
            )
        ).json()

        # Newest-created first initially.
        listing = (
            await client.get("/api/agent/conversations", headers=auth_headers(token))
        ).json()
        assert [c["id"] for c in listing] == [second["id"], first["id"]]

        # Activity in the older conversation bubbles it to the top.
        sent = await client.post(
            f"/api/agent/conversations/{first['id']}/messages",
            headers=auth_headers(token),
            json={"content": "wake up"},
        )
        assert sent.status_code == 201

        listing = (
            await client.get("/api/agent/conversations", headers=auth_headers(token))
        ).json()
        assert [c["id"] for c in listing] == [first["id"], second["id"]]
        bumped = next(c for c in listing if c["id"] == first["id"])
        assert bumped["updated_at"] > first["updated_at"]
    finally:
        app.dependency_overrides.pop(agent_routes.get_runtime, None)


# ---------------------------------------------------------------------------
# Per-user rate limit
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_user_rate_limit_enforced_on_send_message(client, session_factory):
    from api.routes import agent as agent_routes
    from main import app

    app.dependency_overrides[agent_routes.get_runtime] = _fake_runtime_override()
    try:
        user, token = await make_user(session_factory, "limited@example.com")
        await _set_user_fields(session_factory, user.id, rate_limit=2)

        created = await client.post(
            "/api/agent/conversations", headers=auth_headers(token), json={}
        )
        conv_id = created.json()["id"]

        for _ in range(2):
            ok = await client.post(
                f"/api/agent/conversations/{conv_id}/messages",
                headers=auth_headers(token),
                json={"content": "hi"},
            )
            assert ok.status_code == 201

        throttled = await client.post(
            f"/api/agent/conversations/{conv_id}/messages",
            headers=auth_headers(token),
            json={"content": "hi again"},
        )
        assert throttled.status_code == 429
        assert "2 agent messages per minute" in throttled.json()["detail"]
    finally:
        app.dependency_overrides.pop(agent_routes.get_runtime, None)


# ---------------------------------------------------------------------------
# Per-user LLM provider selection (route-level)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_unconfigured_user_provider_returns_502(
    client, session_factory, monkeypatch
):
    from api.routes import agent as agent_routes
    from core.config import settings
    from main import app

    runtime, _ = _real_runtime(session_factory)
    app.dependency_overrides[agent_routes.get_runtime] = lambda: runtime
    monkeypatch.setattr(settings, "OPENAI_API_KEY", None)
    try:
        user, token = await make_user(session_factory, "gptfan@example.com")
        await _set_user_fields(
            session_factory, user.id, llm_provider="openai", llm_model="gpt-4o"
        )

        created = await client.post(
            "/api/agent/conversations", headers=auth_headers(token), json={}
        )
        conv_id = created.json()["id"]

        response = await client.post(
            f"/api/agent/conversations/{conv_id}/messages",
            headers=auth_headers(token),
            json={"content": "hello"},
        )
        assert response.status_code == 502
        assert "openai" in response.json()["detail"]
        assert "not configured" in response.json()["detail"]
    finally:
        app.dependency_overrides.pop(agent_routes.get_runtime, None)


# ---------------------------------------------------------------------------
# Resume-after-approval: the decision is persisted into the conversation
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_approving_action_persists_result_message(client, session_factory):
    from api.routes import agent as agent_routes
    from main import app
    from services.agent.approvals import DbApprovalStore

    executor = RecordingExecutor(result={"ok": True, "result": "email sent to x@y.com"})
    runtime, _ = _real_runtime(session_factory, executor=executor)
    app.dependency_overrides[agent_routes.get_runtime] = lambda: runtime
    try:
        user, token = await make_user(session_factory)
        created = await client.post(
            "/api/agent/conversations", headers=auth_headers(token), json={}
        )
        conv = created.json()

        store = DbApprovalStore(session_factory=session_factory)
        action = await store.create(
            user_id=str(user.id),
            tool_name="google_workspace.send_email",
            arguments={"to": "x@y.com", "subject": "s", "body": "b"},
            reason="needs approval",
            conversation_id=conv["id"],
        )

        decided = await client.post(
            f"/api/agent/approvals/{action.action_id}",
            headers=auth_headers(token),
            json={"approved": True},
        )
        assert decided.status_code == 200
        body = decided.json()
        assert body["approved"] is True
        # The result is still returned to the caller...
        assert body["result"]["tool"] == "google_workspace.send_email"
        assert body["result"]["result"]["ok"] is True
        # ...and the internal routing key is not leaked.
        assert "conversation_id" not in body["result"]
        assert executor.calls == [
            {"tool": "google_workspace.send_email", "approved": True}
        ]

        # The outcome is now part of the conversation transcript.
        fetched = (
            await client.get(
                f"/api/agent/conversations/{conv['id']}", headers=auth_headers(token)
            )
        ).json()
        assert len(fetched["messages"]) == 1
        message = fetched["messages"][0]
        assert message["role"] == "assistant"
        assert "[Approved] Executed 'google_workspace.send_email'" in message["content"]
        assert "email sent to x@y.com" in message["content"]
        assert message["tool_calls"][0]["approved"] is True
        # Activity timestamp bumped.
        assert fetched["updated_at"] > conv["updated_at"]
    finally:
        app.dependency_overrides.pop(agent_routes.get_runtime, None)


@pytest.mark.asyncio
async def test_denying_action_persists_denial_message(client, session_factory):
    from api.routes import agent as agent_routes
    from main import app
    from services.agent.approvals import DbApprovalStore

    executor = RecordingExecutor()
    runtime, _ = _real_runtime(session_factory, executor=executor)
    app.dependency_overrides[agent_routes.get_runtime] = lambda: runtime
    try:
        user, token = await make_user(session_factory)
        created = await client.post(
            "/api/agent/conversations", headers=auth_headers(token), json={}
        )
        conv_id = created.json()["id"]

        store = DbApprovalStore(session_factory=session_factory)
        action = await store.create(
            user_id=str(user.id),
            tool_name="canvas.submit_assignment",
            arguments={},
            reason="needs approval",
            conversation_id=conv_id,
        )

        decided = await client.post(
            f"/api/agent/approvals/{action.action_id}",
            headers=auth_headers(token),
            json={"approved": False},
        )
        assert decided.status_code == 200
        assert executor.calls == []

        fetched = (
            await client.get(
                f"/api/agent/conversations/{conv_id}", headers=auth_headers(token)
            )
        ).json()
        assert len(fetched["messages"]) == 1
        assert "[Denied]" in fetched["messages"][0]["content"]
        assert "canvas.submit_assignment" in fetched["messages"][0]["content"]
    finally:
        app.dependency_overrides.pop(agent_routes.get_runtime, None)


@pytest.mark.asyncio
async def test_approval_result_message_is_compressed(client, session_factory):
    """A huge tool result is stored as a compact (~2000 char) rendering."""
    from api.routes import agent as agent_routes
    from main import app
    from services.agent.approvals import DbApprovalStore

    executor = RecordingExecutor(result={"ok": True, "result": "Z" * 20_000})
    runtime, _ = _real_runtime(session_factory, executor=executor)
    app.dependency_overrides[agent_routes.get_runtime] = lambda: runtime
    try:
        user, token = await make_user(session_factory)
        created = await client.post(
            "/api/agent/conversations", headers=auth_headers(token), json={}
        )
        conv_id = created.json()["id"]

        store = DbApprovalStore(session_factory=session_factory)
        action = await store.create(
            user_id=str(user.id),
            tool_name="google_workspace.send_email",
            arguments={},
            reason="needs approval",
            conversation_id=conv_id,
        )

        decided = await client.post(
            f"/api/agent/approvals/{action.action_id}",
            headers=auth_headers(token),
            json={"approved": True},
        )
        assert decided.status_code == 200

        fetched = (
            await client.get(
                f"/api/agent/conversations/{conv_id}", headers=auth_headers(token)
            )
        ).json()
        content = fetched["messages"][0]["content"]
        assert "chars truncated" in content
        assert len(content) < 3000
    finally:
        app.dependency_overrides.pop(agent_routes.get_runtime, None)
