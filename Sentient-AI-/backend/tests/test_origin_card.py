"""Tests for approval cards an unattended run parked (pending_actions.origin):
the origin is stored with the card in every store, approving one runs exactly
that call, records it in the run's conversation with "Done: <tool> ran." and
gives the channel that line, and never resumes a model turn; a card without
an origin still resumes as before.

Why it exists: the scheduled turn that proposed the call is long over when the
owner taps Approve, so resuming a turn would start a new unattended agent
on the owner's tap. In-memory SQLite, a recording executor, and a runtime
whose chat() must not be called.
"""

from __future__ import annotations

import uuid
from types import SimpleNamespace

import pytest
from sqlalchemy import select

from core.config import settings
from services.agent.approvals import DbApprovalStore, InMemoryApprovalStore
from services.agent.runtime import AgentRuntime, PromptGuard
from tests.conftest import make_user


class RecordingExecutor:
    def __init__(self, result=None):
        self.calls = []
        self.result = result or {"ok": True, "result": "reminder set"}

    async def execute(self, tool_name, arguments, user_id, approved=False, *, task_id=None):
        self.calls.append((tool_name, arguments, approved))
        return self.result


class NoChat(AgentRuntime):
    chats = 0

    async def chat(self, *args, **kwargs):  # type: ignore[override]
        NoChat.chats += 1
        raise AssertionError("an origin card must never resume a turn")


class Audit:
    async def log(self, entry):
        return None


@pytest.mark.asyncio
async def test_every_store_keeps_the_origin():
    memory = InMemoryApprovalStore()
    card = await memory.create(
        user_id="u", tool_name="reminders.create", arguments={}, reason="r", origin="schedule:1"
    )
    assert card.origin == "schedule:1"
    assert (await memory.list_pending("u"))[0].origin == "schedule:1"
    plain = await memory.create(user_id="u", tool_name="x.y", arguments={}, reason="r")
    assert plain.origin is None


@pytest.mark.asyncio
async def test_the_database_store_keeps_the_origin(session_factory):
    user, _ = await make_user(session_factory, "origin-db@example.com")
    store = DbApprovalStore(session_factory)
    card = await store.create(
        user_id=str(user.id),
        tool_name="reminders.create",
        arguments={"title": "Study"},
        reason="r",
        ttl_minutes=180,
        origin="trigger:9",
    )
    assert card.origin == "trigger:9"
    outcome, decided = await store.decide(card.action_id, str(user.id), approved=True)
    assert outcome == "ok" and decided.origin == "trigger:9"


async def _setup(session_factory, origin):
    from models.conversation import Conversation

    user, _ = await make_user(session_factory, f"origin-{uuid.uuid4().hex[:6]}@example.com")
    conversation_id = uuid.uuid4()
    async with session_factory() as session:
        session.add(Conversation(id=conversation_id, user_id=user.id, title="Scheduled: Study", origin=origin))
        await session.commit()
    store = DbApprovalStore(session_factory)
    card = await store.create(
        user_id=str(user.id),
        tool_name="reminders.create",
        arguments={"title": "Study", "delay_minutes": 30},
        reason="Set a reminder",
        conversation_id=str(conversation_id),
        ttl_minutes=180,
        origin=origin,
    )
    executor = RecordingExecutor()
    runtime = NoChat(
        config=settings,
        prompt_guard=PromptGuard(),
        tool_executor=executor,
        audit_service=Audit(),
        approval_store=store,
    )
    return user, conversation_id, card, executor, runtime


@pytest.mark.asyncio
async def test_approving_an_origin_card_runs_the_one_call_and_resumes_nothing(session_factory):
    from api.routes.agent import build_decision_applier
    from models.conversation import Message

    NoChat.chats = 0
    user, conversation_id, card, executor, runtime = await _setup(session_factory, "schedule:abc")
    app = SimpleNamespace(state=SimpleNamespace(agent_runtime=runtime, mcp_catalog=None, installation=None))
    decide = build_decision_applier(app, session_factory)
    outcome = await decide(str(user.id), card.action_id, True)
    assert outcome["status"] == "approved"
    assert outcome["summary"] == "Done: reminders.create ran."
    assert [c[0] for c in executor.calls] == ["reminders.create"] and executor.calls[0][2] is True
    assert NoChat.chats == 0
    async with session_factory() as session:
        contents = [
            m.content
            for m in (
                await session.execute(
                    select(Message).where(Message.conversation_id == conversation_id).order_by(Message.created_at)
                )
            )
            .scalars()
            .all()
        ]
    assert contents[0].startswith("[Approved] Executed 'reminders.create'")
    assert contents[-1] == "Done: reminders.create ran."


@pytest.mark.asyncio
async def test_a_failed_origin_call_says_so(session_factory):
    from api.routes.agent import build_decision_applier

    user, _conversation_id, card, executor, runtime = await _setup(session_factory, "schedule:abc")
    executor.result = {"ok": False, "error": "Reminder storage is unavailable"}
    app = SimpleNamespace(state=SimpleNamespace(agent_runtime=runtime, mcp_catalog=None, installation=None))
    outcome = await build_decision_applier(app, session_factory)(str(user.id), card.action_id, True)
    assert outcome["summary"] == "Not done: reminders.create reported an error."


@pytest.mark.asyncio
async def test_denying_an_origin_card_runs_nothing(session_factory):
    from api.routes.agent import build_decision_applier

    user, _conversation_id, card, executor, runtime = await _setup(session_factory, "schedule:abc")
    app = SimpleNamespace(state=SimpleNamespace(agent_runtime=runtime, mcp_catalog=None, installation=None))
    outcome = await build_decision_applier(app, session_factory)(str(user.id), card.action_id, False)
    assert outcome["status"] == "denied" and executor.calls == [] and NoChat.chats == 0


@pytest.mark.asyncio
async def test_the_web_route_returns_the_result_without_the_origin(client, session_factory):
    from main import app
    from tests.conftest import auth_headers

    user, _conversation_id, card, executor, runtime = await _setup(session_factory, "schedule:abc")
    from core.security import create_access_token

    token = create_access_token({"sub": str(user.id), "email": user.email})
    saved = getattr(app.state, "agent_runtime", None)
    app.state.agent_runtime = runtime
    try:
        resp = await client.post(
            f"/api/agent/approvals/{card.action_id}", json={"approved": True}, headers=auth_headers(token)
        )
    finally:
        app.state.agent_runtime = saved
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["approved"] is True and "origin" not in body["result"]
    assert NoChat.chats == 0 and [c[0] for c in executor.calls] == ["reminders.create"]
