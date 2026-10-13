"""Tests for the approval guard: a canvas.submit_assignment card parked before
tutor mode came on cannot be approved once the chat is in tutor mode (by the
person's /tutor on, or by an owner lock); the tap closes the card as denied,
nothing runs, the refusal is audited under policy tutor_mode and noted in the
chat. Other cards, and the same card in a chat that is not in tutor mode, are
approved as before.

Why it exists: the offer and dispatch gates only see calls made while the
mode is on. A submission card raised a minute earlier would otherwise be one
tap away from handing in the work the mode exists to protect.
"""

from __future__ import annotations

import uuid

import pytest
from sqlalchemy import select, update

from core.config import settings
from models.audit import AuditLog
from models.conversation import Conversation, Message
from models.pending_action import PendingAction, PendingActionStatus
from models.tutor_lock import TutorLock
from services.agent.approvals import DbApprovalStore
from services.agent.runtime import AgentRuntime, PermissionEngine
from services.tutor.policy import APPROVAL_REFUSAL
from services.tutor.state import EngagedLock, TutorState
from tests.conftest import auth_headers, make_user, use_provider
from tests.test_agent_runtime_vision import RecordingAudit, RecordingGuard, RecordingProvider


class RecordingExecutor:
    def __init__(self) -> None:
        self.calls: list[str] = []

    async def execute(self, tool_name, arguments, user_id, approved=False, *, task_id=None):
        self.calls.append(tool_name)
        return {"ok": True, "result": "submitted"}


@pytest.fixture
def wired(session_factory):
    from api.routes import agent as agent_routes
    from main import app

    executor = RecordingExecutor()
    runtime = AgentRuntime(
        config=settings,
        permission_engine=PermissionEngine(),
        prompt_guard=RecordingGuard(),
        audit_service=RecordingAudit(),
        tool_executor=executor,
        approval_store=DbApprovalStore(session_factory),
    )
    use_provider(runtime, RecordingProvider())
    app.dependency_overrides[agent_routes.get_runtime] = lambda: runtime
    yield runtime, executor
    app.dependency_overrides.pop(agent_routes.get_runtime, None)


async def _setup(client, session_factory, runtime, tool_name="canvas.submit_assignment"):
    user, token = await make_user(session_factory, f"{uuid.uuid4().hex[:8]}@example.com")
    headers = auth_headers(token)
    conv_id = (await client.post("/api/agent/conversations", json={"title": "HW"}, headers=headers)).json()["id"]
    card = await runtime._approvals.create(
        user_id=str(user.id),
        tool_name=tool_name,
        arguments={"course_id": "5", "assignment_id": "9", "body": "my essay"},
        reason="Submit the essay",
        conversation_id=conv_id,
    )
    return user, headers, conv_id, card


@pytest.mark.asyncio
async def test_a_submission_card_cannot_be_approved_after_tutor_on(client, session_factory, wired):
    runtime, executor = wired
    user, headers, conv_id, card = await _setup(client, session_factory, runtime)

    await client.post(f"/api/agent/conversations/{conv_id}/messages", json={"content": "/tutor on"}, headers=headers)
    resp = await client.post(f"/api/agent/approvals/{card.action_id}", json={"approved": True}, headers=headers)

    assert resp.status_code == 404
    assert resp.json()["detail"] == APPROVAL_REFUSAL
    assert executor.calls == []
    async with session_factory() as session:
        row = await session.get(PendingAction, uuid.UUID(card.action_id))
        assert row.status == PendingActionStatus.denied  # closed: it cannot be tapped again
        audit = (
            await session.execute(
                select(AuditLog).where(AuditLog.user_id == user.id, AuditLog.action == "submit_assignment")
            )
        ).scalars().all()
        messages = (
            await session.execute(
                select(Message.content).where(Message.conversation_id == uuid.UUID(conv_id)).order_by(Message.created_at)
            )
        ).scalars().all()
    blocked = [a for a in audit if a.reasoning_chain.get("policy") == "tutor_mode"]
    assert len(blocked) == 1 and blocked[0].reasoning_chain["event"] == "tool_blocked"
    assert blocked[0].reasoning_chain["action_id"] == card.action_id
    assert messages[-1].startswith("[Refused] The pending action 'canvas.submit_assignment' was not executed.")
    second = await client.post(f"/api/agent/approvals/{card.action_id}", json={"approved": True}, headers=headers)
    assert second.status_code == 404 and executor.calls == []


@pytest.mark.asyncio
async def test_an_engaged_lock_also_refuses_it(client, session_factory, wired):
    runtime, executor = wired
    _user, headers, conv_id, card = await _setup(client, session_factory, runtime)
    async with session_factory() as session:
        lock = TutorLock(scope="course", label="MATH 221", canvas_course_id="5", course_code="MATH 221")
        session.add(lock)
        await session.flush()
        await session.execute(
            update(Conversation)
            .where(Conversation.id == uuid.UUID(conv_id))
            .values(
                tutor_state=TutorState(
                    lock=EngagedLock(str(lock.id), "MATH 221", "tool_args", "2026-09-30T12:00:00+00:00")
                ).to_stored()
            )
        )
        await session.commit()

    resp = await client.post(f"/api/agent/approvals/{card.action_id}", json={"approved": True}, headers=headers)
    assert resp.status_code == 404 and executor.calls == []


@pytest.mark.asyncio
async def test_outside_tutor_mode_the_card_is_approved_as_before(client, session_factory, wired):
    runtime, executor = wired
    _user, headers, _conv_id, card = await _setup(client, session_factory, runtime)
    resp = await client.post(f"/api/agent/approvals/{card.action_id}", json={"approved": True}, headers=headers)
    assert resp.status_code == 200, resp.text
    assert executor.calls == ["canvas.submit_assignment"]


@pytest.mark.asyncio
async def test_other_cards_and_denials_are_untouched_in_tutor_mode(client, session_factory, wired):
    runtime, executor = wired
    _user, headers, conv_id, card = await _setup(
        client, session_factory, runtime, tool_name="google_workspace.send_email"
    )
    await client.post(f"/api/agent/conversations/{conv_id}/messages", json={"content": "/tutor on"}, headers=headers)
    resp = await client.post(f"/api/agent/approvals/{card.action_id}", json={"approved": True}, headers=headers)
    assert resp.status_code == 200 and executor.calls == ["google_workspace.send_email"]

    submit = await runtime._approvals.create(
        user_id=card.user_id,
        tool_name="canvas.submit_assignment",
        arguments={"course_id": "5"},
        reason="Submit",
        conversation_id=conv_id,
    )
    denied = await client.post(f"/api/agent/approvals/{submit.action_id}", json={"approved": False}, headers=headers)
    assert denied.status_code == 200 and denied.json()["approved"] is False
