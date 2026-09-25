"""Tests for resume-after-approval: approving an action runs one more agent turn
over the updated transcript so the assistant actually uses the tool result, and
that a resume failure never fails the approval itself.

Why it exists: Approving an action used to dead-end: the tool ran but the user
had to send another message to get the answer it was fetched for; the resume is
best-effort so it must never turn an already-recorded approval into a failed
request.

Resume-after-approval.

Approving an action used to dead-end: the tool ran and its result was
written to the transcript, but the user had to send another message just to
get the answer the tool was fetched for. The approval route now runs one
more agent turn over the updated transcript so the assistant actually uses
the result and finishes the task.

The resume is best effort by design — the approval itself already happened
and is recorded, so a resume failure must never fail the request.
"""

from __future__ import annotations

import uuid

import pytest

from tests.conftest import auth_headers, make_user, use_provider


class RecordingExecutor:
    def __init__(self, result=None):
        self.calls = []
        self._result = result if result is not None else {"ok": True, "result": "done"}

    async def execute(self, tool_name, arguments, user_id, approved=False, *, task_id=None):
        self.calls.append({"tool": tool_name, "approved": approved})
        return self._result


class RecordingAudit:
    def __init__(self):
        self.entries = []

    async def log(self, entry):
        self.entries.append(entry)


class ScriptedProvider:
    """Returns scripted responses; records the message history it was sent."""

    def __init__(self, responses):
        self._responses = list(responses)
        self.calls = []

    async def complete(self, messages, tools=None):
        from services.agent.providers import LLMResponse

        self.calls.append(list(messages))
        if self._responses:
            return self._responses.pop(0)
        return LLMResponse(content="fallback")

    async def stream(self, messages, tools=None):
        yield "done"


class ExplodingProvider:
    async def complete(self, messages, tools=None):
        raise RuntimeError("provider is down")

    async def stream(self, messages, tools=None):
        yield ""


def _runtime(session_factory, provider, executor=None):
    from core.config import settings
    from services.agent.approvals import DbApprovalStore
    from services.agent.runtime import AgentRuntime
    from services.agent.tool_registry import RuntimePermissionAdapter

    executor = executor or RecordingExecutor()
    runtime = AgentRuntime(
        config=settings,
        permission_engine=RuntimePermissionAdapter(),
        tool_executor=executor,
        audit_service=RecordingAudit(),
        approval_store=DbApprovalStore(session_factory=session_factory),
    )
    use_provider(runtime, provider)
    return runtime, executor


async def _park_action(session_factory, user, conv_id):
    from services.agent.approvals import DbApprovalStore

    store = DbApprovalStore(session_factory=session_factory)
    return await store.create(
        user_id=str(user.id),
        tool_name="google_workspace.send_email",
        arguments={"to": "prof@school.edu", "subject": "s", "body": "b"},
        reason="needs approval",
        conversation_id=conv_id,
    )


@pytest.mark.asyncio
async def test_approval_resumes_the_task(client, session_factory):
    """After approval the assistant produces a follow-up answer that uses the
    tool result, without the user sending another message."""
    from api.routes import agent as agent_routes
    from main import app
    from services.agent.providers import LLMResponse

    provider = ScriptedProvider(
        [LLMResponse(content="Sent it — your professor has the message now.")]
    )
    runtime, executor = _runtime(
        session_factory, provider, RecordingExecutor(result={"ok": True, "result": "delivered"})
    )
    app.dependency_overrides[agent_routes.get_runtime] = lambda: runtime
    try:
        user, token = await make_user(session_factory, "resume@example.com")
        conv = (
            await client.post(
                "/api/agent/conversations", headers=auth_headers(token), json={}
            )
        ).json()
        action = await _park_action(session_factory, user, conv["id"])

        decided = await client.post(
            f"/api/agent/approvals/{action.action_id}",
            headers=auth_headers(token),
            json={"approved": True},
        )
        assert decided.status_code == 200
        assert executor.calls == [
            {"tool": "google_workspace.send_email", "approved": True}
        ]

        messages = (
            await client.get(
                f"/api/agent/conversations/{conv['id']}", headers=auth_headers(token)
            )
        ).json()["messages"]

        # Two assistant messages: the recorded outcome, then the resumed answer.
        assert len(messages) == 2
        assert "[Approved] Executed" in messages[0]["content"]
        assert messages[1]["content"] == "Sent it — your professor has the message now."

        # The resumed turn saw the tool outcome in its history.
        assert provider.calls, "the runtime never called the provider to resume"
        history = provider.calls[0]
        assert any("[Approved] Executed" in str(m.get("content", "")) for m in history)
    finally:
        app.dependency_overrides.pop(agent_routes.get_runtime, None)


@pytest.mark.asyncio
async def test_the_resumed_turn_gets_the_result_whole_as_a_user_turn(client, session_factory):
    """The resumed turn's history ends on a user turn carrying the approved
    call's result in the runtime's tool-result envelope, whole — not on the
    transcript's assistant row, which is cut at 2000 characters and, as the
    last message, reads to a provider as the model's own unfinished turn."""
    from api.routes import agent as agent_routes
    from main import app
    from models.conversation import Message
    from services.agent.providers import LLMResponse
    from sqlalchemy import select

    provider = ScriptedProvider(
        [LLMResponse(content="Drafted; approve the card."), LLMResponse(content="Sent.")]
    )
    big = {"ok": True, "result": "delivered", "thread": "x" * 3000 + " LAST-WORD"}
    runtime, _ = _runtime(session_factory, provider, RecordingExecutor(result=big))
    app.dependency_overrides[agent_routes.get_runtime] = lambda: runtime
    try:
        user, token = await make_user(session_factory, "resume-whole@example.com")
        conv = (
            await client.post(
                "/api/agent/conversations", headers=auth_headers(token), json={}
            )
        ).json()
        await client.post(
            f"/api/agent/conversations/{conv['id']}/messages",
            headers=auth_headers(token),
            json={"content": "email my prof"},
        )
        action = await _park_action(session_factory, user, conv["id"])
        decided = await client.post(
            f"/api/agent/approvals/{action.action_id}",
            headers=auth_headers(token),
            json={"approved": True},
        )
        assert decided.status_code == 200

        history = [m for m in provider.calls[-1] if m.get("role") != "system"]
        assert history[-1]["role"] == "user"
        assert history[-1]["content"].startswith("[Approved] Executed 'google_workspace.send_email'.")
        assert "LAST-WORD" in history[-1]["content"], "the result was cut"
        assert 'name="google_workspace.send_email"' in history[-1]["content"]
        # The decision row is not in the model's history as an assistant turn.
        assert not any(
            m["role"] == "assistant" and "[Approved] Executed" in str(m["content"])
            for m in history
        )
        # It is still the transcript's record of the decision.
        async with session_factory() as session:
            rows = list(
                (
                    await session.execute(
                        select(Message)
                        .where(Message.conversation_id == uuid.UUID(conv["id"]))
                        .order_by(Message.created_at)
                    )
                ).scalars()
            )
        assert any(r.content.startswith("[Approved] Executed") for r in rows)
        assert rows[-1].content == "Sent."
    finally:
        app.dependency_overrides.pop(agent_routes.get_runtime, None)


@pytest.mark.asyncio
async def test_resume_failure_does_not_fail_the_approval(client, session_factory):
    """The approval already happened and the tool already ran, so a broken
    provider must not turn the request into an error or lose the record."""
    from api.routes import agent as agent_routes
    from main import app

    runtime, executor = _runtime(session_factory, ExplodingProvider())
    app.dependency_overrides[agent_routes.get_runtime] = lambda: runtime
    try:
        user, token = await make_user(session_factory, "resumefail@example.com")
        conv = (
            await client.post(
                "/api/agent/conversations", headers=auth_headers(token), json={}
            )
        ).json()
        action = await _park_action(session_factory, user, conv["id"])

        decided = await client.post(
            f"/api/agent/approvals/{action.action_id}",
            headers=auth_headers(token),
            json={"approved": True},
        )
        # Still a success: the action was approved and executed.
        assert decided.status_code == 200
        assert decided.json()["approved"] is True
        assert executor.calls == [
            {"tool": "google_workspace.send_email", "approved": True}
        ]

        # The outcome message is still in the transcript; just no resumed turn.
        messages = (
            await client.get(
                f"/api/agent/conversations/{conv['id']}", headers=auth_headers(token)
            )
        ).json()["messages"]
        assert len(messages) == 1
        assert "[Approved] Executed" in messages[0]["content"]
    finally:
        app.dependency_overrides.pop(agent_routes.get_runtime, None)


@pytest.mark.asyncio
async def test_denial_does_not_resume(client, session_factory):
    """A denied action must not trigger a follow-up turn — the user said no."""
    from api.routes import agent as agent_routes
    from main import app
    from services.agent.providers import LLMResponse

    provider = ScriptedProvider([LLMResponse(content="should not be produced")])
    runtime, executor = _runtime(session_factory, provider)
    app.dependency_overrides[agent_routes.get_runtime] = lambda: runtime
    try:
        user, token = await make_user(session_factory, "resumedeny@example.com")
        conv = (
            await client.post(
                "/api/agent/conversations", headers=auth_headers(token), json={}
            )
        ).json()
        action = await _park_action(session_factory, user, conv["id"])

        decided = await client.post(
            f"/api/agent/approvals/{action.action_id}",
            headers=auth_headers(token),
            json={"approved": False},
        )
        assert decided.status_code == 200
        assert executor.calls == []
        assert provider.calls == [], "a denial must not run another agent turn"

        messages = (
            await client.get(
                f"/api/agent/conversations/{conv['id']}", headers=auth_headers(token)
            )
        ).json()["messages"]
        assert len(messages) == 1
        assert "[Denied]" in messages[0]["content"]
    finally:
        app.dependency_overrides.pop(agent_routes.get_runtime, None)
