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


# A checkout result as the toolkit returns it: the confirmation page as a
# JPEG data URL for the person (long enough to be redacted for the model).
JPEG = "data:image/jpeg;base64," + "/9j/4AAQ" * 100
SVG = "data:image/svg+xml;base64," + "PHN2Zz4=" * 100
CHECKOUT_RESULT = {
    "ok": True,
    "merchant": "shop.example.com",
    "amount": "23.40",
    "currency": "USD",
    "confirmation_text_summary": "Thank you Order number 8841",
    "summary": "[step 3] checkout → shop.example.com/order-confirmed",
    "mode": "private",
}


async def _park_checkout(session_factory, user, conv_id):
    from services.agent.approvals import DbApprovalStore

    store = DbApprovalStore(session_factory=session_factory)
    return await store.create(
        user_id=str(user.id),
        tool_name="browser.checkout",
        arguments={
            "merchant": "shop.example.com",
            "_checkout": {"checkout_id": "chk-1", "host": "shop.example.com", "amount_usd": "23.40"},
        },
        reason="Pay $23.40 to shop.example.com with Visa ····4242",
        conversation_id=conv_id,
    )


async def _decided_checkout(client, session_factory, provider, result, email):
    """Park a checkout card in a fresh conversation and approve it over
    HTTP. Returns (the decision response body, the model's last request,
    the transcript rows)."""
    from api.routes import agent as agent_routes
    from main import app
    from models.conversation import Message
    from sqlalchemy import select

    runtime, _ = _runtime(session_factory, provider, RecordingExecutor(result=result))
    app.dependency_overrides[agent_routes.get_runtime] = lambda: runtime
    try:
        user, token = await make_user(session_factory, email)
        conv = (
            await client.post("/api/agent/conversations", headers=auth_headers(token), json={})
        ).json()
        await client.post(
            f"/api/agent/conversations/{conv['id']}/messages",
            headers=auth_headers(token),
            json={"content": "buy the ticket"},
        )
        action = await _park_checkout(session_factory, user, conv["id"])
        decided = await client.post(
            f"/api/agent/approvals/{action.action_id}",
            headers=auth_headers(token),
            json={"approved": True},
        )
        assert decided.status_code == 200, decided.text
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
        return decided.json(), provider.calls[-1], rows
    finally:
        app.dependency_overrides.pop(agent_routes.get_runtime, None)


@pytest.mark.asyncio
async def test_the_web_gets_the_approved_calls_confirmation_picture(client, session_factory):
    """The confirmation screenshot of an approved checkout reaches the web
    chat: on the decision response, keyed to the transcript row that
    records the decision (the row itself keeps only the placeholder), and
    the model is told it was delivered."""
    from services.agent.providers import LLMResponse
    from services.agent.runtime import IMAGE_DELIVERED, IMAGE_NOT_SHOWN

    provider = ScriptedProvider([LLMResponse(content="Ask away."), LLMResponse(content="Bought it.")])
    body, request, rows = await _decided_checkout(
        client, session_factory, provider, {**CHECKOUT_RESULT, "user_image": JPEG}, "web-shot@example.com"
    )
    [decision_row] = [r for r in rows if r.content.startswith("[Approved] Executed 'browser.checkout'")]
    assert body["message_id"] == str(decision_row.id)
    assert body["images"] == [
        {"tool": "browser.checkout", "source": "shop.example.com", "index": 0, "data_url": JPEG}
    ]
    # The saved row and the model's view carry the placeholder, never the picture.
    assert JPEG not in str(decision_row.tool_calls) and JPEG not in str(body["result"] or "")
    last = [m for m in request if m.get("role") != "system"][-1]
    assert last["role"] == "user" and IMAGE_DELIVERED in last["content"]
    assert IMAGE_NOT_SHOWN not in last["content"] and JPEG not in last["content"]


@pytest.mark.asyncio
async def test_the_model_is_not_told_a_picture_reached_the_person_when_none_did(client, session_factory):
    """A picture no channel forwards (not a raster data URL) is dropped
    from the response, and the model's placeholder says it was not shown."""
    from services.agent.providers import LLMResponse
    from services.agent.runtime import IMAGE_DELIVERED, IMAGE_NOT_SHOWN

    provider = ScriptedProvider([LLMResponse(content="Ask away."), LLMResponse(content="Bought it.")])
    body, request, _ = await _decided_checkout(
        client, session_factory, provider, {**CHECKOUT_RESULT, "user_image": SVG}, "web-noshot@example.com"
    )
    assert body["images"] == [] and body["message_id"]
    last = [m for m in request if m.get("role") != "system"][-1]
    assert IMAGE_NOT_SHOWN in last["content"] and IMAGE_DELIVERED not in last["content"]
    assert SVG not in last["content"]


@pytest.mark.asyncio
async def test_a_channel_gets_the_confirmation_photo_before_the_reply(client, session_factory):
    """The Telegram applier's outcome carries the approved call's own
    photo first (the resumed turn took none here), captioned from the
    toolkit's facts, so the owner sees the confirmation page in the chat."""
    from api.routes.agent import build_decision_applier
    from main import app
    from services.agent.providers import LLMResponse

    provider = ScriptedProvider([LLMResponse(content="Bought it: $23.40.")])
    runtime, _ = _runtime(
        session_factory, provider, RecordingExecutor(result={**CHECKOUT_RESULT, "user_image": JPEG})
    )
    user, token = await make_user(session_factory, "tg-shot@example.com")
    conv = (await client.post("/api/agent/conversations", headers=auth_headers(token), json={})).json()
    action = await _park_checkout(session_factory, user, conv["id"])
    saved = getattr(app.state, "agent_runtime", None)
    app.state.agent_runtime = runtime
    try:
        outcome = await build_decision_applier(app, session_factory=session_factory)(
            str(user.id), action.action_id, True
        )
    finally:
        if saved is None:
            del app.state.agent_runtime
        else:
            app.state.agent_runtime = saved
    assert outcome["status"] == "approved" and outcome["summary"] == "Bought it: $23.40."
    assert outcome["images"] == [
        {"data_url": JPEG, "caption": "Order confirmation on shop.example.com: $23.40"}
    ]


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
