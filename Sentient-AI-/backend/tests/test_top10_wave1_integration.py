"""Tests for the seams where the wave-1 skills meet: the one-shot model call
(scheduler_briefing's complete_once) honours the owner's "Hide personal
details from the AI provider" switch like a chat turn does (secret_pii_redaction),
and a run nobody is watching (the unattended runner) carries the conversation's
tutor mode, so an owner's lock applies there too and a lock the run engages is
kept on the run's conversation (tutor_mode).

Why it exists: each skill was built on its own from the wave-0 seams; these
are the behaviours that only exist once they are merged. Fake providers and
runtimes and in-memory SQLite; no network, no model.
"""

from __future__ import annotations

import re
import uuid
from types import SimpleNamespace
from typing import Any

import pytest

from core.config import settings
from services.agent.approvals import InMemoryApprovalStore
from services.agent.providers import LLMResponse
from services.agent.runtime import AgentResponse, AgentRuntime, Tool
from services.automation.runner import UnattendedRequest
from services.automation.turns import UnattendedTurnRunner
from services.tutor.state import TutorState, TutorTurn
from tests.conftest import make_user

EMAIL = "ana.lopez@example.com"
CARD = "4111 1111 1111 1111"


class Source:
    async def llm_defaults(self):
        return "gemini", "gemini-2.5-flash"

    async def llm_api_key(self, provider):
        return "k"


class EchoProvider:
    """Replies with the first placeholder it was sent (or nothing)."""

    supports_vision = True

    def __init__(self) -> None:
        self.sent: list[str] = []

    async def complete(self, messages, tools=None, **kwargs):
        text = "\n".join(str(m.get("content")) for m in messages)
        self.sent.append(text)
        placeholder = re.search(r"\[\[EMAIL_[0-9]+(?:@[^\]]+)?\]\]", text)
        return LLMResponse(content=f"Write to {placeholder.group(0) if placeholder else 'nobody'}.", usage={})

    async def aclose(self):
        return None


def runtime(monkeypatch, hidden):
    import services.agent.runtime as rt

    provider = EchoProvider()
    monkeypatch.setattr(rt, "create_provider", lambda **_kwargs: provider)

    async def gate() -> bool:
        if isinstance(hidden, Exception):
            raise hidden
        return hidden

    agent = AgentRuntime(
        config=settings,
        approval_store=InMemoryApprovalStore(),
        settings_source=Source(),
        personal_details_hidden=gate,
    )
    return agent, provider


def once_message() -> list[dict[str, Any]]:
    return [{"role": "user", "content": f"Mail {EMAIL} about card {CARD}."}]


@pytest.mark.asyncio
async def test_complete_once_hides_contact_details_while_the_switch_is_on(monkeypatch):
    agent, provider = runtime(monkeypatch, True)
    result = await agent.complete_once(once_message(), llm_provider=None, llm_model=None, system="s")
    [sent] = provider.sent
    assert EMAIL not in sent and "[[EMAIL_" in sent
    assert "4111" not in sent  # the floor: a card number never leaves
    # The placeholder the model used comes back as the real address.
    assert result.text == f"Write to {EMAIL}."


@pytest.mark.asyncio
async def test_complete_once_keeps_contact_details_while_the_switch_is_off(monkeypatch):
    agent, provider = runtime(monkeypatch, False)
    await agent.complete_once(once_message(), llm_provider=None, llm_model=None, system="s")
    [sent] = provider.sent
    assert EMAIL in sent and "[[EMAIL_" not in sent
    assert "4111" not in sent  # the floor holds whatever the switch says


@pytest.mark.asyncio
async def test_complete_once_hides_when_the_switch_cannot_be_read(monkeypatch):
    agent, provider = runtime(monkeypatch, RuntimeError("store down"))
    await agent.complete_once(once_message(), llm_provider=None, llm_model=None, system="s")
    [sent] = provider.sent
    assert EMAIL not in sent


# -- the unattended runner and tutor mode --------------------------------------


class FakeRuntime:
    def __init__(self, engage: bool = False) -> None:
        self.engage = engage
        self.calls: list[dict[str, Any]] = []

    async def chat(self, **kwargs):
        self.calls.append(kwargs)
        tutor = kwargs.get("tutor")
        if self.engage and tutor is not None:
            tutor.start_by_tool()
        return AgentResponse(content="Done.", usage={}, provider="gemini", model="gemini-2.5-flash")


def tool(name: str) -> Tool:
    return Tool(name=name, description=name, parameters={}, connector_type=name.split(".")[0])


def runner(session_factory, fake, tutor_for):
    async def build_context(user, db, conversation):
        return SimpleNamespace(
            tools=[tool("canvas.get_upcoming"), tool("reminders.now")],
            memory_block=None,
            permissions_text="<permissions>p</permissions>",
            tutor=tutor_for(conversation),
        )

    async def settings_source():
        return {"run_cap_cents": 5, "day_cap_cents": 25, "runs_per_day": 24}

    from api.routes.agent import _usage_columns

    return UnattendedTurnRunner(
        runtime=lambda: fake,
        session_factory=session_factory,
        build_context=build_context,
        usage_columns=_usage_columns,
        settings=settings_source,
    )


def request(user) -> UnattendedRequest:
    return UnattendedRequest(
        user_id=str(user.id),
        origin="schedule:abc",
        label="Canvas summary",
        prompt="Summarise what is due on Canvas.",
        reads=("canvas.get_upcoming",),
        writes=(),
        conversation_title="Scheduled: Canvas summary",
        run_id=f"run-{uuid.uuid4().hex[:6]}",
    )


@pytest.mark.asyncio
async def test_an_unattended_run_carries_the_conversations_tutor_mode_and_keeps_what_it_changed(
    session_factory,
):
    from models.conversation import Conversation

    user, _ = await make_user(session_factory, "tutor-run@example.com")
    turns: list[TutorTurn] = []

    def tutor_for(conversation):
        turn = TutorTurn(TutorState.from_stored(conversation.tutor_state), conversation_id=str(conversation.id))
        turns.append(turn)
        return turn

    fake = FakeRuntime(engage=True)
    outcome = await runner(session_factory, fake, tutor_for).run(request(user))
    assert outcome.status == "ok"
    [call] = fake.calls
    assert call["tutor"] is turns[0] and call["unattended"] is not None
    async with session_factory() as session:
        conversation = await session.get(Conversation, uuid.UUID(outcome.conversation_id))
    assert TutorState.from_stored(conversation.tutor_state).user_on is True


@pytest.mark.asyncio
async def test_a_tutor_command_sent_with_a_file_is_a_normal_turn(client, session_factory):
    """"/tutor on" with an uploaded file attached is not swallowed by the
    command intercept: the file reaches the model like any attachment."""
    from api.routes import agent as agent_routes
    from main import app
    from services.files.intake import FileIntake
    from services.files.sandbox import InProcessSandbox
    from services.files.store import UserFileStore
    from tests.conftest import auth_headers
    from tests.files import builders as b

    from services.agent.runtime import PermissionEngine
    from tests.conftest import use_provider
    from tests.test_agent_runtime_vision import RecordingAudit, RecordingGuard, RecordingProvider

    async def open_gate():
        return None

    async def log(_entry):
        return None

    _, token = await make_user(session_factory, "tutor-file@example.com")
    headers = auth_headers(token)
    previous = getattr(app.state, "file_intake", None)
    app.state.file_intake = FileIntake(
        UserFileStore(session_factory, sandbox=InProcessSandbox()), gate=open_gate, audit=log
    )
    provider = RecordingProvider()
    real = AgentRuntime(
        config=settings,
        permission_engine=PermissionEngine(),
        prompt_guard=RecordingGuard(),
        audit_service=RecordingAudit(),
        approval_store=InMemoryApprovalStore(),
    )
    use_provider(real, provider)
    real._CONTENT_CHUNK_DELAY = 0
    app.dependency_overrides[agent_routes.get_runtime] = lambda: real
    try:
        uploaded = await client.post(
            "/api/files",
            content=b.make_pdf(["Problem set 3"]),
            headers={**headers, "Content-Type": "application/pdf", "X-File-Name": "ps3.pdf"},
        )
        assert uploaded.status_code == 201, uploaded.text
        conv = (await client.post("/api/agent/conversations", json={"title": "T"}, headers=headers)).json()
        for route in ("messages", "messages/stream"):
            sent = await client.post(
                f"/api/agent/conversations/{conv['id']}/{route}",
                json={"content": "/tutor on", "file_ids": [uploaded.json()["id"]]},
                headers=headers,
            )
            assert sent.status_code in (200, 201), sent.text
        # Both went to the model (a command would not have), each with the note.
        assert len(provider.calls) == 2
        for call in provider.calls:
            last_user = [m for m in call["messages"] if m["role"] == "user"][-1]
            assert "[Attached file: 'ps3.pdf'" in str(last_user["content"])
        async with session_factory() as session:
            from models.conversation import Conversation

            stored = await session.get(Conversation, uuid.UUID(conv["id"]))
        assert stored.tutor_state is None
    finally:
        app.dependency_overrides.pop(agent_routes.get_runtime, None)
        app.state.file_intake = previous


@pytest.mark.asyncio
async def test_without_tutor_mode_the_runtime_sees_no_tutor_keyword(session_factory):
    from models.conversation import Conversation

    user, _ = await make_user(session_factory, "no-tutor-run@example.com")
    fake = FakeRuntime()
    outcome = await runner(session_factory, fake, lambda _conversation: None).run(request(user))
    assert outcome.status == "ok"
    [call] = fake.calls
    assert "tutor" not in call
    async with session_factory() as session:
        conversation = await session.get(Conversation, uuid.UUID(outcome.conversation_id))
    assert conversation.tutor_state is None


# -- ids every skill writes vs the secret detector -----------------------------

# Found by scanning random ids: before the fix each held a "card" or "bank
# account" run, so the audit log masked part of the id and the tool-argument
# guard refused a call that named it.
IDS_THAT_LOOKED_SECRET = [
    "f97d6a97-4558-4435-9280-1434a4bfc93a",  # a page watch id (card groups)
    "ccaf68bc-1703-4089-8274-0830a1ecca3a",  # a UUID (card groups)
    "cfb29389-5ae4-41d9-a54b-aba403756815",  # "aba" + digits (bank account)
    "5d8f6cce532a7aeb57196be62344095936793400",  # a 40-hex commit sha (Luhn run)
]


@pytest.mark.parametrize("identifier", IDS_THAT_LOOKED_SECRET)
def test_ids_are_never_secrets_in_any_policy(identifier):
    from services.security import policies
    from services.security.guard import check_call
    from services.security.redact import redact_obj
    from services.security.secrets import Confidence, find

    for text in (identifier, f"watch {identifier} changed", f'{{"id": "{identifier}"}}'):
        assert find(text, min_confidence=Confidence.LOW) == [], text
    row = {"watch_id": identifier, "delivered": True}
    assert redact_obj(row, policies.AUDIT) == row
    assert check_call("call-1", {"file_id": identifier}, None) is None


def test_a_real_card_or_account_next_to_an_id_is_still_found():
    from services.security.secrets import Kind, find

    card = find("id f97d6a97-4558-4435-9280-1434a4bfc93a card 4111 1111 1111 1111")
    assert [f.kind for f in card] == [Kind.payment_card]
    assert [f.kind for f in find("ABA 021000021 for the transfer")] == [Kind.bank_account]
    assert [f.kind for f in find("card:4111111111111111.")] == [Kind.payment_card]
