"""Tests for the scam check's web entry points: "/scam ..." typed in a web chat
(services/scam_check/web.py, reached from api/routes/agent.py's send_message
and stream_message) and the Security page's routes (api/routes/
security_scam.py). They prove a web /scam is answered without a chat turn and
saved with its usage, over the blocking route and the stream; that attached
files are checked by their fingerprint out of turn (never a turn), and another
person's file id checks nothing; that the saved user row holds the message
fenced as someone else's words with picture metadata only, so a later turn in
that chat treats it as untrusted; and that POST /api/security/scam-check
answers the verdict, saves it in the "Scam checks" chat, refuses empty or bad
input with 422, answers 403 / 503 / 429 for the switch, the gate and the
quota, needs a signed-in user, and that the status route says what can be
used.

Why it exists: a pasted scam is someone else's words. Run as a normal turn it
would be blocked whole by PromptGuard or, worse, read as the owner's own
instructions (review SEC-F11); stored unfenced, its links would steer later
turns. These are the paths a person in the browser actually uses.

Everything is offline: the scam service runs with a scripted runtime and
S4/S10-shaped fakes, and the chat runtime's provider fails the test if a turn
ever reaches it.
"""

from __future__ import annotations

import base64
import hashlib
import json
import uuid
from typing import Any

import pytest
from sqlalchemy import select
from structlog.testing import capture_logs

from core.config import settings
from models.conversation import Conversation, Message
from services.agent.approvals import InMemoryApprovalStore
from services.agent.providers import LLMResponse
from services.agent.runtime import AgentRuntime, PermissionEngine
from services.agent.shared_content import outside_fences, untrusted_spans, untrusted_spans_in
from services.scam_check.records import SCAM_CHECKS_ORIGIN, SCAM_CHECKS_TITLE
from services.scam_check.service import ScamCheckService
from services.scam_check.web import FILE_NOT_FOUND, parse_scam_command
from tests.conftest import auth_headers, make_user, use_provider
from tests.test_agent_runtime_vision import RecordingAudit, RecordingGuard, RecordingProvider
from tests.test_scam_check_service import (
    REPLY,
    SCAM_TEXT,
    USAGE,
    Clock,
    FakeFiles,
    FakeLinks,
    FakeRuntime,
    FakeSettings,
    broken_gate,
    gate_for,
)

PNG = b"\x89PNG\r\n\x1a\n" + b"\x00" * 64
PNG_URL = "data:image/png;base64," + base64.b64encode(PNG).decode("ascii")


class NoTurnProvider(RecordingProvider):
    """The chat's own provider: a /scam must never reach it."""

    async def complete(self, messages, tools=None):
        raise AssertionError("a /scam message must not start a chat turn")

    async def stream(self, messages, tools=None):
        raise AssertionError("a /scam message must not start a chat turn")
        yield ""  # pragma: no cover


@pytest.fixture
def chat_runtime():
    """Install a chat runtime on the app with the given provider."""
    from api.routes import agent as agent_routes
    from main import app

    def install(provider) -> AgentRuntime:
        runtime = AgentRuntime(
            config=settings,
            permission_engine=PermissionEngine(),
            prompt_guard=RecordingGuard(),
            audit_service=RecordingAudit(),
            approval_store=InMemoryApprovalStore(),
        )
        use_provider(runtime, provider)
        runtime._CONTENT_CHUNK_DELAY = 0
        app.dependency_overrides[agent_routes.get_runtime] = lambda: runtime
        return runtime

    yield install
    app.dependency_overrides.pop(agent_routes.get_runtime, None)


_MISSING = object()


@pytest.fixture
def scam(session_factory):
    """The process's ScamCheckService on app.state, built from fakes; tests
    change its parts through the returned namespace before posting."""
    from main import app

    class Parts:
        def __init__(self) -> None:
            self.runtime = FakeRuntime()
            self.links = FakeLinks()
            self.files = FakeFiles()
            self.settings = FakeSettings()
            self.gate = gate_for({"scam_check": True})
            self.clock = Clock()
            self.service = ScamCheckService(
                session_factory,
                capability_gate=lambda: self.gate(),
                settings=self.settings,
                runtime_getter=lambda: self.runtime,
                links_getter=lambda: self.links,
                files_getter=lambda: self.files,
                clock=self.clock,
            )

    parts = Parts()
    previous = getattr(app.state, "scam_check", _MISSING)
    app.state.scam_check = parts.service
    yield parts
    if previous is _MISSING:
        if hasattr(app.state, "scam_check"):
            delattr(app.state, "scam_check")
    else:
        app.state.scam_check = previous


@pytest.fixture
def intake(session_factory):
    """A real file intake (encrypted store, in-process sandbox) on the app."""
    from main import app
    from services.files.intake import FileIntake
    from services.files.sandbox import InProcessSandbox
    from services.files.store import UserFileStore

    previous = getattr(app.state, "file_intake", None)
    app.state.file_intake = FileIntake(UserFileStore(session_factory, sandbox=InProcessSandbox()))
    yield app.state.file_intake
    app.state.file_intake = previous


async def _user(session_factory, email: str):
    user, token = await make_user(session_factory, email)
    return user, auth_headers(token)


async def _conversation(client, headers) -> str:
    response = await client.post("/api/agent/conversations", json={"title": "Inbox"}, headers=headers)
    return response.json()["id"]


async def _rows(session_factory, conversation_id) -> list[Message]:
    async with session_factory() as session:
        rows = (
            await session.execute(
                select(Message)
                .where(Message.conversation_id == uuid.UUID(str(conversation_id)))
                .order_by(Message.created_at, Message.id)
            )
        ).scalars().all()
    by_role = {"user": 0, "assistant": 1}
    return sorted(rows, key=lambda m: (m.created_at, by_role.get(m.role.value, 2)))


def _frames(raw: str) -> list[tuple[str, dict[str, Any]]]:
    frames = []
    for block in raw.split("\n\n"):
        event, data = "message", None
        for line in block.splitlines():
            if line.startswith("event:"):
                event = line[6:].strip()
            elif line.startswith("data:"):
                data = json.loads(line[5:].strip())
        if data is not None:
            frames.append((event, data))
    return frames


def test_parse_scam_command_takes_only_a_leading_slash_scam():
    assert parse_scam_command("/scam Pay the fee") == "Pay the fee"
    assert parse_scam_command("  /SCAM\n\nline one\nline two ") == "line one\nline two"
    assert parse_scam_command("/scam") == ""
    for other in ("/scammers are awful", "is this a /scam?", "scam check", "/tutor on", "", None):
        assert parse_scam_command(other) is None  # type: ignore[arg-type]


# ── /scam in a web chat ──────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_slash_scam_in_a_web_chat_is_answered_without_a_turn_and_saved_with_usage(
    client, session_factory, chat_runtime, scam
):
    chat_runtime(NoTurnProvider())
    _user_row, headers = await _user(session_factory, "web-scam@example.com")
    conv_id = await _conversation(client, headers)
    response = await client.post(
        f"/api/agent/conversations/{conv_id}/messages",
        json={"content": f"/scam {SCAM_TEXT}"},
        headers=headers,
    )
    assert response.status_code == 201, response.text
    body = response.json()
    reply = body["assistant_message"]
    # The rules say suspicious (one strong ask and a deadline); the scripted review raises it.
    assert reply["content"].startswith("**\U0001f6a9 Likely a scam**")
    assert "**Your AI provider also noted:**" in reply["content"]
    assert (reply["input_tokens"], reply["output_tokens"]) == (USAGE["input_tokens"], USAGE["output_tokens"])
    assert (reply["llm_provider"], reply["llm_model"]) == ("anthropic", "claude-test")
    assert body["user_message"]["content"].startswith("/scam\n")
    assert untrusted_spans(body["user_message"]["content"]) == [SCAM_TEXT]
    assert len(scam.runtime.calls) == 1
    rows = await _rows(session_factory, conv_id)
    assert [m.role.value for m in rows] == ["user", "assistant"]
    assert rows[1].input_tokens == USAGE["input_tokens"]
    # The usage reaches the conversation's totals (what /usage sums).
    thread = await client.get(f"/api/agent/conversations/{conv_id}", headers=headers)
    assert thread.json()["total_input_tokens"] == USAGE["input_tokens"]


@pytest.mark.asyncio
async def test_slash_scam_over_the_stream_answers_with_the_usual_frames(client, session_factory, chat_runtime, scam):
    chat_runtime(NoTurnProvider())
    _user_row, headers = await _user(session_factory, "web-scam-stream@example.com")
    conv_id = await _conversation(client, headers)
    response = await client.post(
        f"/api/agent/conversations/{conv_id}/messages/stream",
        json={"content": f"/scam {SCAM_TEXT}"},
        headers=headers,
    )
    assert response.status_code == 200
    frames = _frames(response.text)
    assert [name for name, _ in frames] == ["user_message", "content_delta", "done", "saved"]
    reply = frames[1][1]["text"]
    assert reply.startswith("**\U0001f6a9 Likely a scam**")
    assert frames[3][1]["assistant_message"]["content"] == reply
    assert frames[3][1]["assistant_message"]["input_tokens"] == USAGE["input_tokens"]
    assert untrusted_spans(frames[0][1]["user_message"]["content"]) == [SCAM_TEXT]
    assert [m.content for m in await _rows(session_factory, conv_id)][1] == reply


@pytest.mark.asyncio
async def test_a_web_scam_command_with_files_is_checked_out_of_turn_and_never_runs_a_turn(
    client, session_factory, chat_runtime, scam, intake
):
    from tests.files import builders as b

    chat_runtime(NoTurnProvider())
    _user_row, headers = await _user(session_factory, "web-scam-files@example.com")
    pdf = b.make_pdf(["Invoice 4471: pay now"])
    upload = await client.post(
        "/api/files",
        content=pdf,
        headers={**headers, "Content-Type": "application/pdf", "X-File-Name": "invoice.pdf"},
    )
    assert upload.status_code == 201, upload.text
    file_id = upload.json()["id"]
    conv_id = await _conversation(client, headers)
    response = await client.post(
        f"/api/agent/conversations/{conv_id}/messages",
        json={"content": "/scam is this invoice real?", "file_ids": [file_id]},
        headers=headers,
    )
    assert response.status_code == 201, response.text
    digest = hashlib.sha256(pdf).hexdigest()
    assert [call[1] for call in scam.files.calls] == [digest]
    assert scam.files.calls[0][2]["source"] == "scam" and "check_bytes" not in dir(scam.files)
    body = response.json()
    assert "checked by their fingerprint only" in body["assistant_message"]["content"]
    user_content = body["user_message"]["content"]
    assert untrusted_spans(user_content) == ["is this invoice real?"]
    assert "[1 file attached; checked by fingerprint only]" in outside_fences(user_content)
    assert "invoice.pdf" not in user_content


@pytest.mark.asyncio
async def test_a_web_scam_command_with_another_users_file_id_checks_nothing(
    client, session_factory, chat_runtime, scam, intake
):
    from main import app
    from services.scam_check.web import answer_web_scam_command
    from tests.files import builders as b

    chat_runtime(NoTurnProvider())
    _owner, owner_headers = await _user(session_factory, "web-scam-owner@example.com")
    stranger, stranger_headers = await _user(session_factory, "web-scam-stranger@example.com")
    upload = await client.post(
        "/api/files",
        content=b.make_pdf(["Private"]),
        headers={**owner_headers, "Content-Type": "application/pdf", "X-File-Name": "private.pdf"},
    )
    foreign_id = upload.json()["id"]
    conv_id = await _conversation(client, stranger_headers)
    response = await client.post(
        f"/api/agent/conversations/{conv_id}/messages",
        json={"content": "/scam check this", "file_ids": [foreign_id]},
        headers=stranger_headers,
    )
    # The chat route refuses a foreign file before anything runs.
    assert response.status_code == 422
    assert scam.files.calls == [] and scam.runtime.calls == []
    # Called directly, the web handler answers with the sentence and checks nothing.
    async with session_factory() as db:
        conversation = await db.get(Conversation, uuid.UUID(conv_id))
        user_row, reply_row = await answer_web_scam_command(
            db, app, stranger, conversation, "check this", [], file_ids=[uuid.UUID(foreign_id), uuid.uuid4()]
        )
        await db.commit()
    assert reply_row.content == FILE_NOT_FOUND
    assert scam.files.calls == [] and scam.runtime.calls == [] and scam.links.calls == []
    assert untrusted_spans(user_row.content) == ["check this"]


@pytest.mark.asyncio
async def test_the_saved_user_row_holds_the_fenced_message_and_picture_metadata_only(
    client, session_factory, chat_runtime, scam
):
    chat_runtime(NoTurnProvider())
    _user_row, headers = await _user(session_factory, "web-scam-pics@example.com")
    conv_id = await _conversation(client, headers)
    response = await client.post(
        f"/api/agent/conversations/{conv_id}/messages",
        json={"content": f"/scam {SCAM_TEXT}", "images": [{"media_type": "image/png", "data": PNG_URL}]},
        headers=headers,
    )
    assert response.status_code == 201, response.text
    user_row, reply_row = await _rows(session_factory, conv_id)
    assert untrusted_spans(user_row.content) == [SCAM_TEXT]
    assert "[1 picture sent to check; pictures are not kept]" in outside_fences(user_row.content)
    picture, facts = user_row.attachments
    assert picture == {"media_type": "image/png", "size_bytes": len(PNG), "sha256": hashlib.sha256(PNG).hexdigest()}
    assert facts["kind"] == "scam_check" and facts["channel"] == "web_chat" and facts["images"] == 1
    stored = json.dumps([user_row.content, user_row.attachments, reply_row.content, reply_row.attachments])
    assert base64.b64encode(PNG).decode("ascii")[:40] not in stored
    # The picture went to the AI review as an image block.
    (call,) = scam.runtime.calls
    assert [block["type"] for block in call["messages"][0]["content"]] == ["text", "image"]


@pytest.mark.asyncio
async def test_a_later_turn_in_that_chat_sees_the_checked_message_as_untrusted(
    client, session_factory, chat_runtime, scam, monkeypatch
):
    import structlog

    from services.agent import runtime as runtime_module

    # A fresh module logger: one an earlier test file cached before a later
    # configure_logging() would never reach capture_logs (order dependent).
    monkeypatch.setattr(runtime_module, "logger", structlog.get_logger(runtime_module.__name__))
    chat_runtime(NoTurnProvider())
    _user_row, headers = await _user(session_factory, "web-scam-later@example.com")
    conv_id = await _conversation(client, headers)
    first = await client.post(
        f"/api/agent/conversations/{conv_id}/messages", json={"content": f"/scam {SCAM_TEXT}"}, headers=headers
    )
    assert first.status_code == 201
    provider = RecordingProvider([LLMResponse(content="Noted.", usage={"input_tokens": 5, "output_tokens": 1})])
    chat_runtime(provider)
    with capture_logs() as logs:
        later = await client.post(
            f"/api/agent/conversations/{conv_id}/messages",
            json={"content": "Thanks. What should I do next?"},
            headers=headers,
        )
    assert later.status_code == 201, later.text
    sent = provider.calls[0]["messages"]
    assert SCAM_TEXT in untrusted_spans_in(sent)
    # The runtime tainted the fenced span for the turn (its links count as someone else's).
    assert any(entry.get("event") == "shared_content_tainted" and entry.get("spans", 0) >= 1 for entry in logs)
    # The owner's own words in that history never include the message.
    owner_words = " ".join(
        outside_fences(m["content"]) for m in sent if m.get("role") == "user" and isinstance(m.get("content"), str)
    )
    assert "paypa1-secure" not in owner_words


# ── POST /api/security/scam-check and the status route ───────────────────


@pytest.mark.asyncio
async def test_post_scam_check_returns_the_verdict_and_saves_it_in_the_scam_checks_chat(client, session_factory, scam):
    _user_row, headers = await _user(session_factory, "box@example.com")
    response = await client.post(
        "/api/security/scam-check",
        json={"text": SCAM_TEXT, "note": "is this my bank?", "images": [{"media_type": "image/png", "data": PNG_URL}]},
        headers=headers,
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert set(body) == {
        "verdict", "headline", "reasons", "ai_reasons", "advice", "links", "notes", "qr", "checked",
        "cached", "conversation_id", "usage", "provider", "model",
    }
    assert (body["verdict"], body["headline"]) == ("likely_scam", "Likely a scam")
    assert body["ai_reasons"] == REPLY["reasons"]
    assert body["checked"] == {"text_chars": len(SCAM_TEXT), "images": 1, "links": 1, "ai": True}
    assert body["links"][0]["host"] == "paypa1-secure.example" and body["links"][0]["origin"] == "text"
    assert (body["usage"], body["provider"], body["model"]) == (USAGE, "anthropic", "claude-test")
    async with session_factory() as session:
        conversation = await session.get(Conversation, uuid.UUID(body["conversation_id"]))
    assert (conversation.title, conversation.origin) == (SCAM_CHECKS_TITLE, SCAM_CHECKS_ORIGIN)
    user_row, reply_row = await _rows(session_factory, body["conversation_id"])
    assert user_row.content.startswith("Check for scams: is this my bank?\n")
    assert untrusted_spans(user_row.content) == [SCAM_TEXT]
    assert reply_row.input_tokens == USAGE["input_tokens"] and reply_row.content.startswith("**")
    # The next check from the page goes into the same chat.
    again = await client.post("/api/security/scam-check", json={"text": "Send me the code we sent you."}, headers=headers)
    assert again.status_code == 200 and again.json()["conversation_id"] == body["conversation_id"]


@pytest.mark.asyncio
async def test_post_scam_check_refuses_empty_oversize_and_unsupported_pictures_with_422(client, session_factory, scam):
    _user_row, headers = await _user(session_factory, "box-422@example.com")
    bad_bodies = [
        {"text": "   "},
        {"text": "x" * 8001},
        {"text": "hi", "note": "n" * 501},
        {"text": "", "images": [{"media_type": "image/png", "data": PNG_URL}] * 5},
        {"text": "", "images": [{"media_type": "image/png", "data": "not base64!"}]},
        {"text": "", "images": [{"media_type": "image/svg+xml", "data": base64.b64encode(b"<svg/>").decode()}]},
        {"text": "", "images": [{"media_type": "image/png", "data": "A" * (7 * 1024 * 1024)}]},
        # Declared a PNG, but the bytes are no picture at all: nothing is left to check.
        {"text": "", "images": [{"media_type": "image/png", "data": base64.b64encode(b"hello").decode()}]},
    ]
    for body in bad_bodies:
        response = await client.post("/api/security/scam-check", json=body, headers=headers)
        assert response.status_code == 422, (str(body)[:80], response.text[:200])
    assert scam.runtime.calls == [] and scam.links.calls == []


@pytest.mark.asyncio
async def test_post_scam_check_answers_403_when_off_503_on_a_gate_error_and_429_over_the_cap(
    client, session_factory, scam
):
    from services.capabilities.scam_check import CAPABILITY

    _user_row, headers = await _user(session_factory, "box-codes@example.com")
    scam.gate = gate_for({"scam_check": False})
    off = await client.post("/api/security/scam-check", json={"text": SCAM_TEXT}, headers=headers)
    assert (off.status_code, off.json()["detail"]) == (403, CAPABILITY.when_denied)
    status_off = await client.get("/api/security/scam-check/status", headers=headers)
    assert status_off.status_code == 200
    assert (status_off.json()["effective"], status_off.json()["reason"]) == ("off", CAPABILITY.when_denied)

    scam.gate = broken_gate
    gate_error = await client.post("/api/security/scam-check", json={"text": SCAM_TEXT}, headers=headers)
    assert gate_error.status_code == 503 and "couldn't check whether scam checks are on" in gate_error.json()["detail"]
    assert (await client.get("/api/security/scam-check/status", headers=headers)).status_code == 503

    scam.gate = gate_for({"scam_check": True})
    scam.settings.per_day = 2
    for n in range(2):
        ok = await client.post("/api/security/scam-check", json={"text": f"{SCAM_TEXT} {n}"}, headers=headers)
        assert ok.status_code == 200
    over = await client.post("/api/security/scam-check", json={"text": f"{SCAM_TEXT} 3"}, headers=headers)
    assert over.status_code == 429 and "today's 2 scam checks" in over.json()["detail"]
    assert len(scam.runtime.calls) == 2

    # The service not wired yet: 503, nothing runs.
    from main import app

    saved = app.state.scam_check
    del app.state.scam_check
    try:
        missing = await client.post("/api/security/scam-check", json={"text": "hi"}, headers=headers)
        assert missing.status_code == 503
        assert (await client.get("/api/security/scam-check/status", headers=headers)).status_code == 503
    finally:
        app.state.scam_check = saved


@pytest.mark.asyncio
async def test_a_picture_only_check_with_a_blind_provider_is_answered_couldnt_check_not_an_error(
    client, session_factory, scam
):
    _user_row, headers = await _user(session_factory, "box-blind@example.com")
    scam.runtime = FakeRuntime(default=("deepseek", "deepseek-chat"))
    response = await client.post(
        "/api/security/scam-check",
        json={"text": "", "images": [{"media_type": "image/png", "data": PNG_URL}]},
        headers=headers,
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["verdict"] == "not_checked" and body["headline"] == "I couldn't check this"
    assert any("deepseek" in note and "can't look at pictures" in note for note in body["notes"])
    assert scam.runtime.calls == [] and scam.service.quota.used_today(str(_user_row.id)) == 0


@pytest.mark.asyncio
async def test_post_scam_check_needs_a_signed_in_user(client, scam):
    assert (await client.post("/api/security/scam-check", json={"text": "hi"})).status_code == 401
    assert (await client.get("/api/security/scam-check/status")).status_code == 401
    bad = {"Authorization": "Bearer not-a-token"}
    assert (await client.post("/api/security/scam-check", json={"text": "hi"}, headers=bad)).status_code == 401
    assert scam.runtime.calls == []


@pytest.mark.asyncio
async def test_status_says_whether_pictures_and_googles_list_can_be_used(client, session_factory, scam):
    user, headers = await _user(session_factory, "box-status@example.com")
    first = (await client.get("/api/security/scam-check/status", headers=headers)).json()
    assert first == {
        "effective": "on",
        "reason": "",
        "provider": "anthropic",
        "sees_images": True,
        "google_list": False,
        "file_reputation": True,
        "checks_per_day": 30,
        "checks_used_today": 0,
    }
    await client.post("/api/security/scam-check", json={"text": SCAM_TEXT}, headers=headers)
    scam.runtime = FakeRuntime(default=("deepseek", "deepseek-chat"))
    scam.links = FakeLinks(remote=True)
    scam.files = None
    second = (await client.get("/api/security/scam-check/status", headers=headers)).json()
    assert (second["provider"], second["sees_images"], second["google_list"]) == ("deepseek", False, True)
    assert second["file_reputation"] is None and second["checks_used_today"] == 1
    # No provider for the account: no name, and no pictures.
    from services.agent.providers import ProviderNotConfigured

    scam.runtime = FakeRuntime(resolve_raises=ProviderNotConfigured("anthropic", reason="not_set_up"))
    scam.links = None
    third = (await client.get("/api/security/scam-check/status", headers=headers)).json()
    assert (third["provider"], third["sees_images"], third["google_list"]) == ("", False, None)
    assert str(user.id) not in json.dumps(third)
