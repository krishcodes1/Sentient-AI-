"""Tests for the Telegram approval channel: link-code linking is single-use and
expires, only a linked chat's decisions are authorized, an approval card shows
the call without the screen a desktop.act card stores, and the notifying
approval-store decorator, message splitting, and poller-conflict backoff all
behave correctly.

Why it exists: Guards the identity boundary between a Telegram chat and the
account it can approve actions for; the Bot API is faked at the transport level
so this exercises the service's real request and response code.

Connects to: services/notifications/telegram.py and the agent appliers,
with the Bot API faked at the httpx transport.
Used by: pytest (CI backend jobs); FakeTelegramAPI is reused by
test_usage.py, test_telegram_cost_safety.py, test_telegram_decisions.py and
test_telegram_progress.py.

Telegram approval-channel tests: linking security, decision
authorization, and the notifying approval-store decorator.

The Telegram Bot API is faked at the httpx-transport level so the service
under test runs its real request/response code without any network.
"""

from __future__ import annotations

import asyncio
import base64
import json
import uuid
from datetime import datetime, timedelta, timezone

import httpx
import pytest
from sqlalchemy import select

from tests.conftest import auth_headers, make_user, telegram_dm


class FakeTelegramAPI:
    """Records outgoing Bot API calls and scripts their results."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, dict]] = []
        self.username = "sentientai_test_bot"
        # Scripted getUpdates bodies, served in order; the HTTP status
        # follows error_code the way the real API's does.
        self.get_updates: list[dict] = []

    def handler(self, request: httpx.Request) -> httpx.Response:
        method = request.url.path.rsplit("/", 1)[-1]
        try:
            payload = json.loads(request.content or b"{}")
        except ValueError:
            # multipart upload (sendPhoto): record shape, not bytes
            payload = {"_multipart_bytes": len(request.content)}
        self.calls.append((method, payload))
        if method == "getUpdates" and self.get_updates:
            body = self.get_updates.pop(0)
            return httpx.Response(body.get("error_code", 200), json=body)
        if method == "getMe":
            return httpx.Response(
                200, json={"ok": True, "result": {"username": self.username}}
            )
        return httpx.Response(200, json={"ok": True, "result": {}})

    def sent_messages(self) -> list[dict]:
        return [p for m, p in self.calls if m == "sendMessage"]


@pytest.fixture
def fake_api(monkeypatch):
    api = FakeTelegramAPI()
    real_client_cls = httpx.AsyncClient

    def _factory(**kwargs):
        kwargs["transport"] = httpx.MockTransport(api.handler)
        return real_client_cls(**kwargs)

    monkeypatch.setattr(httpx, "AsyncClient", _factory)
    return api


def _make_service(session_factory, decide=None):
    from services.notifications.telegram import TelegramService

    return TelegramService(
        token="123:fake-token", session_factory=session_factory, decide=decide
    )


@pytest.mark.asyncio
async def test_link_code_flow_links_chat_and_is_single_use(
    session_factory, fake_api
):
    from models.user import User

    user, _ = await make_user(session_factory, email="tg-link@example.com")
    service = _make_service(session_factory)

    link = await service.create_link_code(str(user.id))
    assert link is not None
    assert link["bot_username"] == fake_api.username
    code = link["link_url"].split("start=")[1]

    await service._handle_message(telegram_dm(424242, f"/start {code}"))

    async with session_factory() as session:
        row = (
            await session.execute(select(User).where(User.id == user.id))
        ).scalar_one()
        assert row.telegram_chat_id == 424242
        # Single-use: the code is destroyed on link.
        assert row.telegram_link_code is None

    # Replaying the same code must not re-link (it is gone).
    await service._handle_message(telegram_dm(999999, f"/start {code}"))
    async with session_factory() as session:
        row = (
            await session.execute(select(User).where(User.id == user.id))
        ).scalar_one()
        assert row.telegram_chat_id == 424242

    await service._client.aclose()


@pytest.mark.asyncio
async def test_expired_link_code_is_rejected(session_factory, fake_api):
    from models.user import User

    user, _ = await make_user(session_factory, email="tg-exp@example.com")
    service = _make_service(session_factory)
    link = await service.create_link_code(str(user.id))
    code = link["link_url"].split("start=")[1]

    async with session_factory() as session:
        row = (
            await session.execute(select(User).where(User.id == user.id))
        ).scalar_one()
        row.telegram_link_expires_at = datetime.now(timezone.utc) - timedelta(
            minutes=1
        )
        await session.commit()

    await service._handle_message(telegram_dm(555, f"/start {code}"))

    async with session_factory() as session:
        row = (
            await session.execute(select(User).where(User.id == user.id))
        ).scalar_one()
        assert row.telegram_chat_id is None
    await service._client.aclose()


@pytest.mark.asyncio
async def test_callback_from_unlinked_chat_is_refused(session_factory, fake_api):
    decisions: list = []

    async def decide(user_id, action_id, approved):
        decisions.append((user_id, action_id, approved))
        return {"status": "approved"}

    service = _make_service(session_factory, decide=decide)
    await service._handle_callback(
        {
            "id": "cb1",
            "from": {"id": 31337, "is_bot": False},
            "data": "apv:some-action-id",
            "message": {
                "chat": {"id": 31337, "type": "private"},
                "message_id": 1,
                "text": "x",
            },
        }
    )
    await service.wait_for_chats()
    assert decisions == []  # never reached the decision pipeline
    answers = [p for m, p in fake_api.calls if m == "answerCallbackQuery"]
    assert answers and "not linked" in answers[0]["text"]
    await service._client.aclose()


@pytest.mark.asyncio
async def test_callback_from_linked_chat_decides_as_that_user(
    session_factory, fake_api
):
    from models.user import User

    user, _ = await make_user(session_factory, email="tg-decide@example.com")
    async with session_factory() as session:
        row = (
            await session.execute(select(User).where(User.id == user.id))
        ).scalar_one()
        row.telegram_chat_id = 777001
        await session.commit()

    decisions: list = []

    async def decide(user_id, action_id, approved):
        decisions.append((user_id, action_id, approved))
        return {"status": "denied", "summary": None}

    service = _make_service(session_factory, decide=decide)
    await service._handle_callback(
        {
            "id": "cb2",
            "from": {"id": 777001, "is_bot": False},
            "data": "dny:action-abc",
            "message": {
                "chat": {"id": 777001, "type": "private"},
                "message_id": 2,
                "text": "req",
            },
        }
    )
    # The decision runs as the chat's tracked work, off the poll loop.
    await service.wait_for_chats()
    assert decisions == [(str(user.id), "action-abc", False)]
    # The card is frozen (buttons replaced by the verdict).
    edits = [p for m, p in fake_api.calls if m == "editMessageText"]
    assert edits and "Denied" in edits[0]["text"]
    await service._client.aclose()


@pytest.mark.asyncio
async def test_notify_pending_skips_unlinked_and_messages_linked(
    session_factory, fake_api
):
    from models.user import User
    from services.agent.approvals import StoredAction

    user, _ = await make_user(session_factory, email="tg-notify@example.com")
    service = _make_service(session_factory)

    action = StoredAction(
        action_id="a1",
        user_id=str(user.id),
        tool_name="google_workspace.send_email",
        arguments={"to": "prof@example.com"},
        reason="Sending email requires approval",
        created_at=datetime.now(timezone.utc).isoformat(),
        expires_at=(datetime.now(timezone.utc) + timedelta(minutes=15)).isoformat(),
        risk_note="Recipient came from tool output",
    )

    await service.notify_pending(action)
    assert fake_api.sent_messages() == []  # not linked → no push

    async with session_factory() as session:
        row = (
            await session.execute(select(User).where(User.id == user.id))
        ).scalar_one()
        row.telegram_chat_id = 888
        await session.commit()

    await service.notify_pending(action)
    sent = fake_api.sent_messages()
    assert len(sent) == 1
    assert sent[0]["chat_id"] == 888
    assert "google_workspace.send_email" in sent[0]["text"]
    assert "Recipient came from tool output" in sent[0]["text"]
    buttons = sent[0]["reply_markup"]["inline_keyboard"][0]
    assert buttons[0]["callback_data"] == "apv:a1"
    assert buttons[1]["callback_data"] == "dny:a1"
    await service._client.aclose()


@pytest.mark.asyncio
async def test_a_desktop_card_leaves_out_the_screen_it_stores(session_factory, fake_api):
    """A desktop.act card stores the screen it was made from under the
    reserved "_screen" key; the card shows the call without it. Any other
    tool's arguments are shown whole, "_" keys included."""
    from services.agent.approvals import StoredAction

    user = await _link(session_factory, "tg-notify-screen@example.com", 889)
    service = _make_service(session_factory)
    expires = (datetime.now(timezone.utc) + timedelta(minutes=15)).isoformat()

    def action(tool_name: str, arguments: dict) -> StoredAction:
        return StoredAction(
            action_id="a2",
            user_id=str(user.id),
            tool_name=tool_name,
            arguments=arguments,
            reason="Click \"Send\" in Mail",
            created_at=datetime.now(timezone.utc).isoformat(),
            expires_at=expires,
        )

    await service.notify_pending(
        action(
            "desktop.act",
            {"action": "click", "ref": "d3", "_screen": {"app": "Mail", "outline": "9f2c1a"}},
        )
    )
    await service.notify_pending(action("mcp.github.search", {"q": "x", "_scope": "org"}))
    desktop, other = (m["text"] for m in fake_api.sent_messages())
    assert '"ref": "d3"' in desktop
    assert "_screen" not in desktop and "9f2c1a" not in desktop
    assert '"_scope": "org"' in other
    await service._client.aclose()


@pytest.mark.asyncio
async def test_notifying_store_forwards_and_notifies(session_factory, fake_api):
    from services.agent.approvals import InMemoryApprovalStore
    from services.notifications.telegram import NotifyingApprovalStore

    notified: list = []

    async def notify(stored):
        notified.append(stored.action_id)

    store = NotifyingApprovalStore(InMemoryApprovalStore(), notify=notify)
    stored = await store.create(
        user_id="u1",
        tool_name="canvas.submit_assignment",
        arguments={},
        reason="test",
    )
    # The notification task runs on the loop; yield to it.
    import asyncio

    await asyncio.sleep(0)
    assert notified == [stored.action_id]
    assert await store.list_pending("u1")


@pytest.mark.asyncio
async def test_status_and_link_routes(client, session_factory, fake_api):
    """Route surface: unconfigured status is honest; linking requires the
    service; unlink always works."""
    user, token = await make_user(session_factory, email="tg-routes@example.com")

    # No manager on app.state (default in tests) → configured: false.
    resp = await client.get("/api/telegram/status", headers=auth_headers(token))
    assert resp.status_code == 200
    assert resp.json() == {
        "configured": False,
        "linked": False,
        "bot_username": None,
    }

    resp = await client.post("/api/telegram/link", headers=auth_headers(token))
    assert resp.status_code == 503

    # With a running service behind the manager, status reports and link
    # mints a URL.
    from main import app
    from services.notifications.telegram_manager import TelegramManager

    service = _make_service(session_factory)
    manager = TelegramManager(session_factory)
    manager.current = service
    saved_manager = getattr(app.state, "telegram_manager", None)
    app.state.telegram_manager = manager
    try:
        resp = await client.get(
            "/api/telegram/status", headers=auth_headers(token)
        )
        assert resp.json()["configured"] is True
        resp = await client.post(
            "/api/telegram/link", headers=auth_headers(token)
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body["link_url"].startswith("https://t.me/")
        assert body["bot_username"] == fake_api.username

        resp = await client.delete(
            "/api/telegram/link", headers=auth_headers(token)
        )
        assert resp.status_code == 204
    finally:
        app.state.telegram_manager = saved_manager
        await service._client.aclose()


@pytest.mark.asyncio
async def test_plain_message_from_unlinked_chat_is_ignored(session_factory, fake_api):
    """A1: a Telegram account that is not linked gets no reply at all —
    the bot does not even confirm it serves anyone."""
    service = _make_service(session_factory)
    await service._handle_message(telegram_dm(101, "hello?"))
    await service.wait_for_chats()
    assert fake_api.calls == []
    await service._client.aclose()


@pytest.mark.asyncio
async def test_help_and_pending_for_linked_chat(session_factory, fake_api):
    from datetime import datetime, timedelta, timezone

    from models.pending_action import PendingAction, PendingActionStatus
    from models.user import User

    user, _ = await make_user(session_factory, email="tg-cmd@example.com")
    async with session_factory() as session:
        row = (
            await session.execute(select(User).where(User.id == user.id))
        ).scalar_one()
        row.telegram_chat_id = 202
        await session.commit()

    service = _make_service(session_factory)

    # Any non-command text gets the command list, not silence.
    await service._handle_message(telegram_dm(202, "what now"))
    assert "/pending" in fake_api.sent_messages()[-1]["text"]

    # Nothing pending → say so, no cards.
    await service._handle_message(telegram_dm(202, "/pending"))
    assert "Nothing is waiting" in fake_api.sent_messages()[-1]["text"]

    async with session_factory() as session:
        session.add(
            PendingAction(
                user_id=user.id,
                tool_name="canvas.submit_assignment",
                arguments={"course": "CSCI-456"},
                reason="Submitting on your behalf",
                status=PendingActionStatus.pending,
                created_at=datetime.now(timezone.utc),
                expires_at=datetime.now(timezone.utc) + timedelta(minutes=15),
            )
        )
        await session.commit()

    # With a pending action, /pending re-sends the card with live buttons —
    # the group-style "/pending@bot" spelling must work too.
    await service._handle_message(telegram_dm(202, "/pending@sentientai_test_bot"))
    card = fake_api.sent_messages()[-1]
    assert "canvas.submit_assignment" in card["text"]
    buttons = card["reply_markup"]["inline_keyboard"][0]
    assert buttons[0]["callback_data"].startswith("apv:")
    assert buttons[1]["callback_data"].startswith("dny:")
    await service._client.aclose()


@pytest.mark.asyncio
async def test_pending_from_unlinked_chat_reveals_nothing(session_factory, fake_api):
    service = _make_service(session_factory)
    await service._handle_message(telegram_dm(303, "/pending"))
    # Unlinked: ignored outright, so no card (and nothing else) is sent.
    assert fake_api.sent_messages() == []
    await service._client.aclose()


async def _link(session_factory, email: str, chat_id: int):
    from models.user import User

    user, _ = await make_user(session_factory, email=email)
    async with session_factory() as session:
        row = (
            await session.execute(select(User).where(User.id == user.id))
        ).scalar_one()
        row.telegram_chat_id = chat_id
        await session.commit()
    return user


@pytest.mark.asyncio
async def test_plain_text_from_linked_chat_runs_a_turn_and_replies(
    session_factory, fake_api
):
    user = await _link(session_factory, "tg-chat@example.com", 404)
    calls: list = []

    async def chat(user_id, text, *, new_conversation=False):
        calls.append((user_id, text, new_conversation))
        return {"content": "Found it: $211.49 at Amazon.", "pending_approvals": []}

    service = _make_service(session_factory)
    service.chat = chat
    await service._handle_message(telegram_dm(404, "price of Ergotron HX?"))
    await service.wait_for_chats()

    assert calls == [(str(user.id), "price of Ergotron HX?", False)]
    methods = [m for m, _ in fake_api.calls]
    assert "sendChatAction" in methods  # typing indicator while the turn ran
    assert fake_api.sent_messages()[-1]["text"] == "Found it: $211.49 at Amazon."
    await service._client.aclose()


@pytest.mark.asyncio
async def test_new_command_starts_a_fresh_conversation_once(session_factory, fake_api):
    await _link(session_factory, "tg-new@example.com", 505)
    seen: list = []

    async def chat(user_id, text, *, new_conversation=False):
        seen.append(new_conversation)
        return {"content": "ok"}

    service = _make_service(session_factory)
    service.chat = chat
    await service._handle_message(telegram_dm(505, "/new"))
    assert "Fresh start" in fake_api.sent_messages()[-1]["text"]
    await service._handle_message(telegram_dm(505, "first"))
    await service._handle_message(telegram_dm(505, "second"))
    await service.wait_for_chats()
    # Only the message right after /new opens a new conversation.
    assert seen == [True, False]
    await service._client.aclose()


@pytest.mark.asyncio
async def test_chat_error_and_pending_are_surfaced(session_factory, fake_api):
    await _link(session_factory, "tg-err@example.com", 606)

    async def chat(user_id, text, *, new_conversation=False):
        if text == "boom":
            return {"error": "gemini provider error (HTTP 429): quota"}
        return {
            "content": "I drafted the email.",
            "pending_approvals": ["google_workspace.send_email"],
        }

    service = _make_service(session_factory)
    service.chat = chat
    await service._handle_message(telegram_dm(606, "boom"))
    await service.wait_for_chats()
    assert "quota" in fake_api.sent_messages()[-1]["text"]

    await service._handle_message(telegram_dm(606, "email my professor"))
    await service.wait_for_chats()
    last = fake_api.sent_messages()[-1]["text"]
    assert "I drafted the email." in last and "google_workspace.send_email" in last
    await service._client.aclose()


@pytest.mark.asyncio
async def test_long_reply_is_split_into_telegram_sized_messages(session_factory, fake_api):
    await _link(session_factory, "tg-long@example.com", 707)

    async def chat(user_id, text, *, new_conversation=False):
        return {"content": "\n".join(f"line {i} " + "x" * 80 for i in range(120))}

    service = _make_service(session_factory)
    service.chat = chat
    await service._handle_message(telegram_dm(707, "long one"))
    await service.wait_for_chats()
    sent = fake_api.sent_messages()
    assert len(sent) >= 3 and all(len(m["text"]) <= 4096 for m in sent)
    await service._client.aclose()


@pytest.mark.asyncio
async def test_chat_applier_persists_turn_into_telegram_conversation(
    client, session_factory
):
    """The out-of-band applier writes the same rows the HTTP route does:
    a reusable 'Telegram' conversation, the user message, and the assistant
    message with usage — so the exchange shows up in the web app."""
    from api.routes.agent import TELEGRAM_CONVERSATION_TITLE, build_chat_applier
    from main import app
    from models.conversation import Conversation, Message
    from services.agent.runtime import AgentResponse

    user, _ = await make_user(session_factory, email="tg-applier@example.com")

    class FakeRuntime:
        async def chat(self, **kwargs):
            assert kwargs["messages"][-1]["content"] == "what is 2+2?"
            return AgentResponse(
                content="4", usage={"input_tokens": 12, "output_tokens": 1}
            )

    saved_runtime = getattr(app.state, "agent_runtime", None)
    app.state.agent_runtime = FakeRuntime()
    try:
        chat = build_chat_applier(app, session_factory=session_factory)
        first = await chat(str(user.id), "what is 2+2?")
        assert first["content"] == "4" and "error" not in first
        second = await chat(str(user.id), "what is 2+2?")
        assert second["conversation_id"] == first["conversation_id"]
        fresh = await chat(str(user.id), "what is 2+2?", new_conversation=True)
        assert fresh["conversation_id"] != first["conversation_id"]
    finally:
        app.state.agent_runtime = saved_runtime

    async with session_factory() as session:
        convs = (
            await session.execute(
                select(Conversation).where(Conversation.user_id == user.id)
            )
        ).scalars().all()
        assert [c.title for c in convs] == [TELEGRAM_CONVERSATION_TITLE] * 2
        msgs = (
            await session.execute(
                select(Message).where(
                    Message.conversation_id == uuid.UUID(first["conversation_id"])
                ).order_by(Message.created_at)
            )
        ).scalars().all()
        assert [m.role.value for m in msgs] == ["user", "assistant", "user", "assistant"]
        assert msgs[1].input_tokens == 12 and msgs[1].output_tokens == 1


@pytest.mark.asyncio
async def test_screenshots_from_a_turn_are_sent_as_photos(session_factory, fake_api):
    await _link(session_factory, "tg-photo@example.com", 808)
    png = "data:image/png;base64," + base64.b64encode(b"\x89PNG fake bytes " * 40).decode()

    async def chat(user_id, text, *, new_conversation=False):
        return {
            "content": "Here is the Google Flights page.",
            "images": [{"data_url": png, "caption": "https://www.google.com/travel/flights"}],
        }

    service = _make_service(session_factory)
    service.chat = chat
    await service._handle_message(telegram_dm(808, "screenshot flights"))
    await service.wait_for_chats()
    methods = [m for m, _ in fake_api.calls]
    # Photos go first so the text — which ends with the usage line when the
    # turn reports usage — is the last thing the turn sends.
    assert methods[-2:] == ["sendPhoto", "sendMessage"]
    assert fake_api.calls[-2][1]["_multipart_bytes"] > 100
    await service._client.aclose()


def test_model_never_sees_image_bytes():
    from services.agent.runtime import redact_binary_for_model

    result = {
        "ok": True,
        "url": "https://example.com",
        "image": "data:image/jpeg;base64," + "A" * 5000,
        "nested": [{"image": "data:image/png;base64," + "B" * 400}],
        "small": "data:image/png;base64,QUJD",  # tiny: left alone
    }
    view = redact_binary_for_model(result)
    assert view["url"] == "https://example.com"
    assert "delivered to the user" in view["image"]
    assert "delivered to the user" in view["nested"][0]["image"]
    assert view["small"] == result["small"]


# Telegram's answer to getUpdates while another process holds the token's
# long poll.
_POLL_CONFLICT = {
    "ok": False,
    "error_code": 409,
    "description": (
        "Conflict: terminated by other getUpdates request; make sure that "
        "only one bot instance is running"
    ),
}


class _RecordingLogger:
    def __init__(self) -> None:
        self.records: list[tuple[str, str, dict]] = []

    def __getattr__(self, level: str):
        def log(event: str, **fields) -> None:
            self.records.append((level, event, fields))

        return log

    def events(self, name: str) -> list[tuple[str, str, dict]]:
        return [record for record in self.records if record[1] == name]


@pytest.fixture
def telegram_log(monkeypatch):
    # Patched on the module rather than captured through structlog: the app
    # configures cache_logger_on_first_use, so a module logger bound by an
    # earlier test would bypass a capture installed here.
    from services.notifications import telegram

    recorder = _RecordingLogger()
    monkeypatch.setattr(telegram, "logger", recorder)
    return recorder


async def _run_poll_loop(service, max_sleeps: int) -> list[float]:
    """Drive the real poll loop, recording each wait instead of sleeping,
    and stop it at the ``max_sleeps``-th wait."""
    delays: list[float] = []

    async def fake_sleep(seconds: float) -> None:
        delays.append(seconds)
        if len(delays) >= max_sleeps:
            raise asyncio.CancelledError

    service._sleep = fake_sleep
    with pytest.raises(asyncio.CancelledError):
        await service._poll_loop()
    return delays


@pytest.mark.asyncio
async def test_poller_conflict_warns_once_and_backs_off_exponentially(
    session_factory, fake_api, telegram_log
):
    """Two deployments on one token: the loser gets 409 on every
    getUpdates. It must explain that once, then retry at a doubling
    interval up to a ceiling instead of cutting off the other instance's
    poll every few seconds."""
    fake_api.get_updates = [_POLL_CONFLICT] * 8
    service = _make_service(session_factory)

    delays = await _run_poll_loop(service, max_sleeps=8)

    assert delays == [15, 30, 60, 120, 240, 300, 300, 300]
    conflicts = telegram_log.events("telegram_poller_conflict")
    assert len(conflicts) == 1
    level, _, fields = conflicts[0]
    assert level == "warning"
    assert "terminated by other getUpdates request" in fields["description"]
    assert "Only one running deployment may own a bot" in fields["detail"]
    assert fields["retry_in_seconds"] == 15
    # Not also reported as a generic API error on every retry.
    assert telegram_log.events("telegram_api_error") == []
    await service._client.aclose()


@pytest.mark.asyncio
async def test_poller_conflict_backoff_resets_after_a_successful_poll(
    session_factory, fake_api, telegram_log
):
    fake_api.get_updates = [
        _POLL_CONFLICT,
        _POLL_CONFLICT,
        {"ok": True, "result": []},
        _POLL_CONFLICT,
    ]
    service = _make_service(session_factory)

    delays = await _run_poll_loop(service, max_sleeps=3)

    # The clean poll between the conflicts sends the next one back to 15s.
    assert delays == [15, 30, 15]
    # The second episode falls inside the re-warn window: still one line.
    assert len(telegram_log.events("telegram_poller_conflict")) == 1
    await service._client.aclose()


@pytest.mark.asyncio
async def test_persisting_poller_conflict_is_reannounced_after_an_hour(
    session_factory, fake_api, telegram_log
):
    """Suppression bounds the noise; it must not silence a conflict that is
    still going on, or one that starts again days later."""
    fake_api.get_updates = [_POLL_CONFLICT, _POLL_CONFLICT]
    service = _make_service(session_factory)

    await _run_poll_loop(service, max_sleeps=1)
    service._conflict_warned_at -= 3601
    await _run_poll_loop(service, max_sleeps=1)

    assert len(telegram_log.events("telegram_poller_conflict")) == 2
    await service._client.aclose()


@pytest.mark.asyncio
async def test_every_outgoing_message_disables_link_previews(session_factory, fake_api):
    service = _make_service(session_factory)
    await service._api("sendMessage", chat_id=1, text="see https://canvas.school.edu/courses/1?x=1")
    await service._api("editMessageText", chat_id=1, message_id=2, text="edited")
    await service._api("answerCallbackQuery", callback_query_id="q")
    by_method = dict(fake_api.calls)
    assert by_method["sendMessage"]["link_preview_options"] == {"is_disabled": True}
    assert by_method["editMessageText"]["link_preview_options"] == {"is_disabled": True}
    assert "link_preview_options" not in by_method["answerCallbackQuery"]
    await service._client.aclose()
