"""Telegram approval-channel tests: linking security, decision
authorization, and the notifying approval-store decorator.

The Telegram Bot API is faked at the httpx-transport level so the service
under test runs its real request/response code without any network.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

import httpx
import pytest
from sqlalchemy import select

from tests.conftest import auth_headers, make_user


class FakeTelegramAPI:
    """Records outgoing Bot API calls and scripts their results."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, dict]] = []
        self.username = "sentientai_test_bot"

    def handler(self, request: httpx.Request) -> httpx.Response:
        method = request.url.path.rsplit("/", 1)[-1]
        payload = json.loads(request.content or b"{}")
        self.calls.append((method, payload))
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

    await service._handle_message(
        {"chat": {"id": 424242}, "text": f"/start {code}"}
    )

    async with session_factory() as session:
        row = (
            await session.execute(select(User).where(User.id == user.id))
        ).scalar_one()
        assert row.telegram_chat_id == 424242
        # Single-use: the code is destroyed on link.
        assert row.telegram_link_code is None

    # Replaying the same code must not re-link (it is gone).
    await service._handle_message(
        {"chat": {"id": 999999}, "text": f"/start {code}"}
    )
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

    await service._handle_message({"chat": {"id": 555}, "text": f"/start {code}"})

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
            "data": "apv:some-action-id",
            "message": {"chat": {"id": 31337}, "message_id": 1, "text": "x"},
        }
    )
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
            "data": "dny:action-abc",
            "message": {"chat": {"id": 777001}, "message_id": 2, "text": "req"},
        }
    )
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

    # No service on app.state (default in tests) → configured: false.
    resp = await client.get("/api/telegram/status", headers=auth_headers(token))
    assert resp.status_code == 200
    assert resp.json() == {
        "configured": False,
        "linked": False,
        "bot_username": None,
    }

    resp = await client.post("/api/telegram/link", headers=auth_headers(token))
    assert resp.status_code == 503

    # With the service installed, status reports and link mints a URL.
    from main import app

    service = _make_service(session_factory)
    app.state.telegram = service
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
        app.state.telegram = None
        await service._client.aclose()
