"""End-to-end tests for weekly app approvals and approved acts that bring
their app forward, through Telegram and the web routes.

Why it exists: seen live on Telegram. "what am I doing on the 15th of this
month" took six cards (Switch to Calendar, Click, Switch to Calendar, Click,
Switch to Calendar, Click) and about 129k tokens: each Approve tap on the same
computer put Telegram in front, the approved click was refused, and the model
asked for focus_window again (spec 2026-09-25-weekly-app-approvals §1). These
tests drive the real chat and decision appliers, the database approval and
app-approval stores, the HTTP routes and the computer toolkit over the
in-memory fake desktop, with the Bot API faked at the httpx transport.
Nothing calls a model, Telegram or a real screen.
"""

from __future__ import annotations

from contextlib import asynccontextmanager
from types import SimpleNamespace
from typing import Any, AsyncIterator

import httpx
import pytest
from sqlalchemy import select

from services import capabilities as capability_registry
from services.agent import cancel as agent_cancel
from services.agent.app_approvals import DbAppApprovalStore, Channel
from services.agent.providers import LLMResponse, ToolCall
from services.agent.runtime import AgentRuntime
from services.tools.computer import backend as computer_backend
from services.tools.computer.backend_fake import FakeApp, FakeBackend, FakeWindow, make_node
from services.tools.computer.toolkit import ComputerToolkit
from tests.conftest import auth_headers, telegram_dm, use_provider
from tests.test_agent_runtime_vision import RecordingAudit, RecordingProvider
from tests.test_telegram import _link
from tests.test_telegram_decisions import _press, _service
from tests.test_telegram import FakeTelegramAPI
from tests.test_telegram_desktop_resume import (
    _cards,
    _statuses,
    _texts,
    _wait_for,
    calendar_desktop,
)

ASK = "What am I doing on the 15th of this month?"
DEVICE = "7c1f0e2a-5b3d-4c8e-9a6f-0d2e4b6a8c1e"


def act(call_id: str, **arguments: Any) -> LLMResponse:
    return LLMResponse(
        content="", tool_calls=[ToolCall(id=call_id, name="desktop.act", arguments=arguments)]
    )


FOCUS = act("f1", action="focus_window", app="Calendar")
OPEN_CALENDAR = act("o1", action="open_app", app="Calendar")
SCROLL = act("s1", action="scroll", direction="down")
SCROLL_AGAIN = act("s2", action="scroll", direction="up")
OBSERVE = LLMResponse(
    content="",
    tool_calls=[ToolCall(id="ob", name="desktop.observe", arguments={"action": "outline"})],
)
ANSWER = LLMResponse(
    content="On the 15th you have Dentist at 10:00 and Team sync at 15:00.",
    usage={"input_tokens": 900, "output_tokens": 40},
)
ANSWER_16 = LLMResponse(
    content="Nothing on the 16th.", usage={"input_tokens": 900, "output_tokens": 9}
)


@pytest.fixture
def fake_api(monkeypatch):
    """The Bot API, faked at the httpx transport."""
    api = FakeTelegramAPI()
    real_client_cls = httpx.AsyncClient
    monkeypatch.setattr(
        httpx,
        "AsyncClient",
        lambda **kw: real_client_cls(**{**kw, "transport": httpx.MockTransport(api.handler)}),
    )
    return api


@pytest.fixture
def touched():
    """User ids whose stop is forgotten after the test (stops live in
    process memory)."""
    ids: set[str] = set()
    yield ids
    for uid in ids:
        agent_cancel.clear(uid)


@pytest.fixture
def backend_ready(monkeypatch):
    """computer_control reports on (the toolkit runs on each test's own
    FakeBackend)."""
    monkeypatch.setattr(
        computer_backend, "select_backend", lambda name: FakeBackend(available=(True, ""))
    )


def with_telegram(fake):
    fake.apps["Telegram"] = FakeApp(
        "Telegram", 3, [FakeWindow("Chats", (make_node("button", "Approve"),))]
    )
    return fake


@asynccontextmanager
async def wired(session_factory, provider, fake) -> AsyncIterator[Any]:
    """The bot and the HTTP routes over one runtime whose desktop runs on
    *fake* (computer_control on), with the database approval and
    app-approval stores main.py wires."""
    from api.routes.agent import build_chat_applier, build_decision_applier
    from core.config import settings
    from main import app
    from services.agent.approvals import DbApprovalStore
    from services.agent.tool_registry import ConnectorToolExecutor, RuntimePermissionAdapter
    from services.notifications.telegram import NotifyingApprovalStore

    statuses = _statuses()
    by_key = capability_registry.statuses_by_key(statuses)

    async def gate():
        return by_key

    async def report():
        return statuses

    async def setup_completed():
        return True

    service = _service(session_factory)
    audit = RecordingAudit()
    runtime = AgentRuntime(
        config=settings,
        permission_engine=RuntimePermissionAdapter(capability_gate=gate),
        audit_service=audit,
        approval_store=NotifyingApprovalStore(
            DbApprovalStore(session_factory=session_factory), notify=service.notify_pending
        ),
        tool_executor=ConnectorToolExecutor(
            session_factory=None,
            capability_gate=gate,
            computer_toolkit=ComputerToolkit(fake, cancel_flag=agent_cancel.is_cancelled),
        ),
        app_approval_store=DbAppApprovalStore(session_factory),
    )
    use_provider(runtime, provider)
    saved = dict(app.state._state)
    app.state.agent_runtime = runtime
    app.state.installation = SimpleNamespace(report=report, setup_completed=setup_completed)
    app.state.mcp_catalog = None
    service.chat = build_chat_applier(app, session_factory=session_factory)
    service.decide = build_decision_applier(app, session_factory=session_factory)
    service.audit = audit
    try:
        yield service
    finally:
        app.state._state.clear()
        app.state._state.update(saved)
        await service._client.aclose()


def _action_id(card: dict[str, Any]) -> str:
    return card["reply_markup"]["inline_keyboard"][0][0]["callback_data"][4:]


async def _say(service, chat_id: int, text: str) -> None:
    await service._handle_message(telegram_dm(chat_id, text))
    await service.wait_for_chats()


async def _tap(service, data: str, chat_id: int, message_id: int = 9) -> None:
    await service._handle_callback(_press(data, chat_id, message_id))
    await service.wait_for_chats()


def _edits(api) -> list[str]:
    return [p["text"] for m, p in api.calls if m == "editMessageText"]


# ── the loop from the transcript is gone ─────────────────────────────────────


@pytest.mark.asyncio
async def test_an_approve_tap_in_telegram_on_this_computer_no_longer_refuses_the_act(
    session_factory, fake_api, touched, backend_ready
):
    # Before: the approved scroll met Telegram in front, was refused
    # (frontmost_changed), and the model asked for "Switch to Calendar"
    # again, whose tap put Telegram in front again.
    user = await _link(session_factory, "wk-loop@example.com", 9301)
    touched.add(str(user.id))
    fake = with_telegram(calendar_desktop())
    provider = RecordingProvider([FOCUS, SCROLL, ANSWER])
    async with wired(session_factory, provider, fake) as service:
        await _say(service, 9301, ASK)
        assert await _wait_for(lambda: len(_cards(fake_api)) == 1)
        fake.front = "Telegram"  # the tap, in Telegram on this computer
        await _tap(service, "apv:" + _action_id(_cards(fake_api)[0]), 9301)
        assert await _wait_for(lambda: len(_cards(fake_api)) == 2)
        fake.front = "Telegram"
        await _tap(service, "apv:" + _action_id(_cards(fake_api)[1]), 9301, 10)

    assert fake.events == [
        ("focus_window", "Calendar", 0),
        ("focus_window", "Calendar", 0),  # brought forward for the approved scroll
        ("scroll", "down", 5),
    ]
    assert len(_cards(fake_api)) == 2  # no third "Switch to Calendar"
    assert _texts(fake_api)[-1].startswith(ANSWER.content)


# ── Allow for 7 days, from Telegram ──────────────────────────────────────────


@pytest.mark.asyncio
async def test_allow_for_7_days_then_calendar_needs_no_more_cards_from_this_chat(
    session_factory, fake_api, touched, backend_ready
):
    user = await _link(session_factory, "wk-allow@example.com", 9302)
    touched.add(str(user.id))
    fake = calendar_desktop()
    provider = RecordingProvider([OPEN_CALENDAR, SCROLL, ANSWER, SCROLL_AGAIN, ANSWER_16])
    async with wired(session_factory, provider, fake) as service:
        await _say(service, 9302, ASK)
        assert await _wait_for(lambda: len(_cards(fake_api)) == 1)
        [card] = _cards(fake_api)
        keyboard = card["reply_markup"]["inline_keyboard"]
        assert [b["text"] for b in keyboard[0]] == ["✅ Approve", "❌ Deny"]
        assert keyboard[1][0]["text"] == "📅 Allow Calendar for 7 days"
        assert keyboard[1][0]["callback_data"] == "apw:" + _action_id(card)
        assert "Or allow Calendar for 7 days" in card["text"]

        await _tap(service, "apw:" + _action_id(card), 9302)
        # The resumed turn scrolled with no card and answered.
        assert fake.events == [("open_app", "Calendar"), ("scroll", "down", 5)]
        assert _texts(fake_api)[-1].startswith(ANSWER.content)
        assert "Calendar is allowed for 7 days, until" in _edits(fake_api)[-1]

        # A new message from the same chat: Calendar acts at once.
        await _say(service, 9302, "and the 16th?")
        assert fake.events[-1] == ("scroll", "up", 5)
        assert _texts(fake_api)[-1].startswith(ANSWER_16.content)
        assert len(_cards(fake_api)) == 1

    [approval] = await DbAppApprovalStore(session_factory).list_active(str(user.id))
    assert approval.app == "Calendar" and approval.holds_for(Channel.telegram(9302))
    granted = [e for e in service.audit.entries if e["event"] == "app_approval_granted"]
    assert len(granted) == 1


@pytest.mark.asyncio
async def test_a_card_for_an_app_off_the_list_offers_no_week(
    session_factory, fake_api, touched, backend_ready
):
    user = await _link(session_factory, "wk-finder@example.com", 9303)
    touched.add(str(user.id))
    fake = calendar_desktop()  # Finder in front
    provider = RecordingProvider([OBSERVE, SCROLL])
    async with wired(session_factory, provider, fake) as service:
        await _say(service, 9303, "scroll the desktop")
        assert await _wait_for(lambda: len(_cards(fake_api)) == 1)
    [card] = _cards(fake_api)
    assert len(card["reply_markup"]["inline_keyboard"]) == 1
    assert "for 7 days" not in card["text"]


@pytest.mark.asyncio
async def test_an_approval_from_a_chat_ends_when_telegram_is_linked_elsewhere(
    session_factory, fake_api, touched, backend_ready
):
    from models.user import User

    user = await _link(session_factory, "wk-relink@example.com", 9304)
    touched.add(str(user.id))
    await DbAppApprovalStore(session_factory).allow(
        user_id=str(user.id), app="Calendar", channel=Channel.telegram(9304)
    )
    async with session_factory() as session:
        row = (await session.execute(select(User).where(User.id == user.id))).scalar_one()
        row.telegram_chat_id = 9305
        await session.commit()
    fake = calendar_desktop()
    provider = RecordingProvider([OPEN_CALENDAR])
    async with wired(session_factory, provider, fake) as service:
        await _say(service, 9305, ASK)
        assert await _wait_for(lambda: len(_cards(fake_api)) == 1)
    assert fake.events == []


@pytest.mark.asyncio
async def test_the_appliers_use_a_telegram_channel_only_while_it_is_the_linked_chat(
    session_factory, fake_api, touched, backend_ready
):
    # The bot already drops messages and taps from a chat that is not
    # linked; the appliers check again, so no other caller can hand them a
    # chat the account has moved away from.
    from models.user import User

    user = await _link(session_factory, "wk-stale-chat@example.com", 9309)
    touched.add(str(user.id))
    await DbAppApprovalStore(session_factory).allow(
        user_id=str(user.id), app="Calendar", channel=Channel.telegram(9309)
    )
    async with session_factory() as session:
        row = (await session.execute(select(User).where(User.id == user.id))).scalar_one()
        row.telegram_chat_id = 9310
        await session.commit()
    fake = calendar_desktop()
    async with wired(session_factory, RecordingProvider([OPEN_CALENDAR]), fake) as service:
        outcome = await service.chat(str(user.id), ASK, channel=Channel.telegram(9309))
    assert outcome["pending_approvals"] == ["desktop.act"]
    assert fake.events == []


@pytest.mark.asyncio
async def test_apps_lists_the_allowed_apps_and_revokes_one(
    session_factory, fake_api, touched, backend_ready
):
    from models.audit import AuditLog

    user = await _link(session_factory, "wk-apps@example.com", 9306)
    touched.add(str(user.id))
    store = DbAppApprovalStore(session_factory)
    here = await store.allow(user_id=str(user.id), app="Calendar", channel=Channel.telegram(9306))
    await store.allow(user_id=str(user.id), app="Notes", channel=Channel.web(DEVICE))
    async with wired(session_factory, RecordingProvider([]), calendar_desktop()) as service:
        await _say(service, 9306, "/apps")
        [listing] = [m for m in fake_api.sent_messages() if m.get("reply_markup")]
        assert "Calendar — from this chat, until" in listing["text"]
        assert "Notes — from the web app, until" in listing["text"]
        buttons = [row[0] for row in listing["reply_markup"]["inline_keyboard"]]
        assert buttons[0] == {"text": "Revoke Calendar", "callback_data": "rva:" + here.id}

        await _tap(service, "rva:" + here.id, 9306)
        assert "Calendar is no longer allowed" in _texts(fake_api)[-1]
        # A second tap on the same button: already ended, nothing else.
        await _tap(service, "rva:" + here.id, 9306)

    assert [a.app for a in await store.list_active(str(user.id))] == ["Notes"]
    async with session_factory() as session:
        rows = (await session.execute(select(AuditLog))).scalars().all()
    revoked = [r for r in rows if (r.reasoning_chain or {}).get("event") == "app_approval_revoked"]
    assert len(revoked) == 1 and revoked[0].reasoning_chain["app"] == "Calendar"


@pytest.mark.asyncio
async def test_apps_with_nothing_allowed_says_how_to_allow_one(
    session_factory, fake_api, touched, backend_ready
):
    user = await _link(session_factory, "wk-apps-empty@example.com", 9307)
    touched.add(str(user.id))
    async with wired(session_factory, RecordingProvider([]), calendar_desktop()) as service:
        await _say(service, 9307, "/apps")
    assert "No apps are allowed for a week" in _texts(fake_api)[-1]


@pytest.mark.asyncio
async def test_unlinking_telegram_revokes_its_approvals(client, session_factory, backend_ready):
    from tests.conftest import make_user

    user, token = await make_user(session_factory, "wk-unlink@example.com")
    store = DbAppApprovalStore(session_factory)
    await store.allow(user_id=str(user.id), app="Calendar", channel=Channel.telegram(9308))
    web = await store.allow(user_id=str(user.id), app="Calendar", channel=Channel.web(DEVICE))
    async with wired(session_factory, RecordingProvider([]), calendar_desktop()):
        response = await client.delete("/api/telegram/link", headers=auth_headers(token))
    assert response.status_code == 204
    assert [a.id for a in await store.list_active(str(user.id))] == [web.id]


# ── the web app ──────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_web_lists_and_revokes_approvals_and_marks_this_browser(
    client, session_factory, backend_ready
):
    from tests.conftest import make_user

    user, token = await make_user(session_factory, "wk-web-list@example.com")
    other, other_token = await make_user(session_factory, "wk-web-other@example.com")
    store = DbAppApprovalStore(session_factory)
    tg = await store.allow(user_id=str(user.id), app="Calendar", channel=Channel.telegram(1))
    web = await store.allow(user_id=str(user.id), app="Notes", channel=Channel.web(DEVICE))
    headers = {**auth_headers(token), "X-Crawler-Device": DEVICE}
    async with wired(session_factory, RecordingProvider([]), calendar_desktop()):
        listed = (await client.get("/api/agent/app-approvals", headers=headers)).json()
        assert {(a["app"], a["channel"], a["this_device"]) for a in listed} == {
            ("Calendar", "telegram", False),
            ("Notes", "web", True),
        }
        # Another user can neither see nor revoke them.
        assert (
            await client.get("/api/agent/app-approvals", headers=auth_headers(other_token))
        ).json() == []
        assert (
            await client.delete(
                f"/api/agent/app-approvals/{web.id}", headers=auth_headers(other_token)
            )
        ).status_code == 404

        assert (
            await client.delete(f"/api/agent/app-approvals/{web.id}", headers=headers)
        ).status_code == 204
        assert (
            await client.delete(f"/api/agent/app-approvals/{web.id}", headers=headers)
        ).status_code == 404
        listed = (await client.get("/api/agent/app-approvals", headers=headers)).json()
    assert [a["id"] for a in listed] == [tg.id]


@pytest.mark.asyncio
async def test_web_allow_for_7_days_then_this_browser_acts_without_a_card(
    client, session_factory, backend_ready
):
    from tests.conftest import make_user

    user, token = await make_user(session_factory, "wk-web-allow@example.com")
    agent_cancel.clear(str(user.id))
    headers = {**auth_headers(token), "X-Crawler-Device": DEVICE}
    fake = calendar_desktop()
    provider = RecordingProvider([OPEN_CALENDAR, ANSWER, SCROLL, ANSWER_16, SCROLL])
    async with wired(session_factory, provider, fake):
        conv = (await client.post("/api/agent/conversations", headers=headers, json={})).json()
        turn = (
            await client.post(
                f"/api/agent/conversations/{conv['id']}/messages",
                headers=headers,
                json={"content": ASK},
            )
        ).json()
        [card] = turn["pending_approvals"]
        assert card["weekly_app"] == "Calendar"
        listed = (await client.get("/api/agent/approvals", headers=headers)).json()
        assert listed[0]["weekly_app"] == "Calendar"

        decided = await client.post(
            f"/api/agent/approvals/{card['action_id']}",
            headers=headers,
            json={"approved": True, "remember": "week"},
        )
        assert decided.status_code == 200, decided.text
        assert decided.json()["weekly"]["app"] == "Calendar"

        again = (
            await client.post(
                f"/api/agent/conversations/{conv['id']}/messages",
                headers=headers,
                json={"content": "and the 16th?"},
            )
        ).json()
        assert again["pending_approvals"] == []
        assert fake.events[-1] == ("scroll", "down", 5)

        # Another browser (or none) still gets a card.
        elsewhere = (
            await client.post(
                f"/api/agent/conversations/{conv['id']}/messages",
                headers=auth_headers(token),
                json={"content": "scroll once more"},
            )
        ).json()
        assert len(elsewhere["pending_approvals"]) == 1
    agent_cancel.clear(str(user.id))


@pytest.mark.asyncio
async def test_web_week_without_a_device_header_approves_once(
    client, session_factory, backend_ready
):
    from tests.conftest import make_user

    user, token = await make_user(session_factory, "wk-web-nodevice@example.com")
    agent_cancel.clear(str(user.id))
    provider = RecordingProvider([OPEN_CALENDAR, ANSWER])
    async with wired(session_factory, provider, calendar_desktop()):
        conv = (
            await client.post("/api/agent/conversations", headers=auth_headers(token), json={})
        ).json()
        turn = (
            await client.post(
                f"/api/agent/conversations/{conv['id']}/messages",
                headers=auth_headers(token),
                json={"content": ASK},
            )
        ).json()
        [card] = turn["pending_approvals"]
        decided = await client.post(
            f"/api/agent/approvals/{card['action_id']}",
            headers=auth_headers(token),
            json={"approved": True, "remember": "week"},
        )
    assert decided.status_code == 200
    assert decided.json()["weekly"] is None
    assert await DbAppApprovalStore(session_factory).list_active(str(user.id)) == []
    agent_cancel.clear(str(user.id))
