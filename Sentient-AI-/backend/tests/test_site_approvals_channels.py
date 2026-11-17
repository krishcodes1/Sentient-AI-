"""Tests for site approvals in the chat channels and the web routes: a
browser.act card on Telegram offers "Allow clicks on <site> for 1 hour" only
where the runtime may make that approval, the ``aps:`` press approves with
remember="site" and the frozen card says until what time, /apps lists and
turns off a site approval, and the web API carries the offer, takes the
decision and reports the hour.

Why it exists: the hour lets clicks on one website run without a card, so
the button must appear only on a card that can be allowed (an https page,
no money warning, no call-check warning), say exactly which site and what
still asks, and the owner must be able to see and end it from the chat and
from Settings. The Bot API is faked at the httpx transport; the web test
drives the real routes, runtime and executor with a scripted model and a fake
act toolkit. Nothing reaches Telegram, a browser or a model.

Connects to: services/notifications/telegram.py, api/routes/agent.py,
api/routes/app_approvals.py, services/agent/app_approvals.py.
"""

from __future__ import annotations

import re
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from typing import Any, AsyncIterator

import httpx
import pytest

from services import capabilities as capability_registry
from services.agent import cancel as agent_cancel
from services.agent.app_approvals import SITE_TOOL, Channel, DbAppApprovalStore
from services.agent.approvals import StoredAction
from services.agent.providers import LLMResponse
from services.agent.runtime import AgentRuntime
from tests.conftest import auth_headers, telegram_dm, use_provider
from tests.test_agent_runtime_vision import RecordingAudit, RecordingProvider
from tests.test_browser_act_card import ctx as browser_ctx
from tests.test_computer_precheck import call
from tests.test_site_approvals_runtime import ANSWER, CAPS, SITE, FakeAct
from tests.test_telegram import FakeTelegramAPI, _link
from tests.test_telegram_decisions import _edits, _press, _service, _wait_for

ACTION_ID = "5e5e5e5e-2222-4222-8222-222222222222"
DEVICE = "7c1f0e2a-5b3d-4c8e-9a6f-0d2e4b6a8c1e"
SITE_ROW = {"text": f"🖱 Allow clicks on {SITE} for 1 hour", "callback_data": "aps:" + ACTION_ID}
SITE_LINE = (
    f"Or allow clicks on {SITE} for 1 hour: I can then click, pick options and tick boxes on "
    "that site without asking, for requests from this chat. I'll still ask before I type, send "
    "a form, or press anything that changes, cancels, sends, agrees to or pays for something. "
    "Send /apps to see or undo this."
)


@pytest.fixture
def fake_api(monkeypatch):
    api = FakeTelegramAPI()
    real_client_cls = httpx.AsyncClient
    monkeypatch.setattr(
        httpx,
        "AsyncClient",
        lambda **kw: real_client_cls(**{**kw, "transport": httpx.MockTransport(api.handler)}),
    )
    return api


def _card(user_id: str, page: dict[str, Any] | None = None, **extra: Any) -> StoredAction:
    """A browser.act card as the runtime parks it: the call, and the page the
    act toolkit bound it to under ``_page``."""
    now = datetime.now(timezone.utc)
    bound = {"origin": f"https://{SITE}", "address": "a1", "outline": "o1", "scheme": "https", "quiet": True}
    bound.update(page or {})
    return StoredAction(
        action_id=ACTION_ID,
        user_id=user_id,
        tool_name=SITE_TOOL,
        arguments={"action": "click", "ref": "e7", "_page": bound},
        reason=f'Click "Seat F7" on {SITE}',
        created_at=now.isoformat(),
        expires_at=(now + timedelta(minutes=15)).isoformat(),
        **extra,
    )


# ── the card ────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_a_browser_card_offers_the_hour_for_its_site_and_says_what_still_asks(
    session_factory, fake_api
):
    user = await _link(session_factory, "tg-site-card@example.com", 9401)
    service = _service(session_factory)
    try:
        await service.notify_pending(_card(str(user.id)))
    finally:
        await service.stop()
    [message] = fake_api.sent_messages()
    rows = message["reply_markup"]["inline_keyboard"]
    assert [button["callback_data"][:4] for button in rows[0]] == ["apv:", "dny:"]
    assert rows[1:] == [[SITE_ROW]]
    assert message["text"].endswith(SITE_LINE)
    assert "—" not in message["text"] and "browser.act" not in message["text"]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("page", "extra"),
    [
        ({"money": {"order_total": True}}, {}),  # the card warns the step may place an order
        ({"origin": f"http://{SITE}", "scheme": "http"}, {}),  # not an https page
        ({"origin": "https://localhost"}, {}),  # not a public site
        # A call check's warning: this one is approved once, never for longer.
        ({}, {"security_notes": [{"kind": "link", "severity": "warn", "text": "This link is new."}]}),
    ],
    ids=["money-warning", "http", "not-public", "security-warning"],
)
async def test_a_card_that_cannot_be_allowed_for_the_hour_offers_only_approve_and_deny(
    session_factory, fake_api, page, extra
):
    user = await _link(session_factory, f"tg-site-none-{len(str(page)) + len(extra)}@example.com", 9402)
    service = _service(session_factory)
    try:
        await service.notify_pending(_card(str(user.id), page, **extra))
    finally:
        await service.stop()
    [message] = fake_api.sent_messages()
    rows = message["reply_markup"]["inline_keyboard"]
    assert len(rows) == 1 and "1 hour" not in message["text"]


def test_a_long_site_name_keeps_its_end_on_the_button():
    from services.notifications.telegram import _approval_keyboard

    host = "a-very-long-subdomain-name.tickets.example-theatres.com"
    [_, [button]] = _approval_keyboard("x", hourly_site=host)["inline_keyboard"]
    assert button["text"].startswith("🖱 Allow clicks on …") and button["text"].endswith(
        "example-theatres.com for 1 hour"
    )
    assert len(button["text"]) <= 64 and button["callback_data"] == "aps:x"


# ── the press ───────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_aps_approves_with_remember_site_and_says_until_what_time(session_factory, fake_api):
    user = await _link(session_factory, "tg-site-aps@example.com", 9403)
    seen: list[dict[str, Any]] = []
    until = (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat()

    async def decide(user_id, action_id, approved, *, remember=None, channel=None):
        seen.append({"user_id": user_id, "action_id": action_id, "approved": approved,
                     "remember": remember, "channel": channel})
        return {"status": "approved", "site": {"app": SITE, "expires_at": until}}

    service = _service(session_factory, decide=decide)
    try:
        await service._handle_callback(_press("aps:" + ACTION_ID, 9403))
        assert await _wait_for(lambda: bool(_edits(fake_api)))
    finally:
        await service.stop()
    assert seen == [{"user_id": str(user.id), "action_id": ACTION_ID, "approved": True,
                     "remember": "site", "channel": Channel.telegram(9403)}]
    [edited] = _edits(fake_api)
    assert re.search(
        r"\n\n✅ Approved at \d{1,2}:\d{2} [AP]M\. I can click around on "
        + re.escape(SITE)
        + r" without asking until \d{1,2}:\d{2} [AP]M\. Send /apps to undo that\.$",
        edited,
    ), edited


@pytest.mark.asyncio
async def test_aps_without_an_approval_made_says_approved_once(session_factory, fake_api):
    await _link(session_factory, "tg-site-once@example.com", 9404)

    async def decide(user_id, action_id, approved, *, remember=None, channel=None):
        return {"status": "approved"}

    service = _service(session_factory, decide=decide)
    try:
        await service._handle_callback(_press("aps:" + ACTION_ID, 9404))
        assert await _wait_for(lambda: bool(_edits(fake_api)))
    finally:
        await service.stop()
    [edited] = _edits(fake_api)
    assert edited.endswith(
        " I couldn't turn on the hour without asking, so I'll still ask next time."
    ), edited


@pytest.mark.asyncio
async def test_an_unlinked_chat_cannot_press_aps(session_factory, fake_api):
    decided: list[Any] = []

    async def decide(*args, **kwargs):
        decided.append(args)
        return {"status": "approved"}

    service = _service(session_factory, decide=decide)
    try:
        await service._handle_callback(_press("aps:" + ACTION_ID, 9499))
    finally:
        await service.stop()
    assert decided == []


# ── /apps ───────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_apps_lists_a_site_with_its_time_and_turns_it_off(session_factory, fake_api):
    user = await _link(session_factory, "tg-site-apps@example.com", 9405)
    store = DbAppApprovalStore(session_factory)
    here = Channel.telegram(9405)
    site = await store.allow(user_id=str(user.id), app=SITE, channel=here, tool=SITE_TOOL)
    await store.allow(user_id=str(user.id), app="Calendar", channel=here)
    service = _service(session_factory)
    try:
        await service._handle_message(telegram_dm(9405, "/apps"))
        await service.wait_for_chats()
        listing = fake_api.sent_messages()[-1]
        lines = listing["text"].split("\n")
        assert lines[0] == "I can use these apps and websites without asking you, until the time shown:"
        assert any(
            re.fullmatch(rf"• Clicks on {re.escape(SITE)}, allowed from this chat until \d{{1,2}}:\d{{2}} [AP]M", line)
            for line in lines
        ), lines
        assert any(line.startswith("• Calendar, allowed from this chat until ") for line in lines)
        buttons = [row[0] for row in listing["reply_markup"]["inline_keyboard"]]
        [off] = [b for b in buttons if b["text"] == f"Turn off for {SITE}"]
        assert off["callback_data"] == "rva:" + site.id

        await service._handle_callback(_press(off["callback_data"], 9405))
        done = f"Done. I'll ask you first again before clicking on {SITE}."
        assert await _wait_for(lambda: fake_api.sent_messages()[-1]["text"] == done)
    finally:
        await service.stop()
    left = await store.list_active(str(user.id))
    assert [a.app for a in left] == ["Calendar"]
    # The revoke is filed under the browser, as the web's is.
    from sqlalchemy import select

    from models.audit import AuditLog

    async with session_factory() as session:
        rows = (await session.execute(select(AuditLog).where(AuditLog.user_id == user.id))).scalars().all()
    [revoked] = [r for r in rows if (r.reasoning_chain or {}).get("event") == "app_approval_revoked"]
    assert (revoked.connector_name, revoked.action) == ("browser", "act")


# ── the web routes ──────────────────────────────────────────────────────────


@asynccontextmanager
async def wired(session_factory, provider, act: FakeAct) -> AsyncIterator[AgentRuntime]:
    """The HTTP routes over one runtime whose browser.act runs on *act*,
    with the database approval and app-approval stores main.py wires."""
    from core.config import settings
    from main import app
    from services.agent.approvals import DbApprovalStore
    from services.agent.tool_registry import ConnectorToolExecutor, RuntimePermissionAdapter

    switches = {key: key in CAPS for key in capability_registry.keys()}
    statuses = capability_registry.report(switches, browser_ctx(), use_cache=False)
    by_key = capability_registry.statuses_by_key(statuses)

    async def gate():
        return by_key

    async def report():
        return statuses

    async def setup_completed():
        return True

    runtime = AgentRuntime(
        config=settings,
        permission_engine=RuntimePermissionAdapter(capability_gate=gate),
        audit_service=RecordingAudit(),
        approval_store=DbApprovalStore(session_factory=session_factory),
        tool_executor=ConnectorToolExecutor(session_factory=None, capability_gate=gate, act_toolkit=act),
        app_approval_store=DbAppApprovalStore(session_factory),
    )
    use_provider(runtime, provider)
    saved = dict(app.state._state)
    app.state.agent_runtime = runtime
    app.state.installation = SimpleNamespace(report=report, setup_completed=setup_completed)
    app.state.mcp_catalog = None
    try:
        yield runtime
    finally:
        app.state._state.clear()
        app.state._state.update(saved)


@pytest.mark.asyncio
async def test_web_allow_clicks_for_an_hour_then_this_browser_clicks_without_a_card(
    client, session_factory
):
    from tests.conftest import make_user

    user, token = await make_user(session_factory, "site-web-allow@example.com")
    agent_cancel.clear(str(user.id))
    headers = {**auth_headers(token), "X-Crawler-Device": DEVICE}
    act = FakeAct()
    provider = RecordingProvider(
        [
            call("a1", SITE_TOOL, action="click", ref="e7"),
            ANSWER,  # the turn resumed after the approval
            call("a2", SITE_TOOL, action="click", ref="e8"),
            LLMResponse(content="Both seats are picked."),
            call("a3", SITE_TOOL, action="click", ref="e9"),
        ]
    )
    async with wired(session_factory, provider, act):
        conv = (await client.post("/api/agent/conversations", headers=headers, json={})).json()
        turn = (
            await client.post(
                f"/api/agent/conversations/{conv['id']}/messages",
                headers=headers,
                json={"content": "Pick seats F7 and F8 for the 7:15 showing."},
            )
        ).json()
        [card] = turn["pending_approvals"]
        assert card["hourly_site"] == SITE and card["weekly_app"] is None
        listed = (await client.get("/api/agent/approvals", headers=headers)).json()
        assert listed[0]["hourly_site"] == SITE

        decided = await client.post(
            f"/api/agent/approvals/{card['action_id']}",
            headers=headers,
            json={"approved": True, "remember": "site"},
        )
        assert decided.status_code == 200, decided.text
        body = decided.json()
        assert body["site"]["app"] == SITE and body["weekly"] is None
        until = datetime.fromisoformat(body["site"]["expires_at"])
        assert timedelta(minutes=55) < until - datetime.now(timezone.utc) <= timedelta(hours=1)

        # Settings lists it as a site, from this browser.
        [row] = (await client.get("/api/agent/app-approvals", headers=headers)).json()
        assert row["kind"] == "site" and row["app"] == SITE and row["this_device"] is True

        again = (
            await client.post(
                f"/api/agent/conversations/{conv['id']}/messages",
                headers=headers,
                json={"content": "and F8"},
            )
        ).json()
        assert again["pending_approvals"] == []
        assert [action for action, _params, _approved in act.ran] == ["click", "click"]

        # Another browser (no device header) still gets a card.
        elsewhere = (
            await client.post(
                f"/api/agent/conversations/{conv['id']}/messages",
                headers=auth_headers(token),
                json={"content": "one more"},
            )
        ).json()
        assert len(elsewhere["pending_approvals"]) == 1 and len(act.ran) == 2
    agent_cancel.clear(str(user.id))


@pytest.mark.asyncio
async def test_web_site_without_a_device_header_approves_once(client, session_factory):
    from tests.conftest import make_user

    user, token = await make_user(session_factory, "site-web-nodevice@example.com")
    agent_cancel.clear(str(user.id))
    act = FakeAct()
    provider = RecordingProvider([call("a1", SITE_TOOL, action="click", ref="e7"), ANSWER])
    async with wired(session_factory, provider, act):
        conv = (
            await client.post("/api/agent/conversations", headers=auth_headers(token), json={})
        ).json()
        turn = (
            await client.post(
                f"/api/agent/conversations/{conv['id']}/messages",
                headers=auth_headers(token),
                json={"content": "Pick seat F7."},
            )
        ).json()
        [card] = turn["pending_approvals"]
        decided = await client.post(
            f"/api/agent/approvals/{card['action_id']}",
            headers=auth_headers(token),
            json={"approved": True, "remember": "site"},
        )
        assert decided.status_code == 200, decided.text
        assert decided.json()["site"] is None and len(act.ran) == 1
        assert (await client.get("/api/agent/app-approvals", headers=auth_headers(token))).json() == []
    agent_cancel.clear(str(user.id))
