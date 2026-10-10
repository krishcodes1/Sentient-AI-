"""Tests for low-risk grants on Telegram (permission tiers): the card's
"⚡ Allow low-risk on <account> · 7 days" row and line, the ``apl:`` press that
approves with remember="low_risk", what the frozen card says with and without
a grant, /grants with its ``rvg:`` Revoke buttons, and /help.

Why it exists: a grant lets an account's small changes run without a card for
a week, so the button must appear only where the runtime offered it, say which
account it is for, and the owner must be able to list and end grants from the
chat. The Bot API is faked at the httpx transport; the decision is a stub or
the real store over in-memory SQLite. Nothing reaches Telegram.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from typing import Any

import httpx
import pytest
from sqlalchemy import select

from services.agent.approvals import StoredAction
from services.agent.permission_grants import DbPermissionGrantStore
from services.audit import _sanitize
from services.notifications import telegram as telegram_module
from services.notifications.grant_commands import NO_GRANTS_TEXT
from tests.conftest import telegram_dm
from tests.test_telegram import FakeTelegramAPI, _link
from tests.test_telegram_decisions import _edits, _press, _service, _wait_for

ACTION_ID = "0f0f0f0f-1111-4111-8111-111111111111"


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


def _card(user_id: str, *, offer: bool = True, tool: str = "google_workspace.modify_labels") -> StoredAction:
    now = datetime.now(timezone.utc)
    return StoredAction(
        action_id=ACTION_ID,
        user_id=user_id,
        tool_name=tool,
        arguments={"message_id": "m1", "add_label_ids": ["STARRED"]},
        reason="Tool 'google_workspace.modify_labels' requires explicit user approval",
        created_at=now.isoformat(),
        expires_at=(now + timedelta(minutes=15)).isoformat(),
        grant_offer={"kind": "low_risk", "connector_id": "c1", "account": "School Gmail"} if offer else None,
    )


def test_the_keyboard_row_names_the_account_and_is_capped():
    keyboard = telegram_module._approval_keyboard(ACTION_ID, None, "School Gmail")
    rows = keyboard["inline_keyboard"]
    assert rows[1] == [
        {"text": "⚡ Allow low-risk on School Gmail · 7 days", "callback_data": "apl:" + ACTION_ID}
    ]
    long = telegram_module._approval_keyboard(ACTION_ID, None, "My very long\nuniversity account name")
    label = long["inline_keyboard"][1][0]["text"]
    account = label.removeprefix("⚡ Allow low-risk on ").removesuffix(" · 7 days")
    assert len(account) <= 24 and "\n" not in account
    assert len(long["inline_keyboard"][1][0]["callback_data"].encode()) <= 64
    # The week row wins (it is desktop.act's), and no offer means two buttons.
    both = telegram_module._approval_keyboard(ACTION_ID, "Calendar", "School Gmail")
    assert both["inline_keyboard"][1][0]["callback_data"].startswith("apw:")
    assert len(telegram_module._approval_keyboard(ACTION_ID)["inline_keyboard"]) == 1


@pytest.mark.asyncio
async def test_a_card_that_offers_a_grant_says_so(session_factory, fake_api):
    user = await _link(session_factory, "tg-lowrisk-card@example.com", 7201)
    service = _service(session_factory)
    try:
        await service.notify_pending(_card(str(user.id)))
        await service.notify_pending(
            StoredAction(**{**_card(str(user.id), offer=False).__dict__, "action_id": "other"})
        )
    finally:
        await service.stop()
    offered, plain = [m for m in fake_api.sent_messages() if m.get("reply_markup")]
    assert "apl:" + ACTION_ID in json.dumps(offered["reply_markup"])
    assert (
        "Or allow low-risk changes on School Gmail for 7 days: save email drafts (nothing is sent); "
        "star, mark important or apply your own labels to emails"
    ) in offered["text"]
    assert "Sends, deletes, sharing and anything other people see still ask. /grants lists and revokes." in offered["text"]
    assert "apl:" not in json.dumps(plain["reply_markup"])
    assert "low-risk" not in plain["text"]


@pytest.mark.asyncio
async def test_apl_approves_with_remember_low_risk_and_says_until_when(session_factory, fake_api):
    user = await _link(session_factory, "tg-lowrisk-apl@example.com", 7202)
    seen: list[dict[str, Any]] = []
    until = (datetime.now(timezone.utc) + timedelta(days=7)).isoformat()

    async def decide(user_id, action_id, approved, *, remember=None, channel=None):
        seen.append({"user_id": user_id, "action_id": action_id, "approved": approved, "remember": remember})
        return {"status": "approved", "low_risk": {"account": "School Gmail", "expires_at": until}}

    service = _service(session_factory, decide=decide)
    try:
        await service._handle_callback(_press("apl:" + ACTION_ID, 7202))
        assert await _wait_for(lambda: bool(_edits(fake_api)))
    finally:
        await service.stop()
    assert seen == [{"user_id": str(user.id), "action_id": ACTION_ID, "approved": True, "remember": "low_risk"}]
    [edited] = _edits(fake_api)
    assert "✅ Approved from this chat. Low-risk changes on School Gmail are allowed until " in edited
    assert edited.endswith("/grants to revoke.")


@pytest.mark.asyncio
async def test_apl_without_a_grant_says_approved_once(session_factory, fake_api):
    await _link(session_factory, "tg-lowrisk-once@example.com", 7203)

    async def decide(user_id, action_id, approved, *, remember=None, channel=None):
        return {"status": "approved"}

    service = _service(session_factory, decide=decide)
    try:
        await service._handle_callback(_press("apl:" + ACTION_ID, 7203))
        assert await _wait_for(lambda: bool(_edits(fake_api)))
    finally:
        await service.stop()
    [edited] = _edits(fake_api)
    assert edited.endswith("✅ Approved from this chat. (approved once)")


@pytest.mark.asyncio
async def test_an_unlinked_chat_cannot_press_apl(session_factory, fake_api):
    decided: list[Any] = []

    async def decide(*args, **kwargs):
        decided.append(args)
        return {"status": "approved"}

    service = _service(session_factory, decide=decide)
    try:
        await service._handle_callback(_press("apl:" + ACTION_ID, 7299))
    finally:
        await service.stop()
    assert decided == []


async def _gmail_row(session_factory, user_id, name: str) -> str:
    from core.security import encrypt_credentials
    from models.connector import AuthMethod, ConnectorConfig, PermissionTier

    async with session_factory() as session:
        row = ConnectorConfig(
            user_id=user_id,
            connector_type="google_workspace",
            display_name=name,
            auth_method=AuthMethod.oauth2,
            encrypted_credentials=encrypt_credentials(json.dumps({"access_token": "t"})),
            granted_scopes=["gmail.modify"],
            permission_tier=PermissionTier.user_confirm,
        )
        session.add(row)
        await session.commit()
        return str(row.id)


@pytest.mark.asyncio
async def test_grants_lists_and_revokes_with_audit(session_factory, fake_api):
    from models.audit import AuditLog

    user = await _link(session_factory, "tg-lowrisk-grants@example.com", 7204)
    store = DbPermissionGrantStore(session_factory)
    school = await _gmail_row(session_factory, user.id, "School Gmail")
    grant = await store.allow(user_id=str(user.id), connector_id=school)
    assert grant is not None
    service = _service(session_factory)
    try:
        await service._handle_update({"update_id": 1, "message": telegram_dm(7204, "/grants")})
        [listing] = [m for m in fake_api.sent_messages() if m.get("reply_markup")]
        assert "• School Gmail — until " in listing["text"]
        assert listing["reply_markup"]["inline_keyboard"] == [
            [{"text": "Revoke School Gmail", "callback_data": "rvg:" + grant.id}]
        ]
        await service._handle_callback(_press("rvg:" + grant.id, 7204))
        # A second press: already ended.
        await service._handle_callback(_press("rvg:" + grant.id, 7204))
        # Another chat cannot revoke anything.
        await service._handle_callback(_press("rvg:" + grant.id, 7298))
        await service._handle_update({"update_id": 2, "message": telegram_dm(7204, "/grants")})
    finally:
        await service.stop()
    texts = [m["text"] for m in fake_api.sent_messages()]
    assert any("School Gmail no longer makes low-risk changes without asking" in t for t in texts)
    assert texts[-1] == NO_GRANTS_TEXT
    assert await store.list_live(str(user.id)) == []
    async with session_factory() as session:
        rows = (await session.execute(select(AuditLog).where(AuditLog.user_id == user.id))).scalars().all()
    [revoked] = [r.reasoning_chain for r in rows if (r.reasoning_chain or {}).get("event") == "permission_grant_revoked"]
    # Ids pass the audit sanitizer like every other value.
    assert revoked["revoked_from"] == "telegram" and revoked["grant_id"] == _sanitize(grant.id)


def test_help_lists_grants():
    assert any(line.startswith("/grants") for line in telegram_module.HELP_LINES)
