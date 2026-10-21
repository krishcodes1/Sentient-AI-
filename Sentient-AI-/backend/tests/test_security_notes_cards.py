"""Tests for security notes on approval cards (services/agent/approvals.py,
services/notifications/cards.py, telegram.py, slack.py, api/routes/agent.py): they
prove notes survive the database and memory stores (a corrupt column reads as no
notes, and a store without the keyword is called as before); the approvals list and
the turn response carry them; Telegram shows them after the risk note on text,
purchase and act cards and keeps a photo caption within 1,024 units; Slack shows
them after the risk note; a card with a warning offers neither "Allow for 7 days"
nor "Allow low-risk changes" on any channel; notes never change the arguments
digest or check code; the VirusTotal upload card hides its reserved key everywhere;
and a card without notes is byte for byte the text the same card gives on main at
a1587cf (the plain-language cards of docs/bot-message-style.md).

Why it exists: a note is only useful if the owner sees it wherever they decide, and
a card that carries a warning must never offer standing consent (scaffold E, A18).
The card texts without notes are pinned because every channel's existing tests and
the owner's habits depend on them. The Bot API and Slack's Web API are faked at the
httpx transport; nothing reaches a network or a model.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone
from typing import Any

import pytest
from sqlalchemy import select, update

from core.config import settings
from services.agent.approvals import DbApprovalStore, InMemoryApprovalStore, StoredAction
from services.agent.providers import LLMResponse, ToolCall
from services.agent.runtime import AgentResponse, AgentRuntime, PendingApproval, _stored_to_pending
from services.agent.tool_registry import ConnectorSpec, RuntimePermissionAdapter, build_tools
from services.notifications import cards
from services.security.call_checks import CallCheckPipeline, Note
from services.security.guard import check_stored
from services.tools.computer.toolkit import CARD_KEY
from tests.conftest import auth_headers, make_user, use_provider
from tests.test_call_checks import FakeCheck, note
from tests.test_slack_channel import fast_cards as fast_cards  # noqa: F401 - autouse fixture
from tests.test_slack_channel import harness as harness  # noqa: F401 - fixture
from tests.test_slack_channel import linked as linked  # noqa: F401 - fixture
from tests.test_slack_channel import policy_calls as policy_calls  # noqa: F401 - fixture
from tests.test_slack_channel import slack_log as slack_log  # noqa: F401 - fixture
from tests.test_telegram import _link
from tests.test_telegram_purchase_card import CARD, IMAGE, _caption_of, _keyboard_of
from tests.test_telegram_purchase_card import fake_api as fake_api  # noqa: F401 - fixture

SEND = "google_workspace.send_email"
SEND_ARGS = {"to": "ann@example.com", "subject": "Notes", "body": "See you at 3."}
STAR = "google_workspace.modify_labels"
UPLOAD = "security.upload_to_virustotal"
RISK = "Heads up: this request was shaped by external content."
REASON = "Send an email to ann@example.com from your Gmail"
WARN = {"kind": "recipient_first_time", "severity": "warn", "text": "First time Crawler sends to ann@example.com."}
INFO = {"kind": "recipients_resolved", "severity": "info", "text": "This reply goes to: ann@example.com."}
HIGH = {"kind": "link_dangerous", "severity": "high", "text": "Google Safe Browsing lists evil.example."}
OFFER = {"kind": "low_risk", "connector_id": "c1", "account": "School Gmail"}
CALENDAR_ACT = {"action": "click", "ref": "d1", CARD_KEY: {"app": "Calendar", "target": {"role": "cell", "name": "15"}}}

# What the same cards give on main at a1587cf (rendered there and here with the
# same fixtures and "15 minutes" to expiry; they matched byte for byte).
ASK = "Okay to go ahead? This expires in 15 minutes."
CHECK_CODE = "Check code 1bbb cc38 55a1 4b91"
BASE_TELEGRAM_ACT_CAPTION = (
    '🔐 Click "Continue" on shop.example.com\n\n'
    f"⚠️ Heads up: this request was shaped by external content.\n\n{ASK}"
)
BASE_TELEGRAM_PURCHASE_CAPTION = (
    "🛒 Pay $23.40 at shop.example.com\n\n2 items, paid with Visa ····4242.\n"
    "Crawler can make mistakes. Check the amount and the site before you approve.\n\n"
    f"{ASK}\n\n⚠️ Heads up: this request was shaped by external content."
)
_BASE_GENERIC = (
    "🔐 Send an email to ann@example.com from your Gmail\n\n"
    "⚠️ Heads up: this request was shaped by external content.\n\n"
    "To: ann@example.com\nSubject: Notes\nMessage: See you at 3.\n\n"
    f"{ASK}\n{CHECK_CODE}"
)
BASE_TELEGRAM_TEXT_CARD = _BASE_GENERIC
BASE_SLACK_SECTION = _BASE_GENERIC


def action(user_id: str, tool_name: str = SEND, arguments: Any = None, reason: str = REASON, **extra: Any) -> StoredAction:
    return StoredAction(
        action_id="0f0f0f0f-1111-4111-8111-111111111111",
        user_id=user_id,
        tool_name=tool_name,
        arguments=dict(SEND_ARGS) if arguments is None else arguments,
        reason=reason,
        created_at="2026-10-14T12:00:00+00:00",
        expires_at="2026-10-14T12:15:00+00:00",
        **extra,
    )


@pytest.fixture
def fixed_expiry(monkeypatch):
    # Every channel's question ("Okay to go ahead? This expires in ...")
    # comes from cards.ask_line.
    monkeypatch.setattr(cards, "expires_in_text", lambda _iso: "15 minutes")


def telegram(session_factory, image: Any = IMAGE):
    from services.notifications.telegram import TelegramService

    return TelegramService(
        token="123:fake-token", session_factory=session_factory, approval_image=lambda a: image
    )


# ── storage ──────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_notes_survive_the_database_store_and_a_corrupt_row_reads_as_none(session_factory):
    from models.pending_action import PendingAction

    user, _ = await make_user(session_factory, "notes-db@example.com")
    store = DbApprovalStore(session_factory=session_factory)
    noisy = [WARN, {"kind": "mail_scam", "severity": "medium", "text": "Likely\na scam."}, {"kind": "BAD"}, "x"]
    stored = await store.create(
        user_id=str(user.id), tool_name=SEND, arguments=SEND_ARGS, reason=REASON, security_notes=noisy
    )
    expected = (WARN, {"kind": "mail_scam", "severity": "warn", "text": "Likely a scam."})
    assert stored.security_notes == expected
    [listed] = await store.list_pending(str(user.id))
    assert listed.security_notes == expected
    plain = await store.create(user_id=str(user.id), tool_name=SEND, arguments=SEND_ARGS, reason=REASON)
    assert plain.security_notes == ()
    async with session_factory() as session:
        row = (
            await session.execute(select(PendingAction).where(PendingAction.id == uuid.UUID(plain.action_id)))
        ).scalar_one()
        assert row.security_notes is None  # no notes: NULL, not []
        for bad in ({"kind": "x", "severity": "high", "text": "t"}, ["junk", 3], "text"):
            await session.execute(
                update(PendingAction)
                .where(PendingAction.id == uuid.UUID(stored.action_id))
                .values(security_notes=bad)
            )
            await session.commit()
            [corrupt, _plain] = sorted(
                await store.list_pending(str(user.id)), key=lambda a: a.action_id != stored.action_id
            )
            assert corrupt.security_notes == ()
    outcome, decided = await store.decide(stored.action_id, str(user.id), approved=True)
    assert outcome == "ok" and decided is not None and decided.security_notes == ()


@pytest.mark.asyncio
async def test_the_memory_store_keeps_notes_and_a_store_without_the_keyword_is_called_as_before():
    store = InMemoryApprovalStore()
    stored = await store.create(
        user_id="u", tool_name=SEND, arguments=SEND_ARGS, reason=REASON, security_notes=[HIGH, WARN]
    )
    assert stored.security_notes == (HIGH, WARN)
    assert (await store.create(user_id="u", tool_name=SEND, arguments=SEND_ARGS, reason=REASON)).security_notes == ()

    class OldStore(InMemoryApprovalStore):
        """A store written before notes existed: no security_notes keyword."""

        async def create(  # type: ignore[override]
            self, *, user_id, tool_name, arguments, reason, conversation_id=None,
            ttl_minutes=15, risk_note=None, origin=None, grant_offer=None,
        ):
            return await super().create(
                user_id=user_id, tool_name=tool_name, arguments=arguments, reason=reason,
                conversation_id=conversation_id, ttl_minutes=ttl_minutes, risk_note=risk_note,
                origin=origin, grant_offer=grant_offer,
            )

    old = OldStore()
    runtime = AgentRuntime(
        config=settings,
        permission_engine=RuntimePermissionAdapter(),
        approval_store=old,
        call_checks=CallCheckPipeline([FakeCheck("outbound", Note((note("x", "warn"),)))]),
    )

    class Provider:
        def __init__(self) -> None:
            self.steps = [LLMResponse(content="", tool_calls=[ToolCall(id="c1", name=SEND, arguments=SEND_ARGS)])]

        async def complete(self, messages, tools=None):
            return self.steps.pop(0) if self.steps else LLMResponse(content="done")

    use_provider(runtime, Provider())
    response = await runtime.chat(
        messages=[{"role": "user", "content": "send it"}],
        tools=build_tools([ConnectorSpec("google_workspace")], include_builtins=False),
        user_id="notes-old-store",
    )
    [pending] = response.pending_approvals
    assert pending.security_notes == []  # the old store keeps none, and nothing broke
    assert [a.tool_name for a in await old.list_pending("notes-old-store")] == [SEND]


@pytest.mark.asyncio
async def test_the_approvals_list_and_the_turn_response_carry_security_notes(client, session_factory):
    from api.routes import agent as agent_routes
    from main import app

    user, token = await make_user(session_factory, "notes-rest@example.com")
    store = InMemoryApprovalStore()
    runtime = AgentRuntime(config=settings, approval_store=store)
    await store.create(
        user_id=str(user.id), tool_name=SEND, arguments=SEND_ARGS, reason=REASON,
        risk_note=RISK, security_notes=[INFO], grant_offer=OFFER,
    )
    app.dependency_overrides[agent_routes.get_runtime] = lambda: runtime
    try:
        [card] = (await client.get("/api/agent/approvals", headers=auth_headers(token))).json()
    finally:
        app.dependency_overrides.pop(agent_routes.get_runtime, None)
    assert card["security_notes"] == [INFO]
    assert card["low_risk_account"] == "School Gmail"  # an info note keeps the offer

    class FakeRuntime:
        async def chat(self, messages, tools, user_id, conversation_id, **kwargs):
            return AgentResponse(
                content="Waiting for you.",
                pending_approvals=[
                    PendingApproval(
                        action_id="a1", tool_name=SEND, arguments=SEND_ARGS, reason=REASON,
                        security_notes=[HIGH, WARN],
                    )
                ],
            )

    saved = getattr(app.state, "agent_runtime", None)
    app.state.agent_runtime = FakeRuntime()
    try:
        conv = await client.post("/api/agent/conversations", headers=auth_headers(token), json={"title": "t"})
        sent = await client.post(
            f"/api/agent/conversations/{conv.json()['id']}/messages",
            headers=auth_headers(token),
            json={"content": "mail Ann"},
        )
    finally:
        app.state.agent_runtime = saved
    assert sent.status_code == 201, sent.text
    [pending] = sent.json()["pending_approvals"]
    assert pending["security_notes"] == [HIGH, WARN]


# ── Telegram ─────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_telegram_shows_notes_after_the_risk_note_on_text_purchase_and_act_cards(
    session_factory, fake_api, fixed_expiry
):
    user = await _link(session_factory, "notes-tg@example.com", 931)
    uid = str(user.id)
    service = telegram(session_factory)
    await service.notify_pending(action(uid, risk_note=RISK, security_notes=(HIGH, INFO)))
    text = fake_api.sent_messages()[-1]["text"]
    assert text.startswith(
        f"🔐 {REASON}\n\n⚠️ {RISK}\n\n"
        f"🚨 {HIGH['text']}\nℹ️ {INFO['text']}\n\nTo: ann@example.com\n"
    )
    assert text.endswith(f"{ASK}\n{CHECK_CODE}")

    await service.notify_pending(
        action(uid, "browser.checkout", {"merchant": "shop.example.com", "_checkout": dict(CARD)},
               "Pay $23.40", risk_note=RISK, security_notes=(WARN,))
    )
    caption = _caption_of(fake_api.photos[-1])
    assert caption == f"{BASE_TELEGRAM_PURCHASE_CAPTION}\n\n⚠️ {WARN['text']}"

    await service.notify_pending(
        action(uid, "browser.act", {"action": "click", "ref": "e1", "_page": {"origin": "o"}},
               'Click "Continue" on shop.example.com', risk_note=RISK, security_notes=(WARN, INFO))
    )
    caption = _caption_of(fake_api.photos[-1])
    assert caption == (
        f'🔐 Click "Continue" on shop.example.com\n\n⚠️ {RISK}\n\n'
        f"⚠️ {WARN['text']}\nℹ️ {INFO['text']}\n\n{ASK}"
    )
    # Without a picture the act card's text carries the same lines.
    await telegram(session_factory, image=None).notify_pending(
        action(uid, "browser.act", {"action": "click", "ref": "e1"}, "Click it", security_notes=(INFO,))
    )
    assert fake_api.sent_messages()[-1]["text"] == f"🔐 Click it\n\nℹ️ {INFO['text']}\n\n{ASK}"
    await service._client.aclose()


@pytest.mark.asyncio
async def test_a_telegram_photo_caption_with_notes_stays_within_1024_units(session_factory, fake_api, fixed_expiry):
    user = await _link(session_factory, "notes-tg-long@example.com", 932)
    uid = str(user.id)
    service = telegram(session_factory)
    many = tuple(
        {"kind": f"note_{i}", "severity": "warn", "text": f"{i} " + "🙂" * 140} for i in range(8)
    )
    for tool, args, reason in (
        ("browser.act", {"action": "click", "ref": "e1"}, "Click it"),
        ("browser.checkout", {"_checkout": dict(CARD)}, "Pay"),
    ):
        await service.notify_pending(action(uid, tool, args, reason, risk_note=RISK, security_notes=many))
        caption = _caption_of(fake_api.photos[-1])
        assert cards.utf16_len(caption) <= 1024, tool
        assert "security notes" in caption.splitlines()[-1] or ASK == caption.splitlines()[-1]
        assert "ℹ️ and " in caption and " more security notes" in caption, tool
        assert f"⚠️ {RISK}" in caption and ASK in caption, tool
        assert many[0]["text"] in caption  # whole lines kept from the start
    # The text card (no picture) is never trimmed: every note is there.
    await telegram(session_factory, image=None).notify_pending(
        action(uid, "browser.act", {"action": "click", "ref": "e1"}, "Click it", security_notes=many)
    )
    text = fake_api.sent_messages()[-1]["text"]
    assert all(n["text"] in text for n in many) and "more security notes" not in text
    await service._client.aclose()


@pytest.mark.asyncio
async def test_a_card_with_a_warning_offers_no_weekly_or_low_risk_button_on_any_channel(
    session_factory, fake_api, fixed_expiry
):
    user = await _link(session_factory, "notes-tg-buttons@example.com", 933)
    uid = str(user.id)
    service = telegram(session_factory, image=None)

    def buttons() -> list[str]:
        return [b["text"] for row in fake_api.sent_messages()[-1]["reply_markup"]["inline_keyboard"] for b in row]

    star = {"message_id": "m1", "add_label_ids": ["STARRED"]}
    for notes, expect_extra in (((), True), ((INFO,), True), ((WARN,), False), ((HIGH, INFO), False)):
        await service.notify_pending(action(uid, "desktop.act", dict(CALENDAR_ACT), "Click 15", security_notes=notes))
        assert ("📅 Allow Calendar for 7 days" in buttons()) is expect_extra, notes
        assert ("Or allow Calendar for 7 days" in fake_api.sent_messages()[-1]["text"]) is expect_extra
        await service.notify_pending(action(uid, STAR, star, "Star it", grant_offer=OFFER, security_notes=notes))
        assert any("Allow small changes on School Gmail" in b for b in buttons()) is expect_extra, notes
        assert ("Or let me make small changes on School Gmail" in fake_api.sent_messages()[-1]["text"]) is expect_extra
        # The web card is told the same (null buttons for a warning card).
        web = _stored_to_pending(action(uid, STAR, star, "Star it", grant_offer=OFFER, security_notes=notes))
        assert (web.low_risk_account == "School Gmail") is expect_extra
        weekly = _stored_to_pending(action(uid, "desktop.act", dict(CALENDAR_ACT), "Click", security_notes=notes))
        assert (weekly.weekly_app == "Calendar") is expect_extra
        assert cards.offers_standing_consent(action(uid, security_notes=notes)) is expect_extra
    await service._client.aclose()


# ── Slack ────────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_slack_shows_notes_after_the_risk_note(linked, fixed_expiry):
    uid = str(linked.user_id)
    assert await linked.channel.notify_pending(action(uid, risk_note=RISK, security_notes=(HIGH, WARN))) is True
    section, buttons = linked.api.posts()[-1]["blocks"]
    assert section["text"]["text"].startswith(
        f"🔐 {REASON}\n\n⚠️ {RISK}\n\n"
        f"🚨 {HIGH['text']}\n⚠️ {WARN['text']}\n\nTo: ann@example.com\n"
    )
    assert len(buttons["elements"]) == 2

    # A warning card offers no grant; an info-only card keeps it.
    star = {"message_id": "m1", "add_label_ids": ["STARRED"]}
    await linked.channel.notify_pending(action(uid, STAR, star, "Star it", grant_offer=OFFER, security_notes=(WARN,)))
    _section, buttons = linked.api.posts()[-1]["blocks"]
    assert len(buttons["elements"]) == 2
    assert "Or let me make small changes" not in _section["text"]["text"]
    await linked.channel.notify_pending(action(uid, STAR, star, "Star it", grant_offer=OFFER, security_notes=(INFO,)))
    _section, buttons = linked.api.posts()[-1]["blocks"]
    assert len(buttons["elements"]) == 3


# ── what notes never change ──────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_notes_never_change_the_arguments_digest(session_factory, fake_api, fixed_expiry):
    plain = action("u")
    noted = action("u", security_notes=(HIGH, WARN, INFO))
    assert cards.arguments_digest(plain.arguments) == cards.arguments_digest(noted.arguments)
    user = await _link(session_factory, "notes-digest@example.com", 934)
    service = telegram(session_factory)
    await service.notify_pending(action(str(user.id)))
    await service.notify_pending(action(str(user.id), security_notes=(HIGH, WARN, INFO)))
    first, second = (m["text"] for m in fake_api.sent_messages()[-2:])
    assert CHECK_CODE in first and CHECK_CODE in second
    await service._client.aclose()


@pytest.mark.asyncio
async def test_the_virustotal_upload_card_hides_its_reserved_key_on_every_channel(
    session_factory, fake_api, fixed_expiry
):
    from services.notifications.telegram import _card_arguments

    upload = {"sha256": "ab" * 32, "file_name": "invoice.pdf", "_upload": {"holder": "h-1", "size": 1234}}
    assert cards.card_arguments(UPLOAD, upload) == {"sha256": "ab" * 32, "file_name": "invoice.pdf"}
    assert _card_arguments(UPLOAD, upload) == {"sha256": "ab" * 32, "file_name": "invoice.pdf"}
    # The secret guard reads the stored card without the runtime's own key.
    token = "ghp_" + "FAKE" * 9
    assert check_stored(UPLOAD, {**upload, "_upload": {"note": token}}) is None
    assert check_stored(UPLOAD, {**upload, "file_name": token}) is not None
    user = await _link(session_factory, "notes-vt@example.com", 935)
    service = telegram(session_factory, image=None)
    await service.notify_pending(action(str(user.id), UPLOAD, upload, "Send invoice.pdf to VirusTotal"))
    text = fake_api.sent_messages()[-1]["text"]
    assert "invoice.pdf" in text and "_upload" not in text and "h-1" not in text
    await service._client.aclose()


@pytest.mark.asyncio
async def test_the_virustotal_upload_card_hides_its_reserved_key_on_slack(linked, fixed_expiry):
    upload = {"sha256": "ab" * 32, "_upload": {"holder": "h-1"}}
    await linked.channel.notify_pending(action(str(linked.user_id), UPLOAD, upload, "Send it"))
    section, _buttons = linked.api.posts()[-1]["blocks"]
    assert "_upload" not in section["text"]["text"] and "h-1" not in section["text"]["text"]


@pytest.mark.asyncio
async def test_a_card_without_notes_is_byte_for_byte_todays_text(session_factory, fake_api, fixed_expiry):
    user = await _link(session_factory, "notes-base@example.com", 936)
    uid = str(user.id)
    service = telegram(session_factory)
    await service.notify_pending(
        action(uid, "browser.act", {"action": "click", "ref": "e1", "_page": {"origin": "o"}},
               'Click "Continue" on shop.example.com', risk_note=RISK)
    )
    assert _caption_of(fake_api.photos[-1]) == BASE_TELEGRAM_ACT_CAPTION
    await service.notify_pending(
        action(uid, "browser.checkout", {"merchant": "shop.example.com", "_checkout": dict(CARD)},
               "Pay $23.40", risk_note=RISK)
    )
    assert _caption_of(fake_api.photos[-1]) == BASE_TELEGRAM_PURCHASE_CAPTION
    await service.notify_pending(action(uid, risk_note=RISK))
    assert fake_api.sent_messages()[-1]["text"] == BASE_TELEGRAM_TEXT_CARD
    keyboard = _keyboard_of(fake_api.photos[-1])["inline_keyboard"]
    assert [b["text"] for b in keyboard[0]] == ["✅ Approve", "❌ Deny"]
    await service._client.aclose()


@pytest.mark.asyncio
async def test_a_slack_card_without_notes_is_byte_for_byte_todays_text(linked, fixed_expiry):
    assert await linked.channel.notify_pending(action(str(linked.user_id), risk_note=RISK)) is True
    section, _buttons = linked.api.posts()[-1]["blocks"]
    assert section["text"]["text"] == BASE_SLACK_SECTION


def test_note_lines_and_the_caption_fitter():
    assert cards.SEVERITY_MARKS == {"high": "🚨", "warn": "⚠️", "info": "ℹ️"}
    assert cards.security_note_lines([HIGH, WARN, INFO, {"kind": "bad"}]) == [
        f"🚨 {HIGH['text']}", f"⚠️ {WARN['text']}", f"ℹ️ {INFO['text']}",
    ]
    assert cards.security_notes_of(object()) == []
    assert cards.security_notes_of(action("u", security_notes=(WARN,))) == [WARN]

    def render(kept: list[str]) -> str:
        return "head\n" + "\n".join(kept)

    lines = ["a" * 40, "b" * 40, "c" * 40]  # 127 characters with the head
    assert cards.fit_note_lines(render, lines, max_chars=200) == render(lines)
    fitted = cards.fit_note_lines(render, lines, max_chars=100)
    assert fitted == render(["a" * 40, cards.more_notes_line(2)]) and len(fitted) <= 100
    # No room even for the "more" line alone: that line is what goes (the channel cuts).
    assert cards.fit_note_lines(render, lines, max_chars=30) == render([cards.more_notes_line(3)])
    assert cards.fit_note_lines(render, [], max_chars=1) == render([])


def test_expiry_in_the_fixtures_is_a_real_future():
    """The pinned texts use a fixed expiry; the helper itself still counts down."""
    later = (datetime.now(timezone.utc) + timedelta(minutes=15, seconds=30)).isoformat()
    assert cards.expires_in_text(later) == "15 minutes"
