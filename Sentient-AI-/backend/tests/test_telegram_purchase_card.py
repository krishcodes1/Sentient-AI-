"""Tests for the Telegram purchase card: a browser.checkout approval goes out as
a photo of the checkout page with the purchase caption (site, amount, items,
card label, the "Crawler can make mistakes" notice) and the Approve/Deny
keyboard; /pending re-sends it the same way; a card whose picture is gone (or
whose upload fails) falls back to the text card with the same caption; a press
on a photo card edits its caption; and the reserved "_" keys of browser.act and
browser.checkout cards stay off every card.

Why it exists: The card is the owner's one chance to check the amount and the
site before money moves, away from the computer. The Bot API is faked at the
httpx transport (the multipart upload is inspected as bytes), so the service's
real request code runs without any network; no card number ever appears here.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

import httpx
import pytest

from tests.conftest import make_user
from tests.test_telegram import FakeTelegramAPI, _link

IMAGE = "data:image/jpeg;base64,/9j/4AAQSkZJRgABAQAAAQABAAD/2wBDAAgGBgcGBQgHBwcJCQgKDBQNDAsL"
NOTICE = "Crawler can make mistakes. Check the amount and the site before you approve."
CARD = {
    "checkout_id": "chk-1",
    "origin": "https://shop.example.com",
    "host": "shop.example.com",
    "amount_usd": "23.40",
    "currency": "USD",
    "items": ["Concert ticket — $19.00", "Service fee — $4.40"],
    "card_label": "Visa ····4242",
    "outline": "9f2c1a",
    "notice": NOTICE,
}


class PhotoAwareAPI(FakeTelegramAPI):
    """FakeTelegramAPI plus the multipart bodies of sendPhoto, kept raw so a
    test can check what the caption and keyboard fields carried."""

    def __init__(self) -> None:
        super().__init__()
        self.photos: list[bytes] = []
        self.photo_ok = True

    def handler(self, request: httpx.Request) -> httpx.Response:
        method = request.url.path.rsplit("/", 1)[-1]
        if method == "sendPhoto":
            self.photos.append(request.content)
            self.calls.append((method, {"_multipart_bytes": len(request.content)}))
            if not self.photo_ok:
                return httpx.Response(400, json={"ok": False, "error_code": 400, "description": "Bad Request"})
            return httpx.Response(200, json={"ok": True, "result": {"message_id": 7}})
        return super().handler(request)


@pytest.fixture
def fake_api(monkeypatch):
    api = PhotoAwareAPI()
    real_client_cls = httpx.AsyncClient

    def _factory(**kwargs):
        kwargs["transport"] = httpx.MockTransport(api.handler)
        return real_client_cls(**kwargs)

    monkeypatch.setattr(httpx, "AsyncClient", _factory)
    return api


def _service(session_factory, *, image: Optional[str] = IMAGE, decide=None, raise_image=False):
    from services.notifications.telegram import TelegramService

    def approval_image(action: Any) -> Optional[str]:
        if raise_image:
            raise RuntimeError("no picture")
        return image if action.tool_name == "browser.checkout" else None

    return TelegramService(
        token="123:fake-token",
        session_factory=session_factory,
        decide=decide,
        approval_image=approval_image,
    )


def _action(
    user_id: str,
    tool_name: str = "browser.checkout",
    arguments: Optional[dict] = None,
    reason: str = "Pay $23.40 to shop.example.com (2 items) with Visa ····4242",
    **extra,
):
    from services.agent.approvals import StoredAction

    return StoredAction(
        action_id="a1",
        user_id=user_id,
        tool_name=tool_name,
        arguments={"merchant": "shop.example.com", "amount": 23.4, "_checkout": dict(CARD)}
        if arguments is None
        else arguments,
        reason=reason,
        created_at=datetime.now(timezone.utc).isoformat(),
        expires_at=(datetime.now(timezone.utc) + timedelta(minutes=15)).isoformat(),
        **extra,
    )


def _caption_of(multipart: bytes) -> str:
    """The caption field of a multipart sendPhoto body."""
    marker = b'name="caption"\r\n\r\n'
    start = multipart.index(marker) + len(marker)
    end = multipart.index(b"\r\n--", start)
    return multipart[start:end].decode("utf-8")


def _keyboard_of(multipart: bytes) -> dict:
    marker = b'name="reply_markup"\r\n\r\n'
    start = multipart.index(marker) + len(marker)
    end = multipart.index(b"\r\n--", start)
    return json.loads(multipart[start:end].decode("utf-8"))


# ── the card ─────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_purchase_card_is_a_photo_with_the_caption_and_keyboard(session_factory, fake_api):
    user = await _link(session_factory, "tg-buy@example.com", 901)
    service = _service(session_factory)
    await service.notify_pending(_action(str(user.id)))
    assert fake_api.sent_messages() == []  # the photo IS the card
    [photo] = fake_api.photos
    caption = _caption_of(photo)
    assert caption.startswith("🛒 Purchase approval — shop.example.com · $23.40 · 2 items · Visa ····4242 — ")
    assert NOTICE in caption and "Expires in" in caption
    buttons = _keyboard_of(photo)["inline_keyboard"][0]
    assert buttons[0]["callback_data"] == "apv:a1" and buttons[1]["callback_data"] == "dny:a1"
    assert b'name="chat_id"\r\n\r\n901' in photo
    assert b"image/jpeg" in photo and b"4242" not in photo.replace(b"Visa \xc2\xb7\xc2\xb7\xc2\xb7\xc2\xb74242", b"")
    await service._client.aclose()


@pytest.mark.asyncio
async def test_purchase_card_carries_the_risk_note(session_factory, fake_api):
    user = await _link(session_factory, "tg-buy-risk@example.com", 902)
    service = _service(session_factory)
    await service.notify_pending(_action(str(user.id), risk_note="The merchant came from a web page"))
    assert "⚠️ The merchant came from a web page" in _caption_of(fake_api.photos[0])
    await service._client.aclose()


@pytest.mark.asyncio
async def test_purchase_card_falls_back_to_text_when_the_picture_is_gone(session_factory, fake_api):
    user = await _link(session_factory, "tg-buy-text@example.com", 903)
    service = _service(session_factory, image=None)
    await service.notify_pending(_action(str(user.id)))
    assert fake_api.photos == []
    [sent] = fake_api.sent_messages()
    assert sent["chat_id"] == 903
    assert sent["text"].startswith("🛒 Purchase approval — shop.example.com · $23.40 · 2 items · Visa ····4242 — ")
    assert NOTICE in sent["text"]
    assert sent["reply_markup"]["inline_keyboard"][0][0]["callback_data"] == "apv:a1"
    # The raw arguments (with the reserved key) are not dumped on the card.
    assert "_checkout" not in sent["text"] and "9f2c1a" not in sent["text"]
    await service._client.aclose()


@pytest.mark.asyncio
async def test_purchase_card_falls_back_to_text_when_the_upload_fails_or_the_hook_raises(
    session_factory, fake_api
):
    user = await _link(session_factory, "tg-buy-fail@example.com", 904)
    fake_api.photo_ok = False
    service = _service(session_factory)
    await service.notify_pending(_action(str(user.id)))
    assert len(fake_api.photos) == 1 and len(fake_api.sent_messages()) == 1
    assert NOTICE in fake_api.sent_messages()[0]["text"]
    await service._client.aclose()

    fake_api.photo_ok = True
    fake_api.photos.clear()
    raising = _service(session_factory, raise_image=True)
    await raising.notify_pending(_action(str(user.id)))
    assert fake_api.photos == [] and len(fake_api.sent_messages()) == 2
    await raising._client.aclose()


@pytest.mark.asyncio
async def test_no_photo_without_a_wired_hook_and_never_for_other_tools(session_factory, fake_api):
    from services.notifications.telegram import TelegramService

    user = await _link(session_factory, "tg-buy-nohook@example.com", 905)
    service = TelegramService(token="123:fake-token", session_factory=session_factory)
    await service.notify_pending(_action(str(user.id)))
    assert fake_api.photos == [] and NOTICE in fake_api.sent_messages()[0]["text"]
    await service._client.aclose()

    with_hook = _service(session_factory)
    await with_hook.notify_pending(
        _action(
            str(user.id),
            tool_name="browser.act",
            arguments={"action": "fill", "ref": "e7", "text": "krish@example.com", "_page": {"origin": "o"}},
            reason='Type 17 characters into "Email" on shop.example.com',
        )
    )
    assert fake_api.photos == []
    text = fake_api.sent_messages()[-1]["text"]
    # A browser.act card is the toolkit's sentence, built from facts: no
    # JSON, no refs, none of the typed text, and no reserved key.
    assert text.startswith('🔐 Approval required\n\nType 17 characters into "Email" on shop.example.com')
    assert "Expires in" in text
    for absent in ('"ref"', "e7", "krish@example.com", "_page", "Arguments", "Tool:", "{"):
        assert absent not in text, absent
    await with_hook._client.aclose()


@pytest.mark.asyncio
async def test_a_checkout_card_without_facts_is_the_plain_card(session_factory, fake_api):
    user = await _link(session_factory, "tg-buy-plain@example.com", 906)
    service = _service(session_factory)
    await service.notify_pending(
        _action(str(user.id), arguments={"merchant": "shop.example.com", "amount": 23.4})
    )
    assert fake_api.photos == []
    text = fake_api.sent_messages()[0]["text"]
    assert "🔐 Approval required" in text and "browser.checkout" in text
    await service._client.aclose()


def test_caption_reads_every_part_from_the_card():
    from services.notifications.telegram import _purchase_caption

    expires = (datetime.now(timezone.utc) + timedelta(minutes=15)).isoformat()
    one = _purchase_caption({**CARD, "items": ["Ticket"], "card_label": ""}, expires)
    assert "· 1 item — " + NOTICE in one
    assert "Visa" not in one
    eur = _purchase_caption({**CARD, "currency": "EUR", "amount_usd": "23.40"}, expires)
    assert "23.40 EUR" in eur
    # A page whose rows the toolkit could not read as items (common on
    # real shops) gets no count at all, never "0 items".
    none = _purchase_caption({**CARD, "items": []}, expires)
    assert none.startswith("🛒 Purchase approval — shop.example.com · $23.40 · Visa ····4242 — ")
    assert "0 items" not in none and "items" not in none.split(" — ")[1]
    # A card without its own notice gets the toolkit's: never a made-up one.
    from services.tools.browser.checkout import NOTICE as toolkit_notice

    bare = _purchase_caption({"host": "x.example"}, expires)
    assert bare.split("\n")[0] == f"🛒 Purchase approval — x.example · $? — {toolkit_notice}"


def test_card_arguments_hide_reserved_keys_for_act_and_checkout_only():
    from services.notifications.telegram import _card_arguments

    assert _card_arguments("browser.act", {"action": "click", "ref": "e7", "_page": {}}) == {
        "action": "click",
        "ref": "e7",
    }
    assert _card_arguments("browser.checkout", {"merchant": "x", "_checkout": CARD}) == {"merchant": "x"}
    assert _card_arguments("desktop.act", {"action": "click", "_screen": {}}) == {"action": "click"}
    assert _card_arguments("mcp.github.search", {"q": "x", "_scope": "org"}) == {"q": "x", "_scope": "org"}
    assert _card_arguments("browser.checkout", None) == {}


# ── /pending and the press ───────────────────────────────────────────────


@pytest.mark.asyncio
async def test_pending_resends_the_photo_card(session_factory, fake_api):
    from models.pending_action import PendingAction, PendingActionStatus
    from tests.conftest import telegram_dm

    user = await _link(session_factory, "tg-buy-pending@example.com", 907)
    async with session_factory() as session:
        session.add(
            PendingAction(
                user_id=user.id,
                tool_name="browser.checkout",
                arguments={"merchant": "shop.example.com", "_checkout": dict(CARD)},
                reason="Pay $23.40 to shop.example.com (2 items) with Visa ····4242",
                status=PendingActionStatus.pending,
                expires_at=datetime.now(timezone.utc) + timedelta(minutes=10),
            )
        )
        await session.commit()
    service = _service(session_factory)
    await service._handle_message(telegram_dm(907, "/pending"))
    [photo] = fake_api.photos
    assert NOTICE in _caption_of(photo)
    assert fake_api.sent_messages() == []
    await service._client.aclose()


@pytest.mark.asyncio
async def test_a_press_on_the_photo_card_edits_its_caption(session_factory, fake_api):
    user = await _link(session_factory, "tg-buy-press@example.com", 908)
    decisions: list = []

    async def decide(user_id, action_id, approved):
        decisions.append((user_id, action_id, approved))
        return {"status": "approved", "summary": "Paid $23.40 to shop.example.com. Order number 8841."}

    service = _service(session_factory, decide=decide)
    caption = "🛒 Purchase approval — shop.example.com · $23.40 · 2 items · Visa ····4242 — " + NOTICE
    await service._handle_callback(
        {
            "id": "cb-buy",
            "from": {"id": 908, "is_bot": False},
            "data": "apv:a1",
            "message": {
                "chat": {"id": 908, "type": "private"},
                "message_id": 7,
                "photo": [{"file_id": "p1", "width": 10, "height": 10}],
                "caption": caption,
            },
        }
    )
    await service.wait_for_chats()
    assert decisions == [(str(user.id), "a1", True)]
    edits = [p for m, p in fake_api.calls if m == "editMessageCaption"]
    assert len(edits) == 1 and edits[0]["message_id"] == 7
    assert edits[0]["caption"].startswith(caption) and "✅ Approved from this chat" in edits[0]["caption"]
    assert [m for m, _ in fake_api.calls if m == "editMessageText"] == []
    # The resumed turn's reply followed.
    assert "Order number 8841" in fake_api.sent_messages()[-1]["text"]
    await service._client.aclose()


@pytest.mark.asyncio
async def test_a_press_on_a_text_card_still_edits_its_text(session_factory, fake_api):
    user = await _link(session_factory, "tg-buy-press-text@example.com", 909)

    async def decide(user_id, action_id, approved):
        return {"status": "denied", "summary": None}

    service = _service(session_factory, decide=decide)
    await service._handle_callback(
        {
            "id": "cb-deny",
            "from": {"id": 909, "is_bot": False},
            "data": "dny:a1",
            "message": {"chat": {"id": 909, "type": "private"}, "message_id": 8, "text": "🛒 Purchase approval"},
        }
    )
    await service.wait_for_chats()
    edits = [p for m, p in fake_api.calls if m == "editMessageText"]
    assert len(edits) == 1 and "❌ Denied" in edits[0]["text"]
    assert [m for m, _ in fake_api.calls if m == "editMessageCaption"] == []
    assert user is not None
    await service._client.aclose()


@pytest.mark.asyncio
async def test_send_photo_without_a_keyboard_is_unchanged(session_factory, fake_api):
    """The turn's screenshots keep going out as plain photos."""
    await make_user(session_factory, "tg-plain-photo@example.com")
    service = _service(session_factory)
    assert await service._send_photo(910, IMAGE, "A screenshot") is True
    [photo] = fake_api.photos
    assert b'name="reply_markup"' not in photo and _caption_of(photo) == "A screenshot"
    await service._client.aclose()
