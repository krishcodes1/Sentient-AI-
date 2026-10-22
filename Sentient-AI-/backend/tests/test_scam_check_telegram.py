"""Tests for the Telegram scam check (services/scam_check/channels.py,
TelegramScamChecks) with a faked Bot API and a real ScamCheckService over fakes:
/scam with text answers with the verdict and the usage line and never starts a
chat turn or meets the turn's PromptGuard; a reply, a captioned photo, a
screenshot sent as a document and an album are checked as pictures (at most
four); a bare /scam arms the chat for two minutes and the next (forwarded)
message is checked instead of answered; the switch, the quota and the size
caps refuse before any download; voice notes get their own reply; /stop
cancels a check; the check is saved fenced in the Telegram thread with its
usage; links in the reply are defanged; no log line holds the token, a file
address or the message; /help lists /scam; the /kb caption route still gets
its files.

Why it exists: a /scam message is someone else's words, often with look-alike
letters and hidden characters that would block or steer a normal turn. The
interceptor must take it before any command, media route or turn, check it
with the owner's switch and caps before a byte is fetched, and keep the
token-bearing download address out of every log.

Non-ASCII test data is written as \\u escapes.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
from typing import Any, Callable

import httpx
import pytest
from sqlalchemy import select
from structlog.testing import capture_logs

from services.agent.prompt_guard import PromptGuard
from services.agent.shared_content import outside_fences, untrusted_spans
from services.scam_check.channels import (
    CHECKING,
    FILE_TOO_LARGE,
    MORE_PICTURES,
    PICTURE_TOO_LARGE,
    TELEGRAM_ARMED,
    TELEGRAM_PICTURE_FAILED,
    TEXT_UNSUPPORTED_MEDIA,
    UNEXPECTED_ERROR,
    TelegramScamChecks,
    _text_links,
)
from services.scam_check.verdict import headline
from services.scam_check.web import NO_SERVICE
from tests.conftest import telegram_dm
from tests.linear_time import scales_linearly
from tests.test_scam_check_service import (
    JPEG,
    PNG,
    REPLY,
    SCAM_TEXT,
    SCAM_URL,
    USAGE,
    Clock,
    FakeFiles,
    FakeLinks,
    FakeRuntime,
    FakeSettings,
    gate_for,
    report,
    scam_rows,
)
from tests.test_telegram import _link

TOKEN = "123:scam-fake-token"
ON = gate_for({"scam_check": True})
# A PDF's first bytes: a file the check looks up by fingerprint only.
PDF = b"%PDF-1.4\n" + b"0" * 64


class FakeBot:
    """The Bot API: getFile answers a path, /file/bot<token>/<path> the bytes,
    every other method answers ok. Every call is recorded."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, dict]] = []
        self.files: dict[str, bytes] = {}
        self.refuse: set[str] = set()

    async def handler(self, request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path.startswith(f"/file/bot{TOKEN}/"):
            name = path.rsplit("/", 1)[-1]
            self.calls.append(("download", {"file_id": name}))
            return httpx.Response(200, content=self.files[name])
        method = path.rsplit("/", 1)[-1]
        payload = json.loads(request.content or b"{}")
        self.calls.append((method, payload))
        if method == "getFile":
            file_id = payload["file_id"]
            if file_id in self.refuse:
                return httpx.Response(200, json={"ok": False, "error_code": 400, "description": "wrong file"})
            result = {"file_id": file_id, "file_path": f"photos/{file_id}", "file_size": len(self.files[file_id])}
            return httpx.Response(200, json={"ok": True, "result": result})
        return httpx.Response(200, json={"ok": True, "result": {"message_id": 7}})

    def sent(self) -> list[dict]:
        return [p for m, p in self.calls if m == "sendMessage"]

    def texts(self) -> list[str]:
        return [p["text"] for p in self.sent()]

    def fetched(self) -> list[str]:
        return [p["file_id"] for m, p in self.calls if m == "getFile"]


@pytest.fixture
def bot(monkeypatch):
    fake = FakeBot()
    real_client_cls = httpx.AsyncClient

    def _factory(**kwargs):
        kwargs["transport"] = httpx.MockTransport(fake.handler)
        return real_client_cls(**kwargs)

    monkeypatch.setattr(httpx, "AsyncClient", _factory)
    return fake


class RecordingChat:
    """The chat applier: records every turn (none should start for /scam)."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, str, dict]] = []

        async def file_gate():
            return None

        self.file_gate = file_gate

    async def __call__(self, user_id, text, *, new_conversation=False, stop_mark=None, files=None, images=None):
        self.calls.append((user_id, text, {"new": new_conversation, "files": files, "images": images}))
        return {"content": "A chat turn answered."}


def scam_service(session_factory, *, gate=ON, runtime=None, links=None, files=None, settings=None, clock=None):
    """A real ScamCheckService over fakes (no network, no provider)."""
    from services.scam_check.quota import RecentChecks, ScamQuota
    from services.scam_check.service import ScamCheckService

    clock = clock or Clock()
    the_runtime = runtime or FakeRuntime()
    return ScamCheckService(
        session_factory,
        capability_gate=gate,
        settings=settings or FakeSettings(),
        runtime_getter=lambda: the_runtime,
        links_getter=lambda: links,
        files_getter=lambda: files,
        quota=ScamQuota(clock=clock, burst=50),
        recent=RecentChecks(clock=clock),
        clock=clock,
    )


def telegram(session_factory, scam, chat=None):
    from services.notifications.telegram import TelegramService

    svc = TelegramService(token=TOKEN, session_factory=session_factory)
    svc.chat = chat if chat is not None else RecordingChat()
    svc.scam_check = scam
    svc._media_group_wait_s = 0.05
    return svc


def checks_of(svc) -> TelegramScamChecks:
    (hook,) = [h for h in svc.message_interceptors if isinstance(getattr(h, "__self__", None), TelegramScamChecks)]
    return hook.__self__


def photo_sizes(file_id: str, size: int | None = None) -> list[dict]:
    """A photo as Telegram sends it: a thumbnail and the full size."""
    return [
        {"file_id": f"{file_id}-thumb", "file_size": 1, "width": 90, "height": 90},
        {"file_id": file_id, "file_size": size if size is not None else len(JPEG), "width": 1280, "height": 960},
    ]


def media_message(chat_id: int, *, caption: str = "", group: str | None = None, **media) -> dict:
    message = telegram_dm(chat_id, "")
    del message["text"]
    message.update(media)
    if caption:
        message["caption"] = caption
    if group:
        message["media_group_id"] = group
    return message


def review_text(runtime) -> str:
    return runtime.calls[0]["messages"][0]["content"][0]["text"]


def review_images(runtime) -> list[dict]:
    return runtime.calls[0]["messages"][0]["content"][1:]


async def telegram_rows(session_factory, user_id):
    from models.conversation import Conversation, Message

    async with session_factory() as session:
        conversations = (
            await session.execute(
                select(Conversation).where(Conversation.user_id == user_id).order_by(Conversation.created_at)
            )
        ).scalars().all()
        rows = {
            c.id: (
                await session.execute(
                    select(Message).where(Message.conversation_id == c.id).order_by(Message.created_at)
                )
            ).scalars().all()
            for c in conversations
        }
    return conversations, rows


def usage_line() -> str:
    from services.usage import format_turn_usage_line

    return format_turn_usage_line(USAGE, "anthropic", "claude-test")


@pytest.mark.asyncio
async def test_slash_scam_with_text_replies_with_the_verdict_and_the_usage_line(session_factory, bot):
    user = await _link(session_factory, "tg-scam-text@example.com", 3101)
    runtime, links = FakeRuntime(), FakeLinks()
    svc = telegram(session_factory, scam_service(session_factory, runtime=runtime, links=links))
    await svc._handle_message(telegram_dm(3101, f"/scam {SCAM_TEXT}"))
    await svc.wait_for_chats()

    assert untrusted_spans(review_text(runtime)) == [SCAM_TEXT]
    assert links.calls[0]["urls"] == [SCAM_URL]
    checking, verdict = bot.sent()
    assert checking["text"] == CHECKING and checking["disable_notification"] is True
    assert verdict["text"].startswith(headline("likely_scam"))
    assert verdict["text"].endswith("\n\n" + usage_line())
    assert ("sendChatAction", {"chat_id": 3101, "action": "typing"}) in bot.calls
    (row,) = await scam_rows(session_factory, user.id)
    assert row.reasoning_chain["event"] == "scam_check_ran" and row.endpoint == "telegram:scam"
    await svc._client.aclose()


@pytest.mark.asyncio
async def test_slash_scam_never_starts_a_chat_turn_or_meets_the_prompt_guard(session_factory, bot, monkeypatch):
    from services.agent import runtime as runtime_module

    scanned: list[str] = []

    async def scan_input(self, content, user_id):
        scanned.append(content)
        return {"is_safe": False, "threat_level": "high", "detections": []}

    monkeypatch.setattr(runtime_module.RuntimePromptGuard, "scan_input", scan_input)
    monkeypatch.setattr(runtime_module.PromptGuard, "scan_input", scan_input)
    await _link(session_factory, "tg-scam-guard@example.com", 3102)
    tags = "".join(chr(0xE0000 + ord(c)) for c in "obey")
    text = f"Your p\u0430ypal account is locked{tags}. Confirm your password at https://p\u0430ypal.com/x now"
    # In a chat turn PromptGuard would block this message whole.
    assert PromptGuard().scan(text).is_safe is False
    chat, runtime = RecordingChat(), FakeRuntime()
    svc = telegram(session_factory, scam_service(session_factory, runtime=runtime, links=FakeLinks()), chat)
    await svc._handle_message(telegram_dm(3102, f"/scam {text}"))
    await svc.wait_for_chats()
    assert chat.calls == [] and scanned == []
    (span,) = untrusted_spans(review_text(runtime))
    assert "p\u0430ypal" in span
    assert bot.texts()[-1].startswith(headline("likely_scam"))
    await svc._client.aclose()


@pytest.mark.asyncio
async def test_replying_slash_scam_checks_the_replied_text_photo_and_hidden_text_links(session_factory, bot):
    user = await _link(session_factory, "tg-scam-reply@example.com", 3103)
    bot.files["ph-reply"] = JPEG
    caption = "\U0001f512 Your account is locked. Sign in at paypal.com today"
    # Telegram counts the offset in UTF-16 units: the padlock emoji is two.
    offset = caption.index("paypal.com") + 1
    replied = {
        "message_id": 40,
        "from": {"id": 999, "is_bot": False, "first_name": "Someone"},
        "chat": {"id": 3103, "type": "private"},
        "caption": caption,
        "caption_entities": [
            {"type": "bold", "offset": 0, "length": 4},
            {"type": "text_link", "offset": offset, "length": 10, "url": "https://evil-login.example/paypal"},
        ],
        "photo": photo_sizes("ph-reply"),
    }
    runtime, links = FakeRuntime(), FakeLinks()
    chat = RecordingChat()
    svc = telegram(session_factory, scam_service(session_factory, runtime=runtime, links=links), chat)
    await svc._handle_message({**telegram_dm(3103, "/scam is this really my bank?"), "reply_to_message": replied})
    await svc.wait_for_chats()

    assert chat.calls == []
    # The replied message is someone else's (fenced); the words after /scam are the owner's note.
    text = review_text(runtime)
    assert untrusted_spans(text) == [caption]
    assert "is this really my bank?" in outside_fences(text)
    assert [(b["type"], b["media_type"]) for b in review_images(runtime)] == [("image", "image/jpeg")]
    # The largest size is fetched, and the hidden link's real address is checked.
    assert bot.fetched() == ["ph-reply"]
    assert "https://evil-login.example/paypal" in links.calls[0]["urls"]
    (row,) = await scam_rows(session_factory, user.id)
    assert "anchor_mismatch" in row.reasoning_chain["signals"]
    assert row.reasoning_chain["images"] == 1
    await svc._client.aclose()


@pytest.mark.asyncio
async def test_a_photo_captioned_slash_scam_is_downloaded_and_checked_as_a_picture(session_factory, bot):
    user = await _link(session_factory, "tg-scam-photo@example.com", 3104)
    bot.files["ph-1"] = JPEG
    chat, runtime = RecordingChat(), FakeRuntime()
    svc = telegram(session_factory, scam_service(session_factory, runtime=runtime, links=FakeLinks()), chat)
    await svc._handle_message(media_message(3104, caption="/scam", photo=photo_sizes("ph-1")))
    await svc.wait_for_chats()
    assert chat.calls == [] and bot.fetched() == ["ph-1"]
    assert "The user sent only pictures." in review_text(runtime)
    (image,) = review_images(runtime)
    assert image["media_type"] == "image/jpeg"
    (row,) = await scam_rows(session_factory, user.id)
    assert row.reasoning_chain["image_sha256"] == [hashlib.sha256(JPEG).hexdigest()]
    await svc._client.aclose()


@pytest.mark.asyncio
async def test_a_screenshot_sent_as_a_document_is_checked_as_a_picture_not_read_as_a_file(session_factory, bot):
    await _link(session_factory, "tg-scam-doc@example.com", 3105)
    bot.files["doc-shot"] = PNG
    chat, runtime, files = RecordingChat(), FakeRuntime(), FakeFiles()
    svc = telegram(
        session_factory, scam_service(session_factory, runtime=runtime, links=FakeLinks(), files=files), chat
    )
    document = {"file_id": "doc-shot", "file_name": "Screenshot.png", "mime_type": "image/png", "file_size": len(PNG)}
    await svc._handle_message(media_message(3105, caption="/scam is this real?", document=document))
    await svc.wait_for_chats()
    # Never the file turn (and never the document reader): one picture for the review.
    assert chat.calls == [] and files.calls == []
    assert [b["media_type"] for b in review_images(runtime)] == ["image/png"]
    assert untrusted_spans(review_text(runtime)) == ["is this real?"]
    await svc._client.aclose()


@pytest.mark.asyncio
async def test_an_album_captioned_slash_scam_is_one_check_of_at_most_four_pictures(session_factory, bot):
    await _link(session_factory, "tg-scam-album@example.com", 3106)
    for n in range(6):
        bot.files[f"al-{n}"] = JPEG + bytes([n])
    chat, runtime = RecordingChat(), FakeRuntime()
    svc = telegram(session_factory, scam_service(session_factory, runtime=runtime, links=FakeLinks()), chat)
    svc._media_group_wait_s = 0.5
    for n in range(6):
        caption = "/scam all of these came from one number" if n == 0 else ""
        await svc._handle_message(media_message(3106, caption=caption, group="album-1", photo=photo_sizes(f"al-{n}")))
    await svc.wait_for_chats()
    assert chat.calls == [] and len(runtime.calls) == 1
    assert len(review_images(runtime)) == 4
    assert bot.fetched() == ["al-0", "al-1", "al-2", "al-3"]
    assert MORE_PICTURES in bot.texts()[-1]
    await svc._client.aclose()


@pytest.mark.asyncio
async def test_an_album_item_that_arrived_before_its_caption_is_checked_with_it_and_never_starts_a_turn(
    session_factory, bot
):
    await _link(session_factory, "tg-scam-album-early@example.com", 3107)
    bot.files["early-0"] = JPEG
    bot.files["early-1"] = JPEG + b"1"
    chat, runtime = RecordingChat(), FakeRuntime()
    svc = telegram(session_factory, scam_service(session_factory, runtime=runtime, links=FakeLinks()), chat)
    svc._media_group_wait_s = 0.5
    # The uncaptioned item arrives first and starts gathering a file turn ...
    await svc._handle_message(media_message(3107, group="album-2", photo=photo_sizes("early-0")))
    # ... then the /scam caption claims the album, that item included.
    await svc._handle_message(media_message(3107, caption="/scam", group="album-2", photo=photo_sizes("early-1")))
    await svc.wait_for_chats()
    assert chat.calls == []
    assert len(review_images(runtime)) == 2 and sorted(bot.fetched()) == ["early-0", "early-1"]
    await svc._client.aclose()


@pytest.mark.asyncio
async def test_a_bare_slash_scam_arms_the_chat_and_the_next_forwarded_message_is_checked_not_answered(
    session_factory, bot
):
    user = await _link(session_factory, "tg-scam-armed@example.com", 3108)
    chat, runtime = RecordingChat(), FakeRuntime()
    svc = telegram(session_factory, scam_service(session_factory, runtime=runtime, links=FakeLinks()), chat)
    await svc._handle_message(telegram_dm(3108, "/scam"))
    assert bot.texts() == [TELEGRAM_ARMED]
    forwarded = {
        **telegram_dm(3108, SCAM_TEXT),
        "forward_origin": {"type": "hidden_user", "sender_user_name": "PayPal Support", "date": 1},
    }
    await svc._handle_message(forwarded)
    await svc.wait_for_chats()
    assert chat.calls == []
    assert untrusted_spans(review_text(runtime)) == [SCAM_TEXT]
    (row,) = await scam_rows(session_factory, user.id)
    assert row.reasoning_chain["forwarded"] is True
    # One message only: the next one is a chat turn again.
    await svc._handle_message(telegram_dm(3108, "thanks, what's on my calendar?"))
    await svc.wait_for_chats()
    assert [text for _, text, _ in chat.calls] == ["thanks, what's on my calendar?"]
    assert len(runtime.calls) == 1
    await svc._client.aclose()


@pytest.mark.asyncio
async def test_an_armed_chat_checks_a_forwarded_start_with_a_code_and_never_relinks(session_factory, bot):
    # Decision 8b: forwarded commands stay someone else's words, /start
    # included, and the S3 rule still holds: a chat armed by a bare /scam
    # takes the forwarded message for checking.
    from datetime import datetime, timedelta, timezone

    from models.user import User
    from tests.conftest import make_user

    owner = await _link(session_factory, "tg-scam-armed-start@example.com", 3131)
    other, _ = await make_user(session_factory, email="tg-scam-armed-start-other@example.com")
    async with session_factory() as session:
        row = (await session.execute(select(User).where(User.id == other.id))).scalar_one()
        row.telegram_link_code = "other-accounts-code"
        row.telegram_link_expires_at = datetime.now(timezone.utc) + timedelta(minutes=10)
        await session.commit()
    chat, runtime = RecordingChat(), FakeRuntime()
    svc = telegram(session_factory, scam_service(session_factory, runtime=runtime, links=FakeLinks()), chat)
    await svc._handle_message(telegram_dm(3131, "/scam"))
    await svc._handle_message({**telegram_dm(3131, "/start other-accounts-code"), "forward_date": 1700000000})
    await svc.wait_for_chats()

    assert chat.calls == [] and untrusted_spans(review_text(runtime)) == ["/start other-accounts-code"]
    (check,) = await scam_rows(session_factory, owner.id)
    assert check.reasoning_chain["forwarded"] is True
    async with session_factory() as session:
        ids = {
            user.id: (user.telegram_chat_id, user.telegram_link_code)
            for user in (await session.execute(select(User).where(User.id.in_([owner.id, other.id])))).scalars()
        }
    assert ids == {owner.id: (3131, None), other.id: (None, "other-accounts-code")}
    assert not any("now linked" in text for text in bot.texts())
    await svc._client.aclose()


@pytest.mark.asyncio
async def test_the_armed_chat_expires_after_two_minutes_and_another_command_disarms_it(session_factory, bot):
    await _link(session_factory, "tg-scam-expire@example.com", 3109)
    chat, runtime = RecordingChat(), FakeRuntime()
    svc = telegram(session_factory, scam_service(session_factory, runtime=runtime, links=FakeLinks()), chat)
    clock = Clock()
    checks_of(svc)._clock = clock

    await svc._handle_message(telegram_dm(3109, "/scam"))
    clock.now += 121
    await svc._handle_message(telegram_dm(3109, "is the library open?"))
    await svc.wait_for_chats()
    assert [text for _, text, _ in chat.calls] == ["is the library open?"]

    await svc._handle_message(telegram_dm(3109, "/scam"))
    await svc._handle_message(telegram_dm(3109, "/new"))
    assert "Fresh start" in bot.texts()[-1]
    await svc._handle_message(telegram_dm(3109, "hello again"))
    await svc.wait_for_chats()
    assert chat.calls[-1][1] == "hello again" and chat.calls[-1][2]["new"] is True

    # Within the two minutes the next message is checked.
    await svc._handle_message(telegram_dm(3109, "/scam"))
    clock.now += 119
    await svc._handle_message(telegram_dm(3109, SCAM_TEXT))
    await svc.wait_for_chats()
    assert len(chat.calls) == 2 and len(runtime.calls) == 1
    await svc._client.aclose()


@pytest.mark.asyncio
async def test_an_unlinked_chat_gets_no_reply_and_nothing_is_downloaded(session_factory, bot):
    bot.files["ph-unlinked"] = JPEG
    chat, runtime = RecordingChat(), FakeRuntime()
    svc = telegram(session_factory, scam_service(session_factory, runtime=runtime, links=FakeLinks()), chat)
    await svc._handle_message(telegram_dm(3110, f"/scam {SCAM_TEXT}"))
    await svc._handle_message(telegram_dm(3110, "/scam"))
    await svc._handle_message(media_message(3110, caption="/scam", photo=photo_sizes("ph-unlinked")))
    await svc.wait_for_chats()
    assert bot.calls == [] and runtime.calls == [] and chat.calls == []
    assert checks_of(svc)._armed == {}
    await svc._client.aclose()


@pytest.mark.asyncio
async def test_the_switch_off_and_a_spent_quota_refuse_before_any_download(session_factory, bot):
    from services.capabilities.scam_check import CAPABILITY

    user = await _link(session_factory, "tg-scam-off@example.com", 3111)
    bot.files["ph-off"] = JPEG
    chat, runtime, links = RecordingChat(), FakeRuntime(), FakeLinks()
    off = scam_service(session_factory, gate=gate_for({"scam_check": False}), runtime=runtime, links=links)
    svc = telegram(session_factory, off, chat)
    await svc._handle_message(media_message(3111, caption="/scam", photo=photo_sizes("ph-off")))
    await svc._handle_message(telegram_dm(3111, "/scam"))
    await svc.wait_for_chats()
    assert bot.texts() == [CAPABILITY.when_denied, CAPABILITY.when_denied]
    assert bot.fetched() == [] and runtime.calls == [] and links.calls == []
    # A refused bare /scam does not arm the chat.
    await svc._handle_message(telegram_dm(3111, "hello"))
    await svc.wait_for_chats()
    assert [text for _, text, _ in chat.calls] == ["hello"]
    rows = await scam_rows(session_factory, user.id)
    assert [r.reasoning_chain["reason"] for r in rows] == ["capability_off", "capability_off"]
    await svc._client.aclose()

    # The owner's daily cap: the second check of the day is refused before its download.
    capped = scam_service(session_factory, runtime=runtime, links=links, settings=FakeSettings(per_day=1))
    svc = telegram(session_factory, capped, chat)
    await svc._handle_message(telegram_dm(3111, f"/scam {SCAM_TEXT}"))
    await svc.wait_for_chats()
    await svc._handle_message(media_message(3111, caption="/scam", photo=photo_sizes("ph-off")))
    await svc.wait_for_chats()
    assert "today's 1 scam checks" in bot.texts()[-1]
    assert bot.fetched() == [] and len(runtime.calls) == 1
    await svc._client.aclose()


@pytest.mark.asyncio
async def test_a_photo_over_five_megabytes_is_refused_without_a_download(session_factory, bot):
    user = await _link(session_factory, "tg-scam-big@example.com", 3112)
    runtime = FakeRuntime()
    svc = telegram(session_factory, scam_service(session_factory, runtime=runtime, links=FakeLinks()))
    big = [{"file_id": "huge", "file_size": 6 * 1024 * 1024, "width": 4000, "height": 3000}]
    document = {"file_id": "huge-doc", "file_name": "shot.png", "mime_type": "image/png", "file_size": 6 * 1024 * 1024}
    pdf = {"file_id": "huge-pdf", "file_name": "invoice.pdf", "mime_type": "application/pdf", "file_size": 21 * 1024 * 1024}
    for media in ({"photo": big}, {"document": document}, {"document": pdf}):
        await svc._handle_message(media_message(3112, caption="/scam", **media))
        await svc.wait_for_chats()
    assert bot.texts() == [PICTURE_TOO_LARGE, PICTURE_TOO_LARGE, FILE_TOO_LARGE]
    assert bot.fetched() == [] and runtime.calls == []
    rows = await scam_rows(session_factory, user.id)
    assert [r.reasoning_chain["reason"] for r in rows] == ["too_large"] * 3
    assert svc.scam_check.quota.used_today(str(user.id)) == 0
    await svc._client.aclose()


@pytest.mark.asyncio
async def test_a_voice_note_while_armed_gets_the_unsupported_reply(session_factory, bot):
    user = await _link(session_factory, "tg-scam-voice@example.com", 3113)
    chat, runtime = RecordingChat(), FakeRuntime()
    svc = telegram(session_factory, scam_service(session_factory, runtime=runtime, links=FakeLinks()), chat)
    await svc._handle_message(telegram_dm(3113, "/scam"))
    voice = {"file_id": "voice-1", "duration": 4, "mime_type": "audio/ogg", "file_size": 3000}
    await svc._handle_message(media_message(3113, voice=voice))
    await svc.wait_for_chats()
    assert bot.texts() == [TELEGRAM_ARMED, TEXT_UNSUPPORTED_MEDIA]
    assert bot.fetched() == [] and runtime.calls == [] and chat.calls == []
    (row,) = await scam_rows(session_factory, user.id)
    assert row.reasoning_chain["reason"] == "unsupported_media"
    await svc._client.aclose()


@pytest.mark.asyncio
async def test_stop_cancels_a_running_check(session_factory, bot):
    user = await _link(session_factory, "tg-scam-stop@example.com", 3114)
    runtime = FakeRuntime(sleep=30)
    svc = telegram(session_factory, scam_service(session_factory, runtime=runtime, links=FakeLinks()))
    await svc._handle_message(telegram_dm(3114, f"/scam {SCAM_TEXT}"))
    for _ in range(500):
        if runtime.calls:
            break
        await asyncio.sleep(0.01)
    assert runtime.calls
    await svc._handle_message(telegram_dm(3114, "/stop"))
    await svc.wait_for_chats()
    assert bot.texts()[0] == CHECKING
    assert bot.texts()[-1].startswith("\u23f9 Stopped.")
    assert not any(text.startswith(headline("likely_scam")) for text in bot.texts())
    conversations, _ = await telegram_rows(session_factory, user.id)
    assert conversations == []
    await svc._client.aclose()


@pytest.mark.asyncio
async def test_the_check_is_saved_in_the_telegram_thread_fenced_with_usage_columns(session_factory, bot):
    user = await _link(session_factory, "tg-scam-saved@example.com", 3115)
    bot.files["ph-saved"] = JPEG
    svc = telegram(session_factory, scam_service(session_factory, links=FakeLinks()))
    replied = {"message_id": 41, "text": SCAM_TEXT, "photo": photo_sizes("ph-saved")}
    await svc._handle_message({**telegram_dm(3115, "/scam from my bank?"), "reply_to_message": replied})
    await svc.wait_for_chats()
    (conversation,), rows = await telegram_rows(session_factory, user.id)
    assert conversation.title == "Telegram"
    asked, answer = rows[conversation.id]
    assert asked.content.startswith("/scam from my bank?\n")
    assert untrusted_spans(asked.content) == [SCAM_TEXT]
    assert "from my bank?" in outside_fences(asked.content)
    assert asked.attachments[0] == {
        "media_type": "image/jpeg",
        "size_bytes": len(JPEG),
        "sha256": hashlib.sha256(JPEG).hexdigest(),
    }
    assert answer.content.startswith(headline("likely_scam")) and usage_line() not in answer.content
    assert (answer.input_tokens, answer.output_tokens) == (USAGE["input_tokens"], USAGE["output_tokens"])
    # The saved reply is what was sent, without the usage line (the columns carry it).
    assert answer.content == bot.texts()[-1].removesuffix("\n\n" + usage_line())
    assert answer.content.rsplit("\n\n", 1)[-1].startswith("Checked: the text")
    await svc._client.aclose()


@pytest.mark.asyncio
async def test_slash_new_then_slash_scam_starts_a_fresh_telegram_thread(session_factory, bot):
    user = await _link(session_factory, "tg-scam-new@example.com", 3116)
    svc = telegram(session_factory, scam_service(session_factory, links=FakeLinks()))
    await svc._handle_message(telegram_dm(3116, f"/scam {SCAM_TEXT}"))
    await svc.wait_for_chats()
    await svc._handle_message(telegram_dm(3116, f"/scam {SCAM_TEXT} (second copy)"))
    await svc.wait_for_chats()
    await svc._handle_message(telegram_dm(3116, "/new"))
    await svc._handle_message(telegram_dm(3116, "/scam Your parcel is held, pay the fee at https://parcel-fee.example/"))
    await svc.wait_for_chats()
    conversations, rows = await telegram_rows(session_factory, user.id)
    assert [c.title for c in conversations] == ["Telegram", "Telegram"]
    assert [len(rows[c.id]) for c in conversations] == [4, 2]
    assert 3116 not in svc._fresh_chats

    # A /new the check could not use (a refusal) is kept for the next message.
    await svc._handle_message(telegram_dm(3116, "/new"))
    await svc._handle_message(media_message(3116, caption="/scam", voice={"file_id": "v", "duration": 2}))
    await svc.wait_for_chats()
    assert bot.texts()[-1] == TEXT_UNSUPPORTED_MEDIA and 3116 in svc._fresh_chats
    await svc._client.aclose()


@pytest.mark.asyncio
async def test_links_in_the_reply_are_defanged_and_link_previews_stay_off(session_factory, bot):
    await _link(session_factory, "tg-scam-defang@example.com", 3117)
    reply = {**REPLY, "urls": ["https://picture-link.example/pay"]}
    listed = report(SCAM_URL, level="dangerous", status="listed", service="safe_browsing", threats=("SOCIAL_ENGINEERING",))
    links = FakeLinks({SCAM_URL: listed})
    svc = telegram(session_factory, scam_service(session_factory, runtime=FakeRuntime(reply), links=links))
    await svc._handle_message(telegram_dm(3117, f"/scam {SCAM_TEXT}"))
    await svc.wait_for_chats()
    verdict = bot.texts()[-1]
    assert "paypa1-secure" in verdict
    for raw in ("paypa1-secure.example", "picture-link.example", "https://", "http://"):
        assert raw not in verdict
    assert all(p["link_preview_options"] == {"is_disabled": True} for p in bot.sent())
    assert all("parse_mode" not in p for p in bot.sent())
    await svc._client.aclose()


@pytest.mark.asyncio
async def test_no_log_line_holds_the_token_the_file_url_or_the_message_text(session_factory, bot):
    user = await _link(session_factory, "tg-scam-logs@example.com", 3118)
    bot.files["ph-log"] = JPEG
    bot.files["ph-gone"] = JPEG
    bot.refuse.add("ph-gone")
    svc = telegram(session_factory, scam_service(session_factory, links=FakeLinks()))
    with capture_logs() as logs:
        await svc._handle_message(media_message(3118, caption=f"/scam {SCAM_TEXT}", photo=photo_sizes("ph-log")))
        await svc.wait_for_chats()
        await svc._handle_message(media_message(3118, caption=f"/scam {SCAM_TEXT}", photo=photo_sizes("ph-gone")))
        await svc.wait_for_chats()
    assert bot.texts()[-1] == TELEGRAM_PICTURE_FAILED
    dumped = json.dumps(logs, default=str)
    for secret in (TOKEN, "/file/bot", "photos/ph-log", "paypa1", "PayPal account"):
        assert secret not in dumped
    reasons = [r.reasoning_chain.get("reason") for r in await scam_rows(session_factory, user.id)]
    assert reasons == [None, "download_failed"]
    await svc._client.aclose()


@pytest.mark.asyncio
async def test_help_lists_slash_scam_just_before_slash_help(session_factory, bot):
    await _link(session_factory, "tg-scam-help@example.com", 3119)
    svc = telegram(session_factory, scam_service(session_factory))
    await svc._handle_message(telegram_dm(3119, "/help"))
    lines = bot.texts()[-1].split("\n")
    # main's plain-language /help (services/notifications/telegram.py HELP_LINES).
    at = lines.index("/help: show this list")
    assert lines[at - 1].startswith("/scam: ask me if something looks like a scam. Send /scam with the text or link")
    assert sum(line.startswith("/scam") for line in lines) == 1
    await svc._client.aclose()


@pytest.mark.asyncio
async def test_the_kb_caption_route_still_gets_its_files(session_factory, bot):
    await _link(session_factory, "tg-scam-kb@example.com", 3120)
    bot.files["kb-doc"] = PDF
    routed: list[tuple[str, list]] = []

    async def kb(chat_id, user_id, rest, files):
        routed.append((rest, [f.name for f in files]))

    runtime = FakeRuntime()
    svc = telegram(session_factory, scam_service(session_factory, runtime=runtime))
    svc.file_caption_routes["/kb"] = kb
    document = {"file_id": "kb-doc", "file_name": "notes.pdf", "mime_type": "application/pdf", "file_size": len(PDF)}
    await svc._handle_message(media_message(3120, caption="/kb lectures", document=document))
    await svc.wait_for_chats()
    # Even while a bare /scam waits, a /kb caption is a command: it disarms and runs as usual.
    await svc._handle_message(telegram_dm(3120, "/scam"))
    await svc._handle_message(media_message(3120, caption="/kb lectures", document=document))
    await svc.wait_for_chats()
    assert routed == [("lectures", ["notes.pdf"]), ("lectures", ["notes.pdf"])]
    assert runtime.calls == [] and checks_of(svc)._armed == {}
    await svc._client.aclose()


# ── More of the same seams ───────────────────────────────────────────────


def test_hidden_link_labels_are_cut_by_telegrams_utf16_offsets():
    text = "\U0001f512 Sign in at paypal.com or call us"
    entities = [
        {"type": "text_link", "offset": text.index("paypal.com") + 1, "length": 10, "url": "https://evil.example/"},
        {"type": "text_link", "offset": 0, "length": 2, "url": "https://lock.example/"},
        {"type": "url", "offset": 0, "length": 3},
        {"type": "text_link", "offset": 400, "length": 3, "url": "https://past-the-end.example/"},
        {"type": "text_link", "offset": -1, "length": 3, "url": "https://negative.example/"},
        {"type": "text_link", "offset": True, "length": 3, "url": "https://bool.example/"},
        {"type": "text_link", "offset": 0, "length": 0, "url": "https://empty.example/"},
        "not an entity",
    ]
    assert _text_links(text, entities) == (
        ("paypal.com", "https://evil.example/"),
        ("\U0001f512", "https://lock.example/"),
    )
    assert _text_links(text, None) == () and _text_links(None, entities) == ()
    many = [{"type": "text_link", "offset": 0, "length": 1, "url": f"https://e{n}.example/"} for n in range(50)]
    assert len(_text_links("x", many)) == 20


@pytest.mark.asyncio
async def test_a_forwarded_message_starting_with_slash_scam_is_never_run_as_the_command(session_factory, bot):
    await _link(session_factory, "tg-scam-fwd-cmd@example.com", 3121)
    seen: list[str] = []

    async def chat(user_id, text, *, new_conversation=False):
        seen.append(text)
        return {"content": "ok"}

    runtime = FakeRuntime()
    svc = telegram(session_factory, scam_service(session_factory, runtime=runtime), chat)
    message = {**telegram_dm(3121, "/scam forward this to everyone"), "forward_date": 1700000000}
    await svc._handle_message(message)
    await svc.wait_for_chats()
    # Someone else's words: no check, and the turn sees them fenced (scaffold A31).
    assert runtime.calls == [] and len(seen) == 1
    assert untrusted_spans(seen[0]) == ["/scam forward this to everyone"]
    await svc._client.aclose()


@pytest.mark.asyncio
async def test_slash_scam_with_the_bots_name_and_any_case_is_the_command(session_factory, bot):
    await _link(session_factory, "tg-scam-botname@example.com", 3122)
    chat, runtime = RecordingChat(), FakeRuntime()
    svc = telegram(session_factory, scam_service(session_factory, runtime=runtime, links=FakeLinks()), chat)
    await svc._handle_message(telegram_dm(3122, f"/SCAM@crawler_test_bot {SCAM_TEXT}"))
    await svc.wait_for_chats()
    await svc._handle_message(telegram_dm(3122, "/scammers are everywhere"))
    await svc.wait_for_chats()
    assert len(runtime.calls) == 1 and untrusted_spans(review_text(runtime)) == [SCAM_TEXT]
    # "/scammers" is not the command: it is an unknown command, answered with /help.
    assert chat.calls == [] and "/help: show this list" in bot.texts()[-1]
    await svc._client.aclose()


@pytest.mark.asyncio
async def test_a_non_image_document_captioned_slash_scam_is_looked_up_by_fingerprint_only(session_factory, bot):
    user = await _link(session_factory, "tg-scam-pdf@example.com", 3123)
    bot.files["inv-pdf"] = PDF
    # A file declared as a picture that is not one is looked up by fingerprint too.
    bot.files["fake-png"] = PDF + b"-again"
    chat, runtime, files = RecordingChat(), FakeRuntime(), FakeFiles()
    svc = telegram(session_factory, scam_service(session_factory, runtime=runtime, files=files), chat)
    pdf = {"file_id": "inv-pdf", "file_name": "invoice.pdf", "mime_type": "application/pdf", "file_size": len(PDF)}
    await svc._handle_message(media_message(3123, caption="/scam", document=pdf))
    await svc.wait_for_chats()
    fake = {"file_id": "fake-png", "file_name": "shot.png", "mime_type": "image/png", "file_size": len(PDF) + 6}
    await svc._handle_message(media_message(3123, caption="/scam", document=fake))
    await svc.wait_for_chats()
    assert chat.calls == [] and runtime.calls == []
    assert [sha for _, sha, _ in files.calls] == [
        hashlib.sha256(PDF).hexdigest(),
        hashlib.sha256(PDF + b"-again").hexdigest(),
    ]
    assert not hasattr(files, "upload") and all(call[0] == str(user.id) for call in files.calls)
    assert "1 file (by fingerprint)" in bot.texts()[-1]
    rows = await scam_rows(session_factory, user.id)
    assert [r.reasoning_chain["files"] for r in rows] == [1, 1]
    await svc._client.aclose()


@pytest.mark.asyncio
async def test_slash_scam_without_a_wired_service_says_so_and_never_starts_a_turn(session_factory, bot):
    await _link(session_factory, "tg-scam-unwired@example.com", 3124)
    chat = RecordingChat()
    svc = telegram(session_factory, None, chat)
    await svc._handle_message(telegram_dm(3124, f"/scam {SCAM_TEXT}"))
    await svc._handle_message(telegram_dm(3124, "/scam"))
    await svc.wait_for_chats()
    assert bot.texts() == [NO_SERVICE, NO_SERVICE] and chat.calls == []
    assert checks_of(svc)._armed == {}
    await svc._client.aclose()


@pytest.mark.asyncio
async def test_an_unexpected_error_inside_the_check_is_answered_and_logged_by_type_only(session_factory, bot):
    await _link(session_factory, "tg-scam-boom@example.com", 3125)
    scam = scam_service(session_factory, links=FakeLinks())

    async def boom(request):
        raise RuntimeError(f"cannot check {request.text}")

    scam.check = boom
    svc = telegram(session_factory, scam)
    with capture_logs() as logs:
        await svc._handle_message(telegram_dm(3125, f"/scam {SCAM_TEXT}"))
        await svc.wait_for_chats()
    assert bot.texts() == [CHECKING, UNEXPECTED_ERROR]
    failed = [entry for entry in logs if entry["event"] == "scam_check_channel_failed"]
    assert failed == [{"event": "scam_check_channel_failed", "channel": "telegram", "error_type": "RuntimeError", "log_level": "error"}]
    assert "paypa1" not in json.dumps(logs, default=str)
    await svc._client.aclose()


@pytest.mark.asyncio
async def test_the_hook_still_skips_a_raising_interceptor_with_the_scam_check_registered(session_factory, bot):
    await _link(session_factory, "tg-scam-hook@example.com", 3126)
    turns: list[str] = []

    async def chat(user_id, text, *, new_conversation=False):
        turns.append(text)
        return {"content": "ok"}

    async def broken(chat_id, user_id, message):
        raise RuntimeError("boom")

    runtime = FakeRuntime()
    svc = telegram(session_factory, scam_service(session_factory, runtime=runtime, links=FakeLinks()), chat)
    # The scam check is registered once, at construction, ahead of anything added later.
    assert len(svc.message_interceptors) == 1 and isinstance(svc.message_interceptors[0].__self__, TelegramScamChecks)
    from services.scam_check.channels import register_telegram

    register_telegram(svc)
    assert len(svc.message_interceptors) == 1
    svc.message_interceptors.insert(0, broken)
    await svc._handle_message(telegram_dm(3126, f"/scam {SCAM_TEXT}"))
    await svc.wait_for_chats()
    await svc._handle_message(telegram_dm(3126, "what's due this week?"))
    await svc.wait_for_chats()
    assert len(runtime.calls) == 1 and turns == ["what's due this week?"]
    await svc._client.aclose()


@pytest.mark.asyncio
async def test_a_reply_to_a_message_from_another_chat_checks_the_quote_as_someone_elses_words(session_factory, bot):
    user = await _link(session_factory, "tg-scam-external@example.com", 3127)
    runtime = FakeRuntime()
    svc = telegram(session_factory, scam_service(session_factory, runtime=runtime, links=FakeLinks()))
    message = {
        **telegram_dm(3127, "/scam"),
        "external_reply": {"origin": {"type": "channel", "date": 1}, "message_id": 77},
        "quote": {"text": SCAM_TEXT, "position": 0},
    }
    await svc._handle_message(message)
    await svc.wait_for_chats()
    assert untrusted_spans(review_text(runtime)) == [SCAM_TEXT]
    (row,) = await scam_rows(session_factory, user.id)
    assert row.reasoning_chain["forwarded"] is True
    await svc._client.aclose()


def _matches_linearly(pattern: Any, build: Callable[[int], str], size: int) -> bool:
    """scales_linearly for *pattern*.match on *build*'s text, written at *size* and at the eighth
    of it the check times it against before the clock starts."""
    texts = {n: build(n) for n in (size // 8, size)}
    return scales_linearly(lambda n: pattern.match(texts[n]), size)


def test_every_trigger_pattern_matches_a_long_worst_case_in_linear_time():
    # Each 200,000-character worst case is timed against an eighth of it in the same process:
    # a linear match grows 8x, a pattern that backtracks over the run from every position 64x.
    from services.scam_check.channels import SCAM_RE, SLACK_RE

    worst = [
        (SCAM_RE, lambda n: "/scam@" + "a" * n + "!"),
        (SCAM_RE, lambda n: "/scam" + " " * n + "x"),
        (SLACK_RE, lambda n: "is" + " " * n + "x"),
        (SLACK_RE, lambda n: "is this a" + " " * n + "x"),
        (SLACK_RE, lambda n: "scam" + " " * n + "checks"),
        (SLACK_RE, lambda n: "scam" + ":-" * (n // 2)),
    ]
    for pattern, build in worst:
        assert _matches_linearly(pattern, build, 200_000), build(200_000)[:12]


def test_the_stub_marker_is_gone_and_the_names_are_final():
    from services.scam_check import channels

    assert not hasattr(channels, "SCAFFOLD_STUB")
    assert channels.ARM_SECONDS == 120.0 and channels.MAX_CHECK_IMAGES == 4


@pytest.mark.asyncio
async def test_a_refusal_the_audit_log_cannot_take_still_reaches_the_person(session_factory, bot):
    await _link(session_factory, "tg-scam-noaudit@example.com", 3128)
    scam = scam_service(session_factory)

    async def broken(user_id, channel, reason):
        raise RuntimeError("the audit table is locked")

    scam.refused = broken
    svc = telegram(session_factory, scam)
    with capture_logs() as logs:
        await svc._handle_message(telegram_dm(3128, "/scam"))
        await svc._handle_message(media_message(3128, voice={"file_id": "v-2", "duration": 3}))
        await svc.wait_for_chats()
    assert bot.texts() == [TELEGRAM_ARMED, TEXT_UNSUPPORTED_MEDIA]
    assert [e["error_type"] for e in logs if e["event"] == "scam_check_channel_audit_failed"] == ["RuntimeError"]
    await svc._client.aclose()
