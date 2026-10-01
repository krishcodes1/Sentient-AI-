"""Tests for Telegram file intake with a faked Bot API: a document reaches the
chat as files= with its caption as the text, an unlinked chat is ignored
before getFile, files over 20 MB and the switch being off get their reply
without a download, /stop cancels a download, an album is one turn of at
most five files, a photo becomes an image attachment, a caption's first word
can route the files, and no log line holds the bot token or the file URL.
Also the chat applier's files= and images= path: stored metadata and the
note, and a file that cannot be read ends the turn without a model call.

Why it exists: A3's Telegram half lets anyone who can message the bot hand it
a file; the link check, the switch and the caps must all run before a byte is
fetched, and the token-bearing download URL must never be written anywhere.
"""

from __future__ import annotations

import asyncio
import base64
import json
import uuid

import httpx
import pytest
from sqlalchemy import select

from tests.conftest import make_user, telegram_dm
from tests.files import builders as b
from tests.test_telegram import _link

TOKEN = "123:fake-token"
PDF = b.make_pdf(["Question 3 asks about entropy."])


class FakeBot:
    """The Bot API: getFile answers a path, /file/bot<token>/<path> the bytes."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, dict]] = []
        self.files: dict[str, bytes] = {"doc1": PDF, "photo-big": b"B" * 2000, "photo-small": b"s" * 10}
        self.block_download: asyncio.Event | None = None
        self.bad_path = False

    async def handler(self, request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path.startswith(f"/file/bot{TOKEN}/"):
            self.calls.append(("download", {"path": path}))
            if self.block_download is not None:
                await self.block_download.wait()
            name = path.rsplit("/", 1)[-1]
            return httpx.Response(200, content=self.files[name])
        method = path.rsplit("/", 1)[-1]
        payload = json.loads(request.content or b"{}")
        self.calls.append((method, payload))
        if method == "getFile":
            file_id = payload["file_id"]
            file_path = "../etc/passwd" if self.bad_path else f"documents/{file_id}"
            return httpx.Response(200, json={"ok": True, "result": {"file_id": file_id, "file_path": file_path}})
        return httpx.Response(200, json={"ok": True, "result": {}})

    def methods(self) -> list[str]:
        return [m for m, _ in self.calls]

    def texts(self) -> list[str]:
        return [p["text"] for m, p in self.calls if m == "sendMessage"]


@pytest.fixture
def bot(monkeypatch):
    fake = FakeBot()
    real_client_cls = httpx.AsyncClient

    def _factory(**kwargs):
        kwargs["transport"] = httpx.MockTransport(fake.handler)
        return real_client_cls(**kwargs)

    monkeypatch.setattr(httpx, "AsyncClient", _factory)
    return fake


def service(session_factory, chat):
    from services.notifications.telegram import TelegramService

    svc = TelegramService(token=TOKEN, session_factory=session_factory)
    svc.chat = chat
    svc._media_group_wait_s = 0.05
    return svc


def document_message(chat_id: int, *, caption: str = "", name="lecture3.pdf", size=None, file_id="doc1", group=None):
    message = telegram_dm(chat_id, "")
    del message["text"]
    message["document"] = {"file_id": file_id, "file_name": name, "mime_type": "application/pdf", "file_size": size or len(PDF)}
    if caption:
        message["caption"] = caption
    if group:
        message["media_group_id"] = group
    return message


class RecordingChat:
    def __init__(self, refusal=None) -> None:
        self.calls: list[tuple[str, str, dict]] = []
        self.refusal = refusal

        async def file_gate():
            return self.refusal

        self.file_gate = file_gate

    async def __call__(self, user_id, text, *, new_conversation=False, stop_mark=None, files=None, images=None):
        self.calls.append((user_id, text, {"files": files, "images": images}))
        return {"content": "Question 3 asks about entropy."}


@pytest.mark.asyncio
async def test_a_document_reaches_the_chat_with_its_caption(session_factory, bot):
    user = await _link(session_factory, "tg-doc@example.com", 1001)
    chat = RecordingChat()
    svc = service(session_factory, chat)
    await svc._handle_message(document_message(1001, caption="what does question 3 ask?"))
    await svc.wait_for_chats()
    (user_id, text, extra), = chat.calls
    assert user_id == str(user.id) and text == "what does question 3 ask?"
    (inbound,) = extra["files"]
    assert inbound.name == "lecture3.pdf" and inbound.data == PDF and inbound.source == "telegram"
    assert bot.texts()[0] == "📄 Reading lecture3.pdf…"
    reading = next(p for m, p in bot.calls if m == "sendMessage")
    assert reading["disable_notification"] is True
    assert bot.texts()[-1] == "Question 3 asks about entropy."
    await svc._client.aclose()


@pytest.mark.asyncio
async def test_an_unlinked_chat_is_ignored_before_get_file(session_factory, bot):
    chat = RecordingChat()
    svc = service(session_factory, chat)
    await svc._handle_message(document_message(2002))
    await svc.wait_for_chats()
    assert bot.calls == [] and chat.calls == []
    await svc._client.aclose()


@pytest.mark.asyncio
async def test_a_file_over_20_mb_is_refused_without_a_download(session_factory, bot):
    await _link(session_factory, "tg-big@example.com", 1003)
    chat = RecordingChat()
    svc = service(session_factory, chat)
    await svc._handle_message(document_message(1003, size=34 * 1024 * 1024))
    await svc.wait_for_chats()
    assert "getFile" not in bot.methods() and chat.calls == []
    assert bot.texts()[-1] == (
        "⚠️ I couldn't read lecture3.pdf: That file is 34 MB; Crawler reads files up to 20 MB. "
        "Send a smaller file or a link to it."
    )
    await svc._client.aclose()


@pytest.mark.asyncio
async def test_file_reading_off_replies_without_a_download(session_factory, bot):
    await _link(session_factory, "tg-off@example.com", 1004)
    chat = RecordingChat(refusal="Reading files is turned off.")
    svc = service(session_factory, chat)
    await svc._handle_message(document_message(1004))
    await svc.wait_for_chats()
    assert bot.methods() == ["sendMessage"] and bot.texts() == ["⚠️ Reading files is turned off."]
    await svc._client.aclose()


@pytest.mark.asyncio
async def test_a_bad_file_path_is_never_fetched(session_factory, bot):
    await _link(session_factory, "tg-path@example.com", 1005)
    bot.bad_path = True
    chat = RecordingChat()
    svc = service(session_factory, chat)
    await svc._handle_message(document_message(1005))
    await svc.wait_for_chats()
    assert "download" not in bot.methods() and chat.calls == []
    assert bot.texts()[-1].startswith("⚠️ I couldn't read lecture3.pdf")
    await svc._client.aclose()


@pytest.mark.asyncio
async def test_stop_cancels_a_download(session_factory, bot):
    await _link(session_factory, "tg-stop@example.com", 1006)
    bot.block_download = asyncio.Event()
    chat = RecordingChat()
    svc = service(session_factory, chat)
    await svc._handle_message(document_message(1006))
    for _ in range(50):
        if "download" in bot.methods():
            break
        await asyncio.sleep(0.01)
    assert "download" in bot.methods()
    await svc._handle_message(telegram_dm(1006, "/stop"))
    await svc.wait_for_chats()
    assert chat.calls == []
    assert bot.texts()[-1].startswith("⏹ Stopped")
    await svc._client.aclose()


@pytest.mark.asyncio
async def test_an_album_is_one_turn_of_at_most_five_files(session_factory, bot):
    await _link(session_factory, "tg-album@example.com", 1007)
    chat = RecordingChat()
    svc = service(session_factory, chat)
    for index in range(7):
        await svc._handle_message(
            document_message(1007, name=f"part{index}.pdf", group="album-1", caption="summarize these" if index == 3 else "")
        )
    await svc.wait_for_chats()
    await asyncio.sleep(0.1)
    await svc.wait_for_chats()
    (call,) = chat.calls
    assert call[1] == "summarize these"
    assert [f.name for f in call[2]["files"]] == [f"part{i}.pdf" for i in range(5)]
    assert bot.texts()[0] == "📄 Reading 5 files…"
    await svc._client.aclose()


@pytest.mark.asyncio
async def test_an_album_with_file_reading_off_gets_one_reply(session_factory, bot):
    await _link(session_factory, "tg-album-off@example.com", 1010)
    chat = RecordingChat(refusal="Reading files is turned off.")
    svc = service(session_factory, chat)
    for index in range(3):
        await svc._handle_message(document_message(1010, name=f"p{index}.pdf", group="album-2"))
    await svc.wait_for_chats()
    assert bot.texts() == ["⚠️ Reading files is turned off."]
    assert "getFile" not in bot.methods() and chat.calls == []
    await svc._client.aclose()


@pytest.mark.asyncio
async def test_a_photo_becomes_an_image_attachment(session_factory, bot):
    await _link(session_factory, "tg-photo-in@example.com", 1008)
    chat = RecordingChat()
    svc = service(session_factory, chat)
    message = telegram_dm(1008, "")
    del message["text"]
    message["photo"] = [
        {"file_id": "photo-small", "file_size": 10, "width": 90, "height": 90},
        {"file_id": "photo-big", "file_size": 2000, "width": 1280, "height": 960},
        {"file_id": "photo-huge", "file_size": 6 * 1024 * 1024, "width": 4000, "height": 3000},
    ]
    message["caption"] = "what is this?"
    await svc._handle_message(message)
    await svc.wait_for_chats()
    (call,) = chat.calls
    assert call[1] == "what is this?" and call[2]["files"] is None
    (image,) = call[2]["images"]
    assert image["media_type"] == "image/jpeg" and base64.b64decode(image["data"]) == b"B" * 2000
    await svc._client.aclose()


@pytest.mark.asyncio
async def test_a_caption_route_gets_the_files_and_a_caption_is_never_a_command(session_factory, bot):
    await _link(session_factory, "tg-kb@example.com", 1009)
    chat = RecordingChat()
    svc = service(session_factory, chat)
    routed = []

    async def kb(chat_id, user_id, rest, files):
        routed.append((chat_id, rest, [f.name for f in files]))

    svc.file_caption_routes["/kb"] = kb
    await svc._handle_message(document_message(1009, caption="/kb biology notes"))
    await svc._handle_message(document_message(1009, caption="/stop"))
    await svc.wait_for_chats()
    assert routed == [(1009, "biology notes", ["lecture3.pdf"])]
    assert [c[1] for c in chat.calls] == ["/stop"]
    await svc._client.aclose()


@pytest.mark.asyncio
async def test_no_log_line_holds_the_token_or_the_file_url(monkeypatch):
    from services.notifications import telegram_files
    from tests.test_telegram import _RecordingLogger

    recorder = _RecordingLogger()
    monkeypatch.setattr(telegram_files, "logger", recorder)

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/getFile"):
            return httpx.Response(200, json={"ok": True, "result": {"file_path": "documents/f.pdf"}})
        raise httpx.ConnectError(f"cannot reach {request.url}")

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        with pytest.raises(telegram_files.TelegramFileError) as caught:
            await telegram_files.download_telegram_file(client, TOKEN, "f", max_bytes=100)
    assert caught.value.code == "download_failed"
    assert recorder.records and TOKEN not in json.dumps(recorder.records, default=str)
    assert "api.telegram.org" not in json.dumps(recorder.records, default=str)


@pytest.mark.asyncio
async def test_the_download_stops_past_the_cap():
    from services.notifications import telegram_files

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/getFile"):
            return httpx.Response(200, json={"ok": True, "result": {"file_path": "documents/f.pdf"}})
        return httpx.Response(200, content=b"x" * 500)

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        with pytest.raises(telegram_files.TelegramFileError) as caught:
            await telegram_files.download_telegram_file(client, TOKEN, "f", max_bytes=100)
    assert caught.value.code == "too_large"
    assert telegram_files.valid_file_path("photos/file_1.jpg")
    assert not telegram_files.valid_file_path("../secret") and not telegram_files.valid_file_path("/abs")


# -- The chat applier -------------------------------------------------------------------


@pytest.mark.asyncio
async def test_the_applier_stores_files_and_notes_them_in_history(session_factory):
    from api.routes.agent import build_chat_applier
    from main import app
    from models.conversation import Message
    from services.agent.runtime import AgentResponse
    from services.files.intake import FileIntake, InboundFile
    from services.files.sandbox import InProcessSandbox
    from services.files.store import UserFileStore

    user, _ = await make_user(session_factory, "applier-files@example.com")
    seen = []

    class FakeRuntime:
        async def chat(self, **kwargs):
            seen.append(kwargs["messages"])
            return AgentResponse(content="Read it.")

    saved = (getattr(app.state, "agent_runtime", None), getattr(app.state, "file_intake", None))
    app.state.agent_runtime = FakeRuntime()
    app.state.file_intake = FileIntake(UserFileStore(session_factory, sandbox=InProcessSandbox()))
    try:
        chat = build_chat_applier(app, session_factory=session_factory)
        assert await chat.file_gate() is None
        done = await chat(str(user.id), "", files=[InboundFile("hw3.pdf", "application/pdf", PDF, "telegram")])
        assert done["content"] == "Read it."
        assert "[Attached file: 'hw3.pdf' (PDF, 1 page)" in seen[-1][-1]["content"]
        failed = await chat(str(user.id), "and this?", files=[InboundFile("old.doc", "application/msword", b.OLE_HEADER, "telegram")])
        assert failed["error"].startswith("I couldn't read old.doc: This is an older Office format")
        assert len(seen) == 1
    finally:
        app.state.agent_runtime, app.state.file_intake = saved

    async with session_factory() as session:
        rows = (await session.execute(select(Message).where(Message.role == "user"))).scalars().all()
    stored = [r.attachments for r in rows if r.attachments]
    assert stored and stored[0][0]["kind"] == "file" and stored[0][0]["name"] == "hw3.pdf"
    assert uuid.UUID(stored[0][0]["file_id"])
