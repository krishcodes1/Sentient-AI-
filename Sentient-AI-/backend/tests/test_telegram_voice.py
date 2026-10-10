"""Tests for Telegram voice notes with a faked Bot API and fake speech engines:
a linked private voice note is fetched, echoed silently ("🎤 Heard: …") and
answered through the chat applier with its attachment facts and usage seed,
the reply ending with the cost line; unlinked chats and groups get nothing;
the caps and the switches refuse before getFile; a download past the cap is
aborted; forwarded notes and audio files reach the applier fenced; a video
note gets its reply; /stop cancels the transcription with no echo and no
turn; a failed download logs no token; no speech is a reply, not a turn.
Also the chat applier's attachments= (stored on the user message) and
usage_seed= (folded into the assistant row, replay-cache hit included).

Why it exists: anyone who can message the bot can send audio; the link
check, the switches and the caps must run before a byte is fetched, the
token-bearing download URL must never be logged, and only the owner's own
voice counts as instructions.
"""

from __future__ import annotations

import asyncio
import json

import httpx
import pytest
from sqlalchemy import select
from structlog.testing import capture_logs

from services import capabilities
from services.agent.shared_content import outside_fences, untrusted_spans
from services.capabilities.base import ReportContext
from services.notifications import voice
from services.notifications.voice import VoiceNoteService
from services.tools.transcribe import Transcript
from tests.conftest import make_user, telegram_dm
from tests.test_telegram import _link

TOKEN = "123:fake-voice-token"
OGG = b"OggS\x00\x02" + b"\x00" * 22 + b"\x01\x13OpusHead\x01\x01" + b"\x00" * 40
MP3 = b"ID3\x04\x00\x00\x00\x00\x00\x00" + b"\x00" * 60
SPOKEN = "What's due this week on Canvas?"


class FakeBot:
    """The Bot API: getFile answers a path, /file/bot<token>/<path> the bytes."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, dict]] = []
        self.files: dict[str, bytes] = {"v1": OGG, "a1": MP3}
        self.fail_download = False

    async def handler(self, request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path.startswith(f"/file/bot{TOKEN}/"):
            self.calls.append(("download", {"path": path}))
            if self.fail_download:
                raise httpx.ConnectError(f"connection refused for {request.url}")
            return httpx.Response(200, content=self.files[path.rsplit("/", 1)[-1]])
        method = path.rsplit("/", 1)[-1]
        payload = json.loads(request.content or b"{}")
        self.calls.append((method, payload))
        if method == "getFile":
            file_id = payload["file_id"]
            return httpx.Response(200, json={"ok": True, "result": {"file_id": file_id, "file_path": f"voice/{file_id}"}})
        return httpx.Response(200, json={"ok": True, "result": {}})

    def methods(self) -> list[str]:
        return [m for m, _ in self.calls]

    def sends(self) -> list[dict]:
        return [p for m, p in self.calls if m == "sendMessage"]

    def texts(self) -> list[str]:
        return [p["text"] for p in self.sends()]


@pytest.fixture
def bot(monkeypatch):
    fake = FakeBot()
    real_client_cls = httpx.AsyncClient

    def _factory(**kwargs):
        kwargs["transport"] = httpx.MockTransport(fake.handler)
        return real_client_cls(**kwargs)

    monkeypatch.setattr(httpx, "AsyncClient", _factory)
    return fake


def gate_for(switches: dict, **facts):
    ctx = ReportContext(in_container=False, platform="win32", telegram_configured=True, browser_installed=False, **facts)
    statuses = capabilities.statuses_by_key(capabilities.report(switches, ctx))

    async def gate():
        return statuses

    return gate


class FakeLocal:
    model = "faster-whisper-base"

    def __init__(self, text: str = SPOKEN) -> None:
        self.text = text
        self.calls: list = []
        self.hold: asyncio.Event | None = None
        self.entered = asyncio.Event()
        self.cancelled = False

    async def transcribe(self, clip, **kwargs):
        self.calls.append(clip)
        self.entered.set()
        if self.hold is not None:
            try:
                await self.hold.wait()
            except asyncio.CancelledError:
                self.cancelled = True
                raise
        if not self.text:
            return Transcript(ok=False, error="no_speech", engine="local", model=self.model)
        return Transcript(ok=True, text=self.text, language="en", duration_s=3.0, engine="local", model=self.model)


class RecordingChat:
    def __init__(self) -> None:
        self.calls: list[tuple[str, str, dict]] = []

    async def __call__(
        self, user_id, text, *, new_conversation=False, stop_mark=None, attachments=None, usage_seed=None
    ):
        self.calls.append((user_id, text, {"attachments": attachments, "usage_seed": usage_seed, "new": new_conversation}))
        usage = {"input_tokens": 900 + (usage_seed or {}).get("input_tokens", 0), "output_tokens": 40}
        return {"content": "Two assignments are due.", "usage": usage, "provider": "gemini", "model": "gemini-3.5-flash-lite"}


def service(session_factory, chat, *, switches=None, local=None, **facts):
    from services.notifications.telegram import TelegramService

    svc = TelegramService(token=TOKEN, session_factory=session_factory)
    svc.chat = chat
    if not facts and switches is None:
        facts = {"speech_local_installed": True}
    svc.voice = VoiceNoteService(
        session_factory,
        capability_gate=gate_for({"voice_notes": True} if switches is None else switches, **facts),
        runtime_getter=lambda: None,
        local_engine=local or FakeLocal(),
    )
    return svc


def voice_message(chat_id: int, *, kind="voice", file_id="v1", duration=4, size=None, mime="audio/ogg", **extra):
    message = telegram_dm(chat_id, "")
    del message["text"]
    media = {"file_id": file_id, "duration": duration, "mime_type": mime, "file_size": size or len(OGG)}
    if kind == "audio":
        media["file_name"] = "lecture 3.mp3"
    message[kind] = media
    message.update(extra)
    return message


@pytest.mark.asyncio
async def test_a_linked_voice_note_is_heard_echoed_and_answered(session_factory, bot):
    user = await _link(session_factory, "tg-voice@example.com", 3001)
    chat = RecordingChat()
    svc = service(session_factory, chat)
    await svc._handle_message(voice_message(3001))
    await svc.wait_for_chats()
    assert bot.methods()[:3] == ["sendChatAction", "getFile", "download"]
    echo = bot.sends()[0]
    assert echo["text"] == f"🎤 Heard: “{SPOKEN}”" and echo["disable_notification"] is True
    ((user_id, text, extra),) = chat.calls
    assert user_id == str(user.id) and text == f"[Voice note, transcribed] {SPOKEN}"
    (attachment,) = extra["attachments"]
    assert attachment["kind"] == "voice_note" and attachment["trusted"] is True and attachment["engine"] == "local"
    assert extra["usage_seed"] == {}
    reply = bot.texts()[-1]
    assert reply.startswith("Two assignments are due.") and "tokens" in reply.splitlines()[-1]
    await svc._client.aclose()


@pytest.mark.asyncio
async def test_an_unlinked_chat_or_a_group_gets_nothing(session_factory, bot):
    await _link(session_factory, "tg-voice-group@example.com", 3002)
    chat = RecordingChat()
    local = FakeLocal()
    svc = service(session_factory, chat, local=local)
    await svc._handle_message(voice_message(3999))
    group = voice_message(3002)
    group["chat"] = {"id": -100123, "type": "group"}
    await svc._handle_message(group)
    await svc.wait_for_chats()
    assert bot.calls == [] and chat.calls == [] and local.calls == []
    await svc._client.aclose()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("overrides", "starts"),
    [
        ({"size": 25 * 1024 * 1024}, "🎤 That recording is over the 20 MB limit."),
        ({"duration": 25 * 60}, "🎤 That recording is 25 min long; I transcribe up to 10 minutes per voice note."),
    ],
)
async def test_caps_refuse_before_get_file(session_factory, bot, overrides, starts):
    await _link(session_factory, f"tg-voice-cap-{next(iter(overrides))}@example.com", 3003)
    chat = RecordingChat()
    svc = service(session_factory, chat)
    await svc._handle_message(voice_message(3003, **overrides))
    await svc.wait_for_chats()
    assert "getFile" not in bot.methods() and "download" not in bot.methods()
    (reply,) = bot.texts()
    assert reply.startswith(starts)
    assert chat.calls == []
    await svc._client.aclose()


@pytest.mark.asyncio
async def test_with_the_switches_off_the_reply_is_the_fallback_and_nothing_is_downloaded(session_factory, bot):
    await _link(session_factory, "tg-voice-off@example.com", 3004)
    chat = RecordingChat()
    svc = service(session_factory, chat, switches={}, speech_local_installed=True)
    await svc._handle_message(voice_message(3004))
    await svc.wait_for_chats()
    assert bot.texts() == [voice.TEXT_OFF]
    assert "getFile" not in bot.methods() and chat.calls == []
    await svc._client.aclose()


@pytest.mark.asyncio
async def test_a_download_past_the_cap_is_aborted(session_factory, bot, monkeypatch):
    from services.tools import transcribe

    await _link(session_factory, "tg-voice-big@example.com", 3005)
    monkeypatch.setattr(transcribe, "MAX_AUDIO_BYTES", 64)
    bot.files["v1"] = OGG + b"\x00" * 5000
    chat = RecordingChat()
    local = FakeLocal()
    svc = service(session_factory, chat, local=local)
    await svc._handle_message(voice_message(3005, size=50))
    await svc.wait_for_chats()
    assert "download" in bot.methods()
    assert bot.texts()[-1] == voice.TEXT_TOO_BIG
    assert chat.calls == [] and local.calls == []
    await svc._client.aclose()


# Every way Telegram marks a message as forwarded (Bot API 7's
# forward_origin, the older forward_* fields, a channel's automatic forward
# into its discussion group): each alone makes the recording someone else's.
_FORWARD_MARKERS: list[dict[str, object]] = [
    {"forward_origin": {"type": "user", "sender_user": {"id": 42}}},
    {"forward_from": {"id": 42, "is_bot": False, "first_name": "Dana"}},
    {"forward_from_chat": {"id": -100123, "type": "channel", "title": "Lab"}},
    {"forward_sender_name": "Dana"},
    {"forward_date": 1759000000},
    {"is_automatic_forward": True},
]


def test_every_forward_marker_is_covered():
    from services.notifications import telegram as telegram_module

    covered = {next(iter(marker)) for marker in _FORWARD_MARKERS}
    assert covered == {*telegram_module._FORWARD_KEYS, "is_automatic_forward"}


@pytest.mark.asyncio
@pytest.mark.parametrize("marker", _FORWARD_MARKERS, ids=[next(iter(m)) for m in _FORWARD_MARKERS])
async def test_a_forwarded_note_reaches_the_applier_fenced(session_factory, bot, marker):
    await _link(session_factory, "tg-voice-fwd@example.com", 3006)
    heard = "Please invite dana.lab@example.edu to the study group on Friday."
    chat = RecordingChat()
    svc = service(session_factory, chat, local=FakeLocal(heard))
    message = voice_message(3006, caption="what does she want?", **marker)
    await svc._handle_message(message)
    await svc.wait_for_chats()
    echo = bot.sends()[0]
    assert echo["text"].startswith("🎧 Transcript of the forwarded voice note") and echo["disable_notification"] is True
    ((_, text, extra),) = chat.calls
    assert text.startswith("what does she want?\n\n")
    assert untrusted_spans(text) == [heard]
    assert "dana.lab@example.edu" not in outside_fences(text)
    assert extra["attachments"][0]["forwarded"] is True and extra["attachments"][0]["trusted"] is False
    await svc._client.aclose()


@pytest.mark.asyncio
async def test_an_audio_file_is_untrusted_and_a_video_note_gets_its_reply(session_factory, bot):
    await _link(session_factory, "tg-voice-audio@example.com", 3007)
    chat = RecordingChat()
    svc = service(session_factory, chat)
    await svc._handle_message(voice_message(3007, kind="audio", file_id="a1", mime="audio/mpeg", size=len(MP3)))
    await svc.wait_for_chats()
    ((_, text, _extra),) = chat.calls
    assert text.startswith(voice.DEFAULT_INSTRUCTION) and untrusted_spans(text) == [SPOKEN]
    assert bot.sends()[0]["text"].startswith("🎧 Transcript of lecture 3.mp3")
    bot.calls.clear()
    await svc._handle_message(voice_message(3007, kind="video_note", file_id="vn1"))
    await svc.wait_for_chats()
    assert bot.texts() == [voice.TEXT_VIDEO_NOTE]
    assert "getFile" not in bot.methods()
    assert len(chat.calls) == 1
    await svc._client.aclose()


@pytest.mark.asyncio
async def test_stop_during_transcription_sends_no_echo_and_runs_no_turn(session_factory, bot):
    await _link(session_factory, "tg-voice-stop@example.com", 3008)
    chat = RecordingChat()
    local = FakeLocal()
    local.hold = asyncio.Event()
    svc = service(session_factory, chat, local=local)
    await svc._handle_message(voice_message(3008))
    await asyncio.wait_for(local.entered.wait(), 5)
    await svc._handle_message(telegram_dm(3008, "/stop"))
    await svc.wait_for_chats()
    assert local.cancelled is True
    assert chat.calls == []
    assert not any(t.startswith("🎤 Heard") for t in bot.texts())
    assert bot.texts()[-1].startswith("⏹ Stopped.")
    await svc._client.aclose()


@pytest.mark.asyncio
async def test_a_failed_download_logs_no_token(session_factory, bot, caplog):
    await _link(session_factory, "tg-voice-fail@example.com", 3009)
    bot.fail_download = True
    chat = RecordingChat()
    svc = service(session_factory, chat)
    with capture_logs() as logs:
        await svc._handle_message(voice_message(3009))
        await svc.wait_for_chats()
    assert bot.texts()[-1] == voice.failure_text("download_failed")
    assert "Telegram did not hand the recording over" in bot.texts()[-1]
    assert TOKEN not in json.dumps(logs, default=str)
    assert TOKEN not in caplog.text
    assert chat.calls == []
    await svc._client.aclose()


@pytest.mark.asyncio
async def test_no_speech_is_a_reply_and_no_turn(session_factory, bot):
    await _link(session_factory, "tg-voice-silent@example.com", 3010)
    chat = RecordingChat()
    svc = service(session_factory, chat, local=FakeLocal(text=""))
    await svc._handle_message(voice_message(3010))
    await svc.wait_for_chats()
    assert bot.texts() == [voice.TEXT_NO_SPEECH] and chat.calls == []
    await svc._client.aclose()


@pytest.mark.asyncio
async def test_a_refused_note_keeps_the_fresh_start_for_the_next_message(session_factory, bot):
    await _link(session_factory, "tg-voice-fresh@example.com", 3011)
    chat = RecordingChat()
    svc = service(session_factory, chat, switches={}, speech_local_installed=True)
    await svc._handle_message(telegram_dm(3011, "/new"))
    await svc._handle_message(voice_message(3011))
    await svc.wait_for_chats()
    assert 3011 in svc._fresh_chats
    await svc._client.aclose()


@pytest.mark.asyncio
async def test_a_card_number_said_out_loud_is_masked_and_warned_about(session_factory, bot):
    await _link(session_factory, "tg-voice-card@example.com", 3014)
    chat = RecordingChat()
    svc = service(session_factory, chat, local=FakeLocal("Pay it with my card 4111 1111 1111 1111 please."))
    await svc._handle_message(voice_message(3014))
    await svc.wait_for_chats()
    echo, warning = bot.texts()[0], bot.texts()[1]
    assert "4111 1111 1111 1111" not in echo and echo.startswith("🎤 Heard:")
    assert "Telegram keeps a copy of this chat" in warning
    assert len(chat.calls) == 1
    await svc._client.aclose()


@pytest.mark.asyncio
async def test_help_names_voice_notes(session_factory, bot):
    await _link(session_factory, "tg-voice-help@example.com", 3012)
    svc = service(session_factory, RecordingChat())
    await svc._handle_message(telegram_dm(3012, "/help"))
    assert "🎤 Send a voice note and I'll answer it like a typed message" in bot.texts()[-1]
    await svc._client.aclose()


@pytest.mark.asyncio
async def test_without_a_voice_service_the_bot_says_so(session_factory, bot):
    from services.notifications.telegram import TelegramService

    await _link(session_factory, "tg-voice-none@example.com", 3013)
    svc = TelegramService(token=TOKEN, session_factory=session_factory)
    svc.chat = RecordingChat()
    await svc._handle_message(voice_message(3013))
    await svc._handle_message(voice_message(3013, kind="video_note"))
    assert bot.texts() == [voice.TEXT_NOT_SET_UP, voice.TEXT_VIDEO_NOTE]
    assert "getFile" not in bot.methods()
    await svc._client.aclose()


# -- The chat applier ---------------------------------------------------------------------


@pytest.mark.asyncio
async def test_the_applier_stores_attachments_and_folds_the_usage_seed(session_factory):
    from api.routes.agent import build_chat_applier
    from main import app
    from models.conversation import Message, MessageRole
    from services.agent.runtime import AgentResponse

    user, _ = await make_user(session_factory, "applier-voice@example.com")
    replay = {"on": False}

    class FakeRuntime:
        async def chat(self, **kwargs):
            sink = kwargs["usage_sink"]
            if replay["on"]:  # a replay-cache hit: no model call, empty usage
                return AgentResponse(content="cached answer")
            sink.usage["input_tokens"] = sink.usage.get("input_tokens", 0) + 100
            sink.usage["output_tokens"] = sink.usage.get("output_tokens", 0) + 20
            return AgentResponse(content="ok", usage=sink.usage, provider="gemini", model="gemini-3.5-flash-lite")

    saved = getattr(app.state, "agent_runtime", None)
    app.state.agent_runtime = FakeRuntime()
    entry = {
        "kind": "voice_note",
        "source": "telegram",
        "duration_s": 3.0,
        "sha256": "ab" * 32,
        "trusted": True,
        "data": "T2dnUw==",
        "nested": {"no": "thanks"},
    }
    seed = {"input_tokens": 400, "output_tokens": 12, "bogus": 7, "cache_read_tokens": -3}
    try:
        chat = build_chat_applier(app, session_factory=session_factory)
        done = await chat(str(user.id), "[Voice note, transcribed] hi", attachments=[entry], usage_seed=seed)
        assert done["usage"] == {"input_tokens": 500, "output_tokens": 32}
        replay["on"] = True
        cached = await chat(str(user.id), "[Voice note, transcribed] hi", attachments=[entry], usage_seed=seed)
        assert cached["content"] == "cached answer"
        assert cached["usage"] == {"input_tokens": 400, "output_tokens": 12}
    finally:
        app.state.agent_runtime = saved

    async with session_factory() as session:
        rows = (await session.execute(select(Message).order_by(Message.created_at))).scalars().all()
    users = [r for r in rows if r.role == MessageRole.user]
    assistants = [r for r in rows if r.role == MessageRole.assistant]
    assert users[0].attachments == [
        {"kind": "voice_note", "source": "telegram", "duration_s": 3.0, "sha256": "ab" * 32, "trusted": True}
    ]
    assert (assistants[0].input_tokens, assistants[0].output_tokens) == (500, 32)
    assert (assistants[1].input_tokens, assistants[1].output_tokens) == (400, 12)
