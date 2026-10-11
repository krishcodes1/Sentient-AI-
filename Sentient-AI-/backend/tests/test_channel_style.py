"""Tests for the <telegram_style> system-prompt block: a turn from the user's
Telegram chat gets it exactly once, after <user_memory> and before the tutor
block; a web turn, a turn with no channel and an unattended run get a system
message byte-identical to one built without the feature; the tutor block
stays last, so its swap still works; and the replay cache never answers a
Telegram turn with a reply cached for the web. Also the bot's real entry
points: a typed message, a photo and a voice note each hand the chat
callback this chat's Channel, and a typed message plus its Approve tap reach
the model with the block through the real appliers and runtime.

Why it exists: the block only changes how a reply reads on a phone. If it
leaked into the web chat or a scheduled run, those replies would change; if
it landed after the tutor block, swap_tutor_block (which strips the block off
the end) would stop finding it, and a mid-turn lock would stack two tutor
blocks. If an entry point dropped the channel, that path would silently lose
the style while every runtime-level test still passed.
"""

from __future__ import annotations

from datetime import datetime

import httpx
import pytest

from core.config import settings
from services.agent import cancel as agent_cancel
from services.agent.app_approvals import Channel
from services.agent.approvals import InMemoryApprovalStore
from services.agent.channel_style import TELEGRAM_STYLE_PROMPT
from services.agent.providers import LLMResponse
from services.agent.runtime import SECURITY_SYSTEM_PROMPT, AgentRuntime, PermissionEngine
from services.agent.unattended import UnattendedRun
from services.tools.computer import backend as computer_backend
from services.tools.computer.backend_fake import FakeBackend
from services.tutor.prompt import (
    TUTOR_SYSTEM_PROMPT,
    VARIANT_LOCKED_COURSE,
    VARIANT_ON,
    render_tutor_block,
    swap_tutor_block,
)
from services.tutor.state import TutorState, TutorTurn
from tests.conftest import telegram_dm, use_provider
from tests.test_agent_runtime_vision import RecordingAudit, RecordingGuard, RecordingProvider
from tests.test_telegram import FakeTelegramAPI, _link
from tests.test_telegram_desktop_resume import _cards, _wait_for, calendar_desktop
from tests.test_telegram_voice import FakeBot as VoiceBot
from tests.test_telegram_voice import service as voice_service
from tests.test_telegram_voice import voice_message
from tests.test_weekly_app_approvals import (
    ANSWER,
    ASK,
    OPEN_CALENDAR,
    _action_id,
    _say,
    _tap,
    wired,
)

MEMORY = "<user_memory>\n- likes tea\n</user_memory>"
PERMISSIONS = "<permissions>\n- web: on\n</permissions>"
HISTORY = [{"role": "user", "content": "hello"}]
WEB = Channel.web("device-0123456789abcdef")


def _today_line() -> str:
    today = datetime.now().astimezone()
    return "<today>" + today.strftime("%A, %Y-%m-%d") + " (" + (today.tzname() or "local") + ")</today>"


def _golden() -> str:
    return f"{SECURITY_SYSTEM_PROMPT}\n\n{_today_line()}\n\n{PERMISSIONS}\n\n{MEMORY}"


# ── the block itself ─────────────────────────────────────────────────────────


def test_the_block_is_fixed_well_formed_text():
    block = TELEGRAM_STYLE_PROMPT
    assert block.startswith("<telegram_style>\n") and block.endswith("\n</telegram_style>")
    assert block.count("<telegram_style>") == 1 and block.count("</telegram_style>") == 1
    for rule in (
        "Telegram chat on their phone",
        "Lead with the",
        # Telegram renders bold (telegram_format.py), so a little is fine.
        "Bold at most a word or two",
        "No headings, tables or horizontal rules",
        "Paste links as bare URLs",
        "No emoji unless the user",
        # The length rules are defaults, never a silent cut.
        "say what you left out",
        "These are defaults for tone and layout",
        "anything they asked you to write comes in full",
        "approvals, safety and citing sources",
        "If tutor mode is",
    ):
        assert rule in block
    # Replies are rendered as Telegram formatting, so nothing forbids bold.
    assert "no Markdown" not in block


def test_the_block_has_no_em_or_en_dash():
    assert "\u2014" not in TELEGRAM_STYLE_PROMPT and "\u2013" not in TELEGRAM_STYLE_PROMPT


# ── _with_system_prompt ──────────────────────────────────────────────────────


def test_without_a_channel_block_the_system_message_is_the_golden_one():
    built = AgentRuntime._with_system_prompt(HISTORY, MEMORY, PERMISSIONS)
    assert built[0] == {"role": "system", "content": _golden()}
    assert AgentRuntime._with_system_prompt(HISTORY, MEMORY, PERMISSIONS, channel_block=None) == built


def test_the_block_goes_after_memory_and_before_tutor():
    tutor = render_tutor_block(VARIANT_ON)
    styled = AgentRuntime._with_system_prompt(
        HISTORY, MEMORY, PERMISSIONS, channel_block=TELEGRAM_STYLE_PROMPT
    )
    assert styled[0]["content"] == f"{_golden()}\n\n{TELEGRAM_STYLE_PROMPT}"
    both = AgentRuntime._with_system_prompt(
        HISTORY, MEMORY, PERMISSIONS, channel_block=TELEGRAM_STYLE_PROMPT, tutor_block=tutor
    )
    content = both[0]["content"]
    assert content == f"{_golden()}\n\n{TELEGRAM_STYLE_PROMPT}\n\n{tutor}"
    assert (
        content.index("<permissions>")
        < content.index("<user_memory>")
        < content.index("<telegram_style>")
        < content.index("<tutor_mode>")
    )
    assert both[1:] == HISTORY


def test_the_tutor_swap_round_trips_with_the_block_present():
    on, locked = render_tutor_block(VARIANT_ON), render_tutor_block(VARIANT_LOCKED_COURSE)
    base = AgentRuntime._with_system_prompt(
        HISTORY, MEMORY, PERMISSIONS, channel_block=TELEGRAM_STYLE_PROMPT
    )
    with_on = swap_tutor_block(base, None, on)
    assert with_on == AgentRuntime._with_system_prompt(
        HISTORY, MEMORY, PERMISSIONS, channel_block=TELEGRAM_STYLE_PROMPT, tutor_block=on
    )
    swapped = swap_tutor_block(with_on, on, locked)
    assert swapped[0]["content"] == f"{base[0]['content']}\n\n{locked}"
    assert swapped[0]["content"].count("<tutor_mode>") == 1
    assert swapped[0]["content"].count("<telegram_style>") == 1
    assert swap_tutor_block(swapped, locked, None) == base


# ── chat() ───────────────────────────────────────────────────────────────────


def _runtime(provider):
    runtime = AgentRuntime(
        config=settings,
        permission_engine=PermissionEngine(),
        prompt_guard=RecordingGuard(),
        audit_service=RecordingAudit(),
        approval_store=InMemoryApprovalStore(),
    )
    use_provider(runtime, provider)
    return runtime


async def _system_of(**kwargs) -> str:
    provider = RecordingProvider()
    await _runtime(provider).chat(
        messages=list(HISTORY), tools=[], user_id="u1", memory_block=MEMORY, **kwargs
    )
    return provider.calls[0]["messages"][0]["content"]


@pytest.mark.asyncio
async def test_a_telegram_turn_gets_the_block_once_after_memory():
    plain = await _system_of()
    telegram = await _system_of(channel=Channel.telegram(1))
    assert telegram.count(TELEGRAM_STYLE_PROMPT) == 1
    assert telegram == f"{plain}\n\n{TELEGRAM_STYLE_PROMPT}"
    assert plain.endswith(MEMORY)


@pytest.mark.asyncio
async def test_a_web_turn_and_a_turn_without_a_channel_are_unchanged():
    assert WEB is not None and WEB.kind == "web"
    plain = await _system_of()
    assert "<telegram_style>" not in plain
    assert await _system_of(channel=WEB) == plain
    assert await _system_of(channel=None) == plain


@pytest.mark.asyncio
async def test_an_unattended_run_never_gets_the_block():
    run = UnattendedRun(label="Weekly", origin="schedule:1", reads=frozenset(), max_usd=0.05)
    content = await _system_of(unattended=run)
    assert "<unattended" in content
    assert "<telegram_style>" not in content


@pytest.mark.asyncio
async def test_with_tutor_on_the_tutor_block_stays_last_on_telegram():
    content = await _system_of(
        channel=Channel.telegram(1), tutor=TutorTurn(TutorState(user_on=True), [])
    )
    assert content.endswith(f"{MEMORY}\n\n{TELEGRAM_STYLE_PROMPT}\n\n{TUTOR_SYSTEM_PROMPT[VARIANT_ON]}")
    assert content.count("<telegram_style>") == 1 and content.count("<tutor_mode>") == 1


@pytest.mark.asyncio
async def test_the_replay_cache_never_crosses_from_web_to_telegram():
    provider = RecordingProvider(
        [LLMResponse(content="## Answer\n\n| a | b |"), LLMResponse(content="It's 42.")]
    )
    runtime = _runtime(provider)
    web = await runtime.chat(
        messages=list(HISTORY), tools=[], user_id="u1", conversation_id="c1", channel=WEB
    )
    telegram = await runtime.chat(
        messages=list(HISTORY),
        tools=[],
        user_id="u1",
        conversation_id="c1",
        channel=Channel.telegram(1),
    )
    assert web.content == "## Answer\n\n| a | b |"
    assert telegram.content == "It's 42."
    assert len(provider.calls) == 2


# ── the bot's entry points ───────────────────────────────────────────────────


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
def voice_bot(monkeypatch):
    """The Bot API with getFile and downloads: a voice note and a photo."""
    bot = VoiceBot()
    bot.files["photo-big"] = b"B" * 2000
    real_client_cls = httpx.AsyncClient
    monkeypatch.setattr(
        httpx,
        "AsyncClient",
        lambda **kw: real_client_cls(**{**kw, "transport": httpx.MockTransport(bot.handler)}),
    )
    return bot


@pytest.fixture
def touched():
    """User ids whose stop is forgotten after the test."""
    ids: set[str] = set()
    yield ids
    for uid in ids:
        agent_cancel.clear(uid)


@pytest.fixture
def backend_ready(monkeypatch):
    monkeypatch.setattr(
        computer_backend, "select_backend", lambda name: FakeBackend(available=(True, ""))
    )


class ChannelChat:
    """A chat callback taking every keyword the bot can pass; keeps the
    channel of each call."""

    def __init__(self) -> None:
        self.channels: list = []

        async def file_gate():
            return None

        self.file_gate = file_gate

    async def __call__(
        self,
        user_id,
        text,
        *,
        new_conversation=False,
        stop_mark=None,
        channel=None,
        files=None,
        images=None,
        attachments=None,
        usage_seed=None,
    ):
        self.channels.append(channel)
        return {"content": "ok"}


@pytest.mark.asyncio
async def test_a_typed_message_a_photo_and_a_voice_note_carry_this_chat(
    session_factory, voice_bot
):
    await _link(session_factory, "style-media@example.com", 9411)
    chat = ChannelChat()
    svc = voice_service(session_factory, chat)
    photo = telegram_dm(9411, "")
    del photo["text"]
    photo["photo"] = [{"file_id": "photo-big", "file_size": 2000, "width": 1280, "height": 960}]
    photo["caption"] = "what is this?"
    try:
        for message in (telegram_dm(9411, "hi"), photo, voice_message(9411)):
            await svc._handle_message(message)
            await svc.wait_for_chats()
    finally:
        await svc._client.aclose()
    assert "download" in voice_bot.methods()
    assert chat.channels == [Channel.telegram(9411)] * 3


@pytest.mark.asyncio
async def test_a_typed_message_and_its_approve_tap_reach_the_model_with_the_block(
    session_factory, fake_api, touched, backend_ready
):
    # The real bot, appliers and runtime: the turn the message starts and
    # the turn the tap resumes both read the Telegram style, once.
    user = await _link(session_factory, "style-tap@example.com", 9412)
    touched.add(str(user.id))
    provider = RecordingProvider([OPEN_CALENDAR, ANSWER])
    async with wired(session_factory, provider, calendar_desktop()) as service:
        await _say(service, 9412, ASK)
        assert await _wait_for(lambda: len(_cards(fake_api)) == 1)
        await _tap(service, "apv:" + _action_id(_cards(fake_api)[0]), 9412)
    assert len(provider.calls) == 2
    for call in provider.calls:
        assert call["messages"][0]["content"].count(TELEGRAM_STYLE_PROMPT) == 1
