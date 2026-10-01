"""Tests for tutor mode on the chat channels: Telegram's /tutor reaches the
tutor applier only from the linked chat, consumes a pending /new so the fresh
thread is switched, answers a malformed argument with the usage line and is
listed in /help; Slack's bare "tutor on|off" reaches the applier while
"tutor me" goes to the chat; the applier writes the command and its fixed
reply into the channel's thread (a fresh one after /new) without a model
call; and a channel turn's reply carries the notice when the model switched
tutor mode on.

Why it exists: on a phone the chat is the only way to switch the mode. An
unlinked chat that could switch someone's mode, a "/new" that left the old
thread in tutor mode, or a Slack reply that sent every "tutor ..." message to
the applier would each break it quietly.
"""

from __future__ import annotations

import uuid
from types import SimpleNamespace
from typing import Any

import pytest
from sqlalchemy import select

from core.config import settings
from models.conversation import Conversation, Message
from services.agent.approvals import InMemoryApprovalStore
from services.agent.providers import LLMResponse, ToolCall
from services.agent.runtime import AgentRuntime, PermissionEngine
from services.tutor.prompt import NOTICE_ON
from services.tutor.state import TutorState
from tests.conftest import make_user, telegram_dm, use_provider
from tests.test_agent_runtime_vision import RecordingAudit, RecordingGuard, RecordingProvider

LINKED_CHAT = 8101
UNLINKED_CHAT = 8102


def _telegram():
    from services.notifications.telegram import TelegramService

    service = TelegramService(token="123:fake-token", session_factory=lambda: None)
    sent: list[tuple[str, dict[str, Any]]] = []
    applied: list[tuple[Any, ...]] = []

    async def api(method: str, **params: Any) -> Any:
        sent.append((method, params))
        return {}

    async def user_for_chat(chat_id: Any):
        return "tutor-user" if chat_id == LINKED_CHAT else None

    async def tutor(user_id: str, command: str, **kwargs: Any) -> dict[str, Any]:
        applied.append((user_id, command, kwargs))
        return {"reply": f"reply to {command}"}

    service._api = api  # type: ignore[method-assign]
    service._user_for_chat = user_for_chat  # type: ignore[method-assign]
    service.tutor = tutor
    return service, sent, applied


def _texts(sent: list[tuple[str, dict[str, Any]]]) -> list[str]:
    return [params["text"] for method, params in sent if method == "sendMessage"]


@pytest.mark.asyncio
async def test_telegram_tutor_from_the_linked_chat_reaches_the_applier():
    service, sent, applied = _telegram()

    await service._handle_message(telegram_dm(LINKED_CHAT, "/tutor on"))
    await service._handle_message(telegram_dm(LINKED_CHAT, "/tutor@crawler_bot OFF"))
    await service._handle_message(telegram_dm(LINKED_CHAT, "/tutor"))

    assert applied == [
        ("tutor-user", "on", {"new_conversation": False, "text": "/tutor on"}),
        ("tutor-user", "off", {"new_conversation": False, "text": "/tutor off"}),
        ("tutor-user", "status", {"new_conversation": False, "text": "/tutor status"}),
    ]
    assert _texts(sent) == ["reply to on", "reply to off", "reply to status"]
    await service._client.aclose()


@pytest.mark.asyncio
async def test_an_unlinked_chat_gets_no_reply():
    service, sent, applied = _telegram()
    await service._handle_message(telegram_dm(UNLINKED_CHAT, "/tutor on"))
    assert applied == [] and sent == []
    await service._client.aclose()


@pytest.mark.asyncio
async def test_new_then_tutor_on_targets_the_fresh_thread():
    service, _sent, applied = _telegram()
    await service._handle_message(telegram_dm(LINKED_CHAT, "/new"))
    assert LINKED_CHAT in service._fresh_chats
    await service._handle_message(telegram_dm(LINKED_CHAT, "/tutor on"))
    assert applied[-1][2]["new_conversation"] is True
    assert LINKED_CHAT not in service._fresh_chats  # consumed: the next message continues it
    await service._client.aclose()


@pytest.mark.asyncio
async def test_a_failed_command_keeps_the_pending_new():
    service, sent, _applied = _telegram()

    async def failing(user_id: str, command: str, **kwargs: Any) -> dict[str, Any]:
        return {"error": "Unknown account."}

    service.tutor = failing
    service._fresh_chats.add(LINKED_CHAT)
    await service._handle_message(telegram_dm(LINKED_CHAT, "/tutor on"))
    assert LINKED_CHAT in service._fresh_chats
    assert _texts(sent) == ["⚠️ Unknown account."]
    await service._client.aclose()


@pytest.mark.asyncio
async def test_a_malformed_argument_gets_the_usage_line_and_help_lists_tutor():
    service, sent, applied = _telegram()
    await service._handle_message(telegram_dm(LINKED_CHAT, "/tutor please"))
    assert applied == []
    assert _texts(sent) == ["Use /tutor on, /tutor off or /tutor status."]
    await service._handle_message(telegram_dm(LINKED_CHAT, "/help"))
    assert "/tutor — tutor mode for this chat: /tutor on, /tutor off, /tutor status" in _texts(sent)[-1]
    assert "/tutor" in service._commands
    await service._client.aclose()


# ── Slack ────────────────────────────────────────────────────────────────────

TEAM = "T0TEAM001"
LINKED = "U0LINKED1"
DM = "D0DM00001"


def _slack():
    from services.connectors.slack import SlackConnector
    from services.notifications import slack as slack_mod

    connector = SlackConnector.from_credentials({"bot_token": "xoxb-x", "app_token": "xapp-x"})
    channel = slack_mod.SlackChannel(
        connector_id="11111111-1111-1111-1111-111111111111",
        user_id="22222222-2222-2222-2222-222222222222",
        bot_token="xoxb-x",
        app_token="xapp-x",
        session_factory=lambda: None,
        connector=connector,
    )
    channel.team_id = TEAM
    channel.bot_user_id = "U0BOT0001"
    link = SimpleNamespace(team_id=TEAM, slack_user_id=LINKED, link_code_hash=None, link_expires_at=None)

    async def load_link():
        return link

    channel._load_link = load_link  # type: ignore[method-assign]
    return channel


def _dm(text: str, n: int) -> dict[str, Any]:
    return {
        "type": "event_callback",
        "team_id": TEAM,
        "event_id": f"Ev{n:08d}",
        "event": {
            "type": "message",
            "channel": DM,
            "user": LINKED,
            "text": text,
            "ts": f"{n}.000100",
            "channel_type": "im",
        },
    }


@pytest.mark.asyncio
async def test_slack_tutor_words_reach_the_applier_and_other_text_the_chat():
    channel = _slack()
    posted: list[str] = []
    applied: list[tuple[Any, ...]] = []
    chats: list[str] = []

    async def post_text(_ch: str, text: str):
        posted.append(text)
        return {}

    async def tutor(user_id: str, command: str, **kwargs: Any) -> dict[str, Any]:
        applied.append((user_id, command, kwargs))
        return {"reply": f"slack {command}"}

    channel._post_text = post_text  # type: ignore[method-assign]
    channel._handle_chat = lambda ch, text: chats.append(text)  # type: ignore[method-assign]
    channel.tutor = tutor

    for n, text in enumerate(["new", "tutor on", "Tutor off", "tutor me in calc", "/tutor on"], start=1):
        await channel._on_events_api(_dm(text, n))
    await channel.wait_idle()

    assert applied == [
        (channel.user_id, "on", {"new_conversation": True, "text": "tutor on"}),
        (channel.user_id, "off", {"new_conversation": False, "text": "tutor off"}),
    ]
    assert chats == ["tutor me in calc", "/tutor on"]
    assert posted[-2:] == ["slack on", "slack off"]
    assert channel._fresh is False
    await channel._connector.close()


# ── The appliers ─────────────────────────────────────────────────────────────


def _app(runtime: Any = None) -> Any:
    return SimpleNamespace(state=SimpleNamespace(installation=None, mcp_catalog=None, agent_runtime=runtime))


@pytest.mark.asyncio
async def test_the_tutor_applier_writes_into_the_channel_thread_and_after_new_a_fresh_one(session_factory):
    from api.routes.agent import build_chat_applier, build_tutor_applier

    user, _ = await make_user(session_factory, "applier@example.com")
    provider = RecordingProvider([LLMResponse(content="Hi again")])
    runtime = AgentRuntime(
        config=settings,
        permission_engine=PermissionEngine(),
        prompt_guard=RecordingGuard(),
        audit_service=RecordingAudit(),
        approval_store=InMemoryApprovalStore(),
    )
    use_provider(runtime, provider)
    app = _app(runtime)
    apply = build_tutor_applier(app, session_factory, channel="telegram")
    chat = build_chat_applier(app, session_factory)

    first = await apply(str(user.id), "on", text="/tutor on")
    assert first["reply"].endswith("/tutor off switches it off.")
    fresh = await apply(str(user.id), "status", new_conversation=True, text="/tutor")
    assert fresh["conversation_id"] != first["conversation_id"]
    assert fresh["reply"].startswith("Tutor mode: off in this chat.")

    outcome = await chat(str(user.id), "hello")
    assert outcome["conversation_id"] == fresh["conversation_id"]  # the next message continues it
    assert provider.calls and "<tutor_mode>" not in provider.calls[0]["messages"][0]["content"]

    async with session_factory() as session:
        conversations = (
            await session.execute(select(Conversation).where(Conversation.user_id == user.id))
        ).scalars().all()
        rows = (
            await session.execute(
                select(Message)
                .where(Message.conversation_id == uuid.UUID(first["conversation_id"]))
                .order_by(Message.created_at)
            )
        ).scalars().all()
    assert {c.title for c in conversations} == {"Telegram"}
    assert [r.content for r in rows] == ["/tutor on", first["reply"]]
    by_id = {str(c.id): TutorState.from_stored(c.tutor_state) for c in conversations}
    assert by_id[first["conversation_id"]].user_on is True
    assert by_id[fresh["conversation_id"]].user_on is False


@pytest.mark.asyncio
async def test_the_tutor_applier_refuses_unknown_accounts_and_commands(session_factory):
    from api.routes.agent import build_tutor_applier

    apply = build_tutor_applier(_app(), session_factory, channel="slack")
    assert await apply(str(uuid.uuid4()), "on") == {"error": "Unknown account."}
    assert await apply("not-a-uuid", "on") == {"error": "Unknown account."}
    assert await apply(str(uuid.uuid4()), "unlock") == {"error": "Unknown tutor command."}
    with pytest.raises(ValueError):
        build_tutor_applier(_app(), session_factory, channel="email")


@pytest.mark.asyncio
async def test_a_channel_turn_reply_carries_the_notice_and_saves_the_state(session_factory):
    from api.routes.agent import build_chat_applier

    user, _ = await make_user(session_factory, "notice@example.com")
    provider = RecordingProvider(
        [
            LLMResponse(content="", tool_calls=[ToolCall(id="t1", name="tutor.start", arguments={})]),
            LLMResponse(content="What do you already know about derivatives?"),
        ]
    )
    runtime = AgentRuntime(
        config=settings,
        permission_engine=PermissionEngine(),
        prompt_guard=RecordingGuard(),
        audit_service=RecordingAudit(),
        approval_store=InMemoryApprovalStore(),
    )
    use_provider(runtime, provider)
    slack_chat = build_chat_applier(_app(runtime), session_factory, channel="slack")

    outcome = await slack_chat(str(user.id), "be my calculus tutor, don't give answers away")

    assert outcome["content"] == (
        "What do you already know about derivatives?\n\n" + NOTICE_ON.format(off="tutor off")
    )
    async with session_factory() as session:
        conversation = await session.get(Conversation, uuid.UUID(outcome["conversation_id"]))
    assert TutorState.from_stored(conversation.tutor_state).user_on is True


def test_main_wires_the_tutor_applier_on_both_channels(session_factory):
    from main import _wire_slack, _wire_telegram

    service = SimpleNamespace()
    channel = SimpleNamespace()
    _wire_telegram(_app(), service, session_factory)  # type: ignore[arg-type]
    _wire_slack(_app(), channel, session_factory)  # type: ignore[arg-type]
    assert callable(service.tutor) and callable(channel.tutor)
