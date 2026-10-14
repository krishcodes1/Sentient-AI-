"""Tests for secret masking on the chat channels (services/security/channels.py
at Telegram's _api, _send_photo, _send_reply and _handle_chat, Slack's _post,
_send_reply and _run_chat, and cards.layout_card): sendMessage, editMessageText,
photo captions and Slack blocks are masked; a token straddling the 3,900-
character split is masked whole and the footer appears once; the card's digest
is still that of the real arguments; a detector error sends the withheld
notice; a key in the person's own message gets one warning line first; and
contact details are never masked.

Why it exists: Telegram and Slack keep their own copy of every message,
outside Crawler's reach, so anything they are sent is effectively published.
Fake HTTP transports and a fake Slack connector: no network.
"""

from __future__ import annotations

import base64
from types import SimpleNamespace
from typing import Any

import httpx
import pytest

from services.notifications import cards
from services.security import redact as redact_module
from services.security.policies import CHANNEL_WITHHELD

TOKEN = "ghp_" + "FAKE" * 9
CARD = "4111 1111 1111 1111"
CHAT = 7201
FOOTER_TG = "not shown on Telegram."


class TelegramAPI:
    """Records every Bot API request's method and raw body."""

    def __init__(self) -> None:
        self.requests: list[tuple[str, bytes]] = []

    def handler(self, request: httpx.Request) -> httpx.Response:
        self.requests.append((request.url.path.rsplit("/", 1)[-1], request.content))
        return httpx.Response(200, json={"ok": True, "result": {"message_id": 1}})

    def texts(self, method: str = "sendMessage") -> list[str]:
        import json

        return [json.loads(body)["text"] for m, body in self.requests if m == method]


@pytest.fixture
def telegram(monkeypatch):
    from services.notifications.telegram import TelegramService

    api = TelegramAPI()
    real = httpx.AsyncClient

    def factory(**kwargs):
        kwargs["transport"] = httpx.MockTransport(api.handler)
        return real(**kwargs)

    monkeypatch.setattr(httpx, "AsyncClient", factory)
    service = TelegramService(token="123:fake-token", session_factory=lambda: None)
    return service, api


# ── Telegram ─────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_send_and_edit_are_masked_at_the_choke_point(telegram):
    service, api = telegram
    await service._api("sendMessage", chat_id=CHAT, text=f"key {TOKEN}, card {CARD}")
    await service._api("editMessageText", chat_id=CHAT, message_id=1, text=f"now {TOKEN}")
    assert api.texts() == ["key [hidden: GitHub token], card [hidden: card number]"]
    assert api.texts("editMessageText") == ["now [hidden: GitHub token]"]
    await service._client.aclose()


@pytest.mark.asyncio
async def test_contact_details_are_never_masked_on_channels(telegram):
    service, api = telegram
    text = "Write to prof.lee@uni.edu or call (212) 555-0100, 1600 Pennsylvania Avenue NW."
    await service._api("sendMessage", chat_id=CHAT, text=text)
    assert api.texts() == [text]
    await service._client.aclose()


@pytest.mark.asyncio
async def test_a_photo_caption_is_masked(telegram):
    service, api = telegram
    image = "data:image/png;base64," + base64.b64encode(b"\x89PNG fake").decode()
    assert await service._send_photo(CHAT, image, f"card {CARD}")
    [(method, body)] = api.requests
    assert method == "sendPhoto"
    assert CARD.encode() not in body and b"[hidden: card number]" in body
    await service._client.aclose()


@pytest.mark.asyncio
async def test_a_token_straddling_the_split_is_masked_and_the_footer_appears_once(telegram):
    service, api = telegram
    text = "a" * 3880 + " " + TOKEN + " tail " + "b" * 200 + f" and {CARD}"
    await service._send_reply(CHAT, text, {"usage": {"input_tokens": 10, "output_tokens": 5}})
    sent = api.texts()
    assert len(sent) >= 2
    joined = "".join(sent)
    assert "FAKEFAKE" not in joined and "4111" not in joined
    assert joined.count(FOOTER_TG) == 1
    assert "Crawler hid 2 values that look like a key, card or ID number." in joined
    # The usage line stays the last thing.
    assert FOOTER_TG not in sent[-1].rstrip().splitlines()[-1]
    await service._client.aclose()


@pytest.mark.asyncio
async def test_a_clean_reply_has_no_footer(telegram):
    service, api = telegram
    await service._send_reply(CHAT, "All done.", {})
    assert api.texts() == ["All done."]
    await service._client.aclose()


@pytest.mark.asyncio
async def test_a_detector_error_sends_the_withheld_notice(telegram, monkeypatch):
    service, api = telegram

    def boom(*_args, **_kwargs):
        raise RuntimeError("detector bug")

    monkeypatch.setattr(redact_module, "find", boom)
    await service._api("sendMessage", chat_id=CHAT, text=f"anything {TOKEN}")
    assert api.texts() == [CHANNEL_WITHHELD]
    await service._client.aclose()


@pytest.mark.asyncio
async def test_an_inbound_key_gets_one_warning_line_before_the_turn(telegram):
    service, api = telegram
    seen: list[str] = []

    async def chat(user_id: str, text: str, new_conversation: bool = False) -> dict[str, Any]:
        seen.append(text)
        return {"content": "Revoke it; here is how."}

    service.chat = chat
    await service._handle_chat(CHAT, "user-1", f"why does this fail? {TOKEN}")
    await service.wait_for_chats()
    sent = api.texts()
    assert sent[0] == (
        "\U0001f512 Your message has what looks like a GitHub token. Crawler hid it from the "
        "AI, but Telegram keeps a copy of this chat: revoke it and make a new one."
    )
    assert TOKEN not in "".join(sent)
    # The turn itself still runs (the model floor hides the key there).
    assert seen == [f"why does this fail? {TOKEN}"]

    api.requests.clear()
    await service._handle_chat(CHAT, "user-1", "email prof.lee@uni.edu please")
    await service.wait_for_chats()
    assert not any("looks like" in t for t in api.texts())
    await service._client.aclose()


@pytest.mark.asyncio
async def test_a_card_shows_masked_arguments_with_the_real_digest(telegram, monkeypatch):
    service, api = telegram
    arguments = {"to": "prof.lee@uni.edu", "body": f"the key is {TOKEN}"}

    async def linked(_user_id: str) -> int:
        return CHAT

    monkeypatch.setattr(service, "linked_chat_id", linked)
    action = SimpleNamespace(
        action_id="act-1",
        user_id="user-1",
        tool_name="google_workspace.send_email",
        arguments=arguments,
        reason="Send an email",
        risk_note=None,
        expires_at="2099-01-01T00:00:00+00:00",
    )
    await service.notify_pending(action)
    [text] = api.texts()
    assert TOKEN not in text and "[hidden: GitHub token]" in text
    assert "To: prof.lee@uni.edu" in text
    assert cards.check_code_line(arguments) in text
    await service._client.aclose()


# The same call's card in the web app (GET /agent/approvals and the stream,
# api.routes.agent._approval_card_fields) and in a chat must show the same
# check code, so the owner can tell they are the same request. The chat
# masks secrets in what it shows, never in what it codes; a desktop.act
# card leaves out its stored screen in both.
_SAME_CODE_CASES = [
    (
        "google_workspace.send_email",
        {"to": "prof.lee@uni.edu", "subject": "Keys", "body": f"the key is {TOKEN}"},
    ),
    (
        "desktop.act",
        {"action": "type", "ref": "d12", "text": f"card {CARD}", "_screen": {"app": "Notepad"}},
    ),
    ("slack.post_message", {"channel": "C0CHAN001", "text": "line one\nline two"}),
]


def _check_code_of(text: str) -> str:
    [line] = [line for line in text.split("\n") if line.startswith("Check code ")]
    return line.removeprefix("Check code ")


def _card_action(tool_name: str, arguments: dict[str, Any]) -> SimpleNamespace:
    return SimpleNamespace(
        action_id="act-1",
        user_id="22222222-2222-2222-2222-222222222222",
        tool_name=tool_name,
        arguments=arguments,
        reason="Do the thing",
        risk_note=None,
        expires_at="2099-01-01T00:00:00+00:00",
    )


def _assert_same_card(text: str, tool_name: str, arguments: dict[str, Any]) -> None:
    from api.routes import agent as agent_routes

    web = agent_routes._approval_card_fields(tool_name, arguments)
    assert web["check_code"] and _check_code_of(text) == web["check_code"]
    # Every value the web card lists is on the chat card too, under the
    # same label; secrets only ever masked.
    assert web["details"]
    for detail in web["details"]:
        assert f"{detail['label']}:" in text
    assert TOKEN not in text and CARD not in text
    assert "Notepad" not in text and "_screen" not in text


@pytest.mark.asyncio
@pytest.mark.parametrize(("tool_name", "arguments"), _SAME_CODE_CASES)
async def test_the_telegram_card_shows_the_web_cards_check_code(
    telegram, monkeypatch, tool_name, arguments
):
    service, api = telegram

    async def linked(_user_id: str) -> int:
        return CHAT

    monkeypatch.setattr(service, "linked_chat_id", linked)
    await service.notify_pending(_card_action(tool_name, arguments))
    _assert_same_card("\n".join(api.texts()), tool_name, arguments)
    await service._client.aclose()


@pytest.mark.asyncio
@pytest.mark.parametrize(("tool_name", "arguments"), _SAME_CODE_CASES)
async def test_the_slack_card_shows_the_web_cards_check_code(monkeypatch, tool_name, arguments):
    from services.notifications import slack as slack_mod

    channel, posted = _slack()

    async def linked_dm() -> str:
        return "D0DM00001"

    monkeypatch.setattr(slack_mod.SlackChannel, "running", property(lambda self: True))
    monkeypatch.setattr(channel, "_linked_dm", linked_dm)
    assert await channel.notify_pending(_card_action(tool_name, arguments)) is True
    text = "\n".join(
        block["text"]["text"]
        for body in posted
        for block in body.get("blocks", [])
        if block.get("type") == "section"
    )
    _assert_same_card(text, tool_name, arguments)
    await channel._connector.close()


def test_layout_card_masks_the_render_and_keeps_the_check_code():
    arguments = {"body": f"card {CARD}"}
    card = cards.layout_card(["Approval required"], arguments, tool_name="x.y", max_chars=3900)
    text = "\n".join(card.final_lines)
    assert CARD not in text and "Message: card [hidden: card number]" in text
    # The code is of the real arguments, not of what the chat was shown.
    assert card.final_lines[-1] == f"Check code {cards.check_code(arguments)}"
    assert cards.check_code(arguments) != cards.check_code({"body": "card [hidden: card number]"})


def test_layout_card_masks_nested_and_multi_line_values_in_every_part():
    arguments = {
        "to": "prof.lee@uni.edu",
        "options": {"retries": 2, "notes": [f"first {TOKEN}", "second"]},
        "body": "line\n" * 2000 + f"last {CARD}",
    }
    card = cards.layout_card(["Approval required"], arguments, tool_name="x.y", max_chars=3900)
    messages = [*card.leading, "\n".join(card.final_lines)]
    joined = "\n".join(messages)
    assert len(card.leading) >= 2
    assert TOKEN not in joined and "FAKEFAKE" not in joined and "4111" not in joined
    assert "[hidden: GitHub token]" in joined and "[hidden: card number]" in joined
    assert "prof.lee@uni.edu" in joined
    assert card.final_lines[-1] == cards.check_code_line(arguments)


# ── Slack ────────────────────────────────────────────────────────────────


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
    posted: list[dict[str, Any]] = []

    async def send_chat(method: str, body: dict[str, Any], action: str) -> dict[str, Any]:
        posted.append(body)
        return {"ok": True, "ts": "1.0"}

    async def no_sleep(_seconds: float) -> None:
        return None

    channel._connector._send_chat = send_chat  # type: ignore[method-assign]
    channel._sleep = no_sleep
    return channel, posted


@pytest.mark.asyncio
async def test_slack_post_masks_text_and_every_plain_text_block():
    from services.notifications import slack as slack_mod

    channel, posted = _slack()
    await channel._post(
        "D0DM00001",
        f"key {TOKEN}",
        [slack_mod._section(f"card {CARD}"), slack_mod._decision_buttons("act-1")],
    )
    [body] = posted
    assert body["text"] == "key [hidden: GitHub token]"
    assert body["blocks"][0]["text"]["text"] == "card [hidden: card number]"
    assert [e["text"]["text"] for e in body["blocks"][1]["elements"]] == ["Approve", "Deny"]
    await channel._connector.close()


@pytest.mark.asyncio
async def test_slack_reply_is_masked_before_splitting_with_one_footer():
    channel, posted = _slack()
    text = "a" * 3880 + " " + TOKEN + " tail"
    await channel._send_reply("D0DM00001", text, {})
    joined = "".join(body["text"] for body in posted)
    assert len(posted) >= 2
    assert "FAKEFAKE" not in joined
    assert joined.count("It is not shown on Slack.") == 1
    assert "Crawler hid 1 value that looks like a key, card or ID number." in joined
    await channel._connector.close()


@pytest.mark.asyncio
async def test_slack_inbound_key_gets_the_warning_with_slack_wording():
    channel, posted = _slack()

    async def chat(user_id: str, text: str, new_conversation: bool = False) -> dict[str, Any]:
        return {"content": "ok"}

    channel.chat = chat
    await channel._run_chat("D0DM00001", f"my card is {CARD}", False, 0)
    first = posted[0]["text"]
    assert first.startswith("\U0001f512 Your message has what looks like a card number.")
    assert "Slack keeps a copy of this chat" in first
    assert "4111" not in "".join(body["text"] for body in posted)
    await channel._connector.close()
