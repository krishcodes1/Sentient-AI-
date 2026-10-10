"""Tests for Slack DM file intake: a ``file_share`` message is admitted (and
only that subtype), its files are accepted only from files.slack.com under
/files-pri/, and the file turn downloads them with the bot token through the
connector's policy-checked client before one chat call with ``files=``.

Why it exists: admitting a new message subtype widens what reaches the agent;
every other subtype must still be dropped, and the bot token may only ever go
to Slack's own file host.
"""

from __future__ import annotations

import json
import uuid

import httpx
import pytest

import core.network_security as netsec
from services.connectors import registry as _connector_registry  # noqa: F401 - registers the network policies
from services.connectors.slack import SlackConnector
from services.notifications import slack as slack_mod

TEAM = "T0TEAM001"
BOT = "U0BOT0001"
LINKED = "U0HUMAN01"
DM = "D0DM00001"
BOT_TOKEN = "xoxb-test-token-bot"
FILE_URL = "https://files.slack.com/files-pri/T0TEAM001-F1/download/notes.pdf"


def payload(event: dict) -> dict:
    return {
        "type": "event_callback",
        "team_id": TEAM,
        "event_id": f"Ev{uuid.uuid4().hex[:10]}",
        "event": {"type": "message", "channel": DM, "user": LINKED, "ts": "1.2", "channel_type": "im", **event},
    }


def shared(url: str = FILE_URL, name: str = "notes.pdf") -> dict:
    return {"id": "F1", "name": name, "mimetype": "application/pdf", "size": 10, "url_private_download": url}


class SlackWeb:
    def __init__(self, content: bytes) -> None:
        self.content = content
        self.requests: list[httpx.Request] = []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        if request.url.host == "files.slack.com":
            return httpx.Response(200, content=self.content)
        return httpx.Response(200, json={"ok": True, "channel": DM, "ts": "1.000100"})

    def posts(self) -> list[str]:
        return [json.loads(r.content)["text"] for r in self.requests if r.url.path.endswith("chat.postMessage")]


def channel(web: SlackWeb, chat) -> slack_mod.SlackChannel:
    connector = SlackConnector.from_credentials({"bot_token": BOT_TOKEN, "app_token": "xapp-test"})
    assert isinstance(connector, SlackConnector)
    connector.set_network_policy("slack")
    connector._http_client = httpx.AsyncClient(
        transport=httpx.MockTransport(web),
        event_hooks={"request": [connector._enforce_network_policy]},
    )
    ch = slack_mod.SlackChannel(
        connector_id=str(uuid.uuid4()),
        user_id=str(uuid.uuid4()),
        bot_token=BOT_TOKEN,
        app_token="xapp-test",
        session_factory=lambda: None,
        chat=chat,
        connector=connector,
    )
    ch.team_id, ch.bot_user_id = TEAM, BOT
    return ch


@pytest.fixture
def no_dns(monkeypatch):
    monkeypatch.setattr(netsec, "check_ssrf", lambda url: netsec.SSRFCheckResult(safe=True, resolved_ips=("3.3.3.3",)))


def test_file_share_is_admitted_and_other_subtypes_are_dropped():
    ch = channel(SlackWeb(b""), None)
    message = ch.authorize_message(payload({"subtype": "file_share", "text": "what is this?", "files": [shared()]}))
    assert message is not None and message.text == "what is this?"
    assert message.files == (slack_mod.SlackFile("F1", "notes.pdf", "application/pdf", 10, FILE_URL),)
    silent = ch.authorize_message(payload({"subtype": "file_share", "files": [shared()]}))
    assert silent is not None and silent.text == "" and len(silent.files) == 1
    for subtype in ("message_changed", "bot_message", "channel_join", "file_comment", "thread_broadcast"):
        assert ch.authorize_message(payload({"subtype": subtype, "text": "hi", "files": [shared()]})) is None
    assert ch.authorize_message(payload({"text": "plain"})).files == ()


@pytest.mark.parametrize(
    "url",
    [
        "https://evil.example.com/files-pri/x",
        "http://files.slack.com/files-pri/x",
        "https://files.slack.com/files-tmb/x",
        "https://files.slack.com.evil.com/files-pri/x",
    ],
)
def test_files_off_slack_are_never_accepted(url):
    ch = channel(SlackWeb(b""), None)
    assert ch.authorize_message(payload({"subtype": "file_share", "files": [shared(url)]})) is None
    kept = ch.authorize_message(payload({"subtype": "file_share", "text": "hi", "files": [shared(url)]}))
    assert kept is not None and kept.files == ()


@pytest.mark.asyncio
async def test_the_file_turn_downloads_with_the_bot_token_then_chats(no_dns):
    from services.files.intake import InboundFile

    calls = []

    async def chat(user_id, text, *, new_conversation=False, stop_mark=None, files=None):
        calls.append((text, files))
        return {"content": "It is your syllabus."}

    async def file_gate():
        return None

    chat.file_gate = file_gate  # type: ignore[attr-defined]
    web = SlackWeb(b"%PDF-1.4 bytes")
    ch = channel(web, chat)
    message = ch.authorize_message(payload({"subtype": "file_share", "text": "summarize", "files": [shared()]}))
    await ch._run_file_turn(message, False, 0)
    (text, files), = calls
    assert text == "summarize"
    assert files == [InboundFile("notes.pdf", "application/pdf", b"%PDF-1.4 bytes", "slack")]
    download = next(r for r in web.requests if r.url.host == "files.slack.com")
    assert download.url.path.startswith("/files-pri/")
    assert download.headers["Authorization"] == f"Bearer {BOT_TOKEN}"
    assert web.posts() == ["📄 Reading notes.pdf…", "It is your syllabus."]


@pytest.mark.asyncio
async def test_file_reading_off_replies_without_downloading(no_dns):
    async def chat(*args, **kwargs):
        raise AssertionError("no turn")

    async def file_gate():
        return "Reading files is turned off."

    chat.file_gate = file_gate  # type: ignore[attr-defined]
    web = SlackWeb(b"x")
    ch = channel(web, chat)
    message = ch.authorize_message(payload({"subtype": "file_share", "files": [shared()]}))
    await ch._run_file_turn(message, False, 0)
    assert all(r.url.host != "files.slack.com" for r in web.requests)
    assert web.posts() == ["⚠️ Reading files is turned off."]
