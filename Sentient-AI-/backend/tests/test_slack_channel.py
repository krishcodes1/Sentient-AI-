"""Tests for the Slack DM chat channel (services/notifications/slack.py): Socket
Mode acks, the authorization matrix, one-time code linking, chat turns and
keywords, approval cards and button decisions, reconnects, the WebSocket URL
policy, and that no socket URL or token ever reaches a log line.

Why it exists: the channel is the only way someone outside the web app can drive
a user's agent, so who may talk to it and what it sends must be pinned down. No
real network: the Web API is an httpx.MockTransport on the channel's own
SlackConnector, and the socket is a fake WebSocket fed frame by frame.
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
import uuid
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from typing import Any, Callable, Optional

import httpx
import pytest
import pytest_asyncio

import services.connectors.registry  # noqa: F401  (registers the "slack" network policy)
from core.network_security import SSRFCheckResult
from core.security import encrypt_credentials
from models.connector import AuthMethod, ConnectorConfig
from models.conversation import Conversation
from models.slack_link import SlackChannelLink
from services.agent.approvals import DbApprovalStore
from services.connectors.slack import SlackConnector
from services.notifications import cards
from services.notifications import slack as slack_mod
from tests.conftest import make_user

BOT_TOKEN = "xoxb-test-token-bot"
APP_TOKEN = "xapp-test-token-app"
TEAM = "T0TEAM001"
BOT_USER = "U0BOT0001"
LINKED = "U0LINKED1"
STRANGER = "U0STRANGE"
DM = "D0DM00001"
TICKET = "SECRET-TICKET-0123456789"
SOCKET_URL = f"wss://wss-primary.slack.com/link/?ticket={TICKET}&app_id=A0APP0001"
PINNED_IP = "203.0.113.7"


# ── fakes ────────────────────────────────────────────────────────────────


class FakeSocket:
    """A Socket Mode connection: frames pushed by the test, acks recorded."""

    def __init__(self) -> None:
        self.inbox: asyncio.Queue[Any] = asyncio.Queue()
        self.sent: list[dict[str, Any]] = []
        self.closed = False

    async def recv(self) -> Any:
        item = await self.inbox.get()
        if isinstance(item, BaseException):
            raise item
        return item

    async def send(self, message: str) -> None:
        self.sent.append(json.loads(message))

    async def close(self) -> None:
        self.closed = True

    def push(self, frame: Any) -> None:
        self.inbox.put_nowait(json.dumps(frame) if isinstance(frame, dict) else frame)

    def acked(self) -> list[str]:
        return [m.get("envelope_id") for m in self.sent]


class FakeDialer:
    """Stands in for pinned_ws_connect; every socket starts with Slack's hello."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, str, tuple[str, ...]]] = []
        self.sockets: list[FakeSocket] = []
        self.fail_next = 0

    async def __call__(self, url: str, host: str, ips: Any) -> FakeSocket:
        self.calls.append((url, host, tuple(ips)))
        if self.fail_next:
            self.fail_next -= 1
            raise ConnectionError("dial failed")
        sock = FakeSocket()
        sock.push({"type": "hello", "num_connections": 1})
        self.sockets.append(sock)
        return sock


class SlackAPI:
    """The Slack Web API as an httpx.MockTransport handler."""

    def __init__(self) -> None:
        self.requests: list[tuple[str, Optional[str], dict[str, Any]]] = []
        self.socket_url = SOCKET_URL
        self.post_ok = True

    def __call__(self, request: httpx.Request) -> httpx.Response:
        method = request.url.path.rsplit("/", 1)[-1]
        body = json.loads(request.content) if request.content else {}
        self.requests.append((method, request.headers.get("authorization"), body))
        if method == "auth.test":
            return httpx.Response(200, json={"ok": True, "team_id": TEAM, "user_id": BOT_USER})
        if method == "apps.connections.open":
            return httpx.Response(200, json={"ok": True, "url": self.socket_url})
        if method == "conversations.open":
            return httpx.Response(200, json={"ok": True, "channel": {"id": DM}})
        if method == "chat.postMessage":
            if not self.post_ok:
                return httpx.Response(200, json={"ok": False, "error": "ratelimited"})
            return httpx.Response(
                200, json={"ok": True, "channel": body.get("channel"), "ts": "1.000100"}
            )
        if method == "chat.update":
            return httpx.Response(200, json={"ok": True})
        return httpx.Response(200, json={"ok": False, "error": "unknown_method"})

    def calls(self, method: str) -> list[dict[str, Any]]:
        return [body for name, _, body in self.requests if name == method]

    def posts(self) -> list[dict[str, Any]]:
        return self.calls("chat.postMessage")


class RecordingLogger:
    """Replaces a module's structlog logger; keeps every call as text."""

    def __init__(self) -> None:
        self.lines: list[str] = []

    def __getattr__(self, level: str) -> Callable[..., None]:
        def record(event: str, **kwargs: Any) -> None:
            self.lines.append(f"{level} {event} {kwargs!r}")

        return record

    def text(self) -> str:
        return "\n".join(self.lines)


async def wait_for(predicate: Callable[[], bool], timeout: float = 5.0) -> None:
    deadline = asyncio.get_running_loop().time() + timeout
    while not predicate():
        if asyncio.get_running_loop().time() > deadline:
            raise AssertionError("condition not reached in time")
        await asyncio.sleep(0.005)


# ── database helpers ─────────────────────────────────────────────────────


async def make_slack_connector(
    session_factory: Any, user_id: uuid.UUID, *, app_token: Optional[str] = APP_TOKEN
) -> uuid.UUID:
    credentials = {"bot_token": BOT_TOKEN}
    if app_token:
        credentials["app_token"] = app_token
    async with session_factory() as session:
        row = ConnectorConfig(
            user_id=user_id,
            connector_type="slack",
            display_name="Slack",
            auth_method=AuthMethod.bearer_token,
            encrypted_credentials=encrypt_credentials(json.dumps(credentials)),
            granted_scopes=[],
        )
        session.add(row)
        await session.commit()
        return row.id


async def set_link(
    session_factory: Any,
    connector_id: uuid.UUID,
    user_id: uuid.UUID,
    *,
    team: Optional[str] = None,
    slack_user: Optional[str] = None,
    code: Optional[str] = None,
    expires_in: timedelta = timedelta(minutes=10),
) -> None:
    async with session_factory() as session:
        link = await session.get(SlackChannelLink, connector_id)
        if link is None:
            link = SlackChannelLink(connector_id=connector_id, user_id=user_id)
            session.add(link)
        link.team_id, link.slack_user_id = team, slack_user
        link.link_code_hash = slack_mod.hash_link_code(code) if code else None
        link.link_expires_at = datetime.now(timezone.utc) + expires_in if code else None
        await session.commit()


async def get_link(session_factory: Any, connector_id: uuid.UUID) -> Optional[SlackChannelLink]:
    async with session_factory() as session:
        return await session.get(SlackChannelLink, connector_id)


# ── envelopes ────────────────────────────────────────────────────────────


def dm_event(
    text: str,
    *,
    user: str = LINKED,
    team: str = TEAM,
    channel_type: str = "im",
    channel: str = DM,
    extra: Optional[dict[str, Any]] = None,
) -> dict[str, Any]:
    event = {
        "type": "message",
        "channel": channel,
        "user": user,
        "text": text,
        "ts": f"{uuid.uuid4().int % 10**9}.000200",
        "channel_type": channel_type,
        **(extra or {}),
    }
    return {
        "envelope_id": f"env-{uuid.uuid4()}",
        "type": "events_api",
        "accepts_response_payload": False,
        "payload": {
            "type": "event_callback",
            "team_id": team,
            "event_id": f"Ev{uuid.uuid4().hex[:10].upper()}",
            "event": event,
        },
    }


def press(
    action_id: str,
    *,
    approve: bool,
    user: str = LINKED,
    team: str = TEAM,
    blocks: Optional[list[dict[str, Any]]] = None,
) -> dict[str, Any]:
    return {
        "envelope_id": f"env-{uuid.uuid4()}",
        "type": "interactive",
        "payload": {
            "type": "block_actions",
            "user": {"id": user, "team_id": team},
            "team": {"id": team},
            "channel": {"id": DM},
            "container": {"message_ts": "1.000100"},
            "message": {
                "ts": "1.000100",
                "blocks": blocks
                or [
                    {"type": "section", "text": {"type": "plain_text", "text": "card"}},
                    slack_mod._decision_buttons(action_id),
                ],
            },
            "actions": [
                {
                    "action_id": slack_mod.ACTION_APPROVE if approve else slack_mod.ACTION_DENY,
                    "value": action_id,
                    "type": "button",
                }
            ],
        },
    }


# ── harness ──────────────────────────────────────────────────────────────


class Harness:
    def __init__(self, session_factory: Any, user_id: uuid.UUID, connector_id: uuid.UUID) -> None:
        self.session_factory = session_factory
        self.user_id = user_id
        self.connector_id = connector_id
        self.api = SlackAPI()
        self.dialer = FakeDialer()
        self.sleeps: list[float] = []
        self.park_on_sleep = False
        self.chat_calls: list[dict[str, Any]] = []
        self.chat_reply: dict[str, Any] = {"content": "Done."}
        self.chat_gate: Optional[asyncio.Event] = None
        connector = SlackConnector.from_credentials(
            {"bot_token": BOT_TOKEN, "app_token": APP_TOKEN}
        )
        assert isinstance(connector, SlackConnector)
        connector.set_network_policy("slack")
        connector._http_client = httpx.AsyncClient(transport=httpx.MockTransport(self.api))
        self.channel = slack_mod.SlackChannel(
            connector_id=str(connector_id),
            user_id=str(user_id),
            bot_token=BOT_TOKEN,
            app_token=APP_TOKEN,
            session_factory=session_factory,
            chat=self.chat,
            connector=connector,
            ws_connect=self.dialer,
        )
        self.channel._sleep = self.sleep
        self.channel._random = lambda: 1.0

    async def sleep(self, delay: float) -> None:
        self.sleeps.append(delay)
        if self.park_on_sleep:
            await asyncio.Event().wait()
        await asyncio.sleep(0)

    async def chat(
        self,
        user_id: str,
        text: str,
        *,
        new_conversation: bool = False,
        stop_mark: Optional[int] = None,
        on_event: Any = None,
    ) -> dict[str, Any]:
        self.chat_calls.append(
            {"user_id": user_id, "text": text, "new": new_conversation, "stop_mark": stop_mark}
        )
        if self.chat_gate is not None:
            await self.chat_gate.wait()
        return dict(self.chat_reply)

    async def start(self) -> None:
        await self.channel.start()
        await wait_for(lambda: self.channel.connected)

    @property
    def socket(self) -> FakeSocket:
        return self.dialer.sockets[-1]

    async def deliver(self, *frames: dict[str, Any]) -> None:
        """Push frames, then a marker; once the marker is acked every frame
        before it was handled inline, then wait for the work they spawned."""
        sock = self.socket
        for frame in frames:
            sock.push(frame)
        marker = f"sync-{uuid.uuid4()}"
        sock.push({"envelope_id": marker, "type": "sync_marker"})
        await wait_for(lambda: marker in sock.acked())
        await self.channel.wait_idle()


@pytest.fixture(autouse=True)
def fast_cards(monkeypatch):
    monkeypatch.setattr(cards, "PART_INTERVAL_S", 0)
    monkeypatch.setattr(cards, "FAILED_PART_NOTICE_DELAY_S", 0)


@pytest.fixture
def policy_calls(monkeypatch):
    """check_websocket_policy stubbed as a safe answer (no DNS); records the
    URL it was given."""
    seen: list[str] = []

    def fake_policy(url: str, policy_key: str) -> SSRFCheckResult:
        seen.append(url)
        assert policy_key == "slack"
        return SSRFCheckResult(safe=True, resolved_ip=PINNED_IP, resolved_ips=(PINNED_IP,))

    monkeypatch.setattr(slack_mod, "check_websocket_policy", fake_policy)
    return seen


@pytest.fixture
def slack_log(monkeypatch):
    recorder = RecordingLogger()
    monkeypatch.setattr(slack_mod, "logger", recorder)
    return recorder


@pytest_asyncio.fixture
async def harness(session_factory, policy_calls, slack_log):
    user, _ = await make_user(session_factory, f"slack-{uuid.uuid4().hex[:8]}@example.com")
    connector_id = await make_slack_connector(session_factory, user.id)
    h = Harness(session_factory, user.id, connector_id)
    try:
        yield h
    finally:
        await h.channel.stop()


@pytest_asyncio.fixture
async def linked(harness):
    await set_link(
        harness.session_factory, harness.connector_id, harness.user_id, team=TEAM, slack_user=LINKED
    )
    await harness.start()
    return harness


# ── socket basics ────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_connects_through_the_pinned_address_with_the_app_token(harness, policy_calls):
    await harness.start()
    methods = [name for name, _, _ in harness.api.requests]
    assert methods[:2] == ["auth.test", "apps.connections.open"]
    auths = {name: auth for name, auth, _ in harness.api.requests}
    assert auths["auth.test"] == f"Bearer {BOT_TOKEN}"
    assert auths["apps.connections.open"] == f"Bearer {APP_TOKEN}"
    assert harness.dialer.calls == [(SOCKET_URL, "wss-primary.slack.com", (PINNED_IP,))]
    # The policy check never sees the ticket.
    assert policy_calls == ["wss://wss-primary.slack.com/link/"]
    assert harness.channel.team_id == TEAM and harness.channel.bot_user_id == BOT_USER


@pytest.mark.asyncio
async def test_every_envelope_is_acked_even_when_refused(linked):
    frames = [
        dm_event("hello", channel_type="channel"),
        dm_event("hello", team="T0OTHER01"),
        {"envelope_id": "env-unknown", "type": "slash_commands", "payload": {}},
        press(str(uuid.uuid4()), approve=True, user=STRANGER),
    ]
    await linked.deliver(*frames)
    acked = linked.socket.acked()
    for frame in frames:
        assert frame["envelope_id"] in acked
    assert linked.chat_calls == []


@pytest.mark.asyncio
async def test_ack_goes_out_before_the_envelope_is_handled(linked, monkeypatch):
    order: list[str] = []
    original = linked.channel._on_events_api

    async def spy(payload: Any) -> None:
        order.append("handled" if order == ["acked"] else "handled-before-ack")
        await original(payload)

    real_send = linked.socket.send

    async def send(message: str) -> None:
        if not order:
            order.append("acked")
        await real_send(message)

    monkeypatch.setattr(linked.channel, "_on_events_api", spy)
    monkeypatch.setattr(linked.socket, "send", send)
    await linked.deliver(dm_event("hi"))
    assert order[:2] == ["acked", "handled"]


@pytest.mark.asyncio
async def test_reconnects_after_a_disconnect_request(linked):
    first = linked.socket
    first.push({"type": "disconnect", "reason": "refresh_requested"})
    await wait_for(lambda: len(linked.dialer.sockets) == 2 and linked.channel.connected)
    assert first.closed
    assert [name for name, _, _ in linked.api.requests].count("apps.connections.open") == 2
    # auth.test runs once per channel, not per connection.
    assert [name for name, _, _ in linked.api.requests].count("auth.test") == 1
    await linked.deliver(dm_event("after reconnect"))
    assert [c["text"] for c in linked.chat_calls] == ["after reconnect"]


@pytest.mark.asyncio
async def test_reconnects_after_the_socket_drops(linked):
    linked.socket.push(ConnectionError("socket dropped"))
    await wait_for(lambda: len(linked.dialer.sockets) == 2 and linked.channel.connected)


@pytest.mark.asyncio
async def test_failed_dials_back_off_exponentially(harness):
    harness.dialer.fail_next = 3
    await harness.start()
    assert harness.sleeps[:3] == [1.0, 2.0, 4.0]
    assert harness.channel.connected


class SteppingClock:
    """time.monotonic stand-in: each reading moves *step* seconds on, from
    the real clock (so a session opened before the swap measures sensibly)."""

    def __init__(self, step: float) -> None:
        self.now = time.monotonic()
        self.step = step

    def __call__(self) -> float:
        self.now += self.step
        return self.now


@pytest.mark.asyncio
async def test_a_socket_dropped_right_after_hello_backs_off(linked):
    """Slack greeting a socket and dropping it at once (too many
    connections, a refresh storm) must not become back to back
    apps.connections.open calls: short sessions count as failures."""
    linked.channel._clock = SteppingClock(step=1.0)
    linked.sleeps.clear()
    for expected in (1.0, 2.0, 4.0):
        count = len(linked.dialer.sockets)
        linked.socket.push({"type": "disconnect", "reason": "too_many_websockets"})
        await wait_for(
            lambda n=count: len(linked.dialer.sockets) == n + 1 and linked.channel.connected
        )
        assert linked.sleeps[-1] == expected


@pytest.mark.asyncio
async def test_a_long_session_reconnects_at_once_and_resets_the_backoff(linked):
    linked.channel._clock = SteppingClock(step=slack_mod.MIN_HEALTHY_SESSION_S)
    linked.sleeps.clear()
    linked.socket.push({"type": "disconnect", "reason": "refresh_requested"})
    await wait_for(lambda: len(linked.dialer.sockets) == 2 and linked.channel.connected)
    assert linked.sleeps == []
    assert linked.channel.last_error is None


def test_backoff_is_capped_and_jittered(harness):
    harness.channel._random = lambda: 0.0
    assert harness.channel._backoff(1) == 0.5
    harness.channel._random = lambda: 1.0
    assert harness.channel._backoff(30) == slack_mod.BACKOFF_MAX_S


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "url",
    [
        f"ws://wss-primary.slack.com/link/?ticket={TICKET}",
        f"wss://evil.example.com/link/?ticket={TICKET}",
        f"wss://wss-primary.slack.com:8443/link/?ticket={TICKET}",
    ],
)
async def test_socket_url_outside_the_policy_is_refused(
    session_factory, slack_log, monkeypatch, url
):
    """The real WebSocket policy (no stub): refused before any dial, and the
    refusal is logged without the ticket."""
    user, _ = await make_user(session_factory, f"slack-url-{uuid.uuid4().hex[:6]}@example.com")
    connector_id = await make_slack_connector(session_factory, user.id)
    h = Harness(session_factory, user.id, connector_id)
    h.api.socket_url = url
    h.park_on_sleep = True
    try:
        await h.channel.start()
        await wait_for(lambda: bool(h.sleeps))
        assert h.dialer.calls == []
        assert "slack_socket_refused" in slack_log.text()
        assert TICKET not in slack_log.text()
        # Surfaced to the connector card through GET /slack/link.
        assert h.channel.last_error == slack_mod.ERROR_SOCKET_REFUSED
    finally:
        await h.channel.stop()


@pytest.mark.asyncio
async def test_no_socket_url_or_token_is_ever_logged(linked, slack_log, caplog):
    caplog.set_level(logging.DEBUG)
    linked.socket.push({"type": "disconnect", "reason": "link_disabled"})
    await wait_for(lambda: len(linked.dialer.sockets) == 2 and linked.channel.connected)
    linked.api.post_ok = False
    await linked.deliver(dm_event("hi"), dm_event("x", user=STRANGER))
    everything = slack_log.text() + "\n".join(r.getMessage() for r in caplog.records)
    for secret in (TICKET, SOCKET_URL, BOT_TOKEN, APP_TOKEN):
        assert secret not in everything
    assert "slack_socket_disconnect_requested" in slack_log.text()


@pytest.mark.asyncio
async def test_invalid_token_is_retried_with_backoff_and_logged_by_code(harness, slack_log):
    def reject(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"ok": False, "error": "invalid_auth"})

    harness.channel._connector._http_client = httpx.AsyncClient(
        transport=httpx.MockTransport(reject)
    )
    harness.park_on_sleep = True
    await harness.channel.start()
    await wait_for(lambda: bool(harness.sleeps))
    assert harness.dialer.calls == []
    assert "invalid_auth" in slack_log.text()
    assert BOT_TOKEN not in slack_log.text()
    assert harness.channel.last_error == slack_mod.ERROR_AUTH_FAILED


@pytest.mark.asyncio
async def test_a_failed_dial_is_reported_until_slack_says_hello(harness):
    harness.dialer.fail_next = 1
    errors: list[Optional[str]] = []
    real_sleep = harness.sleep

    async def sleep(delay: float) -> None:
        errors.append(harness.channel.last_error)
        await real_sleep(delay)

    harness.channel._sleep = sleep
    await harness.start()
    assert errors[0] == slack_mod.ERROR_CONNECT_FAILED
    assert harness.channel.last_error is None


@pytest.mark.asyncio
@pytest.mark.parametrize("code", ["token_revoked", "invalid_auth", "account_inactive"])
async def test_a_dead_token_stops_retrying_after_a_few_attempts(harness, slack_log, code):
    """A revoked token never heals by itself: after MAX_AUTH_FAILURES
    rejected attempts the loop ends instead of calling Slack and logging a
    warning every minute, and the card keeps saying auth_failed."""
    methods: list[str] = []

    def reject(request: httpx.Request) -> httpx.Response:
        methods.append(request.url.path.rsplit("/", 1)[-1])
        return httpx.Response(200, json={"ok": False, "error": code})

    harness.channel._connector._http_client = httpx.AsyncClient(
        transport=httpx.MockTransport(reject)
    )
    await harness.channel.start()
    await wait_for(lambda: not harness.channel.running)
    assert methods == ["auth.test"] * slack_mod.MAX_AUTH_FAILURES
    # Backed off between attempts, not after the last one.
    assert harness.sleeps == [1.0, 2.0, 4.0, 8.0]
    assert harness.dialer.calls == []
    assert harness.channel.last_error == slack_mod.ERROR_AUTH_FAILED
    assert not harness.channel.connected
    assert slack_log.text().count("slack_channel_auth_given_up") == 1
    assert BOT_TOKEN not in slack_log.text()


@pytest.mark.asyncio
async def test_auth_failures_below_the_cap_recover_and_the_count_resets(linked):
    """A transient rejection still recovers, and the count restarts once
    both tokens work, so rejections spread over a long life never add up
    to giving up."""
    rejections = {"left": 0}

    def flaky(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/apps.connections.open") and rejections["left"]:
            rejections["left"] -= 1
            return httpx.Response(200, json={"ok": False, "error": "invalid_auth"})
        return linked.api(request)

    linked.channel._connector._http_client = httpx.AsyncClient(transport=httpx.MockTransport(flaky))
    for round_number in (2, 3):
        rejections["left"] = slack_mod.MAX_AUTH_FAILURES - 1
        linked.socket.push({"type": "disconnect", "reason": "refresh_requested"})
        await wait_for(
            lambda n=round_number: len(linked.dialer.sockets) == n and linked.channel.connected
        )
        assert rejections["left"] == 0
    assert linked.channel.running
    assert linked.channel.last_error is None


@pytest.mark.asyncio
async def test_malformed_frames_are_skipped_without_ending_the_session(linked):
    """Frames an outside party controls: text that is not JSON, JSON that is
    not an object, bytes that are not UTF-8, and non-text items are dropped
    one by one. The session stays up and the next envelope is handled."""
    for raw in ("not json", "[1, 2]", "null", '"text"', "", b"\xff\xfe", bytearray(b"{"), 42):
        linked.socket.push(raw)
    frame = dm_event("still here")
    await linked.deliver(frame)
    assert frame["envelope_id"] in linked.socket.acked()
    assert len(linked.dialer.calls) == 1
    assert linked.channel.connected
    assert [c["text"] for c in linked.chat_calls] == ["still here"]


@pytest.mark.parametrize(
    "raw, expected",
    [
        ('{"type": "hello"}', {"type": "hello"}),
        (b'{"type": "hello"}', {"type": "hello"}),
        (bytearray(b'{"type": "hello"}'), {"type": "hello"}),
        ("not json", None),
        ("", None),
        ("[1, 2]", None),
        ("null", None),
        ("42", None),
        (b"\xff\xfe", None),
        (None, None),
        (42, None),
    ],
)
def test_parse_frame_returns_only_json_objects(raw, expected):
    assert slack_mod._parse_frame(raw) == expected


# ── authorization matrix ─────────────────────────────────────────────────


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "frame",
    [
        dm_event("hi", channel_type="channel", channel="C0CHAN001"),
        dm_event("hi", channel_type="mpim"),
        dm_event("hi", extra={"bot_id": "B0BOT0001"}),
        dm_event("hi", extra={"subtype": "message_changed"}),
        dm_event("hi", extra={"subtype": "bot_message"}),
        dm_event("hi", team="T0OTHER01"),
        dm_event("hi", extra={"user_team": "T0OTHER01"}),
        dm_event("hi", user=BOT_USER),
        dm_event("hi", user=STRANGER),
        dm_event("   "),
    ],
    ids=[
        "public-channel",
        "group-dm",
        "bot-message",
        "edit",
        "bot-subtype",
        "other-team",
        "slack-connect-partner",
        "own-bot",
        "unlinked-sender",
        "blank",
    ],
)
async def test_refused_messages_reach_nothing_and_get_no_reply(linked, frame):
    await linked.deliver(frame)
    assert linked.chat_calls == []
    assert linked.api.posts() == []


@pytest.mark.asyncio
async def test_a_redelivered_event_runs_once(linked):
    frame = dm_event("only once")
    again = json.loads(json.dumps(frame))
    again["envelope_id"] = "env-retry"
    await linked.deliver(frame, again)
    assert [c["text"] for c in linked.chat_calls] == ["only once"]


# ── linking ──────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_the_pending_code_links_the_sender_once(harness):
    code = slack_mod.new_link_code()
    await set_link(harness.session_factory, harness.connector_id, harness.user_id, code=code)
    await harness.start()

    await harness.deliver(dm_event(code, user=STRANGER))
    link = await get_link(harness.session_factory, harness.connector_id)
    assert link is not None and link.slack_user_id == STRANGER and link.team_id == TEAM
    assert link.link_code_hash is None and link.link_expires_at is None and link.linked_at
    posts = harness.api.posts()
    assert len(posts) == 1 and "Linked" in posts[0]["text"]
    assert posts[0]["unfurl_links"] is False and posts[0]["unfurl_media"] is False
    assert harness.chat_calls == []

    # The code died when it linked: someone else sending it gets nothing.
    await harness.deliver(dm_event(code, user=LINKED))
    link = await get_link(harness.session_factory, harness.connector_id)
    assert link is not None and link.slack_user_id == STRANGER
    assert len(harness.api.posts()) == 1


@pytest.mark.asyncio
@pytest.mark.parametrize("case", ["wrong", "expired"])
async def test_a_wrong_or_expired_code_links_nobody_and_gets_no_reply(harness, case):
    code = slack_mod.new_link_code()
    expires = timedelta(minutes=-1) if case == "expired" else timedelta(minutes=10)
    await set_link(
        harness.session_factory,
        harness.connector_id,
        harness.user_id,
        code=code,
        expires_in=expires,
    )
    await harness.start()
    text = code if case == "expired" else slack_mod.new_link_code()
    await harness.deliver(dm_event(text, user=STRANGER))
    link = await get_link(harness.session_factory, harness.connector_id)
    assert link is not None and link.slack_user_id is None
    assert harness.api.posts() == [] and harness.chat_calls == []


@pytest.mark.asyncio
async def test_no_link_row_means_every_message_is_ignored(harness):
    await harness.start()
    await harness.deliver(dm_event("anything", user=STRANGER))
    assert harness.api.posts() == [] and harness.chat_calls == []


@pytest.mark.asyncio
async def test_linking_moves_the_slack_user_off_any_other_connector(harness):
    other_user, _ = await make_user(
        harness.session_factory, f"slack-other-{uuid.uuid4().hex[:6]}@example.com"
    )
    other_connector = await make_slack_connector(harness.session_factory, other_user.id)
    await set_link(
        harness.session_factory, other_connector, other_user.id, team=TEAM, slack_user=STRANGER
    )
    code = slack_mod.new_link_code()
    await set_link(harness.session_factory, harness.connector_id, harness.user_id, code=code)
    await harness.start()

    await harness.deliver(dm_event(code, user=STRANGER))

    mine = await get_link(harness.session_factory, harness.connector_id)
    theirs = await get_link(harness.session_factory, other_connector)
    assert mine is not None and mine.slack_user_id == STRANGER
    assert theirs is not None and theirs.slack_user_id is None and theirs.team_id is None


@pytest.mark.asyncio
async def test_the_database_refuses_one_slack_user_on_two_connectors(harness):
    from sqlalchemy.exc import IntegrityError

    other_user, _ = await make_user(
        harness.session_factory, f"slack-dup-{uuid.uuid4().hex[:6]}@example.com"
    )
    other_connector = await make_slack_connector(harness.session_factory, other_user.id)
    await set_link(
        harness.session_factory, harness.connector_id, harness.user_id, team=TEAM, slack_user=LINKED
    )
    with pytest.raises(IntegrityError):
        await set_link(
            harness.session_factory, other_connector, other_user.id, team=TEAM, slack_user=LINKED
        )


def test_link_codes_are_hashed_with_a_keyed_domain_separated_hmac():
    code = slack_mod.new_link_code()
    digest = slack_mod.hash_link_code(code)
    assert len(code) >= 24 and code not in digest and len(digest) == 64
    from services.connectors.oauth import hash_state

    assert digest != hash_state(code)


# ── chat ─────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_a_linked_message_runs_a_turn_and_the_reply_is_escaped_with_unfurl_off(linked):
    linked.chat_reply = {
        "content": "See <https://evil.test|this> & more",
        "usage": {"input_tokens": 10, "output_tokens": 5},
        "provider": "anthropic",
        "model": "claude-sonnet-4-6",
    }
    await linked.deliver(dm_event("what is up &amp; &lt;b&gt;"))
    assert len(linked.chat_calls) == 1
    call = linked.chat_calls[0]
    assert call["user_id"] == str(linked.user_id)
    assert call["text"] == "what is up & <b>"
    assert call["new"] is False and isinstance(call["stop_mark"], int)
    posts = linked.api.posts()
    assert len(posts) == 1
    assert posts[0]["channel"] == DM
    assert "&lt;https://evil.test|this&gt; &amp; more" in posts[0]["text"]
    assert posts[0]["unfurl_links"] is False and posts[0]["unfurl_media"] is False


@pytest.mark.asyncio
async def test_long_replies_are_split_and_paced(linked):
    linked.chat_reply = {"content": ("line of reply text\n" * 600).strip()}
    await linked.deliver(dm_event("long please"))
    posts = linked.api.posts()
    assert len(posts) >= 3
    assert all(len(p["text"]) <= slack_mod.TEXT_CHUNK for p in posts)
    assert linked.sleeps.count(slack_mod.POST_INTERVAL_S) == len(posts) - 1


@pytest.mark.asyncio
async def test_a_chat_error_is_reported_in_the_dm(linked):
    linked.chat_reply = {"error": "Rate limit exceeded"}
    await linked.deliver(dm_event("hi"))
    assert linked.api.posts()[0]["text"].endswith("Rate limit exceeded")


@pytest.mark.asyncio
async def test_new_starts_a_fresh_conversation_for_the_next_message(linked):
    await linked.deliver(dm_event("New"))
    assert linked.chat_calls == []
    assert "Fresh start" in linked.api.posts()[-1]["text"]
    await linked.deliver(dm_event("first"), dm_event("second"))
    assert [c["new"] for c in linked.chat_calls] == [True, False]


@pytest.mark.asyncio
async def test_stop_cancels_the_running_turn(linked, monkeypatch):
    stops: list[str] = []
    from services.agent import cancel as agent_cancel

    real = agent_cancel.request_cancel

    def recording(user_id: str) -> None:
        stops.append(user_id)
        real(user_id)

    monkeypatch.setattr(agent_cancel, "request_cancel", recording)
    linked.chat_gate = asyncio.Event()
    linked.socket.push(dm_event("slow task"))
    await wait_for(lambda: len(linked.chat_calls) == 1)
    await linked.deliver(dm_event("stop"))
    assert stops == [str(linked.user_id)]
    texts = [p["text"] for p in linked.api.posts()]
    assert any("Stopped" in t for t in texts)
    assert not any("Done." in t for t in texts)


@pytest.mark.asyncio
async def test_stop_with_nothing_running_says_so(linked):
    await linked.deliver(dm_event("stop"))
    assert linked.api.posts()[-1]["text"].startswith("Nothing is running")


@pytest.mark.asyncio
async def test_stop_names_the_cards_still_waiting(linked):
    await park_action(linked.session_factory, linked.user_id, {"n": 1})
    await linked.deliver(dm_event("stop"))
    text = linked.api.posts()[-1]["text"]
    assert text.startswith("Nothing is running")
    assert "1 action is still waiting for your approval (send pending)." in text


def test_reply_notes_use_the_dm_wording():
    reply = slack_mod._with_turn_notes(
        "Done.",
        {"pending_approvals": ["gmail.send"], "blocked": ["web.fetch"], "images": ["a", "b"]},
    )
    assert reply.startswith("Done.\n\n")
    assert (
        "Waiting on your approval for: gmail.send. The request is in this DM, or send pending."
        in reply
    )
    assert "Blocked by security policy: web.fetch" in reply
    assert "(2 screenshots not shown: Slack DMs carry text only.)" in reply
    assert slack_mod._with_turn_notes("Done.", {}) == "Done."
    assert cards.waiting_cards_note(0, pending_hint="send pending") == ""
    assert "3 actions are still waiting for your approval (send pending). Approving one" in (
        cards.waiting_cards_note(3, pending_hint="send pending")
    )


@pytest.mark.asyncio
async def test_build_chat_applier_writes_slack_turns_into_the_slack_conversation(linked):
    """The applier main.py wires in (channel="slack") keeps its own thread."""
    from api.routes.agent import SLACK_CONVERSATION_TITLE, build_chat_applier
    from services.agent.runtime import AgentResponse

    class FakeRuntime:
        async def chat(self, **kwargs: Any) -> AgentResponse:
            return AgentResponse(content="Hello from Crawler https://example.test/a?b=1")

    app = SimpleNamespace(
        state=SimpleNamespace(agent_runtime=FakeRuntime(), mcp_catalog=None, installation=None)
    )
    linked.channel.chat = build_chat_applier(app, linked.session_factory, channel="slack")
    await linked.deliver(dm_event("hello"))
    assert "Hello from Crawler" in linked.api.posts()[-1]["text"]
    from sqlalchemy import select

    async with linked.session_factory() as session:
        titles = (
            (
                await session.execute(
                    select(Conversation.title).where(Conversation.user_id == linked.user_id)
                )
            )
            .scalars()
            .all()
        )
    assert titles == [SLACK_CONVERSATION_TITLE]


def test_build_chat_applier_rejects_an_unknown_channel():
    from api.routes.agent import TELEGRAM_CONVERSATION_TITLE, build_chat_applier

    assert TELEGRAM_CONVERSATION_TITLE == "Telegram"
    with pytest.raises(ValueError):
        build_chat_applier(SimpleNamespace(state=SimpleNamespace()), channel="fax")


# ── approvals ────────────────────────────────────────────────────────────


async def park_action(session_factory: Any, user_id: uuid.UUID, arguments: dict[str, Any]) -> Any:
    return await DbApprovalStore(session_factory=session_factory).create(
        user_id=str(user_id),
        tool_name="slack.post_message",
        arguments=arguments,
        reason="Posting to a channel needs your approval.",
    )


@pytest.mark.asyncio
async def test_approval_card_shows_every_argument_and_carries_the_buttons(linked):
    arguments = {"channel": "C0CHAN001", "text": "<!channel> hi :x:"}
    action = await park_action(linked.session_factory, linked.user_id, arguments)
    assert await linked.channel.notify_pending(action) is True
    posts = linked.api.posts()
    assert len(posts) == 1
    blocks = posts[0]["blocks"]
    section, buttons = blocks
    assert section["text"]["type"] == "plain_text"
    # Shown verbatim: Slack must not turn ":x:" into an emoji on the card.
    assert section["text"]["emoji"] is False
    body = section["text"]["text"]
    assert "Tool: slack.post_message" in body
    assert '"text": "<!channel> hi :x:"' in body
    assert cards.digest_line(arguments) in body
    assert "Expires in" in body
    assert [e["value"] for e in buttons["elements"]] == [action.action_id, action.action_id]
    assert {e["action_id"] for e in buttons["elements"]} == {
        slack_mod.ACTION_APPROVE,
        slack_mod.ACTION_DENY,
    }
    assert posts[0]["unfurl_links"] is False


@pytest.mark.asyncio
async def test_a_long_card_goes_out_in_labelled_parts_before_the_buttons(linked):
    action = await park_action(
        linked.session_factory, linked.user_id, {"channel": "C0CHAN001", "text": "x" * 7000}
    )
    assert await linked.channel.notify_pending(action) is True
    posts = linked.api.posts()
    assert len(posts) >= 3
    for part in posts[:-1]:
        assert len(part["blocks"]) == 1
        assert len(part["blocks"][0]["text"]["text"]) <= slack_mod.SECTION_CHARS
    assert posts[-1]["blocks"][-1]["type"] == "actions"
    joined = "".join(p["blocks"][0]["text"]["text"] for p in posts[:-1])
    assert joined.count("x") >= 7000


@pytest.mark.asyncio
async def test_a_lost_card_part_withholds_the_buttons(linked):
    linked.api.post_ok = False
    action = await park_action(linked.session_factory, linked.user_id, {"text": "y" * 7000})
    assert await linked.channel.notify_pending(action) is False
    assert not any(p.get("blocks", [{}])[-1].get("type") == "actions" for p in linked.api.posts())


@pytest.mark.asyncio
async def test_no_card_for_another_user_or_while_unlinked(harness):
    await harness.start()
    action = await park_action(harness.session_factory, harness.user_id, {"a": 1})
    assert await harness.channel.notify_pending(action) is False  # nobody linked
    foreign = SimpleNamespace(**{**action.__dict__, "user_id": str(uuid.uuid4())})
    assert await harness.channel.notify_pending(foreign) is False
    assert harness.api.posts() == []


@pytest.mark.asyncio
async def test_card_opens_the_dm_when_the_user_has_not_written_yet(linked):
    action = await park_action(linked.session_factory, linked.user_id, {"a": 1})
    await linked.channel.notify_pending(action)
    assert linked.api.calls("conversations.open") == [{"users": LINKED}]


@pytest.mark.asyncio
async def test_pending_resends_every_waiting_card(linked):
    await park_action(linked.session_factory, linked.user_id, {"n": 1})
    await park_action(linked.session_factory, linked.user_id, {"n": 2})
    await linked.deliver(dm_event("pending"))
    buttons = [
        p for p in linked.api.posts() if p.get("blocks") and p["blocks"][-1]["type"] == "actions"
    ]
    assert len(buttons) == 2


@pytest.mark.asyncio
async def test_pending_with_nothing_waiting_says_so(linked):
    await linked.deliver(dm_event("pending"))
    assert linked.api.posts()[-1]["text"].startswith("Nothing is waiting")


class DecisionRuntime:
    """Just enough runtime for build_decision_applier: decisions go to the
    real database store."""

    def __init__(self, session_factory: Any) -> None:
        self.store = DbApprovalStore(session_factory=session_factory)
        self.decisions: list[tuple[str, str, bool]] = []

    async def deny_action(self, action_id: str, user_id: str) -> dict[str, Any]:
        return await self._decide(action_id, user_id, False)

    async def approve_action(
        self, action_id: str, user_id: str, task_id: Any = None
    ) -> dict[str, Any]:
        return await self._decide(action_id, user_id, True)

    async def _decide(self, action_id: str, user_id: str, approved: bool) -> dict[str, Any]:
        self.decisions.append((action_id, user_id, approved))
        outcome, action = await self.store.decide(action_id, user_id, approved)
        if outcome != "ok" or action is None:
            return {"error": f"Action {outcome}."}
        return {
            "status": "approved" if approved else "denied",
            "tool": action.tool_name,
            "result": {"ok": True},
        }


def wire_decisions(harness: Harness) -> DecisionRuntime:
    from api.routes.agent import build_decision_applier

    runtime = DecisionRuntime(harness.session_factory)
    app = SimpleNamespace(
        state=SimpleNamespace(agent_runtime=runtime, mcp_catalog=None, installation=None)
    )
    harness.channel.decide = build_decision_applier(app, harness.session_factory)
    return runtime


@pytest.mark.asyncio
async def test_a_press_by_another_slack_user_decides_nothing(linked):
    runtime = wire_decisions(linked)
    action = await park_action(linked.session_factory, linked.user_id, {"a": 1})
    await linked.deliver(press(action.action_id, approve=True, user=STRANGER))
    await linked.deliver(press(action.action_id, approve=True, team="T0OTHER01"))
    assert runtime.decisions == []
    assert linked.api.calls("chat.update") == [] and linked.api.posts() == []
    assert (
        len(
            await DbApprovalStore(session_factory=linked.session_factory).list_pending(
                str(linked.user_id)
            )
        )
        == 1
    )


@pytest.mark.asyncio
async def test_the_linked_user_denies_through_the_decision_applier_and_the_card_freezes(linked):
    runtime = wire_decisions(linked)
    action = await park_action(linked.session_factory, linked.user_id, {"a": 1})
    await linked.deliver(press(action.action_id, approve=False))
    assert runtime.decisions == [(action.action_id, str(linked.user_id), False)]
    assert (
        await DbApprovalStore(session_factory=linked.session_factory).list_pending(
            str(linked.user_id)
        )
        == []
    )
    (update,) = linked.api.calls("chat.update")
    assert update["channel"] == DM and update["ts"] == "1.000100"
    assert [b["type"] for b in update["blocks"]] == ["section", "context"]
    assert "Denied" in update["blocks"][-1]["elements"][0]["text"]


@pytest.mark.asyncio
async def test_approving_sends_the_resumed_reply(linked):
    wire_decisions(linked)
    action = await park_action(linked.session_factory, linked.user_id, {"a": 1})
    await linked.deliver(press(action.action_id, approve=True))
    (update,) = linked.api.calls("chat.update")
    assert "Approved" in update["blocks"][-1]["elements"][0]["text"]
    assert "slack.post_message" in linked.api.posts()[-1]["text"]


@pytest.mark.asyncio
async def test_a_second_press_reports_the_error_and_does_not_refreeze(linked):
    wire_decisions(linked)
    action = await park_action(linked.session_factory, linked.user_id, {"a": 1})
    await linked.deliver(press(action.action_id, approve=False))
    await linked.deliver(press(action.action_id, approve=True))
    assert len(linked.api.calls("chat.update")) == 1
    assert linked.api.posts()[-1]["text"].startswith("⚠️")


@pytest.mark.asyncio
async def test_a_malformed_press_is_ignored(linked):
    runtime = wire_decisions(linked)
    bad = press("not-a-uuid", approve=True)
    await linked.deliver(bad)
    assert runtime.decisions == []


# ── reminders ────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_send_text_reaches_only_the_owner_linked_dm(linked):
    assert await linked.channel.send_text(str(linked.user_id), "Reminder: <call mom>") is True
    assert linked.api.posts()[-1]["text"] == "Reminder: &lt;call mom&gt;"
    assert await linked.channel.send_text(str(uuid.uuid4()), "nope") is False


@pytest.mark.asyncio
async def test_send_text_is_false_when_nobody_is_linked(harness):
    await harness.start()
    assert await harness.channel.send_text(str(harness.user_id), "hi") is False


# ── the pinned dialer ────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_pinned_dialer_uses_the_validated_address_and_real_host_for_tls(monkeypatch):
    import websockets.asyncio.client as ws_client

    dialled: list[str] = []
    opened: list[dict[str, Any]] = []

    class FakeSock:
        def __init__(self, ip: str) -> None:
            self.ip = ip
            self.closed = False

        def close(self) -> None:
            self.closed = True

    socks: list[FakeSock] = []

    async def fake_dial(ip: str, port: int) -> FakeSock:
        assert port == 443
        dialled.append(ip)
        if ip == "203.0.113.1":
            raise OSError("unreachable")
        sock = FakeSock(ip)
        socks.append(sock)
        return sock

    async def fake_connect(url: str, **kwargs: Any) -> str:
        opened.append({"url": url, **kwargs})
        if kwargs["sock"].ip == "203.0.113.2":
            raise ConnectionError("handshake failed")
        return "connection"

    monkeypatch.setattr(slack_mod, "_dial", fake_dial)
    monkeypatch.setattr(ws_client, "connect", fake_connect)
    result = await slack_mod.pinned_ws_connect(
        SOCKET_URL, "wss-primary.slack.com", ["203.0.113.1", "203.0.113.2", "203.0.113.3"]
    )
    assert result == "connection"
    assert dialled == ["203.0.113.1", "203.0.113.2", "203.0.113.3"]
    final = opened[-1]
    assert final["server_hostname"] == "wss-primary.slack.com"
    assert final["sock"].ip == "203.0.113.3"
    assert final["max_size"] == slack_mod.MAX_FRAME_BYTES
    assert final["proxy"] is None
    # The socket whose handshake failed was closed, not leaked.
    assert socks[0].closed is True


@pytest.mark.asyncio
async def test_pinned_dialer_builds_the_tls_context_once_off_the_event_loop(monkeypatch):
    """Loading the CA bundle is disk I/O: done once, in a worker thread, and
    shared by every later dial and every channel."""
    import ssl
    import threading

    import websockets.asyncio.client as ws_client

    built: list[str] = []
    real_create = ssl.create_default_context

    def create_default_context(*args: Any, **kwargs: Any) -> ssl.SSLContext:
        built.append(threading.current_thread().name)
        return real_create(*args, **kwargs)

    class FakeSock:
        def close(self) -> None:
            pass

    async def fake_dial(ip: str, port: int) -> FakeSock:
        return FakeSock()

    contexts: list[Any] = []

    async def fake_connect(url: str, **kwargs: Any) -> str:
        contexts.append(kwargs["ssl"])
        return "connection"

    monkeypatch.setattr(slack_mod, "_tls_context", None)
    monkeypatch.setattr(slack_mod.ssl, "create_default_context", create_default_context)
    monkeypatch.setattr(slack_mod, "_dial", fake_dial)
    monkeypatch.setattr(ws_client, "connect", fake_connect)
    for _ in range(3):
        await slack_mod.pinned_ws_connect(SOCKET_URL, "wss-primary.slack.com", [PINNED_IP])
    assert len(built) == 1
    assert built[0] != threading.main_thread().name
    assert contexts[0] is contexts[1] is contexts[2]


def test_card_helpers_come_from_cards_not_the_telegram_channel():
    """The Slack channel must not import telegram.py's private helpers (a
    rename there would break Slack at import time)."""
    import inspect

    source = inspect.getsource(slack_mod)
    assert "services.notifications.telegram" not in source
    assert cards.card_arguments("web.search", {"q": "x", "_k": 1}) == {"q": "x", "_k": 1}
    assert cards.card_arguments("desktop.act", {"q": "x", "_screen": "s"}) == {"q": "x"}
    assert cards.card_arguments("web.search", ["not", "a", "dict"]) == {}
    assert cards.usage_line({}) is None
    later = (datetime.now(timezone.utc) + timedelta(minutes=12, seconds=30)).isoformat()
    assert cards.expires_in_text(later) == "12 min"
    assert cards.expires_in_text("not a time") == "a few minutes"


@pytest.mark.asyncio
async def test_pinned_dialer_error_never_quotes_the_url(monkeypatch):
    async def fake_dial(ip: str, port: int) -> Any:
        raise OSError(f"cannot reach {SOCKET_URL}")

    monkeypatch.setattr(slack_mod, "_dial", fake_dial)
    with pytest.raises(ConnectionError) as info:
        await slack_mod.pinned_ws_connect(SOCKET_URL, "wss-primary.slack.com", ["203.0.113.9"])
    assert TICKET not in str(info.value)


# ── audio clips (top10:voice_notes) ──────────────────────────────────────


def _audio_file(mimetype: str = "audio/webm") -> dict[str, Any]:
    return {
        "id": "F0AUDIO01",
        "name": "audio_message.webm",
        "mimetype": mimetype,
        "size": 48213,
        "url_private_download": "https://files.slack.com/files-pri/T0TEAM001-F0AUDIO01/download/audio_message.webm",
    }


@pytest.mark.asyncio
async def test_a_linked_senders_audio_clip_gets_the_text_reply_and_no_turn(linked):
    await linked.deliver(dm_event("", extra={"subtype": "file_share", "files": [_audio_file()]}))
    assert linked.chat_calls == []
    assert [p["text"] for p in linked.api.posts()] == [slack_mod.SLACK_AUDIO_REPLY]
    assert "voice notes work in Telegram" in slack_mod.SLACK_AUDIO_REPLY
    # Nothing was fetched: only the reply went out.
    assert [name for name, _, _ in linked.api.requests if name not in ("auth.test", "apps.connections.open")] == [
        "chat.postMessage"
    ]


@pytest.mark.asyncio
async def test_an_audio_clip_without_a_download_address_still_gets_the_reply(linked):
    clip = _audio_file("audio/mp4")
    del clip["url_private_download"]
    await linked.deliver(dm_event("", extra={"subtype": "file_share", "files": [clip]}))
    assert [p["text"] for p in linked.api.posts()] == [slack_mod.SLACK_AUDIO_REPLY]
    assert linked.chat_calls == []


@pytest.mark.asyncio
async def test_an_unlinked_senders_audio_clip_gets_nothing(linked):
    await linked.deliver(
        dm_event("", user=STRANGER, extra={"subtype": "file_share", "files": [_audio_file()]})
    )
    assert linked.chat_calls == [] and linked.api.posts() == []


@pytest.mark.asyncio
async def test_other_file_shares_and_subtypes_are_unchanged(linked):
    document = dict(_audio_file("application/pdf"), name="notes.pdf")
    await linked.deliver(dm_event("", extra={"subtype": "file_share", "files": [document]}))
    posts = [p["text"] for p in linked.api.posts()]
    assert slack_mod.SLACK_AUDIO_REPLY not in posts
    await linked.deliver(dm_event("", extra={"subtype": "message_changed", "files": [_audio_file()]}))
    assert slack_mod.SLACK_AUDIO_REPLY not in [p["text"] for p in linked.api.posts()]
    assert linked.chat_calls == []


# ── low-risk grants (permission tiers) ───────────────────────────────────


async def park_low_risk(session_factory: Any, user_id: uuid.UUID, *, offer: bool = True) -> Any:
    return await DbApprovalStore(session_factory=session_factory).create(
        user_id=str(user_id),
        tool_name="google_workspace.modify_labels",
        arguments={"message_id": "m1", "add_label_ids": ["STARRED"]},
        reason="Tool 'google_workspace.modify_labels' requires explicit user approval",
        grant_offer={"kind": "low_risk", "connector_id": "c1", "account": "School Gmail"} if offer else None,
    )


def low_risk_press(action_id: str) -> dict[str, Any]:
    frame = press(action_id, approve=True)
    frame["payload"]["actions"][0]["action_id"] = slack_mod.ACTION_APPROVE_LOW_RISK
    return frame


@pytest.mark.asyncio
async def test_a_card_that_offers_a_grant_has_a_third_button_and_says_what_it_allows(linked):
    action = await park_low_risk(linked.session_factory, linked.user_id)
    assert await linked.channel.notify_pending(action) is True
    section, buttons = linked.api.posts()[-1]["blocks"]
    assert [e["action_id"] for e in buttons["elements"]] == [
        slack_mod.ACTION_APPROVE,
        slack_mod.ACTION_DENY,
        slack_mod.ACTION_APPROVE_LOW_RISK,
    ]
    third = buttons["elements"][2]
    assert third["value"] == action.action_id
    assert third["text"]["text"] == "Allow low-risk on School Gmail · 7 days"
    body = section["text"]["text"]
    assert "Or allow low-risk changes on School Gmail for 7 days: " in body
    assert 'Send "grants" to list them, or "revoke grants" to turn them all off.' in body
    plain = await park_low_risk(linked.session_factory, linked.user_id, offer=False)
    assert await linked.channel.notify_pending(plain) is True
    _section, plain_buttons = linked.api.posts()[-1]["blocks"]
    assert len(plain_buttons["elements"]) == 2


def test_the_low_risk_button_is_an_approval_that_remembers(harness):
    harness.channel.team_id = TEAM
    frame = low_risk_press("0f0f0f0f-1111-4111-8111-111111111111")
    pressed = harness.channel.authorize_press(frame["payload"])
    assert pressed is not None and pressed.approved is True and pressed.remember == "low_risk"
    plain = harness.channel.authorize_press(
        press("0f0f0f0f-1111-4111-8111-111111111111", approve=True)["payload"]
    )
    assert plain is not None and plain.remember is None


class LowRiskRuntime(DecisionRuntime):
    """DecisionRuntime that also takes remember= and grants on low_risk."""

    def __init__(self, session_factory: Any, *, grants: bool = True) -> None:
        super().__init__(session_factory)
        self.remembered: list[Any] = []
        self.grants = grants

    async def approve_action(  # type: ignore[override]
        self, action_id: str, user_id: str, task_id: Any = None, remember: Any = None, channel: Any = None
    ) -> dict[str, Any]:
        self.remembered.append(remember)
        result = await self._decide(action_id, user_id, True)
        if remember == "low_risk" and self.grants and "error" not in result:
            result["low_risk"] = {"account": "School Gmail", "expires_at": "2026-10-07T12:00:00+00:00"}
        return result


def wire_low_risk(harness: Harness, *, grants: bool = True) -> LowRiskRuntime:
    from api.routes.agent import build_decision_applier

    runtime = LowRiskRuntime(harness.session_factory, grants=grants)
    app = SimpleNamespace(
        state=SimpleNamespace(agent_runtime=runtime, mcp_catalog=None, installation=None)
    )
    harness.channel.decide = build_decision_applier(app, harness.session_factory)
    return runtime


@pytest.mark.asyncio
async def test_pressing_allow_low_risk_decides_with_remember_and_freezes_with_the_date(linked):
    runtime = wire_low_risk(linked)
    action = await park_low_risk(linked.session_factory, linked.user_id)
    await linked.deliver(low_risk_press(action.action_id))
    assert runtime.remembered == ["low_risk"]
    (update,) = linked.api.calls("chat.update")
    verdict = update["blocks"][-1]["elements"][0]["text"]
    assert verdict.startswith("✅ Approved · low-risk allowed until ")


@pytest.mark.asyncio
async def test_a_low_risk_press_that_made_no_grant_says_approved_once(linked):
    wire_low_risk(linked, grants=False)
    action = await park_low_risk(linked.session_factory, linked.user_id)
    await linked.deliver(low_risk_press(action.action_id))
    (update,) = linked.api.calls("chat.update")
    assert update["blocks"][-1]["elements"][0]["text"] == "✅ Approved (approved once) from Slack."


@pytest.mark.asyncio
async def test_grants_and_revoke_grants_keywords(linked):
    from sqlalchemy import select

    from models.audit import AuditLog
    from services.agent.permission_grants import DbPermissionGrantStore
    from services.notifications.grant_commands import NO_GRANTS_TEXT

    store = DbPermissionGrantStore(linked.session_factory)
    connector_id = str(linked.connector_id)  # the Slack connector row itself is the user's
    grant = await store.allow(user_id=str(linked.user_id), connector_id=connector_id)
    assert grant is not None
    await linked.deliver(dm_event("grants"))
    listing = linked.api.posts()[-1]["text"]
    assert "until" in listing and 'Send "revoke grants" to turn them all off.' in listing
    await linked.deliver(dm_event("Revoke  Grants"))
    assert "Revoked low-risk changes on 1 account" in linked.api.posts()[-1]["text"]
    await linked.deliver(dm_event("grants"))
    assert linked.api.posts()[-1]["text"] == NO_GRANTS_TEXT
    await linked.deliver(dm_event("revoke grants"))
    assert linked.api.posts()[-1]["text"] == NO_GRANTS_TEXT
    # Neither keyword reached the chat.
    assert linked.chat_calls == []
    assert await store.list_live(str(linked.user_id)) == []
    async with linked.session_factory() as session:
        rows = (
            (await session.execute(select(AuditLog).where(AuditLog.user_id == linked.user_id)))
            .scalars()
            .all()
        )
    [revoked] = [r.reasoning_chain for r in rows if (r.reasoning_chain or {}).get("event") == "permission_grant_revoked"]
    assert revoked["revoked_from"] == "slack" and revoked["count"] == 1
