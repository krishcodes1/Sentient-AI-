"""Runs one Slack DM chat channel over Socket Mode for one user's Slack connector:
links the user's Slack account by one-time code, turns their DMs into agent
turns, pushes approval cards with Approve and Deny buttons, applies presses
through the shared decision pipeline, and delivers reminders.

Why it exists: spec 5.4 "Chat channel". A self-hosted install has no public
URL, so Slack events arrive over a WebSocket the app opens itself (Socket
Mode), using the bot token (xoxb-) and app-level token (xapp-) stored on the
user's Slack connector. SlackManager (slack_manager.py) starts one channel per
active Slack connector that has an app-level token.

External service: the Slack Web API (auth.test, apps.connections.open,
conversations.open, chat.postMessage, chat.update) through the Slack connector's
armed, DNS-pinned client (policy key "slack"), and the Socket Mode WebSocket
(the Slack connector's ws_hosts), dialled at the address the WebSocket policy
validated. Depends on services/connectors/slack.py (HTTP, error mapping, the one
unfurl-off post choke point), core/network_security.check_websocket_policy,
models/slack_link.py, services/notifications/cards.py and progress.py, and the
chat and decision appliers from api/routes/agent.py (wired by main.py).

Security rules, in order, for every inbound envelope: ack it at once; accept
only DMs (channel_type "im") written by a person (no bot_id, no subtype) in the
workspace auth.test named; then the sender must be the linked Slack user. An
unlinked sender whose message is exactly the pending code is linked; everyone
else gets no reply. The socket URL carries a ticket and is never logged, and no
token ever is.
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import logging
import random
import re
import secrets
import socket
import ssl
import time
import uuid as uuid_module
from collections import OrderedDict
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Awaitable, Callable, Coroutine, Optional, Protocol, Sequence
from urllib.parse import urlsplit, urlunsplit

import structlog
from sqlalchemy import update

from core.config import settings
from core.network_security import check_websocket_policy
from models.slack_link import SlackChannelLink
from services.agent import cancel as agent_cancel
from services.connectors.base import AuthenticationError, ConnectorError
from services.connectors.slack import SlackConnector
from services.connectors.slack_api.client import API_BASE, TS_RE, USER_ID_RE, slack_error
from services.notifications import cards
from services.notifications.progress import TurnProgress, takes_keyword, takes_on_event
from services.security import channels as secret_text

logger = structlog.get_logger(__name__)

# The network policy (core.network_security.DEFAULT_POLICIES) of the Slack
# connector: Web API hosts plus the Socket Mode ws_hosts.
POLICY_KEY = "slack"

# How long a link code stays valid, and the HMAC domain its hash is keyed
# under (separate from every other use of ENCRYPTION_KEY).
LINK_CODE_TTL_MINUTES = 10
_LINK_KEY_DOMAIN = b"sentientai.slack.link-code.v1:"

# Longest text per reply message (Slack advises 4,000 characters) and per
# approval card part (a section block's text is capped at 3,000).
TEXT_CHUNK = 3900
SECTION_CHARS = 2900
# Pause between the messages of one multi-part reply: Slack allows about one
# message per second per channel.
POST_INTERVAL_S = 1.0
# Largest Socket Mode frame accepted; Slack's envelopes are a few kilobytes.
MAX_FRAME_BYTES = 1 << 20
# TCP connect and WebSocket opening handshake, each.
OPEN_TIMEOUT_S = 10.0
# Reconnect backoff after a failure: doubled per failure up to the cap, with
# jitter so many channels never reconnect in lockstep.
BACKOFF_INITIAL_S = 1.0
BACKOFF_MAX_S = 60.0
# A session that said hello but ended sooner than this counts as a failure
# for backoff: a socket Slack greets and drops at once (too many
# connections, a refresh storm) must not turn into back to back
# apps.connections.open calls. Normal sessions last hours.
MIN_HEALTHY_SESSION_S = 30.0
# Authentication failures (a revoked or wrong token, a missing scope) in a
# row after which the channel stops retrying: a dead token never heals by
# itself, and retrying it forever costs an API call and a warning a minute.
# last_error keeps saying auth_failed for the connector card, and editing
# the connector restarts the channel (SlackManager.reconcile).
MAX_AUTH_FAILURES = 5
# How long "stop" and channel shutdown wait for cancelled work to unwind.
STOP_WAIT_S = 10.0
# Event ids remembered to drop Slack's redeliveries of an envelope.
_SEEN_EVENTS = 512

ACTION_APPROVE = "crawler_approve"
ACTION_DENY = "crawler_deny"
# The third button of a card that offers a low-risk grant: approve it and
# allow low-risk changes on its account for 7 days (permission tiers).
ACTION_APPROVE_LOW_RISK = "crawler_approve_low_risk"
# The decision option that button carries (permission_grants.REMEMBER_LOW_RISK).
_REMEMBER_LOW_RISK = "low_risk"

_TEAM_ID_RE = re.compile(r"^[TE][A-Z0-9]{1,30}$")
_DM_CHANNEL_RE = re.compile(r"^D[A-Z0-9]{1,30}$")
_UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
_REASON_RE = re.compile(r"^[a-z_]{1,40}$")

# websockets' own logger: it could print the request line (with the ticket)
# at debug level, so it is held at WARNING whatever the app's level is.
_WS_LOGGER = logging.getLogger("services.notifications.slack.websocket")
_WS_LOGGER.setLevel(logging.WARNING)

DecideCallback = Callable[..., Awaitable[dict[str, Any]]]
ChatCallback = Callable[..., Awaitable[dict[str, Any]]]
# (user_id, command, new_conversation=..., text=...) -> {"reply": str} or
# {"error": str}: api/routes/agent.build_tutor_applier.
TutorCallback = Callable[..., Awaitable[dict[str, Any]]]


class WebSocketLike(Protocol):
    """The part of a WebSocket connection the channel uses (tests fake it)."""

    async def recv(self) -> str | bytes: ...

    async def send(self, message: str) -> None: ...

    async def close(self) -> None: ...


# (url, host, pinned addresses) -> an open connection.
WsConnect = Callable[[str, str, Sequence[str]], Awaitable[WebSocketLike]]


class SocketRefused(Exception):
    """The socket URL Slack returned failed the WebSocket policy."""


# Why a channel's socket is not up, as a short fixed code (never an error
# message: those could quote a URL). GET /slack/link reports it so the
# connector card can say what is wrong.
ERROR_SOCKET_REFUSED = "socket_refused"
ERROR_AUTH_FAILED = "auth_failed"
ERROR_CONNECT_FAILED = "connect_failed"


# ── link codes ───────────────────────────────────────────────────────────


def _link_key() -> bytes:
    return hashlib.sha256(_LINK_KEY_DOMAIN + settings.ENCRYPTION_KEY.encode("utf-8")).digest()


def hash_link_code(code: str) -> str:
    """HMAC-SHA256 hex of a link code; the only form ever stored."""
    return hmac.new(_link_key(), code.encode("utf-8"), hashlib.sha256).hexdigest()


def new_link_code() -> str:
    """A fresh one-time code (24 URL-safe characters, 144 bits)."""
    return secrets.token_urlsafe(18)


def _as_utc(value: Optional[datetime]) -> Optional[datetime]:
    if value is not None and value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value


def code_is_pending(link: Optional[SlackChannelLink], *, now: Optional[datetime] = None) -> bool:
    """True when *link* holds an unexpired, unused code."""
    if link is None or not link.link_code_hash:
        return False
    expires = _as_utc(link.link_expires_at)
    return expires is not None and expires > (now or datetime.now(timezone.utc))


def code_matches(link: Optional[SlackChannelLink], text: str) -> bool:
    """Constant-time check of *text* against the pending code's hash."""
    if not code_is_pending(link):
        return False
    assert link is not None and link.link_code_hash is not None
    return hmac.compare_digest(hash_link_code(text), link.link_code_hash)


def link_code_expiry() -> datetime:
    return datetime.now(timezone.utc) + timedelta(minutes=LINK_CODE_TTL_MINUTES)


# ── Slack text helpers ───────────────────────────────────────────────────


def slack_escape(text: str) -> str:
    """Escape the three characters Slack treats as markup, so text the model
    wrote can never become a disguised link or a mention."""
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def slack_unescape(text: str) -> str:
    """Undo the escaping Slack applies to message text in events."""
    return text.replace("&lt;", "<").replace("&gt;", ">").replace("&amp;", "&")


# How the DM tells the person to list their waiting approval cards.
_PENDING_HINT = "send pending"


def _with_turn_notes(reply: str, outcome: dict[str, Any]) -> str:
    """*reply* plus what the turn left for the person (cards.turn_notes),
    and a note for screenshots a text-only DM cannot show."""
    reply += cards.turn_notes(outcome, where="DM", pending_hint=_PENDING_HINT)
    images = outcome.get("images") or []
    if images:
        count = len(images)
        noun = "screenshot" if count == 1 else "screenshots"
        reply += f"\n\n({count} {noun} not shown: Slack DMs carry text only.)"
    return reply


def _section(text: str) -> dict[str, Any]:
    """A section block showing *text* literally: plain text (no markup) with
    emoji conversion off, so an argument such as ":x:" reads as typed and the
    approver sees exactly what will run."""
    return {"type": "section", "text": {"type": "plain_text", "text": text, "emoji": False}}


def _decision_buttons(action_id: str, low_risk_account: Optional[str] = None) -> dict[str, Any]:
    """Approve and Deny, plus "Allow low-risk on <account> · 7 days" when the
    card offers a low-risk grant."""
    extra: list[dict[str, Any]] = []
    if low_risk_account:
        label = " ".join("".join(c if c.isprintable() else " " for c in low_risk_account).split())
        if len(label) > 24:
            label = label[:23] + "…"
        extra.append(
            {
                "type": "button",
                "action_id": ACTION_APPROVE_LOW_RISK,
                "text": {"type": "plain_text", "text": f"Allow low-risk on {label} · 7 days"},
                "value": action_id,
            }
        )
    return {
        "type": "actions",
        "block_id": "crawler_decision",
        "elements": [
            {
                "type": "button",
                "action_id": ACTION_APPROVE,
                "text": {"type": "plain_text", "text": "Approve"},
                "style": "primary",
                "value": action_id,
            },
            {
                "type": "button",
                "action_id": ACTION_DENY,
                "text": {"type": "plain_text", "text": "Deny"},
                "style": "danger",
                "value": action_id,
            },
            *extra,
        ],
    }


def _policy_url(url: str) -> str:
    """*url* without its query and fragment: the WebSocket policy needs only
    scheme, host and port, and the query carries the connection ticket,
    which must never reach a log line (the policy logs refusals)."""
    parts = urlsplit(url)
    return urlunsplit((parts.scheme, parts.netloc, parts.path, "", ""))


# ── the default, pinned WebSocket dialer ─────────────────────────────────

# The TLS context every channel dials with. Building one loads the system CA
# bundle from disk, so it is built once, in a worker thread, and shared (an
# SSLContext is safe to reuse across connections).
_tls_context: Optional[ssl.SSLContext] = None


async def _shared_tls_context() -> ssl.SSLContext:
    global _tls_context
    if _tls_context is None:
        # Two first dials racing both build one; the last assignment wins
        # and both contexts are equivalent, so no lock is needed.
        _tls_context = await asyncio.to_thread(ssl.create_default_context)
    return _tls_context


async def _dial(ip: str, port: int) -> socket.socket:
    family = socket.AF_INET6 if ":" in ip else socket.AF_INET
    sock = socket.socket(family, socket.SOCK_STREAM)
    sock.setblocking(False)
    try:
        loop = asyncio.get_running_loop()
        await asyncio.wait_for(loop.sock_connect(sock, (ip, port)), OPEN_TIMEOUT_S)
    except BaseException:
        sock.close()
        raise
    return sock


async def pinned_ws_connect(url: str, host: str, ips: Sequence[str]) -> WebSocketLike:
    """Open the Socket Mode connection to one of *ips* (the addresses the
    WebSocket policy validated), with TLS verified for *host*.

    The TCP socket is dialled here and handed to websockets, which then
    never resolves DNS, never uses a proxy and cannot follow a redirect (it
    refuses one on a preexisting socket). Frames are bounded by
    MAX_FRAME_BYTES. Errors name only their type: websockets' messages can
    quote the URL.
    """
    from websockets.asyncio.client import connect

    context = await _shared_tls_context()
    failure = "no address"
    for ip in ips:
        try:
            sock = await _dial(ip, 443)
        except (OSError, asyncio.TimeoutError) as exc:
            failure = type(exc).__name__
            continue
        try:
            connection = await connect(
                url,
                sock=sock,
                ssl=context,
                server_hostname=host,
                max_size=MAX_FRAME_BYTES,
                open_timeout=OPEN_TIMEOUT_S,
                proxy=None,
                logger=_WS_LOGGER,
            )
        except Exception as exc:
            sock.close()
            failure = type(exc).__name__
            continue
        return connection
    raise ConnectionError(f"Could not open the Slack socket ({failure}).")


async def _close_quietly(ws: WebSocketLike) -> None:
    try:
        await ws.close()
    except Exception as exc:  # the socket is being discarded anyway
        logger.debug("slack_socket_close_failed", error_type=type(exc).__name__)


# ── inbound shapes ───────────────────────────────────────────────────────


@dataclass(frozen=True)
class SlackFile:
    """A file shared in a DM (top10:file_extraction): its Slack id, name,
    declared type and size, and the bot-token download address, which is
    accepted only on files.slack.com under /files-pri/."""

    id: str
    name: str
    mimetype: str
    size: Optional[int]
    url: str = ""


@dataclass(frozen=True)
class InboundMessage:
    sender: str
    text: str
    channel: str
    event_key: str
    # top10:file_extraction: the files of a ``file_share`` message.
    files: tuple[SlackFile, ...] = ()
    # top10:voice_notes: the ``file_share`` carries an audio clip (any file
    # whose declared type is audio/*), whatever its download address.
    audio: bool = False


def _shares_audio(event: dict[str, Any]) -> bool:
    """Whether a file_share event carries an audio file (top10:voice_notes).
    Only the declared type is read; nothing is fetched."""
    raw = event.get("files")
    return any(
        isinstance(item, dict) and str(item.get("mimetype") or "").lower().startswith("audio/")
        for item in (raw if isinstance(raw, list) else [])
    )


@dataclass(frozen=True)
class ButtonPress:
    sender: str
    channel: str
    message_ts: str
    action_id: str
    approved: bool
    blocks: tuple[dict[str, Any], ...]
    # "low_risk" for the "Allow low-risk" button (permission tiers).
    remember: Optional[str] = None


# A DM keyword handler in SlackChannel._text_handlers: given a linked
# sender's message, the reply to run off the socket loop when the message is
# its keyword, or None to let the next handler (and in the end the chat)
# have it. Called on the socket loop, so it must not block.
TextHandler = Callable[[InboundMessage], Optional[Awaitable[None]]]
# A text handler's method name is "_keyword_<word>"; its reply task is named
# "slack-<word>".
_KEYWORD_HANDLER_PREFIX = "_keyword_"


# top10:voice_notes: what a linked sender's audio clip gets instead of a turn.
SLACK_AUDIO_REPLY = (
    "🎤 I can't listen to Slack audio clips yet. Please type your message — voice "
    "notes work in Telegram when the owner has turned them on."
)

_FILES_HOST = "files.slack.com"
_FILES_PATH_PREFIX = "/files-pri/"
_MAX_SHARED_FILES = 5


def _shared_files(event: dict[str, Any]) -> tuple[SlackFile, ...]:
    """The files of a file_share event that may be downloaded: at most
    _MAX_SHARED_FILES, each with a url_private_download on files.slack.com
    under /files-pri/ (anything else is left out, never fetched)."""
    found: list[SlackFile] = []
    raw = event.get("files")
    for item in raw if isinstance(raw, list) else []:
        if not isinstance(item, dict):
            continue
        url = item.get("url_private_download")
        file_id = item.get("id")
        if not isinstance(url, str) or not isinstance(file_id, str):
            continue
        try:
            parts = urlsplit(url)
        except ValueError:
            continue
        if parts.scheme != "https" or parts.hostname != _FILES_HOST or not parts.path.startswith(_FILES_PATH_PREFIX):
            continue
        size = item.get("size")
        found.append(
            SlackFile(
                id=file_id[:64],
                name=str(item.get("name") or item.get("title") or "file")[:255],
                mimetype=str(item.get("mimetype") or "")[:100],
                size=size if isinstance(size, int) and not isinstance(size, bool) else None,
                url=url,
            )
        )
        if len(found) >= _MAX_SHARED_FILES:
            break
    return tuple(found)


async def _done() -> None:
    """The empty reply of a text handler that started its work itself."""
    return None


def _as_coroutine(reply: Awaitable[None]) -> Coroutine[Any, Any, None]:
    """*reply* as the coroutine SlackChannel._later runs (and closes,
    unstarted, while the channel shuts down)."""
    if isinstance(reply, Coroutine):
        return reply

    async def wait() -> None:
        await reply

    return wait()


def _reply_task_name(handler: TextHandler) -> str:
    name = str(getattr(handler, "__name__", "") or "text")
    return "slack-" + name.removeprefix(_KEYWORD_HANDLER_PREFIX)


class SlackChannel:
    """Socket Mode DM channel for one Slack connector (one Crawler user)."""

    def __init__(
        self,
        *,
        connector_id: str,
        user_id: str,
        bot_token: str,
        app_token: str,
        session_factory: Callable[[], Any],
        chat: Optional[ChatCallback] = None,
        decide: Optional[DecideCallback] = None,
        connector: Optional[SlackConnector] = None,
        ws_connect: WsConnect = pinned_ws_connect,
    ) -> None:
        self.connector_id = str(connector_id)
        self.user_id = str(user_id)
        self.chat = chat
        self.decide = decide
        self._connector_uuid = uuid_module.UUID(self.connector_id)
        self._session_factory = session_factory
        self._app_token = app_token
        if connector is None:
            built = SlackConnector.from_credentials(
                {"bot_token": bot_token, "app_token": app_token}
            )
            assert isinstance(built, SlackConnector)
            built.set_network_policy(POLICY_KEY)
            connector = built
        # One armed, pinned client for every Web API call this channel makes.
        self._connector = connector
        self._ws_connect = ws_connect
        # Seams for tests: backoff and pacing waits, and the jitter source.
        self._sleep: Callable[[float], Awaitable[None]] = asyncio.sleep
        self._random: Callable[[], float] = random.random
        self._clock: Callable[[], float] = time.monotonic
        self._task: Optional[asyncio.Task[None]] = None
        self._closing = False
        self.connected = False
        # Why the last connection attempt failed (an ERROR_* code), None
        # once Slack says hello. Surfaced by GET /slack/link.
        self.last_error: Optional[str] = None
        self.team_id: Optional[str] = None
        self.bot_user_id: Optional[str] = None
        # The channel serves one Crawler user, so one lock orders that
        # user's turns and decisions.
        self._lock = asyncio.Lock()
        self._card_lock = asyncio.Lock()
        # Agent turns and decisions: what "stop" cancels.
        self._work: set[asyncio.Task[None]] = set()
        # Replies and bookkeeping that must not block the socket loop.
        self._control: set[asyncio.Task[None]] = set()
        self._fresh = False
        self._seen: OrderedDict[str, None] = OrderedDict()
        self._dm_channels: dict[str, str] = {}
        # A linked sender's message goes to the first of these that answers
        # it (a keyword), else to the chat (_on_events_api).
        self._text_handlers: list[TextHandler] = []
        self._register_text_handlers()

    def _register_text_handlers(self) -> None:
        """Fill ``_text_handlers``, in the order they are tried."""
        self._text_handlers.append(self._keyword_stop)
        self._text_handlers.append(self._keyword_pending)
        self._text_handlers.append(self._keyword_new)
        # top10:secret_pii_redaction

        # top10:file_extraction
        self._text_handlers.append(self._keyword_files)

        # top10:scheduler_briefing
        from services.scheduler import commands as schedule_commands

        schedule_commands.register_slack(self)

        # top10:tutor_mode
        # "tutor on|off|status" (services/tutor), applied by the tutor applier
        # main.py wires; None until then.
        self.tutor: Optional[TutorCallback] = None
        self._text_handlers.append(self._keyword_tutor)

        # top10:knowledge_base

        # top10:flashcards_quizzes
        from services.study import slack as study_slack

        study_slack.register_slack(self)

        # top10:event_triggers
        from services.triggers import commands as trigger_commands

        trigger_commands.register_slack(self)

        # top10:permission_tiers
        from services.notifications import grant_commands

        grant_commands.register_slack(self)

        # top10:voice_notes
        # Ahead of the files handler: an audio clip gets a text reply and is
        # never downloaded or read as a document.
        files_at = next(
            (
                i
                for i, handler in enumerate(self._text_handlers)
                if getattr(handler, "__name__", "") == "_keyword_files"
            ),
            len(self._text_handlers),
        )
        self._text_handlers.insert(files_at, self._keyword_audio)

        # top10:video_transcripts

    # ── lifecycle ────────────────────────────────────────────────────────

    @property
    def running(self) -> bool:
        return self._task is not None and not self._task.done()

    async def start(self) -> None:
        self._closing = False
        self._task = asyncio.create_task(self._run(), name=f"slack-channel-{self.connector_id[:8]}")
        logger.info("slack_channel_started", connector_id=self.connector_id)

    async def stop(self) -> None:
        """Stop the socket loop, cancel this channel's work (bounded wait),
        then close the HTTP client."""
        self._closing = True
        task, self._task = self._task, None
        if task is not None:
            task.cancel()
            await asyncio.wait({task})
        tasks = [t for t in (*self._work, *self._control) if not t.done()]
        for pending in tasks:
            pending.cancel()
        if tasks:
            _, lingering = await asyncio.wait(tasks, timeout=STOP_WAIT_S)
            if lingering:
                logger.warning(
                    "slack_channel_stop_left_running",
                    connector_id=self.connector_id,
                    tasks=len(lingering),
                )
        self.connected = False
        await self._connector.close()
        logger.info("slack_channel_stopped", connector_id=self.connector_id)

    async def wait_idle(self) -> None:
        """Wait for in-flight work and replies (tests, shutdown)."""
        while True:
            tasks = [t for t in (*self._work, *self._control) if not t.done()]
            if not tasks:
                return
            await asyncio.gather(*tasks, return_exceptions=True)

    def _spawn(
        self, into: set[asyncio.Task[None]], coro: Coroutine[Any, Any, Any], name: str
    ) -> None:
        if self._closing:
            coro.close()
            return
        task = asyncio.create_task(self._logged(coro, name), name=name)
        into.add(task)
        task.add_done_callback(into.discard)

    def _track(self, coro: Coroutine[Any, Any, Any], name: str) -> None:
        """Run a turn or decision as work "stop" can cancel."""
        self._spawn(self._work, coro, name)

    def _later(self, coro: Coroutine[Any, Any, Any], name: str) -> None:
        """Run a reply off the socket loop (acks must never wait on it)."""
        self._spawn(self._control, coro, name)

    @staticmethod
    async def _logged(coro: Coroutine[Any, Any, Any], name: str) -> None:
        try:
            await coro
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            logger.warning("slack_channel_task_failed", task=name, error_type=type(exc).__name__)

    # ── socket loop ──────────────────────────────────────────────────────

    def _backoff(self, failures: int) -> float:
        delay = min(BACKOFF_MAX_S, BACKOFF_INITIAL_S * 2 ** max(0, failures - 1))
        return delay * (0.5 + self._random() / 2)

    async def _run(self) -> None:
        failures = 0
        # Authentication failures since both tokens last worked.
        auth_failures = 0
        while not self._closing:
            try:
                if self.team_id is None:
                    await self._identify()
                url = await self._open_url()
                auth_failures = 0
                host, ips = await self._check_url(url)
                ws = await self._ws_connect(url, host, ips)
                opened_at = self._clock()
                try:
                    greeted = await self._consume(ws)
                finally:
                    self.connected = False
                    await _close_quietly(ws)
                if greeted and self._clock() - opened_at >= MIN_HEALTHY_SESSION_S:
                    # A normal session ended (Slack refreshes sockets every
                    # few hours): reconnect at once.
                    failures = 0
                    continue
                if not greeted:
                    self.last_error = ERROR_CONNECT_FAILED
                failures += 1
            except asyncio.CancelledError:
                raise
            except SocketRefused as exc:
                failures += 1
                self.last_error = ERROR_SOCKET_REFUSED
                logger.warning(
                    "slack_socket_refused", connector_id=self.connector_id, reason=str(exc)[:200]
                )
            except AuthenticationError as exc:
                # A revoked or wrong token: retried a few times with backoff
                # so a transient Slack fault recovers, then given up (see
                # MAX_AUTH_FAILURES). The card says what is wrong either way.
                failures += 1
                auth_failures += 1
                self.last_error = ERROR_AUTH_FAILED
                gave_up = auth_failures >= MAX_AUTH_FAILURES
                logger.warning(
                    "slack_channel_auth_given_up" if gave_up else "slack_channel_connect_failed",
                    connector_id=self.connector_id,
                    error_type=type(exc).__name__,
                    error=str(exc)[:200],
                )
                if gave_up:
                    return
            except ConnectorError as exc:
                # Mapped errors carry a vendor code and a fixed hint only.
                failures += 1
                self.last_error = ERROR_CONNECT_FAILED
                logger.warning(
                    "slack_channel_connect_failed",
                    connector_id=self.connector_id,
                    error_type=type(exc).__name__,
                    error=str(exc)[:200],
                )
            except Exception as exc:
                failures += 1
                self.last_error = ERROR_CONNECT_FAILED
                logger.warning(
                    "slack_channel_connect_failed",
                    connector_id=self.connector_id,
                    error_type=type(exc).__name__,
                )
            await self._sleep(self._backoff(failures))

    async def _identify(self) -> None:
        """auth.test: the workspace every event must come from and the bot's
        own user id. Fetched once per channel."""
        data = await self._connector._call("auth.test")
        team, bot = data.get("team_id"), data.get("user_id")
        if not (isinstance(team, str) and _TEAM_ID_RE.fullmatch(team)):
            raise ConnectorError("Malformed auth.test reply from Slack.")
        if not (isinstance(bot, str) and USER_ID_RE.fullmatch(bot)):
            raise ConnectorError("Malformed auth.test reply from Slack.")
        self.team_id, self.bot_user_id = team, bot

    async def _open_url(self) -> str:
        """apps.connections.open with the app-level token (the only call that
        uses it), through the connector's armed, pinned client."""
        data = await self._connector._request_json(
            "POST",
            f"{API_BASE}/apps.connections.open",
            headers={"Authorization": f"Bearer {self._app_token}"},
            authorized=False,
        )
        if not isinstance(data, dict):
            raise ConnectorError("Malformed response from Slack.")
        if data.get("ok") is not True:
            raise slack_error(data)
        url = data.get("url")
        if not isinstance(url, str) or not url:
            raise ConnectorError("Slack returned no socket URL.")
        return url

    async def _check_url(self, url: str) -> tuple[str, tuple[str, ...]]:
        """The host and the addresses to dial, or SocketRefused. DNS runs in
        a worker thread (check_websocket_policy resolves synchronously)."""
        result = await asyncio.to_thread(check_websocket_policy, _policy_url(url), POLICY_KEY)
        host = urlsplit(url).hostname
        if not result.safe or not result.resolved_ips or not host:
            raise SocketRefused(result.reason or "the socket URL was refused")
        return host, tuple(result.resolved_ips)

    async def _consume(self, ws: WebSocketLike) -> bool:
        """Read envelopes until the socket closes or Slack asks to reconnect.
        True once Slack's hello arrived (the session was good)."""
        greeted = False
        while not self._closing:
            try:
                raw = await ws.recv()
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                logger.info(
                    "slack_socket_closed",
                    connector_id=self.connector_id,
                    error_type=type(exc).__name__,
                )
                return greeted
            frame = _parse_frame(raw)
            if frame is None:
                continue
            envelope_id = frame.get("envelope_id")
            if isinstance(envelope_id, str) and envelope_id:
                # Ack first: Slack redelivers anything not acked within 3 s.
                try:
                    await ws.send(json.dumps({"envelope_id": envelope_id}))
                except asyncio.CancelledError:
                    raise
                except Exception as exc:
                    logger.info(
                        "slack_socket_ack_failed",
                        connector_id=self.connector_id,
                        error_type=type(exc).__name__,
                    )
                    return greeted
            kind = frame.get("type")
            if kind == "hello":
                greeted = True
                self.connected = True
                self.last_error = None
                logger.info("slack_socket_connected", connector_id=self.connector_id)
            elif kind == "disconnect":
                reason = frame.get("reason")
                logger.info(
                    "slack_socket_disconnect_requested",
                    connector_id=self.connector_id,
                    reason=reason
                    if isinstance(reason, str) and _REASON_RE.fullmatch(reason)
                    else None,
                )
                return greeted
            elif kind == "events_api":
                await self._guarded(self._on_events_api(frame.get("payload")), "event")
            elif kind == "interactive":
                await self._guarded(self._on_interactive(frame.get("payload")), "interactive")
        return greeted

    async def _guarded(self, coro: Coroutine[Any, Any, Any], what: str) -> None:
        try:
            await coro
        except asyncio.CancelledError:
            raise
        except Exception as exc:  # one bad envelope never ends the session
            logger.warning(
                "slack_envelope_failed",
                connector_id=self.connector_id,
                kind=what,
                error_type=type(exc).__name__,
            )

    # ── authorization (no I/O) ───────────────────────────────────────────

    def authorize_message(self, payload: Any) -> Optional[InboundMessage]:
        """The DM a person in this workspace wrote, or None. Drops non-DMs,
        bot messages, edits and every other subtype, other workspaces
        (including a Slack Connect partner in a shared DM), and malformed
        events, before any lookup."""
        if not isinstance(payload, dict) or payload.get("type") != "event_callback":
            return None
        team = self.team_id
        if team is None or payload.get("team_id") != team:
            return None
        event = payload.get("event")
        if not isinstance(event, dict) or event.get("type") != "message":
            return None
        if event.get("channel_type") != "im":
            return None
        # top10:file_extraction: a person sharing a file in the DM
        # ("file_share") is the one subtype admitted; every other subtype
        # (edits, joins, bot messages ...) is still dropped.
        if "subtype" in event and event.get("subtype") != "file_share":
            return None
        if event.get("bot_id") or event.get("bot_profile"):
            return None
        for key in ("team", "user_team", "source_team"):
            if key in event and event.get(key) != team:
                return None
        sender = event.get("user")
        if not (isinstance(sender, str) and USER_ID_RE.fullmatch(sender)):
            return None
        if sender == self.bot_user_id:
            return None
        channel = event.get("channel")
        if not (isinstance(channel, str) and _DM_CHANNEL_RE.fullmatch(channel)):
            return None
        files = _shared_files(event) if event.get("subtype") == "file_share" else ()
        # top10:voice_notes: an audio clip is admitted for its text reply.
        audio = event.get("subtype") == "file_share" and _shares_audio(event)
        text = event.get("text")
        if text is None and (files or audio):
            text = ""
        if not isinstance(text, str):
            return None
        text = slack_unescape(text).strip()
        if not text and not files and not audio:
            return None
        event_id = payload.get("event_id")
        key = event_id if isinstance(event_id, str) and event_id else f"{channel}:{event.get('ts')}"
        return InboundMessage(
            sender=sender, text=text, channel=channel, event_key=key, files=files, audio=audio
        )

    def authorize_press(self, payload: Any) -> Optional[ButtonPress]:
        """An Approve or Deny press from this workspace, or None."""
        if not isinstance(payload, dict) or payload.get("type") != "block_actions":
            return None
        team = self.team_id
        user = payload.get("user")
        if team is None or not isinstance(user, dict):
            return None
        sender = user.get("id")
        if not (isinstance(sender, str) and USER_ID_RE.fullmatch(sender)):
            return None
        payload_team = payload.get("team")
        pressed_in = payload_team.get("id") if isinstance(payload_team, dict) else None
        if pressed_in != team or user.get("team_id", team) != team:
            return None
        channel_info = payload.get("channel")
        channel = channel_info.get("id") if isinstance(channel_info, dict) else None
        if not (isinstance(channel, str) and _DM_CHANNEL_RE.fullmatch(channel)):
            return None
        message = payload.get("message")
        container = payload.get("container")
        ts = message.get("ts") if isinstance(message, dict) else None
        if ts is None and isinstance(container, dict):
            ts = container.get("message_ts")
        if not (isinstance(ts, str) and TS_RE.fullmatch(ts)):
            return None
        actions = payload.get("actions")
        if not isinstance(actions, list) or not actions or not isinstance(actions[0], dict):
            return None
        pressed = actions[0]
        if pressed.get("action_id") not in (ACTION_APPROVE, ACTION_DENY, ACTION_APPROVE_LOW_RISK):
            return None
        action_id = pressed.get("value")
        if not (isinstance(action_id, str) and _UUID_RE.fullmatch(action_id)):
            return None
        raw_blocks = message.get("blocks") if isinstance(message, dict) else None
        blocks = (
            tuple(b for b in raw_blocks if isinstance(b, dict))
            if isinstance(raw_blocks, list)
            else ()
        )
        return ButtonPress(
            sender=sender,
            channel=channel,
            message_ts=ts,
            action_id=action_id,
            approved=pressed.get("action_id") in (ACTION_APPROVE, ACTION_APPROVE_LOW_RISK),
            blocks=blocks,
            remember=_REMEMBER_LOW_RISK if pressed.get("action_id") == ACTION_APPROVE_LOW_RISK else None,
        )

    def _first_delivery(self, key: str) -> bool:
        if key in self._seen:
            return False
        self._seen[key] = None
        while len(self._seen) > _SEEN_EVENTS:
            self._seen.popitem(last=False)
        return True

    def _is_linked_sender(self, link: Optional[SlackChannelLink], sender: str) -> bool:
        return (
            link is not None
            and link.team_id is not None
            and link.team_id == self.team_id
            and link.slack_user_id == sender
        )

    # ── inbound handling ─────────────────────────────────────────────────

    async def _load_link(self) -> Optional[SlackChannelLink]:
        async with self._session_factory() as session:
            link: Optional[SlackChannelLink] = await session.get(
                SlackChannelLink, self._connector_uuid
            )
            return link

    async def _on_events_api(self, payload: Any) -> None:
        message = self.authorize_message(payload)
        if message is None or not self._first_delivery(message.event_key):
            return
        link = await self._load_link()
        if code_matches(link, message.text):
            if await self._link_sender(message.sender, message.text):
                self._dm_channels[message.sender] = message.channel
                self._later(self._post_text(message.channel, _LINKED_TEXT), "slack-linked")
            return
        if not self._is_linked_sender(link, message.sender):
            logger.info("slack_message_from_unlinked_user_ignored", connector_id=self.connector_id)
            return
        self._dm_channels[message.sender] = message.channel
        for handler in self._text_handlers:
            reply = handler(message)
            if reply is not None:
                self._later(_as_coroutine(reply), _reply_task_name(handler))
                return
        self._handle_chat(message.channel, message.text)

    # ── DM keywords (_text_handlers) ─────────────────────────────────────

    def _keyword_stop(self, message: InboundMessage) -> Optional[Awaitable[None]]:
        if message.text.lower() != "stop":
            return None
        return self._handle_stop(message.channel)

    def _keyword_pending(self, message: InboundMessage) -> Optional[Awaitable[None]]:
        if message.text.lower() != "pending":
            return None
        return self._handle_pending(message.channel)

    def _keyword_new(self, message: InboundMessage) -> Optional[Awaitable[None]]:
        if message.text.lower() != "new":
            return None
        # Set now, not when the reply goes out: the next message may already
        # be on its way.
        self._fresh = True
        return self._say_fresh_start(message.channel)

    def _keyword_tutor(self, message: InboundMessage) -> Optional[Awaitable[None]]:
        """The bare "tutor", "tutor on|off|status" (Slack's client keeps a
        "/tutor" for itself); "tutor me in calc" goes to the chat."""
        from services.tutor.commands import parse_tutor_command

        command = parse_tutor_command(message.text, slash_required=False)
        if command is None:
            return None
        # Consumed now, like "new": "new" then "tutor on" switches the
        # fresh thread the next message continues.
        fresh, self._fresh = self._fresh, False
        return self._handle_tutor(message.channel, command, fresh)

    async def _handle_tutor(self, channel: str, command: str, fresh: bool) -> None:
        """Apply a tutor command (no model call; off the turn lock, so a turn
        running meanwhile merges its own state over this one when it saves)."""
        if self.tutor is None:
            await self._post_text(channel, "Tutor mode is not available right now.")
            return
        try:
            outcome = await self.tutor(
                self.user_id, command, new_conversation=fresh, text=f"tutor {command}"
            )
        except Exception as exc:
            logger.warning("slack_tutor_failed", error_type=type(exc).__name__)
            outcome = {"error": "Tutor mode could not be changed right now."}
        if outcome.get("error"):
            if fresh:
                self._fresh = True
            await self._post_text(channel, f"⚠️ {outcome['error']}"[:TEXT_CHUNK])
            return
        await self._post_text(channel, str(outcome.get("reply") or "")[:TEXT_CHUNK])

    async def _say_fresh_start(self, channel: str) -> None:
        await self._post_text(channel, "Fresh start: your next message begins a new conversation.")

    # ── audio clips (top10:voice_notes) ──────────────────────────────────

    def _keyword_audio(self, message: InboundMessage) -> Optional[Awaitable[None]]:
        """A DM sharing an audio clip gets a text reply: no download and no
        turn (Slack audio is a follow-up; voice notes work in Telegram)."""
        if not message.audio:
            return None
        return self._say_no_audio(message.channel)

    async def _say_no_audio(self, channel: str) -> None:
        await self._post_text(channel, SLACK_AUDIO_REPLY)

    # ── shared files (top10:file_extraction) ─────────────────────────────

    def _keyword_files(self, message: InboundMessage) -> Optional[Awaitable[None]]:
        """A DM that shares files: its turn starts as tracked work (so
        "stop" cancels the downloads too), and the handler's own reply is
        empty."""
        if not message.files:
            return None
        if self.chat is None:
            logger.warning("slack_chat_unavailable", connector_id=self.connector_id)
            return _done()
        fresh, self._fresh = self._fresh, False
        stop_mark = agent_cancel.mark(self.user_id)
        self._track(
            self._run_file_turn(message, fresh, stop_mark), f"slack-chat-{self.connector_id[:8]}"
        )
        return _done()

    async def _run_file_turn(self, message: InboundMessage, fresh: bool, stop_mark: int) -> None:
        """Check "Read files and documents", download the shared files with
        the bot token (files.slack.com/files-pri/ only, through the Slack
        connector's policy-checked client), then one chat turn with
        ``files=``. A file that cannot be fetched or read ends the turn with
        "⚠️ I couldn't read x: <reason>" and no model call."""
        from services.files.intake import InboundFile
        from services.files.limits import UPLOAD
        from services.files.messages import too_large
        from services.files.prompting import sanitize_display_name

        channel = message.channel
        started = False
        try:
            async with self._lock:
                started = True
                assert self.chat is not None
                gate = getattr(self.chat, "file_gate", None)
                refusal = await gate() if callable(gate) else None
                if refusal is None and not takes_keyword(self.chat, "files"):
                    refusal = "This app can't read files yet."
                if refusal is not None:
                    await self._post_text(channel, f"⚠️ {refusal}"[:TEXT_CHUNK])
                    return
                first = sanitize_display_name(message.files[0].name)
                line = f"📄 Reading {first}…" if len(message.files) == 1 else f"📄 Reading {len(message.files)} files…"
                await self._post_text(channel, line[:200])
                files: list[Any] = []
                for shared in message.files:
                    name = sanitize_display_name(shared.name)
                    if shared.size is not None and shared.size > UPLOAD.max_bytes:
                        await self._post_text(
                            channel, f"⚠️ I couldn't read {name}: {too_large(shared.size, UPLOAD.max_bytes)}"[:TEXT_CHUNK]
                        )
                        return
                    try:
                        body = await self._connector._request_bytes(
                            "GET", shared.url, max_bytes=UPLOAD.max_bytes
                        )
                    except ConnectorError as exc:
                        logger.warning("slack_file_download_failed", error_type=type(exc).__name__)
                        await self._post_text(
                            channel, f"⚠️ I couldn't read {name}: Slack did not hand the file over."[:TEXT_CHUNK]
                        )
                        return
                    if body.truncated:
                        await self._post_text(
                            channel, f"⚠️ I couldn't read {name}: {too_large(None, UPLOAD.max_bytes)}"[:TEXT_CHUNK]
                        )
                        return
                    files.append(
                        InboundFile(name=name, media_type=shared.mimetype, data=body.content, source="slack")
                    )
                progress = self._progress(channel)
                try:
                    listen: dict[str, Any] = (
                        {"on_event": progress.on_event} if takes_on_event(self.chat) else {}
                    )
                    if takes_keyword(self.chat, "stop_mark"):
                        listen["stop_mark"] = stop_mark
                    outcome = await self.chat(
                        self.user_id, message.text, new_conversation=fresh, files=files, **listen
                    )
                except asyncio.CancelledError:
                    raise
                except Exception as exc:
                    logger.error(
                        "slack_chat_failed", connector_id=self.connector_id, error_type=type(exc).__name__
                    )
                    outcome = {"error": "The assistant hit an unexpected error."}
                finally:
                    await progress.aclose()
                if outcome.get("error"):
                    await self._post_text(channel, f"⚠️ {outcome['error']}"[:TEXT_CHUNK])
                    return
                reply = _with_turn_notes(str(outcome.get("content") or "").strip(), outcome)
                await self._send_reply(channel, reply or "(The assistant returned no text.)", outcome)
        except asyncio.CancelledError:
            if fresh and not started:
                self._fresh = True
            raise

    async def _link_sender(self, sender: str, text: str) -> bool:
        """Link *sender* to this connector if *text* is still the pending
        code, detaching that Slack user from any other connector in the same
        transaction. The code dies the moment it links."""
        assert self.team_id is not None
        async with self._session_factory() as session:
            link = await session.get(SlackChannelLink, self._connector_uuid, with_for_update=True)
            if link is None or not code_matches(link, text):
                return False
            await session.execute(
                update(SlackChannelLink)
                .where(
                    SlackChannelLink.team_id == self.team_id,
                    SlackChannelLink.slack_user_id == sender,
                    SlackChannelLink.connector_id != self._connector_uuid,
                )
                .values(team_id=None, slack_user_id=None, linked_at=None)
            )
            link.team_id = self.team_id
            link.slack_user_id = sender
            link.link_code_hash = None
            link.link_expires_at = None
            link.linked_at = datetime.now(timezone.utc)
            await session.commit()
        logger.info("slack_channel_linked", connector_id=self.connector_id)
        return True

    async def _on_interactive(self, payload: Any) -> None:
        press = self.authorize_press(payload)
        if press is None:
            return
        link = await self._load_link()
        if not self._is_linked_sender(link, press.sender):
            logger.info("slack_press_from_unlinked_user_refused", connector_id=self.connector_id)
            return
        if self.decide is None:
            logger.warning("slack_decision_unavailable", connector_id=self.connector_id)
            return
        self._track(self._run_decision(press), f"slack-decision-{self.connector_id[:8]}")

    # ── chat ─────────────────────────────────────────────────────────────

    def _handle_chat(self, channel: str, text: str) -> None:
        if self.chat is None:
            logger.warning("slack_chat_unavailable", connector_id=self.connector_id)
            return
        fresh, self._fresh = self._fresh, False
        # Accepted now: a stop from here on ends this message's turn too.
        stop_mark = agent_cancel.mark(self.user_id)
        self._track(
            self._run_chat(channel, text, fresh, stop_mark), f"slack-chat-{self.connector_id[:8]}"
        )

    async def _run_chat(self, channel: str, text: str, fresh: bool, stop_mark: int) -> None:
        started = False
        try:
            async with self._lock:
                started = True
                # A key, card or ID number in the person's own message: the
                # model never sees it, but Slack keeps the message.
                warning = secret_text.inbound_warning(text, app="Slack")
                if warning is not None:
                    await self._post_text(channel, warning)
                progress = self._progress(channel)
                try:
                    assert self.chat is not None
                    listen: dict[str, Any] = (
                        {"on_event": progress.on_event} if takes_on_event(self.chat) else {}
                    )
                    if takes_keyword(self.chat, "stop_mark"):
                        listen["stop_mark"] = stop_mark
                    outcome = await self.chat(self.user_id, text, new_conversation=fresh, **listen)
                except asyncio.CancelledError:
                    raise
                except Exception as exc:
                    logger.error(
                        "slack_chat_failed",
                        connector_id=self.connector_id,
                        error_type=type(exc).__name__,
                    )
                    outcome = {"error": "The assistant hit an unexpected error."}
                finally:
                    await progress.aclose()
                if outcome.get("error"):
                    await self._post_text(channel, f"⚠️ {outcome['error']}"[:TEXT_CHUNK])
                    return
                reply = _with_turn_notes(str(outcome.get("content") or "").strip(), outcome)
                await self._send_reply(
                    channel, reply or "(The assistant returned no text.)", outcome
                )
        except asyncio.CancelledError:
            if fresh and not started:
                # Stopped while queued: keep the unused "new" for next time.
                self._fresh = True
            raise

    def _progress(self, channel: str) -> TurnProgress:
        return TurnProgress(lambda line: self._post_text(channel, line))

    async def _send_reply(self, channel: str, text: str, outcome: dict[str, Any]) -> None:
        """Send *text* in Slack-sized, paced parts, the turn's usage line last.
        The reply is masked whole before it is split (a value never straddles
        two messages), with one footer when anything was hidden."""
        text = secret_text.mask_reply(text, app="Slack", channel="slack")
        line = cards.usage_line(outcome)
        if line:
            text = f"{text}\n\n{line}"
        for index, part in enumerate(cards.split_text(text, max_chars=TEXT_CHUNK)):
            if index:
                await self._sleep(POST_INTERVAL_S)
            await self._post_text(channel, part)

    async def _handle_stop(self, channel: str) -> None:
        """Cancel this channel's running turn and anything queued behind it,
        and request a stop for the account (services.agent.cancel), as
        Telegram's /stop does."""
        agent_cancel.request_cancel(self.user_id)
        running = [t for t in self._work if not t.done()]
        if not running:
            await self._post_text(
                channel, "Nothing is running right now." + await self._waiting_cards_note()
            )
            return
        for task in running:
            task.cancel()
        _, lingering = await asyncio.wait(running, timeout=STOP_WAIT_S)
        logger.info(
            "slack_stop",
            connector_id=self.connector_id,
            cancelled=len(running),
            lingering=len(lingering),
        )
        head = (
            "⏹ Stopped. Nothing more will be sent for that request."
            if not lingering
            else "⏹ Stopping. Nothing more will be sent for that request."
        )
        await self._post_text(channel, head + await self._waiting_cards_note())

    async def _waiting_cards_note(self) -> str:
        from services.agent.approvals import DbApprovalStore

        try:
            waiting = len(await DbApprovalStore(self._session_factory).list_pending(self.user_id))
        except Exception as exc:
            logger.warning("slack_stop_pending_lookup_failed", error_type=type(exc).__name__)
            return ""
        return cards.waiting_cards_note(waiting, pending_hint=_PENDING_HINT)

    async def _handle_pending(self, channel: str) -> None:
        """Re-send every approval still waiting on this account."""
        from services.agent.approvals import DbApprovalStore

        pending = await DbApprovalStore(self._session_factory).list_pending(self.user_id)
        if not pending:
            await self._post_text(channel, cards.NOTHING_PENDING_TEXT)
            return
        for action in pending:
            await self.notify_pending(action)

    # ── decisions ────────────────────────────────────────────────────────

    async def _run_decision(self, press: ButtonPress) -> None:
        async with self._lock:
            await self._apply_decision(press)

    async def _apply_decision(self, press: ButtonPress) -> None:
        """Apply one press through the decision applier (the web UI's
        pipeline: ownership, single use, expiry, re-scan, resume), then
        freeze the card and send the resumed turn's reply."""
        assert self.decide is not None
        progress: Optional[TurnProgress] = None
        listen: dict[str, Any] = {}
        if press.approved:
            progress = self._progress(press.channel)
            if takes_on_event(self.decide):
                listen = {"on_event": progress.on_event}
            if press.remember and takes_keyword(self.decide, "remember"):
                listen["remember"] = press.remember
        try:
            outcome = await self.decide(self.user_id, press.action_id, press.approved, **listen)
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            logger.error(
                "slack_decision_failed",
                connector_id=self.connector_id,
                action_id=press.action_id,
                error_type=type(exc).__name__,
            )
            outcome = {"error": "Could not apply that decision. See the server logs."}
        finally:
            if progress is not None:
                await progress.aclose()
        logger.info(
            "slack_decision_applied",
            connector_id=self.connector_id,
            action_id=press.action_id,
            approved=press.approved,
            outcome=str(outcome.get("status") or outcome.get("error"))[:80],
        )
        if outcome.get("error"):
            await self._post_text(press.channel, "⚠️ " + str(outcome["error"])[:180])
            return
        verdict = "✅ Approved" if press.approved else "❌ Denied"
        low_risk = outcome.get("low_risk")
        if isinstance(low_risk, dict) and low_risk.get("account"):
            verdict += f" · low-risk allowed until {_day(low_risk.get('expires_at'))}"
        elif press.approved and press.remember == _REMEMBER_LOW_RISK:
            verdict += " (approved once)"
        await self._freeze_card(press, verdict)
        summary = outcome.get("summary")
        if summary:
            await self._send_reply(press.channel, _with_turn_notes(str(summary), outcome), outcome)

    async def _freeze_card(self, press: ButtonPress, verdict: str) -> None:
        """Replace the buttons with the decision so the card cannot be
        pressed twice from the DM history."""
        blocks = [block for block in press.blocks if block.get("type") != "actions"][:48]
        blocks.append(
            {
                "type": "context",
                "elements": [{"type": "plain_text", "text": f"{verdict} from Slack."}],
            }
        )
        try:
            await self._connector._call(
                "chat.update",
                http="POST",
                json_body={
                    "channel": press.channel,
                    "ts": press.message_ts,
                    "text": f"Approval request: {verdict}",
                    "blocks": blocks,
                },
                action="freeze_card",
            )
        except ConnectorError as exc:
            logger.warning(
                "slack_card_freeze_failed", connector_id=self.connector_id, error=str(exc)[:200]
            )

    # ── outbound ─────────────────────────────────────────────────────────

    async def _post(
        self, channel: str, text: str, blocks: Optional[list[dict[str, Any]]] = None
    ) -> Optional[dict[str, Any]]:
        """chat.postMessage through the connector's one choke point (link and
        media unfurling forced off). None on failure (logged, never raised):
        a Slack outage degrades to no message, never breaks a flow. Any key,
        password, card, bank or ID number in the text and in every plain_text
        block is masked first (services.security, policy CHANNEL)."""
        text = secret_text.mask_text(text, channel="slack")[0]
        body: dict[str, Any] = {"channel": channel, "text": text}
        if blocks is not None:
            body["blocks"] = secret_text.mask_blocks(blocks, channel="slack")
        try:
            return await self._connector._send_chat("chat.postMessage", body, "dm_message")
        except ConnectorError as exc:
            logger.warning(
                "slack_post_failed", connector_id=self.connector_id, error=str(exc)[:200]
            )
            return None

    async def _post_text(self, channel: str, text: str) -> Optional[dict[str, Any]]:
        return await self._post(channel, slack_escape(text))

    async def _post_card_part(self, channel: str, text: str) -> bool:
        head = slack_escape(text.split("\n", 1)[0][:150])
        return await self._post(channel, head, [_section(text)]) is not None

    async def _linked_dm(self) -> Optional[str]:
        """The DM channel of the linked Slack user, or None when nobody is
        linked (or the channel is not connected to its workspace yet)."""
        link = await self._load_link()
        if (
            link is None
            or link.slack_user_id is None
            or not self._is_linked_sender(link, link.slack_user_id)
        ):
            return None
        sender = link.slack_user_id
        known = self._dm_channels.get(sender)
        if known is not None:
            return known
        try:
            data = await self._connector._call(
                "conversations.open", http="POST", json_body={"users": sender}, action="open_dm"
            )
        except ConnectorError as exc:
            logger.warning(
                "slack_open_dm_failed", connector_id=self.connector_id, error=str(exc)[:200]
            )
            return None
        info = data.get("channel")
        channel = info.get("id") if isinstance(info, dict) else None
        if not (isinstance(channel, str) and _DM_CHANNEL_RE.fullmatch(channel)):
            logger.warning("slack_open_dm_malformed", connector_id=self.connector_id)
            return None
        self._dm_channels[sender] = channel
        return channel

    async def send_text(self, user_id: str, text: str) -> bool:
        """Push a plain message (a reminder) to the owner's linked DM. False
        when *user_id* is not this channel's owner or nobody is linked."""
        if str(user_id) != self.user_id or not self.running:
            return False
        channel = await self._linked_dm()
        if channel is None:
            return False
        # Masked before it is cut, so a value is never cut in half.
        text = secret_text.mask_text(text, channel="slack")[0]
        return await self._post_text(channel, text[:3500]) is not None

    async def notify_pending(self, action: Any) -> bool:
        """Push an approval card for *action* (a StoredAction) to the owner's
        linked DM: every argument in full, split into paced parts when long,
        the Approve and Deny buttons on the last. True when the buttons went
        out. Never raises."""
        try:
            if str(action.user_id) != self.user_id or not self.running:
                return False
            channel = await self._linked_dm()
            if channel is None:
                return False
            lines = [
                "\U0001f510 Approval required",
                "",
                f"Tool: {action.tool_name}",
                f"Why: {action.reason}",
            ]
            if getattr(action, "risk_note", None):
                lines += ["", f"⚠️ {action.risk_note}"]
            # A LOW action's card may offer "Allow low-risk on <account>".
            low_risk_account = cards.low_risk_account(action)
            card = cards.layout_card(
                lines,
                cards.card_arguments(action.tool_name, action.arguments or {}),
                tool_name=str(action.tool_name),
                max_chars=SECTION_CHARS,
            )

            async def send_part(text: str) -> bool:
                return await self._post_card_part(channel, text)

            async with self._card_lock:
                ready = await cards.send_card_parts(
                    card,
                    send_part,
                    retry_hint="Send pending to get it again, or decide in the web app.",
                )
                if not ready:
                    logger.warning(
                        "slack_approval_card_withheld",
                        action_id=action.action_id,
                        parts=card.parts,
                        oversized=card.notice is not None,
                    )
                    return False
                closing = [*card.final_lines, "", f"Expires in {cards.expires_in_text(action.expires_at)}."]
                if low_risk_account:
                    closing += ["", _low_risk_line(action, low_risk_account)]
                text = "\n".join(closing)
                posted = await self._post(
                    channel,
                    slack_escape(f"Approval required: {action.tool_name}"),
                    [_section(text), _decision_buttons(str(action.action_id), low_risk_account)],
                )
            return posted is not None
        except Exception as exc:  # a notification failure never breaks the flow
            logger.warning(
                "slack_notify_failed", connector_id=self.connector_id, error_type=type(exc).__name__
            )
            return False


def _low_risk_line(action: Any, account: str) -> str:
    """What a card that offers a low-risk grant says about it."""
    from services.agent.risk import low_risk_notes_for_tool

    return cards.low_risk_line(
        account,
        low_risk_notes_for_tool(action.tool_name),
        how='Send "grants" to list them, or "revoke grants" to turn them all off.',
    )


def _day(when: Any) -> str:
    """A date as the DM shows it ("Fri Oct 2"), in this computer's zone."""
    try:
        moment = when if isinstance(when, datetime) else datetime.fromisoformat(str(when))
        if moment.tzinfo is None:
            moment = moment.replace(tzinfo=timezone.utc)
        local = moment.astimezone()
    except (TypeError, ValueError):
        return str(when)
    return f"{local:%a} {local:%b} {local.day}"


_LINKED_TEXT = (
    "✅ Linked. Crawler will chat with you here, and send approval requests "
    "with Approve and Deny buttons. Send stop to end a running request, new to start "
    "a fresh conversation, or pending to see what waits for your approval."
)


def _parse_frame(raw: Any) -> Optional[dict[str, Any]]:
    """One Socket Mode frame as a dict, or None for anything else."""
    if isinstance(raw, (bytes, bytearray)):
        try:
            raw = bytes(raw).decode("utf-8")
        except UnicodeDecodeError:
            return None
    if not isinstance(raw, str):
        return None
    try:
        frame = json.loads(raw)
    except ValueError:
        return None
    return frame if isinstance(frame, dict) else None
