"""Keeps one running Slack DM channel per active Slack connector that has an
app-level token, and routes approval cards and reminders to the right one.

Why it exists: Slack channel tokens live on each user's Slack connector, which
users create, edit and delete at runtime, and the owner can switch the "slack"
capability off. ``reconcile()`` (at startup, after a connector change and after
a capability change) makes the running channels match the database; main.py
wires the approval store and the reminder sweeper to this manager once, and its
proxies are no-ops while nothing runs.

Connects to services/notifications/slack.py (SlackChannel), the
``connector_configs`` table (models/connector.py) and core/security (credential
decryption). Talks to Slack only through the channels it starts.

One socket per Slack app: Slack hands each Socket Mode event to ANY one open
connection of the app, so two sockets for one app split its DMs and button
presses at random, and a channel drops what belongs to another connector's
user as coming from an unlinked sender. Connectors that share an app-level
token (or a bot token, which pins the same app installation) are therefore
grouped: only one of them runs a channel (the one already running, else the
oldest), and the others report ``app_token_in_use`` through
``channel_problem()`` so the connector card can say why. Use one Slack app per
Crawler user for DMs. (Two app-level tokens of one app pasted with two
different bot tokens cannot be told apart here and would still split.)

Single-process note: channels, their locks and the reconcile lock live in this
process. For the same reason as above, two processes (or two deployments)
running the same connector would each receive a random share of the DMs and
button presses. Run one backend process per install, as the production image
and native install do.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Awaitable, Callable, Optional

import structlog
from sqlalchemy import select

from core.security import decrypt_credentials
from models.connector import ConnectorConfig
from models.user import User
from services.connectors.slack_api.client import TOKEN_PREFIXES
from services.notifications.slack import SlackChannel

logger = structlog.get_logger(__name__)

SLACK_CONNECTOR_TYPE = "slack"

# channel_problem() code for a connector whose Slack app already has a
# channel running for another connector (see the module docstring).
PROBLEM_APP_TOKEN_IN_USE = "app_token_in_use"

EnabledCheck = Callable[[], Awaitable[bool]]

_EPOCH = datetime.min.replace(tzinfo=timezone.utc)


def _digest(*parts: str) -> str:
    return hashlib.sha256("\0".join(parts).encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class _Desired:
    connector_id: str
    user_id: str
    bot_token: str
    app_token: str
    created_at: datetime = _EPOCH

    @property
    def fingerprint(self) -> str:
        """Identity of a channel: owner and both tokens. Any change restarts
        it. A digest, so the tokens are not kept twice in memory as keys."""
        return _digest(self.user_id, self.bot_token, self.app_token)

    @property
    def app_keys(self) -> tuple[str, str]:
        """Digests naming the Slack app this connector's socket joins: its
        app-level token and its bot token (one installation of one app)."""
        return _digest("app", self.app_token), _digest("bot", self.bot_token)


def _as_utc(value: Any) -> datetime:
    if not isinstance(value, datetime):
        return _EPOCH
    return value if value.tzinfo is not None else value.replace(tzinfo=timezone.utc)


async def _always_enabled() -> bool:
    return True


def _token(credentials: dict[str, Any], key: str) -> Optional[str]:
    value = credentials.get(key)
    if not isinstance(value, str):
        return None
    value = value.strip()
    return value if value.startswith(TOKEN_PREFIXES[key]) else None


class SlackManager:
    """Starts, restarts and stops SlackChannels to match the database."""

    def __init__(
        self,
        session_factory: Callable[[], Any],
        *,
        on_start: Optional[Callable[[SlackChannel], None]] = None,
        channel_factory: Callable[..., SlackChannel] = SlackChannel,
        enabled: EnabledCheck = _always_enabled,
        on_change: Optional[Callable[[], None]] = None,
    ) -> None:
        self._session_factory = session_factory
        self._on_start = on_start
        self._factory = channel_factory
        self._enabled = enabled
        self._on_change = on_change
        self.channels: dict[str, SlackChannel] = {}
        self._fingerprints: dict[str, str] = {}
        # Connectors held back because their Slack app already has a
        # channel: connector id -> the id of the connector that runs it.
        self._shadowed: dict[str, str] = {}
        # Serializes reconcile()/stop(): two overlapping reconciles could
        # both start a channel for one connector and leak the loser's socket.
        self._lock = asyncio.Lock()
        self._scheduled: set[asyncio.Task[None]] = set()
        self._closed = False

    # ── state ────────────────────────────────────────────────────────────

    @property
    def is_running(self) -> bool:
        """True while at least one channel's socket loop runs."""
        return any(channel.running for channel in self.channels.values())

    def channel_running(self, connector_id: str) -> bool:
        channel = self.channels.get(str(connector_id))
        return channel is not None and channel.running

    def channel_problem(self, connector_id: str) -> Optional[str]:
        """Why *connector_id*'s channel is not serving DMs, as a short code:
        ``app_token_in_use`` (another connector's channel already uses its
        Slack app), or the running channel's last connection error
        (``socket_refused``, ``auth_failed``, ``connect_failed``) until Slack
        greets it. None when there is nothing to report."""
        key = str(connector_id)
        if key in self._shadowed:
            return PROBLEM_APP_TOKEN_IN_USE
        channel = self.channels.get(key)
        if channel is None or getattr(channel, "connected", False):
            return None
        error = getattr(channel, "last_error", None)
        return error if isinstance(error, str) else None

    # ── reconcile ────────────────────────────────────────────────────────

    def _one_per_app(self, candidates: list[_Desired]) -> dict[str, _Desired]:
        """Keep one connector per Slack app (module docstring): the one whose
        channel already runs unchanged, else the oldest, ties by id. The
        rest are recorded in ``_shadowed`` and logged once."""

        def rank(want: _Desired) -> tuple[int, datetime, str]:
            channel = self.channels.get(want.connector_id)
            unchanged = (
                channel is not None
                and channel.running
                and self._fingerprints.get(want.connector_id) == want.fingerprint
            )
            return (0 if unchanged else 1, want.created_at, want.connector_id)

        owners: dict[str, str] = {}
        desired: dict[str, _Desired] = {}
        shadowed: dict[str, str] = {}
        for want in sorted(candidates, key=rank):
            taken = next((owners[k] for k in want.app_keys if k in owners), None)
            if taken is not None:
                shadowed[want.connector_id] = taken
                continue
            for key in want.app_keys:
                owners[key] = want.connector_id
            desired[want.connector_id] = want
        for connector_id, owner in shadowed.items():
            if self._shadowed.get(connector_id) != owner:
                logger.warning(
                    "slack_manager_app_token_in_use",
                    connector_id=connector_id,
                    channel_connector_id=owner,
                )
        self._shadowed = shadowed
        return desired

    async def _desired(self) -> dict[str, _Desired]:
        """Every active Slack connector of an active user that has a bot and
        an app-level token, one per Slack app, in ONE query. Links are not
        loaded here: a channel reads its link on every inbound message, so a
        new code or an unlink applies at once without a reconcile."""
        async with self._session_factory() as session:
            rows = (
                await session.execute(
                    select(
                        ConnectorConfig.id,
                        ConnectorConfig.user_id,
                        ConnectorConfig.encrypted_credentials,
                        ConnectorConfig.created_at,
                    )
                    .join(User, User.id == ConnectorConfig.user_id)
                    .where(
                        ConnectorConfig.connector_type == SLACK_CONNECTOR_TYPE,
                        ConnectorConfig.is_active.is_(True),
                        User.is_active.is_(True),
                    )
                )
            ).all()
        candidates: list[_Desired] = []
        for connector_id, user_id, blob, created_at in rows:
            try:
                credentials = json.loads(decrypt_credentials(blob))
            except Exception as exc:
                logger.warning(
                    "slack_manager_credentials_unreadable",
                    connector_id=str(connector_id),
                    error_type=type(exc).__name__,
                )
                continue
            if not isinstance(credentials, dict):
                continue
            bot, app = _token(credentials, "bot_token"), _token(credentials, "app_token")
            if bot and app:
                candidates.append(
                    _Desired(str(connector_id), str(user_id), bot, app, _as_utc(created_at))
                )
        return self._one_per_app(candidates)

    async def reconcile(self) -> dict[str, list[str]]:
        """Make the running channels match the database: start missing ones,
        restart any whose tokens or owner changed (or whose loop died), stop
        the rest. Everything stops while the "slack" capability is off.
        Returns the connector ids per outcome."""
        summary: dict[str, list[str]] = {"started": [], "restarted": [], "stopped": []}
        async with self._lock:
            if self._closed:
                return summary
            if await self._enabled():
                desired = await self._desired()
            else:
                desired, self._shadowed = {}, {}
            for connector_id in list(self.channels):
                want = desired.get(connector_id)
                channel = self.channels[connector_id]
                if (
                    want is not None
                    and self._fingerprints.get(connector_id) == want.fingerprint
                    and channel.running
                ):
                    continue
                await self._stop_channel(connector_id)
                if want is None:
                    summary["stopped"].append(connector_id)
            for connector_id, want in desired.items():
                if connector_id in self.channels:
                    continue
                restarted = connector_id in self._fingerprints
                self._fingerprints.pop(connector_id, None)
                if await self._start_channel(want):
                    summary["restarted" if restarted else "started"].append(connector_id)
            # Forget identities of channels that are gone for good.
            for connector_id in list(self._fingerprints):
                if connector_id not in self.channels:
                    del self._fingerprints[connector_id]
        if any(summary.values()):
            logger.info("slack_manager_reconciled", **{k: len(v) for k, v in summary.items()})
            if self._on_change is not None:
                self._on_change()
        return summary

    async def _start_channel(self, want: _Desired) -> bool:
        channel = self._factory(
            connector_id=want.connector_id,
            user_id=want.user_id,
            bot_token=want.bot_token,
            app_token=want.app_token,
            session_factory=self._session_factory,
        )
        try:
            if self._on_start is not None:
                self._on_start(channel)
            await channel.start()
        except Exception as exc:
            logger.warning(
                "slack_manager_start_failed",
                connector_id=want.connector_id,
                error_type=type(exc).__name__,
            )
            try:
                await channel.stop()
            except Exception as cleanup_exc:
                logger.warning(
                    "slack_manager_start_cleanup_failed",
                    connector_id=want.connector_id,
                    error_type=type(cleanup_exc).__name__,
                )
            return False
        self.channels[want.connector_id] = channel
        self._fingerprints[want.connector_id] = want.fingerprint
        return True

    async def _stop_channel(self, connector_id: str) -> None:
        channel = self.channels.pop(connector_id, None)
        if channel is None:
            return
        try:
            await channel.stop()
        except Exception as exc:
            logger.warning(
                "slack_manager_stop_failed",
                connector_id=connector_id,
                error_type=type(exc).__name__,
            )

    def schedule_reconcile(self) -> Optional[asyncio.Task[None]]:
        """Reconcile in the background (after a connector change): the
        request that changed the connector never waits on Slack. Failures
        are logged."""
        if self._closed:
            return None

        async def run() -> None:
            try:
                await self.reconcile()
            except Exception as exc:
                logger.warning("slack_manager_reconcile_failed", error_type=type(exc).__name__)

        task = asyncio.get_running_loop().create_task(run(), name="slack-reconcile")
        self._scheduled.add(task)
        task.add_done_callback(self._scheduled.discard)
        return task

    async def wait_idle(self) -> None:
        """Wait for scheduled reconciles (tests)."""
        while self._scheduled:
            await asyncio.gather(*list(self._scheduled), return_exceptions=True)

    async def stop(self) -> None:
        """Stop every channel; later reconciles do nothing (app shutdown)."""
        self._closed = True
        for task in list(self._scheduled):
            task.cancel()
        if self._scheduled:
            await asyncio.wait(list(self._scheduled))
        async with self._lock:
            had_channels = bool(self.channels)
            for connector_id in list(self.channels):
                await self._stop_channel(connector_id)
            self._fingerprints.clear()
            self._shadowed.clear()
        if had_channels:
            logger.info("slack_manager_stopped")
            if self._on_change is not None:
                self._on_change()

    # ── routing ──────────────────────────────────────────────────────────

    def _channels_of(self, user_id: Any) -> list[SlackChannel]:
        owner = str(user_id)
        return [c for c in self.channels.values() if c.user_id == owner and c.running]

    async def notify_pending(self, action: Any) -> None:
        """Push an approval card to each of the action owner's running
        channels. One channel failing never stops another."""
        for channel in self._channels_of(getattr(action, "user_id", None)):
            try:
                await channel.notify_pending(action)
            except Exception as exc:
                logger.warning(
                    "slack_manager_notify_failed",
                    connector_id=channel.connector_id,
                    error_type=type(exc).__name__,
                )

    async def send_text(self, user_id: str, text: str) -> bool:
        """Send a reminder to each of the user's running channels; True when
        at least one delivered."""
        delivered = False
        for channel in self._channels_of(user_id):
            try:
                delivered = (await channel.send_text(user_id, text)) is True or delivered
            except Exception as exc:
                logger.warning(
                    "slack_manager_send_failed",
                    connector_id=channel.connector_id,
                    error_type=type(exc).__name__,
                )
        return delivered
