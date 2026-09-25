"""Runs the Telegram bot: long-polls updates, serves only the linked
Telegram account, turns its messages into agent turns (short progress
lines while one runs, each reply ending with that turn's token and cost
line), handles /stop, links accounts by one-time code, pushes approval
cards, and applies Approve/Deny presses through the shared decision
pipeline.

Why it exists: Approvals must be decidable away from a computer and without a
public webhook URL; the Telegram manager starts this service, and
NotifyingApprovalStore wraps the approval store so every pending action is
pushed.

Connects to: the Telegram Bot API (httpx long polling and sends), the
User table (links), the chat and decision appliers from
api/routes/agent.py, the approval store, services/usage (cost line and
/usage), the progress lines in services/notifications/progress.py and the
stop requests in services/agent/cancel.py.
Used by: TelegramManager, which starts and stops it; main.py wires its
appliers; reminders and approval notifications send through it.

Telegram delivery for the human-approval flow.

When a pending action is created, the linked user gets a Telegram message
with Approve/Deny buttons; pressing one applies the SAME decision pipeline
as the web UI (ownership, single-use, expiry, argument re-scan, transcript
message, resumed agent turn). The user never has to be at a computer.

Design notes:

- Long polling (``getUpdates``), not webhooks: a self-hosted install has no
  public URL, and polling works from behind any NAT. One background task,
  started from the app lifespan.
- Linking is one-time-code based: the Settings page mints a short-lived
  code and shows ``https://t.me/<bot>?start=<code>``; the /start message
  the bot receives proves control of both the Crawler AI session (which
  minted the code) and the Telegram account (which sent it). Chat ids are
  never accepted from user input.
- Only the linked Telegram account is served. Every inbound message and
  button press must come from a private chat whose sender IS that chat
  (``from.id == chat.id``), and that chat must be linked to an active
  account; anything else is dropped before any lookup beyond the one that
  proves it, with no reply. A group can therefore never be linked, and a
  second person can never act through someone else's chat.
- Only the linked chat can decide an approval, and the decision callback
  re-checks ownership server-side (the store scopes by user_id).
- Each chat's in-flight work (agent turns and approval decisions) runs as
  tracked tasks, so /stop can cancel exactly that chat's work.
- The bot token is a server-wide secret from the environment; it is never
  sent to the frontend. Requests go only to https://api.telegram.org.
- Every network call is wrapped: a Telegram outage degrades to "no push
  notification" and never breaks the approval flow itself (the web UI
  keeps working).
"""

from __future__ import annotations

import asyncio
import base64
import json
import secrets
import time
import uuid as uuid_module
from datetime import datetime, timedelta, timezone
from typing import Any, Awaitable, Callable, Coroutine, Optional

import httpx
import structlog
from sqlalchemy import select, update

from services.agent import cancel as agent_cancel
from services.notifications.progress import TurnProgress, takes_keyword, takes_on_event

logger = structlog.get_logger(__name__)

# How long a /start link code stays valid. Short: it is single-use and the
# user taps it within seconds of the Settings page showing it.
LINK_CODE_TTL_MINUTES = 10

# callback_data prefixes (Telegram caps callback_data at 64 bytes; a uuid
# is 36 chars, so prefix + uuid fits comfortably).
_CB_APPROVE = "apv:"
_CB_DENY = "dny:"

# Decision callback signature: (user_id, action_id, approved) -> outcome
# dict with at least {"status": "approved"|"denied"} or {"error": str}.
DecideCallback = Callable[[str, str, bool], Awaitable[dict[str, Any]]]

# Chat callback signature: (user_id, text, new_conversation=...) -> outcome
# dict with "content" (and "pending_approvals"/"blocked") or {"error": str}.
ChatCallback = Callable[..., Awaitable[dict[str, Any]]]

# Telegram rejects messages over 4096 chars; leave headroom for the
# continuation marker.
_MESSAGE_CHUNK = 3900

# Bot API methods whose text Telegram may decorate with a link preview. A
# preview is a card the reader did not ask for, and Telegram's servers fetch
# the URL at once: a reply built from a page the agent read can carry a URL
# with private data (spec §9). Disabled for these in _api, the one place
# every text send and edit goes through.
_TEXT_METHODS = frozenset({"sendMessage", "editMessageText"})

# How long /stop waits for the cancelled work to finish unwinding before it
# answers, and stopping the bot before it closes its client. Unwinding is an
# aborted HTTP request plus one DB write, so this is a ceiling for a wedged
# tool, not an expected wait.
_STOP_WAIT_S = 10.0

# Telegram serves a bot token's getUpdates to one poller at a time and
# answers the other with 409. Every retry from this side terminates the
# other side's long poll, so retrying on the normal 5s cadence keeps the
# two deployments splitting updates at random. Backing off to a ceiling
# lets the other instance keep the token while still noticing, within
# minutes, when it goes away.
_CONFLICT_BACKOFF_INITIAL_S = 15.0
_CONFLICT_BACKOFF_MAX_S = 300.0
# A conflict that persists is re-announced at most this often: visible in
# the logs without a line per retry.
_CONFLICT_REWARN_S = 3600.0


class _PollerConflict(Exception):
    """getUpdates answered 409: something else is consuming this bot's
    updates (another poller, or a webhook set on the token)."""


def _short_json(data: dict[str, Any], limit: int = 700) -> str:
    try:
        text = json.dumps(data, indent=2, default=str)
    except (TypeError, ValueError):
        text = str(data)
    return text if len(text) <= limit else text[: limit - 1] + "…"


def _card_arguments(tool_name: Any, arguments: Any) -> dict[str, Any]:
    """A call's arguments as its approval card shows them. A desktop.act
    card also stores the screen it was made from under a reserved key
    starting with "_" (``services.tools.computer.CARD_KEY``), set by the
    runtime and never by the model (the toolkit refuses any argument no
    action takes), so those keys are left out. Every other tool's arguments
    are shown whole: nothing the owner approves is hidden from the card."""
    if not isinstance(arguments, dict):
        return {}
    if tool_name != "desktop.act":
        return arguments
    return {k: v for k, v in arguments.items() if not str(k).startswith("_")}


def _chunks(text: str, size: int = _MESSAGE_CHUNK) -> list[str]:
    """Split a reply on line boundaries into Telegram-sized messages."""
    if len(text) <= size:
        return [text]
    out: list[str] = []
    current = ""
    for line in text.splitlines(keepends=True):
        if len(current) + len(line) > size and current:
            out.append(current)
            current = ""
        while len(line) > size:
            out.append(line[:size])
            line = line[size:]
        current += line
    if current:
        out.append(current)
    return out


def _own_private_chat(chat: Any, sender: Any) -> Optional[int]:
    """The chat id when ``sender`` is a person writing in their own private
    chat with the bot, else None.

    In a private chat Telegram sets ``chat.id`` to the other party's user
    id, so ``from.id == chat.id`` pins the chat to exactly one Telegram
    account. Groups, channels, bots and anything malformed get None.
    """
    chat = chat if isinstance(chat, dict) else {}
    sender = sender if isinstance(sender, dict) else {}
    chat_id = chat.get("id")
    if chat.get("type") != "private":
        return None
    if not isinstance(chat_id, int) or isinstance(chat_id, bool):
        return None
    if sender.get("is_bot") or sender.get("id") != chat_id:
        return None
    return chat_id


def _usage_line(outcome: dict[str, Any]) -> Optional[str]:
    """The per-reply footer for an outcome that reports its turn's usage,
    else None (see services.usage.format_turn_usage_line)."""
    if not isinstance(outcome.get("usage"), dict):
        return None
    from services.usage import format_turn_usage_line

    return format_turn_usage_line(
        outcome["usage"],
        outcome.get("provider"),
        outcome.get("model"),
        outcome.get("served_model"),
    )


def _expires_in_text(expires_at_iso: str) -> str:
    try:
        expires = datetime.fromisoformat(expires_at_iso)
        if expires.tzinfo is None:
            expires = expires.replace(tzinfo=timezone.utc)
        minutes = max(0, int((expires - datetime.now(timezone.utc)).total_seconds() // 60))
        return f"{minutes} min"
    except (ValueError, TypeError):
        return "a few minutes"


class TelegramService:
    """Poller + sender for approval notifications on Telegram."""

    def __init__(
        self,
        token: str,
        session_factory: Callable[[], Any],
        decide: Optional[DecideCallback] = None,
        chat: Optional[ChatCallback] = None,
    ) -> None:
        self._token = token
        self._session_factory = session_factory
        self.decide: Optional[DecideCallback] = decide
        self.chat: Optional[ChatCallback] = chat
        # Chats that asked for /new; the next message starts a fresh
        # conversation instead of continuing the running one.
        self._fresh_chats: set[int] = set()
        # One turn at a time per chat (messages from a person are ordered),
        # while different chats — and the poll loop itself — keep moving.
        self._chat_locks: dict[int, asyncio.Lock] = {}
        # In-flight work per chat (turns, approval decisions): what /stop
        # cancels, and only ever for the chat that sent it.
        self._chat_tasks: dict[int, set[asyncio.Task[None]]] = {}
        self._client = httpx.AsyncClient(
            base_url=f"https://api.telegram.org/bot{token}",
            timeout=httpx.Timeout(35.0, connect=10.0),
        )
        self._task: Optional[asyncio.Task[None]] = None
        # Set by stop(): no chat work starts from then on.
        self._closing = False
        self._offset: Optional[int] = None
        self._bot_username: Optional[str] = None
        # The poll loop's waits go through here so tests can drive its
        # backoff without real sleeps.
        self._sleep: Callable[[float], Awaitable[None]] = asyncio.sleep
        self._conflict_warned_at: Optional[float] = None

    # ── lifecycle ────────────────────────────────────────────────────────

    async def start(self) -> None:
        self._task = asyncio.create_task(self._poll_loop(), name="telegram-poller")
        logger.info("telegram_poller_started")

    async def stop(self) -> None:
        """Stop polling, then cancel the chats' work and close the client.

        New work is refused first: a started tool call runs to its end
        (runtime._RunsToEnd), and a poll loop still running meanwhile would
        start turns nothing cancels or awaits. The wait for the cancelled
        work is bounded, so a wedged tool cannot hold up the app's shutdown
        or the owner turning Telegram off; whatever is still running then is
        logged and loses the client."""
        self._closing = True
        if self._task is not None:
            self._task.cancel()
            try:
                await self._task
            except (asyncio.CancelledError, Exception):
                pass
            self._task = None
        running = [task for task in self._all_chat_tasks() if not task.done()]
        for task in running:
            task.cancel()
        if running:
            _, lingering = await asyncio.wait(running, timeout=_STOP_WAIT_S)
            if lingering:
                logger.warning(
                    "telegram_stop_left_running",
                    tasks=sorted(task.get_name() for task in lingering),
                )
        await self._client.aclose()

    async def wait_for_chats(self) -> None:
        """Wait for in-flight chat turns (tests, shutdown)."""
        tasks = self._all_chat_tasks()
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)

    def _all_chat_tasks(self) -> list[asyncio.Task[None]]:
        return [task for tasks in self._chat_tasks.values() for task in tasks]

    def _track(self, chat_id: int, coro: Coroutine[Any, Any, None], name: str) -> None:
        """Run one piece of a chat's work as a task /stop can find. Once
        the bot is stopping, the work is dropped instead."""
        if self._closing:
            coro.close()
            logger.info("telegram_chat_work_refused_while_stopping", chat_id=chat_id)
            return
        task = asyncio.create_task(coro, name=name)
        tasks = self._chat_tasks.setdefault(chat_id, set())
        tasks.add(task)

        def forget(done: asyncio.Task[None]) -> None:
            tasks.discard(done)
            if not tasks and self._chat_tasks.get(chat_id) is tasks:
                del self._chat_tasks[chat_id]

        task.add_done_callback(forget)

    # ── Telegram API helpers ─────────────────────────────────────────────

    async def _api(self, method: str, **params: Any) -> Any:
        """Call a Bot API method; None on any failure (logged, never raised).

        Returns the response's ``result`` field verbatim, so the shape is
        method-dependent: a dict for ``getMe``/``sendMessage``, a list for
        ``getUpdates``. Callers narrow before use.

        The one exception is a 409 from ``getUpdates``, raised as
        ``_PollerConflict``: it needs a backoff and a single explanation
        from the poll loop, not a generic warning on every retry.

        Every text send or edit goes out with link previews disabled; this
        is the single choke point, so no reply path can forget it.
        """
        if method in _TEXT_METHODS:
            params.setdefault("link_preview_options", {"is_disabled": True})
        try:
            resp = await self._client.post(f"/{method}", json=params)
            data = resp.json()
            if not data.get("ok"):
                if method == "getUpdates" and data.get("error_code") == 409:
                    raise _PollerConflict(str(data.get("description", ""))[:200])
                logger.warning(
                    "telegram_api_error",
                    method=method,
                    code=data.get("error_code"),
                    description=str(data.get("description", ""))[:200],
                )
                return None
            return data.get("result")
        except _PollerConflict:
            raise
        except Exception as exc:
            logger.warning(
                "telegram_request_failed",
                method=method,
                error=f"{type(exc).__name__}: {exc}",
            )
            return None

    async def _send_photo(self, chat_id: int, data_url: str, caption: str) -> bool:
        """Upload an image (a screenshot the agent took) as a Telegram photo."""
        try:
            header, _, payload = data_url.partition(",")
            media_type = header[len("data:") :].split(";", 1)[0] or "image/jpeg"
            raw = base64.b64decode(payload)
            ext = "png" if media_type.endswith("png") else "jpg"
            resp = await self._client.post(
                "/sendPhoto",
                data={"chat_id": str(chat_id), "caption": caption[:1024]},
                files={"photo": (f"screenshot.{ext}", raw, media_type)},
            )
            data = resp.json()
            if not data.get("ok"):
                logger.warning(
                    "telegram_api_error",
                    method="sendPhoto",
                    code=data.get("error_code"),
                    description=str(data.get("description", ""))[:200],
                )
                return False
            return True
        except Exception as exc:
            logger.warning(
                "telegram_request_failed",
                method="sendPhoto",
                error=f"{type(exc).__name__}: {exc}",
            )
            return False

    async def bot_username(self) -> Optional[str]:
        if self._bot_username is None:
            me = await self._api("getMe")
            if me:
                self._bot_username = me.get("username")
        return self._bot_username

    # ── linking ──────────────────────────────────────────────────────────

    async def create_link_code(self, user_id: str) -> Optional[dict[str, Any]]:
        """Mint a one-time /start code for this user and return the deep
        link. Returns None when the bot is unreachable (no username)."""
        username = await self.bot_username()
        if not username:
            return None
        code = secrets.token_urlsafe(24)
        from models.user import User

        async with self._session_factory() as session:
            user = (
                await session.execute(
                    select(User).where(User.id == uuid_module.UUID(user_id))
                )
            ).scalar_one_or_none()
            if user is None:
                return None
            user.telegram_link_code = code
            user.telegram_link_expires_at = datetime.now(timezone.utc) + timedelta(
                minutes=LINK_CODE_TTL_MINUTES
            )
            await session.commit()
        return {
            "link_url": f"https://t.me/{username}?start={code}",
            "bot_username": username,
            "expires_in_minutes": LINK_CODE_TTL_MINUTES,
        }

    async def unlink(self, user_id: str) -> None:
        from models.user import User

        async with self._session_factory() as session:
            user = (
                await session.execute(
                    select(User).where(User.id == uuid_module.UUID(user_id))
                )
            ).scalar_one_or_none()
            if user is not None:
                user.telegram_chat_id = None
                user.telegram_link_code = None
                user.telegram_link_expires_at = None
                await session.commit()

    async def linked_chat_id(self, user_id: str) -> Optional[int]:
        from models.user import User

        async with self._session_factory() as session:
            user = (
                await session.execute(
                    select(User).where(User.id == uuid_module.UUID(user_id))
                )
            ).scalar_one_or_none()
            return user.telegram_chat_id if user is not None else None

    async def send_text(self, user_id: str, text: str) -> bool:
        """Push a plain message to a user's linked chat. Returns False when
        the user has no linked chat (not an error — the feature is opt-in).
        Used by reminder delivery and any other out-of-band nudge."""
        chat_id = await self.linked_chat_id(user_id)
        if chat_id is None:
            return False
        result = await self._api("sendMessage", chat_id=chat_id, text=text[:3500])
        return result is not None

    # ── outbound: approval notification ──────────────────────────────────

    async def notify_pending(self, action: Any) -> None:
        """Push an approval request to the owner's linked chat (no-op when
        the user has no linked chat). ``action`` is a StoredAction."""
        try:
            chat_id = await self.linked_chat_id(action.user_id)
            if chat_id is None:
                return
            lines = [
                "🔐 Approval required",
                "",
                f"Tool: {action.tool_name}",
                f"Why: {action.reason}",
            ]
            if getattr(action, "risk_note", None):
                lines += ["", f"⚠️ {action.risk_note}"]
            args = _short_json(_card_arguments(action.tool_name, action.arguments or {}))
            if args and args != "{}":
                lines += ["", "Arguments:", args]
            lines += ["", f"Expires in {_expires_in_text(action.expires_at)}."]
            await self._api(
                "sendMessage",
                chat_id=chat_id,
                text="\n".join(lines),
                reply_markup={
                    "inline_keyboard": [
                        [
                            {
                                "text": "✅ Approve",
                                "callback_data": _CB_APPROVE + action.action_id,
                            },
                            {
                                "text": "❌ Deny",
                                "callback_data": _CB_DENY + action.action_id,
                            },
                        ]
                    ]
                },
            )
        except Exception as exc:  # notification failure must never break flow
            logger.warning("telegram_notify_failed", error=str(exc))

    # ── inbound: poll loop ───────────────────────────────────────────────

    async def _poll_loop(self) -> None:
        conflict_delay: Optional[float] = None
        while True:
            try:
                try:
                    updates = await self._api(
                        "getUpdates",
                        timeout=25,
                        offset=self._offset,
                        allowed_updates=["message", "callback_query"],
                    )
                except _PollerConflict as conflict:
                    conflict_delay = (
                        _CONFLICT_BACKOFF_INITIAL_S
                        if conflict_delay is None
                        else min(conflict_delay * 2, _CONFLICT_BACKOFF_MAX_S)
                    )
                    self._warn_poller_conflict(str(conflict), conflict_delay)
                    await self._sleep(conflict_delay)
                    continue
                if not isinstance(updates, list):
                    # None on failure; anything else is a malformed payload.
                    await self._sleep(5)
                    continue
                conflict_delay = None
                for update in updates:
                    self._offset = update["update_id"] + 1
                    try:
                        await self._handle_update(update)
                    except Exception as exc:
                        logger.warning(
                            "telegram_update_failed", error=str(exc)
                        )
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                logger.warning("telegram_poll_failed", error=str(exc))
                await self._sleep(5)

    def _warn_poller_conflict(self, description: str, retry_in: float) -> None:
        now = time.monotonic()
        if (
            self._conflict_warned_at is not None
            and now - self._conflict_warned_at < _CONFLICT_REWARN_S
        ):
            return
        self._conflict_warned_at = now
        logger.warning(
            "telegram_poller_conflict",
            description=description,
            retry_in_seconds=retry_in,
            detail=(
                "Another instance is polling this TELEGRAM_BOT_TOKEN (or, if "
                "the description says so, a webhook is set on it), and "
                "Telegram gives each update to only one poller, so approvals "
                "and chats land on either deployment at random. Only one "
                "running deployment may own a bot: stop the other one or "
                "clear its TELEGRAM_BOT_TOKEN, or give each deployment its "
                "own bot. Polling here backs off meanwhile."
            ),
        )

    async def _handle_update(self, update: dict[str, Any]) -> None:
        # Log every update received. Without this, a button press that never
        # reaches the handler is indistinguishable from one that failed
        # inside it — the difference matters when debugging delivery.
        logger.info(
            "telegram_update_received",
            update_id=update.get("update_id"),
            kinds=sorted(k for k in update if k != "update_id"),
        )
        if "message" in update:
            await self._handle_message(update["message"])
        elif "callback_query" in update:
            await self._handle_callback(update["callback_query"])

    async def _user_for_chat(self, chat_id: Any) -> Optional[str]:
        """The active account a chat is linked to, or None. Linking is the
        only way a chat id ever gets attached, so this is the authorization
        check for every inbound command. A chat that (through data from
        before links were made exclusive) matches more than one account is
        refused rather than guessed."""
        from models.user import User

        if chat_id is None:
            return None
        async with self._session_factory() as session:
            users = (
                (
                    await session.execute(
                        select(User).where(User.telegram_chat_id == chat_id).limit(2)
                    )
                )
                .scalars()
                .all()
            )
        if len(users) != 1:
            if users:
                logger.warning("telegram_chat_linked_to_several_accounts", chat_id=chat_id)
            return None
        user = users[0]
        return str(user.id) if user.is_active else None

    async def _handle_message(self, message: dict[str, Any]) -> None:
        text = (message.get("text") or "").strip()
        # A1, step 1 (no I/O): only a person writing in their own private
        # chat. Group, channel and bot messages are dropped silently.
        chat_id = _own_private_chat(message.get("chat"), message.get("from"))
        if chat_id is None or not text:
            return
        command, _, argument = text.partition(" ")
        # Clients may suffix commands with the bot's name ("/start@bot").
        command = command.split("@", 1)[0].lower()
        if command == "/start":
            # Linking is the one thing an unlinked chat may do: the one-time
            # code proves control of the Crawler AI account.
            await self._handle_start(chat_id, argument.strip())
            return
        # A1, step 2: the chat must be linked to an active account, checked
        # before anything else happens. Anyone else gets no reply at all.
        user_id = await self._user_for_chat(chat_id)
        if user_id is None:
            logger.info("telegram_message_from_unlinked_chat_ignored", chat_id=chat_id)
            return
        if command == "/stop":
            await self._handle_stop(chat_id, user_id)
        elif command == "/pending":
            await self._handle_pending(chat_id, user_id)
        elif command == "/new":
            await self._handle_new(chat_id)
        elif command == "/usage":
            await self._handle_usage(chat_id, user_id)
        elif command.startswith("/"):
            await self._handle_help(chat_id)
        else:
            await self._handle_chat(chat_id, user_id, text)

    async def _handle_stop(self, chat_id: int, user_id: str) -> None:
        """Cancel this chat's running turn, and any messages queued behind
        it. The tasks are cancelled, not asked to finish: provider calls
        abort, nothing further is sent for them, and the transcript records
        the stop. A tool call that has started, or an approval card being
        stored, still finishes and is recorded first (runtime._RunsToEnd).
        Another chat's tasks are never touched.

        A stop is requested for the account too (services.agent.cancel): a
        desktop action runs in a worker thread that task cancellation cannot
        interrupt, and computer control checks the request before every
        step. It ends the account's work accepted before it (a web turn
        included, which then ends as "Stopped.") and nothing later: new work
        takes a fresh mark, so nothing has to lift it. That includes the
        task behind each approval card already waiting: approving the card
        runs its action, then that task ends as "Stopped.", so the reply
        says when cards are waiting."""
        agent_cancel.request_cancel(user_id)
        running = [t for t in self._chat_tasks.get(chat_id, ()) if not t.done()]
        if not running:
            await self._api(
                "sendMessage",
                chat_id=chat_id,
                text="Nothing is running right now." + await self._waiting_cards_note(user_id),
            )
            return
        for task in running:
            task.cancel()
        _, still_running = await asyncio.wait(running, timeout=_STOP_WAIT_S)
        logger.info(
            "telegram_stop", chat_id=chat_id, cancelled=len(running), lingering=len(still_running)
        )
        await self._api(
            "sendMessage",
            chat_id=chat_id,
            text=(
                "⏹ Stopped. Nothing more will be sent for that request."
                if not still_running
                else "⏹ Stopping — nothing more will be sent for that request."
            )
            + await self._waiting_cards_note(user_id),
        )

    async def _waiting_cards_note(self, user_id: str) -> str:
        """What /stop's reply adds when approval cards are waiting on the
        account: the stop also ends each one's task once it is approved
        (services.agent.cancel.mark_since), though the approved action
        itself still runs. Empty when none wait, or when they cannot be
        read: the stop has already been requested either way."""
        from services.agent.approvals import DbApprovalStore

        try:
            waiting = len(await DbApprovalStore(self._session_factory).list_pending(user_id))
        except Exception as exc:
            logger.warning("telegram_stop_pending_lookup_failed", error=str(exc)[:200])
            return ""
        if not waiting:
            return ""
        if waiting == 1:
            return (
                "\n\n1 action is still waiting for your approval (/pending). "
                "Approving it runs that one action; its task stays stopped."
            )
        return (
            f"\n\n{waiting} actions are still waiting for your approval (/pending). "
            "Approving one runs that one action; its task stays stopped."
        )

    async def _handle_pending(self, chat_id: int, user_id: str) -> None:
        """Re-send every approval still waiting on this account, so a card
        that was dismissed, scrolled past, or sent while the phone was off
        can always be recovered from the chat itself."""
        from services.agent.approvals import DbApprovalStore

        pending = await DbApprovalStore(self._session_factory).list_pending(user_id)
        if not pending:
            await self._api(
                "sendMessage",
                chat_id=chat_id,
                text="Nothing is waiting for your approval right now.",
            )
            return
        for action in pending:
            await self.notify_pending(action)

    async def _handle_help(self, chat_id: int) -> None:
        # Only reached for a linked chat (see _handle_message).
        text = (
            "Just type a task or a question and the assistant answers "
            "here \u2014 with the same tools, memory and safety checks as "
            "the web app. When an action needs your permission, the "
            "request appears with Approve / Deny buttons. Each reply ends "
            "with what it used, e.g. \u201c5.3k tokens \u00b7 \u2248$0.002\u201d.\n\n"
            "/stop \u2014 stop the request that is running now\n"
            "/new \u2014 start a fresh conversation\n"
            "/pending \u2014 re-send every action waiting for your decision\n"
            "/usage \u2014 tokens used today and over the last 30 days\n"
            "/help \u2014 this message"
        )
        await self._api("sendMessage", chat_id=chat_id, text=text)

    async def _handle_usage(self, chat_id: int, user_id: str) -> None:
        """Token totals for the linked account, from the same aggregation
        the dashboard reads, so the two can never disagree."""
        from services.usage import format_usage_text, usage_summary

        async with self._session_factory() as session:
            summary = await usage_summary(session, uuid_module.UUID(user_id))
        await self._api("sendMessage", chat_id=chat_id, text=format_usage_text(summary))

    async def _handle_new(self, chat_id: int) -> None:
        self._fresh_chats.add(chat_id)
        await self._api(
            "sendMessage",
            chat_id=chat_id,
            text="Fresh start \u2014 your next message begins a new conversation.",
        )

    async def _handle_chat(self, chat_id: int, user_id: str, text: str) -> None:
        """Turn a plain message into an agent turn for the linked account.

        The turn runs as a background task: an LLM turn with tool calls can
        take a minute, and the poll loop must keep receiving button presses,
        /stop and other chats meanwhile. A per-chat lock keeps one person's
        messages in order.
        """
        if self.chat is None:
            await self._handle_help(chat_id)
            return
        fresh = chat_id in self._fresh_chats
        self._fresh_chats.discard(chat_id)
        # Accepted now: a stop requested from here on (this chat's /stop, or
        # the web Stop button, which only records the stop) ends this
        # message's turn, even while it waits behind the chat's running one.
        stop_mark = agent_cancel.mark(user_id)
        self._track(
            chat_id,
            self._run_chat(chat_id, user_id, text, fresh, stop_mark),
            name=f"telegram-chat-{chat_id}",
        )

    async def _run_chat(
        self, chat_id: int, user_id: str, text: str, fresh: bool, stop_mark: int
    ) -> None:
        started = False
        try:
            lock = self._chat_locks.setdefault(chat_id, asyncio.Lock())
            async with lock:
                started = True
                # First indicator is sent inline so it shows before the turn
                # starts; the task only refreshes it while the turn runs.
                await self._api("sendChatAction", chat_id=chat_id, action="typing")
                typing = asyncio.create_task(self._keep_typing(chat_id))
                # "Searching the web…" lines while a long turn runs, paced and
                # built from facts by progress.py; silent, so they never buzz.
                progress = self._turn_progress(chat_id)
                try:
                    assert self.chat is not None
                    # A callback without on_event still runs; it just gets no lines.
                    listen: dict[str, Any] = (
                        {"on_event": progress.on_event} if takes_on_event(self.chat) else {}
                    )
                    # Likewise one without stop_mark: it takes its mark on entry.
                    if takes_keyword(self.chat, "stop_mark"):
                        listen["stop_mark"] = stop_mark
                    outcome = await self.chat(user_id, text, new_conversation=fresh, **listen)
                except Exception as exc:
                    logger.error("telegram_chat_failed", chat_id=chat_id, error=str(exc))
                    outcome = {"error": "The assistant hit an unexpected error."}
                finally:
                    typing.cancel()
                    # Before anything else goes out (a /stop's reply included),
                    # so no progress line can follow the turn it describes.
                    await progress.aclose()
                if outcome.get("error"):
                    await self._api(
                        "sendMessage",
                        chat_id=chat_id,
                        text=f"⚠️ {outcome['error']}"[:_MESSAGE_CHUNK],
                    )
                    return
                reply = (outcome.get("content") or "").strip()
                if outcome.get("pending_approvals"):
                    names = ", ".join(outcome["pending_approvals"])
                    reply += (
                        f"\n\n\U0001f510 Waiting on your approval for: {names}. "
                        "The request is in this chat — or send /pending."
                    )
                if outcome.get("blocked"):
                    reply += (
                        "\n\n⛔ Blocked by security policy: "
                        + ", ".join(outcome["blocked"])
                    )
                if not reply:
                    reply = "(The assistant returned no text.)"
                # Photos first, so the text (which ends with the usage line)
                # is the last thing the turn sends.
                for image in outcome.get("images") or []:
                    await self._send_photo(
                        chat_id, image.get("data_url", ""), image.get("caption", "")
                    )
                await self._send_reply(chat_id, reply, outcome)
        except asyncio.CancelledError:
            if fresh and not started:
                # Stopped while still queued behind another turn: the /new
                # it carried was never used, so keep it for the next message.
                self._fresh_chats.add(chat_id)
            raise

    def _turn_progress(self, chat_id: int) -> TurnProgress:
        """Progress lines (services/notifications/progress.py) for one turn,
        sent to *chat_id* silently, so they never buzz the phone."""
        return TurnProgress(
            lambda line: self._api(
                "sendMessage", chat_id=chat_id, text=line, disable_notification=True
            )
        )

    async def _send_reply(self, chat_id: int, text: str, outcome: dict[str, Any]) -> None:
        """Send a reply in Telegram-sized chunks, ending with the turn's
        usage line when the outcome reports usage. The line is appended
        after every other suffix and before chunking, so it is the last
        thing in the last message however long the reply is."""
        line = _usage_line(outcome)
        if line:
            text = f"{text}\n\n{line}"
        for chunk in _chunks(text):
            await self._api("sendMessage", chat_id=chat_id, text=chunk)

    async def _keep_typing(self, chat_id: int) -> None:
        # Telegram clears the indicator after ~5s; refresh it while a turn
        # runs so a long tool-using answer does not look like a dead bot.
        try:
            while True:
                await asyncio.sleep(4)
                await self._api("sendChatAction", chat_id=chat_id, action="typing")
        except asyncio.CancelledError:
            pass

    async def _handle_start(self, chat_id: Any, code: str) -> None:
        if not code:
            await self._api(
                "sendMessage",
                chat_id=chat_id,
                text=(
                    "To link this chat, open Crawler AI \u2192 Settings \u2192 "
                    "Telegram approvals and tap Connect."
                ),
            )
            return

        from models.user import User

        async with self._session_factory() as session:
            user = (
                await session.execute(
                    select(User).where(User.telegram_link_code == code)
                )
            ).scalar_one_or_none()
            now = datetime.now(timezone.utc)
            expires = user.telegram_link_expires_at if user is not None else None
            if expires is not None and expires.tzinfo is None:
                expires = expires.replace(tzinfo=timezone.utc)
            if user is None or expires is None or expires < now:
                await self._api(
                    "sendMessage",
                    chat_id=chat_id,
                    text=(
                        "That link has expired. Generate a fresh one from "
                        "Crawler AI → Settings → Telegram approvals."
                    ),
                )
                return
            # One chat, one account: linking here moves the chat off any
            # other account it was linked to, so the lookup behind every
            # later message can never find two owners.
            await session.execute(
                update(User)
                .where(User.telegram_chat_id == int(chat_id), User.id != user.id)
                .values(telegram_chat_id=None)
            )
            user.telegram_chat_id = int(chat_id)
            # Single-use: the code dies the moment it links.
            user.telegram_link_code = None
            user.telegram_link_expires_at = None
            await session.commit()
            display = user.name or user.email
        logger.info("telegram_linked", chat_id=chat_id)
        await self._api(
            "sendMessage",
            chat_id=chat_id,
            text=(
                f"✅ Linked to {display}.\n\n"
                "When the assistant needs your approval for an action, "
                "it will message you here with Approve/Deny buttons."
            ),
        )

    async def _handle_callback(self, callback: dict[str, Any]) -> None:
        callback_id = callback.get("id")
        data = callback.get("data") or ""
        message = callback.get("message") or {}
        # A1: the button must be pressed by the person whose private chat
        # holds the card — callback.from, not just the chat the card is in.
        chat_id = _own_private_chat(message.get("chat"), callback.get("from"))
        message_id = message.get("message_id")

        async def answer(text: str) -> None:
            if callback_id:
                await self._api(
                    "answerCallbackQuery", callback_query_id=callback_id, text=text
                )

        if not (data.startswith(_CB_APPROVE) or data.startswith(_CB_DENY)):
            logger.warning("telegram_callback_unknown_prefix", data=data[:32])
            await answer("Unknown action.")
            return
        approved = data.startswith(_CB_APPROVE)
        action_id = data[len(_CB_APPROVE) :]
        logger.info(
            "telegram_callback_received",
            chat_id=chat_id,
            approved=approved,
            action_id=action_id,
        )

        # Authorization: the pressing account must own a linked chat, and the
        # decision runs scoped to THAT user (the store rejects foreign or
        # already-decided actions). Checked before anything is decided; a
        # press with no chat (inline mode) has none to check and is refused.
        user_id = await self._user_for_chat(chat_id)
        if chat_id is None or user_id is None:
            logger.info("telegram_callback_from_unlinked_account_ignored")
            await answer("This chat is not linked to a Crawler AI account.")
            return
        if self.decide is None:
            await answer("Approvals are not available right now.")
            return

        # Answered now, not when the decision is done: an approval runs the
        # action and then a whole resumed agent turn, which can take a
        # minute, and Telegram shows the button as busy until the press is
        # answered. The verdict then goes on the card itself.
        await answer("Approving…" if approved else "Denying…")
        # The decision runs as this chat's tracked work: the poll loop stays
        # free (other chats, /stop), it queues behind a running turn instead
        # of racing it in the same conversation, and /stop can cancel it.
        self._track(
            chat_id,
            self._run_decision(chat_id, user_id, action_id, approved, message, message_id),
            name=f"telegram-decision-{chat_id}",
        )

    async def _run_decision(
        self,
        chat_id: int,
        user_id: str,
        action_id: str,
        approved: bool,
        message: dict[str, Any],
        message_id: Any,
    ) -> None:
        lock = self._chat_locks.setdefault(chat_id, asyncio.Lock())
        async with lock:
            await self._apply_decision(
                chat_id, user_id, action_id, approved, message, message_id
            )

    async def _apply_decision(
        self,
        chat_id: int,
        user_id: str,
        action_id: str,
        approved: bool,
        message: dict[str, Any],
        message_id: Any,
    ) -> None:
        """Apply one Approve/Deny press, then freeze the card and send the
        resumed turn's reply. While an approval runs, the chat shows
        "typing…" and progress lines, as a message turn does. The press was
        already answered, so a failure goes to the chat as a message."""
        assert self.decide is not None
        typing: Optional[asyncio.Task[None]] = None
        progress: Optional[TurnProgress] = None
        listen: dict[str, Any] = {}
        if approved:
            await self._api("sendChatAction", chat_id=chat_id, action="typing")
            typing = asyncio.create_task(self._keep_typing(chat_id))
            progress = self._turn_progress(chat_id)
            # A callback without on_event still decides; it gets no lines.
            if takes_on_event(self.decide):
                listen = {"on_event": progress.on_event}
        try:
            outcome = await self.decide(user_id, action_id, approved, **listen)
        except Exception as exc:
            # A decision failure must reach the person who pressed the
            # button; silently swallowing it looks like a dead button.
            logger.error(
                "telegram_decision_failed", action_id=action_id, error=str(exc)
            )
            outcome = {"error": "Could not apply that decision — see server logs."}
        finally:
            if typing is not None:
                typing.cancel()
            if progress is not None:
                await progress.aclose()
        logger.info(
            "telegram_decision_applied",
            action_id=action_id,
            approved=approved,
            outcome=str(outcome.get("status") or outcome.get("error"))[:80],
        )
        if outcome.get("error"):
            await self._api(
                "sendMessage",
                chat_id=chat_id,
                text="⚠️ " + str(outcome["error"])[:180],
            )
            return

        verdict = "✅ Approved" if approved else "❌ Denied"
        # Freeze the card: replace the buttons with the decision so it
        # can't be pressed twice from the chat history.
        if message_id is not None:
            original = message.get("text") or "Approval request"
            await self._api(
                "editMessageText",
                chat_id=chat_id,
                message_id=message_id,
                text=f"{original}\n\n— {verdict} from this chat.",
            )
        summary = outcome.get("summary")
        if summary:
            # The resumed turn's reply, in full and with its own usage line.
            await self._send_reply(chat_id, str(summary), outcome)


class NotifyingApprovalStore:
    """ApprovalStore decorator: forwards every call to the wrapped store and
    pushes a Telegram notification after a pending action is created. The
    notification is fire-and-forget — the approval flow itself never waits
    on (or fails because of) Telegram."""

    def __init__(
        self, inner: Any, notify: Callable[[Any], Coroutine[Any, Any, None]]
    ):
        self._inner = inner
        self._notify = notify

    async def create(self, **kwargs: Any) -> Any:
        stored = await self._inner.create(**kwargs)
        try:
            asyncio.get_running_loop().create_task(self._notify(stored))
        except RuntimeError:  # no running loop (sync test context)
            pass
        return stored

    async def list_pending(self, user_id: str) -> Any:
        return await self._inner.list_pending(user_id)

    async def decide(self, action_id: str, user_id: str, approved: bool) -> Any:
        return await self._inner.decide(action_id, user_id, approved)
