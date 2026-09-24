"""Runs the Telegram bot: long-polls updates, links accounts by one-time code,
pushes approval cards, and applies Approve/Deny presses through the shared
decision pipeline.

Why it exists: Approvals must be decidable away from a computer and without a
public webhook URL; the Telegram manager starts this service, and
NotifyingApprovalStore wraps the approval store so every pending action is
pushed.

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
- Only the linked chat can decide an approval, and the decision callback
  re-checks ownership server-side (the store scopes by user_id).
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
from sqlalchemy import select

logger = structlog.get_logger(__name__)

# How long a /start link code stays valid. Short: it is single-use and the
# user taps it within seconds of the Settings page showing it.
LINK_CODE_TTL_MINUTES = 10

_NOT_LINKED_TEXT = (
    "This chat is not linked to a Crawler AI account. Open Crawler AI \u2192 "
    "Settings \u2192 Telegram approvals and tap Connect."
)

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
        self._chat_tasks: set[asyncio.Task[None]] = set()
        self._client = httpx.AsyncClient(
            base_url=f"https://api.telegram.org/bot{token}",
            timeout=httpx.Timeout(35.0, connect=10.0),
        )
        self._task: Optional[asyncio.Task[None]] = None
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
        for task in list(self._chat_tasks):
            task.cancel()
        await self.wait_for_chats()
        if self._task is not None:
            self._task.cancel()
            try:
                await self._task
            except (asyncio.CancelledError, Exception):
                pass
            self._task = None
        await self._client.aclose()

    async def wait_for_chats(self) -> None:
        """Wait for in-flight chat turns (tests, shutdown)."""
        if self._chat_tasks:
            await asyncio.gather(*self._chat_tasks, return_exceptions=True)

    # ── Telegram API helpers ─────────────────────────────────────────────

    async def _api(self, method: str, **params: Any) -> Any:
        """Call a Bot API method; None on any failure (logged, never raised).

        Returns the response's ``result`` field verbatim, so the shape is
        method-dependent: a dict for ``getMe``/``sendMessage``, a list for
        ``getUpdates``. Callers narrow before use.

        The one exception is a 409 from ``getUpdates``, raised as
        ``_PollerConflict``: it needs a backoff and a single explanation
        from the poll loop, not a generic warning on every retry.
        """
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
            args = _short_json(action.arguments or {})
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
        """The account a chat is linked to, or None. Linking is the only
        way a chat id ever gets attached, so this is the authorization
        check for every inbound command."""
        from models.user import User

        async with self._session_factory() as session:
            user = (
                await session.execute(
                    select(User).where(User.telegram_chat_id == chat_id)
                )
            ).scalar_one_or_none()
            return str(user.id) if user is not None else None

    async def _handle_message(self, message: dict[str, Any]) -> None:
        chat_id = message.get("chat", {}).get("id")
        text = (message.get("text") or "").strip()
        if chat_id is None or not text:
            return
        command, _, argument = text.partition(" ")
        # Group clients suffix commands with the bot's name ("/start@bot").
        command = command.split("@", 1)[0].lower()
        if command == "/start":
            await self._handle_start(chat_id, argument.strip())
        elif command == "/pending":
            await self._handle_pending(chat_id)
        elif command == "/new":
            await self._handle_new(chat_id)
        elif command == "/usage":
            await self._handle_usage(chat_id)
        elif command in ("/help", "/settings"):
            await self._handle_help(chat_id)
        elif command.startswith("/"):
            await self._handle_help(chat_id)
        else:
            await self._handle_chat(chat_id, text)

    async def _handle_pending(self, chat_id: Any) -> None:
        """Re-send every approval still waiting on this account, so a card
        that was dismissed, scrolled past, or sent while the phone was off
        can always be recovered from the chat itself."""
        user_id = await self._user_for_chat(chat_id)
        if user_id is None:
            await self._api("sendMessage", chat_id=chat_id, text=_NOT_LINKED_TEXT)
            return
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

    async def _handle_help(self, chat_id: Any) -> None:
        if await self._user_for_chat(chat_id) is None:
            text = _NOT_LINKED_TEXT
        else:
            text = (
                "Just type a task or a question and the assistant answers "
                "here \u2014 with the same tools, memory and safety checks as "
                "the web app. When an action needs your permission, the "
                "request appears with Approve / Deny buttons.\n\n"
                "/new \u2014 start a fresh conversation\n"
                "/pending \u2014 re-send every action waiting for your decision\n"
                "/usage \u2014 tokens used today and over the last 30 days\n"
                "/help \u2014 this message"
            )
        await self._api("sendMessage", chat_id=chat_id, text=text)

    async def _handle_usage(self, chat_id: Any) -> None:
        """Token totals for the linked account, from the same aggregation
        the dashboard reads, so the two can never disagree."""
        user_id = await self._user_for_chat(chat_id)
        if user_id is None:
            await self._api("sendMessage", chat_id=chat_id, text=_NOT_LINKED_TEXT)
            return
        from services.usage import format_usage_text, usage_summary

        async with self._session_factory() as session:
            summary = await usage_summary(session, uuid_module.UUID(user_id))
        await self._api("sendMessage", chat_id=chat_id, text=format_usage_text(summary))

    async def _handle_new(self, chat_id: Any) -> None:
        if await self._user_for_chat(chat_id) is None:
            await self._api("sendMessage", chat_id=chat_id, text=_NOT_LINKED_TEXT)
            return
        self._fresh_chats.add(int(chat_id))
        await self._api(
            "sendMessage",
            chat_id=chat_id,
            text="Fresh start \u2014 your next message begins a new conversation.",
        )

    async def _handle_chat(self, chat_id: Any, text: str) -> None:
        """Turn a plain message into an agent turn for the linked account.

        The turn runs as a background task: an LLM turn with tool calls can
        take a minute, and the poll loop must keep receiving button presses
        and other chats meanwhile. A per-chat lock keeps one person's
        messages in order.
        """
        user_id = await self._user_for_chat(chat_id)
        if user_id is None:
            await self._api("sendMessage", chat_id=chat_id, text=_NOT_LINKED_TEXT)
            return
        if self.chat is None:
            await self._handle_help(chat_id)
            return
        chat_key = int(chat_id)
        fresh = chat_key in self._fresh_chats
        self._fresh_chats.discard(chat_key)
        task = asyncio.create_task(
            self._run_chat(chat_key, user_id, text, fresh),
            name=f"telegram-chat-{chat_key}",
        )
        self._chat_tasks.add(task)
        task.add_done_callback(self._chat_tasks.discard)

    async def _run_chat(
        self, chat_id: int, user_id: str, text: str, fresh: bool
    ) -> None:
        lock = self._chat_locks.setdefault(chat_id, asyncio.Lock())
        async with lock:
            # First indicator is sent inline so it shows before the turn
            # starts; the task only refreshes it while the turn runs.
            await self._api("sendChatAction", chat_id=chat_id, action="typing")
            typing = asyncio.create_task(self._keep_typing(chat_id))
            try:
                assert self.chat is not None
                outcome = await self.chat(user_id, text, new_conversation=fresh)
            except Exception as exc:
                logger.error("telegram_chat_failed", chat_id=chat_id, error=str(exc))
                outcome = {"error": "The assistant hit an unexpected error."}
            finally:
                typing.cancel()
            if outcome.get("error"):
                await self._api(
                    "sendMessage",
                    chat_id=chat_id,
                    text=f"\u26a0\ufe0f {outcome['error']}"[:_MESSAGE_CHUNK],
                )
                return
            reply = (outcome.get("content") or "").strip()
            if outcome.get("pending_approvals"):
                names = ", ".join(outcome["pending_approvals"])
                reply += (
                    f"\n\n\U0001f510 Waiting on your approval for: {names}. "
                    "The request is in this chat \u2014 or send /pending."
                )
            if outcome.get("blocked"):
                reply += (
                    "\n\n\u26d4 Blocked by security policy: "
                    + ", ".join(outcome["blocked"])
                )
            if not reply:
                reply = "(The assistant returned no text.)"
            for chunk in _chunks(reply):
                await self._api("sendMessage", chat_id=chat_id, text=chunk)
            for image in outcome.get("images") or []:
                await self._send_photo(
                    chat_id, image.get("data_url", ""), image.get("caption", "")
                )

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
        chat_id = message.get("chat", {}).get("id")
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

        # Authorization: the pressing chat must be a linked chat, and the
        # decision runs scoped to THAT user (the store rejects foreign or
        # already-decided actions).
        from models.user import User

        async with self._session_factory() as session:
            user = (
                await session.execute(
                    select(User).where(User.telegram_chat_id == chat_id)
                )
            ).scalar_one_or_none()
            user_id = str(user.id) if user is not None else None
        if user_id is None:
            await answer("This chat is not linked to a Crawler AI account.")
            return
        if self.decide is None:
            await answer("Approvals are not available right now.")
            return

        try:
            outcome = await self.decide(user_id, action_id, approved)
        except Exception as exc:
            # A decision failure must reach the person who pressed the
            # button; silently swallowing it looks like a dead button.
            logger.error(
                "telegram_decision_failed", action_id=action_id, error=str(exc)
            )
            await answer("Could not apply that decision — see server logs.")
            return
        logger.info(
            "telegram_decision_applied",
            action_id=action_id,
            approved=approved,
            outcome=str(outcome.get("status") or outcome.get("error"))[:80],
        )
        if outcome.get("error"):
            await answer(str(outcome["error"])[:180])
            return

        verdict = "✅ Approved" if approved else "❌ Denied"
        await answer(verdict)
        # Freeze the card: replace the buttons with the decision so it
        # can't be pressed twice from the chat history.
        if chat_id is not None and message_id is not None:
            original = message.get("text") or "Approval request"
            await self._api(
                "editMessageText",
                chat_id=chat_id,
                message_id=message_id,
                text=f"{original}\n\n— {verdict} from this chat.",
            )
        summary = outcome.get("summary")
        if summary and chat_id is not None:
            await self._api(
                "sendMessage", chat_id=chat_id, text=str(summary)[:3500]
            )


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
