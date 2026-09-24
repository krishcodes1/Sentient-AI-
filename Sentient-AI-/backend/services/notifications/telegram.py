"""Telegram delivery for the human-approval flow.

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
  the bot receives proves control of both the SentientAI session (which
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
import json
import secrets
import uuid as uuid_module
from datetime import datetime, timedelta, timezone
from typing import Any, Awaitable, Callable, Optional

import httpx
import structlog
from sqlalchemy import select

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


def _short_json(data: dict[str, Any], limit: int = 700) -> str:
    try:
        text = json.dumps(data, indent=2, default=str)
    except (TypeError, ValueError):
        text = str(data)
    return text if len(text) <= limit else text[: limit - 1] + "…"


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
    ) -> None:
        self._token = token
        self._session_factory = session_factory
        self.decide: Optional[DecideCallback] = decide
        self._client = httpx.AsyncClient(
            base_url=f"https://api.telegram.org/bot{token}",
            timeout=httpx.Timeout(35.0, connect=10.0),
        )
        self._task: Optional[asyncio.Task[None]] = None
        self._offset: Optional[int] = None
        self._bot_username: Optional[str] = None

    # ── lifecycle ────────────────────────────────────────────────────────

    async def start(self) -> None:
        self._task = asyncio.create_task(self._poll_loop(), name="telegram-poller")
        logger.info("telegram_poller_started")

    async def stop(self) -> None:
        if self._task is not None:
            self._task.cancel()
            try:
                await self._task
            except (asyncio.CancelledError, Exception):
                pass
            self._task = None
        await self._client.aclose()

    # ── Telegram API helpers ─────────────────────────────────────────────

    async def _api(self, method: str, **params: Any) -> Optional[dict[str, Any]]:
        """Call a Bot API method; None on any failure (logged, never raised)."""
        try:
            resp = await self._client.post(f"/{method}", json=params)
            data = resp.json()
            if not data.get("ok"):
                logger.warning(
                    "telegram_api_error",
                    method=method,
                    code=data.get("error_code"),
                    description=str(data.get("description", ""))[:200],
                )
                return None
            return data.get("result")
        except Exception as exc:
            logger.warning("telegram_request_failed", method=method, error=str(exc))
            return None

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
        while True:
            try:
                updates = await self._api(
                    "getUpdates",
                    timeout=25,
                    offset=self._offset,
                    allowed_updates=["message", "callback_query"],
                )
                if updates is None:
                    await asyncio.sleep(5)
                    continue
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
                await asyncio.sleep(5)

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

    async def _handle_message(self, message: dict[str, Any]) -> None:
        chat_id = message.get("chat", {}).get("id")
        text = (message.get("text") or "").strip()
        if chat_id is None or not text.startswith("/start"):
            return
        code = text[len("/start") :].strip()
        if not code:
            await self._api(
                "sendMessage",
                chat_id=chat_id,
                text=(
                    "To link this chat, open SentientAI → Settings → "
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
                        "SentientAI → Settings → Telegram approvals."
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
            await answer("This chat is not linked to a SentientAI account.")
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

    def __init__(self, inner: Any, notify: Callable[[Any], Awaitable[None]]):
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
