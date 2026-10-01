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
import weakref
from datetime import datetime, timedelta, timezone
from typing import Any, Awaitable, Callable, Coroutine, Optional

import httpx
import structlog
from sqlalchemy import select, update

from services.agent import cancel as agent_cancel
from services.agent.app_approvals import REMEMBER_WEEK, Channel, weekly_app_for
from services.agent.permission_grants import REMEMBER_LOW_RISK
from services.notifications import cards
from services.notifications.progress import TurnProgress, takes_keyword, takes_on_event
from services.notifications.voice import (  # top10:voice_notes
    TEXT_NOT_SET_UP,
    TEXT_VIDEO_NOTE,
    VoiceNoteService,
)
from services.security import channels as secret_text
from services.tools.browser.checkout import NOTICE as PURCHASE_NOTICE
from services.tools.transcribe import VoiceNoteMeta  # top10:voice_notes

logger = structlog.get_logger(__name__)

# How long a /start link code stays valid. Short: it is single-use and the
# user taps it within seconds of the Settings page showing it.
LINK_CODE_TTL_MINUTES = 10

# callback_data prefixes (Telegram caps callback_data at 64 bytes; a uuid
# is 36 chars, so prefix + uuid fits comfortably). Every prefix is 4 chars.
_CB_APPROVE = "apv:"
_CB_DENY = "dny:"
# "Allow <app> for 7 days": approve the card and allow its app for a week
# for this chat (services.agent.app_approvals).
_CB_APPROVE_WEEK = "apw:"
# /apps: revoke one weekly app approval.
_CB_REVOKE_APP = "rva:"
# "Allow low-risk on <account> · 7 days": approve the card and allow low-risk
# changes on its account for 7 days (services.agent.permission_grants). The
# /grants Revoke button is "rvg:" (services.notifications.grant_commands).
_CB_APPROVE_LOW_RISK = "apl:"
# Longest account label on the grant button.
_GRANT_BUTTON_ACCOUNT_CHARS = 24
_CB_PREFIX_LEN = 4

# A command handler in TelegramService._commands, called with (chat_id,
# user_id, argument) once the chat passed the A1 link check. "argument" is
# what follows the command word, stripped.
CommandHandler = Callable[[int, str, str], Awaitable[None]]
# A button handler in TelegramService._callback_routes, keyed by its 4-char
# callback_data prefix and called with (chat_id, target, answer): the chat
# is not yet checked (None for an inline press), target is what follows the
# prefix, and answer(text) answers the press.
CallbackRoute = Callable[[Optional[int], str, Callable[[str], Awaitable[None]]], Awaitable[None]]
# top10:file_extraction. A media handler in TelegramService.media_routes,
# called with (chat_id, user_id, message) once the chat passed the A1 link
# check; and a file-caption handler in file_caption_routes, called with
# (chat_id, user_id, rest_of_caption, files) once the files are downloaded.
MediaRoute = Callable[[int, str, dict[str, Any]], Awaitable[None]]
FileCaptionRoute = Callable[[int, str, str, list[Any]], Awaitable[None]]
# The media kinds _handle_message recognises, in the order they are looked for.
MEDIA_KINDS: tuple[str, ...] = ("document", "photo", "voice", "audio", "video_note")
# An album's messages arrive one by one; they are gathered this long into
# one turn of at most MAX_FILES_PER_TURN files.
MEDIA_GROUP_WAIT_S = 2.0
MAX_FILES_PER_TURN = 5
# The largest photo size sent on as an image (the web chat's image cap).
MAX_PHOTO_BYTES = 5 * 1024 * 1024

# The /help reply: the lead paragraph, then one line per command (HELP_LINES,
# in the order they are listed), then the line for /help itself.
_HELP_INTRO = (
    "Just type a task or a question and the assistant answers "
    "here — with the same tools, memory and safety checks as "
    "the web app. When an action needs your permission, the "
    "request appears with Approve / Deny buttons. Each reply ends "
    "with what it used, e.g. “5.3k tokens · ≈$0.002”."
)
HELP_LINES: list[str] = [
    "/stop — stop the request that is running now",
    "/new — start a fresh conversation",
    "/pending — re-send every action waiting for your decision",
    "/apps — apps allowed for a week, with a button to revoke each",
    "/usage — tokens used today and over the last 30 days",
    # top10:secret_pii_redaction

    # top10:file_extraction
    "Send a PDF, Word, PowerPoint or Excel file (up to 20 MB) with a question about it.",

    # top10:scheduler_briefing
    "/schedules — your scheduled tasks, with Run now, Pause and Resume",
    "/briefing — send your daily briefing now",
    "/timezone — show or set your time zone, e.g. /timezone America/Chicago",

    # top10:tutor_mode
    "/tutor — tutor mode for this chat: /tutor on, /tutor off, /tutor status",

    # top10:knowledge_base
    "/kb <collection> — as a file's caption: save the file to your knowledge base",

    # top10:flashcards_quizzes
    "/decks — your flashcard decks",
    "/review [n] — review the flashcards due now (all decks, or deck n)",
    "/quiz n [count] — a practice quiz on deck n",
    "/export n [anki|csv] — download deck n for Anki or a spreadsheet",
    "During a review: /show, /again, /hard, /good, /easy, /skip, /end (quiz: /a to /f)",

    # top10:event_triggers
    "/triggers — your app triggers, with Pause and Resume; /triggers delete 2 removes one",

    # top10:permission_tiers
    "/grants — accounts allowed low-risk changes, with a button to revoke each",

    # top10:voice_notes
    "🎤 Send a voice note and I'll answer it like a typed message (when the owner has "
    "turned voice notes on); I first show what I heard.",

    # top10:video_transcripts

]
_HELP_LAST_LINE = "/help — this message"

# Decision callback signature: (user_id, action_id, approved) -> outcome
# dict with at least {"status": "approved"|"denied"} or {"error": str}.
DecideCallback = Callable[[str, str, bool], Awaitable[dict[str, Any]]]

# Chat callback signature: (user_id, text, new_conversation=...) -> outcome
# dict with "content" (and "pending_approvals"/"blocked") or {"error": str}.
ChatCallback = Callable[..., Awaitable[dict[str, Any]]]

# Tutor callback signature (api/routes/agent.build_tutor_applier):
# (user_id, command, new_conversation=..., text=...) -> {"reply": str} or
# {"error": str}.
TutorCallback = Callable[..., Awaitable[dict[str, Any]]]

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

# One approval card's parts go out at a time per chat, so two cards never
# interleave: service -> chat id -> lock. Keyed weakly by the service, so
# the locks go away with it.
_CARD_LOCKS: weakref.WeakKeyDictionary[TelegramService, dict[Any, asyncio.Lock]] = (
    weakref.WeakKeyDictionary()
)


def _card_lock(service: TelegramService, chat_id: Any) -> asyncio.Lock:
    """The lock that serialises *chat_id*'s approval cards on *service*."""
    return _CARD_LOCKS.setdefault(service, {}).setdefault(chat_id, asyncio.Lock())


class _PollerConflict(Exception):
    """getUpdates answered 409: something else is consuming this bot's
    updates (another poller, or a webhook set on the token)."""


def _short_json(data: dict[str, Any], limit: int = 700) -> str:
    try:
        text = json.dumps(data, indent=2, default=str)
    except (TypeError, ValueError):
        text = str(data)
    return text if len(text) <= limit else text[: limit - 1] + "…"


# Tools whose card stores what it was made from under a reserved key
# starting with "_", set by the runtime and never by the model (each
# toolkit refuses a call that brings its own): desktop.act's screen
# (``services.tools.computer.CARD_KEY``), browser.act's page (``_page``) and
# browser.checkout's page facts (``_checkout``, which the purchase card
# renders itself).
_RESERVED_KEY_TOOLS = frozenset({"desktop.act", "browser.act", "browser.checkout"})

# The reserved key a browser.checkout card carries its facts under
# (services.tools.browser.checkout.toolkit.CARD_KEY).
_CHECKOUT_KEY = "_checkout"
# The tool whose card is the approval sentence alone (see notify_pending).
_ACT_TOOL = "browser.act"


def _card_arguments(tool_name: Any, arguments: Any) -> dict[str, Any]:
    """A call's arguments as its approval card shows them. A desktop.act,
    browser.act or browser.checkout card also stores the screen or page it
    was made from under a reserved key starting with "_" (see
    ``_RESERVED_KEY_TOOLS``), so those keys are left out. Every other
    tool's arguments are shown whole: nothing the owner approves is hidden
    from the card."""
    if not isinstance(arguments, dict):
        return {}
    if tool_name not in _RESERVED_KEY_TOOLS:
        return arguments
    return {k: v for k, v in arguments.items() if not str(k).startswith("_")}


def _purchase_card(action: Any) -> Optional[dict[str, Any]]:
    """The ``_checkout`` facts a browser.checkout card carries (origin, host,
    amount_usd, currency, items, card_label, notice), or None for any other
    action or a checkout card without them."""
    if getattr(action, "tool_name", None) != "browser.checkout":
        return None
    arguments = getattr(action, "arguments", None)
    card = arguments.get(_CHECKOUT_KEY) if isinstance(arguments, dict) else None
    return card if isinstance(card, dict) else None


def _purchase_notice(card: dict[str, Any]) -> str:
    """The "Crawler can make mistakes" line: the card's own copy (the
    checkout toolkit puts NOTICE on every card), else the toolkit's."""
    notice = card.get("notice")
    if isinstance(notice, str) and notice.strip():
        return notice.strip()
    return PURCHASE_NOTICE


def _purchase_caption(card: dict[str, Any], expires_at: Any) -> str:
    """The purchase card's caption, on a photo or as the text card:
    "🛒 Purchase approval — shop.example.com · $23.40 · 2 items ·
    Visa ····4242 — Crawler can make mistakes. …", then the expiry. Every
    part is read from the card's facts; the card number is never on it
    (the label is masked by the vault). The item count is left out when
    the toolkit found no item lines (many shops' rows are not li/tr), as
    the web card and the approval sentence leave it out."""
    host = str(card.get("host") or card.get("origin") or "the site")
    amount = str(card.get("amount_usd") or "?")
    currency = str(card.get("currency") or "USD")
    money = f"${amount}" if currency == "USD" else f"{amount} {currency}"
    items = card.get("items")
    count = len(items) if isinstance(items, list) else 0
    parts = [host, money]
    if count > 0:
        parts.append(f"{count} item{'' if count == 1 else 's'}")
    label = card.get("card_label")
    if isinstance(label, str) and label.strip():
        parts.append(label.strip())
    caption = "🛒 Purchase approval — " + " · ".join(parts)
    notice = _purchase_notice(card)
    if notice:
        caption += f" — {notice}"
    return f"{caption}\n\nExpires in {_expires_in_text(expires_at)}."


def _approval_keyboard(
    action_id: str, weekly_app: Optional[str] = None, low_risk_account: Optional[str] = None
) -> dict[str, Any]:
    """Approve and Deny, plus "Allow <app> for 7 days" on its own row when
    the card may be allowed for a week (a desktop.act in an app on the
    weekly list), or "Allow low-risk on <account> · 7 days" when the card
    offers a low-risk grant (never both: the week is desktop.act's only)."""
    rows: list[list[dict[str, str]]] = [
        [
            {"text": "✅ Approve", "callback_data": _CB_APPROVE + action_id},
            {"text": "❌ Deny", "callback_data": _CB_DENY + action_id},
        ]
    ]
    if weekly_app:
        rows.append(
            [
                {
                    "text": f"📅 Allow {weekly_app} for 7 days",
                    "callback_data": _CB_APPROVE_WEEK + action_id,
                }
            ]
        )
    elif low_risk_account:
        rows.append(
            [
                {
                    "text": f"⚡ Allow low-risk on {_button_account(low_risk_account)} · 7 days",
                    "callback_data": _CB_APPROVE_LOW_RISK + action_id,
                }
            ]
        )
    return {"inline_keyboard": rows}


def _button_account(account: str) -> str:
    """An account label for a button: printable, one line, at most 24
    characters (it came from the owner's connector name)."""
    cleaned = " ".join("".join(c if c.isprintable() else " " for c in account).split())
    if len(cleaned) <= _GRANT_BUTTON_ACCOUNT_CHARS:
        return cleaned
    return cleaned[: _GRANT_BUTTON_ACCOUNT_CHARS - 1] + "…"


def _low_risk_line(action: Any, account: str) -> str:
    """What a card that offers a low-risk grant says about it."""
    from services.agent.risk import low_risk_notes_for_tool

    return cards.low_risk_line(
        account, low_risk_notes_for_tool(action.tool_name), how="/grants lists and revokes."
    )


def _weekly_line(weekly_app: str) -> str:
    """What a card that offers the week says about it."""
    return (
        f"Or allow {weekly_app} for 7 days: Crawler then scrolls and clicks around in "
        f"{weekly_app} without a card for requests from this chat; typing, and buttons "
        "that change or send something, still ask. /apps lists and revokes."
    )


def _day(when: Any) -> str:
    """A date as the chat shows it ("Fri Oct 2"), in this computer's time
    zone; the ISO text or datetime it was given when it cannot be read."""
    try:
        moment = when if isinstance(when, datetime) else datetime.fromisoformat(str(when))
        if moment.tzinfo is None:
            moment = moment.replace(tzinfo=timezone.utc)
        local = moment.astimezone()
    except (TypeError, ValueError):
        return str(when)
    return f"{local:%a} {local:%b} {local.day}"


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


def _media_kind(message: dict[str, Any]) -> Optional[str]:
    """Which media a Telegram message carries (MEDIA_KINDS), or None
    (top10:file_extraction)."""
    for kind in MEDIA_KINDS:
        value = message.get(kind)
        if kind == "photo":
            if isinstance(value, list) and value:
                return kind
        elif isinstance(value, dict) and value.get("file_id"):
            return kind
    return None


# top10:voice_notes: the media kinds VoiceNoteService handles, and the keys
# Telegram sets on a forwarded message (any one of them makes it someone
# else's recording).
_VOICE_KINDS: tuple[str, ...] = ("voice", "audio", "video_note")
_FORWARD_KEYS: tuple[str, ...] = (
    "forward_origin",
    "forward_from",
    "forward_from_chat",
    "forward_sender_name",
    "forward_date",
)


def _voice_meta(kind: str, message: dict[str, Any]) -> VoiceNoteMeta:
    """What the message declares about its recording (top10:voice_notes).
    Every value is checked again after the download."""
    media = message.get(kind)
    media = media if isinstance(media, dict) else {}
    size = media.get("file_size")
    duration = media.get("duration")
    forwarded = any(message.get(key) is not None for key in _FORWARD_KEYS) or bool(
        message.get("is_automatic_forward")
    )
    mime = media.get("mime_type")
    return VoiceNoteMeta(
        kind=kind,
        # A voice note is Opus in Ogg; Telegram usually says so.
        declared_mime=str(mime or ("audio/ogg" if kind == "voice" else ""))[:100],
        declared_size=size if isinstance(size, int) and not isinstance(size, bool) else None,
        declared_duration_s=(
            float(duration)
            if isinstance(duration, (int, float)) and not isinstance(duration, bool)
            else None
        ),
        forwarded=forwarded,
        caption=str(message.get("caption") or "")[:4096],
        file_name=str(media.get("file_name") or "")[:255],
        channel="telegram",
        file_id=str(media.get("file_id") or ""),
    )


def _largest_photo(sizes: Any) -> Optional[dict[str, Any]]:
    """The largest size of a Telegram photo that is at most MAX_PHOTO_BYTES
    (a size without a stated file_size counts as small enough only when it
    is the only one)."""
    if not isinstance(sizes, list):
        return None
    usable = [
        s
        for s in sizes
        if isinstance(s, dict)
        and isinstance(s.get("file_id"), str)
        and (not isinstance(s.get("file_size"), int) or s["file_size"] <= MAX_PHOTO_BYTES)
    ]
    if not usable:
        return None
    return max(usable, key=lambda s: (s.get("file_size") or 0, s.get("width") or 0))


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


def _with_turn_notes(reply: str, outcome: dict[str, Any]) -> str:
    """*reply* with what the turn left for the person to do: the approval
    it parked (its card is already in the chat) and the calls security
    policy blocked. A message turn and the turn resumed after an approval
    report both the same way, so their replies read the same."""
    if outcome.get("pending_approvals"):
        names = ", ".join(outcome["pending_approvals"])
        reply += (
            f"\n\n\U0001f510 Waiting on your approval for: {names}. "
            "The request is in this chat — or send /pending."
        )
    if outcome.get("blocked"):
        reply += "\n\n⛔ Blocked by security policy: " + ", ".join(outcome["blocked"])
    return reply


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
        approval_image: Optional[Callable[[Any], Optional[str]]] = None,
    ) -> None:
        self._token = token
        self._session_factory = session_factory
        self.decide: Optional[DecideCallback] = decide
        self.chat: Optional[ChatCallback] = chat
        # (StoredAction) -> the picture its card shows, as an image data
        # URL, or None: the executor's approval_image, wired by main.py.
        # A purchase card goes out as a photo while the picture is there
        # and as the text card with the same caption once it is gone.
        self.approval_image: Optional[Callable[[Any], Optional[str]]] = approval_image
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
        # The linked chat's commands by lower-case command word ("/stop"),
        # and the non-approval buttons by callback_data prefix ("rva:").
        # /start (before the link check) and /help (any other "/" word) are
        # answered by _handle_message itself, and the approval buttons
        # (apv: dny: apw:) by _handle_callback.
        self._commands: dict[str, CommandHandler] = {}
        self._callback_routes: dict[str, CallbackRoute] = {}
        self._register_builtin_commands()
        self._register_callback_routes()
        # top10:file_extraction: messages that carry media, by kind
        # (document, photo, voice, audio, video_note), called with (chat_id,
        # user_id, message) after the A1 link check; and a file message's
        # caption routes, keyed by the caption's first word ("/kb"), called
        # with (chat_id, user_id, rest_of_caption, files) once the files are
        # downloaded. A caption is never parsed as a command otherwise.
        self.media_routes: dict[str, MediaRoute] = {}
        self.file_caption_routes: dict[str, FileCaptionRoute] = {}
        self._media_groups: dict[tuple[int, str], list[dict[str, Any]]] = {}
        self._media_group_wait_s = MEDIA_GROUP_WAIT_S
        self.media_routes["document"] = self._route_file_message
        self.media_routes["photo"] = self._route_file_message
        # top10:knowledge_base: a file captioned "/kb <collection>" is saved to
        # the knowledge base (services/knowledge/channels.py). Registered here,
        # once file_caption_routes exists.
        from services.knowledge import channels as knowledge_channels

        knowledge_channels.register_telegram_caption(self)
        # top10:voice_notes: voice notes, audio files and video notes, read
        # through the VoiceNoteService main.py wires here (app.state.voice_notes).
        self.voice: Optional[VoiceNoteService] = None
        for kind in _VOICE_KINDS:
            self.media_routes[kind] = self._route_voice_message

    def _register_builtin_commands(self) -> None:
        """Fill ``_commands``. Each handler looks its method up when called,
        so a replaced method is the one that answers."""
        self._commands["/stop"] = lambda chat_id, user_id, _arg: self._handle_stop(
            chat_id, user_id
        )
        self._commands["/pending"] = lambda chat_id, user_id, _arg: self._handle_pending(
            chat_id, user_id
        )
        self._commands["/new"] = lambda chat_id, _user_id, _arg: self._handle_new(chat_id)
        self._commands["/usage"] = lambda chat_id, user_id, _arg: self._handle_usage(
            chat_id, user_id
        )
        self._commands["/apps"] = lambda chat_id, user_id, _arg: self._handle_apps(
            chat_id, user_id
        )
        # top10:secret_pii_redaction

        # top10:file_extraction

        # top10:scheduler_briefing
        from services.scheduler import commands as schedule_commands

        schedule_commands.register_telegram(self)

        # top10:tutor_mode
        # /tutor on|off|status (services/tutor), applied by the tutor applier
        # main.py wires; None until then.
        self.tutor: Optional[TutorCallback] = None
        self._commands["/tutor"] = lambda chat_id, user_id, arg: self._handle_tutor(
            chat_id, user_id, arg
        )

        # top10:knowledge_base
        from services.knowledge import channels as knowledge_channels

        knowledge_channels.register_telegram(self)

        # top10:flashcards_quizzes
        from services.study import telegram as study_telegram

        study_telegram.register_telegram(self)

        # top10:event_triggers
        from services.triggers import commands as trigger_commands

        trigger_commands.register_telegram(self)

        # top10:permission_tiers
        from services.notifications import grant_commands

        grant_commands.register_telegram(self)

        # top10:voice_notes

        # top10:video_transcripts

    def _register_callback_routes(self) -> None:
        """Fill ``_callback_routes`` (4-char prefixes, _CB_PREFIX_LEN)."""
        self._callback_routes[_CB_REVOKE_APP] = lambda chat_id, target, answer: (
            self._route_revoke_app(chat_id, target, answer)
        )
        # top10:secret_pii_redaction

        # top10:file_extraction

        # top10:scheduler_briefing
        from services.scheduler import commands as schedule_commands

        schedule_commands.register_telegram_buttons(self)

        # top10:tutor_mode

        # top10:knowledge_base

        # top10:flashcards_quizzes
        from services.study import telegram as study_telegram

        study_telegram.register_telegram_buttons(self)

        # top10:event_triggers
        from services.triggers import commands as trigger_commands

        trigger_commands.register_telegram_buttons(self)

        # top10:permission_tiers
        from services.notifications import grant_commands

        grant_commands.register_telegram_buttons(self)

        # top10:voice_notes

        # top10:video_transcripts

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

        Every text send or edit goes out with link previews disabled, and
        with any key, password, card, bank or ID number in its text masked
        (services.security, policy CHANNEL; the withheld notice when the
        text cannot be checked); this is the single choke point, so no
        reply path can forget either.
        """
        if method in _TEXT_METHODS:
            params.setdefault("link_preview_options", {"is_disabled": True})
            if isinstance(params.get("text"), str):
                params["text"] = secret_text.mask_text(params["text"], channel="telegram")[0]
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

    async def _send_photo(
        self,
        chat_id: int,
        data_url: str,
        caption: str,
        reply_markup: Optional[dict[str, Any]] = None,
    ) -> bool:
        """Upload an image (a screenshot the agent took) as a Telegram photo,
        with an inline keyboard when the photo is an approval card. The
        caption is masked as a text message is (``_api``)."""
        caption = secret_text.mask_text(caption, channel="telegram")[0]
        try:
            header, _, payload = data_url.partition(",")
            media_type = header[len("data:") :].split(";", 1)[0] or "image/jpeg"
            raw = base64.b64decode(payload)
            ext = "png" if media_type.endswith("png") else "jpg"
            fields: dict[str, str] = {"chat_id": str(chat_id), "caption": caption[:1024]}
            if reply_markup is not None:
                # Multipart carries the keyboard as its JSON text.
                fields["reply_markup"] = json.dumps(reply_markup)
            resp = await self._client.post(
                "/sendPhoto",
                data=fields,
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
        # Masked before it is cut, so a value is never cut in half.
        text = secret_text.mask_text(text, channel="telegram")[0]
        result = await self._api("sendMessage", chat_id=chat_id, text=text[:3500])
        return result is not None

    # ── outbound: approval notification ──────────────────────────────────

    async def notify_pending(self, action: Any) -> None:
        """Push an approval request to the owner's linked chat (no-op when
        the user has no linked chat). ``action`` is a StoredAction.

        A browser.checkout card is a photo of the checkout page with the
        purchase caption (the site, the amount, the items, the card label
        and the "Crawler can make mistakes" notice) and the same
        Approve/Deny keyboard; a browser.act card is a photo of the page
        with the target outlined, captioned with the act's sentence. When
        the picture is gone (a restart) or the upload fails, the text card
        carries the same caption."""
        try:
            chat_id = await self.linked_chat_id(action.user_id)
            if chat_id is None:
                return
            # A desktop.act in an app on the weekly list also offers "Allow
            # <app> for 7 days" (services.agent.app_approvals).
            weekly_app = weekly_app_for(action.tool_name, action.arguments)
            # A LOW action's card may offer "Allow low-risk on <account>"
            # (services.agent.permission_grants).
            low_risk_account = cards.low_risk_account(action)
            keyboard = _approval_keyboard(action.action_id, weekly_app, low_risk_account)
            purchase = _purchase_card(action)
            if purchase is not None:
                caption = _purchase_caption(purchase, action.expires_at)
                if getattr(action, "risk_note", None):
                    caption = f"{caption}\n\n⚠️ {action.risk_note}"
                image = self._approval_image_of(action)
                if image is not None and await self._send_photo(
                    chat_id, image, caption, reply_markup=keyboard
                ):
                    return
                await self._api("sendMessage", chat_id=chat_id, text=caption, reply_markup=keyboard)
                return
            if action.tool_name == _ACT_TOOL:
                # One plain sentence from the act toolkit's facts ('Click
                # "Add to cart" on shop.example.com'): the arguments are
                # refs and typed text, which a JSON dump would only obscure.
                lines = ["🔐 Approval required", "", str(action.reason)]
            else:
                lines = [
                    "🔐 Approval required",
                    "",
                    f"Tool: {action.tool_name}",
                    f"Why: {action.reason}",
                ]
            if getattr(action, "risk_note", None):
                lines += ["", f"⚠️ {action.risk_note}"]
            if action.tool_name != _ACT_TOOL:
                # Every argument in full (F3): a long card goes out as
                # labelled, paced parts, the buttons on the last. An
                # oversized card or a lost part gets a notice instead, and no
                # buttons. The act card keeps its one sentence (above).
                card = cards.layout_card(
                    lines,
                    _card_arguments(action.tool_name, action.arguments or {}),
                    tool_name=str(action.tool_name),
                    max_chars=_MESSAGE_CHUNK,
                    length=cards.utf16_len,
                )

                async def send_part(text: str) -> bool:
                    return await self._api("sendMessage", chat_id=chat_id, text=text) is not None

                async with _card_lock(self, chat_id):
                    ready = await cards.send_card_parts(
                        card,
                        send_part,
                        retry_hint="Send /pending to get it again, or decide in the web app.",
                    )
                if not ready:
                    logger.warning(
                        "telegram_approval_card_withheld",
                        action_id=action.action_id,
                        parts=card.parts,
                        oversized=card.notice is not None,
                    )
                    return
                lines = list(card.final_lines)
            lines += ["", f"Expires in {_expires_in_text(action.expires_at)}."]
            if weekly_app:
                lines += ["", _weekly_line(weekly_app)]
            elif low_risk_account:
                lines += ["", _low_risk_line(action, low_risk_account)]
            text = "\n".join(lines)
            if action.tool_name == _ACT_TOOL:
                # The act card's picture: the page with the target outlined,
                # the sentence as its caption. Without one (it could not be
                # taken, or a restart dropped it) the same text goes alone.
                image = self._approval_image_of(action)
                if image is not None and await self._send_photo(
                    chat_id, image, text, reply_markup=keyboard
                ):
                    return
            await self._api("sendMessage", chat_id=chat_id, text=text, reply_markup=keyboard)
        except Exception as exc:  # notification failure must never break flow
            logger.warning("telegram_notify_failed", error=str(exc))

    def _approval_image_of(self, action: Any) -> Optional[str]:
        """The card's picture from the wired callback, when it is an image
        data URL; None otherwise, and when the callback fails (the card
        then goes out as text: a missing picture never loses the card)."""
        if self.approval_image is None:
            return None
        try:
            image = self.approval_image(action)
        except Exception as exc:
            logger.warning("telegram_approval_image_failed", error_type=type(exc).__name__)
            return None
        if isinstance(image, str) and image.startswith("data:image/"):
            return image
        return None

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
        # top10:file_extraction: a message may carry media (a document, a
        # photo ...) with an optional caption instead of text.
        media = _media_kind(message)
        # A1, step 1 (no I/O): only a person writing in their own private
        # chat. Group, channel and bot messages are dropped silently.
        chat_id = _own_private_chat(message.get("chat"), message.get("from"))
        if chat_id is None or (not text and media is None):
            return
        if media is not None and not text:
            # A1, step 2 before anything else (no download, no reply) for an
            # unlinked chat. A caption is never parsed as a command here.
            media_user = await self._user_for_chat(chat_id)
            if media_user is None:
                logger.info("telegram_message_from_unlinked_chat_ignored", chat_id=chat_id)
                return
            route = self.media_routes.get(media)
            if route is None:
                await self._api(
                    "sendMessage",
                    chat_id=chat_id,
                    text="Crawler can't use that kind of message yet. Send text, a photo or a document.",
                )
                return
            await route(chat_id, media_user, message)
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
        handler = self._commands.get(command)
        if handler is not None:
            await handler(chat_id, user_id, argument.strip())
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
        text = _HELP_INTRO + "\n\n" + "\n".join([*HELP_LINES, _HELP_LAST_LINE])
        await self._api("sendMessage", chat_id=chat_id, text=text)

    async def _handle_apps(self, chat_id: int, user_id: str) -> None:
        """List the apps Crawler may use without asking (weekly app
        approvals), each with a Revoke button, whichever chat or browser
        allowed them: the owner sees every one from here."""
        from services.agent.app_approvals import DbAppApprovalStore

        try:
            approvals = await DbAppApprovalStore(self._session_factory).list_active(user_id)
        except Exception as exc:
            logger.warning("telegram_apps_lookup_failed", error=str(exc)[:200])
            await self._api(
                "sendMessage", chat_id=chat_id, text="Could not read the allowed apps right now."
            )
            return
        if not approvals:
            await self._api(
                "sendMessage",
                chat_id=chat_id,
                text=(
                    "No apps are allowed for a week. When Crawler asks to act in an app "
                    "like Calendar, the card has an \u201cAllow for 7 days\u201d button."
                ),
            )
            return
        here = Channel.telegram(chat_id)
        lines = [
            "Crawler scrolls and clicks around in these apps without a card, until the date shown:",
            "",
        ]
        buttons: list[list[dict[str, str]]] = []
        for approval in approvals:
            if approval.holds_for(here):
                where = "this chat"
            elif approval.channel_kind == "web":
                where = "the web app"
            else:
                where = "another Telegram chat"
            lines.append(f"\u2022 {approval.app} \u2014 from {where}, until {_day(approval.expires_at)}")
            buttons.append(
                [{"text": f"Revoke {approval.app}", "callback_data": _CB_REVOKE_APP + approval.id}]
            )
        await self._api(
            "sendMessage",
            chat_id=chat_id,
            text="\n".join(lines),
            reply_markup={"inline_keyboard": buttons},
        )

    async def _route_revoke_app(
        self,
        chat_id: Optional[int],
        approval_id: str,
        answer: Callable[[str], Awaitable[None]],
    ) -> None:
        """The /apps Revoke button (``rva:``), once the pressing account
        proves it owns a linked chat."""
        user_id = await self._user_for_chat(chat_id)
        if chat_id is None or user_id is None:
            await answer("This chat is not linked to a Crawler AI account.")
            return
        await self._handle_revoke_app(chat_id, user_id, approval_id, answer)

    async def _handle_revoke_app(
        self,
        chat_id: int,
        user_id: str,
        approval_id: str,
        answer: Callable[[str], Awaitable[None]],
    ) -> None:
        """A Revoke button from /apps: end that approval (the owner's own
        only; the store scopes by user) and say so in the chat. Audited as
        the web's revoke is."""
        from services.agent.app_approvals import DbAppApprovalStore

        try:
            revoked = await DbAppApprovalStore(self._session_factory).revoke(
                user_id=user_id, approval_id=approval_id
            )
        except Exception as exc:
            logger.warning("telegram_app_revoke_failed", error=str(exc)[:200])
            await answer("Could not revoke that right now.")
            return
        if revoked is None:
            await answer("That approval has already ended.")
            return
        await answer(f"{revoked.app} revoked.")
        await self._audit_app_revoke(user_id, revoked)
        await self._api(
            "sendMessage",
            chat_id=chat_id,
            text=(
                f"{revoked.app} is no longer allowed. The next action in "
                f"{revoked.app} will ask you first."
            ),
        )

    async def _audit_app_revoke(self, user_id: str, revoked: Any) -> None:
        """The ``app_approval_revoked`` row for a revoke from this chat.
        Best effort: revoking only takes a permission away."""
        from models.audit import AuditStatus
        from services.audit import append_audit_log

        try:
            async with self._session_factory() as session:
                await append_audit_log(
                    session,
                    user_id=user_id,
                    connector_name="desktop",
                    action="act",
                    endpoint="telegram:/apps",
                    scope_used="desktop",
                    status=AuditStatus.approved,
                    reasoning_chain={
                        "event": "app_approval_revoked",
                        "app": revoked.app,
                        "channel": revoked.channel_kind,
                        "app_approval_id": revoked.id,
                        "revoked_from": "telegram",
                    },
                )
                await session.commit()
        except Exception as exc:
            logger.error("telegram_app_revoke_audit_failed", error=str(exc)[:200])

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

    async def _handle_tutor(self, chat_id: int, user_id: str, argument: str) -> None:
        """/tutor on|off|status for the linked chat (services/tutor), never a
        model call. A pending /new is consumed, so "/new" then "/tutor on"
        switches the fresh thread the next message continues. Runs off the
        chat's turn lock, like /usage: a turn running meanwhile merges its
        own state over this one when it saves, so neither is lost."""
        from services.tutor.commands import parse_tutor_argument, usage_line

        command = parse_tutor_argument(argument)
        if command is None:
            await self._api("sendMessage", chat_id=chat_id, text=usage_line("telegram"))
            return
        if self.tutor is None:
            await self._api(
                "sendMessage", chat_id=chat_id, text="Tutor mode is not available right now."
            )
            return
        fresh = chat_id in self._fresh_chats
        self._fresh_chats.discard(chat_id)
        try:
            outcome = await self.tutor(
                user_id, command, new_conversation=fresh, text=f"/tutor {command}"
            )
        except Exception as exc:
            logger.error("telegram_tutor_failed", chat_id=chat_id, error_type=type(exc).__name__)
            outcome = {"error": "Tutor mode could not be changed right now."}
        if outcome.get("error"):
            if fresh:
                # The /new it carried was not used: keep it for the next message.
                self._fresh_chats.add(chat_id)
            await self._api(
                "sendMessage", chat_id=chat_id, text=f"⚠️ {outcome['error']}"[:_MESSAGE_CHUNK]
            )
            return
        await self._api(
            "sendMessage", chat_id=chat_id, text=str(outcome.get("reply") or "")[:_MESSAGE_CHUNK]
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
        # A key, card or ID number in the person's own message: the model
        # never sees it (the model floor), but Telegram keeps the message.
        warning = secret_text.inbound_warning(text, app="Telegram")
        if warning is not None:
            await self._api("sendMessage", chat_id=chat_id, text=warning)
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
                await self._run_turn_locked(chat_id, user_id, text, fresh, stop_mark)
        except asyncio.CancelledError:
            if fresh and not started:
                # Stopped while still queued behind another turn: the /new
                # it carried was never used, so keep it for the next message.
                self._fresh_chats.add(chat_id)
            raise

    async def _run_turn_locked(
        self,
        chat_id: int,
        user_id: str,
        text: str,
        fresh: bool,
        stop_mark: int,
        extra: Optional[dict[str, Any]] = None,
    ) -> None:
        """One agent turn for *text*, its progress lines and its reply; the
        caller holds the chat's lock. Shared by typed messages and voice
        notes (top10:voice_notes). *extra* holds further keywords for the
        chat callback (a voice note's ``attachments`` and ``usage_seed``),
        each passed only when the callback accepts it."""
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
            # This chat, for the apps allowed for a week from it.
            if takes_keyword(self.chat, "channel"):
                listen["channel"] = Channel.telegram(chat_id)
            for name, value in (extra or {}).items():
                if value is not None and takes_keyword(self.chat, name):
                    listen[name] = value
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
        reply = _with_turn_notes((outcome.get("content") or "").strip(), outcome)
        if not reply:
            reply = "(The assistant returned no text.)"
        # Photos first, so the text (which ends with the usage line)
        # is the last thing the turn sends.
        for image in outcome.get("images") or []:
            await self._send_photo(
                chat_id, image.get("data_url", ""), image.get("caption", "")
            )
        await self._send_reply(chat_id, reply, outcome)

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
        thing in the last message however long the reply is. The reply is
        masked whole before it is split (a value never straddles two
        messages), with one footer when anything was hidden."""
        text = secret_text.mask_reply(text, app="Telegram", channel="telegram")
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

    # ── files and photos (top10:file_extraction) ─────────────────────────

    async def _route_file_message(self, chat_id: int, user_id: str, message: dict[str, Any]) -> None:
        """A document or photo from the linked chat: checked against "Read
        files and documents" before anything is downloaded, then read as
        one turn (an album's messages are gathered first)."""
        if self.chat is None:
            await self._handle_help(chat_id)
            return
        group = message.get("media_group_id")
        key = (chat_id, group) if isinstance(group, str) and group else None
        if key is not None:
            waiting = self._media_groups.get(key)
            if waiting is not None:
                # A later message of an album already being gathered (or
                # already refused: its reply went out once).
                if len(waiting) < MAX_FILES_PER_TURN and not self._refused_group(key):
                    waiting.append(message)
                return
        if message.get("document") is not None:
            gate = getattr(self.chat, "file_gate", None)
            refusal = await gate() if callable(gate) else None
            if refusal is None and not takes_keyword(self.chat, "files"):
                refusal = "This bot can't read files yet."
            if refusal is not None:
                if key is not None:
                    # The album's other messages are dropped silently.
                    self._media_groups[key] = [{"refused": True}]
                    self._track(
                        chat_id, self._flush_media_group(chat_id, user_id, key), name=f"telegram-album-{chat_id}"
                    )
                await self._api("sendMessage", chat_id=chat_id, text=f"⚠️ {refusal}"[:_MESSAGE_CHUNK])
                return
        if key is not None:
            self._media_groups[key] = [message]
            self._track(chat_id, self._flush_media_group(chat_id, user_id, key), name=f"telegram-album-{chat_id}")
            return
        self._start_file_turn(chat_id, user_id, [message])

    def _refused_group(self, key: tuple[int, str]) -> bool:
        waiting = self._media_groups.get(key) or []
        return bool(waiting) and waiting[0].get("refused") is True

    async def _flush_media_group(self, chat_id: int, user_id: str, key: tuple[int, str]) -> None:
        try:
            await asyncio.sleep(self._media_group_wait_s)
        finally:
            refused = self._refused_group(key)
            messages = self._media_groups.pop(key, [])
        if messages and not refused:
            self._start_file_turn(chat_id, user_id, messages[:MAX_FILES_PER_TURN])

    def _start_file_turn(self, chat_id: int, user_id: str, messages: list[dict[str, Any]]) -> None:
        fresh = chat_id in self._fresh_chats
        self._fresh_chats.discard(chat_id)
        stop_mark = agent_cancel.mark(user_id)
        self._track(
            chat_id,
            self._run_file_turn(chat_id, user_id, messages, fresh, stop_mark),
            name=f"telegram-chat-{chat_id}",
        )

    async def _download_media(
        self, chat_id: int, messages: list[dict[str, Any]]
    ) -> tuple[list[Any], list[dict[str, str]], Optional[str]]:
        """The documents (as InboundFile) and photos (as image dicts) of
        *messages*, or the reply that ends the turn when one cannot be
        fetched. Runs inside the tracked task, so /stop cancels it."""
        from services.files.intake import InboundFile
        from services.files.limits import UPLOAD
        from services.files.messages import too_large
        from services.files.prompting import sanitize_display_name
        from services.notifications.telegram_files import TelegramFileError, download_telegram_file

        files: list[Any] = []
        images: list[dict[str, str]] = []
        for message in messages:
            document = message.get("document")
            if isinstance(document, dict):
                name = sanitize_display_name(document.get("file_name") or "file")
                size = document.get("file_size")
                if isinstance(size, int) and size > UPLOAD.max_bytes:
                    return [], [], f"I couldn't read {name}: {too_large(size, UPLOAD.max_bytes)}"
                try:
                    data = await download_telegram_file(
                        self._client, self._token, str(document.get("file_id")), max_bytes=UPLOAD.max_bytes
                    )
                except TelegramFileError as exc:
                    reason = (
                        too_large(size if isinstance(size, int) else None, UPLOAD.max_bytes)
                        if exc.code == "too_large"
                        else "Telegram did not hand the file over. Try sending it again."
                    )
                    return [], [], f"I couldn't read {name}: {reason}"
                files.append(
                    InboundFile(
                        name=name,
                        media_type=str(document.get("mime_type") or "")[:100],
                        data=data,
                        source="telegram",
                    )
                )
                continue
            photo = _largest_photo(message.get("photo"))
            if photo is None:
                if message.get("photo"):
                    return [], [], "I couldn't use that photo: it is larger than 5 MB."
                continue
            try:
                raw = await download_telegram_file(
                    self._client, self._token, str(photo["file_id"]), max_bytes=MAX_PHOTO_BYTES
                )
            except TelegramFileError:
                return [], [], "I couldn't use that photo: Telegram did not hand it over."
            images.append({"media_type": "image/jpeg", "data": base64.b64encode(raw).decode("ascii")})
        return files, images, None

    async def _run_file_turn(
        self,
        chat_id: int,
        user_id: str,
        messages: list[dict[str, Any]],
        fresh: bool,
        stop_mark: int,
    ) -> None:
        """One turn for a file message (or an album): a silent "Reading x…"
        line, the downloads, then the caption's route or the chat with
        ``files=`` and ``images=``. A file that cannot be fetched or read
        ends the turn with "⚠️ I couldn't read x: <reason>" and no model
        call."""
        from services.files.prompting import sanitize_display_name

        started = False
        try:
            lock = self._chat_locks.setdefault(chat_id, asyncio.Lock())
            async with lock:
                started = True
                caption = next(
                    ((m.get("caption") or "").strip() for m in messages if (m.get("caption") or "").strip()),
                    "",
                )
                documents = [m["document"] for m in messages if isinstance(m.get("document"), dict)]
                if documents:
                    first = sanitize_display_name(documents[0].get("file_name") or "file")
                    line = f"📄 Reading {first}…" if len(documents) == 1 else f"📄 Reading {len(documents)} files…"
                    await self._api("sendMessage", chat_id=chat_id, text=line[:200], disable_notification=True)
                files, images, problem = await self._download_media(chat_id, messages)
                if problem is not None:
                    await self._api("sendMessage", chat_id=chat_id, text=f"⚠️ {problem}"[:_MESSAGE_CHUNK])
                    return
                word, _, rest = caption.partition(" ")
                caption_route = self.file_caption_routes.get(word.split("@", 1)[0].lower()) if word else None
                if caption_route is not None:
                    await caption_route(chat_id, user_id, rest.strip(), files)
                    return
                await self._chat_with_media(chat_id, user_id, caption, files, images, fresh, stop_mark)
        except asyncio.CancelledError:
            if fresh and not started:
                self._fresh_chats.add(chat_id)
            raise

    async def _chat_with_media(
        self,
        chat_id: int,
        user_id: str,
        caption: str,
        files: list[Any],
        images: list[dict[str, str]],
        fresh: bool,
        stop_mark: int,
    ) -> None:
        """The chat turn for a file message, with the same progress lines,
        typing indicator and reply as a text turn (_run_chat)."""
        assert self.chat is not None
        await self._api("sendChatAction", chat_id=chat_id, action="typing")
        typing = asyncio.create_task(self._keep_typing(chat_id))
        progress = self._turn_progress(chat_id)
        try:
            listen: dict[str, Any] = {"on_event": progress.on_event} if takes_on_event(self.chat) else {}
            if takes_keyword(self.chat, "stop_mark"):
                listen["stop_mark"] = stop_mark
            if takes_keyword(self.chat, "channel"):
                listen["channel"] = Channel.telegram(chat_id)
            if files:
                listen["files"] = files
            if images and takes_keyword(self.chat, "images"):
                listen["images"] = images
            outcome = await self.chat(user_id, caption, new_conversation=fresh, **listen)
        except Exception as exc:
            logger.error("telegram_chat_failed", chat_id=chat_id, error_type=type(exc).__name__)
            outcome = {"error": "The assistant hit an unexpected error."}
        finally:
            typing.cancel()
            await progress.aclose()
        if outcome.get("error"):
            await self._api("sendMessage", chat_id=chat_id, text=f"⚠️ {outcome['error']}"[:_MESSAGE_CHUNK])
            return
        reply = _with_turn_notes((outcome.get("content") or "").strip(), outcome)
        for image in outcome.get("images") or []:
            await self._send_photo(chat_id, image.get("data_url", ""), image.get("caption", ""))
        await self._send_reply(chat_id, reply or "(The assistant returned no text.)", outcome)

    # ── voice notes (top10:voice_notes) ──────────────────────────────────

    async def _route_voice_message(self, chat_id: int, user_id: str, message: dict[str, Any]) -> None:
        """A voice note, audio file or video note from the linked chat (the
        A1 checks already passed). The rest runs as this chat's tracked
        work, so /stop cancels the download and kills the worker."""
        kind = _media_kind(message) or "voice"
        if self.voice is None or self.chat is None:
            text = TEXT_VIDEO_NOTE if kind == "video_note" else TEXT_NOT_SET_UP
            await self._api("sendMessage", chat_id=chat_id, text=text)
            return
        meta = _voice_meta(kind, message)
        fresh = chat_id in self._fresh_chats
        self._fresh_chats.discard(chat_id)
        # Accepted now, as a typed message is (see _handle_chat).
        stop_mark = agent_cancel.mark(user_id)
        self._track(
            chat_id,
            self._run_voice(chat_id, user_id, meta, fresh, stop_mark),
            name=f"telegram-chat-{chat_id}",
        )

    async def _run_voice(
        self, chat_id: int, user_id: str, meta: VoiceNoteMeta, fresh: bool, stop_mark: int
    ) -> None:
        """Under the chat's lock: the precheck (switches, engine, declared
        size and length, quota; a refusal is a text reply and nothing is
        downloaded), the bounded download, the transcription, the silent
        echo, then the same turn a typed message gets. The audio is held in
        memory only for as long as the transcription takes."""
        from services.notifications.telegram_files import TelegramFileError, download_telegram_file
        from services.tools.transcribe import MAX_AUDIO_BYTES

        assert self.voice is not None
        turn_started = False
        try:
            lock = self._chat_locks.setdefault(chat_id, asyncio.Lock())
            async with lock:
                if agent_cancel.stopped_since(user_id, stop_mark):
                    return
                decision = await self.voice.precheck(user_id, meta)
                if not decision.ok:
                    await self._api("sendMessage", chat_id=chat_id, text=decision.refusal)
                    return
                await self._api("sendChatAction", chat_id=chat_id, action="typing")
                typing = asyncio.create_task(self._keep_typing(chat_id))
                try:
                    try:
                        audio = await download_telegram_file(
                            self._client, self._token, meta.file_id, max_bytes=MAX_AUDIO_BYTES
                        )
                    except TelegramFileError as exc:
                        reason = "too_large" if exc.code == "too_large" else "download_failed"
                        refusal = await self.voice.refused(user_id, meta, reason, engine=decision.engine)
                        await self._api("sendMessage", chat_id=chat_id, text=refusal)
                        return
                    turn = await self.voice.transcribe(user_id, meta, audio, decision)
                    del audio
                finally:
                    typing.cancel()
                if agent_cancel.stopped_since(user_id, stop_mark):
                    return
                if not turn.ok:
                    await self._api("sendMessage", chat_id=chat_id, text=turn.refusal)
                    return
                for chunk in _chunks(turn.echo):
                    await self._api(
                        "sendMessage", chat_id=chat_id, text=chunk, disable_notification=True
                    )
                # A key, card or ID number said out loud: the model never
                # sees it (the model floor), but Telegram keeps the recording,
                # as it keeps a typed message (see _handle_chat).
                warning = secret_text.inbound_warning(turn.echo, app="Telegram")
                if warning is not None:
                    await self._api("sendMessage", chat_id=chat_id, text=warning)
                if not turn.turn_text:
                    # Withheld (it read like instructions to an AI): the echo
                    # says so, and no turn runs on it.
                    return
                turn_started = True
                await self._run_turn_locked(
                    chat_id,
                    user_id,
                    turn.turn_text,
                    fresh,
                    stop_mark,
                    {"attachments": [turn.attachment], "usage_seed": turn.usage},
                )
        finally:
            if fresh and not turn_started:
                # No turn used the /new this note carried: keep it.
                self._fresh_chats.add(chat_id)

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

        prefix, target = data[:_CB_PREFIX_LEN], data[_CB_PREFIX_LEN:]
        if prefix not in (_CB_APPROVE, _CB_DENY, _CB_APPROVE_WEEK, _CB_APPROVE_LOW_RISK):
            # Every other button is a route; each one checks the chat itself.
            route = self._callback_routes.get(prefix)
            if route is None:
                logger.warning("telegram_callback_unknown_prefix", data=data[:32])
                await answer("Unknown action.")
                return
            await route(chat_id, target, answer)
            return
        approved = prefix != _CB_DENY
        # "Allow <app> for 7 days" approves the card and remembers the app;
        # "Allow low-risk on <account>" approves it and allows the account.
        remember = (
            REMEMBER_WEEK
            if prefix == _CB_APPROVE_WEEK
            else REMEMBER_LOW_RISK if prefix == _CB_APPROVE_LOW_RISK else None
        )
        action_id = target
        logger.info(
            "telegram_callback_received",
            chat_id=chat_id,
            approved=approved,
            remember=remember,
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
            self._run_decision(
                chat_id, user_id, action_id, approved, message, message_id, remember
            ),
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
        remember: Optional[str] = None,
    ) -> None:
        lock = self._chat_locks.setdefault(chat_id, asyncio.Lock())
        async with lock:
            await self._apply_decision(
                chat_id, user_id, action_id, approved, message, message_id, remember
            )

    async def _apply_decision(
        self,
        chat_id: int,
        user_id: str,
        action_id: str,
        approved: bool,
        message: dict[str, Any],
        message_id: Any,
        remember: Optional[str] = None,
    ) -> None:
        """Apply one Approve/Deny press, then freeze the card and send the
        resumed turn's reply. While an approval runs, the chat shows
        "typing…" and progress lines, as a message turn does. The press was
        already answered, so a failure goes to the chat as a message.

        The decision carries this chat (``channel``): the resumed turn's acts
        in an app allowed for a week from here need no card, and with
        ``remember="week"`` (the "Allow for 7 days" button) the card's app is
        allowed from this chat."""
        assert self.decide is not None
        typing: Optional[asyncio.Task[None]] = None
        progress: Optional[TurnProgress] = None
        listen: dict[str, Any] = {}
        if takes_keyword(self.decide, "channel"):
            listen["channel"] = Channel.telegram(chat_id)
        if remember and takes_keyword(self.decide, "remember"):
            listen["remember"] = remember
        if approved:
            await self._api("sendChatAction", chat_id=chat_id, action="typing")
            typing = asyncio.create_task(self._keep_typing(chat_id))
            progress = self._turn_progress(chat_id)
            # A callback without on_event still decides; it gets no lines.
            if takes_on_event(self.decide):
                listen["on_event"] = progress.on_event
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
        # "Allow for 7 days": the card says until when, and how to undo it.
        weekly = outcome.get("weekly")
        allowed = (
            f" {weekly['app']} is allowed for 7 days, until "
            f"{_day(weekly.get('expires_at'))}. /apps to revoke."
            if isinstance(weekly, dict) and weekly.get("app")
            else ""
        )
        # "Allow low-risk on <account>": until when, and how to undo it; a
        # grant that could not be made (the switch is off, the action no
        # longer grades LOW) leaves the card approved once.
        low_risk = outcome.get("low_risk")
        if isinstance(low_risk, dict) and low_risk.get("account"):
            allowed = (
                f" Low-risk changes on {low_risk['account']} are allowed until "
                f"{_day(low_risk.get('expires_at'))}. /grants to revoke."
            )
        elif approved and remember == REMEMBER_LOW_RISK:
            allowed = " (approved once)"
        # Freeze the card: replace the buttons with the decision so it
        # can't be pressed twice from the chat history. A photo card (a
        # purchase) has a caption, not text, and is edited as one.
        if message_id is not None and message.get("photo"):
            original = message.get("caption") or "Purchase approval"
            await self._api(
                "editMessageCaption",
                chat_id=chat_id,
                message_id=message_id,
                caption=f"{original}\n\n— {verdict} from this chat.{allowed}"[:1024],
            )
        elif message_id is not None:
            original = message.get("text") or "Approval request"
            await self._api(
                "editMessageText",
                chat_id=chat_id,
                message_id=message_id,
                text=f"{original}\n\n— {verdict} from this chat.{allowed}",
            )
        summary = outcome.get("summary")
        if summary:
            # The resumed turn's reply, in full and with its own usage line,
            # after the photos it captured and with the card it parked or
            # the block it met named, as a message turn's reply is.
            for image in outcome.get("images") or []:
                await self._send_photo(
                    chat_id, image.get("data_url", ""), image.get("caption", "")
                )
            await self._send_reply(chat_id, _with_turn_notes(str(summary), outcome), outcome)


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
