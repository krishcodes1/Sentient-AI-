"""Telegram and Slack entry points of the scam check (security S3): /scam in
the linked Telegram chat (a text, a reply, a photo's caption, an album, or a
bare /scam and then the forwarded message), and "scam ...", "is this a
scam ..." or a bare "scam" in a Slack DM (with a shared screenshot too).

Why it exists: the channels already route every message to a chat turn; a
scam check must take its message first (before any command, media route or
turn), so the pasted content never runs as a turn and is stored fenced as
someone else's words. Telegram calls ``TelegramService.message_interceptors``
(after the A1 link check, and before the forwarded-text fence, any command,
media route or turn); Slack inserts a handler ahead of its audio and files
handlers, so a shared screenshot is checked, not read as a document.

How a check runs: the interceptor decides with no I/O beyond the service's
precheck (switch and quota, before any download), then the work runs as the
chat's tracked task under its lock, so /stop (Telegram) and "stop" (Slack)
cancel it: the sizes the channel declares are checked, a silent
"Checking..." line and the typing indicator go out, the downloads run
(pictures at most 5 MB and sniffed; anything else hashed up to 20 MB and
dropped, so only its sha256 is looked up), then one ``ScamCheckService.check``,
the plain defanged verdict with the usage line, and both rows in the
channel's thread (``records.record_channel_check``). Every refusal the channel
meets itself (too large, a download that failed, voice or audio) is audited
through ``ScamCheckService.refused``. A forwarded Telegram message is never
read as a /scam command (it is someone else's words, scaffold A31), but a
chat armed by a bare /scam takes it for checking.

Privacy: logs carry error type names only, never the message, a note, a
link, a file name, the bot token or a download address. Pictures and files
live in memory for one check; files leave only their fingerprint.

Connects to: services/notifications/telegram.py and slack.py (they call the
register functions at construction and hold ``scam_check``, the process's
one ScamCheckService main.py wires), services/scam_check/service.py,
verdict.py (``render_plain``) and records.py (``record_channel_check``).
"""

from __future__ import annotations

import asyncio
import base64
import dataclasses
import hashlib
import re
import time
from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable, Optional, TypeGuard, Union

import structlog

from services.scam_check.records import record_channel_check
from services.scam_check.review import IMAGE_TYPES, MAX_IMAGE_BYTES
from services.scam_check.service import ScamCheckRequest, ScamCheckResult, ScamFile, ScamImage
from services.scam_check.verdict import render_plain
from services.scam_check.web import NO_SERVICE
from services.security.scam_signals import MAX_ANCHORS, MAX_LABEL_CHARS, MAX_URL_CHARS

logger = structlog.get_logger(__name__)

# How long a bare /scam keeps the chat waiting for the message to check.
ARM_SECONDS = 120.0
# The most pictures one check reads (an album, or a reply with several).
MAX_CHECK_IMAGES = 4
# The most other files one check looks up by fingerprint.
MAX_CHECK_FILES = 4
# How long a claimed album keeps taking its later messages (Telegram sends an
# album's items one by one, within a second or two).
ALBUM_CLAIM_S = 10.0
# The most messages one claimed album keeps (Telegram's own album limit is 10).
MAX_ALBUM_ITEMS = 10
# The most claimed albums remembered at once.
MAX_ALBUMS = 32
# The most Telegram entities read from one message.
MAX_ENTITIES = 100
# Longest Telegram reply message, with headroom (telegram._MESSAGE_CHUNK).
TELEGRAM_CHUNK = 3900

# "/scam" (or "/scam@bot") at the very start, then whitespace or the end.
SCAM_RE = re.compile(r"^/scam(?:@\w+)?(?=\s|$)\s*(?P<rest>.*)$", re.IGNORECASE | re.DOTALL)
# Slack: "scam", "scam check", "is this a scam" or "is it a scam", followed by
# whitespace, punctuation or the end ("scammers are awful" goes to the chat).
SLACK_RE = re.compile(
    r"^(?:is\s+(?:this|it)\s+(?:a\s+)?scam|scam(?:\s+check)?)(?=$|[\s:,.!?-])[\s:,.!?-]*(?P<rest>.*)$",
    re.IGNORECASE | re.DOTALL,
)

# What the person sees. Fixed text: never the checked content.
CHECKING = "\U0001f50e Checking for signs of a scam\u2026"
TELEGRAM_ARMED = (
    "\U0001f50e Send or forward the message, link, screenshot or QR code you want checked. "
    "I'll check the next thing you send in the next 2 minutes instead of answering it."
)
SLACK_ARMED = (
    "\U0001f50e Send or paste the message, link or screenshot you want checked. "
    "I'll check the next thing you send in the next 2 minutes instead of answering it."
)
PICTURE_TOO_LARGE = "That picture is over 5 MB. Send a smaller screenshot."
FILE_TOO_LARGE = "That file is over 20 MB, so I couldn't check it."
TELEGRAM_PICTURE_FAILED = "I couldn't get that picture from Telegram. Try sending it again."
TELEGRAM_FILE_FAILED = "I couldn't get that file from Telegram. Try sending it again."
SLACK_DOWNLOAD_FAILED = "I couldn't get that file from Slack. Try sharing it again."
TEXT_UNSUPPORTED_MEDIA = (
    "I can't check voice notes, audio or video for scams. Paste the text or the link, "
    "or send a screenshot instead."
)
UNEXPECTED_ERROR = "\u26a0\ufe0f The scam check hit an unexpected error."
MORE_PICTURES = f"Only the first {MAX_CHECK_IMAGES} pictures were checked."
MORE_FILES = f"Only the first {MAX_CHECK_FILES} files were checked."

# Telegram media a scam check cannot read (a voice note, audio, a video).
_UNSUPPORTED_KINDS: tuple[str, ...] = ("voice", "audio", "video", "video_note", "animation", "sticker")


class _Refused(Exception):
    """A check the channel itself refused before calling the service: the
    sentence to send and the audit reason (too_large, download_failed,
    unsupported_media)."""

    def __init__(self, sentence: str, reason: str) -> None:
        super().__init__(reason)
        self.sentence = sentence
        self.reason = reason


def _is_count(value: Any) -> TypeGuard[int]:
    """A whole number of at least zero (never a bool)."""
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0


def _picture_or_file(raw: bytes, source: str) -> Union[ScamImage, ScamFile]:
    """Downloaded bytes as a picture when they really are a PNG, JPEG, WebP or
    GIF (sniffed as the service does), else as a file to look up by its
    fingerprint: an "image" that is not one is never passed off as a picture,
    and never skipped either."""
    from services.files.detect import detect

    try:
        found = detect(raw)
    except Exception:  # ExtractionRefused and anything a hostile file provokes
        found = None
    if found is not None and found.kind == "image" and found.media_type in IMAGE_TYPES:
        return ScamImage(media_type=found.media_type, data=base64.b64encode(raw).decode("ascii"), source=source)
    return _fingerprint(raw)


def _fingerprint(raw: bytes) -> ScamFile:
    return ScamFile(sha256=hashlib.sha256(raw).hexdigest(), size_bytes=len(raw))


def _usage_line(result: ScamCheckResult) -> str:
    """The check's token and cost line, as a chat turn's reply ends with it;
    "" when the check made no model call (or was answered from memory)."""
    if not result.usage:
        return ""
    from services.usage import format_turn_usage_line

    return format_turn_usage_line(dict(result.usage), result.provider or None, result.model or None, None)


def _rendered(result: ScamCheckResult, extras: list[str]) -> str:
    """The plain verdict (defanged by render_plain) and the channel's own lines:
    what is saved as the reply row."""
    text = render_plain(result)
    if extras:
        text += "\n\n" + "\n".join(extras)
    return text


def _with_usage(rendered: str, result: ScamCheckResult) -> str:
    line = _usage_line(result)
    return f"{rendered}\n\n{line}" if line else rendered


async def _nothing() -> None:
    """The empty reply of a Slack handler that started its work itself."""
    return None


async def _audit_refusal(scam: Any, user_id: str, channel: str, reason: str) -> None:
    """The scam_check_refused row for a refusal the channel met itself. Best
    effort: the person still gets the refusal when the row cannot be written."""
    try:
        await scam.refused(user_id, channel, reason)
    except Exception as exc:
        logger.error("scam_check_channel_audit_failed", channel=channel, error_type=type(exc).__name__)


# ── Telegram ─────────────────────────────────────────────────────────────


def _text_links(text: Any, entities: Any) -> tuple[tuple[str, str], ...]:
    """(label, address) for a message's hidden links (Telegram ``text_link``
    entities): the label is the shown words, cut from *text* by the entity's
    offset and length in UTF-16 units, as Telegram counts them. At most
    MAX_ANCHORS; anything malformed is skipped."""
    if not isinstance(text, str) or not text or not isinstance(entities, list):
        return ()
    units = text.encode("utf-16-le", "surrogatepass")
    found: list[tuple[str, str]] = []
    for entity in entities[:MAX_ENTITIES]:
        if not isinstance(entity, dict) or entity.get("type") != "text_link":
            continue
        url, offset, length = entity.get("url"), entity.get("offset"), entity.get("length")
        if not isinstance(url, str) or not url or len(url) > MAX_URL_CHARS:
            continue
        if not _is_count(offset) or not _is_count(length) or length == 0:
            continue
        start, end = offset * 2, (offset + length) * 2
        if end > len(units):
            continue
        label = units[start:end].decode("utf-16-le", "ignore")[:MAX_LABEL_CHARS]
        if label.strip():
            found.append((label, url))
        if len(found) >= MAX_ANCHORS:
            break
    return tuple(found)


def _message_text(message: dict[str, Any]) -> tuple[str, Any]:
    """A Telegram message's own words and their entities: its text, else its caption."""
    text = message.get("text")
    if isinstance(text, str) and text:
        return text, message.get("entities")
    caption = message.get("caption")
    if isinstance(caption, str) and caption:
        return caption, message.get("caption_entities")
    return "", None


@dataclass(frozen=True)
class _Content:
    """What one Telegram check reads: the text (someone else's words), the
    person's note (their own words, kept outside the fence), the hidden links,
    the messages whose photos and documents are checked, whether the content
    is someone else's forward, where its pictures came from, and how many
    album items arrived past the cap."""

    text: str = ""
    note: str = ""
    anchors: tuple[tuple[str, str], ...] = ()
    messages: tuple[dict[str, Any], ...] = ()
    forwarded: bool = False
    source: str = "photo"
    dropped: int = 0


@dataclass
class _Album:
    """A media group a /scam caption (or an armed chat) claimed: its messages
    as they arrive, until the claim ends."""

    claimed_at: float
    messages: list[dict[str, Any]] = field(default_factory=list)
    dropped: int = 0

    def add(self, message: dict[str, Any]) -> None:
        if len(self.messages) < MAX_ALBUM_ITEMS:
            self.messages.append(message)
        else:
            self.dropped += 1


@dataclass(frozen=True)
class _Item:
    """One photo or document to download: Telegram's file_id, whether it is
    meant as a picture (a photo, or a document declared image/*), and the
    picture's source tag."""

    file_id: str
    picture: bool
    source: str


@dataclass(frozen=True)
class _Plan:
    """What a check will download (before any download), and the reply's
    extra lines for what was left out."""

    pictures: tuple[Any, ...]
    files: tuple[Any, ...]
    extras: tuple[str, ...]


class TelegramScamChecks:
    """The Telegram interceptor: /scam text, replies, captions, albums, and the
    message after a bare /scam. *service* is the TelegramService (its
    ``scam_check`` is read per message, so main.py may wire it later)."""

    def __init__(self, service: Any, *, clock: Callable[[], float] = time.monotonic) -> None:
        self._service = service
        self._clock = clock
        # chat id -> when the bare /scam's wait ends (the clock's time).
        self._armed: dict[int, float] = {}
        # (chat id, media_group_id) -> the album a /scam claimed.
        self._groups: dict[tuple[int, str], _Album] = {}

    # ── deciding (no I/O beyond the precheck) ──────────────────────────

    async def intercept(self, chat_id: int, user_id: str, message: dict[str, Any]) -> bool:
        """True when this message is S3's: a /scam text (with or without a
        reply), a /scam caption, a message while the chat is armed, or a later
        item of an album S3 claimed. Decides without I/O beyond the precheck;
        the work runs as the chat's tracked task under its lock."""
        if not isinstance(message, dict):
            return False
        from services.notifications.telegram import _is_forwarded

        now = self._clock()
        self._forget_old(now)
        key = self._group_key(chat_id, message)
        if key is not None and key in self._groups:
            self._groups[key].add(message)
            return True
        forwarded = _is_forwarded(message)
        own_text = message.get("text")
        words = _message_text(message)[0].strip()
        if not forwarded and words:
            match = SCAM_RE.match(words)
            if match is not None:
                self._armed.pop(chat_id, None)
                rest = match.group("rest").strip()
                if isinstance(own_text, str) and own_text.strip():
                    await self._command(chat_id, user_id, message, rest, now)
                else:
                    await self._caption(chat_id, user_id, message, rest, now)
                return True
        until = self._armed.pop(chat_id, None)
        if until is None or now >= until:
            return False
        if not forwarded and words.startswith("/"):
            # Another command cancels the wait and runs as usual.
            return False
        await self._armed_message(chat_id, user_id, message, forwarded, now)
        return True

    @staticmethod
    def _group_key(chat_id: int, message: dict[str, Any]) -> Optional[tuple[int, str]]:
        group = message.get("media_group_id")
        return (chat_id, group) if isinstance(group, str) and group else None

    def _forget_old(self, now: float) -> None:
        """Drop expired waits and albums claimed long enough ago."""
        for chat, until in list(self._armed.items()):
            if now >= until:
                del self._armed[chat]
        wait_s = getattr(self._service, "_media_group_wait_s", 2.0)
        keep_s = max(ALBUM_CLAIM_S, 4 * float(wait_s if isinstance(wait_s, (int, float)) else 2.0))
        for key, album in list(self._groups.items()):
            if now - album.claimed_at >= keep_s:
                del self._groups[key]
        while len(self._groups) > MAX_ALBUMS:
            del self._groups[next(iter(self._groups))]

    def _claim(self, key: tuple[int, str], message: dict[str, Any], now: float) -> None:
        """Claim an album for checking. Its items that arrived before the
        /scam caption, which the bot is still gathering into a file turn, are
        taken over, so someone else's screenshot never becomes a turn."""
        album = _Album(claimed_at=now)
        gathering = getattr(self._service, "_media_groups", None)
        earlier = gathering.pop(key, None) if isinstance(gathering, dict) else None
        for item in earlier if isinstance(earlier, list) else []:
            if isinstance(item, dict) and item.get("refused") is not True:
                album.add(item)
        album.add(message)
        self._groups[key] = album

    async def _send(self, chat_id: int, text: str, *, silent: bool = False) -> None:
        """One message through TelegramService._api, which masks secrets and
        keeps link previews off."""
        params: dict[str, Any] = {"chat_id": chat_id, "text": text}
        if silent:
            params["disable_notification"] = True
        await self._service._api("sendMessage", **params)

    async def _refusal(self, user_id: str) -> Optional[str]:
        """The precheck's refusal (switch, quota; audited by the service),
        NO_SERVICE without a wired service, or None. Read before any
        download; takes no quota."""
        scam = getattr(self._service, "scam_check", None)
        if scam is None:
            return NO_SERVICE
        try:
            refusal = await scam.precheck(user_id, "telegram")
        except Exception as exc:
            logger.error("scam_check_channel_failed", channel="telegram", error_type=type(exc).__name__)
            return UNEXPECTED_ERROR
        return refusal if isinstance(refusal, str) and refusal else None

    async def _command(self, chat_id: int, user_id: str, message: dict[str, Any], rest: str, now: float) -> None:
        """/scam as a text message: check the replied-to message (the rest is
        the person's note), else the rest of the message, else arm the chat."""
        refusal = await self._refusal(user_id)
        if refusal is not None:
            await self._send(chat_id, refusal)
            return
        from services.notifications.telegram import _is_forwarded

        reply = message.get("reply_to_message")
        external = message.get("external_reply")
        replied = reply if isinstance(reply, dict) else external if isinstance(external, dict) else None
        if replied is not None:
            text, entities = _message_text(replied)
            quote = message.get("quote")
            quoted = quote.get("text") if isinstance(quote, dict) and isinstance(quote.get("text"), str) else ""
            content = _Content(
                text=(quoted or text).strip(),
                note=rest,
                anchors=_text_links(text, entities),
                messages=(replied,),
                # A message from another chat is someone else's, like a forward.
                forwarded=_is_forwarded(replied) or replied is external,
                source="reply",
            )
        elif rest:
            content = _Content(text=rest, anchors=_text_links(message.get("text"), message.get("entities")))
        else:
            self._armed[chat_id] = now + ARM_SECONDS
            await self._send(chat_id, TELEGRAM_ARMED)
            return
        self._start(chat_id, user_id, content)

    async def _caption(self, chat_id: int, user_id: str, message: dict[str, Any], rest: str, now: float) -> None:
        """/scam as a photo's or document's caption: that media (with an
        album's other pictures) and the rest of the caption are checked."""
        key = self._group_key(chat_id, message)
        if key is not None:
            # Claimed first: a refusal still keeps the album's later items out of a turn.
            self._claim(key, message, now)
        refusal = await self._refusal(user_id)
        if refusal is not None:
            await self._send(chat_id, refusal)
            return
        caption, entities = _message_text(message)
        content = _Content(text=rest, anchors=_text_links(caption, entities), messages=(message,))
        if key is not None:
            self._start_album(chat_id, user_id, key, content)
        else:
            self._start(chat_id, user_id, content)

    async def _armed_message(
        self, chat_id: int, user_id: str, message: dict[str, Any], forwarded: bool, now: float
    ) -> None:
        """The message after a bare /scam: its text or caption, its media and
        its hidden links are the content (an album is gathered first)."""
        key = self._group_key(chat_id, message)
        if key is not None:
            self._claim(key, message, now)
        refusal = await self._refusal(user_id)
        if refusal is not None:
            await self._send(chat_id, refusal)
            return
        text, entities = _message_text(message)
        content = _Content(
            text=text.strip(), anchors=_text_links(text, entities), messages=(message,), forwarded=forwarded
        )
        if key is not None:
            self._start_album(chat_id, user_id, key, content)
        else:
            self._start(chat_id, user_id, content)

    # ── running (the chat's tracked work) ───────────────────────────────

    def _take_fresh(self, chat_id: int) -> bool:
        """The chat's pending /new, taken now (as a chat turn takes it)."""
        fresh_chats = self._service._fresh_chats
        fresh = chat_id in fresh_chats
        fresh_chats.discard(chat_id)
        return bool(fresh)

    def _start(self, chat_id: int, user_id: str, content: _Content) -> None:
        fresh = self._take_fresh(chat_id)
        self._service._track(chat_id, self._run(chat_id, user_id, content, fresh), name=f"telegram-chat-{chat_id}")

    def _start_album(self, chat_id: int, user_id: str, key: tuple[int, str], content: _Content) -> None:
        fresh = self._take_fresh(chat_id)
        self._service._track(
            chat_id, self._gather_then_run(chat_id, user_id, key, content, fresh), name=f"telegram-chat-{chat_id}"
        )

    async def _gather_then_run(
        self, chat_id: int, user_id: str, key: tuple[int, str], content: _Content, fresh: bool
    ) -> None:
        """Wait for the album's other messages (as the file intake does), then
        check them together. Items arriving later are still kept out of a turn
        until the claim ends."""
        try:
            await asyncio.sleep(float(getattr(self._service, "_media_group_wait_s", 2.0)))
        except asyncio.CancelledError:
            if fresh:
                self._service._fresh_chats.add(chat_id)
            raise
        album = self._groups.get(key)
        if album is not None:
            content = dataclasses.replace(content, messages=tuple(album.messages), dropped=album.dropped)
        await self._run(chat_id, user_id, content, fresh)

    async def _run(self, chat_id: int, user_id: str, content: _Content, fresh: bool) -> None:
        """One check under the chat's lock. A /new the check did not use (it
        was refused, stopped or could not be saved) is kept for the next
        message."""
        service = self._service
        saved = False
        try:
            lock = service._chat_locks.setdefault(chat_id, asyncio.Lock())
            async with lock:
                saved = await self._check_locked(chat_id, user_id, content, fresh)
        finally:
            if fresh and not saved:
                service._fresh_chats.add(chat_id)

    async def _check_locked(self, chat_id: int, user_id: str, content: _Content, fresh: bool) -> bool:
        """Plan, download, check, reply, record. True once the rows are saved."""
        from services.notifications import cards
        from services.security import channels as secret_text

        service = self._service
        scam = getattr(service, "scam_check", None)
        if scam is None:
            await self._send(chat_id, NO_SERVICE)
            return False
        try:
            plan = self._plan(content)
            warning = secret_text.inbound_warning(f"{content.note}\n{content.text}".strip(), app="Telegram")
            if warning is not None:
                await self._send(chat_id, warning)
            await self._send(chat_id, CHECKING, silent=True)
            await service._api("sendChatAction", chat_id=chat_id, action="typing")
            typing = asyncio.create_task(service._keep_typing(chat_id))
            try:
                request = await self._request(user_id, content, plan)
                result = await scam.check(request)
            finally:
                typing.cancel()
        except _Refused as refused:
            await _audit_refusal(scam, user_id, "telegram", refused.reason)
            await self._send(chat_id, refused.sentence)
            return False
        except Exception as exc:
            logger.error("scam_check_channel_failed", channel="telegram", error_type=type(exc).__name__)
            await self._send(chat_id, UNEXPECTED_ERROR)
            return False
        if not result.ok:
            await self._send(chat_id, result.refusal)
            return False
        rendered = _rendered(result, list(plan.extras))
        reply = _with_usage(rendered, result)
        for part in cards.split_text(reply, max_chars=TELEGRAM_CHUNK, length=cards.utf16_len) or [reply]:
            await self._send(chat_id, part)
        conversation_id = await record_channel_check(service._session_factory, request, result, rendered, new=fresh)
        return conversation_id is not None

    def _plan(self, content: _Content) -> _Plan:
        """The pictures and files to download, from the sizes Telegram declares
        (no download yet): _Refused when one is too large, or when the content
        is only a voice note, audio or a video."""
        from services.files.limits import UPLOAD
        from services.notifications.telegram import _largest_photo

        pictures: list[_Item] = []
        files: list[_Item] = []
        unsupported = False
        for message in content.messages:
            photo = message.get("photo")
            if isinstance(photo, list) and photo:
                best = _largest_photo(photo)
                if best is None:
                    raise _Refused(PICTURE_TOO_LARGE, "too_large")
                pictures.append(_Item(str(best["file_id"]), True, content.source))
                continue
            document = message.get("document")
            file_id = document.get("file_id") if isinstance(document, dict) else None
            if isinstance(document, dict) and isinstance(file_id, str) and file_id:
                mime = str(document.get("mime_type") or "").strip().lower()
                size = document.get("file_size")
                if mime.startswith("image/"):
                    if _is_count(size) and size > MAX_IMAGE_BYTES:
                        raise _Refused(PICTURE_TOO_LARGE, "too_large")
                    pictures.append(_Item(file_id, True, "reply" if content.source == "reply" else "document"))
                else:
                    if _is_count(size) and size > UPLOAD.max_bytes:
                        raise _Refused(FILE_TOO_LARGE, "too_large")
                    files.append(_Item(file_id, False, "document"))
                continue
            if any(message.get(kind) for kind in _UNSUPPORTED_KINDS):
                unsupported = True
        if unsupported and not content.text and not pictures and not files:
            raise _Refused(TEXT_UNSUPPORTED_MEDIA, "unsupported_media")
        extras: list[str] = []
        if len(pictures) > MAX_CHECK_IMAGES or content.dropped:
            extras.append(MORE_PICTURES)
        if len(files) > MAX_CHECK_FILES:
            extras.append(MORE_FILES)
        return _Plan(tuple(pictures[:MAX_CHECK_IMAGES]), tuple(files[:MAX_CHECK_FILES]), tuple(extras))

    async def _download(self, item: _Item) -> bytes:
        """The bytes of one item, capped (5 MB for a picture, 20 MB otherwise).
        The token-bearing address is never logged (telegram_files)."""
        from services.files.limits import UPLOAD
        from services.notifications.telegram_files import TelegramFileError, download_telegram_file

        cap = MAX_IMAGE_BYTES if item.picture else UPLOAD.max_bytes
        try:
            return await download_telegram_file(
                self._service._client, self._service._token, item.file_id, max_bytes=cap
            )
        except TelegramFileError as exc:
            if exc.code == "too_large":
                raise _Refused(PICTURE_TOO_LARGE if item.picture else FILE_TOO_LARGE, "too_large") from None
            sentence = TELEGRAM_PICTURE_FAILED if item.picture else TELEGRAM_FILE_FAILED
            raise _Refused(sentence, "download_failed") from None

    async def _request(self, user_id: str, content: _Content, plan: _Plan) -> ScamCheckRequest:
        """The ScamCheckRequest for *content*, its pictures downloaded and
        sniffed and its other files downloaded, hashed and dropped."""
        images: list[ScamImage] = []
        hashed: list[ScamFile] = []
        for item in plan.pictures:
            got = _picture_or_file(await self._download(item), item.source)
            if isinstance(got, ScamImage):
                images.append(got)
            else:
                hashed.append(got)
        for item in plan.files:
            hashed.append(_fingerprint(await self._download(item)))
        return ScamCheckRequest(
            user_id=str(user_id),
            channel="telegram",
            text=content.text,
            note=content.note,
            images=tuple(images),
            files=tuple(hashed),
            anchors=content.anchors,
            forwarded=content.forwarded,
        )


def register_telegram(service: Any) -> None:
    """Append TelegramScamChecks(service).intercept to
    service.message_interceptors (once)."""
    interceptors = getattr(service, "message_interceptors", None)
    if not isinstance(interceptors, list):
        return
    if any(isinstance(getattr(hook, "__self__", None), TelegramScamChecks) for hook in interceptors):
        return
    interceptors.append(TelegramScamChecks(service).intercept)


# ── Slack ────────────────────────────────────────────────────────────────


class SlackScamChecks:
    """The Slack DM handler for "scam ...", "is this a scam ..." and a bare
    "scam" (the next message is checked). *channel* is the SlackChannel (its
    ``scam_check`` is read per message, so main.py may wire it later)."""

    def __init__(self, channel: Any, *, clock: Callable[[], float] = time.monotonic) -> None:
        self._channel = channel
        self._clock = clock
        # When the bare "scam"'s wait ends (the clock's time), or None.
        self._armed_until: Optional[float] = None

    def _keyword_scam(self, message: Any) -> Optional[Awaitable[None]]:
        """A matching DM (or any DM while armed): starts the check as tracked
        work and returns a no-op awaitable; else None so the next handler
        runs. Called on the socket loop, so it does no I/O."""
        text = message.text if isinstance(getattr(message, "text", None), str) else ""
        files = tuple(getattr(message, "files", ()) or ())
        audio = bool(getattr(message, "audio", False))
        now = self._clock()
        armed = self._armed_until is not None and now < self._armed_until
        self._armed_until = None
        match = SLACK_RE.match(text) if text else None
        if match is None and not armed:
            return None
        if match is not None:
            content = match.group("rest").strip()
            if not content and not files and not audio:
                # Armed now, so the next message is caught even before the reply goes out.
                self._armed_until = now + ARM_SECONDS
                return self._arm(message.channel)
        else:
            content = text
        channel = self._channel
        fresh, channel._fresh = channel._fresh, False
        channel._track(
            self._run(message.channel, content, files, audio, fresh), f"slack-chat-{channel.connector_id[:8]}"
        )
        return _nothing()

    async def _refusal(self) -> Optional[str]:
        """The precheck's refusal (audited by the service), NO_SERVICE without
        a wired service, or None. Read before any download."""
        scam = getattr(self._channel, "scam_check", None)
        if scam is None:
            return NO_SERVICE
        try:
            refusal = await scam.precheck(str(self._channel.user_id), "slack")
        except Exception as exc:
            logger.error("scam_check_channel_failed", channel="slack", error_type=type(exc).__name__)
            return UNEXPECTED_ERROR
        return refusal if isinstance(refusal, str) and refusal else None

    async def _arm(self, where: str) -> None:
        """The reply to a bare "scam": the wait is already on; a refusal (the
        switch is off, the quota is spent) ends it and says why."""
        refusal = await self._refusal()
        if refusal is not None:
            self._armed_until = None
            await self._channel._post_text(where, refusal)
            return
        await self._channel._post_text(where, SLACK_ARMED)

    async def _run(self, where: str, text: str, files: tuple[Any, ...], audio: bool, fresh: bool) -> None:
        """One check under the channel's lock. A "new" the check did not use is
        kept for the next message."""
        channel = self._channel
        saved = False
        try:
            async with channel._lock:
                saved = await self._check_locked(where, text, files, audio, fresh)
        finally:
            if fresh and not saved:
                channel._fresh = True

    async def _check_locked(
        self, where: str, text: str, files: tuple[Any, ...], audio: bool, fresh: bool
    ) -> bool:
        """Precheck, plan, download, check, reply, record. True once the rows are saved."""
        from services.security import channels as secret_text

        channel = self._channel
        refusal = await self._refusal()
        if refusal is not None:
            await channel._post_text(where, refusal)
            return False
        scam = channel.scam_check
        user_id = str(channel.user_id)
        try:
            plan = self._plan(text, files, audio)
            warning = secret_text.inbound_warning(text, app="Slack")
            if warning is not None:
                await channel._post_text(where, warning)
            await channel._post_text(where, CHECKING)
            request = await self._request(user_id, text, plan)
            result = await scam.check(request)
        except _Refused as refused:
            await _audit_refusal(scam, user_id, "slack", refused.reason)
            await channel._post_text(where, refused.sentence)
            return False
        except Exception as exc:
            logger.error("scam_check_channel_failed", channel="slack", error_type=type(exc).__name__)
            await channel._post_text(where, UNEXPECTED_ERROR)
            return False
        if not result.ok:
            await channel._post_text(where, result.refusal)
            return False
        rendered = _rendered(result, list(plan.extras))
        await self._post_reply(where, _with_usage(rendered, result))
        conversation_id = await record_channel_check(channel._session_factory, request, result, rendered, new=fresh)
        return conversation_id is not None

    async def _post_reply(self, where: str, text: str) -> None:
        """The plain verdict in Slack-sized, paced parts, escaped as typed (no
        mrkdwn), masked and unfurl-free through SlackChannel._post."""
        from services.notifications import slack_format
        from services.notifications.slack import POST_INTERVAL_S, TEXT_CHUNK

        channel = self._channel
        for index, part in enumerate(slack_format.split(slack_format.slack_escape(text), max_chars=TEXT_CHUNK)):
            if index:
                await channel._sleep(POST_INTERVAL_S)
            await channel._post(where, part)

    @staticmethod
    def _plan(text: str, files: tuple[Any, ...], audio: bool) -> _Plan:
        """The shared files to download, from their declared types and sizes
        (no download yet): _Refused when one is too large, or when an audio
        clip is all there is."""
        from services.files.limits import UPLOAD

        pictures: list[Any] = []
        others: list[Any] = []
        unsupported = audio
        for shared in files:
            mime = str(getattr(shared, "mimetype", "") or "").strip().lower()
            size = getattr(shared, "size", None)
            if mime.startswith("audio/"):
                unsupported = True
            elif mime.startswith("image/"):
                if _is_count(size) and size > MAX_IMAGE_BYTES:
                    raise _Refused(PICTURE_TOO_LARGE, "too_large")
                pictures.append(shared)
            else:
                if _is_count(size) and size > UPLOAD.max_bytes:
                    raise _Refused(FILE_TOO_LARGE, "too_large")
                others.append(shared)
        if unsupported and not text and not pictures and not others:
            raise _Refused(TEXT_UNSUPPORTED_MEDIA, "unsupported_media")
        extras: list[str] = []
        if len(pictures) > MAX_CHECK_IMAGES:
            extras.append(MORE_PICTURES)
        if len(others) > MAX_CHECK_FILES:
            extras.append(MORE_FILES)
        return _Plan(tuple(pictures[:MAX_CHECK_IMAGES]), tuple(others[:MAX_CHECK_FILES]), tuple(extras))

    async def _download(self, shared: Any, *, picture: bool) -> bytes:
        """One shared file with the bot token, through the connector's
        policy-checked client (only files.slack.com/files-pri addresses ever
        reach here: slack._shared_files), capped at 5 MB for a picture and
        20 MB otherwise."""
        from services.files.limits import UPLOAD

        cap = MAX_IMAGE_BYTES if picture else UPLOAD.max_bytes
        try:
            body = await self._channel._connector._request_bytes("GET", shared.url, max_bytes=cap)
        except Exception as exc:
            logger.warning("scam_check_slack_download_failed", error_type=type(exc).__name__)
            raise _Refused(SLACK_DOWNLOAD_FAILED, "download_failed") from None
        if getattr(body, "truncated", False):
            raise _Refused(PICTURE_TOO_LARGE if picture else FILE_TOO_LARGE, "too_large")
        content = getattr(body, "content", b"")
        return bytes(content) if isinstance(content, (bytes, bytearray)) else b""

    async def _request(self, user_id: str, text: str, plan: _Plan) -> ScamCheckRequest:
        """The ScamCheckRequest: pictures downloaded and sniffed, other files
        downloaded, hashed and dropped. Slack's own link markup
        (<address|label>) stays in the text, where the local pass reads it."""
        images: list[ScamImage] = []
        hashed: list[ScamFile] = []
        for shared in plan.pictures:
            got = _picture_or_file(await self._download(shared, picture=True), "upload")
            if isinstance(got, ScamImage):
                images.append(got)
            else:
                hashed.append(got)
        for shared in plan.files:
            hashed.append(_fingerprint(await self._download(shared, picture=False)))
        return ScamCheckRequest(user_id=user_id, channel="slack", text=text, images=tuple(images), files=tuple(hashed))


def register_slack(channel: Any) -> None:
    """Insert SlackScamChecks(channel)._keyword_scam just before _keyword_audio
    (or _keyword_files, or at the end), so a shared screenshot is never read
    as a document; "stop", "pending" and "new" stay first. Once only."""
    handlers = getattr(channel, "_text_handlers", None)
    if not isinstance(handlers, list):
        return
    names = [str(getattr(handler, "__name__", "")) for handler in handlers]
    if "_keyword_scam" in names:
        return
    at = len(handlers)
    for name in ("_keyword_audio", "_keyword_files"):
        if name in names:
            at = names.index(name)
            break
    handlers.insert(at, SlackScamChecks(channel)._keyword_scam)
