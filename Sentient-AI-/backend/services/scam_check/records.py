"""Writes a scam check into the person's chat history: their message (the
checked content fenced as someone else's words) and Crawler's verdict, with the
check's token usage.

Why it exists: a scam check made outside a chat turn still has to show up
where the person asked (the Telegram or Slack thread, the web chat, or the
Security page's "Scam checks" chat) and its provider spend has to reach
/usage, which sums the Message usage columns. The checked message is stored
inside a shared_content fence with the scam-check preamble, so a later turn in
the same thread reads its links and addresses as untrusted (the runtime seeds
its taint tracker from fenced spans); unfenced, they would read as the owner's
own instruction. Pictures leave only their metadata (media type, size,
sha256), never their bytes.

Import rule: api.routes.agent is imported inside functions only (it imports
services.scam_check.web at module level).

Connects to: services/scam_check/web.py (web chat /scam), api/routes/
security_scam.py (the Security page), services/scam_check/channels.py
(Telegram and Slack), services/automation/conversations.usage_columns.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import uuid
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any, Callable, Literal, Optional

import structlog
from sqlalchemy import select

from models.conversation import Conversation, Message, MessageRole
from services.agent.shared_content import neutralise
from services.scam_check.review import MAX_NOTE_CHARS, fence_message
from services.security.scam_signals import MAX_TEXT_CHARS

if TYPE_CHECKING:
    from services.scam_check.service import ScamCheckRequest, ScamCheckResult

logger = structlog.get_logger(__name__)

SCAM_CHECKS_TITLE = "Scam checks"
SCAM_CHECKS_ORIGIN = "scam_check"

# How the person's message starts in each place they asked.
_HEADS: dict[str, str] = {
    "telegram": "/scam",
    "web_chat": "/scam",
    "slack": "scam",
    "web_box": "Check for scams:",
}


def _note_line(note: str) -> str:
    """The person's own note as one line, with anything shaped like a fence tag escaped."""
    return " ".join(neutralise(note or "", "").split())[:MAX_NOTE_CHARS]


def _plural(n: int, word: str) -> str:
    return f"{n} {word}" if n == 1 else f"{n} {word}s"


def user_row_content(request: "ScamCheckRequest", result: Optional["ScamCheckResult"] = None) -> str:
    """'/scam' (or 'Check for scams:') + the note + the fenced text + a picture
    fact line. The note is the person's own words and stays outside the fence;
    the text is someone else's and is always fenced, even when the check was
    refused, so it never reads as the owner's instruction later."""
    head = _HEADS.get(str(request.channel), "/scam")
    note = _note_line(request.note) if isinstance(request.note, str) else ""
    lines = [f"{head} {note}".rstrip() if note else head]
    text = request.text.strip()[:MAX_TEXT_CHARS] if isinstance(request.text, str) else ""
    if text:
        lines.append(fence_message(text))
    pictures = len(request.images)
    if pictures:
        lines.append(f"[{_plural(pictures, 'picture')} sent to check; pictures are not kept]")
    files = sum(1 for f in request.files if getattr(f, "sha256", ""))
    if files:
        checked = result is not None and result.ok
        lines.append(f"[{_plural(files, 'file')} attached{'; checked by fingerprint only' if checked else ''}]")
    return "\n".join(lines)


def _picture_metadata(image: Any) -> Optional[dict[str, Any]]:
    """What a picture leaves on the row: media type, size and sha256 (the
    ImageAttachment.metadata shape), never the bytes. None when it is not base64."""
    data = getattr(image, "data", "")
    if not isinstance(data, str) or not data:
        return None
    try:
        raw = base64.b64decode(data, validate=True)
    except (binascii.Error, ValueError):
        return None
    return {
        "media_type": str(getattr(image, "media_type", "") or ""),
        "size_bytes": len(raw),
        "sha256": hashlib.sha256(raw).hexdigest(),
    }


def _facts_entry(request: "ScamCheckRequest", result: "ScamCheckResult") -> dict[str, Any]:
    return {
        "kind": "scam_check",
        "channel": str(request.channel),
        "verdict": result.verdict if result.ok else "refused",
        "images": int(result.images) if result.ok else len(request.images),
        "links": len(result.links),
        "files": int(result.files),
        "cached": bool(result.cached),
    }


async def add_check_rows(
    db: Any,
    conversation: Any,
    request: "ScamCheckRequest",
    result: "ScamCheckResult",
    rendered: str,
) -> tuple[Any, Any]:
    """Add the user row (fenced content, picture metadata, facts entry) and the
    assistant row (rendered verdict, usage columns); flushed and refreshed;
    the caller commits."""
    from services.automation.conversations import usage_columns

    pictures = [meta for meta in (_picture_metadata(image) for image in request.images) if meta]
    user_row = Message(
        conversation_id=conversation.id,
        role=MessageRole.user,
        content=user_row_content(request, result),
        attachments=[*pictures, _facts_entry(request, result)],
    )
    db.add(user_row)
    await db.flush()
    columns = usage_columns(result.usage, result.provider, result.model) if result.usage else {}
    reply_row = Message(
        conversation_id=conversation.id,
        role=MessageRole.assistant,
        content=rendered,
        **columns,
    )
    db.add(reply_row)
    conversation.updated_at = datetime.now(timezone.utc)
    await db.flush()
    await db.refresh(user_row)
    await db.refresh(reply_row)
    return user_row, reply_row


async def channel_conversation(
    db: Any, user_id: str, channel: Literal["telegram", "slack"], *, new: bool
) -> Any:
    """The user's newest conversation titled CHANNEL_CONVERSATION_TITLES[channel],
    or a new one (when *new*, after the chat's /new, or when there is none):
    the same thread the channel's chat turns write into."""
    from api.routes.agent import CHANNEL_CONVERSATION_TITLES

    title = CHANNEL_CONVERSATION_TITLES[channel]
    owner = uuid.UUID(str(user_id))
    conversation = None
    if not new:
        conversation = (
            await db.execute(
                select(Conversation)
                .where(Conversation.user_id == owner, Conversation.title == title)
                .order_by(Conversation.updated_at.desc())
                .limit(1)
            )
        ).scalar_one_or_none()
    if conversation is None:
        conversation = Conversation(user_id=owner, title=title)
        db.add(conversation)
        await db.flush()
    return conversation


async def scam_checks_conversation(db: Any, user_id: Any) -> Any:
    """The newest conversation with origin "scam_check" for this user, or a new
    "Scam checks" one (the Security page's checks go here)."""
    owner = user_id if isinstance(user_id, uuid.UUID) else uuid.UUID(str(user_id))
    conversation = (
        await db.execute(
            select(Conversation)
            .where(Conversation.user_id == owner, Conversation.origin == SCAM_CHECKS_ORIGIN)
            .order_by(Conversation.updated_at.desc())
            .limit(1)
        )
    ).scalar_one_or_none()
    if conversation is None:
        conversation = Conversation(user_id=owner, title=SCAM_CHECKS_TITLE, origin=SCAM_CHECKS_ORIGIN)
        db.add(conversation)
        await db.flush()
    return conversation


async def record_channel_check(
    session_factory: Callable[[], Any],
    request: "ScamCheckRequest",
    result: "ScamCheckResult",
    rendered: str,
    *,
    new: bool,
) -> Optional[str]:
    """Telegram/Slack: both rows in the channel thread in a fresh session; the
    conversation id, or None after logging scam_check_record_failed (error
    type only). The reply has already gone out."""
    channel = str(request.channel)
    if channel not in ("telegram", "slack"):
        logger.error("scam_check_record_failed", error_type="UnknownChannel")
        return None
    try:
        async with session_factory() as db:
            conversation = await channel_conversation(
                db, request.user_id, channel, new=new  # type: ignore[arg-type]  # checked above
            )
            await add_check_rows(db, conversation, request, result, rendered)
            conversation_id = str(conversation.id)
            await db.commit()
        return conversation_id
    except Exception as exc:
        logger.error("scam_check_record_failed", error_type=type(exc).__name__)
        return None
