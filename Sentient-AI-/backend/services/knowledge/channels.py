"""Telegram's "/kb <collection>" caption: a document the linked user sends with
that caption is saved to their knowledge base.

Why it exists: saving a syllabus from a phone should not need the web app.
The caption is the verified, linked user's own act (the bot answers only its
linked chat, and file_extraction already checked "Read files and documents"
before downloading), so it needs no approval card, the same as an upload
on the web. It still needs the knowledge base switch on, stays under the
owner's limits and Telegram's 20 MB, and goes through the same sandboxed
reader and passage screening as every other document. The reply is one
line per file, e.g. 'Saved "Syllabus.pdf" to CS101: 14 pages, 42 passages
(2 hidden).' Audit rows keep the document id, source kind and counts, never
a title or any text.

main.py hands the toolkit and the gates over with ``configure``; telegram.py
registers the caption route and the "/kb" command through
``register_telegram``.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Awaitable, Callable, Optional, Sequence

import structlog

from services.knowledge.limits import TELEGRAM_MAX_BYTES
from services.knowledge.store import AddOutcome, clean_collection_name
from services.notifications.sweeper import gate_open

logger = structlog.get_logger(__name__)

USAGE = (
    "To save a document to your knowledge base, send the file with the caption "
    "/kb <collection>, e.g. /kb CS101."
)
NOT_READY = "The knowledge base is not available right now."
HELP_LINE = "/kb <collection> — as a file's caption: save it to your knowledge base"


@dataclass(frozen=True)
class TelegramBackend:
    """What the caption needs: the knowledge toolkit, the knowledge_base
    gate, and the audit writer (``RuntimeAuditLogger.log``)."""

    toolkit: Any
    enabled: Optional[Callable[[], Awaitable[bool]]] = None
    audit: Optional[Callable[[dict[str, Any]], Awaitable[Any]]] = None


_backend: Optional[TelegramBackend] = None


def configure(backend: Optional[TelegramBackend]) -> None:
    global _backend
    _backend = backend


def reply_line(outcome: AddOutcome, collection: str) -> str:
    """The reply for one file."""
    title = outcome.title
    if outcome.status == "ready":
        parts = []
        if outcome.pages:
            parts.append(f"{outcome.pages} page{'s' if outcome.pages != 1 else ''}")
        passages = f"{outcome.passages} passage{'s' if outcome.passages != 1 else ''}"
        if outcome.withheld:
            passages += f" ({outcome.withheld} hidden)"
        parts.append(passages)
        return f'Saved "{title}" to {collection}: {", ".join(parts)}.'
    if outcome.status == "duplicate":
        return f'"{title}" is already in {collection}.'
    return f'⚠️ Could not save "{title}": {outcome.error or "it could not be read."}'


async def save_files(user_id: str, rest: str, files: Sequence[Any]) -> str:
    """Save *files* for *user_id* into the collection named by *rest*; the
    reply to send."""
    backend = _backend
    if backend is None or backend.toolkit is None:
        return f"⚠️ {NOT_READY}"
    if backend.enabled is not None and not await gate_open(backend.enabled, "knowledge_telegram"):
        from services import capabilities as capability_registry

        return f"⚠️ {capability_registry.get('knowledge_base').when_denied}"
    collection = clean_collection_name(rest)
    if collection is None:
        return USAGE
    if not files:
        return USAGE
    lines: list[str] = []
    for inbound in files:
        try:
            outcome = await backend.toolkit.save_inbound(user_id, collection, inbound, max_bytes=TELEGRAM_MAX_BYTES)
        except Exception as exc:  # noqa: BLE001 - one file's failure is its line
            logger.warning("knowledge_telegram_save_failed", error_type=type(exc).__name__)
            outcome = AddOutcome("error", "the file", error="it could not be saved.")
        name = outcome.collection.name if outcome.collection is not None else collection
        lines.append(reply_line(outcome, name))
        await _audit(backend, user_id, outcome)
    return "\n".join(lines)


async def _audit(backend: TelegramBackend, user_id: str, outcome: AddOutcome) -> None:
    if backend.audit is None or outcome.status != "ready":
        return
    try:
        await backend.audit(
            {
                "event": "knowledge_document_added",
                "user_id": user_id,
                "tool": "knowledge.add",
                "endpoint": "telegram:/kb",
                "arguments": {
                    "document_id": outcome.document_id,
                    "source_kind": "telegram",
                    "passages": outcome.passages,
                    "withheld": outcome.withheld,
                    "redacted": outcome.redacted,
                },
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }
        )
    except Exception as exc:  # noqa: BLE001 - the save stands
        logger.warning("knowledge_telegram_audit_failed", error_type=type(exc).__name__)


def register_telegram(service: Any) -> None:
    """Add the "/kb" command (a text reply saying how to use it)."""

    async def usage(chat_id: int, _user_id: str, _argument: str) -> None:
        await service._api("sendMessage", chat_id=chat_id, text=USAGE)

    service._commands["/kb"] = usage


def register_telegram_caption(service: Any) -> None:
    """Route a file message captioned "/kb <collection>" to the knowledge
    base (TelegramService.file_caption_routes)."""

    async def route(chat_id: int, user_id: str, rest: str, files: list[Any]) -> None:
        text = await save_files(user_id, rest, files)
        await service._api("sendMessage", chat_id=chat_id, text=text[:4000])

    service.file_caption_routes["/kb"] = route
