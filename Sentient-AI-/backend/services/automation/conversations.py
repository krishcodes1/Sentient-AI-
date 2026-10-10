"""Finds or creates the web conversation an unattended job writes into, and
adds its messages.

Why it exists: every scheduled task (and, in wave 2, every trigger) keeps one
ordinary conversation, titled after it ("Scheduled: <label>") and marked with
its origin, so the owner reads each result in the web app like any chat. The
runner, the briefing and the nudges all write there through these helpers.
A conversation the owner deleted is simply made again on the next run.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any, Optional

from sqlalchemy.ext.asyncio import AsyncSession

TITLE_PREFIX = "Scheduled: "


def conversation_title(label: str) -> str:
    return f"{TITLE_PREFIX}{label}"[:512]


async def ensure_conversation(
    db: AsyncSession,
    user_id: uuid.UUID,
    conversation_id: Optional[Any],
    title: str,
    origin: str,
) -> Any:
    """The user's conversation *conversation_id* when it still exists and is
    theirs, else a new one with *title* and *origin* (flushed, so it has an
    id)."""
    from models.conversation import Conversation

    if conversation_id:
        try:
            wanted = uuid.UUID(str(conversation_id))
        except (TypeError, ValueError):
            wanted = None
        if wanted is not None:
            found = await db.get(Conversation, wanted)
            if found is not None and found.user_id == user_id:
                return found
    conversation = Conversation(user_id=user_id, title=title[:512], origin=origin[:64])
    db.add(conversation)
    await db.flush()
    return conversation


async def add_message(
    db: AsyncSession,
    conversation: Any,
    role: str,
    content: str,
    **columns: Any,
) -> Any:
    """Add one message (with any usage columns) and bump the conversation's
    activity time; flushed, so it has an id."""
    from models.conversation import Message, MessageRole

    message = Message(
        conversation_id=conversation.id,
        role=MessageRole(role),
        content=content,
        **columns,
    )
    db.add(message)
    conversation.updated_at = datetime.now(timezone.utc)
    await db.flush()
    return message


def usage_columns(usage: Optional[dict[str, Any]], provider: str, model: str) -> dict[str, Any]:
    """The Message usage columns for a reply made outside a chat turn (the
    briefing's overview): the same mapping as the chat routes', which own
    the canonical copy (api/routes/agent._usage_columns)."""
    from api.routes.agent import _usage_columns

    return _usage_columns(usage, provider or None, model or None)
