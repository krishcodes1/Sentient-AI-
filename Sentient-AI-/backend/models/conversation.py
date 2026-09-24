from __future__ import annotations

import enum
import uuid
from datetime import datetime, timezone
from typing import Dict, List, Optional, Union

from sqlalchemy import (
    JSON,
    DateTime,
    Enum,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    Uuid,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from core.database import Base


class MessageRole(str, enum.Enum):
    user = "user"
    assistant = "assistant"
    system = "system"


class Conversation(Base):
    __tablename__ = "conversations"
    __table_args__ = (
        Index("ix_conversations_user_id_updated_at", "user_id", "updated_at"),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        Uuid(),
        primary_key=True,
        default=uuid.uuid4,
    )
    user_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(),
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    title: Mapped[str] = mapped_column(
        String(512),
        nullable=False,
        default="New Conversation",
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
        nullable=False,
    )

    # Relationships
    user: Mapped["User"] = relationship(  # noqa: F821
        back_populates="conversations",
    )
    # lazy="raise": only the conversation-detail endpoint wants the
    # messages, and it asks for them explicitly with selectinload(). Left
    # automatic, listing N conversations dragged in every message of all
    # of them — and, via User.conversations, every message the user has
    # ever sent on every authenticated request.
    messages: Mapped[list["Message"]] = relationship(
        back_populates="conversation",
        lazy="raise",
        order_by="Message.created_at",
        passive_deletes=True,
    )

    def __repr__(self) -> str:
        return f"<Conversation {self.id} title={self.title!r}>"


class Message(Base):
    __tablename__ = "messages"
    __table_args__ = (
        Index("ix_messages_conversation_id_created_at", "conversation_id", "created_at"),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        Uuid(),
        primary_key=True,
        default=uuid.uuid4,
    )
    conversation_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(),
        ForeignKey("conversations.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    role: Mapped[MessageRole] = mapped_column(
        Enum(MessageRole, name="message_role"),
        nullable=False,
    )
    content: Mapped[str] = mapped_column(
        Text,
        nullable=False,
    )
    tool_calls: Mapped[Optional[Union[Dict, List]]] = mapped_column(
        JSON,
        nullable=True,
    )
    # Image attachments sent with a user message, as METADATA only:
    # [{"media_type": "image/jpeg", "size_bytes": 812345, "sha256": "..."}].
    #
    # The bytes themselves are deliberately not stored. A single turn may
    # carry 20MB of photos; putting that in a row would bloat every
    # transcript read (this table is fetched whole to rebuild history on
    # each turn), blow past row-size limits, and land binary in database
    # backups. Blobs belong in object storage with the row holding a key —
    # until that exists, an attachment is replayed to the reader as a chip
    # describing what was sent, and the model sees the image only on the
    # turn it arrived.
    attachments: Mapped[Optional[List]] = mapped_column(
        JSON,
        nullable=True,
    )
    # Tokens the provider billed for this turn. Recorded on assistant rows
    # (the user row is an input to the same call, not a separate charge),
    # so per-conversation cost is a SUM over this table instead of a number
    # that existed only in a log line.
    input_tokens: Mapped[Optional[int]] = mapped_column(
        Integer,
        nullable=True,
    )
    output_tokens: Mapped[Optional[int]] = mapped_column(
        Integer,
        nullable=True,
    )
    # The cached share of input_tokens (a subset, not an addition), and the
    # share written to the cache. Kept apart because they bill at very
    # different rates — a cache read is ~10% of fresh input, an Anthropic
    # cache write 125% — so a cost estimate needs the split. NULL where the
    # provider never reported it.
    cache_read_tokens: Mapped[Optional[int]] = mapped_column(
        Integer,
        nullable=True,
    )
    cache_write_tokens: Mapped[Optional[int]] = mapped_column(
        Integer,
        nullable=True,
    )
    # The provider/model that produced an assistant turn. The user's
    # Settings choice can change between turns, so pricing a past turn by
    # the account's CURRENT model would misattribute it; NULL on rows
    # written before this was recorded, which cost estimates treat as
    # unpriced rather than guessing.
    llm_provider: Mapped[Optional[str]] = mapped_column(
        String(32),
        nullable=True,
    )
    llm_model: Mapped[Optional[str]] = mapped_column(
        String(128),
        nullable=True,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )

    # Relationships
    conversation: Mapped["Conversation"] = relationship(
        back_populates="messages",
    )

    def __repr__(self) -> str:
        return f"<Message {self.id} role={self.role}>"
