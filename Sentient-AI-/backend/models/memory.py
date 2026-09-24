"""Declares the ``memories`` table: one dated fact per row, with a category, a
provenance source and the owning user.

Why it exists: The memory routes, ``services.memory`` and the agent's
system-prompt rendering all read this mapping; the ``source`` and
``source_conversation_id`` columns are what let the UI show where an
agent-proposed memory came from.

Persistent per-user memory.

A memory is a durable fact the user wants the assistant to know across all
conversations (a name, a preference, an ongoing project, a deadline). This
is the "saved memories" model that ChatGPT and Claude ship — a small set of
dated one-line facts rendered into the system prompt at request time, NOT a
vector store. It is deliberately simple: no embeddings, no retrieval, just
a per-user list injected as trusted context.

Memories are owned, scoped, and injection-scanned on write (a memory the
model proposes from a tool result could otherwise poison future turns —
OWASP's "memory poisoning" agentic threat).
"""

from __future__ import annotations

import enum
import uuid
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import DateTime, Enum, ForeignKey, Index, String, Text, Uuid
from sqlalchemy.orm import Mapped, mapped_column, relationship

from core.database import Base


class MemoryCategory(str, enum.Enum):
    """Coarse buckets so the UI can group and the model can prioritize."""

    profile = "profile"        # who the user is (name, role, school)
    preference = "preference"  # how they like the assistant to behave
    project = "project"        # ongoing work / goals
    fact = "fact"              # any other durable fact


class MemorySource(str, enum.Enum):
    """How the memory came to exist — for provenance and UI labeling."""

    user = "user"    # the user wrote it directly
    agent = "agent"  # the assistant proposed it (and the user approved)


class Memory(Base):
    __tablename__ = "memories"
    __table_args__ = (
        Index("ix_memories_user_id_created_at", "user_id", "created_at"),
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
    content: Mapped[str] = mapped_column(
        Text,
        nullable=False,
    )
    category: Mapped[MemoryCategory] = mapped_column(
        Enum(MemoryCategory, name="memory_category"),
        nullable=False,
        default=MemoryCategory.fact,
    )
    source: Mapped[MemorySource] = mapped_column(
        Enum(MemorySource, name="memory_source"),
        nullable=False,
        default=MemorySource.user,
    )
    # Where an agent-proposed memory originated, for provenance. Nullable;
    # not a FK so deleting a conversation never cascades away the memory.
    source_conversation_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        Uuid(),
        nullable=True,
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

    user: Mapped["User"] = relationship(  # noqa: F821
        back_populates="memories",
    )

    def __repr__(self) -> str:
        return f"<Memory {self.id} category={self.category}>"
