"""Declares the knowledge base tables: kb_collections, kb_documents, kb_chunks
(the passages), kb_postings (the keyword index) and kb_embeddings (the meaning
index).

Why it exists: the knowledge base keeps its index in plain tables of portable
types (Uuid, String, Text, Integer, LargeBinary, Boolean), so SQLite and
Postgres hold and rank the same data with no extension. Every table carries
user_id with ON DELETE CASCADE, so deleting an account removes everything.
services.knowledge.store is the only reader and writer, and migration
0020_knowledge_base mirrors these columns so ``create_all`` and the migrated
schema stay identical (tests/test_migrations.py).

A passage's ``text`` is stored after secret redaction; a passage PromptGuard
flagged is stored with ``withheld`` set and is never returned or embedded.
Documents keep no original bytes.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import (
    BigInteger,
    Boolean,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    LargeBinary,
    SmallInteger,
    String,
    Text,
    Uuid,
)
from sqlalchemy.orm import Mapped, mapped_column

from core.database import Base

# kb_chunks.id: 64-bit on Postgres; SQLite needs INTEGER for its rowid alias.
ChunkId = BigInteger().with_variant(Integer(), "sqlite")


def _now() -> datetime:
    return datetime.now(timezone.utc)


class KbCollection(Base):
    __tablename__ = "kb_collections"
    __table_args__ = (Index("ix_kb_collections_user_name", "user_id", "name", unique=True),)

    id: Mapped[uuid.UUID] = mapped_column(Uuid(), primary_key=True, default=uuid.uuid4)
    user_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(), ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )
    name: Mapped[str] = mapped_column(String(80), nullable=False)
    description: Mapped[Optional[str]] = mapped_column(String(300), nullable=True)
    # A linked course, e.g. "canvas:<course id>" (for tutor and flashcards).
    course_ref: Mapped[Optional[str]] = mapped_column(String(120), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=_now)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=_now)


class KbDocument(Base):
    __tablename__ = "kb_documents"
    __table_args__ = (
        Index("ix_kb_documents_user_collection", "user_id", "collection_id"),
        # One copy of the same text per collection: a re-save is a duplicate.
        Index("ix_kb_documents_dedupe", "user_id", "collection_id", "text_sha256", unique=True),
        # The embed sweeper's claim.
        Index("ix_kb_documents_embed", "embed_state", "embed_lease_until"),
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid(), primary_key=True, default=uuid.uuid4)
    user_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(), ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )
    collection_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(), ForeignKey("kb_collections.id", ondelete="CASCADE"), nullable=False
    )
    title: Mapped[str] = mapped_column(String(200), nullable=False)
    # upload | url | text | google_drive | onedrive | canvas | notion | telegram
    source_kind: Mapped[str] = mapped_column(String(16), nullable=False)
    # The URL (no query or fragment) or "<connector namespace>:<id>"; never a
    # token or a pre-signed address.
    source_ref: Mapped[Optional[str]] = mapped_column(String(500), nullable=True)
    media_type: Mapped[str] = mapped_column(String(100), nullable=False)
    original_name: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    byte_size: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    text_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    char_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    chunk_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    page_count: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    withheld_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    redacted_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    truncated: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    # ready | error (the keyword index is written with the document).
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="ready")
    # none | pending | ready | error | skipped
    embed_state: Mapped[str] = mapped_column(String(16), nullable=False, default="pending")
    embed_model: Mapped[Optional[str]] = mapped_column(String(80), nullable=True)
    embed_attempts: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    embed_lease_until: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    # Crawler's own sentence, never provider text.
    embed_error: Mapped[Optional[str]] = mapped_column(String(200), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=_now)
    indexed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=_now)


class KbChunk(Base):
    __tablename__ = "kb_chunks"
    __table_args__ = (
        Index("ix_kb_chunks_document_ordinal", "document_id", "ordinal", unique=True),
        Index("ix_kb_chunks_user_collection", "user_id", "collection_id"),
    )

    id: Mapped[int] = mapped_column(ChunkId, primary_key=True, autoincrement=True)
    document_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(), ForeignKey("kb_documents.id", ondelete="CASCADE"), nullable=False
    )
    user_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(), ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )
    collection_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(), ForeignKey("kb_collections.id", ondelete="CASCADE"), nullable=False
    )
    ordinal: Mapped[int] = mapped_column(Integer, nullable=False)
    locator: Mapped[str] = mapped_column(String(40), nullable=False)
    heading: Mapped[Optional[str]] = mapped_column(String(200), nullable=True)
    text: Mapped[str] = mapped_column(Text, nullable=False)
    char_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    # The BM25 length (terms, the heading's counted once more).
    term_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    withheld: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)


class KbPosting(Base):
    __tablename__ = "kb_postings"
    __table_args__ = (Index("ix_kb_postings_chunk", "chunk_id"),)

    # The primary key (user_id, term, chunk_id) serves "user_id = ? AND
    # term IN (...)".
    user_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(), ForeignKey("users.id", ondelete="CASCADE"), primary_key=True
    )
    term: Mapped[str] = mapped_column(String(64), primary_key=True)
    chunk_id: Mapped[int] = mapped_column(
        ChunkId, ForeignKey("kb_chunks.id", ondelete="CASCADE"), primary_key=True
    )
    collection_id: Mapped[uuid.UUID] = mapped_column(Uuid(), nullable=False)
    tf: Mapped[int] = mapped_column(SmallInteger, nullable=False)
    # The passage's term_count, copied so BM25 needs no second query.
    dl: Mapped[int] = mapped_column(SmallInteger, nullable=False)


class KbEmbedding(Base):
    __tablename__ = "kb_embeddings"
    __table_args__ = (Index("ix_kb_embeddings_user_model", "user_id", "model"),)

    chunk_id: Mapped[int] = mapped_column(
        ChunkId, ForeignKey("kb_chunks.id", ondelete="CASCADE"), primary_key=True, autoincrement=False
    )
    user_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(), ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )
    collection_id: Mapped[uuid.UUID] = mapped_column(Uuid(), nullable=False)
    # e.g. "gemini:gemini-embedding-001:256"
    model: Mapped[str] = mapped_column(String(80), nullable=False)
    dims: Mapped[int] = mapped_column(SmallInteger, nullable=False)
    # float32 little-endian, L2-normalised (services/knowledge/vectors.py).
    vector: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=_now)
