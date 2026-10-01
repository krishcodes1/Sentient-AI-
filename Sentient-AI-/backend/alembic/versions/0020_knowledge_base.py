"""Creates the knowledge base tables (kb_collections, kb_documents, kb_chunks,
kb_postings, kb_embeddings), guarded against them already existing.

Why it exists: the knowledge base keeps saved documents' passages and their
keyword and meaning indexes in plain tables, so ranking is the same on SQLite
and Postgres with no extension. The revision id was reserved for this skill
in the top10 chain (0017 to 0024), so its down_revision never changes.
Guarded like 0011-0018: an adopted legacy database is created from model
metadata (which already has the tables) before the upgrade runs. Columns
mirror models/knowledge.py. No enum types, so nothing is dialect-specific;
the downgrade drops the tables in reverse order.

Revision ID: 0020_knowledge_base
Revises: 0019_tutor_mode
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0020_knowledge_base"
down_revision = "0019_tutor_mode"
branch_labels = None
depends_on = None

_CHUNK_ID = sa.BigInteger().with_variant(sa.Integer(), "sqlite")


def _has_table(name: str) -> bool:
    return sa.inspect(op.get_bind()).has_table(name)


def _user_id(primary_key: bool = False) -> sa.Column:
    return sa.Column(
        "user_id",
        sa.Uuid(),
        sa.ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        primary_key=primary_key,
    )


def upgrade() -> None:
    if not _has_table("kb_collections"):
        op.create_table(
            "kb_collections",
            sa.Column("id", sa.Uuid(), primary_key=True),
            _user_id(),
            sa.Column("name", sa.String(80), nullable=False),
            sa.Column("description", sa.String(300), nullable=True),
            sa.Column("course_ref", sa.String(120), nullable=True),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        )
        op.create_index("ix_kb_collections_user_name", "kb_collections", ["user_id", "name"], unique=True)

    if not _has_table("kb_documents"):
        op.create_table(
            "kb_documents",
            sa.Column("id", sa.Uuid(), primary_key=True),
            _user_id(),
            sa.Column(
                "collection_id",
                sa.Uuid(),
                sa.ForeignKey("kb_collections.id", ondelete="CASCADE"),
                nullable=False,
            ),
            sa.Column("title", sa.String(200), nullable=False),
            sa.Column("source_kind", sa.String(16), nullable=False),
            sa.Column("source_ref", sa.String(500), nullable=True),
            sa.Column("media_type", sa.String(100), nullable=False),
            sa.Column("original_name", sa.String(255), nullable=True),
            sa.Column("byte_size", sa.Integer(), nullable=False),
            sa.Column("text_sha256", sa.String(64), nullable=False),
            sa.Column("char_count", sa.Integer(), nullable=False),
            sa.Column("chunk_count", sa.Integer(), nullable=False),
            sa.Column("page_count", sa.Integer(), nullable=True),
            sa.Column("withheld_count", sa.Integer(), nullable=False),
            sa.Column("redacted_count", sa.Integer(), nullable=False),
            sa.Column("truncated", sa.Boolean(), nullable=False),
            sa.Column("status", sa.String(16), nullable=False),
            sa.Column("embed_state", sa.String(16), nullable=False),
            sa.Column("embed_model", sa.String(80), nullable=True),
            sa.Column("embed_attempts", sa.Integer(), nullable=False),
            sa.Column("embed_lease_until", sa.DateTime(timezone=True), nullable=True),
            sa.Column("embed_error", sa.String(200), nullable=True),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("indexed_at", sa.DateTime(timezone=True), nullable=False),
        )
        op.create_index("ix_kb_documents_user_collection", "kb_documents", ["user_id", "collection_id"])
        op.create_index(
            "ix_kb_documents_dedupe", "kb_documents", ["user_id", "collection_id", "text_sha256"], unique=True
        )
        op.create_index("ix_kb_documents_embed", "kb_documents", ["embed_state", "embed_lease_until"])

    if not _has_table("kb_chunks"):
        op.create_table(
            "kb_chunks",
            sa.Column("id", _CHUNK_ID, primary_key=True, autoincrement=True),
            sa.Column(
                "document_id",
                sa.Uuid(),
                sa.ForeignKey("kb_documents.id", ondelete="CASCADE"),
                nullable=False,
            ),
            _user_id(),
            sa.Column(
                "collection_id",
                sa.Uuid(),
                sa.ForeignKey("kb_collections.id", ondelete="CASCADE"),
                nullable=False,
            ),
            sa.Column("ordinal", sa.Integer(), nullable=False),
            sa.Column("locator", sa.String(40), nullable=False),
            sa.Column("heading", sa.String(200), nullable=True),
            sa.Column("text", sa.Text(), nullable=False),
            sa.Column("char_count", sa.Integer(), nullable=False),
            sa.Column("term_count", sa.Integer(), nullable=False),
            sa.Column("withheld", sa.Boolean(), nullable=False),
        )
        op.create_index("ix_kb_chunks_document_ordinal", "kb_chunks", ["document_id", "ordinal"], unique=True)
        op.create_index("ix_kb_chunks_user_collection", "kb_chunks", ["user_id", "collection_id"])

    if not _has_table("kb_postings"):
        op.create_table(
            "kb_postings",
            _user_id(primary_key=True),
            sa.Column("term", sa.String(64), primary_key=True),
            sa.Column(
                "chunk_id",
                _CHUNK_ID,
                sa.ForeignKey("kb_chunks.id", ondelete="CASCADE"),
                primary_key=True,
            ),
            sa.Column("collection_id", sa.Uuid(), nullable=False),
            sa.Column("tf", sa.SmallInteger(), nullable=False),
            sa.Column("dl", sa.SmallInteger(), nullable=False),
        )
        op.create_index("ix_kb_postings_chunk", "kb_postings", ["chunk_id"])

    if not _has_table("kb_embeddings"):
        op.create_table(
            "kb_embeddings",
            sa.Column(
                "chunk_id",
                _CHUNK_ID,
                sa.ForeignKey("kb_chunks.id", ondelete="CASCADE"),
                primary_key=True,
                autoincrement=False,
            ),
            _user_id(),
            sa.Column("collection_id", sa.Uuid(), nullable=False),
            sa.Column("model", sa.String(80), nullable=False),
            sa.Column("dims", sa.SmallInteger(), nullable=False),
            sa.Column("vector", sa.LargeBinary(), nullable=False),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        )
        op.create_index("ix_kb_embeddings_user_model", "kb_embeddings", ["user_id", "model"])


def downgrade() -> None:
    if _has_table("kb_embeddings"):
        op.drop_index("ix_kb_embeddings_user_model", table_name="kb_embeddings")
        op.drop_table("kb_embeddings")
    if _has_table("kb_postings"):
        op.drop_index("ix_kb_postings_chunk", table_name="kb_postings")
        op.drop_table("kb_postings")
    if _has_table("kb_chunks"):
        op.drop_index("ix_kb_chunks_user_collection", table_name="kb_chunks")
        op.drop_index("ix_kb_chunks_document_ordinal", table_name="kb_chunks")
        op.drop_table("kb_chunks")
    if _has_table("kb_documents"):
        op.drop_index("ix_kb_documents_embed", table_name="kb_documents")
        op.drop_index("ix_kb_documents_dedupe", table_name="kb_documents")
        op.drop_index("ix_kb_documents_user_collection", table_name="kb_documents")
        op.drop_table("kb_documents")
    if _has_table("kb_collections"):
        op.drop_index("ix_kb_collections_user_name", table_name="kb_collections")
        op.drop_table("kb_collections")
