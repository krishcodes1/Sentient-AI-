"""Tests for migration 0020_knowledge_base on SQLite: upgrading creates the five
knowledge tables with their indexes and cascading owner keys; downgrading to
0019 removes only them; an adopted database whose tables already exist
upgrades cleanly (create_all, stamp, upgrade).

Why it exists: the revision id was reserved in the top10 chain, so it must
keep its parent, and its schema must match the models (tests/test_migrations.py
compares the whole head against create_all; this pins the revision itself).
"""

from __future__ import annotations

from pathlib import Path

import sqlalchemy as sa
from alembic import command
from alembic.script import ScriptDirectory

from tests.test_page_watch_migration import _config, _inspect

REVISION = "0020_knowledge_base"
TABLES = ("kb_collections", "kb_documents", "kb_chunks", "kb_postings", "kb_embeddings")


def test_the_revision_keeps_its_reserved_parent():
    script = ScriptDirectory.from_config(_config(Path("unused.db")))
    assert script.get_revision(REVISION).down_revision == "0019_tutor_mode"


def test_upgrade_creates_the_tables_and_downgrade_removes_only_them(tmp_path):
    db_path = tmp_path / "kb.db"
    config = _config(db_path)
    command.upgrade(config, REVISION)
    engine, inspector = _inspect(db_path)
    try:
        assert set(TABLES) <= set(inspector.get_table_names())
        for table in TABLES:
            owners = [fk for fk in inspector.get_foreign_keys(table) if fk["referred_table"] == "users"]
            assert owners and all(fk["options"].get("ondelete") == "CASCADE" for fk in owners), table

        def indexes(table: str) -> dict[str, tuple[tuple[str, ...], bool]]:
            return {i["name"]: (tuple(i["column_names"]), bool(i["unique"])) for i in inspector.get_indexes(table)}

        assert indexes("kb_collections")["ix_kb_collections_user_name"] == (("user_id", "name"), True)
        documents = indexes("kb_documents")
        assert documents["ix_kb_documents_dedupe"] == (("user_id", "collection_id", "text_sha256"), True)
        assert documents["ix_kb_documents_embed"] == (("embed_state", "embed_lease_until"), False)
        assert indexes("kb_chunks")["ix_kb_chunks_document_ordinal"] == (("document_id", "ordinal"), True)
        assert indexes("kb_postings")["ix_kb_postings_chunk"] == (("chunk_id",), False)
        assert inspector.get_pk_constraint("kb_postings")["constrained_columns"] == ["user_id", "term", "chunk_id"]
        assert indexes("kb_embeddings")["ix_kb_embeddings_user_model"] == (("user_id", "model"), False)
        chunk_fks = {fk["referred_table"]: fk["options"].get("ondelete") for fk in inspector.get_foreign_keys("kb_chunks")}
        assert chunk_fks == {"kb_documents": "CASCADE", "users": "CASCADE", "kb_collections": "CASCADE"}
    finally:
        engine.dispose()

    command.downgrade(config, "0019_tutor_mode")
    engine, inspector = _inspect(db_path)
    try:
        tables = set(inspector.get_table_names())
        assert not tables & set(TABLES) and "users" in tables and "user_files" in tables
    finally:
        engine.dispose()
    command.upgrade(config, "head")


def test_an_adopted_database_upgrades_cleanly(tmp_path):
    import models  # noqa: F401 - registers every model
    from core.database import Base

    db_path = tmp_path / "adopted.db"
    engine = sa.create_engine(f"sqlite:///{db_path}")
    try:
        Base.metadata.create_all(engine)
    finally:
        engine.dispose()
    config = _config(db_path)
    command.stamp(config, "0019_tutor_mode")
    command.upgrade(config, "head")
    engine, inspector = _inspect(db_path)
    try:
        assert set(TABLES) <= set(inspector.get_table_names())
    finally:
        engine.dispose()
