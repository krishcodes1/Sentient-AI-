"""Tests for migration 0021_study: upgrading creates the five study tables with
their indexes (the unique per-deck fingerprint among them) and cascading
foreign keys (study_settings' nudge task set to NULL instead), the unique
index refuses a second copy of a card in one deck, downgrading to 0020 removes
exactly those tables, upgrading again works, an adopted database that already
has the tables upgrades without error, and the revision keeps its reserved
place in the chain.

Why it exists: test_migrations.py proves the head schema matches the models;
this pins the revision itself, including its downgrade, on a throwaway SQLite
file (Postgres runs the same through the CI job's TEST_DATABASE_URL).
"""

from __future__ import annotations

from pathlib import Path

import pytest
import sqlalchemy as sa
from alembic import command
from alembic.config import Config

BACKEND_DIR = Path(__file__).resolve().parents[1]
TABLES = {"study_decks", "study_items", "study_reviews", "study_quiz_attempts", "study_settings"}


def _config(db_path: Path) -> Config:
    config = Config(str(BACKEND_DIR / "alembic.ini"))
    config.set_main_option("script_location", str(BACKEND_DIR / "alembic"))
    config.attributes["sqlalchemy_url"] = f"sqlite+aiosqlite:///{db_path}"
    config.attributes["configure_logger"] = False
    return config


def _inspect(db_path: Path):
    engine = sa.create_engine(f"sqlite:///{db_path}")
    try:
        inspector = sa.inspect(engine)
        tables = set(inspector.get_table_names())
        indexes = {t: {i["name"]: bool(i.get("unique")) for i in inspector.get_indexes(t)} for t in tables}
        fks = {
            t: {(tuple(fk["constrained_columns"]), fk["referred_table"], (fk.get("options") or {}).get("ondelete")) for fk in inspector.get_foreign_keys(t)}
            for t in tables
        }
    finally:
        engine.dispose()
    return tables, indexes, fks


def test_upgrade_creates_the_tables_and_downgrade_removes_only_them(tmp_path):
    db_path = tmp_path / "study.db"
    config = _config(db_path)
    command.upgrade(config, "0021_study")
    tables, indexes, fks = _inspect(db_path)
    assert TABLES <= tables
    assert indexes["study_decks"] == {"ix_study_decks_user_id_created_at": False}
    assert indexes["study_items"] == {
        "ix_study_items_user_id_due_at": False,
        "ix_study_items_deck_id_position": False,
        "uq_study_items_deck_id_content_hash": True,
    }
    assert indexes["study_reviews"] == {
        "ix_study_reviews_user_id_reviewed_at": False,
        "ix_study_reviews_item_id": False,
    }
    assert indexes["study_quiz_attempts"] == {"ix_study_quiz_attempts_user_id_started_at": False}
    assert fks["study_items"] == {
        (("deck_id",), "study_decks", "CASCADE"),
        (("user_id",), "users", "CASCADE"),
    }
    assert fks["study_reviews"] == {
        (("user_id",), "users", "CASCADE"),
        (("deck_id",), "study_decks", "CASCADE"),
        (("item_id",), "study_items", "CASCADE"),
    }
    assert fks["study_settings"] == {
        (("user_id",), "users", "CASCADE"),
        (("nudge_task_id",), "scheduled_tasks", "SET NULL"),
    }
    before = tables

    command.downgrade(config, "0020_knowledge_base")
    tables, _indexes, _fks = _inspect(db_path)
    assert not TABLES & tables
    assert before - tables == TABLES

    command.upgrade(config, "head")
    tables, _indexes, _fks = _inspect(db_path)
    assert TABLES <= tables


def test_a_second_copy_of_a_card_in_one_deck_is_refused(tmp_path):
    db_path = tmp_path / "unique.db"
    command.upgrade(_config(db_path), "head")
    engine = sa.create_engine(f"sqlite:///{db_path}")
    try:
        with engine.begin() as conn:
            conn.execute(
                sa.text(
                    "INSERT INTO users (id, email, hashed_password, is_active, created_at, updated_at) "
                    "VALUES ('u1', 's@example.com', 'x', 1, '2026-01-01', '2026-01-01')"
                )
            )
            conn.execute(
                sa.text(
                    "INSERT INTO study_decks (id, user_id, title, source_kind, in_reviews, created_at, updated_at) "
                    "VALUES ('d1', 'u1', 'Deck', 'notes', 1, '2026-01-01', '2026-01-01')"
                )
            )
        insert = sa.text(
            "INSERT INTO study_items (id, deck_id, user_id, kind, front, back, tags, content_hash, position, "
            "suspended, ease, interval_days, repetitions, lapses, created_at, updated_at) VALUES (:id, 'd1', 'u1', "
            "'card', 'Q', 'A', '[]', 'hash', 0, 0, 2.5, 0, 0, 0, '2026-01-01', '2026-01-01')"
        )
        with engine.begin() as conn:
            conn.execute(insert, {"id": "i1"})
        with pytest.raises(sa.exc.IntegrityError):
            with engine.begin() as conn:
                conn.execute(insert, {"id": "i2"})
    finally:
        engine.dispose()


def test_an_adopted_database_that_has_the_tables_upgrades_without_error(tmp_path):
    db_path = tmp_path / "adopted.db"
    config = _config(db_path)
    command.upgrade(config, "0020_knowledge_base")
    import models  # noqa: F401 - registers every model on Base.metadata
    from core.database import Base

    engine = sa.create_engine(f"sqlite:///{db_path}")
    try:
        Base.metadata.create_all(engine, tables=[Base.metadata.tables[t] for t in sorted(TABLES)])
    finally:
        engine.dispose()
    command.upgrade(config, "0021_study")
    tables, _indexes, _fks = _inspect(db_path)
    assert TABLES <= tables


def test_the_revision_keeps_its_reserved_place():
    source = (BACKEND_DIR / "alembic" / "versions" / "0021_study.py").read_text(encoding="utf-8")
    assert 'revision = "0021_study"' in source
    assert 'down_revision = "0020_knowledge_base"' in source
    assert "sa.Enum(" not in source  # kinds and statuses are strings: no Postgres enum type
