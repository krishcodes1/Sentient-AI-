"""Tests for the errands migrations: 0033_errands creates ``errands`` (cascading
with its user, the conversation set to NULL on delete, one row per calendar
event), 0034_errand_details adds the nullable ``details`` and ``event_day`` and
0035_errand_fingerprint the nullable ``source_fingerprint``; each is a no-op on
an adopted database that already has them, and downgrading to
0032_file_reputation drops exactly the table, after which the chain upgrades to
head again.

Why it exists: tests/test_migrations.py proves the head schema matches the
models; this pins the two revisions themselves on a throwaway SQLite file. A
calendar note planned twice (no unique index) would park two purchase cards for
one gift, a lost ``event_day`` would let the calendar finder cancel errands
whose notes still exist, and a lost ``source_fingerprint`` would make a restart
miss a note edited meanwhile.

Connects to: alembic/versions/0033_errands.py, alembic/versions/
0034_errand_details.py, alembic/versions/0035_errand_fingerprint.py,
models/errand.py.
"""

from __future__ import annotations

from pathlib import Path

import sqlalchemy as sa
from alembic import command
from alembic.config import Config

BACKEND_DIR = Path(__file__).resolve().parents[1]
PARENT = "0032_file_reputation"


def _config(db_path: Path) -> Config:
    config = Config(str(BACKEND_DIR / "alembic.ini"))
    config.set_main_option("script_location", str(BACKEND_DIR / "alembic"))
    config.attributes["sqlalchemy_url"] = f"sqlite+aiosqlite:///{db_path}"
    config.attributes["configure_logger"] = False
    return config


def _shape(db_path: Path) -> tuple[set[str], dict[str, bool], dict[str, tuple], set[tuple]]:
    engine = sa.create_engine(f"sqlite:///{db_path}")
    try:
        inspector = sa.inspect(engine)
        tables = set(inspector.get_table_names())
        if "errands" not in tables:
            return tables, {}, {}, set()
        columns = {c["name"]: bool(c["nullable"]) for c in inspector.get_columns("errands")}
        indexes = {
            i["name"]: (tuple(i["column_names"]), bool(i.get("unique")))
            for i in inspector.get_indexes("errands")
        }
        fks = {
            (fk["referred_table"], tuple(fk["constrained_columns"]), fk["options"].get("ondelete"))
            for fk in inspector.get_foreign_keys("errands")
        }
    finally:
        engine.dispose()
    return tables, columns, indexes, fks


def test_the_errand_revisions_create_the_table_with_its_indexes_keys_and_note_columns(tmp_path):
    db_path = tmp_path / "errands.db"
    config = _config(db_path)
    command.upgrade(config, PARENT)
    assert "errands" not in _shape(db_path)[0]

    command.upgrade(config, "0033_errands")
    _tables, columns, _indexes, _fks = _shape(db_path)
    assert "details" not in columns and "event_day" not in columns

    command.upgrade(config, "0034_errand_details")
    _tables, columns, _indexes, _fks = _shape(db_path)
    assert columns["details"] is True and columns["event_day"] is True
    assert "source_fingerprint" not in columns

    command.upgrade(config, "0035_errand_fingerprint")
    _tables, columns, indexes, fks = _shape(db_path)
    assert columns["source_fingerprint"] is True
    assert columns["user_id"] is False and columns["title"] is False
    assert indexes == {
        "ix_errands_status_run_on": (("status", "run_on"), False),
        "uq_errands_user_source_ref": (("user_id", "source", "source_ref"), True),
        "ix_errands_approval_action_id": (("approval_action_id",), False),
    }
    assert fks == {
        ("users", ("user_id",), "CASCADE"),
        ("conversations", ("conversation_id",), "SET NULL"),
    }


def test_the_errand_revisions_change_nothing_on_a_database_built_from_the_models(tmp_path):
    import models  # noqa: F401 (registers every model)
    from models.errand import Errand

    db_path = tmp_path / "adopted.db"
    config = _config(db_path)
    command.upgrade(config, PARENT)
    engine = sa.create_engine(f"sqlite:///{db_path}")
    try:
        Errand.__table__.create(engine)
    finally:
        engine.dispose()
    before = _shape(db_path)

    command.upgrade(config, "0035_errand_fingerprint")

    assert _shape(db_path) == before


def test_downgrading_below_the_errands_drops_the_table_and_upgrading_brings_it_back(tmp_path):
    db_path = tmp_path / "round_trip.db"
    config = _config(db_path)
    command.upgrade(config, "head")
    assert "event_day" in _shape(db_path)[1]

    command.downgrade(config, "0034_errand_details")
    columns = _shape(db_path)[1]
    assert "source_fingerprint" not in columns and "event_day" in columns

    command.downgrade(config, "0033_errands")
    tables, columns, _indexes, _fks = _shape(db_path)
    assert "errands" in tables and "event_day" not in columns and "details" not in columns

    command.downgrade(config, PARENT)
    tables = _shape(db_path)[0]
    assert "errands" not in tables and {"file_reputation_verdicts", "users"} <= tables

    command.upgrade(config, "head")
    assert {"details", "event_day", "source_fingerprint"} <= set(_shape(db_path)[1])
