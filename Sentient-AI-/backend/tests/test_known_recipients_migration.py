"""Tests for migration 0026_known_recipients (security S1) on SQLite: they prove it
creates ``known_recipients`` and ``organisation_domains`` with their columns, unique
lookup indexes and foreign keys, that deleting a user deletes their sent-to history
(ON DELETE CASCADE) while an organisation domain they added stays with ``added_by``
cleared (ON DELETE SET NULL), and that it downgrades cleanly to 0025 and upgrades
again.

Why it exists: tests/test_security_migrations.py checks the whole security chain at
once; this goes into S1's two tables, including the foreign-key actions the privacy
promise rests on (a removed user's fingerprints go with them).
"""

from __future__ import annotations

import uuid
from pathlib import Path
from typing import Any

import sqlalchemy as sa
from alembic import command
from alembic.config import Config

BACKEND_DIR = Path(__file__).resolve().parents[1]
REVISION = "0026_known_recipients"
PARENT = "0025_security_service_keys"


def _config(db_path: Path) -> Config:
    config = Config(str(BACKEND_DIR / "alembic.ini"))
    config.set_main_option("script_location", str(BACKEND_DIR / "alembic"))
    config.attributes["sqlalchemy_url"] = f"sqlite+aiosqlite:///{db_path}"
    config.attributes["configure_logger"] = False
    return config


def _engine(db_path: Path) -> sa.Engine:
    engine = sa.create_engine(f"sqlite:///{db_path}")

    @sa.event.listens_for(engine, "connect")
    def _foreign_keys_on(dbapi_connection: Any, _record: Any) -> None:
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()

    return engine


def _table(db_path: Path, table: str) -> dict[str, Any]:
    engine = _engine(db_path)
    try:
        inspector = sa.inspect(engine)
        return {
            "columns": {c["name"]: c for c in inspector.get_columns(table)},
            "indexes": {
                i["name"]: (tuple(i["column_names"]), bool(i.get("unique")))
                for i in inspector.get_indexes(table)
            },
            "foreign_keys": {
                (
                    tuple(fk["constrained_columns"]),
                    fk["referred_table"],
                    (fk.get("options") or {}).get("ondelete"),
                )
                for fk in inspector.get_foreign_keys(table)
            },
        }
    finally:
        engine.dispose()


def _tables(db_path: Path) -> set[str]:
    engine = _engine(db_path)
    try:
        return set(sa.inspect(engine).get_table_names())
    finally:
        engine.dispose()


def _version(db_path: Path) -> str:
    engine = _engine(db_path)
    try:
        with engine.connect() as conn:
            return str(
                conn.execute(sa.text("SELECT version_num FROM alembic_version")).scalar_one()
            )
    finally:
        engine.dispose()


def test_0026_creates_both_tables_with_their_indexes_cascade_and_set_null(tmp_path):
    db_path = tmp_path / "s1.db"
    command.upgrade(_config(db_path), REVISION)
    assert _version(db_path) == REVISION

    known = _table(db_path, "known_recipients")
    assert set(known["columns"]) == {
        "id",
        "user_id",
        "kind",
        "value_hmac",
        "key_id",
        "first_sent_at",
        "last_sent_at",
        "send_count",
    }
    for name in (
        "user_id",
        "kind",
        "value_hmac",
        "key_id",
        "first_sent_at",
        "last_sent_at",
        "send_count",
    ):
        assert known["columns"][name]["nullable"] is False, name
    assert known["indexes"] == {
        "uq_known_recipients_user_kind_value": (("user_id", "kind", "value_hmac"), True),
        "ix_known_recipients_user_last_sent": (("user_id", "last_sent_at"), False),
    }
    assert known["foreign_keys"] == {(("user_id",), "users", "CASCADE")}

    domains = _table(db_path, "organisation_domains")
    assert set(domains["columns"]) == {"id", "domain", "added_by", "created_at"}
    assert domains["columns"]["added_by"]["nullable"] is True
    assert domains["indexes"] == {"uq_organisation_domains_domain": (("domain",), True)}
    assert domains["foreign_keys"] == {(("added_by",), "users", "SET NULL")}

    # The foreign-key actions really happen: a user's history goes with them, the
    # domain they added stays and forgets who added it.
    user = uuid.uuid4().hex
    engine = _engine(db_path)
    try:
        with engine.begin() as conn:
            conn.execute(
                sa.text(
                    "INSERT INTO users (id, email, hashed_password, is_active, is_admin, created_at, "
                    "updated_at) VALUES (:id, 'ann@northwind.example', 'x', 1, 1, '2026-10-14', "
                    "'2026-10-14')"
                ),
                {"id": user},
            )
            conn.execute(
                sa.text(
                    "INSERT INTO known_recipients (id, user_id, kind, value_hmac, key_id, "
                    "first_sent_at, last_sent_at) VALUES (:id, :user, 'address', :hmac, 'abcd1234', "
                    "'2026-10-14', '2026-10-14')"
                ),
                {"id": uuid.uuid4().hex, "user": user, "hmac": "f" * 64},
            )
            conn.execute(
                sa.text(
                    "INSERT INTO organisation_domains (id, domain, added_by, created_at) "
                    "VALUES (:id, 'northwind.example', :user, '2026-10-14')"
                ),
                {"id": uuid.uuid4().hex, "user": user},
            )
            # The server default counts the first send.
            assert (
                conn.execute(sa.text("SELECT send_count FROM known_recipients")).scalar_one() == 1
            )
            # One fingerprint per user and kind: the lookup index is unique.
            try:
                conn.execute(
                    sa.text(
                        "INSERT INTO known_recipients (id, user_id, kind, value_hmac, key_id, "
                        "first_sent_at, last_sent_at) VALUES (:id, :user, 'address', :hmac, "
                        "'abcd1234', '2026-10-14', '2026-10-14')"
                    ),
                    {"id": uuid.uuid4().hex, "user": user, "hmac": "f" * 64},
                )
            except sa.exc.IntegrityError:
                duplicate_refused = True
            else:  # pragma: no cover - the assertion below reports it
                duplicate_refused = False
            assert duplicate_refused
    finally:
        engine.dispose()

    engine = _engine(db_path)
    try:
        with engine.begin() as conn:
            conn.execute(sa.text("DELETE FROM users WHERE id = :id"), {"id": user})
        with engine.connect() as conn:
            assert conn.execute(sa.text("SELECT COUNT(*) FROM known_recipients")).scalar_one() == 0
            assert conn.execute(
                sa.text("SELECT domain, added_by FROM organisation_domains")
            ).one() == (
                "northwind.example",
                None,
            )
    finally:
        engine.dispose()


def test_0026_downgrades_cleanly_to_0025_and_upgrades_again(tmp_path):
    db_path = tmp_path / "roundtrip.db"
    config = _config(db_path)
    command.upgrade(config, PARENT)
    before = _tables(db_path)
    assert not {"known_recipients", "organisation_domains"} & before

    command.upgrade(config, REVISION)
    assert {"known_recipients", "organisation_domains"} <= _tables(db_path)
    command.downgrade(config, PARENT)
    assert _version(db_path) == PARENT
    assert _tables(db_path) == before

    command.upgrade(config, REVISION)
    assert _version(db_path) == REVISION
    assert {"known_recipients", "organisation_domains"} <= _tables(db_path)
    # And on to the head of the chain from here.
    command.upgrade(config, "head")
    assert {"known_recipients", "organisation_domains"} <= _tables(db_path)
