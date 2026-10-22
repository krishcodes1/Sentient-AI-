"""Tests for migration 0027_mail_security (security S2, the scam check on new
email): upgrading creates ``mail_scan_cursors`` and ``mail_scam_findings``
with their indexes (the per-connector cursor and the per-message finding
unique), a second finding for the same message is refused, deleting a
connector or a user takes both tables' rows with it, and downgrading to
0026_known_recipients removes exactly the two tables before upgrading again.

Why it exists: tests/test_migrations.py proves the head schema matches the
models; this pins the revision itself on a throwaway SQLite file, including the
dedupe index that keeps one email from being flagged twice across workers and
restarts. Written by WAVE 0 with the migration; owned by S2 (S2b) in WAVE 1.
"""

from __future__ import annotations

from pathlib import Path

import pytest
import sqlalchemy as sa
from alembic import command
from alembic.config import Config

BACKEND_DIR = Path(__file__).resolve().parents[1]

REVISION = "0027_mail_security"
PARENT = "0026_known_recipients"
TABLES = {"mail_scan_cursors", "mail_scam_findings"}


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
        indexes = {
            t: {
                i["name"]: (tuple(i["column_names"]), bool(i.get("unique")))
                for i in inspector.get_indexes(t)
            }
            for t in tables & TABLES
        }
        fks = {
            t: {
                (fk["referred_table"], (fk.get("options") or {}).get("ondelete"))
                for fk in inspector.get_foreign_keys(t)
            }
            for t in tables & TABLES
        }
    finally:
        engine.dispose()
    return tables, indexes, fks


def _seed(engine) -> None:
    """One user, one Gmail connector, its cursor and one finding (raw SQL: the
    ORM models describe head, not the revision under test)."""
    with engine.begin() as conn:
        conn.execute(sa.text("PRAGMA foreign_keys=ON"))
        conn.execute(
            sa.text(
                "INSERT INTO users (id, email, hashed_password, is_active, created_at, updated_at) "
                "VALUES ('u1', 'm@example.com', 'x', 1, '2026-01-01', '2026-01-01')"
            )
        )
        conn.execute(
            sa.text(
                "INSERT INTO connector_configs (id, user_id, connector_type, display_name, is_active, "
                "auth_method, encrypted_credentials, granted_scopes, permission_tier, "
                "rate_limit_per_minute, created_at, updated_at) VALUES ('c1', 'u1', "
                "'google_workspace', 'Mail', 1, 'bearer_token', x'00', '[]', 'user_confirm', 30, "
                "'2026-01-01', '2026-01-01')"
            )
        )
        conn.execute(
            sa.text(
                "INSERT INTO mail_scan_cursors (id, user_id, connector_id, provider, next_check_at, "
                "created_at, updated_at) VALUES ('k1', 'u1', 'c1', 'gmail', '2026-01-01', "
                "'2026-01-01', '2026-01-01')"
            )
        )
        conn.execute(_FINDING, {"id": "f1"})


_FINDING = sa.text(
    "INSERT INTO mail_scam_findings (id, user_id, connector_id, provider, external_key, message_ref, "
    "local_level, score, signals, detected_at) VALUES (:id, 'u1', 'c1', 'gmail', '"
    + "a" * 64
    + "', 'm-1', 'suspicious', 4, '[]', '2026-01-02')"
)


def _counts(engine) -> tuple[int, int]:
    with engine.connect() as conn:
        cursors = conn.execute(sa.text("SELECT count(*) FROM mail_scan_cursors")).scalar_one()
        findings = conn.execute(sa.text("SELECT count(*) FROM mail_scam_findings")).scalar_one()
    return cursors, findings


def test_0027_creates_both_tables_with_their_indexes(tmp_path):
    db_path = tmp_path / "mail.db"
    command.upgrade(_config(db_path), REVISION)
    tables, indexes, fks = _inspect(db_path)
    assert TABLES <= tables
    assert indexes["mail_scan_cursors"] == {
        "ux_mail_scan_cursors_connector_id": (("connector_id",), True),
        "ix_mail_scan_cursors_status_next_check_at": (("status", "next_check_at"), False),
        "ix_mail_scan_cursors_user_id": (("user_id",), False),
    }
    assert indexes["mail_scam_findings"] == {
        "ux_mail_scam_findings_connector_id_external_key": (("connector_id", "external_key"), True),
        "ix_mail_scam_findings_status_detected_at": (("status", "detected_at"), False),
        "ix_mail_scam_findings_user_id_detected_at": (("user_id", "detected_at"), False),
        "ix_mail_scam_findings_user_id_reviewed_at": (("user_id", "reviewed_at"), False),
    }
    for table in TABLES:
        assert fks[table] == {("users", "CASCADE"), ("connector_configs", "CASCADE")}, table

    # The server defaults fill what the sweeper leaves out, and the dedupe
    # index refuses the same message twice for one connector.
    engine = sa.create_engine(f"sqlite:///{db_path}")
    try:
        _seed(engine)
        with engine.connect() as conn:
            cursor = conn.execute(
                sa.text(
                    "SELECT status, consecutive_errors, checked_count, flagged_count, skipped_count "
                    "FROM mail_scan_cursors"
                )
            ).one()
            finding = conn.execute(
                sa.text("SELECT status, verdict, alert_delivered, attempts FROM mail_scam_findings")
            ).one()
        assert tuple(cursor) == ("active", 0, 0, 0, 0)
        assert tuple(finding) == ("pending", "unknown", 0, 0)
        with pytest.raises(sa.exc.IntegrityError):
            with engine.begin() as conn:
                conn.execute(_FINDING, {"id": "f2"})
    finally:
        engine.dispose()


@pytest.mark.parametrize(
    "delete",
    ["DELETE FROM connector_configs WHERE id = 'c1'", "DELETE FROM users WHERE id = 'u1'"],
    ids=["connector", "user"],
)
def test_0027_rows_cascade_with_their_user_and_their_connector(tmp_path, delete):
    db_path = tmp_path / "cascade.db"
    command.upgrade(_config(db_path), REVISION)
    engine = sa.create_engine(f"sqlite:///{db_path}")
    try:
        _seed(engine)
        assert _counts(engine) == (1, 1)
        with engine.begin() as conn:
            conn.execute(sa.text("PRAGMA foreign_keys=ON"))
            conn.execute(sa.text(delete))
        assert _counts(engine) == (0, 0)
    finally:
        engine.dispose()


def test_0027_downgrades_to_0026_and_upgrades_again(tmp_path):
    db_path = tmp_path / "roundtrip.db"
    config = _config(db_path)
    command.upgrade(config, REVISION)
    command.downgrade(config, PARENT)
    tables, _indexes, _fks = _inspect(db_path)
    assert not TABLES & tables
    # Only S2's tables went: the revision below it keeps its own.
    assert {"known_recipients", "organisation_domains", "users", "connector_configs"} <= tables
    command.upgrade(config, "head")
    tables, indexes, _fks = _inspect(db_path)
    assert TABLES <= tables
    assert indexes["mail_scam_findings"]["ux_mail_scam_findings_connector_id_external_key"][1]


def test_0027_the_upgrade_is_guarded_on_an_adopted_database(tmp_path):
    """A database whose tables were built from the models (an adopted
    install) already has both tables and their indexes: the upgrade skips
    them instead of failing, and the rows already there are kept."""
    import models  # noqa: F401 - registers every model on Base.metadata
    from core.database import Base

    db_path = tmp_path / "adopted.db"
    config = _config(db_path)
    command.upgrade(config, PARENT)
    engine = sa.create_engine(f"sqlite:///{db_path}")
    try:
        for name in ("mail_scan_cursors", "mail_scam_findings"):
            Base.metadata.tables[name].create(engine)
        _seed(engine)
    finally:
        engine.dispose()
    command.upgrade(config, REVISION)
    tables, indexes, _fks = _inspect(db_path)
    assert TABLES <= tables
    assert set(indexes["mail_scan_cursors"]) == {
        "ux_mail_scan_cursors_connector_id",
        "ix_mail_scan_cursors_status_next_check_at",
        "ix_mail_scan_cursors_user_id",
    }
    assert indexes["mail_scam_findings"]["ux_mail_scam_findings_connector_id_external_key"][1]
    engine = sa.create_engine(f"sqlite:///{db_path}")
    try:
        assert _counts(engine) == (1, 1)
    finally:
        engine.dispose()


def test_0027_keeps_its_reserved_parent_and_uses_no_enum_type():
    source = (BACKEND_DIR / "alembic" / "versions" / f"{REVISION}.py").read_text(encoding="utf-8")
    assert f'revision = "{REVISION}"' in source
    assert f'down_revision = "{PARENT}"' in source
    assert "sa.Enum(" not in source
