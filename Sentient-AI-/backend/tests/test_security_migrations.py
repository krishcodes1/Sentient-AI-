"""Tests for the security wave's migrations 0025_security_service_keys to
0032_file_reputation on SQLite: upgrading to head creates every table, column,
index and foreign-key action the chain reserves, downgrading to
0024_media_transcripts removes exactly that and keeps the other columns of
``installation`` and ``pending_actions`` (and their rows), the round trip
repeats cleanly, and an adopted database built from the models upgrades
without creating anything twice.

Why it exists: tests/test_migrations.py proves the head schema matches the
models; this pins the chain itself, including the way back, so a failed
rollout of the security wave can be reverted without touching anyone's other
data. Each skill's own migration test (WAVE 1) goes deeper into its tables;
this one is the scaffold's single view of all eight revisions.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import sqlalchemy as sa
from alembic import command
from alembic.config import Config

BACKEND_DIR = Path(__file__).resolve().parents[1]

BEFORE = "0024_media_transcripts"
HEAD = "0032_file_reputation"
REVISIONS = (
    "0025_security_service_keys",
    "0026_known_recipients",
    "0027_mail_security",
    "0028_mcp_tool_pins",
    "0029_breach_watch",
    "0030_browser_site_rules",
    "0031_tool_rules",
    "0032_file_reputation",
)

# table -> (columns, {index: (columns, unique)}, {(columns, referred table, on delete)})
TABLES: dict[str, tuple[set[str], dict[str, tuple[tuple[str, ...], bool]], set[tuple[Any, ...]]]] = {
    "known_recipients": (
        {"id", "user_id", "kind", "value_hmac", "key_id", "first_sent_at", "last_sent_at", "send_count"},
        {
            "uq_known_recipients_user_kind_value": (("user_id", "kind", "value_hmac"), True),
            "ix_known_recipients_user_last_sent": (("user_id", "last_sent_at"), False),
        },
        {(("user_id",), "users", "CASCADE")},
    ),
    "organisation_domains": (
        {"id", "domain", "added_by", "created_at"},
        {"uq_organisation_domains_domain": (("domain",), True)},
        {(("added_by",), "users", "SET NULL")},
    ),
    "mail_scan_cursors": (
        {
            "id", "user_id", "connector_id", "provider", "status", "cursor", "pending_ids", "seen",
            "account_domain", "baseline_at", "next_check_at", "last_checked_at",
            "consecutive_errors", "last_error", "checked_count", "flagged_count", "skipped_count",
            "note", "created_at", "updated_at",
        },
        {
            "ux_mail_scan_cursors_connector_id": (("connector_id",), True),
            "ix_mail_scan_cursors_status_next_check_at": (("status", "next_check_at"), False),
            "ix_mail_scan_cursors_user_id": (("user_id",), False),
        },
        {(("user_id",), "users", "CASCADE"), (("connector_id",), "connector_configs", "CASCADE")},
    ),
    "mail_scam_findings": (
        {
            "id", "user_id", "connector_id", "provider", "external_key", "message_ref", "status",
            "verdict", "local_level", "score", "signals", "facts", "review_input", "review",
            "review_note", "reviewed_at", "check_notes", "alert_delivered", "alert_note",
            "alerted_at", "card_ids", "dismissed_at", "received_at", "detected_at",
            "claimed_until", "attempts",
        },
        {
            "ux_mail_scam_findings_connector_id_external_key": (("connector_id", "external_key"), True),
            "ix_mail_scam_findings_status_detected_at": (("status", "detected_at"), False),
            "ix_mail_scam_findings_user_id_detected_at": (("user_id", "detected_at"), False),
            "ix_mail_scam_findings_user_id_reviewed_at": (("user_id", "reviewed_at"), False),
        },
        {(("user_id",), "users", "CASCADE"), (("connector_id",), "connector_configs", "CASCADE")},
    ),
    "mcp_tool_pins": (
        {
            "id", "user_id", "connector_id", "name_key", "remote_name", "exposed_name", "status",
            "review_kind", "trusted_how", "approved_hash", "approved_definition",
            "approved_hidden_chars", "pending_hash", "pending_definition", "pending_hidden_chars",
            "change_count", "notified_hash", "notified_at", "first_seen_at", "approved_at",
            "changed_at", "removed_at", "updated_at",
        },
        {
            "uq_mcp_tool_pins_connector_name": (("connector_id", "name_key"), True),
            "ix_mcp_tool_pins_connector_exposed": (("connector_id", "exposed_name"), False),
            "ix_mcp_tool_pins_user_status": (("user_id", "status"), False),
        },
        {(("user_id",), "users", "CASCADE"), (("connector_id",), "connector_configs", "CASCADE")},
    ),
    "breach_watch_addresses": (
        {
            "id", "user_id", "source", "address_digest", "address_sealed", "status",
            "next_check_at", "last_checked_at", "baseline_at", "breach_count",
            "consecutive_errors", "last_error_code", "created_at", "updated_at",
        },
        {
            "uq_breach_watch_addresses_user_digest": (("user_id", "address_digest"), True),
            "ix_breach_watch_addresses_status_next_check": (("status", "next_check_at"), False),
        },
        {(("user_id",), "users", "CASCADE")},
    ),
    "breach_watch_findings": (
        {
            "id", "address_id", "user_id", "breach_name", "title", "domain", "breach_date",
            "added_at", "pwn_count", "data_classes", "verified", "sensitive", "fabricated",
            "spam_list", "baseline", "first_seen_at", "alerted_at", "acknowledged_at",
        },
        {
            "uq_breach_watch_findings_address_name": (("address_id", "breach_name"), True),
            "ix_breach_watch_findings_user_seen": (("user_id", "first_seen_at"), False),
        },
        {
            (("address_id",), "breach_watch_addresses", "CASCADE"),
            (("user_id",), "users", "CASCADE"),
        },
    ),
    "browser_site_rules": (
        {"id", "target_type", "target", "kind", "created_by", "updated_by", "created_at", "updated_at"},
        {"ux_browser_site_rules_target": (("target_type", "target"), True)},
        {(("created_by",), "users", "SET NULL"), (("updated_by",), "users", "SET NULL")},
    ),
    "tool_rules": (
        {"id", "name", "tool_pattern", "conditions", "created_by", "created_at"},
        {"ix_tool_rules_created_at": (("created_at",), False)},
        {(("created_by",), "users", "SET NULL")},
    ),
    "tool_rule_builtins": (
        {"key", "enabled", "changed_by", "changed_at"},
        {},
        {(("changed_by",), "users", "SET NULL")},
    ),
    "file_reputation_verdicts": (
        {
            "sha256", "verdict", "malicious", "suspicious", "harmless", "undetected", "engines",
            "threat_label", "file_type", "first_seen_at", "analysed_at", "origin", "fetched_at",
            "expires_at",
        },
        {"ix_file_reputation_verdicts_expires_at": (("expires_at",), False)},
        set(),
    ),
    "file_reputation_checks": (
        {
            "id", "user_id", "sha256", "name", "media_type", "size_bytes", "source", "source_ref",
            "source_key", "state", "priority", "verdict", "malicious", "suspicious", "engines",
            "threat_label", "reason", "alerted_verdict", "action_id", "analysis_id", "polls",
            "next_poll_at", "claimed_until", "uploaded_at", "checked_at", "created_at",
            "updated_at", "expires_at",
        },
        {
            "uq_file_reputation_checks_user_sha256": (("user_id", "sha256"), True),
            "ix_file_reputation_checks_user_updated": (("user_id", "updated_at"), False),
            "ix_file_reputation_checks_user_source_key": (("user_id", "source_key"), False),
            "ix_file_reputation_checks_state_due": (("state", "next_poll_at"), False),
            "ix_file_reputation_checks_expires_at": (("expires_at",), False),
        },
        {(("user_id",), "users", "CASCADE")},
    ),
    "file_reputation_calls": (
        {"id", "at", "kind", "priority", "user_id"},
        {
            "ix_file_reputation_calls_at": (("at",), False),
            "ix_file_reputation_calls_user_at": (("user_id", "at"), False),
        },
        {(("user_id",), "users", "SET NULL")},
    ),
}

# The two columns 0025 adds to tables that already exist.
ADDED_COLUMNS = {"installation": "security_service_keys", "pending_actions": "security_notes"}


def _config(db_path: Path) -> Config:
    config = Config(str(BACKEND_DIR / "alembic.ini"))
    config.set_main_option("script_location", str(BACKEND_DIR / "alembic"))
    config.attributes["sqlalchemy_url"] = f"sqlite+aiosqlite:///{db_path}"
    config.attributes["configure_logger"] = False
    return config


def _schema(db_path: Path) -> dict[str, Any]:
    """Every table's columns, indexes and foreign keys, reflected."""
    engine = sa.create_engine(f"sqlite:///{db_path}")
    try:
        inspector = sa.inspect(engine)
        schema: dict[str, Any] = {}
        for table in inspector.get_table_names():
            schema[table] = {
                "columns": {c["name"] for c in inspector.get_columns(table)},
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
        return schema
    finally:
        engine.dispose()


def _versions(db_path: Path) -> list[str]:
    engine = sa.create_engine(f"sqlite:///{db_path}")
    try:
        with engine.connect() as conn:
            return sorted(conn.execute(sa.text("SELECT version_num FROM alembic_version")).scalars())
    finally:
        engine.dispose()


def _assert_security_schema(schema: dict[str, Any]) -> None:
    for table, (columns, indexes, foreign_keys) in TABLES.items():
        assert table in schema, table
        assert schema[table]["columns"] == columns, table
        assert schema[table]["indexes"] == indexes, table
        assert schema[table]["foreign_keys"] == foreign_keys, table
    for table, column in ADDED_COLUMNS.items():
        assert column in schema[table]["columns"], (table, column)


def test_upgrading_to_head_creates_every_table_index_foreign_key_and_added_column(tmp_path):
    db_path = tmp_path / "security.db"
    command.upgrade(_config(db_path), "head")
    assert _versions(db_path) == [HEAD]
    _assert_security_schema(_schema(db_path))


def test_downgrading_to_0024_removes_exactly_the_security_schema_and_keeps_the_rest(tmp_path):
    db_path = tmp_path / "roundtrip.db"
    config = _config(db_path)
    command.upgrade(config, BEFORE)
    before = _schema(db_path)
    # A row in each table 0025 alters, so the batch rebuild is seen to keep data.
    engine = sa.create_engine(f"sqlite:///{db_path}")
    try:
        with engine.begin() as conn:
            conn.execute(
                sa.text(
                    "INSERT INTO installation (id, capabilities, capability_settings, "
                    "allow_registration, updated_at) VALUES (2, '{}', '{}', 0, '2026-10-14')"
                )
            )
    finally:
        engine.dispose()

    command.upgrade(config, "head")
    command.downgrade(config, BEFORE)
    after = _schema(db_path)
    assert _versions(db_path) == [BEFORE]
    assert not set(TABLES) & set(after)
    # Every table that existed before is back exactly as it was: the two
    # altered tables keep their other columns, indexes and foreign keys.
    assert after == before
    engine = sa.create_engine(f"sqlite:///{db_path}")
    try:
        with engine.connect() as conn:
            ids = conn.execute(sa.text("SELECT id FROM installation ORDER BY id")).scalars().all()
    finally:
        engine.dispose()
    assert 2 in ids

    command.upgrade(config, "head")
    assert _versions(db_path) == [HEAD]
    _assert_security_schema(_schema(db_path))


def test_each_revision_downgrades_to_its_parent_and_upgrades_again(tmp_path):
    db_path = tmp_path / "steps.db"
    config = _config(db_path)
    command.upgrade(config, "head")
    for revision, parent in zip(reversed(REVISIONS), reversed((BEFORE, *REVISIONS[:-1])), strict=True):
        assert _versions(db_path) == [revision]
        command.downgrade(config, parent)
    assert _versions(db_path) == [BEFORE]
    command.upgrade(config, "head")
    _assert_security_schema(_schema(db_path))


def test_an_adopted_database_built_from_the_models_upgrades_without_creating_anything_twice(
    tmp_path,
):
    import models  # noqa: F401 - registers every model
    from core.database import Base

    db_path = tmp_path / "adopted.db"
    engine = sa.create_engine(f"sqlite:///{db_path}")
    try:
        Base.metadata.create_all(engine)
    finally:
        engine.dispose()
    config = _config(db_path)
    command.stamp(config, BEFORE)
    command.upgrade(config, "head")
    assert _versions(db_path) == [HEAD]
    _assert_security_schema(_schema(db_path))


def test_every_revision_keeps_its_reserved_place_and_uses_no_enum_type():
    versions = BACKEND_DIR / "alembic" / "versions"
    for revision, parent in zip(REVISIONS, (BEFORE, *REVISIONS[:-1]), strict=True):
        source = (versions / f"{revision}.py").read_text(encoding="utf-8")
        assert f'revision = "{revision}"' in source
        assert f'down_revision = "{parent}"' in source
        # Statuses and kinds are strings checked in code: no Postgres enum type.
        assert "sa.Enum(" not in source, revision
