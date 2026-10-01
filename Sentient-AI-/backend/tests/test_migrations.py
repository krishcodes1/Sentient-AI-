"""Tests for migration and model consistency: the schema `alembic upgrade head`
builds matches the schema `Base.metadata.create_all()` expects, that there is a
single migration head, and that Postgres-only behavior like native ENUM types
and cascading deletes is correct.

Why it exists: A model changed without a matching Alembic revision would
otherwise only surface as a broken production deploy instead of failing here.

Migrations have to stay honest.

The schema `alembic upgrade head` builds and the schema the ORM expects are
two independent descriptions of the same thing, and nothing keeps them in
sync except discipline. These tests build a database each way — one by
running every migration, one by `Base.metadata.create_all()` — and compare
what the database actually ended up with. A model changed without a
matching revision fails here instead of at 3am on a production deploy.

Everything runs on a throwaway SQLite file so CI needs no Postgres.
Behaviour that only exists on Postgres (native ENUM types) is checked in a
separate test that skips unless TEST_DATABASE_URL points at one.
"""

from __future__ import annotations

import asyncio
import os
import uuid
from pathlib import Path
from typing import Any

import pytest
import sqlalchemy as sa
from alembic import command
from alembic.config import Config

BACKEND_DIR = Path(__file__).resolve().parents[1]

TEST_DATABASE_URL = os.environ.get("TEST_DATABASE_URL", "")

# Columns that used to be bolted on by core.database.init_db's inline ALTER
# list. They are the ones most likely to be dropped from a hand-written
# baseline, and the ones whose absence breaks the app in ways a smoke test
# does not catch (the audit chain, the settings page, approval risk notes).
RETROFITTED_COLUMNS = {
    "audit_logs": {"previous_hash", "seq"},
    "users": {
        "name",
        "default_permission_tier",
        "rate_limit",
        "llm_provider",
        "llm_model",
        "memory_enabled",
        "token_epoch",
    },
    "memories": {"source", "source_conversation_id"},
    "pending_actions": {"risk_note"},
}


def _alembic_config(url: str) -> Config:
    """Alembic Config pointed at a specific database.

    Paths are absolute because pytest's working directory is not guaranteed
    to be backend/, and `configure_logger` is off so env.py's fileConfig()
    never tears down the logging the test session is already using.
    """
    config = Config(str(BACKEND_DIR / "alembic.ini"))
    config.set_main_option("script_location", str(BACKEND_DIR / "alembic"))
    config.attributes["sqlalchemy_url"] = url
    config.attributes["configure_logger"] = False
    return config


def _snapshot(sync_url: str) -> dict[str, Any]:
    """Reflect a database into a comparable structure.

    Indexes, primary keys and foreign keys are included alongside columns:
    a baseline that gets every column right but loses an index or an
    ON DELETE CASCADE is still a production incident, just a slower one.
    """
    engine = sa.create_engine(sync_url)
    try:
        inspector = sa.inspect(engine)
        snapshot: dict[str, Any] = {}
        for table in inspector.get_table_names():
            # Alembic's own bookkeeping; only the migrated database has it.
            if table == "alembic_version":
                continue
            snapshot[table] = {
                "columns": {
                    column["name"]: (
                        str(column["type"]),
                        bool(column["nullable"]),
                        column.get("default"),
                    )
                    for column in inspector.get_columns(table)
                },
                "primary_key": tuple(
                    inspector.get_pk_constraint(table)["constrained_columns"]
                ),
                "indexes": {
                    index["name"]: (
                        tuple(index["column_names"]),
                        bool(index.get("unique")),
                    )
                    for index in inspector.get_indexes(table)
                },
                "foreign_keys": {
                    (
                        tuple(fk["constrained_columns"]),
                        fk["referred_table"],
                        tuple(fk["referred_columns"]),
                        (fk.get("options") or {}).get("ondelete"),
                    )
                    for fk in inspector.get_foreign_keys(table)
                },
            }
        return snapshot
    finally:
        engine.dispose()


@pytest.fixture(scope="module")
def migrated(tmp_path_factory) -> dict[str, Any]:
    """Schema produced by `alembic upgrade head`."""
    db_path = tmp_path_factory.mktemp("alembic") / "migrated.db"
    command.upgrade(_alembic_config(f"sqlite+aiosqlite:///{db_path}"), "head")
    return _snapshot(f"sqlite:///{db_path}")


@pytest.fixture(scope="module")
def created(tmp_path_factory) -> dict[str, Any]:
    """Schema produced by Base.metadata.create_all() — what the ORM expects."""
    import models  # noqa: F401 — registers every model on Base.metadata
    from core.database import Base

    db_path = tmp_path_factory.mktemp("create_all") / "metadata.db"
    engine = sa.create_engine(f"sqlite:///{db_path}")
    try:
        Base.metadata.create_all(engine)
    finally:
        engine.dispose()
    return _snapshot(f"sqlite:///{db_path}")


# ---------------------------------------------------------------------------
# Migrated schema == ORM schema
# ---------------------------------------------------------------------------


def test_same_tables(migrated, created):
    assert set(migrated) == set(created)


def test_tables_are_not_empty(created):
    """Guards the comparison itself: two empty snapshots also compare equal."""
    assert {
        "users",
        "conversations",
        "messages",
        "connector_configs",
        "audit_logs",
        "memories",
        "pending_actions",
    } <= set(created)


@pytest.mark.parametrize(
    "aspect", ["columns", "primary_key", "indexes", "foreign_keys"]
)
def test_schema_aspect_matches(migrated, created, aspect):
    """Compare one aspect at a time so a failure names what actually drifted."""
    for table in sorted(created):
        assert migrated[table][aspect] == created[table][aspect], (
            f"{table}.{aspect} differs between 'alembic upgrade head' and "
            f"Base.metadata.create_all()"
        )


# ---------------------------------------------------------------------------
# The columns the old inline-ALTER list used to add
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("table", sorted(RETROFITTED_COLUMNS))
def test_retrofitted_columns_survive_the_baseline(migrated, table):
    missing = RETROFITTED_COLUMNS[table] - set(migrated[table]["columns"])
    assert not missing, f"baseline is missing {table} columns: {sorted(missing)}"


def test_audit_seq_index_exists(migrated):
    """Appending an audit row looks up the chain head by seq; without this
    index that is a full scan of the user's history on every tool call."""
    assert migrated["audit_logs"]["indexes"]["ix_audit_logs_seq"] == (("seq",), False)


def test_users_email_index_is_unique(migrated):
    assert migrated["users"]["indexes"]["ix_users_email"] == (("email",), True)


def test_user_owned_rows_cascade_on_delete(migrated):
    """Deleting a user must not strand their audit logs, conversations,
    connectors, memories, parked approvals, connector sign-in flows or
    Slack DM links."""
    for table in (
        "audit_logs",
        "connector_configs",
        "conversations",
        "memories",
        "oauth_states",
        "pending_actions",
        "slack_channel_links",
        "scheduled_tasks",
        "automation_runs",
        "user_files",
        # top10:knowledge_base
        "kb_collections",
        "kb_documents",
        "kb_chunks",
        "kb_postings",
        "kb_embeddings",
        # top10:flashcards_quizzes
        "study_decks",
        "study_items",
        "study_reviews",
        "study_quiz_attempts",
        "study_settings",
        "media_transcripts",
        "event_triggers",
        "trigger_events",
        "permission_grants",
    ):
        cascades = {
            fk[3]
            for fk in migrated[table]["foreign_keys"]
            if fk[1] == "users"
        }
        assert cascades == {"CASCADE"}, f"{table}.user_id is missing ON DELETE CASCADE"


def test_slack_links_cascade_with_their_connector(migrated):
    """A Slack DM link dies with its connector, is keyed by it, and is
    found by user through an index."""
    table = migrated["slack_channel_links"]
    assert (("connector_id",), "connector_configs", ("id",), "CASCADE") in table["foreign_keys"]
    assert table["primary_key"] == ("connector_id",)
    assert table["indexes"]["ix_slack_channel_links_user_id"] == (("user_id",), False)


# ---------------------------------------------------------------------------
# Migration mechanics
# ---------------------------------------------------------------------------


def test_single_head():
    """Two heads mean a merge is missing and `upgrade head` is ambiguous."""
    from alembic.script import ScriptDirectory

    script = ScriptDirectory.from_config(_alembic_config("sqlite://"))
    assert len(script.get_heads()) == 1


def test_head_is_recorded(tmp_path):
    """`alembic current` must report the head after an upgrade — otherwise a
    later `upgrade` would try to replay the baseline over a live schema."""
    from alembic.script import ScriptDirectory

    db_path = tmp_path / "stamped.db"
    config = _alembic_config(f"sqlite+aiosqlite:///{db_path}")
    command.upgrade(config, "head")

    engine = sa.create_engine(f"sqlite:///{db_path}")
    try:
        with engine.connect() as conn:
            recorded = conn.execute(
                sa.text("SELECT version_num FROM alembic_version")
            ).scalars().all()
    finally:
        engine.dispose()

    assert recorded == list(ScriptDirectory.from_config(config).get_heads())


def test_stamp_does_not_touch_an_existing_schema(tmp_path):
    """The documented adoption path for existing deployments: build the
    schema the way the app does today, `stamp` the baseline, and end up
    with a versioned database whose tables were never re-created."""
    import models  # noqa: F401
    from core.database import Base

    db_path = tmp_path / "legacy.db"
    engine = sa.create_engine(f"sqlite:///{db_path}")
    try:
        Base.metadata.create_all(engine)
        with engine.begin() as conn:
            conn.execute(
                sa.text(
                    "INSERT INTO users (id, email, hashed_password, is_active, "
                    "created_at, updated_at) VALUES "
                    "('abc', 'legacy@example.com', 'x', 1, "
                    "'2026-01-01 00:00:00', '2026-01-01 00:00:00')"
                )
            )
    finally:
        engine.dispose()

    command.stamp(_alembic_config(f"sqlite+aiosqlite:///{db_path}"), "0001_baseline")

    engine = sa.create_engine(f"sqlite:///{db_path}")
    try:
        with engine.connect() as conn:
            assert conn.execute(
                sa.text("SELECT version_num FROM alembic_version")
            ).scalar_one() == "0001_baseline"
            # The pre-existing row is still there: stamping recorded history,
            # it did not rebuild anything.
            assert conn.execute(
                sa.text("SELECT email FROM users")
            ).scalar_one() == "legacy@example.com"
    finally:
        engine.dispose()


def test_downgrade_removes_every_table(tmp_path):
    """An un-revertable migration is an outage with no exit."""
    db_path = tmp_path / "roundtrip.db"
    config = _alembic_config(f"sqlite+aiosqlite:///{db_path}")
    command.upgrade(config, "head")
    command.downgrade(config, "base")

    engine = sa.create_engine(f"sqlite:///{db_path}")
    try:
        remaining = set(sa.inspect(engine).get_table_names()) - {"alembic_version"}
    finally:
        engine.dispose()
    assert remaining == set()


def test_no_pending_autogenerate_diff(tmp_path):
    """A model added without a migration shows up as a pending operation.

    This is the check that keeps the two schemas converged going forward:
    test_schema_aspect_matches compares what exists, this one asks alembic
    whether anything is *missing*.
    """
    import models  # noqa: F401
    from alembic.autogenerate import compare_metadata
    from alembic.runtime.migration import MigrationContext

    from core.database import Base

    db_path = tmp_path / "diff.db"
    command.upgrade(_alembic_config(f"sqlite+aiosqlite:///{db_path}"), "head")

    engine = sa.create_engine(f"sqlite:///{db_path}")
    try:
        with engine.connect() as conn:
            context = MigrationContext.configure(conn, opts={"compare_type": True})
            diff = compare_metadata(context, Base.metadata)
    finally:
        engine.dispose()

    assert diff == [], f"models and migrations have diverged: {diff}"


# ---------------------------------------------------------------------------
# 0011: connector_type ENUM -> VARCHAR(64)
# ---------------------------------------------------------------------------

_BEFORE_0011 = "0010_vault_items"
_REVISION_0011 = "0011_connector_type_string"


def _seed_connector(sync_url: str, connector_type: str) -> str:
    """Insert one user and one connector row with raw SQL (the ORM model
    describes the head schema, not the revision under test)."""
    connector_id = uuid.uuid4().hex
    engine = sa.create_engine(sync_url)
    try:
        with engine.begin() as conn:
            user_id = conn.execute(sa.text("SELECT id FROM users")).scalar()
            if user_id is None:
                user_id = uuid.uuid4().hex
                conn.execute(
                    sa.text(
                        "INSERT INTO users (id, email, hashed_password, is_active, "
                        "created_at, updated_at) VALUES (:id, 'c@example.com', 'x', 1, "
                        "'2026-01-01 00:00:00', '2026-01-01 00:00:00')"
                    ),
                    {"id": user_id},
                )
            conn.execute(
                sa.text(
                    "INSERT INTO connector_configs (id, user_id, connector_type, "
                    "display_name, is_active, auth_method, encrypted_credentials, "
                    "granted_scopes, permission_tier, rate_limit_per_minute, "
                    "created_at, updated_at) VALUES (:id, :user_id, :type, 'Mine', 1, "
                    "'bearer_token', :blob, '[]', 'user_confirm', 30, "
                    "'2026-01-01 00:00:00', '2026-01-01 00:00:00')"
                ),
                {
                    "id": connector_id,
                    "user_id": user_id,
                    "type": connector_type,
                    "blob": b"\x00",
                },
            )
    finally:
        engine.dispose()
    return connector_id


def _connector_type_column(sync_url: str) -> sa.types.TypeEngine:
    engine = sa.create_engine(sync_url)
    try:
        columns = sa.inspect(engine).get_columns("connector_configs")
    finally:
        engine.dispose()
    return next(c["type"] for c in columns if c["name"] == "connector_type")


def _stored_types(sync_url: str) -> list[str]:
    engine = sa.create_engine(sync_url)
    try:
        with engine.connect() as conn:
            return sorted(
                conn.execute(
                    sa.text("SELECT connector_type FROM connector_configs")
                ).scalars()
            )
    finally:
        engine.dispose()


def _recorded_revision(sync_url: str) -> str:
    engine = sa.create_engine(sync_url)
    try:
        with engine.connect() as conn:
            return conn.execute(
                sa.text("SELECT version_num FROM alembic_version")
            ).scalar_one()
    finally:
        engine.dispose()


def test_0011_widens_the_column_and_keeps_existing_rows(tmp_path):
    db_path = tmp_path / "widen.db"
    config = _alembic_config(f"sqlite+aiosqlite:///{db_path}")
    sync_url = f"sqlite:///{db_path}"
    command.upgrade(config, _BEFORE_0011)
    assert str(_connector_type_column(sync_url)) == "VARCHAR(16)"
    _seed_connector(sync_url, "canvas")
    _seed_connector(sync_url, "mcp")

    command.upgrade(config, _REVISION_0011)

    assert str(_connector_type_column(sync_url)) == "VARCHAR(64)"
    assert _stored_types(sync_url) == ["canvas", "mcp"]
    # A registry key longer than the old 16 characters now fits.
    _seed_connector(sync_url, "a_connector_key_longer_than_sixteen")
    assert "a_connector_key_longer_than_sixteen" in _stored_types(sync_url)


def test_0011_keeps_the_index_and_the_cascading_foreign_key(tmp_path):
    """The SQLite path rebuilds the table; the rebuild must not drop the
    user_id index or the ON DELETE CASCADE."""
    db_path = tmp_path / "rebuild.db"
    command.upgrade(_alembic_config(f"sqlite+aiosqlite:///{db_path}"), _REVISION_0011)
    table = _snapshot(f"sqlite:///{db_path}")["connector_configs"]
    assert table["indexes"]["ix_connector_configs_user_id"] == (("user_id",), False)
    assert (("user_id",), "users", ("id",), "CASCADE") in table["foreign_keys"]


def test_0011_downgrade_restores_the_legacy_column(tmp_path):
    db_path = tmp_path / "restore.db"
    config = _alembic_config(f"sqlite+aiosqlite:///{db_path}")
    sync_url = f"sqlite:///{db_path}"
    command.upgrade(config, _REVISION_0011)
    _seed_connector(sync_url, "google_workspace")

    command.downgrade(config, _BEFORE_0011)

    assert str(_connector_type_column(sync_url)) == "VARCHAR(16)"
    assert _stored_types(sync_url) == ["google_workspace"]
    assert _recorded_revision(sync_url) == _BEFORE_0011


def test_0011_downgrade_refuses_types_the_old_enum_cannot_hold(tmp_path):
    db_path = tmp_path / "refuse.db"
    config = _alembic_config(f"sqlite+aiosqlite:///{db_path}")
    sync_url = f"sqlite:///{db_path}"
    command.upgrade(config, _REVISION_0011)
    _seed_connector(sync_url, "canvas")
    _seed_connector(sync_url, "github")

    with pytest.raises(RuntimeError, match="github") as excinfo:
        command.downgrade(config, _BEFORE_0011)

    # Only the offending type is named, and the fix is spelled out.
    assert "type(s) github," in str(excinfo.value)
    assert "Delete those connectors first" in str(excinfo.value)
    # Nothing changed: still the wide column, every row intact, still at 0011.
    assert str(_connector_type_column(sync_url)) == "VARCHAR(64)"
    assert _stored_types(sync_url) == ["canvas", "github"]
    assert _recorded_revision(sync_url) == _REVISION_0011


def test_0011_upgrade_is_a_no_op_on_an_already_converted_column(tmp_path):
    """An adopted database built from the current models already has
    VARCHAR(64); re-running the revision must leave it and its rows alone."""
    db_path = tmp_path / "noop.db"
    config = _alembic_config(f"sqlite+aiosqlite:///{db_path}")
    sync_url = f"sqlite:///{db_path}"
    command.upgrade(config, _REVISION_0011)
    _seed_connector(sync_url, "notion")
    command.stamp(config, _BEFORE_0011)

    command.upgrade(config, _REVISION_0011)

    assert str(_connector_type_column(sync_url)) == "VARCHAR(64)"
    assert _stored_types(sync_url) == ["notion"]


# ---------------------------------------------------------------------------
# Postgres-only: native ENUM types
# ---------------------------------------------------------------------------


@pytest.mark.skipif(
    "postgresql" not in TEST_DATABASE_URL,
    reason=(
        "native ENUM types exist only on Postgres; SQLite renders sa.Enum as "
        "VARCHAR. Set TEST_DATABASE_URL to an asyncpg URL (the backend-postgres "
        "CI job does) to exercise this."
    ),
)
def test_postgres_enum_types_match_the_models():
    """The native ENUM types an upgraded database ends up with match the
    model enums, and `connector_type` is no longer one of them: revision
    0011 turned the column into VARCHAR(64) (validated against the
    connector registry at the API) and dropped the type, so a new connector
    needs no `ALTER TYPE`. A leftover type would also make `alembic check`
    and the create_all schema disagree.

    Runs against a throwaway database so it cannot disturb the shared test
    schema the rest of the suite uses.
    """
    from sqlalchemy.engine import make_url
    from sqlalchemy.ext.asyncio import create_async_engine

    from models.connector import AuthMethod, PermissionTier

    admin_url = make_url(TEST_DATABASE_URL)
    scratch = f"migration_check_{uuid.uuid4().hex[:12]}"
    scratch_url = admin_url.set(database=scratch)

    async def _run(statement: str) -> None:
        engine = create_async_engine(admin_url, isolation_level="AUTOCOMMIT")
        try:
            async with engine.connect() as conn:
                await conn.execute(sa.text(statement))
        finally:
            await engine.dispose()

    try:
        asyncio.run(_run(f'CREATE DATABASE "{scratch}"'))
    except Exception as exc:  # no CREATEDB privilege, etc.
        pytest.skip(f"cannot provision a throwaway database: {exc}")

    try:
        command.upgrade(
            _alembic_config(scratch_url.render_as_string(hide_password=False)), "head"
        )

        async def _enum_labels() -> dict[str, list[str]]:
            engine = create_async_engine(scratch_url)
            try:
                async with engine.connect() as conn:
                    rows = await conn.execute(
                        sa.text(
                            "SELECT t.typname, e.enumlabel FROM pg_type t "
                            "JOIN pg_enum e ON e.enumtypid = t.oid "
                            "ORDER BY t.typname, e.enumsortorder"
                        )
                    )
                    labels: dict[str, list[str]] = {}
                    for typname, label in rows.all():
                        labels.setdefault(typname, []).append(label)
                    return labels
            finally:
                await engine.dispose()

        async def _connector_type_column() -> tuple[str, int | None]:
            engine = create_async_engine(scratch_url)
            try:
                async with engine.connect() as conn:
                    row = await conn.execute(
                        sa.text(
                            "SELECT data_type, character_maximum_length "
                            "FROM information_schema.columns "
                            "WHERE table_name = 'connector_configs' "
                            "AND column_name = 'connector_type'"
                        )
                    )
                    data_type, length = row.one()
                    return str(data_type), length
            finally:
                await engine.dispose()

        labels = asyncio.run(_enum_labels())

        assert "connector_type" not in labels
        assert asyncio.run(_connector_type_column()) == ("character varying", 64)
        assert set(labels["auth_method"]) == {m.value for m in AuthMethod}
        assert set(labels["permission_tier"]) == {t.value for t in PermissionTier}
    finally:
        try:
            asyncio.run(_run(f'DROP DATABASE IF EXISTS "{scratch}" WITH (FORCE)'))
        except Exception:
            # A leaked scratch database is noise in CI, not a test failure.
            pass


# ---------------------------------------------------------------------------
# 0023_permission_grants (permission tiers)
# ---------------------------------------------------------------------------


def test_permission_grants_cascade_with_their_connector(migrated):
    """A grant dies with its connection (and its user), and is found by
    (user, connector, kind) through one index."""
    table = migrated["permission_grants"]
    assert (("connector_id",), "connector_configs", ("id",), "CASCADE") in table["foreign_keys"]
    assert (("user_id",), "users", ("id",), "CASCADE") in table["foreign_keys"]
    assert table["indexes"]["ix_permission_grants_lookup"] == (
        ("user_id", "connector_id", "kind"),
        False,
    )
    assert "grant_offer" in migrated["pending_actions"]["columns"]


def test_0023_downgrade_maps_low_risk_tiers_to_user_confirm(tmp_path):
    """Nothing that asked before a downgrade stops asking after it: every
    low_risk tier (a connection's or an account's) becomes user_confirm, and
    the table and column go."""
    db_path = tmp_path / "tiers.db"
    config = _alembic_config(f"sqlite+aiosqlite:///{db_path}")
    command.upgrade(config, "0023_permission_grants")

    user_id, connector_id = uuid.uuid4().hex, uuid.uuid4().hex
    engine = sa.create_engine(f"sqlite:///{db_path}")
    try:
        with engine.begin() as conn:
            conn.execute(
                sa.text(
                    "INSERT INTO users (id, email, hashed_password, is_active, "
                    "default_permission_tier, created_at, updated_at) VALUES "
                    "(:id, 'tiers@example.com', 'x', 1, 'low_risk', "
                    "'2026-01-01 00:00:00', '2026-01-01 00:00:00')"
                ),
                {"id": user_id},
            )
            conn.execute(
                sa.text(
                    "INSERT INTO connector_configs (id, user_id, connector_type, display_name, "
                    "is_active, auth_method, encrypted_credentials, granted_scopes, "
                    "permission_tier, rate_limit_per_minute, created_at, updated_at) VALUES "
                    "(:id, :user, 'github', 'GH', 1, 'bearer_token', x'00', '[]', 'low_risk', 30, "
                    "'2026-01-01 00:00:00', '2026-01-01 00:00:00')"
                ),
                {"id": connector_id, "user": user_id},
            )
    finally:
        engine.dispose()

    command.downgrade(config, "0022_event_triggers")

    engine = sa.create_engine(f"sqlite:///{db_path}")
    try:
        with engine.connect() as conn:
            assert conn.execute(sa.text("SELECT default_permission_tier FROM users")).scalar_one() == "user_confirm"
            assert conn.execute(sa.text("SELECT permission_tier FROM connector_configs")).scalar_one() == "user_confirm"
        inspector = sa.inspect(engine)
        assert "permission_grants" not in inspector.get_table_names()
        assert "grant_offer" not in {c["name"] for c in inspector.get_columns("pending_actions")}
    finally:
        engine.dispose()
