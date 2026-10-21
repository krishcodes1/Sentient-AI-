"""Tests for migration 0028_mcp_tool_pins (security S5): they prove the revision
creates ``mcp_tool_pins`` with every column and its three indexes (one of them
the unique per-server tool key), that pins die with their user and with their
connector (ON DELETE CASCADE), and that downgrading drops the table while a
second upgrade recreates it.

Why it exists: the unique key is what makes two workers trusting one server
at once settle on one set of pins, and the cascades are why deleting a
connector or an account leaves no pin behind. tests/test_security_migrations.py
checks the whole chain at a glance; this one goes into S5's table.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
import sqlalchemy as sa
from alembic import command
from alembic.config import Config

BACKEND_DIR = Path(__file__).resolve().parents[1]
REVISION = "0028_mcp_tool_pins"
PARENT = "0027_mail_security"
COLUMNS = {
    "id", "user_id", "connector_id", "name_key", "remote_name", "exposed_name", "status",
    "review_kind", "trusted_how", "approved_hash", "approved_definition",
    "approved_hidden_chars", "pending_hash", "pending_definition", "pending_hidden_chars",
    "change_count", "notified_hash", "notified_at", "first_seen_at", "approved_at",
    "changed_at", "removed_at", "updated_at",
}
INDEXES = {
    "uq_mcp_tool_pins_connector_name": (("connector_id", "name_key"), True),
    "ix_mcp_tool_pins_connector_exposed": (("connector_id", "exposed_name"), False),
    "ix_mcp_tool_pins_user_status": (("user_id", "status"), False),
}


def _config(db_path: Path) -> Config:
    config = Config(str(BACKEND_DIR / "alembic.ini"))
    config.set_main_option("script_location", str(BACKEND_DIR / "alembic"))
    config.attributes["sqlalchemy_url"] = f"sqlite+aiosqlite:///{db_path}"
    config.attributes["configure_logger"] = False
    return config


def _pins_table(db_path: Path):
    engine = sa.create_engine(f"sqlite:///{db_path}")
    try:
        inspector = sa.inspect(engine)
        if "mcp_tool_pins" not in inspector.get_table_names():
            return None
        return {
            "columns": {c["name"] for c in inspector.get_columns("mcp_tool_pins")},
            "nullable": {c["name"]: c["nullable"] for c in inspector.get_columns("mcp_tool_pins")},
            "indexes": {
                i["name"]: (tuple(i["column_names"]), bool(i.get("unique")))
                for i in inspector.get_indexes("mcp_tool_pins")
            },
            "foreign_keys": {
                (
                    tuple(fk["constrained_columns"]),
                    fk["referred_table"],
                    (fk.get("options") or {}).get("ondelete"),
                )
                for fk in inspector.get_foreign_keys("mcp_tool_pins")
            },
        }
    finally:
        engine.dispose()


def test_0028_creates_mcp_tool_pins_with_its_three_indexes(tmp_path):
    db_path = tmp_path / "pins.db"
    command.upgrade(_config(db_path), PARENT)
    assert _pins_table(db_path) is None

    command.upgrade(_config(db_path), REVISION)
    table = _pins_table(db_path)
    assert table is not None
    assert table["columns"] == COLUMNS
    assert table["indexes"] == INDEXES
    assert table["foreign_keys"] == {
        (("user_id",), "users", "CASCADE"),
        (("connector_id",), "connector_configs", "CASCADE"),
    }
    # The columns the code relies on being present are NOT NULL.
    for column in ("user_id", "connector_id", "name_key", "remote_name", "exposed_name", "status"):
        assert table["nullable"][column] is False, column
    for column in ("pending_hash", "approved_hash", "review_kind", "removed_at"):
        assert table["nullable"][column] is True, column


@pytest.mark.asyncio
async def test_mcp_tool_pins_cascade_with_their_user_and_their_connector(session_factory):
    from sqlalchemy import delete, func, select

    from core.security import encrypt_credentials
    from models.connector import AuthMethod, ConnectorConfig, ConnectorType
    from models.mcp_tool_pin import McpToolPin
    from models.user import User
    from tests.conftest import make_user

    async def connector_for(user_id) -> object:
        async with session_factory() as session:
            row = ConnectorConfig(
                user_id=user_id,
                connector_type=ConnectorType.mcp,
                display_name="Notes Server",
                auth_method=AuthMethod.bearer_token,
                encrypted_credentials=encrypt_credentials(json.dumps({"url": "https://a.test/mcp"})),
                granted_scopes=[],
            )
            session.add(row)
            await session.commit()
            return row.id

    async def pin(user_id, connector_id, key: str) -> None:
        async with session_factory() as session:
            session.add(
                McpToolPin(
                    user_id=user_id,
                    connector_id=connector_id,
                    name_key=key * 64,
                    remote_name="t",
                    exposed_name="t",
                    status="approved",
                    approved_hash="a" * 64,
                )
            )
            await session.commit()

    async def count() -> int:
        async with session_factory() as session:
            return int((await session.execute(select(func.count()).select_from(McpToolPin))).scalar_one())

    user, _ = await make_user(session_factory)
    first = await connector_for(user.id)
    second = await connector_for(user.id)
    await pin(user.id, first, "1")
    await pin(user.id, second, "2")
    assert await count() == 2

    async with session_factory() as session:
        await session.execute(delete(ConnectorConfig).where(ConnectorConfig.id == first))
        await session.commit()
    assert await count() == 1

    async with session_factory() as session:
        await session.execute(delete(User).where(User.id == user.id))
        await session.commit()
    assert await count() == 0


def test_0028_downgrade_drops_the_table_and_upgrade_recreates_it(tmp_path):
    db_path = tmp_path / "roundtrip.db"
    config = _config(db_path)
    command.upgrade(config, REVISION)
    engine = sa.create_engine(f"sqlite:///{db_path}")
    try:
        with engine.begin() as conn:
            assert conn.execute(sa.text("SELECT count(*) FROM mcp_tool_pins")).scalar_one() == 0
    finally:
        engine.dispose()

    command.downgrade(config, PARENT)
    assert _pins_table(db_path) is None

    command.upgrade(config, REVISION)
    table = _pins_table(db_path)
    assert table is not None and table["indexes"] == INDEXES

    # And the rest of the chain still stacks on top of it.
    command.upgrade(config, "head")
    assert _pins_table(db_path) is not None
