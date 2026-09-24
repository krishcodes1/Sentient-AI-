"""Makes ``users.llm_provider`` and ``llm_model`` nullable and drops their
server defaults, through a batch operation so it also works on SQLite.

Why it exists: NULL now means an account follows the install's provider, so a
key the owner saves later reaches every account that never chose one; the
nullability guard lets the revision run on an adopted database built from the
models.

Let an account's provider/model be NULL: "follow this Crawler's default".

``users.llm_provider``/``llm_model`` were NOT NULL with a server default of
the historical Anthropic pair, and the ORM stamped the server's configured
pair onto every new account. Either way an account named a provider it
never chose, so a key the owner later saved for a different provider (the
setup wizard) never reached it. NULL now means "use the install default,
whatever it is when the turn runs". Both server defaults go too: a row
written without a provider must follow the install, not silently pin the
old default.

Which existing rows become NULL is decided at startup
(``core.database.backfill_user_llm_defaults``), because it depends on the
server's configured defaults — runtime settings, not static DDL.

The alter is guarded for the same reason as 0003-0008: an adopted legacy
database is created from model metadata (which already has nullable
columns) before the upgrade runs. SQLite cannot ALTER a column's
nullability in place, so the change goes through a batch operation, which
rebuilds the table there and is a plain ALTER on Postgres.

Downgrade restores NOT NULL, filling NULLs with the historical default
first so it cannot fail on accounts that follow the install.

Revision ID: 0009_user_llm_nullable
Revises: 0008_installation
"""

import sqlalchemy as sa
from alembic import op

revision = "0009_user_llm_nullable"
down_revision = "0008_installation"
branch_labels = None
depends_on = None

_LEGACY_PROVIDER = "anthropic"
_LEGACY_MODEL = "claude-sonnet-4-20250514"

_COLUMNS = (
    ("llm_provider", sa.String(length=32), _LEGACY_PROVIDER),
    ("llm_model", sa.String(length=128), _LEGACY_MODEL),
)


def _nullable(table: str, column: str) -> bool:
    inspector = sa.inspect(op.get_bind())
    for info in inspector.get_columns(table):
        if info["name"] == column:
            return bool(info["nullable"])
    raise RuntimeError(f"{table}.{column} is missing")


def upgrade() -> None:
    pending = [c for c in _COLUMNS if not _nullable("users", c[0])]
    if not pending:
        return
    with op.batch_alter_table("users") as batch:
        for name, type_, legacy in pending:
            batch.alter_column(
                name,
                existing_type=type_,
                existing_server_default=legacy,
                existing_nullable=False,
                nullable=True,
                server_default=None,
            )


def downgrade() -> None:
    pending = [c for c in _COLUMNS if _nullable("users", c[0])]
    if not pending:
        return
    users = sa.table(
        "users",
        sa.column("llm_provider", sa.String()),
        sa.column("llm_model", sa.String()),
    )
    # A NULL provider means "the install default"; the closest static value
    # the old schema can hold is the historical default pair.
    op.execute(
        users.update()
        .where(users.c.llm_provider.is_(None))
        .values(llm_provider=_LEGACY_PROVIDER, llm_model=_LEGACY_MODEL)
    )
    op.execute(
        users.update()
        .where(users.c.llm_model.is_(None))
        .values(llm_model=_LEGACY_MODEL)
    )
    with op.batch_alter_table("users") as batch:
        for name, type_, legacy in pending:
            batch.alter_column(
                name,
                existing_type=type_,
                existing_nullable=True,
                nullable=False,
                server_default=legacy,
            )
