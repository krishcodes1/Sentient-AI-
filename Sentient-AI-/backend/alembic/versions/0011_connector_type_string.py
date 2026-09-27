"""Turns ``connector_configs.connector_type`` from the ``connector_type`` ENUM
into a plain ``VARCHAR(64)``.

Why it exists: connectors are now declared in ``services.connectors.registry``
and validated against it at the API boundary, so adding one must not need a
schema change. Connects to ``models.connector.ConnectorConfig`` and the
``/api/connectors`` routes; talks to no external service.

Postgres converts in place (``USING connector_type::text``) and then drops the
now unused type. SQLite has no ALTER COLUMN TYPE, so it goes through a batch
operation (a table rebuild).

The guard inspects the column rather than trusting the revision history,
like 0003 to 0009, because an adopted legacy database is built from the model
metadata (already ``VARCHAR(64)``) before the upgrade runs. It checks for a
non-Enum ``String`` of length 64: ``sa.Enum`` subclasses ``sa.String``, and
SQLite already reflects the old enum as ``VARCHAR(16)``, so a bare "is it a
string" check would skip SQLite and break create_all/upgrade parity.

Downgrade recreates the enum with its original five labels in their original
order, and refuses (changing nothing) while any row holds another type.

Revision ID: 0011_connector_type_string
Revises: 0010_vault_items
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0011_connector_type_string"
down_revision = "0010_vault_items"
branch_labels = None
depends_on = None

_TABLE = "connector_configs"
_COLUMN = "connector_type"
_ENUM_NAME = "connector_type"
_STRING_LENGTH = 64

# Frozen copy of the pre-0011 ENUM, in declaration order. Deliberately not
# imported from models: a migration must describe the schema as it was, not
# as the code later becomes.
_LEGACY_LABELS: tuple[str, ...] = (
    "canvas",
    "google_workspace",
    "robinhood",
    "mcp",
    "custom",
)


def _column_type() -> sa.types.TypeEngine:
    inspector = sa.inspect(op.get_bind())
    for info in inspector.get_columns(_TABLE):
        if info["name"] == _COLUMN:
            return info["type"]
    raise RuntimeError(f"{_TABLE}.{_COLUMN} is missing")


def _is_varchar64(type_: sa.types.TypeEngine) -> bool:
    return (
        isinstance(type_, sa.String)
        and not isinstance(type_, sa.Enum)
        and type_.length == _STRING_LENGTH
    )


def _is_postgres() -> bool:
    return op.get_bind().dialect.name == "postgresql"


def upgrade() -> None:
    existing = _column_type()
    if not _is_varchar64(existing):
        if _is_postgres():
            op.alter_column(
                _TABLE,
                _COLUMN,
                type_=sa.String(_STRING_LENGTH),
                existing_type=existing,
                existing_nullable=False,
                postgresql_using=f"{_COLUMN}::text",
            )
        else:
            with op.batch_alter_table(_TABLE) as batch:
                batch.alter_column(
                    _COLUMN,
                    type_=sa.String(_STRING_LENGTH),
                    existing_type=existing,
                    existing_nullable=False,
                )
    if _is_postgres():
        # Nothing references the type any more. IF EXISTS keeps a database
        # that never had it (adopted from the new models) a no-op.
        op.execute(sa.text(f"DROP TYPE IF EXISTS {_ENUM_NAME}"))


def _refuse_unknown_types() -> None:
    """Abort the downgrade while a row holds a type the old enum lacks.

    Converting such a row would either fail half way (Postgres) or leave a
    value the old code cannot read (SQLite), so nothing is changed.
    """
    table = sa.table(_TABLE, sa.column(_COLUMN, sa.String()))
    rows = op.get_bind().execute(
        sa.select(table.c[_COLUMN]).where(table.c[_COLUMN].not_in(_LEGACY_LABELS)).distinct()
    )
    unknown = sorted(str(value) for (value,) in rows)
    if unknown:
        raise RuntimeError(
            "Cannot downgrade 0011_connector_type_string: connector_configs "
            f"has rows of type(s) {', '.join(unknown)}, which the old "
            f"connector_type enum ({', '.join(_LEGACY_LABELS)}) cannot hold. "
            "Delete those connectors first, then run the downgrade again."
        )


def downgrade() -> None:
    if not _is_varchar64(_column_type()):
        return
    _refuse_unknown_types()
    if _is_postgres():
        bind = op.get_bind()
        postgresql.ENUM(*_LEGACY_LABELS, name=_ENUM_NAME).create(bind, checkfirst=True)
        op.alter_column(
            _TABLE,
            _COLUMN,
            type_=postgresql.ENUM(*_LEGACY_LABELS, name=_ENUM_NAME, create_type=False),
            existing_type=sa.String(_STRING_LENGTH),
            existing_nullable=False,
            postgresql_using=f"{_COLUMN}::{_ENUM_NAME}",
        )
    else:
        with op.batch_alter_table(_TABLE) as batch:
            batch.alter_column(
                _COLUMN,
                type_=sa.Enum(*_LEGACY_LABELS, name=_ENUM_NAME),
                existing_type=sa.String(_STRING_LENGTH),
                existing_nullable=False,
            )
