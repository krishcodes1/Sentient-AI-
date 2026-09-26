"""Creates the ``page_watches`` table with its status enum and its two
indexes, each guarded against already existing.

Why it exists: Page watch needs a durable row per watched page that the
sweeper can query by status and next check time; the guards let the revision
run on an adopted database that was built from the models.

Pages the assistant checks on a schedule for the user.

Guarded with inspector checks and ``if_not_exists`` for the same reason as
0003-0009: an adopted pre-Alembic database is built from model metadata
(which already contains this table) before it is stamped and upgraded.

Numbered 0011 because 0010 is taken: the browser-control spec reserves it
for the vault, and the feat/purchases branch already ships it as
``0010_vault_items``, also revising 0009. The connectors spec plans
``0010_connector_type_string`` and a Slack ``0011`` as well; those must be
renumbered to follow this revision and 0010_vault_items.

Keep ``down_revision`` at 0009 for good, even after 0010_vault_items lands.
Databases have already run this revision on top of 0009 (the owner's live
one among them). Re-parented onto 0010, it would make Alembic treat 0010 as
applied on those databases: ``upgrade head`` would do nothing, and
vault_items and installation.capability_settings would never be created.
Whichever branch merges second adds a merge revision instead, which heals a
database whichever of the two it ran first::

    revision = "0012_merge_0010_0011"
    down_revision = ("0010_vault_items", "0011_page_watches")
    # upgrade() and downgrade(): pass

test_migrations.py fails on two heads, so the merge revision cannot be
forgotten. (The alternative, re-parenting, also needs ``alembic stamp
--purge 0009_user_llm_nullable`` and then ``alembic upgrade head`` on every
database that already ran this revision; the guards make the re-run safe.)

Revision ID: 0011_page_watches
Revises: 0009_user_llm_nullable
"""

import sqlalchemy as sa
from alembic import op

revision = "0011_page_watches"
down_revision = "0009_user_llm_nullable"
branch_labels = None
depends_on = None


def _has_table(name: str) -> bool:
    return name in sa.inspect(op.get_bind()).get_table_names()


def upgrade() -> None:
    if not _has_table("page_watches"):
        op.create_table(
            "page_watches",
            sa.Column("id", sa.Uuid(), primary_key=True, nullable=False),
            sa.Column(
                "user_id",
                sa.Uuid(),
                sa.ForeignKey("users.id", ondelete="CASCADE"),
                nullable=False,
            ),
            sa.Column("url", sa.String(500), nullable=False),
            sa.Column("label", sa.String(80), nullable=False),
            sa.Column("interval_minutes", sa.Integer(), nullable=False),
            sa.Column("last_hash", sa.String(64), nullable=True),
            sa.Column("last_excerpt", sa.Text(), nullable=True),
            sa.Column("last_checked_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("next_check_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("last_changed_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column(
                "status",
                sa.Enum("active", "paused", "error", name="page_watch_status"),
                server_default="active",
                nullable=False,
            ),
            sa.Column(
                "consecutive_errors",
                sa.Integer(),
                server_default="0",
                nullable=False,
            ),
            sa.Column("last_error", sa.String(200), nullable=True),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        )
    op.create_index(
        "ix_page_watches_status_next_check_at",
        "page_watches",
        ["status", "next_check_at"],
        if_not_exists=True,
    )
    op.create_index(
        "ix_page_watches_user_id_url",
        "page_watches",
        ["user_id", "url"],
        unique=True,
        if_not_exists=True,
    )


def downgrade() -> None:
    op.drop_index(
        "ix_page_watches_user_id_url", table_name="page_watches", if_exists=True
    )
    op.drop_index(
        "ix_page_watches_status_next_check_at",
        table_name="page_watches",
        if_exists=True,
    )
    op.drop_table("page_watches")
    # Postgres keeps enum types after the table goes; SQLite has none.
    bind = op.get_bind()
    if bind.dialect.name == "postgresql":
        sa.Enum(name="page_watch_status").drop(bind, checkfirst=True)
