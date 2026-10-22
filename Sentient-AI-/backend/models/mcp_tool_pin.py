"""Declares the ``mcp_tool_pins`` table: what each tool of a user's MCP server
said it does when it was last approved, and any newer definition waiting for
the owner's review.

Why it exists: MCP servers can change a tool's description or input schema at
any moment (a "rug pull"). services/mcp/pin_store.py (the only reader and
writer) compares every discovery against these rows; a changed or new tool is
held until the owner approves it on the Security page. Rows are per user and
per connector, die with either (ON DELETE CASCADE), and hold hashes and the
server's own public tool metadata only, never credentials. Migration
0028_mcp_tool_pins mirrors these columns exactly (tests/test_migrations.py).
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any, Optional

from sqlalchemy import JSON, DateTime, ForeignKey, Index, Integer, String, Uuid
from sqlalchemy.orm import Mapped, mapped_column

from core.database import Base


def _now() -> datetime:
    return datetime.now(timezone.utc)


class McpToolPin(Base):
    __tablename__ = "mcp_tool_pins"
    __table_args__ = (
        # One pin per remote tool per server; the name is hashed so a server
        # cannot blow the index up with a huge tool name.
        Index("uq_mcp_tool_pins_connector_name", "connector_id", "name_key", unique=True),
        # The call check: which pin does mcp.<label>.<exposed> mean?
        Index("ix_mcp_tool_pins_connector_exposed", "connector_id", "exposed_name"),
        # The Security tab and the Connectors chip: what waits for this user?
        Index("ix_mcp_tool_pins_user_status", "user_id", "status"),
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid(), primary_key=True, default=uuid.uuid4)
    user_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(), ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )
    connector_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(), ForeignKey("connector_configs.id", ondelete="CASCADE"), nullable=False
    )
    name_key: Mapped[str] = mapped_column(String(64), nullable=False)
    remote_name: Mapped[str] = mapped_column(String(512), nullable=False)
    exposed_name: Mapped[str] = mapped_column(String(64), nullable=False)
    # approved | needs_review | kept_off (and the server sentinel row).
    status: Mapped[str] = mapped_column(String(16), nullable=False)
    # changed | new; set exactly while pending_hash is set.
    review_kind: Mapped[Optional[str]] = mapped_column(String(16), nullable=True)
    # first_use | owner_test | owner_review: how approved_hash was set.
    trusted_how: Mapped[Optional[str]] = mapped_column(String(16), nullable=True)
    approved_hash: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    approved_definition: Mapped[Optional[dict[str, Any]]] = mapped_column(JSON, nullable=True)
    approved_hidden_chars: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0, server_default="0"
    )
    pending_hash: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    pending_definition: Mapped[Optional[dict[str, Any]]] = mapped_column(JSON, nullable=True)
    pending_hidden_chars: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0, server_default="0"
    )
    change_count: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0, server_default="0"
    )
    notified_hash: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    notified_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    first_seen_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_now
    )
    approved_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    changed_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    removed_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_now, onupdate=_now
    )

    def __repr__(self) -> str:
        # Never the remote name or definitions: third-party text stays out of logs.
        return f"<McpToolPin {self.status} connector={self.connector_id} tool={self.exposed_name}>"
