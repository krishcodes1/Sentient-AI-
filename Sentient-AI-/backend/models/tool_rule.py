"""Declares the tool_rules and tool_rule_builtins tables: the owner's rules on tool-call
arguments, and the owner's on/off choice for each built-in rule.

Why it exists: a rule is owner policy that is not a number, so it cannot live in the capability
settings. Only the owner creates or removes rules, or switches a built-in, from the Security page
(api/routes/security_tool_rules.py); every turn reads them through
services/security/tool_rules/store.py. Validation (name charset, glob alphabet, operators, the
regex limits, at most 50 rules, no duplicates, nothing secret-shaped) lives in
services/security/tool_rules/grammar.py rather than in constraints. A built-in with no row is on.
Migration 0031_tool_rules mirrors these columns (tests/test_migrations.py drift check).
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any, Optional

from sqlalchemy import JSON, Boolean, DateTime, ForeignKey, String, Uuid
from sqlalchemy.orm import Mapped, mapped_column

from core.database import Base


def _now() -> datetime:
    return datetime.now(timezone.utc)


class ToolRule(Base):
    __tablename__ = "tool_rules"

    id: Mapped[uuid.UUID] = mapped_column(Uuid(), primary_key=True, default=uuid.uuid4)
    name: Mapped[str] = mapped_column(String(60), nullable=False)
    tool_pattern: Mapped[str] = mapped_column(String(120), nullable=False)
    conditions: Mapped[list[dict[str, Any]]] = mapped_column(JSON, nullable=False, default=list)
    created_by: Mapped[Optional[uuid.UUID]] = mapped_column(
        Uuid(), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    # Indexed (ix_tool_rules_created_at) for the oldest-first listing.
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_now, nullable=False, index=True
    )

    def __repr__(self) -> str:
        return f"<ToolRule {self.name!r} {self.tool_pattern!r}>"


class ToolRuleBuiltin(Base):
    __tablename__ = "tool_rule_builtins"

    # untrusted_recipient | many_recipients | outside_share | untrusted_link
    key: Mapped[str] = mapped_column(String(40), primary_key=True)
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False)
    changed_by: Mapped[Optional[uuid.UUID]] = mapped_column(
        Uuid(), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    changed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_now, nullable=False
    )

    def __repr__(self) -> str:
        return f"<ToolRuleBuiltin {self.key} enabled={self.enabled}>"
