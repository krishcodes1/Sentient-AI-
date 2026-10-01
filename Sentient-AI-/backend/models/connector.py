"""Declares the ``connector_configs`` table and its enums: connector type, auth
method and permission tier, with credentials stored as an AES-encrypted
blob.

Why it exists: The connector routes, the tool registry's tier gating and the
MCP loader all key off the same ``ConnectorType`` and ``PermissionTier``
values, so they are defined once beside the row that carries them.

``connector_type`` is a plain ``VARCHAR(64)`` (migration
``0011_connector_type_string``) so a new connector needs no schema change; the
API validates it against ``services.connectors.registry``. ``ConnectorType``
stays for existing imports and comparisons (it is a ``str`` enum, so it
compares equal to the stored string).
"""

from __future__ import annotations

import enum
import uuid
from datetime import datetime, timezone

from sqlalchemy import (
    JSON,
    Boolean,
    DateTime,
    Enum,
    ForeignKey,
    Integer,
    LargeBinary,
    String,
    Uuid,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship, validates

from core.database import Base


class ConnectorType(str, enum.Enum):
    canvas = "canvas"
    google_workspace = "google_workspace"
    robinhood = "robinhood"
    mcp = "mcp"
    custom = "custom"


# The only labels the pre-0011 ``connector_type`` Postgres ENUM held, in its
# declaration order. The 0011 downgrade recreates exactly these.
LEGACY_CONNECTOR_TYPES: tuple[str, ...] = tuple(t.value for t in ConnectorType)

CONNECTOR_TYPE_MAX_LENGTH = 64


def connector_type_key(value: str | ConnectorType) -> str:
    """The plain string form of a connector type.

    ``str(ConnectorType.canvas)`` is ``"ConnectorType.canvas"``, not
    ``"canvas"``, so formatting an enum member where a key is expected would
    silently produce a type that matches nothing. Every reader of a row's
    type goes through this (or relies on the model normalising on write).
    """
    if isinstance(value, enum.Enum):
        return str(value.value)
    return str(value)


class AuthMethod(str, enum.Enum):
    oauth2 = "oauth2"
    api_key = "api_key"
    bearer_token = "bearer_token"


class PermissionTier(str, enum.Enum):
    auto_approve = "auto_approve"
    # "Allow low-risk changes" (permission tiers, migration 0023): only the
    # actions graded LOW (services/agent/risk.py) run without a card. Eight
    # characters, so the SQLite VARCHAR(12) the baseline made still fits it.
    low_risk = "low_risk"
    user_confirm = "user_confirm"
    admin_only = "admin_only"
    hard_blocked = "hard_blocked"


class ConnectorConfig(Base):
    __tablename__ = "connector_configs"

    id: Mapped[uuid.UUID] = mapped_column(
        Uuid(),
        primary_key=True,
        default=uuid.uuid4,
    )
    user_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(),
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    # A registry key (``services.connectors.registry``) or ``mcp``/``custom``.
    # Not an ENUM: adding a connector must not need a migration. Values are
    # validated at the API boundary, and a row whose type is no longer
    # registered is listed as unavailable rather than crashing a reader.
    connector_type: Mapped[str] = mapped_column(
        String(CONNECTOR_TYPE_MAX_LENGTH),
        nullable=False,
    )
    display_name: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
    )
    is_active: Mapped[bool] = mapped_column(
        Boolean,
        default=True,
        nullable=False,
    )
    auth_method: Mapped[AuthMethod] = mapped_column(
        Enum(AuthMethod, name="auth_method"),
        nullable=False,
    )
    encrypted_credentials: Mapped[bytes] = mapped_column(
        LargeBinary,
        nullable=False,
    )
    granted_scopes: Mapped[list[str]] = mapped_column(
        JSON,
        nullable=False,
        default=list,
    )
    permission_tier: Mapped[PermissionTier] = mapped_column(
        Enum(PermissionTier, name="permission_tier"),
        nullable=False,
        default=PermissionTier.user_confirm,
    )
    rate_limit_per_minute: Mapped[int] = mapped_column(
        Integer,
        default=30,
        nullable=False,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
        nullable=False,
    )

    # Relationships
    user: Mapped["User"] = relationship(  # noqa: F821
        back_populates="connectors",
    )

    @validates("connector_type")
    def _normalise_connector_type(self, _key: str, value: str | ConnectorType) -> str:
        """Store the plain key even when a caller passes a ``ConnectorType``
        member, so a freshly added row reads back exactly like a loaded one."""
        return connector_type_key(value)

    def __repr__(self) -> str:
        return f"<ConnectorConfig {self.display_name} ({self.connector_type})>"
