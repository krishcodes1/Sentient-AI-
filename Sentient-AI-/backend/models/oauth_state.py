"""Declares the ``oauth_states`` table: one row per connector sign-in flow
started through the OAuth broker (browser consent or device code).

Why it exists: the provider's redirect back to the callback carries no bearer
token, so the row is what binds that redirect to the user who started it. It
holds only the HMAC of the ``state`` value, the encrypted PKCE verifier or
device code (wiped when the flow ends), the connector draft, and the flow's
status for the Connectors page to poll.

Connects to ``services/connectors/oauth.py`` (the only writer) and
``api/routes/oauth.py``; the row cascades away with its user. Talks to no
external service.
"""

from __future__ import annotations

import enum
import uuid
from datetime import datetime, timezone
from typing import Any, Optional

from sqlalchemy import (
    JSON,
    DateTime,
    ForeignKey,
    LargeBinary,
    String,
    Uuid,
)
from sqlalchemy.orm import Mapped, mapped_column

from core.database import Base


class OAuthFlowKind(str, enum.Enum):
    """How the user signs in: browser consent page, or a device code."""

    oauth = "oauth"
    device = "device"


class OAuthFlowStatus(str, enum.Enum):
    """Lifecycle of a flow. ``exchanging`` means the callback consumed the
    state and is trading the code for tokens; it is shown as pending."""

    pending = "pending"
    exchanging = "exchanging"
    complete = "complete"
    error = "error"
    expired = "expired"


class OAuthState(Base):
    __tablename__ = "oauth_states"

    # The flow id the UI polls with. Random, and only ever answered for
    # the user who owns the row.
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
    # OAuth broker URL segment (``google``) and the connector key it
    # creates (``google_workspace``).
    provider: Mapped[str] = mapped_column(String(32), nullable=False)
    connector_type: Mapped[str] = mapped_column(String(64), nullable=False)
    kind: Mapped[str] = mapped_column(String(16), nullable=False)
    # HMAC-SHA256 hex of the ``state`` sent to the provider. Never the raw
    # value. NULL for device flows, which have no redirect. Kept after the
    # flow closes (a deliberate deviation from spec 4.3's delete; see
    # oauth._finish_flow) so a replayed callback is audited to the user.
    state_hash: Mapped[Optional[str]] = mapped_column(
        String(64),
        nullable=True,
        index=True,
        unique=True,
    )
    # AES-GCM blob of the PKCE verifier (``oauth``) or the device code
    # (``device``). Set to NULL as soon as the flow ends.
    encrypted_secret: Mapped[Optional[bytes]] = mapped_column(
        LargeBinary,
        nullable=True,
    )
    # Catalog scopes (``gmail.read``) the user asked for.
    requested_scopes: Mapped[list[str]] = mapped_column(
        JSON,
        nullable=False,
        default=list,
    )
    # Connector fields to use when the flow completes: display_name,
    # permission_tier, rate_limit_per_minute and, for a reconnect,
    # connector_id.
    draft: Mapped[dict[str, Any]] = mapped_column(
        JSON,
        nullable=False,
        default=dict,
    )
    # Device flows: user_code, verification_uri and the poll interval the
    # UI shows. Not secret (the user types the code in themselves).
    device_info: Mapped[Optional[dict[str, Any]]] = mapped_column(
        JSON,
        nullable=True,
    )
    status: Mapped[str] = mapped_column(
        String(16),
        nullable=False,
        default=OAuthFlowStatus.pending.value,
        server_default=OAuthFlowStatus.pending.value,
    )
    # A generic, user-safe reason when status is ``error``. Never a
    # provider message.
    error: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    # The connector the flow created or updated.
    connector_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        Uuid(),
        ForeignKey("connector_configs.id", ondelete="SET NULL"),
        nullable=True,
    )
    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        index=True,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )

    def __repr__(self) -> str:
        return f"<OAuthState {self.id} {self.provider} {self.status}>"
