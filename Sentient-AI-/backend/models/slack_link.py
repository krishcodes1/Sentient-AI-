"""Declares the ``slack_channel_links`` table: which Slack account may chat with
Crawler through one user's Slack connector, plus the pending one-time link code.

Why it exists: the Slack DM channel runs on the tokens stored on a user's Slack
connector, and only the Slack user who proved control of the Crawler account
(by sending the one-time code shown on the connector card) may use it. Only the
HMAC of the code is stored, never the code itself.

Connects to ``services/notifications/slack.py`` (links on a correct code, reads
the link for every inbound DM and button press) and ``api/routes/slack.py``
(mints codes, reports and removes the link). The row cascades away with its
connector and its user. Talks to no external service.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Optional

from sqlalchemy import DateTime, ForeignKey, String, UniqueConstraint, Uuid
from sqlalchemy.orm import Mapped, mapped_column

from core.database import Base

# Slack team and user ids ("T0123ABCD", "U0123ABCD") are short; 32 leaves room.
SLACK_ID_MAX_LENGTH = 32


class SlackChannelLink(Base):
    __tablename__ = "slack_channel_links"
    # One Slack user links to exactly one Crawler connector. NULLs (a row
    # with only a pending code) never collide.
    __table_args__ = (
        UniqueConstraint("team_id", "slack_user_id", name="uq_slack_channel_links_team_user"),
    )

    connector_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(),
        ForeignKey("connector_configs.id", ondelete="CASCADE"),
        primary_key=True,
    )
    user_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(),
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    # The linked Slack workspace and account; NULL until a code is used.
    team_id: Mapped[Optional[str]] = mapped_column(String(SLACK_ID_MAX_LENGTH), nullable=True)
    slack_user_id: Mapped[Optional[str]] = mapped_column(String(SLACK_ID_MAX_LENGTH), nullable=True)
    # HMAC-SHA256 hex of the pending one-time code; NULL when none is pending.
    link_code_hash: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    link_expires_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    linked_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)

    @property
    def is_linked(self) -> bool:
        return bool(self.team_id and self.slack_user_id)

    def __repr__(self) -> str:
        return f"<SlackChannelLink {self.connector_id} linked={self.is_linked}>"
