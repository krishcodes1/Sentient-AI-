"""Serves the Slack DM channel link routes on a Slack connector: mint a one-time
link code, report the link and whether the channel runs, and unlink.

Why it exists: the Slack DM channel (services/notifications/slack.py) serves
only the Slack account that sent the code shown on the connector card, proving
control of both the Crawler session (which minted the code) and the Slack
account (which sent it). Slack user ids are never accepted from the browser.

Connects to ``models.slack_link.SlackChannelLink`` (only the code's HMAC is
stored), the connector rows (``models.connector``), and the SlackManager on
``app.state.slack_manager`` for the running state. Talks to no external service.
Every route answers 404 unless the connector is the caller's own active Slack
connector.
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime
from typing import Any, Optional

import structlog
from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from api.routes.agent import UserRateLimiter
from core.database import get_db
from core.security import decrypt_credentials
from models.connector import ConnectorConfig
from models.slack_link import SlackChannelLink
from models.user import User
from services.auth import get_current_user
from services.notifications.slack import (
    code_is_pending,
    hash_link_code,
    link_code_expiry,
    new_link_code,
)

logger = structlog.get_logger(__name__)

router = APIRouter(prefix="/connectors", tags=["slack"])

# Codes one user may mint per minute: a code is needed once per link, so a
# handful covers retries while bounding writes from a looping client.
LINK_CODES_PER_MINUTE = 5
_code_limiter = UserRateLimiter()

_NOT_FOUND = "Connector not found"


class SlackLinkCode(BaseModel):
    code: str
    expires_at: datetime


class SlackLinkStatus(BaseModel):
    linked: bool
    team_id: Optional[str] = None
    slack_user_id: Optional[str] = None
    channel_running: bool
    # Why the DM channel is not serving this connector, as a short code, or
    # None: "app_token_in_use" (another Slack connector already runs a
    # channel on the same Slack app, so this one is held back),
    # "socket_refused" (Slack's socket URL failed the WebSocket policy),
    # "auth_failed" (Slack refused a token) or "connect_failed".
    channel_error: Optional[str] = None
    pending_code_expires_at: Optional[datetime] = None
    # Whether the connector holds an app-level token (xapp-), without which
    # no link code can be minted; the connector card uses it to offer linking.
    has_app_token: bool = False


async def _owned_slack_connector(
    connector_id: uuid.UUID, user: User, db: AsyncSession
) -> ConnectorConfig:
    """The caller's own active Slack connector, else 404 (ids are not
    enumerable, and another user's connector looks exactly like none)."""
    connector = (
        await db.execute(
            select(ConnectorConfig).where(
                ConnectorConfig.id == connector_id,
                ConnectorConfig.user_id == user.id,
                ConnectorConfig.connector_type == "slack",
                ConnectorConfig.is_active.is_(True),
            )
        )
    ).scalar_one_or_none()
    if connector is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=_NOT_FOUND)
    return connector


def _has_app_token(connector: ConnectorConfig) -> bool:
    try:
        credentials: Any = json.loads(decrypt_credentials(connector.encrypted_credentials))
    except Exception as exc:
        logger.warning(
            "slack_link_credentials_unreadable",
            connector_id=str(connector.id),
            error_type=type(exc).__name__,
        )
        return False
    token = credentials.get("app_token") if isinstance(credentials, dict) else None
    return isinstance(token, str) and token.strip().startswith("xapp-")


def _channel_running(request: Request, connector_id: uuid.UUID) -> bool:
    manager = getattr(request.app.state, "slack_manager", None)
    return bool(manager is not None and manager.channel_running(str(connector_id)))


def _channel_error(request: Request, connector_id: uuid.UUID) -> Optional[str]:
    manager = getattr(request.app.state, "slack_manager", None)
    if manager is None:
        return None
    problem = manager.channel_problem(str(connector_id))
    return problem if isinstance(problem, str) else None


@router.post("/{connector_id}/slack/link", response_model=SlackLinkCode)
async def create_slack_link_code(
    connector_id: uuid.UUID,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> SlackLinkCode:
    """Mint a one-time code (10 minutes, single use) the user sends to the
    Crawler app in a Slack DM. A new code replaces any pending one; an
    existing link stays until the code is used."""
    connector = await _owned_slack_connector(connector_id, current_user, db)
    if not _has_app_token(connector):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=(
                "This Slack connector has no app-level token (xapp-...). Add one in "
                "Connectors to chat with Crawler in Slack."
            ),
        )
    if not _code_limiter.allow(str(current_user.id), LINK_CODES_PER_MINUTE):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many link codes requested. Wait a minute and try again.",
        )
    code = new_link_code()
    expires_at = link_code_expiry()
    link = await db.get(SlackChannelLink, connector.id)
    if link is None:
        link = SlackChannelLink(connector_id=connector.id, user_id=current_user.id)
        db.add(link)
    link.link_code_hash = hash_link_code(code)
    link.link_expires_at = expires_at
    await db.flush()
    # The code is a short-lived secret; SecurityHeadersMiddleware already
    # marks every API response no-store, so no browser or proxy caches it.
    return SlackLinkCode(code=code, expires_at=expires_at)


@router.get("/{connector_id}/slack/link", response_model=SlackLinkStatus)
async def get_slack_link(
    connector_id: uuid.UUID,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> SlackLinkStatus:
    connector = await _owned_slack_connector(connector_id, current_user, db)
    link = await db.get(SlackChannelLink, connector.id)
    linked = bool(link is not None and link.team_id and link.slack_user_id)
    return SlackLinkStatus(
        linked=linked,
        team_id=link.team_id if linked and link is not None else None,
        slack_user_id=link.slack_user_id if linked and link is not None else None,
        channel_running=_channel_running(request, connector.id),
        channel_error=_channel_error(request, connector.id),
        pending_code_expires_at=link.link_expires_at if code_is_pending(link) and link else None,
        has_app_token=_has_app_token(connector),
    )


@router.delete("/{connector_id}/slack/link", status_code=status.HTTP_204_NO_CONTENT)
async def delete_slack_link(
    connector_id: uuid.UUID,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> None:
    """Unlink: the channel stops serving that Slack account at once (it
    reads the link on every message) and any pending code dies."""
    connector = await _owned_slack_connector(connector_id, current_user, db)
    link = await db.get(SlackChannelLink, connector.id)
    if link is not None:
        await db.delete(link)
        await db.flush()
