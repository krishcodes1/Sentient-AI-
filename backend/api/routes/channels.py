"""Channel management API — CRUD for messaging channel configurations
that get synced to the OpenClaw gateway.
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from typing import Any, Optional

import httpx
import structlog
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from core.config import settings
from core.database import get_db
from core.security import decrypt_credentials, encrypt_credentials
from models.channel import Channel, ChannelType
from models.user import User
from services.auth import get_current_user
from services.openclaw.config_manager import sync_openclaw_config_for_user

logger = structlog.get_logger(__name__)

router = APIRouter(prefix="/channels", tags=["channels"])


# ── Schemas ───────────────────────────────────────────────────────────────


class ChannelConfigInput(BaseModel):
    bot_token: Optional[str] = None
    app_token: Optional[str] = None
    dm_policy: str = "pairing"
    group_policy: str = "allowlist"
    allow_from: list[str] = []
    webhook_url: Optional[str] = None


class CreateChannelRequest(BaseModel):
    channel_type: ChannelType
    display_name: str
    config: ChannelConfigInput
    is_enabled: bool = True


class UpdateChannelRequest(BaseModel):
    display_name: Optional[str] = None
    config: Optional[ChannelConfigInput] = None
    is_enabled: Optional[bool] = None


class ChannelResponse(BaseModel):
    id: uuid.UUID
    channel_type: ChannelType
    display_name: str
    is_enabled: bool
    config_meta: dict | None = None
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


class OpenClawStatusResponse(BaseModel):
    gateway_online: bool
    gateway_url: str
    channels_configured: int
    details: dict[str, Any] = {}


# ── Helpers ───────────────────────────────────────────────────────────────


def _config_to_meta(channel_type: str, config: ChannelConfigInput) -> dict:
    """Extract non-secret metadata for the response (masks tokens)."""
    meta: dict[str, Any] = {
        "dm_policy": config.dm_policy,
        "group_policy": config.group_policy,
    }
    if config.bot_token:
        meta["has_bot_token"] = True
        meta["bot_token_preview"] = config.bot_token[:8] + "..." if len(config.bot_token) > 8 else "***"
    if config.app_token:
        meta["has_app_token"] = True
    if config.allow_from:
        meta["allow_from"] = config.allow_from
    if config.webhook_url:
        meta["webhook_url"] = config.webhook_url
    return meta


def _encrypt_config(config: ChannelConfigInput) -> bytes:
    """Serialize and encrypt the full channel config."""
    raw = config.model_dump_json()
    return encrypt_credentials(raw)


def _decrypt_config(enc: bytes) -> dict:
    """Decrypt and parse a channel config blob."""
    raw = decrypt_credentials(enc)
    return json.loads(raw)


async def _get_user_channels_data(user_id: uuid.UUID, db: AsyncSession) -> list[dict[str, Any]]:
    """Load all enabled channels for a user as config dicts for OpenClaw."""
    result = await db.execute(
        select(Channel)
        .where(Channel.user_id == user_id, Channel.is_enabled.is_(True))
    )
    channels = result.scalars().all()
    data = []
    for ch in channels:
        config = {}
        if ch.config_enc:
            try:
                config = _decrypt_config(ch.config_enc)
            except Exception:
                logger.warning("channel_decrypt_failed", channel_id=str(ch.id))
        data.append({
            "channel_type": ch.channel_type.value,
            "config": config,
        })
    return data


async def _sync_config(user: User, db: AsyncSession) -> None:
    """Rebuild and write the OpenClaw config for a user."""
    try:
        channels_data = await _get_user_channels_data(user.id, db)
        await sync_openclaw_config_for_user(user, channels_data)
    except Exception as exc:
        logger.error("openclaw_config_sync_failed", error=str(exc))


# ── Endpoints ─────────────────────────────────────────────────────────────


@router.get("", response_model=list[ChannelResponse])
async def list_channels(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(Channel)
        .where(Channel.user_id == current_user.id)
        .order_by(Channel.created_at.desc())
    )
    return result.scalars().all()


@router.post("", response_model=ChannelResponse, status_code=status.HTTP_201_CREATED)
async def create_channel(
    body: CreateChannelRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    existing = await db.execute(
        select(Channel).where(
            Channel.user_id == current_user.id,
            Channel.channel_type == body.channel_type,
        )
    )
    if existing.scalar_one_or_none():
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Channel '{body.channel_type.value}' already configured. Update it instead.",
        )

    channel = Channel(
        user_id=current_user.id,
        channel_type=body.channel_type,
        display_name=body.display_name,
        is_enabled=body.is_enabled,
        config_enc=_encrypt_config(body.config),
        config_meta=_config_to_meta(body.channel_type.value, body.config),
    )
    db.add(channel)
    await db.flush()
    await db.refresh(channel)

    await _sync_config(current_user, db)

    return channel


@router.patch("/{channel_id}", response_model=ChannelResponse)
async def update_channel(
    channel_id: uuid.UUID,
    body: UpdateChannelRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(Channel).where(
            Channel.id == channel_id,
            Channel.user_id == current_user.id,
        )
    )
    channel = result.scalar_one_or_none()
    if not channel:
        raise HTTPException(status_code=404, detail="Channel not found")

    if body.display_name is not None:
        channel.display_name = body.display_name
    if body.is_enabled is not None:
        channel.is_enabled = body.is_enabled
    if body.config is not None:
        channel.config_enc = _encrypt_config(body.config)
        channel.config_meta = _config_to_meta(channel.channel_type.value, body.config)

    channel.updated_at = datetime.now(timezone.utc)
    await db.flush()
    await db.refresh(channel)

    await _sync_config(current_user, db)

    return channel


@router.delete("/{channel_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_channel(
    channel_id: uuid.UUID,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(Channel).where(
            Channel.id == channel_id,
            Channel.user_id == current_user.id,
        )
    )
    channel = result.scalar_one_or_none()
    if not channel:
        raise HTTPException(status_code=404, detail="Channel not found")

    await db.delete(channel)
    await db.flush()

    await _sync_config(current_user, db)


@router.get("/openclaw/status", response_model=OpenClawStatusResponse)
async def get_openclaw_status(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    gateway_url = settings.OPENCLAW_GATEWAY_URL
    gateway_online = False
    details: dict[str, Any] = {}

    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            resp = await client.get(f"{gateway_url}/healthz")
            gateway_online = resp.status_code == 200
            if resp.status_code == 200:
                details = resp.json() if resp.headers.get("content-type", "").startswith("application/json") else {"status": "ok"}
    except Exception as exc:
        details["error"] = str(exc)

    result = await db.execute(
        select(Channel)
        .where(Channel.user_id == current_user.id, Channel.is_enabled.is_(True))
    )
    channels_count = len(result.scalars().all())

    return OpenClawStatusResponse(
        gateway_online=gateway_online,
        gateway_url=gateway_url,
        channels_configured=channels_count,
        details=details,
    )


@router.post("/openclaw/restart", status_code=status.HTTP_200_OK)
async def restart_openclaw_sync(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Force re-sync the OpenClaw config from current user settings."""
    await _sync_config(current_user, db)
    return {"status": "config_synced"}
