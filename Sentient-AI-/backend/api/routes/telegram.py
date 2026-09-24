"""Telegram approval-channel linking endpoints.

The bot token itself is owner configuration (TELEGRAM_BOT_TOKEN, or the
one saved in the setup wizard) and is never exposed here; these routes
only manage the per-user link between a Crawler AI account and a Telegram
chat. The poller behind them is started and stopped at runtime by the
TelegramManager, so what they report follows the owner's settings without
a restart.
"""

from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from core.database import get_db
from models.user import User
from services.auth import get_current_user

router = APIRouter(prefix="/telegram", tags=["telegram"])


class TelegramStatus(BaseModel):
    configured: bool
    linked: bool
    bot_username: Optional[str] = None


class TelegramLinkResponse(BaseModel):
    link_url: str
    bot_username: str
    expires_in_minutes: int


def _service(request: Request):
    """The running TelegramService, or None while the manager has none
    (no token, Telegram switched off, or the app never wired one)."""
    manager = getattr(request.app.state, "telegram_manager", None)
    return getattr(manager, "current", None) if manager is not None else None


@router.get("/status", response_model=TelegramStatus)
async def telegram_status(
    request: Request,
    current_user: User = Depends(get_current_user),
) -> TelegramStatus:
    service = _service(request)
    if service is None:
        return TelegramStatus(configured=False, linked=False)
    return TelegramStatus(
        configured=True,
        linked=current_user.telegram_chat_id is not None,
        bot_username=await service.bot_username(),
    )


@router.post("/link", response_model=TelegramLinkResponse)
async def create_telegram_link(
    request: Request,
    current_user: User = Depends(get_current_user),
) -> TelegramLinkResponse:
    """Mint a one-time deep link the user taps to connect their chat."""
    service = _service(request)
    if service is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=(
                "Telegram is not configured on this server. Add a bot token "
                "in Settings → Telegram (or TELEGRAM_BOT_TOKEN in backend/.env) "
                "and make sure Telegram is turned on in Settings → Permissions."
            ),
        )
    link = await service.create_link_code(str(current_user.id))
    if link is None:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="Could not reach Telegram. Check the bot token and try again.",
        )
    return TelegramLinkResponse(**link)


@router.delete("/link", status_code=status.HTTP_204_NO_CONTENT)
async def remove_telegram_link(
    request: Request,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> None:
    """Unlink this account's Telegram chat (approvals stop being pushed)."""
    current_user.telegram_chat_id = None
    current_user.telegram_link_code = None
    current_user.telegram_link_expires_at = None
    await db.flush()
