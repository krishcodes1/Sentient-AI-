"""Serves the /reminders API: create a reminder, list the scheduled (or all)
ones, and cancel one.

Why it exists: The web UI needs a way to add and cancel the rows the delivery
sweeper (services.notifications.reminders) acts on; the request model here
normalizes naive datetimes to UTC and rejects due dates more than a decade out,
so the sweeper never holds a typo.

Reminder CRUD.

Reminders are owner-scoped like every other resource here: identity comes
from the JWT and a foreign id returns 404 rather than 403, so the API never
confirms that someone else's reminder exists.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from core.database import get_db
from core.validation import SafeStr
from models.reminder import Reminder, ReminderSource, ReminderStatus
from models.user import User
from services.auth import get_current_user

router = APIRouter(prefix="/reminders", tags=["reminders"])

# A reminder more than a decade out is a typo, not an intention.
_MAX_HORIZON_DAYS = 3650


class CreateReminderRequest(BaseModel):
    title: SafeStr = Field(min_length=1, max_length=200)
    note: Optional[SafeStr] = Field(default=None, max_length=2000)
    due_at: datetime

    @field_validator("due_at")
    @classmethod
    def _sane_due_date(cls, value: datetime) -> datetime:
        # Naive datetimes are read as UTC: the API is timezone-explicit, and
        # silently treating them as server-local would drift by hours.
        if value.tzinfo is None:
            value = value.replace(tzinfo=timezone.utc)
        horizon = datetime.now(timezone.utc).timestamp() + _MAX_HORIZON_DAYS * 86400
        if value.timestamp() > horizon:
            raise ValueError("due_at is unreasonably far in the future")
        return value


class ReminderResponse(BaseModel):
    id: uuid.UUID
    title: str
    note: Optional[str] = None
    due_at: datetime
    status: ReminderStatus
    source: ReminderSource
    delivered_at: Optional[datetime] = None
    created_at: datetime

    model_config = {"from_attributes": True}


async def _get_owned_reminder(
    reminder_id: str, user: User, db: AsyncSession
) -> Reminder:
    try:
        reminder_uuid = uuid.UUID(reminder_id)
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Reminder not found"
        ) from None
    reminder = (
        await db.execute(
            select(Reminder).where(
                Reminder.id == reminder_uuid, Reminder.user_id == user.id
            )
        )
    ).scalar_one_or_none()
    if reminder is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Reminder not found"
        )
    return reminder


@router.post("/", response_model=ReminderResponse, status_code=status.HTTP_201_CREATED)
async def create_reminder(
    body: CreateReminderRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> Reminder:
    reminder = Reminder(
        user_id=current_user.id,
        title=body.title,
        note=body.note,
        due_at=body.due_at,
        source=ReminderSource.user,
    )
    db.add(reminder)
    await db.flush()
    await db.refresh(reminder)
    return reminder


@router.get("/", response_model=list[ReminderResponse])
async def list_reminders(
    include_delivered: bool = Query(default=False),
    limit: int = Query(default=100, ge=1, le=500),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> list[Reminder]:
    query = select(Reminder).where(Reminder.user_id == current_user.id)
    if not include_delivered:
        query = query.where(Reminder.status == ReminderStatus.scheduled)
    query = query.order_by(Reminder.due_at).limit(limit)
    return list((await db.execute(query)).scalars().all())


@router.delete("/{reminder_id}", status_code=status.HTTP_204_NO_CONTENT)
async def cancel_reminder(
    reminder_id: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> None:
    """Cancel a scheduled reminder. Delivered rows stay as a record."""
    reminder = await _get_owned_reminder(reminder_id, current_user, db)
    reminder.status = ReminderStatus.cancelled
    await db.flush()
