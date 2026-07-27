"""Memory CRUD API.

Owner-scoped, JWT-only identity (like every other route). Content is
injection-screened on write because saved memories are replayed into the
agent's system prompt on every future turn.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Response, status
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from core.database import get_db
from core.validation import SafeStr
from models.memory import Memory, MemoryCategory, MemorySource
from models.user import User
from services.auth import get_current_user
from services.memory import MemoryRejected, screen_memory_content

router = APIRouter(prefix="/memories", tags=["memory"])


class MemoryCreateRequest(BaseModel):
    content: SafeStr = Field(min_length=1, max_length=500)
    category: MemoryCategory = MemoryCategory.fact


class MemoryUpdateRequest(BaseModel):
    content: Optional[SafeStr] = Field(default=None, max_length=500)
    category: Optional[MemoryCategory] = None


class MemoryResponse(BaseModel):
    id: uuid.UUID
    content: str
    category: MemoryCategory
    source: MemorySource
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


async def _get_owned_memory(
    memory_id: uuid.UUID, user: User, db: AsyncSession
) -> Memory:
    result = await db.execute(select(Memory).where(Memory.id == memory_id))
    memory = result.scalar_one_or_none()
    if memory is None or memory.user_id != user.id:
        # 404 (not 403) so ids are not enumerable.
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Memory not found"
        )
    return memory


@router.get("/", response_model=list[MemoryResponse])
async def list_memories(
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> list[Memory]:
    """List the authenticated user's saved memories, newest first."""
    result = await db.execute(
        select(Memory)
        .where(Memory.user_id == current_user.id)
        .order_by(Memory.created_at.desc())
        .offset(offset)
        .limit(limit)
    )
    return list(result.scalars().all())


@router.post("/", response_model=MemoryResponse, status_code=status.HTTP_201_CREATED)
async def create_memory(
    body: MemoryCreateRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> Memory:
    """Save a new memory. Content is injection-screened before storage."""
    try:
        content = screen_memory_content(body.content)
    except MemoryRejected as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)
        ) from None

    memory = Memory(
        user_id=current_user.id,
        content=content,
        category=body.category,
        source=MemorySource.user,
    )
    db.add(memory)
    await db.flush()
    await db.refresh(memory)
    return memory


@router.patch("/{memory_id}", response_model=MemoryResponse)
async def update_memory(
    memory_id: uuid.UUID,
    body: MemoryUpdateRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> Memory:
    """Edit a memory's content and/or category (owner-scoped)."""
    memory = await _get_owned_memory(memory_id, current_user, db)
    if body.content is not None:
        try:
            memory.content = screen_memory_content(body.content)
        except MemoryRejected as exc:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)
            ) from None
    if body.category is not None:
        memory.category = body.category
    await db.flush()
    await db.refresh(memory)
    return memory


@router.delete("/{memory_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_memory(
    memory_id: uuid.UUID,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> Response:
    """Delete one of the authenticated user's memories."""
    memory = await _get_owned_memory(memory_id, current_user, db)
    await db.delete(memory)
    await db.flush()
    return Response(status_code=status.HTTP_204_NO_CONTENT)
