"""Serves /api/skills: the signed-in user's skills (list, create, edit, turn on
or off, delete).

Why it exists: the Skills page is the only place a skill is written; the model
can read one (skills.read) but never add, change or remove one. Each skill
belongs to its user: another user's id is a 404, as an unknown one is. Every
description and instruction text passes services/skills.screen_skill before
it is stored.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Response, status
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from core.database import get_db
from core.validation import SafeStr
from models.skill import Skill
from models.user import User
from services.auth import get_current_user
from services.skills import (
    DESCRIPTION_MAX_CHARS,
    INSTRUCTIONS_MAX_CHARS,
    MAX_SKILLS,
    NAME_MAX_CHARS,
    NAME_PATTERN,
    SkillRejected,
    screen_skill,
)

router = APIRouter(prefix="/skills", tags=["skills"])


class SkillCreate(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True)

    name: SafeStr = Field(min_length=1, max_length=NAME_MAX_CHARS, pattern=NAME_PATTERN)
    description: SafeStr = Field(min_length=1, max_length=DESCRIPTION_MAX_CHARS)
    instructions: SafeStr = Field(min_length=1, max_length=INSTRUCTIONS_MAX_CHARS)


class SkillPatch(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True)

    description: Optional[SafeStr] = Field(
        default=None, min_length=1, max_length=DESCRIPTION_MAX_CHARS
    )
    instructions: Optional[SafeStr] = Field(
        default=None, min_length=1, max_length=INSTRUCTIONS_MAX_CHARS
    )
    enabled: Optional[bool] = None


class SkillResponse(BaseModel):
    id: uuid.UUID
    name: str
    description: str
    instructions: str
    enabled: bool
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


async def _screen(description: str, instructions: str) -> None:
    try:
        await screen_skill(description, instructions)
    except SkillRejected as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)
        ) from None


async def _owned(skill_id: uuid.UUID, user: User, db: AsyncSession) -> Skill:
    skill = await db.get(Skill, skill_id)
    if skill is None or skill.user_id != user.id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Skill not found")
    return skill


@router.get("", response_model=list[SkillResponse])
async def list_skills(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db, scope="function"),
) -> list[Skill]:
    rows = await db.execute(
        select(Skill).where(Skill.user_id == current_user.id).order_by(Skill.name)
    )
    return list(rows.scalars().all())


@router.post("", response_model=SkillResponse, status_code=status.HTTP_201_CREATED)
async def create_skill(
    body: SkillCreate,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db, scope="function"),
) -> Skill:
    count = await db.scalar(
        select(func.count()).select_from(Skill).where(Skill.user_id == current_user.id)
    )
    if (count or 0) >= MAX_SKILLS:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"You have {MAX_SKILLS} skills, the most Crawler keeps. Delete one to add another.",
        )
    taken = await db.scalar(
        select(Skill.id).where(Skill.user_id == current_user.id, Skill.name == body.name)
    )
    if taken is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f'You already have a skill called "{body.name}".',
        )
    await _screen(body.description, body.instructions)
    skill = Skill(
        user_id=current_user.id,
        name=body.name,
        description=body.description,
        instructions=body.instructions,
    )
    db.add(skill)
    await db.flush()
    await db.refresh(skill)
    return skill


@router.patch("/{skill_id}", response_model=SkillResponse)
async def update_skill(
    skill_id: uuid.UUID,
    body: SkillPatch,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db, scope="function"),
) -> Skill:
    skill = await _owned(skill_id, current_user, db)
    if body.description is not None or body.instructions is not None:
        description = body.description or skill.description
        instructions = body.instructions or skill.instructions
        await _screen(description, instructions)
        skill.description, skill.instructions = description, instructions
    if body.enabled is not None:
        skill.enabled = body.enabled
    await db.flush()
    await db.refresh(skill)
    return skill


@router.delete("/{skill_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_skill(
    skill_id: uuid.UUID,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db, scope="function"),
) -> Response:
    await db.delete(await _owned(skill_id, current_user, db))
    await db.flush()
    return Response(status_code=status.HTTP_204_NO_CONTENT)
