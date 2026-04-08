from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, EmailStr
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from core.database import get_db
from core.security import (
    create_access_token,
    decrypt_credentials,
    encrypt_credentials,
    hash_password,
    verify_password,
)
from models.user import User
from services.auth import get_current_user

router = APIRouter(prefix="/auth", tags=["auth"])


# ── Request / response schemas ────────────────────────────────────────────


class RegisterRequest(BaseModel):
    email: EmailStr
    password: str
    name: Optional[str] = None


class LoginRequest(BaseModel):
    email: EmailStr
    password: str


class UserResponse(BaseModel):
    id: uuid.UUID
    email: str
    name: Optional[str] = None
    is_active: bool
    llm_provider: str
    llm_model: str
    onboarding_completed: bool
    created_at: datetime

    model_config = {"from_attributes": True}


class AuthResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user: UserResponse


class UpdateSettingsRequest(BaseModel):
    name: Optional[str] = None
    llm_provider: Optional[str] = None
    llm_model: Optional[str] = None
    llm_api_key: Optional[str] = None
    onboarding_completed: Optional[bool] = None


# ── Endpoints ─────────────────────────────────────────────────────────────


@router.post("/register", response_model=AuthResponse, status_code=status.HTTP_201_CREATED)
async def register(body: RegisterRequest, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(User).where(User.email == body.email))
    if result.scalar_one_or_none() is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Email already registered",
        )

    if len(body.password) < 8:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Password must be at least 8 characters",
        )

    user = User(
        email=body.email,
        name=body.name,
        hashed_password=hash_password(body.password),
    )
    db.add(user)
    await db.flush()
    await db.refresh(user)

    token = create_access_token(data={"sub": str(user.id), "email": user.email})
    return AuthResponse(
        access_token=token,
        user=UserResponse.model_validate(user),
    )


@router.post("/login", response_model=AuthResponse)
async def login(body: LoginRequest, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(User).where(User.email == body.email))
    user = result.scalar_one_or_none()

    if user is None or not verify_password(body.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password",
        )

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account is deactivated",
        )

    token = create_access_token(data={"sub": str(user.id), "email": user.email})
    return AuthResponse(
        access_token=token,
        user=UserResponse.model_validate(user),
    )


@router.get("/me", response_model=UserResponse)
async def get_me(current_user: User = Depends(get_current_user)):
    return current_user


VALID_PROVIDERS = {"anthropic", "openai", "gemini", "grok", "deepseek", "groq", "mistral", "ollama"}


@router.patch("/settings", response_model=UserResponse)
async def update_settings(
    body: UpdateSettingsRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    if body.name is not None:
        current_user.name = body.name

    if body.llm_provider is not None:
        if body.llm_provider not in VALID_PROVIDERS:
            raise HTTPException(status_code=422, detail=f"Invalid provider. Must be one of: {', '.join(sorted(VALID_PROVIDERS))}")
        current_user.llm_provider = body.llm_provider

    if body.llm_model is not None:
        current_user.llm_model = body.llm_model

    if body.llm_api_key is not None:
        current_user.llm_api_key_enc = encrypt_credentials(body.llm_api_key)

    if body.onboarding_completed is not None:
        current_user.onboarding_completed = body.onboarding_completed

    current_user.updated_at = datetime.now(timezone.utc)
    await db.flush()
    await db.refresh(current_user)
    return current_user
