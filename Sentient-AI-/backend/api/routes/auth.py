from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Literal, Optional

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, EmailStr, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from core.database import get_db
from core.security import create_access_token, hash_password, verify_password
from core.validation import SafeStr, normalize_email
from models.user import User
from services.auth import get_current_user

# LLM providers the platform can construct. Validated at the settings
# boundary so an unknown provider fails fast with 422 instead of surfacing
# later as a 502 mid-chat.
_KNOWN_PROVIDERS = frozenset(
    {"anthropic", "openai", "gemini", "grok", "deepseek", "groq", "mistral", "ollama"}
)

router = APIRouter(prefix="/auth", tags=["auth"])

PermissionTierLiteral = Literal[
    "auto_approve", "user_confirm", "admin_only", "hard_blocked"
]


class RegisterRequest(BaseModel):
    email: EmailStr
    password: str
    name: Optional[SafeStr] = Field(default=None, max_length=255)


class LoginRequest(BaseModel):
    email: EmailStr
    password: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"


class UserResponse(BaseModel):
    id: uuid.UUID
    email: str
    name: Optional[str] = None
    is_active: bool
    default_permission_tier: str
    rate_limit: int
    llm_provider: str
    llm_model: str
    memory_enabled: bool = True
    created_at: datetime

    model_config = {"from_attributes": True}


class ProfileUpdateRequest(BaseModel):
    name: Optional[SafeStr] = Field(default=None, max_length=255)
    email: Optional[EmailStr] = None


class PasswordChangeRequest(BaseModel):
    current_password: str
    new_password: str = Field(min_length=8)


class SettingsUpdateRequest(BaseModel):
    default_permission_tier: Optional[PermissionTierLiteral] = None
    rate_limit: Optional[int] = Field(default=None, ge=10, le=600)
    llm_provider: Optional[SafeStr] = Field(default=None, max_length=32)
    llm_model: Optional[SafeStr] = Field(default=None, max_length=128)
    memory_enabled: Optional[bool] = None


@router.post(
    "/register",
    response_model=UserResponse,
    status_code=status.HTTP_201_CREATED,
)
async def register(body: RegisterRequest, db: AsyncSession = Depends(get_db)) -> User:
    """Create a new user account."""
    email = normalize_email(body.email)
    result = await db.execute(select(User).where(User.email == email))
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
        email=email,
        name=body.name,
        hashed_password=hash_password(body.password),
    )
    db.add(user)
    await db.flush()
    await db.refresh(user)
    return user


@router.post("/login", response_model=TokenResponse)
async def login(body: LoginRequest, db: AsyncSession = Depends(get_db)) -> dict:
    """Authenticate and return a JWT."""
    email = normalize_email(body.email)
    result = await db.execute(select(User).where(User.email == email))
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
    return {"access_token": token, "token_type": "bearer"}


@router.get("/me", response_model=UserResponse)
async def get_me(current_user: User = Depends(get_current_user)) -> User:
    """Return the currently authenticated user."""
    return current_user


@router.patch("/profile", response_model=UserResponse)
async def update_profile(
    body: ProfileUpdateRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> User:
    """Update the current user's name and/or email."""
    if body.email is not None:
        new_email = normalize_email(body.email)
        if new_email != current_user.email:
            existing = await db.execute(
                select(User).where(User.email == new_email)
            )
            if existing.scalar_one_or_none() is not None:
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail="Email already in use by another account",
                )
            current_user.email = new_email

    if body.name is not None:
        current_user.name = body.name

    await db.flush()
    await db.refresh(current_user)
    return current_user


@router.post("/password", status_code=status.HTTP_204_NO_CONTENT)
async def change_password(
    body: PasswordChangeRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> None:
    """Change the current user's password after verifying the old one."""
    if not verify_password(body.current_password, current_user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Current password is incorrect",
        )
    current_user.hashed_password = hash_password(body.new_password)
    await db.flush()


@router.patch("/settings", response_model=UserResponse)
async def update_settings(
    body: SettingsUpdateRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> User:
    """Update the current user's account settings.

    Field validation (tier enum, rate-limit range) is enforced by the
    Pydantic model, so anything that reaches here is already valid.
    """
    if body.default_permission_tier is not None:
        current_user.default_permission_tier = body.default_permission_tier
    if body.rate_limit is not None:
        current_user.rate_limit = body.rate_limit
    if body.llm_provider is not None:
        provider = body.llm_provider.strip().lower()
        if provider not in _KNOWN_PROVIDERS:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail=(
                    f"Unknown LLM provider '{body.llm_provider}'. Choose one of: "
                    + ", ".join(sorted(_KNOWN_PROVIDERS))
                ),
            )
        current_user.llm_provider = provider
    if body.llm_model is not None:
        current_user.llm_model = body.llm_model
    if body.memory_enabled is not None:
        current_user.memory_enabled = body.memory_enabled

    await db.flush()
    await db.refresh(current_user)
    return current_user


@router.delete("/account", status_code=status.HTTP_204_NO_CONTENT)
async def delete_account(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> None:
    """Permanently delete the current user.

    Conversations, connectors, and audit logs are removed via the
    existing ON DELETE CASCADE foreign keys.
    """
    await db.delete(current_user)
    await db.flush()
