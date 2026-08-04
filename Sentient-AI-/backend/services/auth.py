"""
Authentication service for SentientAI.

Uses the canonical User model from models.user and security utilities
from core.security. Single source of truth for JWT and password handling.
"""

from __future__ import annotations

import asyncio
from typing import Optional

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jose import JWTError
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from core.config import settings
from core.database import get_db
from core.security import (
    create_access_token,
    hash_password,
    verify_access_token,
    verify_password,
)
from models.user import User

_bearer_scheme = HTTPBearer()


async def register_user(email: str, password: str, db: AsyncSession) -> User:
    """Register a new user. Raises HTTPException on conflict or weak password."""
    import uuid
    from datetime import datetime, timezone

    email = email.strip().lower()

    if len(password) < 8:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Password must be at least 8 characters.",
        )

    existing = await db.execute(select(User).where(User.email == email))
    if existing.scalar_one_or_none() is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="A user with this email already exists.",
        )

    user = User(
        email=email,
        hashed_password=await asyncio.to_thread(hash_password, password),
    )
    db.add(user)
    await db.flush()
    await db.refresh(user)
    return user


async def authenticate_user(
    email: str, password: str, db: AsyncSession
) -> Optional[User]:
    """Validate credentials and return the User, or None on failure."""
    email = email.strip().lower()
    result = await db.execute(select(User).where(User.email == email))
    user = result.scalar_one_or_none()

    if user is None or not user.is_active:
        return None
    if not await asyncio.to_thread(verify_password, password, user.hashed_password):
        return None
    return user


async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(_bearer_scheme),
    db: AsyncSession = Depends(get_db),
) -> User:
    """FastAPI dependency — extract and validate the current user from a Bearer token."""
    token = credentials.credentials

    try:
        payload = verify_access_token(token)
    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired authentication token.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    import uuid

    try:
        user_id = uuid.UUID(str(payload.get("sub", "")))
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token payload missing or malformed subject.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()

    if user is None or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found or inactive.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Tokens minted before a password change carry a stale epoch and are
    # rejected — this is the revocation path. Tokens issued before the
    # claim existed count as epoch 0, matching the column's backfill.
    if int(payload.get("epoch", 0)) != (user.token_epoch or 0):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token was revoked by a password change. Log in again.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    return user
