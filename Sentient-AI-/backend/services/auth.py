"""Registers and authenticates users, resolves the current user from a bearer JWT,
and counts failed sign-ins per account.

Why it exists: Every protected route depends on get_current_user, and the per-
account lockout bounds brute force in a way the per-IP limiter cannot; both are
defined once so the auth routes and the dependencies agree.

Authentication service for Crawler AI.

Uses the canonical User model from models.user and security utilities
from core.security. Single source of truth for JWT and password handling.

Also owns :class:`AccountLockout`, the per-account half of the
brute-force bound. The per-IP limiter in ``api/middleware/security.py``
only constrains attempts an attacker routes through one address, and the
attacker picks the addresses; counting consecutive failures per account
constrains the one thing they cannot choose — which account they are
trying to break into.
"""

from __future__ import annotations

import asyncio
import hashlib
import time
from dataclasses import dataclass
from typing import Optional

import structlog
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

logger = structlog.get_logger(__name__)

_bearer_scheme = HTTPBearer()


# ------------------------------------------------------------------ #
# Per-account lockout
# ------------------------------------------------------------------ #


@dataclass
class _AttemptState:
    failures: int = 0
    # monotonic deadlines; 0.0 means "not set"
    locked_until: float = 0.0
    expires_at: float = 0.0


class AccountLockout:
    """Counts consecutive failed logins per account and locks it briefly.

    Keyed on the normalized email, hashed: the counter has to exist for
    addresses that do not resolve to an account too (otherwise the response
    timing and status code differ between a real and an unknown address,
    which is an enumeration oracle), and hashing keeps a list of attempted
    addresses from accumulating in memory or in a log dump.

    State is process-local. The check runs on every login attempt, and
    putting a network round trip on that path means deciding what happens
    when it fails — failing open restores exactly the bypass this closes,
    and failing closed turns a Redis blip into a total login outage. A
    multi-worker deployment therefore allows up to threshold x workers
    consecutive failures before the lock engages: still a hard ceiling,
    unlike the per-IP limit, which an attacker can widen at will by
    changing source address. The durable form of this is a ``locked_until``
    column on ``users``, which needs a migration.
    """

    # Counters for an account that stops failing decay after this multiple
    # of the lockout window, so one typo a week never accumulates into a
    # lock and abandoned entries do not grow without bound.
    DECAY_FACTOR = 2

    def __init__(
        self,
        threshold: Optional[int] = None,
        duration_minutes: Optional[int] = None,
    ) -> None:
        self._threshold = threshold
        self._duration_minutes = duration_minutes
        self._states: dict[str, _AttemptState] = {}
        self._lock = asyncio.Lock()

    @property
    def threshold(self) -> int:
        if self._threshold is not None:
            return self._threshold
        return settings.LOCKOUT_THRESHOLD

    @property
    def duration_seconds(self) -> int:
        minutes = (
            self._duration_minutes
            if self._duration_minutes is not None
            else settings.LOCKOUT_DURATION_MINUTES
        )
        return minutes * 60

    @staticmethod
    def _key(email: str) -> str:
        return hashlib.sha256(
            b"sentientai.login.lockout.v1:" + email.strip().lower().encode("utf-8")
        ).hexdigest()

    def _purge(self, now: float) -> None:
        for key in [k for k, s in self._states.items() if s.expires_at <= now]:
            del self._states[key]

    async def seconds_remaining(self, email: str) -> int:
        """Seconds this account stays locked, or 0 when it is not locked."""
        key = self._key(email)
        now = time.monotonic()
        async with self._lock:
            self._purge(now)
            state = self._states.get(key)
            if state is None or state.locked_until <= now:
                return 0
            return int(state.locked_until - now) + 1

    async def record_failure(self, email: str) -> int:
        """Count one failed attempt. Returns the lock duration it triggered.

        Zero means the account is still under the threshold.
        """
        key = self._key(email)
        now = time.monotonic()
        duration = self.duration_seconds
        async with self._lock:
            self._purge(now)
            state = self._states.setdefault(key, _AttemptState())
            state.failures += 1
            state.expires_at = now + duration * self.DECAY_FACTOR
            if state.failures >= self.threshold:
                state.locked_until = now + duration
                state.expires_at = max(state.expires_at, state.locked_until)
                return duration
            return 0

    async def reset(self, email: str) -> None:
        """Clear the counter after a successful authentication."""
        key = self._key(email)
        async with self._lock:
            self._states.pop(key, None)

    async def clear(self) -> None:
        """Drop all tracked state (used by tests to isolate cases)."""
        async with self._lock:
            self._states.clear()


# Module-level so every worker's login handler shares one counter and
# tests can reach in to reset it.
login_lockout = AccountLockout()


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
            detail="Session was signed out or the password changed. Log in again.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    return user
