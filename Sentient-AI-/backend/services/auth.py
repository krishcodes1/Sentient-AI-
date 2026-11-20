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
from core.security import verify_access_token
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

    async def begin_attempt(self, email: str) -> tuple[int, int]:
        """Check the lock and count one attempt in a single step, before the
        password is verified. Returns (seconds the account is still locked,
        else 0; lock seconds this attempt triggered, else 0). A locked
        account's attempt is refused and not counted.

        Counting only after the ~200ms bcrypt let every attempt already in
        flight pass the check, so N concurrent guesses were all verified before
        the lock engaged. Counted up front, the threshold holds however many
        arrive at once; ``reset`` clears the count when the password was right.
        """
        key = self._key(email)
        now = time.monotonic()
        duration = self.duration_seconds
        async with self._lock:
            self._purge(now)
            state = self._states.setdefault(key, _AttemptState())
            if state.locked_until > now:
                return int(state.locked_until - now) + 1, 0
            state.failures += 1
            state.expires_at = now + duration * self.DECAY_FACTOR
            if state.failures >= self.threshold:
                state.locked_until = now + duration
                state.expires_at = max(state.expires_at, state.locked_until)
                return 0, duration
            return 0, 0

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


async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(_bearer_scheme),
    db: AsyncSession = Depends(get_db, scope="function"),
) -> User:
    """FastAPI dependency: the user behind the Bearer token.

    Function scope, like the routes' own ``Depends(get_db, scope="function")``:
    FastAPI caches a dependency per scope, so a matching scope is what makes the
    route and this lookup share one session, committed before the response.
    """
    return await _user_for_token(credentials.credentials, db)


async def get_current_user_streaming(
    credentials: HTTPAuthorizationCredentials = Depends(_bearer_scheme),
    db: AsyncSession = Depends(get_db),
) -> User:
    """get_current_user on the request-scoped session, for a route that pairs it
    with a plain ``Depends(get_db)`` because its StreamingResponse keeps using the
    session after the handler returns (agent stream, account export)."""
    return await _user_for_token(credentials.credentials, db)


async def _user_for_token(token: str, db: AsyncSession) -> User:
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
