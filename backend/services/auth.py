"""
Authentication service for SentientAI.

Single source of truth for register/login/refresh/logout/reset flows.
Uses the canonical User and AuthSession models, plus security utilities
from ``core.security`` (PyJWT-backed, AAD-capable AES-GCM).
"""

from __future__ import annotations

import logging
import secrets
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Optional, Tuple

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jwt import InvalidTokenError
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from core.config import settings
from core.database import get_db
from core.security import (
    create_access_token,
    create_refresh_token,
    hash_password,
    hash_token,
    verify_access_token,
    verify_password,
)
from models.auth_session import AuthSession
from models.user import User

logger = logging.getLogger(__name__)

_bearer_scheme = HTTPBearer()


# ── Exceptions ───────────────────────────────────────────────────────────────


class AuthError(Exception):
    """Base class for authentication-service errors."""


class InvalidCredentialsError(AuthError):
    """Email/password did not match an active user."""


class AccountLocked(AuthError):
    """Account is currently in a lockout window."""

    def __init__(self, locked_until: datetime) -> None:
        super().__init__(f"Account locked until {locked_until.isoformat()}")
        self.locked_until = locked_until


class WeakPasswordError(AuthError):
    """Password failed complexity requirements."""


class InvalidResetTokenError(AuthError):
    """Password-reset / verification token missing, expired, or revoked."""


class InvalidRefreshTokenError(AuthError):
    """Refresh token unknown, expired, or revoked."""


# ── Result containers ────────────────────────────────────────────────────────


@dataclass
class IssuedSession:
    user: User
    access_token: str
    refresh_token: str
    session_id: int


# ── Password complexity ──────────────────────────────────────────────────────


def _validate_password_complexity(password: str, email: str) -> None:
    """Raise :class:`WeakPasswordError` if *password* fails policy.

    Policy:
      - minimum length from settings.PASSWORD_MIN_LENGTH (default 12)
      - at least one digit
      - at least one letter
      - must NOT end with the user's email address
    """
    min_len = settings.PASSWORD_MIN_LENGTH
    if len(password) < min_len:
        raise WeakPasswordError(
            f"Password must be at least {min_len} characters."
        )
    if not any(c.isdigit() for c in password):
        raise WeakPasswordError("Password must contain at least one digit.")
    if not any(c.isalpha() for c in password):
        raise WeakPasswordError("Password must contain at least one letter.")
    if email and password.lower().endswith(email.strip().lower()):
        raise WeakPasswordError("Password must not end with your email address.")


# ── Token generation helpers ─────────────────────────────────────────────────


def _new_opaque_token() -> str:
    """Return a URL-safe, ~256-bit random token."""
    return secrets.token_urlsafe(32)


def _request_meta(request: Optional[Request]) -> tuple[Optional[str], Optional[str]]:
    if request is None:
        return None, None
    ua = request.headers.get("user-agent")
    if ua and len(ua) > 255:
        ua = ua[:255]
    ip = request.client.host if request.client else None
    return ua, ip


# ── Registration ─────────────────────────────────────────────────────────────


async def register_user(
    email: str,
    password: str,
    db: AsyncSession,
    *,
    name: Optional[str] = None,
) -> tuple[User, str]:
    """Register a new user.

    Returns ``(user, verification_token_plaintext)``. The verification token
    is a one-time secret the caller is expected to deliver out-of-band
    (email link). It is stored only as a SHA-256 hash on the user row.

    Raises :class:`HTTPException` for conflicts and :class:`WeakPasswordError`
    for password-policy failures.
    """
    email = email.strip().lower()
    _validate_password_complexity(password, email)

    existing = await db.execute(select(User).where(User.email == email))
    if existing.scalar_one_or_none() is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="A user with this email already exists.",
        )

    verification_token = _new_opaque_token()
    user = User(
        email=email,
        name=name,
        hashed_password=hash_password(password),
        verification_token_hash=hash_token(verification_token),
        verification_expires_at=datetime.now(timezone.utc) + timedelta(days=2),
    )
    db.add(user)
    await db.flush()
    await db.refresh(user)

    # TODO: send verification email out-of-band. For dev, log token at INFO.
    if settings.ENVIRONMENT == "development":
        logger.info(
            "auth.verification_token_issued user_id=%s token=%s",
            user.id,
            verification_token,
        )

    return user, verification_token


# ── Authentication / lockout ─────────────────────────────────────────────────


async def authenticate(
    email: str,
    password: str,
    db: AsyncSession,
) -> User:
    """Validate credentials, applying lockout policy.

    Raises :class:`AccountLocked` when within a lockout window, or
    :class:`InvalidCredentialsError` for any other failure (unknown email,
    bad password, deactivated account).
    """
    email = email.strip().lower()
    result = await db.execute(select(User).where(User.email == email))
    user = result.scalar_one_or_none()

    now = datetime.now(timezone.utc)

    if user is None or not user.is_active:
        raise InvalidCredentialsError("Invalid email or password.")

    # Lockout window check before password verification.
    if user.lockout_until is not None and user.lockout_until > now:
        raise AccountLocked(user.lockout_until)

    if not verify_password(password, user.hashed_password):
        user.failed_login_count = (user.failed_login_count or 0) + 1
        if user.failed_login_count >= settings.LOCKOUT_THRESHOLD:
            user.lockout_until = now + timedelta(
                minutes=settings.LOCKOUT_DURATION_MINUTES
            )
            user.failed_login_count = 0
            await db.flush()
            raise AccountLocked(user.lockout_until)
        await db.flush()
        raise InvalidCredentialsError("Invalid email or password.")

    # Successful login — reset counters.
    if user.failed_login_count or user.lockout_until is not None:
        user.failed_login_count = 0
        user.lockout_until = None
        await db.flush()

    return user


# ── Session lifecycle ────────────────────────────────────────────────────────


async def create_session(
    user: User,
    db: AsyncSession,
    request: Optional[Request] = None,
) -> IssuedSession:
    """Issue an access+refresh pair and persist an :class:`AuthSession` row.

    The refresh token is generated as an opaque random secret AND wrapped
    in a JWT (so clients can introspect ``sub``/``exp`` if useful). Only
    the SHA-256 hash of the JWT is stored.
    """
    access_token = create_access_token(
        subject=str(user.id),
        extra_claims={"email": user.email},
    )
    refresh_token = create_refresh_token(subject=str(user.id))

    ua, ip = _request_meta(request)
    expires_at = datetime.now(timezone.utc) + timedelta(
        days=settings.REFRESH_TOKEN_EXPIRE_DAYS
    )
    session = AuthSession(
        user_id=user.id,
        refresh_token_hash=hash_token(refresh_token),
        user_agent=ua,
        ip_address=ip,
        expires_at=expires_at,
    )
    db.add(session)
    await db.flush()
    await db.refresh(session)

    return IssuedSession(
        user=user,
        access_token=access_token,
        refresh_token=refresh_token,
        session_id=session.id,
    )


async def refresh_session(
    refresh_token: str,
    db: AsyncSession,
    request: Optional[Request] = None,
) -> IssuedSession:
    """Rotate a refresh token: revoke the existing session, issue a new one.

    Raises :class:`InvalidRefreshTokenError` if the token is unknown,
    revoked, expired, or fails JWT validation.
    """
    if not refresh_token:
        raise InvalidRefreshTokenError("Missing refresh token.")

    token_hash = hash_token(refresh_token)
    result = await db.execute(
        select(AuthSession).where(AuthSession.refresh_token_hash == token_hash)
    )
    session = result.scalar_one_or_none()
    now = datetime.now(timezone.utc)
    if session is None:
        raise InvalidRefreshTokenError("Refresh token not recognized.")
    if session.revoked_at is not None:
        raise InvalidRefreshTokenError("Refresh token has been revoked.")
    if session.expires_at <= now:
        raise InvalidRefreshTokenError("Refresh token has expired.")

    # JWT-level validation (signature + expiry + type).
    try:
        from core.security import verify_token  # local import to avoid cycle at module load
        verify_token(refresh_token, expected_type="refresh")
    except InvalidTokenError as exc:
        raise InvalidRefreshTokenError(str(exc)) from exc

    user = await db.get(User, session.user_id)
    if user is None or not user.is_active:
        raise InvalidRefreshTokenError("User no longer active.")

    # Rotate: revoke the old row, issue a new session.
    session.revoked_at = now
    await db.flush()

    return await create_session(user, db, request)


async def revoke_session(session_id: int, user: User, db: AsyncSession) -> None:
    """Mark a single session revoked. Idempotent."""
    result = await db.execute(
        select(AuthSession).where(
            AuthSession.id == session_id,
            AuthSession.user_id == user.id,
        )
    )
    session = result.scalar_one_or_none()
    if session is None or session.revoked_at is not None:
        return
    session.revoked_at = datetime.now(timezone.utc)
    await db.flush()


async def revoke_session_by_refresh_token(
    refresh_token: str, db: AsyncSession
) -> None:
    """Logout helper — revoke whichever session owns *refresh_token*. Idempotent."""
    if not refresh_token:
        return
    token_hash = hash_token(refresh_token)
    await db.execute(
        update(AuthSession)
        .where(
            AuthSession.refresh_token_hash == token_hash,
            AuthSession.revoked_at.is_(None),
        )
        .values(revoked_at=datetime.now(timezone.utc))
    )
    await db.flush()


async def revoke_all_sessions(user: User, db: AsyncSession) -> None:
    """Mark every session for *user* revoked. Used after password change."""
    await db.execute(
        update(AuthSession)
        .where(
            AuthSession.user_id == user.id,
            AuthSession.revoked_at.is_(None),
        )
        .values(revoked_at=datetime.now(timezone.utc))
    )
    await db.flush()


# ── Password reset / verification flows ──────────────────────────────────────


async def request_password_reset(email: str, db: AsyncSession) -> None:
    """Issue a password-reset token without revealing whether the email exists.

    Always returns ``None``. In development, logs the issued token at INFO
    level so the flow can be tested end-to-end without SMTP wiring.
    """
    if not email:
        return
    email = email.strip().lower()
    result = await db.execute(select(User).where(User.email == email))
    user = result.scalar_one_or_none()
    if user is None or not user.is_active:
        # Constant-time-ish: no DB write, no signal to caller.
        return

    token = _new_opaque_token()
    user.password_reset_token_hash = hash_token(token)
    user.password_reset_expires_at = datetime.now(timezone.utc) + timedelta(hours=1)
    await db.flush()

    # TODO: deliver token via email (SMTP wiring out of scope).
    if settings.ENVIRONMENT == "development":
        logger.info(
            "auth.password_reset_token_issued user_id=%s token=%s",
            user.id,
            token,
        )


async def reset_password(
    token: str,
    new_password: str,
    db: AsyncSession,
) -> None:
    """Consume a password-reset token, set the new password, revoke sessions.

    Raises :class:`InvalidResetTokenError` if the token is unknown or
    expired, or :class:`WeakPasswordError` if the new password fails policy.
    """
    if not token:
        raise InvalidResetTokenError("Missing reset token.")
    token_hash = hash_token(token)
    result = await db.execute(
        select(User).where(User.password_reset_token_hash == token_hash)
    )
    user = result.scalar_one_or_none()
    now = datetime.now(timezone.utc)
    if (
        user is None
        or user.password_reset_expires_at is None
        or user.password_reset_expires_at <= now
    ):
        raise InvalidResetTokenError("Reset token invalid or expired.")

    _validate_password_complexity(new_password, user.email)

    user.hashed_password = hash_password(new_password)
    user.password_reset_token_hash = None
    user.password_reset_expires_at = None
    user.failed_login_count = 0
    user.lockout_until = None
    await db.flush()

    await revoke_all_sessions(user, db)


async def verify_email(token: str, db: AsyncSession) -> None:
    """Consume an email-verification token. Idempotent: silently no-ops if
    the token has already been used.

    Raises :class:`InvalidResetTokenError` if the token is unknown or expired.
    """
    if not token:
        raise InvalidResetTokenError("Missing verification token.")
    token_hash = hash_token(token)
    result = await db.execute(
        select(User).where(User.verification_token_hash == token_hash)
    )
    user = result.scalar_one_or_none()
    now = datetime.now(timezone.utc)
    if (
        user is None
        or user.verification_expires_at is None
        or user.verification_expires_at <= now
    ):
        raise InvalidResetTokenError("Verification token invalid or expired.")

    user.email_verified_at = now
    user.verification_token_hash = None
    user.verification_expires_at = None
    await db.flush()


async def resend_verification(email: str, db: AsyncSession) -> None:
    """Issue a fresh verification token. Does not reveal whether the email
    exists or whether the user is already verified."""
    if not email:
        return
    email = email.strip().lower()
    result = await db.execute(select(User).where(User.email == email))
    user = result.scalar_one_or_none()
    if user is None or not user.is_active or user.email_verified_at is not None:
        return

    token = _new_opaque_token()
    user.verification_token_hash = hash_token(token)
    user.verification_expires_at = datetime.now(timezone.utc) + timedelta(days=2)
    await db.flush()

    if settings.ENVIRONMENT == "development":
        logger.info(
            "auth.verification_token_reissued user_id=%s token=%s",
            user.id,
            token,
        )


# ── Back-compat helpers (used by older callers / tests) ─────────────────────


async def authenticate_user(
    email: str, password: str, db: AsyncSession
) -> Optional[User]:
    """Legacy ``Optional[User]`` shim around :func:`authenticate`."""
    try:
        return await authenticate(email, password, db)
    except (InvalidCredentialsError, AccountLocked):
        return None


# ── FastAPI dependency ───────────────────────────────────────────────────────


async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(_bearer_scheme),
    db: AsyncSession = Depends(get_db),
) -> User:
    """FastAPI dependency — extract and validate the current user from a Bearer token."""
    token = credentials.credentials

    try:
        payload = verify_access_token(token)
    except InvalidTokenError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired authentication token.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    user_id_raw: str = payload.get("sub", "")
    if not user_id_raw:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token payload missing subject.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    try:
        user_id = uuid.UUID(user_id_raw)
    except (ValueError, TypeError):
        # Allow non-UUID subjects through to the equality query, which will
        # simply find nothing. Keeps the path narrow without leaking detail.
        user_id = user_id_raw  # type: ignore[assignment]

    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()

    if user is None or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found or inactive.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    return user
