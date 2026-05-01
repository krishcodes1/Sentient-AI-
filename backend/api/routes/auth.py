from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from pydantic import BaseModel, EmailStr
from sqlalchemy.ext.asyncio import AsyncSession

from core.database import get_db
from core.security import encrypt_credentials
from models.user import User
from services.auth import (
    AccountLocked,
    InvalidCredentialsError,
    InvalidRefreshTokenError,
    InvalidResetTokenError,
    WeakPasswordError,
    create_session,
    get_current_user,
    refresh_session,
    register_user as svc_register_user,
    request_password_reset as svc_request_password_reset,
    resend_verification as svc_resend_verification,
    reset_password as svc_reset_password,
    revoke_session_by_refresh_token,
    verify_email as svc_verify_email,
)
from services.auth import authenticate as svc_authenticate

router = APIRouter(prefix="/auth", tags=["auth"])


# ── Request / response schemas ────────────────────────────────────────────


class RegisterRequest(BaseModel):
    email: EmailStr
    password: str
    name: Optional[str] = None


class LoginRequest(BaseModel):
    email: EmailStr
    password: str


class RefreshRequest(BaseModel):
    refresh_token: str


class LogoutRequest(BaseModel):
    refresh_token: Optional[str] = None


class ForgotPasswordRequest(BaseModel):
    email: EmailStr


class ResetPasswordRequest(BaseModel):
    token: str
    new_password: str


class VerifyEmailRequest(BaseModel):
    token: str


class ResendVerificationRequest(BaseModel):
    email: EmailStr


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
    refresh_token: str
    token_type: str = "bearer"
    user: UserResponse


class TokenPairResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"


class UpdateSettingsRequest(BaseModel):
    name: Optional[str] = None
    llm_provider: Optional[str] = None
    llm_model: Optional[str] = None
    llm_api_key: Optional[str] = None
    onboarding_completed: Optional[bool] = None


# ── Endpoints ─────────────────────────────────────────────────────────────


@router.post(
    "/register",
    response_model=AuthResponse,
    status_code=status.HTTP_201_CREATED,
)
async def register(
    body: RegisterRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    try:
        user, _verification_token = await svc_register_user(
            email=body.email,
            password=body.password,
            db=db,
            name=body.name,
        )
    except WeakPasswordError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(exc),
        ) from exc

    issued = await create_session(user, db, request)
    return AuthResponse(
        access_token=issued.access_token,
        refresh_token=issued.refresh_token,
        user=UserResponse.model_validate(user),
    )


@router.post("/login", response_model=AuthResponse)
async def login(
    body: LoginRequest,
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_db),
):
    try:
        user = await svc_authenticate(body.email, body.password, db)
    except AccountLocked as exc:
        retry_after = max(
            1,
            int((exc.locked_until - datetime.now(timezone.utc)).total_seconds()),
        )
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Account temporarily locked due to too many failed login attempts.",
            headers={
                "Retry-After": str(retry_after),
                "X-Lockout-Until": exc.locked_until.isoformat(),
            },
        ) from exc
    except InvalidCredentialsError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password.",
        ) from exc

    issued = await create_session(user, db, request)
    return AuthResponse(
        access_token=issued.access_token,
        refresh_token=issued.refresh_token,
        user=UserResponse.model_validate(user),
    )


@router.post("/refresh", response_model=TokenPairResponse)
async def refresh(
    body: RefreshRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    try:
        issued = await refresh_session(body.refresh_token, db, request)
    except InvalidRefreshTokenError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired refresh token.",
        ) from exc

    return TokenPairResponse(
        access_token=issued.access_token,
        refresh_token=issued.refresh_token,
    )


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
async def logout(
    body: LogoutRequest | None = None,
    db: AsyncSession = Depends(get_db),
):
    """Idempotent. Revokes the session associated with the supplied refresh token.

    Note: when no refresh token is supplied the call is a no-op — clients
    using only an access token can simply discard it locally; access tokens
    are short-lived and not server-tracked.
    """
    if body is not None and body.refresh_token:
        await revoke_session_by_refresh_token(body.refresh_token, db)
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.post("/forgot-password", status_code=status.HTTP_204_NO_CONTENT)
async def forgot_password(
    body: ForgotPasswordRequest,
    db: AsyncSession = Depends(get_db),
):
    # Always 204 — never reveal whether the email exists.
    await svc_request_password_reset(body.email, db)
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.post("/reset-password", status_code=status.HTTP_204_NO_CONTENT)
async def reset_password(
    body: ResetPasswordRequest,
    db: AsyncSession = Depends(get_db),
):
    try:
        await svc_reset_password(body.token, body.new_password, db)
    except InvalidResetTokenError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Reset token invalid or expired.",
        ) from exc
    except WeakPasswordError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(exc),
        ) from exc

    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.post("/verify-email", status_code=status.HTTP_204_NO_CONTENT)
async def verify_email(
    body: VerifyEmailRequest,
    db: AsyncSession = Depends(get_db),
):
    try:
        await svc_verify_email(body.token, db)
    except InvalidResetTokenError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Verification token invalid or expired.",
        ) from exc
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.post("/resend-verification", status_code=status.HTTP_204_NO_CONTENT)
async def resend_verification(
    body: ResendVerificationRequest,
    db: AsyncSession = Depends(get_db),
):
    # Always 204 — never reveal whether the email exists or is already verified.
    await svc_resend_verification(body.email, db)
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.get("/me", response_model=UserResponse)
async def get_me(current_user: User = Depends(get_current_user)):
    return current_user


VALID_PROVIDERS = {
    "anthropic",
    "openai",
    "gemini",
    "grok",
    "deepseek",
    "groq",
    "mistral",
    "ollama",
}


@router.patch("/settings", response_model=UserResponse)
async def update_settings(
    body: UpdateSettingsRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    llm_changed = False

    if body.name is not None:
        current_user.name = body.name

    if body.llm_provider is not None:
        if body.llm_provider not in VALID_PROVIDERS:
            raise HTTPException(
                status_code=422,
                detail=(
                    f"Invalid provider. Must be one of: "
                    f"{', '.join(sorted(VALID_PROVIDERS))}"
                ),
            )
        current_user.llm_provider = body.llm_provider
        llm_changed = True

    if body.llm_model is not None:
        current_user.llm_model = body.llm_model
        llm_changed = True

    if body.llm_api_key is not None:
        current_user.llm_api_key_enc = encrypt_credentials(body.llm_api_key)
        llm_changed = True

    if body.onboarding_completed is not None:
        current_user.onboarding_completed = body.onboarding_completed

    current_user.updated_at = datetime.now(timezone.utc)
    await db.flush()
    await db.refresh(current_user)

    if llm_changed:
        try:
            from services.openclaw.config_manager import (
                sync_openclaw_config_for_user,
            )
            await sync_openclaw_config_for_user(current_user)
        except Exception:
            pass

    return current_user
