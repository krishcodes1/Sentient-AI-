from __future__ import annotations

import asyncio
import json
import re
import uuid
from datetime import datetime, timezone
from typing import Literal, Optional

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, EmailStr, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from core.config import settings
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

# Rows fetched per query while streaming an account export. Module-level so
# tests can shrink it and actually exercise the multi-page path.
_EXPORT_BATCH_SIZE = 500

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
    if not settings.ALLOW_REGISTRATION:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Registration is disabled on this server",
        )

    email = normalize_email(body.email)
    result = await db.execute(select(User).where(User.email == email))
    if result.scalar_one_or_none() is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Email already registered",
        )

    if len(body.password) < settings.PASSWORD_MIN_LENGTH:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=(
                f"Password must be at least {settings.PASSWORD_MIN_LENGTH} characters"
            ),
        )

    user = User(
        email=email,
        name=body.name,
        # bcrypt is ~200ms of pure CPU; run it in a worker thread so the
        # event loop (and every in-flight SSE stream) keeps moving.
        hashed_password=await asyncio.to_thread(hash_password, body.password),
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

    if user is None or not await asyncio.to_thread(
        verify_password, body.password, user.hashed_password
    ):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password",
        )

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account is deactivated",
        )

    token = create_access_token(
        data={
            "sub": str(user.id),
            "email": user.email,
            "epoch": user.token_epoch,
        }
    )
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
    """Change the current user's password after verifying the old one.

    Bumps ``token_epoch`` so every previously issued JWT stops working —
    without this, a user rotating their password because a token leaked
    would get no actual eviction until the token expired on its own.
    """
    if not await asyncio.to_thread(
        verify_password, body.current_password, current_user.hashed_password
    ):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Current password is incorrect",
        )
    if len(body.new_password) < settings.PASSWORD_MIN_LENGTH:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=(
                f"Password must be at least {settings.PASSWORD_MIN_LENGTH} characters"
            ),
        )
    current_user.hashed_password = await asyncio.to_thread(
        hash_password, body.new_password
    )
    current_user.token_epoch = (current_user.token_epoch or 0) + 1
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
        model = body.llm_model.strip()
        # Model ids are provider catalog names (letters, digits, and a few
        # separators). Anything else is a typo or probe; rejecting it here
        # keeps garbage strings out of the runtime's provider cache.
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}", model):
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail=(
                    "Model name may only contain letters, digits, and ./_:-"
                ),
            )
        current_user.llm_model = model
    if body.memory_enabled is not None:
        current_user.memory_enabled = body.memory_enabled

    await db.flush()
    await db.refresh(current_user)
    return current_user


@router.get("/export")
async def export_account(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> StreamingResponse:
    """Download everything this account holds, as one JSON document.

    Streamed and fetched in batches rather than assembled in memory: an
    account's transcript and audit chain are the two tables that grow
    without bound, and a personal-data export is exactly when they are
    largest.

    Connector credentials are deliberately excluded. They are stored
    encrypted and are re-enterable secrets belonging to third parties;
    putting them in a file that lands in the user's Downloads folder would
    undo the reason they are encrypted at rest.
    """
    from models.audit import AuditLog
    from models.connector import ConnectorConfig
    from models.conversation import Conversation, Message
    from models.memory import Memory

    BATCH = _EXPORT_BATCH_SIZE

    def _json(value: object) -> str:
        return json.dumps(value, default=str)

    async def _stream_table(model, order_col, label: str, to_dict):
        """Yield one JSON array of rows, paged by primary-key order."""
        yield f'"{label}":['
        offset = 0
        first = True
        while True:
            rows = (
                (
                    await db.execute(
                        select(model)
                        .where(model.user_id == current_user.id)
                        .order_by(order_col)
                        .offset(offset)
                        .limit(BATCH)
                    )
                )
                .scalars()
                .all()
            )
            if not rows:
                break
            for row in rows:
                yield ("" if first else ",") + _json(to_dict(row))
                first = False
            offset += len(rows)
            if len(rows) < BATCH:
                break
        yield "]"

    async def _generate():
        yield "{"
        yield '"exported_at":' + _json(datetime.now(timezone.utc).isoformat()) + ","
        yield '"account":' + _json(
            {
                "id": str(current_user.id),
                "email": current_user.email,
                "name": current_user.name,
                "created_at": current_user.created_at,
                "default_permission_tier": current_user.default_permission_tier,
                "llm_provider": current_user.llm_provider,
                "llm_model": current_user.llm_model,
                "memory_enabled": current_user.memory_enabled,
            }
        ) + ","

        # Conversations with their transcripts, paged over messages so a
        # long thread never lands in memory whole.
        yield '"conversations":['
        conversations = (
            (
                await db.execute(
                    select(Conversation)
                    .where(Conversation.user_id == current_user.id)
                    .order_by(Conversation.created_at)
                )
            )
            .scalars()
            .all()
        )
        for idx, conv in enumerate(conversations):
            head = {
                "id": str(conv.id),
                "title": conv.title,
                "created_at": conv.created_at,
                "updated_at": conv.updated_at,
            }
            yield ("" if idx == 0 else ",") + _json(head)[:-1] + ',"messages":['
            offset = 0
            first_msg = True
            while True:
                messages = (
                    (
                        await db.execute(
                            select(Message)
                            .where(Message.conversation_id == conv.id)
                            .order_by(Message.created_at)
                            .offset(offset)
                            .limit(BATCH)
                        )
                    )
                    .scalars()
                    .all()
                )
                if not messages:
                    break
                for msg in messages:
                    yield ("" if first_msg else ",") + _json(
                        {
                            "role": msg.role.value,
                            "content": msg.content,
                            "tool_calls": msg.tool_calls,
                            "created_at": msg.created_at,
                        }
                    )
                    first_msg = False
                offset += len(messages)
                if len(messages) < BATCH:
                    break
            yield "]}"
        yield "],"

        async for chunk in _stream_table(
            Memory,
            Memory.created_at,
            "memories",
            lambda m: {
                "content": m.content,
                "category": m.category.value,
                "source": m.source.value,
                "created_at": m.created_at,
            },
        ):
            yield chunk
        yield ","

        async for chunk in _stream_table(
            ConnectorConfig,
            ConnectorConfig.created_at,
            "connectors",
            lambda c: {
                "display_name": c.display_name,
                "connector_type": c.connector_type.value,
                "granted_scopes": c.granted_scopes,
                "permission_tier": c.permission_tier.value,
                "is_active": c.is_active,
                "created_at": c.created_at,
                # credentials intentionally omitted — see the docstring
            },
        ):
            yield chunk
        yield ","

        async for chunk in _stream_table(
            AuditLog,
            AuditLog.timestamp,
            "audit_logs",
            lambda a: {
                "timestamp": a.timestamp,
                "connector_name": a.connector_name,
                "action": a.action,
                "endpoint": a.endpoint,
                "scope_used": a.scope_used,
                "status": a.status.value,
                "integrity_hash": a.integrity_hash,
                "previous_hash": a.previous_hash,
                "request_id": a.request_id,
            },
        ):
            yield chunk
        yield "}"

    filename = f"sentientai-export-{datetime.now(timezone.utc):%Y%m%d}.json"
    return StreamingResponse(
        _generate(),
        media_type="application/json",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


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
