from __future__ import annotations

import asyncio
import json
import uuid
from datetime import datetime, timedelta, timezone
from typing import Literal, Optional

import structlog
from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.responses import StreamingResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, EmailStr, Field
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from core.config import settings
from core.database import get_db
from core.security import (
    create_access_token,
    hash_password,
    verify_access_token,
    verify_password,
)
from core.validation import MODEL_ID_RULES, SafeStr, is_valid_model_id, normalize_email
from models.audit import AuditStatus
from models.installation import INSTALLATION_ROW_ID, Installation
from models.user import User
from services.audit import append_auth_event
from services.auth import get_current_user, login_lockout

# LLM providers the platform can construct. Validated at the settings
# boundary so an unknown provider fails fast with 422 instead of surfacing
# later as a 502 mid-chat.
_KNOWN_PROVIDERS = frozenset(
    {"anthropic", "openai", "gemini", "grok", "deepseek", "groq", "mistral", "ollama"}
)

logger = structlog.get_logger(__name__)

router = APIRouter(prefix="/auth", tags=["auth"])

# Reads the same Authorization header get_current_user does; the refresh
# handler needs the raw token to inspect the session-start claim, which the
# resolved User object does not carry.
_bearer_scheme = HTTPBearer()

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
    is_admin: bool = False
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
    # Required only when `email` changes — the address is the account's
    # recovery identity, so handing it over is as destructive as deleting
    # the account. See update_profile.
    current_password: Optional[str] = None


class PasswordChangeRequest(BaseModel):
    current_password: str
    new_password: str = Field(min_length=8)


class AccountDeleteRequest(BaseModel):
    # Optional on the model, mandatory in the handler: a missing
    # confirmation is a refusal to act, which deserves an explicit 403 with
    # a reason, not a schema-validation 422 the UI has to translate.
    current_password: Optional[str] = None


class SettingsUpdateRequest(BaseModel):
    default_permission_tier: Optional[PermissionTierLiteral] = None
    rate_limit: Optional[int] = Field(default=None, ge=10, le=600)
    llm_provider: Optional[SafeStr] = Field(default=None, max_length=32)
    llm_model: Optional[SafeStr] = Field(default=None, max_length=128)
    memory_enabled: Optional[bool] = None


async def lock_installation_row(db: AsyncSession) -> None:
    """Take the installation row with SELECT ... FOR UPDATE for the rest of
    this transaction.

    The per-process locks around account creation cannot see a second
    worker or a second replica. Holding this row makes the "is there an
    owner yet?" check and the insert that depends on it atomic across
    processes on Postgres: a concurrent creator waits here until this
    transaction commits, then sees its user. SQLite ignores FOR UPDATE
    (and serialises writers anyway), so this is a no-op in the tests.
    """
    await db.execute(
        select(Installation).where(Installation.id == INSTALLATION_ROW_ID).with_for_update()
    )


async def create_account(
    db: AsyncSession,
    *,
    email: str,
    password: str,
    name: Optional[str],
    endpoint: str,
) -> User:
    """Create a user; the first account on the install becomes the owner (admin).

    Shared by open registration and the first-run wizard's owner step, so
    the duplicate check, the password policy, the owner rule and the audit
    row cannot drift apart between the two ways an account comes to exist.
    The caller decides whether creating an account is allowed at all.
    """
    email = normalize_email(email)
    result = await db.execute(select(User).where(User.email == email))
    if result.scalar_one_or_none() is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Email already registered",
        )

    if len(password) < settings.PASSWORD_MIN_LENGTH:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=(
                f"Password must be at least {settings.PASSWORD_MIN_LENGTH} characters"
            ),
        )

    # The first account on a self-hosted install belongs to whoever deployed
    # it, so it owns the deployment. This is what makes the `admin_only`
    # connector tier mean something rather than "disabled for everyone".
    # Locked first, so two processes creating accounts at once cannot both
    # conclude they are first.
    await lock_installation_row(db)
    is_first_account = (
        await db.execute(select(User.id).limit(1))
    ).scalar_one_or_none() is None

    user = User(
        email=email,
        name=name,
        is_admin=is_first_account,
        # bcrypt is ~200ms of pure CPU; run it in a worker thread so the
        # event loop (and every in-flight SSE stream) keeps moving.
        hashed_password=await asyncio.to_thread(hash_password, password),
    )
    db.add(user)
    await db.flush()
    await db.refresh(user)
    await append_auth_event(
        db,
        user_id=user.id,
        action="account_created",
        status=AuditStatus.approved,
        endpoint=endpoint,
        reason="owner account" if is_first_account else None,
    )
    return user


@router.post(
    "/register",
    response_model=UserResponse,
    status_code=status.HTTP_201_CREATED,
)
async def register(
    body: RegisterRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
) -> User:
    """Create a new user account.

    Closed until the setup wizard is finished, with zero users too: the
    first account comes from /setup/owner, so open sign-up can never race
    the person installing the server for ownership. Once setup is complete
    the owner's stored switch decides. Without an installation service
    (unit tests that do not wire the app) the environment's
    ALLOW_REGISTRATION decides, as it did before the wizard existed.
    """
    installation = getattr(request.app.state, "installation", None)
    if installation is not None:
        if not await installation.setup_completed():
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Registration is disabled until setup is complete",
            )
        allowed = await installation.registration_allowed()
    else:
        allowed = settings.ALLOW_REGISTRATION
    if not allowed:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Registration is disabled on this server",
        )

    return await create_account(
        db,
        email=body.email,
        password=body.password,
        name=body.name,
        endpoint="/api/auth/register",
    )


async def _record_auth_event(
    db: AsyncSession,
    *,
    user: User,
    action: str,
    auth_status: AuditStatus,
    endpoint: str,
    reason: Optional[str] = None,
) -> None:
    """Chain an account event, committing it before the caller may raise.

    The failure paths below all end in an HTTPException, and the request
    session is rolled back when one propagates — so a failed-login row
    written and left uncommitted would vanish exactly when it matters.
    Committing here keeps the record of a refusal independent of the
    refusal's own control flow.
    """
    await append_auth_event(
        db,
        user_id=user.id,
        action=action,
        status=auth_status,
        endpoint=endpoint,
        reason=reason,
    )
    await db.commit()


async def _require_current_password(
    user: User,
    supplied: Optional[str],
    *,
    detail: str,
) -> None:
    """Re-authenticate before an irreversible account operation.

    A bearer token is a capability, not evidence that the person holding it
    owns the account: it outlives the browser tab, sits in local storage,
    and gets copied into curl commands and proxy logs. Operations with no
    undo — moving the account to a different address, destroying it — ask
    for the one factor a stolen token does not carry.

    403 rather than 401 on purpose: the token is valid and the session
    should survive a refused confirmation, not be torn down.
    """
    if not supplied or not await asyncio.to_thread(
        verify_password, supplied, user.hashed_password
    ):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=detail)


@router.post("/login", response_model=TokenResponse)
async def login(body: LoginRequest, db: AsyncSession = Depends(get_db)) -> dict:
    """Authenticate and return a JWT.

    Failures are counted per account (``services.auth.login_lockout``) as
    well as per IP. The per-IP limiter alone leaves the attacker in control
    of the denominator — they choose the source addresses — so the account
    itself has to carry a counter for the bound to mean anything.

    The lockout is checked before the password is verified, so a locked
    account cannot be opened even with the correct password, and the
    counter is keyed on the submitted address whether or not it resolves to
    an account, so the two cases stay indistinguishable.
    """
    email = normalize_email(body.email)
    result = await db.execute(select(User).where(User.email == email))
    user = result.scalar_one_or_none()

    locked_for = await login_lockout.seconds_remaining(email)
    if locked_for:
        if user is not None:
            await _record_auth_event(
                db,
                user=user,
                action="login_locked_out",
                auth_status=AuditStatus.blocked,
                endpoint="/api/auth/login",
                reason=f"account locked for another {locked_for}s",
            )
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=(
                "Too many failed sign-in attempts. Try again in "
                f"{locked_for} seconds."
            ),
            headers={"Retry-After": str(locked_for)},
        )

    if user is None or not await asyncio.to_thread(
        verify_password, body.password, user.hashed_password
    ):
        triggered = await login_lockout.record_failure(email)
        if user is not None:
            await _record_auth_event(
                db,
                user=user,
                action="login_locked_out" if triggered else "login_failed",
                auth_status=AuditStatus.blocked,
                endpoint="/api/auth/login",
                reason=(
                    f"locked for {triggered}s after "
                    f"{login_lockout.threshold} failed attempts"
                    if triggered
                    else "invalid password"
                ),
            )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password",
        )

    # The credentials were correct, so this is not a brute-force signal.
    await login_lockout.reset(email)

    if not user.is_active:
        await _record_auth_event(
            db,
            user=user,
            action="login_denied",
            auth_status=AuditStatus.blocked,
            endpoint="/api/auth/login",
            reason="account is deactivated",
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account is deactivated",
        )

    await append_auth_event(
        db,
        user_id=user.id,
        action="login",
        status=AuditStatus.approved,
        endpoint="/api/auth/login",
    )

    token = create_access_token(
        data={
            "sub": str(user.id),
            "email": user.email,
            "epoch": user.token_epoch,
            # When this SESSION began, as opposed to when this token was
            # issued. Refreshing carries it forward unchanged, so the
            # absolute cap is measured from the actual login.
            "sst": int(datetime.now(timezone.utc).timestamp()),
        }
    )
    return {"access_token": token, "token_type": "bearer"}


@router.post("/refresh", response_model=TokenResponse)
async def refresh_token(
    credentials: HTTPAuthorizationCredentials = Depends(_bearer_scheme),
    current_user: User = Depends(get_current_user),
) -> dict:
    """Exchange a still-valid token for one with a fresh expiry.

    Deliberately NOT a refresh-token scheme: there is no second, longer-lived
    credential to steal or store. You can only extend a session you are
    already authenticated for, which means the only thing this adds over
    re-logging-in is convenience.

    Two limits keep that bounded: the session cannot be extended past
    SESSION_MAX_HOURS from the original login, and a password change still
    invalidates the token immediately (get_current_user checks token_epoch
    before this handler runs).
    """
    payload = verify_access_token(credentials.credentials)

    session_started = payload.get("sst")
    if session_started is None:
        # Issued before sessions were tracked. Treat the token's own issue
        # time as the session start rather than granting an unbounded one.
        session_started = payload.get("iat")
    if session_started is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token cannot be refreshed. Please log in again.",
        )

    age = datetime.now(timezone.utc) - datetime.fromtimestamp(
        int(session_started), tz=timezone.utc
    )
    if age >= timedelta(hours=settings.SESSION_MAX_HOURS):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=(
                f"This session reached its {settings.SESSION_MAX_HOURS}-hour "
                "limit. Please log in again."
            ),
        )

    token = create_access_token(
        data={
            "sub": str(current_user.id),
            "email": current_user.email,
            "epoch": current_user.token_epoch,
            "sst": int(session_started),
        }
    )
    return {"access_token": token, "token_type": "bearer"}


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
async def logout(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> None:
    """End the session server-side and record that it ended.

    Two things have to happen and neither substitutes for the other.

    Revocation: a client that merely forgets its token leaves a signed
    credential valid for the rest of TOKEN_EXPIRE_MINUTES, which is the
    window a copied token is used in. Bumping ``token_epoch`` invalidates
    every outstanding JWT for the account immediately — so signing out on
    one device signs out all of them, the right default for a single-token
    scheme with no per-device sessions.

    Audit: the chain needs the bookend. Without it a reviewer can see when
    an account was signed into but never when the operator stepped away,
    which is half of any "who had access, when" question.
    """
    current_user.token_epoch = (current_user.token_epoch or 0) + 1
    await append_auth_event(
        db,
        user_id=current_user.id,
        action="logout",
        status=AuditStatus.approved,
        endpoint="/api/auth/logout",
    )
    await db.flush()


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
    """Update the current user's name and/or email.

    Changing the email requires the current password. The address is the
    account's identity and its recovery path, so a leaked token that can
    rewrite it converts temporary access into permanent ownership — the
    attacker moves the account to an address they control and the real
    owner can no longer sign in. Re-authenticating costs a legitimate user
    one field and costs a token thief everything.
    """
    if body.email is not None:
        new_email = normalize_email(body.email)
        if new_email != current_user.email:
            await _require_current_password(
                current_user,
                body.current_password,
                detail="Changing your email requires your current password",
            )
            existing = await db.execute(
                select(User).where(User.email == new_email)
            )
            if existing.scalar_one_or_none() is not None:
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail="Email already in use by another account",
                )
            previous_email = current_user.email
            current_user.email = new_email
            await append_auth_event(
                db,
                user_id=current_user.id,
                action="email_changed",
                status=AuditStatus.approved,
                endpoint="/api/auth/profile",
                reason=f"{previous_email} -> {new_email}",
            )

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
        await _record_auth_event(
            db,
            user=current_user,
            action="password_change_failed",
            auth_status=AuditStatus.blocked,
            endpoint="/api/auth/password",
            reason="current password incorrect",
        )
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
    await append_auth_event(
        db,
        user_id=current_user.id,
        action="password_changed",
        status=AuditStatus.approved,
        endpoint="/api/auth/password",
        reason="all outstanding tokens revoked",
    )
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
        # keeps garbage strings out of the runtime's provider cache and
        # path-like ids out of any provider URL they are spliced into.
        if not is_valid_model_id(model):
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail=MODEL_ID_RULES,
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

    filename = f"crawler-ai-export-{datetime.now(timezone.utc):%Y%m%d}.json"
    return StreamingResponse(
        _generate(),
        media_type="application/json",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.delete("/account", status_code=status.HTTP_204_NO_CONTENT)
async def delete_account(
    body: Optional[AccountDeleteRequest] = None,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> None:
    """Permanently delete the current user.

    Conversations, connectors, and audit logs are removed via the
    existing ON DELETE CASCADE foreign keys.

    Requires the current password. This is the single most destructive
    operation the API offers and it has no undo, so a bearer token alone is
    not enough authority to trigger it — see ``_require_current_password``.

    The last owner cannot leave (409): with no active admin left nobody
    could finish setup, change capabilities or use an admin_only
    connector, and /setup/owner stays closed while other accounts exist.
    The check runs under the installation row lock so two admins deleting
    themselves at once cannot each count the other as the one remaining.

    The refusals are audited; the deletion itself cannot be, because the
    same cascade that erases the account erases its audit chain. That is
    the correct outcome for an erasure request, so the durable record of
    the event is the application log, not a row that deletes itself.
    """
    supplied = body.current_password if body is not None else None
    if not supplied:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Deleting your account requires your current password",
        )
    if not await asyncio.to_thread(
        verify_password, supplied, current_user.hashed_password
    ):
        await _record_auth_event(
            db,
            user=current_user,
            action="account_delete_denied",
            auth_status=AuditStatus.blocked,
            endpoint="/api/auth/account",
            reason="current password incorrect",
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Deleting your account requires your current password",
        )

    if current_user.is_admin:
        await lock_installation_row(db)
        other_admins = (
            await db.execute(
                select(func.count())
                .select_from(User)
                .where(
                    User.is_admin.is_(True),
                    User.is_active.is_(True),
                    User.id != current_user.id,
                )
            )
        ).scalar_one()
        if not other_admins:
            await _record_auth_event(
                db,
                user=current_user,
                action="account_delete_denied",
                auth_status=AuditStatus.blocked,
                endpoint="/api/auth/account",
                reason="last owner account",
            )
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="Transfer ownership before deleting the last owner account",
            )

    logger.warning(
        "account_deleted",
        user_id=str(current_user.id),
        email=current_user.email,
    )
    await db.delete(current_user)
    await db.flush()
