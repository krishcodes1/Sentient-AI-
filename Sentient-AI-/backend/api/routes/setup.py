"""First-run setup: the owner account, the AI provider, Telegram, finish.

A native install has no .env to edit, so the /setup wizard writes the
same settings into the installation record instead (services.installation,
where the environment still wins). Everything here except the status
probe and the owner step needs an admin; the owner step itself works only
while the users table is empty, so it cannot be used to mint a second
admin later.

Secrets travel in one direction only. Provider keys and the bot token
arrive in request bodies and are stored encrypted; no response, log line
or error message carries them back. Errors from the outside world are
reduced to a status or an exception type, and a provider message that
happens to quote the key is scrubbed before it is returned. A secret the
environment already provides cannot be replaced here (409): the
environment always wins, so a stored copy would never be used.
"""

from __future__ import annotations

import asyncio
import re
import time
from collections import deque
from datetime import datetime, timezone
from typing import Any, Optional

import httpx
import structlog
from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from api.routes.auth import (
    RegisterRequest,
    UserResponse,
    create_account,
    lock_installation_row,
)
from core.config import PROVIDER_KEY_FIELDS, settings
from core.database import get_db
from core.security import create_access_token
from core.validation import MODEL_ID_RULES, is_valid_model_id
from models.audit import AuditStatus
from models.user import User
from services.agent import providers as llm_providers
from services.agent.providers import ProviderError
from services.audit import append_auth_event
from services.auth import get_current_user
from services.installation import UNREADABLE_KEYS_MESSAGE

logger = structlog.get_logger(__name__)

router = APIRouter(prefix="/setup", tags=["setup"])

# Suggested model ids per provider, best default first. The wizard offers
# these as choices; any id the provider accepts still works, because the
# save path runs a real completion against it before storing anything.
SUGGESTED_MODELS: dict[str, list[str]] = {
    "gemini": ["gemini-2.5-flash", "gemini-2.5-flash-lite"],
    "anthropic": ["claude-sonnet-5", "claude-haiku-4-5-20251001"],
    "openai": ["gpt-4o-mini"],
    "grok": ["grok-4.3"],
    "deepseek": ["deepseek-flash"],
    "groq": ["openai/gpt-oss-120b"],
    "mistral": ["mistral-large-latest"],
    "ollama": ["llama3.2"],
}

_PROVIDER_NAMES: tuple[str, ...] = (*PROVIDER_KEY_FIELDS, "ollama")

# BotFather tokens: numeric bot id, colon, 35-ish url-safe characters.
# [0-9] rather than \d, which also matches non-ASCII digits.
_TELEGRAM_TOKEN_RE = re.compile(r"^[0-9]{1,20}:[A-Za-z0-9_-]{30,64}$")
_ENV_MANAGED = "Provided by server configuration; remove it from .env to manage it here."
_MAX_API_KEY_LENGTH = 512
# Starlette renamed the 422 constant; the number is stable across versions.
_UNPROCESSABLE = 422

_PROVIDER_TEST_TIMEOUT_S = 30
_TELEGRAM_TIMEOUT_S = 10
_TELEGRAM_API = "https://api.telegram.org"

# ── rate limit for the calls that reach a third party ─────────────────────
#
# A test sends a real request with a real key, so an unthrottled endpoint
# would let a stolen admin session probe keys or burn credit. The save
# routes run the same test, so they count against the same bucket; one
# wizard pass (test, then save) uses two of the five.
_RATE_LIMIT = 5
_RATE_WINDOW_S = 60.0
_rate_buckets: dict[str, deque[float]] = {}


def _reset_rate_limits() -> None:
    """Forget every bucket (tests)."""
    _rate_buckets.clear()


def _check_rate_limit(kind: str, user_id: Any) -> None:
    now = time.monotonic()
    bucket = _rate_buckets.setdefault(f"{kind}:{user_id}", deque())
    while bucket and now - bucket[0] >= _RATE_WINDOW_S:
        bucket.popleft()
    if len(bucket) >= _RATE_LIMIT:
        retry_after = int(_RATE_WINDOW_S - (now - bucket[0])) + 1
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"Too many attempts. Try again in {retry_after} seconds.",
            headers={"Retry-After": str(retry_after)},
        )
    bucket.append(now)


# ── dependencies ──────────────────────────────────────────────────────────


def _installation(request: Request) -> Any:
    service = getattr(request.app.state, "installation", None)
    if service is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Setup is not available while the server is starting. Try again shortly.",
        )
    return service


async def _require_admin(current_user: User = Depends(get_current_user)) -> User:
    if not current_user.is_admin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only the owner of this install can change its setup.",
        )
    return current_user


# ── request bodies ────────────────────────────────────────────────────────
#
# Secret fields are plain `str` with no declared constraints on purpose: a
# pydantic constraint failure echoes the offending input in the 422 body,
# which for these fields is the secret. They are checked by hand below.


class ProviderChoice(BaseModel):
    provider: str = Field(max_length=32)
    model: str = Field(max_length=128)
    api_key: Optional[str] = None


class TelegramTokenBody(BaseModel):
    token: str


class CompleteBody(BaseModel):
    allow_registration: bool = False


def _validated_choice(body: ProviderChoice) -> tuple[str, str, Optional[str]]:
    provider = body.provider.strip().lower()
    if provider not in _PROVIDER_NAMES:
        raise HTTPException(
            status_code=_UNPROCESSABLE,
            detail=f"Unknown provider. Choose one of: {', '.join(sorted(_PROVIDER_NAMES))}",
        )
    model = body.model.strip()
    # Same rule auth.update_settings applies to a per-user model choice.
    if not is_valid_model_id(model):
        raise HTTPException(status_code=_UNPROCESSABLE, detail=MODEL_ID_RULES)
    api_key = (body.api_key or "").strip() or None
    if api_key is not None and (
        len(api_key) > _MAX_API_KEY_LENGTH
        or not api_key.isascii()
        or not api_key.isprintable()
        or " " in api_key
    ):
        raise HTTPException(
            status_code=_UNPROCESSABLE,
            detail="That API key is not in a recognisable format.",
        )
    return provider, model, api_key


def _validated_telegram_token(body: TelegramTokenBody) -> str:
    token = body.token.strip()
    if not _TELEGRAM_TOKEN_RE.fullmatch(token):
        raise HTTPException(
            status_code=_UNPROCESSABLE,
            detail="That does not look like a bot token. BotFather gives one like 123456:ABC-DEF…",
        )
    return token


def _env_provider_key(provider: str) -> bool:
    """Whether the environment supplies this provider's key (it then wins
    over anything stored, see services.installation)."""
    attr = PROVIDER_KEY_FIELDS.get(provider)
    return bool(attr and (getattr(settings, attr, "") or "").strip())


def _env_telegram_token() -> bool:
    return bool((getattr(settings, "TELEGRAM_BOT_TOKEN", "") or "").strip())


def _refuse_env_managed(env_provides: bool, supplied: Optional[str]) -> None:
    """A secret typed in while the environment provides one is refused:
    storing it would do nothing (the environment wins) while the wizard
    reported success, and testing it would vouch for a key the server will
    never use."""
    if env_provides and supplied:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=_ENV_MANAGED)


def _scrub(message: str, secret: Optional[str]) -> str:
    """Remove a secret a third party chose to quote back in its error."""
    if secret and len(secret) >= 4 and secret in message:
        return message.replace(secret, "[redacted]")
    return message


# ── provider test ─────────────────────────────────────────────────────────


async def _try_provider(provider: str, model: str, api_key: Optional[str]) -> dict[str, Any]:
    """One tiny no-tools completion: proves the key, the model id and the
    network path in a single round trip, without storing anything."""
    try:
        llm = llm_providers.create_provider(
            provider_name=provider,
            model=model,
            api_key=api_key or None,
            base_url=settings.OLLAMA_BASE_URL,
        )
    except (ValueError, ImportError) as exc:
        return {"ok": False, "error": _scrub(str(exc), api_key)}
    except Exception as exc:
        # A vendor client that refused to construct. Its message can quote
        # the configuration it was handed, key included, so only the type
        # is reported or logged.
        logger.warning(
            "setup_provider_init_failed", provider=provider, error_type=type(exc).__name__
        )
        return {
            "ok": False,
            "error": f"Could not initialise the {provider} provider ({type(exc).__name__}).",
        }
    try:
        resp = await asyncio.wait_for(
            llm.complete([{"role": "user", "content": "Reply with the single word OK."}]),
            timeout=_PROVIDER_TEST_TIMEOUT_S,
        )
        return {"ok": True, "reply": (resp.content or "")[:40]}
    except (ProviderError, asyncio.TimeoutError) as exc:
        message = str(exc) or f"The provider did not answer within {_PROVIDER_TEST_TIMEOUT_S} seconds."
        return {"ok": False, "error": _scrub(message, api_key)}
    except Exception as exc:
        # A vendor SDK error that escaped the provider's own translation.
        # Its message may quote the request (URL, headers), so only the
        # type is reported.
        logger.warning("setup_provider_test_failed", provider=provider, error_type=type(exc).__name__)
        return {"ok": False, "error": f"The provider call failed ({type(exc).__name__})."}
    finally:
        try:
            await llm.aclose()
        except Exception:  # closing must never turn a verdict into a 500
            logger.warning("setup_provider_close_failed", provider=provider)


async def _resolve_key(installation: Any, provider: str, supplied: Optional[str]) -> Optional[str]:
    """The key a test should use: the one just typed, else the configured one
    (environment first, then the stored one). Ollama needs none."""
    if supplied:
        return supplied
    return await installation.llm_api_key(provider)


# ── Telegram test ─────────────────────────────────────────────────────────


async def _telegram_get_me(token: str) -> dict[str, Any]:
    """Ask Telegram who the bot is. The request URL embeds the token, so no
    httpx exception text is ever passed on or logged, only its type."""
    try:
        async with httpx.AsyncClient(timeout=_TELEGRAM_TIMEOUT_S) as client:
            resp = await client.get(f"{_TELEGRAM_API}/bot{token}/getMe")
    except httpx.HTTPError as exc:
        return {"ok": False, "error": f"Could not reach Telegram ({type(exc).__name__})."}
    try:
        data = resp.json()
    except ValueError:
        data = None
    if resp.status_code == 200 and isinstance(data, dict) and data.get("ok"):
        result = data.get("result") or {}
        username = result.get("username") if isinstance(result, dict) else None
        if username:
            return {"ok": True, "bot_username": str(username)}
        return {"ok": False, "error": "Telegram answered without a bot username."}
    if resp.status_code in (401, 404):
        return {"ok": False, "error": "Telegram rejected that token."}
    return {"ok": False, "error": f"Telegram answered with HTTP {resp.status_code}."}


def _poller_running(request: Request) -> bool:
    """Whether a Telegram poller runs now.

    The routes never start or stop it themselves: saving or clearing the
    token fires the installation's change listener (main.wire_services),
    which re-applies the manager with the effective token (an environment
    token still wins) and swallows a start failure after logging its type.
    So by the time the save returns, this reflects the outcome, and a
    poller that could not start shows as not running rather than as a 500
    for a token that was in fact saved and audited."""
    manager = getattr(request.app.state, "telegram_manager", None)
    return bool(manager is not None and manager.is_running)


# ── routes ────────────────────────────────────────────────────────────────


@router.get("/status")
async def setup_status(request: Request) -> dict[str, bool]:
    """Public and cheap: the app asks this before anyone has signed in."""
    installation = _installation(request)
    has_owner = await installation.has_users()
    setup_completed = await installation.setup_completed()
    return {
        "needs_setup": not has_owner or not setup_completed,
        "has_owner": has_owner,
        "provider_configured": await installation.provider_configured(),
        "setup_completed": setup_completed,
        # Stored secrets exist that the current ENCRYPTION_KEY cannot open;
        # DELETE /setup/secrets is the way out.
        "secrets_unreadable": await installation.secrets_unreadable(),
    }


# Serializes owner creation inside this process so two browsers racing
# through step one cannot both see an empty users table.
_owner_lock = asyncio.Lock()


@router.post("/owner")
async def create_owner(body: RegisterRequest, db: AsyncSession = Depends(get_db)) -> dict[str, Any]:
    """Create the first account and sign it in. Refused (409) as soon as any
    account exists: after that, accounts come from /auth/register, which the
    owner controls."""
    async with _owner_lock:
        # The asyncio lock covers this process; the row lock covers another
        # worker or replica racing through the same step.
        await lock_installation_row(db)
        existing = (await db.execute(select(User.id).limit(1))).scalar_one_or_none()
        if existing is not None:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="This install already has an owner. Sign in instead.",
            )
        user = await create_account(
            db,
            email=body.email,
            password=body.password,
            name=body.name,
            endpoint="/api/setup/owner",
        )
        # The owner leaves this step signed in, so the chain records a
        # login exactly as /auth/login would.
        await append_auth_event(
            db,
            user_id=user.id,
            action="login",
            status=AuditStatus.approved,
            endpoint="/api/setup/owner",
        )
        # Committed before the lock is released, so the next request in the
        # queue sees this row and gets its 409.
        await db.commit()

    token = create_access_token(
        data={
            "sub": str(user.id),
            "email": user.email,
            "epoch": user.token_epoch,
            "sst": int(datetime.now(timezone.utc).timestamp()),
        }
    )
    return {
        "access_token": token,
        "token_type": "bearer",
        "user": UserResponse.model_validate(user).model_dump(mode="json"),
    }


@router.get("/providers")
async def list_providers(
    request: Request, _admin: User = Depends(_require_admin)
) -> dict[str, Any]:
    installation = _installation(request)
    stored = await installation.stored_provider_keys()
    providers = []
    for name in _PROVIDER_NAMES:
        providers.append(
            {
                "name": name,
                "key_from_env": _env_provider_key(name),
                "key_stored": name in stored,
                "models": list(SUGGESTED_MODELS.get(name, [])),
            }
        )
    provider, model = await installation.llm_defaults()
    return {"providers": providers, "current": {"provider": provider, "model": model}}


@router.post("/provider/test")
async def test_provider(
    body: ProviderChoice, request: Request, admin: User = Depends(_require_admin)
) -> dict[str, Any]:
    installation = _installation(request)
    provider, model, supplied = _validated_choice(body)
    _refuse_env_managed(_env_provider_key(provider), supplied)
    _check_rate_limit("provider", admin.id)
    key = await _resolve_key(installation, provider, supplied)
    if not key and provider != "ollama":
        return {"ok": False, "error": "Enter an API key."}
    return await _try_provider(provider, model, key)


@router.put("/provider")
async def save_provider(
    body: ProviderChoice, request: Request, admin: User = Depends(_require_admin)
) -> dict[str, bool]:
    """Test first, store only on success: a key that cannot answer one
    prompt would otherwise become the default every chat fails against."""
    installation = _installation(request)
    provider, model, supplied = _validated_choice(body)
    _refuse_env_managed(_env_provider_key(provider), supplied)
    _check_rate_limit("provider", admin.id)
    key = await _resolve_key(installation, provider, supplied)
    if not key and provider != "ollama":
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Enter an API key.")
    result = await _try_provider(provider, model, key)
    if not result["ok"]:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=result["error"])
    # Only a key typed into the request is stored; an environment key stays
    # in the environment and a previously stored one is kept as it is.
    try:
        await installation.set_llm(provider, model, supplied, actor_id=admin.id)
    except RuntimeError as exc:
        # The stored keys no longer decrypt, and saving would silently
        # replace all of them with this one; DELETE /setup/secrets is the
        # owner's explicit way out. Any other RuntimeError is a bug.
        if str(exc) != UNREADABLE_KEYS_MESSAGE:
            raise
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=UNREADABLE_KEYS_MESSAGE)
    except ValueError as exc:
        # The service's own messages never quote the input.
        raise HTTPException(status_code=_UNPROCESSABLE, detail=str(exc))
    return {"ok": True}


@router.post("/telegram/test")
async def test_telegram(
    body: TelegramTokenBody, request: Request, admin: User = Depends(_require_admin)
) -> dict[str, Any]:
    _installation(request)
    token = _validated_telegram_token(body)
    _refuse_env_managed(_env_telegram_token(), token)
    _check_rate_limit("telegram", admin.id)
    return await _telegram_get_me(token)


@router.put("/telegram")
async def save_telegram(
    body: TelegramTokenBody, request: Request, admin: User = Depends(_require_admin)
) -> dict[str, Any]:
    installation = _installation(request)
    token = _validated_telegram_token(body)
    _refuse_env_managed(_env_telegram_token(), token)
    _check_rate_limit("telegram", admin.id)
    result = await _telegram_get_me(token)
    if not result["ok"]:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=result["error"])
    # Saving fires the change listener, which (re)starts the poller.
    await installation.set_telegram_token(token, actor_id=admin.id)
    return {
        "ok": True,
        "bot_username": result["bot_username"],
        "running": _poller_running(request),
    }


@router.delete("/telegram", status_code=status.HTTP_204_NO_CONTENT)
async def clear_telegram(request: Request, admin: User = Depends(_require_admin)) -> Response:
    installation = _installation(request)
    # Clearing fires the change listener, which stops the poller.
    await installation.set_telegram_token(None, actor_id=admin.id)
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.delete("/secrets", status_code=status.HTTP_204_NO_CONTENT)
async def clear_secrets(request: Request, admin: User = Depends(_require_admin)) -> Response:
    """Discard every stored provider key and the stored bot token.

    The documented way out after ENCRYPTION_KEY was rotated or lost: the
    old blobs can no longer be read, and the service refuses to overwrite
    them implicitly. Keys in the environment are untouched, and a cleared
    bot token stops the poller through the change listener."""
    installation = _installation(request)
    await installation.clear_stored_secrets(actor_id=admin.id)
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.post("/complete")
async def complete_setup(
    body: CompleteBody, request: Request, admin: User = Depends(_require_admin)
) -> dict[str, bool]:
    installation = _installation(request)
    await installation.mark_setup_complete(
        allow_registration=body.allow_registration, actor_id=admin.id
    )
    return {"ok": True}
