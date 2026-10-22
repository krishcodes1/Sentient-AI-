"""Serves Security -> Service keys (/api/security/keys): the owner lists the
outside security services a key can be saved for, tests a key, saves one
(only after it passed its test) and removes one.

Why it exists: link reputation (Google Safe Browsing / Web Risk), the breach
monitor (Have I Been Pwned) and file reputation (VirusTotal) each send data to
a third party with the owner's own key, and nothing is sent without one
(decisions 2). This module is where a typed key is validated by hand, refused
when the environment already supplies it, rate-limited per owner and service,
proved with the service's own tester, and handed to the installation service,
which keeps it encrypted.

Secrets travel in one direction only, as in the setup wizard
(api/routes/setup.py): a key arrives in a request body and no response, log
line or error message ever carries it back. Bodies are read and checked by
hand rather than through a pydantic model, because a validation error would
echo the offending input (the key) in its 422 body. Logs name the event, the
service and whether it passed, nothing else.

Connects to: services/installation (the encrypted store and the booleans),
services/reputation/keys (the rows and the lazy testers) and the audit log
(service_key_updated, written by the installation service).
Used by: the Security page's Service keys tab; main.py mounts the router.
"""

from __future__ import annotations

import asyncio
import json
import time
from collections import deque
from typing import Any, Optional

import structlog
from fastapi import APIRouter, Depends, HTTPException, Request, Response, status

from api.routes._deps import installation_service, require_admin
from models.user import User
from services.installation import UNREADABLE_SERVICE_KEYS_MESSAGE, InstallationService
from services.reputation.keys import KeyTestResult, ServiceKeySpec, service_key_specs, spec_for

logger = structlog.get_logger(__name__)

router = APIRouter(prefix="/security/keys", tags=["security"])

# Starlette renamed the 422 constant; the number is stable across versions.
_UNPROCESSABLE = 422
# A key is at most a few dozen characters; a body this large is never one.
_MAX_BODY_BYTES = 4096
# How long a service's own key test may take before it counts as failed.
_TEST_TIMEOUT_S = 10.0

_NO_SUCH_SERVICE = "No such service."
_ENTER_A_KEY = "Enter a key."

# ── rate limit for the calls that reach a third party ─────────────────────
#
# A test sends a real request with a real key, so an unthrottled endpoint
# would let a stolen owner session probe keys or burn a quota (VirusTotal's
# public key allows 4 lookups a minute). Saving runs the same test, so both
# count against one bucket per owner and service: 5 in any 60 seconds.
_RATE_LIMIT = 5
_RATE_WINDOW_S = 60.0
_rate_buckets: dict[str, deque[float]] = {}


def _reset_rate_limits() -> None:
    """Forget every bucket (tests)."""
    _rate_buckets.clear()


def _check_rate_limit(service: str, user_id: Any) -> None:
    now = time.monotonic()
    bucket = _rate_buckets.setdefault(f"{service}:{user_id}", deque())
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


# ── request handling ──────────────────────────────────────────────────────


def _spec_or_404(name: str) -> ServiceKeySpec:
    """The service's row; 404 for any other name, which is never echoed."""
    spec = spec_for(name)
    if spec is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=_NO_SUCH_SERVICE)
    return spec


async def _typed_key(request: Request, spec: ServiceKeySpec) -> Optional[str]:
    """The key in the body's ``key`` field, stripped and checked against the
    service's format; None when the body has none (or an empty one). Every
    refusal is a fixed sentence: nothing of the body comes back."""
    raw = await request.body()
    if len(raw) > _MAX_BODY_BYTES:
        raise HTTPException(status_code=_UNPROCESSABLE, detail=spec.format_message)
    if not raw.strip():
        return None
    try:
        body = json.loads(raw)
    except ValueError:
        raise HTTPException(
            status_code=_UNPROCESSABLE, detail="The request body must be a JSON object."
        )
    if not isinstance(body, dict):
        raise HTTPException(
            status_code=_UNPROCESSABLE, detail="The request body must be a JSON object."
        )
    value = body.get("key")
    if value is None:
        return None
    if not isinstance(value, str):
        raise HTTPException(status_code=_UNPROCESSABLE, detail=spec.format_message)
    key = value.strip()
    if not key:
        return None
    if not spec.key_pattern.fullmatch(key):
        raise HTTPException(status_code=_UNPROCESSABLE, detail=spec.format_message)
    return key


def _refuse_env_managed(spec: ServiceKeySpec, key_from_env: bool) -> None:
    """A key typed in while the environment provides one is refused: the
    environment always wins, so a stored copy would never be used."""
    if key_from_env:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"{spec.label} is set in the server's .env file; change it there.",
        )


def _scrub(message: str, key: str) -> str:
    """Remove the key from a tester's sentence. Testers never quote it; this
    is the second line, as in the setup wizard."""
    if key and len(key) >= 4 and key in message:
        return message.replace(key, "[redacted]")
    return message


async def _run_test(spec: ServiceKeySpec, key: str) -> KeyTestResult:
    """The service's own key test, bounded in time. A tester that raises,
    times out or answers something else counts as failed, named by type only
    (an exception's text can quote a request, and so the key)."""
    try:
        result = await asyncio.wait_for(spec.tester(key), timeout=_TEST_TIMEOUT_S)
    except Exception as exc:
        logger.warning(
            "security_key_test_failed", service=spec.name, error_type=type(exc).__name__
        )
        return KeyTestResult(False, f"Could not check the key ({type(exc).__name__}).")
    if not isinstance(result, KeyTestResult):
        logger.warning(
            "security_key_test_failed", service=spec.name, error_type=type(result).__name__
        )
        return KeyTestResult(False, f"Could not check the key ({type(result).__name__}).")
    return KeyTestResult(bool(result.ok), _scrub(str(result.detail), key))


def _row(spec: ServiceKeySpec, state: dict[str, bool]) -> dict[str, Any]:
    return {
        "name": spec.name,
        "label": spec.label,
        "used_for": spec.used_for,
        "note": spec.note,
        "console_url": spec.console_url,
        "key_hint": spec.key_hint,
        "key_from_env": bool(state.get("key_from_env")),
        "key_stored": bool(state.get("key_stored")),
    }


async def _state(installation: InstallationService, name: str) -> dict[str, bool]:
    return (await installation.service_key_status()).get(name, {})


# ── routes ────────────────────────────────────────────────────────────────


@router.get("")
async def list_service_keys(
    request: Request, _admin: User = Depends(require_admin)
) -> dict[str, Any]:
    """Every service a key can be saved for, with booleans only: whether the
    environment provides its key and whether one is stored. Never a key."""
    installation = installation_service(request)
    status_by_name = await installation.service_key_status()
    return {
        "services": [
            _row(spec, status_by_name.get(spec.name, {})) for spec in service_key_specs()
        ],
        # The stored blob does not decrypt with the current ENCRYPTION_KEY:
        # saving or removing is refused until the owner restores the key or
        # clears the stored secrets (DELETE /api/setup/secrets).
        "secrets_unreadable": await installation.service_keys_unreadable(),
    }


@router.post("/{name}/test")
async def test_service_key(
    name: str, request: Request, admin: User = Depends(require_admin)
) -> dict[str, Any]:
    """Test a typed key, or with none the configured one (environment first,
    then stored). Nothing is stored."""
    installation = installation_service(request)
    spec = _spec_or_404(name)
    key = await _typed_key(request, spec)
    if key is not None:
        _refuse_env_managed(spec, (await _state(installation, spec.name)).get("key_from_env", False))
    else:
        key = await installation.service_key(spec.name)
    if not key:
        # Nothing to test, so nothing reaches the service and no attempt counts.
        return {"ok": False, "error": _ENTER_A_KEY}
    _check_rate_limit(spec.name, admin.id)
    result = await _run_test(spec, key)
    logger.info("security_key_tested", service=spec.name, ok=result.ok)
    if result.ok:
        return {"ok": True, "detail": result.detail}
    return {"ok": False, "error": result.detail}


@router.put("/{name}")
async def save_service_key(
    name: str, request: Request, admin: User = Depends(require_admin)
) -> dict[str, Any]:
    """Test first, store only on success: a key the service rejects would
    otherwise switch a check on that then fails on every call."""
    installation = installation_service(request)
    spec = _spec_or_404(name)
    key = await _typed_key(request, spec)
    if key is None:
        raise HTTPException(status_code=_UNPROCESSABLE, detail=_ENTER_A_KEY)
    _refuse_env_managed(spec, (await _state(installation, spec.name)).get("key_from_env", False))
    if await installation.service_keys_unreadable():
        # Saving would replace every stored service key with this one.
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT, detail=UNREADABLE_SERVICE_KEYS_MESSAGE
        )
    _check_rate_limit(spec.name, admin.id)
    result = await _run_test(spec, key)
    if not result.ok:
        logger.info("security_key_saved", service=spec.name, ok=False)
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=result.detail)
    try:
        await installation.set_service_key(spec.name, key, actor_id=admin.id)
    except RuntimeError as exc:
        # The blob stopped decrypting between the check above and the write;
        # any other RuntimeError is a bug.
        if str(exc) != UNREADABLE_SERVICE_KEYS_MESSAGE:
            raise
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT, detail=UNREADABLE_SERVICE_KEYS_MESSAGE
        )
    logger.info("security_key_saved", service=spec.name, ok=True)
    # The tester's own sentence ("Google answered: the key works."): testers
    # never quote the key (keys.py), so it is safe to hand back.
    return {
        "ok": True,
        "service": _row(spec, await _state(installation, spec.name)),
        "detail": result.detail,
    }


@router.delete("/{name}", status_code=status.HTTP_204_NO_CONTENT)
async def remove_service_key(
    name: str, request: Request, admin: User = Depends(require_admin)
) -> Response:
    """Remove the stored key. A key in the environment is untouched (and
    keeps working); the owner changes that one in .env."""
    installation = installation_service(request)
    spec = _spec_or_404(name)
    try:
        await installation.set_service_key(spec.name, None, actor_id=admin.id)
    except RuntimeError as exc:
        if str(exc) != UNREADABLE_SERVICE_KEYS_MESSAGE:
            raise
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT, detail=UNREADABLE_SERVICE_KEYS_MESSAGE
        )
    logger.info("security_key_removed", service=spec.name, ok=True)
    return Response(status_code=status.HTTP_204_NO_CONTENT)
