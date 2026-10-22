"""Serves Security -> Breach monitor (/api/security/breach) and the
in-browser password check's range proxy (/api/security/pwned-passwords/
range): the owner's watched addresses and the breaches found for them,
adding, pausing and removing an address, Check now, acknowledging findings,
and the keyless Pwned Passwords range for a 5-character hash prefix.

Why it exists: the breach monitor watches the owners' addresses with the
owner's own key, so its routes are owner-only, and every row they touch is
looked up by the signed-in owner's id (another owner's id answers 404, the
same as one that does not exist). The range proxy lets any signed-in person
check a password in their own browser (k-anonymity: only a 5-character
prefix of its SHA-1 leaves the browser, and nothing about the check is kept:
no cache, no audit row, and no log line with the prefix or the number of
entries, review SEC-F13). It is gated by the owner's breach-monitor switch
(the owner's setting, not the key-gated effective state, so it works
without a Have I Been Pwned key) and limited per user, so it is never an
open relay. Body fields are read and checked by hand, so a 422 never echoes
an address or a prefix, and no answer ever carries the HIBP key or any key
field.

Connects to: services/notifications/breach_monitor.py
(``app.state.breach_monitor``: its store, Check now and the audit writer),
services/breach (addresses, store, pwned_passwords),
services/installation.py (the capability report).
Used by: the Security page's Breach monitor tab; main.py mounts the router.
"""

from __future__ import annotations

import json
import uuid
from typing import Any, Optional

import structlog
from fastapi import APIRouter, Depends, HTTPException, Request, Response, status

from api.routes._deps import installation_service, require_admin
from models.user import User
from services.auth import get_current_user
from services.breach.addresses import MAX_ADDED_PER_OWNER, REJECTED_MESSAGE, AddressRejected
from services.breach.messages import failure_sentence
from services.breach.pwned_passwords import UNAVAILABLE_MESSAGE as RANGE_UNAVAILABLE
from services.breach.pwned_passwords import (
    PwnedPasswordsUnavailable,
    RangeRateLimiter,
    fetch_range,
    range_answer,
    valid_prefix,
)
from services.breach.store import (
    CHECK_EVERY,
    FINDING_NOT_FOUND_MESSAGE,
    NOT_FOUND_MESSAGE,
    Conflict,
    LimitReached,
    NotFound,
)
from services.installation import InstallationService
from services.notifications.breach_monitor import (
    BreachMonitorService,
    BreachUnavailable,
    CheckTooSoon,
)

logger = structlog.get_logger(__name__)

router = APIRouter(prefix="/security", tags=["security"])

CAPABILITY = "breach_monitor"
# Starlette renamed the 422 constant; the number is stable across versions.
_UNPROCESSABLE = 422
# An address is at most 254 characters and a prefix 5: a body this large is never one.
_MAX_BODY_BYTES = 2048

STARTING = "The server is still starting. Try again shortly."
BODY_NOT_JSON = "The request body must be a JSON object."
PAUSED_NOT_BOOL = "Send paused as true or false."
PREFIX_REFUSED = "Send the first 5 characters of the password's SHA-1 fingerprint (0-9, A-F)."
SWITCHED_OFF = "The owner turned off breach checks in Settings → Permissions."
REPORT_UNREADABLE = "Breach checks are unavailable right now."
ATTRIBUTION = {"text": "Breach data: Have I Been Pwned", "url": "https://haveibeenpwned.com"}

# The password proxy's per-user limit (20 a minute, sliding window). In memory:
# one process per install, like the key routes' limit.
_range_limiter = RangeRateLimiter()


def _reset_rate_limits() -> None:
    """Forget every bucket (tests)."""
    _range_limiter.reset()


def breach_service(request: Request) -> BreachMonitorService:
    """The BreachMonitorService main.py hangs on app.state; 503 until it exists."""
    service = getattr(request.app.state, "breach_monitor", None)
    if service is None:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=STARTING)
    return service


def _row_id(value: str, missing: str) -> uuid.UUID:
    """A path id as a UUID; anything else is the same 404 as an id that is not this owner's
    (the value is never echoed)."""
    try:
        return uuid.UUID(value)
    except (ValueError, AttributeError, TypeError):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=missing) from None


async def _capped_body(request: Request, refusal: str) -> bytes:
    """The raw body, refused (422 with *refusal*) as soon as it passes _MAX_BODY_BYTES: a
    declared length over the cap is refused before anything is read, and a streamed one
    is never held whole in memory."""
    declared = request.headers.get("content-length", "").strip()
    # The length check first: int() refuses a number past 4,300 digits (ValueError).
    if declared.isascii() and declared.isdigit():
        if len(declared) > 12 or int(declared) > _MAX_BODY_BYTES:
            raise HTTPException(status_code=_UNPROCESSABLE, detail=refusal)
    raw = bytearray()
    async for chunk in request.stream():
        raw += chunk
        if len(raw) > _MAX_BODY_BYTES:
            raise HTTPException(status_code=_UNPROCESSABLE, detail=refusal)
    return bytes(raw)


async def _body(request: Request, refusal: str) -> dict[str, Any]:
    """The request body as a JSON object, or 422 with *refusal* (too large) or the fixed
    JSON sentence. Nothing of the body comes back in any answer."""
    raw = await _capped_body(request, refusal)
    try:
        body = json.loads(raw) if raw.strip() else None
    except (ValueError, RecursionError):
        raise HTTPException(status_code=_UNPROCESSABLE, detail=BODY_NOT_JSON) from None
    if not isinstance(body, dict):
        raise HTTPException(status_code=_UNPROCESSABLE, detail=BODY_NOT_JSON)
    return body


async def _monitor_status(installation: InstallationService) -> Any:
    """The breach_monitor row of the owner's capability report; None when it cannot be read
    (every caller then fails closed)."""
    try:
        return (await installation.capability_statuses()).get(CAPABILITY)
    except Exception as exc:
        logger.warning("breach_report_unreadable", error_type=type(exc).__name__)
        return None


# ---------------------------------------------------------------------------
# The owner's breach monitor
# ---------------------------------------------------------------------------


@router.get("/breach")
async def breach_overview(
    admin: User = Depends(require_admin),
    installation: InstallationService = Depends(installation_service),
    service: BreachMonitorService = Depends(breach_service),
) -> dict[str, Any]:
    """The monitor's state (the report's), the owner's watched addresses and the breaches
    found for them. Makes sure the owner's sign-in address is watched first: a database
    write only, nothing is sent anywhere."""
    capability = await _monitor_status(installation)
    if capability is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=REPORT_UNREADABLE
        )
    account_note = await service.store.ensure_account_row(admin.id)
    view = await service.store.overview(admin.id)
    state = capability.effective if capability.effective in ("on", "off", "blocked") else "off"
    if state != "on":
        # Nothing is looked up while checks are off or have no key, so no failure sentence
        # may promise that "Crawler tries again" (the rate-limited one has it built in).
        for row in view["addresses"]:
            if row.get("readable") and row.get("last_error_code"):
                row["last_error"] = failure_sentence(row["last_error_code"], retrying=False)
    return {
        "state": state,
        "reason": "" if state == "on" else str(capability.reason or ""),
        "switch_on": capability.enabled is True,
        "key_configured": capability.available is True,
        "check_every_days": CHECK_EVERY.days,
        "max_addresses": MAX_ADDED_PER_OWNER,
        "account_note": account_note,
        "addresses": view["addresses"],
        "findings": view["findings"],
        "attribution": dict(ATTRIBUTION),
    }


@router.post("/breach/addresses", status_code=status.HTTP_201_CREATED)
async def add_breach_address(
    request: Request,
    admin: User = Depends(require_admin),
    service: BreachMonitorService = Depends(breach_service),
) -> dict[str, Any]:
    """Watch one more address (at most 10 typed ones). Stored due at once; the tab then
    presses Check now itself, and without a key the row waits for the first sweep."""
    body = await _body(request, REJECTED_MESSAGE)
    address = body.get("address")
    if not isinstance(address, str):
        raise HTTPException(status_code=_UNPROCESSABLE, detail=REJECTED_MESSAGE)
    try:
        row = await service.store.add(admin.id, address)
    except AddressRejected:
        raise HTTPException(status_code=_UNPROCESSABLE, detail=REJECTED_MESSAGE) from None
    except LimitReached as exc:
        raise HTTPException(status_code=_UNPROCESSABLE, detail=str(exc)) from None
    except Conflict as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from None
    await service.audit_owner_action(
        admin.id,
        "breach_address_added",
        {"address_id": row["id"], "source": row["source"]},
        endpoint="/api/security/breach/addresses",
    )
    return row


@router.patch("/breach/addresses/{address_id}")
async def pause_breach_address(
    address_id: str,
    request: Request,
    admin: User = Depends(require_admin),
    service: BreachMonitorService = Depends(breach_service),
) -> dict[str, Any]:
    """Pause or resume one watched address (``{"paused": true}``). Resuming makes it due at
    once and clears its failure count."""
    row_id = _row_id(address_id, NOT_FOUND_MESSAGE)
    body = await _body(request, PAUSED_NOT_BOOL)
    paused = body.get("paused")
    if not isinstance(paused, bool):
        raise HTTPException(status_code=_UNPROCESSABLE, detail=PAUSED_NOT_BOOL)
    try:
        row = await service.store.set_paused(admin.id, row_id, paused)
    except NotFound as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from None
    await service.audit_owner_action(
        admin.id,
        "breach_address_paused" if paused else "breach_address_resumed",
        {"address_id": row["id"], "source": row["source"]},
        endpoint=f"/api/security/breach/addresses/{row_id}",
    )
    return row


@router.delete("/breach/addresses/{address_id}", status_code=status.HTTP_204_NO_CONTENT)
async def remove_breach_address(
    address_id: str,
    admin: User = Depends(require_admin),
    service: BreachMonitorService = Depends(breach_service),
) -> Response:
    """Stop watching a typed address and forget its breaches (the sign-in one can only be
    paused: 409)."""
    row_id = _row_id(address_id, NOT_FOUND_MESSAGE)
    try:
        removed = await service.store.remove(admin.id, row_id)
    except NotFound as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from None
    except Conflict as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from None
    await service.audit_owner_action(
        admin.id,
        "breach_address_removed",
        {"address_id": str(row_id), "findings_removed": removed},
        endpoint=f"/api/security/breach/addresses/{row_id}",
    )
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.post("/breach/addresses/{address_id}/check")
async def check_breach_address_now(
    address_id: str,
    admin: User = Depends(require_admin),
    installation: InstallationService = Depends(installation_service),
    service: BreachMonitorService = Depends(breach_service),
) -> dict[str, Any]:
    """Look one address up now (Check now). A lookup that failed is a 200 "not_checked"
    with its plain reason, never "no breaches"; 409 when breach checks cannot run (the
    report's reason) or the address is paused; 429 with Retry-After when it was checked
    moments ago or the pacer is busy."""
    row_id = _row_id(address_id, NOT_FOUND_MESSAGE)
    try:
        report = await service.check_now(admin.id, row_id)
    except BreachUnavailable as exc:
        capability = await _monitor_status(installation)
        reason = exc.reason
        if capability is not None and capability.effective != "on" and capability.reason:
            reason = str(capability.reason)
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=reason) from None
    except CheckTooSoon as exc:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=str(exc),
            headers={"Retry-After": str(max(1, int(exc.retry_after_s)))},
        ) from None
    except NotFound as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from None
    except Conflict as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from None
    return {
        "outcome": report.outcome,
        "address": report.address,
        "new_findings": report.new_findings,
        "note": report.note,
    }


@router.post("/breach/findings/{finding_id}/acknowledge")
async def acknowledge_breach_finding(
    finding_id: str,
    admin: User = Depends(require_admin),
    service: BreachMonitorService = Depends(breach_service),
) -> dict[str, Any]:
    """Mark one finding as handled (the tab's "Mark as handled"; nothing changes anywhere
    else)."""
    row_id = _row_id(finding_id, FINDING_NOT_FOUND_MESSAGE)
    try:
        finding = await service.store.acknowledge(admin.id, row_id)
    except NotFound as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from None
    await service.audit_owner_action(
        admin.id,
        "breach_findings_acknowledged",
        {"count": 1, "finding_id": finding["id"]},
        endpoint=f"/api/security/breach/findings/{row_id}/acknowledge",
    )
    return finding


@router.post("/breach/findings/acknowledge-all")
async def acknowledge_all_breach_findings(
    admin: User = Depends(require_admin),
    service: BreachMonitorService = Depends(breach_service),
) -> dict[str, Any]:
    """Mark every finding of this owner as handled; answers how many changed."""
    count = await service.store.acknowledge_all(admin.id)
    await service.audit_owner_action(
        admin.id,
        "breach_findings_acknowledged",
        {"count": count},
        endpoint="/api/security/breach/findings/acknowledge-all",
    )
    return {"acknowledged": count}


# ---------------------------------------------------------------------------
# The password check's range proxy
# ---------------------------------------------------------------------------


@router.post("/pwned-passwords/range")
async def pwned_passwords_range(
    request: Request,
    current_user: User = Depends(get_current_user),
    installation: InstallationService = Depends(installation_service),
) -> dict[str, Any]:
    """The Pwned Passwords range for one 5-character SHA-1 prefix, for any signed-in
    person. The prefix travels in the body (never a URL, so never an access log), the
    answer is handed back unchanged and the browser makes the match. Order: the owner's
    switch (403 off, 503 unreadable), the per-user limit (429), the prefix (422), then one
    request through the guarded client (503 "not checked" on any failure)."""
    capability = await _monitor_status(installation)
    if capability is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=REPORT_UNREADABLE
        )
    # The owner's switch, not the effective state: the check needs no HIBP key.
    if capability.enabled is not True:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=SWITCHED_OFF)
    wait = _range_limiter.retry_after(current_user.id)
    if wait is not None:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"Too many password checks. Try again in {wait} seconds.",
            headers={"Retry-After": str(wait)},
        )
    body = await _body(request, PREFIX_REFUSED)
    prefix: Optional[str] = valid_prefix(body.get("prefix"))
    if prefix is None:
        raise HTTPException(status_code=_UNPROCESSABLE, detail=PREFIX_REFUSED)
    try:
        entries = await fetch_range(prefix)
    except Exception as exc:
        # Any failure is "not checked", never "not found". A fixed reason code (or the
        # exception type) and the user only: never the prefix.
        reason = exc.reason if isinstance(exc, PwnedPasswordsUnavailable) else type(exc).__name__
        logger.warning("pwned_range_failed", user_id=str(current_user.id), reason=reason)
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=RANGE_UNAVAILABLE
        ) from None
    # The user only: a count next to a user id would narrow down their hash (SEC-F13).
    logger.info("pwned_range_served", user_id=str(current_user.id))
    return range_answer(prefix, entries)
