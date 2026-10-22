"""Serves Security -> Mail alerts (/api/security/mail): the mail scam scan's
status, the caller's alerts, a Move-to-Spam/Junk card for one alert,
dismissing an alert, and pausing one account's checks.

Why it exists: the person whose inbox raised an alert must be able to see
why, act on it through an approval card (never directly), say it was not a
scam, and pause the checks of one account. Every route works on the
caller's own rows only; another user's id answers 404, like an unknown one.
The owner also gets install-wide counts on the status (numbers only, never
anyone's mail). The work is ``app.state.mail_scan``'s
(services/notifications/mail_scan.py), which also writes the audit rows (ids
only); these handlers check the request's shape and map the service's
refusals to status codes. Approving or denying a card uses the existing
approvals route, so it runs the same decision pipeline as the Dashboard.

Connects to: services/notifications/mail_scan.py (``MailScanService``).
Used by: the Security page's Mail alerts tab; main.py mounts the router.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, NoReturn, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from pydantic import BaseModel

from models.user import User
from services.auth import get_current_user

router = APIRouter(prefix="/security/mail", tags=["security"])

STARTING = "The server is still starting. Try again shortly."
_KNOWN_STATUSES = {404, 409, 422, 503}


class MailActionRequest(BaseModel):
    action: str


class MailPauseRequest(BaseModel):
    paused: bool


def _service(request: Request) -> Any:
    service = getattr(request.app.state, "mail_scan", None)
    if service is None:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=STARTING)
    return service


def _refuse(result: Any) -> NoReturn:
    code = result.get("status") if isinstance(result, dict) else None
    detail = result.get("error") if isinstance(result, dict) else None
    if code not in _KNOWN_STATUSES:
        code = status.HTTP_503_SERVICE_UNAVAILABLE
    raise HTTPException(status_code=int(code), detail=str(detail or STARTING))


def _checked(result: Any) -> dict[str, Any]:
    if not isinstance(result, dict) or result.get("ok") is not True:
        _refuse(result)
    return {k: v for k, v in result.items() if k != "ok"}


def _before(value: Optional[str]) -> Optional[datetime]:
    if value is None or value == "":
        return None
    try:
        moment = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
    except (ValueError, AttributeError):
        raise HTTPException(
            status_code=422, detail="'before' must be an ISO 8601 time."
        ) from None
    return moment.replace(tzinfo=timezone.utc) if moment.tzinfo is None else moment


@router.get("/status")
async def mail_scan_status(request: Request, current_user: User = Depends(get_current_user)) -> dict[str, Any]:
    """The scan's state for the caller (and install-wide counts for the owner)."""
    result = await _service(request).status(str(current_user.id), is_admin=bool(current_user.is_admin))
    return _checked(result)


@router.get("/alerts")
async def list_mail_alerts(
    request: Request,
    view: str = Query("open"),
    before: Optional[str] = Query(None, max_length=64),
    limit: int = Query(20, ge=1, le=50),
    current_user: User = Depends(get_current_user),
) -> dict[str, Any]:
    """The caller's alerts, newest first (?view=open|all&before=&limit=)."""
    if view not in ("open", "all"):
        raise HTTPException(status_code=422, detail="'view' must be open or all.")
    result = await _service(request).list_alerts(
        str(current_user.id), view=view, before=_before(before), limit=limit
    )
    return _checked(result)


@router.post("/alerts/{finding_id}/actions", status_code=status.HTTP_201_CREATED)
async def request_mail_alert_action(
    finding_id: str,
    body: MailActionRequest,
    request: Request,
    current_user: User = Depends(get_current_user),
) -> dict[str, Any]:
    """Park a Move-to-Spam/Junk approval card for one alert."""
    result = await _service(request).request_action(str(current_user.id), finding_id, body.action)
    return {"card": _checked(result)["card"]}


@router.post("/alerts/{finding_id}/dismiss")
async def dismiss_mail_alert(
    finding_id: str, request: Request, current_user: User = Depends(get_current_user)
) -> dict[str, Any]:
    """Mark one alert "not a scam" (idempotent)."""
    result = await _service(request).dismiss(str(current_user.id), finding_id)
    return {"ok": True, "status": _checked(result)["status"]}


@router.patch("/accounts/{connector_id}")
async def pause_mail_account(
    connector_id: str,
    body: MailPauseRequest,
    request: Request,
    current_user: User = Depends(get_current_user),
) -> dict[str, Any]:
    """Pause or resume the checks of one of the caller's mail accounts."""
    result = await _service(request).set_paused(str(current_user.id), connector_id, body.paused)
    account: dict[str, Any] = _checked(result)["account"]
    return account
