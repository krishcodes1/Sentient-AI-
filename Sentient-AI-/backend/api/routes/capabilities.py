"""Capability report and owner controls (/api/capabilities).

Any signed-in user may read the report: the chat UI uses it to explain
why a tool is unavailable. Every write is the owner's (``is_admin``)
alone, because a switch here changes what the agent may do for everyone
on the install.

Responses carry CapabilityStatus dicts and install results only. The
InstallationService also holds provider keys and the Telegram token;
nothing from it but the report is ever serialized here.
"""

from __future__ import annotations

import asyncio
from typing import Any

import structlog
from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, StrictBool
from sqlalchemy.ext.asyncio import AsyncSession

from core.database import get_db
from models.audit import AuditStatus
from models.user import User
from services import capabilities
from services.audit import append_audit_log
from services.auth import get_current_user
from services.capabilities.base import Capability
from services.installation import InstallationService
from services.tools.system import SystemToolkit

logger = structlog.get_logger(__name__)

router = APIRouter(prefix="/capabilities", tags=["capabilities"])

# One toolkit for every admin-triggered install, so its lock serializes
# them: a double-click must not start two pip processes on the same
# environment.
_toolkit = SystemToolkit()


class CapabilitiesPatch(BaseModel):
    # Strict: a security switch must be a real boolean, not "yes" or 1.
    capabilities: dict[str, StrictBool]


def _installation(request: Request) -> InstallationService:
    service = getattr(request.app.state, "installation", None)
    if service is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Installation service not available",
        )
    return service


def _require_admin(user: User) -> None:
    if not user.is_admin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only the owner can change permissions",
        )


def _capability(key: str) -> Capability:
    try:
        return capabilities.get(key)
    except KeyError:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Unknown capability")


async def _audit(
    db: AsyncSession, *, user_id: Any, action: str, endpoint: str, data: dict[str, Any]
) -> None:
    await append_audit_log(
        db,
        user_id=user_id,
        connector_name="installation",
        action=action,
        endpoint=endpoint,
        scope_used="admin",
        status=AuditStatus.approved,
        request_data=data,
    )


@router.get("")
async def list_capabilities(
    request: Request,
    current_user: User = Depends(get_current_user),
) -> dict[str, Any]:
    statuses = await _installation(request).report()
    return {"capabilities": [s.to_dict() for s in statuses]}


@router.put("")
async def update_capabilities(
    body: CapabilitiesPatch,
    request: Request,
    current_user: User = Depends(get_current_user),
) -> dict[str, Any]:
    """Partial update: keys not in the patch keep their stored value. The
    service validates the keys and writes the audit row with the diff."""
    _require_admin(current_user)
    service = _installation(request)
    if not body.capabilities:
        statuses = await service.report()
    else:
        try:
            statuses = await service.set_capabilities(
                body.capabilities, actor_id=current_user.id
            )
        except ValueError as exc:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)
            )
    return {"capabilities": [s.to_dict() for s in statuses]}


@router.post("/{key}/request-access")
async def request_access(
    key: str,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> dict[str, Any]:
    """Show the OS permission prompt / open the settings pane.

    Native installs only: in a container (or on an unsupported platform)
    the capability is unavailable and there is no OS to ask, so the reason
    comes back as a 409 the UI can show as-is.
    """
    _require_admin(current_user)
    cap = _capability(key)
    service = _installation(request)
    current = capabilities.statuses_by_key(await service.report()).get(key)
    if cap.request_access is None or current is None or not current.available:
        reason = current.availability_reason if current is not None else ""
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=reason or "This capability has nothing to request here.",
        )

    try:
        await asyncio.to_thread(cap.request_access)
    except Exception as exc:
        logger.warning(
            "capability_request_access_failed", capability=key, error_type=type(exc).__name__
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Could not open the permission prompt.",
        )
    # The probe is cached for a few seconds; the answer must reflect what
    # the owner just granted, not the denial cached a moment ago.
    capabilities.clear_probe_cache()
    fresh = capabilities.statuses_by_key(await service.report())[key]

    await _audit(
        db,
        user_id=current_user.id,
        action="capability_access_requested",
        endpoint=request.url.path,
        data={"capability": key},
    )
    return {"ok": True, "status": fresh.to_dict()}


@router.post("/{key}/install")
async def install(
    key: str,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> dict[str, Any]:
    """Run the allowlisted install behind ``capability.install``.

    The agent's ``system.install_capability`` waits for a human approval;
    here the owner pressing the button is that approval. Only the name is
    taken from the registry: the steps themselves are fixed in
    services.tools.system.ALLOWLIST.
    """
    _require_admin(current_user)
    cap = _capability(key)
    if not cap.install:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="This capability has nothing to install.",
        )

    user_id = current_user.id
    endpoint = request.url.path
    await _audit(
        db,
        user_id=user_id,
        action="capability_install_started",
        endpoint=endpoint,
        data={"capability": key, "install": cap.install},
    )
    # Commit now: an install can run for minutes, and the audit append
    # holds this user's chain lock until the transaction ends. The row
    # must also survive a crash mid-install.
    await db.commit()

    try:
        result = await _toolkit.install_capability(cap.install)
    except Exception as exc:  # install_capability reports errors as results; this is a bug path
        logger.warning(
            "capability_install_crashed", capability=key, error_type=type(exc).__name__
        )
        result = {"ok": False, "error": "The install failed unexpectedly."}

    await _audit(
        db,
        user_id=user_id,
        action="capability_install_finished",
        endpoint=endpoint,
        data={"capability": key, "install": cap.install, "ok": result.get("ok")},
    )
    await db.commit()
    return result
