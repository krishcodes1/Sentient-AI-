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
from typing import Any, Callable

import structlog
from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, StrictBool
from sqlalchemy.ext.asyncio import AsyncSession

from api.routes._deps import installation_service, require_admin
from core.database import async_session
from models.audit import AuditStatus
from models.user import User
from services import capabilities
from services.audit import append_audit_log
from services.auth import get_current_user
from services.capabilities.base import Capability
from services.tools.system import SystemToolkit

logger = structlog.get_logger(__name__)

router = APIRouter(prefix="/capabilities", tags=["capabilities"])

# One toolkit for every admin-triggered install, so its lock serializes
# them: a double-click must not start two pip processes on the same
# environment. A wired app hands the route its own shared instance through
# app.state.system_toolkit; this module-level one is the fallback for tests
# and any app that never set one.
_toolkit = SystemToolkit()

# Audit rows must never sit behind a running install: each write opens its
# own short-lived session from this factory instead of borrowing the
# request's session. Tests point it at their own database.
_session_factory: Callable[[], AsyncSession] = async_session

# Capability keys with an install currently running. A second POST for the
# same key while one is in flight is rejected outright — queueing it behind
# SystemToolkit's own lock would silently make the caller wait minutes for
# someone else's install instead of getting an answer.
_installs_in_progress: set[str] = set()


class CapabilitiesPatch(BaseModel):
    # Strict: a security switch must be a real boolean, not "yes" or 1.
    capabilities: dict[str, StrictBool]


def _system_toolkit(request: Request) -> SystemToolkit:
    return getattr(request.app.state, "system_toolkit", None) or _toolkit


def _capability(key: str) -> Capability:
    try:
        return capabilities.get(key)
    except KeyError:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Unknown capability")


async def _audit(*, user_id: Any, action: str, endpoint: str, data: dict[str, Any]) -> None:
    """Write one audit row through a short-lived session.

    Never the request's own DB session: an install can run for minutes,
    and holding a session open that long would tie up a pool connection
    for nothing.
    """
    async with _session_factory() as session:
        await append_audit_log(
            session,
            user_id=user_id,
            connector_name="installation",
            action=action,
            endpoint=endpoint,
            scope_used="admin",
            status=AuditStatus.approved,
            request_data=data,
        )
        await session.commit()


@router.get("")
async def list_capabilities(
    request: Request,
    current_user: User = Depends(get_current_user),
) -> dict[str, Any]:
    statuses = await installation_service(request).report()
    return {"capabilities": [s.to_dict() for s in statuses]}


@router.put("")
async def update_capabilities(
    body: CapabilitiesPatch,
    request: Request,
    current_user: User = Depends(require_admin),
) -> dict[str, Any]:
    """Partial update: keys not in the patch keep their stored value. The
    service validates the keys and writes the audit row with the diff."""
    service = installation_service(request)
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
    current_user: User = Depends(require_admin),
) -> dict[str, Any]:
    """Show the OS permission prompt / open the settings pane.

    Native installs only: in a container (or on an unsupported platform)
    the capability is unavailable and there is no OS to ask; switched off
    or already granted, there is nothing left to request either. Any of
    those come back as a 409 the UI can show as-is.
    """
    cap = _capability(key)
    service = installation_service(request)
    current = capabilities.statuses_by_key(await service.report()).get(key)
    request_access_fn = cap.request_access
    if current is None or not current.can_request_access or request_access_fn is None:
        detail = (current.availability_reason or current.reason) if current is not None else None
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=detail or "Nothing to request for this capability.",
        )

    try:
        await asyncio.to_thread(request_access_fn)
    except Exception as exc:
        logger.warning(
            "capability_request_access_failed", capability=key, error_type=type(exc).__name__
        )
        await _audit(
            user_id=current_user.id,
            action="capability_access_request_failed",
            endpoint=request.url.path,
            data={"capability": key, "error_type": type(exc).__name__},
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Could not open the permission prompt.",
        )
    # The probe and the report are cached for a few seconds; the answer
    # must reflect what the owner just granted, not the denial cached a
    # moment ago.
    capabilities.clear_probe_cache()
    service.invalidate()
    fresh = capabilities.statuses_by_key(await service.report())[key]

    await _audit(
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
    current_user: User = Depends(require_admin),
) -> dict[str, Any]:
    """Run the allowlisted install behind ``capability.install``.

    The agent's ``system.install_capability`` waits for a human approval;
    here the owner pressing the button is that approval. Only the name is
    taken from the registry: the steps themselves are fixed in
    services.tools.system.ALLOWLIST.

    Holds no DB session across the install itself (it can run for
    minutes): each audit row below opens its own short-lived session. A
    second POST for the same key while one is already running is refused
    outright rather than queued.
    """
    cap = _capability(key)
    if not cap.install:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="This capability has nothing to install.",
        )

    if key in _installs_in_progress:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="An install for this capability is already running.",
        )

    user_id = current_user.id
    endpoint = request.url.path
    _installs_in_progress.add(key)
    try:
        await _audit(
            user_id=user_id,
            action="capability_install_started",
            endpoint=endpoint,
            data={"capability": key, "install": cap.install},
        )

        toolkit = _system_toolkit(request)
        try:
            result = await toolkit.install_capability(cap.install)
        except Exception as exc:  # install_capability reports errors as results; this is a bug path
            logger.warning(
                "capability_install_crashed", capability=key, error_type=type(exc).__name__
            )
            result = {"ok": False, "error": "The install failed unexpectedly."}

        if result.get("ok") is True:
            # The report is cached for a few seconds; the component just
            # installed must show up (and its tools unblock) right away.
            service = getattr(request.app.state, "installation", None)
            if service is not None:
                service.invalidate()

        await _audit(
            user_id=user_id,
            action="capability_install_finished",
            endpoint=endpoint,
            data={"capability": key, "install": cap.install, "ok": result.get("ok")},
        )
        return result
    finally:
        _installs_in_progress.discard(key)
