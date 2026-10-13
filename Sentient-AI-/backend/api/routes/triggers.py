"""Serves /api/triggers: the signed-in user's app-event triggers (list, pause or
resume, delete) for the future reminders-and-automations page (backlog D2).

Why it exists: the owner manages what watches their apps without the chat and
without an approval card, since these are their own actions. Creating a
trigger stays a chat action behind its card (the whole rule is stated there).
Every rule the triggers.* tools apply to a change applies here too
(services/tools/triggers.py). Each trigger belongs to its user: another
user's id is a 404, as an unknown one is. Listing, pausing and deleting work
whatever the switches say, so a user can always clean up. Every change is
audited with ids only.
"""

from __future__ import annotations

from typing import Any

import structlog
from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from core.database import get_db
from models.audit import AuditStatus
from models.user import User
from services.audit import append_audit_log
from services.auth import get_current_user

logger = structlog.get_logger(__name__)

router = APIRouter(prefix="/triggers", tags=["triggers"])


class TriggerPatch(BaseModel):
    paused: bool


def _toolkit(request: Request) -> Any:
    toolkit = getattr(request.app.state, "trigger_toolkit", None)
    if toolkit is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Triggers are not available yet. Try again shortly.",
        )
    return toolkit


async def _audit(db: AsyncSession, user: User, action: str, endpoint: str, trigger_id: str) -> None:
    await append_audit_log(
        db,
        user_id=user.id,
        connector_name="triggers",
        action=action,
        endpoint=endpoint,
        scope_used="event_triggers",
        status=AuditStatus.approved,
        request_data={"trigger_id": trigger_id, "source": "web"},
    )


def _refusal(result: dict[str, Any]) -> HTTPException:
    if result.get("not_found"):
        return HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=result.get("error"))
    return HTTPException(
        status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=result.get("error") or "Try again shortly."
    )


@router.get("")
async def list_triggers(request: Request, current_user: User = Depends(get_current_user)) -> dict[str, Any]:
    """The user's triggers, oldest first (never event content)."""
    result = await _toolkit(request).list_triggers(str(current_user.id))
    if not result.get("ok"):
        raise _refusal(result)
    return {"count": result.get("count"), "triggers": result.get("triggers")}


@router.patch("/{trigger_id}")
async def patch_trigger(
    trigger_id: str,
    body: TriggerPatch,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> dict[str, Any]:
    """Pause, or resume (the error count is cleared and it checks now)."""
    result = await _toolkit(request).set_paused(str(current_user.id), trigger_id, body.paused)
    if not result.get("ok"):
        raise _refusal(result)
    await _audit(
        db,
        current_user,
        "trigger_paused" if body.paused else "trigger_resumed",
        "/api/triggers/{id}",
        str(result["trigger_id"]),
    )
    return {"trigger_id": result["trigger_id"], "label": result["label"], "status": result["status"]}


@router.delete("/{trigger_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_trigger(
    trigger_id: str,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> Response:
    """Delete one trigger and its queued events; its conversation is kept."""
    result = await _toolkit(request).delete_trigger(str(current_user.id), trigger_id)
    if not result.get("ok"):
        raise _refusal(result)
    await _audit(db, current_user, "trigger_deleted", "/api/triggers/{id}", str(result["trigger_id"]))
    return Response(status_code=status.HTTP_204_NO_CONTENT)
