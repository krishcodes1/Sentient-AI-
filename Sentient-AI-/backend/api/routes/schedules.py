"""Serves /api/schedules: the signed-in user's scheduled tasks and daily
briefing (list, create, pause or resume, delete, run now) and their saved time
zone.

Why it exists: the owner manages what runs on their behalf without the chat
and without an approval card, since these are their own actions, and the
future reminders-and-automations page (backlog D2) reads the same routes.
Every rule the schedule.* tools apply applies here too (services/tools/
schedule.py): the same validation, the same limits. Each task belongs to its
user: another user's id is a 404, as an unknown one is. Creating a task and
running one now are refused with 409 while the owner's "Scheduled tasks and
daily briefing" switch is off; listing, pausing and deleting still work, so a
user can always clean up. Every change is audited with ids only, never the
prompt.
"""

from __future__ import annotations

import uuid
from typing import Any, Literal, Optional

import structlog
from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from core.database import get_db
from models.audit import AuditStatus
from models.user import User
from services.audit import append_audit_log
from services.auth import get_current_user
from services.scheduler.timezones import parse_zone

logger = structlog.get_logger(__name__)

router = APIRouter(prefix="/schedules", tags=["schedules"])

_CAPABILITY = "scheduled_tasks"


class ScheduleCreate(BaseModel):
    """A new task. ``kind`` "prompt" takes the schedule.create fields;
    "briefing" takes schedule.briefing's (and changes an existing
    briefing)."""

    kind: Literal["prompt", "briefing"] = "prompt"
    label: Optional[str] = None
    prompt: Optional[str] = None
    freq: Optional[str] = None
    time: Optional[str] = None
    days: Optional[list[str]] = None
    day_of_month: Optional[int] = None
    date: Optional[str] = None
    tools: Optional[list[str]] = None
    write_tools: Optional[list[str]] = None
    sections: Optional[list[str]] = None
    topic: Optional[str] = None
    summary: Optional[bool] = None
    timezone: Optional[str] = None
    channels: Optional[list[str]] = None


class SchedulePatch(BaseModel):
    paused: bool


class TimezoneBody(BaseModel):
    timezone: str = Field(min_length=1, max_length=64)


def _toolkit(request: Request) -> Any:
    toolkit = getattr(request.app.state, "schedule_toolkit", None)
    if toolkit is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Scheduled tasks are not available yet. Try again shortly.",
        )
    return toolkit


async def _require_on(request: Request) -> None:
    """409 with the capability's own sentence while it is not on."""
    from services import capabilities as registry

    installation = getattr(request.app.state, "installation", None)
    try:
        on = installation is not None and _CAPABILITY in await installation.enabled_keys()
    except Exception as exc:
        logger.warning("schedules_gate_unreadable", error_type=type(exc).__name__)
        on = False
    if not on:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT, detail=registry.get(_CAPABILITY).when_denied
        )


async def _audit(
    db: AsyncSession, user: User, action: str, endpoint: str, data: dict[str, Any]
) -> None:
    await append_audit_log(
        db,
        user_id=user.id,
        connector_name="schedule",
        action=action,
        endpoint=endpoint,
        scope_used=_CAPABILITY,
        status=AuditStatus.approved,
        request_data={**data, "source": "web"},
    )


def _refusal(result: dict[str, Any]) -> HTTPException:
    if result.get("not_found"):
        return HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=result.get("error"))
    code = (
        status.HTTP_409_CONFLICT
        if result.get("duplicate") or result.get("rule") == "task_limit"
        else status.HTTP_422_UNPROCESSABLE_ENTITY
    )
    return HTTPException(status_code=code, detail={"message": result.get("error"), "rule": result.get("rule")})


@router.get("")
async def list_schedules(
    request: Request, current_user: User = Depends(get_current_user)
) -> dict[str, Any]:
    """The user's tasks (nudges included) with their saved zone."""
    result = await _toolkit(request).list(str(current_user.id))
    if not result.get("ok"):
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=result.get("error"))
    return {"timezone": result.get("timezone"), "count": result.get("count"), "tasks": result.get("tasks")}


@router.get("/timezone")
async def get_timezone(current_user: User = Depends(get_current_user)) -> dict[str, Optional[str]]:
    return {"timezone": current_user.timezone}


@router.put("/timezone")
async def put_timezone(
    body: TimezoneBody,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> dict[str, Optional[str]]:
    """Save the user's IANA zone. Existing tasks keep their own zone."""
    zone, error = parse_zone(body.timezone)
    if zone is None:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=error)
    current_user.timezone = body.timezone.strip()
    await _audit(db, current_user, "timezone", "/api/schedules/timezone", {"timezone": current_user.timezone})
    return {"timezone": current_user.timezone}


@router.post("", status_code=status.HTTP_201_CREATED)
async def create_schedule(
    body: ScheduleCreate,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> dict[str, Any]:
    await _require_on(request)
    params = body.model_dump(exclude_none=True)
    kind = params.pop("kind", "prompt")
    toolkit = _toolkit(request)
    if kind == "briefing":
        result = await toolkit.briefing(str(current_user.id), params, source="user")
    else:
        result = await toolkit.create(str(current_user.id), params, source="user")
    if not result.get("ok"):
        raise _refusal(result)
    await _audit(
        db,
        current_user,
        "briefing" if kind == "briefing" else "create",
        "/api/schedules",
        {"task_id": result.get("task_id"), "kind": kind},
    )
    return result


@router.patch("/{task_id}")
async def patch_schedule(
    task_id: uuid.UUID,
    body: SchedulePatch,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> dict[str, Any]:
    result = await _toolkit(request).set_paused(current_user.id, task_id, body.paused)
    if not result.get("ok"):
        raise _refusal(result)
    await _audit(
        db,
        current_user,
        "pause" if body.paused else "resume",
        "/api/schedules/{task_id}",
        {"task_id": str(task_id)},
    )
    return result


@router.delete("/{task_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_schedule(
    task_id: uuid.UUID,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> Response:
    result = await _toolkit(request).delete_task(current_user.id, task_id)
    if not result.get("ok"):
        raise _refusal(result)
    await _audit(db, current_user, "delete", "/api/schedules/{task_id}", {"task_id": str(task_id)})
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.post("/{task_id}/run", status_code=status.HTTP_202_ACCEPTED)
async def run_schedule_now(
    task_id: uuid.UUID,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> dict[str, Any]:
    await _require_on(request)
    service = getattr(request.app.state, "schedules", None)
    if service is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Scheduled tasks are not available yet. Try again shortly.",
        )
    result = await service.run_now(current_user.id, task_id)
    if not result.get("ok"):
        if result.get("not_found"):
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=result.get("error"))
        if result.get("rate_limited"):
            raise HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS, detail=result.get("error"))
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=result.get("error"))
    await _audit(db, current_user, "run_now", "/api/schedules/{task_id}/run", {"task_id": str(task_id)})
    return result
