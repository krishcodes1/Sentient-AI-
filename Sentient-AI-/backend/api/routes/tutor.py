"""The owner's tutor locks: list, create and delete them, and list the owner's
own Canvas courses to pick one from (Settings → Permissions).

Why it exists: a lock forces tutor mode on for one Canvas course (by id, code,
name or aliases) or a whole account, for one account or for every account on
the install. Locks are owner policy, so every route here is owner-only
(``require_admin``: 403 for anyone else) and web-only: no chat command,
channel or tool can create or lift one. Every create and delete is audited
(``tutor_lock_created`` / ``tutor_lock_deleted``). The rules a lock must pass
(a course named, no generic, too-short, injection- or secret-shaped terms, at
most 100 locks, no duplicates) live in services/tutor/locks.py; a refusal is
a 422 whose detail the Settings page shows as is.

Connects to: services/tutor/service.py (CRUD and audit), the capability
report (whether tutor mode is on at all), and the tool executor's
canvas.get_courses for the owner's course picker (the executor applies the
connector's own gates; the course names are Canvas data, shown only to the
owner, and screened again if one becomes a lock).
"""

from __future__ import annotations

import uuid
from typing import Any, Literal, Optional

import structlog
from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from api.routes._deps import require_admin
from api.routes.agent import _tutor_enabled
from core.database import get_db
from models.tutor_lock import TutorLock
from models.user import User
from services.tutor import service as tutor_service
from services.tutor.locks import LockValidationError

logger = structlog.get_logger(__name__)

router = APIRouter(prefix="/tutor", tags=["tutor"])

# The owner's course picker shows at most this many courses.
_MAX_COURSES = 100


class TutorLockOut(BaseModel):
    id: str
    # "course" | "account"
    scope: str
    # None: every account on the install.
    user_id: Optional[str] = None
    # "every account", or the account's email.
    applies_to: str
    label: str
    canvas_course_id: Optional[str] = None
    course_code: Optional[str] = None
    course_name: Optional[str] = None
    aliases: list[str] = []
    created_at: str


class TutorLocksOut(BaseModel):
    # The tutor_mode capability: while it is off, locks do nothing.
    enabled: bool
    locks: list[TutorLockOut]


class TutorLockCreate(BaseModel):
    scope: Literal["course", "account"]
    # "all": every account; "me": the owner's own; "email": the account
    # with ``email``.
    applies_to: Literal["all", "me", "email"] = "all"
    email: Optional[str] = Field(default=None, max_length=320)
    canvas_course_id: Optional[str] = Field(default=None, max_length=40)
    course_code: Optional[str] = Field(default=None, max_length=200)
    course_name: Optional[str] = Field(default=None, max_length=400)
    aliases: list[str] = Field(default_factory=list, max_length=10)


class CanvasCourseOut(BaseModel):
    id: str
    name: str = ""
    course_code: str = ""


class CanvasCoursesOut(BaseModel):
    # False when the owner has no working Canvas connector: the picker is
    # hidden and the course is typed instead.
    available: bool
    courses: list[CanvasCourseOut] = []


async def _emails(db: AsyncSession, rows: list[TutorLock]) -> dict[uuid.UUID, str]:
    ids = {row.user_id for row in rows if row.user_id is not None}
    if not ids:
        return {}
    result = await db.execute(select(User.id, User.email).where(User.id.in_(ids)))
    return {row.id: row.email for row in result}


def _lock_out(row: TutorLock, emails: dict[uuid.UUID, str]) -> TutorLockOut:
    aliases = row.aliases if isinstance(row.aliases, list) else []
    return TutorLockOut(
        id=str(row.id),
        scope=row.scope,
        user_id=str(row.user_id) if row.user_id is not None else None,
        applies_to=tutor_service.applies_to_label(row, emails),
        label=row.label,
        canvas_course_id=row.canvas_course_id,
        course_code=row.course_code,
        course_name=row.course_name,
        aliases=[a for a in aliases if isinstance(a, str)],
        created_at=row.created_at.isoformat() if row.created_at else "",
    )


@router.get("/locks", response_model=TutorLocksOut)
async def list_tutor_locks(
    request: Request,
    owner: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
) -> TutorLocksOut:
    """Every tutor lock on the install, oldest first, and whether tutor
    mode is on at all."""
    rows = await tutor_service.list_locks(db)
    emails = await _emails(db, rows)
    return TutorLocksOut(
        enabled=await _tutor_enabled(getattr(request.app.state, "installation", None)),
        locks=[_lock_out(row, emails) for row in rows],
    )


@router.post("/locks", response_model=TutorLockOut, status_code=status.HTTP_201_CREATED)
async def create_tutor_lock(
    body: TutorLockCreate,
    owner: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
) -> TutorLockOut:
    """Create one lock (validated and audited); 422 with the reason when a
    rule refuses it."""
    target: Optional[uuid.UUID] = None
    if body.applies_to == "me":
        target = owner.id
    elif body.applies_to == "email":
        email = (body.email or "").strip().lower()
        account = (
            (await db.execute(select(User).where(User.email == email))).scalar_one_or_none()
            if email
            else None
        )
        if account is None:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail="No account on this Crawler uses that email.",
            )
        target = account.id
    try:
        row = await tutor_service.create_lock(
            db,
            owner,
            scope=body.scope,
            user_id=target,
            canvas_course_id=body.canvas_course_id,
            course_code=body.course_code,
            course_name=body.course_name,
            aliases=body.aliases,
        )
    except LockValidationError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)
        ) from None
    logger.info("tutor_lock_created", lock_id=str(row.id), scope=row.scope)
    return _lock_out(row, await _emails(db, [row]))


@router.delete("/locks/{lock_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_tutor_lock(
    lock_id: str,
    owner: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
) -> Response:
    """Delete one lock (audited). Chats it held go back to each person's
    own switch. 404 when there is no such lock."""
    if not await tutor_service.delete_lock(db, owner, lock_id):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="No such tutor lock.")
    logger.info("tutor_lock_deleted", lock_id=lock_id)
    return Response(status_code=status.HTTP_204_NO_CONTENT)


def _course_rows(result: Any) -> Optional[list[CanvasCourseOut]]:
    """The courses in a canvas.get_courses executor result, or None when the
    call did not succeed (no connector, a failed sign-in)."""
    if not isinstance(result, dict) or result.get("ok") is not True:
        return None
    raw = result.get("result")
    if not isinstance(raw, list):
        return None
    courses: list[CanvasCourseOut] = []
    for item in raw[:_MAX_COURSES]:
        if not isinstance(item, dict):
            continue
        course_id = item.get("id")
        if isinstance(course_id, bool) or not isinstance(course_id, (int, str)):
            continue
        text_id = str(course_id).strip()
        if not text_id.isdigit() or len(text_id) > 20:
            continue
        name = item.get("name")
        code = item.get("course_code")
        courses.append(
            CanvasCourseOut(
                id=text_id,
                name=name[:120] if isinstance(name, str) else "",
                course_code=code[:40] if isinstance(code, str) else "",
            )
        )
    return courses


@router.get("/canvas-courses", response_model=CanvasCoursesOut)
async def list_canvas_courses(
    request: Request,
    owner: User = Depends(require_admin),
) -> CanvasCoursesOut:
    """The owner's own Canvas courses, through the tool executor's
    canvas.get_courses (a read, under the owner's identity and the
    connector's own gates). ``available`` is False when there is none to
    read, so the page asks for the course to be typed instead."""
    executor = getattr(request.app.state, "tool_executor", None)
    if executor is None:
        return CanvasCoursesOut(available=False)
    try:
        result = await executor.execute("canvas.get_courses", {}, str(owner.id))
    except Exception as exc:
        logger.warning("tutor_canvas_courses_failed", error_type=type(exc).__name__)
        return CanvasCoursesOut(available=False)
    courses = _course_rows(result)
    if courses is None:
        return CanvasCoursesOut(available=False)
    return CanvasCoursesOut(available=True, courses=courses)
