"""Serves /api/goals: the signed-in user's goals for the Goals page (list by
status, create, read one with its milestones and latest progress notes,
change, add a progress note, delete).

Why it exists: a goal made on the page and one made in chat (the goals.*
tools) must obey identical rules, so every route calls the goals store
(services/goals/store.py) with the request's own session and nothing else
writes the goals tables. Identity comes from the JWT only; another user's
goal, or an id that is not one, is a 404. The store's refusals map to 409
(a duplicate open goal, a limit) and 422 (bad fields, text the prompt guard
or the secret detector refuses), with its message, which never repeats the
user's text. Deleting needs no card here: the person clicking Delete (after
the page's confirm step) is the approval. The routes work whatever the
"goals" switch says, which gates only the agent's tools, so a user can
always see and clean up their own goals. Every change is audited with ids
only, never a title or a note.
"""

from __future__ import annotations

from typing import Annotated, Any, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Response, status
from pydantic import BaseModel, ConfigDict, Field, StrictBool
from sqlalchemy.ext.asyncio import AsyncSession

from core.database import get_db
from core.validation import SafeStr
from models.audit import AuditStatus
from models.goal import (
    CATEGORY_MAX_CHARS,
    CURRENT_STATE_MAX_CHARS,
    DESCRIPTION_MAX_CHARS,
    MAX_MILESTONES_PER_GOAL,
    MILESTONE_TITLE_MAX_CHARS,
    NOTE_MAX_CHARS,
    TITLE_MAX_CHARS,
)
from models.user import User
from services.audit import append_audit_log
from services.auth import get_current_user
from services.goals import store as goal_store
from services.goals.store import GoalError

router = APIRouter(prefix="/goals", tags=["goals"])

EVENT_CREATED = "goal_created"
EVENT_UPDATED = "goal_updated"
EVENT_DELETED = "goal_deleted"
EVENT_PROGRESS_LOGGED = "goal_progress_logged"

# How many progress notes a goal's detail shows, newest first, read or
# changed (the goals.get and goals.update tools show
# goal_store.DEFAULT_ENTRIES).
DETAIL_ENTRIES = 50

# Ceilings on a request body, not the rules: the store applies the real
# limits (models/goal.py) after cleaning the text, with the same message a
# goals.* tool call gets. These only keep an oversized body from reaching it.
_TEXT_SLACK = 2
_DATE_CHARS = 32
_ID_CHARS = 64
_CHOICE_CHARS = 2 * CATEGORY_MAX_CHARS

MilestoneId = Annotated[SafeStr, Field(max_length=_ID_CHARS)]


class MilestoneIn(BaseModel):
    """One new milestone: ``{title, due_date?}`` (due_date as YYYY-MM-DD)."""

    model_config = ConfigDict(extra="forbid")

    title: SafeStr = Field(max_length=_TEXT_SLACK * MILESTONE_TITLE_MAX_CHARS)
    due_date: Optional[SafeStr] = Field(default=None, max_length=_DATE_CHARS)


class GoalCreate(BaseModel):
    """The fields goals.create takes (services.goals.store.CREATE_KEYS)."""

    model_config = ConfigDict(extra="forbid")

    title: SafeStr = Field(max_length=_TEXT_SLACK * TITLE_MAX_CHARS)
    description: Optional[SafeStr] = Field(
        default=None, max_length=_TEXT_SLACK * DESCRIPTION_MAX_CHARS
    )
    category: Optional[SafeStr] = Field(default=None, max_length=_CHOICE_CHARS)
    target_date: Optional[SafeStr] = Field(default=None, max_length=_DATE_CHARS)
    current_state: Optional[SafeStr] = Field(
        default=None, max_length=_TEXT_SLACK * CURRENT_STATE_MAX_CHARS
    )
    check_in: Optional[SafeStr] = Field(default=None, max_length=_CHOICE_CHARS)
    milestones: Optional[list[MilestoneIn]] = Field(
        default=None, max_length=MAX_MILESTONES_PER_GOAL
    )


class GoalUpdate(BaseModel):
    """The fields goals.update takes (services.goals.store.UPDATE_KEYS). A
    field left out or sent as null is not changed; an empty description or
    current_state clears it."""

    model_config = ConfigDict(extra="forbid")

    title: Optional[SafeStr] = Field(default=None, max_length=_TEXT_SLACK * TITLE_MAX_CHARS)
    description: Optional[SafeStr] = Field(
        default=None, max_length=_TEXT_SLACK * DESCRIPTION_MAX_CHARS
    )
    category: Optional[SafeStr] = Field(default=None, max_length=_CHOICE_CHARS)
    status: Optional[SafeStr] = Field(default=None, max_length=_CHOICE_CHARS)
    current_state: Optional[SafeStr] = Field(
        default=None, max_length=_TEXT_SLACK * CURRENT_STATE_MAX_CHARS
    )
    target_date: Optional[SafeStr] = Field(default=None, max_length=_DATE_CHARS)
    clear_target_date: Optional[StrictBool] = None
    check_in: Optional[SafeStr] = Field(default=None, max_length=_CHOICE_CHARS)
    add_milestones: Optional[list[MilestoneIn]] = Field(
        default=None, max_length=MAX_MILESTONES_PER_GOAL
    )
    complete_milestones: Optional[list[MilestoneId]] = Field(
        default=None, max_length=MAX_MILESTONES_PER_GOAL
    )
    reopen_milestones: Optional[list[MilestoneId]] = Field(
        default=None, max_length=MAX_MILESTONES_PER_GOAL
    )
    drop_milestones: Optional[list[MilestoneId]] = Field(
        default=None, max_length=MAX_MILESTONES_PER_GOAL
    )


class EntryCreate(BaseModel):
    """A progress note written on the page (source ``user``)."""

    model_config = ConfigDict(extra="forbid")

    note: SafeStr = Field(max_length=_TEXT_SLACK * NOTE_MAX_CHARS)
    milestone_id: Optional[MilestoneId] = None


def _refused(exc: GoalError) -> HTTPException:
    """A store refusal as the route's answer: its status (404, 409 or 422)
    and its message, which never holds the user's text."""
    return HTTPException(status_code=exc.status, detail=exc.message)


async def _audit(db: AsyncSession, user: User, event: str, endpoint: str, **ids: str) -> None:
    await append_audit_log(
        db,
        user_id=user.id,
        connector_name="goals",
        action=event,
        endpoint=endpoint,
        scope_used="goals",
        status=AuditStatus.approved,
        reasoning_chain={"event": event},
        request_data={**ids, "source": "web"},
    )


@router.get("")
async def list_goals(
    goal_status: str = Query(default="active", alias="status", max_length=_CHOICE_CHARS),
    category: Optional[str] = Query(default=None, max_length=_CHOICE_CHARS),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> list[dict[str, Any]]:
    """The user's goals with one status (default active, or all), most
    recently updated first, each with its progress (done / total
    milestones)."""
    try:
        return await goal_store.list_goals(
            db, current_user.id, status=goal_status, category=category
        )
    except GoalError as exc:
        raise _refused(exc) from None


@router.post("", status_code=status.HTTP_201_CREATED)
async def create_goal(
    body: GoalCreate,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> dict[str, Any]:
    """Save a new active goal with its first milestones (the goals.create
    rules); answers the goal with its milestones."""
    try:
        goal = await goal_store.create_goal(
            db, current_user.id, body.model_dump(exclude_unset=True), source="user"
        )
    except GoalError as exc:
        raise _refused(exc) from None
    await _audit(db, current_user, EVENT_CREATED, "/api/goals", goal_id=goal["id"])
    return goal


@router.get("/{goal_id}")
async def get_goal(
    goal_id: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> dict[str, Any]:
    """One goal with its milestones in order and its latest progress
    notes, newest first."""
    try:
        return await goal_store.get_goal(
            db, current_user.id, goal_id, entries_limit=DETAIL_ENTRIES
        )
    except GoalError as exc:
        raise _refused(exc) from None


@router.patch("/{goal_id}")
async def update_goal(
    goal_id: str,
    body: GoalUpdate,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> dict[str, Any]:
    """Change a goal, its status or its milestones (the goals.update rules:
    milestones are dropped, never deleted); answers the goal as it is now,
    with as many progress notes as reading it does (the page shows the
    reply in place of what it read)."""
    try:
        goal = await goal_store.update_goal(
            db,
            current_user.id,
            goal_id,
            body.model_dump(exclude_unset=True),
            entries_limit=DETAIL_ENTRIES,
        )
    except GoalError as exc:
        raise _refused(exc) from None
    await _audit(db, current_user, EVENT_UPDATED, "/api/goals/{id}", goal_id=goal["id"])
    return goal


@router.post("/{goal_id}/entries", status_code=status.HTTP_201_CREATED)
async def add_entry(
    goal_id: str,
    body: EntryCreate,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> dict[str, Any]:
    """Add a progress note to a goal, optionally about one of its
    milestones; answers the note."""
    try:
        entry = await goal_store.log_progress(
            db,
            current_user.id,
            goal_id,
            body.note,
            milestone_id=body.milestone_id,
            source="user",
        )
    except GoalError as exc:
        raise _refused(exc) from None
    await _audit(
        db,
        current_user,
        EVENT_PROGRESS_LOGGED,
        "/api/goals/{id}/entries",
        goal_id=str(goal_store.as_uuid(goal_id)),
        entry_id=entry["id"],
    )
    return entry


@router.delete("/{goal_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_goal(
    goal_id: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> Response:
    """Delete a goal with its milestones and progress notes."""
    try:
        deleted = await goal_store.delete_goal(db, current_user.id, goal_id)
    except GoalError as exc:
        raise _refused(exc) from None
    await _audit(db, current_user, EVENT_DELETED, "/api/goals/{id}", goal_id=deleted["goal_id"])
    return Response(status_code=status.HTTP_204_NO_CONTENT)
