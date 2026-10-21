"""Serves Security -> MCP reviews (/api/security/mcp): the caller's MCP tools
whose definitions changed or are new and wait for review, one tool's diff,
approving or keeping off one tool, and approving every shown change of one
server at once.

Why it exists: a connected MCP server can change a tool's description after
it was approved (a "rug pull"); a changed tool is never offered or run
until its owner has seen exactly what changed and approved that exact
definition hash. Nothing is ever approved automatically: an approval names
the hash the page showed, and a definition that changed again since answers
409. MCP connectors are per user, so every route serves the caller's own
servers only and answers 404 (never 403) for anything else, so ids are not
enumerable. Server text reaches the page only as text parts (hidden
characters as labelled parts), never as markup.

Connects to: services/mcp/pin_store.py (the reads and writes),
services/mcp/pinning.py (the review and the hashes), services/audit.py
(``mcp_tool_review_approved`` / ``mcp_tool_review_kept_off`` rows),
services/mcp/integration.py (``forget_mcp_catalog_cache``),
``app.state.mcp_pins`` (the owner's switch).
Used by: the Security page's MCP reviews tab and the Connectors page's
review badge; main.py mounts the router.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Annotated, Any, Literal, Optional

import structlog
from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from pydantic import BaseModel, Field, StringConstraints
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from api.routes.agent import UserRateLimiter
from core.database import get_db
from models.audit import AuditStatus
from models.connector import ConnectorConfig, ConnectorType
from models.mcp_tool_pin import McpToolPin
from models.user import User
from services.audit import append_auth_event
from services.auth import get_current_user
from services.mcp.integration import forget_mcp_catalog_cache
from services.mcp.pin_store import (
    StaleReview,
    approve_pin,
    get_owned_pin,
    keep_pin_off,
    list_reviews,
    pin_view,
)
from services.mcp.pinning import (
    SENTINEL_STATUS,
    STATUS_APPROVED,
    STATUS_KEPT_OFF,
    is_waiting,
    review_detail,
    shown_hash,
)

logger = structlog.get_logger(__name__)

router = APIRouter(prefix="/security/mcp", tags=["security"])

# Approve, keep-off and the server approve share one budget per user: enough
# for a person working through a list, small enough to bound a looping client.
REVIEW_ACTIONS_PER_MINUTE = 30
MAX_SERVER_APPROVALS = 200
_review_limiter = UserRateLimiter()

_ENDPOINT = "/api/security/mcp/pins"
_NOT_FOUND = "Not found."
_TOO_MANY = "Too many review actions. Wait a minute and try again."
_STALE_TOOL = "This tool changed again since you looked. Reload to see the latest version."
_STALE_SERVER = (
    "Something on this server changed since you looked. Reload to see the latest versions."
)
_HASH_PATTERN = r"^[0-9a-f]{64}$"

DefinitionHash = Annotated[str, StringConstraints(pattern=_HASH_PATTERN)]


class McpTextPartOut(BaseModel):
    text: str
    hidden: bool
    decoded: Optional[str] = None


class McpToolPinViewOut(BaseModel):
    pin_id: str
    tool_name: str
    remote_name: list[McpTextPartOut]
    status: str  # "approved" | "needs_review" | "kept_off"
    review_kind: Optional[str] = None  # "changed" | "new"
    removed: bool
    trusted_how: Optional[str] = None  # "first_use" | "owner_test" | "owner_review"
    hidden_characters: int
    change_count: int
    first_seen_at: datetime
    approved_at: Optional[datetime] = None
    changed_at: Optional[datetime] = None


class McpServerReviewOut(BaseModel):
    connector_id: str
    display_name: str
    is_active: bool
    needs_review_count: int
    tools: list[McpToolPinViewOut]


class McpReviewListOut(BaseModel):
    pinning_enabled: bool
    servers: list[McpServerReviewOut]


class McpReviewLineOut(BaseModel):
    op: Literal["context", "added", "removed", "hunk"]
    parts: list[McpTextPartOut]


class McpReviewFlagsOut(BaseModel):
    hidden_characters: int
    looks_like_instructions: bool
    too_large: bool


class McpToolReviewDetailOut(BaseModel):
    pin: McpToolPinViewOut
    connector_id: str
    server_name: str
    definition_hash: str
    previous_hash: Optional[str] = None
    flags: McpReviewFlagsOut
    lines: list[McpReviewLineOut]
    truncated: bool


class McpApproveBody(BaseModel):
    # Exactly the hash the review showed; anything else is not a hash (422).
    definition_hash: DefinitionHash


class McpServerApproveBody(BaseModel):
    pins: dict[uuid.UUID, DefinitionHash] = Field(min_length=1, max_length=MAX_SERVER_APPROVALS)


class McpServerApprovalOut(BaseModel):
    approved: list[McpToolPinViewOut]


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _not_found() -> HTTPException:
    return HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=_NOT_FOUND)


def _limit(user: User) -> None:
    if not _review_limiter.allow(str(user.id), REVIEW_ACTIONS_PER_MINUTE):
        raise HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS, detail=_TOO_MANY)


async def _pinning_enabled(request: Request) -> bool:
    """The owner's switch from the process's pin service; absent counts as on
    (is_enabled itself treats an unreadable switch as on)."""
    pins = getattr(request.app.state, "mcp_pins", None)
    is_enabled = getattr(pins, "is_enabled", None)
    if is_enabled is None:
        return True
    try:
        return bool(await is_enabled())
    except Exception as exc:
        logger.warning("mcp_pinning_switch_unreadable", error_type=type(exc).__name__)
        return True


async def _audit_approved(
    db: AsyncSession,
    user: User,
    pin: McpToolPin,
    *,
    definition_hash: str,
    previous_hash: Optional[str],
    review_kind: Optional[str],
) -> None:
    await append_auth_event(
        db,
        user_id=user.id,
        action="mcp_tool_review_approved",
        status=AuditStatus.approved,
        endpoint=_ENDPOINT,
        details={
            "connector_id": str(pin.connector_id),
            "pin_id": str(pin.id),
            "definition_hash": definition_hash,
            "previous_hash": previous_hash,
            "review_kind": review_kind,
        },
    )


def _was_already_approved(pin: McpToolPin, definition_hash: str) -> bool:
    return (
        pin.status == STATUS_APPROVED
        and pin.pending_hash is None
        and pin.approved_hash == definition_hash
    )


@router.get("/reviews", response_model=McpReviewListOut)
async def list_mcp_reviews(
    request: Request,
    connector_id: Optional[str] = Query(default=None, max_length=64),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> dict[str, Any]:
    """The caller's MCP servers and their tools' review state. With
    ``connector_id``, that one server only, and 404 when it is not the
    caller's MCP connector (the Connectors badge then shows nothing)."""
    target: Optional[uuid.UUID] = None
    if connector_id is not None:
        try:
            target = uuid.UUID(connector_id)
        except ValueError:
            raise _not_found() from None
    servers = await list_reviews(db, current_user.id, connector_id=target)
    if target is not None and not servers:
        raise _not_found()
    return {
        "pinning_enabled": await _pinning_enabled(request),
        "servers": [
            {
                "connector_id": str(server.connector_id),
                "display_name": server.display_name,
                "is_active": server.is_active,
                "needs_review_count": server.needs_review_count,
                "tools": [pin_view(pin) for pin in server.tools],
            }
            for server in servers
        ],
    }


@router.get("/pins/{pin_id}", response_model=McpToolReviewDetailOut)
async def mcp_pin_detail(
    pin_id: uuid.UUID,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> dict[str, Any]:
    """One tool's definition, or its diff from the approved one, as text parts.
    ``definition_hash`` is the hash Approve must send back."""
    owned = await get_owned_pin(db, current_user.id, pin_id)
    if owned is None:
        raise _not_found()
    pin, connector = owned
    return {
        **review_detail(pin).to_dict(),
        "pin": pin_view(pin),
        "connector_id": str(connector.id),
        "server_name": str(connector.display_name),
    }


@router.post("/pins/{pin_id}/approve", response_model=McpToolPinViewOut)
async def approve_mcp_pin(
    pin_id: uuid.UUID,
    body: McpApproveBody,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> dict[str, Any]:
    """Approve exactly the definition hash the page showed: 409 when the tool
    changed again since; 200 and no change when it is already approved with that
    hash. The tool is offered again from the next build (the catalog cache of
    that server is dropped; its name bindings are kept)."""
    _limit(current_user)
    owned = await get_owned_pin(db, current_user.id, pin_id)
    if owned is None:
        raise _not_found()
    pin, connector = owned
    unchanged = _was_already_approved(pin, body.definition_hash)
    previous_hash, review_kind = pin.approved_hash, pin.review_kind
    try:
        pin = await approve_pin(db, pin, body.definition_hash, now=_now())
    except StaleReview:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=_STALE_TOOL) from None
    view = pin_view(pin)
    if not unchanged:
        await _audit_approved(
            db,
            current_user,
            pin,
            definition_hash=body.definition_hash,
            previous_hash=previous_hash,
            review_kind=review_kind,
        )
        await db.commit()
        forget_mcp_catalog_cache(connector.id)
    return view


@router.post("/pins/{pin_id}/keep-off", response_model=McpToolPinViewOut)
async def keep_mcp_pin_off(
    pin_id: uuid.UUID,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> dict[str, Any]:
    """Keep a changed or new tool off (any status; idempotent). The safe
    direction, so the page asks for no confirmation."""
    _limit(current_user)
    owned = await get_owned_pin(db, current_user.id, pin_id)
    if owned is None:
        raise _not_found()
    pin, _connector = owned
    already_off = pin.status == STATUS_KEPT_OFF
    pin = await keep_pin_off(db, pin, now=_now())
    view = pin_view(pin)
    if not already_off:
        await append_auth_event(
            db,
            user_id=current_user.id,
            action="mcp_tool_review_kept_off",
            status=AuditStatus.approved,
            endpoint=_ENDPOINT,
            details={
                "connector_id": str(pin.connector_id),
                "pin_id": str(pin.id),
                "definition_hash": shown_hash(pin),
                "review_kind": pin.review_kind,
            },
        )
        await db.commit()
    return view


@router.post("/servers/{connector_id}/approve", response_model=McpServerApprovalOut)
async def approve_mcp_server(
    connector_id: uuid.UUID,
    body: McpServerApproveBody,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> dict[str, Any]:
    """Approve every shown change of one server, by the exact hashes shown, in
    one transaction: every pin must be one of that server's waiting pins (404
    otherwise), and if any hash is no longer the current one nothing is
    approved (409). One audit row per pin, then one catalog cache drop."""
    _limit(current_user)
    connector = (
        await db.execute(
            select(ConnectorConfig).where(
                ConnectorConfig.id == connector_id,
                ConnectorConfig.user_id == current_user.id,
                ConnectorConfig.connector_type == ConnectorType.mcp,
            )
        )
    ).scalar_one_or_none()
    if connector is None:
        raise _not_found()
    rows = (
        (
            await db.execute(
                select(McpToolPin).where(
                    McpToolPin.id.in_(list(body.pins)),
                    McpToolPin.connector_id == connector.id,
                    McpToolPin.user_id == current_user.id,
                    McpToolPin.status != SENTINEL_STATUS,
                )
            )
        )
        .scalars()
        .all()
    )
    by_id = {pin.id: pin for pin in rows}
    ordered: list[McpToolPin] = []
    for pin_id in sorted(body.pins, key=str):
        pin = by_id.get(pin_id)
        if pin is None or not is_waiting(pin):
            raise _not_found()
        ordered.append(pin)
    if any(shown_hash(pin) != body.pins[pin.id] for pin in ordered):
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=_STALE_SERVER)

    now = _now()
    approved: list[McpToolPin] = []
    try:
        async with db.begin_nested():
            for pin in ordered:
                previous_hash, review_kind = pin.approved_hash, pin.review_kind
                done = await approve_pin(db, pin, body.pins[pin.id], now=now)
                await _audit_approved(
                    db,
                    current_user,
                    done,
                    definition_hash=body.pins[pin.id],
                    previous_hash=previous_hash,
                    review_kind=review_kind,
                )
                approved.append(done)
    except StaleReview:
        # A discovery changed one of them between the read and the write:
        # the savepoint undid every approval of this request.
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=_STALE_SERVER) from None
    views = [pin_view(pin) for pin in approved]
    await db.commit()
    forget_mcp_catalog_cache(connector.id)
    return {"approved": views}
