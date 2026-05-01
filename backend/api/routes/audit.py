"""Audit log API.

All endpoints require an authenticated user, and ``user_id`` is ALWAYS
derived from the bearer token. The previous public ``POST /api/audit/``
endpoint has been removed: audit log creation is an internal-only
operation (see :class:`services.audit.AuditService`). This is a P0 IDOR
fix.

The current :class:`models.user.User` model exposes no admin/role flag.
Until that field is added, the admin-only ``GET /api/audit/all`` route
returns 403 unconditionally — see the comment on that handler.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from core.database import get_db
from models.audit import AuditLog, AuditStatus
from models.user import User
from services.audit import AuditService, _GENESIS_HASH
from services.auth import get_current_user

router = APIRouter(prefix="/audit", tags=["audit"])


# ── Schemas ───────────────────────────────────────────────────────────────


class AuditLogOut(BaseModel):
    id: uuid.UUID
    user_id: uuid.UUID
    action: str
    endpoint: str
    status: str
    reasoning: Optional[str] = None
    confidence_score: Optional[float] = None
    integrity_hash: str
    previous_hash: Optional[str] = None
    timestamp: datetime

    model_config = {"from_attributes": True}

    @classmethod
    def from_model(
        cls, log: AuditLog, previous_hash: Optional[str] = None
    ) -> "AuditLogOut":
        reasoning_value: Optional[str]
        if log.reasoning_chain is None:
            reasoning_value = None
        elif isinstance(log.reasoning_chain, str):
            reasoning_value = log.reasoning_chain
        else:
            # JSON dict/list — render as a string so the schema stays simple.
            try:
                import json as _json

                reasoning_value = _json.dumps(log.reasoning_chain, default=str)
            except (TypeError, ValueError):
                reasoning_value = str(log.reasoning_chain)

        status_value = (
            log.status.value if isinstance(log.status, AuditStatus) else str(log.status)
        )

        return cls(
            id=log.id,
            user_id=log.user_id,
            action=log.action,
            endpoint=log.endpoint,
            status=status_value,
            reasoning=reasoning_value,
            confidence_score=log.confidence_score,
            integrity_hash=log.integrity_hash,
            previous_hash=previous_hash,
            timestamp=log.timestamp,
        )


class AuditStatsOut(BaseModel):
    total: int
    approved: int
    blocked: int
    pending: int


class AuditVerifyOut(BaseModel):
    ok: bool
    total: int
    broken_at: Optional[uuid.UUID] = None
    broken_field: Optional[str] = None


# ── Helpers ───────────────────────────────────────────────────────────────


def _is_admin(user: User) -> bool:
    """Whether the user has admin privileges.

    The current :class:`models.user.User` model has no ``is_admin`` /
    ``role`` / ``tier`` attribute. Until that field is added, no user is
    treated as an admin. When the field is introduced, update this helper
    accordingly (e.g. ``return getattr(user, "is_admin", False)``).
    """
    if hasattr(user, "is_admin"):
        return bool(getattr(user, "is_admin"))
    if hasattr(user, "tier"):
        return getattr(user, "tier") == "admin"
    if hasattr(user, "role"):
        return getattr(user, "role") == "admin"
    return False


# ── Endpoints ─────────────────────────────────────────────────────────────
# NOTE: The legacy public ``POST /api/audit/`` endpoint has been removed.
# Audit log creation is internal only (see AuditService.log_action).


@router.get("/stats", response_model=AuditStatsOut)
async def get_audit_stats(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> AuditStatsOut:
    """Aggregate audit statistics for the current user only."""
    user_id = current_user.id

    total_q = select(func.count(AuditLog.id)).where(AuditLog.user_id == user_id)
    total = (await db.execute(total_q)).scalar() or 0

    counts: dict[str, int] = {}
    for st in (AuditStatus.APPROVED, AuditStatus.BLOCKED, AuditStatus.PENDING):
        q = select(func.count(AuditLog.id)).where(
            AuditLog.user_id == user_id,
            AuditLog.status == st,
        )
        counts[st.value] = (await db.execute(q)).scalar() or 0

    return AuditStatsOut(
        total=int(total),
        approved=int(counts.get("approved", 0)),
        blocked=int(counts.get("blocked", 0)),
        pending=int(counts.get("pending", 0)),
    )


@router.get("/verify", response_model=AuditVerifyOut)
async def verify_audit_chain(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> AuditVerifyOut:
    """Walk the SHA-256 hash chain for the current user's audit logs.

    Returns ``ok=False`` and the offending row's id at the first hash
    mismatch encountered.
    """
    user_id = current_user.id

    stmt = (
        select(AuditLog)
        .where(AuditLog.user_id == user_id)
        .order_by(AuditLog.timestamp.asc(), AuditLog.id.asc())
    )
    result = await db.execute(stmt)
    logs = list(result.scalars().all())

    previous = _GENESIS_HASH
    for log in logs:
        expected = AuditService._compute_hash(
            log.timestamp.isoformat(),
            str(log.user_id),
            log.action,
            log.endpoint,
            previous,
        )
        if expected != log.integrity_hash:
            return AuditVerifyOut(
                ok=False,
                total=len(logs),
                broken_at=log.id,
                broken_field="integrity_hash",
            )
        previous = log.integrity_hash

    return AuditVerifyOut(ok=True, total=len(logs))


@router.get("/all", response_model=List[AuditLogOut])
async def list_all_audit_logs(
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> List[AuditLogOut]:
    """Admin-only: list audit logs across all users.

    The current ``User`` model has no admin field; this endpoint always
    returns 403 until one is added (see ``_is_admin``). Frontend is free
    to call this for an admin dashboard once admin support lands.
    """
    if not _is_admin(current_user):
        raise HTTPException(status_code=403, detail="Admin access required")

    stmt = (
        select(AuditLog)
        .order_by(AuditLog.timestamp.desc())
        .offset(offset)
        .limit(limit)
    )
    result = await db.execute(stmt)
    rows = list(result.scalars().all())
    return [AuditLogOut.from_model(r) for r in rows]


@router.get("/", response_model=List[AuditLogOut])
async def list_audit_logs(
    action: Optional[str] = Query(default=None),
    status_filter: Optional[AuditStatus] = Query(default=None, alias="status"),
    from_ts: Optional[datetime] = Query(default=None),
    to_ts: Optional[datetime] = Query(default=None),
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> List[AuditLogOut]:
    """List audit logs for the current user only, with optional filters."""
    stmt = select(AuditLog).where(AuditLog.user_id == current_user.id)

    if action is not None:
        stmt = stmt.where(AuditLog.action == action)
    if status_filter is not None:
        stmt = stmt.where(AuditLog.status == status_filter)
    if from_ts is not None:
        stmt = stmt.where(AuditLog.timestamp >= from_ts)
    if to_ts is not None:
        stmt = stmt.where(AuditLog.timestamp <= to_ts)

    stmt = (
        stmt.order_by(AuditLog.timestamp.desc())
        .offset(offset)
        .limit(limit)
    )
    result = await db.execute(stmt)
    rows = list(result.scalars().all())
    return [AuditLogOut.from_model(r) for r in rows]


@router.get("/{log_id}", response_model=AuditLogOut)
async def get_audit_log(
    log_id: uuid.UUID,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> AuditLogOut:
    """Retrieve a single audit log entry owned by the current user."""
    result = await db.execute(
        select(AuditLog).where(
            AuditLog.id == log_id,
            AuditLog.user_id == current_user.id,
        )
    )
    log = result.scalar_one_or_none()
    if log is None:
        raise HTTPException(status_code=404, detail="Audit log not found")
    return AuditLogOut.from_model(log)
