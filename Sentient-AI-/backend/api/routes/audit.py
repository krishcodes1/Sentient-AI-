"""Serves the read-only /audit API: the signed-in user's audit rows, dashboard
aggregates, a single row, and a per-row integrity check against the keyed
hash chain.

Why it exists: Audit rows are written only server-side by services.audit, so a
client-facing create endpoint would let anyone forge validly chained history;
this module exposes just the owner-scoped reads and the verify step that
recomputes a row's HMAC (or legacy unkeyed hash) from its stored fields.
"""

from __future__ import annotations
from typing import Dict, List, Optional, Union

import uuid
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from core.database import get_db
from core.security import compute_audit_hash, compute_audit_hash_legacy
from models.audit import AuditLog, AuditStatus
from models.user import User
from services.audit import build_hash_payload
from services.auth import get_current_user

router = APIRouter(prefix="/audit", tags=["audit"])

# Audit rows are written exclusively server-side (services.audit) as a
# side effect of agent/tool activity. There is intentionally no public
# create endpoint: a client-facing POST would let any caller forge
# validly-chained audit entries, which defeats the purpose of the log.
# These routes are read-only and scoped to the authenticated user.


class AuditLogResponse(BaseModel):
    id: uuid.UUID
    user_id: uuid.UUID
    timestamp: datetime
    connector_name: str
    action: str
    endpoint: str
    scope_used: str
    status: AuditStatus
    reasoning_chain: Optional[Union[Dict, List]] = None
    detection_method: Optional[str] = None
    confidence_score: Optional[float] = None
    request_data: Optional[dict] = None
    response_summary: Optional[str] = None
    integrity_hash: str
    previous_hash: Optional[str] = None
    request_id: str

    model_config = {"from_attributes": True}


class AuditIntegrityCheck(BaseModel):
    id: uuid.UUID
    # True ONLY when the row matched the keyed (HMAC) hash. That is the
    # single claim worth making: an adversary with database write access
    # but without AUDIT_HMAC_KEY cannot produce a row that sets this.
    valid: bool
    # True when the row matched the pre-upgrade UNKEYED digest instead.
    # Such a row is *unverifiable by key*, not verified: anyone who can
    # write to the database can recompute an unkeyed digest, so reporting
    # it as valid would let a forger mint "verified" history. The two flags
    # are therefore three distinct states — (valid, legacy) is
    # (True, False) keyed-verified, (False, True) legacy/unverifiable, and
    # (False, False) tampered.
    legacy: bool = False


async def _get_owned_log(
    log_id: uuid.UUID,
    user: User,
    db: AsyncSession,
) -> AuditLog:
    """Load an audit row and verify ownership (404 on missing or not owned)."""
    result = await db.execute(
        select(AuditLog).where(
            AuditLog.id == log_id,
            AuditLog.user_id == user.id,
        )
    )
    entry = result.scalar_one_or_none()
    if entry is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Audit log not found",
        )
    return entry


@router.get("/", response_model=list[AuditLogResponse])
async def list_audit_logs(
    connector_name: Optional[str] = None,
    status_filter: Optional[AuditStatus] = Query(default=None, alias="status"),
    limit: int = Query(default=50, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> list[AuditLog]:
    """Retrieve the authenticated user's audit logs with optional filtering."""
    query = select(AuditLog).where(AuditLog.user_id == current_user.id)

    if connector_name is not None:
        query = query.where(AuditLog.connector_name == connector_name)
    if status_filter is not None:
        query = query.where(AuditLog.status == status_filter)

    query = query.order_by(AuditLog.timestamp.desc()).offset(offset).limit(limit)
    result = await db.execute(query)
    return list(result.scalars().all())


class AuditStatsDayEntry(BaseModel):
    date: str
    approved: int
    blocked: int
    pending: int


class AuditStatsResponse(BaseModel):
    total_actions_24h: int
    blocked_24h: int
    pending_approvals: int
    approved_24h: int
    by_day: list[AuditStatsDayEntry]


# NOTE: must be registered before "/{log_id}" or "stats" would be
# captured by the UUID path parameter.
@router.get("/stats", response_model=AuditStatsResponse)
async def get_audit_stats(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> AuditStatsResponse:
    """Owner-scoped dashboard aggregates, computed with SQL (no
    client-side scans over raw rows).

    - ``*_24h``: audit rows in the trailing 24 hours by status.
    - ``pending_approvals``: unexpired pending rows in pending_actions.
    - ``by_day``: last 7 calendar days (oldest first) of audit rows
      grouped by status.
    """
    from datetime import timedelta, timezone

    from models.pending_action import PendingAction, PendingActionStatus

    now = datetime.now(timezone.utc)
    day_ago = now - timedelta(hours=24)

    status_counts_result = await db.execute(
        select(AuditLog.status, func.count(AuditLog.id))
        .where(
            AuditLog.user_id == current_user.id,
            AuditLog.timestamp >= day_ago,
        )
        .group_by(AuditLog.status)
    )
    counts_24h = {row_status: count for row_status, count in status_counts_result.all()}

    pending_result = await db.execute(
        select(func.count(PendingAction.id)).where(
            PendingAction.user_id == current_user.id,
            PendingAction.status == PendingActionStatus.pending,
            PendingAction.expires_at > now,
        )
    )
    pending_approvals = int(pending_result.scalar_one() or 0)

    # Last 7 calendar days (UTC), today included.
    today = now.date()
    window_start = datetime(
        today.year, today.month, today.day, tzinfo=timezone.utc
    ) - timedelta(days=6)
    # Postgres' date() converts a TIMESTAMPTZ to the SESSION's time zone
    # before truncating, so on a server whose zone is not UTC the rows get
    # bucketed by local date while the keys below are built in UTC — the
    # buckets never line up and the dashboard chart silently reads zero for
    # part of the window. Convert explicitly. SQLite stores the ISO-8601 UTC
    # string, so plain date() is already UTC there.
    if db.get_bind().dialect.name == "postgresql":
        day_expr = func.date(func.timezone("UTC", AuditLog.timestamp))
    else:
        day_expr = func.date(AuditLog.timestamp)
    by_day_result = await db.execute(
        select(day_expr, AuditLog.status, func.count(AuditLog.id))
        .where(
            AuditLog.user_id == current_user.id,
            AuditLog.timestamp >= window_start,
        )
        .group_by(day_expr, AuditLog.status)
    )

    day_keys = [(today - timedelta(days=offset)).isoformat() for offset in range(6, -1, -1)]
    by_day_map: Dict[str, Dict[str, int]] = {
        key: {"approved": 0, "blocked": 0, "pending": 0} for key in day_keys
    }
    for day_value, row_status, count in by_day_result.all():
        key = str(day_value)[:10]  # date object (PG) or string (SQLite)
        if key in by_day_map:
            by_day_map[key][row_status.value] = count

    return AuditStatsResponse(
        total_actions_24h=sum(counts_24h.values()),
        blocked_24h=counts_24h.get(AuditStatus.blocked, 0),
        pending_approvals=pending_approvals,
        approved_24h=counts_24h.get(AuditStatus.approved, 0),
        by_day=[
            AuditStatsDayEntry(date=key, **by_day_map[key]) for key in day_keys
        ],
    )


@router.get("/{log_id}", response_model=AuditLogResponse)
async def get_audit_log(
    log_id: uuid.UUID,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> AuditLog:
    """Retrieve a single audit log entry owned by the authenticated user."""
    return await _get_owned_log(log_id, current_user, db)


@router.get("/{log_id}/verify", response_model=AuditIntegrityCheck)
async def verify_audit_integrity(
    log_id: uuid.UUID,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> dict:
    """Verify the tamper-evident hash of an audit log entry.

    Hashes computed from the row's stored fields (including
    ``previous_hash``) so chain rotation, deletion, or field tampering
    all surface as a hash mismatch.

    Only the keyed HMAC sets ``valid``. Rows written before that upgrade
    carry an unkeyed SHA-256 and are reported as ``legacy`` — intact as far
    as this route can tell, but carrying no forgery protection, because
    anyone who can write to the database can recompute an unkeyed digest.
    Calling those rows valid would hand a database-write adversary a way to
    mint "verified" history: write the forged row, compute its unkeyed
    hash, and this endpoint blesses it.

    The unkeyed fallback is additionally gated on ``seq IS NULL``, matching
    ``scripts/verify_audit_log.py``. Every row written since the upgrade
    carries a seq, so a forged post-upgrade row cannot reach the fallback
    at all; clearing seq to reach it is itself the legacy label, not a
    verification.
    """
    entry = await _get_owned_log(log_id, current_user, db)

    hash_payload = build_hash_payload(
        user_id=str(entry.user_id),
        connector_name=entry.connector_name,
        action=entry.action,
        endpoint=entry.endpoint,
        scope_used=entry.scope_used,
        status_value=entry.status.value,
        request_id=entry.request_id,
        request_data=entry.request_data,
        response_summary=entry.response_summary,
        previous_hash=entry.previous_hash,
        reasoning_chain=entry.reasoning_chain,
        detection_method=entry.detection_method,
        confidence_score=entry.confidence_score,
    )
    if entry.integrity_hash == compute_audit_hash(hash_payload):
        return {"id": entry.id, "valid": True, "legacy": False}
    if entry.seq is None and entry.integrity_hash == compute_audit_hash_legacy(
        hash_payload
    ):
        return {"id": entry.id, "valid": False, "legacy": True}
    return {"id": entry.id, "valid": False, "legacy": False}
