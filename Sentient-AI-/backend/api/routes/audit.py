from __future__ import annotations
from typing import Any, Dict, List, Optional, Union

import uuid
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from core.database import get_db
from core.security import compute_audit_hash
from models.audit import AuditLog, AuditStatus

router = APIRouter(prefix="/audit", tags=["audit"])


class AuditLogCreate(BaseModel):
    user_id: uuid.UUID
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
    request_id: str


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
    valid: bool


def _build_hash_payload(
    *,
    user_id: str,
    connector_name: str,
    action: str,
    endpoint: str,
    scope_used: str,
    status_value: str,
    request_id: str,
    request_data: Any,
    response_summary: Any,
    previous_hash: Optional[str],
) -> dict[str, Any]:
    """Canonical payload that gets hashed for one audit row.

    Including ``previous_hash`` chains each row to its predecessor, so
    deleting or reordering rows is detectable, not just per-row tampering.
    """
    return {
        "user_id": user_id,
        "connector_name": connector_name,
        "action": action,
        "endpoint": endpoint,
        "scope_used": scope_used,
        "status": status_value,
        "request_id": request_id,
        "request_data": request_data,
        "response_summary": response_summary,
        "previous_hash": previous_hash,
    }


@router.post(
    "/",
    response_model=AuditLogResponse,
    status_code=status.HTTP_201_CREATED,
)
async def create_audit_log(
    body: AuditLogCreate,
    db: AsyncSession = Depends(get_db),
) -> AuditLog:
    """Record a new audit log entry, chained to the previous row in this
    user's audit log via ``previous_hash``. Per-user chains avoid the
    cross-user race that a global chain would introduce.
    """
    # Look up the most recent row for this user to get its hash
    prev_result = await db.execute(
        select(AuditLog)
        .where(AuditLog.user_id == body.user_id)
        .order_by(AuditLog.timestamp.desc())
        .limit(1)
    )
    prev = prev_result.scalar_one_or_none()
    previous_hash = prev.integrity_hash if prev is not None else None

    hash_payload = _build_hash_payload(
        user_id=str(body.user_id),
        connector_name=body.connector_name,
        action=body.action,
        endpoint=body.endpoint,
        scope_used=body.scope_used,
        status_value=body.status.value,
        request_id=body.request_id,
        request_data=body.request_data,
        response_summary=body.response_summary,
        previous_hash=previous_hash,
    )
    integrity_hash = compute_audit_hash(hash_payload)

    entry = AuditLog(
        user_id=body.user_id,
        connector_name=body.connector_name,
        action=body.action,
        endpoint=body.endpoint,
        scope_used=body.scope_used,
        status=body.status,
        reasoning_chain=body.reasoning_chain,
        detection_method=body.detection_method,
        confidence_score=body.confidence_score,
        request_data=body.request_data,
        response_summary=body.response_summary,
        integrity_hash=integrity_hash,
        previous_hash=previous_hash,
        request_id=body.request_id,
    )
    db.add(entry)
    await db.flush()
    await db.refresh(entry)
    return entry


@router.get("/", response_model=list[AuditLogResponse])
async def list_audit_logs(
    user_id: uuid.UUID,
    connector_name: Optional[str] = None,
    status_filter: Optional[AuditStatus] = Query(default=None, alias="status"),
    limit: int = Query(default=50, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    db: AsyncSession = Depends(get_db),
) -> list[AuditLog]:
    """Retrieve audit logs with optional filtering."""
    query = select(AuditLog).where(AuditLog.user_id == user_id)

    if connector_name is not None:
        query = query.where(AuditLog.connector_name == connector_name)
    if status_filter is not None:
        query = query.where(AuditLog.status == status_filter)

    query = query.order_by(AuditLog.timestamp.desc()).offset(offset).limit(limit)
    result = await db.execute(query)
    return list(result.scalars().all())


@router.get("/{log_id}", response_model=AuditLogResponse)
async def get_audit_log(
    log_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
) -> AuditLog:
    """Retrieve a single audit log entry."""
    result = await db.execute(select(AuditLog).where(AuditLog.id == log_id))
    entry = result.scalar_one_or_none()
    if entry is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Audit log not found",
        )
    return entry


@router.get("/{log_id}/verify", response_model=AuditIntegrityCheck)
async def verify_audit_integrity(
    log_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
) -> dict:
    """Verify the tamper-evident hash of an audit log entry.

    Hashes computed from the row's stored fields (including
    ``previous_hash``) so chain rotation, deletion, or field tampering
    all surface as a hash mismatch.
    """
    result = await db.execute(select(AuditLog).where(AuditLog.id == log_id))
    entry = result.scalar_one_or_none()
    if entry is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Audit log not found",
        )

    hash_payload = _build_hash_payload(
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
    )
    expected = compute_audit_hash(hash_payload)
    return {"id": entry.id, "valid": entry.integrity_hash == expected}
