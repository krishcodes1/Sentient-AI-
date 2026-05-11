from __future__ import annotations
from typing import Any, Dict, List, Literal, Optional, Union

import json
import uuid
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from core.database import get_db
from core.security import decrypt_credentials, encrypt_credentials
from models.audit import AuditLog
from models.connector import (
    AuthMethod,
    ConnectorConfig,
    ConnectorType,
    PermissionTier,
)

router = APIRouter(prefix="/connectors", tags=["connectors"])


class ConnectorCreateRequest(BaseModel):
    user_id: uuid.UUID
    connector_type: ConnectorType
    display_name: str = Field(..., min_length=1, max_length=255)
    auth_method: AuthMethod
    credentials: dict
    granted_scopes: list[str] = []
    permission_tier: PermissionTier = PermissionTier.user_confirm
    rate_limit_per_minute: int = Field(default=30, ge=1, le=600)


class ConnectorResponse(BaseModel):
    id: uuid.UUID
    user_id: uuid.UUID
    connector_type: ConnectorType
    display_name: str
    is_active: bool
    auth_method: AuthMethod
    granted_scopes: list[str]
    permission_tier: PermissionTier
    rate_limit_per_minute: int
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


class ConnectorUpdateRequest(BaseModel):
    display_name: Optional[str] = Field(default=None, min_length=1, max_length=255)
    is_active: Optional[bool] = None
    credentials: Optional[dict] = None
    granted_scopes: Optional[List[str]] = None
    permission_tier: Optional[PermissionTier] = None
    rate_limit_per_minute: Optional[int] = Field(default=None, ge=1, le=600)


@router.post(
    "/",
    response_model=ConnectorResponse,
    status_code=status.HTTP_201_CREATED,
)
async def create_connector(
    body: ConnectorCreateRequest,
    db: AsyncSession = Depends(get_db),
) -> ConnectorConfig:
    """Register a new external connector with encrypted credentials."""
    encrypted = encrypt_credentials(json.dumps(body.credentials))

    connector = ConnectorConfig(
        user_id=body.user_id,
        connector_type=body.connector_type,
        display_name=body.display_name,
        auth_method=body.auth_method,
        encrypted_credentials=encrypted,
        granted_scopes=body.granted_scopes,
        permission_tier=body.permission_tier,
        rate_limit_per_minute=body.rate_limit_per_minute,
    )
    db.add(connector)
    await db.flush()
    await db.refresh(connector)
    return connector


@router.get("/", response_model=list[ConnectorResponse])
async def list_connectors(
    user_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
) -> list[ConnectorConfig]:
    """List all connectors for a user."""
    result = await db.execute(
        select(ConnectorConfig).where(ConnectorConfig.user_id == user_id)
    )
    return list(result.scalars().all())


HealthStatus = Literal["healthy", "degraded", "unhealthy"]
_DEGRADED_AFTER = timedelta(hours=24)


class ConnectorHealthEntry(BaseModel):
    id: uuid.UUID
    name: str
    type: ConnectorType
    status: HealthStatus
    uptime: float
    last_check: str


@router.get("/health", response_model=list[ConnectorHealthEntry])
async def get_connector_health(
    user_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
) -> list[ConnectorHealthEntry]:
    """Derive a per-connector health summary for the user.

    Status rules (no third-party network calls; this is platform-level
    health, not the remote service's health):
    - ``unhealthy``: connector is disabled (``is_active = False``)
    - ``degraded``: enabled but no audit-log activity in the last 24h
    - ``healthy``:  enabled and used in the last 24h
    """
    conn_result = await db.execute(
        select(ConnectorConfig).where(ConnectorConfig.user_id == user_id)
    )
    connectors = list(conn_result.scalars().all())

    if not connectors:
        return []

    names = [c.display_name for c in connectors]
    audit_result = await db.execute(
        select(AuditLog)
        .where(AuditLog.user_id == user_id)
        .where(AuditLog.connector_name.in_(names))
        .order_by(AuditLog.timestamp.desc())
    )
    audit_rows = list(audit_result.scalars().all())

    last_seen_by_name: Dict[str, datetime] = {}
    for row in audit_rows:
        if row.connector_name not in last_seen_by_name:
            last_seen_by_name[row.connector_name] = row.timestamp

    now = datetime.now(timezone.utc)
    entries: list[ConnectorHealthEntry] = []
    for c in connectors:
        last_seen = last_seen_by_name.get(c.display_name)

        if not c.is_active:
            status_value: HealthStatus = "unhealthy"
            uptime = 0.0
        elif last_seen is None or (now - last_seen) > _DEGRADED_AFTER:
            status_value = "degraded"
            uptime = 95.0
        else:
            status_value = "healthy"
            uptime = 100.0

        last_check = last_seen.isoformat() if last_seen else "Never"

        entries.append(
            ConnectorHealthEntry(
                id=c.id,
                name=c.display_name,
                type=c.connector_type,
                status=status_value,
                uptime=uptime,
                last_check=last_check,
            )
        )
    return entries


@router.get("/{connector_id}", response_model=ConnectorResponse)
async def get_connector(
    connector_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
) -> ConnectorConfig:
    """Retrieve a single connector by ID."""
    result = await db.execute(
        select(ConnectorConfig).where(ConnectorConfig.id == connector_id)
    )
    connector = result.scalar_one_or_none()
    if connector is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Connector not found",
        )
    return connector


@router.patch("/{connector_id}", response_model=ConnectorResponse)
async def update_connector(
    connector_id: uuid.UUID,
    body: ConnectorUpdateRequest,
    db: AsyncSession = Depends(get_db),
) -> ConnectorConfig:
    """Update connector configuration."""
    result = await db.execute(
        select(ConnectorConfig).where(ConnectorConfig.id == connector_id)
    )
    connector = result.scalar_one_or_none()
    if connector is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Connector not found",
        )

    update_data = body.model_dump(exclude_unset=True)

    if "credentials" in update_data:
        connector.encrypted_credentials = encrypt_credentials(
            json.dumps(update_data.pop("credentials"))
        )

    for field, value in update_data.items():
        setattr(connector, field, value)

    await db.flush()
    await db.refresh(connector)
    return connector


@router.delete("/{connector_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_connector(
    connector_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
) -> None:
    """Delete a connector."""
    result = await db.execute(
        select(ConnectorConfig).where(ConnectorConfig.id == connector_id)
    )
    connector = result.scalar_one_or_none()
    if connector is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Connector not found",
        )
    await db.delete(connector)
