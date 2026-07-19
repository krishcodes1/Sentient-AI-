from __future__ import annotations
from typing import Dict, List, Literal, Optional

import json
import uuid
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from core.database import get_db
from core.security import encrypt_credentials
from models.audit import AuditLog
from models.connector import (
    AuthMethod,
    ConnectorConfig,
    ConnectorType,
    PermissionTier,
)
from models.user import User
from services.agent.tool_registry import default_read_scopes
from services.auth import get_current_user
from services.connectors.factory import validate_credentials

router = APIRouter(prefix="/connectors", tags=["connectors"])


# Identity comes exclusively from the verified JWT (get_current_user).
# Connector rows are always scoped to the authenticated user: creating for,
# reading, modifying, or deleting another user's connector is impossible by
# construction (queries filter on user_id), and lookups for rows the caller
# does not own return 404 so connector ids are not enumerable.


class ConnectorCreateRequest(BaseModel):
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


async def _get_owned_connector(
    connector_id: uuid.UUID,
    user: User,
    db: AsyncSession,
) -> ConnectorConfig:
    """Load a connector and verify ownership (404 on missing or not owned)."""
    result = await db.execute(
        select(ConnectorConfig).where(
            ConnectorConfig.id == connector_id,
            ConnectorConfig.user_id == user.id,
        )
    )
    connector = result.scalar_one_or_none()
    if connector is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Connector not found",
        )
    return connector


@router.post(
    "/",
    response_model=ConnectorResponse,
    status_code=status.HTTP_201_CREATED,
)
async def create_connector(
    body: ConnectorCreateRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> ConnectorConfig:
    """Register a new external connector with encrypted credentials.

    When no scopes are chosen the connector defaults to its read-only
    scope set (least privilege); write scopes must be granted explicitly.
    """
    # 'custom' is reserved for forward compatibility: no code path can
    # produce tools, dispatch, or test such a connector yet, so storing
    # credentials for one would be a dead end. Reject creation outright.
    if body.connector_type == ConnectorType.custom:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="custom connectors are not yet supported",
        )

    problems = validate_credentials(body.connector_type.value, body.credentials)
    if problems:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="; ".join(problems),
        )

    encrypted = encrypt_credentials(json.dumps(body.credentials))
    granted_scopes = body.granted_scopes or default_read_scopes(
        body.connector_type.value
    )

    connector = ConnectorConfig(
        user_id=current_user.id,
        connector_type=body.connector_type,
        display_name=body.display_name,
        auth_method=body.auth_method,
        encrypted_credentials=encrypted,
        granted_scopes=granted_scopes,
        permission_tier=body.permission_tier,
        rate_limit_per_minute=body.rate_limit_per_minute,
    )
    db.add(connector)
    await db.flush()
    await db.refresh(connector)
    return connector


@router.get("/", response_model=list[ConnectorResponse])
async def list_connectors(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> list[ConnectorConfig]:
    """List the authenticated user's connectors."""
    result = await db.execute(
        select(ConnectorConfig).where(ConnectorConfig.user_id == current_user.id)
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
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> list[ConnectorHealthEntry]:
    """Derive a per-connector health summary for the authenticated user.

    Status rules (no third-party network calls; this is platform-level
    health, not the remote service's health):
    - ``unhealthy``: connector is disabled (``is_active = False``)
    - ``degraded``: enabled but no observed activity in the last 24h
    - ``healthy``:  enabled and used in the last 24h

    First-party connectors derive activity from the audit log. MCP rows
    cannot (the audit logger stores them under ``connector_name="mcp"``,
    not the display name), so they use the in-process MCP activity
    registry populated by discovery/dispatch/tests instead.
    """
    conn_result = await db.execute(
        select(ConnectorConfig).where(ConnectorConfig.user_id == current_user.id)
    )
    connectors = list(conn_result.scalars().all())

    if not connectors:
        return []

    # Audit rows usually record the connector segment of the tool name
    # ("canvas", "google_workspace", ...) rather than the display name, so
    # match on both.
    names = {c.display_name for c in connectors} | {
        c.connector_type.value for c in connectors
    }
    audit_result = await db.execute(
        select(AuditLog)
        .where(AuditLog.user_id == current_user.id)
        .where(AuditLog.connector_name.in_(names))
        .order_by(AuditLog.timestamp.desc())
    )
    audit_rows = list(audit_result.scalars().all())

    last_seen_by_name: Dict[str, datetime] = {}
    for row in audit_rows:
        if row.connector_name not in last_seen_by_name:
            last_seen_by_name[row.connector_name] = row.timestamp

    from services.mcp.activity import mcp_activity

    now = datetime.now(timezone.utc)
    entries: list[ConnectorHealthEntry] = []
    for c in connectors:
        if c.connector_type == ConnectorType.mcp:
            activity = mcp_activity.get(c.id)
            last_seen = activity.last_success if activity else None
        else:
            # Audit rows record the connector segment of the tool name
            # (e.g. "canvas" from "canvas.submit_assignment"), so fall back
            # to the connector type when no row matches the display name.
            last_seen = last_seen_by_name.get(
                c.display_name
            ) or last_seen_by_name.get(c.connector_type.value)

        if not c.is_active:
            status_value: HealthStatus = "unhealthy"
            uptime = 0.0
        elif last_seen is None or (now - _as_utc(last_seen)) > _DEGRADED_AFTER:
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


def _as_utc(dt: datetime) -> datetime:
    """Normalize naive timestamps (SQLite test backend) to UTC-aware."""
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt


@router.get("/{connector_id}", response_model=ConnectorResponse)
async def get_connector(
    connector_id: uuid.UUID,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> ConnectorConfig:
    """Retrieve a single connector owned by the authenticated user."""
    return await _get_owned_connector(connector_id, current_user, db)


@router.patch("/{connector_id}", response_model=ConnectorResponse)
async def update_connector(
    connector_id: uuid.UUID,
    body: ConnectorUpdateRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> ConnectorConfig:
    """Update connector configuration."""
    connector = await _get_owned_connector(connector_id, current_user, db)

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
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> None:
    """Delete a connector owned by the authenticated user."""
    connector = await _get_owned_connector(connector_id, current_user, db)
    await db.delete(connector)


class ConnectorTestResult(BaseModel):
    ok: bool
    detail: str


@router.post("/{connector_id}/test", response_model=ConnectorTestResult)
async def test_connector(
    connector_id: uuid.UUID,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> ConnectorTestResult:
    """Verify stored credentials against the live service.

    Decrypts the connector's credentials, authenticates, and runs the
    connector's health check — all under the deny-by-default network
    policy. Nothing is modified on the remote service.
    """
    from core.security import decrypt_credentials
    from services.connectors.base import AuthenticationError, ConnectorError
    from services.connectors.factory import create_connector

    row = await _get_owned_connector(connector_id, current_user, db)

    if row.connector_type == ConnectorType.custom:
        return ConnectorTestResult(
            ok=False, detail="Custom connectors do not support automated tests yet."
        )

    try:
        credentials = json.loads(decrypt_credentials(row.encrypted_credentials))
    except Exception:
        return ConnectorTestResult(
            ok=False,
            detail="Stored credentials could not be decrypted. Re-enter them to fix.",
        )

    if row.connector_type == ConnectorType.mcp:
        from services.mcp.activity import mcp_activity
        from services.mcp.client import HttpMCPTransport, MCPClient, MCPError

        client = MCPClient(
            HttpMCPTransport(
                str(credentials.get("url", "")),
                headers=dict(credentials.get("headers") or {}),
            )
        )
        try:
            tools = await client.list_tools()
            mcp_activity.record_success(row.id)
            return ConnectorTestResult(
                ok=True,
                detail=f"Connected. Server advertises {len(tools)} tool(s).",
            )
        except MCPError as exc:
            mcp_activity.record_error(row.id, str(exc))
            return ConnectorTestResult(ok=False, detail=str(exc))
        except Exception as exc:
            mcp_activity.record_error(row.id, str(exc))
            return ConnectorTestResult(ok=False, detail=f"Connection test failed: {exc}")
        finally:
            await client.close()

    try:
        connector = create_connector(
            row.connector_type.value,
            credentials,
            rate_limit=row.rate_limit_per_minute,
        )
    except ConnectorError as exc:
        return ConnectorTestResult(ok=False, detail=str(exc))

    try:
        await connector.authenticate(credentials)
        healthy = await connector.health_check()
        if healthy:
            return ConnectorTestResult(ok=True, detail="Connection verified.")
        return ConnectorTestResult(
            ok=False, detail="Authenticated, but the service health check failed."
        )
    except AuthenticationError as exc:
        return ConnectorTestResult(ok=False, detail=f"Authentication failed: {exc}")
    except ConnectorError as exc:
        return ConnectorTestResult(ok=False, detail=str(exc))
    except Exception as exc:
        return ConnectorTestResult(ok=False, detail=f"Connection test failed: {exc}")
    finally:
        await connector.close()
