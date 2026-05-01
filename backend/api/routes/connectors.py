"""Connector configuration API.

All endpoints require an authenticated user. ``user_id`` is ALWAYS derived
from the bearer token via :func:`services.auth.get_current_user` — never
trusted from request body or query string. This is a P0 IDOR fix.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from datetime import datetime
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession

from core.database import get_db
from core.security import encrypt_credentials
from models.connector import (
    AuthMethod,
    ConnectorConfig,
    ConnectorType,
    PermissionTier,
)
from models.user import User
from services.audit import AuditService
from services.auth import get_current_user

router = APIRouter(prefix="/connectors", tags=["connectors"])


# ── Schemas ───────────────────────────────────────────────────────────────


class ConnectorCreate(BaseModel):
    """Input for creating a connector. Note: NO ``user_id`` field — that
    is derived from the authenticated bearer token."""

    connector_type: ConnectorType
    display_name: str = Field(..., min_length=1, max_length=255)
    auth_method: AuthMethod
    credentials: dict
    granted_scopes: List[str] = Field(default_factory=list)
    permission_tier: PermissionTier = PermissionTier.user_confirm
    rate_limit_per_minute: int = Field(default=30, ge=1, le=600)

    @field_validator("granted_scopes")
    @classmethod
    def _validate_scopes(cls, v: List[str]) -> List[str]:
        if len(v) > 50:
            raise ValueError("granted_scopes may not contain more than 50 entries")
        for scope in v:
            if not isinstance(scope, str):
                raise ValueError("each scope must be a string")
            if len(scope) > 100:
                raise ValueError("scope strings may not exceed 100 characters")
        return v


class ConnectorUpdate(BaseModel):
    display_name: Optional[str] = Field(default=None, min_length=1, max_length=255)
    is_active: Optional[bool] = None
    credentials: Optional[dict] = None
    granted_scopes: Optional[List[str]] = None
    permission_tier: Optional[PermissionTier] = None
    rate_limit_per_minute: Optional[int] = Field(default=None, ge=1, le=600)

    @field_validator("granted_scopes")
    @classmethod
    def _validate_scopes(cls, v: Optional[List[str]]) -> Optional[List[str]]:
        if v is None:
            return v
        if len(v) > 50:
            raise ValueError("granted_scopes may not contain more than 50 entries")
        for scope in v:
            if not isinstance(scope, str):
                raise ValueError("each scope must be a string")
            if len(scope) > 100:
                raise ValueError("scope strings may not exceed 100 characters")
        return v


class ConnectorOut(BaseModel):
    """Public-facing connector view. Never exposes ``encrypted_credentials``."""

    id: uuid.UUID
    connector_type: ConnectorType
    name: str
    scopes: List[str]
    permission_tier: PermissionTier
    is_enabled: bool
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}

    @classmethod
    def from_model(cls, connector: ConnectorConfig) -> "ConnectorOut":
        return cls(
            id=connector.id,
            connector_type=connector.connector_type,
            name=connector.display_name,
            scopes=list(connector.granted_scopes or []),
            permission_tier=connector.permission_tier,
            is_enabled=connector.is_active,
            created_at=connector.created_at,
            updated_at=connector.updated_at,
        )


# ── Helpers ───────────────────────────────────────────────────────────────


def _redact_credentials_for_audit(credentials: dict | None) -> dict:
    """Return a redacted summary of credentials safe for audit logs.

    Never logs raw credential material — produces a SHA-256 fingerprint and
    the set of keys, nothing more.
    """
    if not credentials:
        return {"keys": [], "fingerprint": None}
    try:
        keys = sorted(str(k) for k in credentials.keys())
    except AttributeError:
        keys = []
    try:
        raw = json.dumps(credentials, sort_keys=True, default=str).encode("utf-8")
        fingerprint = hashlib.sha256(raw).hexdigest()[:16]
    except (TypeError, ValueError):
        fingerprint = None
    return {"keys": keys, "fingerprint": fingerprint}


def _validate_scopes_against_connector(
    connector_type: ConnectorType, granted_scopes: List[str]
) -> None:
    """Validate granted scopes against the connector class registry.

    TODO: Wire this up once the connector class registry exposes
    ``required_scopes`` / ``allowed_scopes`` for each connector type.
    For now this is a no-op safety net — the Pydantic validators on
    ``ConnectorCreate`` / ``ConnectorUpdate`` already cap list size and
    string length.
    """
    return None


async def _audit_safe(
    db: AsyncSession,
    *,
    user_id: uuid.UUID,
    action: str,
    endpoint: str,
    request_data: dict,
) -> None:
    """Best-effort audit logging — never blocks the primary request."""
    try:
        from models.audit import AuditStatus

        service = AuditService(db)
        # AuditStatus enum values are lowercase strings.
        await service.log_action(
            user_id=str(user_id),
            connector_name="connectors_api",
            action=action,
            endpoint=endpoint,
            scope_used="connectors:write",
            status=AuditStatus.APPROVED,
            request_data=request_data,
        )
    except Exception:
        # Audit failure must never block the API operation.
        pass


# ── Endpoints ─────────────────────────────────────────────────────────────


@router.post(
    "/",
    response_model=ConnectorOut,
    status_code=status.HTTP_201_CREATED,
)
async def create_connector(
    body: ConnectorCreate,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> ConnectorOut:
    """Create a connector owned by the authenticated user."""
    _validate_scopes_against_connector(body.connector_type, body.granted_scopes)

    try:
        encrypted = encrypt_credentials(json.dumps(body.credentials))

        connector = ConnectorConfig(
            user_id=current_user.id,
            connector_type=body.connector_type,
            display_name=body.display_name,
            auth_method=body.auth_method,
            encrypted_credentials=encrypted,
            granted_scopes=body.granted_scopes,
            permission_tier=body.permission_tier,
            rate_limit_per_minute=body.rate_limit_per_minute,
        )
        db.add(connector)
        await db.commit()
        await db.refresh(connector)
    except SQLAlchemyError:
        await db.rollback()
        raise

    await _audit_safe(
        db,
        user_id=current_user.id,
        action="connector.create",
        endpoint=str(request.url.path),
        request_data={
            "connector_type": body.connector_type.value,
            "display_name": body.display_name,
            "auth_method": body.auth_method.value,
            "granted_scopes": list(body.granted_scopes),
            "permission_tier": body.permission_tier.value,
            "credentials": _redact_credentials_for_audit(body.credentials),
        },
    )

    return ConnectorOut.from_model(connector)


@router.get("/", response_model=List[ConnectorOut])
async def list_connectors(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> List[ConnectorOut]:
    """List the current user's connectors only."""
    result = await db.execute(
        select(ConnectorConfig).where(ConnectorConfig.user_id == current_user.id)
    )
    rows = result.scalars().all()
    return [ConnectorOut.from_model(c) for c in rows]


@router.get("/{connector_id}", response_model=ConnectorOut)
async def get_connector(
    connector_id: uuid.UUID,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> ConnectorOut:
    """Retrieve a single connector belonging to the current user.

    Returns 404 (not 403) when the connector exists but is owned by
    another user, to avoid leaking row existence.
    """
    result = await db.execute(
        select(ConnectorConfig).where(
            ConnectorConfig.id == connector_id,
            ConnectorConfig.user_id == current_user.id,
        )
    )
    connector = result.scalar_one_or_none()
    if connector is None:
        raise HTTPException(status_code=404, detail="Connector not found")
    return ConnectorOut.from_model(connector)


@router.patch("/{connector_id}", response_model=ConnectorOut)
async def update_connector(
    connector_id: uuid.UUID,
    body: ConnectorUpdate,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> ConnectorOut:
    """Update a connector owned by the current user."""
    result = await db.execute(
        select(ConnectorConfig).where(
            ConnectorConfig.id == connector_id,
            ConnectorConfig.user_id == current_user.id,
        )
    )
    connector = result.scalar_one_or_none()
    if connector is None:
        raise HTTPException(status_code=404, detail="Connector not found")

    update_data = body.model_dump(exclude_unset=True)

    if "granted_scopes" in update_data and update_data["granted_scopes"] is not None:
        _validate_scopes_against_connector(
            connector.connector_type, update_data["granted_scopes"]
        )

    creds_redacted: dict | None = None

    try:
        if "credentials" in update_data:
            creds = update_data.pop("credentials")
            creds_redacted = _redact_credentials_for_audit(creds)
            connector.encrypted_credentials = encrypt_credentials(json.dumps(creds))

        for field, value in update_data.items():
            setattr(connector, field, value)

        await db.commit()
        await db.refresh(connector)
    except SQLAlchemyError:
        await db.rollback()
        raise

    audit_payload: dict = {k: v for k, v in update_data.items()}
    if creds_redacted is not None:
        audit_payload["credentials"] = creds_redacted

    await _audit_safe(
        db,
        user_id=current_user.id,
        action="connector.update",
        endpoint=str(request.url.path),
        request_data=audit_payload,
    )

    return ConnectorOut.from_model(connector)


@router.delete("/{connector_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_connector(
    connector_id: uuid.UUID,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> None:
    """Delete a connector owned by the current user."""
    result = await db.execute(
        select(ConnectorConfig).where(
            ConnectorConfig.id == connector_id,
            ConnectorConfig.user_id == current_user.id,
        )
    )
    connector = result.scalar_one_or_none()
    if connector is None:
        raise HTTPException(status_code=404, detail="Connector not found")

    try:
        await db.delete(connector)
        await db.commit()
    except SQLAlchemyError:
        await db.rollback()
        raise

    await _audit_safe(
        db,
        user_id=current_user.id,
        action="connector.delete",
        endpoint=str(request.url.path),
        request_data={"connector_id": str(connector_id)},
    )
