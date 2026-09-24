"""Serves the /connectors API: create, list, read, update, delete and test a
user's connector configurations, plus a per-connector health summary derived
from the audit log.

Why it exists: Credentials must be validated against the connector's own
service and stored AES-encrypted, requested scopes checked against the
first-party catalog, and MCP state forgotten on delete; owning those steps here
keeps every connector mutation behind the same ownership check and the same 422
rules.
"""

from __future__ import annotations
from typing import Dict, List, Literal, Optional

import json
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from core.database import get_db
from core.security import encrypt_credentials
from core.validation import SafeStr
from models.audit import AuditLog, AuditStatus
from models.connector import (
    AuthMethod,
    ConnectorConfig,
    ConnectorType,
    PermissionTier,
)
from models.user import User
from services.agent.tool_registry import connector_scopes, default_read_scopes
from services.auth import get_current_user
from services.connectors.factory import validate_credentials

router = APIRouter(prefix="/connectors", tags=["connectors"])


def _validate_scopes(connector_type: str, scopes: list[str]) -> None:
    """Reject scopes that are not in a first-party connector's catalog.

    MCP servers expose dynamic, per-server tools, so their scope names are
    not knowable ahead of time and are left unvalidated. For Canvas, Google
    Workspace, and Robinhood the catalog is fixed: an unknown scope is a
    typo or an attempt to grant something that does not exist, and is
    inert at dispatch anyway, so reject it up front with a clear 422.
    Financial scopes (e.g. crypto.trade) are intentionally absent from the
    catalog and therefore rejected here too.
    """
    catalog = connector_scopes(connector_type)
    known = set(catalog["read"]) | set(catalog["write"])
    if not known:
        # Unknown/dynamic connector type (mcp) — nothing to validate against.
        return
    unknown = sorted(s for s in scopes if s not in known)
    if unknown:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=(
                f"Unknown scope(s) for {connector_type}: {', '.join(unknown)}. "
                f"Allowed: {', '.join(sorted(known))}."
            ),
        )


# Identity comes exclusively from the verified JWT (get_current_user).
# Connector rows are always scoped to the authenticated user: creating for,
# reading, modifying, or deleting another user's connector is impossible by
# construction (queries filter on user_id), and lookups for rows the caller
# does not own return 404 so connector ids are not enumerable.


class ConnectorCreateRequest(BaseModel):
    connector_type: ConnectorType
    display_name: SafeStr = Field(..., min_length=1, max_length=255)
    auth_method: AuthMethod
    credentials: dict
    granted_scopes: list[SafeStr] = Field(default_factory=list, max_length=64)
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
    display_name: Optional[SafeStr] = Field(default=None, min_length=1, max_length=255)
    is_active: Optional[bool] = None
    credentials: Optional[dict] = None
    granted_scopes: Optional[List[SafeStr]] = Field(default=None, max_length=64)
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

    _validate_scopes(body.connector_type.value, body.granted_scopes)

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
_HEALTH_WINDOW = timedelta(hours=24)


@dataclass
class _Observations:
    """Audited outcomes for one connector inside the health window."""

    carried_out: int = 0
    refused: int = 0

    @property
    def total(self) -> int:
        return self.carried_out + self.refused

    @property
    def success_rate(self) -> float:
        if not self.total:
            return 100.0
        return round(100.0 * self.carried_out / self.total, 1)


class ConnectorHealthEntry(BaseModel):
    id: uuid.UUID
    name: str
    type: ConnectorType
    status: HealthStatus
    # Share of this connector's audited actions in the last 24h that the
    # platform carried out rather than refused. It is a measured ratio,
    # not an availability figure: with ``checks_24h == 0`` there is
    # nothing to measure and it reads 100.0, which ``checks_24h`` and
    # ``detail`` are there to qualify.
    uptime: float
    checks_24h: int
    failures_24h: int
    last_check: str
    detail: str


@router.get("/health", response_model=list[ConnectorHealthEntry])
async def get_connector_health(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> list[ConnectorHealthEntry]:
    """Derive a per-connector health summary for the authenticated user.

    Every number here comes from a recorded observation (no third-party
    network calls; this is platform-level health, not the remote
    service's health):
    - ``unhealthy``: connector is disabled (``is_active = False``)
    - ``degraded``:  a failure was observed in the last 24h
    - ``healthy``:   no failure was observed

    A connector nobody has used yet is ``healthy``, not ``degraded``:
    "never called" is not evidence of a problem, and reporting it as one
    told every user their brand-new connector was already failing.

    First-party connectors derive their counts from the audit log: an
    ``approved`` row is one action the platform carried out, a
    ``blocked`` row one it refused. ``pending`` rows are the
    intent-before-side-effect half of an approved action and are skipped,
    so a single tool call counts once. MCP rows cannot use the audit log
    at all (the audit logger stores them under ``connector_name="mcp"``,
    not the display name), so they use the in-process MCP activity
    registry populated by discovery/dispatch/tests instead.
    """
    conn_result = await db.execute(
        select(ConnectorConfig).where(ConnectorConfig.user_id == current_user.id)
    )
    connectors = list(conn_result.scalars().all())

    if not connectors:
        return []

    now = datetime.now(timezone.utc)
    window_start = now - _HEALTH_WINDOW

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
    observed_by_name: Dict[str, _Observations] = {}
    for row in audit_rows:
        if row.connector_name not in last_seen_by_name:
            last_seen_by_name[row.connector_name] = row.timestamp
        if _as_utc(row.timestamp) < window_start:
            continue
        counts = observed_by_name.setdefault(row.connector_name, _Observations())
        if row.status == AuditStatus.approved:
            counts.carried_out += 1
        elif row.status == AuditStatus.blocked:
            counts.refused += 1

    from services.mcp.activity import mcp_activity

    entries: list[ConnectorHealthEntry] = []
    for c in connectors:
        failed_recently = False
        observed_recently = False
        if c.connector_type == ConnectorType.mcp:
            # The registry keeps only the latest outcome of each kind, so
            # an MCP server has no tally to report — only whether the last
            # thing observed was a failure. Its counts stay at zero and
            # ``detail`` says what was actually seen.
            activity = mcp_activity.get(c.id)
            last_seen = activity.last_success if activity else None
            counts = _Observations()
            if activity and activity.last_error:
                failed_recently = _as_utc(activity.last_error) >= window_start and (
                    last_seen is None
                    or _as_utc(activity.last_error) > _as_utc(last_seen)
                )
            observed_recently = (
                last_seen is not None and _as_utc(last_seen) >= window_start
            )
        else:
            # Audit rows record the connector segment of the tool name
            # (e.g. "canvas" from "canvas.submit_assignment"), so fall back
            # to the connector type when no row matches the display name.
            last_seen = last_seen_by_name.get(
                c.display_name
            ) or last_seen_by_name.get(c.connector_type.value)
            counts = observed_by_name.get(c.display_name) or observed_by_name.get(
                c.connector_type.value
            ) or _Observations()
            failed_recently = counts.refused > 0
            observed_recently = counts.total > 0

        if not c.is_active:
            status_value: HealthStatus = "unhealthy"
            detail = "Disabled. Enable it to let the agent use it again."
        elif failed_recently:
            status_value = "degraded"
            detail = (
                f"{counts.refused} of {counts.total} action(s) refused in the "
                "last 24h."
                if counts.total
                else "The most recent call to this server failed."
            )
        elif observed_recently:
            status_value = "healthy"
            detail = (
                f"{counts.total} action(s) in the last 24h, none refused."
                if counts.total
                else "Last call to this server succeeded."
            )
        else:
            status_value = "healthy"
            detail = "No activity in the last 24h."

        last_check = last_seen.isoformat() if last_seen else "Never"

        entries.append(
            ConnectorHealthEntry(
                id=c.id,
                name=c.display_name,
                type=c.connector_type,
                status=status_value,
                uptime=counts.success_rate,
                checks_24h=counts.total,
                failures_24h=counts.refused,
                last_check=last_check,
                detail=detail,
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

    if update_data.get("granted_scopes") is not None:
        _validate_scopes(connector.connector_type.value, update_data["granted_scopes"])

    if "credentials" in update_data:
        credentials = update_data.pop("credentials") or {}
        # The same gate POST applies. Without it an edit could store a
        # credential blob the connector can never use — and the failure
        # then surfaces at tool-call time, far from the change that caused
        # it.
        problems = validate_credentials(connector.connector_type.value, credentials)
        if problems:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail="; ".join(problems),
            )
        connector.encrypted_credentials = encrypt_credentials(json.dumps(credentials))

    for field, value in update_data.items():
        setattr(connector, field, value)

    await db.flush()
    await db.refresh(connector)
    _forget_mcp_state(connector)
    return connector


def _forget_mcp_state(connector: ConnectorConfig) -> None:
    """Drop in-process state tied to an MCP connector's old configuration.

    Tool-name bindings are sticky against a *server* that tries to rebind
    an approved name. They must not outlive the *user* repointing or
    removing the connector: the bindings then name tools on a server that
    is no longer configured, and every call fails until the process
    restarts.
    """
    if connector.connector_type != ConnectorType.mcp:
        return
    from services.mcp.integration import invalidate_mcp_connector

    invalidate_mcp_connector(connector.id)


@router.delete("/{connector_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_connector(
    connector_id: uuid.UUID,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> None:
    """Delete a connector owned by the authenticated user."""
    connector = await _get_owned_connector(connector_id, current_user, db)
    await db.delete(connector)
    _forget_mcp_state(connector)


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

    # Decryption and parsing fail for different reasons and only one of
    # them is fixed by re-entering the credentials, so they must not share
    # a message: a rotated ENCRYPTION_KEY reported as "re-enter them" sends
    # the user round a loop that cannot work.
    try:
        decrypted = decrypt_credentials(row.encrypted_credentials)
    except Exception:
        return ConnectorTestResult(
            ok=False,
            detail=(
                "Stored credentials could not be decrypted — the server's "
                "encryption key has changed since they were saved. Re-enter "
                "them to fix."
            ),
        )
    try:
        credentials = json.loads(decrypted)
        if not isinstance(credentials, dict):
            raise ValueError("credentials are not a JSON object")
    except Exception:
        return ConnectorTestResult(
            ok=False,
            detail="Stored credentials are malformed. Re-enter them to fix.",
        )

    if row.connector_type == ConnectorType.mcp:
        from services.connectors.factory import coerce_header_map
        from services.mcp.activity import mcp_activity
        from services.mcp.client import HttpMCPTransport, MCPClient, MCPError

        headers = coerce_header_map(credentials.get("headers"))
        if headers is None:
            mcp_activity.record_error(row.id, "malformed 'headers' credential")
            return ConnectorTestResult(
                ok=False,
                detail=(
                    "This connector is misconfigured: 'headers' must be an "
                    "object of header name -> value. Re-enter the credentials "
                    "to fix."
                ),
            )

        client = MCPClient(
            HttpMCPTransport(str(credentials.get("url", "")), headers=headers)
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
        # Token-based connectors (Canvas, Google) store the token without a
        # round-trip to the service, so reaching here means the stored
        # credentials did not pass the live health check — most often they are
        # invalid or expired. Do not claim the credentials "authenticated".
        return ConnectorTestResult(
            ok=False,
            detail=(
                "Service health check failed — the stored credentials may be "
                "invalid or expired. Re-enter them to fix."
            ),
        )
    except AuthenticationError as exc:
        return ConnectorTestResult(ok=False, detail=f"Authentication failed: {exc}")
    except ConnectorError as exc:
        return ConnectorTestResult(ok=False, detail=str(exc))
    except Exception as exc:
        return ConnectorTestResult(ok=False, detail=f"Connection test failed: {exc}")
    finally:
        await connector.close()
