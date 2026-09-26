"""Serves the /connectors API: create, list, read, update, delete and test a
user's connector configurations, plus a per-connector health summary derived
from the audit log.

Why it exists: Credentials must be validated against the connector's own
service and stored AES-encrypted, requested scopes checked against the
first-party catalog, and MCP state forgotten on delete; owning those steps here
keeps every connector mutation behind the same ownership check and the same 422
rules.

The connector type is a plain string validated against
``services.connectors.registry`` (plus ``mcp``); ``GET /types`` serves the
registry's catalog so the UI renders its cards from it. A stored row whose type
is no longer registered is listed with ``available: false`` and never offered.
"""

from __future__ import annotations
from typing import Any, Callable, Dict, List, Literal, Optional

import json
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

import structlog
from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field, computed_field
from sqlalchemy import delete as sa_delete
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from api.routes.oauth import session_factory_dependency
from core.database import get_db
from core.security import decrypt_credentials, encrypt_credentials
from core.validation import SafeStr
from models.audit import AuditLog, AuditStatus
from models.connector import (
    CONNECTOR_TYPE_MAX_LENGTH,
    AuthMethod,
    ConnectorConfig,
    ConnectorType,
    PermissionTier,
    connector_type_key,
)
from models.slack_link import SlackChannelLink
from models.user import User
from services.agent.tool_registry import connector_scopes, default_read_scopes
from services.audit import append_auth_event
from services.auth import get_current_user
from services.connectors import oauth as oauth_broker
from services.connectors import registry as connector_registry
from services.connectors.base import BaseConnector
from services.connectors.factory import validate_credentials

logger = structlog.get_logger(__name__)

router = APIRouter(prefix="/connectors", tags=["connectors"])

# Shape of a connector key. Checked before the registry lookup so a
# rejected value is safe to echo back in the 422 detail.
_CONNECTOR_TYPE_PATTERN = rf"^[a-z][a-z0-9_]{{0,{CONNECTOR_TYPE_MAX_LENGTH - 1}}}$"

_UNAVAILABLE_DETAIL = (
    "This connector type is no longer available on this server, so the "
    "agent cannot use it. Delete it, or restore the version that provides it."
)


def connector_type_available(connector_type: str | ConnectorType) -> bool:
    """True when rows of this type can be created, offered to the agent and
    dispatched: a registered connector or an MCP server.

    ``custom`` is not available (nothing can produce tools for it), and
    neither is a stored type whose connector was removed from the registry.
    """
    key = connector_type_key(connector_type)
    return key == ConnectorType.mcp.value or connector_registry.is_registered(key)


def _is_unknown_type(connector_type: str | ConnectorType) -> bool:
    """A stored type this server does not know at all (neither available
    nor the legacy ``custom`` placeholder)."""
    key = connector_type_key(connector_type)
    return key != ConnectorType.custom.value and not connector_type_available(key)


def _creatable_types() -> list[str]:
    keys = {definition.key for definition in connector_registry.REGISTRY}
    return sorted(keys | {ConnectorType.mcp.value})


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
    # A registry key or "mcp"; the registry check happens in the route so
    # the 422 can name the supported types.
    connector_type: str = Field(
        ...,
        min_length=1,
        max_length=CONNECTOR_TYPE_MAX_LENGTH,
        pattern=_CONNECTOR_TYPE_PATTERN,
    )
    display_name: SafeStr = Field(..., min_length=1, max_length=255)
    auth_method: AuthMethod
    credentials: dict
    granted_scopes: list[SafeStr] = Field(default_factory=list, max_length=64)
    permission_tier: PermissionTier = PermissionTier.user_confirm
    rate_limit_per_minute: int = Field(default=30, ge=1, le=600)


class ConnectorResponse(BaseModel):
    id: uuid.UUID
    user_id: uuid.UUID
    connector_type: str
    display_name: str
    is_active: bool
    auth_method: AuthMethod
    granted_scopes: list[str]
    permission_tier: PermissionTier
    rate_limit_per_minute: int
    created_at: datetime
    updated_at: datetime
    # True when the provider refused this sign-in's refresh token, so the
    # card shows "Needs reconnect". Set by ``_connector_response``.
    needs_reconnect: bool = False

    model_config = {"from_attributes": True}

    @computed_field  # type: ignore[prop-decorator]
    @property
    def available(self) -> bool:
        """False for a stored row whose type this server can no longer use
        (its connector left the registry, or the legacy ``custom``). Such a
        row is listed so the user can delete it, and is never offered."""
        return connector_type_available(self.connector_type)


def _connector_response(row: ConnectorConfig) -> ConnectorResponse:
    """The API view of *row*. Only a signed-in (OAuth) row can carry the
    broker's needs-reconnect flag, so only those are decrypted."""
    response = ConnectorResponse.model_validate(row)
    if row.auth_method == AuthMethod.oauth2:
        try:
            credentials = json.loads(decrypt_credentials(row.encrypted_credentials))
        except Exception:  # noqa: BLE001 - an unreadable blob is not a reconnect hint
            credentials = None
        if isinstance(credentials, dict):
            response.needs_reconnect = oauth_broker.needs_reconnect(credentials)
    return response


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
    request: Request,
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
    if not connector_type_available(body.connector_type):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=(
                f"Unknown connector type '{body.connector_type}'. "
                f"Supported: {', '.join(_creatable_types())}."
            ),
        )

    problems = validate_credentials(body.connector_type, body.credentials)
    if problems:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="; ".join(problems),
        )

    _validate_scopes(body.connector_type, body.granted_scopes)

    encrypted = encrypt_credentials(json.dumps(body.credentials))
    granted_scopes = body.granted_scopes or default_read_scopes(body.connector_type)

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
    await _reconcile_slack_channels(request, db, connector.connector_type)
    return connector


@router.get("/", response_model=list[ConnectorResponse])
async def list_connectors(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> list[ConnectorResponse]:
    """List the authenticated user's connectors."""
    result = await db.execute(
        select(ConnectorConfig).where(ConnectorConfig.user_id == current_user.id)
    )
    return [_connector_response(row) for row in result.scalars().all()]


@router.get("/types")
async def list_connector_types(
    current_user: User = Depends(get_current_user),
) -> list[dict[str, Any]]:
    """The connector catalog the UI renders its cards and forms from.

    Served verbatim from ``services.connectors.registry`` so there is one
    description of every connector. Declared before ``/{connector_id}`` so
    "types" is never parsed as a connector id. Requires a signed-in user
    like every other connector route, though it holds no per-user data.
    """
    return connector_registry.connector_types_payload()


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
    type: str
    status: HealthStatus
    # False when the row's type is no longer usable here (see
    # ConnectorResponse.available); such a row reads "unhealthy".
    available: bool = True
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
        connector_type_key(c.connector_type) for c in connectors
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
            type_key = connector_type_key(c.connector_type)
            last_seen = last_seen_by_name.get(
                c.display_name
            ) or last_seen_by_name.get(type_key)
            counts = observed_by_name.get(c.display_name) or observed_by_name.get(
                type_key
            ) or _Observations()
            failed_recently = counts.refused > 0
            observed_recently = counts.total > 0

        unknown_type = _is_unknown_type(c.connector_type)
        if unknown_type:
            status_value: HealthStatus = "unhealthy"
            detail = _UNAVAILABLE_DETAIL
        elif not c.is_active:
            status_value = "unhealthy"
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
                type=connector_type_key(c.connector_type),
                status=status_value,
                available=connector_type_available(c.connector_type),
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
) -> ConnectorResponse:
    """Retrieve a single connector owned by the authenticated user."""
    return _connector_response(await _get_owned_connector(connector_id, current_user, db))


@router.patch("/{connector_id}", response_model=ConnectorResponse)
async def update_connector(
    connector_id: uuid.UUID,
    body: ConnectorUpdateRequest,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> ConnectorResponse:
    """Update connector configuration."""
    connector = await _get_owned_connector(connector_id, current_user, db)

    update_data = body.model_dump(exclude_unset=True)
    type_key = connector_type_key(connector.connector_type)

    if _is_unknown_type(type_key) and (
        update_data.get("granted_scopes") is not None or "credentials" in update_data
    ):
        # With no catalog there is nothing to validate scopes or
        # credentials against; renaming, disabling or deleting still work.
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=_UNAVAILABLE_DETAIL,
        )

    if update_data.get("granted_scopes") is not None:
        _validate_scopes(type_key, update_data["granted_scopes"])

    if "credentials" in update_data:
        credentials = update_data.pop("credentials") or {}
        # The same gate POST applies. Without it an edit could store a
        # credential blob the connector can never use — and the failure
        # then surfaces at tool-call time, far from the change that caused
        # it.
        problems = validate_credentials(type_key, credentials)
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
    await _reconcile_slack_channels(request, db, type_key)
    return _connector_response(connector)


async def _reconcile_slack_channels(
    request: Request, db: AsyncSession, connector_type: str | ConnectorType
) -> None:
    """After a Slack connector is created, edited or deleted, have the Slack
    manager (services/notifications/slack_manager.py) start, restart or stop
    its DM channel. The change is committed first, since the manager reads
    with its own session; the reconcile then runs in the background and a
    failure to schedule it is logged, never turned into an error response."""
    if connector_type_key(connector_type) != "slack":
        return
    manager = getattr(request.app.state, "slack_manager", None)
    if manager is None:
        return
    await db.commit()
    try:
        manager.schedule_reconcile()
    except Exception as exc:
        logger.warning("slack_reconcile_schedule_failed", error_type=type(exc).__name__)


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


def supports_revoke(connector_type: str | ConnectorType) -> bool:
    """True when the connector's class declares ``SUPPORTS_REVOKE`` (its
    ``revoke`` really calls the provider), so a revoke is worth scheduling;
    its outcome is audited by the broker. MCP, retired types and classes
    whose provider offers no revoke are skipped."""
    definition = connector_registry.get_definition(connector_type_key(connector_type))
    return definition is not None and definition.connector_class.SUPPORTS_REVOKE


def _stored_credentials(encrypted: bytes) -> Optional[dict[str, Any]]:
    """Decrypt and parse a credentials blob; None when it holds nothing."""
    credentials = json.loads(decrypt_credentials(encrypted))
    return credentials if isinstance(credentials, dict) and credentials else None


def revocable_credentials(connector: ConnectorConfig) -> Optional[dict[str, Any]]:
    """The decrypted credentials to revoke once *connector* is deleted.

    None when its type cannot revoke or the stored blob is unreadable (a
    rotated ENCRYPTION_KEY): the deletion then simply goes ahead. Read
    before the delete, since the row is gone afterwards.
    """
    if not supports_revoke(connector.connector_type):
        return None
    try:
        return _stored_credentials(connector.encrypted_credentials)
    except Exception as exc:
        logger.warning(
            "connector_revoke_credentials_unreadable",
            connector_id=str(connector.id),
            error_type=type(exc).__name__,
        )
        return None


# Stored credential keys whose value a provider revoke invalidates.
_GRANT_TOKEN_KEYS = ("access_token", "refresh_token", "bot_token", "user_token")


def grant_markers(credentials: dict[str, Any]) -> frozenset[tuple[str, str]]:
    """What ties *credentials* to a provider grant another row may share.

    Every stored token value (a Slack bot token is one per app and workspace,
    so connectors sharing a Slack app hold the same one), plus the broker's
    OAuth provider: every broker row signs in through this install's single
    OAuth client, and Google revokes the whole grant of an account and
    client, so two broker rows may share a grant through different tokens.
    The Google account is not recorded, so such rows count as shared.
    """
    markers = {
        ("token", value)
        for key in _GRANT_TOKEN_KEYS
        if isinstance(value := credentials.get(key), str) and value
    }
    provider = credentials.get("oauth_provider")
    if isinstance(provider, str) and provider:
        markers.add(("oauth_provider", provider))
    return frozenset(markers)


async def revoke_is_shared(
    db: AsyncSession,
    connector_type: str | ConnectorType,
    credentials: dict[str, Any],
    *,
    exclude_ids: tuple[uuid.UUID, ...] = (),
    exclude_user_id: Optional[uuid.UUID] = None,
) -> bool:
    """True when a remaining connector (of any user) of the same type uses
    the grant *credentials* belong to, so revoking it would silently break
    that connector. Rows in *exclude_ids*, or owned by *exclude_user_id*,
    are the ones being deleted. Rows whose credentials cannot be read are
    unusable anyway and do not count."""
    markers = grant_markers(credentials)
    if not markers:
        return False
    query = select(ConnectorConfig.encrypted_credentials).where(
        ConnectorConfig.connector_type == connector_type_key(connector_type)
    )
    if exclude_ids:
        query = query.where(ConnectorConfig.id.notin_(exclude_ids))
    if exclude_user_id is not None:
        query = query.where(ConnectorConfig.user_id != exclude_user_id)
    for encrypted in (await db.execute(query)).scalars():
        try:
            other = _stored_credentials(encrypted)
        except Exception:
            continue
        if other is not None and markers & grant_markers(other):
            return True
    return False


@router.delete("/{connector_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_connector(
    connector_id: uuid.UUID,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
    session_factory: Callable[[], AsyncSession] = Depends(session_factory_dependency),
) -> None:
    """Delete a connector owned by the authenticated user, then revoke its
    grant at the provider (best effort) and audit the deletion.

    The delete is committed BEFORE the revoke is scheduled: revoking first
    and then failing the commit would leave a live row with dead
    credentials. The revoke task audits its own outcome. A grant another
    connector still uses is left alone (audited as ``skipped_shared``).
    """
    connector = await _get_owned_connector(connector_id, current_user, db)
    type_key = connector_type_key(connector.connector_type)
    credentials = revocable_credentials(connector)
    revoke = "not_supported"
    if credentials is not None and await revoke_is_shared(
        db, type_key, credentials, exclude_ids=(connector.id,)
    ):
        credentials, revoke = None, "skipped_shared"
    if type_key == "slack":
        # Its DM link holds a Slack user id: removed explicitly, since a
        # SQLite database without foreign key enforcement would keep it.
        await db.execute(
            sa_delete(SlackChannelLink).where(SlackChannelLink.connector_id == connector.id)
        )
    await db.delete(connector)
    _forget_mcp_state(connector)
    await db.commit()
    await _reconcile_slack_channels(request, db, type_key)

    if credentials is not None:
        task = oauth_broker.schedule_revoke(
            type_key, credentials, user_id=current_user.id, session_factory=session_factory
        )
        revoke = "scheduled" if task is not None else "not_scheduled"

    try:
        await append_auth_event(
            db,
            user_id=current_user.id,
            action="connector_deleted",
            status=AuditStatus.approved,
            endpoint="/api/connectors",
            reason=f"revoke {revoke}",
            details={
                "connector_type": type_key,
                "connector_id": str(connector_id),
                "revoke": revoke,
            },
        )
        await db.commit()
    except Exception as exc:
        # The connector is already gone; a failed audit write must not turn
        # a completed deletion into an error response.
        await db.rollback()
        logger.error(
            "connector_delete_audit_failed",
            connector_id=str(connector_id),
            error_type=type(exc).__name__,
        )


class ConnectorTestResult(BaseModel):
    ok: bool
    detail: str


@router.post("/{connector_id}/test", response_model=ConnectorTestResult)
async def test_connector(
    connector_id: uuid.UUID,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
    session_factory: Callable[[], AsyncSession] = Depends(session_factory_dependency),
) -> ConnectorTestResult:
    """Verify stored credentials against the live service.

    Decrypts the connector's credentials, authenticates, and runs the
    connector's health check — all under the deny-by-default network
    policy. Nothing is modified on the remote service.

    A broker-made OAuth row whose access token is expiring is refreshed
    first, and a token the connector rotated during the probe (a legacy
    Google or Canvas refresh) is persisted afterwards. Each happens at
    most once per test, so a failing health check never loops.
    """
    from services.connectors.base import AuthenticationError, ConnectorError
    from services.connectors.factory import create_connector

    row = await _get_owned_connector(connector_id, current_user, db)

    if row.connector_type == ConnectorType.custom:
        return ConnectorTestResult(
            ok=False, detail="Custom connectors do not support automated tests yet."
        )
    if not connector_type_available(row.connector_type):
        return ConnectorTestResult(ok=False, detail=_UNAVAILABLE_DETAIL)

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

    type_key = connector_type_key(row.connector_type)
    try:
        credentials = await oauth_broker.ensure_fresh_credentials(
            session_factory,
            config_id=row.id,
            connector_type=type_key,
            credentials=credentials,
        )
    except AuthenticationError as exc:
        return ConnectorTestResult(ok=False, detail=f"Authentication failed: {exc}")
    except ConnectorError as exc:
        return ConnectorTestResult(ok=False, detail=str(exc))

    try:
        connector = create_connector(
            type_key,
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
        # Only the type: an unexpected error's text can carry a URL with a
        # token in it.
        logger.error(
            "connector_test_unexpected_error",
            connector_type=type_key,
            error_type=type(exc).__name__,
        )
        return ConnectorTestResult(
            ok=False, detail=f"Connection test failed ({type(exc).__name__})."
        )
    finally:
        await _persist_rotated_credentials(
            connector, credentials, row.id, type_key, session_factory
        )
        await connector.close()


async def _persist_rotated_credentials(
    connector: BaseConnector,
    credentials: dict[str, Any],
    config_id: uuid.UUID,
    type_key: str,
    session_factory: Callable[[], AsyncSession],
) -> None:
    """Store the tokens *connector* rotated during a test (a legacy Google
    or Canvas refresh), compared with the credentials the test used. A
    failure is logged, never raised: the test result stands either way."""
    try:
        rotated = connector.updated_credentials(credentials)
        if rotated:
            await oauth_broker.persist_credentials(session_factory, config_id, rotated)
    except Exception as exc:
        logger.warning(
            "connector_test_persist_failed",
            connector_type=type_key,
            error_type=type(exc).__name__,
        )
