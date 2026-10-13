"""Lists and revokes the signed-in user's low-risk grants: the connections they
allowed to make small, undoable changes without an approval card for 7 days
(permission tiers, services/agent/permission_grants.py).

Why it exists: a grant lets starring, labels, drafts, private events and
to-dos run with no card on one account for a week, so the owner must be able
to see every one (which account, until when, last used, how many runs) and end
any of them at once. The Settings page reads and revokes through here;
Telegram's /grants and Slack's "grants" do the same through the store. Each
grant belongs to its user: another user's id is a 404, as an unknown one is.

Connects to: the runtime's PermissionGrantStore (``AgentRuntime.permission_grants``)
and the audit log (``permission_grant_revoked``).
"""

from __future__ import annotations

from typing import Optional

import structlog
from fastapi import APIRouter, Depends, HTTPException, Response, status
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from api.routes.agent import get_runtime
from core.database import get_db
from models.user import User
from services.agent.permission_grants import audit_revoked
from services.agent.runtime import AgentRuntime
from services.auth import get_current_user

logger = structlog.get_logger(__name__)

router = APIRouter(prefix="/agent/permission-grants", tags=["agent"])


class PermissionGrantOut(BaseModel):
    id: str
    connector_id: str
    # The connection's label ("School Gmail") and type ("google_workspace").
    account: str
    connector_type: str
    kind: str
    # "web" | "telegram" | "slack", or None when it was not recorded.
    granted_from: Optional[str] = None
    granted_at: str
    expires_at: str
    last_used_at: Optional[str] = None
    uses: int = 0


@router.get("", response_model=list[PermissionGrantOut])
async def list_permission_grants(
    current_user: User = Depends(get_current_user),
    runtime: AgentRuntime = Depends(get_runtime),
) -> list[PermissionGrantOut]:
    """The user's live low-risk grants, soonest to expire first."""
    grants = await runtime.permission_grants.list_live(str(current_user.id))
    return [
        PermissionGrantOut(
            id=g.id,
            connector_id=g.connector_id,
            account=g.account,
            connector_type=g.connector_type,
            kind=g.kind,
            granted_from=g.granted_from,
            granted_at=g.granted_at.isoformat(),
            expires_at=g.expires_at.isoformat(),
            last_used_at=g.last_used_at.isoformat() if g.last_used_at else None,
            uses=g.uses,
        )
        for g in grants
    ]


@router.delete("/{grant_id}", status_code=status.HTTP_204_NO_CONTENT)
async def revoke_permission_grant(
    grant_id: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
    runtime: AgentRuntime = Depends(get_runtime),
) -> Response:
    """End one grant: that account's next low-risk change gets a card again.
    404 when it is not one of the user's grants. The audit row is best
    effort: revoking only takes a permission away, and must not be undone
    because the log could not be written."""
    revoked = await runtime.permission_grants.revoke(
        user_id=str(current_user.id), grant_id=grant_id
    )
    if revoked is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="No such grant.")
    try:
        await audit_revoked(
            db,
            user_id=current_user.id,
            connector_type=revoked.connector_type,
            endpoint="/api/agent/permission-grants",
            revoked_from="web",
            grant_id=revoked.id,
            connector_id=revoked.connector_id,
        )
    except Exception as exc:
        await db.rollback()
        logger.error("permission_grant_revoke_audit_failed", error_type=type(exc).__name__)
    return Response(status_code=status.HTTP_204_NO_CONTENT)
