"""Lists and revokes the apps the signed-in user allowed Crawler to operate
for a week (weekly app approvals, spec 2026-09-25-weekly-app-approvals).

Why it exists: an approval lets desktop acts in one app run with no card for
7 days, so the owner must be able to see every one (which app, from which
chat or browser, until when, last used) and end any of them at once. The
Settings page reads and revokes through here; Telegram's /apps does the same
through the store. Each approval belongs to its user: another user's id is a
404, as an unknown one is.

Connects to: the runtime's AppApprovalStore (``AgentRuntime.app_approvals``),
the audit log (``app_approval_revoked``) and the web device header
(``this_device`` marks the approvals this browser gave).
"""

from __future__ import annotations

from typing import Optional

import structlog
from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from api.routes.agent import get_runtime, web_channel
from core.database import get_db
from models.audit import AuditStatus
from models.user import User
from services.agent.app_approvals import TOOL
from services.agent.runtime import AgentRuntime
from services.audit import append_audit_log
from services.auth import get_current_user

logger = structlog.get_logger(__name__)

router = APIRouter(prefix="/agent/app-approvals", tags=["agent"])


class AppApprovalOut(BaseModel):
    id: str
    app: str
    # "telegram" | "web"
    channel: str
    # Given from the browser this request came from.
    this_device: bool
    granted_at: str
    expires_at: str
    last_used_at: Optional[str] = None


@router.get("", response_model=list[AppApprovalOut])
async def list_app_approvals(
    request: Request,
    current_user: User = Depends(get_current_user),
    runtime: AgentRuntime = Depends(get_runtime),
) -> list[AppApprovalOut]:
    """The user's live weekly app approvals, soonest to expire first."""
    here = web_channel(request)
    approvals = await runtime.app_approvals.list_active(str(current_user.id))
    return [
        AppApprovalOut(
            id=a.id,
            app=a.app,
            channel=a.channel_kind,
            this_device=a.holds_for(here),
            granted_at=a.granted_at.isoformat(),
            expires_at=a.expires_at.isoformat(),
            last_used_at=a.last_used_at.isoformat() if a.last_used_at else None,
        )
        for a in approvals
    ]


@router.delete("/{approval_id}", status_code=status.HTTP_204_NO_CONTENT)
async def revoke_app_approval(
    approval_id: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
    runtime: AgentRuntime = Depends(get_runtime),
) -> Response:
    """End one weekly app approval: the next act in that app gets a card.
    404 when it is not one of the user's live approvals. The audit row is
    best effort: revoking only takes a permission away, and must not be
    undone because the log could not be written."""
    revoked = await runtime.app_approvals.revoke(
        user_id=str(current_user.id), approval_id=approval_id
    )
    if revoked is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="No such approval.")
    connector, _, action = TOOL.partition(".")
    try:
        await append_audit_log(
            db,
            user_id=current_user.id,
            connector_name=connector,
            action=action,
            endpoint="/api/agent/app-approvals",
            scope_used=connector,
            status=AuditStatus.approved,
            reasoning_chain={
                "event": "app_approval_revoked",
                "app": revoked.app,
                "channel": revoked.channel_kind,
                "app_approval_id": revoked.id,
                "revoked_from": "web",
            },
        )
    except Exception as exc:
        await db.rollback()
        logger.error("app_approval_revoke_audit_failed", error=str(exc)[:200])
    return Response(status_code=status.HTTP_204_NO_CONTENT)
