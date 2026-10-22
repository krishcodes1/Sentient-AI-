"""Serves Security -> Service keys' link-check status
(/api/security/link-reputation/status): the owner's view of the link
lookups: the switch, the active Google service, lookups against the
limits, the cool-down and the last problem.

Why it exists: the owner pays for (or is rate-limited on) their own Google
key, so they should see how much of it Crawler uses and why a lookup did
not happen. The answer never carries a key, a link or a host.

The route only forwards to ``LinkReputation.status()``
(services/reputation/links.py), which counts per process and holds no key,
link or host; it answers 403 for non-owners and 503 until the service is
wired.

Connects to: services/reputation/links.py (``app.state.link_reputation``).
Used by: the Security page's Service keys tab; main.py mounts the router.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request, status

from api.routes._deps import require_admin
from models.user import User

router = APIRouter(prefix="/security/link-reputation", tags=["security"])


@router.get("/status")
async def link_reputation_status(
    request: Request, _admin: User = Depends(require_admin)
) -> dict[str, Any]:
    """The owner's view of link checks. Never a key, link or host. 503
    until wired."""
    service = getattr(request.app.state, "link_reputation", None)
    if service is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="The server is still starting. Try again shortly.",
        )
    answer: dict[str, Any] = dict(await service.status())
    return answer
