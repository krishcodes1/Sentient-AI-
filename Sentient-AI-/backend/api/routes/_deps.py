"""Dependencies shared by the owner-facing routes (setup, capabilities)."""

from __future__ import annotations

from fastapi import Depends, HTTPException, Request, status

from models.user import User
from services.auth import get_current_user
from services.installation import InstallationService


def installation_service(request: Request) -> InstallationService:
    """The InstallationService the lifespan hangs on app.state; 503 until it
    exists (the server is still starting, or a test app never wired it)."""
    service = getattr(request.app.state, "installation", None)
    if service is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="The server is still starting. Try again shortly.",
        )
    return service


async def require_admin(current_user: User = Depends(get_current_user)) -> User:
    """The signed-in owner (``is_admin``); 403 for anyone else. Every
    install-wide change goes through this: it affects every account."""
    if not current_user.is_admin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only the owner of this install can change this.",
        )
    return current_user
