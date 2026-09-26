"""Serves /api/vault: the owner's stored payment card as masked views, the
one form that stores a card, and its removal (purchases spec §4).

Why it exists: The card is entered here and nowhere else: never through
chat, never by the model. Every route is the owner's alone
(``require_admin``); the store route also insists on a loopback peer, so
the form only ever works from the machine the vault key lives on. No
response carries more than the masked view, the request models print
their secret fields as elided, the 422 handler never echoes input, and the
audit rows name kind, label and masked label only.
"""

from __future__ import annotations

import asyncio
import ipaddress
from typing import Any, Optional

import structlog
from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field, StrictInt
from sqlalchemy.ext.asyncio import AsyncSession

from api.routes._deps import require_admin
from core.database import get_db
from models.audit import AuditStatus
from models.user import User
from services.audit import append_audit_log
from services.vault.keys import VaultUnavailable
from services.vault.service import VaultItemView, VaultService

logger = structlog.get_logger(__name__)

router = APIRouter(prefix="/vault", tags=["vault"])

# Starlette renamed the 422 constant; the number is stable across versions.
_UNPROCESSABLE = 422
# Longer than any card number with every separator a person might type.
_MAX_NUMBER_CHARS = 32
_MAX_CVC_CHARS = 8

LOCALHOST_ONLY = (
    "The card can only be stored from the computer Crawler runs on. "
    "Open Settings on that machine."
)


class CardBody(BaseModel):
    """The card form. ``number`` and ``cvc`` carry no pydantic constraints
    on purpose: a constraint failure would put the offending value in the
    error, and they are elided from the model's repr for the same reason.
    Both are checked by hand in the vault service."""

    label: Optional[str] = Field(default=None, max_length=120)
    number: str = Field(repr=False)
    exp_month: StrictInt
    exp_year: StrictInt
    cvc: str = Field(repr=False)
    name: str = Field(max_length=120)


def vault_service(request: Request) -> VaultService:
    """The VaultService the lifespan hangs on app.state; 503 until it
    exists (the server is still starting, or a test app never wired it)."""
    service = getattr(request.app.state, "vault", None)
    if service is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="The server is still starting. Try again shortly.",
        )
    return service


def peer_is_loopback(request: Request) -> bool:
    """True when the direct peer is 127.0.0.0/8 or ::1 (also IPv4-mapped).
    The direct peer on purpose, not X-Forwarded-For: the only proxied
    deployment is the container, where the vault is unavailable anyway,
    and a header must never be able to claim "local"."""
    host = request.client.host if request.client else None
    if not host:
        return False
    try:
        addr: Any = ipaddress.ip_address(host)
    except ValueError:
        return False
    mapped = getattr(addr, "ipv4_mapped", None)
    return bool(addr.is_loopback or (mapped is not None and mapped.is_loopback))


def _unavailable(reason: str) -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_409_CONFLICT,
        detail={"message": reason, "code": "vault_unavailable"},
    )


async def _audit(
    db: AsyncSession, *, user_id: Any, action: str, endpoint: str, view: VaultItemView
) -> None:
    """One row naming the item by its masked label only."""
    await append_audit_log(
        db,
        user_id=user_id,
        connector_name="vault",
        action=action,
        endpoint=endpoint,
        scope_used="admin",
        status=AuditStatus.approved,
        request_data={"kind": view.kind, "label": view.label, "masked": view.masked},
    )


@router.get("/items")
async def list_items(
    request: Request,
    current_user: User = Depends(require_admin),
) -> dict[str, Any]:
    """Masked views only, plus whether the vault can be used here so the
    Settings page can show the reason instead of the form."""
    vault = vault_service(request)
    available, reason = await asyncio.to_thread(vault.available)
    items = await vault.list_items(current_user.id)
    return {
        "items": [item.to_dict() for item in items],
        "available": available,
        "reason": reason,
    }


@router.put("/card")
async def put_card(
    body: CardBody,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_admin),
) -> dict[str, Any]:
    """Store (or replace) the owner's card. 409 when there is no key store
    here (a container), 403 from any peer but this machine, 422 for a
    number that fails Luhn or a card that has expired."""
    vault = vault_service(request)
    available, reason = await asyncio.to_thread(vault.available)
    if not available:
        raise _unavailable(reason)
    if not peer_is_loopback(request):
        logger.warning("vault_card_store_refused", reason="not_loopback")
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={"message": LOCALHOST_ONLY, "code": "localhost_only"},
        )
    if len(body.number) > _MAX_NUMBER_CHARS or len(body.cvc) > _MAX_CVC_CHARS:
        raise HTTPException(
            status_code=_UNPROCESSABLE, detail="That does not look like a valid card number."
        )
    try:
        view = await vault.put_card(
            current_user.id,
            label=body.label or "",
            number=body.number,
            exp_month=body.exp_month,
            exp_year=body.exp_year,
            cvc=body.cvc,
            name=body.name,
        )
    except ValueError as exc:
        raise HTTPException(status_code=_UNPROCESSABLE, detail=str(exc))
    except VaultUnavailable as exc:
        raise _unavailable(str(exc))
    await _audit(
        db,
        user_id=current_user.id,
        action="vault_card_stored",
        endpoint=request.url.path,
        view=view,
    )
    return view.to_dict()


@router.delete("/items/{item_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_item(
    item_id: str,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_admin),
) -> None:
    vault = vault_service(request)
    view = next((v for v in await vault.list_items(current_user.id) if v.id == item_id), None)
    if view is None or not await vault.delete_item(current_user.id, item_id):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="No such item.")
    await _audit(
        db,
        user_id=current_user.id,
        action="vault_item_deleted",
        endpoint=request.url.path,
        view=view,
    )
