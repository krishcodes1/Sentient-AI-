"""Serves Security -> Outgoing messages (/api/security/outbound): what each
user's outgoing-message checks know (counts of the sent-to history, the
organisation's domains), forgetting one's own history, and the owner's
edits of the organisation's domain list.

Why it exists: S1's notes ("first time Crawler sends to ...", "outside your
organisation") depend on facts the person should be able to see and reset,
and on a domain list only the owner may change. Responses carry counts and
domains, never an address (the history holds keyed fingerprints only), and
the audit rows these routes write carry counts only, never a domain or an
address.

Connects to: services/security/outbound.py (``app.state.outbound``, whose
``known`` store holds the sent-to history), services/security/outbound_store.py
(``app.state.organisation_domains``), the InstallationService (the
``outbound_checks`` switch, read only), the audit log
(``known_recipients_cleared``, ``outbound_domains_changed``).
Used by: the Security page's Outgoing messages tab; main.py mounts the router.
"""

from __future__ import annotations

from typing import Any, Optional

import structlog
from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from api.routes._deps import require_admin
from core.database import get_db
from models.audit import AuditStatus
from models.user import User
from services.audit import append_audit_log
from services.auth import get_current_user
from services.security.outbound_recipients import organisation_domain_of
from services.security.outbound_store import (
    NO_SUCH_DOMAIN,
    DomainRefused,
    KnownRecipientStore,
    OrganisationDomainRow,
    OrganisationDomainStore,
)

logger = structlog.get_logger(__name__)

router = APIRouter(prefix="/security/outbound", tags=["security"])

CAPABILITY_KEY = "outbound_checks"
STARTING = "The server is still starting. Try again shortly."
# A posted domain longer than this is refused before any parsing (a domain
# is at most 253 characters; NFKC on a megabyte would be wasted work).
MAX_DOMAIN_INPUT = 1000
ENTER_A_DOMAIN = "Enter a domain such as acme.com."
AUDIT_CONNECTOR = "outbound_checks"


class KnownOut(BaseModel):
    addresses: int
    domains: int
    since: Optional[str] = None


class OrganisationDomainOut(BaseModel):
    id: str
    domain: str
    added_at: str


class OutboundSettingsOut(BaseModel):
    enabled: bool
    known: KnownOut
    own_domains: list[str]
    organisation_domains: list[OrganisationDomainOut]
    can_edit_domains: bool
    domain_limit: int


class DomainIn(BaseModel):
    domain: str


def _known_store(request: Request) -> KnownRecipientStore:
    """The sent-to history the executor records into; 503 until main.py
    wired the outbound service."""
    service = getattr(request.app.state, "outbound", None)
    store = getattr(service, "known", None)
    if store is None:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=STARTING)
    return store  # type: ignore[no-any-return]


def _domain_store(request: Request) -> OrganisationDomainStore:
    store = getattr(request.app.state, "organisation_domains", None)
    if store is None:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=STARTING)
    return store  # type: ignore[no-any-return]


async def _switch_on(request: Request) -> bool:
    """The owner's switch as the check reads it: unknown or unreadable
    counts as on (the hide_personal_details rule)."""
    installation = getattr(request.app.state, "installation", None)
    if installation is None:
        return True
    try:
        return CAPABILITY_KEY in await installation.enabled_keys()
    except Exception as exc:
        logger.warning("outbound_switch_unreadable", error_type=type(exc).__name__)
        return True


def _domain_out(row: OrganisationDomainRow) -> OrganisationDomainOut:
    return OrganisationDomainOut(id=row.id, domain=row.domain, added_at=row.added_at.isoformat())


async def _audit(
    db: AsyncSession, user: User, event: str, endpoint: str, counts: dict[str, int]
) -> None:
    """One counts-only row, best effort: the change already happened and is
    not undone because the log could not be written (the
    api/routes/permission_grants.py pattern)."""
    try:
        await append_audit_log(
            db,
            user_id=user.id,
            connector_name=AUDIT_CONNECTOR,
            action=event,
            endpoint=endpoint,
            scope_used=AUDIT_CONNECTOR,
            status=AuditStatus.approved,
            reasoning_chain={"event": event},
            request_data=counts,
        )
    except Exception as exc:
        await db.rollback()
        logger.error("outbound_audit_failed", audit_event=event, error_type=type(exc).__name__)


@router.get("", response_model=OutboundSettingsOut)
async def outbound_settings(
    request: Request, current_user: User = Depends(get_current_user)
) -> OutboundSettingsOut:
    """The caller's sent-to counts, own domains and the organisation's list."""
    known = await _known_store(request).summary(str(current_user.id))
    domains = _domain_store(request)
    rows = await domains.domains()
    own = organisation_domain_of(current_user.email) if current_user.email else None
    return OutboundSettingsOut(
        enabled=await _switch_on(request),
        known=KnownOut(
            addresses=known.addresses,
            domains=known.domains,
            since=known.since.isoformat() if known.since is not None else None,
        ),
        own_domains=[own] if own else [],
        organisation_domains=[_domain_out(row) for row in rows],
        can_edit_domains=bool(current_user.is_admin),
        domain_limit=domains.limit,
    )


@router.delete("/known-recipients")
async def forget_known_recipients(
    request: Request,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> dict[str, Any]:
    """Forget the caller's own sent-to history: {"removed": <rows>}. Every
    address counts as new again."""
    removed = await _known_store(request).forget(str(current_user.id))
    await _audit(
        db,
        current_user,
        "known_recipients_cleared",
        "/api/security/outbound/known-recipients",
        {"rows": removed},
    )
    return {"removed": removed}


@router.post("/domains", status_code=status.HTTP_201_CREATED, response_model=OrganisationDomainOut)
async def add_organisation_domain(
    body: DomainIn,
    request: Request,
    admin: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
) -> OrganisationDomainOut:
    """The owner adds one of the organisation's own domains: 201 with the
    stored row, 409 when it is listed already, 422 with one plain sentence
    otherwise (not a domain, a public mail service, a domain ending, the
    list is full)."""
    store = _domain_store(request)
    if len(body.domain) > MAX_DOMAIN_INPUT:
        raise HTTPException(status_code=422, detail=ENTER_A_DOMAIN)
    try:
        row = await store.add(body.domain, added_by=str(admin.id))
    except DomainRefused as refused:
        raise HTTPException(status_code=refused.status, detail=refused.message) from None
    total = len(await store.domains())
    await _audit(
        db,
        admin,
        "outbound_domains_changed",
        "/api/security/outbound/domains",
        {"added": 1, "removed": 0, "total": total},
    )
    return _domain_out(row)


@router.delete("/domains/{domain_id}", status_code=status.HTTP_204_NO_CONTENT)
async def remove_organisation_domain(
    domain_id: str,
    request: Request,
    admin: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
) -> Response:
    """The owner removes one listed domain: 204, or 404 when there is no
    such row."""
    store = _domain_store(request)
    if not await store.remove(domain_id):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=NO_SUCH_DOMAIN)
    total = len(await store.domains())
    await _audit(
        db,
        admin,
        "outbound_domains_changed",
        "/api/security/outbound/domains",
        {"added": 0, "removed": 1, "total": total},
    )
    return Response(status_code=status.HTTP_204_NO_CONTENT)
