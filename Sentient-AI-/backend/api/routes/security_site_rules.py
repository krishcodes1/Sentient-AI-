"""Serves Security -> Site rules (/api/security/site-rules): the owner's
Blocked / Always ask / Trusted rules for Crawler's browser, the built-in
sensitive-site categories and their kinds, recent hits, and "which rule
applies to this site?".

Why it exists: site rules are install-wide browser policy, so every route is
owner-only (``require_admin``). Each write goes through
``services/site_rules/store.py`` (validated, and audited in the same
transaction), is committed here, and then refreshes the process's snapshot,
so a new Blocked rule applies to the very next navigation of every open
browser session. Rules are never changed from chat: this module is the only
way in.

Answers: refusals carry the store's plain sentence as ``detail`` (422 for a
site or kind the owner cannot have, 409 for a rule that already exists, 404
for an unknown rule or category); a write that fails for any other reason
(its audit row, the database) is rolled back and answered 500 "The rule
could not be saved. Try again." with nothing changed. The Check route reads
the committed rows, not the cached snapshot, so it always answers what the
database holds, and it explains the rules even while the switch is off.

Connects to: services/site_rules (the store, the snapshot, the patterns and
``app.state.site_rules``, the service the routes refresh and whose recent
hits they list), the installation service (the ``browser_site_rules``
switch). Used by: the Security page's Site rules tab; main.py mounts the
router.
"""

from __future__ import annotations

from typing import Any, Optional

import structlog
from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from api.routes._deps import require_admin
from core.database import get_db
from models.browser_site_rule import BrowserSiteRule
from models.user import User
from services.site_rules import messages, store
from services.site_rules.patterns import (
    MAX_HOST_RULES,
    SiteRuleError,
    as_kind,
    display_host,
    host_of,
    is_wildcard,
    parse_site,
    pattern_base,
)
from services.site_rules.sensitive_sites import (
    CATEGORIES,
    DEFAULT_CATEGORY_KIND,
    Category,
    category,
)
from services.site_rules.snapshot import SiteRuleSnapshot, overlapping_builtin

logger = structlog.get_logger(__name__)

router = APIRouter(prefix="/security/site-rules", tags=["security"])

CAPABILITY_KEY = "browser_site_rules"
# What a person pastes into the site box is a URL at most; a longer body is
# refused before anything reads it (the readers are linear, but there is no
# reason to read a megabyte the owner never typed).
_MAX_SITE_CHARS = 4096
_MAX_KIND_CHARS = 32
_UNPROCESSABLE = 422


class SiteRuleCreateIn(BaseModel):
    site: str
    include_subdomains: bool = False
    kind: str


class SiteRuleKindIn(BaseModel):
    kind: str


class SiteCheckIn(BaseModel):
    site: str


def _refusal(exc: SiteRuleError) -> HTTPException:
    """The store's or the patterns' refusal, with its plain sentence."""
    return HTTPException(status_code=exc.status, detail=str(exc))


def _typed_site(site: str) -> str:
    text = site.strip()
    if not text:
        raise HTTPException(status_code=_UNPROCESSABLE, detail=messages.EMPTY_SITE)
    if len(text) > _MAX_SITE_CHARS:
        raise HTTPException(status_code=_UNPROCESSABLE, detail=messages.TOO_LONG)
    return text


def _typed_kind(kind: str) -> str:
    if len(kind) > _MAX_KIND_CHARS or as_kind(kind) is None:
        raise HTTPException(status_code=_UNPROCESSABLE, detail=messages.BAD_KIND)
    return kind


async def _switch_on(request: Request) -> bool:
    """The owner's ``browser_site_rules`` switch. No installation service
    (plain route tests): the registry default, on. One that cannot be read
    counts as on, as the service reads it (fail closed)."""
    installation = getattr(request.app.state, "installation", None)
    if installation is None:
        return True
    try:
        return CAPABILITY_KEY in await installation.enabled_keys()
    except Exception as exc:  # noqa: BLE001 - an unread switch keeps the rules on
        logger.warning("site_rules_switch_unreadable", error_type=type(exc).__name__)
        return True


async def _refresh(request: Request) -> None:
    """After a committed change: mark the process's snapshot stale and read
    it again now. A refresh that fails leaves it stale, so the next browser
    call retries; the change itself is already saved."""
    service = getattr(request.app.state, "site_rules", None)
    if service is None:
        return
    try:
        service.invalidate()
        await service.refresh()
    except Exception as exc:  # noqa: BLE001 - the saved change stands; the next call retries
        logger.warning("site_rules_refresh_after_write_failed", error_type=type(exc).__name__)


def _recent(request: Request) -> list[dict[str, Any]]:
    service = getattr(request.app.state, "site_rules", None)
    if service is None:
        return []
    try:
        return list(service.recent())
    except Exception as exc:  # noqa: BLE001 - the list is a convenience, never a failure
        logger.warning("site_rules_recent_failed", error_type=type(exc).__name__)
        return []


def _stamp(value: Any) -> str:
    return value.isoformat() if value is not None else ""


def _rule_out(row: BrowserSiteRule) -> dict[str, Any]:
    pattern = row.target
    return {
        "id": str(row.id),
        "pattern": pattern,
        "host": display_host(pattern),
        "include_subdomains": is_wildcard(pattern),
        "kind": as_kind(row.kind) or row.kind,
        "overrides_builtin": overlapping_builtin(pattern) is not None,
        "created_at": _stamp(row.created_at),
        "updated_at": _stamp(row.updated_at),
    }


def _category_out(entry: Category, kind: str) -> dict[str, Any]:
    return {
        "key": entry.key,
        "label": entry.label,
        "kind": kind,
        "default_kind": DEFAULT_CATEGORY_KIND,
        "site_count": len(entry.sites),
        "sites": [pattern_base(site) for site in entry.sites],
    }


async def _committed_snapshot(
    db: AsyncSession, *, enabled: bool
) -> tuple[list[BrowserSiteRule], SiteRuleSnapshot]:
    rows = await store.list_rows(db)
    return rows, store.snapshot_from_rows(rows, enabled=enabled, loaded_at=0.0)


async def _save(db: AsyncSession, request: Request, event: str) -> None:
    """Commit the change and its audit row, then refresh the snapshot."""
    await db.commit()
    logger.info(event)
    await _refresh(request)


async def _failed_write(db: AsyncSession, exc: Exception) -> HTTPException:
    """A write that failed for a reason the owner cannot fix (its audit row,
    the database): rolled back, logged by type only, answered 500."""
    try:
        await db.rollback()
    except Exception:  # noqa: BLE001 - the request's session handler rolls back too
        pass
    logger.warning("site_rules_write_failed", error_type=type(exc).__name__)
    return HTTPException(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=messages.SAVE_FAILED
    )


@router.get("")
async def list_site_rules(
    request: Request,
    _owner: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
) -> dict[str, Any]:
    """Every rule, every built-in category with its kind, the recent hits,
    and whether the switch is on."""
    enabled = await _switch_on(request)
    rows, snapshot = await _committed_snapshot(db, enabled=enabled)
    return {
        "enabled": enabled,
        "rules": [_rule_out(row) for row in rows if row.target_type == store.HOST],
        "categories": [
            _category_out(entry, snapshot.category_kind(entry.key)) for entry in CATEGORIES
        ],
        "recent": _recent(request),
        "max_rules": MAX_HOST_RULES,
    }


@router.post("", status_code=status.HTTP_201_CREATED)
async def add_site_rule(
    body: SiteRuleCreateIn,
    request: Request,
    owner: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
) -> dict[str, Any]:
    """Add a rule for a typed site (validated and audited)."""
    site = _typed_site(body.site)
    kind = _typed_kind(body.kind)
    try:
        row = await store.create_rule(
            db, owner, site=site, include_subdomains=body.include_subdomains, kind=kind
        )
    except SiteRuleError as exc:
        raise _refusal(exc) from None
    except Exception as exc:  # noqa: BLE001 - an unsaved rule is a 500 with nothing changed
        raise await _failed_write(db, exc) from None
    try:
        await _save(db, request, "site_rule_created")
    except Exception as exc:  # noqa: BLE001 - see _failed_write
        raise await _failed_write(db, exc) from None
    return _rule_out(row)


@router.post("/check")
async def check_site(
    body: SiteCheckIn,
    request: Request,
    _owner: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
) -> dict[str, Any]:
    """Which rule applies to a typed site, and why (read from the committed
    rows; explained even while the switch is off)."""
    text = _typed_site(body.site)
    if text.startswith("*."):
        text = text[2:]  # the owner typed a pattern: check its site
    # What could not be a rule is not explained either: the same plain
    # refusals as the Add form (a stray "*", a non-web address, ...).
    try:
        parse_site(text, include_subdomains=False)
    except SiteRuleError as exc:
        raise _refusal(exc) from None
    host = host_of(text)
    if not host:
        raise HTTPException(status_code=_UNPROCESSABLE, detail=messages.UNREADABLE_SITE)
    enabled = await _switch_on(request)
    _rows, snapshot = await _committed_snapshot(db, enabled=enabled)
    verdict = snapshot.would_apply(host)
    return {
        "host": host,
        "kind": verdict.kind,
        "source": verdict.source,
        "category": verdict.category,
        "rule_id": verdict.rule_id,
        "pattern": verdict.pattern,
        "protected": verdict.protected,
        "enabled": enabled,
        "explanation": snapshot.explain(host),
    }


@router.put("/categories/{key}")
async def set_site_category(
    key: str,
    body: SiteRuleKindIn,
    request: Request,
    owner: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
) -> dict[str, Any]:
    """Change the kind of one built-in category ("always_ask" resets it)."""
    entry: Optional[Category] = category(key)
    if entry is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=messages.NO_SUCH_CATEGORY)
    kind = _typed_kind(body.kind)
    try:
        applied = await store.set_category(db, owner, key, kind=kind)
    except SiteRuleError as exc:
        raise _refusal(exc) from None
    except Exception as exc:  # noqa: BLE001 - see _failed_write
        raise await _failed_write(db, exc) from None
    try:
        await _save(db, request, "site_category_changed")
    except Exception as exc:  # noqa: BLE001 - see _failed_write
        raise await _failed_write(db, exc) from None
    return _category_out(entry, applied)


@router.patch("/{rule_id}")
async def change_site_rule(
    rule_id: str,
    body: SiteRuleKindIn,
    request: Request,
    owner: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
) -> dict[str, Any]:
    """Change one rule's kind (validated and audited)."""
    kind = _typed_kind(body.kind)
    try:
        row = await store.update_rule(db, owner, rule_id, kind=kind)
    except SiteRuleError as exc:
        raise _refusal(exc) from None
    except Exception as exc:  # noqa: BLE001 - see _failed_write
        raise await _failed_write(db, exc) from None
    if row is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=messages.NO_SUCH_RULE)
    try:
        await _save(db, request, "site_rule_updated")
    except Exception as exc:  # noqa: BLE001 - see _failed_write
        raise await _failed_write(db, exc) from None
    return _rule_out(row)


@router.delete("/{rule_id}", status_code=status.HTTP_204_NO_CONTENT)
async def remove_site_rule(
    rule_id: str,
    request: Request,
    owner: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
) -> Response:
    """Remove one rule (audited)."""
    try:
        removed = await store.delete_rule(db, owner, rule_id)
    except Exception as exc:  # noqa: BLE001 - see _failed_write
        raise await _failed_write(db, exc) from None
    if not removed:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=messages.NO_SUCH_RULE)
    try:
        await _save(db, request, "site_rule_deleted")
    except Exception as exc:  # noqa: BLE001 - see _failed_write
        raise await _failed_write(db, exc) from None
    return Response(status_code=status.HTTP_204_NO_CONTENT)
