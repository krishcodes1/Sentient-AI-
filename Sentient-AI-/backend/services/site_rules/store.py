"""The owner's site rules in the database: list, create, change and delete
host rules, set a built-in category's kind, and turn the rows into a
snapshot.

Why it exists: a rule is owner policy, so every change is checked here the
same way whoever calls (the Security tab's routes today), and every change
writes its audit row in the same transaction as the change itself. The
caller (the route) commits; if the audit row cannot be written the whole
change rolls back, so the log never misses a rule change and no rule
changes without one.

What the audit rows hold (S7 §4.9, ``connector_name="site_rules"``): rule
ids, kinds, the category key and a keyed hash of the site
(``patterns.host_hash``), never the host, a URL or a path.

Errors are ``patterns.SiteRuleError`` with the status the route answers:
422 for a site or kind the owner cannot have (and the 501st rule), 409 for
a rule that already exists, 404 for an unknown category. After a 409 from
a lost race (the unique index fired on flush) the session must be rolled
back by the caller, as the request's ``get_db`` does on any exception.
"""

from __future__ import annotations

import uuid
from typing import Any, Iterable, Optional, cast

from sqlalchemy import case, delete, func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from core.config import settings
from models.audit import AuditStatus
from models.browser_site_rule import BrowserSiteRule
from models.user import User
from services.audit import append_audit_log
from services.site_rules import messages
from services.site_rules.patterns import (
    MAX_HOST_RULES,
    RuleKind,
    SiteRuleError,
    as_kind,
    host_hash,
    is_wildcard,
    parse_site,
    pattern_base,
    validate_kind,
)
from services.site_rules.sensitive_sites import DEFAULT_CATEGORY_KIND, category
from services.site_rules.snapshot import OwnerRule, SiteRuleSnapshot

HOST = "host"
CATEGORY = "category"
CONNECTOR = "site_rules"
ENDPOINT = "/api/security/site-rules"


def _hash(pattern: str) -> str:
    return host_hash(pattern_base(pattern), settings.ENCRYPTION_KEY)


def _rule_uuid(rule_id: str) -> Optional[uuid.UUID]:
    try:
        return uuid.UUID(str(rule_id))
    except (TypeError, ValueError, AttributeError):
        return None


async def _audit(db: AsyncSession, actor: User, event: str, facts: dict[str, Any]) -> None:
    """One owner-change row in the request's transaction (it raises, so a
    failed write rolls the change back with it)."""
    await append_audit_log(
        db,
        user_id=actor.id,
        connector_name=CONNECTOR,
        action=event,
        endpoint=ENDPOINT,
        scope_used="admin",
        status=AuditStatus.approved,
        reasoning_chain={"event": event},
        request_data=facts,
    )


async def list_rows(db: AsyncSession) -> list[BrowserSiteRule]:
    """Every row: host rules oldest first, then category overrides."""
    host_first = case((BrowserSiteRule.target_type == HOST, 0), else_=1)
    result = await db.execute(
        select(BrowserSiteRule).order_by(
            host_first, BrowserSiteRule.created_at, BrowserSiteRule.target
        )
    )
    return list(result.scalars().all())


async def count_host_rules(db: AsyncSession) -> int:
    result = await db.execute(
        select(func.count()).select_from(BrowserSiteRule).where(BrowserSiteRule.target_type == HOST)
    )
    return int(result.scalar_one())


async def _host_row(db: AsyncSession, rule_id: str) -> Optional[BrowserSiteRule]:
    key = _rule_uuid(rule_id)
    if key is None:
        return None
    row = await db.get(BrowserSiteRule, key)
    return row if row is not None and row.target_type == HOST else None


async def _target_row(db: AsyncSession, target_type: str, target: str) -> Optional[BrowserSiteRule]:
    result = await db.execute(
        select(BrowserSiteRule).where(
            BrowserSiteRule.target_type == target_type, BrowserSiteRule.target == target
        )
    )
    return result.scalars().first()


async def create_rule(
    db: AsyncSession, actor: User, *, site: str, include_subdomains: bool, kind: str
) -> BrowserSiteRule:
    """Add the owner's rule for what they typed; raises SiteRuleError (422 a
    site, kind or count the owner cannot have, 409 an existing rule)."""
    pattern = parse_site(site, include_subdomains=include_subdomains)
    checked = validate_kind(pattern, kind)
    if await _target_row(db, HOST, pattern) is not None:
        raise SiteRuleError(messages.duplicate_rule(pattern_base(pattern)), status=409)
    if await count_host_rules(db) >= MAX_HOST_RULES:
        raise SiteRuleError(messages.too_many_rules(MAX_HOST_RULES))
    row = BrowserSiteRule(
        target_type=HOST,
        target=pattern,
        kind=checked,
        created_by=actor.id,
        updated_by=actor.id,
    )
    db.add(row)
    try:
        await db.flush()
    except IntegrityError:
        # Another request added the same rule between the check and here.
        raise SiteRuleError(messages.duplicate_rule(pattern_base(pattern)), status=409)
    await _audit(
        db,
        actor,
        "site_rule_created",
        {
            "rule_id": str(row.id),
            "target_type": HOST,
            "kind": checked,
            "include_subdomains": is_wildcard(pattern),
            "host_hash": _hash(pattern),
        },
    )
    return row


async def update_rule(
    db: AsyncSession, actor: User, rule_id: str, *, kind: str
) -> Optional[BrowserSiteRule]:
    """Change a host rule's kind; None when there is no such rule (404).
    The same kind again writes nothing."""
    row = await _host_row(db, rule_id)
    if row is None:
        return None
    checked = validate_kind(row.target, kind)
    previous = row.kind
    if checked == previous:
        return row
    row.kind = checked
    row.updated_by = actor.id
    await db.flush()
    await _audit(
        db,
        actor,
        "site_rule_updated",
        {
            "rule_id": str(row.id),
            "kind": checked,
            "previous_kind": previous,
            "host_hash": _hash(row.target),
        },
    )
    return row


async def delete_rule(db: AsyncSession, actor: User, rule_id: str) -> bool:
    """Remove a host rule; False when there is no such rule (404)."""
    row = await _host_row(db, rule_id)
    if row is None:
        return False
    facts = {"rule_id": str(row.id), "previous_kind": row.kind, "host_hash": _hash(row.target)}
    await db.delete(row)
    await db.flush()
    await _audit(db, actor, "site_rule_deleted", facts)
    return True


async def set_category(db: AsyncSession, actor: User, key: str, *, kind: str) -> RuleKind:
    """Set a built-in category's kind. Always ask (the default) removes the
    override row, so "Reset" and "set to Always ask" are one thing. The
    same kind again writes nothing. Raises SiteRuleError (404 an unknown
    category, 422 an unknown kind)."""
    if category(key) is None:
        raise SiteRuleError(messages.NO_SUCH_CATEGORY, status=404)
    checked = as_kind(kind)
    if checked is None:
        raise SiteRuleError(messages.BAD_KIND)
    row = await _target_row(db, CATEGORY, key)
    previous = as_kind(row.kind) if row is not None else None
    previous = previous or DEFAULT_CATEGORY_KIND
    if checked == previous and (row is None) == (checked == DEFAULT_CATEGORY_KIND):
        return checked
    if checked == DEFAULT_CATEGORY_KIND:
        await db.execute(
            delete(BrowserSiteRule).where(
                BrowserSiteRule.target_type == CATEGORY, BrowserSiteRule.target == key
            )
        )
    elif row is None:
        db.add(
            BrowserSiteRule(
                target_type=CATEGORY,
                target=key,
                kind=checked,
                created_by=actor.id,
                updated_by=actor.id,
            )
        )
    else:
        row.kind = checked
        row.updated_by = actor.id
    await db.flush()
    await _audit(
        db,
        actor,
        "site_category_changed",
        {"category": key, "kind": checked, "previous_kind": previous},
    )
    return checked


def snapshot_from_rows(
    rows: Iterable[BrowserSiteRule], *, enabled: bool, loaded_at: float
) -> SiteRuleSnapshot:
    """The snapshot the guard, the resolver and the call check read, from the
    rows as stored. ``SiteRuleSnapshot.build`` checks every row again and
    skips (and counts) one that is not a rule."""
    owner: list[OwnerRule] = []
    categories: dict[str, str] = {}
    for row in rows:
        if row.target_type == HOST:
            # build() re-reads the kind with as_kind and skips a bad one.
            owner.append(OwnerRule(id=str(row.id), pattern=row.target, kind=cast(RuleKind, row.kind)))
        elif row.target_type == CATEGORY:
            categories[row.target] = row.kind
    return SiteRuleSnapshot.build(owner, categories, enabled=enabled, loaded_at=loaded_at)
