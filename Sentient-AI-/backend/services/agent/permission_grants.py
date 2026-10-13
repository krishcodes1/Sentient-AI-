"""Low-risk grants and the per-turn standing-consent decision: when a call may
run without an approval card because of the owner's standing consent (the
auto_approve tier, the "Allow low-risk changes" tier, or a 7-day grant for one
connection), and when it must ask.

Why it exists: permission tiers (top10) lets the owner stop answering cards for
small, undoable changes on the accounts they choose, without ever loosening
sends, deletes, sharing or invitations. The grade that decides it is computed
in code (services/agent/risk.py). This module holds the rest:

- ``PermissionGrant`` and the stores (``InMemoryPermissionGrantStore`` for
  tests and a runtime with no database, ``DbPermissionGrantStore`` over the
  ``permission_grants`` table). A grant is per user and per connection (not
  per channel), lasts ``GRANT_TTL``, renews when allowed again, is taken back
  on revoke, on credential replacement, reconnect or scope widening, and dies
  with the connector or the user. Expiry is compared in Python, as the weekly
  app approvals store does, so naive SQLite and aware Postgres timestamps read
  the same.
- ``StandingConsent``: one turn's decisions, in the runtime's canonical gate
  order (after the permission check and the unattended rule, before the taint
  gate). Never in an unattended turn, never after a result PromptGuard flagged
  this turn (the tripwire), at most ``LOW_RISK_MAX_PER_TURN`` low-risk runs a
  turn, and a HIGH grade always asks, even under auto_approve.
- Helpers the routes and the OAuth broker use to revoke a connection's grants
  inside their own transaction, and to audit revokes and tier changes.

Nothing here is sent to any model; audit rows carry ids, labels, fixed reasons
and grades, never argument values.

Connects to: services/agent/runtime.py (the anchors call StandingConsent),
services/agent/tool_registry.py (the executor's backstop reads a store),
api/routes/permission_grants.py (list and revoke), api/routes/connectors.py and
services/connectors/oauth.py (revocation on credential change), the Telegram
and Slack channels (/grants, "grants"), models/permission_grant.py.
"""

from __future__ import annotations

import inspect
import uuid
from dataclasses import dataclass, field, replace
from datetime import datetime, timedelta, timezone
from typing import Any, Awaitable, Callable, Iterable, Mapping, Optional, Protocol

import structlog

from services.agent.risk import (
    LOW_RISK_MAX_PER_TURN,
    RiskGrade,
    card_note,
    grade_tool,
    ran_without_asking_line,
    ref_args_of,
)

logger = structlog.get_logger(__name__)

# What a grant allows. One kind in v1.
KIND_LOW_RISK = "low_risk"
# How long one "Allow low-risk changes" lasts; allowing again renews it.
GRANT_TTL = timedelta(days=7)
# The decision option (approve_action(remember=...)) that makes a grant.
REMEMBER_LOW_RISK = "low_risk"
# Where a grant can be given from (display only).
GRANTED_FROM: tuple[str, ...] = ("web", "telegram", "slack")

# How a call ran without a card, as audit rows and the executor name it.
APPROVAL_TIER = "tier"
APPROVAL_LOW_RISK = "low_risk"
APPROVAL_LOW_RISK_GRANT = "low_risk_grant"
STANDING_APPROVALS: frozenset[str] = frozenset(
    {APPROVAL_TIER, APPROVAL_LOW_RISK, APPROVAL_LOW_RISK_GRANT}
)
_LOW_KINDS = frozenset({APPROVAL_LOW_RISK, APPROVAL_LOW_RISK_GRANT})

# Card notes (fixed text) for a call standing consent would have covered but
# did not. CAP_NOTE (like risk.card_note) is routine policy: it joins the
# card's reason ("Why"), shown in plain text. SUSPENDED_NOTE reports a result
# that looked like an attempt to steer Crawler, so it is a warning: it goes
# in the card's risk note, which the web app, Telegram and Slack draw as a
# risk warning.
CAP_NOTE = (
    f"Asking first: {LOW_RISK_MAX_PER_TURN} low-risk changes already ran without asking "
    "in this request."
)
SUSPENDED_NOTE = (
    "Asking first: a result earlier in this request looked like an attempt to steer "
    "Crawler, so nothing more runs without your approval in it."
)

# Audit event names.
EVENT_GRANTED = "permission_grant_granted"
EVENT_REVOKED = "permission_grant_revoked"
EVENT_CONNECTOR_TIER = "connector_tier_changed"
EVENT_ACCOUNT_TIER = "account_tier_changed"


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _as_utc(dt: datetime) -> datetime:
    """Naive timestamps (the SQLite backend) as UTC-aware."""
    return dt.replace(tzinfo=timezone.utc) if dt.tzinfo is None else dt


def _uuid(value: Any) -> Optional[uuid.UUID]:
    try:
        return uuid.UUID(str(value))
    except (TypeError, ValueError):
        return None


@dataclass(frozen=True)
class PermissionGrant:
    """Store-agnostic view of one grant. ``account`` and ``connector_type``
    are the connection's label and type when the store can read them."""

    id: str
    user_id: str
    connector_id: str
    kind: str
    granted_at: datetime
    expires_at: datetime
    granted_from: Optional[str] = None
    last_used_at: Optional[datetime] = None
    uses: int = 0
    revoked_at: Optional[datetime] = None
    source_action_id: Optional[str] = None
    account: str = ""
    connector_type: str = ""

    def live(self, now: datetime) -> bool:
        return self.revoked_at is None and self.expires_at > now


class PermissionGrantStore(Protocol):
    async def allow(
        self,
        *,
        user_id: str,
        connector_id: str,
        kind: str = KIND_LOW_RISK,
        granted_from: Optional[str] = None,
        source_action_id: Optional[str] = None,
    ) -> Optional[PermissionGrant]:
        """Make (or renew to now + GRANT_TTL) the grant. None when the
        connection is not the user's, is not active, or is admin_only or
        hard_blocked: no grant is made."""
        ...

    async def find_live(
        self, *, user_id: str, connector_id: str, kind: str = KIND_LOW_RISK
    ) -> Optional[PermissionGrant]: ...

    async def record_use(self, grant_id: str) -> None: ...

    async def list_live(self, user_id: str) -> list[PermissionGrant]: ...

    async def revoke(self, *, user_id: str, grant_id: str) -> Optional[PermissionGrant]: ...

    async def revoke_connector(self, *, user_id: str, connector_id: str) -> int: ...

    async def revoke_all(self, *, user_id: str) -> int: ...


def _granted_from(value: Optional[str]) -> Optional[str]:
    return value if value in GRANTED_FROM else None


# ---------------------------------------------------------------------------
# In-memory store (tests, no database)
# ---------------------------------------------------------------------------


class InMemoryPermissionGrantStore:
    """Single-process store for tests and a runtime with no database; main.py
    injects ``DbPermissionGrantStore``.

    ``connection(user_id, connector_id)`` stands in for the database's check
    of the connector row (the user's own, active, not admin_only or
    hard_blocked); unset, every connection passes."""

    def __init__(
        self,
        now: Callable[[], datetime] = _utcnow,
        connection: Optional[Callable[[str, str], bool]] = None,
    ) -> None:
        self._now = now
        self._connection = connection
        self._grants: dict[str, PermissionGrant] = {}

    def _matching(self, user_id: str, connector_id: str, kind: str) -> Optional[PermissionGrant]:
        now = self._now()
        for grant in self._grants.values():
            if (
                grant.user_id == user_id
                and grant.connector_id == connector_id
                and grant.kind == kind
                and grant.live(now)
            ):
                return grant
        return None

    async def allow(
        self,
        *,
        user_id: str,
        connector_id: str,
        kind: str = KIND_LOW_RISK,
        granted_from: Optional[str] = None,
        source_action_id: Optional[str] = None,
    ) -> Optional[PermissionGrant]:
        if self._connection is not None and not self._connection(user_id, connector_id):
            return None
        now = self._now()
        existing = self._matching(user_id, connector_id, kind)
        if existing is not None:
            renewed = replace(
                existing,
                granted_at=now,
                expires_at=now + GRANT_TTL,
                granted_from=_granted_from(granted_from),
                source_action_id=source_action_id,
            )
            self._grants[renewed.id] = renewed
            return renewed
        grant = PermissionGrant(
            id=str(uuid.uuid4()),
            user_id=user_id,
            connector_id=connector_id,
            kind=kind,
            granted_at=now,
            expires_at=now + GRANT_TTL,
            granted_from=_granted_from(granted_from),
            source_action_id=source_action_id,
        )
        self._grants[grant.id] = grant
        return grant

    async def find_live(
        self, *, user_id: str, connector_id: str, kind: str = KIND_LOW_RISK
    ) -> Optional[PermissionGrant]:
        return self._matching(user_id, connector_id, kind)

    async def record_use(self, grant_id: str) -> None:
        grant = self._grants.get(grant_id)
        if grant is not None:
            self._grants[grant_id] = replace(grant, uses=grant.uses + 1, last_used_at=self._now())

    async def list_live(self, user_id: str) -> list[PermissionGrant]:
        now = self._now()
        live = [g for g in self._grants.values() if g.user_id == user_id and g.live(now)]
        return sorted(live, key=lambda g: g.expires_at)

    async def revoke(self, *, user_id: str, grant_id: str) -> Optional[PermissionGrant]:
        grant = self._grants.get(grant_id)
        if grant is None or grant.user_id != user_id or grant.revoked_at is not None:
            return None
        revoked = replace(grant, revoked_at=self._now())
        self._grants[grant_id] = revoked
        return revoked

    async def _revoke_where(self, match: Callable[[PermissionGrant], bool]) -> int:
        count = 0
        now = self._now()
        for grant_id, grant in list(self._grants.items()):
            if grant.revoked_at is None and match(grant):
                self._grants[grant_id] = replace(grant, revoked_at=now)
                count += 1
        return count

    async def revoke_connector(self, *, user_id: str, connector_id: str) -> int:
        return await self._revoke_where(
            lambda g: g.user_id == user_id and g.connector_id == connector_id
        )

    async def revoke_all(self, *, user_id: str) -> int:
        return await self._revoke_where(lambda g: g.user_id == user_id)


# ---------------------------------------------------------------------------
# Database store
# ---------------------------------------------------------------------------


def _view(row: Any, connector: Any = None) -> PermissionGrant:
    account, connector_type = "", ""
    if connector is not None:
        connector_type = str(getattr(connector.connector_type, "value", connector.connector_type))
        account = account_label(connector.display_name, connector_type)
    return PermissionGrant(
        id=str(row.id),
        user_id=str(row.user_id),
        connector_id=str(row.connector_id),
        kind=row.kind,
        granted_at=_as_utc(row.granted_at),
        expires_at=_as_utc(row.expires_at),
        granted_from=row.granted_from,
        last_used_at=_as_utc(row.last_used_at) if row.last_used_at else None,
        uses=int(row.uses or 0),
        revoked_at=_as_utc(row.revoked_at) if row.revoked_at else None,
        source_action_id=str(row.source_action_id) if row.source_action_id else None,
        account=account,
        connector_type=connector_type,
    )


def account_label(display_name: Any, connector_type: str = "") -> str:
    """A connection's label as cards and lists show it: the owner's display
    name cleaned like the tool registry's (printable, one line, at most 40
    characters), else the connector's own label."""
    cleaned = ""
    if isinstance(display_name, str) and display_name:
        printable = "".join(c if c.isprintable() else " " for c in display_name)
        cleaned = " ".join(printable.split())[:40]
    if cleaned:
        return cleaned
    from services.connectors import registry as connector_registry

    definition = connector_registry.get_definition(connector_type) if connector_type else None
    return definition.label if definition is not None else (connector_type or "this account")


async def connection_allows_grants(session: Any, user_uuid: uuid.UUID, connector_uuid: uuid.UUID) -> Any:
    """The connector row when a grant may be made for it: the user's own,
    active, and neither admin_only nor hard_blocked once the account default
    is applied (the stricter tier wins). None otherwise."""
    from sqlalchemy import select

    from models.connector import ConnectorConfig
    from models.user import User
    from services.agent.tool_registry import effective_tier

    connector = (
        await session.execute(
            select(ConnectorConfig).where(
                ConnectorConfig.id == connector_uuid, ConnectorConfig.user_id == user_uuid
            )
        )
    ).scalar_one_or_none()
    if connector is None or not connector.is_active:
        return None
    user = (await session.execute(select(User).where(User.id == user_uuid))).scalar_one_or_none()
    if user is None or not user.is_active:
        return None
    raw = getattr(connector.permission_tier, "value", connector.permission_tier)
    tier = effective_tier(raw, getattr(user, "default_permission_tier", None))
    if tier in ("admin_only", "hard_blocked"):
        return None
    return connector


class DbPermissionGrantStore:
    """Persists grants in the ``permission_grants`` table, with its own
    short-lived sessions (the runtime that calls it has no request scope)."""

    def __init__(
        self,
        session_factory: Optional[Callable[[], Any]] = None,
        now: Callable[[], datetime] = _utcnow,
    ) -> None:
        if session_factory is None:
            from core.database import async_session

            session_factory = async_session
        self._session_factory = session_factory
        self._now = now

    async def _live_rows(self, session: Any, user_uuid: uuid.UUID, **where: Any) -> list[Any]:
        from sqlalchemy import select

        from models.permission_grant import PermissionGrantRow

        query = select(PermissionGrantRow).where(
            PermissionGrantRow.user_id == user_uuid,
            PermissionGrantRow.revoked_at.is_(None),
        )
        for column, value in where.items():
            query = query.where(getattr(PermissionGrantRow, column) == value)
        now = self._now()
        rows = (await session.execute(query)).scalars().all()
        return [row for row in rows if _as_utc(row.expires_at) > now]

    async def allow(
        self,
        *,
        user_id: str,
        connector_id: str,
        kind: str = KIND_LOW_RISK,
        granted_from: Optional[str] = None,
        source_action_id: Optional[str] = None,
    ) -> Optional[PermissionGrant]:
        from models.permission_grant import PermissionGrantRow

        user_uuid, connector_uuid = _uuid(user_id), _uuid(connector_id)
        if user_uuid is None or connector_uuid is None:
            return None
        source = _uuid(source_action_id) if source_action_id else None
        now = self._now()
        async with self._session_factory() as session:
            connector = await connection_allows_grants(session, user_uuid, connector_uuid)
            if connector is None:
                return None
            live = await self._live_rows(session, user_uuid, connector_id=connector_uuid, kind=kind)
            if live:
                row = live[0]
                row.granted_at, row.expires_at = now, now + GRANT_TTL
                row.granted_from = _granted_from(granted_from)
                row.source_action_id = source
            else:
                row = PermissionGrantRow(
                    user_id=user_uuid,
                    connector_id=connector_uuid,
                    kind=kind,
                    granted_from=_granted_from(granted_from),
                    granted_at=now,
                    expires_at=now + GRANT_TTL,
                    source_action_id=source,
                )
                session.add(row)
            await session.flush()
            view = _view(row, connector)
            await session.commit()
        return view

    async def find_live(
        self, *, user_id: str, connector_id: str, kind: str = KIND_LOW_RISK
    ) -> Optional[PermissionGrant]:
        user_uuid, connector_uuid = _uuid(user_id), _uuid(connector_id)
        if user_uuid is None or connector_uuid is None:
            return None
        async with self._session_factory() as session:
            live = await self._live_rows(session, user_uuid, connector_id=connector_uuid, kind=kind)
            return _view(live[0]) if live else None

    async def record_use(self, grant_id: str) -> None:
        from sqlalchemy import update

        from models.permission_grant import PermissionGrantRow

        grant_uuid = _uuid(grant_id)
        if grant_uuid is None:
            return
        async with self._session_factory() as session:
            await session.execute(
                update(PermissionGrantRow)
                .where(PermissionGrantRow.id == grant_uuid)
                .values(uses=PermissionGrantRow.uses + 1, last_used_at=self._now())
            )
            await session.commit()

    async def list_live(self, user_id: str) -> list[PermissionGrant]:
        from sqlalchemy import select

        from models.connector import ConnectorConfig

        user_uuid = _uuid(user_id)
        if user_uuid is None:
            return []
        async with self._session_factory() as session:
            live = await self._live_rows(session, user_uuid)
            if not live:
                return []
            ids = {row.connector_id for row in live}
            connectors = {
                c.id: c
                for c in (
                    await session.execute(
                        select(ConnectorConfig).where(
                            ConnectorConfig.id.in_(ids), ConnectorConfig.user_id == user_uuid
                        )
                    )
                ).scalars()
            }
            views = [_view(row, connectors.get(row.connector_id)) for row in live]
        return sorted(views, key=lambda g: g.expires_at)

    async def revoke(self, *, user_id: str, grant_id: str) -> Optional[PermissionGrant]:
        from sqlalchemy import select

        from models.connector import ConnectorConfig
        from models.permission_grant import PermissionGrantRow

        user_uuid, grant_uuid = _uuid(user_id), _uuid(grant_id)
        if user_uuid is None or grant_uuid is None:
            return None
        async with self._session_factory() as session:
            row = (
                await session.execute(
                    select(PermissionGrantRow).where(
                        PermissionGrantRow.id == grant_uuid,
                        PermissionGrantRow.user_id == user_uuid,
                        PermissionGrantRow.revoked_at.is_(None),
                    )
                )
            ).scalar_one_or_none()
            if row is None:
                return None
            row.revoked_at = self._now()
            connector = (
                await session.execute(
                    select(ConnectorConfig).where(ConnectorConfig.id == row.connector_id)
                )
            ).scalar_one_or_none()
            view = _view(row, connector)
            await session.commit()
        return view

    async def revoke_connector(self, *, user_id: str, connector_id: str) -> int:
        user_uuid, connector_uuid = _uuid(user_id), _uuid(connector_id)
        if user_uuid is None or connector_uuid is None:
            return 0
        async with self._session_factory() as session:
            count = await revoke_grants_in_session(
                session, user_uuid, connector_uuid=connector_uuid, now=self._now()
            )
            await session.commit()
        return count

    async def revoke_all(self, *, user_id: str) -> int:
        user_uuid = _uuid(user_id)
        if user_uuid is None:
            return 0
        async with self._session_factory() as session:
            count = await revoke_grants_in_session(session, user_uuid, now=self._now())
            await session.commit()
        return count


async def revoke_grants_in_session(
    session: Any,
    user_uuid: uuid.UUID,
    *,
    connector_uuid: Optional[uuid.UUID] = None,
    now: Optional[datetime] = None,
) -> int:
    """Revoke the user's live grants (one connection's, or all of them)
    inside the caller's transaction; the caller commits. Returns the count."""
    from sqlalchemy import update

    from models.permission_grant import PermissionGrantRow

    statement = update(PermissionGrantRow).where(
        PermissionGrantRow.user_id == user_uuid,
        PermissionGrantRow.revoked_at.is_(None),
    )
    if connector_uuid is not None:
        statement = statement.where(PermissionGrantRow.connector_id == connector_uuid)
    result = await session.execute(
        statement.values(revoked_at=now or _utcnow()).execution_options(synchronize_session=False)
    )
    # An UPDATE's result is a CursorResult, which counts the rows.
    return int(getattr(result, "rowcount", 0) or 0)


# ---------------------------------------------------------------------------
# Audit rows written outside the runtime (routes, channels, the broker)
# ---------------------------------------------------------------------------


async def audit_revoked(
    session: Any,
    *,
    user_id: Any,
    connector_type: str,
    endpoint: str,
    revoked_from: str,
    grant_id: Optional[str] = None,
    connector_id: Optional[str] = None,
    count: Optional[int] = None,
    reason: Optional[str] = None,
) -> None:
    """One ``permission_grant_revoked`` row in the user's chain: ids, the
    kind, where it was revoked from and why; the caller commits."""
    from services.audit import append_audit_log

    chain: dict[str, Any] = {
        "event": EVENT_REVOKED,
        "kind": KIND_LOW_RISK,
        "revoked_from": revoked_from,
    }
    if grant_id:
        chain["grant_id"] = grant_id
    if connector_id:
        chain["connector_id"] = connector_id
    if count is not None:
        chain["count"] = count
    if reason:
        chain["reason"] = reason
    await append_audit_log(
        session,
        user_id=user_id,
        connector_name=connector_type or "permission_grants",
        action="permission_grant",
        endpoint=endpoint,
        scope_used=connector_type or "permission_grants",
        status=_approved_status(),
        reasoning_chain=chain,
    )


async def audit_tier_changed(
    session: Any,
    *,
    user_id: Any,
    event: str,
    endpoint: str,
    old: Any,
    new: Any,
    connector_type: str = "",
    connector_id: Optional[str] = None,
) -> None:
    """A ``connector_tier_changed`` or ``account_tier_changed`` row: the
    old and new tier (and which connection); the caller commits."""
    from services.audit import append_audit_log

    chain: dict[str, Any] = {
        "event": event,
        "from": str(getattr(old, "value", old)),
        "to": str(getattr(new, "value", new)),
    }
    if connector_id:
        chain["connector_id"] = connector_id
    await append_audit_log(
        session,
        user_id=user_id,
        connector_name=connector_type or "auth",
        action=event,
        endpoint=endpoint,
        scope_used=connector_type or "auth",
        status=_approved_status(),
        reasoning_chain=chain,
    )


def _approved_status() -> Any:
    from models.audit import AuditStatus

    return AuditStatus.approved


def scopes_widened(old: Iterable[str] | None, new: Iterable[str] | None) -> bool:
    """Whether *new* grants a scope *old* did not (a narrower or equal set
    keeps the connection's grants)."""
    return bool(set(new or ()) - set(old or ()))


async def on_connector_updated(
    session: Any,
    *,
    user_id: Any,
    connector: Any,
    connector_type: str,
    old_tier: Any,
    old_scopes: Iterable[str] | None,
    credentials_changed: bool,
    endpoint: str,
) -> int:
    """After a connection's settings changed (PATCH /api/connectors/{id} or
    a reconnect), inside the caller's transaction: audit a tier change
    (``connector_tier_changed``), and when its credentials were replaced or
    a scope was added, revoke its low-risk grants (audited with the count)
    so standing consent never carries over to access nobody granted it
    for. Returns the number of grants revoked. The caller commits; a failed
    audit write fails the change with it."""
    user_uuid = _uuid(user_id)
    connector_uuid = _uuid(getattr(connector, "id", None))
    if user_uuid is None or connector_uuid is None:
        return 0
    new_tier = getattr(connector.permission_tier, "value", connector.permission_tier)
    old_value = getattr(old_tier, "value", old_tier)
    if old_value != new_tier:
        await audit_tier_changed(
            session,
            user_id=user_uuid,
            event=EVENT_CONNECTOR_TIER,
            endpoint=endpoint,
            old=old_value,
            new=new_tier,
            connector_type=connector_type,
            connector_id=str(connector_uuid),
        )
    widened = scopes_widened(old_scopes, getattr(connector, "granted_scopes", None))
    if not (credentials_changed or widened):
        return 0
    count = await revoke_grants_in_session(session, user_uuid, connector_uuid=connector_uuid)
    if count:
        await audit_revoked(
            session,
            user_id=user_uuid,
            connector_type=connector_type,
            endpoint=endpoint,
            revoked_from="connector_change",
            connector_id=str(connector_uuid),
            count=count,
            reason="credentials replaced" if credentials_changed else "scope added",
        )
    return count


# ---------------------------------------------------------------------------
# One turn's standing consent (the runtime's anchors)
# ---------------------------------------------------------------------------


def accepts_keyword(callback: Any, name: str) -> bool:
    """Whether *callback* takes the keyword *name* (by name or **kwargs):
    fakes and older callers without it are called exactly as before."""
    try:
        params = inspect.signature(callback).parameters.values()
    except (TypeError, ValueError):
        return False
    return any(
        p.kind is p.VAR_KEYWORD
        or (p.name == name and p.kind in (p.KEYWORD_ONLY, p.POSITIONAL_OR_KEYWORD))
        for p in params
    )


def connection_of(tool_name: str) -> str:
    """The connection a tool name belongs to: its namespace (``gmail`` part
    of ``google_workspace__1a2b3c4d.get_message``). Two accounts of one type
    have different namespaces, so provenance never crosses accounts."""
    return tool_name.partition(".")[0] if isinstance(tool_name, str) else ""


def _flagged(result: Any) -> bool:
    """Whether a recorded tool result carries PromptGuard's redaction
    (runtime._scan_and_redact_result): the whole result, or one item of a
    list in it, replaced by a ``{"redacted": True, "reason": ...}`` marker,
    or a line of an outline replaced by ``[line redacted: ...]``."""
    if not isinstance(result, Mapping):
        return False
    if result.get("redacted") is True and "reason" in result:
        return True
    for value in result.values():
        if not isinstance(value, list):
            continue
        for item in value:
            if isinstance(item, Mapping) and item.get("redacted") is True and "reason" in item:
                return True
            if isinstance(item, str) and item.startswith("[line redacted: "):
                return True
    return False


def _succeeded(result: Any) -> bool:
    return isinstance(result, Mapping) and result.get("ok") is True


@dataclass
class _Decision:
    """What standing consent decided for one call."""

    grade: RiskGrade
    tool: str
    connector_id: Optional[str] = None
    account: str = ""
    # "tier" | "low_risk" | "low_risk_grant" when it runs without a card.
    kind: Optional[str] = None
    grant_id: Optional[str] = None
    # A warning its card carries (SUSPENDED_NOTE) in the risk note.
    note: Optional[str] = None
    # Why its card asks when standing consent did not cover it (the grade's
    # sentence, CAP_NOTE): plain policy, added to the card's reason.
    why: Optional[str] = None
    # Standing consent could have covered it (a tier or a grant applied):
    # its card offers no grant.
    covered: bool = False


@dataclass
class StandingConsent:
    """One turn's standing-consent state: the per-turn low-risk count, the
    tripwire (``suspended``), each call's decision and the low-risk runs
    for the reply's "Done without asking" line.

    ``grants`` is the runtime's store (None: no grant ever applies);
    ``switch`` answers whether the owner's low_risk_actions capability is
    on (read once per turn, on first need; an error reads as off)."""

    user_id: str
    grants: Optional[PermissionGrantStore] = None
    switch: Optional[Callable[[], Awaitable[bool]]] = None
    count: int = 0
    suspended: bool = False
    _scanned: int = 0
    _switch_on: Optional[bool] = None
    _grant_cache: dict[str, Optional[PermissionGrant]] = field(default_factory=dict)
    _current: Optional[tuple[Any, _Decision]] = None
    _runs: list[tuple[str, str, Optional[str]]] = field(default_factory=list)

    # -- the tripwire ---------------------------------------------------------

    def _watch(self, results: list[dict[str, Any]]) -> None:
        """Suspend standing consent for the rest of the turn once any result
        recorded so far was flagged by PromptGuard."""
        for record in results[self._scanned :]:
            if not self.suspended and _flagged(record.get("result")):
                self.suspended = True
                logger.info("standing_consent_suspended", user_id=self.user_id)
        self._scanned = len(results)

    async def _switch_is_on(self) -> bool:
        if self._switch_on is None:
            if self.switch is None:
                self._switch_on = True
            else:
                try:
                    self._switch_on = bool(await self.switch())
                except Exception as exc:
                    logger.warning("low_risk_switch_unreadable", error_type=type(exc).__name__)
                    self._switch_on = False
        return self._switch_on

    async def _live_grant(self, connector_id: str) -> Optional[PermissionGrant]:
        if self.grants is None:
            return None
        if connector_id not in self._grant_cache:
            try:
                grant = await self.grants.find_live(user_id=self.user_id, connector_id=connector_id)
            except Exception as exc:
                # A store that fails answers "no grant": a card, never a run.
                logger.warning("permission_grant_lookup_failed", error_type=type(exc).__name__)
                grant = None
            self._grant_cache[connector_id] = grant
        return self._grant_cache[connector_id]

    def _decision_for(self, tc: Any) -> Optional[_Decision]:
        if self._current is None or self._current[0] is not tc:
            return None
        return self._current[1]

    # -- call_post_permission -------------------------------------------------

    async def decide(
        self,
        tc: Any,
        offered: Any,
        permission: str,
        approved_via_tier: bool,
        *,
        unattended: bool,
        results: list[dict[str, Any]],
    ) -> tuple[str, bool]:
        """The call's ``(permission, approved_via_tier)`` after standing
        consent, right after the permission check (and the unattended rule).

        - An unattended turn, or one whose earlier result PromptGuard flagged,
          uses no standing consent: the call asks.
        - The auto_approve tier ("auto" label) runs it unless it grades HIGH.
        - The low_risk tier ("low_risk" label) or a live grant for the
          offered connection runs it only when it grades LOW, the owner's
          switch is on and fewer than LOW_RISK_MAX_PER_TURN such runs
          happened this turn.
        Anything else is unchanged; a blocked call stays blocked."""
        self._watch(results)
        self._current = None
        if permission == "blocked" or not (permission == "requires_approval" or approved_via_tier):
            return permission, approved_via_tier
        if unattended:
            # No decision is kept: the unattended rule already made it a card
            # (with its origin, note and trusted-text taint check), and no
            # grant is ever offered on it.
            return "requires_approval", False
        grade = grade_tool(tc.name, tc.arguments)
        decision = _Decision(
            grade=grade,
            tool=_canonical(tc.name),
            connector_id=getattr(offered, "connector_id", None) or None,
            account=getattr(offered, "account", "") or "",
        )
        self._current = (tc, decision)
        label = getattr(offered, "permission_tier", "")
        if self.suspended:
            decision.covered = True
            if approved_via_tier or label == "low_risk":
                decision.note = SUSPENDED_NOTE
            return "requires_approval", False
        if approved_via_tier:
            decision.covered = True
            if grade.is_high:
                decision.why = card_note(grade)
                return "requires_approval", False
            decision.kind = APPROVAL_TIER
            return "approved", True
        grant = None
        if label != "low_risk" and decision.connector_id:
            grant = await self._live_grant(decision.connector_id)
        if label != "low_risk" and grant is None:
            return permission, approved_via_tier
        decision.covered = True
        if not grade.is_low:
            decision.why = card_note(grade)
            return permission, approved_via_tier
        if not await self._switch_is_on():
            return permission, approved_via_tier
        if self.count >= LOW_RISK_MAX_PER_TURN:
            decision.why = CAP_NOTE
            return permission, approved_via_tier
        self.count += 1
        if label == "low_risk":
            decision.kind = APPROVAL_LOW_RISK
        else:
            assert grant is not None
            decision.kind, decision.grant_id = APPROVAL_LOW_RISK_GRANT, grant.id
        return "approved", True

    # -- call_taint -----------------------------------------------------------

    def taint_reason(self, tc: Any, taint: Any, reason: Optional[str]) -> Optional[str]:
        """The taint reason with the ref_args exemption applied: a LOW call
        may name an object id its own connection returned this turn. A
        standing-consent run that is still tainted goes back to a card (the
        runtime's taint gate), and no longer counts as a low-risk run."""
        decision = self._decision_for(tc)
        if decision is None:
            return reason
        if reason is not None and decision.grade.is_low:
            refs = ref_args_of(tc.name)
            if refs:
                reason = taint.taint_reason(
                    tc.arguments, ref_args=refs, source=connection_of(tc.name)
                )
        if reason is not None and decision.kind is not None:
            if decision.kind in _LOW_KINDS:
                self.count = max(0, self.count - 1)
            decision.kind, decision.grant_id = None, None
        return reason

    # -- card_create ----------------------------------------------------------

    async def card_fields(
        self,
        tc: Any,
        taint_reason: Optional[str],
        note: Optional[str],
        extra: dict[str, Any],
        *,
        accepts_offer: bool,
    ) -> tuple[Optional[str], dict[str, Any]]:
        """The card's risk note (the tripwire's warning after any taint
        warning; standing consent's routine "why" goes in the reason instead,
        ``card_reason``) and its store arguments: ``grant_offer`` only for an
        untainted, attended LOW card with the owner's switch on, no origin,
        no tripwire, and no tier or grant already covering the account."""
        decision = self._decision_for(tc)
        if decision is None:
            return note, extra
        if decision.note:
            note = f"{note} {decision.note}" if note else decision.note
        if (
            accepts_offer
            and not decision.covered
            and not self.suspended
            and taint_reason is None
            and "origin" not in extra
            and decision.grade.is_low
            and decision.connector_id
            and self.grants is not None
            and await self._switch_is_on()
        ):
            extra = {
                **extra,
                "grant_offer": {
                    "kind": KIND_LOW_RISK,
                    "connector_id": decision.connector_id,
                    "account": decision.account,
                },
            }
        return note, extra

    def card_reason(self, tc: Any, reason: str) -> str:
        """The card's reason with standing consent's routine sentence after
        it (why a tier or grant did not cover this call), when there is one.
        Plain text on every channel, unlike the risk note."""
        decision = self._decision_for(tc)
        if decision is None or not decision.why:
            return reason
        return f"{reason} {decision.why}" if reason else decision.why

    # -- execution ------------------------------------------------------------

    def execute_kwargs(self, tc: Any, execute: Any) -> dict[str, Any]:
        """``{"approval": kind}`` for a call standing consent runs, when the
        executor takes it (its backstop re-checks), else {}."""
        decision = self._decision_for(tc)
        if decision is None or decision.kind is None or not accepts_keyword(execute, "approval"):
            return {}
        return {"approval": decision.kind}

    def audit_fields(self, tc: Any) -> dict[str, Any]:
        """What a run's tool_executing and tool_executed rows add: how it
        ran without a card, its grade and reason, and the grant."""
        decision = self._decision_for(tc)
        if decision is None or decision.kind is None:
            return {}
        fields: dict[str, Any] = {
            "approval": decision.kind,
            "risk": decision.grade.risk.value,
            "risk_reason": decision.grade.reason,
        }
        if decision.grant_id:
            fields["grant_id"] = decision.grant_id
        return fields

    def ran(self, tc: Any, result: Any) -> None:
        """Note a low-risk run that succeeded, for the reply's line."""
        decision = self._decision_for(tc)
        if decision is not None and decision.kind in _LOW_KINDS and _succeeded(result):
            self._runs.append((decision.tool, decision.account, decision.grant_id))

    # -- turn_end -------------------------------------------------------------

    async def finish(self, content: str) -> str:
        """*content* with the "Done without asking" line when low-risk
        changes ran without a card, and each grant's use recorded (best
        effort: the changes already ran)."""
        if not self._runs:
            return content
        if self.grants is not None:
            for _tool, _account, grant_id in self._runs:
                if grant_id:
                    try:
                        await self.grants.record_use(grant_id)
                    except Exception as exc:
                        logger.warning("permission_grant_use_not_recorded", error_type=type(exc).__name__)
        line = ran_without_asking_line((tool, account) for tool, account, _ in self._runs)
        return f"{content.rstrip()}\n\n{line}" if content.strip() else line


def _canonical(tool_name: str) -> str:
    from services.agent.runtime import canonical_tool_name

    return canonical_tool_name(tool_name)
