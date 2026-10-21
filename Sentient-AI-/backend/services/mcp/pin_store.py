"""MCP tool pins (security S5): reads and writes the approved definition of
every tool a connected MCP server advertises, for the catalog, the
dispatcher, the call check and the Security page's MCP reviews.

Why it exists: an MCP server can change a tool's description or inputs after
the owner connected it (a "rug pull"), and the new text reaches the model as
trusted tool metadata. Pinning each tool's definition the first time it is
seen, and holding any change for the owner's review, means a changed tool is
never offered or run until the owner looked at it. A pin read that fails
withholds the server's tools (fail closed).

Every decision (what changed, what may be offered, what the owner is shown)
is a pure function in services/mcp/pinning.py; this module only reads the
rows, writes what the plan says inside one transaction, and then audits and
tells the owner's linked chats about the transitions this call won. Writes
are conditional (``status`` and ``pending_hash`` must still be what the plan
read), so two workers racing on one server settle on one set of pins, and
only the winner audits or notifies. Logs carry ids, counts and exception
type names only: never a remote tool name, a definition or a server URL.

Connects to: services/mcp/pinning.py (the plan and the review),
services/mcp/pin_notify.py (the words), models/mcp_tool_pin.py (the table),
services/mcp/integration.py (catalog and dispatcher ``pins=``),
services/agent/tool_registry.py (``use_mcp_pins``), api/routes/connectors.py
(the owner Test and credential edits), api/routes/security_mcp.py (the
review routes), main.py, services/mcp/pin_check.py.
"""

from __future__ import annotations

import json
import uuid
from collections.abc import Awaitable, Callable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING, Any, Optional

import structlog
from sqlalchemy import delete, func, select, update
from sqlalchemy.exc import IntegrityError

from models.audit import AuditStatus
from models.connector import ConnectorConfig, ConnectorType
from models.mcp_tool_pin import McpToolPin
from services.mcp.pin_notify import (
    NOTIFY_EVERY,
    HeldTool,
    held_message,
    may_notify,
    owner_test_note,
)
from services.mcp.pinning import (
    MAX_PINS_PER_SERVER,
    MAX_STORED_DEFINITION_BYTES,
    REMOVED_PIN_RETENTION,
    RULE_PIN_UNAVAILABLE,
    RULE_TOOL_REMOVED,
    SENTINEL_STATUS,
    STATUS_NEEDS_REVIEW,
    NewPin,
    PinState,
    PinUpdate,
    ReconcilePlan,
    SeenTool,
    TrustSource,
    decide_approval,
    decide_call,
    keep_off_values,
    name_key,
    plan_reconcile,
    refusal_message,
    same_server,
    sort_for_review,
    text_parts,
)

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession

    from services.mcp.client import MCPToolInfo

logger = structlog.get_logger(__name__)

# The storage limits and the message throttle live beside the pure plan
# (pinning.py, pin_notify.py) because the plan needs them; they are re-exported
# here, where the spec places them, for callers that think of them as the
# store's.
__all__ = [
    "MAX_PINS_PER_SERVER",
    "MAX_STORED_DEFINITION_BYTES",
    "NOTIFY_EVERY",
    "REMOVED_PIN_RETENTION",
    "CallPinVerdict",
    "McpPinService",
    "PinServer",
    "PinStoreUnavailable",
    "ReconcileResult",
    "ServerReviewRow",
    "StaleReview",
    "approve_pin",
    "get_owned_pin",
    "keep_pin_off",
    "list_reviews",
    "pin_note_after_owner_test",
    "pin_view",
    "reset_pins_if_server_moved",
]

# The two audit events this module writes through the runtime's audit sink
# (services/audit.py _EVENT_STATUS registers both; a test pins that they
# agree). Used directly only when an owner Test writes on its request session.
_AUDIT_STATUS: Mapping[str, AuditStatus] = {
    "mcp_tool_pinned": AuditStatus.approved,
    "mcp_tool_changed": AuditStatus.blocked,
}


class PinStoreUnavailable(Exception):
    """The pins could not be read or written; callers withhold the server's
    tools (fail closed)."""


class StaleReview(Exception):
    """The definition hash the owner approved is no longer the one waiting (409)."""


@dataclass(frozen=True)
class PinServer:
    connector_id: uuid.UUID
    user_id: uuid.UUID
    label: str  # slug, as in mcp.<label>.<tool>
    display_name: str  # the owner's own name for the connector, for messages


@dataclass(frozen=True)
class ReconcileResult:
    entries: tuple[tuple[str, Any], ...]  # (exposed, MCPToolInfo) for every seen tool
    offered: frozenset[str]  # name_keys allowed
    rules: Mapping[str, str]  # name_key -> rule for the held ones
    removed_exposed: frozenset[str]  # exposed names held by removed pins
    needs_discovery: bool
    first_use: bool = False  # this call trusted the server on first use

    def offered_entries(self) -> list[tuple[str, Any]]:
        """(exposed, info) for every tool that may be offered and run."""
        return [
            (exposed, info) for exposed, info in self.entries if name_key(info.name) in self.offered
        ]

    def resolve(self, exposed_name: str) -> tuple[Optional[Any], Optional[str]]:
        """The dispatcher's lookup of ``mcp.<label>.<exposed_name>`` through the
        persisted names: ``(info, None)`` when it may run, ``(info, rule)`` when
        it is held, ``(None, "mcp_tool_removed")`` when only a removed pin holds
        the name, ``(None, None)`` when the server does not advertise it."""
        for exposed, info in self.entries:
            if exposed == exposed_name:
                key = name_key(info.name)
                if key in self.offered:
                    return info, None
                return info, self.rules.get(key, RULE_PIN_UNAVAILABLE)
        if exposed_name in self.removed_exposed:
            return None, RULE_TOOL_REMOVED
        return None, None


@dataclass(frozen=True)
class CallPinVerdict:
    allowed: bool
    rule: str = ""
    message: str = ""
    hidden_chars: int = 0  # of the approved definition, for the card note


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _no_session_factory() -> Any:
    # A service built without a database (the owner Test's fallback, which
    # only ever writes on the request's session) fails closed if it is
    # ever asked to open one.
    raise PinStoreUnavailable("No database is wired for MCP tool pins.")


def _utc(moment: Optional[datetime]) -> Optional[datetime]:
    # SQLite hands timezone-aware columns back without a zone; they are UTC.
    if moment is None:
        return None
    return moment if moment.tzinfo is not None else moment.replace(tzinfo=timezone.utc)


# The hot-path projection of a row: no definitions, no remote name.
_LIGHT_COLUMNS = (
    McpToolPin.id,
    McpToolPin.connector_id,
    McpToolPin.name_key,
    McpToolPin.exposed_name,
    McpToolPin.status,
    McpToolPin.review_kind,
    McpToolPin.approved_hash,
    McpToolPin.pending_hash,
    McpToolPin.approved_hidden_chars,
    McpToolPin.updated_at,
    McpToolPin.removed_at,
)

# What the Security tab's list needs: still no definitions.
_REVIEW_COLUMNS = (
    McpToolPin.id,
    McpToolPin.connector_id,
    McpToolPin.remote_name,
    McpToolPin.exposed_name,
    McpToolPin.status,
    McpToolPin.review_kind,
    McpToolPin.trusted_how,
    McpToolPin.approved_hash,
    McpToolPin.pending_hash,
    McpToolPin.approved_hidden_chars,
    McpToolPin.pending_hidden_chars,
    McpToolPin.change_count,
    McpToolPin.first_seen_at,
    McpToolPin.approved_at,
    McpToolPin.changed_at,
    McpToolPin.removed_at,
    McpToolPin.updated_at,
)


async def _read_light(
    session: AsyncSession,
    connector_ids: Sequence[uuid.UUID],
    *,
    user_id: Optional[uuid.UUID] = None,
) -> dict[uuid.UUID, list[PinState]]:
    """ONE SELECT of the light columns for every listed server. Joined with
    connector_configs (and the pin's owner must be the connector's), so an
    orphan row can never be read even on a database without foreign keys."""
    query = (
        select(*_LIGHT_COLUMNS)
        .join(ConnectorConfig, ConnectorConfig.id == McpToolPin.connector_id)
        .where(
            McpToolPin.connector_id.in_(list(connector_ids)),
            McpToolPin.user_id == ConnectorConfig.user_id,
        )
        .order_by(McpToolPin.connector_id, McpToolPin.name_key)
    )
    if user_id is not None:
        query = query.where(McpToolPin.user_id == user_id)
    found: dict[uuid.UUID, list[PinState]] = {}
    for row in (await session.execute(query)).all():
        found.setdefault(row.connector_id, []).append(PinState.from_row(row))
    return found


@dataclass
class _Outcome:
    """What one write transaction did: the plan it applied, the rows it
    inserted, the updates it won (with the change count they left), and the
    tools whose update another worker made first."""

    plan: ReconcilePlan
    inserted: list[tuple[NewPin, McpToolPin]] = field(default_factory=list)
    won: list[tuple[PinUpdate, int]] = field(default_factory=list)
    lost: set[str] = field(default_factory=set)


def _result(plan: ReconcilePlan, lost: Optional[set[str]] = None) -> ReconcileResult:
    """The caller's view of a plan: a tool whose transition another worker made
    first is not offered this turn (its rule is kept, or "could not check")."""
    lost = lost or set()
    rules = dict(plan.rules)
    for key in lost:
        rules.setdefault(key, RULE_PIN_UNAVAILABLE)
    return ReconcileResult(
        entries=tuple((exposed, tool.info) for exposed, tool in plan.entries),
        offered=frozenset(key for key in plan.offered if key not in lost),
        rules=rules,
        removed_exposed=plan.removed_exposed,
        needs_discovery=plan.needs_discovery,
        first_use=plan.first_use and plan.has_writes,
    )


async def _apply(
    session: AsyncSession,
    server: PinServer,
    seen: Sequence[SeenTool],
    *,
    now: datetime,
    source: TrustSource,
    fresh: Optional[bool],
) -> _Outcome:
    """Re-read this server's pins inside the caller's transaction, re-plan, and
    write what the plan says. Inserts that race raise IntegrityError (the unique
    key, the sentinel included); updates are conditional and a lost one is
    recorded, never retried."""
    pins = (await _read_light(session, [server.connector_id], user_id=server.user_id)).get(
        server.connector_id, []
    )
    plan = plan_reconcile(server.label, pins, seen, now=now, source=source, fresh=fresh)
    outcome = _Outcome(plan)
    if not plan.has_writes:
        return outcome

    for new in plan.inserts:
        row = McpToolPin(user_id=server.user_id, connector_id=server.connector_id, **new.columns())
        session.add(row)
        outcome.inserted.append((new, row))
    if plan.inserts:
        await session.flush()

    for change in plan.updates:
        values: dict[str, Any] = dict(change.values)
        if change.bump_change_count:
            values["change_count"] = McpToolPin.change_count + 1
        statement = (
            update(McpToolPin)
            .where(
                McpToolPin.id == change.pin_id,
                McpToolPin.connector_id == server.connector_id,
                McpToolPin.user_id == server.user_id,
                McpToolPin.status == change.expect_status,
                McpToolPin.pending_hash.is_not_distinct_from(change.expect_pending_hash),
            )
            .values(**values)
            .returning(McpToolPin.change_count)
            .execution_options(synchronize_session=False)
        )
        written = (await session.execute(statement)).first()
        if written is None:
            # Another worker made this transition first: it audits and tells
            # the owner; this call does neither and does not offer the tool.
            outcome.lost.add(change.name_key)
            continue
        outcome.won.append((change, int(written.change_count)))

    if plan.deletes:
        await session.execute(
            delete(McpToolPin)
            .where(
                McpToolPin.id.in_(list(plan.deletes)),
                McpToolPin.connector_id == server.connector_id,
                McpToolPin.user_id == server.user_id,
            )
            .execution_options(synchronize_session=False)
        )
    return outcome


def _audit_entries(server: PinServer, outcome: _Outcome, source: str) -> list[dict[str, Any]]:
    """The audit rows for the transitions *outcome* won: one ``mcp_tool_pinned``
    per first-use pinning (with a count), one ``mcp_tool_changed`` per new
    pending definition. Ids, kinds, counts and hashes only."""
    plan = outcome.plan
    user = str(server.user_id)
    connector = str(server.connector_id)
    entries: list[dict[str, Any]] = []
    if plan.first_use and outcome.inserted:
        entries.append(
            {
                "event": "mcp_tool_pinned",
                "user_id": user,
                "tool": f"mcp.{server.label}",
                "connector_id": connector,
                "kind": source,
                "arguments": {"tools": plan.pinned_on_first_use},
            }
        )
    exposed_of = {tool.name_key: exposed for exposed, tool in plan.entries}
    for new, row in outcome.inserted:
        if new.held is None:
            continue
        entries.append(
            {
                "event": "mcp_tool_changed",
                "user_id": user,
                "tool": f"mcp.{server.label}.{new.exposed_name}",
                "connector_id": connector,
                "kind": new.held.kind,
                "arguments": {
                    "pin_id": str(row.id),
                    "previous_hash": new.held.previous_hash,
                    "definition_hash": new.held.definition_hash,
                    "change_count": new.change_count,
                },
            }
        )
    for change, change_count in outcome.won:
        if change.held is None:
            continue
        exposed = str(change.values.get("exposed_name") or exposed_of.get(change.name_key, ""))
        entries.append(
            {
                "event": "mcp_tool_changed",
                "user_id": user,
                "tool": f"mcp.{server.label}.{exposed}",
                "connector_id": connector,
                "kind": change.held.kind,
                "arguments": {
                    "pin_id": str(change.pin_id),
                    "previous_hash": change.held.previous_hash,
                    "definition_hash": change.held.definition_hash,
                    "change_count": change_count,
                },
            }
        )
    return entries


def _notify_ids(outcome: _Outcome) -> list[uuid.UUID]:
    """The pins this call just held whose change should be told (never a
    kept-off pin: the owner chose to keep it off)."""
    ids = [row.id for new, row in outcome.inserted if new.held is not None and new.held.notify]
    ids += [
        change.pin_id
        for change, _ in outcome.won
        if change.held is not None and change.held.notify
    ]
    return ids


async def _append_in_session(session: AsyncSession, entry: Mapping[str, Any]) -> None:
    """One audit row on the caller's session, shaped exactly as
    RuntimeAuditLogger.log shapes it, so it commits with the pins it records."""
    from services.audit import append_audit_log

    connector_name, _, action = str(entry["tool"]).partition(".")
    event = str(entry["event"])
    await append_audit_log(
        session,
        user_id=str(entry["user_id"]),
        connector_name=connector_name,
        action=action,
        endpoint=f"agent.{event}",
        scope_used=connector_name,
        status=_AUDIT_STATUS[event],
        reasoning_chain={
            "event": event,
            "connector_id": entry["connector_id"],
            "kind": entry["kind"],
        },
        request_data=entry.get("arguments"),
    )


class McpPinService:
    """Reads and writes MCP tool pins for the catalog, the dispatcher, the call
    check and the routes. One per process (main.py); tests build their own.

    *enabled* is the owner's switch (``mcp_pinning``); a hook that raises, or
    none at all, counts as on, because this is an integrity gate and failing
    open would let a changed tool through. *notify* is the owner's sender
    ``(user_id, text) -> delivered``; *audit* the runtime audit sink."""

    def __init__(
        self,
        session_factory: Optional[Callable[[], Any]],
        *,
        enabled: Optional[Callable[[], Awaitable[bool]]] = None,
        notify: Optional[Callable[[str, str], Awaitable[bool]]] = None,
        audit: Optional[Callable[[dict[str, Any]], Awaitable[None]]] = None,
        clock: Callable[[], datetime] = _utcnow,
        notify_every: timedelta = NOTIFY_EVERY,
    ) -> None:
        self._session_factory = (
            session_factory if session_factory is not None else _no_session_factory
        )
        self._enabled = enabled
        self._notify = notify
        self._audit = audit
        self._clock = clock
        self._notify_every = notify_every

    async def is_enabled(self) -> bool:
        """The owner's switch; a hook that raises, or none, counts as on."""
        if self._enabled is None:
            return True
        try:
            return bool(await self._enabled())
        except Exception as exc:
            logger.warning("mcp_pinning_switch_unreadable", error_type=type(exc).__name__)
            return True

    async def read_pins(self, connector_ids: Sequence[uuid.UUID]) -> dict[uuid.UUID, list[PinState]]:
        """ONE light SELECT for every listed server (no definition columns); raises
        PinStoreUnavailable on any database error. Every listed server gets an
        entry (an empty list when it has no rows)."""
        ids = list(dict.fromkeys(connector_ids))
        if not ids:
            return {}
        try:
            async with self._session_factory() as session:
                found = await _read_light(session, ids)
        except Exception as exc:
            logger.warning("mcp_pins_read_failed", servers=len(ids), error_type=type(exc).__name__)
            raise PinStoreUnavailable("MCP tool pins could not be read.") from exc
        return {connector_id: found.get(connector_id, []) for connector_id in ids}

    async def reconcile(
        self,
        server: PinServer,
        seen: Sequence[SeenTool],
        *,
        known: Optional[Sequence[PinState]] = None,
        source: TrustSource = "first_use",
        notify: bool = True,
        fresh: Optional[bool] = None,
    ) -> ReconcileResult:
        """Plan against *known* (or a fresh read); when the plan writes, open one
        transaction, re-read this server's pins inside it, re-plan, apply, commit,
        then audit and notify for the transitions this call won. Raises
        PinStoreUnavailable. *fresh* is False for the catalog's cached listing
        (pinning.plan_reconcile: a cached list never moves a pin's state)."""
        now = self._clock()
        pins = (
            list(known)
            if known is not None
            else (await self.read_pins([server.connector_id]))[server.connector_id]
        )
        plan = plan_reconcile(server.label, pins, seen, now=now, source=source, fresh=fresh)
        if not plan.has_writes:
            return _result(plan)
        outcome = await self._write(server, seen, now=now, source=source, fresh=fresh)
        if outcome.plan.has_writes:
            await self._audit_won(server, outcome, source)
            if notify and source == "first_use":
                await self._tell_owner(server, _notify_ids(outcome), now=now)
        return _result(outcome.plan, outcome.lost)

    async def _write(
        self,
        server: PinServer,
        seen: Sequence[SeenTool],
        *,
        now: datetime,
        source: TrustSource,
        fresh: Optional[bool],
    ) -> _Outcome:
        """One write transaction, retried once when an insert raced another
        worker's (the re-read then sees its rows)."""
        for attempt in (1, 2):
            try:
                async with self._session_factory() as session:
                    async with session.begin():
                        return await _apply(
                            session, server, seen, now=now, source=source, fresh=fresh
                        )
            except IntegrityError:
                logger.info(
                    "mcp_pin_write_raced", connector_id=str(server.connector_id), attempt=attempt
                )
            except Exception as exc:
                logger.warning(
                    "mcp_pin_write_failed",
                    connector_id=str(server.connector_id),
                    error_type=type(exc).__name__,
                )
                raise PinStoreUnavailable("MCP tool pins could not be written.") from exc
        raise PinStoreUnavailable("MCP tool pins could not be written.")

    async def reconcile_in_session(
        self,
        session: AsyncSession,
        server: PinServer,
        seen: Sequence[SeenTool],
        *,
        source: TrustSource,
        notify: bool,
        fresh: Optional[bool] = None,
    ) -> ReconcileResult:
        """The same on a caller's session (the Test route's request session),
        inside a SAVEPOINT so a pin failure cannot spoil the request's
        transaction; it flushes and the request commits. The audit rows are
        written on that session too, so they commit (or roll back) with the
        pins. No channel message goes from here whatever *notify* says: messages
        follow a commit, and the owner running a Test is looking at the page."""
        now = self._clock()
        for attempt in (1, 2):
            try:
                async with session.begin_nested():
                    outcome = await _apply(
                        session, server, seen, now=now, source=source, fresh=fresh
                    )
                    for entry in _audit_entries(server, outcome, source):
                        await _append_in_session(session, entry)
                return _result(outcome.plan, outcome.lost)
            except IntegrityError:
                logger.info(
                    "mcp_pin_write_raced", connector_id=str(server.connector_id), attempt=attempt
                )
            except Exception as exc:
                logger.warning(
                    "mcp_pin_write_failed",
                    connector_id=str(server.connector_id),
                    error_type=type(exc).__name__,
                )
                raise PinStoreUnavailable("MCP tool pins could not be written.") from exc
        raise PinStoreUnavailable("MCP tool pins could not be written.")

    async def _audit_won(self, server: PinServer, outcome: _Outcome, source: str) -> None:
        """Best effort: the pin state, the real control, is already committed."""
        if self._audit is None:
            return
        for entry in _audit_entries(server, outcome, source):
            try:
                await self._audit(entry)
            except Exception as exc:
                logger.warning(
                    "mcp_pin_audit_failed", event=entry["event"], error_type=type(exc).__name__
                )

    async def _tell_owner(
        self, server: PinServer, pin_ids: Sequence[uuid.UUID], *, now: datetime
    ) -> None:
        """Claim the new pending hashes, then send one fact-only message for the
        server unless one went out within the throttle window. A claimed change
        is never told later, whatever happens to the message; it stays held and
        listed on the Security page. Never raises."""
        if self._notify is None or not pin_ids:
            return
        try:
            async with self._session_factory() as session:
                async with session.begin():
                    claimed = (
                        await session.execute(
                            update(McpToolPin)
                            .where(
                                McpToolPin.id.in_(list(pin_ids)),
                                McpToolPin.connector_id == server.connector_id,
                                McpToolPin.user_id == server.user_id,
                                McpToolPin.status == STATUS_NEEDS_REVIEW,
                                McpToolPin.notified_hash.is_distinct_from(McpToolPin.pending_hash),
                            )
                            .values(notified_hash=McpToolPin.pending_hash)
                            .returning(
                                McpToolPin.id, McpToolPin.exposed_name, McpToolPin.review_kind
                            )
                            .execution_options(synchronize_session=False)
                        )
                    ).all()
                    if not claimed:
                        return
                    recent = (
                        (
                            await session.execute(
                                select(McpToolPin.notified_at).where(
                                    McpToolPin.connector_id == server.connector_id,
                                    McpToolPin.notified_at.is_not(None),
                                )
                            )
                        )
                        .scalars()
                        .all()
                    )
                    allowed = may_notify(recent, now=now, every=self._notify_every)
                    if allowed:
                        await session.execute(
                            update(McpToolPin)
                            .where(McpToolPin.id.in_([row.id for row in claimed]))
                            .values(notified_at=now)
                            .execution_options(synchronize_session=False)
                        )
        except Exception as exc:
            logger.warning(
                "mcp_pin_notify_claim_failed",
                connector_id=str(server.connector_id),
                error_type=type(exc).__name__,
            )
            return
        if not allowed:
            # Claimed, so never sent later; the change is held and listed.
            logger.info(
                "mcp_pin_notify_throttled",
                connector_id=str(server.connector_id),
                tools=len(claimed),
            )
            return
        text = held_message(
            server.display_name,
            [HeldTool(str(row.exposed_name), str(row.review_kind or "changed")) for row in claimed],
        )
        try:
            delivered = await self._notify(str(server.user_id), text)
        except Exception as exc:
            logger.warning(
                "mcp_pin_notify_failed",
                connector_id=str(server.connector_id),
                error_type=type(exc).__name__,
            )
            return
        if not delivered:
            logger.info("mcp_pin_notify_not_delivered", connector_id=str(server.connector_id))

    async def check_call(self, user_id: str, tool_name: str) -> CallPinVerdict:
        """Whether mcp.<label>.<tool> may be carded or run, from the database only:
        two light queries (the user's active MCP connectors, then their pins).
        Allowed for a name that is not an MCP name, while the switch is off, and
        when no active MCP connector has that label; refused when any connector
        with the label holds the tool; refused ``mcp_pin_unavailable`` on any
        database error (fail closed)."""
        # Deferred: integration imports this module.
        from services.mcp.integration import slugify_label, split_mcp_tool

        parts = split_mcp_tool(str(tool_name))
        if parts is None:
            return CallPinVerdict(allowed=True)
        label, exposed = parts
        if not await self.is_enabled():
            return CallPinVerdict(allowed=True)
        try:
            user_uuid = uuid.UUID(str(user_id))
        except ValueError:
            return CallPinVerdict(allowed=True)
        try:
            async with self._session_factory() as session:
                connectors = (
                    await session.execute(
                        select(ConnectorConfig.id, ConnectorConfig.display_name).where(
                            ConnectorConfig.user_id == user_uuid,
                            ConnectorConfig.connector_type == ConnectorType.mcp,
                            ConnectorConfig.is_active.is_(True),
                        )
                    )
                ).all()
                ids = [row.id for row in connectors if slugify_label(row.display_name) == label]
                if not ids:
                    return CallPinVerdict(allowed=True)
                found = await _read_light(session, ids, user_id=user_uuid)
        except Exception as exc:
            logger.warning("mcp_pin_check_failed", error_type=type(exc).__name__)
            return CallPinVerdict(
                allowed=False,
                rule=RULE_PIN_UNAVAILABLE,
                message=refusal_message(RULE_PIN_UNAVAILABLE, tool=exposed, label=label),
            )
        decision = decide_call(exposed, [found.get(connector_id, []) for connector_id in ids])
        if decision.allowed:
            return CallPinVerdict(allowed=True, hidden_chars=decision.hidden_chars)
        return CallPinVerdict(
            allowed=False,
            rule=decision.rule,
            message=refusal_message(decision.rule, tool=exposed, label=label),
        )


# ---------------------------------------------------------------------------
# Route helpers (the request session; api/routes/security_mcp.py)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ServerReviewRow:
    """One of the caller's MCP servers with its pins in the Security tab's order
    (light review columns only; the sentinel is never among them)."""

    connector_id: uuid.UUID
    display_name: str
    is_active: bool
    tools: tuple[Any, ...]

    @property
    def needs_review_count(self) -> int:
        """Tools waiting for review that the server still offers (a removed one
        cannot be offered whatever the owner decides; it is listed, not counted)."""
        return sum(
            1
            for pin in self.tools
            if pin.status == STATUS_NEEDS_REVIEW and getattr(pin, "removed_at", None) is None
        )


def pin_view(pin: Any) -> dict[str, Any]:
    """The ``McpToolPinView`` JSON of one pin row (or a row of its review columns).
    The remote name is split into text parts, so a hidden character in it shows
    as a labelled chip and never as invisible text. Times are UTC."""
    waiting = pin.pending_hash is not None
    hidden = pin.pending_hidden_chars if waiting else pin.approved_hidden_chars
    return {
        "pin_id": str(pin.id),
        "tool_name": str(pin.exposed_name),
        "remote_name": [part.to_dict() for part in text_parts(str(pin.remote_name or ""))],
        "status": str(pin.status),
        "review_kind": pin.review_kind,
        "removed": pin.removed_at is not None,
        "trusted_how": pin.trusted_how,
        "hidden_characters": int(hidden or 0),
        "change_count": int(pin.change_count or 0),
        "first_seen_at": _utc(pin.first_seen_at),
        "approved_at": _utc(pin.approved_at),
        "changed_at": _utc(pin.changed_at),
    }


async def list_reviews(
    session: AsyncSession, user_id: uuid.UUID, *, connector_id: Optional[uuid.UUID]
) -> list[ServerReviewRow]:
    """The caller's MCP servers (active or not), each with its pins in review
    order, sorted by display name. With *connector_id*, only that server, and
    an empty list when it is not the caller's MCP connector."""
    query = select(
        ConnectorConfig.id, ConnectorConfig.display_name, ConnectorConfig.is_active
    ).where(
        ConnectorConfig.user_id == user_id,
        ConnectorConfig.connector_type == ConnectorType.mcp,
    )
    if connector_id is not None:
        query = query.where(ConnectorConfig.id == connector_id)
    connectors = (await session.execute(query)).all()
    if not connectors:
        return []
    rows = (
        await session.execute(
            select(*_REVIEW_COLUMNS)
            .join(ConnectorConfig, ConnectorConfig.id == McpToolPin.connector_id)
            .where(
                McpToolPin.connector_id.in_([row.id for row in connectors]),
                McpToolPin.user_id == user_id,
                ConnectorConfig.user_id == user_id,
                McpToolPin.status != SENTINEL_STATUS,
            )
        )
    ).all()
    by_server: dict[uuid.UUID, list[Any]] = {}
    for row in rows:
        by_server.setdefault(row.connector_id, []).append(row)
    servers = [
        ServerReviewRow(
            connector_id=row.id,
            display_name=str(row.display_name),
            is_active=bool(row.is_active),
            tools=tuple(sort_for_review(by_server.get(row.id, []))),
        )
        for row in connectors
    ]
    return sorted(
        servers, key=lambda server: (server.display_name.casefold(), str(server.connector_id))
    )


async def get_owned_pin(
    session: AsyncSession, user_id: uuid.UUID, pin_id: uuid.UUID
) -> Optional[tuple[McpToolPin, ConnectorConfig]]:
    """One pin of this user's MCP connector, with the connector; None for
    anything else (another user's pin, a sentinel, a missing id), so the route
    answers 404 and ids are not enumerable."""
    row = (
        await session.execute(
            select(McpToolPin, ConnectorConfig)
            .join(ConnectorConfig, ConnectorConfig.id == McpToolPin.connector_id)
            .where(
                McpToolPin.id == pin_id,
                McpToolPin.user_id == user_id,
                ConnectorConfig.user_id == user_id,
                ConnectorConfig.connector_type == ConnectorType.mcp,
                McpToolPin.status != SENTINEL_STATUS,
            )
        )
    ).first()
    if row is None:
        return None
    return row[0], row[1]


async def approve_pin(
    session: AsyncSession, pin: McpToolPin, definition_hash: str, *, now: datetime
) -> McpToolPin:
    """Approve exactly the definition the owner was shown (raises StaleReview when
    *definition_hash* is no longer the one waiting, or a discovery changed the
    row in between). Already approved with that hash: unchanged (idempotent)."""
    decision = decide_approval(pin, definition_hash, now=now)
    if decision.outcome == "stale":
        raise StaleReview()
    if decision.outcome == "unchanged":
        return pin
    written = (
        await session.execute(
            update(McpToolPin)
            .where(
                McpToolPin.id == pin.id,
                McpToolPin.user_id == pin.user_id,
                McpToolPin.status == pin.status,
                McpToolPin.pending_hash.is_not_distinct_from(pin.pending_hash),
                McpToolPin.approved_hash.is_not_distinct_from(pin.approved_hash),
            )
            .values(**decision.values)
            .returning(McpToolPin.id)
            .execution_options(synchronize_session=False)
        )
    ).first()
    if written is None:
        raise StaleReview()
    await session.refresh(pin)
    return pin


async def keep_pin_off(session: AsyncSession, pin: McpToolPin, *, now: datetime) -> McpToolPin:
    """Keep a tool off: any status becomes ``kept_off``, the waiting definition is
    kept for display. Idempotent. Not conditional on the waiting hash: turning a
    tool off is the safe direction whatever the server sent meanwhile."""
    values = keep_off_values(pin, now=now)
    if values is None:
        return pin
    await session.execute(
        update(McpToolPin)
        .where(
            McpToolPin.id == pin.id,
            McpToolPin.user_id == pin.user_id,
            McpToolPin.status != SENTINEL_STATUS,
        )
        .values(**values)
        .execution_options(synchronize_session=False)
    )
    await session.refresh(pin)
    return pin


async def _waiting_count(session: AsyncSession, connector_id: uuid.UUID) -> int:
    return int(
        (
            await session.execute(
                select(func.count())
                .select_from(McpToolPin)
                .where(
                    McpToolPin.connector_id == connector_id,
                    McpToolPin.status == STATUS_NEEDS_REVIEW,
                    McpToolPin.removed_at.is_(None),
                )
            )
        ).scalar_one()
    )


async def pin_note_after_owner_test(
    app: Any, session: AsyncSession, row: ConnectorConfig, tools: Sequence[MCPToolInfo]
) -> str:
    """The owner Test's sentence suffix: a server never seen is pinned with
    ``trusted_how="owner_test"``; otherwise changes are recorded (a Test never
    approves anything) and the note says how many tools wait for review. Reads
    the switch from ``app.state.mcp_pins`` when wired (absent or unreadable ->
    on). Writes in a SAVEPOINT on the request session. "" when the switch is off
    or anything fails; never raises (logged ``mcp_pin_test_note_failed`` by
    type only)."""
    try:
        # Deferred: integration imports this module.
        from services.mcp.integration import seen_tools_for, slugify_label

        service = getattr(getattr(app, "state", None), "mcp_pins", None)
        if not isinstance(service, McpPinService):
            service = McpPinService(None)
        if not await service.is_enabled():
            return ""
        label = slugify_label(row.display_name)
        server = PinServer(
            connector_id=row.id,
            user_id=row.user_id,
            label=label,
            display_name=str(row.display_name),
        )
        result = await service.reconcile_in_session(
            session,
            server,
            seen_tools_for(label, tools),
            source="owner_test",
            notify=False,
            fresh=True,
        )
        waiting = await _waiting_count(session, row.id)
        return owner_test_note(first_use=result.first_use, waiting=waiting, tools=len(tools))
    except Exception as exc:
        logger.warning("mcp_pin_test_note_failed", error_type=type(exc).__name__)
        return ""


def _server_url(encrypted: Optional[bytes]) -> str:
    """The server URL inside a connector's encrypted credentials (raises when the
    blob cannot be read). Never logged: it can carry a token."""
    from core.security import decrypt_credentials

    if not encrypted:
        raise ValueError("no credentials")
    credentials = json.loads(decrypt_credentials(encrypted))
    if not isinstance(credentials, dict):
        raise ValueError("credentials are not an object")
    return str(credentials.get("url", "")).strip()


async def reset_pins_if_server_moved(
    session: AsyncSession,
    connector: Any,
    previous_encrypted: Optional[bytes],
    *,
    user_id: uuid.UUID,
) -> int:
    """Delete a connector's pins when its server URL changed (a header-only or
    userinfo-only change keeps them; pinning.normalized_server_url): a new server
    is a new server, trusted on first use by the Test the page runs after saving.
    The old blob unreadable counts as moved. Deletes inside a SAVEPOINT and audits
    ``mcp_pins_reset`` with the count. Returns how many tool pins went (the
    sentinel goes too but is not counted). Never raises: a failed reset keeps the
    old pins, the safe direction (every tool on the new server shows for review)."""
    try:
        new_url = _server_url(connector.encrypted_credentials)
        try:
            old_url: Optional[str] = _server_url(previous_encrypted)
        except Exception:
            old_url = None
        if old_url is not None and same_server(old_url, new_url):
            return 0
        from services.audit import append_auth_event

        async with session.begin_nested():
            gone = (
                (
                    await session.execute(
                        delete(McpToolPin)
                        .where(
                            McpToolPin.connector_id == connector.id,
                            McpToolPin.user_id == user_id,
                        )
                        .returning(McpToolPin.status)
                        .execution_options(synchronize_session=False)
                    )
                )
                .scalars()
                .all()
            )
            if not gone:
                return 0
            count = sum(1 for status in gone if status != SENTINEL_STATUS)
            await append_auth_event(
                session,
                user_id=user_id,
                action="mcp_pins_reset",
                status=AuditStatus.approved,
                endpoint=f"/api/connectors/{connector.id}",
                details={"connector_id": str(connector.id), "pins": count},
            )
        return count
    except Exception as exc:
        logger.warning("mcp_pins_reset_failed", error_type=type(exc).__name__)
        return 0
