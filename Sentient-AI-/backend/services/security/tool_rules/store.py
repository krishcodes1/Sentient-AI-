"""Where the tool rules live (security S9): the owner's rules and the switch per built-in rule,
in the database (``DbToolRuleStore``, with a short snapshot cache) or in memory
(``InMemoryToolRuleStore``, for tests and an unwired runtime).

Why it exists: the call check reads one snapshot per turn (and one per executor backstop) and
must never raise: an unreadable store answers ``RuleSnapshot(error=True)``, so the check fails
closed (every write asks). The owner's routes write through the same store, and each write and
its audit row commit together; the cache is dropped on every write, so a new rule applies to
the next call at once. A stored row today's validator refuses is not dropped: it becomes an
"unreadable" rule that makes every write its glob covers ask (grammar.unreadable_rule). A
built-in rule with no row is on; a row whose key the code does not know is ignored.

Audit rows (``tool_rule_created`` / ``tool_rule_deleted`` / ``tool_rule_builtin_changed``)
carry ids, names, the tool pattern, argument and operator names and a digest of the rule;
never a condition value (an address list or a pattern may name third parties).

Connects to: models/tool_rule.py (the two tables), services/audit.py (append_audit_log),
grammar.py (validation, JSON, audit fields), builtins.py (the known keys), engine.py (the
snapshot types).
Used by: check.py (snapshot), api/routes/security_tool_rules.py (everything else), main.py.
"""

from __future__ import annotations

import asyncio
import time
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Iterable, Optional, Protocol, Sequence

import structlog
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from models.tool_rule import ToolRule, ToolRuleBuiltin
from services.audit import AuditStatus, append_audit_log
from services.security.tool_rules import grammar
from services.security.tool_rules.builtins import BUILTIN_KEYS, builtin
from services.security.tool_rules.engine import OwnerRule, RuleSnapshot
from services.security.tool_rules.grammar import RuleDraft, RuleValidationError

logger = structlog.get_logger(__name__)

AUDIT_CONNECTOR = "agent"
AUDIT_ENDPOINT = "/api/security/tool-rules"
EVENT_CREATED = "tool_rule_created"
EVENT_DELETED = "tool_rule_deleted"
EVENT_BUILTIN_CHANGED = "tool_rule_builtin_changed"
SNAPSHOT_TTL_S = 30.0

BuiltinStates = dict[str, tuple[bool, Optional[datetime]]]


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _created_after(existing: Sequence[OwnerRule]) -> datetime:
    """Now, or just after the newest stored rule when the clock has not moved past it: the
    Windows clock can answer the same instant twice, and rules are listed (and evaluated)
    oldest first, so a new rule must never sort before an older one. SQLite hands back naive
    datetimes, which are UTC here."""
    now = _now()
    if existing:
        newest = existing[-1].created_at
        if newest.tzinfo is None:
            newest = newest.replace(tzinfo=timezone.utc)
        if newest >= now:
            now = newest + timedelta(microseconds=1)
    return now


class ToolRuleStore(Protocol):
    """What the check and the routes need from a store."""

    async def snapshot(self) -> RuleSnapshot: ...  # never raises: error=True instead

    async def list_rules(self) -> list[OwnerRule]: ...

    async def builtin_states(self) -> BuiltinStates: ...

    async def create(self, actor_id: str, draft: RuleDraft) -> OwnerRule: ...

    async def delete(self, actor_id: str, rule_id: str) -> Optional[OwnerRule]: ...

    async def set_builtin(self, actor_id: str, key: str, enabled: bool) -> bool: ...

    def invalidate(self) -> None: ...


def _known_key(key: str) -> str:
    if builtin(key) is None:
        raise KeyError(key)
    return key


def _states(rows: Iterable[tuple[str, bool, Optional[datetime]]]) -> BuiltinStates:
    """Every built-in's (on, changed_at): a missing row reads as on, an unknown key is ignored."""
    states: BuiltinStates = dict.fromkeys(BUILTIN_KEYS, (True, None))
    for key, enabled, changed_at in rows:
        if builtin(key) is not None:
            states[key] = (bool(enabled), changed_at)
    return states


def _snapshot_of(rules: Sequence[OwnerRule], states: BuiltinStates) -> RuleSnapshot:
    return RuleSnapshot(
        owner_rules=tuple(rules),
        builtins_off=frozenset(key for key, (on, _) in states.items() if not on),
    )


def _rule_of(row: ToolRule) -> OwnerRule:
    """A stored row as an OwnerRule, re-checked with today's validator; a row it refuses
    becomes an unreadable rule (asks before every write its glob covers)."""
    try:
        return grammar.owner_rule_from_stored(
            rule_id=row.id,
            name=grammar.stored_name(row.name),
            tool=row.tool_pattern,
            conditions=row.conditions,
            created_at=row.created_at,
            created_by=row.created_by,
        )
    except (RuleValidationError, TypeError, ValueError, AttributeError):
        logger.warning("tool_rule_unreadable", rule_id=str(row.id))
        return grammar.unreadable_rule(
            rule_id=row.id,
            name=row.name,
            tool=row.tool_pattern,
            created_at=row.created_at,
            created_by=row.created_by,
        )


def _uuid(value: Any) -> Optional[uuid.UUID]:
    try:
        return uuid.UUID(str(value))
    except (TypeError, ValueError, AttributeError):
        return None


@dataclass(frozen=True)
class _Cached:
    snapshot: RuleSnapshot
    at: float


class DbToolRuleStore:
    """Rules in the database with a 30 s in-process snapshot cache, dropped on every write made
    through this store; each write and its audit row commit together."""

    def __init__(
        self,
        session_factory: Callable[[], AsyncSession],
        *,
        ttl_s: float = SNAPSHOT_TTL_S,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._session_factory = session_factory
        self._ttl_s = ttl_s
        self._clock = clock
        self._cached: Optional[_Cached] = None
        # Bumped by every write: a read that started before a write never caches what it read.
        self._generation = 0
        # One write at a time in this process, so the cap of 50 rules and the duplicate checks
        # cannot be raced past by two requests.
        self._write_lock = asyncio.Lock()

    def invalidate(self) -> None:
        self._generation += 1
        self._cached = None

    async def snapshot(self) -> RuleSnapshot:
        """Every rule a call is checked against: cached for ttl_s; an error snapshot (never
        cached) when the database cannot be read."""
        cached = self._cached
        if cached is not None and self._clock() - cached.at < self._ttl_s:
            return cached.snapshot
        generation = self._generation
        try:
            async with self._session_factory() as session:
                rules = await self._rules(session)
                states = await self._builtin_rows(session)
        except Exception as exc:  # noqa: BLE001 - an unreadable store makes every write ask
            logger.warning("tool_rules_store_unreadable", error_type=type(exc).__name__)
            return RuleSnapshot(error=True)
        snapshot = _snapshot_of(rules, states)
        if generation == self._generation:
            self._cached = _Cached(snapshot, self._clock())
        return snapshot

    @staticmethod
    async def _rules(session: AsyncSession) -> list[OwnerRule]:
        rows = (
            await session.execute(select(ToolRule).order_by(ToolRule.created_at, ToolRule.id))
        ).scalars()
        return [_rule_of(row) for row in rows]

    @staticmethod
    async def _builtin_rows(session: AsyncSession) -> BuiltinStates:
        result = await session.execute(
            select(ToolRuleBuiltin.key, ToolRuleBuiltin.enabled, ToolRuleBuiltin.changed_at)
        )
        return _states((row[0], row[1], row[2]) for row in result)

    async def list_rules(self) -> list[OwnerRule]:
        """The owner's rules, oldest first (raises when the database cannot be read)."""
        async with self._session_factory() as session:
            return await self._rules(session)

    async def builtin_states(self) -> BuiltinStates:
        """Every built-in's (on, when the owner last changed it); raises when unreadable."""
        async with self._session_factory() as session:
            return await self._builtin_rows(session)

    async def create(self, actor_id: str, draft: RuleDraft) -> OwnerRule:
        """Store one validated rule and its audit row. The draft is checked once more against
        the stored rules (the cap, names, duplicates), so a request that raced another cannot
        get past them: RuleValidationError then, and nothing is written."""
        async with self._write_lock:
            async with self._session_factory() as session:
                existing = await self._rules(session)
                checked = grammar.validate_rule(
                    draft.name,
                    draft.tool,
                    grammar.conditions_json(draft.conditions),
                    existing=existing,
                )
                row = ToolRule(
                    id=uuid.uuid4(),
                    name=checked.name,
                    tool_pattern=checked.tool,
                    conditions=grammar.conditions_json(checked.conditions),
                    created_by=_uuid(actor_id),
                    created_at=_created_after(existing),
                )
                session.add(row)
                await session.flush()
                rule = OwnerRule(
                    id=str(row.id),
                    name=checked.name,
                    tool=checked.tool,
                    conditions=checked.conditions,
                    created_at=row.created_at,
                    created_by=str(row.created_by) if row.created_by is not None else None,
                )
                await _audit(session, actor_id, EVENT_CREATED, grammar.audit_fields(rule, rule_id=rule.id))
                await session.commit()
            self.invalidate()
        return rule

    async def delete(self, actor_id: str, rule_id: str) -> Optional[OwnerRule]:
        """Remove one rule and audit it; the rule as it was, or None when there is no such
        rule."""
        uid = _uuid(rule_id)
        if uid is None:
            return None
        async with self._write_lock:
            async with self._session_factory() as session:
                row = await session.get(ToolRule, uid)
                if row is None:
                    return None
                rule = _rule_of(row)
                await _audit(session, actor_id, EVENT_DELETED, grammar.audit_fields(rule, rule_id=rule.id))
                await session.delete(row)
                await session.commit()
            self.invalidate()
        return rule

    async def set_builtin(self, actor_id: str, key: str, enabled: bool) -> bool:
        """Switch one built-in rule; True when that changed something (a row and its audit row
        are written only then). KeyError for a key no built-in rule has."""
        _known_key(key)
        async with self._write_lock:
            async with self._session_factory() as session:
                row = await session.get(ToolRuleBuiltin, key)
                current = True if row is None else bool(row.enabled)
                if current == bool(enabled):
                    return False
                if row is None:
                    row = ToolRuleBuiltin(key=key, enabled=bool(enabled))
                    session.add(row)
                row.enabled = bool(enabled)
                row.changed_by = _uuid(actor_id)
                row.changed_at = _now()
                await session.flush()
                await _audit(
                    session, actor_id, EVENT_BUILTIN_CHANGED, {"key": key, "enabled": bool(enabled)}
                )
                await session.commit()
            self.invalidate()
        return True


async def _audit(session: AsyncSession, actor_id: str, event: str, request_data: dict[str, Any]) -> None:
    """One owner-change row, in the caller's session (it commits with the change)."""
    await append_audit_log(
        session,
        user_id=actor_id,
        connector_name=AUDIT_CONNECTOR,
        action=event,
        endpoint=AUDIT_ENDPOINT,
        scope_used=AUDIT_CONNECTOR,
        status=AuditStatus.approved,
        reasoning_chain={"event": event},
        request_data=request_data,
    )


class InMemoryToolRuleStore:
    """The same contract in memory, for tests and an unwired runtime. ``error`` set to True
    makes every read fail as an unreachable database would (snapshot answers error=True, the
    other reads raise); ``audit`` records what the database store would have audited."""

    def __init__(
        self,
        rules: Sequence[OwnerRule] = (),
        *,
        builtins_off: Iterable[str] = (),
        error: bool = False,
    ) -> None:
        self._rules: list[OwnerRule] = list(rules)
        self._builtins: BuiltinStates = {_known_key(key): (False, _now()) for key in builtins_off}
        self.error = error
        self.audit: list[dict[str, Any]] = []
        self.snapshot_reads = 0

    def _check_readable(self) -> None:
        if self.error:
            raise RuntimeError("tool rules store unreadable")

    def invalidate(self) -> None:
        return None

    async def snapshot(self) -> RuleSnapshot:
        self.snapshot_reads += 1
        if self.error:
            return RuleSnapshot(error=True)
        return _snapshot_of(self._rules, await self.builtin_states())

    async def list_rules(self) -> list[OwnerRule]:
        self._check_readable()
        return list(self._rules)

    async def builtin_states(self) -> BuiltinStates:
        self._check_readable()
        return _states((key, on, at) for key, (on, at) in self._builtins.items())

    async def create(self, actor_id: str, draft: RuleDraft) -> OwnerRule:
        self._check_readable()
        checked = grammar.validate_rule(
            draft.name, draft.tool, grammar.conditions_json(draft.conditions), existing=self._rules
        )
        rule = OwnerRule(
            id=str(uuid.uuid4()),
            name=checked.name,
            tool=checked.tool,
            conditions=checked.conditions,
            created_at=_created_after(self._rules),
            created_by=actor_id or None,
        )
        self._rules.append(rule)
        self.audit.append({"event": EVENT_CREATED, **grammar.audit_fields(rule, rule_id=rule.id)})
        return rule

    async def delete(self, actor_id: str, rule_id: str) -> Optional[OwnerRule]:
        self._check_readable()
        for index, rule in enumerate(self._rules):
            if rule.id == str(rule_id):
                del self._rules[index]
                self.audit.append(
                    {"event": EVENT_DELETED, **grammar.audit_fields(rule, rule_id=rule.id)}
                )
                return rule
        return None

    async def set_builtin(self, actor_id: str, key: str, enabled: bool) -> bool:
        self._check_readable()
        _known_key(key)
        current = self._builtins.get(key, (True, None))[0]
        if current == bool(enabled):
            return False
        self._builtins[key] = (bool(enabled), _now())
        self.audit.append({"event": EVENT_BUILTIN_CHANGED, "key": key, "enabled": bool(enabled)})
        return True


__all__ = [
    "AUDIT_ENDPOINT",
    "BuiltinStates",
    "DbToolRuleStore",
    "EVENT_BUILTIN_CHANGED",
    "EVENT_CREATED",
    "EVENT_DELETED",
    "InMemoryToolRuleStore",
    "SNAPSHOT_TTL_S",
    "ToolRuleStore",
]
