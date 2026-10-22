"""The process's site rules (security S7): a snapshot refreshed from the
database, the per-user hook the browser guard reads, the resolver wrapper
the web toolkit, page watches and knowledge imports use, the pipeline
check, and the recent hits the Security tab lists.

Why it exists: the guard, the page fetchers and the call check must all
judge a site by the same rules at the same moment, without a database read
per navigation; one service owns the cached snapshot, its refresh, and the
fail-closed rule (no snapshot ever loaded: the call check refuses browser,
web page, watch and web-import calls, the guard stops navigations, and page
watches and knowledge imports fetch nothing).

How fresh the snapshot is (S7 §4.7): rebuilt after every owner change (the
routes call ``refresh``), marked stale on a "capabilities" change, and
re-read lazily once older than REFRESH_TTL_S; ``ensure_fresh`` re-reads the
switch on every call (the installation service caches it for 5 s). A
refresh that fails keeps the last good snapshot and is retried after
RETRY_AFTER_FAILURE_S. The snapshot is immutable and swapped whole, so the
guard (on the event loop) and the resolver (in a worker thread) read it
with no lock.

What is remembered (S7 §3.4), in memory only and lost on restart: the 20
most recent (host, kind) pairs that were stopped or flagged, with a count,
for the tab (hosts, never a user); and when each (user, keyed host hash,
event) last wrote an audit row, so a page that reloads in a loop writes one
row per 10 minutes. Audit rows hold kinds, the category and a keyed hash of
the host (``patterns.host_hash``), never a host, URL, path or query.

Connects to: main.py (``EgressHooks``, the resolvers of the web, watch and
knowledge toolkits and of the page-watch sweeper, the call check,
``on_installation_change``), services/site_rules/check.py,
services/site_rules/hooks.py, services/site_rules/store.py,
api/routes/security_site_rules.py.
"""

from __future__ import annotations

import asyncio
import threading
import time
from collections import OrderedDict
from datetime import datetime, timezone
from typing import Any, Awaitable, Callable, Optional

import structlog
from sqlalchemy.ext.asyncio import AsyncSession

from core.config import settings
from models.audit import AuditStatus
from services.audit import append_audit_log
from services.site_rules import store
from services.site_rules.check import SiteRulesCallCheck
from services.site_rules.hooks import SiteRuleGuardHook, Where
from services.site_rules.hooks import wrap_resolver as _wrap_resolver
from services.site_rules.messages import short_host
from services.site_rules.patterns import MAX_HOST_CHARS, RuleKind, host_hash
from services.site_rules.snapshot import SiteRuleSnapshot, SiteVerdict
from services.tools.net import AddressResolver

logger = structlog.get_logger(__name__)

CONNECTOR = "site_rules"
BLOCKED_EVENT = "site_rule_blocked"
NOTED_EVENT = "site_rule_noted"


class SiteRulesService:
    """The process's site rules (see the module docstring)."""

    REFRESH_TTL_S = 60.0
    RETRY_AFTER_FAILURE_S = 5.0
    RECENT_LIMIT = 20
    AUDIT_WINDOW_S = 600.0
    AUDIT_KEYS_LIMIT = 2048

    def __init__(
        self,
        session_factory: Callable[[], AsyncSession],
        *,
        enabled: Callable[[], Awaitable[bool]],
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._session_factory = session_factory
        self._enabled = enabled
        self._clock = clock
        self._snapshot: Optional[SiteRuleSnapshot] = None
        self._stale = False
        self._failed_at: Optional[float] = None
        # Created on first use, inside the running loop (single-flight refresh).
        self._refresh_lock: Optional[asyncio.Lock] = None
        # The resolver records hits from a worker thread: one lock for both maps.
        self._hits_lock = threading.Lock()
        self._recent: OrderedDict[tuple[str, str], dict[str, Any]] = OrderedDict()
        self._audited: OrderedDict[tuple[str, str, str], float] = OrderedDict()
        self._tasks: set[asyncio.Task[None]] = set()
        self._loop: Optional[asyncio.AbstractEventLoop] = None

    # -- the snapshot --------------------------------------------------------

    @property
    def snapshot(self) -> Optional[SiteRuleSnapshot]:
        """The current snapshot, or None when none was ever loaded (callers fail closed)."""
        return self._snapshot

    async def refresh(self) -> Optional[SiteRuleSnapshot]:
        """Re-read the rows and the switch now (single-flight); keeps the last
        good snapshot when the read fails (and answers it, or None)."""
        self._remember_loop()
        async with self._lock():
            return await self._load(await self._switch())

    async def ensure_fresh(self) -> Optional[SiteRuleSnapshot]:
        """The snapshot, re-read when older than REFRESH_TTL_S or marked stale
        (at most once per RETRY_AFTER_FAILURE_S after a failed read), and the
        switch re-read every call."""
        self._remember_loop()
        enabled = await self._switch()
        if self._needs_load() and self._may_retry():
            async with self._lock():
                # Another caller may have loaded it while this one waited.
                if self._needs_load() and self._may_retry():
                    await self._load(enabled)
        snapshot = self._snapshot
        if snapshot is not None and snapshot.enabled != enabled:
            snapshot = snapshot.with_enabled(enabled)
            self._snapshot = snapshot
        return snapshot

    def invalidate(self) -> None:
        """Mark the snapshot stale (after an owner change or a capabilities
        change): the next ``ensure_fresh`` reads the rows again."""
        self._stale = True
        self._failed_at = None

    async def on_installation_change(self, topic: str) -> None:
        """InstallationService.on_change callback: a "capabilities" change
        (the switch may have moved) marks the snapshot stale."""
        if topic == "capabilities":
            self.invalidate()

    def _lock(self) -> asyncio.Lock:
        if self._refresh_lock is None:
            self._refresh_lock = asyncio.Lock()
        return self._refresh_lock

    def _needs_load(self) -> bool:
        snapshot = self._snapshot
        return (
            snapshot is None
            or self._stale
            or self._clock() - snapshot.loaded_at >= self.REFRESH_TTL_S
        )

    def _may_retry(self) -> bool:
        failed_at = self._failed_at
        return failed_at is None or self._clock() - failed_at >= self.RETRY_AFTER_FAILURE_S

    async def _switch(self) -> bool:
        """The owner's switch; one that cannot be read counts as on (fail closed)."""
        try:
            return bool(await self._enabled())
        except Exception as exc:  # noqa: BLE001 - an unread switch keeps the rules on
            logger.warning("site_rules_switch_unreadable", error_type=type(exc).__name__)
            return True

    async def _load(self, enabled: bool) -> Optional[SiteRuleSnapshot]:
        try:
            async with self._session_factory() as db:
                rows = await store.list_rows(db)
            snapshot = store.snapshot_from_rows(rows, enabled=enabled, loaded_at=self._clock())
        except Exception as exc:  # noqa: BLE001 - keep the last good snapshot, retry later
            self._failed_at = self._clock()
            logger.warning("site_rules_refresh_failed", error_type=type(exc).__name__)
            return self._snapshot
        self._snapshot = snapshot
        self._stale = False
        self._failed_at = None
        if snapshot.skipped:
            logger.warning("site_rules_rows_skipped", count=snapshot.skipped)
        return snapshot

    # -- what the browser, the web toolkit and the pipeline get ---------------

    def guard_hook_for(self, user_id: str) -> SiteRuleGuardHook:
        """The per-user hook the browser guard state carries (EgressHooks.site_rules)."""
        return SiteRuleGuardHook(self, user_id)

    def wrap_resolver(self, inner: AddressResolver, *, fail_closed: bool = False) -> AddressResolver:
        """*inner* refusing every Blocked host on every hop, before a socket
        opens (the web.* toolkit; with *fail_closed*, page watches and
        knowledge imports, which also refuse while no rules were ever read)."""
        return _wrap_resolver(self, inner, fail_closed=fail_closed)

    def call_check(self, *, page_origin: Callable[[str], Optional[str]]) -> SiteRulesCallCheck:
        """The pipeline check, reading the user's last observed page origin for act/checkout/read."""
        return SiteRulesCallCheck(self, page_origin=page_origin)

    # -- hits -----------------------------------------------------------------

    def record_hit(
        self,
        *,
        user_id: Optional[str],
        host: str,
        kind: RuleKind,
        where: Where,
        verdict: SiteVerdict,
        audit: bool,
    ) -> None:
        """Add to the recent list and, when *audit* (and a user is known),
        schedule one de-duplicated audit row. Never raises: the block or the
        notice itself already happened."""
        try:
            row: Optional[dict[str, Any]] = None
            with self._hits_lock:
                self._note_recent(short_host(host, MAX_HOST_CHARS), kind, where)
                if audit and user_id:
                    row = self._audit_row(user_id, host, kind, where, verdict)
            if row is not None:
                self._schedule(row)
        except Exception as exc:  # noqa: BLE001 - recording never breaks a block
            logger.warning("site_rules_hit_failed", error_type=type(exc).__name__)

    def _note_recent(self, host: str, kind: str, where: str) -> None:
        key = (host, kind)
        entry = self._recent.pop(key, None) or {"host": host, "kind": kind, "count": 0}
        entry["count"] += 1
        entry["where"] = where
        entry["last_at"] = datetime.now(timezone.utc).isoformat(timespec="seconds")
        self._recent[key] = entry
        while len(self._recent) > self.RECENT_LIMIT:
            self._recent.popitem(last=False)

    def _audit_row(
        self, user_id: str, host: str, kind: str, where: str, verdict: SiteVerdict
    ) -> Optional[dict[str, Any]]:
        """The row to write for this hit, or None when the same user, site and
        event wrote one within AUDIT_WINDOW_S."""
        event = BLOCKED_EVENT if kind == "blocked" else NOTED_EVENT
        hashed = host_hash(host, settings.ENCRYPTION_KEY)
        key = (user_id, hashed, event)
        now = self._clock()
        last = self._audited.get(key)
        if last is not None and now - last < self.AUDIT_WINDOW_S:
            return None
        self._audited.pop(key, None)
        self._audited[key] = now
        while len(self._audited) > self.AUDIT_KEYS_LIMIT:
            self._audited.popitem(last=False)
        facts: dict[str, Any] = {
            "where": where,
            "source": verdict.source,
            "category": verdict.category,
            "host_hash": hashed,
            "kind": kind,
        }
        return {"event": event, "user_id": user_id, "facts": facts}

    def recent(self) -> list[dict[str, Any]]:
        """The recent hits, newest first, for GET /api/security/site-rules."""
        with self._hits_lock:
            return [dict(entry) for entry in reversed(self._recent.values())]

    def _remember_loop(self) -> None:
        try:
            self._loop = asyncio.get_running_loop()
        except RuntimeError:
            pass

    def _schedule(self, row: dict[str, Any]) -> None:
        """Write *row* in the background on the service's event loop (a
        worker thread hands it over thread-safely)."""
        try:
            asyncio.get_running_loop()
        except RuntimeError:
            loop = self._loop
            if loop is None or loop.is_closed():
                logger.warning("site_rules_audit_skipped", audit_event=row["event"], reason="no_loop")
                return
            loop.call_soon_threadsafe(self._spawn, row)
            return
        self._spawn(row)

    def _spawn(self, row: dict[str, Any]) -> None:
        task = asyncio.get_running_loop().create_task(self._write(row))
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)

    async def _write(self, row: dict[str, Any]) -> None:
        event = row["event"]
        try:
            async with self._session_factory() as db:
                await append_audit_log(
                    db,
                    user_id=row["user_id"],
                    connector_name=CONNECTOR,
                    action=event,
                    endpoint=f"agent.{event}",
                    scope_used=CONNECTOR,
                    status=AuditStatus.blocked if event == BLOCKED_EVENT else AuditStatus.approved,
                    reasoning_chain={"event": event},
                    request_data=row["facts"],
                )
                await db.commit()
        except Exception as exc:  # noqa: BLE001 - logged and ignored (S7 §4.8)
            logger.warning("site_rules_audit_failed", audit_event=event, error_type=type(exc).__name__)

    async def drain(self) -> None:
        """Await the audit writes scheduled so far (tests, shutdown)."""
        await asyncio.sleep(0)  # let a write a worker thread handed over start
        while self._tasks:
            await asyncio.gather(*list(self._tasks), return_exceptions=True)
