"""Runs the breach monitor: once a week per address, ask Have I Been Pwned (with
the owner's own key) whether the owners' watched email addresses appear in a
breach Crawler has not seen for them, and tell the owner on Telegram and Slack;
plus the owner's "Check now" on the Security page.

Why it exists: the lookup sends an owner's address to a third party with
nobody watching, so every rule that keeps it narrow lives here. Nothing is sent
while the "breach_monitor" switch is off or unreadable (the gate is re-read
before the claim and before every lookup) or while no key is configured. Due
rows are claimed with a conditional UPDATE (BreachStore.claim_due), so two
workers or a kick racing the loop never both look one address up. Lookups are
paced to the key's limit by the client's shared pacer. Only breaches this call
inserted into the seen list are alerted, so a breach is announced once. The
first answer for an address is its baseline: one summary, not one alert per
old breach. Messages are built in code (services/breach/messages.py), go only
to the owner's own linked chats through ``send``, and are never retried. A
failed lookup is stored as a fixed code and never reads as "no breaches"; a
refused key holds every address for a day and tells each owner once; five
failures in a row stop an address with one message. Logs and audit rows carry
ids, counts and codes only, never an address or a key.

Built like PageWatchService (page_watch.py) on the shared SweepLoop
(sweeper.py). main.py wires ``api_key`` to the owner key store, ``send`` to
``fan_out_send`` over Telegram and Slack, and ``enabled`` to
``capability_gate(installation, "breach_monitor")``, and calls ``kick()`` on
every "capabilities" change (a key saved or removed, a switch flipped).
"""

from __future__ import annotations

import asyncio
import math
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Awaitable, Callable, Literal, Optional

import structlog

from services.breach.addresses import address_hint, open_address
from services.breach.hibp import (
    AddressRefused,
    Breach,
    HibpClient,
    HibpError,
    KeyRefused,
    RateLimited,
)
from services.breach.messages import (
    baseline_message,
    checked_note,
    key_refused_message,
    new_breaches_message,
    not_checked_note,
    stopped_message,
)
from services.breach.store import (
    CHECK_EVERY,
    STATUS_ACTIVE,
    BreachStore,
    CheckTooSoon,
    Claim,
    NotFound,
    Recorded,
)
from services.notifications.sweeper import Gate, SweepLoop, gate_open

__all__ = [
    "CHECK_EVERY",
    "BreachMonitorService",
    "BreachUnavailable",
    "CheckReport",
    "CheckTooSoon",
]

logger = structlog.get_logger(__name__)

SWEEP_INTERVAL_SECONDS = 900  # the loop wakes every 15 minutes; addresses are due weekly
LEASE = timedelta(minutes=30)  # a crash mid-check is retried after this
MAX_CHECKS_PER_SWEEP = 20  # with the pacer, about 2 minutes per sweep at most
# Total per lookup, like page_watch.py: HIBP's time to answer, both requests together (the
# client's asyncio.wait_for); the pacer's queue and a 429's hold are not counted.
CHECK_DEADLINE_SECONDS = 45.0
ERROR_LIMIT = 5
RETRY_BASE = timedelta(hours=1)  # 1 h, 2 h, 4 h, ... capped at RETRY_CAP
RETRY_CAP = timedelta(hours=24)
RATE_LIMITED_RETRY = timedelta(hours=1)
KEY_REFUSED_RETRY = timedelta(hours=24)
CHECK_NOW_COOLDOWN = timedelta(minutes=5)
CHECK_NOW_MAX_WAIT_S = 15.0
HOUSEKEEP_EVERY = timedelta(hours=24)

SWEEPER_ENDPOINT = "breach_monitor_sweeper"
OFF_REASON = "Breach monitoring is turned off in Settings → Permissions. Nothing is sent."
NO_KEY_REASON = (
    "Breach checks use your own Have I Been Pwned key, and none is saved yet. Nothing is "
    "sent until you add one."
)
PACING_MESSAGE = "Crawler is pacing lookups to your key's limit. Try again in {seconds} seconds."

Trigger = Literal["schedule", "owner"]


class BreachUnavailable(Exception):
    """Breach checks cannot run now (switch off, no key); .reason is owner-facing."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


@dataclass(frozen=True)
class CheckReport:
    outcome: Literal["checked", "not_checked"]
    address: dict[str, Any]  # the row as GET returns it
    new_findings: list[dict[str, Any]]
    # "Found in 1 new breach." / "No new breaches." /
    # "Not checked: <failure sentence> <retry sentence>"
    note: str


@dataclass
class _Outcome:
    """What one lookup did: answered (``recorded``) or failed (``code``)."""

    sent: bool  # a request reached HIBP's answer path (for the sweep's count)
    recorded: Optional[Recorded] = None
    code: Optional[str] = None
    retry_in: Optional[timedelta] = None
    stop_sweep: bool = False
    new_ids: tuple[uuid.UUID, ...] = field(default_factory=tuple)
    # False when the row is not looked up again on its own (stopped, paused, gone): the
    # Check now note then promises no retry.
    retrying: bool = True


def _backoff(failures: int) -> timedelta:
    """1 h, 2 h, 4 h, ... capped at RETRY_CAP (sweeper.backoff_minutes' doubling, hourly)."""
    return min(RETRY_BASE * 2 ** max(0, failures - 1), RETRY_CAP)


class BreachMonitorService:
    """Weekly HIBP lookups of the owners' watched addresses on the shared SweepLoop.
    ``api_key()`` is the owner's HIBP key (None: send nothing). ``send(user_id, text)`` is
    main.fan_out_send over Telegram and Slack. ``enabled()`` is
    capability_gate(installation, 'breach_monitor'), re-read before the claim and before every
    lookup (gate_open). ``client``, ``store``, ``clock`` and ``audit`` are test seams."""

    def __init__(
        self,
        session_factory: Any,
        *,
        api_key: Callable[[], Awaitable[Optional[str]]],
        send: Optional[Callable[[str, str], Awaitable[bool]]] = None,
        enabled: Optional[Gate] = None,
        client: Optional[HibpClient] = None,
        store: Optional[BreachStore] = None,
        interval_seconds: float = SWEEP_INTERVAL_SECONDS,
        clock: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
        audit: bool = True,
    ) -> None:
        self._session_factory = session_factory
        self._api_key = api_key
        self.send = send
        self._enabled = enabled
        self.client = client if client is not None else HibpClient()
        self._clock = clock
        # Public: the routes use it.
        self.store: BreachStore = (
            store if store is not None else BreachStore(session_factory, clock=clock)
        )
        self._audit_enabled = audit
        self._last_housekeep: Optional[datetime] = None
        # Sweeps never overlap (the loop and a kick queue on this lock).
        self._sweep_lock = asyncio.Lock()
        self._kick_task: Optional[asyncio.Task[int]] = None
        # Set by a kick that arrives while a kick is running: that one runs once more.
        self._kick_again = False
        # The loop runs ungated; the gate is read inside sweep_once.
        self._sweeper = SweepLoop(
            name="breach_monitor", interval_seconds=interval_seconds, sweep=self.sweep_once
        )

    # -- lifecycle -------------------------------------------------------------

    async def start(self) -> None:
        await self._sweeper.start()

    async def stop(self) -> None:
        """Stop the loop and cancel a running kick."""
        await self._sweeper.stop()
        task, self._kick_task = self._kick_task, None
        if task is not None and not task.done():
            task.cancel()
            try:
                await task
            except (asyncio.CancelledError, Exception):
                pass

    # -- gates -------------------------------------------------------------------

    async def _is_enabled(self) -> bool:
        return await gate_open(self._enabled, "breach_monitor")

    async def _key(self) -> Optional[str]:
        """The owner's key, or None. A key store that cannot be read counts as no key."""
        try:
            key = await self._api_key()
        except Exception as exc:
            logger.warning("breach_monitor_key_unreadable", error_type=type(exc).__name__)
            return None
        return key or None

    def _pacer_wait(self) -> float:
        pacer = getattr(self.client, "pacer", None)
        try:
            return float(pacer.wait_estimate()) if pacer is not None else 0.0
        except Exception:
            return 0.0

    # -- the sweep -----------------------------------------------------------------

    async def sweep_once(self) -> int:
        """One gated pass: housekeep (at most daily), claim due rows, look each up. Returns
        lookups sent."""
        async with self._sweep_lock:
            return await self._sweep()

    async def _sweep(self) -> int:
        if not await self._is_enabled():
            return 0
        # Nothing is sent without a key, even when the report is stale.
        key = await self._key()
        if key is None:
            return 0
        now = self._clock()
        if self._last_housekeep is None or now - self._last_housekeep >= HOUSEKEEP_EVERY:
            try:
                await self.store.housekeep()
                self._last_housekeep = now
            except Exception as exc:
                logger.warning("breach_monitor_housekeep_failed", error_type=type(exc).__name__)
        claims = await self.store.claim_due(now, MAX_CHECKS_PER_SWEEP, LEASE)
        sent = 0
        for index, claim in enumerate(claims):
            if index:
                # Re-read before each lookup: a sweep can run for minutes, and nothing is
                # sent once the owner turns it off or removes the key. Leased rows come
                # back after LEASE.
                if not await self._is_enabled():
                    break
                key = await self._key()
                if key is None:
                    break
            outcome = await self._check(claim, key, "schedule")
            if outcome.sent:
                sent += 1
            if outcome.stop_sweep:
                break
        return sent

    def kick(self) -> Optional[asyncio.Task[int]]:
        """Release key holds, then run one sweep in the background unless one is already running
        (single flight). Called by main.py on every 'capabilities' change (a key saved or
        removed, a switch flipped). Returns the task, so tests can await it.

        A kick that arrives while one is running returns None, and the running one releases
        the holds and sweeps once more when it ends, so a key saved meanwhile is never lost."""
        if self._kick_task is not None and not self._kick_task.done():
            self._kick_again = True
            return None
        try:
            asyncio.get_running_loop()
        except RuntimeError:
            return None
        self._kick_again = False
        self._kick_task = asyncio.create_task(self._kicked(), name="breach-monitor-kick")
        return self._kick_task

    async def _kicked(self) -> int:
        sent = 0
        while True:
            self._kick_again = False
            try:
                sent += await self._release_and_sweep()
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                logger.warning("breach_monitor_sweep_failed", error_type=type(exc).__name__)
            if not self._kick_again:
                return sent

    async def _release_and_sweep(self) -> int:
        """Release the key holds and sweep, both under the sweep lock. Released inside the
        lock on purpose: a sweep already running when the key changed can still meet a
        refusal of the old key and hold every row; releasing before waiting for it would
        leave that hold in place, and the kick's own sweep would then find nothing due."""
        async with self._sweep_lock:
            try:
                await self.store.release_key_hold(self._clock())
            except Exception as exc:
                logger.warning("breach_monitor_release_failed", error_type=type(exc).__name__)
            return await self._sweep()

    # -- Check now ------------------------------------------------------------------

    async def check_now(self, user_id: uuid.UUID, address_id: uuid.UUID) -> CheckReport:
        """The owner's Check now: BreachUnavailable / CheckTooSoon / NotFound / Conflict, else one
        lookup through the same path as the sweeper (trigger 'owner'). Sends no channel message:
        the owner is looking at the answer. The pacer is asked before the claim, so a busy
        pacer never moves the address's schedule."""
        if not await self._is_enabled():
            raise BreachUnavailable(OFF_REASON)
        key = await self._key()
        if key is None:
            raise BreachUnavailable(NO_KEY_REASON)
        estimate = self._pacer_wait()
        if estimate > CHECK_NOW_MAX_WAIT_S:
            seconds = math.ceil(estimate)
            raise CheckTooSoon(seconds, PACING_MESSAGE.format(seconds=seconds))
        now = self._clock()
        claim = await self.store.claim_one(user_id, address_id, now, CHECK_NOW_COOLDOWN, LEASE)
        outcome = await self._check(claim, key, "owner")
        view = await self.store.overview(user_id)
        address = next((row for row in view["addresses"] if row["id"] == str(address_id)), None)
        if address is None:
            raise NotFound("No such address.")
        if outcome.recorded is not None:
            wanted = {str(finding_id) for finding_id in outcome.new_ids}
            new_findings = [row for row in view["findings"] if row["id"] in wanted]
            return CheckReport("checked", address, new_findings, checked_note(len(outcome.new_ids)))
        return CheckReport(
            "not_checked",
            address,
            [],
            not_checked_note(
                outcome.code or "unavailable", outcome.retry_in, retrying=outcome.retrying
            ),
        )

    # -- one lookup -----------------------------------------------------------------

    async def _check(self, claim: Claim, key: str, trigger: Trigger) -> _Outcome:
        now = self._clock()
        address = open_address(claim.sealed)
        if address is None:
            # Never sent: the row goes straight to "error" with its fix shown on the tab.
            return await self._fail(
                claim,
                trigger,
                "unreadable",
                now,
                counts=True,
                retry_at=now + RETRY_CAP,
                limit=1,
                stop_sweep=False,
                sent=False,
                announce_stop=False,
            )
        try:
            # The deadline is HIBP's time to answer (both requests together). The client keeps
            # the pacer's queue and a 429's hold outside it, so a rate limit takes the
            # uncounted "rate_limited" path or its one retry, never a counted "timeout".
            breaches = await self.client.breaches_for(
                address, key, deadline_s=CHECK_DEADLINE_SECONDS
            )
        except asyncio.CancelledError:
            raise
        except asyncio.TimeoutError:
            return await self._fail_counting(claim, trigger, "timeout", address)
        except KeyRefused:
            return await self._key_refused(claim, trigger, key)
        except RateLimited:
            now = self._clock()
            return await self._fail(
                claim,
                trigger,
                "rate_limited",
                now,
                counts=False,
                retry_at=now + RATE_LIMITED_RETRY,
                limit=ERROR_LIMIT,
                stop_sweep=True,
            )
        except AddressRefused:
            now = self._clock()
            return await self._fail(
                claim,
                trigger,
                "address_refused",
                now,
                counts=True,
                retry_at=now + RETRY_CAP,
                limit=1,
                stop_sweep=False,
                announce_stop=False,
            )
        except HibpError as exc:
            # Unavailable, BadAnswer, PolicyRefused: the service is down for everyone.
            return await self._fail_counting(claim, trigger, exc.code, address)
        except Exception as exc:
            logger.warning(
                "breach_check_crashed", address_id=str(claim.id), error_type=type(exc).__name__
            )
            return await self._fail_counting(
                claim, trigger, "unavailable", address, stop_sweep=False
            )
        return await self._answered(claim, trigger, address, breaches)

    async def _answered(
        self, claim: Claim, trigger: Trigger, address: str, breaches: list[Breach]
    ) -> _Outcome:
        now = self._clock()
        recorded = await self.store.record_result(claim, breaches, now)
        await self._audit(
            claim.user_id,
            "breach_checked",
            "approved",
            {
                "address_id": str(claim.id),
                "source": claim.source,
                "trigger": trigger,
                "breaches": recorded.total,
                "new": len(recorded.new),
                "baseline": recorded.baseline,
            },
            claim.id,
            trigger,
        )
        outcome = _Outcome(sent=True, recorded=recorded, new_ids=recorded.new_ids)
        if trigger == "owner":
            # The owner sees the answer: no channel message, and the new ones count as told.
            await self.store.mark_alerted(recorded.new_ids, now)
            if recorded.new_ids:
                await self._found(claim, trigger, recorded, delivered=False)
            return outcome
        hint = address_hint(address)
        if recorded.baseline:
            delivered = await self._deliver(claim.user_id, baseline_message(hint, breaches))
            if delivered:
                await self.store.mark_alerted(recorded.new_ids, now)
            if recorded.total > 0:
                await self._found(claim, trigger, recorded, delivered=delivered)
        elif recorded.new:
            delivered = await self._deliver(claim.user_id, new_breaches_message(hint, recorded.new))
            if delivered:
                await self.store.mark_alerted(recorded.new_ids, now)
            await self._found(claim, trigger, recorded, delivered=delivered)
        return outcome

    async def _found(
        self, claim: Claim, trigger: Trigger, recorded: Recorded, *, delivered: bool
    ) -> None:
        await self._audit(
            claim.user_id,
            "breach_found",
            "approved",
            {
                "address_id": str(claim.id),
                "trigger": trigger,
                "new": len(recorded.new),
                "baseline": recorded.baseline,
                "delivered": delivered,
            },
            claim.id,
            trigger,
        )

    async def _key_refused(self, claim: Claim, trigger: Trigger, key: str) -> _Outcome:
        """Hold every address for a day, tell each owner once, and stop the sweep: every
        further lookup would be refused too.

        On a Check now the owner who pressed it reads the refusal in the answer, so only the
        other owners get the channel message; they would otherwise count as told (their rows
        now carry the code) and never hear of it.

        A refusal of a key that was replaced (or removed) while the lookup was out says
        nothing about the key now saved: nothing is held, nobody is told, this address is due
        again at once, and the sweep goes on (it re-reads the key before every lookup)."""
        now = self._clock()
        replaced = await self._key() != key
        if replaced:
            await self.store.release_claim(claim, now)
        else:
            owners = await self.store.defer_for_key(now, now + KEY_REFUSED_RETRY)
            for owner in owners:
                if trigger == "owner" and owner == claim.user_id:
                    continue
                await self._deliver(owner, key_refused_message())
        logger.warning(
            "breach_check_failed",
            address_id=str(claim.id),
            code="key_refused",
            key_replaced=replaced,
        )
        await self._audit(
            claim.user_id,
            "breach_check_failed",
            "blocked",
            {
                "address_id": str(claim.id),
                "source": claim.source,
                "trigger": trigger,
                "error_code": "key_refused",
                "failures": claim.consecutive_errors,
                "stopped": False,
            },
            claim.id,
            trigger,
        )
        return _Outcome(sent=True, code="key_refused", stop_sweep=not replaced)

    async def _fail_counting(
        self,
        claim: Claim,
        trigger: Trigger,
        code: str,
        address: str,
        *,
        stop_sweep: bool = True,
    ) -> _Outcome:
        """A failure that counts toward ERROR_LIMIT, retried after an hourly doubling back-off;
        the fifth in a row stops the address with one message."""
        now = self._clock()
        retry_in = _backoff(claim.consecutive_errors + 1)
        return await self._fail(
            claim,
            trigger,
            code,
            now,
            counts=True,
            retry_at=now + retry_in,
            limit=ERROR_LIMIT,
            stop_sweep=stop_sweep,
            hint=address_hint(address),
            retry_in=retry_in,
        )

    async def _fail(
        self,
        claim: Claim,
        trigger: Trigger,
        code: str,
        now: datetime,
        *,
        counts: bool,
        retry_at: datetime,
        limit: int,
        stop_sweep: bool,
        sent: bool = True,
        announce_stop: bool = True,
        hint: Optional[str] = None,
        retry_in: Optional[timedelta] = None,
    ) -> _Outcome:
        failed = await self.store.record_failure(
            claim, code, now, counts=counts, retry_at=retry_at, limit=limit
        )
        logger.warning(
            "breach_check_failed",
            address_id=str(claim.id),
            code=code,
            failures=failed.failures,
            stopped=failed.stopped,
        )
        if failed.stopped and announce_stop and trigger == "schedule" and hint is not None:
            await self._deliver(claim.user_id, stopped_message(hint, failed.failures, code))
        await self._audit(
            claim.user_id,
            "breach_check_failed",
            "blocked",
            {
                "address_id": str(claim.id),
                "source": claim.source,
                "trigger": trigger,
                "error_code": code,
                "failures": failed.failures,
                "stopped": failed.stopped,
            },
            claim.id,
            trigger,
        )
        # Only an active row is looked up again on its own. One stopped by this call, one
        # already in "error" (a Check now that failed again), one paused mid-check or one
        # gone is not, so its note promises no retry.
        retrying = failed.status == STATUS_ACTIVE
        shown_retry = retry_in if retrying and code in _RETRY_SHOWN else None
        return _Outcome(
            sent=sent,
            code=code,
            retry_in=shown_retry,
            stop_sweep=stop_sweep,
            retrying=retrying,
        )

    # -- delivery and audit ------------------------------------------------------------

    async def _deliver(self, user_id: uuid.UUID, text: str) -> bool:
        if self.send is None:
            return False
        try:
            # False with no linked chat: the finding stays NEW on the web tab.
            return (await self.send(str(user_id), text)) is True
        except Exception as exc:
            # Not retried: a broken channel must not turn into a storm.
            logger.warning("breach_monitor_delivery_failed", error_type=type(exc).__name__)
            return False

    async def _audit(
        self,
        user_id: uuid.UUID,
        action: str,
        status: str,
        data: dict[str, Any],
        address_id: uuid.UUID,
        trigger: Trigger,
    ) -> None:
        """One row in the owner's audit log: ids, counts and codes only, never an address or
        a key. A failure is logged by type and never stops a check. The failure code is stored
        as ``error_code``: the audit sanitizer masks a key named exactly ``code`` (an OAuth
        code, policies.AUDIT_KEY_NAMES), which would leave the row unreadable."""
        endpoint = (
            SWEEPER_ENDPOINT
            if trigger == "schedule"
            else f"/api/security/breach/addresses/{address_id}/check"
        )
        await self._write_audit(user_id, action, status, data, endpoint)

    async def audit_owner_action(
        self, user_id: uuid.UUID, action: str, data: dict[str, Any], *, endpoint: str
    ) -> None:
        """One "approved" audit row for what an owner did on the Security page (an address
        added, removed, paused or resumed, findings acknowledged). The routes call it, so every
        breach-monitor row goes through one writer: ids, counts and sources only, never an
        address. Best effort: a failure is logged by type and never undoes the change."""
        await self._write_audit(user_id, action, "approved", data, endpoint)

    async def _write_audit(
        self,
        user_id: uuid.UUID,
        action: str,
        status: str,
        data: dict[str, Any],
        endpoint: str,
    ) -> None:
        if not self._audit_enabled:
            return
        from models.audit import AuditStatus
        from services.audit import append_audit_log

        try:
            async with self._session_factory() as session:
                await append_audit_log(
                    session,
                    user_id=user_id,
                    connector_name="breach_monitor",
                    action=action,
                    endpoint=endpoint,
                    scope_used="breach_monitor",
                    status=AuditStatus(status),
                    request_data=data,
                )
                await session.commit()
        except Exception as exc:
            logger.warning(
                "breach_monitor_audit_failed", action=action, error_type=type(exc).__name__
            )


# Failure codes whose note gets "Crawler tries again in ...": the counting failures. The
# others already say what happens next (FAILURE_SENTENCES) or are not retried on their own.
_RETRY_SHOWN = frozenset({"unavailable", "bad_answer", "refused_by_policy", "timeout"})
