"""Keeps VirusTotal's per-key limits (the public key's 4 lookups a minute and 500 a day) true
across restarts and across users, with a share for automatic checks and one per person.

Why it exists: VirusTotal's limits belong to the owner's key, not to a process, and a public key
that goes over them gets refused. So every request is reserved before it is made: one row in
``file_reputation_calls`` (through the store), written first, so a request that then crashes or
fails still counts. The windows slide: "minute" means calls with ``at > now - 60 s`` and "day"
means ``at > now - 24 h``. A rolling 24-hour window is never looser than VirusTotal's calendar
day, because any calendar day's count up to a moment is at most that moment's rolling count.

On top of the key's limits, automatic checks (uploads in chat, email attachments) stop at their
own daily share so the owner can always still check a file by hand, and one person's explicit
lookups stop at their daily share so nobody spends the owner's whole key. Uploads and analysis
polls count toward the minute and the day, never toward a person's share. After VirusTotal
answers 429, nothing is sent for 60 s, doubling with each 429 in a row up to an hour. After it
refuses the key itself (401/403), ``KeyRejection`` pauses that key for 10 minutes and lets the
owner be alerted at most once a day.

The decisions are pure functions over the counts (``refusal``, ``minute_wait_s``,
``cool_down_seconds``, ``limits_from_settings``); ``VirusTotalQuota`` adds the clock, the lock
and the waiting. One process-wide ``asyncio.Lock`` covers "count, then insert", which is enough
for the single-process assumption of ``services/installation.py``. The cool-down is in memory:
losing it on a restart only means one more request that VirusTotal may refuse again.

Connects to: a ``CallLog`` (services/file_reputation/store.py ``FileReputationStore``), the
capability's settings (``lookups_per_minute``, ``lookups_per_day``, ``automatic_lookups_per_day``,
``lookups_per_user_per_day``) read per request through the *limits* callable, so an owner's
change applies without a restart.

Used by: services/file_reputation/service.py.
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Literal, Optional, Protocol

import structlog

logger = structlog.get_logger(__name__)

CallKind = Literal["lookup", "upload", "analysis"]
Priority = Literal["explicit", "automatic"]
QuotaRefusal = Literal[
    "virustotal_limit", "daily_limit", "automatic_limit", "user_limit", "minute_limit"
]

MINUTE = timedelta(seconds=60)
DAY = timedelta(hours=24)
COOL_DOWN_FIRST_S = 60.0
COOL_DOWN_MAX_S = 3600.0
# After VirusTotal refuses the key (401/403): no request with it for 10 minutes, and the owner
# is alerted at most once a day (S10 2.3).
KEY_REJECTED_COOL_DOWN_S = 600.0
OWNER_ALERT_INTERVAL = timedelta(hours=24)
# Capability settings are whole numbers 1..10000 (services/capabilities/base.py).
LIMIT_MIN = 1
LIMIT_MAX = 10_000
# The shortest pause between two tries while waiting for the minute window, so a clock that
# disagrees with the stored times by a hair cannot spin.
_MIN_WAIT_S = 0.05


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


@dataclass(frozen=True)
class QuotaLimits:
    per_minute: int
    per_day: int
    automatic_per_day: int
    per_user_per_day: int


# VirusTotal's public-key limits and the shares the capability defaults to. Keep in step with
# FILE_REPUTATION_SETTINGS_DEFAULTS in services/capabilities/file_reputation.py.
DEFAULT_LIMITS = QuotaLimits(per_minute=4, per_day=500, automatic_per_day=100, per_user_per_day=100)

# QuotaLimits field -> capability setting key.
SETTING_KEYS: Mapping[str, str] = {
    "per_minute": "lookups_per_minute",
    "per_day": "lookups_per_day",
    "automatic_per_day": "automatic_lookups_per_day",
    "per_user_per_day": "lookups_per_user_per_day",
}


@dataclass(frozen=True)
class CallCounts:
    """What the request log says right now, for one caller."""

    # Reservation times inside the minute window, oldest first.
    minute_times: tuple[datetime, ...]
    # Every reservation in the last 24 h, and the automatic ones among them.
    last_24h: int
    automatic_last_24h: int
    # This person's explicit lookups in the last 24 h (0 without a person).
    user_last_24h: int

    @property
    def last_minute(self) -> int:
        return len(self.minute_times)


@dataclass(frozen=True)
class QuotaUsage:
    last_minute: int
    last_24h: int
    automatic_last_24h: int
    user_last_24h: int
    limits: QuotaLimits


class CallLog(Protocol):
    """The request log the quota counts and writes (``FileReputationStore`` satisfies it)."""

    async def call_counts(self, *, now: datetime, user_id: Optional[str]) -> CallCounts: ...

    async def record_call(
        self, *, at: datetime, kind: CallKind, priority: Priority, user_id: Optional[str]
    ) -> None: ...


def _setting(settings: Mapping[str, Any], key: str, default: int) -> int:
    value = settings.get(key, default)
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return default
    if isinstance(value, float):
        if value != value or value in (float("inf"), float("-inf")):
            return default
        value = int(value)
    return max(LIMIT_MIN, min(LIMIT_MAX, value))


def limits_from_settings(
    settings: Optional[Mapping[str, Any]], *, defaults: QuotaLimits = DEFAULT_LIMITS
) -> QuotaLimits:
    """The four limits from the capability's merged settings, each a whole number clamped to
    1..10000; a missing or malformed value takes its default."""
    values = settings if isinstance(settings, Mapping) else {}
    return QuotaLimits(
        per_minute=_setting(values, SETTING_KEYS["per_minute"], defaults.per_minute),
        per_day=_setting(values, SETTING_KEYS["per_day"], defaults.per_day),
        automatic_per_day=_setting(
            values, SETTING_KEYS["automatic_per_day"], defaults.automatic_per_day
        ),
        per_user_per_day=_setting(
            values, SETTING_KEYS["per_user_per_day"], defaults.per_user_per_day
        ),
    )


def refusal(
    counts: CallCounts,
    limits: QuotaLimits,
    *,
    kind: CallKind,
    priority: Priority,
    user_id: Optional[str],
) -> Optional[QuotaRefusal]:
    """Why one more request may not be reserved now, or None when it may. The day is asked
    first (waiting cannot help it), then the automatic share, then the person's share (explicit
    lookups only), then the minute (the only one worth waiting for)."""
    if counts.last_24h >= limits.per_day:
        return "daily_limit"
    if priority == "automatic" and counts.automatic_last_24h >= limits.automatic_per_day:
        return "automatic_limit"
    if (
        kind == "lookup"
        and priority == "explicit"
        and user_id
        and counts.user_last_24h >= limits.per_user_per_day
    ):
        return "user_limit"
    if counts.last_minute >= limits.per_minute:
        return "minute_limit"
    return None


def minute_wait_s(counts: CallCounts, limits: QuotaLimits, now: datetime) -> float:
    """Seconds until the minute window has room for one more request (0 when it has room now):
    until enough of the oldest reservations are more than 60 s old."""
    excess = counts.last_minute - limits.per_minute
    if excess < 0:
        return 0.0
    times = sorted(counts.minute_times)
    frees_at = times[excess] + MINUTE
    return max(0.0, (frees_at - now).total_seconds())


def cool_down_seconds(streak: int) -> float:
    """The pause after the *streak*-th 429 in a row: 60 s, doubling each time, at most 1 h."""
    if streak <= 0:
        return 0.0
    return min(COOL_DOWN_MAX_S, COOL_DOWN_FIRST_S * (2 ** min(streak - 1, 16)))


class CoolDown:
    """VirusTotal's own "slow down": in memory, per process."""

    def __init__(self) -> None:
        self.streak = 0
        self.until: Optional[datetime] = None

    def active(self, now: datetime) -> bool:
        return self.until is not None and now < self.until

    def remaining_s(self, now: datetime) -> float:
        if self.until is None:
            return 0.0
        return max(0.0, (self.until - now).total_seconds())

    def trip(self, now: datetime) -> float:
        """One more 429: start (or lengthen) the pause; the seconds it lasts."""
        self.streak += 1
        seconds = cool_down_seconds(self.streak)
        self.until = now + timedelta(seconds=seconds)
        return seconds

    def reset(self) -> None:
        self.streak = 0
        self.until = None


class KeyRejection:
    """VirusTotal refused the owner's key (401/403): no request with that key for
    ``KEY_REJECTED_COOL_DOWN_S``, and the owner is told at most once per
    ``OWNER_ALERT_INTERVAL`` (S10 2.3, review FEA-SF8).

    Only a SHA-256 of the refused key is kept, in memory, so saving a different key lifts the
    pause at once without any wiring, and nothing key-shaped is ever stored or logged.
    """

    def __init__(
        self,
        *,
        cool_down_s: float = KEY_REJECTED_COOL_DOWN_S,
        alert_interval: timedelta = OWNER_ALERT_INTERVAL,
    ) -> None:
        self._cool_down = timedelta(seconds=cool_down_s)
        self._alert_interval = alert_interval
        self._key_digest: Optional[str] = None
        self.until: Optional[datetime] = None
        self.last_alert_at: Optional[datetime] = None

    @staticmethod
    def _digest(key: str) -> str:
        return hashlib.sha256(key.encode("utf-8")).hexdigest()

    def blocks(self, key: str, now: datetime) -> bool:
        """True while *key* is the refused key and its pause has not ended."""
        return (
            self.until is not None
            and now < self.until
            and self._key_digest is not None
            and hmac.compare_digest(self._key_digest, self._digest(key))
        )

    def trip(self, key: str, now: datetime) -> bool:
        """VirusTotal just refused *key*: start the pause. True when the owner should be alerted
        now (the first refusal, or the first one a day after the last alert)."""
        self._key_digest = self._digest(key)
        self.until = now + self._cool_down
        if self.last_alert_at is None or now - self.last_alert_at >= self._alert_interval:
            self.last_alert_at = now
            return True
        return False

    def clear(self) -> None:
        """VirusTotal accepted a key again: no pause (the alert interval is kept)."""
        self._key_digest = None
        self.until = None


class VirusTotalQuota:
    """Reserve-before-request limits for one VirusTotal key, one per process."""

    def __init__(
        self,
        store: CallLog,
        limits: Callable[[], Awaitable[QuotaLimits]],
        *,
        clock: Callable[[], datetime] = _utcnow,
        sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
    ) -> None:
        self._store = store
        self._limits = limits
        self._clock = clock
        self._sleep = sleep
        self._lock = asyncio.Lock()
        self._cool = CoolDown()

    async def _current_limits(self) -> QuotaLimits:
        try:
            return await self._limits()
        except Exception as exc:
            # The defaults are VirusTotal's public limits: never looser than the key allows.
            logger.warning("file_reputation_limits_unreadable", error_type=type(exc).__name__)
            return DEFAULT_LIMITS

    async def acquire(
        self,
        *,
        kind: CallKind,
        priority: Priority,
        user_id: Optional[str],
        wait_s: float,
    ) -> Optional[QuotaRefusal]:
        """Reserve one VirusTotal request now (one row in file_reputation_calls, written before
        the request so a crash still counts it) and answer None, or the reason it cannot:
        'virustotal_limit' (cooling down after a 429), 'daily_limit', 'automatic_limit',
        'user_limit', or 'minute_limit' after waiting up to wait_s for the minute window.
        A store failure is raised to the caller (nothing was reserved)."""
        deadline = self._clock() + timedelta(seconds=max(0.0, wait_s))
        while True:
            async with self._lock:
                now = self._clock()
                if self._cool.active(now):
                    return "virustotal_limit"
                limits = await self._current_limits()
                counts = await self._store.call_counts(now=now, user_id=user_id)
                reason = refusal(counts, limits, kind=kind, priority=priority, user_id=user_id)
                if reason is None:
                    await self._store.record_call(
                        at=now, kind=kind, priority=priority, user_id=user_id
                    )
                    return None
                if reason != "minute_limit":
                    return reason
                wait = max(minute_wait_s(counts, limits, now), _MIN_WAIT_S)
            # Waiting happens outside the lock, so other callers can still be refused (or let
            # through for a different window) meanwhile.
            if now + timedelta(seconds=wait) > deadline:
                return "minute_limit"
            await self._sleep(wait)

    def cool_down(self) -> None:
        """After a 429: no requests for 60 s, doubling per 429 in a row, at most 1 h."""
        seconds = self._cool.trip(self._clock())
        logger.warning(
            "file_reputation_cooling_down", seconds=seconds, streak=self._cool.streak
        )

    def recovered(self) -> None:
        """VirusTotal answered normally again: the next 429 starts from 60 s."""
        self._cool.reset()

    def cooling_down_for(self) -> float:
        """Seconds left of the current pause (0 when none)."""
        return self._cool.remaining_s(self._clock())

    async def usage(self, user_id: Optional[str]) -> QuotaUsage:
        """The counts behind the Security tab's "37 of 500 in the last 24 hours"."""
        now = self._clock()
        limits = await self._current_limits()
        counts = await self._store.call_counts(now=now, user_id=user_id)
        return QuotaUsage(
            last_minute=counts.last_minute,
            last_24h=counts.last_24h,
            automatic_last_24h=counts.automatic_last_24h,
            user_last_24h=counts.user_last_24h,
            limits=limits,
        )
