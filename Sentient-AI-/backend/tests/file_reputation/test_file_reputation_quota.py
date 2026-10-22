"""Tests for services/file_reputation/quota.py over the real request log
(services/file_reputation/store.py on the test database): they prove the owner's key never makes
more than its minute and daily requests, the count survives a restart because it is read from
the table, a reserved slot counts even when its request fails, automatic checks and each person
stop at their own share, a 429 pauses everything with a growing cool-down, the owner's changed
limits apply at once, and old log rows are pruned.

Why it exists: VirusTotal's public key allows 4 lookups a minute and 500 a day; going over gets
the owner's key refused. Clocks and sleeps are injected, so no test waits.
"""

from __future__ import annotations

from datetime import timedelta

import pytest
from sqlalchemy import delete, func, select

from models.file_reputation import FileReputationCall
from models.user import User
from services.file_reputation.quota import (
    DEFAULT_LIMITS,
    KEY_REJECTED_COOL_DOWN_S,
    CallCounts,
    KeyRejection,
    QuotaLimits,
    VirusTotalQuota,
    cool_down_seconds,
    limits_from_settings,
    minute_wait_s,
    refusal,
)
from services.file_reputation.store import FileReputationStore
from tests.conftest import make_user
from tests.file_reputation.fakevt import T0, Clock, FakeSleep


class Limits:
    """The owner's settings, changeable between calls."""

    def __init__(self, limits: QuotaLimits = DEFAULT_LIMITS) -> None:
        self.current = limits

    async def __call__(self) -> QuotaLimits:
        return self.current


def build(session_factory, clock: Clock, limits: Limits):
    store = FileReputationStore(session_factory, clock=clock)
    sleep = FakeSleep(clock)
    return store, VirusTotalQuota(store, limits, clock=clock, sleep=sleep), sleep


def limits(**overrides: int) -> QuotaLimits:
    values = {"per_minute": 4, "per_day": 500, "automatic_per_day": 100, "per_user_per_day": 100}
    values.update(overrides)
    return QuotaLimits(**values)


async def call_rows(session_factory) -> int:
    async with session_factory() as session:
        return int(await session.scalar(select(func.count()).select_from(FileReputationCall)))


@pytest.mark.asyncio
async def test_four_lookups_a_minute_then_the_fifth_waits_or_is_refused(session_factory):
    user, _ = await make_user(session_factory, "quota-minute@example.com")
    clock = Clock()
    _store, quota, sleep = build(session_factory, clock, Limits())
    uid = str(user.id)

    for _ in range(4):
        assert await quota.acquire(kind="lookup", priority="explicit", user_id=uid, wait_s=0) is None
        clock.advance(5)
    # The fifth inside the same minute: refused at once without waiting...
    assert await quota.acquire(kind="lookup", priority="explicit", user_id=uid, wait_s=0) == (
        "minute_limit"
    )
    # ...or refused after the wait it was given ran out before a slot freed...
    assert await quota.acquire(kind="lookup", priority="explicit", user_id=uid, wait_s=10) == (
        "minute_limit"
    )
    assert sleep.calls == []
    # ...or let through once the oldest reservation is a minute old.
    assert await quota.acquire(kind="lookup", priority="explicit", user_id=uid, wait_s=60) is None
    assert sleep.calls == [pytest.approx(40.0)]
    assert clock.now == T0 + timedelta(seconds=60)
    assert await call_rows(session_factory) == 5


@pytest.mark.asyncio
async def test_the_daily_count_survives_a_restart_because_it_is_read_from_the_table(
    session_factory,
):
    clock = Clock()
    day = Limits(limits(per_minute=100, per_day=3))
    _store, quota, _sleep = build(session_factory, clock, day)
    for _ in range(3):
        assert await quota.acquire(kind="lookup", priority="explicit", user_id=None, wait_s=0) is None

    # A new process: new store, new quota, same table.
    _store2, restarted, _sleep2 = build(session_factory, clock, day)
    assert await restarted.acquire(kind="lookup", priority="explicit", user_id=None, wait_s=0) == (
        "daily_limit"
    )
    usage = await restarted.usage(None)
    assert (usage.last_24h, usage.limits.per_day) == (3, 3)
    # Uploads and analysis polls are VirusTotal requests too.
    assert await restarted.acquire(kind="upload", priority="explicit", user_id=None, wait_s=0) == (
        "daily_limit"
    )
    # The window slides: 24 hours after the first reservation there is room again.
    clock.advance(24 * 3600)
    assert await restarted.acquire(kind="analysis", priority="explicit", user_id=None, wait_s=0) is None


@pytest.mark.asyncio
async def test_a_reserved_slot_counts_even_when_the_request_then_fails(session_factory):
    clock = Clock()
    _store, quota, _sleep = build(session_factory, clock, Limits(limits(per_minute=1)))

    assert await quota.acquire(kind="lookup", priority="automatic", user_id=None, wait_s=0) is None
    # (The request to VirusTotal fails here; nothing gives the slot back.)
    usage = await quota.usage(None)

    assert (usage.last_minute, usage.last_24h, usage.automatic_last_24h) == (1, 1, 1)
    assert await quota.acquire(kind="lookup", priority="explicit", user_id=None, wait_s=0) == (
        "minute_limit"
    )


@pytest.mark.asyncio
async def test_automatic_lookups_stop_at_their_own_share_and_leave_the_rest_for_explicit_ones(
    session_factory,
):
    clock = Clock()
    _store, quota, _sleep = build(
        session_factory, clock, Limits(limits(per_minute=100, automatic_per_day=2))
    )

    for _ in range(2):
        assert await quota.acquire(kind="lookup", priority="automatic", user_id=None, wait_s=0) is None
    assert await quota.acquire(kind="lookup", priority="automatic", user_id=None, wait_s=0) == (
        "automatic_limit"
    )
    assert await quota.acquire(kind="lookup", priority="explicit", user_id=None, wait_s=0) is None
    usage = await quota.usage(None)
    assert (usage.last_24h, usage.automatic_last_24h) == (3, 2)


@pytest.mark.asyncio
async def test_one_person_cannot_spend_more_than_their_daily_share_of_the_owners_key(
    session_factory,
):
    alice, _ = await make_user(session_factory, "quota-alice@example.com")
    bob, _ = await make_user(session_factory, "quota-bob@example.com")
    clock = Clock()
    _store, quota, _sleep = build(
        session_factory, clock, Limits(limits(per_minute=100, per_user_per_day=2))
    )
    a, b = str(alice.id), str(bob.id)

    for _ in range(2):
        assert await quota.acquire(kind="lookup", priority="explicit", user_id=a, wait_s=0) is None
    assert await quota.acquire(kind="lookup", priority="explicit", user_id=a, wait_s=0) == (
        "user_limit"
    )
    # Someone else's share is their own.
    assert await quota.acquire(kind="lookup", priority="explicit", user_id=b, wait_s=0) is None
    # Automatic checks of Alice's files, her uploads and their polls are not her share.
    assert await quota.acquire(kind="lookup", priority="automatic", user_id=a, wait_s=0) is None
    assert await quota.acquire(kind="upload", priority="explicit", user_id=a, wait_s=0) is None
    assert await quota.acquire(kind="analysis", priority="explicit", user_id=a, wait_s=0) is None
    assert (await quota.usage(a)).user_last_24h == 2
    assert (await quota.usage(b)).user_last_24h == 1


@pytest.mark.asyncio
async def test_a_429_pauses_every_request_with_a_growing_cool_down(session_factory):
    clock = Clock()
    _store, quota, sleep = build(session_factory, clock, Limits())

    quota.cool_down()
    assert quota.cooling_down_for() == 60.0
    for kind in ("lookup", "upload", "analysis"):
        assert await quota.acquire(kind=kind, priority="explicit", user_id=None, wait_s=30) == (
            "virustotal_limit"
        )
    # Nothing was reserved and nobody waited while cooling down.
    assert await call_rows(session_factory) == 0 and sleep.calls == []
    clock.advance(60)
    assert await quota.acquire(kind="lookup", priority="explicit", user_id=None, wait_s=0) is None

    quota.cool_down()  # a second 429 in a row
    assert quota.cooling_down_for() == 120.0
    clock.advance(119)
    assert await quota.acquire(kind="lookup", priority="explicit", user_id=None, wait_s=0) == (
        "virustotal_limit"
    )
    quota.recovered()
    assert await quota.acquire(kind="lookup", priority="explicit", user_id=None, wait_s=0) is None
    quota.cool_down()
    assert quota.cooling_down_for() == 60.0

    assert [cool_down_seconds(n) for n in range(0, 9)] == [
        0.0, 60.0, 120.0, 240.0, 480.0, 960.0, 1920.0, 3600.0, 3600.0
    ]
    assert cool_down_seconds(10_000) == 3600.0


@pytest.mark.asyncio
async def test_the_owners_changed_limits_apply_without_a_restart(session_factory):
    clock = Clock()
    owner_settings = Limits(limits(per_minute=1))
    _store, quota, _sleep = build(session_factory, clock, owner_settings)

    assert await quota.acquire(kind="lookup", priority="explicit", user_id=None, wait_s=0) is None
    assert await quota.acquire(kind="lookup", priority="explicit", user_id=None, wait_s=0) == (
        "minute_limit"
    )
    owner_settings.current = limits(per_minute=3)
    assert await quota.acquire(kind="lookup", priority="explicit", user_id=None, wait_s=0) is None
    owner_settings.current = limits(per_minute=3, per_day=2)
    assert await quota.acquire(kind="lookup", priority="explicit", user_id=None, wait_s=0) == (
        "daily_limit"
    )


@pytest.mark.asyncio
async def test_unreadable_limits_fall_back_to_virustotals_public_limits(session_factory):
    clock = Clock()

    async def broken() -> QuotaLimits:
        raise RuntimeError("settings unavailable")

    store = FileReputationStore(session_factory, clock=clock)
    quota = VirusTotalQuota(store, broken, clock=clock, sleep=FakeSleep(clock))
    for _ in range(4):
        assert await quota.acquire(kind="lookup", priority="explicit", user_id=None, wait_s=0) is None
    assert await quota.acquire(kind="lookup", priority="explicit", user_id=None, wait_s=0) == (
        "minute_limit"
    )
    assert (await quota.usage(None)).limits == DEFAULT_LIMITS


@pytest.mark.asyncio
async def test_call_rows_older_than_two_days_are_pruned(session_factory):
    clock = Clock()
    store = FileReputationStore(session_factory, clock=clock)
    for hours_ago in (72, 49, 47, 1):
        await store.record_call(
            at=T0 - timedelta(hours=hours_ago), kind="lookup", priority="explicit", user_id=None
        )

    purged = await store.purge()

    assert purged.calls == 2
    assert await call_rows(session_factory) == 2
    counts = await store.call_counts(now=T0, user_id=None)
    assert (counts.last_24h, counts.last_minute) == (1, 0)


@pytest.mark.asyncio
async def test_a_deleted_users_requests_still_count_toward_the_day(session_factory):
    user, _ = await make_user(session_factory, "quota-gone@example.com")
    clock = Clock()
    _store, quota, _sleep = build(session_factory, clock, Limits(limits(per_minute=100, per_day=2)))
    uid = str(user.id)

    assert await quota.acquire(kind="lookup", priority="explicit", user_id=uid, wait_s=0) is None
    assert await quota.acquire(kind="lookup", priority="explicit", user_id=uid, wait_s=0) is None
    async with session_factory() as session:
        await session.execute(delete(User).where(User.id == user.id))
        await session.commit()

    assert await quota.acquire(kind="lookup", priority="explicit", user_id=None, wait_s=0) == (
        "daily_limit"
    )
    async with session_factory() as session:
        owners = (await session.execute(select(FileReputationCall.user_id))).scalars().all()
    assert owners == [None, None]


def test_a_refused_key_pauses_for_ten_minutes_and_alerts_the_owner_at_most_once_a_day():
    rejection = KeyRejection()
    key, new_key = "a" * 64, "c" * 64

    assert not rejection.blocks(key, T0)
    assert rejection.trip(key, T0) is True  # first refusal: tell the owner
    assert rejection.blocks(key, T0 + timedelta(seconds=599))
    assert not rejection.blocks(key, T0 + timedelta(seconds=600))
    # Saving a different key lifts the pause at once.
    assert not rejection.blocks(new_key, T0 + timedelta(seconds=1))
    # Refused again within the day: paused again, but no second alert.
    assert rejection.trip(key, T0 + timedelta(hours=3)) is False
    assert rejection.blocks(key, T0 + timedelta(hours=3, seconds=10))
    assert rejection.trip(key, T0 + timedelta(hours=24)) is True
    rejection.clear()
    assert not rejection.blocks(key, T0 + timedelta(hours=24, seconds=1))
    # Only a digest of the key is held.
    assert key not in repr(vars(rejection))
    assert KEY_REJECTED_COOL_DOWN_S == 600.0


# ---------------------------------------------------------------------------------------------
# The pure rules
# ---------------------------------------------------------------------------------------------


def counts(minute: int = 0, day: int = 0, automatic: int = 0, user: int = 0) -> CallCounts:
    return CallCounts(
        minute_times=tuple(T0 + timedelta(seconds=i) for i in range(minute)),
        last_24h=day,
        automatic_last_24h=automatic,
        user_last_24h=user,
    )


def test_the_day_is_asked_before_the_shares_and_the_minute_last():
    tight = limits(per_minute=1, per_day=1, automatic_per_day=1, per_user_per_day=1)
    full = counts(minute=1, day=1, automatic=1, user=1)

    assert refusal(full, tight, kind="lookup", priority="automatic", user_id="u") == "daily_limit"
    no_day = limits(per_minute=1, per_day=9, automatic_per_day=1, per_user_per_day=1)
    assert refusal(full, no_day, kind="lookup", priority="automatic", user_id="u") == (
        "automatic_limit"
    )
    assert refusal(full, no_day, kind="lookup", priority="explicit", user_id="u") == "user_limit"
    # The person's share applies to explicit lookups of a known person only.
    assert refusal(full, no_day, kind="lookup", priority="explicit", user_id=None) == (
        "minute_limit"
    )
    assert refusal(full, no_day, kind="upload", priority="explicit", user_id="u") == (
        "minute_limit"
    )
    assert refusal(counts(), no_day, kind="lookup", priority="explicit", user_id="u") is None


def test_the_wait_for_the_minute_window_is_until_the_oldest_needed_slot_frees():
    four = limits(per_minute=4)
    now = T0 + timedelta(seconds=10)

    assert minute_wait_s(counts(minute=3), four, now) == 0.0
    # Slots taken at T0 .. T0+3s: the first frees at T0+60s, 50 s from now.
    assert minute_wait_s(counts(minute=4), four, now) == pytest.approx(50.0)
    # After an owner lowered the limit, enough old slots must free, not just one.
    assert minute_wait_s(counts(minute=4), limits(per_minute=2), now) == pytest.approx(52.0)
    assert minute_wait_s(counts(minute=4), four, T0 + timedelta(seconds=90)) == 0.0


def test_limits_come_from_the_capability_settings_clamped_to_whole_numbers():
    assert limits_from_settings(None) == DEFAULT_LIMITS
    assert limits_from_settings({}) == DEFAULT_LIMITS
    assert DEFAULT_LIMITS == QuotaLimits(4, 500, 100, 100)
    assert limits_from_settings(
        {
            "lookups_per_minute": 30,
            "lookups_per_day": 50_000,
            "automatic_lookups_per_day": 0,
            "lookups_per_user_per_day": "lots",
        }
    ) == QuotaLimits(per_minute=30, per_day=10_000, automatic_per_day=1, per_user_per_day=100)
    assert limits_from_settings({"lookups_per_minute": True}).per_minute == 4
    assert limits_from_settings({"lookups_per_minute": 7.9}).per_minute == 7
    assert limits_from_settings({"lookups_per_minute": float("nan")}).per_minute == 4
