"""Tests for the shared sweeper pieces (services/notifications/sweeper.py): the
loop runs its sweep behind a gate that fails closed, survives a sweep that
raises, stops cleanly; the conditional-UPDATE claim picks exactly one winner;
the back-off doubles within its cap; the capability gate answers False when
the owner's report cannot be read.

Why it exists: the page-watch, schedule and later sweepers all rely on these
behaving the same way; a gate that failed open would run background work the
owner switched off.
"""

from __future__ import annotations

import asyncio
import uuid
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import update

from services.notifications.sweeper import (
    SweepLoop,
    backoff_minutes,
    capability_gate,
    claim,
    gate_open,
)
from tests.conftest import make_user


@pytest.mark.asyncio
async def test_run_once_is_gated_and_a_raising_gate_is_off():
    calls: list[int] = []

    async def sweep() -> int:
        calls.append(1)
        return 3

    async def on() -> bool:
        return True

    async def off() -> bool:
        return False

    async def broken() -> bool:
        raise RuntimeError("settings unreadable")

    assert await SweepLoop(name="t", interval_seconds=1, sweep=sweep).run_once() == 3
    assert await SweepLoop(name="t", interval_seconds=1, sweep=sweep, enabled=on).run_once() == 3
    assert await SweepLoop(name="t", interval_seconds=1, sweep=sweep, enabled=off).run_once() == 0
    assert await SweepLoop(name="t", interval_seconds=1, sweep=sweep, enabled=broken).run_once() == 0
    assert len(calls) == 2
    assert await gate_open(None, "t") is True


@pytest.mark.asyncio
async def test_the_loop_survives_a_failing_sweep_and_stops():
    calls: list[int] = []

    async def sweep() -> int:
        calls.append(1)
        raise ValueError("boom")

    loop = SweepLoop(name="t", interval_seconds=0.01, sweep=sweep)
    await loop.start()
    for _ in range(100):
        if len(calls) >= 3:
            break
        await asyncio.sleep(0.01)
    assert loop.running
    await loop.stop()
    assert len(calls) >= 3 and loop.task is None and not loop.running


@pytest.mark.asyncio
async def test_claim_has_exactly_one_winner(session_factory):
    from models.page_watch import PageWatch

    user, _ = await make_user(session_factory, "claim@example.com")
    now = datetime(2026, 9, 29, 12, 0, tzinfo=timezone.utc)
    watch_id = uuid.uuid4()
    async with session_factory() as session:
        session.add(
            PageWatch(
                id=watch_id,
                user_id=user.id,
                url="https://example.edu/x",
                label="x",
                interval_minutes=60,
                next_check_at=now,
                created_at=now,
            )
        )
        await session.commit()

    def stmt():
        return (
            update(PageWatch)
            .where(PageWatch.id == watch_id, PageWatch.next_check_at <= now)
            .values(next_check_at=now + timedelta(hours=1))
        )

    async with session_factory() as session:
        first = await claim(session, stmt())
        second = await claim(session, stmt())
        await session.commit()
    assert (first, second) == (True, False)


def test_backoff_doubles_within_its_cap_and_never_under_the_interval():
    assert backoff_minutes(30, 1, 1440) == 60
    assert backoff_minutes(30, 3, 1440) == 240
    assert backoff_minutes(30, 20, 1440) == 1440
    assert backoff_minutes(2880, 5, 1440) == 2880
    assert backoff_minutes(30, 0, 1440) == 30


@pytest.mark.asyncio
async def test_capability_gate_reads_the_report_and_fails_closed():
    class Installation:
        def __init__(self, keys=None, error=None):
            self.keys, self.error = keys, error

        async def enabled_keys(self):
            if self.error:
                raise self.error
            return self.keys

    assert await capability_gate(Installation({"scheduled_tasks"}), "scheduled_tasks")() is True
    assert await capability_gate(Installation(frozenset()), "scheduled_tasks")() is False
    assert await capability_gate(Installation(error=OSError("db down")), "scheduled_tasks")() is False
