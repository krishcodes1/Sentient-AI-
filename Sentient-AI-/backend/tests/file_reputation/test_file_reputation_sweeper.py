"""Tests for FileReputationSweeper (services/file_reputation/sweeper.py): they prove building it
starts nothing and hands the service its kick, a kick runs one sweep at once (finishing a queued
lookup) and a second kick while one runs joins it, and the loop keeps going after a sweep that
crashes and stops cleanly.

Why it exists: wire_services builds the sweeper without starting it (the lifespan does), the
service kicks it after an approved upload so the analysis poll is not a whole interval late,
and a broken sweep must never stop the queue, the polls or the purge for good.
"""

from __future__ import annotations

import asyncio

import pytest

from services.file_reputation.sweeper import FileReputationSweeper
from tests.conftest import make_user
from tests.file_reputation.fakevt import T0, Clock, FakeSettings, FakeVirusTotal, build_service, sha_of


class CountingService:
    """The two things the sweeper uses of the service: ``sweep`` and ``use_kick``."""

    def __init__(self, *, fail_first: bool = False) -> None:
        self.sweeps = 0
        self.kick = None
        self.fail_first = fail_first
        self.release = asyncio.Event()
        self.release.set()

    def use_kick(self, kick) -> None:
        self.kick = kick

    async def sweep(self) -> int:
        self.sweeps += 1
        if self.fail_first and self.sweeps == 1:
            raise RuntimeError("database down")
        await self.release.wait()
        return 1


@pytest.mark.asyncio
async def test_building_the_sweeper_starts_nothing_and_hands_the_service_its_kick():
    before = set(asyncio.all_tasks())
    service = CountingService()

    sweeper = FileReputationSweeper(service)  # type: ignore[arg-type]

    assert sweeper.running is False and service.sweeps == 0
    assert service.kick == sweeper.kick
    assert set(asyncio.all_tasks()) == before


@pytest.mark.asyncio
async def test_a_kick_runs_one_sweep_at_once_and_a_second_kick_joins_it(session_factory):
    user, _ = await make_user(session_factory, "sweeper-kick@example.com")
    clock = Clock(T0)
    vt = FakeVirusTotal()
    vt.add_file(sha_of(b"queued"), malicious=4, undetected=60)
    service, parts = build_service(
        session_factory, vt=vt, settings=FakeSettings(settings={"lookups_per_minute": 1}), clock=clock
    )
    sweeper = FileReputationSweeper(service)
    uid = str(user.id)
    await service.check_hash(uid, sha_of(b"first"), alert="caller")
    waiting = await service.check_hash(uid, sha_of(b"queued"), alert="caller")
    assert waiting.verdict == "pending"

    clock.advance(61)
    first = sweeper.kick()
    second = sweeper.kick()
    assert first is not None and first is second
    await first
    await service.drain()

    row = await service.store.check_for(uid, sha_of(b"queued"))
    assert row is not None and row.state == "checked" and row.verdict == "malicious"
    assert len(parts.outbox.to(user.id)) == 1
    await sweeper.stop()


@pytest.mark.asyncio
async def test_the_loop_keeps_going_after_a_sweep_that_crashes_and_stops_cleanly():
    service = CountingService(fail_first=True)
    sweeper = FileReputationSweeper(service, interval_seconds=0.01)  # type: ignore[arg-type]

    await sweeper.start()
    assert sweeper.running is True
    for _ in range(200):
        if service.sweeps >= 3:
            break
        await asyncio.sleep(0.01)
    service.release.clear()
    kicked = sweeper.kick()
    await sweeper.stop()

    assert service.sweeps >= 3
    assert sweeper.running is False
    assert kicked is None or kicked.done()
