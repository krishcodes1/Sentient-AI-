"""The one background-sweeper design every poll loop shares: a SweepLoop that
calls a sweep function every N seconds behind a gate, a conditional-UPDATE
claim, an exponential back-off, and a capability gate that fails closed.

Why it exists: the page-watch sweeper, the schedule sweeper and (wave 2) the
event-trigger and media sweepers must behave the same way: nothing runs while
the owner's switch is off or unreadable, a crash in one sweep never stops the
loop, logs carry exception types only (a message can quote a URL with a
token), and a row is owned by whoever moves it past "due" first. One loop
means there is no second scheduler engine to reason about.
"""

from __future__ import annotations

import asyncio
from typing import Any, Awaitable, Callable, Optional

import structlog

logger = structlog.get_logger(__name__)

Gate = Callable[[], Awaitable[bool]]


async def gate_open(enabled: Optional[Gate], name: str) -> bool:
    """Whether *enabled* says yes. None means no gate (tests). A gate that
    raises, or answers anything but True, counts as off: nothing runs."""
    if enabled is None:
        return True
    try:
        return (await enabled()) is True
    except Exception as exc:
        logger.warning(f"{name}_gate_failed", error_type=type(exc).__name__)
        return False


class SweepLoop:
    """Calls ``sweep()`` every ``interval_seconds`` until stopped.

    ``enabled()`` (optional) is read before every sweep; off, raising or
    unreadable skips that sweep. A sweep that raises is logged by type and
    the loop goes on. ``run_once()`` is one gated sweep (tests and "run now"
    callers), returning what the sweep returned (0 when gated off)."""

    def __init__(
        self,
        *,
        name: str,
        interval_seconds: float,
        sweep: Callable[[], Awaitable[int]],
        enabled: Optional[Gate] = None,
    ) -> None:
        self.name = name
        self.interval_seconds = interval_seconds
        self._sweep = sweep
        self._enabled = enabled
        self.task: Optional[asyncio.Task[None]] = None

    @property
    def running(self) -> bool:
        return self.task is not None and not self.task.done()

    async def start(self) -> None:
        self.task = asyncio.create_task(
            self._loop(), name=f"{self.name.replace('_', '-')}-sweeper"
        )
        logger.info(f"{self.name}_sweeper_started", interval=self.interval_seconds)

    async def stop(self) -> None:
        task, self.task = self.task, None
        if task is not None:
            task.cancel()
            try:
                await task
            except (asyncio.CancelledError, Exception):
                pass

    async def run_once(self) -> int:
        if not await gate_open(self._enabled, self.name):
            return 0
        return await self._sweep()

    async def _loop(self) -> None:
        while True:
            try:
                await self.run_once()
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                # Type only: a message can quote a URL with a token in it.
                logger.warning(f"{self.name}_sweep_failed", error_type=type(exc).__name__)
            await asyncio.sleep(self.interval_seconds)


async def claim(session: Any, stmt: Any) -> bool:
    """Run a conditional UPDATE (``WHERE id = ... AND <still due>``) and say
    whether this caller won the row: exactly one row changed. Whoever moves
    a row past "due" first owns it; everyone else sees rowcount 0."""
    result = await session.execute(stmt)
    return getattr(result, "rowcount", 0) == 1


def backoff_minutes(interval: int, errors: int, cap: int) -> int:
    """Minutes to wait after *errors* failures in a row: the interval doubled
    per failure, capped at *cap* but never shorter than the interval."""
    return int(min(interval * 2**max(0, errors), max(cap, interval)))


def capability_gate(installation: Any, key: str) -> Gate:
    """A gate that is open while capability *key* is effectively on in the
    owner's report. A report that cannot be read closes it (fail closed)."""

    async def gate() -> bool:
        try:
            return key in await installation.enabled_keys()
        except Exception as exc:
            logger.warning("capability_gate_unreadable", capability=key, error_type=type(exc).__name__)
            return False

    return gate
