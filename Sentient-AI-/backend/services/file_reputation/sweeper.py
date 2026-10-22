"""The file reputation sweeper (security S10): on the shared SweepLoop, it
runs the lookups that waited for room in VirusTotal's minute window, polls
the analyses of approved uploads, and purges expired rows.

Why it exists: VirusTotal's public key allows 4 lookups a minute, so a burst
of files queues; the queue, the analysis polls and the purge must keep going
in the background under the same loop every sweeper uses (a crash in one
sweep never stops it, and logs carry error types only). There is no
capability gate on the loop on purpose: the purge of expired rows runs
whether or not the switch is on (S10 3.7), and ``FileReputationService.sweep``
itself reads the switch and the key before any network work, failing closed.
Concurrent sweeps (the loop and a kick) are serialised by a lock inside
``sweep``.

``kick()`` runs one sweep at once in the background: the service calls it
after an approved upload (it is handed the kick when the sweeper is built), so
the queue and the polls do not wait a whole interval.

Connects to: services/file_reputation/service.py (``sweep``, ``use_kick``),
services/notifications/sweeper.py (``SweepLoop``), main.py (built in
wire_services, started and stopped in the lifespan).
"""

from __future__ import annotations

import asyncio
from typing import Optional

import structlog

from services.file_reputation.service import FileReputationService
from services.notifications.sweeper import SweepLoop

logger = structlog.get_logger(__name__)

SWEEP_INTERVAL_SECONDS = 30.0


class FileReputationSweeper:
    """Background lookups, polls and purges (see the module docstring)."""

    def __init__(
        self, service: FileReputationService, *, interval_seconds: float = SWEEP_INTERVAL_SECONDS
    ) -> None:
        self._service = service
        self._interval_seconds = interval_seconds
        self._loop = SweepLoop(
            name="file_reputation", interval_seconds=interval_seconds, sweep=service.sweep
        )
        self._kicked: Optional[asyncio.Task[int]] = None
        # The service kicks a sweep after an upload; building the sweeper starts nothing.
        service.use_kick(self.kick)

    @property
    def running(self) -> bool:
        """Whether the loop runs."""
        return self._loop.running

    async def start(self) -> None:
        """Start the loop (the lifespan)."""
        if not self._loop.running:
            await self._loop.start()

    async def stop(self) -> None:
        """Stop the loop and any kicked sweep still running."""
        kicked, self._kicked = self._kicked, None
        if kicked is not None and not kicked.done():
            kicked.cancel()
            try:
                await kicked
            except (asyncio.CancelledError, Exception):
                pass
        await self._loop.stop()

    async def run_once(self) -> int:
        """One sweep now, awaited (tests and callers that want the result)."""
        return await self._loop.run_once()

    def kick(self) -> Optional[asyncio.Task[int]]:
        """Run one sweep at once in the background. A kick while an earlier one is still
        running joins it. Outside a running event loop there is nothing to schedule on, so
        nothing happens (the loop's next sweep does the work)."""
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            return None
        if self._kicked is not None and not self._kicked.done():
            return self._kicked
        task = loop.create_task(self._kicked_sweep(), name="file-reputation-kick")
        self._kicked = task
        return task

    async def _kicked_sweep(self) -> int:
        try:
            return await self._loop.run_once()
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            # Type only, like the loop: a message could quote a URL.
            logger.warning("file_reputation_kick_failed", error_type=type(exc).__name__)
            return 0
