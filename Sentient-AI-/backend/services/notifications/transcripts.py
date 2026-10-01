"""The transcript janitor: every 6 hours it deletes cached video and podcast
transcripts past their expiry (or unused for longer than the owner's
keep_transcripts_days) and trims every user to their 200 most recently used.

Why it exists: video.transcript and video.list purge the caller's own
expired rows as they go, but a user who stops asking would keep theirs; the
janitor makes the 14-day retention hold for everyone. It runs on the shared
SweepLoop (services/notifications/sweeper.py). It is deliberately not gated
on the video_transcripts switch: deleting old data must go on while the
feature is off. Logs carry counts only.
"""

from __future__ import annotations

from typing import Awaitable, Callable, Optional

import structlog

from services.notifications.sweeper import SweepLoop
from services.tools.video.store import KEEP_DAYS_DEFAULT, MAX_ROWS_PER_USER, TranscriptStore

logger = structlog.get_logger(__name__)

SWEEP_INTERVAL_S = 6 * 3600.0

KeepDays = Callable[[], Awaitable[int]]


class TranscriptJanitor:
    """Purges and trims ``media_transcripts`` on a SweepLoop.
    ``keep_days`` reads the owner's keep_transcripts_days (a failed read
    falls back to the default, which still purges)."""

    def __init__(
        self,
        store: TranscriptStore,
        *,
        interval_seconds: float = SWEEP_INTERVAL_S,
        keep_days: Optional[KeepDays] = None,
    ) -> None:
        self.store = store
        self._keep_days = keep_days
        self.loop = SweepLoop(name="transcripts", interval_seconds=interval_seconds, sweep=self.sweep)

    async def _days(self) -> int:
        if self._keep_days is None:
            return KEEP_DAYS_DEFAULT
        try:
            days = int(await self._keep_days())
        except Exception as exc:  # noqa: BLE001 - retention still applies at its default
            logger.warning("transcripts_keep_days_unreadable", error_type=type(exc).__name__)
            return KEEP_DAYS_DEFAULT
        return days if days >= 1 else KEEP_DAYS_DEFAULT

    async def sweep(self) -> int:
        """One pass: the rows purged plus the rows trimmed."""
        purged = await self.store.purge_expired(keep_days=await self._days())
        trimmed = await self.store.trim(MAX_ROWS_PER_USER)
        if purged or trimmed:
            logger.info("transcripts_swept", purged=purged, trimmed=trimmed)
        return purged + trimmed

    async def start(self) -> None:
        await self.loop.start()

    async def stop(self) -> None:
        await self.loop.stop()
