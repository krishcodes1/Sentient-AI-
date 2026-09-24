"""Starts, restarts or stops the TelegramService when the owner saves or clears
the bot token.

Why it exists: main.py wires the approval store and the reminder sweeper to one
stable object while the poller behind it changes at runtime; the proxies are
no-ops while stopped so callers never have to check.

Starts, restarts and stops the Telegram poller at runtime.

main.py wires the approval store and the reminder sweeper to this manager
once; whether a poller exists behind it can change whenever the owner
saves or clears the bot token in the wizard. Proxies are no-ops while
stopped so callers never need to know.
"""

from __future__ import annotations

import asyncio
from typing import Any, Callable, Optional

import structlog

from services.notifications.telegram import TelegramService

logger = structlog.get_logger(__name__)


class TelegramManager:
    def __init__(
        self,
        session_factory: Any,
        *,
        on_start: Optional[Callable[[TelegramService], None]] = None,
        service_factory: Callable[..., TelegramService] = TelegramService,
    ) -> None:
        self._session_factory = session_factory
        self._on_start = on_start
        self._factory = service_factory
        self.current: Optional[TelegramService] = None
        self._token: Optional[str] = None
        # Serializes apply()/stop() so two concurrent saves (or a save
        # racing a clear) can't both construct a service, both win the
        # `self.current = service` assignment, and leak the loser's
        # poller/http client running with nothing left to stop it.
        self._lock = asyncio.Lock()

    @property
    def is_running(self) -> bool:
        return self.current is not None

    async def apply(self, token: Optional[str], enabled: bool) -> str:
        want = bool(token) and enabled
        async with self._lock:
            if not want:
                if self.current is None:
                    return "unchanged"
                await self._stop_locked()
                return "stopped"
            if self.current is not None and token == self._token:
                return "unchanged"
            restarted = self.current is not None
            if restarted:
                # Stop the old service before starting the new one so we
                # never run two pollers for the same manager at once.
                await self._stop_locked()
            service = self._factory(token=token, session_factory=self._session_factory)
            try:
                if self._on_start is not None:
                    self._on_start(service)
                await service.start()
            except Exception:
                logger.warning("telegram_manager_start_failed", restarted=restarted)
                # Best-effort cleanup: the service may already hold an
                # open http client (opened in __init__) even though
                # start() never completed. A failed restart is NOT
                # rolled back to the old service — it was already
                # stopped above, so the manager is simply left stopped.
                try:
                    await service.stop()
                except Exception:
                    logger.warning("telegram_manager_start_cleanup_failed", restarted=restarted)
                raise
            self.current, self._token = service, token
            logger.info("telegram_manager_applied", state="restarted" if restarted else "started")
            return "restarted" if restarted else "started"

    async def stop(self) -> None:
        async with self._lock:
            await self._stop_locked()

    async def _stop_locked(self) -> None:
        """Body of stop(), assuming the caller already holds self._lock."""
        service, self.current, self._token = self.current, None, None
        if service is not None:
            await service.stop()
            logger.info("telegram_manager_stopped")

    async def notify_pending(self, action: Any) -> None:
        if self.current is not None:
            await self.current.notify_pending(action)

    async def send_text(self, user_id: str, text: str) -> bool:
        if self.current is None:
            return False
        return await self.current.send_text(user_id, text)

    async def bot_username(self) -> Optional[str]:
        if self.current is None:
            return None
        return await self.current.bot_username()
