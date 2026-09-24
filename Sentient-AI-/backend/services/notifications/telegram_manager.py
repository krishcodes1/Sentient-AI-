"""Starts, restarts and stops the Telegram poller at runtime.

main.py wires the approval store and the reminder sweeper to this manager
once; whether a poller exists behind it can change whenever the owner
saves or clears the bot token in the wizard. Proxies are no-ops while
stopped so callers never need to know.
"""

from __future__ import annotations

import hashlib
from typing import Any, Callable, Optional

import structlog

from services.notifications.telegram import TelegramService

logger = structlog.get_logger(__name__)


def _fingerprint(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()[:16]


class TelegramManager:
    def __init__(
        self,
        session_factory: Any,
        *,
        on_start: Optional[Callable[[Any], None]] = None,
        service_factory: Callable[..., Any] = TelegramService,
    ) -> None:
        self._session_factory = session_factory
        self._on_start = on_start
        self._factory = service_factory
        self.current: Optional[Any] = None
        self._fingerprint: Optional[str] = None

    @property
    def is_running(self) -> bool:
        return self.current is not None

    async def apply(self, token: Optional[str], enabled: bool) -> str:
        want = bool(token) and enabled
        fp = _fingerprint(token) if token else None
        if not want:
            if self.current is None:
                return "unchanged"
            await self.stop()
            return "stopped"
        if self.current is not None and fp == self._fingerprint:
            return "unchanged"
        restarted = self.current is not None
        if restarted:
            await self.stop()
        service = self._factory(token=token, session_factory=self._session_factory)
        if self._on_start is not None:
            self._on_start(service)
        await service.start()
        self.current, self._fingerprint = service, fp
        logger.info("telegram_manager_applied", state="restarted" if restarted else "started")
        return "restarted" if restarted else "started"

    async def stop(self) -> None:
        service, self.current, self._fingerprint = self.current, None, None
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
