"""Tests for TelegramManager: `apply()` starts, restarts, stops, and no-ops
idempotently, that proxied calls (`notify_pending`, `send_text`,
`bot_username`) no-op while stopped and forward while running, and that
concurrent `apply()` calls serialize to exactly one running service with no
orphaned instances left behind.

Why it exists: Guards against a failed start or restart leaving an orphaned
service running alongside the new one, or concurrent `apply()` calls racing to
leave two Telegram pollers active at once.
"""

from __future__ import annotations

import asyncio

import pytest

from services.notifications.telegram_manager import TelegramManager


class FakeService:
    instances: list["FakeService"] = []

    def __init__(self, token, session_factory, decide=None, chat=None, start_error=None):
        self.token = token
        self.started = False
        self.stopped = False
        self.decide = decide
        self.chat = chat
        self.start_error = start_error
        FakeService.instances.append(self)

    async def start(self):
        # A real checkpoint (like the real service's network calls) so
        # concurrent apply() calls actually interleave in tests instead
        # of running to completion back-to-back.
        await asyncio.sleep(0)
        if self.start_error is not None:
            raise self.start_error
        self.started = True

    async def stop(self):
        await asyncio.sleep(0)
        self.stopped = True

    async def notify_pending(self, action):
        self.notified = action

    async def send_text(self, user_id, text):
        return True

    async def bot_username(self):
        return "crawler_bot"


@pytest.fixture(autouse=True)
def _reset():
    FakeService.instances.clear()


@pytest.mark.asyncio
async def test_apply_starts_restarts_stops_and_is_idempotent():
    hooks: list[str] = []
    mgr = TelegramManager(session_factory=object(), on_start=lambda svc: hooks.append(svc.token), service_factory=FakeService)
    assert mgr.is_running is False
    assert await mgr.apply("111:aaa", True) == "started"
    assert mgr.is_running and FakeService.instances[-1].started and hooks == ["111:aaa"]
    assert await mgr.apply("111:aaa", True) == "unchanged"
    assert await mgr.apply("222:bbb", True) == "restarted"
    assert FakeService.instances[0].stopped and FakeService.instances[-1].token == "222:bbb"
    assert await mgr.apply("222:bbb", False) == "stopped"
    assert mgr.is_running is False and mgr.current is None
    assert await mgr.apply(None, True) == "unchanged"


@pytest.mark.asyncio
async def test_proxies_noop_when_stopped_and_forward_when_running():
    mgr = TelegramManager(session_factory=object(), service_factory=FakeService)
    await mgr.notify_pending({"id": 1})  # no error
    assert await mgr.send_text("u", "hi") is False
    assert await mgr.bot_username() is None
    await mgr.apply("111:aaa", True)
    await mgr.notify_pending({"id": 2})
    assert FakeService.instances[-1].notified == {"id": 2}
    assert await mgr.send_text("u", "hi") is True
    assert await mgr.bot_username() == "crawler_bot"
    await mgr.stop()
    assert mgr.is_running is False


@pytest.mark.asyncio
async def test_concurrent_apply_is_serialized_with_no_orphans():
    mgr = TelegramManager(session_factory=object(), service_factory=FakeService)
    await asyncio.gather(mgr.apply("111:aaa", True), mgr.apply("222:bbb", True))

    assert mgr.is_running is True
    running = [svc for svc in FakeService.instances if not svc.stopped]
    assert len(running) == 1
    assert running[0] is mgr.current
    for svc in FakeService.instances:
        if svc is not mgr.current:
            assert svc.stopped is True


@pytest.mark.asyncio
async def test_failed_start_cleans_up_and_propagates():
    def make_failing(**kwargs):
        return FakeService(**kwargs, start_error=RuntimeError("boom"))

    mgr = TelegramManager(session_factory=object(), service_factory=make_failing)

    with pytest.raises(RuntimeError):
        await mgr.apply("111:aaa", True)

    assert FakeService.instances[-1].stopped is True
    assert mgr.is_running is False
    assert mgr.current is None


@pytest.mark.asyncio
async def test_failed_restart_stops_old_service_and_leaves_manager_stopped():
    def make_failing(**kwargs):
        return FakeService(**kwargs, start_error=RuntimeError("boom"))

    mgr = TelegramManager(session_factory=object(), service_factory=FakeService)
    assert await mgr.apply("111:aaa", True) == "started"
    first = mgr.current

    mgr._factory = make_failing
    with pytest.raises(RuntimeError):
        await mgr.apply("222:bbb", True)

    assert first.stopped is True
    assert FakeService.instances[-1].stopped is True
    assert mgr.is_running is False
    assert mgr.current is None
