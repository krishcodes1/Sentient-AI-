from __future__ import annotations

import pytest

from services.notifications.telegram_manager import TelegramManager


class FakeService:
    instances: list["FakeService"] = []

    def __init__(self, token, session_factory, decide=None, chat=None):
        self.token = token
        self.started = False
        self.stopped = False
        self.decide = decide
        self.chat = chat
        FakeService.instances.append(self)

    async def start(self):
        self.started = True

    async def stop(self):
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
