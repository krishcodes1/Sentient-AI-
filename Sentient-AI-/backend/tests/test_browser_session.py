"""Session manager against a fake launcher: no Playwright, no browser."""

from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

from services.tools.browser.session import BrowserSession, BrowserSessionManager, TaskState


class FakePage:
    def __init__(self, url: str = "about:blank") -> None:
        self.url = url
        self.closed = False
        self.fronted = 0

    async def title(self):
        return "T"

    async def bring_to_front(self):
        self.fronted += 1

    async def close(self):
        self.closed = True


class FakeContext:
    def __init__(self) -> None:
        self.pages: list[FakePage] = [FakePage()]
        self.closed = False

    async def new_page(self):
        page = FakePage()
        self.pages.append(page)
        return page

    async def close(self):
        self.closed = True


class FakeLauncher:
    def __init__(self) -> None:
        self.calls: list[dict] = []

    async def __call__(self, **kwargs):
        self.calls.append(kwargs)
        return FakeContext()


class Plat:
    def __init__(self, name: str, channel, root: Path) -> None:
        self.name, self._channel, self._root = name, channel, root

    def browser_channel(self):
        return self._channel

    def profile_dir(self, user_id: str) -> Path:
        path = self._root / "browser-profiles" / user_id
        path.mkdir(parents=True, exist_ok=True)
        return path

    def data_dir(self) -> Path:
        return self._root

    def bring_to_front(self, *, pid=None, title=None) -> bool:
        return False

    def port_owner(self, port: int):
        return None


def manager(tmp_path, *, name="container", channel=None, **kw):
    launcher = FakeLauncher()
    plat = Plat(name, channel, tmp_path)
    return BrowserSessionManager(headless=name == "container", platform=plat, launcher=launcher, **kw), launcher


def test_task_state_defaults():
    state = TaskState(task_id="t1")
    assert (state.actions, state.spend_usd, state.notes, state.summaries, state.last_outline_chars) == (0, 0.0, [], [], 0)


@pytest.mark.asyncio
async def test_nothing_launches_until_the_first_get(tmp_path):
    mgr, launcher = manager(tmp_path)
    assert launcher.calls == []
    session = await mgr.get("u1", mode="account", task_id="t1")
    assert isinstance(session, BrowserSession) and len(launcher.calls) == 1
    assert launcher.calls[0]["headless"] is True and launcher.calls[0]["channel"] is None
    assert launcher.calls[0]["user_data_dir"] is None  # container: nothing persistent on disk


@pytest.mark.asyncio
@pytest.mark.parametrize("name, channel, profile_tail", [("mac", "chrome", "browser-profiles/u1"), ("windows", "msedge", "browser-profiles/u1")])
async def test_native_platforms_launch_headed_with_their_channel_and_profile(tmp_path, name, channel, profile_tail):
    mgr, launcher = manager(tmp_path, name=name, channel=channel)
    await mgr.get("u1", mode="account", task_id="t1")
    call = launcher.calls[0]
    assert call["headless"] is False and call["channel"] == channel
    assert Path(call["user_data_dir"]) == tmp_path / Path(profile_tail)
    assert call["viewport"] == {"width": 1280, "height": 800}


@pytest.mark.asyncio
async def test_public_mode_gets_a_fresh_non_persistent_context(tmp_path):
    mgr, launcher = manager(tmp_path, name="mac", channel="chrome")
    await mgr.get("u1", mode="public", task_id="t1")
    assert launcher.calls[0]["user_data_dir"] is None


@pytest.mark.asyncio
async def test_sessions_are_reused_per_user_and_task_state_resets_on_a_new_task(tmp_path):
    mgr, launcher = manager(tmp_path)
    first = await mgr.get("u1", mode="account", task_id="t1")
    first.task.actions = 5
    first.task.notes.append("keep")
    again = await mgr.get("u1", mode="account", task_id="t1")
    assert again is first and again.task.actions == 5 and len(launcher.calls) == 1
    fresh = await mgr.get("u1", mode="account", task_id="t2")
    assert fresh is first and fresh.task == TaskState(task_id="t2")
    other = await mgr.get("u2", mode="account", task_id="t1")
    assert other is not first and len(launcher.calls) == 2


@pytest.mark.asyncio
async def test_max_sessions_evicts_the_idle_oldest(tmp_path):
    mgr, launcher = manager(tmp_path, max_sessions=2)
    a = await mgr.get("a", mode="account", task_id="t")
    await mgr.get("b", mode="account", task_id="t")
    await mgr.get("c", mode="account", task_id="t")
    assert a.context.closed is True and len(mgr.sessions) == 2


@pytest.mark.asyncio
async def test_tabs_switch_and_the_tab_cap(tmp_path):
    mgr, _ = manager(tmp_path, max_tabs=2)
    session = await mgr.get("u1", mode="account", task_id="t1")
    assert [t["index"] for t in await session.tabs()] == [0]
    second = await session.new_tab()
    assert (await session.page()) is second
    tabs = await session.tabs()
    assert [t["active"] for t in tabs] == [False, True] and tabs[1]["title"] == "T"
    with pytest.raises(RuntimeError, match="2 tabs"):
        await session.new_tab()
    await session.switch(0)
    assert (await session.page()) is session.context.pages[0]
    with pytest.raises(IndexError):
        await session.switch(7)


@pytest.mark.asyncio
async def test_reap_idle_closes_idle_sessions_but_never_a_pending_one(tmp_path):
    now = [1000.0]
    mgr, _ = manager(tmp_path, idle_seconds=60, clock=lambda: now[0])
    idle = await mgr.get("idle", mode="account", task_id="t")
    parked = await mgr.get("parked", mode="account", task_id="t")
    fresh = await mgr.get("fresh", mode="account", task_id="t")
    parked.pending = "handoff"
    now[0] += 61
    fresh.last_used = now[0]
    assert await mgr.reap_idle() == 1
    assert idle.context.closed and not parked.context.closed and not fresh.context.closed
    assert set(mgr.sessions) == {"parked", "fresh"}


@pytest.mark.asyncio
async def test_close_and_close_all(tmp_path):
    mgr, _ = manager(tmp_path)
    a = await mgr.get("a", mode="account", task_id="t")
    b = await mgr.get("b", mode="account", task_id="t")
    await mgr.close("a")
    assert a.context.closed and "a" not in mgr.sessions
    await mgr.close("missing")  # no-op
    await mgr.close_all()
    assert b.context.closed and mgr.sessions == {}


@pytest.mark.asyncio
async def test_concurrent_gets_launch_once(tmp_path):
    mgr, launcher = manager(tmp_path)
    sessions = await asyncio.gather(*(mgr.get("u1", mode="account", task_id="t") for _ in range(5)))
    assert len({id(s) for s in sessions}) == 1 and len(launcher.calls) == 1


# -- the real launcher against a fake Playwright (no browser starts) -------------


class FakePlaywright:
    def __init__(self, *, fail: bool = False) -> None:
        self.stopped = False
        self.calls: list[tuple[str, dict]] = []
        self._fail = fail
        self.chromium = self

    async def stop(self):
        self.stopped = True

    async def launch_persistent_context(self, **kwargs):
        self.calls.append(("launch_persistent_context", kwargs))
        if self._fail:
            raise RuntimeError("Chromium distribution 'chrome' is not found")
        return FakeContext()

    async def launch(self, **kwargs):
        self.calls.append(("launch", kwargs))
        if self._fail:
            raise RuntimeError("Executable doesn't exist")
        return self

    async def new_context(self, **kwargs):
        self.calls.append(("new_context", kwargs))
        return FakeContext()


@pytest.fixture
def fake_playwright(monkeypatch):
    api = pytest.importorskip("playwright.async_api")
    made: list[FakePlaywright] = []

    def install(*, fail: bool = False) -> list[FakePlaywright]:
        class Starter:
            async def start(self):
                made.append(FakePlaywright(fail=fail))
                return made[-1]

        monkeypatch.setattr(api, "async_playwright", Starter)
        return made

    return install


@pytest.mark.asyncio
async def test_launcher_blocks_service_workers_and_downloads_in_the_persistent_profile(fake_playwright, tmp_path):
    # A service worker answers requests before context.route sees them, so
    # it would slip redirects past the egress guard: blocked on both paths.
    from services.tools.browser.session import VIEWPORT, playwright_launcher

    made = fake_playwright()
    context = await playwright_launcher(headless=False, channel="chrome", user_data_dir=str(tmp_path), viewport=dict(VIEWPORT))
    name, kwargs = made[0].calls[0]
    assert name == "launch_persistent_context"
    assert kwargs["service_workers"] == "block" and kwargs["accept_downloads"] is False
    assert kwargs["headless"] is False and kwargs["channel"] == "chrome" and kwargs["user_data_dir"] == str(tmp_path)
    assert context._crawler_playwright is made[0]


@pytest.mark.asyncio
async def test_launcher_throwaway_context_blocks_service_workers_permissions_and_downloads(fake_playwright):
    from services.tools.browser.session import VIEWPORT, playwright_launcher

    made = fake_playwright()
    await playwright_launcher(headless=True, channel=None, user_data_dir=None, viewport=dict(VIEWPORT))
    (launch, launch_kwargs), (new_context, kwargs) = made[0].calls
    assert (launch, new_context) == ("launch", "new_context") and launch_kwargs["headless"] is True
    assert kwargs["service_workers"] == "block" and kwargs["permissions"] == [] and kwargs["accept_downloads"] is False


@pytest.mark.asyncio
@pytest.mark.parametrize("profile", [True, False])
async def test_a_failed_launch_stops_the_playwright_driver(fake_playwright, tmp_path, profile):
    from services.tools.browser.session import VIEWPORT, playwright_launcher

    made = fake_playwright(fail=True)
    with pytest.raises(RuntimeError):
        await playwright_launcher(
            headless=True, channel=None, user_data_dir=str(tmp_path) if profile else None, viewport=dict(VIEWPORT)
        )
    assert made[0].stopped is True  # no orphaned driver process per failed attempt


@pytest.mark.asyncio
async def test_close_stops_the_driver_even_when_the_context_will_not_close(tmp_path):
    driver = FakePlaywright()

    class StuckContext(FakeContext):
        async def close(self):
            raise RuntimeError("Target page, context or browser has been closed")

    async def launcher(**_kwargs):
        context = StuckContext()
        context._crawler_playwright = driver  # type: ignore[attr-defined]
        return context

    mgr = BrowserSessionManager(headless=True, platform=Plat("container", None, tmp_path), launcher=launcher)
    await mgr.get("u1", mode="account", task_id="t")
    await mgr.close("u1")
    assert driver.stopped is True and mgr.sessions == {}


# -- HTTPS errors are never ignored in production (purchases spec §9) ------------


@pytest.mark.asyncio
@pytest.mark.parametrize("profile", [True, False])
async def test_production_launcher_never_ignores_https_errors(fake_playwright, tmp_path, profile):
    """The write tiers' https-only rule is worth nothing if the browser
    accepts a forged certificate: only the test launcher may pass
    ignore_https_errors, and it does so for the fake site's self-signed
    certificate alone."""
    from services.tools.browser.session import VIEWPORT, playwright_launcher

    made = fake_playwright()
    await playwright_launcher(
        headless=True, channel=None, user_data_dir=str(tmp_path) if profile else None, viewport=dict(VIEWPORT)
    )
    assert made[0].calls  # the fake saw every launch call
    for _name, kwargs in made[0].calls:
        assert "ignore_https_errors" not in kwargs
        assert "ignoreHTTPSErrors" not in kwargs


@pytest.mark.asyncio
async def test_test_launcher_ignores_https_errors_only_on_a_throwaway_headless_context(fake_playwright):
    from services.tools.browser.session import VIEWPORT
    from tests.conftest import CHROMIUM_TEST_ARGS, tls_launcher

    made = fake_playwright()
    context = await tls_launcher(headless=False, channel="chrome", user_data_dir="/tmp/profile", viewport=dict(VIEWPORT))
    (launch, launch_kwargs), (new_context, kwargs) = made[0].calls
    assert (launch, new_context) == ("launch", "new_context")
    assert launch_kwargs == {"headless": True, "args": CHROMIUM_TEST_ARGS}  # never headed, never the real profile or channel
    assert kwargs["ignore_https_errors"] is True
    assert kwargs["service_workers"] == "block" and kwargs["accept_downloads"] is False and kwargs["permissions"] == []
    assert context._crawler_playwright is made[0]
