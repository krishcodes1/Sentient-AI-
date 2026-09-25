"""One browser context per user, one TaskState per task (contracts §2).

Native (Mac/Windows): the installed Chrome/Edge, headed, in a private
Crawler profile the platform layer created (0700 / current-user ACL), so
a login the owner made by hand persists. Container/tests: headless
Chromium with a throwaway context. PUBLIC mode is a fresh non-persistent
context either way. ``launcher`` is injectable so tests pass a fake and
never start a browser.
"""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Awaitable, Callable, Literal, Optional

import structlog

if TYPE_CHECKING:
    # Annotation only: the manager duck-types the platform (name,
    # browser_channel, profile_dir), so importing this module never needs
    # the OS layer loaded.
    from services.platform.base import Platform

logger = structlog.get_logger(__name__)

Mode = Literal["account", "public"]
VIEWPORT = {"width": 1280, "height": 800}
# What a launcher must accept: everything the two Playwright paths need.
Launcher = Callable[..., Awaitable[Any]]


@dataclass
class TaskState:
    task_id: str  # conversation id + resume chain; carried across approval/handoff resumes
    actions: int = 0
    spend_usd: float = 0.0
    notes: list[str] = field(default_factory=list)  # note(text) entries, ≤2k chars total
    summaries: list[str] = field(default_factory=list)  # toolkit-written one-liners, newest last
    last_outline_chars: int = 0


class BrowserSession:
    def __init__(self, user_id: str, mode: Mode, context: Any, task_id: str, clock: Callable[[], float]) -> None:
        self.user_id = user_id
        self.mode: Mode = mode
        self.context = context
        self.lock = asyncio.Lock()
        self.task = TaskState(task_id=task_id)
        self.last_used = clock()
        self.typed_secrets: list[str] = []  # redaction list (phase 2 fills it)
        # "approval" | "handoff" while a turn is parked; the reaper skips it.
        self.pending: Optional[str] = None
        self._active = 0
        self._max_tabs = 4

    async def page(self) -> Any:
        pages = self.context.pages
        if not pages:
            self._active = 0
            return await self.context.new_page()
        self._active = min(self._active, len(pages) - 1)
        return pages[self._active]

    async def tabs(self) -> list[dict[str, Any]]:
        out = []
        for index, page in enumerate(self.context.pages):
            out.append({"index": index, "url": page.url, "title": await page.title(), "active": index == self._active})
        return out

    async def switch(self, index: int) -> None:
        pages = self.context.pages
        if not 0 <= index < len(pages):
            raise IndexError(index)
        self._active = index
        await pages[index].bring_to_front()

    async def new_tab(self) -> Any:
        if len(self.context.pages) >= self._max_tabs:
            raise RuntimeError(f"This session already has {self._max_tabs} tabs open; close or reuse one.")
        page = await self.context.new_page()
        self._active = len(self.context.pages) - 1
        return page


async def playwright_launcher(
    *, headless: bool, channel: Optional[str], user_data_dir: Optional[str], viewport: dict[str, int]
) -> Any:
    """The real thing: a persistent context in the private profile when
    ``user_data_dir`` is given (native ACCOUNT mode), else a throwaway
    context on a headless/headed Chromium with downloads and permissions off.

    Service workers are blocked on both paths: a worker answers requests
    before ``context.route`` sees them, so it could hand the page a
    redirect the egress guard never checks. A failed launch (Chrome/Edge
    not installed, profile locked) stops the driver it started instead of
    leaving one orphaned node process per attempt."""
    from playwright.async_api import ViewportSize, async_playwright

    size = ViewportSize(width=viewport["width"], height=viewport["height"])
    playwright = await async_playwright().start()
    context: Any  # Any: carries the private _crawler_playwright handle below
    try:
        if user_data_dir is not None:
            context = await playwright.chromium.launch_persistent_context(
                user_data_dir=user_data_dir, channel=channel, headless=headless, viewport=size,
                service_workers="block", accept_downloads=False,
            )
        else:
            browser = await playwright.chromium.launch(headless=headless, channel=channel)
            context = await browser.new_context(
                viewport=size, service_workers="block", accept_downloads=False, permissions=[]
            )
    except BaseException:
        await playwright.stop()
        raise
    context._crawler_playwright = playwright  # closed with the context in close()
    return context


class BrowserSessionManager:
    def __init__(
        self,
        *,
        headless: bool,
        platform: Platform,
        max_sessions: int = 3,
        max_tabs: int = 4,
        idle_seconds: int = 900,
        launcher: Optional[Launcher] = None,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._headless = headless
        self._platform = platform
        self._max_sessions = max_sessions
        self._max_tabs = max_tabs
        self._idle_seconds = idle_seconds
        self._launch: Launcher = launcher or playwright_launcher
        self._clock = clock
        self.sessions: dict[str, BrowserSession] = {}
        self._creating = asyncio.Lock()

    async def get(self, user_id: str, *, mode: Mode, task_id: str) -> BrowserSession:
        """Create or reuse the user's session; a new task id resets TaskState."""
        async with self._creating:
            session = self.sessions.get(user_id)
            if session is None or session.mode != mode:
                if session is not None:
                    await self._close_session(session)
                if len(self.sessions) >= self._max_sessions:
                    await self._evict_one()
                session = await self._create(user_id, mode, task_id)
                self.sessions[user_id] = session
        if session.task.task_id != task_id:
            session.task = TaskState(task_id=task_id)
        session.last_used = self._clock()
        return session

    async def _create(self, user_id: str, mode: Mode, task_id: str) -> BrowserSession:
        persistent = mode == "account" and self._platform.name != "container"
        context = await self._launch(
            headless=self._headless,
            channel=self._platform.browser_channel(),
            user_data_dir=str(self._platform.profile_dir(user_id)) if persistent else None,
            viewport=dict(VIEWPORT),
        )
        session = BrowserSession(user_id, mode, context, task_id, self._clock)
        session._max_tabs = self._max_tabs
        logger.info("browser_session_started", user_id=user_id, mode=mode, headless=self._headless)
        return session

    async def _evict_one(self) -> None:
        candidates = [s for s in self.sessions.values() if s.pending is None]
        if not candidates:
            raise RuntimeError("Every browser session is waiting on the person; try again later.")
        oldest = min(candidates, key=lambda s: s.last_used)
        await self._close_session(oldest)

    async def _close_session(self, session: BrowserSession) -> None:
        self.sessions.pop(session.user_id, None)
        # Two steps, each tolerated on its own: a context that will not
        # close must still have its driver (and so its browser) stopped.
        try:
            await session.context.close()
        except Exception as exc:  # noqa: BLE001 - a browser that will not quit is logged, not raised
            logger.warning("browser_session_close_failed", user_id=session.user_id, error=str(exc)[:200])
        playwright = getattr(session.context, "_crawler_playwright", None)
        if playwright is not None:
            try:
                await playwright.stop()
            except Exception as exc:  # noqa: BLE001 - same: logged, never raised into the caller
                logger.warning("browser_driver_stop_failed", user_id=session.user_id, error=str(exc)[:200])

    async def close(self, user_id: str) -> None:
        session = self.sessions.get(user_id)
        if session is not None:
            await self._close_session(session)

    async def close_all(self) -> None:
        for session in list(self.sessions.values()):
            await self._close_session(session)

    async def reap_idle(self) -> int:
        """Close sessions idle past the limit; never one parked on an
        approval or a handoff (the person is expected back)."""
        cutoff = self._clock() - self._idle_seconds
        reaped = 0
        for session in list(self.sessions.values()):
            if session.pending is None and session.last_used < cutoff and not session.lock.locked():
                await self._close_session(session)
                reaped += 1
        return reaped
