"""One browser context per user, one TaskState per task (contracts §2).

Native (Mac/Windows): the installed Chrome/Edge, headed, in a private
Crawler profile the platform layer created (0700 / current-user ACL), so
a login the owner made by hand persists. Container/tests: headless
Chromium with a throwaway context. PUBLIC mode is a fresh non-persistent
context either way. ``launcher`` is injectable so tests pass a fake and
never start a browser.

How long a session lives: the reaper closes one nobody has used for the
idle limit, except while the person holds its window (``pending``, set
by ``_shared.hand_over`` and cleared by ``_shared.take_back``), which is
given PENDING_IDLE_SECONDS so they are not cut off while they type. An
errand's purchase card parks the session until a set time
(``park_for_purchase``: ``pending`` "purchase", ``held_until``): the card
waits hours for the owner, and an approval must find the checkout page
still open. The next action on the session ends the parking (``take_back``
clears ``pending``), and so do the card's approval being used, a denied
card and a cancelled errand (``release_purchase``, from the checkout
toolkit, only for the checkout it parked for). A
browser the person quit, or one that crashed, is noticed by its
context's ``close`` event (``BrowserSession.closed``) and replaced on
the next ``get``; handed out again, every call on it would fail.

A tab a click opened (``target=_blank``, ``window.open``) becomes the
active one through ``adopt_new_tab``, so the next look is at the page
the click opened and not at the tab it was made in.
"""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Awaitable, Callable, Literal, Optional, Sequence

import structlog

if TYPE_CHECKING:
    # Annotation only: the manager duck-types the platform (name,
    # browser_channel, profile_dir), so importing this module never needs
    # the OS layer loaded.
    from services.platform.base import Platform

logger = structlog.get_logger(__name__)

Mode = Literal["account", "public"]
VIEWPORT = {"width": 1280, "height": 800}
# How long a session the person holds (a handoff, an approval) may sit
# unused before the reaper closes it anyway: long enough to find a
# password or a phone, short enough that a person who never comes back
# does not pin a browser window forever.
PENDING_IDLE_SECONDS = 2 * 60 * 60
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
        # "approval" | "handoff" | "purchase" while a turn is parked: the
        # reaper gives it PENDING_IDLE_SECONDS ("purchase": until
        # held_until), and it is never evicted for another user.
        self.pending: Optional[str] = None
        self.held_until: Optional[float] = None
        # True once the context is gone (the person quit the browser, or it
        # crashed): the manager launches a new one on the next get.
        self.closed = False
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

    async def adopt_new_tab(self, before: Sequence[Any]) -> Optional[Any]:
        """Make the tab a click opened the session's active one. Without
        this the session went on describing the tab the click was made
        in, and the model took the click for one that did nothing.

        The contract browser.read's click and browser.act's approved act
        both rely on:

        - *before* is the tabs that were open before the click: a copy of
          ``context.pages`` taken then (``list(session.context.pages)``;
          the live list would already hold the new tab). Call this once
          the click and its settle time are over.
        - Returns the newest tab that is not in *before*, now the active
          one (``page()`` returns it from here on), so the caller can
          wait for it to settle and describe it. Returns None, and leaves
          the active tab as it was, when the click opened no tab, when
          the new tab shows Chrome's error page, or when it closed itself
          meanwhile (a popup that only passes through).
        - Closes a new tab left on Chrome's error page (its navigation
          was stopped or failed: it shows nothing) and, above the tab
          cap, the oldest tabs that are neither the new one nor the one
          the click was made in, so tabs that pages open cannot pile up.
          The tab the click was made in stays open: a page reports back
          to the one that opened it (a sign-in window, a payment step).
          It never navigates, waits or describes anything."""
        opened = [tab for tab in self.context.pages if tab not in before]
        if not opened:
            return None
        tab = opened[-1]
        if tab.url.startswith("chrome-error://"):
            await tab.close()
            return None
        pages = self.context.pages
        clicked_in = pages[self._active] if self._active < len(pages) else None
        spare = [other for other in pages if other is not tab and other is not clicked_in]
        for old in spare[: max(0, len(pages) - self._max_tabs)]:
            await old.close()
        pages = self.context.pages
        if tab not in pages:  # it closed itself meanwhile (a popup that only passes through)
            return None
        self._active = pages.index(tab)
        return tab


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

    from services.tools.browser.egress_proxy import EgressProxy

    size = ViewportSize(width=viewport["width"], height=viewport["height"])
    # Every connection Chrome makes goes through a proxy that judges its
    # address (egress_proxy.py): a walled page Chrome loads itself, and the
    # redirects it then follows, still reach no private or local address.
    proxy = await EgressProxy().start()
    # Loopback through the proxy too, whatever Playwright's environment
    # says; WebRTC sends no UDP around it.
    via = {"server": proxy.url, "bypass": "<-loopback>"}
    webrtc = ["--force-webrtc-ip-handling-policy=disable_non_proxied_udp"]
    playwright: Any = None
    context: Any  # Any: carries the private _crawler_playwright handle below
    try:
        playwright = await async_playwright().start()
        if user_data_dir is not None:
            context = await playwright.chromium.launch_persistent_context(
                user_data_dir=user_data_dir, channel=channel, headless=headless, viewport=size,
                service_workers="block", accept_downloads=False, proxy=via, args=webrtc,
            )
        else:
            browser = await playwright.chromium.launch(headless=headless, channel=channel, proxy=via, args=webrtc)
            context = await browser.new_context(
                viewport=size, service_workers="block", accept_downloads=False, permissions=[]
            )
    except BaseException:
        if playwright is not None:
            await playwright.stop()
        await proxy.close()
        raise
    context._crawler_playwright = playwright  # closed with the context in close()
    context._crawler_proxy = proxy  # closed with it too; the guard reads that it is there
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
        """Create or reuse the user's session; a new task id resets TaskState.
        A session whose browser is gone (``closed``) is closed properly, so
        its driver stops too, and replaced like one of the other mode."""
        async with self._creating:
            session = self.sessions.get(user_id)
            if session is None or session.mode != mode or session.closed:
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
        # Playwright says when a context goes away, whoever closed it: the
        # person quitting Crawler's browser, a crash, or this manager.
        context.on("close", lambda _context: setattr(session, "closed", True))
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
        proxy = getattr(session.context, "_crawler_proxy", None)
        if proxy is not None:
            await proxy.close()

    async def close(self, user_id: str) -> None:
        session = self.sessions.get(user_id)
        if session is not None:
            await self._close_session(session)

    async def close_all(self) -> None:
        for session in list(self.sessions.values()):
            await self._close_session(session)

    def park_for_purchase(self, user_id: str, seconds: float) -> bool:
        """Keep *user_id*'s session open for *seconds* from now while an
        errand's purchase card waits. False when there is no live session
        to keep."""
        session = self.sessions.get(user_id)
        if session is None or session.closed:
            return False
        session.pending = "purchase"
        session.held_until = self._clock() + seconds
        return True

    def release_purchase(self, user_id: str) -> None:
        """End *user_id*'s purchase parking (the errand's card was used,
        denied or its errand cancelled): the session goes back to the idle
        limit. A session parked for anything else is left as it is."""
        session = self.sessions.get(user_id)
        if session is not None and session.pending == "purchase":
            session.pending, session.held_until = None, None

    async def reap_idle(self) -> int:
        """Close sessions idle past the limit. One parked on an approval or
        a handoff is given PENDING_IDLE_SECONDS instead: the person is
        expected back, and one who never returns must not keep a window
        open forever. One parked for a purchase card stays until its
        ``held_until``."""
        now = self._clock()
        parked_limit = max(self._idle_seconds, PENDING_IDLE_SECONDS)
        reaped = 0
        for session in list(self.sessions.values()):
            if session.pending == "purchase" and (session.held_until or 0.0) > now:
                continue
            limit = self._idle_seconds if session.pending is None else parked_limit
            if session.last_used < now - limit and not session.lock.locked():
                await self._close_session(session)
                reaped += 1
        return reaped
