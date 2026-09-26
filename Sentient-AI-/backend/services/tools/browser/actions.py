"""browser.read: the agent reads pages in Crawler's own browser.

One toolkit per process, one browser session per user (session.py).
Every action here is READ tier: it may navigate and look, never type or
submit. ``click`` is the one grey area, and it has no approval card, so
nobody sees the page before it happens: it asks the guard at execution
time whether the target is consequential (a submit control, a form with
a password or payment field, a name like "sign up"), then judges the
control the click lands on (``markers.read_click_allowed``): only a
plain GET link that is not an order step, or a control outside any form
with no purchase words on a page that shows no order total, payment
method on file or wallet, is clicked. Everything else is refused with
``markers.READ_CLICK_MESSAGE`` and left to browser.act, whose card shows
the owner the page; the model never decides that. The egress guard, for
its part, never lets a read open an order step's address or send a
page's own request to an order address, and while the click and its
settle time run (``EgressState.read_click``, until the network is quiet,
at most 2 s) it lets no page script send anything but a GET, no request
go to an order address other than an order history and no frame open
one: a click that tries is answered with ``markers.READ_CLICK_MESSAGE``
too.

Every navigating or observing action returns the fresh page outline
inline (spec §5): the runtime keeps only the newest one in context and
replaces older ones with the ``summary`` line written here, so the model
never spends a turn "looking". Failures are results, never exceptions:
``{"ok": False, "error": ...}``, with ``stale_ref`` when a ref no longer
resolves and ``needs_human`` when the page is a challenge the person has
to clear (spec §8). Every result carries ``mode`` so the channel knows
whether URLs in the reply must lose their query strings.

Per task (``task_id``, carried across approval and handoff resumes) the
session's ``TaskState`` counts actions and holds notes; this toolkit
enforces the action and spend caps and the loop detector (spec §10). The
runtime adds each turn's estimated spend to ``TaskState.spend_usd`` and
turns a ``cap`` result into a "Continue?" message.

The observation, screenshot and handoff helpers live in ``_shared.py``
(browser.act and browser.checkout end their actions the same way); this
module keeps them under their old names. With a ``page_memory`` every
observation is also recorded as the page the user's next write may be
bound to.
"""

from __future__ import annotations

import asyncio
import base64
import inspect
import io
import re
import time
from typing import Any, Awaitable, Callable, Optional, Protocol

import structlog

from services.tools.browser import _shared
from services.tools.browser import snapshot as snap
from services.tools.browser._shared import BROWSER_MAX_ACTIONS as BROWSER_MAX_ACTIONS
from services.tools.browser._shared import BROWSER_MAX_USD as BROWSER_MAX_USD
from services.tools.browser._shared import ELEMENT_NAME_JS as _CLICK_NAME_JS
from services.tools.browser._shared import (
    JPEG_QUALITY,
    NAVIGATION_TIMEOUT_MS,
    REF_TIMEOUT_MS,
    HandoffDetector,
    PlaywrightError,
    PlaywrightTimeoutError,
)
from services.tools.browser._shared import call_key as _call_key
from services.tools.browser._shared import error_result as _error
from services.tools.browser._shared import log_failure as _log_failure
from services.tools.browser._shared import stale_result as _stale
from services.tools.browser._shared import valid_ref as _valid_ref
from services.tools.browser.checkout import markers
from services.tools.browser.guard import READ_CLICK_REASONS, StaleRef, wait_for_quiet
from services.tools.browser.pagememory import PageMemory
from services.tools.browser.session import BrowserSession, BrowserSessionManager, Mode

logger = structlog.get_logger(__name__)

# The ``action`` enum of the single flat browser.read schema (tool_registry).
ACTIONS: tuple[str, ...] = (
    "open",
    "snapshot",
    "find",
    "text",
    "scroll",
    "back",
    "tabs",
    "switch",
    "wait",
    "screenshot",
    "note",
    "handoff",
    "click",
)
SCROLL_DIRECTIONS: tuple[str, ...] = ("up", "down", "top", "bottom")

LOOP_REPEATS = 3
NOTES_CHAR_BUDGET = 2000
TEXT_CHAR_LIMIT = 8000
MAX_WAIT_MS = 10_000
MODEL_IMAGE_EDGE_PX = 768
_SCROLL_DELTA = {"up": -640, "down": 640, "top": -1_000_000, "bottom": 1_000_000}
_SUMMARY_LABEL_CHARS = 40
# Bookkeeping actions that do not touch the page: not counted as actions.
_UNCOUNTED = frozenset({"note", "handoff"})
# Why a read-tier click was left to browser.act by the purchase rules.
_ORDER_REASON = "may place an order (a payment method, a total or a price is on the page)"
# Why a read-tier click was left to browser.act otherwise: it is neither a
# plain link nor a control outside a form on a page with nothing to pay.
_ACT_REASON = "only browser.act, with the owner's approval, clicks that"


class Guard(Protocol):
    """What the toolkit needs from services/tools/browser/guard.py; the
    module satisfies it, tests pass a fake. ``consequential`` may raise
    ``guard.StaleRef``; ``BLOCKED_NAVIGATION_MARKER``, ``egress_state`` and
    ``settle_blocked_navigation`` are the blocked-navigation seam."""

    BLOCKED_NAVIGATION_MARKER: str

    def check_url(self, url: str) -> Optional[str]: ...
    async def install_egress_guard(self, context: Any, *, account_mode: bool) -> None: ...
    async def consequential(self, page: Any, ref: str) -> Optional[str]: ...
    async def settle_blocked_navigation(self, page: Any, *, timeout_ms: int = 1500) -> None: ...
    def egress_state(self, context: Any) -> Any: ...


def mode_for(user_id: str) -> Mode:
    """Which mode a task runs in. Phase 1 has no credential store, so every
    task runs as ACCOUNT: the persistent Crawler profile may hold a login
    the owner made by hand, and the private-data rules must apply. Phase 2
    derives this per origin from site_credentials."""
    return "account"


class BrowserReadToolkit:
    def __init__(
        self,
        sessions: BrowserSessionManager,
        *,
        guard: Guard,
        handoff: HandoffDetector,
        clock: Callable[[], float] = time.monotonic,
        page_memory: Optional[PageMemory] = None,
    ) -> None:
        self._sessions = sessions
        self._guard = guard
        self._handoff = handoff
        self._clock = clock
        # Shared with the write tiers: every observation here is the page
        # their next approval card is bound to (spec §5).
        self._memory = page_memory
        # task_id -> keys of the last LOOP_REPEATS calls, newest last.
        self._recent: dict[str, list[str]] = {}
        # user_id -> the context the egress guard is installed on. The
        # object itself, compared by identity: an id() can be reused by a
        # relaunched context once the old one is freed, which would skip
        # the guard on it. Holds at most one (possibly closed) context per
        # user until the next relaunch replaces it.
        self._guarded: dict[str, Any] = {}
        self._handlers: dict[str, Callable[..., Awaitable[dict[str, Any]]]] = {
            "open": self.open,
            "snapshot": self.snapshot,
            "click": self.click,
            "find": self.find,
            "text": self.text,
            "scroll": self.scroll,
            "back": self.back,
            "tabs": self.tabs,
            "switch": self.switch,
            "wait": self.wait,
            "screenshot": self.screenshot,
            "note": self.note,
            "handoff": self.handoff,
        }

    async def execute(
        self, action: str, params: dict[str, Any], *, user_id: str, task_id: str
    ) -> dict[str, Any]:
        """Run one browser.read action for *user_id*'s task. Unknown actions
        and bad arguments fail closed before a browser is even started."""
        handler = self._handlers.get(action) if isinstance(action, str) else None
        if handler is None:
            return _error(f"Unknown browser action '{action}'. Actions: {', '.join(ACTIONS)}.")
        # The flat schema carries every field; Gemini sends null for the
        # ones an action does not use, and null means "not given".
        if params is None:
            params = {}
        if not isinstance(params, dict):
            return _error(f"Invalid arguments for browser.read {action}: expected an object.")
        params = {k: v for k, v in params.items() if v is not None}
        try:
            inspect.signature(handler).bind(None, **params)
        except TypeError as exc:
            return _error(f"Invalid arguments for browser.read {action}: {exc}")
        refusal = self._loop_refusal(task_id, action, params)
        if refusal is not None:
            return refusal
        try:
            session = await self._sessions.get(user_id, mode=mode_for(user_id), task_id=task_id)
        except Exception as exc:  # launch errors quote paths; keep them in the log
            _log_failure("browser_session_failed", exc, action=action)
            return _error(
                "Could not start the browser. The owner can check Settings → "
                "Permissions → Control a browser."
            )
        async with session.lock:
            cap = self._cap_refusal(session.task)
            if cap is not None:
                return cap
            try:
                await self._ensure_guard(session)
            except Exception as exc:  # fail closed: never act on an unguarded context
                _log_failure("browser_guard_failed", exc, action=action)
                return _error(
                    "The browser's network guard could not be set up, so nothing was "
                    "opened. Try again; if it keeps failing, the owner can restart Crawler."
                )
            if action not in _UNCOUNTED:
                session.task.actions += 1
            try:
                await self._take_back(session)
                return await handler(session, **params)
            except Exception as exc:  # last resort: never raise into the agent loop
                _log_failure("browser_action_failed", exc, action=action)
                return _error(f"browser.read {action} failed.")

    # -- gates ---------------------------------------------------------------

    def _loop_refusal(
        self, task_id: str, action: str, params: dict[str, Any]
    ) -> Optional[dict[str, Any]]:
        """The same action with the same arguments LOOP_REPEATS times in a
        row is a loop: refuse the last one. History is per task and bounded."""
        if len(self._recent) > 64:
            for stale in [t for t in self._recent if t != task_id][:32]:
                del self._recent[stale]
        key = _call_key(action, params)
        recent = self._recent.setdefault(task_id, [])
        streak = LOOP_REPEATS - 1
        if len(recent) >= streak and all(k == key for k in recent[-streak:]):
            recent.clear()
            return _error(
                f"Loop detected: browser.read {action} was called {LOOP_REPEATS} times in a "
                "row with the same arguments. Change approach, or answer with what you have."
            )
        recent.append(key)
        del recent[:-LOOP_REPEATS]
        return None

    @staticmethod
    def _cap_refusal(task: Any) -> Optional[dict[str, Any]]:
        return _shared.cap_refusal(task)

    async def _ensure_guard(self, session: BrowserSession) -> None:
        """Install the egress route guard on a context the first time this
        toolkit sees it (the manager may relaunch the browser between calls)."""
        context = session.context
        if self._guarded.get(session.user_id) is context:
            return
        await self._guard.install_egress_guard(context, account_mode=session.mode == "account")
        self._guarded[session.user_id] = context

    # -- observation ---------------------------------------------------------

    async def _observe(
        self,
        session: BrowserSession,
        action: str,
        args: dict[str, Any],
        *,
        query: Optional[str] = None,
        full: bool = False,
        extra: Optional[dict[str, Any]] = None,
    ) -> dict[str, Any]:
        """The fresh page as the model sees it, or ``needs_human`` when the
        page is a challenge (checked first, so a CAPTCHA wall is never
        described as if it were content). Remembered in the page memory
        when this toolkit has one."""
        return await _shared.observe(
            session,
            self._handoff,
            action,
            args,
            query=query,
            full=full,
            extra=extra,
            memory=self._memory,
            guard=self._guard,
        )

    @staticmethod
    def _record(session: BrowserSession, line: str) -> str:
        """The one-liner the runtime keeps in place of this step's result,
        for actions that return no outline (find, text, tabs, refusals)."""
        summary = f"[step {session.task.actions}] {line}"
        session.task.summaries.append(summary)
        return summary

    @staticmethod
    def _where(session: BrowserSession, page: Any) -> str:
        return _shared.where(session, page)

    async def _page_or_challenge(
        self, session: BrowserSession
    ) -> tuple[Any, Optional[dict[str, Any]]]:
        page = await session.page()
        challenge = await self._handoff.detect_challenge(page)
        if challenge is None:
            return page, None
        return page, await self._needs_human(session, page, challenge.kind, challenge.detail)

    async def _needs_human(
        self, session: BrowserSession, page: Any, kind: str, detail: str
    ) -> dict[str, Any]:
        """End the turn: the person clears the challenge (or does what the
        model asked for) and resumes. The masked picture goes to them, and
        until the agent's next action on this session the person is
        driving Crawler's window, so their own submit (the sign-in form)
        passes the guard's read-tier block (``_shared.hand_over``, shut
        again by ``_take_back``)."""
        return await _shared.needs_human(session, page, kind, detail, guard=self._guard)

    async def _take_back(self, session: BrowserSession) -> None:
        """The agent is acting again, so the person is no longer driving
        (``_shared.take_back``: shut the window, let their last click land)."""
        await _shared.take_back(self._guard, session)

    async def _jpeg(self, page: Any, ref: Optional[str]) -> str:
        """Masked JPEG data URL of the page or of one element (``_shared.jpeg``)."""
        return await _shared.jpeg(page, ref)

    @staticmethod
    async def _settle(page: Any) -> None:
        """Give a click that navigates a moment to land (``_shared.settle``)."""
        await _shared.settle(page)

    def _blocked_count(self, session: BrowserSession) -> int:
        state = self._guard.egress_state(session.context)
        return 0 if state is None else len(state.blocked)

    def _blocked_reason(self, session: BrowserSession, *, since: int = 0) -> Optional[str]:
        """What the egress guard refused last, as ``"<url>: <reason>"``, if
        it refused anything after the first *since* entries (so an old
        block is never blamed for a later failure)."""
        state = self._guard.egress_state(session.context)
        if state is None or len(state.blocked) <= since:
            return None
        last = state.blocked[-1]
        return f"{last['url']}: {last['reason']}"

    def _click_sent(self, session: BrowserSession, *, since: int) -> Optional[str]:
        """Why the guard stopped a read-tier click sending something (a
        page script's request, a form, an order address), or None."""
        state = self._guard.egress_state(session.context)
        if state is None:
            return None
        for entry in state.blocked[since:]:
            if entry.get("reason") in READ_CLICK_REASONS:
                return str(entry["reason"])
        return None

    @staticmethod
    def _label(session: BrowserSession, value: str) -> str:
        """Model- or page-supplied text as it may appear in a summary: one
        line, typed secrets redacted, short (summaries stay in context)."""
        value = BrowserReadToolkit._redact(session, " ".join(value.split()))
        if len(value) > _SUMMARY_LABEL_CHARS:
            value = value[: _SUMMARY_LABEL_CHARS - 1] + "…"
        return value

    @staticmethod
    def _redact(session: BrowserSession, content: str) -> str:
        """Page text with every typed secret replaced the way the outline
        does it (``snap.redact``): a card number in any grouping a page
        prints it in, a short code as a whole digit run, and the escaped
        and percent-encoded forms; a plain replace of the value as typed
        would let "4242 4242 4242 4242" through."""
        return snap.redact(content, session.typed_secrets, "•••")

    async def _title(self, session: BrowserSession, page: Any) -> str:
        """The page title, redacted like the outline's (it is page-controlled)."""
        return self._redact(session, await page.title())[:200]

    # -- navigating and observing actions ------------------------------------

    async def open(self, session: BrowserSession, url: str) -> dict[str, Any]:
        if not isinstance(url, str) or not url.strip():
            return _error("open needs a 'url'.")
        # check_url resolves the host (blocking getaddrinfo): off the loop,
        # as the route guard does it.
        reason = await asyncio.to_thread(self._guard.check_url, url)
        if reason is not None:
            return _error(f"Refusing to open that URL: {reason}")
        page = await session.page()
        try:
            await page.goto(url, wait_until="domcontentloaded", timeout=NAVIGATION_TIMEOUT_MS)
        except PlaywrightTimeoutError:
            return _error(f"The page did not load within {NAVIGATION_TIMEOUT_MS // 1000} s.")
        except PlaywrightError as exc:
            if self._guard.BLOCKED_NAVIGATION_MARKER in str(exc):
                # The route guard aborted a hop (a redirect to a private host,
                # for instance). Let Chromium commit its error page so the
                # next navigation is not "interrupted", and say which URL.
                await self._guard.settle_blocked_navigation(page)
                blocked = self._blocked_reason(session) or "blocked by the network policy"
                return _error(f"Refusing to open {blocked}")
            _log_failure("browser_open_failed", exc)
            return _error("Could not open the page: the navigation failed.")
        return await self._observe(session, "open", {"url": url})

    async def snapshot(
        self, session: BrowserSession, query: Optional[str] = None, full: bool = False
    ) -> dict[str, Any]:
        if query is not None and not isinstance(query, str):
            return _error("query must be text.")
        return await self._observe(
            session,
            "snapshot",
            {"query": query, "full": bool(full)},
            query=query or None,
            full=bool(full),
        )

    async def click(self, session: BrowserSession, ref: str) -> dict[str, Any]:
        """Read-tier click: only on targets the guard finds non-consequential,
        never on a challenge page."""
        if not _valid_ref(ref):
            return _error("click needs a ref from the outline, e.g. e7.")
        page, refusal = await self._page_or_challenge(session)
        if refusal is not None:
            return refusal
        try:
            reason = await self._guard.consequential(page, ref)
            if reason is None:
                reason = await self._order_reason(page, ref)
        except (StaleRef, PlaywrightError) as exc:  # the ref could not be resolved at all
            _log_failure("browser_click_gate_failed", exc, ref=ref)
            return _stale()
        if reason is not None:
            self._record(session, f"click {ref} refused: {reason}")
            return _error(markers.READ_CLICK_MESSAGE, consequential=reason)
        locator = page.locator(f"aria-ref={ref}")
        blocked_before = self._blocked_count(session)
        # A click with no card sends nothing: the guard stops any page
        # script's request but a GET, and any order address, until the
        # click has settled and the network is quiet (at most 2 s).
        state = self._guard.egress_state(session.context)
        if state is not None:
            state.read_click = True
        try:
            try:
                # The pre-click accessible name, so the summary reads
                # 'click "Grades"' and not 'click e3' (contracts §3).
                name = await locator.evaluate(_CLICK_NAME_JS, timeout=REF_TIMEOUT_MS)
                await locator.click(timeout=REF_TIMEOUT_MS)
            except PlaywrightTimeoutError:
                return _stale()
            except PlaywrightError as exc:
                _log_failure("browser_click_failed", exc, ref=ref)
                return _error(
                    "The click failed (the element may be covered or gone); re-snapshot and try again."
                )
            clicked = time.monotonic()
            await self._guard.settle_blocked_navigation(page, timeout_ms=300)
            await self._settle(page)
            await wait_for_quiet(state, since=clicked)
        finally:
            if state is not None:
                state.read_click = False
        sent = self._click_sent(session, since=blocked_before)
        if sent is not None:
            self._record(session, f"click {ref} refused: {sent}")
            return _error(markers.READ_CLICK_MESSAGE, consequential=sent)
        blocked = self._blocked_reason(session, since=blocked_before)
        if blocked is not None and page.url.startswith("chrome-error://"):
            return _error(f"That click was refused by the network policy: {blocked}")
        return await self._observe(
            session, "click", {"ref": ref, "name": self._label(session, str(name or ""))}
        )

    @staticmethod
    async def _order_reason(page: Any, ref: str) -> Optional[str]:
        """The live page's answer for a click that has no approval card at
        all: the control the click lands on, its words, its form, its link
        and every frame's facts. A click the purchase rules flag
        (``markers.read_click_pays``) may place an order; any other click
        but a plain link or a control outside a form on a page with nothing
        to pay (``markers.read_click_allowed``) is left to browser.act,
        whose card shows the owner the page first."""
        target = await page.locator(f"aria-ref={ref}").evaluate(
            markers.PURCHASE_TARGET_JS, timeout=REF_TIMEOUT_MS
        )
        target = markers.join_page(target, await _shared.page_facts(page))
        if markers.read_click_pays(target):
            return _ORDER_REASON
        return None if markers.read_click_allowed(target) else _ACT_REASON

    async def find(self, session: BrowserSession, text: str) -> dict[str, Any]:
        """Lines mentioning *text*, each with its row/listitem/article so the
        assignment name comes back next to its "Missing". Goes through
        snapshot.find so the same pruning and redaction apply."""
        if not isinstance(text, str) or not text.strip():
            return _error("find needs the 'text' to look for.")
        page, refusal = await self._page_or_challenge(session)
        if refusal is not None:
            return refusal
        lines = await snap.find(
            page, text, account_mode=session.mode == "account", secrets=session.typed_secrets
        )
        matches: list[str] = []
        used, truncated = 0, False
        for line in lines:
            if used + len(line) > TEXT_CHAR_LIMIT:
                truncated = True
                break
            matches.append(line)
            used += len(line)
        where = self._where(session, page)
        summary = self._record(
            session,
            f'find "{self._label(session, text)}" → {snap.host_path(where)} · '
            f"{len(matches)} matches",
        )
        return {
            "ok": True,
            "url": where,
            "title": await self._title(session, page),
            "matches": matches,
            "count": len(matches),
            "truncated": truncated,
            "summary": summary,
            "notes": list(session.task.notes),
            "mode": session.mode,
        }

    async def text(self, session: BrowserSession, ref: Optional[str] = None) -> dict[str, Any]:
        """Visible text of the page or of one element (innerText: nothing
        display:none or visibility:hidden gets a side door in)."""
        if ref is not None and not _valid_ref(ref):
            return _error("text takes a ref from the outline, e.g. e7, or nothing for the page.")
        page, refusal = await self._page_or_challenge(session)
        if refusal is not None:
            return refusal
        target = page.locator(f"aria-ref={ref}") if ref else page.locator("body")
        try:
            content = await target.inner_text(timeout=REF_TIMEOUT_MS)
        except PlaywrightTimeoutError:
            return _stale()
        except PlaywrightError as exc:
            if not ref:
                raise
            # e.g. "Invalid frame in aria-ref selector": not on this page.
            _log_failure("browser_text_ref_failed", exc, ref=ref)
            return _stale()
        content = self._redact(session, re.sub(r"\n{3,}", "\n\n", content.strip()))
        truncated = len(content) > TEXT_CHAR_LIMIT
        content = content[:TEXT_CHAR_LIMIT]
        where = self._where(session, page)
        summary = self._record(
            session, f"text {ref or 'page'} → {snap.host_path(where)} · {len(content)} chars"
        )
        return {
            "ok": True,
            "url": where,
            "title": await self._title(session, page),
            "text": content,
            "chars": len(content),
            "truncated": truncated,
            "summary": summary,
            "notes": list(session.task.notes),
            "mode": session.mode,
        }

    async def scroll(self, session: BrowserSession, direction: str) -> dict[str, Any]:
        if direction not in SCROLL_DIRECTIONS:
            return _error(f"direction must be one of {', '.join(SCROLL_DIRECTIONS)}.")
        page = await session.page()
        await page.mouse.wheel(0, _SCROLL_DELTA[direction])
        await page.wait_for_timeout(150)  # lazy content renders before the outline
        return await self._observe(session, "scroll", {"direction": direction})

    async def back(self, session: BrowserSession) -> dict[str, Any]:
        page = await session.page()
        before = page.url
        try:
            await page.go_back(wait_until="domcontentloaded", timeout=NAVIGATION_TIMEOUT_MS)
        except PlaywrightTimeoutError:
            return _error(f"Going back did not finish within {NAVIGATION_TIMEOUT_MS // 1000} s.")
        if page.url == "about:blank":
            # The tab's first history entry is blank: nothing earlier to read.
            if before != "about:blank":
                await page.go_forward(wait_until="domcontentloaded", timeout=NAVIGATION_TIMEOUT_MS)
            return _error("There is no earlier page to go back to.")
        return await self._observe(session, "back", {})

    async def tabs(self, session: BrowserSession) -> dict[str, Any]:
        account = session.mode == "account"
        listed = [
            {
                **tab,
                "url": self._redact(session, snap.strip_url(tab["url"], account)),
                "title": self._redact(session, str(tab.get("title") or ""))[:200],
            }
            for tab in await session.tabs()
        ]
        summary = self._record(session, f"tabs · {len(listed)} open")
        return {
            "ok": True,
            "tabs": listed,
            "summary": summary,
            "notes": list(session.task.notes),
            "mode": session.mode,
        }

    async def switch(self, session: BrowserSession, index: int) -> dict[str, Any]:
        if isinstance(index, bool) or not isinstance(index, int) or index < 0:
            return _error("switch needs a tab 'index' from tabs (0 = first).")
        try:
            await session.switch(index)
        except (IndexError, ValueError):
            return _error(f"No tab {index}; {len(await session.tabs())} tab(s) open.")
        return await self._observe(session, "switch", {"index": index})

    async def wait(
        self, session: BrowserSession, text: Optional[str] = None, ms: Optional[int] = None
    ) -> dict[str, Any]:
        if ms is not None and (
            isinstance(ms, bool) or not isinstance(ms, int) or not 0 < ms <= MAX_WAIT_MS
        ):
            return _error(f"ms must be between 1 and {MAX_WAIT_MS}.")
        if text is None and ms is None:
            return _error("wait needs 'text' to wait for, or 'ms' to pause.")
        page = await session.page()
        if text is not None:
            if not isinstance(text, str) or not text.strip():
                return _error("text must be non-empty.")
            timeout = ms or MAX_WAIT_MS
            try:
                await page.get_by_text(text).first.wait_for(state="visible", timeout=timeout)
            except PlaywrightTimeoutError:
                return _error(f"'{text}' did not appear within {timeout} ms.")
        else:
            await page.wait_for_timeout(ms)
        return await self._observe(session, "wait", {"text": text, "ms": ms})

    @staticmethod
    def _shrink(data_url: str, edge: int) -> str:
        """A copy small enough for the model (≤ *edge* px on the long side).
        Runs in a worker thread: Pillow decode/resize/encode is CPU work."""
        from PIL import Image

        raw = base64.b64decode(data_url.split(",", 1)[1])
        image = Image.open(io.BytesIO(raw))
        image.thumbnail((edge, edge))
        buf = io.BytesIO()
        image.convert("RGB").save(buf, format="JPEG", quality=JPEG_QUALITY, optimize=True)
        return "data:image/jpeg;base64," + base64.b64encode(buf.getvalue()).decode("ascii")

    async def screenshot(
        self, session: BrowserSession, ref: Optional[str] = None, for_model: bool = False
    ) -> dict[str, Any]:
        """A masked picture for the person (``user_image``, delivered by the
        channel, never shown to the model); ``for_model`` adds a ≤768 px
        ``image`` the model may look at. Secret fields are blacked out."""
        if ref is not None and not _valid_ref(ref):
            return _error(
                "screenshot takes a ref from the outline, e.g. e7, or nothing for the page."
            )
        # Only a real boolean true sends pixels to the model: a stray "false"
        # string must not (bool("false") is True).
        for_model = for_model is True
        page = await session.page()
        try:
            user_image = await self._jpeg(page, ref)
        except PlaywrightTimeoutError:
            return _stale() if ref else _error("The screenshot timed out.")
        except PlaywrightError as exc:
            _log_failure("browser_screenshot_failed", exc, ref=ref)
            # A ref into a frame that is not there fails before any wait.
            return _stale() if ref else _error("The screenshot failed.")
        extra: dict[str, Any] = {"user_image": user_image}
        if for_model:
            extra["image"] = await asyncio.to_thread(self._shrink, user_image, MODEL_IMAGE_EDGE_PX)
        return await self._observe(
            session, "screenshot", {"ref": ref, "for_model": for_model}, extra=extra
        )

    async def handoff(self, session: BrowserSession, reason: str) -> dict[str, Any]:
        """The model asks the person to take over (sign in, solve a puzzle).
        Same shape as a detected challenge, so the runtime ends the turn
        the same way."""
        if not isinstance(reason, str) or not reason.strip():
            return _error("handoff needs a 'reason' the person will read.")
        page = await session.page()
        return await self._needs_human(session, page, "requested", " ".join(reason.split())[:300])

    # -- bookkeeping actions -------------------------------------------------

    async def note(self, session: BrowserSession, text: str) -> dict[str, Any]:
        """Keep one fact for later steps (the runtime shows notes in the
        task-facts block). Bounded so notes cannot become a second context."""
        if not isinstance(text, str) or not text.strip():
            return _error("note needs 'text'.")
        text = " ".join(text.split())
        used = sum(len(n) for n in session.task.notes)
        if used + len(text) > NOTES_CHAR_BUDGET:
            return _error(
                f"Notes are full ({used} of {NOTES_CHAR_BUDGET} characters). Keep this one "
                "shorter, or answer with what you have.",
                notes=list(session.task.notes),
            )
        session.task.notes.append(text)
        return {
            "ok": True,
            "notes": list(session.task.notes),
            "summary": f"note · {len(session.task.notes)} kept",
            "mode": session.mode,
        }
