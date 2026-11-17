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
the owner the page; the model never decides that. The refusal carries
the ref (browser.act is called with the same one) and the rule that
refused it in fixed words (``_click_rule``). The egress guard, for
its part, never lets a read open an order step's address or send a
page's own request to an order address, and while the click and its
settle time run (``EgressState.read_click``, until the network is quiet,
at most 2 s) it lets no page script send anything but a GET, no request
go to an order address other than an order history and no frame open
one: a click that tries is answered with ``markers.READ_CLICK_MESSAGE``
too, with one exception. When the click did open a page (the address
changed, or a new tab opened) and all the guard stopped was a page
script's own request (click statistics, what the new page sends as it
loads), the page is described as it is, with ``stopped_request`` added:
nothing was sent either way, and reported as refused the click left the
model, and the page memory, on the page before it. A click whose own
navigation was stopped (by this rule or by the network policy), or
failed (nothing answers there), leaves the tab on Chrome's error page:
the click answers with what happened, the tab is taken back to the page
the click was made on, and the answer carries that page's fresh outline
in place of the ref, which the reload made stale (``_put_back``).

Every navigating or observing action returns the fresh page outline
inline (spec §5): the runtime keeps only the newest one in context and
replaces older ones with the ``summary`` line written here, so the model
never spends a turn "looking". The outline is the part of the page on
screen, taken once the page has stopped loading: ``open`` and ``back``
wait, once the document is in, until the network has been quiet
(``guard.wait_for_quiet``, at most LOAD_QUIET_CAP_S), so what a page
fetches after its document (a film's showtimes) is in the outline too;
every observation says how many lines lie below (``below`` and a hint,
``_shared.observe``); and a click that opens a new tab describes that
tab (``new_tab``, ``BrowserSession.adopt_new_tab``), waiting for one
whose first page is slow to answer. The document's HTTP status comes with
open, click and back: an error page says what it is (``error_page``),
and one a site turned the browser away with (401, 403, 429, 451 or 503,
and no sign-in offered on it) is marked ``blocked``, so a block page is
not read as content or taken for a permission of Crawler's that is off.
Failures are results, never exceptions:
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

``read_results`` is not a browser.read action: it is web.search's
fallback when the search endpoint asks for a bot check (the executor
offers it only while "Control a browser" is on). It loads one results
page in a tab of its own, under the same guard and caps, and returns the
rows a script reads off it.
"""

from __future__ import annotations

import asyncio
import base64
import inspect
import io
import re
import time
from typing import Any, Awaitable, Callable, Optional, Protocol
from urllib.parse import urlsplit

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
from services.tools.browser.guard import (
    READ_CLICK_REASONS,
    READ_CLICK_REQUEST,
    EgressHooks,
    StaleRef,
    wait_for_quiet,
)
from services.tools.browser.pagememory import PageMemory, page_address
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
# Why a read-tier click is left to browser.act, in the words of a rule
# that refuses it (``_click_rule``). Fixed text: the model reads it and
# the log keeps it, and neither ever holds the page's own words. What the
# purchase rules refuse (``markers.read_click_pays``) leads with
# _MAY_ORDER; a control in a form, which is merely not a read's to click,
# does not.
_MAY_ORDER = "may place an order"
_RULE_UNKNOWN = "could not tell what this click lands on"
_RULE_ADDRESS = "it leads to an order address"
_RULE_CARD = "its form holds a card number"
_RULE_WORDS = "its words read as a purchase"
_RULE_PAGE = "the page shows a payment method or an order total"
_RULE_CONTROL = "it is a button or a form control"
# The judged facts a refusal's log line keeps: booleans, never the
# control's words, its link or its form's address.
_LOGGED_FACTS = (
    "link", "plain_link", "buttonish", "in_form", "sends", "card_in_form", *markers.PAGE_FACT_KEYS
)
# What a click's result adds when the click opened a page (or a tab) and
# the guard stopped a request a page script tried to send meanwhile. The
# guard stops every such request while browser.read clicks; this only
# says so, instead of calling a click that did navigate refused. Nearly
# every shop sends click statistics, so the note says first that nothing
# needs doing, and only then what to do when the request mattered.
# The address of the link a click lands on ("" for a button).
_CLICK_HREF_JS = "el => { const a = el.closest('a[href]'); return a ? a.href : ''; }"
# What a click's answer adds when the page a link opened shows nothing at
# all: some ticket and shop sites give an automated browser an empty page.
EMPTY_PAGE_NOTE = (
    "This page came up empty in Crawler's browser. Some sites do this to automated browsers; "
    "it is not a Crawler permission and looking again will not fill it. Do not retry. Tell "
    "the person what you found so far and give them the exact link to finish on their own "
    "device: opened_link when a click result has one, else this page's address."
)


def _note_empty(result: dict[str, Any]) -> dict[str, Any]:
    """*result* with EMPTY_PAGE_NOTE when it describes a web page that
    shows nothing at all (no line of outline), and no other note already
    says why (an error page, a block)."""
    if (
        result.get("ok")
        and result.get("outline") == []
        and str(result.get("url") or "").startswith(("https://", "http://"))
        and "error_page" not in result
    ):
        result["empty_page"] = EMPTY_PAGE_NOTE
    return result
STOPPED_REQUEST_NOTE = (
    "The click was made and this is the page it opened. While it ran, a request the page's "
    "own script tried to send was stopped, because reading sends nothing. That is usually page "
    "statistics and needs nothing done. Only if what the click was for did not happen (it was "
    "meant to add or save something, or the page lacks its content), make it again with "
    "browser.act."
)
# What a click's answer adds when the navigation it started was stopped,
# or failed, and the tab had to go back to the page the click was made on
# (``_put_back``): the outline in the answer is that page loaded again, so
# the ref that was clicked no longer names anything.
RELOADED_NOTE = (
    "The click left the tab on an error page, so the tab went back to the page the click was "
    "made on. That page was loaded again and its refs are new: use the outline in this "
    "result. To make the same click with browser.act, find the same control in this outline "
    "and use its new ref."
)
# The same, when one step back was not that page (the stopped navigation
# had replaced it in the tab's history).
EARLIER_PAGE_NOTE = (
    "The tab is on an earlier page now, not the one the click was made on. "
    "This outline is that earlier page's."
)
# A page script tried to send to an order address while a read click ran
# (the guard stopped the request). With no page opened the click is left to
# browser.act for this reason; next to a page that did open, the answer
# says what was stopped instead of calling it statistics.
ORDER_REQUEST_REASON = "the page tried to send to an order address"
STOPPED_ORDER_NOTE = (
    "The click was made and this is the page it opened. While it ran, the page tried to send "
    "a form or reach an order address and was stopped, because reading sends nothing: nothing "
    "was added, ordered or paid. If the click was meant to add or order something, make it "
    "again with browser.act."
)
# How long open follows zero-second refreshes (redirect hops) before it
# describes the page as it is.
REDIRECT_WAIT_MS = 10_000
# How long open and back wait, once the document is in, for the network to
# go quiet (``guard.wait_for_quiet``) before they describe the page: what a
# page fetches after its document (showtimes, prices, search results) is
# then in the outline. A page that never goes quiet is described as it is.
LOAD_QUIET_CAP_S = 3.0
# How long a click waits for a new tab whose first page had not answered
# when the click's own window closed (``_tab_on_its_way``).
NEW_TAB_WAIT_MS = 8_000
# How long read_results waits for a results page to show its rows.
RESULTS_READY_MS = 8_000
# True once the page is not one that moves on at once.
_MOVING_ON_JS = r"""() => ![...document.querySelectorAll('meta[http-equiv="refresh" i]')]
  .some(m => /^\s*0+(\.0*)?\s*([;,]|$)/.test(m.getAttribute('content') || ''))"""
# The HTTP status of the page's current document, as the browser got it.
_STATUS_JS = (
    "() => { const n = performance.getEntriesByType('navigation')[0]; return n ? n.responseStatus || 0 : 0; }"
)
# What an open that landed on an error page adds to its result: a
# missing page, or any other refusal or failure the site answered with.
_NOT_FOUND_NOTE = (
    "The site answered HTTP {status}: there is no page at this address. Do not try other "
    "made-up addresses; open the site's home page and use its search or its links."
)
_ERROR_PAGE_NOTE = "The site answered HTTP {status}: the outline shows its error page, not the page asked for."
# The statuses a site turns a browser away with (a CDN's bot block answers
# 403, a rate limit 429), and what the result says then. Shown as an
# ordinary page, a block page was read as content, or passed on to the
# owner as a permission of Crawler's that was off.
_BLOCKED_STATUSES = frozenset({401, 403, 429, 451, 503})
_BLOCKED_NOTE = (
    "The site refused Crawler's browser (HTTP {status}). This is the site's own block, not a "
    "Crawler permission, and the person can't clear it. Don't retry or hand off: get the same "
    "information from another site and tell the person this one blocked Crawler."
)
# True when the page offers a sign-in: a password field, or a link or a
# button that says "log in" or "sign in". Such a refusal is the site asking
# for the person's account, which a handoff clears, so it is not called a
# block. English words only: a refusal that offers its sign-in in another
# language is still called a block.
_SIGN_IN_JS = r"""() => !!document.querySelector('input[type=password]')
  || [...document.querySelectorAll(
      'a[href], button, [role=button], [role=link], input[type=submit]')]
    .some(el => /\b(?:log|sign)[\s-]?in\b/i.test(
      [el.innerText, el.value, el.getAttribute('aria-label')].join(' ')))"""


def _click_rule(target: object) -> str:
    """A rule that leaves this refused click to browser.act, in fixed words.
    *target* is what ``_order_reason`` judged: the facts
    ``markers.read_click_pays`` and ``markers.read_click_allowed`` decide
    on, read here in their order (an address before words, words before
    what the page shows), so the words name a rule that does refuse it."""
    if not isinstance(target, dict) or target.get("frame"):
        return _RULE_UNKNOWN
    if markers.ORDER_ACTION_RE.search(str(target.get("action") or "")) or (
        target.get("link") and markers.READ_LINK_RE.search(str(target.get("href") or ""))
    ):
        return _RULE_ADDRESS
    if target.get("card_in_form"):
        return _RULE_CARD
    name = str(target.get("name") or "")
    pays_by_name = markers.PURCHASE_RE.search(name) or markers.WALLET_RE.search(name)
    if pays_by_name or markers.priced_control(name):
        return _RULE_WORDS
    if target.get("order_total") or target.get("saved_payment") or target.get("wallet"):
        return _RULE_PAGE
    return _RULE_CONTROL


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
        egress_hooks: Optional[EgressHooks] = None,
    ) -> None:
        self._sessions = sessions
        self._guard = guard
        self._handoff = handoff
        self._clock = clock
        # Security wave (S4, S7): the owner's site rules and the link
        # lookup, bound to each context this toolkit guards (None: neither).
        self._egress_hooks = egress_hooks
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
        _shared.attach_egress_hooks(self._guard, session, self._egress_hooks)
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

    def _notes_count(self, session: BrowserSession) -> int:
        """How many security notes the guard's hooks have left on this
        context so far (none without a state: a test double)."""
        state = self._guard.egress_state(session.context)
        notes = getattr(state, "notes", None) if state is not None else None
        return len(notes) if isinstance(notes, list) else 0

    def _with_notes(self, session: BrowserSession, result: dict[str, Any], *, since: int) -> dict[str, Any]:
        """*result* with the texts of the notes the hooks added after the
        first *since* (security wave: a look-alike site, a lookup that could
        not run) as ``security_notes``; unchanged when there are none."""
        state = self._guard.egress_state(session.context)
        notes = getattr(state, "notes", None) if state is not None else None
        if not isinstance(notes, list):
            return result
        texts = [n["text"] for n in notes[since:] if isinstance(n, dict) and n.get("text")]
        if texts:
            result["security_notes"] = texts
        return result

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
        page script's request, a form, an order address), or None. A
        form or an order address is named before a page script's request
        (READ_CLICK_REQUEST): that one is the click's own doing, the
        other may be the page's statistics, and ``click`` tells them
        apart by it."""
        state = self._guard.egress_state(session.context)
        if state is None:
            return None
        sent: Optional[str] = None
        for entry in state.blocked[since:]:
            reason = entry.get("reason")
            if reason in READ_CLICK_REASONS and reason != READ_CLICK_REQUEST:
                return str(reason)
            if reason == READ_CLICK_REQUEST:
                # A script's request to an order address is no statistic:
                # it is named as what it was, so the answer can say so.
                if markers.ORDER_ACTION_RE.search(urlsplit(str(entry.get("url") or "")).path):
                    sent = ORDER_REQUEST_REASON
                elif sent is None:
                    sent = READ_CLICK_REQUEST
        return sent

    def _leave_page(self, session: BrowserSession) -> Any:
        """The context's egress state as open or back starts to leave the
        page, with the requests still counted in flight forgotten. They
        belong to the page being left, and one a page leaves unfinished
        never reports an end (measured: a slow fetch, a beacon the guard
        stopped): counted on, it would run this wait for quiet and every
        later one to its cap."""
        state = self._guard.egress_state(session.context)
        in_flight = getattr(state, "in_flight", None)
        if in_flight is not None:
            in_flight.clear()
        return state

    @staticmethod
    def _tabs(session: BrowserSession) -> list[Any]:
        """The tabs open in the session's browser (none for a session
        double that has no browser behind it)."""
        return list(getattr(session.context, "pages", ()))

    @staticmethod
    def _tab_on_its_way(state: Any, earlier: set[Any]) -> bool:
        """Whether the first page of a new tab is still on its way: a
        navigation that started after *earlier* (the requests in flight
        before the click) and has no frame yet. Playwright lists a tab a
        page opens only once its first page has answered, so the new tab
        of a slow site, or of a chain of redirects, is not among the tabs
        when the click's window closes."""
        for request in set(getattr(state, "in_flight", ())) - earlier:
            if not request.is_navigation_request():
                continue
            try:
                _ = request.frame
            except Exception:  # noqa: BLE001 - what a new tab's first navigation answers
                return True
        return False

    def _refused_click(self, session: BrowserSession, ref: str, reason: str) -> dict[str, Any]:
        """What a click browser.read leaves to browser.act answers: the
        fixed message, why, and the ref the same click is made with there.
        The reason stays in the summary line too."""
        self._record(session, f"click {ref} refused: {reason}")
        return _error(markers.READ_CLICK_MESSAGE, consequential=reason, ref=ref)

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
        blocked_before = self._blocked_count(session)
        notes_before = self._notes_count(session)
        state = self._leave_page(session)
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
        # The guard hands each redirect back as a page that moves on at once
        # (guard._client_redirect), so the goto ends on the first hop: wait
        # for the page the chain lands on, and when the guard stopped a
        # later hop, say so as it would have been said for the first.
        await self._past_redirects(page)
        stopped = self._blocked_reason(session, since=blocked_before)
        if stopped is not None and page.url.startswith("chrome-error://"):
            await self._guard.settle_blocked_navigation(page)
            return _error(f"Refusing to open {stopped}")
        # The document is in; what it fetches next (a film's showtimes, a
        # search's results) is not. Taken now, the outline had none of it.
        await wait_for_quiet(state, since=time.monotonic(), cap_s=LOAD_QUIET_CAP_S)
        result = await self._observe(session, "open", {"url": url})
        result = await self._with_status(session, page, result)
        return self._with_notes(session, _note_empty(result), since=notes_before)

    async def _with_status(
        self, session: BrowserSession, page: Any, result: dict[str, Any]
    ) -> dict[str, Any]:
        """*result* (an observation of *page*) with the HTTP status of the
        document it describes and, when the site answered with an error,
        what that means: no such page, the site turning the browser away
        (``blocked``), or its error page. Kept in the summary line too,
        which outlives the outline."""
        status = await self._http_status(page) if result.get("ok") else None
        if status is None:
            return result
        result["http_status"] = status
        if status < 400:
            return result
        if status in _BLOCKED_STATUSES and not await self._asks_for_sign_in(page):
            result["blocked"] = True
            note = _BLOCKED_NOTE
        elif status in (404, 410):
            # A shop's 404 page is a whole page with menus, and reads like
            # one: say plainly that the address is not a page of the site.
            note = _NOT_FOUND_NOTE
        else:
            note = _ERROR_PAGE_NOTE
        result["error_page"] = note.format(status=status)
        result["summary"] = f"{result['summary']} · HTTP {status}"
        if session.task.summaries:
            session.task.summaries[-1] = result["summary"]
        return result

    @staticmethod
    async def _asks_for_sign_in(page: Any) -> bool:
        """Whether the page offers a sign-in (``_SIGN_IN_JS``). A site that
        answers 401 or 403 with its sign-in form, or a link to it, is not
        blocking the browser: the person can clear that by signing in, so
        it is not called a block (which tells the model not to hand off)."""
        try:
            return bool(await _shared.frame_evaluate(page.main_frame, _SIGN_IN_JS))
        except Exception as exc:  # noqa: BLE001 - a page that cannot say is described as a block
            _log_failure("browser_sign_in_check_failed", exc)
            return False

    @staticmethod
    async def _past_redirects(page: Any) -> None:
        """Wait (at most REDIRECT_WAIT_MS) while the page is one that moves
        on at once (a zero-second refresh: the guard's redirect hops, and a
        site's own); a page that keeps doing so is described as it is."""
        try:
            await page.wait_for_function(_MOVING_ON_JS, timeout=REDIRECT_WAIT_MS)
        except Exception as exc:  # noqa: BLE001 - the page is described as it is
            _log_failure("browser_redirect_wait_failed", exc)

    @staticmethod
    async def _http_status(page: Any) -> Optional[int]:
        """The HTTP status of the document the page shows now (after the
        redirects the guard turned into client hops), or None when the
        page cannot say."""
        try:
            status = await _shared.frame_evaluate(page.main_frame, _STATUS_JS)
        except Exception as exc:  # noqa: BLE001 - the page is described without it
            _log_failure("browser_status_failed", exc)
            return None
        return status if isinstance(status, int) and status > 0 else None

    async def read_results(
        self, url: str, *, script: str, ready: str, user_id: str, task_id: str
    ) -> dict[str, Any]:
        """Load *url* in a tab of its own and return what *script* reads off
        it: web.search's fallback when the search endpoint asks for a bot
        check (services.tools.web), never a model action. Read tier and one
        page load: the URL is checked and the egress guard installed as for
        open, nothing is clicked or typed, the agent's own tab and outline
        stay as they were, and the tab is closed again. Waits at most
        RESULTS_READY_MS for *ready* (a selector the rows match) and counts
        as one action of the task, so the task's caps apply."""
        try:
            session = await self._sessions.get(user_id, mode=mode_for(user_id), task_id=task_id)
        except Exception as exc:  # launch errors quote paths; keep them in the log
            _log_failure("browser_session_failed", exc, action="results")
            return _error("Could not start the browser.")
        async with session.lock:
            cap = self._cap_refusal(session.task)
            if cap is not None:
                return cap
            try:
                await self._ensure_guard(session)
            except Exception as exc:  # fail closed: never load a page on an unguarded context
                _log_failure("browser_guard_failed", exc, action="results")
                return _error("The browser's network guard could not be set up, so nothing was opened.")
            reason = await asyncio.to_thread(self._guard.check_url, url)
            if reason is not None:
                return _error(f"Refusing to open that URL: {reason}")
            session.task.actions += 1
            await self._take_back(session)
            page = await session.context.new_page()
            try:
                await page.goto(url, wait_until="domcontentloaded", timeout=NAVIGATION_TIMEOUT_MS)
                await self._past_redirects(page)
                try:
                    await page.wait_for_selector(ready, timeout=RESULTS_READY_MS)
                except PlaywrightTimeoutError:
                    pass  # read what is there: a page without rows is an answer too
                read = await _shared.frame_evaluate(page.main_frame, script)
            except Exception as exc:  # noqa: BLE001 - a page that will not load is a result
                _log_failure("browser_results_failed", exc)
                return _error("The results page could not be read.")
            finally:
                try:
                    await page.close()
                except Exception as exc:  # noqa: BLE001 - logged, never raised into the caller
                    _log_failure("browser_results_close_failed", exc)
        if not isinstance(read, dict):
            return _error("The results page could not be read.")
        return {**read, "ok": True}

    async def snapshot(
        self, session: BrowserSession, query: Optional[str] = None, full: bool = False
    ) -> dict[str, Any]:
        if query is not None and not isinstance(query, str):
            return _error("query must be text.")
        result = await self._observe(
            session,
            "snapshot",
            {"query": query, "full": bool(full)},
            query=query or None,
            full=bool(full),
        )
        # With a query, no line only means nothing matched it.
        return result if query else _note_empty(result)

    async def click(self, session: BrowserSession, ref: str) -> dict[str, Any]:
        """Read-tier click: only on targets the guard finds non-consequential,
        never on a challenge page. A click it leaves to browser.act
        answers with the ref and the rule that refused it
        (``_refused_click``). One that was made is described where it
        landed: the same tab, or the new tab it opened (``new_tab``). One
        whose navigation was stopped or failed says so, with the tab back
        on the page it was made on (``_put_back``)."""
        if not _valid_ref(ref):
            return _error("click needs a ref from the outline, e.g. e7.")
        page, refusal = await self._page_or_challenge(session)
        if refusal is not None:
            return refusal
        try:
            reason = await self._guard.consequential(page, ref)
            if reason is not None:
                # The guard's rule by its name alone ("name matches", not the word).
                logger.info("browser_read_click_refused", rule=reason.partition(":")[0])
            else:
                reason = await self._order_reason(page, ref)
        except (StaleRef, PlaywrightError) as exc:  # the ref could not be resolved at all
            _log_failure("browser_click_gate_failed", exc, ref=ref)
            return _stale()
        if reason is not None:
            return self._refused_click(session, ref, reason)
        locator = page.locator(f"aria-ref={ref}")
        blocked_before = self._blocked_count(session)
        notes_before = self._notes_count(session)
        # What tells afterwards where the click landed: the tabs that were
        # open, and the address of the page it was made on.
        tabs_before = self._tabs(session)
        address_before = page_address(page.url)
        # A click with no card sends nothing: the guard stops any page
        # script's request but a GET, and any order address, until the
        # click has settled and the network is quiet (at most 2 s).
        state = self._guard.egress_state(session.context)
        in_flight_before = set(getattr(state, "in_flight", ()))
        if state is not None:
            state.read_click = True
        late = False
        href = ""
        try:
            try:
                # The pre-click accessible name, so the summary reads
                # 'click "Grades"' and not 'click e3' (contracts §3).
                name = await locator.evaluate(_CLICK_NAME_JS, timeout=REF_TIMEOUT_MS)
                href = await locator.evaluate(_CLICK_HREF_JS, timeout=REF_TIMEOUT_MS)
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
            # A tab that is on its way is waited for with the click window
            # still up, so what it opens first is judged like a navigation
            # in the tab the click was made in.
            late = not any(
                tab not in tabs_before for tab in self._tabs(session)
            ) and self._tab_on_its_way(state, in_flight_before)
            if late:
                try:
                    await session.context.wait_for_event("page", timeout=NEW_TAB_WAIT_MS)
                except PlaywrightError:
                    pass  # it never answered: the tab the click was made in is described
        finally:
            if state is not None:
                state.read_click = False
        sent = self._click_sent(session, since=blocked_before)
        # Where the click landed: the newest tab it opened (target=_blank,
        # window.open), else the tab it was made in.
        new_tabs = [tab for tab in self._tabs(session) if tab not in tabs_before]
        blocked = self._blocked_reason(session, since=blocked_before)
        landed = new_tabs[-1] if new_tabs else page
        dead = landed.url.startswith("chrome-error://")  # its navigation was stopped, or failed
        if (
            dead
            and new_tabs
            and not page.url.startswith("chrome-error://")
            and page_address(page.url) != address_before
        ):
            # The click moved its own tab and also opened a tab that did
            # not load (an ad, a blocked host): the page it moved to is
            # where it landed, and the dead tab is only closed.
            for tab in new_tabs:
                await tab.close()
            new_tabs, landed, dead = [], page, False
        # Whether the click opened a page: a new tab that shows one (an
        # empty tab is no page), or another address in the tab it was made in.
        if new_tabs:
            moved = not dead and landed.url != "about:blank"
        else:
            moved = not dead and page_address(page.url) != address_before
        # The guard stopped something while the click ran. A form or an
        # order address is the click's own doing, and so is a request from
        # a page that stayed where it was: left to browser.act, as before.
        # Only a page script's request next to a navigation that did go
        # through (a link's click statistics, what the new page sends as it
        # loads) is passed over: nothing was sent either way, and calling
        # that click refused left the model on a page it believed unchanged.
        if (
            not moved and not dead and not new_tabs and sent is None
            and isinstance(href, str) and href.startswith(("https://", "http://"))
            and page_address(href) != address_before
        ):
            # The click was on a link and the page is where it was: a slide
            # of a carousel that moved under the click, a link a banner
            # covers. Following a link is opening its address, so that is
            # done, and judged by the guard like any open.
            state_now = self._leave_page(session)
            try:
                await page.goto(href, wait_until="domcontentloaded", timeout=NAVIGATION_TIMEOUT_MS)
                await wait_for_quiet(state_now, since=time.monotonic(), cap_s=LOAD_QUIET_CAP_S)
            except PlaywrightError as exc:
                _log_failure("browser_click_follow_failed", exc)
            dead = page.url.startswith("chrome-error://")
            moved = not dead and page_address(page.url) != address_before
            blocked = self._blocked_reason(session, since=blocked_before)
        # Any other stop next to a page that did open (a redirect of the new
        # page to an order address, a form its script tried to send) is not
        # passed over either: the answer describes the page the tab is on
        # and says what was stopped. Answered as refused, the model held a
        # ref of a page that was gone.
        refused = sent is not None and not moved
        if refused and sent == READ_CLICK_REQUEST and not new_tabs and not dead:
            # A banner's own button: the click closed it and the page's
            # script tried to report that. The control is gone, so "make
            # the same click with browser.act" had nothing to click; the
            # page as it is now is the answer.
            try:
                refused = await locator.count() > 0
            except PlaywrightError:
                pass
        if refused or dead:
            for tab in new_tabs:
                await tab.close()  # the session stays on the page the ref belongs to
            if refused:
                stopped = self._refused_click(session, ref, str(sent))
            elif blocked is not None:
                stopped = _error(f"That click was refused by the network policy: {blocked}")
            elif new_tabs:
                stopped = _error("The page that click opened in a new tab did not load.")
            else:
                stopped = _error("The page that click leads to did not load.")
            return await self._put_back(session, page, stopped, address_before)
        extra: dict[str, Any] = {}
        opened = await session.adopt_new_tab(tabs_before) if new_tabs else None
        if opened is not None:
            await self._settle(opened)
            if late:
                # It came after the click's own wait for quiet: give what it
                # fetches the time an open gets.
                await wait_for_quiet(state, since=time.monotonic(), cap_s=LOAD_QUIET_CAP_S)
            extra["new_tab"] = True
        if sent is not None:
            extra["stopped_request"] = (
                STOPPED_REQUEST_NOTE if sent == READ_CLICK_REQUEST else STOPPED_ORDER_NOTE
            )
        args = {"ref": ref, "name": self._label(session, str(name or ""))}
        if moved and isinstance(href, str):
            _shared.note_entry_link(opened or page, href)
        result = await self._observe(session, "click", args, extra=extra)
        result = await self._with_status(session, opened or page, result)
        if sent is not None and result.get("ok") and result.get("outline") == []:
            # The page the click opened shows nothing, and what it tried to
            # fetch as it started was stopped with the click (a seat page
            # that asks for its cart by POST). Loaded again like an open,
            # outside the click's window, it gets what any opened page gets.
            landed_tab = opened or page
            state = self._leave_page(session)
            try:
                await landed_tab.reload(wait_until="domcontentloaded", timeout=NAVIGATION_TIMEOUT_MS)
                await wait_for_quiet(state, since=time.monotonic(), cap_s=LOAD_QUIET_CAP_S)
            except PlaywrightError as exc:
                _log_failure("browser_click_reload_failed", exc)
            else:
                extra.pop("stopped_request", None)
                result = await self._observe(session, "click, loaded again", args, extra=extra)
                result = await self._with_status(session, landed_tab, result)
        if moved and result.get("ok") and isinstance(href, str) and href.startswith(("https://", "http://")):
            # The link the click followed, as the page wrote it: the page's
            # own address loses its query in ACCOUNT mode, and that query
            # is what makes a showtime or a search result this one.
            try:
                result["opened_link"] = (
                    snap.strip_url_secrets(href) if session.mode == "account" else href
                )
            except ValueError:
                pass
        return self._with_notes(session, _note_empty(result), since=notes_before)

    async def _put_back(
        self, session: BrowserSession, page: Any, stopped: dict[str, Any], address_before: str
    ) -> dict[str, Any]:
        """*stopped* (what a click that opened no page answers) once the
        tab shows the page the click was made on again. A navigation the
        guard stops, or one that fails, leaves the tab on Chrome's error
        page: the refusal named a ref of a page that was gone, the next
        look found an empty page, and browser.act had nothing to make
        the click on. Going back loads the page again, so its refs are
        new: the answer then carries its fresh outline in place of the
        old ref and says so (RELOADED_NOTE). A tab still on its page is
        left alone, and one that will not come back is answered for as
        before."""
        if not page.url.startswith("chrome-error://"):
            return stopped
        state = self._leave_page(session)
        # The click window stays up while the page loads again: a page that
        # sends itself on to the order address by script would otherwise
        # get there now, with nothing stopping it.
        if state is not None:
            state.read_click = True
        try:
            await page.go_back(wait_until="domcontentloaded", timeout=NAVIGATION_TIMEOUT_MS)
            await wait_for_quiet(state, since=time.monotonic(), cap_s=LOAD_QUIET_CAP_S)
        except PlaywrightError as exc:
            _log_failure("browser_click_put_back_failed", exc)
            return stopped
        finally:
            if state is not None:
                state.read_click = False
        # Nothing earlier in the tab, or a page that moved on to what was
        # stopped once more: there is no page to describe.
        if page.url.startswith(("chrome-error://", "about:")):
            return stopped
        # The summary line outlives the outline: it says both things.
        seen = await self._observe(session, "click stopped, back", {})
        if not seen.get("ok"):
            return seen  # the page asks for the person now, or the owner's rules block it
        stopped.pop("ref", None)
        if page_address(page.url) != address_before:
            # The stopped navigation had replaced the page in the tab's
            # history: one step back is the page before it, and the
            # control is not on it.
            return {**seen, **stopped, "reloaded": EARLIER_PAGE_NOTE}
        return {**seen, **stopped, "reloaded": RELOADED_NOTE}

    @staticmethod
    async def _order_reason(page: Any, ref: str) -> Optional[str]:
        """The live page's answer for a click that has no approval card at
        all: the control the click lands on, its words, its form, its link
        and every frame's facts. A click the purchase rules flag
        (``markers.read_click_pays``) may place an order; any other click
        but a plain link or a control outside a form on a page with nothing
        to pay (``markers.read_click_allowed``) is left to browser.act,
        whose card shows the owner the page first. The answer names the
        rule in fixed words (``_click_rule``), and one log line keeps the
        rule and the judged facts as booleans."""
        target = await page.locator(f"aria-ref={ref}").evaluate(
            markers.PURCHASE_TARGET_JS, timeout=REF_TIMEOUT_MS
        )
        target = markers.join_page(target, await _shared.page_facts(page))
        pays = markers.read_click_pays(target)
        if not pays and markers.read_click_allowed(target):
            return None
        rule = _click_rule(target)
        facts = target if isinstance(target, dict) else {}
        logger.info(
            "browser_read_click_refused",
            rule=rule,
            pays=pays,
            **{key: bool(facts.get(key)) for key in _LOGGED_FACTS},
        )
        return f"{_MAY_ORDER}: {rule}" if pays else rule

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
        if self._memory is not None:
            # What a find shows can be acted on: its refs join the page memory.
            self._memory.add_names(session.user_id, url=page.url, lines=matches)
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
        state = self._leave_page(session)
        try:
            await page.go_back(wait_until="domcontentloaded", timeout=NAVIGATION_TIMEOUT_MS)
        except PlaywrightTimeoutError:
            return _error(f"Going back did not finish within {NAVIGATION_TIMEOUT_MS // 1000} s.")
        if page.url == "about:blank":
            # The tab's first history entry is blank: nothing earlier to read.
            if before != "about:blank":
                await page.go_forward(wait_until="domcontentloaded", timeout=NAVIGATION_TIMEOUT_MS)
            return _error("There is no earlier page to go back to.")
        # As after open: the page loads again and fetches what it shows.
        await wait_for_quiet(state, since=time.monotonic(), cap_s=LOAD_QUIET_CAP_S)
        return await self._with_status(session, page, await self._observe(session, "back", {}))

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
