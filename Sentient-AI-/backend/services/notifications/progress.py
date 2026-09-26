"""Turns a running agent turn's events into short progress lines for a chat
channel ("Searching the web…", "Opening canvas.nyit.edu…", "Taking a
screenshot…") and paces them.

Why it exists: A Telegram turn with several tool calls can run for a minute,
and a chat that shows only "typing…" for that long looks stuck. The runtime
already reports every tool call through its event sink; this module maps those
events to phrases and decides which ones are worth a message, so telegram.py
only hands it a send function. ``on_event`` goes only to a chat callback that
accepts it (``takes_on_event``), so one written without it still answers.

Every phrase is fixed text chosen by the tool's name and, for the tools that
take one, its action; the only variable part is the host of a page being
opened, which the runtime extracts (``runtime.tool_call_facts``). Never model
text, a URL's path or query, search terms or typed text.

Pacing, per turn:

- nothing in the first ``GRACE_S`` seconds, so a quick answer arrives alone;
- at most one line every ``MIN_INTERVAL_S`` seconds; while waiting, only the
  newest phrase is kept, since an older one is already out of date;
- never the same phrase twice in a row, and at most ``MAX_PER_TURN`` lines;
- the final reply comes at least ``REPLY_GAP_S`` after the last line that
  went out, since Telegram asks for about one message per second per chat;
- a line that fails to send is logged and dropped: the turn never waits on
  a progress line nor fails because of one.

A parked approval gets no line: its card and the reply already say so.
"""

from __future__ import annotations

import asyncio
import inspect
import re
import time
from typing import Any, Awaitable, Callable, Mapping, Optional

import structlog

logger = structlog.get_logger(__name__)

GRACE_S = 2.0
MIN_INTERVAL_S = 4.0
MAX_PER_TURN = 6
MAX_PHRASE_CHARS = 80
# A host longer than this reads as noise in a one-line status; the phrase
# falls back to its host-free wording instead.
MAX_HOST_CHARS = 60
# How long the final reply waits for a progress line already on its way, so
# the reply is never overtaken by a status about the turn it ends.
SEND_WAIT_S = 2.0
# How long after a progress line the final reply may follow it, so the two
# never reach the chat in the same instant.
REPLY_GAP_S = 1.0

# Seams for tests: pacing reads the clock and waits through these, so a test
# can drive a whole turn's timeline without real sleeps.
_now: Callable[[], float] = time.monotonic
_sleep: Callable[[float], Awaitable[None]] = asyncio.sleep

DEFAULT_PHRASE = "Working on it…"

# Keyed by tool name, or "tool/action" for the tools that take an action.
# None means say nothing: the call is instant or bookkeeping.
_TOOL_PHRASES: dict[str, Optional[str]] = {
    "web.search": "Searching the web…",
    "web.research": "Reading several sources…",
    "web.screenshot": "Taking a screenshot…",
    "browser.read/click": "Clicking on the page…",
    "browser.read/snapshot": "Reading the page…",
    "browser.read/find": "Reading the page…",
    "browser.read/text": "Reading the page…",
    "browser.read/scroll": "Scrolling the page…",
    "browser.read/back": "Going back a page…",
    "browser.read/tabs": "Checking the open tabs…",
    "browser.read/switch": "Switching tabs…",
    "browser.read/wait": "Waiting for the page to load…",
    "browser.read/screenshot": "Taking a screenshot…",
    "browser.read/note": None,
    # The turn ends right after with its own explanation.
    "browser.read/handoff": None,
    "desktop.screenshot": "Taking a screenshot…",
    "desktop.observe/outline": "Looking at the app on your screen…",
    "desktop.observe/apps": "Checking which apps are open…",
    "desktop.observe/windows": "Checking the open windows…",
    "desktop.act/click": "Clicking in an app…",
    "desktop.act/double_click": "Clicking in an app…",
    "desktop.act/type": "Typing…",
    "desktop.act/key": "Pressing keys…",
    "desktop.act/scroll": "Scrolling…",
    "desktop.act/open_app": "Opening an app…",
    "desktop.act/focus_window": "Switching windows…",
    "canvas.get_courses": "Checking your Canvas courses…",
    "canvas.get_assignments": "Checking your Canvas assignments…",
    "canvas.get_upcoming": "Checking what's due on Canvas…",
    "canvas.get_grades": "Checking your grades…",
    "canvas.grade_whatif": "Working out your grade…",
    "canvas.get_calendar_events": "Checking your Canvas calendar…",
    "canvas.get_submissions": "Checking your Canvas submissions…",
    "canvas.submit_assignment": "Submitting to Canvas…",
    "google_workspace.get_messages": "Checking your email…",
    "google_workspace.get_message": "Reading an email…",
    "google_workspace.search_emails": "Searching your email…",
    "google_workspace.send_email": "Sending the email…",
    "google_workspace.get_events": "Checking your calendar…",
    "google_workspace.check_availability": "Checking your calendar…",
    "google_workspace.create_event": "Adding the event to your calendar…",
    "robinhood.get_crypto_prices": "Checking crypto prices…",
    "reminders.now": None,
    "reminders.create": "Setting a reminder…",
    "reminders.list": "Checking your reminders…",
    "reminders.cancel": "Cancelling a reminder…",
    "memory.remember": "Saving that to your memory…",
    "watch.list": "Checking your page watches…",
    "watch.delete": "Removing a page watch…",
    "system.capabilities": "Checking what this computer can do…",
    "system.install_capability": "Installing software…",
}

# Phrases that name the host of the page being opened, with the wording
# used when the event carries no usable host.
_HOST_PHRASES: dict[str, tuple[str, str]] = {
    "web.fetch_page": ("Reading {host}…", "Reading a web page…"),
    "browser.read/open": ("Opening {host}…", "Opening a web page…"),
    "watch.create": ("Setting up a watch on {host}…", "Setting up a page watch…"),
}

# A tool of a known family that has no entry above (a new action, an MCP
# server's tool): still a truthful line, just a less specific one.
_FAMILY_PHRASES: dict[str, str] = {
    "web": "Using the web…",
    "browser": "Using the browser…",
    "desktop": "Using your computer…",
    "canvas": "Checking Canvas…",
    "google_workspace": "Checking your Google account…",
    "robinhood": "Checking your crypto portfolio…",
    "reminders": "Checking your reminders…",
    "watch": "Checking your page watches…",
    "system": "Checking this computer's setup…",
    "mcp": "Using a connected app…",
}

_HOST_RE = re.compile(r"[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?")


def _capped(text: str) -> str:
    return text if len(text) <= MAX_PHRASE_CHARS else text[: MAX_PHRASE_CHARS - 1] + "…"


def phrase_for(event: Mapping[str, Any]) -> Optional[str]:
    """The progress line for one runtime event, or None for no line.

    Only ``tool_call`` events speak; results, blocked actions and parked
    approvals show up in the final reply (and the approval card) instead.
    """
    kind = event.get("type")
    if kind != "tool_call":
        return None
    data = event.get("data")
    if not isinstance(data, Mapping):
        return DEFAULT_PHRASE
    name = data.get("name")
    if not isinstance(name, str) or not name:
        return DEFAULT_PHRASE
    family, _, rest = name.partition(".")
    # A second connector of one type is offered as "canvas__1f2e3d4c.get_courses".
    family = family.split("__", 1)[0]
    tool = f"{family}.{rest}"
    action = data.get("action")
    keys = ([f"{tool}/{action}"] if isinstance(action, str) and action else []) + [tool]
    for key in keys:
        if key in _HOST_PHRASES:
            with_host, without_host = _HOST_PHRASES[key]
            host = data.get("host")
            if isinstance(host, str) and len(host) <= MAX_HOST_CHARS and _HOST_RE.fullmatch(host):
                return _capped(with_host.format(host=host))
            return without_host
        if key in _TOOL_PHRASES:
            phrase = _TOOL_PHRASES[key]
            return _capped(phrase) if phrase is not None else None
    return _FAMILY_PHRASES.get(family, DEFAULT_PHRASE)


def takes_on_event(chat: Callable[..., Any]) -> bool:
    """Whether a chat callback accepts ``on_event=`` (by name or ``**kwargs``).

    A callback written before progress lines existed, such as
    ``(user_id, text, *, new_conversation=False)``, would fail every turn with
    a TypeError if handed the keyword; it keeps working and gets no lines.
    """
    return takes_keyword(chat, "on_event")


def takes_keyword(callback: Callable[..., Any], name: str) -> bool:
    """Whether *callback* accepts the keyword *name* (by name or
    ``**kwargs``); telegram.py also asks it about ``stop_mark``."""
    try:
        params = inspect.signature(callback).parameters.values()
    except (TypeError, ValueError):  # a callable Python cannot introspect
        return False
    return any(
        p.kind is p.VAR_KEYWORD
        or (p.name == name and p.kind in (p.KEYWORD_ONLY, p.POSITIONAL_OR_KEYWORD))
        for p in params
    )


class TurnProgress:
    """Paces one turn's progress lines onto a channel.

    ``on_event`` is the runtime's event sink: it only records the newest
    phrase and wakes the sender, so the turn never waits on the network.
    ``aclose`` ends the turn's progress before the final reply goes out.
    """

    def __init__(self, send: Callable[[str], Awaitable[Any]]) -> None:
        self._send = send
        self._started = _now()
        self._pending: Optional[str] = None
        self._last: Optional[str] = None
        self._last_at: Optional[float] = None
        # When the newest line finished sending; None until one has.
        self._landed_at: Optional[float] = None
        self._sent = 0
        self._sending = False
        self._closed = False
        self._task: Optional[asyncio.Task[None]] = None

    async def on_event(self, event: dict[str, Any]) -> None:
        if self._closed or self._sent >= MAX_PER_TURN:
            return
        phrase = phrase_for(event)
        if phrase is None:
            return
        self._pending = phrase
        if self._task is None or self._task.done():
            self._task = asyncio.create_task(self._deliver(), name="chat-progress")

    def _next_at(self) -> float:
        earliest = self._started + GRACE_S
        if self._last_at is None:
            return earliest
        return max(earliest, self._last_at + MIN_INTERVAL_S)

    async def _deliver(self) -> None:
        while self._pending is not None and not self._closed and self._sent < MAX_PER_TURN:
            wait = self._next_at() - _now()
            if wait > 0:
                await _sleep(wait)
                continue
            phrase, self._pending = self._pending, None
            if phrase == self._last:
                continue
            self._last, self._last_at = phrase, _now()
            self._sent += 1
            self._sending = True
            try:
                await self._send(phrase)
                self._landed_at = _now()
            except Exception as exc:
                logger.warning("chat_progress_send_failed", error=type(exc).__name__)
            finally:
                self._sending = False

    async def aclose(self) -> None:
        """Drop whatever is still waiting; let a line already on its way
        land first (up to ``SEND_WAIT_S``) so it cannot follow the reply,
        then wait until ``REPLY_GAP_S`` has passed since the last line."""
        self._closed, self._pending = True, None
        task, self._task = self._task, None
        if task is not None and not task.done():
            if not self._sending:
                task.cancel()
            # asyncio.wait neither raises the task's cancellation here nor
            # swallows one aimed at the caller.
            await asyncio.wait({task}, timeout=SEND_WAIT_S)
            task.cancel()
        # A line that never finished sending (hung, then abandoned above)
        # sets no gap; the reply has already waited for it.
        if self._landed_at is not None:
            gap = self._landed_at + REPLY_GAP_S - _now()
            if gap > 0:
                await _sleep(gap)
