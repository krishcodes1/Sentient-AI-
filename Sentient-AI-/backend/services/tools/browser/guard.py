"""Egress and consequential-action checks for the browser (spec §6, §9).

Three gates: ``check_url`` on every model-supplied URL before a goto; a
``context.route`` handler that re-checks every top-level navigation the
browser makes on its own (redirects, links) and aborts non-GET navigations
of any frame from read-tier actions (not the person's own, while a handoff
is pending: ``EgressState.human_driving``); and ``consequential(page, ref)``, the
live-page facts that decide whether a click is a read. Outside a write
window no frame may send a form: a field change whose page script submits
the form (a radio that sends on change, a hidden frame's POST) is stopped
here, and while a browser.act change runs (``EgressState.changing``) no
frame may open an order address (``markers.ORDER_ACTION_RE``) either,
directly or through a redirect. Outside a write window (browser.read,
and the person's handoff too) no frame opens an order step's address
(``markers.ORDER_STEP_RE``: a GET to /place-order can be the order), no
frame sends anything to an order address, and no page script sends a
request to one (POST /orders, /pay, /buy...): a script button whose
``fetch()`` places the order, a page that orders on load or when
scrolled to, and a page that sends its own order form while the person
holds it are all stopped here whatever their words. Only an approved
act or checkout (``write_allowed``) and the person's handoff right after
an approved checkout (``checkout_handoff``: the bank's 3-D Secure page
returns to the shop's payment address) lift that. While browser.read
clicks (``EgressState.read_click``, the click and its settle time) no
page script sends anything but a GET and no frame opens an order
address other than an order history (``markers.READ_LINK_RE``):
browser.read then answers ``markers.READ_CLICK_MESSAGE``. Loopback is
allowed only under ``CRAWLER_ALLOW_LOOPBACK_FOR_TESTS=1`` (the fake
site), read at call time, never in production paths.

Every window is the page's it was opened for (``EgressState.write_page``,
``EgressState.handoff_page``): a request from another tab, from a worker
or from a frame whose page cannot be told is judged as outside it, so
approving a step on one tab opens nothing for another. Inside a window
the tab is navigated only by its own document (``_started_by``): another
site's tab that holds it (it opened the shop, or the shop opened it) may
point it anywhere, even at a page of its own that then opens an order
step, and is stopped. Outside a write window no request of any method, a
page's image, GET fetch or beacon included, goes to an order step's
address, and while browser.read clicks none goes to an address
``markers.READ_LINK_RE`` matches. The click's window stays open until
the network is quiet (``wait_for_quiet``). A WebSocket is not a request
the route sees: ``_socket`` drops what a page sends on one while
browser.read clicks, and always on a page's socket whose address is an
order address (a socket's page cannot be told, so it is never inside a
write window). A socket a worker opens is not routed at all
(``context.route_web_socket`` sees the page's only).

A bound write window (``EgressState.write_origin``, the checkout's order
POST) is judged on every frame, not only the top one: a POST from a
frame to another origin is aborted, and the order POST itself is fetched
here so the merchant's answer is checked before the browser acts on it
(a 307/308 would re-send the card). What a page's own script sends (an
XHR, a fetch, a beacon) is judged only by where it goes and outside a
write window: a GET to anything but an order step, and a request to any
other address, passes (a search box's suggestions, analytics), except
while browser.read clicks.

A top-level GET the guard admits is fetched here
(``route.fetch(max_redirects=0)``, with the browser's own headers and
cookies) and its answer handed to the browser, never passed on with
``route.continue_()``: Playwright (1.63) calls a route for the first URL
of a request only, so a redirect the browser followed itself would reach
its next hop (a private address, an order step) unjudged, and the
``request`` event that shows the hop fires once it is already sent. A
3xx answer instead becomes a client-side hop (``_client_redirect``) that
comes back through here and is judged like any navigation, however many
hops the chain has. What the fetch cannot carry is Chrome's own TLS and
HTTP/2 fingerprint; the browser-control spec (§9) says when that matters
and what would carry it without losing a hop.
"""

from __future__ import annotations

import asyncio
import html
import ipaddress
import os
import re
import socket
import time
import weakref
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Callable, Optional
from urllib.parse import urljoin, urlsplit, urlunsplit

import structlog

# The same blocked-range table check_ssrf applies, used on the one
# resolution this module makes (see Guard.check_url).
from core.network_security import _blocked_network_for
from services.tools.browser.checkout.markers import ORDER_ACTION_RE, ORDER_STEP_RE, READ_LINK_RE

if TYPE_CHECKING:
    from playwright.async_api import BrowserContext, Page, Request, Route, WebSocketRoute

logger = structlog.get_logger(__name__)

BLOCKED_NAVIGATION_MARKER = "net::ERR_BLOCKED_BY_CLIENT"  # what a blocked goto/click reports

CONSEQUENTIAL_NAMES = (
    "send", "submit", "post", "pay", "buy", "order", "delete", "confirm", "sign up",
    "register", "subscribe", "call", "accept", "agree", "allow", "authorize",
)
# Word-boundary, case-insensitive; a space in a name also matches "-" or nothing
# ("sign up", "sign-up", "signup"). Site packs extend the tuple later.
_NAME_PATTERN = re.compile(
    r"\b(" + "|".join(re.escape(n).replace(r"\ ", r"[\s-]?") for n in CONSEQUENTIAL_NAMES) + r")\b",
    re.IGNORECASE,
)
_REF_PATTERN = re.compile(r"(?:f\d+)?e\d+")
# Why a navigation that would have sent the page was stopped outside a
# write window: browser.act reports these to the person as a change that
# tried to send the page (``SENDING_REASONS``).
READ_TIER_POST = "non-GET top-level navigation from a read-tier action"
READ_TIER_FRAME_POST = "non-GET frame navigation from a read-tier action"
ORDER_ADDRESS = "a change on the page tried to open an order address"
ORDER_REQUEST = "a change on the page tried to send a request to an order address"
SENDING_REASONS: frozenset[str] = frozenset(
    {READ_TIER_POST, READ_TIER_FRAME_POST, ORDER_ADDRESS, ORDER_REQUEST}
)
# Why a navigation or a page's own request was stopped outside any write
# window: an order step is placed by opening it, and only browser.act and
# browser.checkout may do that.
READ_TIER_ORDER_STEP = "an order step's address, outside an approved action"
# Why a page's own request, or a form, to an order address was stopped
# outside any write window (the person's handoff included).
READ_TIER_ORDER_REQUEST = "a request to an order address, outside an approved action"
# Why a navigation of the approved tab was stopped inside its window: the
# window is the page's the card showed, and another page (a tab of another
# site that holds this one) started it.
OTHER_PAGE_NAVIGATION = "another page tried to navigate the approved tab"
# Why something was stopped while browser.read clicked: a click with no
# approval card sends nothing and opens no order address.
READ_CLICK_REQUEST = "a read-tier click tried to send a request"
READ_CLICK_ADDRESS = "a read-tier click tried to open an order address"
READ_CLICK_REASONS: frozenset[str] = frozenset(
    {READ_CLICK_REQUEST, READ_CLICK_ADDRESS, READ_TIER_POST, READ_TIER_FRAME_POST,
     READ_TIER_ORDER_STEP, READ_TIER_ORDER_REQUEST}
)
# Methods that ask and never send: a page's own request by one of these is
# never stopped (a CORS preflight precedes the request it asks about).
_SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})
_CONSEQUENTIAL_TIMEOUT_MS = 3000
# How long browser.read's click window stays open after the click: until
# no request has been in flight for READ_CLICK_QUIET_S, at most
# READ_CLICK_CAP_S (a page that polls forever is not waited out).
READ_CLICK_QUIET_S = 0.25
READ_CLICK_CAP_S = 2.0


class StaleRef(Exception):
    """The ref does not resolve on the current page; the caller re-snapshots."""


_CONSEQUENTIAL_JS = r"""
el => {
  const tag = el.tagName.toLowerCase();
  const type = (el.getAttribute('type') || '').toLowerCase();
  const role = (el.getAttribute('role') || '').toLowerCase();
  // el.form follows the form= attribute (a control rendered outside its
  // <form>); closest() covers links and plain elements inside one.
  const form = el.form || el.closest('form');
  const byId = (el.getAttribute('aria-labelledby') || '').split(/\s+/).filter(Boolean)
    .map(id => { const n = document.getElementById(id); return n ? n.textContent : ''; }).join(' ');
  const name = [el.getAttribute('aria-label'), byId, el.innerText, el.value,
                el.getAttribute('title'), el.getAttribute('alt')]
    .map(s => (s || '').replace(/\s+/g, ' ').trim()).find(s => s) || '';
  const submit = (tag === 'button' && (type === '' || type === 'submit'))
    || (tag === 'input' && (type === 'submit' || type === 'image'));
  const method = (el.getAttribute('formmethod') || (form && form.getAttribute('method')) || 'get')
    .toLowerCase();
  const SENSITIVE =
    'input[type="password"], input[autocomplete^="cc-"], input[autocomplete="one-time-code"], ' +
    'input[name*="card" i], input[name*="cvc" i], input[name*="cvv" i], input[name*="iban" i], ' +
    'iframe[src*="stripe" i], iframe[src*="paypal" i], iframe[src*="braintree" i], iframe[src*="adyen" i]';
  // form.elements includes fields associated from outside via form=.
  const sensitive = !!(form && (form.querySelector(SENSITIVE)
    || [...form.elements].some(f => f.matches(SENSITIVE))));
  const buttonish = submit || tag === 'button' || role === 'button'
    || (tag === 'input' && ['button', 'submit', 'image', 'reset'].includes(type));
  return {tag, type, name, submit, in_form: !!form, method, sensitive, buttonish};
}
"""


def classify_target(facts: dict[str, Any]) -> Optional[str]:
    """Pure rule table over the facts ``_CONSEQUENTIAL_JS`` collects; first
    match wins. The password/payment-form rule leads because it is the more
    specific reason: a login or checkout submit is reported as such."""
    if facts.get("in_form") and facts.get("sensitive"):
        return "inside a form with a password/payment field"
    if facts.get("submit") and facts.get("in_form"):
        return "submit control"
    match = _NAME_PATTERN.search(facts.get("name") or "")
    if match:
        return "name matches: " + re.sub(r"[\s-]+|(?<=sign)(?=up)", " ", match.group(1).lower())
    if facts.get("in_form") and facts.get("buttonish") and (facts.get("method") or "get") != "get":
        return "non-GET navigation"
    return None


@dataclass
class EgressState:
    """Per-context guard state. ``write_allowed`` is flipped by the write
    tier around one approved action (phase 3). ``write_origin`` narrows an
    open window to one origin: the checkout sets it to where the order
    form says it posts, so a card can only travel there, and only as a
    POST (a GET would put it in a URL); it binds the window whoever holds
    it, a pending handoff included. ``human_driving`` is set by a toolkit
    while a handoff is pending: from the moment it hands the page to the
    person (``needs_human``, from a read, an act or a checkout) until the
    agent's next action on this context, whichever toolkit takes it. While
    it is set the person's own submit (a sign-in form, a one-time code in
    Crawler's window) passes the read-tier block; the address checks
    still apply, and so do the order ones: the model can ask for a
    handoff whenever it likes, and a page's own script may send its order
    form while the person looks. ``checkout_handoff`` is set with it only
    by browser.checkout, when a challenge follows the approved order (3-D
    Secure): the order addresses are then open to the person as in a
    write window. Both reset on the agent's next action and when the
    context closes. ``changing`` is set by browser.act around an act that
    is not meant to send anything (a fill, a check, a select, a key other
    than Enter, a plain link): no frame may then open an order address,
    even by GET or through a redirect, and no page script may send a
    request to one. With neither window open, no frame opens an order
    step's address or sends to an order address, and no page script sends
    to one. ``read_click`` is set by browser.read around its click: no
    page script sends anything but a GET, and no frame opens an order
    address other than an order history. ``blocked`` is the audit trail
    the toolkit and the tests read.

    ``write_page`` is the page an open write window was opened for, and
    ``handoff_page`` the page of the checkout's handoff: ``write_allowed``
    and ``checkout_handoff`` hold only for a request whose frame belongs
    to that page (another tab, a worker, a frame that cannot be told is
    outside), and a navigation of that page only when its own document
    started it (``_started_by``). ``write_origin``, ``changing`` and
    ``read_click`` only ever narrow, so they hold for every page, and so
    does ``human_driving``, which lifts no order block (the person's
    sign-in may open a popup).
    ``in_flight`` and ``last_request`` are what ``wait_for_quiet`` reads."""

    account_mode: bool
    write_allowed: bool = False
    write_origin: Optional[str] = None
    write_page: Any = None
    human_driving: bool = False
    checkout_handoff: bool = False
    handoff_page: Any = None
    changing: bool = False
    read_click: bool = False
    blocked: list[dict[str, str]] = field(default_factory=list)
    in_flight: set[Any] = field(default_factory=set)
    last_request: float = 0.0


def _origin(url: str) -> str:
    """``scheme://host[:port]`` of *url*, lower-cased, userinfo dropped:
    what "the same site" means to a browser."""
    try:
        parts = urlsplit(url)
    except ValueError:
        return ""
    return f"{parts.scheme.lower()}://{parts.netloc.rpartition('@')[2].lower()}"


_STATES: "weakref.WeakKeyDictionary[Any, EgressState]" = weakref.WeakKeyDictionary()


def egress_state(context: "BrowserContext") -> Optional[EgressState]:
    return _STATES.get(context)


def _without_query(url: str) -> str:
    """scheme://host/path: what a log line or an ACCOUNT-mode audit entry
    may keep. Query strings and fragments carry session ids, OAuth codes
    and SAML state on exactly the pages this guard sees."""
    try:
        parts = urlsplit(url)
    except ValueError:
        return "<unparseable URL>"
    return urlunsplit((parts.scheme, parts.netloc, parts.path, "", ""))


def _order_address(url: str) -> bool:
    """Whether *url*'s path or query names an order step (/place-order,
    /checkout/complete, ?next=/pay...)."""
    try:
        parts = urlsplit(url)
    except ValueError:
        return True
    return bool(ORDER_ACTION_RE.search(parts.path + ("?" + parts.query if parts.query else "")))


def _read_link(url: str) -> bool:
    """Whether *url* is an order address other than an order history
    (``READ_LINK_RE``): what a read-tier click never opens."""
    try:
        parts = urlsplit(url)
    except ValueError:
        return True
    return bool(READ_LINK_RE.search(parts.path + ("?" + parts.query if parts.query else "")))


def _order_step(url: str) -> bool:
    """Whether *url*'s path or query names a step whose opening may place
    an order (/place-order, /checkout/complete, ?next=/confirm-order)."""
    try:
        parts = urlsplit(url)
    except ValueError:
        return True
    return bool(ORDER_STEP_RE.search(parts.path + ("?" + parts.query if parts.query else "")))


def _client_redirect(target: str) -> str:
    escaped = html.escape(target, quote=True)
    return (
        '<!doctype html><html><head><meta http-equiv="refresh" content="0;url='
        f'{escaped}"><title>Redirecting</title></head><body></body></html>'
    )


def _is_top_level(request: "Request") -> bool:
    try:
        return request.frame.parent_frame is None
    except Exception:  # noqa: BLE001 - a popup's first navigation has no frame yet: guard it
        return True


def _page_of(request: Any) -> Any:
    """The page *request* was made for, or None when it cannot be told (a
    service worker's request, a popup's first navigation, a gone frame):
    a window is never open for None."""
    try:
        return request.frame.page
    except Exception:  # noqa: BLE001 - no frame: outside every window
        return None


def _started_by(request: Any, page: Any) -> bool:
    """Whether *page*'s own document started the navigation *request*: its
    Origin (a POST's) or its Referer names the page's origin. A tab of
    another site that holds this one (it opened the shop, or the shop
    opened it) may point it at any address, and its navigation carries
    that site's origin. One that names no origin at all (a page whose
    referrer policy sends none) is taken as the page's own only while no
    other tab is open to have started it."""
    try:
        headers = request.headers
        origin = headers.get("origin") or ""
        if origin in ("", "null"):
            referer = headers.get("referer")
            origin = _origin(referer) if referer else ""
        if origin:
            return bool(origin.lower() == _origin(page.url))
        return len(page.context.pages) == 1
    except Exception:  # noqa: BLE001 - what cannot be told was not the page's
        return False


async def wait_for_quiet(
    state: Any, *, since: float, quiet_s: float = READ_CLICK_QUIET_S, cap_s: float = READ_CLICK_CAP_S
) -> None:
    """Return once no request of the context has been in flight for
    *quiet_s* (counted from *since*, a ``time.monotonic()`` reading), or
    *cap_s* after *since*: how long browser.read keeps its click window
    open, so a request the click's script sends once an earlier one
    answers is still judged inside it. A request of a closed page is not
    waited for; a state without the counters (a test double) waits only
    *quiet_s*."""
    deadline = since + cap_s
    while True:
        now = time.monotonic()
        if now >= deadline:
            return
        in_flight: set[Any] = getattr(state, "in_flight", set())
        for request in list(in_flight):
            page = _page_of(request)
            if page is not None and page.is_closed():
                in_flight.discard(request)
        last = max(float(getattr(state, "last_request", 0.0) or 0.0), since)
        if not in_flight and now - last >= quiet_s:
            return
        await asyncio.sleep(min(0.05, deadline - now))


async def settle_blocked_navigation(page: "Page", *, timeout_ms: int = 1500) -> None:
    """Wait for Chromium's error page after a blocked navigation.

    An aborted top-level request commits ``chrome-error://chromewebdata/``
    a few ms later; a ``goto`` issued before that fails with "interrupted
    by another navigation". ``wait_for_load_state`` returns too early;
    this does not. Returns quietly when nothing was blocked.
    """
    try:
        await page.wait_for_url(lambda u: u.startswith("chrome-error://"), timeout=timeout_ms)
    except Exception:  # noqa: BLE001 - already settled, or no error page was ever committed
        return


LOOPBACK_TOGGLE = "CRAWLER_ALLOW_LOOPBACK_FOR_TESTS"
Resolver = Callable[[str], list[str]]


def _system_resolver(host: str) -> list[str]:
    try:
        # str(): typeshed widens sockaddr[0] to str | int; it is always the address.
        return sorted({str(info[4][0]) for info in socket.getaddrinfo(host, None)})
    except socket.gaierror:
        return []


def _loopback_allowed() -> bool:
    return os.environ.get(LOOPBACK_TOGGLE) == "1"


class Guard:
    def __init__(self, *, resolver: Resolver = _system_resolver) -> None:
        self._resolve = resolver

    # -- URL gate --------------------------------------------------------------

    def check_url(self, url: str) -> Optional[str]:
        """None if the model may open *url*; else the reason. http(s) only,
        no userinfo; every address the host resolves to is judged by the
        same blocked ranges as ``core.network_security.check_ssrf`` (private,
        loopback, link-local, CGNAT, NAT64/6to4-wrapped, non-global).

        The host is resolved exactly once, through ``self._resolve``:
        ``check_ssrf`` itself would resolve a second time through the
        system resolver, bypassing an injected resolver and opening a
        rebinding window between the two answers. Fails closed when the
        name does not resolve or an answer is not an address.
        """
        if not isinstance(url, str) or not url.strip():
            return "no URL given"
        try:
            parts = urlsplit(url)
            _ = parts.port  # raises ValueError when out of range
        except ValueError:
            return "Malformed URL"
        if parts.scheme not in ("http", "https"):
            return f"only http(s) URLs may be opened, not {parts.scheme or 'a bare path'}"
        if parts.username is not None or parts.password is not None:
            return "URLs with embedded credentials are refused"
        host = parts.hostname or ""
        if not host:
            return "no host in URL"
        if _loopback_allowed() and self._all_loopback(host):
            return None
        addresses = self._addresses(host)
        if not addresses:
            return f"could not resolve {host}"
        for address in addresses:
            try:
                ip = ipaddress.ip_address(address)
            except ValueError:
                return f"could not resolve {host} to an address"
            if _blocked_network_for(ip) is not None:
                return f"{host} resolves to a private or local address ({address})"
        return None

    def _addresses(self, host: str) -> list[str]:
        """An IP-literal host *is* its address (``http://10.0.0.1/`` connects
        there whatever DNS says), so only names reach the resolver. Without
        this a resolver that answers 127.0.0.1 for everything would pass a
        literal private address under the loopback toggle."""
        try:
            return [str(ipaddress.ip_address(host))]
        except ValueError:
            return self._resolve(host)

    def _all_loopback(self, host: str) -> bool:
        addresses = self._addresses(host) or ([host] if host in ("localhost",) else [])
        try:
            return bool(addresses) and all(ipaddress.ip_address(a).is_loopback for a in addresses)
        except ValueError:
            return False

    # -- route-level egress guard --------------------------------------------

    async def install_egress_guard(self, context: "BrowserContext", *, account_mode: bool) -> None:
        """Route every request of *context* through ``_route``. Idempotent:
        the toolkit calls this after every ``sessions.get()``."""
        if context in _STATES:
            return
        state = EgressState(account_mode=account_mode)
        _STATES[context] = state

        async def handler(route: "Route", request: "Request") -> None:
            await self._route(route, request, state)

        def closed(_context: "BrowserContext") -> None:
            state.human_driving = False  # a pending handoff ends with its window
            state.checkout_handoff = False
            state.handoff_page = None

        def started(request: "Request") -> None:
            state.in_flight.add(request)
            state.last_request = time.monotonic()

        def ended(request: "Request") -> None:
            state.in_flight.discard(request)
            state.last_request = time.monotonic()

        def socket_opened(ws: "WebSocketRoute") -> None:
            self._socket(ws, state)

        context.on("close", closed)
        context.on("request", started)
        context.on("requestfinished", ended)
        context.on("requestfailed", ended)
        await context.route("**/*", handler)
        await context.route_web_socket(lambda _url: True, socket_opened)

    def _socket(self, ws: "WebSocketRoute", state: EgressState) -> None:
        """A page's WebSocket, connected through to its server. What the
        page sends on it is dropped while browser.read clicks, and always
        when the socket's address is an order address: a socket's page
        cannot be told, so no write window is ever open for it. What the
        server sends passes untouched. A worker's socket never comes here
        (see the module's notes)."""
        server = ws.connect_to_server()
        order = _order_address(ws.url)

        def from_page(message: "str | bytes") -> None:
            if state.read_click:
                self._record(state, url=ws.url, reason=READ_CLICK_REQUEST)
            elif order:
                self._record(state, url=ws.url, reason=READ_TIER_ORDER_REQUEST)
            else:
                server.send(message)

        ws.on_message(from_page)

    async def _route(self, route: "Route", request: "Request", state: EgressState) -> None:
        try:
            url = request.url
            # A window is open only for the page it was opened for: another
            # tab, a worker, a frame whose page cannot be told is outside.
            page = _page_of(request)
            write_allowed = state.write_allowed and page is not None and page is state.write_page
            # What only an approved act or checkout opens: an order step,
            # and anything sent to an order address. The person's handoff
            # does not (the model asks for one whenever it likes), except
            # the one right after an approved checkout (3-D Secure).
            orders_open = write_allowed or (
                state.checkout_handoff and page is not None and page is state.handoff_page
            )
            if not request.is_navigation_request():
                # A page's own request (fetch, XHR, beacon, an image): one
                # that sends to an order address outside a write window is
                # stopped, and so is anything but a GET while browser.read
                # clicks; one of any method to an order step (a GET can be
                # the order), or while browser.read clicks to an order
                # address other than an order history, too.
                reason: Optional[str] = None
                if request.method not in _SAFE_METHODS and not write_allowed:
                    if state.read_click:
                        reason = READ_CLICK_REQUEST
                    elif state.changing and _order_address(url):
                        reason = ORDER_REQUEST
                    elif not orders_open and _order_address(url):
                        reason = READ_TIER_ORDER_STEP if _order_step(url) else READ_TIER_ORDER_REQUEST
                if reason is None and not orders_open:
                    if _order_step(url):
                        reason = ORDER_REQUEST if state.changing else READ_TIER_ORDER_STEP
                    elif state.read_click and _read_link(url):
                        reason = READ_CLICK_ADDRESS
                if reason is not None:
                    await self._block(route, state, url=url, reason=reason)
                    return
                await route.continue_()
                return
            if orders_open and _is_top_level(request) and not _started_by(request, page):
                # The window is the approved page's: a tab of another site
                # that holds it (window.open) may not point it anywhere
                # while the window is open, not even at a page of its own
                # that would then open an order step as the tab's own.
                await self._block(route, state, url=url, reason=OTHER_PAGE_NAVIGATION)
                return
            if state.changing and _order_address(url):
                await self._block(
                    route, state, url=url,
                    reason=ORDER_ADDRESS,
                )
                return
            if state.read_click and _read_link(url):
                await self._block(route, state, url=url, reason=READ_CLICK_ADDRESS)
                return
            if not orders_open and _order_step(url):
                await self._block(route, state, url=url, reason=READ_TIER_ORDER_STEP)
                return
            if request.method != "GET" and state.human_driving and not orders_open and _order_address(url):
                # The person's own submit passes below, but not to an order
                # address: a page may send its order form while they look.
                await self._block(route, state, url=url, reason=READ_TIER_ORDER_REQUEST)
                return
            if not _is_top_level(request):
                # A frame's own navigation is left alone, except that a
                # bound write window admits no POST from a frame to any
                # other origin (an order form aimed at a hidden iframe and
                # at another site would carry the card there unseen), and
                # no frame sends a form outside a write window, as no top
                # page does.
                if request.method != "GET" and state.write_origin is not None and _origin(url) != state.write_origin:
                    await self._block(
                        route, state, url=url,
                        reason=f"the order form tried to send its data from a frame to "
                        f"{_origin(url) or 'an unreadable address'} by {request.method}, "
                        f"not by POST to {state.write_origin}",
                    )
                    return
                if request.method != "GET" and not (write_allowed or state.human_driving):
                    await self._block(
                        route, state, url=url,
                        reason=READ_TIER_FRAME_POST,
                    )
                    return
                await route.continue_()
                return
            if request.method != "GET" and not (write_allowed or state.human_driving):
                await self._block(
                    route, state, url=url,
                    reason=READ_TIER_POST,
                )
                return
            if request.method != "GET" and state.write_origin is not None:
                if request.method != "POST" or _origin(url) != state.write_origin:
                    await self._block(
                        route, state, url=url,
                        reason=f"the order form tried to send its data to {_origin(url) or 'an unreadable address'} "
                        f"by {request.method}, not by POST to {state.write_origin}",
                    )
                    return
            reason = await asyncio.to_thread(self.check_url, url)
            if reason is not None:
                await self._block(route, state, url=url, reason=reason)
                return
            if request.method != "GET":
                if state.write_origin is None:
                    # An approved act, or the person's own submit during a
                    # handoff. Forwarded as-is; its redirect lands on a GET
                    # the browser follows unseen.
                    await route.continue_()
                    return
                await self._bound_post(route, state, url)
                return
            response = await route.fetch(max_redirects=0)
            if response.status >= 400:
                # A site's error page or bot wall, for the logs: the status
                # and whether its CDN says it challenged the request.
                logger.info(
                    "browser_document_status",
                    url=_without_query(url),
                    status=response.status,
                    challenged=bool(response.headers.get("cf-mitigated")),
                )
            location = response.headers.get("location")
            if 300 <= response.status < 400 and location:
                target = urljoin(url, location)
                reason = await asyncio.to_thread(self.check_url, target)
                if reason is None and state.changing and _order_address(target):
                    reason = ORDER_ADDRESS
                if reason is None and state.read_click and _read_link(target):
                    reason = READ_CLICK_ADDRESS
                if reason is None and not orders_open and _order_step(target):
                    reason = READ_TIER_ORDER_STEP
                if reason is not None:
                    await self._block(route, state, url=target, reason=reason, via=url)
                    return
                await route.fulfill(
                    status=200,
                    content_type="text/html; charset=utf-8",
                    body=_client_redirect(target),
                )
                return
            await route.fulfill(response=response)
        except Exception as exc:  # noqa: BLE001 - an unhandled route hangs the request forever
            logger.warning(
                "browser_egress_handler_failed",
                url=_without_query(request.url),
                error_type=type(exc).__name__,  # Playwright messages quote the full URL
            )
            try:
                await route.abort("failed")
            except Exception:  # noqa: BLE001 - already handled, or the page is gone
                pass

    async def _bound_post(self, route: "Route", state: EgressState, url: str) -> None:
        """The checkout's order POST, to the bound origin. Fetched here so
        the merchant's answer is judged before the browser acts on it: a
        307 or 308 makes a browser send the same POST again, card
        included, so one that points to another origin (or to a refused
        address) is aborted; any other redirect becomes a client-side GET
        hop, checked like every navigation; a plain answer is passed on as
        it is, its cookies included."""
        response = await route.fetch(max_redirects=0)
        location = response.headers.get("location")
        if not (300 <= response.status < 400 and location):
            await route.fulfill(response=response)
            return
        target = urljoin(url, location)
        reason = await asyncio.to_thread(self.check_url, target)
        if reason is None and response.status in (307, 308) and _origin(target) != state.write_origin:
            reason = (
                f"the site's answer to the order pointed the same POST at "
                f"{_origin(target) or 'an unreadable address'} (a {response.status} sends the card again), "
                f"not by POST to {state.write_origin}"
            )
        if reason is not None:
            await self._block(route, state, url=target, reason=reason, via=url)
            return
        if response.status in (307, 308):
            await route.fulfill(response=response)  # the same origin: the browser re-sends the POST there
            return
        headers = {"set-cookie": response.headers["set-cookie"]} if "set-cookie" in response.headers else {}
        await route.fulfill(
            status=200,
            content_type="text/html; charset=utf-8",
            headers=headers,
            body=_client_redirect(target),
        )

    async def _block(
        self, route: "Route", state: EgressState, *, url: str, reason: str, via: Optional[str] = None
    ) -> None:
        self._record(state, url=url, reason=reason, via=via)
        await route.abort("blockedbyclient")

    @staticmethod
    def _record(state: EgressState, *, url: str, reason: str, via: Optional[str] = None) -> None:
        # The toolkit reports these entries to the model: in ACCOUNT mode
        # they follow the same query/fragment stripping as every URL there.
        def shown(value: str) -> str:
            return _without_query(value) if state.account_mode else value

        entry = {"url": shown(url), "reason": reason}
        if via is not None:
            entry["via"] = shown(via)
        state.blocked.append(entry)
        logger.warning(
            "browser_egress_blocked",
            url=_without_query(url),
            reason=reason,
            via=_without_query(via) if via is not None else None,
        )

    # -- consequential clicks --------------------------------------------------

    async def consequential(self, page: "Page", ref: str) -> Optional[str]:
        """None if *ref* is safe to click at read tier; else the reason.
        Raises ``StaleRef`` when the ref is malformed or gone (≤3 s)."""
        if not isinstance(ref, str) or not _REF_PATTERN.fullmatch(ref):
            raise StaleRef("stale ref: re-snapshot (not a ref from the current snapshot)")
        try:
            facts = await page.locator(f"aria-ref={ref}").evaluate(
                _CONSEQUENTIAL_JS, timeout=_CONSEQUENTIAL_TIMEOUT_MS
            )
        except Exception as exc:  # noqa: BLE001 - TimeoutError/Error both mean "not on this page"
            raise StaleRef("stale ref: re-snapshot") from exc
        return classify_target(facts)


_DEFAULT = Guard()


def check_url(url: str) -> Optional[str]:
    return _DEFAULT.check_url(url)


async def install_egress_guard(context: "BrowserContext", *, account_mode: bool) -> None:
    await _DEFAULT.install_egress_guard(context, account_mode=account_mode)


async def consequential(page: "Page", ref: str) -> Optional[str]:
    return await _DEFAULT.consequential(page, ref)
