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
browser.read then answers ``markers.READ_CLICK_MESSAGE``. A browser.act
step that runs with no card (``EgressState.no_orders``: an errand step, a
site approval's click, for a time browser.act sets) reaches no order
address or order step by any route, its own write window included, and
sends nothing from any frame, script or socket but a GET, a request to a
cart (``CART_PATH_RE``, never one that names an order after the cart,
``CART_ORDER_RE``; a page script's only on a cart step,
``EgressState.unasked_cart``) or its own judged form
(``EgressState.unasked_sends``): an allowlist, so an order endpoint no
list knows is stopped too. A beacon (resource type ping) is held back
and not counted as the step sending (``UNASKED_HELD``). What it may send
is fetched here (``_unasked_send``), and so is every GET of a page or a
frame (``_unasked_get``, ``_navigate``), with each redirect hop judged:
a page's request goes on only to a cart or a checkout's entry page
(``CHECKOUT_ENTRY_RE``), its next hop made here; a 307/308 only to a
cart of the same site; a form's redirect is a client hop. Loopback is
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
page's image, GET fetch or beacon included, is sent to an order step's
address, and while browser.read clicks none to an address
``markers.READ_LINK_RE`` matches; a page's own GET is judged by its first
address only, though, since the browser follows its redirect unseen,
except while a step runs with no card (above). The click's window stays
open until the network is quiet (``wait_for_quiet``). A WebSocket is not
a request the route sees: ``_socket`` drops what a page sends on one
while browser.read clicks or a step runs with no card, and always on a
page's socket whose address is an order address (a socket's page cannot
be told, so it is never inside a write window). A socket a worker opens
is not routed at all (``context.route_web_socket`` sees the page's
only).

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

Security wave (S4 link reputation, S7 site rules): each toolkit hands its
``EgressHooks`` to ``_shared.attach_egress_hooks``, which binds them to the
context's ``EgressState`` for the session's user, so no hook is module
state. A top-level navigation and every client-hop redirect target then
pass the owner's site rules (``_site_reason``, after ``check_url``) and the
link lookup (``_reputation_reason``), in that order, before the order
checks; a frame's navigation passes the site rules only, and the bound
order POST's redirect the lookup only. A hook that raises blocks with its
named reason (``SITE_RULES_FAILED``, ``NAVIGATION_CHECK_FAILED``). Without
hooks every path behaves as before.
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
from typing import TYPE_CHECKING, Any, Awaitable, Callable, Literal, Optional, Protocol
from urllib.parse import urljoin, urlsplit, urlunsplit

import structlog

# The same blocked-range table check_ssrf applies, used on the one
# resolution this module makes (see Guard.check_url).
from core.network_security import _blocked_network_for
from services.tools.browser.checkout.markers import ORDER_ACTION_RE, ORDER_STEP_RE, READ_LINK_RE

if TYPE_CHECKING:
    from playwright.async_api import BrowserContext, Page, Request, Response, Route, WebSocketRoute

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
# Of those names, the ones that on a plain link (an http(s) <a href> to
# another page, with no script or role of its own) only say where the link
# leads: "Buy tickets for 7:15 PM" and "Order online" open a page by GET.
# Such a link is not held back for its words: the purchase rules judge its
# address next (markers.read_click_pays leaves an order path to an act), and
# the click window lets no request but a GET and no order address through.
# A link worded as an act (confirm, delete, accept, send, sign up, pay)
# keeps the rule: a GET can do those.
_LINK_NAVIGATION_NAMES = frozenset({"buy", "order"})
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
# Why something was stopped while a step ran with no card
# (``EgressState.no_orders``): browser.act then answers that the step
# asks first.
UNASKED_ORDER = "a step taken without asking tried to reach an order address"
UNASKED_REQUEST = "a step taken without asking tried to send a request"
UNASKED_REASONS: frozenset[str] = frozenset({UNASKED_ORDER, UNASKED_REQUEST})
# Why a page's beacon (navigator.sendBeacon, an <a ping>: resource type
# "ping"), or its POST to another site than its own (an analytics or ad
# host), was stopped while a step ran with no card. Not the step's own
# doing on the site: it is held back and is no reason to say the step
# tried to send.
UNASKED_HELD = "a background request was held back while a step ran without asking"
# A cart's own address, judged by its path: a cart segment (/cart,
# /cart/change.js, /gp/cart/view.html, Amazon's /gp/add-to-cart/json,
# /api/cart_items), a basket, a bag or a trolley, and Amazon's buy box
# form (/gp/product/handle-buy-box/), which adds to the cart. What a
# quantity or an "Add to cart" sends to while it runs unasked.
CART_PATH_RE = re.compile(
    r"(?:[/-]cart|/(?:basket|bag|trolley)|/handle-buy-box)(?![a-z0-9])", re.IGNORECASE
)
# A cart address with an order verb after the cart (/cart/complete,
# /basket/confirm, /cart/payment-information, /api/cart/place): an order
# sent to a cart-looking address, never a cart. Judged on the path and
# query.
CART_ORDER_RE = re.compile(
    CART_PATH_RE.pattern + r".*?(?<![a-z])(?:complete|submit|confirm|place|finali[sz]e|process|pay|charge)",
    re.IGNORECASE,
)
# The most redirects the guard follows for one request itself (Chrome's
# own limit): past it the request fails, as it would in the browser.
_MAX_HOPS = 20
# A checkout's entry page, which a cart's form answers with and which only
# shows the order to review (Amazon's /gp/buy/spc/handlers/display.html,
# /checkout/entry, Shopify's /checkouts/...): opening it orders nothing.
CHECKOUT_ENTRY_RE = re.compile(
    r"/gp/buy/spc/handlers/display\.html|/checkout/entry(?=[/?#;]|$)|/checkouts/", re.IGNORECASE
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
  // A plain link, as the purchase rules define one (markers._JUDGE_FN): an
  // http(s) link to another page with no script, role or download of its own.
  let plain_link = false;
  if ((tag === 'a' || tag === 'area') && el.hasAttribute('href')) {
    try {
      const to = new URL(el.getAttribute('href') || '', document.baseURI);
      const here = new URL(document.location.href);
      const samePage = to.origin === here.origin && to.pathname === here.pathname && to.search === here.search;
      plain_link = (to.protocol === 'https:' || to.protocol === 'http:') && !samePage && !role
        && !el.hasAttribute('onclick') && !el.hasAttribute('download');
    } catch (e) { plain_link = false; }
  }
  return {tag, type, name, submit, in_form: !!form, method, sensitive, buttonish, plain_link};
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
    words = [
        re.sub(r"[\s-]+|(?<=sign)(?=up)", " ", match.group(1).lower())
        for match in _NAME_PATTERN.finditer(facts.get("name") or "")
    ]
    if facts.get("plain_link") is True:
        # Where a plain link leads is not a reason to hold it (see
        # _LINK_NAVIGATION_NAMES); any other consequential word is.
        words = [word for word in words if word not in _LINK_NAVIGATION_NAMES]
    if words:
        return "name matches: " + words[0]
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
    form while the person looks. A top-level POST's order address is then
    judged by its path only, since a sign-in on the way to checkout names
    where it goes next in its query (?next=/checkout/payment/); an order
    step is still judged by the whole address. ``checkout_handoff`` is set with it only
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
    ``in_flight`` and ``last_request`` are what ``wait_for_quiet`` reads.

    ``site_rules`` and ``reputation`` are the security wave's hooks for this
    context's user (``EgressHooks``, attached by the toolkits): the owner's
    site rules (``SiteRuleHook``) and the link lookup (``NavigationCheck``).
    None runs neither. ``notes`` collects what a hook noticed without
    blocking (``{"kind", "text"}``), which browser.read hands back."""

    account_mode: bool
    # The context's Chrome goes through the egress proxy (egress_proxy.py):
    # a read-tier page whose fetch here met a bot wall is loaded by Chrome.
    proxied: bool = False
    write_allowed: bool = False
    write_origin: Optional[str] = None
    write_page: Any = None
    human_driving: bool = False
    checkout_handoff: bool = False
    handoff_page: Any = None
    changing: bool = False
    read_click: bool = False
    # Set by browser.act around a step that runs with no card (an errand
    # step, a site approval's click), until its page has gone quiet (a
    # plain link: until its page commits a new document): no request,
    # navigation or socket message of any frame reaches an order address
    # or an order step (a checkout's entry page opens by GET), its write
    # window open or not; nothing is sent but to a cart (``CART_PATH_RE``,
    # never ``CART_ORDER_RE``; a page script only on a cart step,
    # ``unasked_cart``) or, by a form, to ``unasked_sends``; a beacon is
    # held back (``UNASKED_HELD``); and what may go, and every GET of a
    # page or a frame, is fetched here with each redirect hop judged
    # (``UNASKED_REASONS``).
    no_orders: bool = False
    # The paths an unasked step's own form may send to besides a cart: the
    # form the toolkit judged it by, a cart button's or a cookie banner's.
    unasked_sends: frozenset[str] = frozenset()
    # Whether the unasked step is itself a cart step (cart words, a
    # quantity): only then may a page script send to a cart.
    unasked_cart: bool = False
    # How many sends an unasked step was let make went out (``_unasked_send``):
    # browser.act tells by it that the step itself went through.
    unasked_went: int = 0
    blocked: list[dict[str, str]] = field(default_factory=list)
    in_flight: set[Any] = field(default_factory=set)
    last_request: float = 0.0
    # Security wave: the hooks bound to this context (see the docstring).
    site_rules: Any = None
    reputation: Any = None
    # Non-blocking notes for the toolkit to pass on, {"kind", "text"} (security wave: S4 link
    # reputation, S7 site rules); browser.read open() and click() return the ones added during
    # their navigation as security_notes.
    notes: list[dict[str, str]] = field(default_factory=list)
    # The page's own data requests its own site refused (``_data_refused``):
    # page -> [(host/path of the page when it asked, HTTP status)]. What tells
    # that a site turned the browser away at a step (a seat map, a cart)
    # while the page itself loaded.
    data_refusals: "weakref.WeakKeyDictionary[Any, list[tuple[str, int]]]" = field(
        default_factory=weakref.WeakKeyDictionary
    )


# The answers to a page's own data request that mean its site would not
# give it the data: not a sign-in (401), which a person can clear.
_REFUSED_DATA = frozenset({403, 404, 410, 429})
_DATA_REFUSALS_KEPT = 20


def page_place(url: str) -> str:
    """``host/path`` of *url*, lower-case host: the same page whatever its
    query and fragment say (a single-page app rewrites them as it goes)."""
    try:
        parts = urlsplit(url)
    except ValueError:
        return ""
    return f"{(parts.hostname or '').lower()}{parts.path}"


def _data_refused(state: EgressState, response: "Response") -> None:
    """Record *response* when it is a page's own fetch or XHR to the page's
    own host that the site refused (``_REFUSED_DATA`` or a server error)."""
    try:
        request = response.request
        if request.resource_type not in ("fetch", "xhr"):
            return
        status = response.status
        if status not in _REFUSED_DATA and status < 500:
            return
        page = request.frame.page
        page_url = page.url
        if (urlsplit(response.url).hostname or "").lower() != (urlsplit(page_url).hostname or "").lower():
            return
    except Exception:  # noqa: BLE001 - a worker's request has no frame; nothing to record
        return
    seen = state.data_refusals.setdefault(page, [])
    seen.append((page_place(page_url), status))
    del seen[:-_DATA_REFUSALS_KEPT]


def data_refusals(context: "BrowserContext", page: Any) -> list[int]:
    """The statuses with which *page*'s own site refused its data requests
    while it showed the page it shows now; [] without a guard."""
    state = _STATES.get(context)
    if state is None:
        return []
    here = page_place(page.url)
    return [status for place, status in state.data_refusals.get(page, ()) if place == here]


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


def _path(url: str) -> str:
    try:
        return urlsplit(url).path
    except ValueError:
        return ""


def _cart_order(url: str) -> bool:
    """Whether *url* is a cart address that names an order after the cart
    (``CART_ORDER_RE``, on its path and query)."""
    try:
        parts = urlsplit(url)
    except ValueError:
        return True
    return bool(CART_ORDER_RE.search(parts.path + ("?" + parts.query if parts.query else "")))


def _cart(url: str) -> bool:
    """Whether *url* is a cart's own address (and names no order)."""
    return bool(CART_PATH_RE.search(_path(url))) and not _cart_order(url)


def _unasked_may_send(state: EgressState, url: str, *, form: bool) -> bool:
    """Whether a step with no card may send to *url*: for a form (a
    navigation of any frame) a cart or the path the toolkit judged it by,
    for a page script a cart while the step itself is a cart step."""
    # A form gets the cart exemption only on a cart step too: a "Show more"
    # button's script submitting a hidden form to a cart path is no cart step.
    return (state.unasked_cart and _cart(url)) or (form and _path(url) in state.unasked_sends)


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


# What a bot wall answers a client it will not serve.
_WALL_STATUSES = frozenset({403, 429, 503})
# The sites whose bot wall refuses the guard's fetch where Chrome gets the
# page, and whose pages Chrome may load itself. Only a short list: the
# redirects Chrome then follows are judged by the egress proxy for their
# address only, never for order steps, site rules or the link lookup, so
# any other site (one that walls the fetch on purpose, then redirects
# Chrome to a shop's order step with its cookies) keeps the guard's fetch.
# ponytail: a fixed list; judging Chrome's own redirects at the protocol
# level (CDP Fetch at the response stage) would let every site load.
_CHROME_LOADS_WALLS = frozenset({
    "amazon.com", "amctheatres.com", "walmart.com", "target.com", "bestbuy.com", "homedepot.com",
    "lowes.com", "costco.com", "regmovies.com", "fandango.com", "ticketmaster.com", "ebay.com",
})


def _chrome_may_load(
    state: "EgressState", orders_open: bool, checkout_window: bool, url: str = ""
) -> bool:
    """Whether a walled top-level GET to *url* may be loaded by Chrome
    itself, its redirects unseen here: only through the egress proxy, only
    on a site of ``_CHROME_LOADS_WALLS``, and only on a plain read (no order
    or checkout window, no write window, no step with no card, no
    browser.read click, no change, no handoff)."""
    from services.security.lookalike import registrable_domain

    site = registrable_domain(urlsplit(url).hostname or "")
    return state.proxied and site in _CHROME_LOADS_WALLS and not (
        orders_open or checkout_window or state.write_allowed or state.no_orders
        or state.read_click or state.changing or state.human_driving
    )


def _frame_or_page(request: Any, page: Any) -> Any:
    """What a request's own site is read from: its frame (a URL), else its
    page."""
    frame = getattr(request, "frame", None)
    return frame if isinstance(getattr(frame, "url", None), str) else page


def _other_site(url: str, page: Any) -> bool:
    """Whether *url* is on another site (registrable domain) than *page*'s
    own: an analytics or ad host that a page's script posts to on every
    click. False when the page cannot be told (a worker's request)."""
    from services.security.lookalike import registrable_domain

    try:
        mine = registrable_domain(urlsplit(str(page.url)).hostname or "") if page is not None else ""
    except Exception:  # noqa: BLE001 - a page that is gone cannot be told
        return False
    theirs = registrable_domain(urlsplit(url).hostname or "")
    return bool(mine and theirs and mine != theirs)


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

# Security wave (S4, S7): the hooks a navigation passes after check_url.
# A link lookup for one URL: its block reason, or None.
NavigationCheck = Callable[[str, "EgressState"], Awaitable[Optional[str]]]


@dataclass(frozen=True)
class PageNotice:
    """What the owner's site rules say about the page a read is about to
    describe: ``blocked`` (the page is blanked and nothing is described) or
    ``always_ask`` (described, with *text* added as a notice)."""

    kind: Literal["blocked", "always_ask"]
    rule: str
    text: str


class SiteRuleHook(Protocol):
    """The owner's site rules for one user (security S7). Pure and in memory;
    *exempt* is True inside an approved checkout's window (the order POST and
    the 3-D Secure hand-off right after it)."""

    def navigation_reason(self, url: str, *, exempt: bool) -> Optional[str]: ...

    def page_notice(self, url: str, *, exempt: bool) -> Optional[PageNotice]: ...


@dataclass(frozen=True)
class EgressHooks:
    """Per-user hook factories a toolkit binds to each context it guards
    (``_shared.attach_egress_hooks``): ``site_rules(user_id)`` (S7) and
    ``reputation(user_id)`` (S4). Either may be None; with neither, the
    guard behaves exactly as before."""

    site_rules: Optional[Callable[[str], SiteRuleHook]] = None
    reputation: Optional[Callable[[str], NavigationCheck]] = None


# Why a navigation was stopped when a hook itself failed: an unread rule
# must not let a Blocked site open. Neither joins SENDING_REASONS or
# READ_CLICK_REASONS: nothing was sent, and no click caused it.
SITE_RULES_FAILED = "the owner's site rules could not be checked"
NAVIGATION_CHECK_FAILED = "a safety check on this address could not run"


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
        return self.checked_addresses(host)[0]

    def checked_addresses(self, host: str) -> tuple[Optional[str], list[str]]:
        """``(None, addresses)``: *host* resolved once and every address
        allowed, to be connected to as they are (services/tools/browser/
        egress_proxy.py); else ``(reason, [])``."""
        if _loopback_allowed() and self._all_loopback(host):
            return None, self._addresses(host) or ["127.0.0.1"]
        addresses = self._addresses(host)
        if not addresses:
            return f"could not resolve {host}", []
        for address in addresses:
            try:
                ip = ipaddress.ip_address(address)
            except ValueError:
                return f"could not resolve {host} to an address", []
            if _blocked_network_for(ip) is not None:
                return f"{host} resolves to a private or local address ({address})", []
        return None, addresses

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
        state = EgressState(account_mode=account_mode, proxied=getattr(context, "_crawler_proxy", None) is not None)
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

        def responded(response: "Response") -> None:
            _data_refused(state, response)

        context.on("close", closed)
        context.on("request", started)
        context.on("requestfinished", ended)
        context.on("requestfailed", ended)
        context.on("response", responded)
        await context.route("**/*", handler)
        await context.route_web_socket(lambda _url: True, socket_opened)

    def _socket(self, ws: "WebSocketRoute", state: EgressState) -> None:
        """A page's WebSocket, connected through to its server. What the
        page sends on it is dropped while browser.read clicks, while a
        step runs with no card (a shop that runs every click over one
        socket, Phoenix LiveView or Blazor Server, would send the step's
        order there; recorded like a stopped request, so the step asks
        first next time), and always when the socket's address is an order
        address: a socket's page cannot be told, so no write window is ever
        open for it. What the server sends passes untouched. A worker's
        socket never comes here (see the module's notes)."""
        server = ws.connect_to_server()
        order = _order_address(ws.url)

        def from_page(message: "str | bytes") -> None:
            if state.read_click:
                self._record(state, url=ws.url, reason=READ_CLICK_REQUEST)
            elif state.no_orders:
                self._record(state, url=ws.url, reason=UNASKED_ORDER if order else UNASKED_REQUEST)
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
            # Security wave (S7, review SEC-F4): an approved checkout's
            # window (the bound order POST, the 3-D Secure hand-off right
            # after it), where the site rules exempt only protected and bank
            # hosts. browser.act's window and an ordinary hand-off are not.
            checkout_window = (write_allowed and state.write_origin is not None) or (
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
                sending = request.method not in _SAFE_METHODS
                if reason is None and state.no_orders:
                    # A step with no card: no order address, no beacon,
                    # and nothing sent but to a cart, its window open or not.
                    if _order_step(url) or (sending and (_order_address(url) or _cart_order(url))):
                        reason = UNASKED_ORDER
                    elif sending and getattr(request, "resource_type", "") == "ping":
                        reason = UNASKED_HELD
                    elif sending and not _unasked_may_send(state, url, form=False):
                        # Sent to another site than its own frame's (an
                        # analytics host): held back, not the step's doing.
                        # A widget's frame posting to its own site counts.
                        reason = UNASKED_HELD if _other_site(url, _frame_or_page(request, page)) else UNASKED_REQUEST
                if reason is None and not orders_open:
                    if _order_step(url):
                        reason = ORDER_REQUEST if state.changing else READ_TIER_ORDER_STEP
                    elif state.read_click and _read_link(url):
                        reason = READ_CLICK_ADDRESS
                if reason is not None:
                    await self._block(route, state, url=url, reason=reason)
                    return
                if sending and state.no_orders:
                    await self._unasked_send(route, state, url, navigation=False)
                    return
                if request.method == "GET" and state.no_orders:
                    await self._unasked_get(route, state, url)
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
            if state.no_orders and (
                # An entry page is a step only when it is not itself an
                # order step: /checkouts/abc/place-order sits under the prefix.
                _order_step(url)
                or (_order_address(url) and not (request.method == "GET" and CHECKOUT_ENTRY_RE.search(_path(url))))
                or (request.method != "GET" and _cart_order(url))
            ):
                await self._block(route, state, url=url, reason=UNASKED_ORDER)
                return
            if state.no_orders and request.method != "GET" and not _unasked_may_send(
                state, url, form=True
            ):
                await self._block(route, state, url=url, reason=UNASKED_REQUEST)
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
            if request.method != "GET" and state.human_driving and not orders_open and _order_address(
                _without_query(url) if _is_top_level(request) else url
            ):
                # The person's own submit passes below, but not to an order
                # address: a page may send its order form while they look.
                # Their top-level POST is judged by its path: a sign-in's
                # query names where it goes next (?next=/checkout/payment/).
                await self._block(route, state, url=url, reason=READ_TIER_ORDER_REQUEST)
                return
            if not _is_top_level(request):
                # Security wave (S7): a frame never loads a site the owner
                # blocked (the link lookup is for top-level pages only).
                reason = self._site_reason(state, url, exempt=checkout_window)
                if reason is not None:
                    await self._block(route, state, url=url, reason=reason)
                    return
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
                if request.method != "GET" and state.no_orders:
                    await self._unasked_send(route, state, url, navigation=True)
                    return
                if state.no_orders:
                    # The browser would follow its redirect unseen.
                    await self._navigate(
                        route, state, url, orders_open=orders_open, checkout_window=checkout_window, top=False
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
            if reason is None:
                reason = self._site_reason(state, url, exempt=checkout_window)
            if reason is None:
                reason = await self._reputation_reason(state, url)
            if reason is not None:
                await self._block(route, state, url=url, reason=reason)
                return
            if request.method != "GET" and state.no_orders and state.write_origin is None:
                await self._unasked_send(route, state, url, navigation=True)
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
            await self._navigate(route, state, url, orders_open=orders_open, checkout_window=checkout_window, top=True)
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

    async def _navigate(
        self, route: "Route", state: EgressState, url: str, *, orders_open: bool, checkout_window: bool, top: bool
    ) -> None:
        """A GET navigation the guard admitted (a top-level page; a frame's
        while a step runs with no card), fetched here with its redirect
        held: a 3xx becomes a client hop, which comes back through here and
        is judged like every navigation of its frame, once its target
        passed ``check_url``, the owner's site rules, the link lookup (a
        top-level page only) and the order checks. A plain answer is handed
        to the browser as it is."""
        response = await route.fetch(max_redirects=0)
        if top and response.status >= 400:
            # A site's error page or bot wall, for the logs: the status
            # and whether its CDN says it challenged the request.
            logger.info(
                "browser_document_status",
                url=_without_query(url),
                status=response.status,
                challenged=bool(response.headers.get("cf-mitigated")),
            )
        if top and response.status in _WALL_STATUSES and _chrome_may_load(state, orders_open, checkout_window, url):
            # The fetch here is not Chrome on the wire, and a bot wall
            # refuses it where Chrome gets the page (AMC's Cloudflare,
            # Amazon's search). A read-tier page is loaded by Chrome itself
            # through the egress proxy, which keeps every hop off private
            # addresses; no order window, write window or unasked step is
            # open, so no hop can carry anything.
            logger.info("browser_wall_loaded_by_chrome", url=_without_query(url), status=response.status)
            await route.continue_()
            return
        location = response.headers.get("location")
        if not (300 <= response.status < 400 and location):
            await route.fulfill(response=response)
            return
        target = urljoin(url, location)
        reason = await asyncio.to_thread(self.check_url, target)
        if reason is None:
            reason = self._site_reason(state, target, exempt=checkout_window)
        if reason is None and top:
            reason = await self._reputation_reason(state, target)
        if reason is None and state.no_orders and (
            _order_step(target)
            or (_order_address(target) and not CHECKOUT_ENTRY_RE.search(_path(target)))
        ):
            reason = UNASKED_ORDER
        if reason is None and state.changing and _order_address(target):
            reason = ORDER_ADDRESS
        if reason is None and state.read_click and _read_link(target):
            reason = READ_CLICK_ADDRESS
        if reason is None and not orders_open and _order_step(target):
            reason = READ_TIER_ORDER_STEP
        if reason is not None:
            await self._block(route, state, url=target, reason=reason, via=url)
            return
        await route.fulfill(status=200, content_type="text/html; charset=utf-8", body=_client_redirect(target))

    async def _unasked_get(self, route: "Route", state: EgressState, url: str) -> None:
        """A page's own GET (an image, a script, a GET fetch) while a step
        runs with no card, fetched here hop by hop: the browser would follow
        its redirect unseen (Playwright routes a request's first URL only).
        Each hop is judged as its first address was (no order step, and no
        address ``check_url`` refuses), and the last answer is handed to
        the browser as the request's own."""
        response = await route.fetch(max_redirects=0)
        hop = url
        for _ in range(_MAX_HOPS):
            location = response.headers.get("location")
            if not (300 <= response.status < 400 and location):
                await route.fulfill(response=response)
                return
            hop = urljoin(hop, location)
            reason = UNASKED_ORDER if _order_step(hop) else await asyncio.to_thread(self.check_url, hop)
            if reason is not None:
                await self._block(route, state, url=hop, reason=reason, via=url)
                return
            response = await route.fetch(url=hop, max_redirects=0)
        await route.abort("failed")  # a redirect loop, as the browser would end it

    async def _unasked_send(
        self, route: "Route", state: EgressState, url: str, *, navigation: bool
    ) -> None:
        """What a step with no card may send (a cart, its own judged form),
        fetched here since the browser would follow its redirect unseen
        (Playwright routes a request's first URL only); its going out is
        counted (``unasked_went``). A 307/308, the same request sent
        again, may only go on to a cart of the same site, sent from here.
        A redirect to an order address or an order step is stopped, except
        that a cart's redirect to a checkout's entry page
        (``CHECKOUT_ENTRY_RE``) is the next page. Any other redirect of a
        navigation becomes a client hop, judged like every navigation; a
        page request's goes on only to a cart or a checkout's entry page,
        its GET made here, hop after hop. The last answer is handed to the
        browser as it is, cookies included."""
        response = await route.fetch(max_redirects=0)
        state.unasked_went += 1
        hop = url
        for _ in range(_MAX_HOPS):
            location = response.headers.get("location")
            if not (300 <= response.status < 400 and location):
                await route.fulfill(response=response)
                return
            target = urljoin(hop, location)
            entry = bool(CART_PATH_RE.search(_path(hop)) and CHECKOUT_ENTRY_RE.search(_path(target)))
            again = response.status in (307, 308)
            reason: Optional[str] = None
            if again and not (_origin(target) == _origin(hop) and _cart(target)):
                reason = UNASKED_ORDER
            elif _order_step(target) or _cart_order(target) or (_order_address(target) and not entry):
                reason = UNASKED_ORDER
            elif not (again or navigation or entry or _cart(target)):
                reason = UNASKED_REQUEST
            if reason is None and navigation and not again:
                headers = response.headers
                cookies = {"set-cookie": headers["set-cookie"]} if "set-cookie" in headers else {}
                await route.fulfill(
                    status=200, content_type="text/html; charset=utf-8", headers=cookies,
                    body=_client_redirect(target),
                )
                return
            if reason is None:  # the next hop is made from here
                reason = await asyncio.to_thread(self.check_url, target)
            if reason is not None:
                await self._block(route, state, url=target, reason=reason, via=url)
                return
            if again:
                response = await route.fetch(url=target, max_redirects=0)
            else:
                response = await route.fetch(url=target, method="GET", post_data=b"", max_redirects=0)
            hop = target
        await route.abort("failed")  # a redirect loop, as the browser would end it

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
        if reason is None:
            # Security wave (S4): the merchant's redirect after the order is
            # looked up too (it is always inside the checkout window, so the
            # site rules are left to the navigation it becomes).
            reason = await self._reputation_reason(state, target)
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

    def _site_reason(self, state: EgressState, url: str, *, exempt: bool) -> Optional[str]:
        """The owner's site rules' block reason for *url*, or None (no hook
        attached: None). A hook that raises blocks: an unread rule list
        must not let a Blocked site open (an exception escaping ``_route``
        would abort the navigation silently instead)."""
        hook = getattr(state, "site_rules", None)
        if hook is None:
            return None
        try:
            reason = hook.navigation_reason(url, exempt=exempt)
        except Exception as exc:  # noqa: BLE001 - fail closed with a named reason
            logger.warning(
                "browser_site_rules_failed",
                url=_without_query(url),
                error_type=type(exc).__name__,
            )
            return SITE_RULES_FAILED
        return reason if isinstance(reason, str) and reason else None

    async def _reputation_reason(self, state: EgressState, url: str) -> Optional[str]:
        """The link lookup's block reason for *url*, or None (no hook
        attached: None). The lookup owns its own failure policy (it fails
        open on a slow or broken service); one that raises anyway blocks
        here with a named reason."""
        check = getattr(state, "reputation", None)
        if check is None:
            return None
        try:
            reason = await check(url, state)
        except Exception as exc:  # noqa: BLE001 - fail closed with a named reason
            logger.warning(
                "browser_navigation_check_failed",
                url=_without_query(url),
                error_type=type(exc).__name__,
            )
            return NAVIGATION_CHECK_FAILED
        return reason if isinstance(reason, str) and reason else None

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
