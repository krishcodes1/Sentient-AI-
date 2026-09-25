"""Egress and consequential-action checks for the browser (spec §6, §9).

Three gates: ``check_url`` on every model-supplied URL before a goto; a
``context.route`` handler that re-checks every top-level navigation the
browser makes on its own (redirects, links) and aborts non-GET top-level
navigations from read-tier actions; and ``consequential(page, ref)``, the
live-page facts that decide whether a click is a read. Loopback is
allowed only under ``CRAWLER_ALLOW_LOOPBACK_FOR_TESTS=1`` (the fake
site), read at call time, never in production paths.
"""

from __future__ import annotations

import asyncio
import html
import ipaddress
import os
import re
import socket
import weakref
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Callable, Optional
from urllib.parse import urljoin, urlsplit, urlunsplit

import structlog

# The same blocked-range table check_ssrf applies, used on the one
# resolution this module makes (see Guard.check_url).
from core.network_security import _blocked_network_for

if TYPE_CHECKING:
    from playwright.async_api import BrowserContext, Page, Request, Route

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
_CONSEQUENTIAL_TIMEOUT_MS = 3000


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
    tier around one approved action (phase 3); ``blocked`` is the audit
    trail the toolkit and the tests read."""

    account_mode: bool
    write_allowed: bool = False
    blocked: list[dict[str, str]] = field(default_factory=list)


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

        await context.route("**/*", handler)

    async def _route(self, route: "Route", request: "Request", state: EgressState) -> None:
        try:
            if not request.is_navigation_request() or not _is_top_level(request):
                await route.continue_()
                return
            url = request.url
            if request.method != "GET" and not state.write_allowed:
                await self._block(
                    route, state, url=url,
                    reason="non-GET top-level navigation from a read-tier action",
                )
                return
            reason = await asyncio.to_thread(self.check_url, url)
            if reason is not None:
                await self._block(route, state, url=url, reason=reason)
                return
            if request.method != "GET":
                # An approved write. Forwarded as-is; its redirect lands on a
                # GET the browser follows unseen (phase 3 tightens this).
                await route.continue_()
                return
            response = await route.fetch(max_redirects=0)
            location = response.headers.get("location")
            if 300 <= response.status < 400 and location:
                target = urljoin(url, location)
                reason = await asyncio.to_thread(self.check_url, target)
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

    async def _block(
        self, route: "Route", state: EgressState, *, url: str, reason: str, via: Optional[str] = None
    ) -> None:
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
        await route.abort("blockedbyclient")

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
