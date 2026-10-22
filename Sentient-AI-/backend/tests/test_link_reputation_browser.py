"""Tests for LinkReputation.navigation_check, the browser guard's reputation step: they prove a
site Google lists gets Google's hedged advisory as the block reason (also inside a checkout's
3-D Secure hand-off), a lookup error or timeout lets the navigation through with a "not
checked" note, an owner without a key gets neither a delay nor a note except for look-alike
letters, look-alike letters only ever add a note and that note passes PromptGuard unredacted,
sign-in and CAPTCHA hosts are never looked up while google.com itself still is, only the page's
scheme and host are sent, the reason is in neither of the guard's pinned reason vocabularies,
notes are not repeated within one browser context, a listed parent blocks a host written with
characters DNS names do not use, an address the hook cannot read is noted as not checked, and
the hook never raises. Through the real
guard (EgressHooks, scaffold A1) they prove the lookup runs only after the SSRF check and the
owner's site rules passed, aborts a top-level navigation, a redirect hop and the order POST's
redirect to a listed site, never runs for a page's own requests or its frames, still runs for
a host the owner trusts, and that browser.read's open and click hand back the notes of their
own navigation (and work with a guard double that has no state).

Why it exists: an exception escaping the guard's route handler aborts the navigation, which
would turn "Google is down" into "block"; a block that is not a Google listing would stop
legitimate pages; and a note with a raw mixed-script host would be redacted whole by
PromptGuard before the model reads it (review SEC-F12). No browser and no network: the guard's
route handler is driven with request and route doubles (copied from tests/test_browser_guard.py,
not imported, so pytest does not collect that module twice), check_ssrf is replaced and
MockTransport answers for Google.
"""

from __future__ import annotations

import asyncio
from collections.abc import Iterator
from dataclasses import dataclass, field
from types import SimpleNamespace
from typing import Any, Optional
from urllib.parse import urlsplit

import httpx
import pytest

import core.network_security as netsec
from services.agent.prompt_guard import PromptGuard
from services.reputation import links
from services.reputation.links import LinkReputation
from services.tools.browser import _shared
from services.tools.browser import actions as browser_actions
from services.tools.browser import guard as browser_guard
from services.tools.browser.actions import BrowserReadToolkit
from services.tools.browser.session import TaskState

KEY = "AIza" + "FAKEfake" * 4 + "000"
PUBLIC_IP = "203.0.113.10"
EVIL_PAGE = "https://paypa1-verify.xyz/login?session=abc123#step2"


@pytest.fixture(autouse=True)
def no_dns(monkeypatch) -> Iterator[None]:
    def fake_check_ssrf(url: str) -> netsec.SSRFCheckResult:
        return netsec.SSRFCheckResult(safe=True, resolved_ip=PUBLIC_IP, resolved_ips=(PUBLIC_IP,))

    monkeypatch.setattr(netsec, "check_ssrf", fake_check_ssrf)
    monkeypatch.setattr(links, "DEFAULT_TRANSPORT", None)
    yield


@dataclass
class State:
    """The fields of the guard's EgressState the hook reads or writes."""
    notes: list[dict[str, str]] = field(default_factory=list)
    checkout_handoff: bool = False
    account_mode: bool = True


@dataclass
class Status:
    effective: str
    reason: str = ""


class Source:
    def __init__(self, keys: Optional[dict[str, str]] = None, effective: str = "on") -> None:
        self.keys = {"safe_browsing": KEY} if keys is None else keys
        self.effective = effective

    async def service_key(self, name: str) -> Optional[str]:
        return self.keys.get(name)

    async def capability_statuses(self):
        return {"link_reputation": Status(self.effective)}

    async def capability_settings(self, key: str) -> dict[str, Any]:
        return {"lookups_per_minute": 60, "lookups_per_day": 2000}


class Google:
    """Safe Browsing behind MockTransport: hosts in ``listed`` match, everything is recorded."""

    def __init__(self) -> None:
        self.listed: dict[str, tuple[str, ...]] = {}
        self.sent: list[str] = []
        self.fail: Optional[Any] = None
        self.gate: Optional[asyncio.Event] = None

    async def handler(self, request: httpx.Request) -> httpx.Response:
        import json

        entries = [e["url"] for e in json.loads(request.content)["threatInfo"]["threatEntries"]]
        self.sent += entries
        if self.gate is not None:
            await self.gate.wait()
        if isinstance(self.fail, Exception):
            raise self.fail
        if self.fail is not None:
            return self.fail
        matches = [{"threatType": kind, "threat": {"url": url}}
                   for url in entries for kind in self.listed.get(url, ())]
        return httpx.Response(200, json={"matches": matches} if matches else {})


def reputation(google: Google, source: Optional[Source] = None) -> LinkReputation:
    return LinkReputation(source or Source(), transport=httpx.MockTransport(google.handler))


@pytest.mark.asyncio
async def test_a_listed_site_returns_googles_advisory_as_the_block_reason():
    google = Google()
    google.listed["https://paypa1-verify.xyz/"] = ("SOCIAL_ENGINEERING",)
    state = State()
    reason = await reputation(google).navigation_check(EVIL_PAGE, state)
    assert reason == (
        "Google Safe Browsing says this site may be phishing or a scam (advisory provided by Google)"
    )
    assert f"Refusing to open https://paypa1-verify.xyz/: {reason}." == (
        "Refusing to open https://paypa1-verify.xyz/: Google Safe Browsing says this site may be "
        "phishing or a scam (advisory provided by Google)."
    )


@pytest.mark.asyncio
async def test_browser_lookups_send_only_the_scheme_and_host_of_the_page():
    google = Google()
    await reputation(google).navigation_check(
        "https://bank.example.org:8443/oauth/callback?code=s3cr3t&state=xyz#frag", State()
    )
    assert google.sent == ["https://bank.example.org:8443/"]


@pytest.mark.asyncio
async def test_a_reputation_error_or_timeout_lets_the_navigation_through_and_notes_it_was_not_checked(
    monkeypatch,
):
    google = Google()
    google.fail = httpx.Response(503)
    state = State()
    assert await reputation(google).navigation_check("https://shop.example.org/", state) is None
    assert state.notes == [{
        "kind": "link_not_checked",
        "text": "This site was not checked against Google Safe Browsing "
                "(Google could not be reached).",
    }]

    monkeypatch.setattr(links, "BROWSER_TIMEOUT_S", 0.01)
    slow = Google()
    slow.gate = asyncio.Event()
    state = State()
    rep = reputation(slow)
    assert await rep.navigation_check("https://slow.example.org/", state) is None
    (note,) = state.notes
    assert note["kind"] == "link_not_checked"
    assert note["text"].endswith("(Google did not answer in time).")
    slow.gate.set()
    await asyncio.gather(*rep._tasks)
    # The lookup the page did not wait for still lands in the cache for the next hop.
    assert rep.cached_report("https://slow.example.org/", purpose="browser") is not None


@pytest.mark.asyncio
async def test_the_hook_never_raises_and_fails_open_with_a_note(monkeypatch):
    rep = reputation(Google())

    async def boom(*_a, **_k):
        raise RuntimeError("internal")

    monkeypatch.setattr(rep, "check_one", boom)
    state = State()
    assert await rep.navigation_check("https://shop.example.org/", state) is None
    assert state.notes[0]["kind"] == "link_not_checked"
    assert await rep.navigation_check("https://shop.example.org/", None) is None


@pytest.mark.asyncio
async def test_without_a_key_navigation_is_never_delayed_or_noted_except_for_look_alike_letters():
    google = Google()
    rep = reputation(google, Source(keys={}, effective="blocked"))
    state = State()
    for url in ("https://shop.example.org/", "https://bit.ly/x", "https://invoice.xyz/",
                "https://amazon.shop/"):
        assert await rep.navigation_check(url, state) is None
    assert state.notes == [] and google.sent == []
    assert await rep.navigation_check("https://pаypal.com/", state) is None
    assert [n["kind"] for n in state.notes] == ["link_suspicious"]
    off = reputation(google, Source(effective="off"))
    quiet = State()
    assert await off.navigation_check("https://shop.example.org/", quiet) is None
    assert quiet.notes == [] and google.sent == []


@pytest.mark.asyncio
async def test_look_alike_letters_add_a_note_but_never_block():
    google = Google()
    state = State()
    rep = reputation(google)
    assert await rep.navigation_check("https://pаypal.com/signin", state) is None
    assert await rep.navigation_check("https://amazom.com/", state) is None
    assert state.notes == [
        {"kind": "link_suspicious",
         "text": "The address uses look-alike letters: xn--pypal-4ve.com reads as paypal.com."},
        {"kind": "link_suspicious",
         "text": "amazom.com looks like amazon.com but is a different site."},
    ]
    assert google.sent == ["https://xn--pypal-4ve.com/", "https://amazom.com/"]


@pytest.mark.asyncio
async def test_browser_notes_returned_to_the_model_pass_promptguard():
    state = State()
    rep = reputation(Google(), Source(keys={}, effective="blocked"))
    for host in ("pаypal.com", "аррӏе.com", "gооgle.com"):
        await rep.navigation_check(f"https://{host}/", state)
    assert len(state.notes) == 3
    guard = PromptGuard()
    for note in state.notes:
        assert note["text"].isascii()
        assert "xn--" in note["text"]
        result = guard.scan(note["text"])
        assert not [d for d in result.detections if d.severity in ("high", "critical")], note


@pytest.mark.asyncio
async def test_notes_are_added_once_per_browser_context():
    state = State()
    rep = reputation(Google(), Source(keys={}, effective="blocked"))
    for _ in range(3):
        await rep.navigation_check("https://pаypal.com/x", state)
    assert len(state.notes) == 1


@pytest.mark.asyncio
async def test_a_listed_site_reached_from_a_3ds_handoff_page_is_blocked():
    google = Google()
    google.listed["https://secure-bank-verify.example.net/"] = ("SOCIAL_ENGINEERING",)
    state = State(checkout_handoff=True)
    reason = await reputation(google).navigation_check(
        "https://secure-bank-verify.example.net/3ds?txn=1", state
    )
    assert reason is not None and "may be phishing or a scam" in reason


@pytest.mark.asyncio
async def test_a_lookup_error_during_a_3ds_handoff_lets_the_bank_page_open():
    google = Google()
    google.fail = httpx.ConnectError("down")
    state = State(checkout_handoff=True)
    assert await reputation(google).navigation_check("https://acs.bank.example.org/3ds", state) is None
    assert state.notes[0]["kind"] == "link_not_checked"


@pytest.mark.asyncio
async def test_sign_in_and_captcha_hosts_are_never_looked_up():
    google = Google()
    rep = reputation(google)
    state = State()
    for url in ("https://accounts.google.com/signin/v2", "https://login.microsoftonline.com/x",
                "https://okta.com/login", "https://api-1.duosecurity.com/frame",
                "https://www.recaptcha.net/recaptcha/api2", "https://newassets.hcaptcha.com/c",
                "https://challenges.cloudflare.com/turnstile", "https://client-api.arkoselabs.com/"):
        assert await rep.navigation_check(url, state) is None
    assert google.sent == [] and state.notes == []
    assert "google.com" not in links.EXEMPT_HOSTS


@pytest.mark.asyncio
async def test_an_okta_tenant_anyone_can_register_is_still_looked_up_and_a_listing_blocks_it():
    # Review of S4: every *.okta.com was exempt, and anyone can sign up for a tenant and dress
    # its sign-in page up, so an attacker's tenant was never looked up.
    google = Google()
    google.listed["https://dev-123.okta.com/"] = ("SOCIAL_ENGINEERING",)
    rep = reputation(google)
    reason = await rep.navigation_check("https://dev-123.okta.com/x", State())
    assert reason is not None and "may be phishing or a scam" in reason
    assert await rep.navigation_check("https://acme.oktapreview.com/login", State()) is None
    assert google.sent == ["https://dev-123.okta.com/", "https://acme.oktapreview.com/"]
    assert links.TENANT_IDP_DOMAINS <= set(links.EXEMPT_HOSTS)


@pytest.mark.asyncio
async def test_a_company_okta_sign_in_still_opens_when_the_lookup_fails():
    google = Google()
    google.fail = httpx.ConnectError("down")
    state = State()
    assert await reputation(google).navigation_check("https://acme.okta.com/login", state) is None
    assert state.notes[0]["kind"] == "link_not_checked"


@pytest.mark.asyncio
async def test_google_com_and_its_user_content_sites_are_still_looked_up_although_recaptcha_is_exempt():
    google = Google()
    google.listed["https://sites.google.com/"] = ("SOCIAL_ENGINEERING",)
    rep = reputation(google)
    assert await rep.navigation_check("https://www.google.com/search?q=x", State()) is None
    blocked = await rep.navigation_check("https://sites.google.com/view/fake-login", State())
    assert blocked is not None
    assert google.sent == ["https://www.google.com/", "https://sites.google.com/"]


@pytest.mark.asyncio
async def test_the_unsafe_site_reason_is_neither_a_sending_nor_a_read_click_reason():
    google = Google()
    google.listed["https://paypa1-verify.xyz/"] = ("MALWARE",)
    reason = await reputation(google).navigation_check(EVIL_PAGE, State())
    assert reason is not None
    assert reason not in browser_guard.SENDING_REASONS
    assert reason not in browser_guard.READ_CLICK_REASONS


@pytest.mark.asyncio
async def test_the_hook_writes_its_notes_on_the_guards_own_state_and_leaves_one_without_notes_alone():
    google = Google()
    google.listed["https://paypa1-verify.xyz/"] = ("MALWARE",)
    rep = reputation(google)
    state = browser_guard.EgressState(account_mode=True)
    assert await rep.navigation_check("https://pаypal.com/", state) is None
    assert [n["kind"] for n in state.notes] == ["link_suspicious"]
    assert await rep.navigation_check(EVIL_PAGE, state) is not None
    # A state without a notes list (another guard double) is never written to.
    bare = object()
    assert await rep.navigation_check("https://pаypal.com/", bare) is None


@pytest.mark.asyncio
async def test_an_exempt_host_written_after_a_backslash_or_userinfo_does_not_exempt_another_site():
    google = Google()
    google.listed["https://evil.example.net/"] = ("SOCIAL_ENGINEERING",)
    rep = reputation(google)
    reason = await rep.navigation_check(r"https://evil.example.net\@accounts.google.com/", State())
    assert reason is not None
    assert google.sent == ["https://evil.example.net/"]
    assert await rep.navigation_check("https://someone@accounts.google.com/", State()) is None
    assert google.sent == ["https://evil.example.net/"]


@pytest.mark.asyncio
async def test_a_slow_switch_read_is_capped_by_the_hops_budget_and_noted_as_not_answered(monkeypatch):
    monkeypatch.setattr(links, "BROWSER_TIMEOUT_S", 0.02)

    class SlowSource(Source):
        async def capability_statuses(self):
            await asyncio.sleep(1)
            return await super().capability_statuses()

    google = Google()
    state = State()
    rep = reputation(google, SlowSource())
    assert await rep.navigation_check("https://shop.example.org/", state) is None
    assert state.notes == [{
        "kind": "link_not_checked",
        "text": "This site was not checked against Google's list of dangerous sites "
                "(Google did not answer in time).",
    }]
    assert google.sent == []


@pytest.mark.asyncio
async def test_a_listed_parent_blocks_a_host_with_characters_the_url_standard_allows():
    """Review of S4: navigation_check("https://x$y.listed.example.org/") answered None with no
    note and sent nothing, because the host was read as unreadable, while the browser opens it
    and Google lists listed.example.org. Its nearest DNS ancestor is looked up now; so is a
    listed site behind a zero-padded port, which used to raise inside the parser."""
    google = Google()
    google.listed["https://listed.example.org/"] = ("SOCIAL_ENGINEERING",)
    rep = reputation(google)
    for url in ("https://x$y.listed.example.org/login", "https://a~b.c!d.listed.example.org/",
                "https://listed.example.org:" + "0" * 5_000 + "443/login",
                "https://user[@listed.example.org/"):
        reason = await rep.navigation_check(url, State())
        assert reason is not None and "may be phishing or a scam" in reason, url
    assert set(google.sent) == {"https://listed.example.org/"}


@pytest.mark.asyncio
async def test_an_address_the_hook_cannot_read_is_noted_as_not_checked_never_passed_on_silently():
    """A reading gap must not look like a clean lookup: when the owner has Google set up and
    the guard opens an address this module cannot read, the model is told it was not checked.
    Without a key nothing is noted, as for every other link."""
    google = Google()
    state = State()
    rep = reputation(google)
    for url in ("http://pay$pal.com/", "http://-1.0.0.1/", "http://example.org:99999/"):
        assert await rep.navigation_check(url, state) is None
    assert state.notes == [{
        "kind": "link_not_checked",
        "text": "This site was not checked against Google Safe Browsing (its address could not "
                "be read).",
    }]
    assert google.sent == []
    result = PromptGuard().scan(state.notes[0]["text"])
    assert not [d for d in result.detections if d.severity in ("high", "critical")]
    quiet = State()
    no_key = reputation(google, Source(keys={}, effective="blocked"))
    assert await no_key.navigation_check("http://pay$pal.com/", quiet) is None
    assert quiet.notes == []


# ── through the real guard (EgressHooks, scaffold A1) ──────────────────
#
# The request and route doubles below are copied from tests/test_browser_guard.py (not imported,
# so pytest does not collect that module twice). The guard is the real Guard; only DNS is
# answered by an injected resolver.

TAB = SimpleNamespace(name="the page's tab", url="https://shop.example.org/cart")


def public_resolver(host: str) -> list[str]:
    return ["93.184.216.34"]


def private_resolver(host: str) -> list[str]:
    return ["10.0.0.1"]


@pytest.fixture
def no_system_dns(monkeypatch):
    """The guard must judge the injected resolver's answer and nothing else."""
    def refuse(*_args, **_kwargs):
        raise AssertionError("check_url resolved through the system resolver")

    monkeypatch.setattr(browser_guard.socket, "getaddrinfo", refuse)
    monkeypatch.setattr(netsec.socket, "getaddrinfo", refuse)


class FakeFrame:
    def __init__(self, parent: Any = None, page: Any = TAB) -> None:
        self.parent_frame = parent
        self.page = page


class FakeRequest:
    def __init__(self, url: str, *, method: str = "GET", navigation: bool = True, top: bool = True,
                 page: Any = TAB) -> None:
        self.url, self.method, self._navigation = url, method, navigation
        self.frame = FakeFrame(None if top else FakeFrame(page=page), page=page)
        self.headers = {"referer": TAB.url}

    def is_navigation_request(self) -> bool:
        return self._navigation


class FakeResponse:
    def __init__(self, status: int, location: Optional[str] = None) -> None:
        self.status = status
        self.headers = {"location": location} if location else {}


class FakeRoute:
    def __init__(self, response: Any = None) -> None:
        self.calls: list[tuple[str, object]] = []
        self._response = response

    async def continue_(self) -> None:
        self.calls.append(("continue", None))

    async def abort(self, code: str) -> None:
        self.calls.append(("abort", code))

    async def fetch(self, *, max_redirects: int):
        assert max_redirects == 0
        return self._response

    async def fulfill(self, **kwargs) -> None:
        self.calls.append(("fulfill", kwargs))


class TrustingSiteRules:
    """S7's hook as a test double: blocks the hosts in *blocked*, lets every other host through
    (a Trusted host included: trusting a site never exempts it from the lookup) and records
    the order it was asked in."""

    def __init__(self, calls: list[str], *, blocked: tuple[str, ...] = ()) -> None:
        self.calls, self.blocked = calls, blocked

    def navigation_reason(self, url: str, *, exempt: bool) -> Optional[str]:
        self.calls.append(f"site_rules {url}")
        host = urlsplit(url).hostname or ""
        return f"the owner blocked {host}" if host in self.blocked else None

    def page_notice(self, url: str, *, exempt: bool) -> None:
        return None


def guarded_state(rep: LinkReputation, *, user_id: str = "ann") -> browser_guard.EgressState:
    """A context's egress state with S4's hook bound the way the toolkits bind it."""
    state = browser_guard.EgressState(account_mode=True, write_page=TAB, handoff_page=TAB)
    hooks = browser_guard.EgressHooks(reputation=lambda _uid: rep.navigation_check)
    session = SimpleNamespace(context=object(), user_id=user_id)
    _shared.attach_egress_hooks(SimpleNamespace(egress_state=lambda _ctx: state), session, hooks)
    assert state.reputation is not None
    return state


ADVISORY = "Google Safe Browsing says this site may be phishing or a scam (advisory provided by Google)"


@pytest.mark.asyncio
async def test_a_navigation_to_a_listed_site_is_aborted_with_googles_advisory_as_the_reason(no_system_dns):
    google = Google()
    google.listed["https://paypa1-verify.xyz/"] = ("SOCIAL_ENGINEERING",)
    state = guarded_state(reputation(google))
    route = FakeRoute(FakeResponse(200))
    await browser_guard.Guard(resolver=public_resolver)._route(route, FakeRequest(EVIL_PAGE), state)
    assert route.calls == [("abort", "blockedbyclient")]
    # ACCOUNT mode: the entry the toolkit reports keeps no query or fragment.
    assert state.blocked == [{"url": "https://paypa1-verify.xyz/login", "reason": ADVISORY}]
    assert google.sent == ["https://paypa1-verify.xyz/"]
    # An unlisted page is fetched and handed over as before.
    answer = FakeResponse(200)
    route = FakeRoute(answer)
    await browser_guard.Guard(resolver=public_resolver)._route(
        route, FakeRequest("https://shop.example.org/a"), state
    )
    assert route.calls == [("fulfill", {"response": answer})] and len(state.blocked) == 1


@pytest.mark.asyncio
async def test_a_redirect_hop_to_a_listed_site_is_aborted_like_a_navigation(no_system_dns):
    google = Google()
    google.listed["https://paypa1-verify.xyz/"] = ("SOCIAL_ENGINEERING",)
    state = guarded_state(reputation(google))
    route = FakeRoute(FakeResponse(302, "https://paypa1-verify.xyz/landing?id=7"))
    await browser_guard.Guard(resolver=public_resolver)._route(
        route, FakeRequest("https://news.example.org/out?to=x"), state
    )
    assert route.calls == [("abort", "blockedbyclient")]
    assert state.blocked == [{
        "url": "https://paypa1-verify.xyz/landing",
        "reason": ADVISORY,
        "via": "https://news.example.org/out",
    }]
    assert google.sent == ["https://news.example.org/", "https://paypa1-verify.xyz/"]


@pytest.mark.asyncio
async def test_the_order_posts_redirect_target_is_checked_after_its_own_rules(no_system_dns):
    google = Google()
    google.listed["https://collect.example.net/"] = ("SOCIAL_ENGINEERING",)
    state = guarded_state(reputation(google))
    state.write_allowed, state.write_origin = True, "https://shop.example.org"
    g = browser_guard.Guard(resolver=public_resolver)
    # The merchant's answer sends the person to a listed site: looked up, and stopped.
    route = FakeRoute(FakeResponse(303, "https://collect.example.net/thanks"))
    await g._route(route, FakeRequest("https://shop.example.org/pay", method="POST"), state)
    assert route.calls == [("abort", "blockedbyclient")]
    assert state.blocked[-1] == {"url": "https://collect.example.net/thanks", "reason": ADVISORY,
                                 "via": "https://shop.example.org/pay"}
    # A 307 to another origin breaks the order's own rule first: refused without a lookup.
    google.sent.clear()
    route = FakeRoute(FakeResponse(307, "https://other.example.net/pay"))
    await g._route(route, FakeRequest("https://shop.example.org/pay", method="POST"), state)
    assert route.calls == [("abort", "blockedbyclient")]
    assert "a 307 sends the card again" in state.blocked[-1]["reason"]
    assert "https://other.example.net/" not in google.sent


@pytest.mark.asyncio
async def test_the_navigation_checks_run_only_after_the_ssrf_check_passes(no_system_dns):
    google = Google()
    state = guarded_state(reputation(google))
    route = FakeRoute(FakeResponse(200))
    await browser_guard.Guard(resolver=private_resolver)._route(
        route, FakeRequest("https://intranet.example.org/admin"), state
    )
    assert route.calls == [("abort", "blockedbyclient")]
    assert state.blocked[-1]["reason"] != ADVISORY
    # Nothing about a refused address ever reaches Google.
    assert google.sent == [] and state.notes == []
    # A redirect to a private address is refused by the same check, before any lookup of it.
    route = FakeRoute(FakeResponse(302, "http://10.0.0.5/"))
    await browser_guard.Guard(resolver=public_resolver)._route(
        route, FakeRequest("https://shop.example.org/go"), state
    )
    assert route.calls == [("abort", "blockedbyclient")]
    assert google.sent == ["https://shop.example.org/"]


@pytest.mark.asyncio
async def test_site_rules_run_before_the_reputation_lookup_and_a_block_stops_it(no_system_dns):
    google = Google()
    google.listed["https://paypa1-verify.xyz/"] = ("SOCIAL_ENGINEERING",)
    state = guarded_state(reputation(google))
    calls: list[str] = []
    state.site_rules = TrustingSiteRules(calls, blocked=("paypa1-verify.xyz",))
    route = FakeRoute(FakeResponse(200))
    await browser_guard.Guard(resolver=public_resolver)._route(route, FakeRequest(EVIL_PAGE), state)
    assert route.calls == [("abort", "blockedbyclient")]
    assert state.blocked[-1]["reason"] == "the owner blocked paypa1-verify.xyz"
    # The owner's block decided it: the link never left for Google.
    assert calls == [f"site_rules {EVIL_PAGE}"] and google.sent == []


@pytest.mark.asyncio
async def test_a_site_rule_trusted_host_is_still_looked_up_and_a_listing_wins(no_system_dns):
    google = Google()
    google.listed["https://trusted.example.org/"] = ("MALWARE",)
    state = guarded_state(reputation(google))
    calls: list[str] = []
    state.site_rules = TrustingSiteRules(calls)
    route = FakeRoute(FakeResponse(200))
    await browser_guard.Guard(resolver=public_resolver)._route(
        route, FakeRequest("https://trusted.example.org/dashboard"), state
    )
    assert calls == ["site_rules https://trusted.example.org/dashboard"]
    assert google.sent == ["https://trusted.example.org/"]
    assert route.calls == [("abort", "blockedbyclient")]
    assert state.blocked[-1]["reason"].startswith("Google Safe Browsing says this site may host malware")


@pytest.mark.asyncio
async def test_a_navigation_check_that_raises_fails_closed_in_the_guard(no_system_dns):
    """The guard blocks with its own named reason when a hook raises (WAVE 0's
    _reputation_reason); S4's hook is built never to, so a broken Google never blocks."""
    state = guarded_state(reputation(Google()))

    async def broken(url: str, egress: Any) -> Optional[str]:
        raise RuntimeError("a bug in a hook")

    state.reputation = broken
    route = FakeRoute(FakeResponse(200))
    await browser_guard.Guard(resolver=public_resolver)._route(
        route, FakeRequest("https://shop.example.org/a"), state
    )
    assert route.calls == [("abort", "blockedbyclient")]
    assert state.blocked[-1]["reason"] == browser_guard.NAVIGATION_CHECK_FAILED
    # S4's own hook with every Google request failing: the page opens, with a note.
    google = Google()
    google.fail = httpx.ConnectError("down")
    state = guarded_state(reputation(google))
    answer = FakeResponse(200)
    route = FakeRoute(answer)
    await browser_guard.Guard(resolver=public_resolver)._route(
        route, FakeRequest("https://shop.example.org/a"), state
    )
    assert route.calls == [("fulfill", {"response": answer})] and state.blocked == []
    assert [n["kind"] for n in state.notes] == ["link_not_checked"]


@pytest.mark.asyncio
async def test_a_listed_site_is_blocked_inside_an_approved_checkouts_hand_off_window(no_system_dns):
    """Review SEC-F4 through the guard: the 3-D Secure hand-off window no longer switches the
    lookup off, so a hop from the bank's page to a listed look-alike is stopped."""
    google = Google()
    google.listed["https://secure-bank-verify.example.net/"] = ("SOCIAL_ENGINEERING",)
    state = guarded_state(reputation(google))
    state.checkout_handoff, state.human_driving = True, True
    route = FakeRoute(FakeResponse(200))
    await browser_guard.Guard(resolver=public_resolver)._route(
        route, FakeRequest("https://secure-bank-verify.example.net/3ds?txn=1"), state
    )
    assert route.calls == [("abort", "blockedbyclient")]
    assert state.blocked[-1]["reason"] == ADVISORY


@pytest.mark.asyncio
async def test_subresources_and_subframes_are_never_looked_up(no_system_dns):
    google = Google()
    google.listed["https://paypa1-verify.xyz/"] = ("SOCIAL_ENGINEERING",)
    state = guarded_state(reputation(google))
    g = browser_guard.Guard(resolver=public_resolver)
    for request in (FakeRequest("https://paypa1-verify.xyz/pixel.gif", navigation=False),
                    FakeRequest("https://paypa1-verify.xyz/widget", top=False)):
        route = FakeRoute()
        await g._route(route, request, state)
        assert route.calls == [("continue", None)]
    assert google.sent == [] and state.blocked == [] and state.notes == []


# ── browser.read open and click hand back their own navigation's notes ─


class GuardDouble:
    """What browser.read needs of the guard module: the real Guard judges every navigation
    the fake page makes, on one context's real EgressState."""

    BLOCKED_NAVIGATION_MARKER = "net::ERR_BLOCKED_BY_CLIENT"

    def __init__(self, *, stateless: bool = False) -> None:
        self.guard = browser_guard.Guard(resolver=public_resolver)
        self.state = None if stateless else browser_guard.EgressState(account_mode=True)

    def check_url(self, url: str) -> Optional[str]:
        return self.guard.check_url(url)

    async def install_egress_guard(self, context: Any, *, account_mode: bool) -> None:
        return None

    def egress_state(self, context: Any) -> Any:
        return self.state

    async def consequential(self, page: Any, ref: str) -> None:
        return None

    async def settle_blocked_navigation(self, page: Any, *, timeout_ms: int = 1500) -> None:
        return None


class FakePage:
    """A page whose navigations go through the guard's route handler as Chromium's would."""

    def __init__(self, guard: GuardDouble, links_on_page: dict[str, str]) -> None:
        self.guard, self.links, self.url = guard, links_on_page, "about:blank"

    async def navigate(self, url: str) -> None:
        if self.guard.state is not None:
            route = FakeRoute(FakeResponse(200))
            await self.guard.guard._route(route, FakeRequest(url, page=self), self.guard.state)
            assert route.calls[-1][0] == "fulfill", route.calls
        self.url = url

    async def goto(self, url: str, **_kwargs: Any) -> None:
        await self.navigate(url)

    def locator(self, selector: str) -> "FakeLink":
        return FakeLink(self, self.links[selector.removeprefix("aria-ref=")])

    def is_closed(self) -> bool:
        return False


class FakeLink:
    def __init__(self, page: FakePage, target: str) -> None:
        self.page, self.target = page, target

    async def evaluate(self, _script: str, timeout: int = 0) -> str:
        return "Next page"

    async def click(self, timeout: int = 0) -> None:
        await self.page.navigate(self.target)


class FakeSession:
    def __init__(self, page: FakePage) -> None:
        self.user_id, self.mode, self.context = "ann", "account", object()
        self.lock = asyncio.Lock()
        self.task = TaskState(task_id="t1")
        self.typed_secrets: list[str] = []
        self._page = page

    async def page(self) -> FakePage:
        return self._page


class FakeSessions:
    def __init__(self, session: FakeSession) -> None:
        self.session = session

    async def get(self, user_id: str, *, mode: str, task_id: str) -> FakeSession:
        return self.session


class NoChallenge:
    async def detect_challenge(self, page: Any) -> None:
        return None


def read_kit(monkeypatch, guard: GuardDouble, rep: LinkReputation,
             links_on_page: dict[str, str]) -> BrowserReadToolkit:
    """browser.read with S4's hook, on a fake page; the page description is a stand-in (the
    outline is not what these tests are about)."""
    page = FakePage(guard, links_on_page)
    kit = BrowserReadToolkit(
        FakeSessions(FakeSession(page)),  # type: ignore[arg-type]
        guard=guard,  # type: ignore[arg-type]
        handoff=NoChallenge(),  # type: ignore[arg-type]
        egress_hooks=browser_guard.EgressHooks(reputation=lambda _uid: rep.navigation_check),
    )

    async def observe(session: Any, action: str, args: dict[str, Any], **_kwargs: Any) -> dict[str, Any]:
        return {"ok": True, "summary": f"{action} {page.url}", "url": page.url}

    async def nothing(*_args: Any, **_kwargs: Any) -> None:
        return None

    monkeypatch.setattr(kit, "_observe", observe)
    monkeypatch.setattr(kit, "_past_redirects", nothing)
    monkeypatch.setattr(kit, "_http_status", nothing)
    monkeypatch.setattr(kit, "_settle", nothing)
    monkeypatch.setattr(kit, "_order_reason", nothing)
    monkeypatch.setattr(browser_actions, "wait_for_quiet", nothing)
    return kit


@pytest.mark.asyncio
async def test_open_and_click_return_the_notes_added_during_their_navigation(monkeypatch, no_system_dns):
    google = Google()
    google.fail = httpx.Response(503)
    guard = GuardDouble()
    kit = read_kit(monkeypatch, guard, reputation(google), {"e1": "https://pаypal.com/signin"})
    opened = await kit.execute("open", {"url": "https://shop.example.org/"}, user_id="ann", task_id="t1")
    assert opened["ok"] is True
    assert opened["security_notes"] == [
        "This site was not checked against Google Safe Browsing (Google could not be reached)."
    ]
    clicked = await kit.execute("click", {"ref": "e1"}, user_id="ann", task_id="t1")
    assert clicked["ok"] is True
    # Only the click's own navigation, never the open's note again; the look-alike note names
    # the host in punycode, so PromptGuard leaves it for the model to read.
    assert clicked["security_notes"][0] == (
        "The address uses look-alike letters: xn--pypal-4ve.com reads as paypal.com."
    )
    assert opened["security_notes"][0] not in clicked["security_notes"]
    assert guard.state is not None and len(guard.state.notes) >= 2
    looked = await kit.execute("snapshot", {}, user_id="ann", task_id="t1")
    assert "security_notes" not in looked


@pytest.mark.asyncio
async def test_open_and_click_work_with_a_fake_guard_that_has_no_state(monkeypatch, no_system_dns):
    google = Google()
    guard = GuardDouble(stateless=True)
    kit = read_kit(monkeypatch, guard, reputation(google), {"e1": "https://pаypal.com/signin"})
    opened = await kit.execute("open", {"url": "https://shop.example.org/"}, user_id="ann", task_id="t1")
    assert opened["ok"] is True and "security_notes" not in opened
    clicked = await kit.execute("click", {"ref": "e1"}, user_id="ann", task_id="t1")
    assert clicked["ok"] is True and "security_notes" not in clicked
    assert google.sent == []


@pytest.mark.asyncio
async def test_a_listed_site_is_blocked_in_every_form_the_browser_hands_the_guard():
    """Review of S4 (batch 2): the Cherokee ACE form Chromium hands the guard
    ("xn--g9da0d5gqac.com") was unreadable, so a listed site there was never looked up and got
    only a "could not be read" note, never a block. Hosts folded the way a browser folds them
    (a Persian name with its ZWNJ, a host spelled with letters the browser maps) are looked up
    as the host the browser opens and blocked when it is listed."""
    google = Google()
    for url in ("https://xn--g9da0d5gqac.com/", "https://xn--mgbn2ecje63gr19l.com/",
                "https://xn--q1aa.com/"):
        google.listed[url] = ("SOCIAL_ENGINEERING",)
    rep = reputation(google)
    persian = "".join(map(chr, (0x645, 0x6CC, 0x200C, 0x62E, 0x648, 0x627, 0x647, 0x645)))
    for url in ("https://xn--g9da0d5gqac.com/login", "https://xn--mgbn2ecje63gr19l.com/a",
                "https://" + persian + ".com/", "https://" + chr(0x1C83) * 2 + ".com/x"):
        state = State()
        reason = await rep.navigation_check(url, state)
        assert reason is not None and "may be phishing or a scam" in reason, url
        assert not [n for n in state.notes if n["kind"] == "link_not_checked"], url
    assert set(google.sent) == set(google.listed)
