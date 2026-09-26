"""URL gate, route-level egress guard and consequential-click detection.
Pure cases run everywhere; the browser-backed ones use the fake site."""

from __future__ import annotations

import asyncio
import re
import time
from types import SimpleNamespace
from urllib.parse import urlsplit

import pytest
import pytest_asyncio

from services.tools.browser import _shared, guard
from services.tools.browser.guard import (
    BLOCKED_NAVIGATION_MARKER,
    Guard,
    StaleRef,
    classify_target,
    egress_state,
    settle_blocked_navigation,
)

# -- check_url -----------------------------------------------------------------


def public_resolver(host: str) -> list[str]:
    return ["93.184.216.34"]


def private_resolver(host: str) -> list[str]:
    return ["10.0.0.1"]


@pytest.mark.parametrize(
    "url, fragment",
    [
        ("ftp://example.com/x", "http"),
        ("javascript:alert(1)", "http"),
        ("data:text/html,hi", "http"),
        ("blob:https://example.com/abc", "http"),
        ("file:///etc/hosts", "http"),
        ("", "URL"),
        ("https://user:pw@example.com/", "credentials"),
        ("https://example.com:99999/", "Malformed"),
    ],
)
def test_check_url_refuses_schemes_userinfo_and_malformed(url, fragment):
    reason = Guard(resolver=public_resolver).check_url(url)
    assert reason is not None and fragment in reason


def test_check_url_allows_a_public_host_and_refuses_a_private_one():
    assert Guard(resolver=public_resolver).check_url("https://example.com/path?q=1") is None
    reason = Guard(resolver=private_resolver).check_url("https://example.com/")
    assert reason is not None and "10.0.0.1" in reason


def test_check_url_refuses_loopback_by_default_and_allows_it_with_the_test_toggle(monkeypatch):
    monkeypatch.delenv("CRAWLER_ALLOW_LOOPBACK_FOR_TESTS", raising=False)
    assert guard.check_url("http://127.0.0.1:1/") is not None
    monkeypatch.setenv("CRAWLER_ALLOW_LOOPBACK_FOR_TESTS", "1")
    assert guard.check_url("http://127.0.0.1:1/") is None  # read at call time
    assert Guard(resolver=private_resolver).check_url("http://example.com/") is not None  # not a blanket allow


def test_module_level_check_url_uses_the_default_guard(monkeypatch, fakesite):
    assert guard.check_url(fakesite.url("/")) is None
    monkeypatch.delenv("CRAWLER_ALLOW_LOOPBACK_FOR_TESTS")
    assert guard.check_url("http://127.0.0.1:1/") is not None


# -- route guard (headless Chromium + fake site) ----------------------------------


@pytest_asyncio.fixture
async def guarded(page, fakesite, loopback_resolver):
    g = Guard(resolver=loopback_resolver)
    await g.install_egress_guard(page.context, account_mode=True)
    return g, page


@pytest.mark.asyncio
async def test_guard_lets_the_fake_site_through_and_records_nothing(guarded, fakesite):
    _g, page = guarded
    await page.goto(fakesite.url("/grades"))
    assert "Grades" in await page.title()
    assert egress_state(page.context).blocked == []


@pytest.mark.asyncio
async def test_guard_aborts_a_redirect_to_a_private_host(guarded, fakesite):
    _g, page = guarded
    with pytest.raises(Exception, match=BLOCKED_NAVIGATION_MARKER):
        await page.goto(fakesite.url("/redirect-private"))
    await settle_blocked_navigation(page)
    blocked = egress_state(page.context).blocked
    assert blocked[-1]["url"] == "http://10.0.0.1/" and blocked[-1]["via"] == fakesite.url("/redirect-private")
    assert "10.0.0.1" in blocked[-1]["reason"]
    await page.goto(fakesite.url("/"))  # the next navigation works after settling


@pytest.mark.asyncio
async def test_guard_follows_an_allowed_redirect_chain_hop_by_hop(guarded, fakesite):
    _g, page = guarded
    await page.goto(fakesite.url("/sso/start"))
    await page.wait_for_url("**/sso/otp")
    assert egress_state(page.context).blocked == []


@pytest.mark.asyncio
async def test_guard_aborts_a_read_tier_post_but_not_when_write_is_allowed(guarded, fakesite):
    _g, page = guarded
    await page.goto(fakesite.url("/post"))
    await page.click("text=Sign up")
    await settle_blocked_navigation(page)
    state = egress_state(page.context)
    assert state.blocked[-1]["reason"].startswith("non-GET top-level navigation")
    await page.goto(fakesite.url("/post"))
    state.write_allowed, state.write_page = True, page
    await page.click("text=Sign up")
    await page.wait_for_load_state("domcontentloaded")
    assert "Thanks" in await page.content()


async def sign_in_by_hand(page) -> None:
    """What the person does in Crawler's window during a handoff."""
    await page.fill("input[name=username]", "krish")
    await page.fill("input[name=password]", "hunter2")
    await page.locator("button").click()


@pytest.mark.asyncio
async def test_guard_lets_the_person_submit_a_login_while_a_handoff_is_pending(guarded, fakesite):
    _g, page = guarded
    state = egress_state(page.context)
    await page.goto(fakesite.url("/login"))
    state.human_driving = True  # the toolkit set this when it handed over
    await sign_in_by_hand(page)
    await page.wait_for_url("**/home")
    assert "Signed in" in await page.content() and state.blocked == []
    state.human_driving = False  # the agent acted again
    await page.goto(fakesite.url("/login"))
    await sign_in_by_hand(page)
    await settle_blocked_navigation(page)
    assert state.blocked[-1]["reason"].startswith("non-GET top-level navigation")


@pytest.mark.asyncio
async def test_guard_still_blocks_a_private_address_post_while_a_handoff_is_pending(guarded, fakesite):
    _g, page = guarded
    state = egress_state(page.context)
    state.human_driving = True
    await page.goto(fakesite.url("/login"))
    await page.evaluate("document.querySelector('form').action = 'http://10.0.0.1/login?sid=SECRET'")
    await sign_in_by_hand(page)
    await settle_blocked_navigation(page)
    assert state.blocked[-1]["url"] == "http://10.0.0.1/login" and "10.0.0.1" in state.blocked[-1]["reason"]
    assert page.url.startswith("chrome-error://")


@pytest.mark.asyncio
async def test_a_pending_handoff_ends_when_its_context_closes(guarded):
    _g, page = guarded
    state = egress_state(page.context)
    state.human_driving = True
    await page.context.close()
    assert state.human_driving is False


@pytest.mark.asyncio
async def test_guard_leaves_fetch_and_subframes_alone(guarded, fakesite):
    _g, page = guarded
    await page.goto(fakesite.url("/frame"))
    assert await page.frame_locator("iframe").locator("button").count() == 1
    status = await page.evaluate("fetch('/grades').then(r => r.status)")
    assert status == 200 and egress_state(page.context).blocked == []


async def _received(fakesite, message: str, *, timeout_s: float = 3.0) -> bool:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        if ("WS", message) in fakesite.handled:
            return True
        await asyncio.sleep(0.05)
    return False


@pytest.mark.asyncio
async def test_a_websocket_sends_nothing_while_a_read_clicks_nor_on_an_order_address(guarded, fakesite):
    """What a page sends on a WebSocket never reaches the route handler,
    so the guard connects every socket itself (plain ws:// to the fake
    site here; wss:// takes the same handler): a message passes to the
    server, except while browser.read clicks, and never on a socket whose
    address is an order address, even with a write window open for the
    page (a socket's page cannot be told)."""
    _g, page = guarded
    state = egress_state(page.context)
    await page.goto(fakesite.url("/"))
    base = fakesite.base.replace("http://", "ws://")
    opened = """url => new Promise((ok, fail) => { const s = new WebSocket(url);
        s.onopen = () => ok(true); s.onerror = () => fail(new Error('no socket')); window.sockets.push(s); })"""
    await page.evaluate("window.sockets = []")
    await page.evaluate(opened, base + "/live")
    await page.evaluate(opened, base + "/orders/ws")
    send = "([i, m]) => window.sockets[i].send(m)"
    await page.evaluate(send, [0, "hello"])
    assert await _received(fakesite, "hello")
    state.read_click = True
    await page.evaluate(send, [0, "while-clicking"])
    state.read_click = False
    state.write_allowed, state.write_page = True, page
    await page.evaluate(send, [1, "place the order"])
    state.write_allowed, state.write_page = False, None
    await page.evaluate(send, [0, "after"])
    assert await _received(fakesite, "after")  # the same socket, in order: the one before it was dropped
    await asyncio.sleep(0.3)
    got = [h for h in fakesite.handled if h[0] == "WS"]
    assert got == [("WS", "hello"), ("WS", "after")], got
    assert [entry["reason"] for entry in state.blocked] == [guard.READ_CLICK_REQUEST, guard.READ_TIER_ORDER_REQUEST]
    assert state.blocked[-1]["url"] == base + "/orders/ws"


@pytest.mark.asyncio
async def test_install_is_idempotent_per_context(page, loopback_resolver):
    g = Guard(resolver=loopback_resolver)
    await g.install_egress_guard(page.context, account_mode=True)
    state = egress_state(page.context)
    await g.install_egress_guard(page.context, account_mode=False)
    assert egress_state(page.context) is state and state.account_mode is True


@pytest.mark.asyncio
async def test_settle_returns_quietly_when_nothing_was_blocked(page, fakesite, loopback_resolver):
    await page.goto(fakesite.url("/"))
    started = time.monotonic()
    await settle_blocked_navigation(page, timeout_ms=300)
    assert time.monotonic() - started < 2
    assert page.url == fakesite.url("/")


# -- consequential --------------------------------------------------------------


@pytest.mark.parametrize(
    "facts, reason",
    [
        ({"submit": True, "in_form": True, "name": "Search", "method": "get"}, "submit control"),
        ({"submit": True, "in_form": False, "name": "Go"}, None),
        ({"in_form": True, "sensitive": True, "name": "Next", "buttonish": True, "method": "get"},
         "inside a form with a password/payment field"),
        ({"name": "Sign-Up today"}, "name matches: sign up"),
        ({"name": "Posted 3 days ago"}, None),
        ({"name": "Place order"}, "name matches: order"),
        ({"in_form": True, "buttonish": True, "method": "post", "name": "Continue"}, "non-GET navigation"),
        ({"in_form": True, "buttonish": False, "method": "post", "name": "Email"}, None),
    ],
)
def test_classify_target_rule_table(facts, reason):
    assert classify_target(facts) == reason


_REF_LINE = re.compile(r"^\s*- (?P<line>.+?) \[ref=(?P<ref>[a-z0-9]+)\]", re.M)


def ref_for(snapshot: str, prefix: str) -> str:
    for match in _REF_LINE.finditer(snapshot):
        if match.group("line").startswith(prefix):
            return match.group("ref")
    raise AssertionError(f"{prefix!r} not in snapshot:\n{snapshot}")


@pytest_asyncio.fixture
async def controls(page, fakesite, loopback_resolver):
    await page.goto(fakesite.url("/controls"))
    snapshot = await page.locator("body").aria_snapshot(mode="ai")
    return Guard(resolver=loopback_resolver), page, snapshot


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "target, reason",
    [
        ('link "Grades"', None),
        ('button "Show more"', None),
        ('button "Search"', "submit control"),
        ('button "Log in"', "inside a form with a password/payment field"),
        ('link "Review order"', "inside a form with a password/payment field"),
        ('link "Sign up now"', "name matches: sign up"),
        ('link "Subscribe to updates"', "name matches: subscribe"),
        ('button "Post comment"', "name matches: post"),
        ('button "Continue"', "non-GET navigation"),
        # Form-associated through the form= attribute, outside the <form>:
        # closest('form') alone misses both the form and its password field.
        ('button "Apply filter"', "submit control"),
        ('button "Unlock"', "inside a form with a password/payment field"),
    ],
)
async def test_consequential_reads_live_page_facts(controls, target, reason):
    guard, page, snapshot = controls
    assert await guard.consequential(page, ref_for(snapshot, target)) == reason


@pytest.mark.asyncio
async def test_consequential_resolves_a_ref_inside_a_same_origin_iframe(page, fakesite, loopback_resolver):
    await page.goto(fakesite.url("/frame"))
    snapshot = await page.locator("body").aria_snapshot(mode="ai")
    ref = ref_for(snapshot, 'button "Submit inner"')
    assert ref.startswith("f1e")
    assert await Guard(resolver=loopback_resolver).consequential(page, ref) == "submit control"


@pytest.mark.asyncio
async def test_stale_ref_is_reported_within_three_seconds(controls):
    guard, page, _ = controls
    started = time.monotonic()
    with pytest.raises(StaleRef, match="re-snapshot"):
        await guard.consequential(page, "e999")
    assert time.monotonic() - started < 4


@pytest.mark.asyncio
async def test_malformed_ref_never_reaches_the_page(controls):
    guard, page, _ = controls
    with pytest.raises(StaleRef):
        await guard.consequential(page, 'e1"], [x')
    with pytest.raises(StaleRef):
        await guard.consequential(page, "")


# -- review hardening: one resolution, core's blocked ranges, fail closed -------


@pytest.fixture
def no_system_dns(monkeypatch):
    """check_url must judge the injected resolver's answer and nothing else:
    a second lookup through the system resolver is network in a unit test
    and a rebinding window in production."""
    import core.network_security as network_security

    def refuse(*_args, **_kwargs):
        raise AssertionError("check_url resolved through the system resolver")

    monkeypatch.setattr(guard.socket, "getaddrinfo", refuse)
    monkeypatch.setattr(network_security.socket, "getaddrinfo", refuse)


def test_check_url_uses_only_the_injected_resolver(no_system_dns):
    assert Guard(resolver=public_resolver).check_url("https://example.com/path?q=1") is None


@pytest.mark.parametrize(
    "address",
    [
        "100.64.0.1",  # carrier-grade NAT: not "private" to the stdlib, blocked by core
        "::ffff:10.0.0.1",  # IPv4-mapped private address
        "64:ff9b::a00:1",  # NAT64 wrapping 10.0.0.1
        "0.0.0.0",
        "169.254.169.254",  # cloud metadata
    ],
)
def test_check_url_refuses_every_range_core_ssrf_refuses(no_system_dns, address):
    reason = Guard(resolver=lambda host: [address]).check_url("https://example.com/")
    assert reason is not None and "private or local" in reason


def test_check_url_refuses_one_private_record_among_public_ones(no_system_dns):
    reason = Guard(resolver=lambda host: ["93.184.216.34", "10.0.0.1"]).check_url("https://example.com/")
    assert reason is not None and "10.0.0.1" in reason


@pytest.mark.parametrize("answer", [[], ["not-an-address"]])
def test_check_url_fails_closed_on_an_empty_or_unparseable_resolution(no_system_dns, answer):
    reason = Guard(resolver=lambda host: answer).check_url("https://example.com/")
    assert reason is not None and "example.com" in reason


def test_ip_literal_is_judged_as_itself_even_under_the_loopback_toggle(monkeypatch, loopback_resolver, no_system_dns):
    monkeypatch.setenv("CRAWLER_ALLOW_LOOPBACK_FOR_TESTS", "1")
    reason = Guard(resolver=loopback_resolver).check_url("http://10.0.0.1/")
    assert reason is not None and "10.0.0.1" in reason


# -- review hardening: the route handler without a browser -----------------------
# The Chromium-backed tests above skip where no browser is installed (the
# Windows unit job); these pin the same decisions with fakes everywhere.


# The tab the fake requests come from, and the one every window of
# ``_state()`` is opened for; and a tab no card showed.
TAB = SimpleNamespace(name="the card's tab", url="https://shop.example/cart")
OTHER_TAB = SimpleNamespace(name="another tab", url="https://deals.example/")
# What a navigation the card's page started says of where it came from.
FROM_TAB = {"referer": "https://shop.example/cart"}


class FakeFrame:
    def __init__(self, parent=None, page=TAB) -> None:
        self.parent_frame = parent
        self.page = page


class FakeRequest:
    def __init__(
        self,
        url: str,
        *,
        method: str = "GET",
        navigation: bool = True,
        top: bool = True,
        page=TAB,
        headers: dict[str, str] | None = None,
    ) -> None:
        self.url, self.method, self._navigation = url, method, navigation
        self.frame = FakeFrame(None if top else FakeFrame(page=page), page=page)
        self.headers = dict(FROM_TAB if headers is None else headers)

    def is_navigation_request(self) -> bool:
        return self._navigation


class FakeResponse:
    def __init__(self, status: int, location: str | None = None) -> None:
        self.status = status
        self.headers = {"location": location} if location else {}


class FakeRoute:
    def __init__(self, response: FakeResponse | Exception | None = None) -> None:
        self.calls: list[tuple[str, object]] = []
        self._response = response

    async def continue_(self) -> None:
        self.calls.append(("continue", None))

    async def abort(self, code: str) -> None:
        self.calls.append(("abort", code))

    async def fetch(self, *, max_redirects: int):
        assert max_redirects == 0  # every hop is ours to check
        if isinstance(self._response, Exception):
            raise self._response
        return self._response

    async def fulfill(self, **kwargs) -> None:
        self.calls.append(("fulfill", kwargs))


def _state(*, account_mode: bool = True) -> guard.EgressState:
    return guard.EgressState(account_mode=account_mode, write_page=TAB, handoff_page=TAB)


@pytest.mark.asyncio
async def test_route_passes_subresources_and_subframes_untouched(no_system_dns):
    g = Guard(resolver=private_resolver)
    for request in (FakeRequest("http://10.0.0.1/x", navigation=False), FakeRequest("http://10.0.0.1/", top=False)):
        route = FakeRoute()
        await g._route(route, request, _state())
        assert route.calls == [("continue", None)]


@pytest.mark.asyncio
async def test_route_aborts_a_read_tier_post(no_system_dns):
    state, route = _state(), FakeRoute()
    await Guard(resolver=public_resolver)._route(route, FakeRequest("https://shop.example/buy", method="POST"), state)
    assert route.calls == [("abort", "blockedbyclient")]
    assert state.blocked[-1]["reason"].startswith("non-GET top-level navigation")


@pytest.mark.asyncio
async def test_route_forwards_the_persons_post_during_a_handoff_but_still_checks_the_address(no_system_dns):
    state = _state()
    state.human_driving = True
    route = FakeRoute()
    await Guard(resolver=public_resolver)._route(route, FakeRequest("https://canvas.school.edu/login", method="POST"), state)
    assert route.calls == [("continue", None)] and state.blocked == []
    route = FakeRoute()
    await Guard(resolver=private_resolver)._route(route, FakeRequest("http://intranet.example/login", method="POST"), state)
    assert route.calls == [("abort", "blockedbyclient")] and "10.0.0.1" in state.blocked[-1]["reason"]


@pytest.mark.asyncio
async def test_route_turns_an_allowed_redirect_into_a_rechecked_client_hop(no_system_dns):
    route = FakeRoute(FakeResponse(302, '/next?a="b"'))
    await Guard(resolver=public_resolver)._route(route, FakeRequest("https://shop.example/start"), _state())
    kind, kwargs = route.calls[-1]
    assert kind == "fulfill" and isinstance(kwargs, dict) and kwargs["status"] == 200
    assert "url=https://shop.example/next?a=&quot;b&quot;" in kwargs["body"]


@pytest.mark.asyncio
async def test_route_fails_closed_when_the_handler_breaks(no_system_dns):
    route = FakeRoute(RuntimeError("socket hang up"))
    await Guard(resolver=public_resolver)._route(route, FakeRequest("https://shop.example/"), _state())
    assert route.calls == [("abort", "failed")]


@pytest.mark.asyncio
async def test_account_mode_blocks_and_logs_carry_no_query_or_fragment(no_system_dns):
    from structlog.testing import capture_logs

    state = _state(account_mode=True)
    route = FakeRoute(FakeResponse(302, "http://10.0.0.1/collect?session=SECRET1#frag"))
    request = FakeRequest("https://canvas.school.edu/courses?token=SECRET2")
    with capture_logs() as logs:
        await Guard(resolver=public_resolver)._route(route, request, state)
    assert route.calls == [("abort", "blockedbyclient")]
    assert state.blocked[-1]["url"] == "http://10.0.0.1/collect"
    assert state.blocked[-1]["via"] == "https://canvas.school.edu/courses"
    assert logs and "SECRET" not in repr(logs) and "SECRET" not in repr(state.blocked)


@pytest.mark.asyncio
async def test_public_mode_blocks_keep_the_full_url_but_logs_do_not(no_system_dns):
    from structlog.testing import capture_logs

    state, route = _state(account_mode=False), FakeRoute()
    with capture_logs() as logs:
        await Guard(resolver=private_resolver)._route(route, FakeRequest("http://intranet.example/a?q=SECRET3"), state)
    assert route.calls == [("abort", "blockedbyclient")]
    assert state.blocked[-1]["url"] == "http://intranet.example/a?q=SECRET3"
    assert logs and "SECRET3" not in repr(logs)


@pytest.mark.asyncio
async def test_a_bound_write_window_admits_one_post_to_its_origin_only(no_system_dns):
    """The checkout binds the window to where the order form said it
    posts: a POST there passes (fetched by the guard, the merchant's
    answer passed on), a POST anywhere else, a PUT there and a
    GET-with-the-card-in-the-URL are aborted and recorded."""
    g = Guard(resolver=public_resolver)
    state = _state()
    state.write_allowed, state.write_origin = True, "https://shop.example"
    answer = FakeResponse(200)
    route = FakeRoute(answer)
    await g._route(route, FakeRequest("https://shop.example/pay", method="POST"), state)
    assert route.calls == [("fulfill", {"response": answer})] and state.blocked == []
    for url, method in (
        ("https://collector.example/steal", "POST"),
        ("https://shop.example/pay", "PUT"),
        ("http://shop.example/pay", "POST"),
    ):
        route = FakeRoute()
        await g._route(route, FakeRequest(url, method=method), state)
        assert route.calls == [("abort", "blockedbyclient")], (url, method)
        assert state.blocked[-1]["url"] == url and "not by POST to https://shop.example" in state.blocked[-1]["reason"]
    # An unbound window (browser.act's) is unchanged: any origin.
    state.write_origin = None
    route = FakeRoute()
    await g._route(route, FakeRequest("https://collector.example/steal", method="POST"), state)
    assert route.calls == [("continue", None)]


@pytest.mark.asyncio
async def test_a_bound_write_window_blocks_a_frames_post_to_another_origin(no_system_dns):
    """An order form aimed at a hidden iframe and at another origin sends
    the card as a frame's navigation: while the window is bound, that is
    aborted; a frame's POST to the bound origin passes. With no window open
    a frame's POST is a read-tier one and is aborted like a top page's;
    the person's own, during a handoff, passes."""
    g = Guard(resolver=public_resolver)
    state = _state()
    state.write_allowed, state.write_origin = True, "https://shop.example"
    route = FakeRoute()
    await g._route(route, FakeRequest("https://collector.example/steal", method="POST", top=False), state)
    assert route.calls == [("abort", "blockedbyclient")]
    assert state.blocked[-1]["url"] == "https://collector.example/steal"
    assert "from a frame" in state.blocked[-1]["reason"] and "not by POST to https://shop.example" in state.blocked[-1]["reason"]
    route = FakeRoute()
    await g._route(route, FakeRequest("https://shop.example/pay", method="POST", top=False), state)
    assert route.calls == [("continue", None)]
    state.write_allowed, state.write_origin = False, None
    route = FakeRoute()
    await g._route(route, FakeRequest("https://collector.example/steal", method="POST", top=False), state)
    assert route.calls == [("abort", "blockedbyclient")]
    assert state.blocked[-1]["reason"] == guard.READ_TIER_FRAME_POST
    state.human_driving = True
    route = FakeRoute()
    await g._route(route, FakeRequest("https://shop.example/otp", method="POST", top=False), state)
    assert route.calls == [("continue", None)] and len(state.blocked) == 2


@pytest.mark.asyncio
async def test_a_bound_post_is_fetched_and_its_answer_judged_before_the_browser_follows_it(no_system_dns):
    """The order POST is fetched by the guard: a 307/308 to another
    origin (the browser would send the card again) is aborted and
    recorded with the order as ``via``; a 303 becomes the same client-side
    GET hop every redirect gets; a plain answer is passed on as it is.
    Without a bound window a POST is still forwarded untouched."""
    g = Guard(resolver=public_resolver)
    state = _state()
    state.write_allowed, state.write_origin = True, "https://shop.example"
    route = FakeRoute(FakeResponse(307, "https://collector.example/confirm"))
    await g._route(route, FakeRequest("https://shop.example/pay", method="POST"), state)
    assert route.calls == [("abort", "blockedbyclient")]
    assert state.blocked[-1]["url"] == "https://collector.example/confirm"
    assert state.blocked[-1]["via"] == "https://shop.example/pay"
    assert "307" in state.blocked[-1]["reason"] and "not by POST to https://shop.example" in state.blocked[-1]["reason"]
    # A 307 to a private address is refused by the address check first.
    route = FakeRoute(FakeResponse(308, "https://shop.example/again"))
    await Guard(resolver=private_resolver)._route(route, FakeRequest("https://shop.example/pay", method="POST"), state)
    assert route.calls == [("abort", "blockedbyclient")] and "10.0.0.1" in state.blocked[-1]["reason"]
    # A 303 lands on a GET the browser makes through the route again.
    route = FakeRoute(FakeResponse(303, "/order-confirmed"))
    await g._route(route, FakeRequest("https://shop.example/pay", method="POST"), state)
    kind, kwargs = route.calls[-1]
    assert kind == "fulfill" and isinstance(kwargs, dict) and kwargs["status"] == 200
    assert "url=https://shop.example/order-confirmed" in kwargs["body"]
    # A plain answer is the merchant's own.
    answer = FakeResponse(200)
    route = FakeRoute(answer)
    await g._route(route, FakeRequest("https://shop.example/pay", method="POST"), state)
    assert route.calls == [("fulfill", {"response": answer})]
    assert len(state.blocked) == 2
    # An act's window (unbound) forwards the POST as before.
    state.write_origin = None
    route = FakeRoute(FakeResponse(307, "https://collector.example/confirm"))
    await g._route(route, FakeRequest("https://shop.example/pay", method="POST"), state)
    assert route.calls == [("continue", None)]


@pytest.mark.asyncio
async def test_a_pending_handoff_does_not_widen_a_bound_write_window(no_system_dns):
    """The person may be driving (a handoff left ``human_driving`` set)
    while the checkout sends the order: the window is still bound to the
    order form's origin, so a POST elsewhere is aborted; with no bound
    window the person's own POST passes as before."""
    g = Guard(resolver=public_resolver)
    state = _state()
    state.human_driving, state.write_allowed, state.write_origin = True, True, "https://shop.example"
    route = FakeRoute()
    await g._route(route, FakeRequest("https://collector.example/steal", method="POST"), state)
    assert route.calls == [("abort", "blockedbyclient")]
    assert "not by POST to https://shop.example" in state.blocked[-1]["reason"]
    state.write_allowed, state.write_origin = False, None
    route = FakeRoute()
    await g._route(route, FakeRequest("https://canvas.school.edu/login", method="POST"), state)
    assert route.calls == [("continue", None)]


@pytest.mark.asyncio
async def test_a_change_may_not_open_an_order_address_from_any_frame(no_system_dns):
    """While browser.act runs an act not meant to send (a fill, a check, a
    select, a plain link: ``changing``), no frame may open an order
    address, by GET or through a redirect; the same addresses pass when
    nothing is changing (an order history page is a read)."""
    g = Guard(resolver=public_resolver)
    state = _state()
    state.changing = True
    for request in (
        FakeRequest("https://shop.example/place-order-now?token=abc"),
        FakeRequest("https://shop.example/checkout/complete", top=False),
    ):
        route = FakeRoute()
        await g._route(route, request, state)
        assert route.calls == [("abort", "blockedbyclient")]
        assert state.blocked[-1]["reason"] == guard.ORDER_ADDRESS
    route = FakeRoute(FakeResponse(302, "/pay"))
    await g._route(route, FakeRequest("https://shop.example/go"), state)
    assert route.calls == [("abort", "blockedbyclient")]
    assert state.blocked[-1] == {"url": "https://shop.example/pay", "reason": guard.ORDER_ADDRESS, "via": "https://shop.example/go"}
    route = FakeRoute(FakeResponse(302, "/cart"))
    await g._route(route, FakeRequest("https://shop.example/go"), state)
    assert route.calls[-1][0] == "fulfill" and len(state.blocked) == 3
    state.changing = False
    route = FakeRoute(FakeResponse(200))
    await g._route(route, FakeRequest("https://shop.example/orders/"), state)
    assert route.calls[-1][0] == "fulfill" and len(state.blocked) == 3
    assert guard.SENDING_REASONS == {
        guard.READ_TIER_POST, guard.READ_TIER_FRAME_POST, guard.ORDER_ADDRESS, guard.ORDER_REQUEST
    }


@pytest.mark.asyncio
async def test_a_read_never_opens_an_order_step_by_any_route(no_system_dns):
    """With no write window open (browser.read: open, a link's click,
    back, a redirect) no frame opens an address whose opening may be the
    order itself (/place-order-now?token=, /checkout/complete). An order
    history (/orders) is still read; the checkout's window and its
    handoff after the order (3-D Secure) open a step, and a handoff the
    model asked for does not."""
    g = Guard(resolver=public_resolver)
    state = _state()
    for request in (
        FakeRequest("https://shop.example/place-order-now?token=abc"),
        FakeRequest("https://shop.example/checkout/complete", top=False),
    ):
        route = FakeRoute(FakeResponse(200))
        await g._route(route, request, state)
        assert route.calls == [("abort", "blockedbyclient")], request.url
        assert state.blocked[-1]["reason"] == guard.READ_TIER_ORDER_STEP
    route = FakeRoute(FakeResponse(302, "/confirm-order?id=7"))
    await g._route(route, FakeRequest("https://shop.example/go"), state)
    assert route.calls == [("abort", "blockedbyclient")]
    assert state.blocked[-1]["via"] == "https://shop.example/go"
    assert state.blocked[-1]["reason"] == guard.READ_TIER_ORDER_STEP
    assert guard.READ_TIER_ORDER_STEP not in guard.SENDING_REASONS
    for url in ("https://shop.example/orders/8841", "https://shop.example/checkout/pay", "https://shop.example/pay"):
        route = FakeRoute(FakeResponse(200))
        await g._route(route, FakeRequest(url), state)
        assert route.calls[-1][0] == "fulfill", url
    blocked = len(state.blocked)
    for window in ("write_allowed", "checkout_handoff"):
        setattr(state, window, True)
        route = FakeRoute(FakeResponse(200))
        await g._route(route, FakeRequest("https://shop.example/checkout/complete"), state)
        assert route.calls[-1][0] == "fulfill", window
        setattr(state, window, False)
    assert len(state.blocked) == blocked
    state.human_driving = True
    route = FakeRoute(FakeResponse(200))
    await g._route(route, FakeRequest("https://shop.example/checkout/complete"), state)
    assert route.calls == [("abort", "blockedbyclient")]
    assert state.blocked[-1]["reason"] == guard.READ_TIER_ORDER_STEP


@pytest.mark.asyncio
async def test_a_page_request_to_an_order_address_is_stopped_outside_a_write_window(no_system_dns):
    """A page's own request (fetch, XHR, beacon) is not a navigation. Sent
    to an order address with no write window open (a read-tier click on a
    script button, a page that orders on load) it is stopped; while
    browser.act changes something (``changing``) too, and browser.act
    reports it (``SENDING_REASONS``). A GET, a request anywhere else
    (suggestions, analytics) and anything inside a write window or the
    checkout's own handoff pass; a handoff the model asked for does not
    open the order addresses."""
    g = Guard(resolver=public_resolver)
    state = _state()
    route = FakeRoute()
    await g._route(route, FakeRequest("https://shop.example/place-order", method="POST", navigation=False), state)
    assert route.calls == [("abort", "blockedbyclient")]
    assert state.blocked[-1]["reason"] == guard.READ_TIER_ORDER_STEP
    for url in ("https://shop.example/api/orders", "https://shop.example/orders", "https://shop.example/pay?x=1",
                "https://shop.example/buy/1", "https://shop.example/purchase"):
        route = FakeRoute()
        await g._route(route, FakeRequest(url, method="POST", navigation=False), state)
        assert route.calls == [("abort", "blockedbyclient")], url
        assert state.blocked[-1]["reason"] == guard.READ_TIER_ORDER_REQUEST
    assert guard.READ_TIER_ORDER_REQUEST not in guard.SENDING_REASONS
    for url, method in (
        ("https://shop.example/orders", "GET"),
        ("https://shop.example/pay", "OPTIONS"),
        ("https://shop.example/api/suggest", "POST"),
        ("https://www.google-analytics.com/g/collect", "POST"),
    ):
        route = FakeRoute()
        await g._route(route, FakeRequest(url, method=method, navigation=False), state)
        assert route.calls == [("continue", None)], (url, method)
    state.changing = True
    route = FakeRoute()
    await g._route(route, FakeRequest("https://shop.example/api/orders", method="POST", navigation=False), state)
    assert route.calls == [("abort", "blockedbyclient")]
    assert state.blocked[-1]["reason"] == guard.ORDER_REQUEST and guard.ORDER_REQUEST in guard.SENDING_REASONS
    route = FakeRoute()
    await g._route(route, FakeRequest("https://shop.example/api/suggest", method="POST", navigation=False), state)
    assert route.calls == [("continue", None)]
    state.changing = False
    blocked = len(state.blocked)
    for window in ("write_allowed", "checkout_handoff"):
        setattr(state, window, True)
        route = FakeRoute()
        await g._route(route, FakeRequest("https://shop.example/place-order", method="POST", navigation=False), state)
        assert route.calls == [("continue", None)], window
        setattr(state, window, False)
    assert len(state.blocked) == blocked
    state.human_driving = True
    for url in ("https://shop.example/place-order", "https://shop.example/orders"):
        route = FakeRoute()
        await g._route(route, FakeRequest(url, method="POST", navigation=False), state)
        assert route.calls == [("abort", "blockedbyclient")], url


@pytest.mark.asyncio
async def test_a_page_request_of_any_method_to_an_order_step_is_stopped_outside_a_write_window(no_system_dns):
    """Opening an order step can be the order, whoever opens it: outside a
    write window a page's image, GET fetch or preflight to one is stopped
    like a navigation (while browser.act changes something, as the change
    sending itself). An ordinary GET, and one to an order history, pass;
    inside the window, or the checkout's handoff, the step is open."""
    g = Guard(resolver=public_resolver)
    state = _state()
    for url, method in (
        ("https://shop.example/place-order?sku=1", "GET"),
        ("https://shop.example/checkout/complete", "GET"),
        ("https://shop.example/confirm_order", "HEAD"),
        ("https://shop.example/place-order", "OPTIONS"),
    ):
        route = FakeRoute()
        await g._route(route, FakeRequest(url, method=method, navigation=False), state)
        assert route.calls == [("abort", "blockedbyclient")], (url, method)
        assert state.blocked[-1]["reason"] == guard.READ_TIER_ORDER_STEP
    state.changing = True
    route = FakeRoute()
    await g._route(route, FakeRequest("https://shop.example/place-order", navigation=False), state)
    assert route.calls == [("abort", "blockedbyclient")] and state.blocked[-1]["reason"] == guard.ORDER_REQUEST
    state.changing = False
    blocked = len(state.blocked)
    for url in ("https://shop.example/img/logo.png", "https://shop.example/orders/8841", "https://shop.example/pay"):
        route = FakeRoute()
        await g._route(route, FakeRequest(url, navigation=False), state)
        assert route.calls == [("continue", None)], url
    for window in ("write_allowed", "checkout_handoff"):
        setattr(state, window, True)
        route = FakeRoute()
        await g._route(route, FakeRequest("https://shop.example/place-order", navigation=False), state)
        assert route.calls == [("continue", None)], window
        setattr(state, window, False)
    assert len(state.blocked) == blocked


@pytest.mark.asyncio
async def test_a_window_is_open_only_for_the_page_it_was_opened_for(no_system_dns):
    """Approving a step on one tab opens nothing for another: a request
    from another tab, and one whose frame (or page) cannot be told (a
    service worker's, a popup's first navigation), is judged as if no
    window were open, for the write window and the checkout's handoff
    alike. The card's own tab, any frame of it, is inside."""

    class NoFrame(FakeRequest):
        """Playwright raises on ``request.frame`` here; so does this."""

        def __init__(self, url: str, **kwargs) -> None:
            super().__init__(url, **kwargs)
            del self.frame

    g = Guard(resolver=public_resolver)
    state = _state()
    for window in ("write_allowed", "checkout_handoff"):
        setattr(state, window, True)
        for request in (
            FakeRequest("https://shop.example/place-order", method="POST", navigation=False, page=OTHER_TAB),
            FakeRequest("https://shop.example/checkout/complete", page=OTHER_TAB),
            FakeRequest("https://shop.example/place-order", method="POST", top=False, page=OTHER_TAB),
            NoFrame("https://shop.example/place-order", method="POST", navigation=False),
            NoFrame("https://shop.example/checkout/complete"),
        ):
            route = FakeRoute(FakeResponse(200))
            await g._route(route, request, state)
            assert route.calls == [("abort", "blockedbyclient")], (window, request.url)
        for request in (
            FakeRequest("https://shop.example/place-order", method="POST", navigation=False),
            FakeRequest("https://shop.example/checkout/complete"),
        ):
            route = FakeRoute(FakeResponse(200))
            await g._route(route, request, state)
            assert route.calls[-1][0] in ("continue", "fulfill"), (window, request.url)
        setattr(state, window, False)
    state.write_allowed = True
    route = FakeRoute()
    await g._route(route, FakeRequest("https://shop.example/cart/add", method="POST", page=OTHER_TAB), state)
    assert route.calls == [("abort", "blockedbyclient")] and state.blocked[-1]["reason"] == guard.READ_TIER_POST
    state.write_page = None  # a window opened for no page is open for none
    route = FakeRoute()
    await g._route(route, FakeRequest("https://shop.example/cart/add", method="POST"), state)
    assert route.calls == [("abort", "blockedbyclient")]


@pytest.mark.asyncio
async def test_while_a_read_clicks_no_page_script_sends_and_no_order_address_opens(no_system_dns):
    """browser.read's click has no card: while it runs (``read_click``) a
    page script's request is stopped unless it only asks (GET, HEAD,
    OPTIONS), and no frame opens an order address other than an order
    history, directly or through a redirect."""
    g = Guard(resolver=public_resolver)
    state = _state()
    state.read_click = True
    for url in ("https://shop.example/api/cart", "https://collector.example/beacon"):
        route = FakeRoute()
        await g._route(route, FakeRequest(url, method="POST", navigation=False), state)
        assert route.calls == [("abort", "blockedbyclient")], url
        assert state.blocked[-1]["reason"] == guard.READ_CLICK_REQUEST
    route = FakeRoute()
    await g._route(route, FakeRequest("https://shop.example/api/suggest", navigation=False), state)
    assert route.calls == [("continue", None)]
    # A page's GET to an order address other than an order history too.
    route = FakeRoute()
    await g._route(route, FakeRequest("https://shop.example/buy/1", navigation=False), state)
    assert route.calls == [("abort", "blockedbyclient")] and state.blocked[-1]["reason"] == guard.READ_CLICK_ADDRESS
    route = FakeRoute()
    await g._route(route, FakeRequest("https://shop.example/orders/8841", navigation=False), state)
    assert route.calls == [("continue", None)]
    for url in ("https://shop.example/buy/1", "https://shop.example/orders/8841/reorder"):
        route = FakeRoute(FakeResponse(200))
        await g._route(route, FakeRequest(url), state)
        assert route.calls == [("abort", "blockedbyclient")], url
        assert state.blocked[-1]["reason"] == guard.READ_CLICK_ADDRESS
    route = FakeRoute(FakeResponse(302, "/buy/1"))
    await g._route(route, FakeRequest("https://shop.example/go"), state)
    assert route.calls == [("abort", "blockedbyclient")] and state.blocked[-1]["via"] == "https://shop.example/go"
    route = FakeRoute(FakeResponse(200))
    await g._route(route, FakeRequest("https://shop.example/orders"), state)
    assert route.calls[-1][0] == "fulfill"
    assert {guard.READ_CLICK_REQUEST, guard.READ_CLICK_ADDRESS} <= guard.READ_CLICK_REASONS
    state.read_click = False
    route = FakeRoute(FakeResponse(200))
    await g._route(route, FakeRequest("https://shop.example/buy/1"), state)
    assert route.calls[-1][0] == "fulfill"  # a product's buy page is opened to be read


@pytest.mark.asyncio
async def test_the_persons_handoff_sends_nothing_to_an_order_address_unless_it_follows_the_checkout(no_system_dns):
    """The model may ask for a handoff on any page: while the person holds
    it their own sign-in passes, but no frame sends to an order address.
    Only browser.checkout's handoff after the approved order (3-D Secure)
    opens them, and the agent's next action shuts both (``take_back``)."""
    g = Guard(resolver=public_resolver)
    state = _state()
    session = SimpleNamespace(context=object())

    class Page:
        async def wait_for_load_state(self, *_args, **_kwargs):
            return None

    async def page():
        return Page()

    session.page = page
    fake = SimpleNamespace(egress_state=lambda _context: state)
    _shared.hand_over(fake, session, TAB)
    assert state.human_driving is True and state.checkout_handoff is False
    route = FakeRoute()
    await g._route(route, FakeRequest("https://shop.example/login", method="POST"), state)
    assert route.calls == [("continue", None)]
    for url in ("https://shop.example/orders", "https://shop.example/pay/confirm"):
        route = FakeRoute()
        await g._route(route, FakeRequest(url, method="POST"), state)
        assert route.calls == [("abort", "blockedbyclient")], url
        assert state.blocked[-1]["reason"] == guard.READ_TIER_ORDER_REQUEST
    await _shared.take_back(fake, session)
    _shared.hand_over(fake, session, TAB, checkout=True)
    assert state.human_driving is True and state.checkout_handoff is True
    route = FakeRoute()
    await g._route(route, FakeRequest("https://shop.example/pay/confirm", method="POST"), state)
    assert route.calls == [("continue", None)]
    # The checkout's handoff is its page's: another tab still sends nothing there.
    route = FakeRoute()
    await g._route(route, FakeRequest("https://shop.example/pay/confirm", method="POST", page=OTHER_TAB), state)
    assert route.calls == [("abort", "blockedbyclient")]
    await _shared.take_back(fake, session)
    assert state.human_driving is False and state.checkout_handoff is False and state.handoff_page is None


# -- the tab's own navigation, inside a window ---------------------------------


@pytest.mark.asyncio
async def test_inside_a_window_only_the_approved_page_navigates_its_tab(no_system_dns):
    """Another site's tab that holds the approved one (it opened the shop
    with window.open) may point it anywhere: the navigation is the approved
    tab's, but its Origin or Referer names the other site, so it is stopped
    inside the window, an order step and a page of that site's own (which
    would then open the step as the tab's own) alike. The approved page's
    own passes, and so does one that names no origin while its tab is the
    only one. Outside a window the rule does not apply."""
    g = Guard(resolver=public_resolver)
    state = _state()
    for window in ("write_allowed", "checkout_handoff"):
        setattr(state, window, True)
        for method, headers in (
            ("GET", {"referer": "https://deals.example/"}),
            ("POST", {"origin": "https://deals.example", "referer": "https://deals.example/"}),
            ("GET", {}),
        ):
            route = FakeRoute(FakeResponse(200))
            await g._route(route, FakeRequest("https://shop.example/place-order?sku=9", method=method, headers=headers), state)
            assert route.calls == [("abort", "blockedbyclient")], (window, headers)
            assert state.blocked[-1]["reason"] == guard.OTHER_PAGE_NAVIGATION
        for headers in (FROM_TAB, {"origin": "https://shop.example"}, {"origin": "null", "referer": "https://shop.example/c"}):
            route = FakeRoute(FakeResponse(200))
            await g._route(route, FakeRequest("https://shop.example/place-order?sku=1", headers=headers), state)
            assert route.calls[-1][0] == "fulfill", (window, headers)
        route = FakeRoute(FakeResponse(200))
        await g._route(route, FakeRequest("https://deals.example/bounce", headers={"referer": "https://deals.example/"}), state)
        assert route.calls == [("abort", "blockedbyclient")], window
        route = FakeRoute(FakeResponse(200))
        await g._route(route, FakeRequest("https://pay.example/start", headers=FROM_TAB), state)
        assert route.calls[-1][0] == "fulfill", window  # the page's own, to another site
        setattr(state, window, False)
    route = FakeRoute(FakeResponse(200))
    await g._route(route, FakeRequest("https://shop.example/cart", headers={"referer": "https://deals.example/"}), state)
    assert route.calls[-1][0] == "fulfill"
    alone = SimpleNamespace(url="https://shop.example/cart")
    alone.context = SimpleNamespace(pages=[alone])
    state.write_allowed, state.write_page = True, alone
    route = FakeRoute(FakeResponse(200))
    await g._route(route, FakeRequest("https://shop.example/place-order", headers={}, page=alone), state)
    assert route.calls[-1][0] == "fulfill"
    alone.context.pages.append(OTHER_TAB)
    route = FakeRoute(FakeResponse(200))
    await g._route(route, FakeRequest("https://shop.example/place-order", headers={}, page=alone), state)
    assert route.calls == [("abort", "blockedbyclient")] and state.blocked[-1]["reason"] == guard.OTHER_PAGE_NAVIGATION


# -- every hop of a redirect chain is judged (the navigation path) --------------
# A top-level GET is fetched by the guard and a 3xx comes back as a client
# hop, never route.continue_()d: Playwright routes only a request's first
# URL, so a hop the browser followed itself would go out unjudged.


class _InternalHostGuard(Guard):
    """The real guard, with a second local server standing in for a host on
    the private network: its port is refused the way check_url refuses a
    private address, and every URL checked is kept in order."""

    def __init__(self, internal_port: int) -> None:
        super().__init__(resolver=lambda host: ["127.0.0.1"])
        self.internal_port = internal_port
        self.checked: list[str] = []

    def check_url(self, url: str):
        self.checked.append(url)
        if urlsplit(url).port == self.internal_port:
            return "resolves to a private or local address (127.0.0.1, the stand-in internal host)"
        return super().check_url(url)


@pytest.fixture
def internal_site():
    from tests.fakesite import FakeSite

    site = FakeSite().start()
    try:
        yield site
    finally:
        site.stop()


def _chain_guard(internal_site) -> _InternalHostGuard:
    return _InternalHostGuard(int(urlsplit(internal_site.base).port or 0))


@pytest.mark.asyncio
@pytest.mark.parametrize("hops", [1, 2, 4])
async def test_a_redirect_chain_is_stopped_at_whichever_hop_turns_private(page, fakesite, internal_site, monkeypatch, hops):
    """/chain/1 → … → /chain/<hops> → the internal host: every hop is
    judged before the browser sends it, so the internal host never gets a
    request, however deep in the chain it comes."""
    from tests.fakesite.pages import REDIRECTS

    for i in range(1, hops):
        monkeypatch.setitem(REDIRECTS, f"/chain/{i}", f"/chain/{i + 1}")
    monkeypatch.setitem(REDIRECTS, f"/chain/{hops}", internal_site.url("/admin"))
    g = _chain_guard(internal_site)
    await g.install_egress_guard(page.context, account_mode=True)
    try:
        await page.goto(fakesite.url("/chain/1"))
    except Exception as exc:  # noqa: BLE001 - a one-hop chain fails the goto itself
        assert BLOCKED_NAVIGATION_MARKER in str(exc)
    deadline = time.monotonic() + 5
    while not egress_state(page.context).blocked and time.monotonic() < deadline:
        await asyncio.sleep(0.05)  # a later hop is a navigation of the page's own
    await settle_blocked_navigation(page)
    assert internal_site.handled == []
    assert [path for _method, path in fakesite.handled] == [f"/chain/{i}" for i in range(1, hops + 1)]
    # Each hop is judged as a redirect's target and again as a navigation.
    assert list(dict.fromkeys(g.checked)) == [fakesite.url(f"/chain/{i}") for i in range(1, hops + 1)] + [
        internal_site.url("/admin")
    ]
    assert egress_state(page.context).blocked == [
        {
            "url": internal_site.url("/admin"),
            "reason": "resolves to a private or local address (127.0.0.1, the stand-in internal host)",
            "via": fakesite.url(f"/chain/{hops}"),
        }
    ]


@pytest.mark.asyncio
async def test_a_multi_hop_public_redirect_chain_loads_with_every_hop_judged(page, fakesite, internal_site, monkeypatch):
    from tests.fakesite.pages import REDIRECTS

    monkeypatch.setitem(REDIRECTS, "/chain/1", "/chain/2")
    monkeypatch.setitem(REDIRECTS, "/chain/2", fakesite.url("/chain/3"))  # absolute, as a CDN writes it
    monkeypatch.setitem(REDIRECTS, "/chain/3", "/grades")
    g = _chain_guard(internal_site)
    await g.install_egress_guard(page.context, account_mode=True)
    await page.goto(fakesite.url("/chain/1"))
    await page.wait_for_url("**/grades")
    assert "Grades" in await page.title()
    hops = [fakesite.url(path) for path in ("/chain/1", "/chain/2", "/chain/3", "/grades")]
    assert list(dict.fromkeys(g.checked)) == hops
    assert [path for _method, path in fakesite.handled] == ["/chain/1", "/chain/2", "/chain/3", "/grades"]
    assert egress_state(page.context).blocked == []


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "location",
    [
        "http://127.0.0.1:8080/admin",
        "http://[::1]/",
        "http://169.254.169.254/latest/meta-data/",
        "http://10.0.0.1/",
        "http://0.0.0.0/",
    ],
)
async def test_route_never_lets_a_hop_reach_a_loopback_private_or_link_local_address(no_system_dns, monkeypatch, location):
    """Without the test toggle (production), a public page's redirect to
    any local address is aborted before the browser sends it."""
    monkeypatch.delenv("CRAWLER_ALLOW_LOOPBACK_FOR_TESTS", raising=False)
    state, route = _state(), FakeRoute(FakeResponse(302, location))
    await Guard(resolver=public_resolver)._route(route, FakeRequest("https://shop.example/go"), state)
    assert route.calls == [("abort", "blockedbyclient")]
    assert state.blocked[-1]["url"] == location and state.blocked[-1]["via"] == "https://shop.example/go"
    assert "private or local" in state.blocked[-1]["reason"]
