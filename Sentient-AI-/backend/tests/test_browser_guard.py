"""URL gate, route-level egress guard and consequential-click detection.
Pure cases run everywhere; the browser-backed ones use the fake site."""

from __future__ import annotations

import re
import time

import pytest
import pytest_asyncio

from services.tools.browser import guard
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
    state.write_allowed = True
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


class FakeFrame:
    def __init__(self, parent=None) -> None:
        self.parent_frame = parent


class FakeRequest:
    def __init__(self, url: str, *, method: str = "GET", navigation: bool = True, top: bool = True) -> None:
        self.url, self.method, self._navigation = url, method, navigation
        self.frame = FakeFrame(None if top else FakeFrame())

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
    return guard.EgressState(account_mode=account_mode)


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
