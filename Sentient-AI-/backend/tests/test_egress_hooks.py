"""Tests for the browser guard's security-wave hooks (services/tools/browser/guard.py
``EgressHooks``, ``Guard._site_reason`` and ``Guard._reputation_reason``, and
services/tools/browser/_shared.py ``attach_egress_hooks``): they prove that without
hooks the route behaves exactly as before; that attaching binds each hook to the
session's user and never replaces a hook with None; that a top-level navigation and
every redirect target pass the SSRF check, then the owner's site rules, then the link
lookup, in that order, while a frame's navigation passes the site rules only and the
bound order POST's redirect the lookup only; that a hook which raises blocks with its
own named reason; that the new reasons join neither SENDING_REASONS nor
READ_CLICK_REASONS; and that browser.read's open and click hand back the notes the
hooks left during their own navigation.

Why it exists: S4 (link reputation) and S7 (site rules) plug into the browser guard
through these seams in WAVE 1, built in parallel against fakes. The order, the
fail-closed handling and the per-context binding are the contract between them, and
nothing else pins them before both skills land. The route cases use fakes (copied from
tests/test_browser_guard.py, not imported, so pytest does not collect that module
twice); the open/click case drives the fake site in headless Chromium and skips where
Playwright's Chromium is not installed.
"""

from __future__ import annotations

import re
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Optional
from urllib.parse import urlsplit

import pytest
import pytest_asyncio

from services.tools.browser import _shared, guard, handoff
from services.tools.browser.actions import BrowserReadToolkit
from services.tools.browser.guard import (
    NAVIGATION_CHECK_FAILED,
    READ_CLICK_REASONS,
    SENDING_REASONS,
    SITE_RULES_FAILED,
    EgressHooks,
    EgressState,
    Guard,
    PageNotice,
)
from services.tools.browser.session import BrowserSessionManager
from services.tools.system import browser_installed

# -- fakes (copied from tests/test_browser_guard.py) ---------------------------------


def public_resolver(host: str) -> list[str]:
    return ["93.184.216.34"]


def private_resolver(host: str) -> list[str]:
    return ["10.0.0.1"]


@pytest.fixture
def no_system_dns(monkeypatch):
    """The guard must judge the injected resolver's answer and nothing else."""
    import core.network_security as network_security

    def refuse(*_args, **_kwargs):
        raise AssertionError("check_url resolved through the system resolver")

    monkeypatch.setattr(guard.socket, "getaddrinfo", refuse)
    monkeypatch.setattr(network_security.socket, "getaddrinfo", refuse)


TAB = SimpleNamespace(name="the card's tab", url="https://shop.example/cart")
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
        headers: Optional[dict[str, str]] = None,
    ) -> None:
        self.url, self.method, self._navigation = url, method, navigation
        self.frame = FakeFrame(None if top else FakeFrame(page=page), page=page)
        self.headers = dict(FROM_TAB if headers is None else headers)

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
        if isinstance(self._response, Exception):
            raise self._response
        return self._response

    async def fulfill(self, **kwargs) -> None:
        self.calls.append(("fulfill", kwargs))


def _state(*, account_mode: bool = True) -> EgressState:
    return EgressState(account_mode=account_mode, write_page=TAB, handoff_page=TAB)


class ScriptedSiteRules:
    """A SiteRuleHook that blocks the hosts it was given and records every call."""

    def __init__(self, calls: list[tuple[str, str]], *, blocked: tuple[str, ...] = (), raises: bool = False):
        self.calls, self.blocked, self.raises = calls, blocked, raises
        self.exempt: list[bool] = []

    def navigation_reason(self, url: str, *, exempt: bool) -> Optional[str]:
        self.calls.append(("site_rules", url))
        self.exempt.append(exempt)
        if self.raises:
            raise RuntimeError("rules not loaded")
        host = urlsplit(url).hostname or ""
        return f"the owner blocked {host}" if host in self.blocked else None

    def page_notice(self, url: str, *, exempt: bool) -> Optional[PageNotice]:
        return None


def scripted_reputation(calls: list[tuple[str, str]], *, listed: tuple[str, ...] = (), raises: bool = False):
    """A NavigationCheck that blocks the listed hosts and records every call."""

    async def check(url: str, state: Any) -> Optional[str]:
        calls.append(("reputation", url))
        if raises:
            raise RuntimeError("lookup service broke")
        host = urlsplit(url).hostname or ""
        return f"Google Safe Browsing says {host} is deceptive" if host in listed else None

    return check


# -- the route without and with hooks ------------------------------------------------


@pytest.mark.asyncio
async def test_without_hooks_the_route_behaves_exactly_as_before(no_system_dns):
    state = _state()
    assert (state.site_rules, state.reputation, state.notes) == (None, None, [])
    g = Guard(resolver=public_resolver)
    answer = FakeResponse(200)
    route = FakeRoute(answer)
    await g._route(route, FakeRequest("https://shop.example/a"), state)
    assert route.calls == [("fulfill", {"response": answer})]
    route = FakeRoute()
    await g._route(route, FakeRequest("https://ads.example/frame", top=False), state)
    assert route.calls == [("continue", None)]
    route = FakeRoute(FakeResponse(302, "https://shop.example/next"))
    await g._route(route, FakeRequest("https://shop.example/start"), state)
    assert route.calls[-1][0] == "fulfill"
    assert state.blocked == [] and state.notes == []


def test_attach_binds_the_user_and_never_replaces_a_hook_with_none():
    state = _state()
    fake_guard = SimpleNamespace(egress_state=lambda context: state)
    session = SimpleNamespace(context=object(), user_id="ann")
    bound: list[tuple[str, str]] = []

    def site_rules_for(user_id: str):
        bound.append(("site_rules", user_id))
        return ScriptedSiteRules([])

    def reputation_for(user_id: str):
        bound.append(("reputation", user_id))
        return scripted_reputation([])

    _shared.attach_egress_hooks(fake_guard, session, EgressHooks(site_rules=site_rules_for))
    rules = state.site_rules
    assert isinstance(rules, ScriptedSiteRules) and state.reputation is None
    _shared.attach_egress_hooks(fake_guard, session, EgressHooks(reputation=reputation_for))
    assert state.site_rules is rules and callable(state.reputation)
    _shared.attach_egress_hooks(fake_guard, session, None)
    _shared.attach_egress_hooks(fake_guard, session, EgressHooks())
    assert state.site_rules is rules and callable(state.reputation)
    assert bound == [("site_rules", "ann"), ("reputation", "ann")]
    # No egress state (a test double's guard): nothing to bind, nothing raised.
    _shared.attach_egress_hooks(
        SimpleNamespace(egress_state=lambda context: None), session, EgressHooks(site_rules=site_rules_for)
    )
    assert bound == [("site_rules", "ann"), ("reputation", "ann")]


@pytest.mark.asyncio
async def test_site_rules_run_after_ssrf_and_before_reputation_on_navigations_and_redirects(no_system_dns):
    calls: list[tuple[str, str]] = []
    state = _state()
    state.site_rules = ScriptedSiteRules(calls, blocked=("blocked.example",))
    state.reputation = scripted_reputation(calls, listed=("listed.example",))
    # SSRF first: a private address never reaches either hook.
    route = FakeRoute()
    await Guard(resolver=private_resolver)._route(route, FakeRequest("https://intranet.example/"), state)
    assert route.calls == [("abort", "blockedbyclient")] and calls == []
    g = Guard(resolver=public_resolver)
    # A Blocked site stops the navigation before any lookup is made.
    route = FakeRoute(FakeResponse(200))
    await g._route(route, FakeRequest("https://blocked.example/x"), state)
    assert route.calls == [("abort", "blockedbyclient")]
    assert calls == [("site_rules", "https://blocked.example/x")]
    assert state.blocked[-1]["reason"] == "the owner blocked blocked.example"
    # Allowed by the rules: the lookup runs next and its listing blocks.
    calls.clear()
    route = FakeRoute(FakeResponse(200))
    await g._route(route, FakeRequest("https://listed.example/"), state)
    assert calls == [("site_rules", "https://listed.example/"), ("reputation", "https://listed.example/")]
    assert route.calls == [("abort", "blockedbyclient")]
    assert state.blocked[-1]["reason"] == "Google Safe Browsing says listed.example is deceptive"
    # A redirect's target is judged the same way, in the same order, with via.
    calls.clear()
    route = FakeRoute(FakeResponse(302, "https://listed.example/landing"))
    await g._route(route, FakeRequest("https://shop.example/go"), state)
    assert calls == [
        ("site_rules", "https://shop.example/go"),
        ("reputation", "https://shop.example/go"),
        ("site_rules", "https://listed.example/landing"),
        ("reputation", "https://listed.example/landing"),
    ]
    assert route.calls == [("abort", "blockedbyclient")]
    assert state.blocked[-1] == {
        "url": "https://listed.example/landing",
        "reason": "Google Safe Browsing says listed.example is deceptive",
        "via": "https://shop.example/go",
    }
    # Nothing to say: the page is fetched and handed over as before.
    calls.clear()
    answer = FakeResponse(200)
    route = FakeRoute(answer)
    await g._route(route, FakeRequest("https://shop.example/fine"), state)
    assert route.calls == [("fulfill", {"response": answer})] and len(calls) == 2
    # No window is open here, so the rules were never told to exempt anything.
    assert set(state.site_rules.exempt) == {False}


@pytest.mark.asyncio
async def test_frame_navigations_are_judged_by_site_rules_only(no_system_dns):
    calls: list[tuple[str, str]] = []
    state = _state()
    state.site_rules = ScriptedSiteRules(calls, blocked=("blocked.example",))
    state.reputation = scripted_reputation(calls, listed=("listed.example",))
    g = Guard(resolver=public_resolver)
    route = FakeRoute()
    await g._route(route, FakeRequest("https://listed.example/widget", top=False), state)
    assert route.calls == [("continue", None)]
    route = FakeRoute()
    await g._route(route, FakeRequest("https://blocked.example/widget", top=False), state)
    assert route.calls == [("abort", "blockedbyclient")]
    assert calls == [
        ("site_rules", "https://listed.example/widget"),
        ("site_rules", "https://blocked.example/widget"),
    ]
    # A page's own requests (images, fetches) are not navigations: neither hook runs.
    calls.clear()
    route = FakeRoute()
    await g._route(route, FakeRequest("https://blocked.example/pixel.gif", navigation=False), state)
    assert route.calls == [("continue", None)] and calls == []


@pytest.mark.asyncio
async def test_the_bound_post_redirect_is_judged_by_reputation_only(no_system_dns):
    calls: list[tuple[str, str]] = []
    state = _state()
    state.write_allowed, state.write_origin = True, "https://shop.example"
    rules = ScriptedSiteRules(calls, blocked=("listed.example",))
    state.site_rules = rules
    state.reputation = scripted_reputation(calls, listed=("listed.example",))
    g = Guard(resolver=public_resolver)
    route = FakeRoute(FakeResponse(302, "https://shop.example/thanks"))
    await g._route(route, FakeRequest("https://shop.example/pay", method="POST"), state)
    assert route.calls[-1][0] == "fulfill" and state.blocked == []
    assert calls == [
        ("site_rules", "https://shop.example/pay"),
        ("reputation", "https://shop.example/pay"),
        ("reputation", "https://shop.example/thanks"),
    ]
    # Inside the approved order's window the rules are told so (review SEC-F4).
    assert rules.exempt == [True]
    calls.clear()
    route = FakeRoute(FakeResponse(303, "https://listed.example/collect"))
    await g._route(route, FakeRequest("https://shop.example/pay", method="POST"), state)
    assert route.calls == [("abort", "blockedbyclient")]
    assert ("site_rules", "https://listed.example/collect") not in calls
    assert calls[-1] == ("reputation", "https://listed.example/collect")
    assert state.blocked[-1]["via"] == "https://shop.example/pay"


@pytest.mark.asyncio
async def test_a_hook_that_raises_blocks_with_its_named_reason(no_system_dns):
    from structlog.testing import capture_logs

    g = Guard(resolver=public_resolver)
    calls: list[tuple[str, str]] = []
    state = _state()
    state.site_rules = ScriptedSiteRules(calls, raises=True)
    state.reputation = scripted_reputation(calls)
    with capture_logs() as logs:
        route = FakeRoute(FakeResponse(200))
        await g._route(route, FakeRequest("https://shop.example/a?token=SECRET"), state)
        frame = FakeRoute()
        await g._route(frame, FakeRequest("https://shop.example/frame", top=False), state)
    assert route.calls == [("abort", "blockedbyclient")] and frame.calls == route.calls
    assert [entry["reason"] for entry in state.blocked] == [SITE_RULES_FAILED, SITE_RULES_FAILED]
    assert ("reputation", "https://shop.example/a?token=SECRET") not in calls
    failed = [entry for entry in logs if entry["event"] == "browser_site_rules_failed"]
    assert failed and failed[0]["error_type"] == "RuntimeError" and "SECRET" not in repr(logs)

    state = _state()
    state.reputation = scripted_reputation(calls, raises=True)
    with capture_logs() as logs:
        route = FakeRoute(FakeResponse(200))
        await g._route(route, FakeRequest("https://shop.example/b?token=SECRET"), state)
    assert route.calls == [("abort", "blockedbyclient")]
    assert state.blocked[-1]["reason"] == NAVIGATION_CHECK_FAILED
    failed = [entry for entry in logs if entry["event"] == "browser_navigation_check_failed"]
    assert failed and failed[0]["error_type"] == "RuntimeError" and "SECRET" not in repr(logs)


def test_the_new_reasons_join_neither_sending_nor_read_click_reasons():
    for reason in (SITE_RULES_FAILED, NAVIGATION_CHECK_FAILED):
        assert reason not in SENDING_REASONS and reason not in READ_CLICK_REASONS
    assert SITE_RULES_FAILED == "the owner's site rules could not be checked"
    assert NAVIGATION_CHECK_FAILED == "a safety check on this address could not run"


# -- observe: the owner's site rules before a page is described ----------------------


class _BlankablePage:
    url = "https://blocked.example/inbox"

    def __init__(self) -> None:
        self.visited: list[str] = []

    async def goto(self, url: str, timeout: int = 0) -> None:
        self.visited.append(url)


class _NeverCalledHandoff:
    async def detect_challenge(self, page):
        raise AssertionError("a blocked page is never examined")


class _NoticeRules:
    def __init__(self, notice: Optional[PageNotice] = None, *, raises: bool = False) -> None:
        self.notice, self.raises = notice, raises

    def navigation_reason(self, url: str, *, exempt: bool) -> Optional[str]:
        return None

    def page_notice(self, url: str, *, exempt: bool) -> Optional[PageNotice]:
        if self.raises:
            raise RuntimeError("rules not loaded")
        return self.notice


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "rules, rule, text",
    [
        (_NoticeRules(PageNotice("blocked", "site_blocked", "The owner blocked this site.")),
         "site_blocked", "The owner blocked this site."),
        (_NoticeRules(raises=True), "site_rules_unavailable", _shared.UNAVAILABLE_TEXT),
    ],
)
async def test_a_blocked_or_unreadable_site_notice_blanks_the_page_and_describes_nothing(rules, rule, text):
    page = _BlankablePage()
    state = _state()
    state.site_rules = rules
    session = SimpleNamespace(context=object(), user_id="ann", mode="account")

    async def current_page():
        return page

    session.page = current_page
    fake_guard = SimpleNamespace(egress_state=lambda context: state)
    result = await _shared.observe(session, _NeverCalledHandoff(), "open", {"url": page.url}, guard=fake_guard)
    assert result == {"ok": False, "refused": True, "rule": rule, "error": text, "mode": "account"}
    assert page.visited == ["about:blank"]


# -- browser.read open and click hand back their own navigation's notes ---------------


class _Platform:
    """Headless Chromium, no channel, profiles under the test's tmp dir."""

    name = "container"

    def __init__(self, root: Path) -> None:
        self._root = root

    def browser_channel(self):
        return None

    def profile_dir(self, user_id: str) -> Path:
        path = self._root / user_id
        path.mkdir(parents=True, exist_ok=True)
        return path

    def data_dir(self) -> Path:
        return self._root

    def bring_to_front(self, *, pid=None, title=None) -> bool:
        return False

    def port_owner(self, port: int):
        return None


@pytest_asyncio.fixture
async def noting_kit(fakesite, tmp_path):
    """browser.read on the fake site with a link lookup that never blocks and
    leaves one note per navigation it sees, naming the path."""
    if not browser_installed():
        pytest.skip("Playwright's Chromium is not installed (python -m playwright install chromium)")

    async def note_path(url: str, state: Any) -> Optional[str]:
        state.notes.append({"kind": "link_not_checked", "text": f"looked at {urlsplit(url).path}"})
        return None

    sessions = BrowserSessionManager(headless=True, platform=_Platform(tmp_path), max_sessions=1, max_tabs=2)
    toolkit = BrowserReadToolkit(
        sessions, guard=guard, handoff=handoff, egress_hooks=EgressHooks(reputation=lambda _uid: note_path)
    )
    try:
        yield toolkit
    finally:
        await sessions.close_all()


def _plain_link(result) -> tuple[str, str]:
    """(ref, name) of the first link whose name is not a consequential word."""
    for line in result["outline"]:
        match = re.search(r'- link "([^"]+)".*\[ref=((?:f\d+)?e\d+)\]', line)
        if match and not any(word in match.group(1).lower() for word in guard.CONSEQUENTIAL_NAMES):
            return match.group(2), match.group(1)
    raise AssertionError(f"no plain link in {result['outline']}")


@pytest.mark.asyncio
async def test_open_and_click_return_the_notes_added_during_their_navigation(noting_kit, fakesite):
    opened = await noting_kit.execute("open", {"url": fakesite.url("/")}, user_id="u1", task_id="t1")
    assert opened["ok"] is True
    assert opened["security_notes"] == ["looked at /"]
    ref, _name = _plain_link(opened)
    clicked = await noting_kit.execute("click", {"ref": ref}, user_id="u1", task_id="t1")
    assert clicked["ok"] is True and clicked["url"] != opened["url"]
    # Only the click's own navigation, never the open's note again.
    assert clicked["security_notes"] == [f"looked at {urlsplit(clicked['url']).path}"]
    # A look that navigates nowhere carries none.
    looked = await noting_kit.execute("snapshot", {}, user_id="u1", task_id="t1")
    assert looked["ok"] is True and "security_notes" not in looked
