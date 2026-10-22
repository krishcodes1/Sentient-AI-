"""Tests for the owner's site rules at the browser guard's single choke point
(``Guard._route``, through ``services/site_rules/hooks.py``): they prove
that a top-level navigation, a redirect hop and a frame navigation to a
Blocked site are aborted with the site-rules reason (the hop named), that a
page's own subresources are not judged by site rules, that inside an
approved checkout's window only protected and built-in bank hosts are set
aside (a bank's 3-D Secure page opens even when banks are blocked, an owner
block on any other host still holds), that browser.act's window and the
person's ordinary hand-off are not exempt, that SSRF is asked first, that a
hook that raises or rules that were never read stop the navigation, that
Always ask never stops one, and that without a hook nothing changes.

Why it exists: every way a page can reach a site passes ``_route``, and an
exception there would abort a navigation silently; the order SSRF -> site
rules -> reputation, and the narrow checkout exemption (review SEC-F4,
scaffold A32), are the guarantees owners rely on. Pure: fakes for the
request and the route, no browser, no DNS.
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any, Optional

import pytest

from services.site_rules import messages
from services.site_rules.hooks import SiteRuleGuardHook
from services.site_rules.service import SiteRulesService
from services.tools.browser import _shared, guard
from services.tools.browser.guard import SITE_RULES_FAILED, EgressHooks, Guard
from tests.site_rules_fakes import (
    TAB,
    FakeRequest,
    FakeResponse,
    FakeRoute,
    FakeSiteRules,
    egress_state,
    private_resolver,
    public_resolver,
    snapshot_of,
)

BLOCKED = messages.NAVIGATION_BLOCKED
ABORTED = [("abort", "blockedbyclient")]


@pytest.fixture
def no_system_dns(monkeypatch):
    """check_url must judge the injected resolver's answer only (a lookup
    through the system resolver is network in a unit test)."""
    import core.network_security as network_security

    def refuse(*_args, **_kwargs):
        raise AssertionError("check_url resolved through the system resolver")

    monkeypatch.setattr(guard.socket, "getaddrinfo", refuse)
    monkeypatch.setattr(network_security.socket, "getaddrinfo", refuse)


def _hooked(rules: Any = None, categories: Optional[dict[str, str]] = None, **state: Any):
    """A guard state with the site-rules hook of user "ann" attached."""
    service = FakeSiteRules(snapshot_of(rules or {"*.example-casino.com": "blocked"}, categories))
    egress = egress_state()
    for name, value in state.items():
        setattr(egress, name, value)
    egress.site_rules = SiteRuleGuardHook(service, "ann")
    return egress, service


class RecordingHook:
    """Blocks the URLs that contain one of *blocks*, and records every ask."""

    def __init__(self, *blocks: str, raises: bool = False) -> None:
        self.asked: list[tuple[str, bool]] = []
        self.blocks, self.raises = blocks, raises

    def navigation_reason(self, url: str, *, exempt: bool) -> Optional[str]:
        self.asked.append((url, exempt))
        if self.raises:
            raise RuntimeError("rules exploded")
        return BLOCKED if any(block in url for block in self.blocks) else None

    def page_notice(self, url: str, *, exempt: bool) -> None:
        return None


@pytest.mark.asyncio
async def test_a_top_level_navigation_to_a_blocked_host_is_aborted_with_the_site_rules_reason(no_system_dns):
    state, service = _hooked()
    route = FakeRoute(FakeResponse(200))
    await Guard(resolver=public_resolver)._route(
        route, FakeRequest("https://www.example-casino.com/slots?session=SECRET1"), state
    )
    assert route.calls == ABORTED
    assert state.blocked[-1] == {"url": "https://www.example-casino.com/slots", "reason": BLOCKED}
    assert service.hits == [
        {"user_id": "ann", "host": "www.example-casino.com", "kind": "blocked", "where": "navigation", "audit": True}
    ]
    # An ordinary site opens as before.
    route = FakeRoute(FakeResponse(200))
    await Guard(resolver=public_resolver)._route(route, FakeRequest("https://shop.example/"), state)
    assert route.calls[-1][0] == "fulfill"


@pytest.mark.asyncio
async def test_a_redirect_to_a_blocked_host_is_aborted_and_names_the_hop(no_system_dns):
    state, _ = _hooked()
    route = FakeRoute(FakeResponse(302, "https://example-casino.com/welcome?ref=SECRET2"))
    await Guard(resolver=public_resolver)._route(route, FakeRequest("https://links.example/go?to=casino"), state)
    assert route.calls == ABORTED
    assert state.blocked[-1] == {
        "url": "https://example-casino.com/welcome",
        "reason": BLOCKED,
        "via": "https://links.example/go",
    }


@pytest.mark.asyncio
async def test_a_frame_navigation_to_a_blocked_host_is_aborted(no_system_dns):
    state, _ = _hooked()
    route = FakeRoute()
    await Guard(resolver=public_resolver)._route(
        route, FakeRequest("https://example-casino.com/embed", top=False), state
    )
    assert route.calls == ABORTED and state.blocked[-1]["reason"] == BLOCKED
    # A frame of an ordinary site is left alone, as before.
    route = FakeRoute()
    await Guard(resolver=public_resolver)._route(route, FakeRequest("https://maps.example/embed", top=False), state)
    assert route.calls == [("continue", None)]


@pytest.mark.asyncio
async def test_a_page_subresource_on_a_blocked_host_is_not_judged_by_site_rules(no_system_dns):
    # Blocked means "never navigate there"; a page's own image or script
    # request is outside S7 (documented follow-up).
    state, service = _hooked()
    route = FakeRoute()
    await Guard(resolver=public_resolver)._route(
        route, FakeRequest("https://cdn.example-casino.com/logo.png", navigation=False), state
    )
    assert route.calls == [("continue", None)] and state.blocked == [] and service.hits == []


@pytest.mark.asyncio
async def test_the_bank_3ds_page_opens_inside_an_approved_checkout_even_when_banks_are_blocked(no_system_dns):
    three_ds = "https://secure.chase.com/3ds/challenge"
    # The order POST's window of an approved checkout (it binds write_origin).
    state, _ = _hooked({}, {"banks": "blocked"}, write_allowed=True, write_origin="https://shop.example")
    route = FakeRoute(FakeResponse(200))
    await Guard(resolver=public_resolver)._route(route, FakeRequest(three_ds), state)
    assert route.calls[-1][0] == "fulfill" and state.blocked == []
    # The 3-D Secure hand-off right after it, on the checkout's page.
    state, _ = _hooked({}, {"banks": "blocked"}, checkout_handoff=True, human_driving=True)
    route = FakeRoute(FakeResponse(200))
    await Guard(resolver=public_resolver)._route(route, FakeRequest(three_ds), state)
    assert route.calls[-1][0] == "fulfill" and state.blocked == []
    # A protected payment host the owner's rows somehow block opens there too.
    state, _ = _hooked({"*.cardinalcommerce.com": "blocked"}, checkout_handoff=True, human_driving=True)
    route = FakeRoute(FakeResponse(200))
    await Guard(resolver=public_resolver)._route(route, FakeRequest("https://centinelapi.cardinalcommerce.com/"), state)
    assert route.calls[-1][0] == "fulfill"
    # Outside the window, the blocked bank stays blocked.
    state, _ = _hooked({}, {"banks": "blocked"})
    route = FakeRoute(FakeResponse(200))
    await Guard(resolver=public_resolver)._route(route, FakeRequest(three_ds), state)
    assert route.calls == ABORTED


@pytest.mark.asyncio
async def test_an_owner_blocked_non_bank_host_is_blocked_inside_the_checkout_window(no_system_dns):
    # Review SEC-F4: the window is when the person types bank details, so a
    # redirect from a compromised shop to a site the owner blocked must stop.
    for window in (
        {"write_allowed": True, "write_origin": "https://shop.example"},
        {"checkout_handoff": True, "human_driving": True},
    ):
        state, _ = _hooked(**window)
        route = FakeRoute(FakeResponse(302, "https://pay.example-casino.com/collect"))
        await Guard(resolver=public_resolver)._route(route, FakeRequest("https://shop.example/thanks"), state)
        assert route.calls == ABORTED, window
        assert state.blocked[-1]["reason"] == BLOCKED
        # A built-in bank the owner blocked by its own rule is set aside there, as the bank list is.
        state, _ = _hooked({"*.wellsfargo.com": "blocked"}, **window)
        route = FakeRoute(FakeResponse(200))
        await Guard(resolver=public_resolver)._route(route, FakeRequest("https://connect.secure.wellsfargo.com/3ds"), state)
        assert route.calls[-1][0] == "fulfill", window


@pytest.mark.asyncio
async def test_browser_acts_window_and_the_persons_ordinary_handoff_are_not_exempt(no_system_dns):
    three_ds = "https://secure.chase.com/3ds"
    # browser.act opens a write window without binding an order origin.
    act_window, _ = _hooked({}, {"banks": "blocked"}, write_allowed=True)
    # The person's own hand-off (a sign-in the model asked for).
    handoff, _ = _hooked({}, {"banks": "blocked"}, human_driving=True)
    # The checkout's hand-off, but on another tab than the checkout's page.
    other_tab, _ = _hooked({}, {"banks": "blocked"}, checkout_handoff=True, human_driving=True)
    other_tab.handoff_page = SimpleNamespace(name="another tab")
    for state in (act_window, handoff, other_tab):
        route = FakeRoute(FakeResponse(200))
        await Guard(resolver=public_resolver)._route(route, FakeRequest(three_ds, page=TAB), state)
        assert route.calls == ABORTED
        assert state.blocked[-1]["reason"] == BLOCKED


@pytest.mark.asyncio
async def test_an_always_ask_site_is_never_a_navigation_block(no_system_dns):
    state, service = _hooked({"*.example-bank.test": "always_ask"})
    for url in ("https://secure.chase.com/login", "https://www.example-bank.test/"):
        route = FakeRoute(FakeResponse(200))
        await Guard(resolver=public_resolver)._route(route, FakeRequest(url), state)
        assert route.calls[-1][0] == "fulfill", url
    assert state.blocked == [] and service.hits == []


@pytest.mark.asyncio
async def test_an_ssrf_refusal_wins_and_the_site_hook_is_not_asked(no_system_dns):
    state = egress_state()
    # The hook would block both addresses; SSRF must answer first.
    hook = RecordingHook("intranet.example", "10.0.0.5")
    state.site_rules = hook
    route = FakeRoute()
    await Guard(resolver=private_resolver)._route(route, FakeRequest("http://intranet.example/"), state)
    assert route.calls == ABORTED
    assert state.blocked[-1]["reason"] != BLOCKED and "10.0.0.1" in state.blocked[-1]["reason"]
    assert hook.asked == []
    # On a redirect, too: the hop's SSRF verdict comes first.
    route = FakeRoute(FakeResponse(302, "http://10.0.0.5/admin"))
    await Guard(resolver=lambda host: ["10.0.0.5"] if host == "10.0.0.5" else ["93.184.216.34"])._route(
        route, FakeRequest("https://shop.example/"), state
    )
    assert route.calls == ABORTED and "10.0.0.5" in state.blocked[-1]["reason"]
    assert [url for url, _ in hook.asked] == ["https://shop.example/"]


@pytest.mark.asyncio
async def test_a_hook_that_raises_blocks_the_navigation(no_system_dns, monkeypatch):
    import structlog
    from structlog.testing import capture_logs

    # A fresh module logger: one an earlier test file cached before a later
    # configure_logging() would never reach capture_logs (order dependent).
    monkeypatch.setattr(guard, "logger", structlog.get_logger(guard.__name__))
    state = egress_state()
    state.site_rules = RecordingHook(raises=True)
    route = FakeRoute(FakeResponse(200))
    with capture_logs() as logs:
        await Guard(resolver=public_resolver)._route(
            route, FakeRequest("https://shop.example/a?token=SECRET3"), state
        )
    assert route.calls == ABORTED and state.blocked[-1]["reason"] == SITE_RULES_FAILED
    assert any(entry.get("event") == "browser_site_rules_failed" for entry in logs)
    assert "SECRET3" not in repr(logs)


@pytest.mark.asyncio
async def test_rules_that_were_never_read_stop_every_navigation(no_system_dns):
    state = egress_state()
    state.site_rules = SiteRuleGuardHook(FakeSiteRules(None), "ann")
    route = FakeRoute(FakeResponse(200))
    await Guard(resolver=public_resolver)._route(route, FakeRequest("https://shop.example/"), state)
    assert route.calls == ABORTED
    assert state.blocked[-1]["reason"] == messages.NAVIGATION_UNAVAILABLE


@pytest.mark.asyncio
async def test_without_a_hook_the_route_behaves_exactly_as_before(no_system_dns):
    state = egress_state()
    assert state.site_rules is None
    route = FakeRoute(FakeResponse(200))
    await Guard(resolver=public_resolver)._route(route, FakeRequest("https://example-casino.com/"), state)
    assert route.calls[-1][0] == "fulfill" and state.blocked == []
    # The switch off is the same as no rule at all.
    off = egress_state()
    switched_off = snapshot_of({"*.example-casino.com": "blocked"}, enabled=False)
    off.site_rules = SiteRuleGuardHook(FakeSiteRules(switched_off), "ann")
    route = FakeRoute(FakeResponse(200))
    await Guard(resolver=public_resolver)._route(route, FakeRequest("https://example-casino.com/"), off)
    assert route.calls[-1][0] == "fulfill" and off.blocked == []


def test_the_site_reasons_join_neither_sending_nor_read_click_reasons():
    for reason in (BLOCKED, messages.NAVIGATION_UNAVAILABLE, SITE_RULES_FAILED):
        assert reason not in guard.SENDING_REASONS
        assert reason not in guard.READ_CLICK_REASONS


def test_attach_egress_hooks_binds_the_user_and_never_replaces_a_hook_with_none():
    async def never_called() -> bool:
        raise AssertionError("binding a hook reads nothing")

    service = SiteRulesService(lambda: None, enabled=never_called)  # type: ignore[arg-type, return-value]
    state = egress_state()
    fake_guard = SimpleNamespace(egress_state=lambda context: state)
    session = SimpleNamespace(context=object(), user_id="ann")
    _shared.attach_egress_hooks(fake_guard, session, EgressHooks(site_rules=service.guard_hook_for))  # type: ignore[arg-type]
    hook = state.site_rules
    assert isinstance(hook, SiteRuleGuardHook) and hook.user_id == "ann"
    # A toolkit built without site rules never takes them away.
    _shared.attach_egress_hooks(fake_guard, session, EgressHooks(site_rules=None))  # type: ignore[arg-type]
    _shared.attach_egress_hooks(fake_guard, session, None)  # type: ignore[arg-type]
    assert state.site_rules is hook
    # The bound hook reads the live service: a never-loaded service stops navigations.
    assert hook.navigation_reason("https://shop.example/", exempt=False) == messages.NAVIGATION_UNAVAILABLE
