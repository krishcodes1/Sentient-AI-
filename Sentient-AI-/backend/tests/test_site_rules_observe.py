"""Tests for the owner's site rules in the shared observe step
(``services/tools/browser/_shared.observe`` through
``SiteRuleGuardHook.page_notice``): they prove that a page on an Always-ask
site is described with a ``site_notice`` (and the read is recorded for the
audit log), that a page on a Blocked site is blanked, refused and never
remembered as the page a later act binds to, that inside the checkout's
3-D Secure hand-off a blocked bank page is described with its own notice,
that rules which were never read refuse to describe a web page (but not a
blank one), that a hook that raises refuses too, and that without a guard
or a hook nothing changes.

Why it exists: a page can be on a Blocked site without any navigation the
guard saw (a page loaded before the rule existed, a "back" from the
browser's cache), and the model must be told a sensitive site is sensitive
before it plans actions there. Pure: a fake page and a fake outline, no
browser.
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any, Optional

import pytest

from services.site_rules import messages
from services.site_rules.hooks import SiteRuleGuardHook
from services.tools.browser import _shared
from services.tools.browser import snapshot as snap
from services.tools.browser.guard import PageNotice
from services.tools.browser.pagememory import PageMemory
from services.tools.browser.session import TaskState
from tests.site_rules_fakes import FakeSiteRules, egress_state, snapshot_of


class FakePage:
    def __init__(self, url: str) -> None:
        self.url = url
        self.visited: list[str] = []

    async def goto(self, url: str, timeout: int = 0) -> None:
        self.visited.append(url)
        self.url = url


class NoChallenge:
    def __init__(self) -> None:
        self.asked = 0

    async def detect_challenge(self, page: Any) -> None:
        self.asked += 1
        return None


def _session(page: FakePage) -> SimpleNamespace:
    async def current_page() -> FakePage:
        return page

    return SimpleNamespace(
        context=object(),
        user_id="ann",
        mode="account",
        task=TaskState(task_id="t1"),
        typed_secrets=[],
        page=current_page,
    )


@pytest.fixture
def fake_outline(monkeypatch):
    """The outline of whatever page is open, without a browser."""

    async def outline(page: Any, **_kwargs: Any) -> snap.Outline:
        return snap.Outline(
            url=page.url, title="A page", lines=['- heading "Sign in" [ref=e1]'], refs=1, chars=30, truncated=False
        )

    monkeypatch.setattr(_shared.snap, "outline", outline)


def _guard_with(hook: Any, **state_fields: Any) -> tuple[SimpleNamespace, Any]:
    state = egress_state()
    for name, value in state_fields.items():
        setattr(state, name, value)
    state.site_rules = hook
    return SimpleNamespace(egress_state=lambda context: state), state


@pytest.mark.asyncio
async def test_an_observed_sensitive_page_carries_a_site_notice(fake_outline):
    service = FakeSiteRules(snapshot_of({}))
    guard, _ = _guard_with(SiteRuleGuardHook(service, "ann"))
    page = FakePage("https://secure.chase.com/accounts?id=SECRET1")
    result = await _shared.observe(_session(page), NoChallenge(), "open", {"url": page.url}, guard=guard)
    assert result["ok"] is True and result["outline"] == ['- heading "Sign in" [ref=e1]']
    assert result["site_notice"] == (
        "secure.chase.com is a sensitive site (Banks and money accounts list in Site rules). "
        "Reading it is fine; every action on it needs the person's approval, and the approval "
        "card will say it is a sensitive site."
    )
    assert "SECRET1" not in result["site_notice"]
    assert service.hits == [
        {"user_id": "ann", "host": "secure.chase.com", "kind": "always_ask", "where": "read", "audit": True}
    ]
    # A Trusted or unlisted page carries no notice.
    trusted = FakeSiteRules(snapshot_of({"secure.chase.com": "trusted"}))
    guard, _ = _guard_with(SiteRuleGuardHook(trusted, "ann"))
    result = await _shared.observe(_session(page), NoChallenge(), "open", {}, guard=guard)
    assert result["ok"] is True and "site_notice" not in result and trusted.hits == []


@pytest.mark.asyncio
async def test_an_observed_blocked_page_is_blanked_refused_and_not_remembered(fake_outline):
    service = FakeSiteRules(snapshot_of({"*.example-casino.com": "blocked"}))
    guard, _ = _guard_with(SiteRuleGuardHook(service, "ann"))
    page = FakePage("https://www.example-casino.com/lobby")
    memory = PageMemory()
    challenge = NoChallenge()
    result = await _shared.observe(
        _session(page), challenge, "back", {}, guard=guard, memory=memory
    )
    assert result == {
        "ok": False,
        "refused": True,
        "rule": "site_blocked",
        "error": messages.blocked_page("www.example-casino.com"),
        "mode": "account",
    }
    assert page.visited == ["about:blank"]
    assert memory.get("ann") is None  # no later act can bind to it
    assert challenge.asked == 0  # never examined, never described
    assert service.hits[-1]["where"] == "read" and service.hits[-1]["kind"] == "blocked"


@pytest.mark.asyncio
async def test_inside_the_checkout_handoff_a_blocked_bank_page_is_described_with_its_own_notice(fake_outline):
    service = FakeSiteRules(snapshot_of({}, {"banks": "blocked"}))
    page = FakePage("https://secure.chase.com/3ds")
    guard, _ = _guard_with(SiteRuleGuardHook(service, "ann"), checkout_handoff=True, handoff_page=page)
    result = await _shared.observe(_session(page), NoChallenge(), "wait", {}, guard=guard)
    assert result["ok"] is True
    assert result["site_notice"] == messages.read_notice_exempt("secure.chase.com")
    # The same page outside the hand-off is refused.
    guard, _ = _guard_with(SiteRuleGuardHook(service, "ann"))
    result = await _shared.observe(_session(FakePage(page.url)), NoChallenge(), "wait", {}, guard=guard)
    assert result["refused"] is True and result["rule"] == "site_blocked"


@pytest.mark.asyncio
async def test_rules_that_were_never_read_refuse_to_describe_a_web_page_but_not_a_blank_one(fake_outline):
    guard, _ = _guard_with(SiteRuleGuardHook(FakeSiteRules(None), "ann"))
    page = FakePage("https://shop.example/")
    result = await _shared.observe(_session(page), NoChallenge(), "open", {}, guard=guard)
    assert result == {
        "ok": False,
        "refused": True,
        "rule": "site_rules_unavailable",
        "error": messages.UNAVAILABLE_PAGE,
        "mode": "account",
    }
    assert messages.UNAVAILABLE_PAGE == _shared.UNAVAILABLE_TEXT
    # A web page behind a wrapper is still a web page.
    for wrapped in ("blob:https://shop.example/1f2e", "view-source:https://shop.example/"):
        result = await _shared.observe(_session(FakePage(wrapped)), NoChallenge(), "open", {}, guard=guard)
        assert result["refused"] is True and result["rule"] == "site_rules_unavailable", wrapped
    blank = FakePage("about:blank")
    result = await _shared.observe(_session(blank), NoChallenge(), "tabs", {}, guard=guard)
    assert result["ok"] is True and blank.visited == []


@pytest.mark.asyncio
async def test_observe_without_a_guard_or_a_hook_is_unchanged(fake_outline):
    page = FakePage("https://www.example-casino.com/")
    for guard in (
        None,
        SimpleNamespace(egress_state=lambda context: None),
        _guard_with(None)[0],
    ):
        result = await _shared.observe(_session(page), NoChallenge(), "open", {}, guard=guard)
        assert result["ok"] is True and "site_notice" not in result
        assert page.visited == []


class RaisingRules:
    def navigation_reason(self, url: str, *, exempt: bool) -> Optional[str]:
        return None

    def page_notice(self, url: str, *, exempt: bool) -> Optional[PageNotice]:
        raise RuntimeError("rules exploded")


@pytest.mark.asyncio
async def test_a_notice_hook_that_raises_refuses_to_describe_the_page(fake_outline):
    guard, _ = _guard_with(RaisingRules())
    page = FakePage("https://shop.example/")
    result = await _shared.observe(_session(page), NoChallenge(), "open", {}, guard=guard)
    assert result["refused"] is True and result["rule"] == "site_rules_unavailable"
    assert result["error"] == _shared.UNAVAILABLE_TEXT
    assert page.visited == ["about:blank"]
