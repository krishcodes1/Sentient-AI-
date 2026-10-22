"""Tests for the owner's site rules in a real browser: browser.read in
headless Chromium against the fake site, with the site-rules hooks bound
the way the toolkits bind them in production. They prove that opening a
page on a Blocked site is stopped by the route guard before the site
answers, that a redirect from the fake site into a Blocked host stops at
that hop (the hop named, the target never requested), and that a page on an
Always-ask site is read and described with a ``site_notice``.

Why it exists: the fakes in test_site_rules_guard.py and
test_site_rules_observe.py pin the decisions; this pins that Chromium's own
navigations really pass through them. Skipped where Playwright's Chromium
is not installed; never a real website (the fake site on 127.0.0.1).
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Optional

import pytest
import pytest_asyncio

from services.site_rules import messages
from services.site_rules.hooks import SiteRuleGuardHook
from services.tools.browser import guard, handoff
from services.tools.browser.actions import BrowserReadToolkit
from services.tools.browser.guard import EgressHooks
from services.tools.browser.session import BrowserSessionManager
from services.tools.system import browser_installed
from tests.fakesite.pages import REDIRECTS
from tests.site_rules_fakes import FakeSiteRules, snapshot_of


class _Platform:
    """Headless Chromium, no channel, profiles under the test's tmp dir."""

    name = "container"

    def __init__(self, root: Path) -> None:
        self._root = root

    def browser_channel(self) -> None:
        return None

    def profile_dir(self, user_id: str) -> Path:
        path = self._root / user_id
        path.mkdir(parents=True, exist_ok=True)
        return path

    def data_dir(self) -> Path:
        return self._root

    def bring_to_front(self, *, pid: Any = None, title: Any = None) -> bool:
        return False

    def port_owner(self, port: int) -> None:
        return None


@pytest_asyncio.fixture
async def browse(fakesite, tmp_path):
    """A function that builds browser.read with the given owner rules bound
    through ``EgressHooks`` (as main.py hands them to the toolkit)."""
    if not browser_installed():
        pytest.skip("Playwright's Chromium is not installed (python -m playwright install chromium)")
    managers: list[BrowserSessionManager] = []

    def build(rules: dict[str, str]) -> tuple[BrowserReadToolkit, FakeSiteRules]:
        service = FakeSiteRules(snapshot_of(rules))
        sessions = BrowserSessionManager(
            headless=True, platform=_Platform(tmp_path), max_sessions=1, max_tabs=2
        )
        managers.append(sessions)
        toolkit = BrowserReadToolkit(
            sessions,
            guard=guard,
            handoff=handoff,
            egress_hooks=EgressHooks(site_rules=lambda user_id: SiteRuleGuardHook(service, user_id)),
        )
        return toolkit, service

    try:
        yield build
    finally:
        for sessions in managers:
            await sessions.close_all()


async def _open(toolkit: BrowserReadToolkit, url: str) -> dict[str, Any]:
    return await toolkit.execute("open", {"url": url}, user_id="ann", task_id="t1")


def _requested(fakesite: Any, path: str) -> list[tuple[str, str]]:
    return [entry for entry in fakesite.handled if entry[1].split("?")[0] == path]


@pytest.mark.asyncio
async def test_opening_a_blocked_fake_site_page_is_refused_by_the_route_guard(browse, fakesite):
    toolkit, service = browse({"127.0.0.1": "blocked"})
    url = fakesite.url("/")
    result = await _open(toolkit, url)
    assert result["ok"] is False
    assert result["error"] == f"Refusing to open {url}: {messages.NAVIGATION_BLOCKED}"
    assert _requested(fakesite, "/") == []  # the site never answered
    assert any(hit["where"] == "navigation" and hit["host"] == "127.0.0.1" for hit in service.hits)


@pytest.mark.asyncio
async def test_a_redirect_from_the_fake_site_to_a_blocked_host_stops_at_the_hop(
    browse, fakesite, monkeypatch
):
    port = fakesite.base.rsplit(":", 1)[1]
    monkeypatch.setitem(REDIRECTS, "/to-blocked", f"http://localhost:{port}/")
    toolkit, _ = browse({"localhost": "blocked"})
    result = await _open(toolkit, fakesite.url("/to-blocked"))
    assert result["ok"] is False
    assert result["error"] == (
        f"Refusing to open http://localhost:{port}/: {messages.NAVIGATION_BLOCKED}"
    )
    assert _requested(fakesite, "/to-blocked") and _requested(fakesite, "/") == []


@pytest.mark.asyncio
async def test_reading_a_sensitive_fake_site_page_returns_its_outline_with_a_notice(browse, fakesite):
    toolkit, service = browse({"127.0.0.1": "always_ask"})
    result = await _open(toolkit, fakesite.url("/"))
    assert result["ok"] is True and result["outline"]
    assert result["site_notice"] == messages.read_notice_owner("127.0.0.1")
    assert [(hit["kind"], hit["where"], hit["audit"]) for hit in service.hits] == [
        ("always_ask", "read", True)
    ]
    # A Trusted page carries no notice at all.
    trusted, _ = browse({"127.0.0.1": "trusted"})
    plain: Optional[dict[str, Any]] = await _open(trusted, fakesite.url("/"))
    assert plain is not None and plain["ok"] is True and "site_notice" not in plain
