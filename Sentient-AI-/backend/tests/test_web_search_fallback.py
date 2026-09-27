"""web.search's browser fallback, end to end through the executor: the search
endpoint answers with DuckDuckGo's bot check (a mock transport), and the query
runs in Crawler's own browser (headless Chromium) on the fake site's results
pages, which the fallback is pointed at through ``WebToolkit(search_pages=...)``.
Never a real website: the tracking links on those pages name the real engines
and the tests prove none of them is followed.

Why it exists: the endpoint's bot check was reported as an empty search, and
the model went on to guess shop addresses. The fallback only runs while
"Control a browser" is on, and only reads.
"""

from __future__ import annotations

import httpx
import pytest
import pytest_asyncio

from services.agent.tool_registry import ConnectorToolExecutor
from services.tools.browser import guard, handoff
from services.tools.browser.actions import BrowserReadToolkit
from services.tools.browser.session import BrowserSessionManager
from services.tools.system import browser_installed
from services.tools.web import SEARCH_BLOCKED, WebToolkit
from tests.test_browser_read import TestPlatform
from tests.test_purchases_wiring import _gate as gate_with
from tests.test_web_tools import DBRAND, DDG, challenged, resolver_for

QUERY = "dbrand grip iphone 16 pro max holo white"
REDDIT = "https://www.reddit.com/r/dbrand/comments/abc/grip_holo_white/"


@pytest_asyncio.fixture
async def browser(fakesite, tmp_path):
    if not browser_installed():
        pytest.skip("Playwright's Chromium is not installed (python -m playwright install chromium)")
    sessions = BrowserSessionManager(
        headless=True, platform=TestPlatform(tmp_path), max_sessions=1, max_tabs=2
    )
    try:
        yield BrowserReadToolkit(sessions, guard=guard, handoff=handoff), sessions
    finally:
        await sessions.close_all()


def executor(fakesite, browser, *pages: str, capabilities=("web_browsing", "browser_control")):
    web = WebToolkit(
        transport=httpx.MockTransport(challenged),
        resolver=resolver_for(DDG),
        search_pages=tuple(fakesite.url(f"/search-results/{page}?{{query}}") for page in pages),
    )
    read, _ = browser
    return ConnectorToolExecutor(
        capability_gate=gate_with(*capabilities), web_toolkit=web, browser_toolkit=read
    )


@pytest.mark.asyncio
async def test_a_challenged_search_is_answered_from_bing_in_the_browser(fakesite, browser):
    ex = executor(fakesite, browser, "challenge", "bing")
    result = await ex.execute("web.search", {"query": QUERY}, "u1", task_id="t1")

    assert result["ok"] is True and result["source"] == "browser"
    assert [row["url"] for row in result["results"]] == [DBRAND, REDDIT]
    assert result["results"][0] == {
        "title": "Grip Case - iPhone 16 Pro Max | dbrand",
        "url": DBRAND,
        "snippet": "Holo White, Black Dot and more. Free shipping.",
    }
    # Two page loads, one per results page; no link on them was followed.
    assert fakesite.handled == [("GET", "/search-results/challenge"), ("GET", "/search-results/bing")]
    _, sessions = browser
    assert sessions.sessions["u1"].task.actions == 2


@pytest.mark.asyncio
async def test_duckduckgo_results_in_the_browser_are_unwrapped_and_ads_dropped(fakesite, browser):
    ex = executor(fakesite, browser, "duckduckgo", "bing")
    result = await ex.execute("web.search", {"query": QUERY}, "u1", task_id="t1")

    assert result["source"] == "browser"
    assert result["results"] == [
        {
            "title": "Grip Case - iPhone 16 Pro Max",
            "url": DBRAND,
            "snippet": "The case that fits like a glove. Holo White and more.",
        },
        {"title": "r/dbrand", "url": "https://www.reddit.com/r/dbrand/", "snippet": "Grip owners compare colours."},
    ]
    assert fakesite.handled == [("GET", "/search-results/duckduckgo")]


@pytest.mark.asyncio
async def test_the_search_tab_leaves_the_agents_own_page_alone(fakesite, browser):
    read, sessions = browser
    opened = await read.execute("open", {"url": fakesite.url("/grades")}, user_id="u1", task_id="t1")
    assert opened["ok"] is True

    ex = executor(fakesite, browser, "bing")
    assert (await ex.execute("web.search", {"query": QUERY}, "u1", task_id="t1"))["ok"] is True

    session = sessions.sessions["u1"]
    assert [page.url for page in session.context.pages] == [fakesite.url("/grades")]


@pytest.mark.asyncio
async def test_every_results_page_challenged_is_blocked_with_the_hint(fakesite, browser):
    ex = executor(fakesite, browser, "challenge", "challenge")
    result = await ex.execute("web.search", {"query": QUERY}, "u1", task_id="t1")

    assert result["ok"] is False and result["blocked"] is True
    assert result["error"] == SEARCH_BLOCKED
    assert "Don't guess addresses" in result["hint"]


@pytest.mark.asyncio
async def test_no_browser_fallback_while_browser_control_is_off(fakesite, browser):
    ex = executor(fakesite, browser, "bing", capabilities=("web_browsing",))
    result = await ex.execute("web.search", {"query": QUERY}, "u1", task_id="t1")

    assert result["ok"] is False and result["blocked"] is True
    assert result["error"] == SEARCH_BLOCKED
    # Nothing was launched and nothing was loaded.
    _, sessions = browser
    assert sessions.sessions == {}
    assert fakesite.handled == []
