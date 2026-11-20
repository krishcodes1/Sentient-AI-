"""Tests for the built-in web tools: search parsing and truncation, page-fetch
text extraction and redirect handling, and screenshot capture all work over a
mocked transport while the real SSRF address-validation policy still runs in
front of it. Search is also checked on answers that match only part of the
query (Bing's plain page searching a long query's first word alone): the
browser is asked, or the rows come back with a note, and research reads none.

Why it exists: The egress policy is deliberately not mocked, so a tool that
bypasses `validated_addresses` and reaches an internal address would still be
caught here. A search answer about something else used to come back as a
plain success, and the model went on to guess page addresses.

Tests for the built-in web tools.

Every HTTP call is served by an ``httpx.MockTransport``, so parsing and
truncation are exercised without touching the network. The egress policy
is *not* mocked: the request hook runs the real
``services.tools.net.validated_addresses`` in front of the mock
transport, and refusal tests use IP literals or names resolvable from
/etc/hosts so no DNS query is needed either.
"""

from __future__ import annotations

from html import escape
from pathlib import Path
from typing import Any, Optional
from urllib.parse import parse_qs, urlparse

import httpx
import pytest

from services.agent.tool_registry import ConnectorToolExecutor
from services.tools.net import (
    EgressBlocked,
    build_guarded_client,
    validated_addresses,
)
from services.tools.html_text import clean_result_rows, parse_bing_results
from services.tools.web import (
    BROWSER_SEARCH_PAGES,
    FETCH_REFUSED_HINT,
    MAX_PAGE_CHARS,
    RESEARCH_OFF_TOPIC_NOTE,
    SEARCH_BLOCKED,
    SEARCH_OFF_TOPIC_NOTE,
    WebToolError,
    WebToolkit,
    _off_topic,
)

PUBLIC_ADDRESS = "93.184.216.34"


def resolver_for(hosts: dict[str, tuple[str, ...]]):
    """A DNS stand-in for *hosts* that applies the real policy elsewhere.

    Everything outside the mapping — notably a redirect to a loopback
    address — still goes through ``validated_addresses``, so the refusal
    under test is the production one.
    """

    def resolve(url: str) -> tuple[str, ...]:
        host = urlparse(url).hostname
        if host in hosts:
            return hosts[host]
        return validated_addresses(url)

    return resolve


def toolkit(handler, hosts: Optional[dict[str, tuple[str, ...]]] = None) -> WebToolkit:
    return WebToolkit(
        transport=httpx.MockTransport(handler),
        resolver=resolver_for(hosts or {}),
    )


SEARCH_HTML = """
<html><body>
<div class="result results_links">
  <h2 class="result__title">
    <a class="result__a" href="//duckduckgo.com/l/?uddg=https%3A%2F%2Fexample.com%2Fflights&amp;rut=abc">
      Cheap <b>flights</b> to Tokyo
    </a>
  </h2>
  <a class="result__snippet" href="#">Compare fares from every major carrier.</a>
</div>
<div class="result results_links result--ad">
  <a class="result__a" href="//duckduckgo.com/y.js?ad_provider=bing">Sponsored offer</a>
  <a class="result__snippet" href="#">An advert, not a result.</a>
</div>
<div class="result results_links result--ad">
  <h2 class="result__title">
    <a class="result__a" href="//duckduckgo.com/l/?uddg=https%3A%2F%2Fduckduckgo.com%2Fy.js%3Fad_domain%3Dshop.example%26ad_provider%3Dbingv7aa&amp;rut=def">
      Doubly wrapped advert
    </a>
  </h2>
  <a class="result__snippet" href="#">Ads are wrapped twice in the live markup.</a>
</div>
<div class="result results_links">
  <h2 class="result__title">
    <a class="result__a" href="//duckduckgo.com/l/?uddg=https%3A%2F%2Fnews.example.org%2Fa">Second result</a>
  </h2>
  <a class="result__snippet" href="#">SNIPPET</a>
</div>
</body></html>
"""

PAGE_HTML = """
<html><head><title>  Monitor mounts  </title>
<style>body { color: red }</style></head>
<body>
<nav>Home Shop Cart</nav>
<script>window.tracking = 1;</script>
<h1>VESA monitor mount</h1>
<p>Holds   a   display up to 32 inches.</p>
<p>Ships free.</p>
<footer>Copyright</footer>
</body></html>
"""


# ---------------------------------------------------------------------------
# search
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_search_parses_title_url_and_snippet():
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.host == "html.duckduckgo.com"
        assert request.url.params["q"] == "cheap flights tokyo"
        return httpx.Response(200, html=SEARCH_HTML)

    result = await toolkit(handler, {"html.duckduckgo.com": (PUBLIC_ADDRESS,)}).search(
        "cheap flights tokyo"
    )

    assert result["ok"] is True
    assert result["count"] == 2
    first = result["results"][0]
    assert first["title"] == "Cheap flights to Tokyo"
    assert first["url"] == "https://example.com/flights"
    assert first["snippet"] == "Compare fares from every major carrier."


@pytest.mark.asyncio
async def test_search_drops_sponsored_rows():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, html=SEARCH_HTML)

    result = await toolkit(handler, {"html.duckduckgo.com": (PUBLIC_ADDRESS,)}).search("q")
    urls = [r["url"] for r in result["results"]]
    assert urls == ["https://example.com/flights", "https://news.example.org/a"]


@pytest.mark.asyncio
async def test_search_honours_max_results_and_its_ceiling():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, html=SEARCH_HTML)

    tools = toolkit(handler, {"html.duckduckgo.com": (PUBLIC_ADDRESS,)})
    assert (await tools.search("q", max_results=1))["count"] == 1
    # Asking for 500 results cannot make the payload unbounded.
    assert (await tools.search("q", max_results=500))["count"] == 2


@pytest.mark.asyncio
async def test_search_caps_snippet_length():
    long_snippet = "x" * 900

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            html=(
                '<a class="result__a" href="https://example.com/a">T</a>'
                f'<a class="result__snippet">{long_snippet}</a>'
            ),
        )

    result = await toolkit(handler, {"html.duckduckgo.com": (PUBLIC_ADDRESS,)}).search("q")
    assert len(result["results"][0]["snippet"]) == 200


@pytest.mark.asyncio
async def test_search_reports_upstream_failure():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(503, text="busy")

    result = await toolkit(handler, ENGINES).search("q")
    assert result["ok"] is False
    assert result["blocked"] is True
    assert result["status_code"] == 503


# What html.duckduckgo.com answered instead of results (HTTP 202): the
# anomaly modal and its duck picture challenge, no result__a rows.
CHALLENGE_HTML = (Path(__file__).parent / "fixtures" / "ddg_challenge.html").read_text()
DDG = {"html.duckduckgo.com": (PUBLIC_ADDRESS,)}
BING = {"www.bing.com": (PUBLIC_ADDRESS,)}
# Every engine a search may ask: DuckDuckGo, then Bing after a bot check.
ENGINES = {**DDG, **BING}


def challenged(request: httpx.Request) -> httpx.Response:
    return httpx.Response(202, html=CHALLENGE_HTML)


@pytest.mark.asyncio
async def test_a_bot_check_is_reported_as_blocked_not_as_an_empty_search():
    result = await toolkit(challenged, ENGINES).execute("search", {"query": "dbrand grip"})

    assert result["ok"] is False
    assert result["blocked"] is True
    assert result["error"] == SEARCH_BLOCKED
    assert "Don't guess addresses" in result["hint"]
    # Worded for any search, not only for finding a shop.
    assert "shop" not in result["hint"] and "its own search" in result["hint"]
    assert result["status_code"] == 202
    assert "results" not in result and "count" not in result


@pytest.mark.asyncio
async def test_a_bot_check_served_with_200_is_still_blocked():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, html=CHALLENGE_HTML)

    result = await toolkit(handler, ENGINES).search("q")
    assert result["ok"] is False and result["blocked"] is True


@pytest.mark.asyncio
async def test_no_rows_on_a_page_that_reads_like_a_bot_check_is_blocked():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            html="<html><body><p>Unfortunately, bots use DuckDuckGo too.</p>"
            "<p>Please complete the following challenge.</p></body></html>",
        )

    result = await toolkit(handler, ENGINES).search("q")
    assert result["ok"] is False and result["blocked"] is True


class FakeBrowser:
    """web.search's browser fallback as the executor hands it over: one
    answer per results page, in order; records the pages asked for."""

    def __init__(self, *answers: dict[str, Any]) -> None:
        self.answers = list(answers)
        self.urls: list[str] = []

    async def __call__(self, url: str, script: str, ready: str) -> dict[str, Any]:
        self.urls.append(url)
        assert "querySelectorAll" in script and ready
        return self.answers.pop(0)


DBRAND = "https://www.dbrand.com/shop/grip/iphone-16-pro-max-cases"
WRAPPED_DBRAND = (
    "https://duckduckgo.com/l/?uddg=https%3A%2F%2Fwww.dbrand.com%2Fshop%2Fgrip"
    "%2Fiphone-16-pro-max-cases&rut=abc"
)


@pytest.mark.asyncio
async def test_the_browser_fallback_reads_rows_only_off_the_search_engines_own_page():
    """A results address can end up somewhere else (a redirect, a search
    engine's shortcut syntax). Another site could mark up its page like a
    results page, so rows are read only when the page that loaded is the
    engine's own; the next engine is asked instead."""
    elsewhere = {
        "ok": True,
        "host": "tickets.attacker.example",
        "rows": [{"title": "dbrand grip case", "url": "https://tickets.attacker.example/x", "snippet": "s"}],
    }
    real = {
        "ok": True,
        "host": "www.bing.com",
        "rows": [{"title": "Grip Case - dbrand", "url": DBRAND, "snippet": "The grippiest case."}],
    }
    browser = FakeBrowser(elsewhere, real)
    result = await toolkit(challenged, ENGINES).search("dbrand grip case", browser=browser)
    assert len(browser.urls) == 2  # the first page was skipped, the second read
    assert [row["url"] for row in result["results"]] == [DBRAND]
    assert "attacker" not in str(result)


@pytest.mark.asyncio
async def test_a_blocked_search_runs_in_the_browser_when_one_is_given():
    browser = FakeBrowser(
        {
            "ok": True,
            "rows": [
                {"title": "Ad", "url": "https://duckduckgo.com/y.js?ad_provider=bingv7aa", "snippet": ""},
                {"title": " Grip  Case ", "url": WRAPPED_DBRAND, "snippet": "Holo White"},
                {"title": "Grip Case again", "url": WRAPPED_DBRAND, "snippet": "duplicate"},
                "not a row",
            ],
        }
    )
    result = await toolkit(challenged, ENGINES).execute(
        "search", {"query": "dbrand grip holo white"}, browser=browser
    )

    assert result == {
        "ok": True,
        "query": "dbrand grip holo white",
        "source": "browser",
        "results": [{"title": "Grip Case", "url": DBRAND, "snippet": "Holo White"}],
        "count": 1,
    }
    # DuckDuckGo's own page first, with the query encoded into it.
    assert len(browser.urls) == 1
    first = urlparse(browser.urls[0])
    assert (first.hostname, parse_qs(first.query)["q"]) == ("duckduckgo.com", ["dbrand grip holo white"])


@pytest.mark.asyncio
async def test_the_browser_fallback_moves_on_when_a_page_is_challenged_or_fails():
    browser = FakeBrowser(
        {"ok": True, "rows": [], "challenge": True, "text": "Unfortunately, bots use DuckDuckGo too."},
        {"ok": True, "rows": [{"title": "Grip", "url": DBRAND, "snippet": ""}]},
    )
    result = await toolkit(challenged, ENGINES).search("q", browser=browser)
    assert result["source"] == "browser" and result["results"][0]["url"] == DBRAND
    assert [urlparse(u).hostname for u in browser.urls] == ["duckduckgo.com", "www.bing.com"]
    assert len(BROWSER_SEARCH_PAGES) == 2

    failing = FakeBrowser({"ok": False, "error": "The results page could not be read."},
                          {"ok": True, "rows": [], "text": ""})
    result = await toolkit(challenged, ENGINES).search("q", browser=failing)
    assert result["ok"] is False and result["blocked"] is True
    assert "Don't guess addresses" in result["hint"]
    assert len(failing.urls) == 2


@pytest.mark.asyncio
async def test_an_unavailable_browser_stops_the_fallback_and_reports_blocked():
    browser = FakeBrowser({"ok": False, "unavailable": True, "error": "Browser control is turned off."})
    result = await toolkit(challenged, ENGINES).search("q", browser=browser)

    assert result["ok"] is False and result["blocked"] is True
    assert result["error"] == SEARCH_BLOCKED
    assert len(browser.urls) == 1


@pytest.mark.asyncio
async def test_a_search_the_endpoint_answers_never_touches_the_browser():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, html=SEARCH_HTML)

    browser = FakeBrowser()
    result = await toolkit(handler, DDG).execute("search", {"query": "q"}, browser=browser)
    assert result["ok"] is True and "source" not in result
    assert browser.urls == []


@pytest.mark.asyncio
async def test_the_browser_fallback_cannot_come_from_tool_arguments():
    result = await toolkit(unreachable_handler).execute(
        "search", {"query": "q", "browser": "https://evil.example/"}
    )
    assert result["ok"] is False and "Invalid arguments" in result["error"]


@pytest.mark.asyncio
async def test_research_reports_a_blocked_search_instead_of_no_sources():
    requested: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requested.append(request.url.host)
        return challenged(request)

    result = await toolkit(handler, ENGINES).execute("research", {"query": "q"})

    assert result["ok"] is False and result["blocked"] is True
    assert result["error"] == SEARCH_BLOCKED
    assert "Don't guess addresses" in result["hint"]
    # Nothing past the refused searches is fetched.
    assert requested == ["html.duckduckgo.com", "www.bing.com"]


@pytest.mark.asyncio
async def test_research_reads_the_sources_the_browser_fallback_found():
    requested: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requested.append(request.url.host)
        if request.url.host == "html.duckduckgo.com":
            return challenged(request)
        return httpx.Response(200, html=PAGE_HTML)

    browser = FakeBrowser(
        {
            "ok": True,
            "rows": [
                # Refused by the egress policy before any request is made.
                {"title": "Internal", "url": "http://127.0.0.1/admin", "snippet": ""},
                {"title": "Grip", "url": WRAPPED_DBRAND, "snippet": "Holo White"},
            ],
        }
    )
    result = await toolkit(handler, {**ENGINES, "www.dbrand.com": (PUBLIC_ADDRESS,)}).execute(
        "research", {"query": "dbrand grip"}, browser=browser
    )

    assert result["ok"] is True and result["source"] == "browser"
    assert [(r["url"], r["ok"]) for r in result["results"]] == [(DBRAND, True)]
    assert "VESA monitor mount" in result["results"][0]["excerpt"]
    # Bing's page here is an article with no result rows, so the browser
    # is asked next.
    assert requested == ["html.duckduckgo.com", "www.bing.com", "www.dbrand.com"]


@pytest.mark.asyncio
async def test_the_research_browser_fallback_cannot_come_from_tool_arguments():
    result = await toolkit(unreachable_handler).execute(
        "research", {"query": "q", "browser": "https://evil.example/"}
    )
    assert result["ok"] is False and "Invalid arguments" in result["error"]


# What www.bing.com serves a request with no JavaScript, trimmed from a live
# page: organic rows (li.b_algo: the h2 link, wrapped in /ck/a, and its
# snippet paragraph), a favicon link ahead of each title, an advert
# (li.b_ad), a result's deep links in a nested list, and the pager. The
# Wikipedia row's address carries Bing's session id (msockid), as live
# ones do; it is dropped.
BING_HTML = (Path(__file__).parent / "fixtures" / "bing_results.html").read_text()
BING_ROWS = [
    {
        "title": "Python Release Python 3.14.0 | Python.org",
        "url": "https://www.python.org/downloads/release/python-3140/",
        "snippet": "Release date: Oct. 7, 2025 This is the stable release of Python 3.14.0 …",
    },
    {
        "title": "What's new in Python 3.14",
        "url": "https://docs.python.org/3/whatsnew/3.14.html",
        "snippet": (
            "This article explains the new features in Python 3.14, compared to 3.13. "
            "Editor: Hugo van Kemenade"
        ),
    },
    {
        "title": "History of Python - Wikipedia",
        "url": "https://en.wikipedia.org/wiki/History_of_Python",
        "snippet": "Python 3.14 was released on 7 October 2025.",
    },
]


def bing_after_a_bot_check(request: httpx.Request) -> httpx.Response:
    """DuckDuckGo asks for a bot check; Bing answers with its plain page."""
    if request.url.host == "www.bing.com":
        return httpx.Response(200, html=BING_HTML)
    return challenged(request)


def test_bings_plain_page_gives_its_organic_rows_only():
    # No advert, no favicon link read as a title, no deep link or pager,
    # and no row whose address cannot be decoded.
    assert parse_bing_results(BING_HTML, 10, 200) == BING_ROWS
    assert parse_bing_results(BING_HTML, 2, 200) == BING_ROWS[:2]
    assert len(parse_bing_results(BING_HTML, 10, 20)[1]["snippet"]) == 20
    assert parse_bing_results(CHALLENGE_HTML, 10, 200) == []
    assert parse_bing_results("<li class='b_algo'><h2><a href='https://x.example/'>cut", 10, 200) == []


def test_bings_session_id_is_dropped_from_result_addresses_and_nothing_else():
    html = (
        "<li class='b_algo'><h2><a href='https://www.expedia.com/Flights?from=NYC"
        "&amp;MSOCKID=ab12&amp;to=LON%2FLHR'>Flights</a></h2></li>"
        "<li class='b_algo'><h2><a href='https://x.example/page?msockid=ab12'>X</a></h2></li>"
    )
    assert [r["url"] for r in parse_bing_results(html, 10, 200)] == [
        "https://www.expedia.com/Flights?from=NYC&to=LON%2FLHR",
        "https://x.example/page",
    ]


def test_bings_stand_in_for_a_missing_description_is_not_a_snippet():
    # Bing prints this where a site keeps its crawler out. Read by the model
    # it passes for the search tool reporting a block.
    html = (
        "<li class='b_algo'><h2><a href='https://www.fandango.com/'>Fandango</a></h2>"
        "<div class='b_caption'><p>We would like to show you a description here but the "
        "site won&#8217;t allow us.</p></div></li>"
        "<li class='b_algo'><h2><a href='https://x.example/'>X</a></h2>"
        "<div class='b_caption'><p>A real description.</p></div></li>"
    )
    assert parse_bing_results(html, 10, 200) == [
        {"title": "Fandango", "url": "https://www.fandango.com/", "snippet": ""},
        {"title": "X", "url": "https://x.example/", "snippet": "A real description."},
    ]
    # The same words read off Bing's page in the browser.
    row = {
        "title": "Fandango",
        "url": "https://www.fandango.com/",
        "snippet": "We would like to show you a description here but the site won't allow us.",
    }
    assert clean_result_rows([row], 10, 200) == [{**row, "snippet": ""}]


@pytest.mark.asyncio
async def test_a_bot_check_is_answered_from_bings_plain_page_without_a_browser():
    asked: list[tuple[str, str]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        asked.append((request.url.host, request.url.params["q"]))
        return bing_after_a_bot_check(request)

    result = await toolkit(handler, ENGINES).execute(
        "search", {"query": "python 3.14 release date"}
    )

    assert result == {
        "ok": True,
        "query": "python 3.14 release date",
        "source": "bing",
        "results": BING_ROWS,
        "count": 3,
    }
    assert asked == [
        ("html.duckduckgo.com", "python 3.14 release date"),
        ("www.bing.com", "python 3.14 release date"),
    ]


@pytest.mark.asyncio
async def test_bings_plain_page_is_asked_before_the_browser():
    browser = FakeBrowser()
    result = await toolkit(bing_after_a_bot_check, ENGINES).search("q", browser=browser)
    assert result["source"] == "bing" and result["count"] == 3
    assert browser.urls == []


@pytest.mark.asyncio
async def test_a_bing_page_without_rows_is_not_reported_as_an_empty_search():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.host == "www.bing.com":
            return httpx.Response(200, html="<html><body><p>Something else</p></body></html>")
        return challenged(request)

    result = await toolkit(handler, ENGINES).search("q")
    assert result["ok"] is False and result["blocked"] is True
    assert result["error"] == SEARCH_BLOCKED
    assert result["status_code"] == 202


@pytest.mark.asyncio
async def test_bing_refusing_too_moves_on_to_the_browser():
    # challenged() answers Bing with the same 202 bot check.
    browser = FakeBrowser({"ok": True, "rows": [{"title": "Grip", "url": DBRAND, "snippet": ""}]})
    result = await toolkit(challenged, ENGINES).search("q", browser=browser)
    assert result["source"] == "browser" and result["results"][0]["url"] == DBRAND


@pytest.mark.asyncio
async def test_a_bing_request_that_fails_moves_on_instead_of_failing_the_search():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.host == "www.bing.com":
            raise httpx.ConnectError("connection reset", request=request)
        return challenged(request)

    result = await toolkit(handler, ENGINES).execute("search", {"query": "q"})
    assert result["ok"] is False and result["blocked"] is True
    assert result["error"] == SEARCH_BLOCKED


@pytest.mark.asyncio
async def test_research_reads_the_sources_bing_found():
    requested: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requested.append(request.url.host)
        if request.url.host in ENGINES:
            return bing_after_a_bot_check(request)
        return httpx.Response(200, html=PAGE_HTML)

    hosts = {
        **ENGINES,
        "www.python.org": (PUBLIC_ADDRESS,),
        "docs.python.org": (PUBLIC_ADDRESS,),
    }
    result = await toolkit(handler, hosts).execute(
        "research", {"query": "python 3.14 release date", "max_sources": 2}
    )

    assert result["ok"] is True and result["source"] == "bing"
    assert [(r["url"], r["ok"]) for r in result["results"]] == [
        (BING_ROWS[0]["url"], True),
        (BING_ROWS[1]["url"], True),
    ]
    assert requested[:2] == ["html.duckduckgo.com", "www.bing.com"]
    assert sorted(requested[2:]) == ["docs.python.org", "www.python.org"]


# ---------------------------------------------------------------------------
# search: rows that answer only part of the query
#
# Bing's plain page answers a long query with the results for its first word
# alone: organic, well-formed rows about something else. The Lincoln, AMC and
# Paper Tiger rows are rebuilt from what it returned on 2026-11-12 for the
# queries below (lincoln.com, Lincoln Financial and Abraham Lincoln; AMC
# Theatres' home page, amc.com and AMC+; Wikipedia and IMDb on the film).
# Their addresses, titles and snippets are written to match, not recorded.
# The Fandango rows are the same pattern for a query that starts with a
# site's name.
# ---------------------------------------------------------------------------

LINCOLN_ROWS = [
    {
        "title": "Lincoln Luxury Crossovers and SUVs | Lincoln.com",
        "url": "https://www.lincoln.com/",
        "snippet": "Explore the 2026 Lincoln lineup. Build and price a vehicle or find a retailer.",
    },
    {
        "title": "Lincoln Financial: Retirement, Insurance and Wealth Protection",
        "url": "https://www.lincolnfinancial.com/",
        "snippet": "Lincoln Financial helps people plan for retirement and protect their income.",
    },
    {
        "title": "Abraham Lincoln - Wikipedia",
        "url": "https://en.wikipedia.org/wiki/Abraham_Lincoln",
        "snippet": "Abraham Lincoln was the 16th president of the United States.",
    },
]
AMC_ROWS = [
    {
        "title": "AMC Theatres - movie times, movie trailers, buy tickets and gift cards.",
        "url": "https://www.amctheatres.com/",
        "snippet": "Find movies near you, view showtimes, watch trailers and buy movie tickets.",
    },
    {
        "title": "AMC: Shows, Movies and Schedule",
        "url": "https://www.amc.com/",
        "snippet": "Watch full episodes and video extras for AMC shows.",
    },
    {
        "title": "AMC+ | Stream Exclusive Shows and Movies",
        "url": "https://www.amcplus.com/",
        "snippet": "Stream series and films from AMC, Shudder and Sundance Now.",
    },
]
FANDANGO_ROWS = [
    {
        "title": "Movie Tickets & Movie Times | Fandango",
        "url": "https://www.fandango.com/",
        "snippet": "Buy movie tickets in advance, find showtimes, watch trailers and read reviews.",
    },
    {
        "title": "Fandango Media - Wikipedia",
        "url": "https://en.wikipedia.org/wiki/Fandango_Media",
        "snippet": "Fandango Media is a ticketing company that sells movie tickets online.",
    },
    {
        "title": "Fandango at Home",
        "url": "https://athome.fandango.com/",
        "snippet": "Rent or buy new movies and TV shows.",
    },
]
PAPER_TIGER_ROWS = [
    {
        "title": "Paper Tiger (2026 film) - Wikipedia",
        "url": "https://en.wikipedia.org/wiki/Paper_Tiger_(2026_film)",
        "snippet": "Paper Tiger is a 2026 crime drama film.",
    },
    {
        "title": "Paper Tiger (2026) - IMDb",
        "url": "https://www.imdb.com/title/tt0000000/",
        "snippet": "Paper Tiger: cast, crew, trailer and release date.",
    },
]
SHOWTIMES_QUERY = "AMC Lincoln Square Paper Tiger showtimes"
# What a search of the whole query finds.
SHOWTIMES_ROWS = [
    {
        "title": "Paper Tiger showtimes at AMC Lincoln Square 13",
        "url": "https://www.amctheatres.com/movie-theatres/new-york-city/amc-lincoln-square-13",
        "snippet": "Tonight's showtimes for Paper Tiger at AMC Lincoln Square 13 in New York.",
    }
]
THEATRE_ROWS = [
    {
        "title": "Showtimes",
        "url": "https://www.amctheatres.com/movie-theatres/lincoln-square-13",
        "snippet": "",
    }
]


@pytest.mark.parametrize(
    ("query", "rows", "off_topic"),
    [
        ("Lincoln Square AMC Paper Tiger 2026 showtimes tonight", LINCOLN_ROWS, True),
        (SHOWTIMES_QUERY, AMC_ROWS, True),
        ("fandango amc lincoln square 13 showtimes", FANDANGO_ROWS, True),
        ('"Paper Tiger" movie 2026', PAPER_TIGER_ROWS, False),
        (SHOWTIMES_QUERY, SHOWTIMES_ROWS, False),
        # Half of the query's words is enough (paper and tiger of four); under
        # half is not (the same two of five).
        ("Paper Tiger AMC showtimes", PAPER_TIGER_ROWS, False),
        ("Paper Tiger AMC Lincoln showtimes", PAPER_TIGER_ROWS, True),
        # Two words say too little to judge by.
        ("AMC showtimes", LINCOLN_ROWS, False),
        # Fillers and words of one or two letters are not counted: paper,
        # tiger and 2026 of four, not of ten.
        ("what are the Paper Tiger 2026 showtimes for tonight near me", PAPER_TIGER_ROWS, False),
        # A word counts wherever it appears, an address included, in any
        # case and whatever punctuation the query wraps it in.
        ('"PAPER TIGER" (AMC), Lincoln-Square: Showtimes?', THEATRE_ROWS, False),
    ],
)
def test_rows_holding_under_half_of_the_querys_words_are_off_topic(query, rows, off_topic):
    assert _off_topic(query, rows) is off_topic


def bing_page(rows: list[dict[str, str]]) -> str:
    """Bing's plain results page for *rows*, in the markup the parser reads."""
    items = "".join(
        f'<li class="b_algo"><h2><a href="{escape(row["url"])}">{escape(row["title"])}</a></h2>'
        f'<div class="b_caption"><p>{escape(row["snippet"])}</p></div></li>'
        for row in rows
    )
    return f'<html><body><ol id="b_results">{items}</ol></body></html>'


def bing_answers(rows: list[dict[str, str]]):
    """DuckDuckGo asks for a bot check; Bing's plain page answers *rows*."""

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.host == "www.bing.com":
            return httpx.Response(200, html=bing_page(rows))
        return challenged(request)

    return handler


def hosts_of_rows(*row_sets: list[dict[str, str]]) -> dict[str, tuple[str, ...]]:
    """The engines plus every host the rows name, so no test asks real DNS."""
    hosts = dict(ENGINES)
    for rows in row_sets:
        hosts.update({urlparse(row["url"]).hostname: (PUBLIC_ADDRESS,) for row in rows})
    return hosts


@pytest.mark.asyncio
async def test_bing_rows_for_part_of_the_query_come_back_with_a_note():
    result = await toolkit(bing_answers(AMC_ROWS), ENGINES).execute(
        "search", {"query": SHOWTIMES_QUERY}
    )

    assert result == {
        "ok": True,
        "query": SHOWTIMES_QUERY,
        "source": "bing",
        "results": AMC_ROWS,
        "count": 3,
        "note": SEARCH_OFF_TOPIC_NOTE,
    }
    assert result["note"] == (
        "These results match only part of the query. Search again with fewer words, with "
        "the exact name first and in quotes, or open the site you need and use its own "
        "search. Don't guess addresses."
    )


@pytest.mark.asyncio
async def test_bing_rows_for_part_of_the_query_send_the_search_to_the_browser():
    browser = FakeBrowser({"ok": True, "rows": SHOWTIMES_ROWS})
    result = await toolkit(bing_answers(AMC_ROWS), ENGINES).execute(
        "search", {"query": SHOWTIMES_QUERY}, browser=browser
    )

    # The browser's answer, as it would be had Bing had no rows at all.
    assert result == {
        "ok": True,
        "query": SHOWTIMES_QUERY,
        "source": "browser",
        "results": SHOWTIMES_ROWS,
        "count": 1,
    }
    assert len(browser.urls) == 1


@pytest.mark.parametrize(
    ("query", "rows"),
    [("python 3.14 release date", BING_ROWS), ('"Paper Tiger" movie 2026', PAPER_TIGER_ROWS)],
)
@pytest.mark.asyncio
async def test_bing_rows_on_topic_stay_as_they_were_and_never_touch_the_browser(query, rows):
    browser = FakeBrowser()
    result = await toolkit(bing_answers(rows), ENGINES).search(query, browser=browser)

    assert result == {
        "ok": True,
        "query": query,
        "source": "bing",
        "results": rows,
        "count": len(rows),
    }
    assert browser.urls == []


@pytest.mark.parametrize(
    "answers",
    [
        # "Control a browser" is off.
        [{"ok": False, "unavailable": True, "error": "Browser control is turned off."}],
        # Both results pages were challenged or empty.
        [{"ok": True, "rows": [], "challenge": True}, {"ok": True, "rows": [], "text": ""}],
    ],
)
@pytest.mark.asyncio
async def test_bings_partial_rows_are_kept_with_the_note_when_the_browser_has_none(answers):
    browser = FakeBrowser(*answers)
    result = await toolkit(bing_answers(AMC_ROWS), ENGINES).search(SHOWTIMES_QUERY, browser=browser)

    assert result["ok"] is True and result["source"] == "bing"
    assert result["results"] == AMC_ROWS and result["note"] == SEARCH_OFF_TOPIC_NOTE
    assert len(browser.urls) == len(answers)


@pytest.mark.asyncio
async def test_a_browser_that_raises_is_a_browser_with_no_rows_not_a_failed_search():
    # The browser is now asked after an answer Bing did give, so its failure
    # must not turn that answer into an error.
    asked: list[str] = []

    async def closed(url: str, script: str, ready: str) -> dict[str, Any]:
        asked.append(url)
        raise RuntimeError("Target page, context or browser has been closed")

    kept = await toolkit(bing_answers(AMC_ROWS), ENGINES).execute(
        "search", {"query": SHOWTIMES_QUERY}, browser=closed
    )
    assert kept["ok"] is True and kept["source"] == "bing"
    assert kept["results"] == AMC_ROWS and kept["note"] == SEARCH_OFF_TOPIC_NOTE
    assert len(asked) == len(BROWSER_SEARCH_PAGES)

    blocked = await toolkit(challenged, ENGINES).execute(
        "search", {"query": SHOWTIMES_QUERY}, browser=closed
    )
    assert blocked["ok"] is False and blocked["blocked"] is True
    assert blocked["error"] == SEARCH_BLOCKED


@pytest.mark.asyncio
async def test_browser_rows_for_part_of_the_query_get_the_note_and_no_second_page():
    # challenged() answers Bing's plain page with the bot check too. The one
    # answer is all the browser has: asking it for a second page would raise.
    browser = FakeBrowser({"ok": True, "rows": AMC_ROWS})
    result = await toolkit(challenged, ENGINES).search(SHOWTIMES_QUERY, browser=browser)

    assert result == {
        "ok": True,
        "query": SHOWTIMES_QUERY,
        "source": "browser",
        "results": AMC_ROWS,
        "count": 3,
        "note": SEARCH_OFF_TOPIC_NOTE,
    }
    assert len(browser.urls) == 1


@pytest.mark.asyncio
async def test_the_largest_search_answer_is_under_ten_thousand_characters_as_shown():
    """What runtime.RESULT_CHAR_BUDGETS has to hold for web.search: ten rows at
    their caps (title 140, address 500, snippet 200), the note and a 300
    character query. The runtime's default of 2000 cuts the middle out of any
    answer of more than about five rows. With an entry for web.search this
    checks that entry; until then, the 10000 it needs."""
    import json

    from services.agent.runtime import RESULT_CHAR_BUDGETS

    rows = [
        {
            "title": f"{n} " + "t" * 300,
            "url": f"https://example.org/{n}/" + "u" * 800,
            "snippet": "s" * 500,
        }
        for n in range(12)
    ]
    query = "alpha beta gamma " + "q" * 283
    result = await toolkit(challenged, ENGINES).search(
        query, max_results=50, browser=FakeBrowser({"ok": True, "rows": rows})
    )
    assert result["count"] == 10 and result["note"] == SEARCH_OFF_TOPIC_NOTE
    # As the runtime renders a result for the model (_wrap_tool_results).
    shown = json.dumps(result, ensure_ascii=False, separators=(",", ":"))
    assert 9000 < len(shown) <= RESULT_CHAR_BUDGETS["web.search"]


@pytest.mark.asyncio
async def test_research_reads_nothing_when_the_search_answers_part_of_the_query():
    requested: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requested.append(request.url.host)
        return bing_answers(AMC_ROWS)(request)

    result = await toolkit(handler, hosts_of_rows(AMC_ROWS)).execute(
        "research", {"query": SHOWTIMES_QUERY}
    )

    assert result == {
        "ok": True,
        "query": SHOWTIMES_QUERY,
        "results": [],
        "note": RESEARCH_OFF_TOPIC_NOTE,
    }
    assert "none was read" in result["note"] and "Don't guess addresses" in result["note"]
    # Not one of the three pages about something else was fetched.
    assert requested == ["html.duckduckgo.com", "www.bing.com"]


@pytest.mark.asyncio
async def test_research_reads_what_the_browser_found_for_the_whole_query():
    requested: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requested.append(request.url.host)
        if request.url.host in ENGINES:
            return bing_answers(AMC_ROWS)(request)
        return httpx.Response(200, html=PAGE_HTML)

    browser = FakeBrowser({"ok": True, "rows": SHOWTIMES_ROWS})
    result = await toolkit(handler, hosts_of_rows(AMC_ROWS, SHOWTIMES_ROWS)).execute(
        "research", {"query": SHOWTIMES_QUERY}, browser=browser
    )

    assert result["ok"] is True and result["source"] == "browser" and "note" not in result
    assert [(r["url"], r["ok"]) for r in result["results"]] == [(SHOWTIMES_ROWS[0]["url"], True)]
    assert requested == ["html.duckduckgo.com", "www.bing.com", "www.amctheatres.com"]


@pytest.mark.asyncio
async def test_the_fixed_notes_and_hints_reach_the_model_through_the_runtimes_scan():
    """The runtime scans every tool result and redacts one that reads like an
    instruction to the model. These sentences do tell it what to do next, so
    each is checked against the real guard: flagged, it would take the whole
    answer with it."""
    from tests.test_agent_loop_security import ScriptedProvider, _runtime

    def refused(request: httpx.Request) -> httpx.Response:
        if request.url.host in ENGINES:
            return bing_answers(PAPER_TIGER_ROWS)(request)
        return httpx.Response(403, text="no bots")

    partial = await toolkit(bing_answers(AMC_ROWS), ENGINES).search(SHOWTIMES_QUERY)
    unread = await toolkit(bing_answers(AMC_ROWS), ENGINES).research(SHOWTIMES_QUERY)
    blocked = await toolkit(challenged, ENGINES).search(SHOWTIMES_QUERY)
    wall = await toolkit(refused, {"example.com": (PUBLIC_ADDRESS,)}).fetch_page(
        "https://example.com/wall"
    )
    # Both sources the search found refuse the reader.
    walled = await toolkit(refused, hosts_of_rows(PAPER_TIGER_ROWS)).research(
        '"Paper Tiger" movie 2026'
    )
    assert (partial["note"], unread["note"]) == (SEARCH_OFF_TOPIC_NOTE, RESEARCH_OFF_TOPIC_NOTE)
    assert blocked["hint"] and wall["hint"] == FETCH_REFUSED_HINT
    assert [source["hint"] for source in walled["results"]] == [FETCH_REFUSED_HINT] * 2

    runtime, _, _ = _runtime(ScriptedProvider([]))
    for result in (partial, unread, blocked, wall, walled):
        assert await runtime._scan_and_redact_result(result, "u1") == result


def test_bing_and_duckduckgo_tracking_links_are_unwrapped_without_being_followed():
    rows = [
        {"title": "dbrand", "url": "https://www.bing.com/ck/a?!&&p=4f&ptn=3&u=a1aHR0cHM6Ly93d3cuZGJyYW5kLmNvbS9zaG9wL2dyaXAvaXBob25lLTE2LXByby1tYXgtY2FzZXM&ntb=1", "snippet": "s"},
        {"title": "ddg", "url": "https://duckduckgo.com/l/?uddg=https%3A%2F%2Fnews.example.org%2Fa", "snippet": ""},
        {"title": "Bing itself", "url": "https://www.bing.com/maps", "snippet": ""},
        {"title": "advert", "url": "https://www.bing.com/aclk?ld=e8&u=aHR0cHM6Ly9jYXNlcy5leGFtcGxl", "snippet": ""},
        {"title": "not base64", "url": "https://www.bing.com/ck/a?u=a1%%%", "snippet": ""},
        {"title": "script", "url": "javascript:alert(1)", "snippet": ""},
        {"title": "", "url": "https://example.com/untitled", "snippet": ""},
    ]
    urls = [row["url"] for row in clean_result_rows(rows, 10, 200)]
    assert urls == [DBRAND, "https://news.example.org/a", "https://www.bing.com/maps"]
    assert len(clean_result_rows(rows * 20, 10, 200)) == 3
    assert clean_result_rows("not a list", 10, 200) == []


@pytest.mark.asyncio
async def test_search_empty_result_set_is_not_an_error():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, html="<html><body>no results</body></html>")

    result = await toolkit(handler, {"html.duckduckgo.com": (PUBLIC_ADDRESS,)}).search("q")
    # A results page with nothing that reads as a bot check: a real empty.
    assert result == {"ok": True, "query": "q", "results": [], "count": 0}


@pytest.mark.asyncio
async def test_search_requires_a_query():
    def handler(request: httpx.Request) -> httpx.Response:  # pragma: no cover
        raise AssertionError("must not reach the network")

    assert (await toolkit(handler).search("   "))["ok"] is False


# ---------------------------------------------------------------------------
# fetch_page
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_fetch_page_returns_readable_text_without_chrome():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, html=PAGE_HTML)

    result = await toolkit(handler, {"example.com": (PUBLIC_ADDRESS,)}).fetch_page(
        "https://example.com/mount"
    )

    assert result["ok"] is True
    assert result["title"] == "Monitor mounts"
    assert "VESA monitor mount" in result["text"]
    assert "Holds a display up to 32 inches." in result["text"]
    assert "window.tracking" not in result["text"]
    assert "color: red" not in result["text"]
    assert "Home Shop Cart" not in result["text"]
    assert "Copyright" not in result["text"]
    assert result["truncated"] is False


@pytest.mark.asyncio
async def test_fetch_page_reads_a_page_that_names_an_unknown_charset():
    """A charset Python has no codec for raised LookupError out of fetch_page."""

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            headers={"content-type": "text/html; charset=x-no-such-codec"},
            content=PAGE_HTML.encode("utf-8"),
        )

    result = await toolkit(handler, {"example.com": (PUBLIC_ADDRESS,)}).fetch_page(
        "https://example.com/mount"
    )

    assert result["ok"] is True
    assert "VESA monitor mount" in result["text"]


@pytest.mark.asyncio
async def test_fetch_page_truncates_and_says_so():
    body = "<html><body>" + "<p>word word word</p>" * 400 + "</body></html>"

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, html=body)

    result = await toolkit(handler, {"example.com": (PUBLIC_ADDRESS,)}).fetch_page(
        "https://example.com/long", max_chars=300
    )

    assert result["truncated"] is True
    assert result["chars"] <= 300
    assert "Truncated" in result["note"]


@pytest.mark.asyncio
async def test_fetch_page_max_chars_has_a_ceiling():
    body = "<html><body>" + "<p>word</p>" * 20000 + "</body></html>"

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, html=body)

    result = await toolkit(handler, {"example.com": (PUBLIC_ADDRESS,)}).fetch_page(
        "https://example.com/long", max_chars=10_000_000
    )
    assert result["chars"] <= MAX_PAGE_CHARS


@pytest.mark.asyncio
async def test_fetch_page_reports_the_url_it_ended_on():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/start":
            return httpx.Response(302, headers={"location": "https://example.com/final"})
        return httpx.Response(200, html="<title>Final</title><p>Here</p>")

    result = await toolkit(handler, {"example.com": (PUBLIC_ADDRESS,)}).fetch_page(
        "https://example.com/start"
    )
    assert result["url"] == "https://example.com/final"
    assert result["title"] == "Final"


@pytest.mark.asyncio
async def test_fetch_page_refuses_non_text_content():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=b"\x89PNG\r\n\x1a\n", headers={"content-type": "image/png"})

    result = await toolkit(handler, {"example.com": (PUBLIC_ADDRESS,)}).fetch_page(
        "https://example.com/photo.png"
    )
    assert result["ok"] is False
    assert "image/png" in result["error"]


@pytest.mark.asyncio
async def test_fetch_page_reads_a_pdf_only_in_a_document_context():
    # top10:file_extraction: a PDF is read as sections, which needs the
    # executor's document context ("Read files and documents"); without
    # one the answer is that switch's refusal (tests/files/test_files_web.py
    # covers the read itself).
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=b"%PDF-1.4", headers={"content-type": "application/pdf"})

    result = await toolkit(handler, {"example.com": (PUBLIC_ADDRESS,)}).fetch_page(
        "https://example.com/doc.pdf"
    )
    assert result["ok"] is False
    assert "Read files and documents" in result["error"]


@pytest.mark.asyncio
async def test_fetch_page_reports_http_error_status():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(404, html="<p>gone</p>")

    result = await toolkit(handler, {"example.com": (PUBLIC_ADDRESS,)}).fetch_page(
        "https://example.com/missing"
    )
    assert result["ok"] is False
    assert result["status_code"] == 404


async def fetch_answered_with(status: int) -> dict[str, Any]:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(status, html="<p>Access denied</p>")

    return await toolkit(handler, {"example.com": (PUBLIC_ADDRESS,)}).fetch_page(
        "https://example.com/wall"
    )


@pytest.mark.parametrize("status", [401, 403, 429, 503])
@pytest.mark.asyncio
async def test_fetch_page_says_what_to_do_when_a_site_refuses_automated_readers(status: int):
    assert await fetch_answered_with(status) == {
        "ok": False,
        "error": f"Fetch failed with HTTP {status}.",
        "status_code": status,
        "url": "https://example.com/wall",
        "hint": (
            "This site blocks automated reads. Don't retry this page. Answer from the search "
            "results you already have and name the source, or say plainly what is still missing."
        ),
    }


@pytest.mark.asyncio
async def test_a_page_read_that_times_out_says_so_and_points_at_the_search_results():
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ReadTimeout("slow", request=request)

    tools = toolkit(handler, {"example.com": (PUBLIC_ADDRESS,)})
    result = await tools.execute("fetch_page", {"url": "https://example.com/slow"})

    assert result == {
        "ok": False,
        "error": "The site did not answer in time (ReadTimeout).",
        # Slow is not blocked: the hint never says the site blocks readers.
        "hint": (
            "Don't retry this page. Answer from the search results you already have and "
            "name the source, or say plainly what is still missing."
        ),
    }


@pytest.mark.parametrize("status", [404, 410, 500])
@pytest.mark.asyncio
async def test_fetch_page_gives_that_hint_for_no_other_failure(status: int):
    # A missing or broken page is not a refusal: the browser would not help.
    assert await fetch_answered_with(status) == {
        "ok": False,
        "error": f"Fetch failed with HTTP {status}.",
        "status_code": status,
        "url": "https://example.com/wall",
    }


# ---------------------------------------------------------------------------
# Egress policy
# ---------------------------------------------------------------------------


def unreachable_handler(request: httpx.Request) -> httpx.Response:  # pragma: no cover
    raise AssertionError(f"request escaped the policy: {request.url}")


@pytest.mark.parametrize(
    "url",
    [
        "http://127.0.0.1:8000/admin",
        "http://[::1]:8000/admin",
        "http://169.254.169.254/latest/meta-data/",
        "http://10.0.0.5/internal",
        "http://192.168.1.1/router",
        "http://localhost:8000/admin",
    ],
)
@pytest.mark.asyncio
async def test_fetch_page_refuses_internal_destinations(url: str):
    result = await toolkit(unreachable_handler).execute("fetch_page", {"url": url})
    assert result["ok"] is False
    assert result["blocked"] is True


@pytest.mark.parametrize("url", ["file:///etc/passwd", "ftp://example.com/x", "gopher://x/1"])
@pytest.mark.asyncio
async def test_fetch_page_refuses_non_http_schemes(url: str):
    result = await toolkit(unreachable_handler).execute("fetch_page", {"url": url})
    assert result["ok"] is False
    assert "http" in result["error"]


@pytest.mark.asyncio
async def test_redirect_to_a_private_address_is_refused():
    hops: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        hops.append(str(request.url))
        return httpx.Response(302, headers={"location": "http://127.0.0.1:8000/admin"})

    result = await toolkit(handler, {"example.com": (PUBLIC_ADDRESS,)}).execute(
        "fetch_page", {"url": "https://example.com/redirect"}
    )

    assert result["ok"] is False
    assert result["blocked"] is True
    # The first hop was allowed and the second never left the process.
    assert hops == ["https://example.com/redirect"]


def test_validated_addresses_refuses_a_name_that_resolves_to_loopback():
    with pytest.raises(EgressBlocked):
        validated_addresses("http://localhost:8000/")


def test_validated_addresses_returns_public_addresses():
    assert validated_addresses(f"https://{PUBLIC_ADDRESS}/") == (PUBLIC_ADDRESS,)


# ---------------------------------------------------------------------------
# Address pinning
#
# The socket layer itself (refusing an unpinned origin, falling over to
# the next validated address, refusing unix sockets) is shared with the
# MCP transport and covered in test_mcp_dns_pinning.py. What matters here
# is that the web client actually feeds that table.
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_guarded_client_pins_the_address_the_check_validated():
    pins: dict[tuple[str, int], tuple[str, ...]] = {}

    def resolve(url: str) -> tuple[str, ...]:
        return (PUBLIC_ADDRESS,)

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text="ok")

    client = build_guarded_client(
        transport=httpx.MockTransport(handler), resolver=resolve, pins=pins
    )
    async with client:
        await client.get("https://example.com/")

    assert pins[("example.com", 443)] == (PUBLIC_ADDRESS,)


# ---------------------------------------------------------------------------
# screenshot
# ---------------------------------------------------------------------------


async def fake_capture(url: str, **kwargs: Any) -> tuple[bytes, str, int, int]:
    return b"\x89PNG-bytes", url, kwargs["width"], kwargs["height"]


@pytest.mark.asyncio
async def test_screenshot_without_playwright_explains_the_install():
    tools = WebToolkit(
        resolver=resolver_for({"example.com": (PUBLIC_ADDRESS,)}),
        playwright_loader=lambda: None,
    )
    result = await tools.screenshot("https://example.com/")

    assert result["ok"] is False
    assert result["playwright_available"] is False
    assert "Playwright" in result["error"]
    # The error names the capability so the model reaches for the
    # approval-gated installer rather than telling the user to run pip,
    # and tells it to ask in plain words. No shell command reaches the
    # model at all, so none can be pasted into a reply.
    assert result["capability"] == "browser"
    assert "call system.install_capability with name='browser'" in result["error"]
    assert "Ask them in plain words" in result["error"]
    assert "install" not in result
    assert "pip" not in str(result) and "python -m" not in str(result)
    assert "\u2014" not in result["error"] and "\u2013" not in result["error"]


@pytest.mark.asyncio
async def test_screenshot_returns_a_data_url_and_dimensions():
    tools = WebToolkit(
        resolver=resolver_for({"example.com": (PUBLIC_ADDRESS,)}), capture=fake_capture
    )
    result = await tools.screenshot("https://example.com/", width=800, height=600)

    assert result["ok"] is True
    assert result["image"].startswith("data:image/jpeg;base64,")
    assert (result["width"], result["height"]) == (800, 600)
    assert result["bytes"] == len(b"\x89PNG-bytes")


@pytest.mark.asyncio
async def test_screenshot_omits_an_oversized_image():
    async def huge_capture(url: str, **kwargs: Any) -> tuple[bytes, str, int, int]:
        return b"0" * (5 * 1024 * 1024), url, 1024, 768

    tools = WebToolkit(
        resolver=resolver_for({"example.com": (PUBLIC_ADDRESS,)}), capture=huge_capture
    )
    result = await tools.screenshot("https://example.com/")

    assert result["ok"] is True
    assert "image" not in result
    assert "inline limit" in result["image_omitted"]


@pytest.mark.asyncio
async def test_screenshot_refuses_an_internal_url_before_launching_a_browser():
    def loader() -> Any:  # pragma: no cover
        raise AssertionError("browser launched for a blocked URL")

    tools = WebToolkit(resolver=validated_addresses, playwright_loader=loader)
    result = await tools.execute("screenshot", {"url": "http://127.0.0.1:3000/"})

    assert result["ok"] is False
    assert result["blocked"] is True


@pytest.mark.asyncio
async def test_screenshot_revalidates_the_url_the_page_settled_on():
    async def redirecting_capture(url: str, **kwargs: Any) -> tuple[bytes, str, int, int]:
        return b"png", "http://169.254.169.254/latest/meta-data/", 1024, 768

    tools = WebToolkit(
        resolver=resolver_for({"example.com": (PUBLIC_ADDRESS,)}),
        capture=redirecting_capture,
    )
    result = await tools.execute("screenshot", {"url": "https://example.com/"})

    assert result["ok"] is False
    assert result["blocked"] is True


@pytest.mark.asyncio
async def test_screenshot_capture_failure_is_not_reported_as_a_missing_install():
    async def failing_capture(url: str, **kwargs: Any) -> tuple[bytes, str, int, int]:
        raise WebToolError("Screenshot failed: TimeoutError")

    tools = WebToolkit(
        resolver=resolver_for({"example.com": (PUBLIC_ADDRESS,)}), capture=failing_capture
    )
    result = await tools.screenshot("https://example.com/")

    assert result["ok"] is False
    assert "playwright_available" not in result


@pytest.mark.parametrize(
    ("message", "reason"),
    [
        # What Playwright raises when a site closes the connection on the browser.
        ("Page.goto: net::ERR_HTTP2_PROTOCOL_ERROR at https://example.com/?token=s3cret", "net::ERR_HTTP2_PROTOCOL_ERROR"),
        # No net:: code: the class name is all that is safe to show.
        ("Page.goto: Target closed at https://example.com/?token=s3cret", "Error"),
    ],
)
@pytest.mark.asyncio
async def test_screenshot_failure_names_the_browsers_reason_and_never_the_address(
    message: str, reason: str
):
    class Error(Exception):
        """Same class name as playwright's own, which is why it used to read just "Error"."""

    class FailingPlaywright:
        def async_playwright(self) -> Any:
            raise Error(message)

    tools = WebToolkit(
        resolver=resolver_for({"example.com": (PUBLIC_ADDRESS,)}),
        playwright_loader=lambda: FailingPlaywright(),
    )
    result = await tools.execute("screenshot", {"url": "https://example.com/"})

    assert result["ok"] is False
    assert result["error"].startswith(f"Screenshot failed: {reason}. Don't retry this page.")
    assert "s3cret" not in result["error"] and "example.com" not in result["error"]


def test_the_prompt_tells_the_model_to_report_only_tried_steps_and_to_fall_back_to_search():
    from services.agent.runtime import SECURITY_SYSTEM_PROMPT

    rules = " ".join(SECURITY_SYSTEM_PROMPT.split("<tool_use>")[1].split("</tool_use>")[0].split())
    assert "Only report what your own tool calls returned" in rules
    assert "try it or say you haven't" in rules
    assert "answer from the search results you already have and name the source" in rules
    assert "read one likely page" in rules
    assert "also give the page link, and its date when the page shows one" in rules


@pytest.mark.asyncio
async def test_screenshot_rejects_an_unknown_image_format():
    tools = WebToolkit(
        resolver=resolver_for({"example.com": (PUBLIC_ADDRESS,)}), capture=fake_capture
    )
    result = await tools.screenshot("https://example.com/", image_format="webp")
    assert result["ok"] is False


# ---------------------------------------------------------------------------
# Dispatch
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_execute_rejects_an_unknown_action():
    result = await toolkit(unreachable_handler).execute("login", {"url": "https://example.com"})
    assert result["ok"] is False


@pytest.mark.asyncio
async def test_execute_reports_bad_arguments_instead_of_raising():
    result = await toolkit(unreachable_handler).execute("fetch_page", {"nonsense": 1})
    assert result["ok"] is False
    assert "Invalid arguments" in result["error"]


@pytest.mark.asyncio
async def test_registry_executor_runs_the_web_toolkit():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, html=SEARCH_HTML)

    executor = ConnectorToolExecutor(
        web_toolkit=toolkit(handler, {"html.duckduckgo.com": (PUBLIC_ADDRESS,)})
    )
    result = await executor.execute("web.search", {"query": "flights"}, "user-1")

    assert result["ok"] is True
    assert result["results"][0]["url"] == "https://example.com/flights"


@pytest.mark.asyncio
async def test_registry_executor_blocks_web_tools_it_cannot_run():
    executor = ConnectorToolExecutor(web_toolkit=toolkit(unreachable_handler))
    result = await executor.execute("web.purchase", {}, "user-1")
    assert result["ok"] is False
