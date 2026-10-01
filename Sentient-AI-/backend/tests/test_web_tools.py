"""Tests for the built-in web tools: search parsing and truncation, page-fetch
text extraction and redirect handling, and screenshot capture all work over a
mocked transport while the real SSRF address-validation policy still runs in
front of it.

Why it exists: The egress policy is deliberately not mocked, so a tool that
bypasses `validated_addresses` and reaches an internal address would still be
caught here.

Tests for the built-in web tools.

Every HTTP call is served by an ``httpx.MockTransport``, so parsing and
truncation are exercised without touching the network. The egress policy
is *not* mocked: the request hook runs the real
``services.tools.net.validated_addresses`` in front of the mock
transport, and refusal tests use IP literals or names resolvable from
/etc/hosts so no DNS query is needed either.
"""

from __future__ import annotations

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
    MAX_PAGE_CHARS,
    SEARCH_BLOCKED,
    WebToolError,
    WebToolkit,
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
    assert "playwright install chromium" in result["install"]
    assert "Playwright" in result["error"]
    # The error names the capability so the model reaches for the
    # approval-gated installer rather than telling the user to run pip.
    assert result["capability"] == "browser"
    assert "system.install_capability" in result["error"]


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
