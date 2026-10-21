"""Tests for the owner's site rules in the web toolkit (``web.fetch_page``,
``web.research``, ``web.screenshot``) through the wrapped resolver
(``SiteRulesService.wrap_resolver`` / ``hooks.wrap_resolver``): they prove
that a fetch redirected into a Blocked site is refused before that hop is
requested, that research skips a Blocked source without reading it, that a
screenshot whose page settled on a Blocked site is refused, that a Blocked
host never reaches the resolver it wraps (DNS, or S4's lookup), that the log
line names the host and never a path or query, that the switch off or
rules never read let every hop through (the call check has already refused
the call in that case), and that the fail-closed resolver page watches and
knowledge imports get refuses every URL while no rules were ever read.

Why it exists: without this the agent could read a Blocked site one tool
call away from the browser (S7 deviation D1). Every HTTP call is served by
an ``httpx.MockTransport``; no DNS query is made.
"""

from __future__ import annotations

from typing import Any, Optional
from urllib.parse import quote

import httpx
import pytest

from services.site_rules import messages
from services.site_rules.hooks import wrap_resolver
from services.tools.net import EgressBlocked, OwnerRuleBlocked
from services.tools.web import WebToolkit
from tests.site_rules_fakes import FakeSiteRules, snapshot_of

PUBLIC_ADDRESS = "93.184.216.34"
SEARCH_HOST = "html.duckduckgo.com"
CASINO = "https://www.example-casino.com/promo?token=SECRET1"
NEWS = "https://news.example/story"


class Resolver:
    """DNS stand-in: every host is public; records what it was asked."""

    def __init__(self) -> None:
        self.asked: list[str] = []

    def __call__(self, url: str) -> tuple[str, ...]:
        self.asked.append(url)
        return (PUBLIC_ADDRESS,)


class Web:
    """A mock transport: the search engine and a few pages."""

    def __init__(self, pages: dict[str, httpx.Response], results: Optional[list[str]] = None) -> None:
        self.pages, self.results = pages, results or []
        self.requests: list[str] = []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        url = str(request.url)
        self.requests.append(url)
        if request.url.host == SEARCH_HOST:
            rows = "".join(
                '<div class="result results_links">'
                f'<a class="result__a" href="//duckduckgo.com/l/?uddg={quote(result, safe="")}">'
                f"Result {index}</a>"
                f'<a class="result__snippet" href="#">About result {index}.</a></div>'
                for index, result in enumerate(self.results)
            )
            return httpx.Response(200, html=f"<html><body>{rows}</body></html>")
        reply = self.pages.get(url)
        return reply if reply is not None else httpx.Response(404, text="missing")


def _page(title: str) -> httpx.Response:
    return httpx.Response(
        200, html=f"<html><head><title>{title}</title></head><body><h1>{title}</h1><p>Story text.</p></body></html>"
    )


def _rules(**kwargs: Any) -> FakeSiteRules:
    snapshot = kwargs.pop("snapshot", snapshot_of({"*.example-casino.com": "blocked"}, **kwargs))
    return FakeSiteRules(snapshot)


@pytest.mark.asyncio
async def test_fetch_page_redirected_to_a_blocked_host_is_refused_before_the_hop():
    web = Web(
        {
            NEWS: httpx.Response(302, headers={"location": CASINO}),
            CASINO: _page("Casino"),
        }
    )
    rules = _rules()
    inner = Resolver()
    tools = WebToolkit(transport=httpx.MockTransport(web), resolver=wrap_resolver(rules, inner))
    result = await tools.execute("fetch_page", {"url": NEWS})
    assert result["ok"] is False and result["blocked"] is True
    assert result["error"] == messages.blocked_call("www.example-casino.com")
    assert web.requests == [NEWS]  # the Blocked hop was never requested
    assert not any("example-casino" in url for url in inner.asked)
    assert rules.hits == [
        {"user_id": None, "host": "www.example-casino.com", "kind": "blocked", "where": "web", "audit": False}
    ]
    # A page on an ordinary site is fetched as before.
    web.pages[NEWS] = _page("News")
    result = await tools.execute("fetch_page", {"url": NEWS})
    assert result["ok"] is True and "Story text." in result["text"]


@pytest.mark.asyncio
async def test_research_skips_a_blocked_source():
    web = Web({CASINO: _page("Casino"), NEWS: _page("News")}, results=[CASINO, NEWS])
    tools = WebToolkit(transport=httpx.MockTransport(web), resolver=wrap_resolver(_rules(), Resolver()))
    result = await tools.execute("research", {"query": "weekend news", "max_sources": 2})
    assert result["ok"] is True
    assert [source["url"] for source in result["results"]] == [NEWS]
    assert CASINO not in web.requests


@pytest.mark.asyncio
async def test_screenshot_whose_final_url_is_blocked_is_refused():
    captured: list[str] = []

    async def capture(url: str, **kwargs: Any) -> tuple[bytes, str, int, int]:
        captured.append(url)
        return b"png", "https://www.example-casino.com/landing", kwargs["width"], kwargs["height"]

    tools = WebToolkit(resolver=wrap_resolver(_rules(), Resolver()), capture=capture)
    result = await tools.execute("screenshot", {"url": NEWS})
    assert result["ok"] is False and result["blocked"] is True
    assert result["error"] == messages.blocked_call("www.example-casino.com")
    assert "image" not in result
    # A Blocked first URL never launches a capture at all.
    result = await tools.execute("screenshot", {"url": CASINO})
    assert result["ok"] is False and result["blocked"] is True
    assert captured == [NEWS]


def test_the_wrapped_resolver_logs_the_host_never_the_query():
    from structlog.testing import capture_logs

    resolve = wrap_resolver(_rules(), Resolver())
    with capture_logs() as logs:
        with pytest.raises(EgressBlocked):
            resolve("https://login.example-casino.com/account/me?token=SECRET2#frag")
    (entry,) = [entry for entry in logs if entry.get("event") == "web_site_rule_blocked"]
    assert entry["host"] == "login.example-casino.com"
    text = repr(logs)
    assert "SECRET2" not in text and "/account" not in text and "frag" not in text


def test_a_blocked_host_never_reaches_the_resolver_it_wraps():
    # S7 is composed outermost (main.py): DNS, and S4's lookup if it wraps
    # too, are never asked about a site the owner blocked.
    inner = Resolver()
    resolve = wrap_resolver(_rules(), inner)
    with pytest.raises(EgressBlocked):
        resolve(CASINO)
    assert inner.asked == []
    assert resolve(NEWS) == (PUBLIC_ADDRESS,) and inner.asked == [NEWS]


def test_the_switch_off_or_rules_never_read_let_every_hop_through():
    for rules in (_rules(enabled=False), FakeSiteRules(None)):
        inner = Resolver()
        assert wrap_resolver(rules, inner)(CASINO) == (PUBLIC_ADDRESS,)
        assert inner.asked == [CASINO]


def test_a_blocked_host_is_refused_as_the_owners_rule_with_s7s_sentence():
    # OwnerRuleBlocked is an EgressBlocked, so every fetcher still refuses
    # it; a page watch shows its sentence instead of its own generic one.
    with pytest.raises(OwnerRuleBlocked) as caught:
        wrap_resolver(_rules(), Resolver())(CASINO)
    assert isinstance(caught.value, EgressBlocked)
    assert str(caught.value) == messages.blocked_call("www.example-casino.com")


def test_a_fail_closed_resolver_refuses_every_url_while_no_rules_were_ever_read():
    # Page watches and knowledge imports (main.py): a background check has
    # no call check in front of it, so unread rules open nothing.
    inner = Resolver()
    resolve = wrap_resolver(FakeSiteRules(None), inner, fail_closed=True)
    for url in (CASINO, NEWS):
        with pytest.raises(OwnerRuleBlocked) as caught:
            resolve(url)
        assert str(caught.value) == messages.UNAVAILABLE
    assert inner.asked == []
    # Read rules: a Blocked host is refused, any other goes to the inner
    # resolver unchanged, and the switch off lets every host through.
    resolve = wrap_resolver(_rules(), inner, fail_closed=True)
    with pytest.raises(OwnerRuleBlocked):
        resolve(CASINO)
    assert resolve(NEWS) == (PUBLIC_ADDRESS,) and inner.asked == [NEWS]
    assert wrap_resolver(_rules(enabled=False), inner, fail_closed=True)(CASINO) == (PUBLIC_ADDRESS,)
    assert inner.asked == [NEWS, CASINO]
