"""Tests for the built-in web tools.

Every HTTP call is served by an ``httpx.MockTransport``, so parsing and
truncation are exercised without touching the network. The egress policy
is *not* mocked: the request hook runs the real
``services.tools.net.validated_addresses`` in front of the mock
transport, and refusal tests use IP literals or names resolvable from
/etc/hosts so no DNS query is needed either.
"""

from __future__ import annotations

from typing import Any, Optional
from urllib.parse import urlparse

import httpx
import pytest

from services.agent.tool_registry import ConnectorToolExecutor
from services.tools.net import (
    EgressBlocked,
    build_guarded_client,
    validated_addresses,
)
from services.tools.web import WebToolError, WebToolkit

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

    result = await toolkit(handler, {"html.duckduckgo.com": (PUBLIC_ADDRESS,)}).search("q")
    assert result["ok"] is False
    assert result["status_code"] == 503


@pytest.mark.asyncio
async def test_search_empty_result_set_is_not_an_error():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, html="<html><body>no results</body></html>")

    result = await toolkit(handler, {"html.duckduckgo.com": (PUBLIC_ADDRESS,)}).search("q")
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
    assert result["chars"] <= 20000


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
        return httpx.Response(200, content=b"%PDF-1.4", headers={"content-type": "application/pdf"})

    result = await toolkit(handler, {"example.com": (PUBLIC_ADDRESS,)}).fetch_page(
        "https://example.com/doc.pdf"
    )
    assert result["ok"] is False
    assert "application/pdf" in result["error"]


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
