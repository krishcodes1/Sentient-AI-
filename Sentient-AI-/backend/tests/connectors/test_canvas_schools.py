"""Tests for services/connectors/canvas_schools.py, the "find your school"
search over Instructure's public Canvas directory.

Why it exists: the answer comes from a third party and becomes the Canvas
address the user connects to, so only plain hostnames may come through, the
request may reach nothing but the one search address, and typing a name must
not become a request per keystroke. No real network or DNS: check_ssrf is
replaced, and httpx.MockTransport answers behind the real request hook.
"""

from __future__ import annotations

from collections.abc import Iterator
from typing import Any, Optional

import httpx
import pytest

import core.network_security as netsec
from services.connectors import canvas_schools
from services.connectors.canvas_schools import (
    CanvasSchool,
    SchoolSearchError,
    search_schools,
)
from services.tools.net import EgressBlocked

PUBLIC_IP = "203.0.113.10"  # TEST-NET-3; check_ssrf is stubbed


@pytest.fixture(autouse=True)
def ssrf_urls(monkeypatch) -> Iterator[list[str]]:
    """A fresh cache, and the URLs that reached the DNS check."""
    canvas_schools.clear_cache()
    urls: list[str] = []

    def fake_check_ssrf(url: str) -> netsec.SSRFCheckResult:
        urls.append(url)
        return netsec.SSRFCheckResult(
            safe=True, resolved_ip=PUBLIC_IP, resolved_ips=(PUBLIC_IP,)
        )

    monkeypatch.setattr(netsec, "check_ssrf", fake_check_ssrf)
    yield urls
    canvas_schools.clear_cache()


def directory(
    payload: Any = None,
    *,
    status: int = 200,
    seen: Optional[list[httpx.Request]] = None,
    content: Optional[bytes] = None,
) -> httpx.MockTransport:
    """A mock directory answering every request the same way."""

    def handler(request: httpx.Request) -> httpx.Response:
        if seen is not None:
            seen.append(request)
        if content is not None:
            return httpx.Response(status, content=content)
        return httpx.Response(status, json=payload)

    return httpx.MockTransport(handler)


def school(name: str, domain: str) -> dict[str, Any]:
    return {"name": name, "domain": domain, "distance": None, "authentication_provider": None}


# ---------------------------------------------------------------------------
# The request and the answer
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_search_asks_the_one_directory_address_without_credentials(ssrf_urls):
    seen: list[httpx.Request] = []
    payload = [school("NYIT", "nyit.instructure.com"), school("NYITCOM", "nyit.instructure.com")]

    schools = await search_schools("  NYIT ", transport=directory(payload, seen=seen))

    assert schools == [CanvasSchool(name="NYIT", domain="nyit.instructure.com")]
    (request,) = seen
    assert (request.method, request.url.scheme, request.url.host, request.url.path) == (
        "GET",
        "https",
        "canvas.instructure.com",
        "/api/v1/accounts/search",
    )
    assert dict(request.url.params) == {"name": "nyit", "per_page": "50"}
    assert request.headers["Accept"] == "application/json"
    assert "Authorization" not in request.headers
    # The policy hook ran in front of the mock transport.
    assert len(ssrf_urls) == 1 and ssrf_urls[0].startswith(canvas_schools.SEARCH_URL)


@pytest.mark.asyncio
async def test_only_named_schools_with_plain_hostnames_come_through():
    too_long = ("a" * 63 + ".") * 4 + "com"  # valid labels, 259 characters
    payload = [
        school("Good School", "Good.Instructure.com"),
        school("Scheme", "https://scheme.instructure.com"),
        school("Port", "port.instructure.com:8443"),
        school("Path", "path.instructure.com/login"),
        school("Userinfo", "user@info.instructure.com"),
        school("Space", "spa ce.instructure.com"),
        school("No dot", "localhost"),
        school("Address", "10.0.0.1"),
        school("Empty label", "a..instructure.com"),
        school("Trailing dot", "dot.instructure.com."),
        school("Hyphen edge", "-edge.instructure.com"),
        school("Unicode", "b" + chr(0xFC) + "cher.instructure.com"),
        school("Too long", too_long),
        {"name": "Not a string", "domain": 42},
        {"name": "No domain"},
        school("", "empty-name.instructure.com"),
        school("   ", "blank-name.instructure.com"),
        {"name": None, "domain": "none-name.instructure.com"},
        "not an object",
        None,
        school("Duplicate", "good.instructure.com"),
        school("Second" + chr(7) + " School" + chr(0x202E), "second.instructure.com"),
        school("x" * 200, "long-name.instructure.com"),
        school("Punycode", "xn--bcher-kva.example.edu"),
    ]

    schools = await search_schools("school", transport=directory(payload))

    assert schools == [
        CanvasSchool(name="Good School", domain="good.instructure.com"),
        CanvasSchool(name="Second School", domain="second.instructure.com"),
        CanvasSchool(name="x" * canvas_schools.NAME_MAX_CHARS, domain="long-name.instructure.com"),
        CanvasSchool(name="Punycode", domain="xn--bcher-kva.example.edu"),
    ]


@pytest.mark.asyncio
async def test_results_are_capped():
    payload = [school(f"School {n}", f"school{n}.instructure.com") for n in range(30)]

    schools = await search_schools("school", transport=directory(payload))

    assert len(schools) == canvas_schools.MAX_RESULTS == 20
    assert schools[0] == CanvasSchool(name="School 0", domain="school0.instructure.com")
    assert schools[-1].domain == "school19.instructure.com"


# ---------------------------------------------------------------------------
# Cache
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_answers_are_cached_per_lowercased_query():
    seen: list[httpx.Request] = []
    transport = directory([school("NYIT", "nyit.instructure.com")], seen=seen)

    first = await search_schools("NYIT", transport=transport)
    again = await search_schools(" nyit ", transport=transport)
    assert again == first and len(seen) == 1

    await search_schools("nyu", transport=transport)
    assert len(seen) == 2

    # Past the time to live the directory is asked again.
    stored_at, schools = canvas_schools._cache["nyit"]
    canvas_schools._cache["nyit"] = (stored_at - canvas_schools.CACHE_TTL_S - 1, schools)
    await search_schools("nyit", transport=transport)
    assert len(seen) == 3


@pytest.mark.asyncio
async def test_cache_is_bounded_and_drops_the_oldest(monkeypatch):
    monkeypatch.setattr(canvas_schools, "CACHE_MAX_ENTRIES", 3)
    transport = directory([school("NYIT", "nyit.instructure.com")])

    for query in ("aa", "bb", "cc", "dd"):
        await search_schools(query, transport=transport)

    assert list(canvas_schools._cache) == ["bb", "cc", "dd"]


# ---------------------------------------------------------------------------
# Failures
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "transport",
    [
        directory({"errors": [{"message": "nope"}]}),
        directory(None, content=b"<html>maintenance</html>"),
        directory([], status=500),
        directory([], status=429),
        # A redirect is never followed, wherever it points.
        httpx.MockTransport(
            lambda r: httpx.Response(302, headers={"Location": "https://evil.example/"})
        ),
    ],
    ids=["not-a-list", "not-json", "server-error", "rate-limited", "redirect"],
)
async def test_bad_answers_raise_and_are_not_cached(transport):
    with pytest.raises(SchoolSearchError):
        await search_schools("nyit", transport=transport)
    assert canvas_schools._cache == {}


@pytest.mark.asyncio
async def test_transport_errors_raise_without_the_query():
    def refuse(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectTimeout("timed out reaching " + str(request.url), request=request)

    with pytest.raises(SchoolSearchError) as caught:
        await search_schools("secret school name", transport=httpx.MockTransport(refuse))
    assert "ConnectTimeout" in str(caught.value)
    assert "secret" not in str(caught.value)


@pytest.mark.asyncio
async def test_a_failure_is_retried_on_the_next_search():
    answers = iter([httpx.Response(503), httpx.Response(200, json=[school("NYIT", "nyit.instructure.com")])])
    transport = httpx.MockTransport(lambda r: next(answers))

    with pytest.raises(SchoolSearchError):
        await search_schools("nyit", transport=transport)
    assert await search_schools("nyit", transport=transport) == [
        CanvasSchool(name="NYIT", domain="nyit.instructure.com")
    ]


# ---------------------------------------------------------------------------
# Network policy
# ---------------------------------------------------------------------------


def test_the_search_has_its_own_narrow_policy():
    policy = netsec.DEFAULT_POLICIES[netsec.CANVAS_SCHOOL_SEARCH_POLICY]
    assert netsec.CANVAS_SCHOOL_SEARCH_POLICY == "canvas_school_search"
    assert policy.allowed_hosts == ["canvas.instructure.com"]
    assert policy.allowed_paths == {"canvas.instructure.com": ["/api/v1/accounts/search"]}
    assert policy.https_only is True
    assert policy.instance_paths == [] and policy.redirect_hosts == {}


@pytest.mark.parametrize(
    "url",
    [
        "https://evil.example/api/v1/accounts/search",
        "https://nyit.instructure.com/api/v1/accounts/search",
        "https://canvas.instructure.com.evil.example/api/v1/accounts/search",
        "http://canvas.instructure.com/api/v1/accounts/search",
        "https://canvas.instructure.com:8443/api/v1/accounts/search",
        "https://user@canvas.instructure.com/api/v1/accounts/search",
        "https://canvas.instructure.com/api/v1/users/self",
        "https://canvas.instructure.com/api/v1/accounts/search/../../users/self",
    ],
)
def test_the_policy_refuses_everything_but_the_search_address(url, ssrf_urls):
    with pytest.raises(EgressBlocked):
        canvas_schools._policy_addresses(url)
    assert ssrf_urls == []  # refused before any DNS lookup


def test_the_policy_admits_the_search_address_and_returns_the_pins(ssrf_urls):
    url = canvas_schools.SEARCH_URL + "?name=nyit&per_page=50"
    assert canvas_schools._policy_addresses(url) == (PUBLIC_IP,)
    assert ssrf_urls == [url]


@pytest.mark.asyncio
async def test_a_search_pointed_elsewhere_never_leaves(monkeypatch):
    monkeypatch.setattr(canvas_schools, "SEARCH_URL", "https://evil.example/api/v1/accounts/search")
    seen: list[httpx.Request] = []

    with pytest.raises(SchoolSearchError, match="network policy"):
        await search_schools("nyit", transport=directory([], seen=seen))
    assert seen == []
