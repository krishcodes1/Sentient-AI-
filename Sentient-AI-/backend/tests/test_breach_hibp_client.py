"""Tests for services/breach/hibp.py and services/breach/egress.py, the Have I
Been Pwned v3 client: they prove that a lookup asks only breachedaccount with
the key in the hibp-api-key header, an accurate user agent and the address
URL-encoded in the path, that redirects are not followed, that a 404 means no
breaches, that each failure maps to its fixed code (401 key refused, 400
address refused, 429 one paced retry then rate limited, 5xx/403/timeout/
connection error unavailable, not-JSON/wrong shape/redirect/oversized bad
answer, a policy refusal refused_by_policy), that the parser keeps only the
facts Crawler stores and cleans them, that HIBP's network policy allows only
its two paths over HTTPS, that the SSRF check and its log line see only the
origin, that no exception message or log line holds the address or the key,
that the pacer spaces requests by the key's limit, and that the Service keys
tester answers plain sentences that never quote the key.

Why it exists: this client sends an owner's email address and their paid key
to a third party, so the request must be exactly the one the design allows and
its failures must never leak either value into logs, audit rows or API
answers. No real network or DNS: check_ssrf is replaced (or fed a fake
getaddrinfo), and httpx.MockTransport answers behind the real request hook.
"""

from __future__ import annotations

import asyncio
import json
import socket
from collections.abc import Iterator
from datetime import date, datetime, timezone
from typing import Any, Callable, Optional

import httpx
import pytest
from structlog.testing import capture_logs

import core.network_security as netsec
from core.network_security import DEFAULT_POLICIES, HIBP_POLICY, check_network_policy
from services.breach import hibp
from services.breach.egress import policy_resolver
from services.breach.hibp import (
    API_BASE,
    MAX_BREACHES,
    USER_AGENT,
    AddressRefused,
    BadAnswer,
    Breach,
    HibpClient,
    HibpError,
    KeyRefused,
    Pacer,
    PolicyRefused,
    RateLimited,
    Unavailable,
    check_key,
    key_format_ok,
    parse_breaches,
)
from services.reputation.keys import KeyTestResult, spec_for
from services.tools.net import EgressBlocked

PUBLIC_IP = "203.0.113.10"  # TEST-NET-3; check_ssrf is stubbed
# Built by concatenation so no literal key is ever in the source (scaffold C6).
KEY = "0123456789abcdef" * 2
ADDRESS = "kash@example.com"
ENCODED = "kash%40example.com"
REAL_CHECK_SSRF = netsec.check_ssrf


@pytest.fixture(autouse=True)
def ssrf_urls(monkeypatch) -> Iterator[list[str]]:
    """The URLs that reached the DNS check (each one answered with a public address)."""
    urls: list[str] = []

    def fake_check_ssrf(url: str) -> netsec.SSRFCheckResult:
        urls.append(url)
        return netsec.SSRFCheckResult(safe=True, resolved_ip=PUBLIC_IP, resolved_ips=(PUBLIC_IP,))

    monkeypatch.setattr(netsec, "check_ssrf", fake_check_ssrf)
    yield urls


class FakeTime:
    """A monotonic clock and a sleep that only moves it, recording each sleep."""

    def __init__(self, start: float = 1000.0) -> None:
        self.now = start
        self.sleeps: list[float] = []

    def clock(self) -> float:
        return self.now

    async def sleep(self, seconds: float) -> None:
        self.sleeps.append(round(seconds, 6))
        self.now += seconds


def scripted(*answers: Any, seen: Optional[list[httpx.Request]] = None) -> httpx.MockTransport:
    """A mock HIBP answering each request with the next answer: an httpx.Response, an
    exception (raised), or a callable taking the request."""
    queue = list(answers)

    def handler(request: httpx.Request) -> httpx.Response:
        if seen is not None:
            seen.append(request)
        answer = queue.pop(0) if len(queue) > 1 else queue[0]
        if callable(answer) and not isinstance(answer, httpx.Response):
            answer = answer(request)
        if isinstance(answer, BaseException):
            raise answer
        return _fresh(answer)

    return httpx.MockTransport(handler)


def _fresh(answer: httpx.Response) -> httpx.Response:
    """A new Response with the same status, headers and body, so one scripted answer can
    serve several requests (a streamed body is served as is, once)."""
    try:
        content = answer.content
    except httpx.ResponseNotRead:
        return answer
    return httpx.Response(answer.status_code, headers=answer.headers, content=content)


def client_for(transport: httpx.MockTransport, clock: Optional[FakeTime] = None) -> HibpClient:
    clock = clock or FakeTime()
    return HibpClient(transport=transport, pacer=Pacer(clock=clock.clock, sleep=clock.sleep))


def breach_json(name: str = "ExampleShop", **override: Any) -> dict[str, Any]:
    item: dict[str, Any] = {
        "Name": name,
        "Title": "Example Shop",
        "Domain": "example-shop.com",
        "BreachDate": "2026-08-30",
        "AddedDate": "2026-10-12T03:11:00Z",
        "ModifiedDate": "2026-10-12T03:11:00Z",
        "PwnCount": 1200000,
        "Description": '<a href="https://evil.example/">Click here</a> to learn more.',
        "LogoPath": "https://haveibeenpwned.com/Content/Images/PwnedLogos/ExampleShop.png",
        "DataClasses": ["Email addresses", "Passwords", "Phone numbers"],
        "IsVerified": True,
        "IsFabricated": False,
        "IsSensitive": False,
        "IsRetired": False,
        "IsSpamList": False,
        "IsMalware": False,
    }
    item.update(override)
    return item


# ---------------------------------------------------------------------------
# The request
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_breaches_for_asks_breachedaccount_with_the_key_and_user_agent_headers_and_the_address_url_encoded_in_the_path(
    ssrf_urls,
):
    seen: list[httpx.Request] = []
    client = client_for(scripted(httpx.Response(200, json=[breach_json()]), seen=seen))

    breaches = await client.breaches_for(ADDRESS, KEY)

    assert [b.name for b in breaches] == ["ExampleShop"]
    (request,) = seen
    assert request.method == "GET"
    assert (request.url.scheme, request.url.host, request.url.port) == (
        "https",
        "haveibeenpwned.com",
        None,
    )
    assert (
        request.url.raw_path == f"/api/v3/breachedaccount/{ENCODED}?truncateResponse=false".encode()
    )
    assert request.headers["hibp-api-key"] == KEY
    assert request.headers["user-agent"] == USER_AGENT == "Crawler-AI-breach-monitor"
    assert request.headers["accept"] == "application/json"
    assert "authorization" not in request.headers
    # The policy hook ran in front of the mock transport, on the origin only.
    assert ssrf_urls == ["https://haveibeenpwned.com/"]


@pytest.mark.asyncio
async def test_an_address_with_reserved_characters_is_percent_encoded_and_normalised_first():
    seen: list[httpx.Request] = []
    client = client_for(scripted(httpx.Response(404), seen=seen))

    assert await client.breaches_for("  O'Brien+News%1@Example.org ", KEY) == []

    (request,) = seen
    assert request.url.raw_path.startswith(
        b"/api/v3/breachedaccount/o%27brien%2Bnews%251%40example.org"
    )


@pytest.mark.asyncio
async def test_the_key_never_appears_in_the_url_and_redirects_are_not_followed(ssrf_urls):
    seen: list[httpx.Request] = []
    redirect = httpx.Response(
        302, headers={"location": f"https://evil.example/collect?key={KEY}&a={ADDRESS}"}
    )
    client = client_for(scripted(redirect, seen=seen))

    with pytest.raises(BadAnswer) as caught:
        await client.breaches_for(ADDRESS, KEY)

    assert caught.value.code == "bad_answer"
    # One request, to HIBP only: the redirect target was never asked.
    assert len(seen) == 1 and seen[0].url.host == "haveibeenpwned.com"
    assert ssrf_urls == ["https://haveibeenpwned.com/"]
    for request in seen:
        assert KEY not in str(request.url)
        assert KEY.encode() not in request.url.raw_path


@pytest.mark.asyncio
async def test_a_404_means_no_breaches():
    client = client_for(scripted(httpx.Response(404, text="Not found")))
    assert await client.breaches_for(ADDRESS, KEY) == []


@pytest.mark.asyncio
async def test_an_empty_list_means_no_breaches_too():
    client = client_for(scripted(httpx.Response(200, json=[])))
    assert await client.breaches_for(ADDRESS, KEY) == []


@pytest.mark.asyncio
async def test_a_401_is_key_refused_and_a_400_is_address_refused():
    with pytest.raises(KeyRefused) as refused:
        await client_for(scripted(httpx.Response(401, json={"message": "Bad key"}))).breaches_for(
            ADDRESS, KEY
        )
    assert refused.value.code == "key_refused"

    with pytest.raises(AddressRefused) as address:
        await client_for(scripted(httpx.Response(400, text="Bad request"))).breaches_for(
            ADDRESS, KEY
        )
    assert address.value.code == "address_refused"


@pytest.mark.asyncio
async def test_a_malformed_key_or_address_is_never_sent():
    seen: list[httpx.Request] = []
    client = client_for(scripted(httpx.Response(200, json=[]), seen=seen))

    with pytest.raises(KeyRefused):
        await client.breaches_for(ADDRESS, KEY + "\n")
    with pytest.raises(KeyRefused):
        await client.breaches_for(ADDRESS, "not-a-key")
    with pytest.raises(AddressRefused):
        await client.breaches_for("kash@example.com, other@example.com", KEY)
    with pytest.raises(AddressRefused):
        await client.breaches_for("../../subscription/status@example.com", KEY)

    assert seen == []


@pytest.mark.asyncio
async def test_a_429_waits_retry_after_and_retries_once_then_reports_rate_limited():
    # One 429, then an answer: the retry waits out the hold and succeeds.
    clock = FakeTime()
    seen: list[httpx.Request] = []
    client = client_for(
        scripted(
            httpx.Response(429, headers={"retry-after": "30"}),
            httpx.Response(200, json=[breach_json()]),
            seen=seen,
        ),
        clock,
    )
    breaches = await client.breaches_for(ADDRESS, KEY)
    assert [b.name for b in breaches] == ["ExampleShop"]
    assert len(seen) == 2
    # retry-after + 1 second, which is longer than the 6.5 s gap.
    assert clock.sleeps == [31.0]

    # Two 429s in a row: rate limited after exactly one retry.
    clock = FakeTime()
    seen = []
    client = client_for(
        scripted(httpx.Response(429, headers={"retry-after": "2"}), seen=seen), clock
    )
    with pytest.raises(RateLimited) as caught:
        await client.breaches_for(ADDRESS, KEY)
    assert caught.value.code == "rate_limited"
    assert caught.value.retry_after_s == 2
    assert len(seen) == 2
    # The retry waited for the pacer's own gap (longer than retry-after + 1).
    assert clock.sleeps == [6.5]
    # The second 429 holds the shared slot for the next lookup too.
    assert client.pacer.wait_estimate() == pytest.approx(6.5)


@pytest.mark.asyncio
async def test_a_429_with_a_long_retry_after_is_rate_limited_at_once_and_holds_the_pacer():
    clock = FakeTime()
    seen: list[httpx.Request] = []
    client = client_for(
        scripted(httpx.Response(429, headers={"retry-after": "3600"}), seen=seen), clock
    )
    with pytest.raises(RateLimited) as caught:
        await client.breaches_for(ADDRESS, KEY)
    assert caught.value.retry_after_s == 3600
    assert len(seen) == 1
    assert clock.sleeps == []
    # Held for the most Crawler waits for (60 s) plus one.
    assert client.pacer.wait_estimate() == pytest.approx(61.0)


@pytest.mark.asyncio
async def test_a_429_without_a_usable_retry_after_is_treated_as_the_longest_wait():
    clock = FakeTime()
    client = client_for(
        scripted(
            httpx.Response(429, headers={"retry-after": "soon"}),
            httpx.Response(404),
        ),
        clock,
    )
    assert await client.breaches_for(ADDRESS, KEY) == []
    assert clock.sleeps == [61.0]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "answer",
    [
        httpx.Response(503, text="Service unavailable"),
        httpx.Response(500, text="Internal error"),
        httpx.Response(403, text="No user agent"),
        httpx.Response(418, text="I'm a teapot"),
        lambda request: httpx.ReadTimeout("timed out", request=request),
        lambda request: httpx.ConnectTimeout("timed out", request=request),
        lambda request: httpx.ConnectError(f"cannot reach {request.url}", request=request),
    ],
)
async def test_a_503_a_timeout_and_a_connection_error_are_unavailable(answer):
    with pytest.raises(Unavailable) as caught:
        await client_for(scripted(answer)).breaches_for(ADDRESS, KEY)
    assert caught.value.code == "unavailable"
    assert ADDRESS not in str(caught.value) and ENCODED not in str(caught.value)


async def _oversized_stream(chunk: bytes, times: int):
    for _ in range(times):
        yield chunk


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "answer",
    [
        httpx.Response(200, text="<html>not json</html>"),
        httpx.Response(200, json={"Name": "ExampleShop"}),
        httpx.Response(200, json="ExampleShop"),
        httpx.Response(200, content=b"[" * 200_000),
        httpx.Response(204),
        httpx.Response(301, headers={"location": "https://haveibeenpwned.com/elsewhere"}),
        # Over the cap, declared up front.
        httpx.Response(200, content=b"[" + b" " * hibp.MAX_BODY_BYTES + b"]"),
        # Over the cap, streamed without a length.
        httpx.Response(200, content=_oversized_stream(b" " * 65_536, 40)),
        # A declared length too long for int() to read (over 4,300 digits) is too large,
        # never an unmapped ValueError.
        httpx.Response(
            200, headers={"content-length": "9" * 5000}, content=_oversized_stream(b"[]", 1)
        ),
    ],
)
async def test_an_answer_that_is_not_a_json_list_or_is_over_the_size_cap_is_a_bad_answer(answer):
    with pytest.raises(BadAnswer) as caught:
        await client_for(scripted(answer)).breaches_for(ADDRESS, KEY)
    assert caught.value.code == "bad_answer"


@pytest.mark.asyncio
async def test_a_policy_refusal_is_refused_by_policy_and_sends_nothing(monkeypatch):
    seen: list[httpx.Request] = []

    def unsafe(url: str) -> netsec.SSRFCheckResult:
        return netsec.SSRFCheckResult(safe=False, reason=f"blocked {url}")

    monkeypatch.setattr(netsec, "check_ssrf", unsafe)
    with pytest.raises(PolicyRefused) as caught:
        await client_for(scripted(httpx.Response(200, json=[]), seen=seen)).breaches_for(
            ADDRESS, KEY
        )
    assert caught.value.code == "refused_by_policy"
    assert str(caught.value) == "The network policy refused the request to Have I Been Pwned."
    assert seen == []


# ---------------------------------------------------------------------------
# Parsing
# ---------------------------------------------------------------------------


def test_parse_breaches_keeps_name_title_domain_dates_counts_classes_and_flags_and_drops_description_and_logo():
    (breach,) = parse_breaches(
        [breach_json(IsSensitive=True, IsFabricated=True, IsSpamList=True, IsVerified=False)]
    )
    assert breach == Breach(
        name="ExampleShop",
        title="Example Shop",
        domain="example-shop.com",
        breach_date=date(2026, 8, 30),
        added_at=datetime(2026, 10, 12, 3, 11, tzinfo=timezone.utc),
        pwn_count=1200000,
        data_classes=("Email addresses", "Passwords", "Phone numbers"),
        verified=False,
        sensitive=True,
        fabricated=True,
        spam_list=True,
    )
    # Nothing else of HIBP's answer is kept.
    kept = repr(breach)
    assert "Click here" not in kept and "evil.example" not in kept and "PwnedLogos" not in kept
    assert not hasattr(breach, "description") and not hasattr(breach, "logo_path")


def test_parse_breaches_skips_entries_without_a_name_and_tolerates_missing_or_odd_fields():
    payload = [
        {"Title": "No name"},
        {"Name": 42},
        {"Name": "   "},
        "not an object",
        None,
        breach_json(
            "Bare",
            Title=None,
            Domain="",
            BreachDate="yesterday",
            AddedDate="soon",
            PwnCount=True,
            DataClasses="Passwords",
            IsVerified="yes",
        ),
        breach_json("Negative", PwnCount=-5, AddedDate="2020-01-02T03:04:05", BreachDate=None),
        breach_json("ExampleShop"),
        breach_json("ExampleShop", Title="A later duplicate"),
    ]
    breaches = parse_breaches(payload)
    assert [b.name for b in breaches] == ["Bare", "Negative", "ExampleShop"]
    bare, negative, shop = breaches
    assert bare.title == "Bare"  # the name stands in for a missing title
    assert (bare.domain, bare.breach_date, bare.added_at, bare.pwn_count) == (
        None,
        None,
        None,
        None,
    )
    assert bare.data_classes == ()
    assert bare.verified is False  # only a real true counts
    assert negative.pwn_count is None
    # A date without an offset is read as UTC.
    assert negative.added_at == datetime(2020, 1, 2, 3, 4, 5, tzinfo=timezone.utc)
    assert shop.title == "Example Shop"


@pytest.mark.parametrize(
    "added",
    [
        "0001-01-01T00:00:00+05:00",
        "9999-12-31T23:59:59-05:00",
        "0001-01-01T00:00:00+23:59",
    ],
)
def test_an_added_date_at_the_edge_of_the_calendar_drops_only_that_field_and_keeps_the_breach(
    added,
):
    # These parse, but moving them to UTC overflows the calendar (OverflowError). One odd
    # date must cost only that one field, never the whole answer.
    good, odd = parse_breaches([breach_json("ExampleShop"), breach_json("Edge", AddedDate=added)])
    assert good.added_at == datetime(2026, 10, 12, 3, 11, tzinfo=timezone.utc)
    assert (odd.name, odd.added_at, odd.breach_date) == ("Edge", None, date(2026, 8, 30))


@pytest.mark.asyncio
async def test_an_answer_with_an_out_of_range_added_date_is_still_an_answer_not_an_outage():
    # The checker's probe: a real client over a mock HIBP whose second breach carries an
    # AddedDate that overflows on the way to UTC. Before the fix the whole lookup failed
    # (recorded as "could not be reached" for every address in that breach, every week).
    payload = [
        breach_json("ExampleShop"),
        breach_json("Edge", AddedDate="9999-12-31T23:59:59-05:00"),
    ]
    client = client_for(scripted(httpx.Response(200, json=payload)))
    breaches = await client.breaches_for(ADDRESS, KEY)
    assert [(b.name, b.added_at is None) for b in breaches] == [
        ("ExampleShop", False),
        ("Edge", True),
    ]


def test_parse_breaches_cleans_control_and_invisible_characters_and_drops_a_domain_that_is_not_a_hostname():
    zero_width = "​"
    rtl_override = "‮"
    tag_a = "\U000e0041"
    payload = [
        breach_json(
            "Ex" + zero_width + "ample" + tag_a + "Shop",
            Title="Example\nShop\t" + rtl_override + "Login" + "\x00" + "  Portal",
            Domain="https://example-shop.com/login",
            DataClasses=[
                "Email\naddresses",
                "Pass" + zero_width + "words",
                "",
                7,
                "Email\naddresses",
            ],
        ),
        breach_json("Other", Domain="10.0.0.1"),
        breach_json("Third", Domain="localhost"),
        breach_json("Fourth", Domain=" Example-Shop.COM "),
        breach_json(
            "Long", Title="T" * 500, DataClasses=["C" * 500] + [f"class {i}" for i in range(100)]
        ),
    ]
    first, other, third, fourth, long = parse_breaches(payload)
    assert first.name == "ExampleShop"
    assert first.title == "Example Shop Login Portal"
    assert "\n" not in first.title and rtl_override not in first.title and "\x00" not in first.title
    assert first.domain is None
    assert first.data_classes == ("Email addresses", "Passwords")
    assert other.domain is None and third.domain is None
    assert fourth.domain == "example-shop.com"
    assert len(long.title) == 160
    assert len(long.data_classes) == hibp.MAX_DATA_CLASSES
    assert len(long.data_classes[0]) == hibp.DATA_CLASS_MAX_CHARS


def test_parse_breaches_keeps_at_most_the_cap_and_refuses_an_answer_that_is_not_a_list():
    payload = [breach_json(f"Breach{i}") for i in range(MAX_BREACHES + 25)]
    assert len(parse_breaches(payload)) == MAX_BREACHES
    for not_a_list in ({"Name": "x"}, "x", None, 3):
        with pytest.raises(BadAnswer):
            parse_breaches(not_a_list)


# ---------------------------------------------------------------------------
# Egress: the policy and the logs
# ---------------------------------------------------------------------------


def test_the_hibp_policy_allows_only_the_two_api_paths_over_https():
    policy = DEFAULT_POLICIES[HIBP_POLICY]
    assert policy.allowed_hosts == ["haveibeenpwned.com"]
    assert policy.allowed_paths == {
        "haveibeenpwned.com": ["/api/v3/breachedaccount/", "/api/v3/subscription/status"]
    }
    assert policy.https_only is True

    def allowed(url: str) -> bool:
        return check_network_policy(url, HIBP_POLICY, resolve=False).safe

    assert allowed(f"{API_BASE}/breachedaccount/{ENCODED}?truncateResponse=false")
    assert allowed(f"{API_BASE}/subscription/status")
    assert not allowed(f"http://haveibeenpwned.com/api/v3/breachedaccount/{ENCODED}")
    assert not allowed(f"https://haveibeenpwned.com:8443/api/v3/breachedaccount/{ENCODED}")
    assert not allowed("https://haveibeenpwned.com/api/v3/breaches")
    assert not allowed("https://haveibeenpwned.com/api/v3/pasteaccount/x")
    assert not allowed("https://haveibeenpwned.com/api/v3/breachedaccount/%2e%2e/breaches")
    assert not allowed(f"https://evil.example/api/v3/breachedaccount/{ENCODED}")
    assert not allowed(f"https://user:pw@haveibeenpwned.com/api/v3/breachedaccount/{ENCODED}")


def test_the_resolver_refuses_off_policy_urls_with_its_fixed_sentence_and_no_dns(ssrf_urls):
    resolve = policy_resolver(HIBP_POLICY, "Refused by the breach policy.")
    assert resolve(f"{API_BASE}/breachedaccount/{ENCODED}") == (PUBLIC_IP,)
    for url in (
        f"http://haveibeenpwned.com/api/v3/breachedaccount/{ENCODED}",
        f"https://haveibeenpwned.com/api/v3/breaches?a={ENCODED}",
        f"https://evil.example/api/v3/breachedaccount/{ENCODED}",
    ):
        with pytest.raises(EgressBlocked) as caught:
            resolve(url)
        assert str(caught.value) == "Refused by the breach policy."
    # Only the one allowed URL reached the DNS check, and only as its origin.
    assert ssrf_urls == ["https://haveibeenpwned.com/"]


@pytest.mark.asyncio
async def test_the_ssrf_check_sees_only_the_origin_so_no_log_line_carries_the_address(monkeypatch):
    # The real check_ssrf, fed a DNS answer that points at loopback: it refuses and logs.
    monkeypatch.setattr(netsec, "check_ssrf", REAL_CHECK_SSRF)

    def loopback(host, port, *args, **kwargs):
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", port or 443))]

    monkeypatch.setattr(netsec.socket, "getaddrinfo", loopback)
    seen: list[httpx.Request] = []

    with capture_logs() as logs:
        with pytest.raises(PolicyRefused) as caught:
            await client_for(scripted(httpx.Response(200, json=[]), seen=seen)).breaches_for(
                ADDRESS, KEY
            )

    assert seen == []
    blocked = [entry for entry in logs if entry["event"] == "ssrf_blocked"]
    assert blocked and blocked[0]["url"] == "https://haveibeenpwned.com/"
    for entry in logs:
        text = json.dumps(entry, default=str)
        assert "kash" not in text and ENCODED not in text and KEY not in text
    assert "kash" not in str(caught.value)


@pytest.mark.asyncio
async def test_no_exception_message_or_log_line_holds_the_address_or_the_key(monkeypatch):
    failures: list[Callable[[httpx.Request], Any]] = [
        lambda r: httpx.Response(401, json={"message": f"Bad key {KEY}"}),
        lambda r: httpx.Response(400, text=f"Bad address {ADDRESS}"),
        lambda r: httpx.Response(403, text=f"Forbidden for {ADDRESS}"),
        lambda r: httpx.Response(503, text=f"Down while looking up {ADDRESS}"),
        lambda r: httpx.Response(302, headers={"location": f"https://x.example/{ADDRESS}"}),
        lambda r: httpx.Response(200, text=f"not json {ADDRESS}"),
        lambda r: httpx.Response(429, headers={"retry-after": "100"}, text=ADDRESS),
        lambda r: httpx.ConnectError(f"cannot reach {r.url} with {KEY}", request=r),
        lambda r: httpx.ReadTimeout(f"timed out on {r.url}", request=r),
    ]
    with capture_logs() as logs:
        for failure in failures:
            with pytest.raises(HibpError) as caught:
                await client_for(scripted(failure)).breaches_for(ADDRESS, KEY)
            message = str(caught.value)
            for secret in (ADDRESS, ENCODED, "kash", KEY):
                assert secret not in message, (failure, message)
            # Nothing from the vendor or the transport is chained into the error.
            assert caught.value.__cause__ is None
        # A refused egress check too.
        monkeypatch.setattr(
            netsec,
            "check_ssrf",
            lambda url: netsec.SSRFCheckResult(safe=False, reason=f"no {url}"),
        )
        with pytest.raises(PolicyRefused) as refused:
            await client_for(scripted(httpx.Response(200, json=[]))).breaches_for(ADDRESS, KEY)
        assert "kash" not in str(refused.value)
    for entry in logs:
        text = json.dumps(entry, default=str)
        for secret in (ADDRESS, ENCODED, "kash", KEY):
            assert secret not in text, entry


# ---------------------------------------------------------------------------
# The pacer
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_the_pacer_spaces_requests_by_the_key_limit_and_a_hold_pushes_the_next_slot_back():
    clock = FakeTime()
    pacer = Pacer(rpm=10, clock=clock.clock, sleep=clock.sleep)
    assert pacer.gap_s == pytest.approx(6.5)  # 60 / 10 + the 0.5 s margin
    assert pacer.wait_estimate() == 0.0

    await pacer.wait()  # free: no sleep
    assert clock.sleeps == []
    assert pacer.wait_estimate() == pytest.approx(6.5)

    clock.now += 2.0
    await pacer.wait()
    assert clock.sleeps == [4.5]

    pacer.hold(30)
    assert pacer.wait_estimate() == pytest.approx(30.0)
    await pacer.wait()
    assert clock.sleeps == [4.5, 30.0]

    # A short hold never pulls the next slot forward.
    pacer.hold(1)
    assert pacer.wait_estimate() == pytest.approx(6.5)

    # A faster plan has a shorter gap.
    assert Pacer(rpm=50, clock=clock.clock, sleep=clock.sleep).gap_s == pytest.approx(1.7)


@pytest.mark.asyncio
async def test_the_pacer_gives_concurrent_waiters_one_slot_each():
    clock = FakeTime()
    pacer = Pacer(rpm=10, clock=clock.clock, sleep=clock.sleep)
    taken: list[float] = []

    async def take() -> None:
        await pacer.wait()
        taken.append(clock.now)

    await asyncio.gather(take(), take(), take())
    assert taken == [pytest.approx(1000.0), pytest.approx(1006.5), pytest.approx(1013.0)]


@pytest.mark.asyncio
async def test_every_lookup_waits_for_the_shared_pacer():
    clock = FakeTime()
    pacer = Pacer(clock=clock.clock, sleep=clock.sleep)
    transport = scripted(httpx.Response(404))
    first = HibpClient(transport=transport, pacer=pacer)
    second = HibpClient(transport=transport, pacer=pacer)

    await first.breaches_for(ADDRESS, KEY)
    await second.breaches_for("other@example.org", KEY)
    await first.breaches_for(ADDRESS, KEY)

    assert clock.sleeps == [6.5, 6.5]


class ScaledTime(FakeTime):
    """A pacer clock whose sleeps also take real time, scaled down: the pacer believes it
    waited *seconds*, the event loop sees seconds / scale go by. This puts a 429's hold on the
    loop's own clock (the one asyncio.wait_for measures) without a real minute-long wait."""

    def __init__(self, scale: float) -> None:
        super().__init__()
        self.scale = scale

    async def sleep(self, seconds: float) -> None:
        await super().sleep(seconds)
        await asyncio.sleep(seconds / self.scale)


@pytest.mark.asyncio
async def test_the_answer_deadline_leaves_out_a_429_hold_longer_than_itself_so_the_retry_still_answers():
    # The hold (retry-after 59 + 1 = 60 s on the pacer's clock) takes 1.5 s of loop time, past
    # the 1 s deadline; the requests themselves answer at once. Counting the hold against the
    # deadline turned this rate limit into a "timeout" before the retry was ever sent.
    clock = ScaledTime(scale=40)
    seen: list[httpx.Request] = []
    client = HibpClient(
        transport=scripted(
            httpx.Response(429, headers={"retry-after": "59"}),
            httpx.Response(200, json=[breach_json()]),
            seen=seen,
        ),
        pacer=Pacer(clock=clock.clock, sleep=clock.sleep),
    )
    breaches = await client.breaches_for(ADDRESS, KEY, deadline_s=1.0)
    assert [b.name for b in breaches] == ["ExampleShop"]
    assert len(seen) == 2
    assert clock.sleeps == [60.0]


@pytest.mark.asyncio
async def test_a_slow_answer_runs_out_the_deadline_and_both_requests_share_one_deadline():
    # One request that never answers in time: asyncio.TimeoutError (the sweeper's "timeout").
    async def never(request: httpx.Request) -> httpx.Response:
        await asyncio.sleep(30)
        return httpx.Response(404)

    with pytest.raises(asyncio.TimeoutError):
        await client_for(httpx.MockTransport(never)).breaches_for(ADDRESS, KEY, deadline_s=0.2)

    # Two answers of 0.4 s each against a 0.5 s deadline: the first fits, the retry gets only
    # what is left, so the deadline is the lookup's total, not each request's.
    answers = iter([httpx.Response(429, headers={"retry-after": "1"}), httpx.Response(404)])

    async def slow(request: httpx.Request) -> httpx.Response:
        await asyncio.sleep(0.4)
        return next(answers)

    with pytest.raises(asyncio.TimeoutError):
        await client_for(httpx.MockTransport(slow)).breaches_for(ADDRESS, KEY, deadline_s=0.5)

    # Without a deadline the client waits as long as HIBP takes (httpx's own timeout_s still
    # bounds each real network request).
    answers = iter([httpx.Response(404)])
    assert await client_for(httpx.MockTransport(slow)).breaches_for(ADDRESS, KEY) == []


# ---------------------------------------------------------------------------
# The key
# ---------------------------------------------------------------------------


def test_key_format_ok_accepts_32_hex_characters_only():
    assert key_format_ok(KEY)
    assert key_format_ok(KEY.upper())
    for bad in ("", KEY[:-1], KEY + "0", KEY + "\n", " " + KEY, "g" * 32, "0" * 31 + "-", None, 32):
        assert not key_format_ok(bad), bad  # type: ignore[arg-type]
    # The key registry's own pattern agrees with the client.
    spec = spec_for("hibp")
    assert spec is not None and spec.key_pattern.fullmatch(KEY)


@pytest.mark.asyncio
async def test_check_key_reports_the_plan_and_limit_on_success_and_plain_sentences_on_refusal_or_outage():
    seen: list[httpx.Request] = []
    status = {
        "SubscriptionName": "Pwned 1",
        "Description": "Up to 10 email addresses per minute and searches 25 breached accounts",
        "SubscribedUntil": "2027-10-01T00:00:00",
        "Rpm": 10,
        "DomainSearchMaxBreachedAccounts": 25,
    }
    ok = await check_key(KEY, transport=scripted(httpx.Response(200, json=status), seen=seen))
    assert ok == KeyTestResult(True, "Key works: Pwned 1 plan, up to 10 lookups a minute.")
    (request,) = seen
    assert request.url.path == "/api/v3/subscription/status"
    assert request.headers["hibp-api-key"] == KEY
    assert request.headers["user-agent"] == USER_AGENT

    refused = await check_key(KEY, transport=scripted(httpx.Response(401)))
    assert refused == KeyTestResult(
        False,
        "Have I Been Pwned refused that key. Copy it again from haveibeenpwned.com/API/Key.",
    )
    limited = await check_key(
        KEY, transport=scripted(httpx.Response(429, headers={"retry-after": "5"}))
    )
    assert limited == KeyTestResult(
        False, "Have I Been Pwned is rate limiting this key. Try again in a minute."
    )
    unreachable = (
        "Have I Been Pwned could not be reached, so the key was not checked or saved. "
        "Try again later."
    )
    for answer in (
        httpx.Response(503),
        httpx.Response(200, text="not json"),
        httpx.Response(200, json={"SubscriptionName": "Pwned 1"}),
        lambda r: httpx.ConnectError("down", request=r),
    ):
        assert await check_key(KEY, transport=scripted(answer)) == KeyTestResult(False, unreachable)

    # A plan without a name still reads well, and the vendor's name is cleaned and capped.
    unnamed = await check_key(KEY, transport=scripted(httpx.Response(200, json={"Rpm": 50})))
    assert unnamed == KeyTestResult(True, "Key works: up to 50 lookups a minute.")
    noisy = await check_key(
        KEY,
        transport=scripted(
            httpx.Response(200, json={"SubscriptionName": "Pwned\n​" + "x" * 80, "Rpm": 10})
        ),
    )
    assert noisy.ok and "\n" not in noisy.detail and "​" not in noisy.detail
    assert "x" * 41 not in noisy.detail


@pytest.mark.asyncio
async def test_check_key_refuses_a_malformed_key_without_sending_it_and_never_quotes_a_key():
    seen: list[httpx.Request] = []
    transport = scripted(
        httpx.Response(200, json={"SubscriptionName": "Pwned 1", "Rpm": 10}), seen=seen
    )
    for bad in ("", "short", KEY + "00", "z" * 32):
        result = await check_key(bad, transport=transport)
        assert result == KeyTestResult(
            False, "A Have I Been Pwned key is 32 characters, 0-9 and a-f."
        )
    assert seen == []
    # Surrounding spaces are trimmed (the key routes strip too).
    assert (await check_key(f"  {KEY} ", transport=transport)).ok
    assert len(seen) == 1 and seen[0].headers["hibp-api-key"] == KEY
    # The tester's own sentences never hold the key.
    for answer in (httpx.Response(401), httpx.Response(429), httpx.Response(500)):
        result = await check_key(KEY, transport=scripted(answer))
        assert not result.ok and KEY not in result.detail


@pytest.mark.asyncio
async def test_the_key_registry_reaches_this_tester_lazily(monkeypatch):
    calls: list[str] = []

    async def fake_check_key(key: str) -> KeyTestResult:
        calls.append(key)
        return KeyTestResult(True, "Key works: up to 10 lookups a minute.")

    monkeypatch.setattr(hibp, "check_key", fake_check_key)
    spec = spec_for("hibp")
    assert spec is not None
    assert await spec.tester(KEY) == KeyTestResult(True, "Key works: up to 10 lookups a minute.")
    assert calls == [KEY]
