"""Tests for services/breach/pwned_passwords.py, the backend half of the
Security page's password check: they prove that only a 5-character hex prefix
is ever sent, uppercased, to the range path with Add-Padding and Crawler's user
agent; that the answer's CRLF lines come back unchanged as (suffix, count) with
padding and malformed lines dropped; that a redirect, a non-200 answer, a
timeout, a connection error, a policy refusal, an oversized body or an answer
longer than the entry cap is "not checked" (never a cut list that could read as
"not found"); that the Pwned Passwords network policy allows only the range
path over HTTPS; that no message or log line holds the prefix or the entry
count; and that the proxy's per-user limit allows 20 requests a minute.

Why it exists: the password check is a k-anonymity protocol, so the server
must never see or keep more than the prefix, and a failure must never look
like a clean result. No real network or DNS: check_ssrf is replaced and
httpx.MockTransport answers behind the real request hook.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterator
from typing import Any, Optional

import httpx
import pytest
from structlog.testing import capture_logs

import core.network_security as netsec
from core.network_security import DEFAULT_POLICIES, PWNED_PASSWORDS_POLICY, check_network_policy
from services.breach import pwned_passwords
from services.breach.pwned_passwords import (
    MAX_ENTRIES,
    RANGE_URL,
    SOURCE,
    UNAVAILABLE_MESSAGE,
    USER_AGENT,
    PwnedPasswordsUnavailable,
    RangeRateLimiter,
    fetch_range,
    parse_range,
    range_answer,
    valid_prefix,
)

PUBLIC_IP = "203.0.113.20"  # TEST-NET-3; check_ssrf is stubbed
# SHA-1 of "password", the protocol's documented example.
PASSWORD_HASH = hashlib.sha1(b"password").hexdigest().upper()
PREFIX, SUFFIX = PASSWORD_HASH[:5], PASSWORD_HASH[5:]


@pytest.fixture(autouse=True)
def ssrf_urls(monkeypatch) -> Iterator[list[str]]:
    urls: list[str] = []

    def fake_check_ssrf(url: str) -> netsec.SSRFCheckResult:
        urls.append(url)
        return netsec.SSRFCheckResult(safe=True, resolved_ip=PUBLIC_IP, resolved_ips=(PUBLIC_IP,))

    monkeypatch.setattr(netsec, "check_ssrf", fake_check_ssrf)
    yield urls


def range_body(*lines: str, crlf: bool = True) -> str:
    return ("\r\n" if crlf else "\n").join(lines)


def service(answer: Any, *, seen: Optional[list[httpx.Request]] = None) -> httpx.MockTransport:
    def handler(request: httpx.Request) -> httpx.Response:
        if seen is not None:
            seen.append(request)
        result = answer(request) if callable(answer) else answer
        if isinstance(result, BaseException):
            raise result
        return result

    return httpx.MockTransport(handler)


def padded_answer() -> str:
    return range_body(
        "0018A45C4D1DEF81644B54AB7F969B88D65:1",
        f"{SUFFIX}:52256",
        "00D4F6E8FA6EECAD2A3AA415EEC418D38EC:0",  # padding
        "011053FD0102E94D6AE2F8B83D76FAF94F6:3",
    )


@pytest.mark.asyncio
async def test_fetch_range_asks_the_range_path_with_add_padding_and_the_uppercase_prefix(ssrf_urls):
    seen: list[httpx.Request] = []
    entries = await fetch_range(
        PREFIX.lower(), transport=service(httpx.Response(200, text=padded_answer()), seen=seen)
    )

    (request,) = seen
    assert request.method == "GET"
    assert (
        str(request.url) == RANGE_URL + PREFIX == f"https://api.pwnedpasswords.com/range/{PREFIX}"
    )
    assert request.headers["Add-Padding"] == "true"
    assert request.headers["user-agent"] == USER_AGENT == "Crawler-AI-password-check"
    # Nothing but the prefix is sent: no body, no query, no auth.
    assert request.content == b""
    assert request.url.query == b""
    assert "authorization" not in request.headers and "hibp-api-key" not in request.headers
    assert ssrf_urls == ["https://api.pwnedpasswords.com/"]
    # The entries pass through unchanged, padding dropped.
    assert entries == [
        ("0018A45C4D1DEF81644B54AB7F969B88D65", 1),
        (SUFFIX, 52256),
        ("011053FD0102E94D6AE2F8B83D76FAF94F6", 3),
    ]


@pytest.mark.asyncio
async def test_fetch_range_refuses_a_bad_prefix_without_sending_anything():
    seen: list[httpx.Request] = []
    for bad in ("", "5BAA", "5BAA61", "5BAG6", " 5BAA6", "5BAA6\n", PASSWORD_HASH, None, 12345):
        with pytest.raises(ValueError) as caught:
            await fetch_range(bad, transport=service(httpx.Response(200, text=""), seen=seen))  # type: ignore[arg-type]
        if isinstance(bad, str) and bad.strip():
            assert bad.strip() not in str(caught.value)
    assert seen == []


def test_parse_range_reads_crlf_lines_and_drops_padding_and_malformed_entries():
    text = range_body(
        f"{SUFFIX}:52256",
        "0018A45C4D1DEF81644B54AB7F969B88D65:0",  # padding
        "0018a45c4d1def81644b54ab7f969b88d65:4",  # lowercase: not the service's format
        "0018A45C4D1DEF81644B54AB7F969B88D6:4",  # 34 characters
        "0018A45C4D1DEF81644B54AB7F969B88D655:4",  # 36 characters
        "0018A45C4D1DEF81644B54AB7F969B88D65:",  # no count
        "0018A45C4D1DEF81644B54AB7F969B88D65:12345678901",  # 11 digits
        "0018A45C4D1DEF81644B54AB7F969B88D65 : 7",
        "011053FD0102E94D6AE2F8B83D76FAF94F6:3",
        "",
        "garbage",
    )
    assert parse_range(text) == [(SUFFIX, 52256), ("011053FD0102E94D6AE2F8B83D76FAF94F6", 3)]
    # Plain LF and a trailing line break work too.
    assert parse_range(range_body(f"{SUFFIX}:2", crlf=False) + "\n") == [(SUFFIX, 2)]
    assert parse_range("") == []


def test_parse_range_keeps_at_most_the_entry_cap():
    lines = [f"{i:035X}:1" for i in range(MAX_ENTRIES + 10)]
    assert len(parse_range("\r\n".join(lines))) == MAX_ENTRIES
    assert len(parse_range("\r\n".join(lines), limit=5)) == 5


async def _stream(chunk: bytes, times: int):
    for _ in range(times):
        yield chunk


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("answer", "reason"),
    [
        (
            httpx.Response(302, headers={"location": "https://evil.example/range/5BAA6"}),
            "http_status",
        ),
        (httpx.Response(404, text="Not found"), "http_status"),
        (httpx.Response(429, headers={"retry-after": "2"}), "http_status"),
        (httpx.Response(503, text="Service unavailable"), "http_status"),
        (httpx.Response(200, content=b"A" * (pwned_passwords.MAX_BODY_BYTES + 1)), "too_large"),
        (httpx.Response(200, content=_stream(b"A" * 65_536, 5)), "too_large"),
        # A declared length int() cannot read (over 4,300 digits): too large, never a 500.
        (
            httpx.Response(200, headers={"content-length": "9" * 5000}, content=_stream(b"", 1)),
            "too_large",
        ),
        (httpx.Response(200, content="é".encode("utf-8")), "bad_answer"),
        (lambda r: httpx.ReadTimeout("timed out", request=r), "timeout"),
        (lambda r: httpx.ConnectError(f"cannot reach {r.url}", request=r), "network"),
    ],
)
async def test_fetch_range_refuses_redirects_non_200_answers_and_oversized_bodies_as_unavailable(
    answer, reason
):
    seen: list[httpx.Request] = []
    with pytest.raises(PwnedPasswordsUnavailable) as caught:
        await fetch_range(PREFIX, transport=service(answer, seen=seen))
    assert caught.value.reason == reason
    assert str(caught.value) == UNAVAILABLE_MESSAGE
    assert UNAVAILABLE_MESSAGE == "Not checked: the Pwned Passwords service could not be reached."
    assert PREFIX not in str(caught.value)
    assert caught.value.__cause__ is None
    # Redirects are never followed: one request, to the range host only.
    assert len(seen) == 1 and seen[0].url.host == "api.pwnedpasswords.com"


@pytest.mark.asyncio
async def test_an_answer_longer_than_the_entry_cap_is_not_checked_rather_than_cut():
    lines = [f"{i:035X}:1" for i in range(MAX_ENTRIES + 1)]
    with pytest.raises(PwnedPasswordsUnavailable) as caught:
        await fetch_range(PREFIX, transport=service(httpx.Response(200, text="\r\n".join(lines))))
    assert caught.value.reason == "too_many_entries"
    # Exactly the cap is fine.
    entries = await fetch_range(
        PREFIX, transport=service(httpx.Response(200, text="\r\n".join(lines[:MAX_ENTRIES])))
    )
    assert len(entries) == MAX_ENTRIES


@pytest.mark.asyncio
async def test_a_policy_refusal_is_unavailable_and_sends_nothing(monkeypatch):
    seen: list[httpx.Request] = []
    monkeypatch.setattr(
        netsec, "check_ssrf", lambda url: netsec.SSRFCheckResult(safe=False, reason=f"no {url}")
    )
    with pytest.raises(PwnedPasswordsUnavailable) as caught:
        await fetch_range(PREFIX, transport=service(httpx.Response(200, text=""), seen=seen))
    assert caught.value.reason == "refused_by_policy"
    assert seen == []


def test_the_pwned_passwords_policy_allows_only_the_range_path_over_https():
    policy = DEFAULT_POLICIES[PWNED_PASSWORDS_POLICY]
    assert policy.allowed_hosts == ["api.pwnedpasswords.com"]
    assert policy.allowed_paths == {"api.pwnedpasswords.com": ["/range/"]}
    assert policy.https_only is True

    def allowed(url: str) -> bool:
        return check_network_policy(url, PWNED_PASSWORDS_POLICY, resolve=False).safe

    assert allowed(f"https://api.pwnedpasswords.com/range/{PREFIX}")
    assert not allowed(f"http://api.pwnedpasswords.com/range/{PREFIX}")
    assert not allowed(f"https://api.pwnedpasswords.com:8443/range/{PREFIX}")
    assert not allowed("https://api.pwnedpasswords.com/pwnedpassword/x")
    assert not allowed(f"https://pwnedpasswords.com/range/{PREFIX}")
    assert not allowed(f"https://haveibeenpwned.com/range/{PREFIX}")
    assert not allowed("https://api.pwnedpasswords.com/range/%2e%2e/admin")


def test_valid_prefix_accepts_exactly_five_hex_characters():
    assert valid_prefix("5baa6") == "5BAA6"
    assert valid_prefix("5BAA6") == "5BAA6"
    assert valid_prefix("00000") == "00000"
    for bad in (
        "",
        "5BAA",
        "5BAA61",
        "5BAG6",
        " 5BAA6",
        "5BAA6 ",
        "5BAA6\n",
        "5baé6",
        None,
        5,
        ["5BAA6"],
    ):
        assert valid_prefix(bad) is None, bad


@pytest.mark.asyncio
async def test_range_answer_passes_the_entries_through_with_the_attribution():
    entries = await fetch_range(
        PREFIX, transport=service(httpx.Response(200, text=padded_answer()))
    )
    answer = range_answer(PREFIX, entries)
    assert answer == {
        "prefix": PREFIX,
        "suffixes": [
            ["0018A45C4D1DEF81644B54AB7F969B88D65", 1],
            [SUFFIX, 52256],
            ["011053FD0102E94D6AE2F8B83D76FAF94F6", 3],
        ],
        "source": SOURCE,
    }
    assert SOURCE == "Pwned Passwords by Have I Been Pwned (haveibeenpwned.com)"
    # JSON-ready, and the browser can match the full hash against it.
    decoded = json.loads(json.dumps(answer))
    assert [SUFFIX, 52256] in decoded["suffixes"]


@pytest.mark.asyncio
async def test_no_log_line_from_a_range_fetch_holds_the_prefix_or_the_entry_count(monkeypatch):
    with capture_logs() as logs:
        entries = await fetch_range(
            PREFIX, transport=service(httpx.Response(200, text=padded_answer()))
        )
        with pytest.raises(PwnedPasswordsUnavailable):
            await fetch_range(PREFIX, transport=service(httpx.Response(503)))
        monkeypatch.setattr(
            netsec, "check_ssrf", lambda url: netsec.SSRFCheckResult(safe=False, reason=url)
        )
        with pytest.raises(PwnedPasswordsUnavailable):
            await fetch_range(PREFIX, transport=service(httpx.Response(200, text="")))
    for entry in logs:
        text = json.dumps(entry, default=str)
        assert PREFIX not in text and SUFFIX not in text
        assert str(len(entries)) not in [str(value) for value in entry.values()]


def test_the_range_rate_limiter_allows_twenty_a_minute_per_user_and_answers_the_wait():
    now = [100.0]
    limiter = RangeRateLimiter(clock=lambda: now[0])
    for _ in range(20):
        assert limiter.retry_after("user-a") is None
    wait = limiter.retry_after("user-a")
    assert wait == 61
    # Another user has their own window.
    assert limiter.retry_after("user-b") is None
    # The window slides: 30 s later the wait has shrunk; 60 s after the burst it is all
    # free again, and a refused request was never counted.
    now[0] += 30.0
    assert limiter.retry_after("user-a") == 31
    now[0] += 30.0
    for _ in range(20):
        assert limiter.retry_after("user-a") is None
    assert limiter.retry_after("user-a") == 61
    limiter.reset()
    assert limiter.retry_after("user-a") is None
