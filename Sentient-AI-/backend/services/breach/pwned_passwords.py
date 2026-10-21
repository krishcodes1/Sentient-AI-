"""The Pwned Passwords range lookup behind the Security page's password check:
the backend half of a k-anonymity check whose other half runs in the browser.

Why it exists: the browser works out the password's SHA-1 itself and sends
only the first 5 hex characters; this module asks Pwned Passwords for every
hash suffix sharing that prefix (``GET https://api.pwnedpasswords.com/range/
<prefix>``) and hands the list back unchanged, and the browser makes the match.
The password, and the rest of its hash, never reach the server. The SPA's CSP
(``connect-src 'self'``) is why the request goes through this proxy at all.

The request asks for padding (``Add-Padding: true``) so the answer's size says
nothing about the prefix; padding entries (count 0) are dropped before the
answer goes back. Nothing about a check is kept: no cache, no audit row, and
no log line with the prefix or the number of entries (each prefix has a
fairly distinctive count, so a logged count next to a user id would narrow
down that user's password hash; review SEC-F13). The request goes through the
SSRF-guarded client under the ``pwned_passwords`` network policy, redirects are
not followed, and the body is capped. ``RangeRateLimiter`` is the proxy route's
per-user limit (so the route is not an open relay); ``range_answer`` is the
route's response body.
"""

from __future__ import annotations

import re
import time
from collections import deque
from typing import Any, Callable, Optional

import httpx
import structlog

from core.network_security import PWNED_PASSWORDS_POLICY
from services.breach.egress import policy_resolver
from services.tools.net import EgressBlocked, build_guarded_client

logger = structlog.get_logger(__name__)

RANGE_URL = "https://api.pwnedpasswords.com/range/"
USER_AGENT = "Crawler-AI-password-check"
TIMEOUT_S = 10.0
MAX_BODY_BYTES = 262_144
# Far above any prefix's real entry count (padded answers hold 800 to 1,000
# lines). An answer with more is refused rather than cut: a cut list could
# miss the password's suffix and read as "not found".
MAX_ENTRIES = 2000
_LINE_RE = re.compile(r"^([0-9A-F]{35}):([0-9]{1,10})$")
_PREFIX_RE = re.compile(r"[0-9A-Fa-f]{5}")

# The answer's attribution (CC BY 4.0), shown under the password check.
SOURCE = "Pwned Passwords by Have I Been Pwned (haveibeenpwned.com)"
# The one sentence every failure carries; the route answers it with a 503.
UNAVAILABLE_MESSAGE = "Not checked: the Pwned Passwords service could not be reached."
POLICY_REFUSAL = "The network policy refused the request to Pwned Passwords."

# The proxy route's per-user limit: 20 requests per 60 s, sliding window.
RATE_LIMIT = 20
RATE_WINDOW_S = 60.0


class PwnedPasswordsUnavailable(Exception):
    """The range could not be fetched; the message is a fixed sentence (never the prefix).
    ``reason`` is a short fixed code for the server log."""

    def __init__(self, reason: str) -> None:
        super().__init__(UNAVAILABLE_MESSAGE)
        self.reason = reason


def valid_prefix(value: object) -> Optional[str]:
    """*value* uppercased when it is exactly 5 hex characters, else None."""
    if not isinstance(value, str) or not _PREFIX_RE.fullmatch(value):
        return None
    return value.upper()


def parse_range(text: str, *, limit: int = MAX_ENTRIES) -> list[tuple[str, int]]:
    """(suffix, count) per line; CRLF tolerated; malformed lines and padding entries
    (count 0, from Add-Padding) dropped; at most *limit* (MAX_ENTRIES)."""
    entries: list[tuple[str, int]] = []
    for raw in text.split("\n"):
        match = _LINE_RE.fullmatch(raw.rstrip("\r"))
        if match is None:
            continue
        count = int(match.group(2))
        if count <= 0:
            continue
        entries.append((match.group(1), count))
        if len(entries) >= limit:
            break
    return entries


async def _read_capped(response: httpx.Response, cap: int) -> bytes:
    declared = response.headers.get("content-length", "").strip()
    # The length check first: int() refuses a number past 4,300 digits (ValueError), which
    # would otherwise escape the "not checked" mapping as a server error.
    if declared.isascii() and declared.isdigit() and (len(declared) > 12 or int(declared) > cap):
        raise PwnedPasswordsUnavailable("too_large")
    chunks: list[bytes] = []
    total = 0
    async for chunk in response.aiter_bytes():
        total += len(chunk)
        if total > cap:
            raise PwnedPasswordsUnavailable("too_large")
        chunks.append(chunk)
    return b"".join(chunks)


async def fetch_range(
    prefix: str, *, transport: Optional[httpx.AsyncBaseTransport] = None
) -> list[tuple[str, int]]:
    """GET RANGE_URL + prefix with headers Add-Padding: true and user-agent, through
    build_guarded_client(resolver=policy_resolver(PWNED_PASSWORDS_POLICY, ...),
    follow_redirects=False). Not cached: nothing about a check is kept. Raises
    PwnedPasswordsUnavailable on refusal, non-200, timeout, an oversized body, or an answer
    with more entries than MAX_ENTRIES. ValueError (never quoting it) for a prefix that is not
    5 hex characters: the route validates first, so nothing else is ever sent."""
    checked = valid_prefix(prefix)
    if checked is None:
        raise ValueError("A range prefix is exactly 5 hex characters.")
    try:
        client = build_guarded_client(
            timeout_s=TIMEOUT_S,
            headers={"Add-Padding": "true", "user-agent": USER_AGENT},
            resolver=policy_resolver(PWNED_PASSWORDS_POLICY, POLICY_REFUSAL),
            transport=transport,
            follow_redirects=False,
        )
        async with client:
            async with client.stream("GET", RANGE_URL + checked) as response:
                if response.status_code != 200:
                    raise PwnedPasswordsUnavailable("http_status")
                body = await _read_capped(response, MAX_BODY_BYTES)
    except EgressBlocked:
        raise PwnedPasswordsUnavailable("refused_by_policy") from None
    except httpx.TimeoutException:
        raise PwnedPasswordsUnavailable("timeout") from None
    except httpx.HTTPError:
        raise PwnedPasswordsUnavailable("network") from None
    try:
        text = body.decode("ascii")
    except UnicodeDecodeError:
        raise PwnedPasswordsUnavailable("bad_answer") from None
    entries = parse_range(text, limit=MAX_ENTRIES + 1)
    if len(entries) > MAX_ENTRIES:
        raise PwnedPasswordsUnavailable("too_many_entries")
    return entries


def range_answer(prefix: str, entries: list[tuple[str, int]]) -> dict[str, Any]:
    """The proxy route's 200 body: the prefix as checked, every (suffix, count) as Pwned
    Passwords listed it (padding already dropped), and the attribution."""
    return {
        "prefix": prefix,
        "suffixes": [[suffix, count] for suffix, count in entries],
        "source": SOURCE,
    }


class RangeRateLimiter:
    """The proxy route's per-user sliding window (the setup.py ``_check_rate_limit`` shape):
    at most *limit* requests per *window_s* seconds for each user. In memory, like the key
    routes' limit: one process per install."""

    def __init__(
        self,
        limit: int = RATE_LIMIT,
        window_s: float = RATE_WINDOW_S,
        *,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._limit = limit
        self._window_s = window_s
        self._clock = clock
        self._buckets: dict[str, deque[float]] = {}

    def retry_after(self, user_id: object) -> Optional[int]:
        """None (and the request is counted) when *user_id* may make one more request now,
        else the whole seconds until it may (for the 429's Retry-After)."""
        now = self._clock()
        key = str(user_id)
        bucket = self._buckets.setdefault(key, deque())
        while bucket and now - bucket[0] >= self._window_s:
            bucket.popleft()
        if len(bucket) >= self._limit:
            return int(self._window_s - (now - bucket[0])) + 1
        bucket.append(now)
        return None

    def reset(self) -> None:
        """Forget every bucket (tests)."""
        self._buckets.clear()
