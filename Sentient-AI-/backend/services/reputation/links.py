"""Looks links up in Google's list of dangerous sites (Safe Browsing v4 Lookup or Web Risk
uris.search) with the owner's own key, and combines the answer with the local checks.

Why it exists: the owner's key is the only thing that may send a link out (decisions 2), so one
service holds the key handling, what leaves the machine (link_checks.lookup_url), the cache that
Google's terms bound, the owner's lookup limits, the fail-open rule (never "safe", always
"not checked") and the browser guard's reputation step. Every request goes through the guarded
client under the "link_reputation" network policy.

Connects to: InstallationService (key, switch, limits; any ``ReputationSource``),
core.network_security (LINK_REPUTATION_POLICY), services.tools.net (guarded client),
services.tools.browser.guard (``EgressHooks.reputation`` -> ``navigation_check``, scaffold A1),
S1/S2/S3 through services.security.link_checks.LinkChecker, the shared key routes through
``test_google_key`` (services/reputation/keys.py).

What is kept, and where: verdicts in process memory only (``(service, lookup_url)`` -> expiry,
never written to disk, logs or audit rows); request counters per service and key fingerprint
(sha256 of the key, first 16 hex, in memory only, so a replaced key starts fresh counters).
Logs carry event names, the service, an HTTP status and exception type names; never a link, a
host, a query, a key or an exception message (an httpx message can quote the URL).
"""

from __future__ import annotations

import asyncio
import dataclasses
import hashlib
import json
import math
import re
import time
from collections import OrderedDict, deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from typing import (
    Any,
    Awaitable,
    Callable,
    Coroutine,
    Mapping,
    Optional,
    Protocol,
    Sequence,
    Union,
)
from urllib.parse import urlsplit, urlunsplit

import httpx
import structlog

from core.network_security import LINK_REPUTATION_POLICY, check_network_policy
from services.capabilities.link_reputation import LINK_REPUTATION_SETTINGS_DEFAULTS
from services.reputation.keys import KeyTestResult
from services.security import link_checks
from services.security.link_checks import (
    NOT_CHECKED_STATUSES,
    LinkReport,
    Purpose,
    ServiceName,
    ServiceStatus,
    advisory,
    level_for,
    local_report,
    lookup_url,
    text_for,
)
from services.tools.browser.handoff import CAPTCHA_HOSTS, MFA_HOSTS
from services.tools.net import EgressBlocked, build_guarded_client

logger = structlog.get_logger(__name__)

SAFE_BROWSING_URL = "https://safebrowsing.googleapis.com/v4/threatMatches:find"
WEB_RISK_URL = "https://webrisk.googleapis.com/v1/uris:search"
# Google's own test pages, which the key test looks up.
SAFE_BROWSING_TEST_URL = "http://malware.testing.google.test/testing/malware/"
WEB_RISK_TEST_URL = "http://testsafebrowsing.appspot.com/s/malware.html"
SERVICE_LABELS: Mapping[str, str] = link_checks.SERVICE_LABELS
SB_THREAT_TYPES = ("MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE",
                   "POTENTIALLY_HARMFUL_APPLICATION")
WR_THREAT_TYPES = ("MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE")
CLIENT_ID, CLIENT_VERSION = "crawler-ai", "1.0"

POSITIVE_TTL_S = 1800.0          # ceiling; Google's cacheDuration / expireTime may shorten it
NEGATIVE_TTL_S = 300.0
CACHE_MAX_ENTRIES = 4096
HTTP_TIMEOUT_S = 5.0             # one Google request
CHECK_TIMEOUT_S = 8.0            # one check() call, network part
BROWSER_TIMEOUT_S = 2.5          # the guard hook
MAX_URLS_PER_CALL = 100
SB_BATCH = 100                   # threatEntries per Safe Browsing request (API allows 500)
WR_MAX_PER_CALL = 10             # Web Risk requests per check() call (one link each)
WR_CONCURRENCY = 3
MAX_RESPONSE_BYTES = 1_000_000
COOL_DOWN_5XX_S = 30.0
COOL_DOWN_429_S = (60.0, 900.0)  # Retry-After clamped to this; doubling when absent
KEY_REJECTED_COOL_DOWN_S = 600.0
OWNER_ALERT_EVERY_S = 86400.0
# Sign-in, MFA and CAPTCHA hosts the browser must reach for a person's hand-off: never looked
# up. handoff.MFA_HOSTS plus the CAPTCHA_HOSTS entries that are plain hosts; a path-qualified
# entry ("google.com/recaptcha") is left out, so google.com (and sites.google.com,
# docs.google.com, which can host phishing) is still looked up.
EXEMPT_HOSTS: tuple[str, ...] = tuple(
    dict.fromkeys((*MFA_HOSTS, *(host for host in CAPTCHA_HOSTS if "/" not in host)))
)
# EXEMPT_HOSTS entries whose subdomains are customer tenants anyone can sign up for and dress up
# (dev-123.okta.com serves the tenant's own customisable sign-in page): only the bare host is
# exempt, and every tenant is looked up like any other site, for the same reason google.com is
# not exempt (sites.google.com can host phishing). A real company's sign-in keeps working: a
# lookup error or timeout fails open, and a genuine tenant is not on Google's list. The other
# entries' subdomains serve only the vendor's own pages (Duo's prompt, the CAPTCHA widgets).
TENANT_IDP_DOMAINS: frozenset[str] = frozenset({"okta.com", "oktapreview.com"})
# Background purposes may use at most BACKGROUND_SHARE of each limiter window (per minute and
# per day), so the mail sweep can never use up the lookups a person is waiting on (review
# FEA-SF1, scaffold A36). Interactive purposes (browser, chat, outbound, scam_check) may use all.
BACKGROUND_PURPOSES: frozenset[str] = frozenset({"mail"})
BACKGROUND_SHARE = 0.5

# Which Google service is used when both keys exist: Web Risk first (its terms allow commercial
# use; Safe Browsing v4 is for non-commercial use).
_PREFERENCE: tuple[ServiceName, ...] = ("web_risk", "safe_browsing")

MINUTE_S = 60.0
DAY_S = 86400.0
# The owner's day counters keep one entry per this many seconds at most (_DayCount).
COUNT_RESOLUTION_S = 10.0
_ACCEPT_HEADERS = {"Accept": "application/json", "User-Agent": "Crawler-AI"}

# Test seam for the key routes (WAVE 0's security_keys routes call test_google_key without a
# transport); tests set it, production leaves it None.
DEFAULT_TRANSPORT: Optional[httpx.AsyncBaseTransport] = None


class ReputationSource(Protocol):
    """What LinkReputation reads from InstallationService."""
    async def service_key(self, name: str) -> Optional[str]: ...
    async def capability_statuses(self) -> Mapping[str, Any]: ...
    async def capability_settings(self, key: str) -> dict[str, Any]: ...


OwnerAlert = Callable[[str, Mapping[str, Any]], Awaitable[None]]  # (message, audit facts)


# ── the two Google clients ─────────────────────────────────────────────

# What went wrong with one Google request: the transport failed ("network"), it ran out of
# time ("timeout"), Google answered 5xx ("server"), 429 ("throttled"), refused the key
# ("key_rejected"), or answered something that is not a verdict ("bad_answer").
Problem = str
_DURATION_RE = re.compile(r"^(\d{1,9})(?:\.(\d{1,9}))?s$")
_FRACTION_RE = re.compile(r"\.(\d+)")


@dataclass(frozen=True)
class GoogleAnswer:
    """What one Google request said. ``listed`` maps each URL Google matched to its threat
    types and how long Google allows the match to be cached (seconds, None when unstated).
    ``problem`` is "" when Google gave a verdict; ``http_status`` is set whenever Google
    answered at all; ``error_type`` names the exception of a failed transport."""
    listed: Mapping[str, tuple[tuple[str, ...], Optional[float]]] = field(default_factory=dict)
    problem: Problem = ""
    http_status: Optional[int] = None
    retry_after_s: Optional[float] = None
    error_type: str = ""

    @property
    def ok(self) -> bool:
        return not self.problem


def _guarded_client(transport: Optional[httpx.AsyncBaseTransport]) -> httpx.AsyncClient:
    """One guarded client: the request hook checks every hop against LINK_REPUTATION_POLICY
    (through _policy_addresses) and pins the addresses it checked; redirects are never
    followed (Google's endpoints do not redirect, and a redirect could carry the key away)."""
    return build_guarded_client(
        timeout_s=HTTP_TIMEOUT_S,
        headers=dict(_ACCEPT_HEADERS),
        resolver=_policy_addresses,
        transport=transport,
        follow_redirects=False,
    )


def _policy_addresses(url: str) -> tuple[str, ...]:
    """The guarded client's resolver: the URL with its query and fragment removed is checked
    against LINK_REPUTATION_POLICY, then its addresses are pinned. The query never reaches
    check_network_policy, because check_ssrf logs the URL it is given when a host resolves to a
    private address (core/network_security.py:178-184), and Web Risk carries the checked link in
    its query."""
    parts = urlsplit(url)
    bare = urlunsplit((parts.scheme, parts.netloc, parts.path, "", ""))
    result = check_network_policy(bare, LINK_REPUTATION_POLICY)
    if not result.safe:
        # The policy's own reason can name the host; only a fixed sentence goes out.
        raise EgressBlocked("The link lookup address is not allowed by the network policy.")
    return result.resolved_ips


def _retry_after(value: Optional[str], now: datetime) -> Optional[float]:
    """Seconds from a Retry-After header (a number or an HTTP date), or None."""
    if not value:
        return None
    text = value.strip()
    if text.isdigit():
        return float(text)
    try:
        moment = parsedate_to_datetime(text)
    except (TypeError, ValueError, IndexError):
        return None
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=timezone.utc)
    return max((moment - now).total_seconds(), 0.0)


def _duration(value: Any) -> Optional[float]:
    """Seconds in a protobuf Duration string ("300s", "1.5s"), or None."""
    if not isinstance(value, str):
        return None
    match = _DURATION_RE.match(value.strip())
    if not match:
        return None
    return float(f"{match.group(1)}.{match.group(2) or '0'}")


def _timestamp(value: Any) -> Optional[datetime]:
    """An RFC 3339 timestamp ("2026-10-14T12:30:00Z", nanoseconds allowed), or None."""
    if not isinstance(value, str) or not value.strip():
        return None
    text = value.strip().replace("Z", "+00:00").replace("z", "+00:00")
    text = _FRACTION_RE.sub(lambda m: "." + m.group(1)[:6].ljust(6, "0"), text, count=1)
    try:
        moment = datetime.fromisoformat(text)
    except ValueError:
        return None
    return moment if moment.tzinfo else moment.replace(tzinfo=timezone.utc)


async def _exchange(
    client: httpx.AsyncClient,
    method: str,
    url: str,
    *,
    key: str,
    now: datetime,
    params: Optional[httpx.QueryParams] = None,
    body: Optional[dict[str, Any]] = None,
) -> Union[GoogleAnswer, tuple[int, bytes]]:
    """Send one request with the key in the X-Goog-Api-Key header (never in the URL) and read
    at most MAX_RESPONSE_BYTES. A failed exchange comes back as a GoogleAnswer with its
    problem; a 200 comes back as (200, body) for the caller to parse."""
    headers = {"X-Goog-Api-Key": key}
    if body is not None:
        headers["Content-Type"] = "application/json"
    try:
        async with client.stream(
            method,
            url,
            params=params,
            content=json.dumps(body).encode("utf-8") if body is not None else None,
            headers=headers,
        ) as response:
            status = response.status_code
            chunks: list[bytes] = []
            size = 0
            oversized = False
            async for chunk in response.aiter_bytes():
                size += len(chunk)
                if size > MAX_RESPONSE_BYTES:
                    oversized = True
                    break
                chunks.append(chunk)
            retry_header = response.headers.get("Retry-After")
    except httpx.TimeoutException as exc:
        return GoogleAnswer(problem="timeout", error_type=type(exc).__name__)
    except (httpx.HTTPError, EgressBlocked, OSError) as exc:
        return GoogleAnswer(problem="network", error_type=type(exc).__name__)
    payload = b"".join(chunks)
    if oversized:
        return GoogleAnswer(problem="bad_answer", http_status=status, error_type="oversized")
    if status == 200:
        return status, payload
    if status == 429:
        return GoogleAnswer(
            problem="throttled", http_status=status, retry_after_s=_retry_after(retry_header, now)
        )
    if status in (401, 403) or (status == 400 and b"API_KEY_INVALID" in payload):
        return GoogleAnswer(problem="key_rejected", http_status=status)
    if status >= 500:
        return GoogleAnswer(problem="server", http_status=status)
    return GoogleAnswer(problem="bad_answer", http_status=status)


def parse_safe_browsing(payload: bytes, sent: Sequence[str]) -> GoogleAnswer:
    """A threatMatches:find answer: ``{}`` (no match) or ``{"matches": [...]}``. A match counts
    only when its ``threat.url`` is exactly one of the URLs sent and its ``threatType`` is one
    we asked for; anything that is not a JSON object with a list of matches is a bad answer."""
    try:
        data = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        return GoogleAnswer(problem="bad_answer", http_status=200, error_type="not_json")
    if not isinstance(data, dict):
        return GoogleAnswer(problem="bad_answer", http_status=200, error_type="not_object")
    matches = data.get("matches") or []
    if not isinstance(matches, list):
        return GoogleAnswer(problem="bad_answer", http_status=200, error_type="matches")
    wanted = set(sent)
    listed: dict[str, tuple[tuple[str, ...], Optional[float]]] = {}
    for match in matches:
        if not isinstance(match, dict):
            continue
        threat = match.get("threat")
        url = threat.get("url") if isinstance(threat, dict) else None
        kind = match.get("threatType")
        if url not in wanted or kind not in SB_THREAT_TYPES:
            continue
        ttl = _duration(match.get("cacheDuration"))
        threats, previous = listed.get(url, ((), None))
        if kind not in threats:
            threats = (*threats, kind)
        if previous is not None and ttl is not None:
            ttl = min(previous, ttl)
        elif previous is not None:
            ttl = previous
        listed[url] = (threats, ttl)
    return GoogleAnswer(listed=listed, http_status=200)


def parse_web_risk(payload: bytes, url: str, now: datetime) -> GoogleAnswer:
    """A uris:search answer: ``{}`` (no match) or ``{"threat": {"threatTypes": [...],
    "expireTime": "..."}}``. Threat types we did not ask for are ignored; a match with none
    left is no match; Google's expireTime bounds how long it may be cached."""
    try:
        data = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        return GoogleAnswer(problem="bad_answer", http_status=200, error_type="not_json")
    if not isinstance(data, dict):
        return GoogleAnswer(problem="bad_answer", http_status=200, error_type="not_object")
    threat = data.get("threat")
    if threat is None:
        return GoogleAnswer(http_status=200)
    if not isinstance(threat, dict) or not isinstance(threat.get("threatTypes"), list):
        return GoogleAnswer(problem="bad_answer", http_status=200, error_type="threat")
    kinds = tuple(dict.fromkeys(t for t in threat["threatTypes"] if t in WR_THREAT_TYPES))
    if not kinds:
        return GoogleAnswer(http_status=200)
    expires = _timestamp(threat.get("expireTime"))
    ttl = (expires - now).total_seconds() if expires is not None else None
    return GoogleAnswer(listed={url: (kinds, ttl)}, http_status=200)


async def safe_browsing_lookup(
    client: httpx.AsyncClient, key: str, urls: Sequence[str], *, now: Optional[datetime] = None
) -> GoogleAnswer:
    """One Safe Browsing v4 Lookup request (``threatMatches:find``) for up to SB_BATCH *urls*,
    with *key* in the X-Goog-Api-Key header. *client* must be the guarded client."""
    body = {
        "client": {"clientId": CLIENT_ID, "clientVersion": CLIENT_VERSION},
        "threatInfo": {
            "threatTypes": list(SB_THREAT_TYPES),
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url} for url in urls],
        },
    }
    moment = now or datetime.now(timezone.utc)
    result = await _exchange(client, "POST", SAFE_BROWSING_URL, key=key, now=moment, body=body)
    if isinstance(result, GoogleAnswer):
        return result
    return parse_safe_browsing(result[1], urls)


async def web_risk_lookup(
    client: httpx.AsyncClient, key: str, url: str, *, now: Optional[datetime] = None
) -> GoogleAnswer:
    """One Web Risk ``uris:search`` request for *url*, with *key* in the X-Goog-Api-Key header
    (the checked link travels in the query, which is why the policy resolver never sees it).
    *client* must be the guarded client."""
    params = httpx.QueryParams(
        (*(("threatTypes", kind) for kind in WR_THREAT_TYPES), ("uri", url))
    )
    moment = now or datetime.now(timezone.utc)
    result = await _exchange(client, "GET", WEB_RISK_URL, key=key, now=moment, params=params)
    if isinstance(result, GoogleAnswer):
        return result
    return parse_web_risk(result[1], url, moment)


# ── the service ────────────────────────────────────────────────────────


@dataclass(frozen=True)
class _Outcome:
    """One link's answer from the cache or Google: its status and, when listed, the threats."""
    status: ServiceStatus
    threats: tuple[str, ...] = ()
    cached: bool = False


Bucket = tuple[str, str]   # (service, key fingerprint)


def _fingerprint(key: str) -> str:
    """The first 16 hex characters of the key's sha256: names the limiter's counters for this
    key (a replaced key starts fresh) without holding the key. Never logged."""
    return hashlib.sha256(key.encode("utf-8")).hexdigest()[:16]


def _iso(moment: datetime) -> str:
    return moment.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _whole(value: Any, default: int) -> int:
    """A limit from the owner's settings as a whole number; the default when it is not one."""
    if isinstance(value, bool) or not isinstance(value, (int, float)) or value != value:
        return default
    return max(int(value), 0)


def _scrub(text: str, key: str) -> str:
    """*text* with every copy of *key* removed (setup._scrub's discipline)."""
    return text.replace(key, "[the key]") if key else text


class _DayCount:
    """How many events happened in the last 24 hours (the owner's "dangerous links found" and
    "links not checked" counters). Events within COUNT_RESOLUTION_S of each other share one
    entry, and old entries are dropped on every add and read, so a flood of checked links (a
    mail sweep while the key is rejected) never grows the process's memory past a day of
    entries, whether or not anyone opens the owner's tab."""

    def __init__(self) -> None:
        self._entries: deque[list[float]] = deque()   # [first event's time, count]

    def _prune(self, now: float) -> None:
        while self._entries and now - self._entries[0][0] >= DAY_S:
            self._entries.popleft()

    def add(self, now: float) -> None:
        self._prune(now)
        if self._entries and now - self._entries[-1][0] < COUNT_RESOLUTION_S:
            self._entries[-1][1] += 1
        else:
            self._entries.append([now, 1])

    def count(self, now: float) -> int:
        self._prune(now)
        return int(sum(entry[1] for entry in self._entries))

    def __len__(self) -> int:
        """Entries kept (for the memory bound's test), not events."""
        return len(self._entries)


class LinkReputation:
    """The owner-keyed link lookup service (one per process; ``app.state.link_reputation``)."""

    def __init__(
        self,
        source: ReputationSource,
        *,
        transport: Optional[httpx.AsyncBaseTransport] = None,
        clock: Callable[[], float] = time.monotonic,
        wall_clock: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
        owner_alert: Optional[OwnerAlert] = None,
    ) -> None:
        self._source = source
        self._transport = transport
        self._clock = clock
        self._wall_clock = wall_clock
        self._owner_alert = owner_alert
        self._started = wall_clock()
        self._cache_max = CACHE_MAX_ENTRIES
        self._tasks: set[asyncio.Task[Any]] = set()
        self._reset()

    def _reset(self) -> None:
        self._cache: OrderedDict[tuple[str, str], tuple[float, bool, tuple[str, ...]]] = (
            OrderedDict()
        )
        self._windows: dict[Bucket, deque[tuple[float, bool]]] = {}
        self._cool_until: dict[Bucket, float] = {}
        self._throttle_streak: dict[Bucket, int] = {}
        self._alerted: dict[str, float] = {}
        self._dangerous = _DayCount()
        self._not_checked = _DayCount()
        self._last_problem: Optional[dict[str, Any]] = None
        self._inflight: dict[tuple[str, str], asyncio.Future[_Outcome]] = {}
        self._last_service: Optional[str] = None

    def clear(self) -> None:
        """Forget the cache, counters, cool-downs and alerts (tests). Lookups still running are
        cancelled, so nothing they learn lands after the reset."""
        for task in list(self._tasks):
            task.cancel()
        self._tasks.clear()
        self._reset()

    # ── configuration ──────────────────────────────────────────────────

    async def _config(self) -> Union[ServiceStatus, tuple[ServiceName, str]]:
        """The active (service, key), or why Google is not asked: "settings_unreadable" when the
        switch or key cannot be read (privacy first: nothing is sent), "off" when the owner
        switched it off, "no_key" when it is blocked (no Google key) or the key just went.
        Web Risk wins when both keys exist (its terms allow commercial use)."""
        try:
            statuses = await self._source.capability_statuses()
            status = statuses.get("link_reputation")
        except Exception as exc:  # noqa: BLE001 - fail closed for egress
            logger.warning("link_reputation_settings_unreadable", error_type=type(exc).__name__)
            return "settings_unreadable"
        effective = getattr(status, "effective", None)
        if effective == "off":
            return "off"
        if effective != "on":
            return "no_key"
        try:
            for service in _PREFERENCE:
                key = await self._source.service_key(service)
                if key:
                    return service, key
        except Exception as exc:  # noqa: BLE001 - fail closed for egress
            logger.warning("link_reputation_settings_unreadable", error_type=type(exc).__name__)
            return "settings_unreadable"
        return "no_key"

    async def _limits(self) -> tuple[int, int]:
        """(lookups per minute, lookups per day) from the owner's settings; the defaults when
        they cannot be read."""
        defaults = LINK_REPUTATION_SETTINGS_DEFAULTS
        try:
            stored = await self._source.capability_settings("link_reputation")
        except Exception as exc:  # noqa: BLE001 - the defaults bound the cost instead
            logger.warning("link_reputation_limits_unreadable", error_type=type(exc).__name__)
            stored = {}
        return (
            _whole(stored.get("lookups_per_minute"), defaults["lookups_per_minute"]),
            _whole(stored.get("lookups_per_day"), defaults["lookups_per_day"]),
        )

    async def remote_configured(self) -> bool:
        """True when a Google key exists and link_reputation is on: a check may ask Google."""
        try:
            return not isinstance(await self._config(), str)
        except Exception:  # noqa: BLE001 - never raises
            return False

    # ── cache ──────────────────────────────────────────────────────────

    def _cache_get(self, service: str, lookup: str) -> Optional[_Outcome]:
        key = (service, lookup)
        entry = self._cache.get(key)
        if entry is None:
            return None
        expires, listed, threats = entry
        if expires <= self._clock():
            del self._cache[key]
            return None
        self._cache.move_to_end(key)
        return _Outcome("listed", threats, cached=True) if listed else _Outcome(
            "not_listed", cached=True
        )

    def _cache_put(self, service: str, lookup: str, listed: bool, threats: tuple[str, ...],
                   ttl: float) -> None:
        if ttl <= 0:
            return
        key = (service, lookup)
        self._cache[key] = (self._clock() + ttl, listed, threats)
        self._cache.move_to_end(key)
        while len(self._cache) > self._cache_max:
            self._cache.popitem(last=False)

    def _service_order(self) -> tuple[ServiceName, ...]:
        """The services whose cache entries count, the last one used first."""
        if self._last_service == "safe_browsing":
            return ("safe_browsing", "web_risk")
        return _PREFERENCE

    # ── limiter and cool-downs ─────────────────────────────────────────

    def _window(self, bucket: Bucket) -> deque[tuple[float, bool]]:
        if bucket not in self._windows:
            # A replaced key starts fresh counters; the old key's are dropped with it, so
            # rotating keys never keeps a day of entries per key ever used.
            for old in [b for b in self._windows if b[0] == bucket[0]]:
                del self._windows[old]
        window = self._windows.setdefault(bucket, deque())
        now = self._clock()
        while window and now - window[0][0] >= DAY_S:
            window.popleft()
        return window

    def _used(self, bucket: Bucket) -> tuple[int, int]:
        """(requests in the last minute, requests in the last day) for *bucket*."""
        window = self._window(bucket)
        now = self._clock()
        return sum(1 for at, _ in window if now - at < MINUTE_S), len(window)

    def _reserve(self, bucket: Bucket, purpose: str, wanted: int, per_minute: int,
                 per_day: int) -> tuple[int, Optional[str]]:
        """How many of *wanted* requests may go now (they are counted), and the window
        ("minute" or "day") that stopped the rest. A background purpose also stops at
        BACKGROUND_SHARE of each window, counting its own requests."""
        window = self._window(bucket)
        now = self._clock()
        background = purpose in BACKGROUND_PURPOSES
        minute = sum(1 for at, _ in window if now - at < MINUTE_S)
        day = len(window)
        bg_minute = sum(1 for at, bg in window if bg and now - at < MINUTE_S)
        bg_day = sum(1 for _, bg in window if bg)
        bg_minute_cap = math.floor(per_minute * BACKGROUND_SHARE)
        bg_day_cap = math.floor(per_day * BACKGROUND_SHARE)
        granted = 0
        while granted < wanted:
            if minute >= per_minute or (background and bg_minute >= bg_minute_cap):
                return granted, "minute"
            if day >= per_day or (background and bg_day >= bg_day_cap):
                return granted, "day"
            window.append((now, background))
            minute, day, granted = minute + 1, day + 1, granted + 1
            if background:
                bg_minute, bg_day = bg_minute + 1, bg_day + 1
        return granted, None

    def _cooling(self, bucket: Bucket) -> bool:
        until = self._cool_until.get(bucket)
        if until is None:
            return False
        if until <= self._clock():
            del self._cool_until[bucket]
            return False
        return True

    def _cool(self, bucket: Bucket, seconds: float) -> None:
        until = self._clock() + seconds
        self._cool_until[bucket] = max(self._cool_until.get(bucket, 0.0), until)

    def _problem(self, kind: str, http_status: Optional[int]) -> None:
        self._last_problem = {
            "kind": kind,
            "at": _iso(self._wall_clock()),
            "http_status": http_status,
        }

    # ── one batch of requests ──────────────────────────────────────────

    def _spawn(self, coro: Coroutine[Any, Any, Any]) -> None:
        """Run *coro* as a task this service keeps a reference to until it ends."""
        task = asyncio.get_running_loop().create_task(coro)
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)

    def _settle(self, service: ServiceName, bucket: Bucket, lookups: Sequence[str],
                answer: GoogleAnswer, futures: Mapping[str, asyncio.Future[_Outcome]]) -> None:
        """Turn one Google answer into outcomes for *lookups*: cache verdicts, start
        cool-downs, record the problem, alert the owner on a rejected key."""
        outcomes: dict[str, _Outcome] = {}
        if answer.ok:
            self._throttle_streak.pop(bucket, None)
            for lookup in lookups:
                if lookup in answer.listed:
                    threats, google_ttl = answer.listed[lookup]
                    ttl = POSITIVE_TTL_S if google_ttl is None else min(POSITIVE_TTL_S, google_ttl)
                    self._cache_put(service, lookup, True, threats, ttl)
                    outcomes[lookup] = _Outcome("listed", threats)
                else:
                    self._cache_put(service, lookup, False, (), NEGATIVE_TTL_S)
                    outcomes[lookup] = _Outcome("not_listed")
        else:
            status = self._failure(service, bucket, answer)
            outcomes = {lookup: _Outcome(status) for lookup in lookups}
        for lookup, outcome in outcomes.items():
            future = futures.get(lookup)
            if future is not None and not future.done():
                future.set_result(outcome)
            if self._inflight.get((service, lookup)) is future:
                self._inflight.pop((service, lookup), None)

    def _failure(self, service: ServiceName, bucket: Bucket, answer: GoogleAnswer) -> ServiceStatus:
        """The status, cool-down, log line, problem record and owner alert for a failed
        request (section 4.7's table)."""
        problem, http_status = answer.problem, answer.http_status
        if problem == "key_rejected":
            self._cool(bucket, KEY_REJECTED_COOL_DOWN_S)
            self._problem("key_rejected", http_status)
            logger.warning("link_reputation_key_rejected", service=service, status_code=http_status)
            self._alert_owner(service, http_status)
            return "key_rejected"
        logger.warning(
            "link_reputation_lookup_failed",
            service=service,
            status_code=http_status,
            error_type=answer.error_type or problem,
        )
        if problem == "throttled":
            streak = self._throttle_streak.get(bucket, 0) + 1
            self._throttle_streak[bucket] = streak
            low, high = COOL_DOWN_429_S
            if answer.retry_after_s is not None:
                seconds = min(max(answer.retry_after_s, low), high)
            else:
                seconds = min(low * 2 ** (streak - 1), high)
            self._cool(bucket, seconds)
            self._problem("rate_limited", http_status)
            return "rate_limited"
        if problem == "timeout":
            self._problem("timeout", None)
            return "timeout"
        if problem == "server":
            self._cool(bucket, COOL_DOWN_5XX_S)
        self._problem("error", http_status)
        return "error"

    def _alert_owner(self, service: ServiceName, http_status: Optional[int]) -> None:
        """At most one owner alert per service per OWNER_ALERT_EVERY_S, sent in the background
        so the check that found the problem is not held up by Telegram or Slack."""
        if self._owner_alert is None:
            return
        now = self._clock()
        last = self._alerted.get(service)
        if last is not None and now - last < OWNER_ALERT_EVERY_S:
            return
        self._alerted[service] = now
        label = SERVICE_LABELS.get(service, "Google")
        status_text = f" (HTTP {http_status})" if http_status else ""
        message = (
            f"Link checks with {label} stopped working: Google refused the key{status_text}. "
            "Links are checked on this computer only until you replace the key in Security → "
            "Service keys."
        )
        facts = {"service": service, "http_status": http_status}
        alert = self._owner_alert

        async def send() -> None:
            try:
                await alert(message, facts)
            except Exception as exc:  # noqa: BLE001 - an alert never breaks a check
                logger.warning("link_reputation_owner_alert_failed", error_type=type(exc).__name__)

        self._spawn(send())

    async def _run(self, service: ServiceName, key: str, bucket: Bucket, lookups: list[str],
                   futures: dict[str, asyncio.Future[_Outcome]]) -> None:
        """Ask Google about *lookups* and settle every future, whatever happens. Runs as its own
        task, so a caller that stops waiting (timeout, cancel) never cancels it: the answer
        still lands in the cache and reaches every other caller waiting on the same link."""
        transport = self._transport if self._transport is not None else DEFAULT_TRANSPORT
        try:
            async with _guarded_client(transport) as client:
                if service == "safe_browsing":
                    for start in range(0, len(lookups), SB_BATCH):
                        chunk = lookups[start:start + SB_BATCH]
                        if self._cooling(bucket):
                            self._settle_status(service, chunk, "cooling_down", futures)
                            continue
                        answer = await safe_browsing_lookup(
                            client, key, chunk, now=self._wall_clock()
                        )
                        self._settle(service, bucket, chunk, answer, futures)
                else:
                    gate = asyncio.Semaphore(WR_CONCURRENCY)

                    async def one(lookup: str) -> None:
                        async with gate:
                            if self._cooling(bucket):
                                self._settle_status(service, [lookup], "cooling_down", futures)
                                return
                            answer = await web_risk_lookup(
                                client, key, lookup, now=self._wall_clock()
                            )
                        self._settle(service, bucket, [lookup], answer, futures)

                    await asyncio.gather(*(one(lookup) for lookup in lookups))
        except Exception as exc:  # noqa: BLE001 - fail open with a not-checked status
            logger.warning(
                "link_reputation_lookup_failed",
                service=service,
                status_code=None,
                error_type=type(exc).__name__,
            )
            self._problem("error", None)
        finally:
            self._settle_status(service, lookups, "error", futures)

    def _settle_status(self, service: str, lookups: Sequence[str], status: ServiceStatus,
                       futures: Mapping[str, asyncio.Future[_Outcome]]) -> None:
        """Settle every future of *lookups* not settled yet with *status*."""
        for lookup in lookups:
            future = futures.get(lookup)
            if future is not None and not future.done():
                future.set_result(_Outcome(status))
            if self._inflight.get((service, lookup)) is future:
                self._inflight.pop((service, lookup), None)

    async def _lookup(self, service: ServiceName, key: str, lookups: list[str], purpose: str,
                      timeout_s: float) -> dict[str, _Outcome]:
        """Outcomes for the distinct *lookups* (none cached when the caller looked): shared
        in-flight requests, cool-down, the owner's limits, then one batch task, waited on for at
        most *timeout_s*.

        Single-flight: the owner's limits are read first, because that read can wait (a database
        read when the settings snapshot is stale). From the cache and in-flight look below to
        registering this call's own futures nothing waits, so two concurrent checks of one link
        can never both miss each other's request; an answer that landed during the wait is
        taken from the cache."""
        bucket: Bucket = (service, _fingerprint(key))
        per_minute, per_day = await self._limits()
        outcomes: dict[str, _Outcome] = {}
        waiting: dict[str, asyncio.Future[_Outcome]] = {}
        fresh: list[str] = []
        for lookup in lookups:
            hit = self._cache_get(service, lookup)
            if hit is not None:
                outcomes[lookup] = hit
                continue
            shared = self._inflight.get((service, lookup))
            if shared is not None:
                waiting[lookup] = shared
            else:
                fresh.append(lookup)
        if fresh and self._cooling(bucket):
            outcomes.update({lookup: _Outcome("cooling_down") for lookup in fresh})
            fresh = []
        if fresh and service == "web_risk" and len(fresh) > WR_MAX_PER_CALL:
            outcomes.update({lookup: _Outcome("too_many") for lookup in fresh[WR_MAX_PER_CALL:]})
            fresh = fresh[:WR_MAX_PER_CALL]
        if fresh:
            per_request = 1 if service == "web_risk" else SB_BATCH
            wanted = math.ceil(len(fresh) / per_request)
            granted, window = self._reserve(bucket, purpose, wanted, per_minute, per_day)
            if granted < wanted:
                logger.warning("link_reputation_rate_limited", service=service, window=window)
                self._problem("rate_limited", None)
                allowed = granted * per_request
                outcomes.update({lookup: _Outcome("rate_limited") for lookup in fresh[allowed:]})
                fresh = fresh[:allowed]
        if fresh:
            loop = asyncio.get_running_loop()
            futures = {lookup: loop.create_future() for lookup in fresh}
            for lookup, future in futures.items():
                self._inflight[(service, lookup)] = future
            waiting.update(futures)
            self._spawn(self._run(service, key, bucket, fresh, futures))
        if waiting:
            await asyncio.wait(set(waiting.values()), timeout=max(timeout_s, 0.0))
            for lookup, future in waiting.items():
                if future.done() and not future.cancelled():
                    outcomes[lookup] = future.result()
                else:
                    outcomes[lookup] = _Outcome("timeout")
        return outcomes

    # ── reports ────────────────────────────────────────────────────────

    @staticmethod
    def _merge(report: LinkReport, status: ServiceStatus, *, service: Optional[ServiceName],
               threats: tuple[str, ...] = (), cached: bool = False) -> LinkReport:
        if report.service_status == "not_eligible":
            # A mail, phone or text-message link: nothing to look up whatever the service says.
            return report
        return dataclasses.replace(
            report,
            service_status=status,
            service=service,
            threats=threats,
            cached=cached,
            level=level_for(report.signals, status),
        )

    def _local(self, url: str, text: Optional[str], status: ServiceStatus) -> LinkReport:
        """The local report, which never loses the link's own findings to its text: when the
        report with *text* fails, the report without it; when that fails too, the report of a
        link that could not be read (the "unreadable" signal), never a bare one."""
        try:
            return local_report(url, text=text, service_status=status)
        except Exception as exc:  # noqa: BLE001 - never raises; a report still comes back
            logger.warning("link_reputation_local_check_failed", error_type=type(exc).__name__)
        if text:
            try:
                return local_report(url, service_status=status)
            except Exception as exc:  # noqa: BLE001 - as above
                logger.warning("link_reputation_local_check_failed",
                               error_type=type(exc).__name__)
        return link_checks.unreadable_report(url, service_status=status)

    async def check(self, urls: Sequence[str], *, purpose: Purpose,
                    texts: Optional[Mapping[str, str]] = None, network: bool = True,
                    timeout_s: float = CHECK_TIMEOUT_S) -> list[LinkReport]:
        """One report per input URL, in input order (duplicates share one lookup). Local checks
        always; a Google lookup only with a key, the switch on, network=True and an eligible
        link. Never raises; never says safe."""
        try:
            items = list(urls)
        except Exception as exc:  # noqa: BLE001 - nothing to report on
            logger.warning("link_reputation_check_failed", error_type=type(exc).__name__)
            return []
        try:
            return await self._check(items, purpose, texts, network, timeout_s)
        except Exception as exc:  # noqa: BLE001 - fail open with a not-checked status
            logger.warning("link_reputation_check_failed", error_type=type(exc).__name__)
            return [self._local(url, text_for(texts, url), "error") for url in items]

    async def _check(self, urls: list[str], purpose: Purpose,
                     texts: Optional[Mapping[str, str]], network: bool,
                     timeout_s: float) -> list[LinkReport]:
        unique = list(dict.fromkeys(urls))
        base = {url: self._local(url, text_for(texts, url), "no_key") for url in unique}
        candidates, overflow = unique[:MAX_URLS_PER_CALL], unique[MAX_URLS_PER_CALL:]
        final: dict[str, LinkReport] = {}

        if not network:
            for url in candidates:
                # One link that cannot be read never costs the others their cached answers.
                try:
                    final[url] = self._from_cache(base[url], url, purpose, miss="cache_miss")
                except Exception as exc:  # noqa: BLE001 - this link alone is not checked
                    logger.warning("link_reputation_cache_read_failed",
                                   error_type=type(exc).__name__)
                    final[url] = self._merge(base[url], "error", service=None)
            for url in overflow:
                final[url] = self._merge(base[url], "too_many", service=None)
            return [final[url] for url in urls]

        config = await self._config()
        if isinstance(config, str):
            for url in unique:
                final[url] = self._merge(base[url], config, service=None)
            return [final[url] for url in urls]

        service, key = config
        self._last_service = service
        lookups: dict[str, Optional[str]] = {}
        failed: set[str] = set()
        for url in candidates:
            if base[url].service_status == "not_eligible":
                lookups[url] = None
                continue
            try:
                lookups[url] = lookup_url(url, purpose)
            except Exception as exc:  # noqa: BLE001 - this link alone is not checked
                logger.warning("link_reputation_lookup_url_failed", error_type=type(exc).__name__)
                lookups[url] = None
                failed.add(url)
        outcomes: dict[str, _Outcome] = {}
        misses: list[str] = []
        for lookup in dict.fromkeys(v for v in lookups.values() if v is not None):
            hit = self._cache_get(service, lookup)
            if hit is not None:
                outcomes[lookup] = hit
            else:
                misses.append(lookup)
        if misses:
            outcomes.update(await self._lookup(service, key, misses, purpose, timeout_s))

        now = self._clock()
        for url in candidates:
            sent = lookups[url]
            if sent is None:
                # A link whose lookup could not be worked out was due one: it is not checked
                # (a note says so), never quietly not eligible.
                status: ServiceStatus = "error" if url in failed else "not_eligible"
                final[url] = self._merge(base[url], status, service=service)
                continue
            outcome = outcomes.get(sent, _Outcome("error"))
            final[url] = self._merge(
                base[url], outcome.status, service=service, threats=outcome.threats,
                cached=outcome.cached,
            )
        for url in overflow:
            final[url] = self._merge(base[url], "too_many", service=service)
        for url in unique:
            status = final[url].service_status
            if status == "listed":
                self._dangerous.add(now)
            elif status in NOT_CHECKED_STATUSES:
                self._not_checked.add(now)
        return [final[url] for url in urls]

    def _from_cache(self, report: LinkReport, url: str, purpose: Purpose, *,
                    miss: Optional[ServiceStatus]) -> LinkReport:
        """*report* with a live cache entry for *url* merged in; with none, *report* with
        status *miss*."""
        lookup = lookup_url(url, purpose) if report.service_status != "not_eligible" else None
        if lookup is not None:
            for service in self._service_order():
                hit = self._cache_get(service, lookup)
                if hit is not None:
                    return self._merge(report, hit.status, service=service,
                                       threats=hit.threats, cached=True)
        if miss is None:
            return report
        status: ServiceStatus = miss if lookup is not None else "not_eligible"
        return self._merge(report, status, service=None)

    async def check_one(self, url: str, *, purpose: Purpose, text: Optional[str] = None,
                        network: bool = True, timeout_s: float = CHECK_TIMEOUT_S) -> LinkReport:
        """check() for one link."""
        texts = {url: text} if text else None
        reports = await self.check([url], purpose=purpose, texts=texts, network=network,
                                   timeout_s=timeout_s)
        return reports[0]

    def check_local(self, url: str, *, text: Optional[str] = None) -> LinkReport:
        """Local checks only (link_checks.local_report); synchronous, no network."""
        return self._local(url, text, "no_key")

    def cached_report(self, url: str, *, purpose: Purpose) -> Optional[LinkReport]:
        """The local report merged with a live cache entry for the active service, or None when
        nothing is cached. Synchronous and network-free: for code that must not wait (S1's
        execute-time re-check)."""
        try:
            report = self._local(url, None, "no_key")
            if report.service_status == "not_eligible":
                return None
            merged = self._from_cache(report, url, purpose, miss=None)
            return merged if merged.cached else None
        except Exception as exc:  # noqa: BLE001 - never raises
            logger.warning("link_reputation_cached_report_failed", error_type=type(exc).__name__)
            return None

    # ── the browser guard's step ───────────────────────────────────────

    @staticmethod
    def _exempt(url: str) -> bool:
        """The host the browser really opens (read as the browser reads it, so a backslash or
        an "@" cannot dress another site up as a sign-in host) is an EXEMPT_HOSTS entry or one
        of its subdomains; for a TENANT_IDP_DOMAINS entry only the entry itself (a tenant
        anyone can register is looked up)."""
        host = link_checks.host_of(url)
        return bool(host) and any(
            host == entry
            or (host.endswith("." + entry) and entry not in TENANT_IDP_DOMAINS)
            for entry in EXEMPT_HOSTS
        )

    @staticmethod
    def _note(state: Any, kind: str, text: str) -> None:
        """Append a non-blocking note to the guard state, once per text per context. A state
        without notes (a fake, or a guard before the notes field) is left alone."""
        notes = getattr(state, "notes", None)
        if not isinstance(notes, list):
            return
        note = {"kind": kind, "text": text}
        if note not in notes:
            notes.append(note)

    @staticmethod
    def _not_checked_text(service: Optional[str], status: str) -> str:
        label = SERVICE_LABELS.get(service or "", "Google's list of dangerous sites")
        why = {
            "settings_unreadable": "the owner's settings could not be read",
            "too_many": "too many links at once",
            "rate_limited": "the lookup limit was reached",
            "cooling_down": "lookups are paused after a problem with Google",
            "timeout": "Google did not answer in time",
            "error": "Google could not be reached",
            "key_rejected": "Google refused the key",
            "unreadable": "its address could not be read",
        }.get(status, "Google could not be reached")
        return f"This site was not checked against {label} ({why})."

    async def navigation_check(self, url: str, state: Any) -> Optional[str]:
        """The browser guard's reputation step (EgressHooks.reputation, scaffold A1): a block
        reason for a site Google lists, else None. Adds non-blocking notes to state.notes.
        Never raises: an exception escaping the guard's route handler would abort the
        navigation, turning "Google is down" into "block"."""
        try:
            if self._exempt(url):
                return None
            # The lookup's own wait ends a little before the hop's cap, so a slow Google reads as
            # "did not answer in time"; the cap also bounds the switch and key reads.
            report = await asyncio.wait_for(
                self.check_one(url, purpose="browser", timeout_s=BROWSER_TIMEOUT_S * 0.8),
                BROWSER_TIMEOUT_S,
            )
            if report.level == "dangerous":
                return advisory(report.service, report.threats)
            for signal in report.signals:
                if signal.code in ("lookalike_characters", "lookalike_brand"):
                    self._note(state, "link_suspicious", link_checks.model_safe_text(signal))
            if report.service_status in NOT_CHECKED_STATUSES:
                self._note(
                    state, "link_not_checked",
                    self._not_checked_text(report.service, report.service_status),
                )
            elif report.service_status == "not_eligible" and any(
                signal.code == "unreadable" for signal in report.signals
            ):
                # The guard is opening an address this module could not read, so nothing was
                # looked up although the owner set Google up: say so instead of passing it on
                # silently (a reading gap must never look like a clean lookup).
                self._note(
                    state, "link_not_checked",
                    self._not_checked_text(report.service, "unreadable"),
                )
            return None
        except Exception as exc:  # noqa: BLE001 - fail open, with a note
            logger.warning("link_reputation_navigation_check_failed", error_type=type(exc).__name__)
            why = "timeout" if isinstance(exc, TimeoutError) else "error"
            self._note(state, "link_not_checked", self._not_checked_text(None, why))
            return None

    # ── the owner's view ───────────────────────────────────────────────

    async def status(self) -> dict[str, Any]:
        """Counts, limits, the active service, cool-down and the last problem for the owner's
        tab. No key, link or host."""
        capability, reason = "blocked", ""
        try:
            statuses = await self._source.capability_statuses()
            found = statuses.get("link_reputation")
            if found is not None:
                capability = str(getattr(found, "effective", "blocked"))
                reason = str(getattr(found, "reason", ""))
        except Exception as exc:  # noqa: BLE001 - the tab still shows the counters
            logger.warning("link_reputation_settings_unreadable", error_type=type(exc).__name__)
            capability, reason = "blocked", "The owner's settings could not be read."
        keys: dict[str, Optional[str]] = {}
        for name in ("web_risk", "safe_browsing"):
            try:
                keys[name] = await self._source.service_key(name) or None
            except Exception:  # noqa: BLE001 - reads as no key
                keys[name] = None
        service = "web_risk" if keys["web_risk"] else (
            "safe_browsing" if keys["safe_browsing"] else None
        )
        per_minute, per_day = await self._limits()
        minute = day = 0
        cooling_until: Optional[str] = None
        if service is not None:
            bucket: Bucket = (service, _fingerprint(keys[service] or ""))
            minute, day = self._used(bucket)
            if self._cooling(bucket):
                left = self._cool_until[bucket] - self._clock()
                wall = self._wall_clock().timestamp() + left
                cooling_until = _iso(datetime.fromtimestamp(wall, tz=timezone.utc))
        now = self._clock()
        return {
            "capability": capability,
            "reason": reason,
            "service": service,
            "both_keys": bool(keys["web_risk"] and keys["safe_browsing"]),
            "lookups_last_minute": minute,
            "lookups_per_minute": per_minute,
            "lookups_last_day": day,
            "lookups_per_day": per_day,
            "counting_since": _iso(self._started),
            "cache_entries": len(self._cache),
            "dangerous_found_last_day": self._dangerous.count(now),
            "not_checked_last_day": self._not_checked.count(now),
            "cooling_down_until": cooling_until,
            "last_problem": dict(self._last_problem) if self._last_problem else None,
        }


# ── the key test and the owner alert ───────────────────────────────────


async def test_google_key(service: ServiceName, key: str, *,
                          transport: Optional[httpx.AsyncBaseTransport] = None) -> KeyTestResult:
    """Look up Google's test page with *key* (nothing stored, no cache, no limiter): proves the
    key, the API being enabled and the network path in one request."""
    if service not in SERVICE_LABELS:
        return KeyTestResult(False, "That is not a Google link-check service.")
    api = "Safe Browsing" if service == "safe_browsing" else "Web Risk"
    try:
        async with _guarded_client(transport if transport is not None else DEFAULT_TRANSPORT) as client:
            if service == "safe_browsing":
                answer = await safe_browsing_lookup(client, key, [SAFE_BROWSING_TEST_URL])
            else:
                answer = await web_risk_lookup(client, key, WEB_RISK_TEST_URL)
    except Exception as exc:  # noqa: BLE001 - the type only, never the message
        return KeyTestResult(False, _scrub(f"Could not reach Google ({type(exc).__name__}).", key))
    status = answer.http_status
    if status == 200:
        detail, ok = "Google answered: the key works.", True
    elif status is None:
        detail, ok = f"Could not reach Google ({answer.error_type or 'network error'}).", False
    elif status == 403:
        detail, ok = (
            f"Google refused the key: the {api} API is not turned on for this key's project, "
            "or the key is restricted to other APIs."
        ), False
    elif answer.problem == "key_rejected":
        detail, ok = "Google refused the key: it is not a valid API key.", False
    elif status == 429:
        detail, ok = "Google says this key's quota is used up. Try again later.", False
    else:
        detail, ok = f"Google answered HTTP {status}.", False
    return KeyTestResult(ok, _scrub(detail, key))


def owner_alert(session_factory: Callable[[], Any], send: Callable[[str, str], Awaitable[Any]],
                audit: Callable[[dict[str, Any]], Awaitable[None]]) -> OwnerAlert:
    """An OwnerAlert that sends *message* to every admin user through *send*
    (app.state.owner_send, scaffold A34) and writes one link_reputation_key_rejected row per
    admin. Contains every failure (logged by type)."""

    async def alert(message: str, facts: Mapping[str, Any]) -> None:
        try:
            from sqlalchemy import select

            from models.user import User

            async with session_factory() as session:
                rows = await session.execute(
                    select(User.id).where(User.is_admin.is_(True), User.is_active.is_(True))
                )
                admins = [str(admin_id) for admin_id in rows.scalars().all()]
        except Exception as exc:  # noqa: BLE001 - logged by type only
            logger.warning("link_reputation_owner_alert_failed", step="admins",
                           error_type=type(exc).__name__)
            return
        arguments = {"service": facts.get("service"), "http_status": facts.get("http_status")}
        for admin in admins:
            try:
                await send(admin, message)
            except Exception as exc:  # noqa: BLE001 - one channel failing never stops the rest
                logger.warning("link_reputation_owner_alert_failed", step="send",
                               error_type=type(exc).__name__)
            try:
                await audit({
                    "event": "link_reputation_key_rejected",
                    "user_id": admin,
                    "tool": "link_reputation.key_rejected",
                    "kind": "key_rejected",
                    "arguments": dict(arguments),
                })
            except Exception as exc:  # noqa: BLE001 - logged by type only
                logger.warning("link_reputation_owner_alert_failed", step="audit",
                               error_type=type(exc).__name__)

    return alert
