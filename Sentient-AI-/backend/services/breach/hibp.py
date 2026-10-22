"""The Have I Been Pwned (HIBP) v3 client: ``breachedaccount`` lookups of one
email address with the owner's own key, ``subscription/status`` for the key
test, a process-wide pacer for the key's rate limit, and the parser that turns
HIBP's answer into plain ``Breach`` values.

Why it exists: the breach monitor sends an owner's email address to a third
party, so this is the one place that request is made, and it is made the
narrow way. Every request goes through the SSRF-guarded client with
``egress.policy_resolver`` (HIBP's own network policy, HTTPS only, two paths;
the SSRF log line sees the origin only), redirects are not followed, the body
is streamed under a size cap, and the key travels only in the
``hibp-api-key`` header. HIBP requires an accurate user agent and enforces a
per-key request rate (10 a minute on the lowest plan); the ``Pacer`` spaces
lookups by that rate plus a small margin and honours a 429's retry-after with
one paced retry. A 404 means the address is in no breach. Every other outcome
is a ``HibpError`` subclass with a fixed ``code`` the store and the tab use;
no exception message ever holds the address, the key or HIBP's own text, and
the vendor's ``Description`` (HTML) and logo are never kept.

``check_key`` is the Service keys tab's tester (services/reputation/keys.py
imports it lazily): it calls ``subscription/status`` once and answers a
``KeyTestResult`` sentence that never quotes the key.
"""

from __future__ import annotations

import asyncio
import json
import re
import time
from dataclasses import dataclass
from datetime import date, datetime, timezone
from typing import Any, Awaitable, Callable, Mapping, Optional, TypeVar
from urllib.parse import quote

import httpx
import structlog

from core.network_security import HIBP_POLICY
from models.breach_watch import BREACH_NAME_MAX_CHARS, TITLE_MAX_CHARS
from services.agent.prompt_guard import _INVISIBLE_CHARS
from services.breach.addresses import AddressRejected, normalize_address, plain_hostname
from services.breach.egress import policy_resolver
from services.connectors.base import clean_display_text
from services.reputation.keys import KeyTestResult
from services.tools.net import EgressBlocked, build_guarded_client

logger = structlog.get_logger(__name__)

API_BASE = "https://haveibeenpwned.com/api/v3"
USER_AGENT = "Crawler-AI-breach-monitor"  # HIBP requires an accurate user agent
TIMEOUT_S = 20.0
# The key test answers before the key route's own 10 s deadline (C5).
KEY_CHECK_TIMEOUT_S = 8.0
MAX_BODY_BYTES = 2_000_000  # streamed; a larger answer is BadAnswer
MAX_BREACHES = 1000
DEFAULT_RPM = 10  # the lowest paid plan (resolutions: 10 req/min)
GAP_MARGIN_S = 0.5  # HIBP docs advise a small margin over the limit
MAX_RETRY_AFTER_S = 60
KEY_RE = re.compile(r"^[0-9a-fA-F]{32}$")  # HIBP keys are 32 hex characters
SUBSCRIPTION_NAME_MAX_CHARS = 40
DATA_CLASS_MAX_CHARS = 64
MAX_DATA_CLASSES = 40
# A retry-after past this is not believed; it is clamped (one day).
_RETRY_AFTER_CLAMP_S = 86_400
# The largest value a BIGINT column holds (pwn_count).
_MAX_PWN_COUNT = 2**63 - 1
_DATE_MAX_CHARS = 40

POLICY_REFUSAL = "The network policy refused the request to Have I Been Pwned."
KEY_FORMAT_MESSAGE = "A Have I Been Pwned key is 32 characters, 0-9 and a-f."
KEY_REFUSED_DETAIL = (
    "Have I Been Pwned refused that key. Copy it again from haveibeenpwned.com/API/Key."
)
KEY_RATE_LIMITED_DETAIL = "Have I Been Pwned is rate limiting this key. Try again in a minute."
KEY_UNREACHABLE_DETAIL = (
    "Have I Been Pwned could not be reached, so the key was not checked or saved. Try again later."
)
RATE_LIMITED_MESSAGE = "Have I Been Pwned asked to slow down."


@dataclass(frozen=True)
class Breach:
    name: str  # HIBP "Name", the stable key (Title can change)
    title: str
    domain: Optional[str]
    breach_date: Optional[date]
    added_at: Optional[datetime]
    pwn_count: Optional[int]
    data_classes: tuple[str, ...]
    verified: bool
    sensitive: bool
    fabricated: bool
    spam_list: bool


class HibpError(Exception):
    """A lookup that did not answer. ``code`` is fixed; ``str(exc)`` never holds the address,
    the key or vendor text."""

    code: str = "unavailable"


class KeyRefused(HibpError):
    code = "key_refused"  # 401


class RateLimited(HibpError):
    code = "rate_limited"  # 429 twice

    # The WAVE 0 contract's signature: the message first, the wait by keyword.
    def __init__(self, message: str = "", *, retry_after_s: int = 0) -> None:
        super().__init__(message or RATE_LIMITED_MESSAGE)
        self.retry_after_s = retry_after_s


class AddressRefused(HibpError):
    code = "address_refused"  # 400


class Unavailable(HibpError):
    code = "unavailable"  # 5xx, 403, network error, timeout


class BadAnswer(HibpError):
    code = "bad_answer"  # not JSON, wrong shape, 3xx, too big


class PolicyRefused(HibpError):
    code = "refused_by_policy"  # EgressBlocked


def key_format_ok(key: str) -> bool:
    """True when *key* looks like an HIBP key (32 hex characters). fullmatch, so a trailing
    newline (which ``$`` alone would let through) is refused."""
    return isinstance(key, str) and KEY_RE.fullmatch(key) is not None


# ---------------------------------------------------------------------------
# Parsing
# ---------------------------------------------------------------------------


def _clean(value: Any, max_chars: int) -> str:
    """Third-party text as one display line: control characters become spaces,
    whitespace runs collapse (clean_display_text), invisible characters
    (zero-width, bidi, tag characters) are removed, then the result is cut."""
    if not isinstance(value, str):
        return ""
    text = clean_display_text(value, len(value))
    text = _INVISIBLE_CHARS.sub("", text)
    return " ".join(text.split())[:max_chars].rstrip()


def _breach_date(value: Any) -> Optional[date]:
    if not isinstance(value, str) or len(value) > _DATE_MAX_CHARS:
        return None
    try:
        return date.fromisoformat(value.strip()[:10])
    except ValueError:
        return None


def _added_at(value: Any) -> Optional[datetime]:
    """HIBP's AddedDate as an aware UTC datetime, or None when it cannot be read. One bad
    date only drops this field: a moment at the edge of the calendar with an offset
    ('0001-01-01T00:00:00+05:00') parses but cannot move to UTC (OverflowError), and that
    must never throw the whole answer away (it would be recorded as a counted outage for
    every address in that breach, week after week)."""
    if not isinstance(value, str) or len(value) > _DATE_MAX_CHARS:
        return None
    try:
        moment = datetime.fromisoformat(value.strip())
        if moment.tzinfo is None:
            # HIBP's dates are UTC; a missing offset is read as UTC.
            moment = moment.replace(tzinfo=timezone.utc)
        return moment.astimezone(timezone.utc)
    except (ValueError, OverflowError):
        return None


def _count(value: Any) -> Optional[int]:
    if isinstance(value, bool) or not isinstance(value, int):
        return None
    return value if 0 <= value <= _MAX_PWN_COUNT else None


def _data_classes(value: Any) -> tuple[str, ...]:
    if not isinstance(value, list):
        return ()
    classes: list[str] = []
    for item in value:
        text = _clean(item, DATA_CLASS_MAX_CHARS)
        if text and text not in classes:
            classes.append(text)
            if len(classes) == MAX_DATA_CLASSES:
                break
    return tuple(classes)


def parse_breaches(payload: object) -> list[Breach]:
    """The usable breaches in a breachedaccount answer (a JSON list), at most MAX_BREACHES.
    Skips entries without a string Name; cleans Title/Name/data classes with
    connectors.base.clean_display_text and removes prompt_guard._INVISIBLE_CHARS; keeps Domain
    only when it is a plain hostname; Description, LogoPath and everything else are dropped.
    A later entry whose cleaned Name was already seen is dropped. Raises BadAnswer when
    *payload* is not a list."""
    if not isinstance(payload, list):
        raise BadAnswer("Have I Been Pwned's answer was not a list.")
    breaches: list[Breach] = []
    seen: set[str] = set()
    for item in payload:
        if not isinstance(item, dict):
            continue
        name = _clean(item.get("Name"), BREACH_NAME_MAX_CHARS)
        if not name or name in seen:
            continue
        seen.add(name)
        breaches.append(
            Breach(
                name=name,
                title=_clean(item.get("Title"), TITLE_MAX_CHARS) or name[:TITLE_MAX_CHARS],
                domain=plain_hostname(item.get("Domain")),
                breach_date=_breach_date(item.get("BreachDate")),
                added_at=_added_at(item.get("AddedDate")),
                pwn_count=_count(item.get("PwnCount")),
                data_classes=_data_classes(item.get("DataClasses")),
                verified=item.get("IsVerified") is True,
                sensitive=item.get("IsSensitive") is True,
                fabricated=item.get("IsFabricated") is True,
                spam_list=item.get("IsSpamList") is True,
            )
        )
        if len(breaches) == MAX_BREACHES:
            break
    return breaches


# ---------------------------------------------------------------------------
# Pacing
# ---------------------------------------------------------------------------


class Pacer:
    """Process-wide spacing between HIBP requests: at least 60/rpm + GAP_MARGIN_S seconds apart.
    A 429's retry-after holds the next slot back. *clock* and *sleep* are test seams.

    In memory on purpose: Crawler runs one process per install, and the schedule itself is
    persisted (next_check_at), so a restart starts the pacer free and sends at most one
    request at once."""

    def __init__(
        self,
        rpm: int = DEFAULT_RPM,
        *,
        clock: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], Awaitable[Any]] = asyncio.sleep,
    ) -> None:
        self.gap_s = 60.0 / max(1, rpm) + GAP_MARGIN_S
        self._clock = clock
        self._sleep = sleep
        # The clock time the next request may go; None while free.
        self._next: Optional[float] = None
        self._lock = asyncio.Lock()

    def wait_estimate(self) -> float:
        """Seconds until the next request may go (0 when free)."""
        if self._next is None:
            return 0.0
        return max(0.0, self._next - self._clock())

    async def wait(self) -> None:
        """Sleep until the next slot, then take it. Waiters queue on a lock, so two lookups
        never take one slot."""
        async with self._lock:
            # Re-read after every sleep: a 429 elsewhere may have held the slot back.
            while (delay := self.wait_estimate()) > 0:
                await self._sleep(delay)
            self._next = self._clock() + self.gap_s

    def hold(self, seconds: float) -> None:
        """Keep the next slot at least *seconds* away (after a 429)."""
        until = self._clock() + max(0.0, float(seconds))
        self._next = until if self._next is None else max(self._next, until)


# ---------------------------------------------------------------------------
# The client
# ---------------------------------------------------------------------------


def _retry_after(headers: Mapping[str, str]) -> int:
    """HIBP's retry-after in whole seconds; a missing or unreadable one counts as the most
    Crawler waits for (MAX_RETRY_AFTER_S), a huge one is clamped."""
    raw = (headers.get("retry-after") or "").strip()
    # ASCII digits only: str.isdigit() also accepts "²", which int() refuses.
    if not (raw.isascii() and raw.isdigit()):
        return MAX_RETRY_AFTER_S
    if len(raw) > 9:
        return _RETRY_AFTER_CLAMP_S
    return min(int(raw), _RETRY_AFTER_CLAMP_S)


_T = TypeVar("_T")


class _AnswerBudget:
    """How long one lookup may wait for HIBP's answers, summed over its requests (the first
    one and a 429's retry). Waiting for the pacer is not counted: a queue in front of the
    lookup, or a 429's retry-after hold (up to MAX_RETRY_AFTER_S + 1 s), is Crawler keeping
    to the key's rate, not HIBP failing to answer. Counting it made a long retry-after end as
    a counted "timeout" instead of the retry or the uncounted rate-limited path. Past the
    budget, asyncio.TimeoutError (the sweeper's "timeout" code). None: no budget."""

    def __init__(self, seconds: Optional[float]) -> None:
        self._left = seconds

    async def run(self, call: Callable[[], Awaitable[_T]]) -> _T:
        if self._left is None:
            return await call()
        if self._left <= 0:
            raise asyncio.TimeoutError
        loop = asyncio.get_running_loop()
        started = loop.time()
        try:
            return await asyncio.wait_for(call(), self._left)
        finally:
            self._left -= loop.time() - started


def _raise_for_status(status: int, *, address_lookup: bool) -> None:
    """Map an HTTP status other than 200 (and 404/429, handled by the caller) to its
    HibpError. The vendor's body is never read into a message."""
    if status == 200:
        return
    if status == 401:
        raise KeyRefused("Have I Been Pwned refused the API key.")
    if status == 400 and address_lookup:
        raise AddressRefused("Have I Been Pwned would not look this address up.")
    if 300 <= status < 400:
        raise BadAnswer(f"Have I Been Pwned answered with a redirect (HTTP {status}).")
    if 200 <= status < 300:
        raise BadAnswer(f"Have I Been Pwned answered HTTP {status}.")
    raise Unavailable(f"Have I Been Pwned answered HTTP {status}.")


def _json(body: bytes) -> Any:
    try:
        return json.loads(body)
    except (ValueError, RecursionError):
        raise BadAnswer("Have I Been Pwned's answer was not JSON.") from None


class HibpClient:
    """One HIBP v3 client per sweeper (the pacer is shared by everything that holds it)."""

    def __init__(
        self,
        *,
        transport: Optional[httpx.AsyncBaseTransport] = None,
        pacer: Optional[Pacer] = None,
        timeout_s: float = TIMEOUT_S,
    ) -> None:
        self._transport = transport
        self.pacer = pacer if pacer is not None else Pacer()
        self._timeout_s = timeout_s

    async def _get(
        self, url: str, api_key: str, params: Optional[dict[str, str]] = None
    ) -> tuple[int, httpx.Headers, bytes]:
        """One guarded GET: (status, headers, body). The body is read only for a 200, streamed
        and capped at MAX_BODY_BYTES (BadAnswer past it)."""
        try:
            client = build_guarded_client(
                timeout_s=self._timeout_s,
                headers={
                    "hibp-api-key": api_key,
                    "user-agent": USER_AGENT,
                    "accept": "application/json",
                },
                resolver=policy_resolver(HIBP_POLICY, POLICY_REFUSAL),
                transport=self._transport,
                follow_redirects=False,
            )
            async with client:
                async with client.stream("GET", url, params=params) as response:
                    status = response.status_code
                    body = b""
                    if status == 200:
                        body = await _read_capped(response, MAX_BODY_BYTES)
                    return status, response.headers, body
        except EgressBlocked:
            raise PolicyRefused(POLICY_REFUSAL) from None
        except httpx.TimeoutException:
            raise Unavailable("Have I Been Pwned did not answer in time.") from None
        except httpx.HTTPError as exc:
            # The type only: an httpx message can carry the URL, and the URL holds the address.
            raise Unavailable(f"The request failed ({type(exc).__name__}).") from None

    async def breaches_for(
        self, address: str, api_key: str, *, deadline_s: Optional[float] = None
    ) -> list[Breach]:
        """GET {API_BASE}/breachedaccount/{quote(address, safe='')}?truncateResponse=false with
        headers hibp-api-key, user-agent, accept: application/json; follow_redirects=False;
        resolver=policy_resolver(HIBP_POLICY, ...). 404 -> []. 429 -> hold(retry-after+1) and
        retry once when retry-after <= MAX_RETRY_AFTER_S, else RateLimited. Other codes map to
        the HibpError subclasses above. Every request first awaits the pacer.

        *deadline_s* bounds the time spent waiting for HIBP's answers, both requests together
        (asyncio.TimeoutError past it). The pacer's waits, a 429's hold included, are outside
        it (``_AnswerBudget``), so a rate limit never reads as "did not answer in time".

        Nothing is sent for an address that is not one plain mailbox address (AddressRefused)
        or a key that is not 32 hex characters (KeyRefused): a malformed .env key must not be
        sent, and only a normalised address may reach the URL path."""
        try:
            normalized = normalize_address(address)
        except AddressRejected:
            raise AddressRefused("Crawler would not look this address up.") from None
        if not key_format_ok(api_key):
            raise KeyRefused("The saved key is not a Have I Been Pwned key.")
        url = f"{API_BASE}/breachedaccount/{quote(normalized, safe='')}"
        params = {"truncateResponse": "false"}
        budget = _AnswerBudget(deadline_s)
        retried = False
        while True:
            await self.pacer.wait()
            status, headers, body = await budget.run(lambda: self._get(url, api_key, params))
            if status != 429:
                break
            retry_after = _retry_after(headers)
            # Hold the shared slot for everyone, then retry once if the wait is short.
            self.pacer.hold(min(retry_after, MAX_RETRY_AFTER_S) + 1)
            logger.info("hibp_rate_limited", retry_after_s=retry_after, retried=retried)
            if retried or retry_after > MAX_RETRY_AFTER_S:
                raise RateLimited(retry_after_s=retry_after)
            retried = True
        if status == 404:
            return []
        _raise_for_status(status, address_lookup=True)
        return parse_breaches(_json(body))

    async def subscription(self, api_key: str) -> tuple[str, int]:
        """GET {API_BASE}/subscription/status -> (SubscriptionName cleaned to 40 chars, Rpm).
        Not paced: it is the key test, which the key routes rate-limit themselves."""
        if not key_format_ok(api_key):
            raise KeyRefused("The key is not a Have I Been Pwned key.")
        status, headers, body = await self._get(f"{API_BASE}/subscription/status", api_key)
        if status == 429:
            raise RateLimited(retry_after_s=_retry_after(headers))
        _raise_for_status(status, address_lookup=False)
        payload = _json(body)
        if not isinstance(payload, dict):
            raise BadAnswer("Have I Been Pwned's answer was not an object.")
        rpm = payload.get("Rpm")
        if isinstance(rpm, bool) or not isinstance(rpm, int) or rpm <= 0:
            raise BadAnswer("Have I Been Pwned's answer had no request rate.")
        return _clean(payload.get("SubscriptionName"), SUBSCRIPTION_NAME_MAX_CHARS), rpm


async def _read_capped(response: httpx.Response, cap: int) -> bytes:
    """The body, refusing (BadAnswer) as soon as it passes *cap* bytes, before it is all read."""
    declared = response.headers.get("content-length", "").strip()
    # The length check first: int() refuses a number past 4,300 digits (ValueError), which
    # would otherwise escape as an unmapped error.
    if declared.isascii() and declared.isdigit() and (len(declared) > 12 or int(declared) > cap):
        raise BadAnswer("Have I Been Pwned's answer was too large.")
    chunks: list[bytes] = []
    total = 0
    async for chunk in response.aiter_bytes():
        total += len(chunk)
        if total > cap:
            raise BadAnswer("Have I Been Pwned's answer was too large.")
        chunks.append(chunk)
    return b"".join(chunks)


async def check_key(
    key: str, *, transport: Optional[httpx.AsyncBaseTransport] = None
) -> KeyTestResult:
    """Test-before-store for the Service keys tab (services/reputation/keys.py, the key
    routes). Calls subscription/status once; never stores, caches or quotes the key.
    200 -> ok, "Key works: <plan> plan, up to <rpm> lookups a minute."
    401 -> "Have I Been Pwned refused that key. Copy it again from haveibeenpwned.com/API/Key."
    429 -> "Have I Been Pwned is rate limiting this key. Try again in a minute."
    other/network -> "Have I Been Pwned could not be reached, so the key was not checked or
    saved. Try again later."
    A key that is not 32 hex characters is refused without being sent."""
    candidate = key.strip() if isinstance(key, str) else ""
    if not key_format_ok(candidate):
        return KeyTestResult(False, KEY_FORMAT_MESSAGE)
    client = HibpClient(transport=transport, timeout_s=KEY_CHECK_TIMEOUT_S)
    try:
        plan, rpm = await client.subscription(candidate)
    except KeyRefused:
        return KeyTestResult(False, KEY_REFUSED_DETAIL)
    except RateLimited:
        return KeyTestResult(False, KEY_RATE_LIMITED_DETAIL)
    except HibpError as exc:
        logger.info("hibp_key_check_failed", code=exc.code, error_type=type(exc).__name__)
        return KeyTestResult(False, KEY_UNREACHABLE_DETAIL)
    if plan:
        return KeyTestResult(True, f"Key works: {plan} plan, up to {rpm} lookups a minute.")
    return KeyTestResult(True, f"Key works: up to {rpm} lookups a minute.")
