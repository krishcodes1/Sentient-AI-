"""Defines BaseConnector and the response-sanitising, rate-limiting and error
types every third-party connector builds on.

Why it exists: Canvas, Google Workspace and Robinhood must scan responses,
throttle requests and honour the network policy the same way; the factory and
the tool executor rely on this shared contract.

Base connector framework for Crawler AI.

Provides abstract base class with built-in content sanitization,
rate limiting, and timeout enforcement for all third-party connectors.
"""

from __future__ import annotations

import asyncio
import email.utils
import functools
import math
import re
import time
from abc import ABC, abstractmethod
from collections import deque
from dataclasses import dataclass
from typing import Any, Awaitable, Callable, Optional
from urllib.parse import quote

import httpcore
import httpx
import structlog

from core.http_pinning import (
    PinnedHTTPTransport,
    PinningUnavailable,
    PinTable,
    pin_for_request,
    pin_key,
)

logger = structlog.get_logger(__name__)


def path_segment(value: Any) -> str:
    """Percent-encode *value* for use as a single URL path segment.

    Identifiers reaching a connector come from tool arguments the model
    chose, which in turn can be shaped by untrusted content the model
    read. Interpolating one raw lets ``../`` or a bare ``/`` inside it
    add path segments, so ``/courses/{id}/assignments`` reaches any
    sibling endpoint on the allowlisted host — outside whatever scopes
    the user granted. ``safe=""`` keeps the separator itself encoded, so
    the value can only ever be one segment.
    """
    return quote(str(value), safe="")

# ---------------------------------------------------------------------------
# Prompt injection / content sanitization
# ---------------------------------------------------------------------------

class PromptGuard:
    """Lightweight scanner that strips common prompt-injection patterns
    from connector response payloads before they reach the LLM layer."""

    _DANGEROUS_PATTERNS: list[re.Pattern[str]] = [
        re.compile(r"ignore\s+(all\s+)?previous\s+instructions", re.IGNORECASE),
        re.compile(r"you\s+are\s+now\s+in\s+developer\s+mode", re.IGNORECASE),
        re.compile(r"system\s*:\s*", re.IGNORECASE),
        re.compile(r"<\s*/?script", re.IGNORECASE),
        re.compile(r"javascript\s*:", re.IGNORECASE),
        re.compile(r"data\s*:\s*text/html", re.IGNORECASE),
        re.compile(r"\bdo\s+not\s+follow\s+safety\b", re.IGNORECASE),
        re.compile(r"\boverride\s+instructions\b", re.IGNORECASE),
        re.compile(r"\bact\s+as\s+(root|admin|sudo)\b", re.IGNORECASE),
    ]

    @classmethod
    def scan(cls, payload: Any) -> tuple[Any, bool]:
        """Recursively scan *payload* and redact dangerous strings.

        Returns ``(cleaned_payload, was_modified)``.
        """
        modified = False
        if isinstance(payload, str):
            cleaned = payload
            for pat in cls._DANGEROUS_PATTERNS:
                cleaned, n = pat.subn("[REDACTED]", cleaned)
                if n:
                    modified = True
            return cleaned, modified
        if isinstance(payload, dict):
            out: dict[str, Any] = {}
            for k, v in payload.items():
                cleaned_v, m = cls.scan(v)
                out[k] = cleaned_v
                modified = modified or m
            return out, modified
        if isinstance(payload, list):
            out_list: list[Any] = []
            for item in payload:
                cleaned_item, m = cls.scan(item)
                out_list.append(cleaned_item)
                modified = modified or m
            return out_list, modified
        return payload, False


# ---------------------------------------------------------------------------
# Rate limiter
# ---------------------------------------------------------------------------

class RateLimiter:
    """Sliding-window rate limiter tracking calls per minute."""

    def __init__(self, max_calls_per_minute: int = 60) -> None:
        self.max_calls = max_calls_per_minute
        self._timestamps: deque[float] = deque()

    def acquire(self) -> None:
        """Block-free check. Raises if rate limit exceeded."""
        now = time.monotonic()
        # Purge timestamps older than 60 s
        while self._timestamps and (now - self._timestamps[0]) > 60.0:
            self._timestamps.popleft()
        if len(self._timestamps) >= self.max_calls:
            raise RateLimitExceededError(
                f"Rate limit of {self.max_calls} calls/min exceeded. "
                f"Retry after {60.0 - (now - self._timestamps[0]):.1f}s."
            )
        self._timestamps.append(now)

    @property
    def remaining(self) -> int:
        now = time.monotonic()
        while self._timestamps and (now - self._timestamps[0]) > 60.0:
            self._timestamps.popleft()
        return max(0, self.max_calls - len(self._timestamps))


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------

class ConnectorError(Exception):
    """Base exception for all connector errors.

    ``status_code`` and ``vendor_code`` are set by ``http_error_for`` (the
    HTTP status and the short vendor error code it validated) so callers
    branch on them instead of parsing the message; both are ``None`` for
    errors that did not come from an HTTP response.
    """

    status_code: Optional[int] = None
    vendor_code: Optional[str] = None

    def __init__(
        self,
        *args: object,
        status_code: Optional[int] = None,
        vendor_code: Optional[str] = None,
    ) -> None:
        super().__init__(*args)
        self.status_code = status_code
        self.vendor_code = vendor_code


class AuthenticationError(ConnectorError):
    """Raised when authentication fails."""


class RateLimitExceededError(ConnectorError):
    """Raised when the rate limit is exceeded."""


class UserConfirmationRequired(ConnectorError):
    """Raised when an action requires explicit user confirmation before execution."""

    def __init__(self, action: str, details: str) -> None:
        self.action = action
        self.details = details
        super().__init__(f"USER_CONFIRM required for '{action}': {details}")


class HardBlockError(ConnectorError):
    """Raised for permanently blocked actions that can never be executed."""

    def __init__(self, action: str, reason: Optional[str] = None) -> None:
        self.action = action
        self.reason = reason or "This action is permanently blocked by security policy."
        super().__init__(f"HARD_BLOCK: '{action}' - {self.reason}")


# ---------------------------------------------------------------------------
# Response dataclass
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class ConnectorResponse:
    """Standardised response from any connector action."""

    success: bool
    data: dict[str, Any]
    sanitized: bool
    execution_time_ms: float


@dataclass(frozen=True)
class BoundedBody:
    """A 2xx response body read by ``BaseConnector._request_bytes``.

    ``content`` holds at most the requested number of bytes (the start of
    the body, or its end for a tail read); ``truncated`` says the body was
    longer and the rest was never kept in memory.
    """

    content: bytes
    truncated: bool
    status_code: int
    headers: httpx.Headers


# ---------------------------------------------------------------------------
# HTTP error mapping and retry rules
# ---------------------------------------------------------------------------

# The longest Retry-After (seconds) honoured in-line. Anything longer is
# reported to the model instead of stalling the turn.
MAX_RETRY_AFTER_S = 10.0
# Backoff before retrying a gateway error or a failed connect.
TRANSIENT_BACKOFF_S = 0.5
# Wait before retrying a 429 that names no Retry-After.
DEFAULT_RATE_LIMIT_BACKOFF_S = 1.0
# Bytes of a streamed error body read to find its vendor code.
MAX_ERROR_BODY_BYTES = 16_384

# Methods a retry cannot duplicate: repeating them leaves the provider in
# the same state as sending them once.
IDEMPOTENT_METHODS = frozenset({"GET", "HEAD", "OPTIONS", "PUT", "DELETE"})

# Headers that always carry a credential, whatever a connector declares.
_ALWAYS_CREDENTIAL_HEADERS = frozenset({"authorization", "proxy-authorization", "cookie"})
# Generic headers that never carry one. httpx sends several on every
# request, so none of them may mark a request as credentialed (that would
# shut every download host), and their values are never treated as secrets.
NON_CREDENTIAL_HEADERS = frozenset(
    {
        "accept",
        "accept-encoding",
        "accept-language",
        "connection",
        "content-length",
        "content-type",
        "host",
        "user-agent",
    }
)

# Vendor error codes are echoed only in this shape: short, one token, no
# spaces. Free text never is (a vendor error body can quote the request,
# including a token).
_VENDOR_CODE_RE = re.compile(r"^[A-Za-z0-9_.:-]{1,64}$")
# Codes shaped like a credential are dropped even when they match above.
_TOKEN_LIKE_RE = re.compile(
    r"^(xox[a-z]-|xapp-|gh[opusr]_|github_pat_|secret_|ntn_|ya29\.|1//|"
    r"gocspx-|sk-|bearer|eyj)",
    re.IGNORECASE,
)

_STATUS_HINTS: dict[int, str] = {
    403: "missing permission or scope",
    404: "not found",
    409: "conflict with the current state",
}


def _overlaps_secret(candidate: str, secrets: tuple[str, ...]) -> bool:
    lowered = candidate.lower()
    for secret in secrets:
        value = secret.strip().lower()
        if len(value) < 4:
            continue
        if lowered in value or value in lowered:
            return True
        # "Bearer <token>": compare the credential itself too.
        token = value.rsplit(" ", 1)[-1]
        if len(token) >= 4 and (lowered in token or token in lowered):
            return True
    return False


def _vendor_error_code(
    response: httpx.Response, secrets: tuple[str, ...] = ()
) -> Optional[str]:
    """A short machine-readable error code from a JSON error body, if any.

    Tried in order: ``error`` (a string), ``error.code``, ``error.status``,
    ``code``, ``errors[0].code``. Only string values matching
    ``_VENDOR_CODE_RE`` qualify, and a candidate that looks like a credential
    or overlaps one of *secrets* (the connector's own header values) is
    dropped. Nothing else from the body is ever used.
    """
    try:
        body = response.json()
    except (ValueError, UnicodeDecodeError, httpx.ResponseNotRead):
        return None
    if not isinstance(body, dict):
        return None
    candidates: list[Any] = []
    error = body.get("error")
    if isinstance(error, str):
        candidates.append(error)
    elif isinstance(error, dict):
        candidates.extend((error.get("code"), error.get("status")))
    candidates.append(body.get("code"))
    errors = body.get("errors")
    if isinstance(errors, list) and errors and isinstance(errors[0], dict):
        candidates.append(errors[0].get("code"))
    for candidate in candidates:
        if (
            isinstance(candidate, str)
            and _VENDOR_CODE_RE.fullmatch(candidate)
            and not _TOKEN_LIKE_RE.match(candidate)
            and not _overlaps_secret(candidate, secrets)
        ):
            return candidate
    return None


def parse_retry_after(value: Optional[str], *, now: Optional[float] = None) -> Optional[float]:
    """Seconds to wait from a ``Retry-After`` header, or ``None``.

    Accepts both forms RFC 9110 allows: delay-seconds and an HTTP date.
    A date in the past means "now" (0). Unparseable values count as absent.
    """
    if value is None:
        return None
    text = value.strip()
    if not text:
        return None
    try:
        seconds = float(text)
    except ValueError:
        try:
            when = email.utils.parsedate_to_datetime(text)
        except (TypeError, ValueError, IndexError):
            return None
        if when is None:
            return None
        current = time.time() if now is None else now
        seconds = when.timestamp() - current
    if math.isnan(seconds) or math.isinf(seconds):
        return None
    return max(0.0, seconds)


def is_rate_limited(response: httpx.Response) -> bool:
    """429, or a 403 that is really a rate limit (GitHub's primary and
    secondary limits answer 403 with ``Retry-After`` or
    ``x-ratelimit-remaining: 0``)."""
    if response.status_code == 429:
        return True
    if response.status_code != 403:
        return False
    headers = response.headers
    return "retry-after" in headers or headers.get("x-ratelimit-remaining", "").strip() == "0"


def rate_limit_wait(response: httpx.Response, *, now: Optional[float] = None) -> Optional[float]:
    """Seconds the provider asked us to wait, or ``None`` when it did not say.

    ``Retry-After`` wins; GitHub's ``x-ratelimit-reset`` (epoch seconds)
    is the fallback when the remaining quota is exhausted.
    """
    wait = parse_retry_after(response.headers.get("retry-after"), now=now)
    if wait is not None:
        return wait
    if response.headers.get("x-ratelimit-remaining", "").strip() == "0":
        reset = response.headers.get("x-ratelimit-reset", "").strip()
        try:
            reset_at = float(reset)
        except ValueError:
            return None
        current = time.time() if now is None else now
        return max(0.0, reset_at - current)
    return None


def http_error_for(
    name: str, response: httpx.Response, *, secrets: tuple[str, ...] = ()
) -> ConnectorError:
    """Map a non-2xx *response* to the exception the executor branches on.

    The message is ``HTTP <status> from <name>``, then ``(<vendor code>)``
    when the body carries a short code, then a fixed hint. The response
    body text is never included: vendors echo request data (including
    tokens) in error bodies, and this string reaches the model, the
    audit log and the chat.

    The returned error also carries ``status_code`` and ``vendor_code``
    (``None`` when the body had no qualifying code) as attributes.
    """
    status = response.status_code
    code = _vendor_error_code(response, secrets)
    head = f"HTTP {status} from {name}" + (f" ({code})" if code else "")
    fields: dict[str, Any] = {"status_code": status, "vendor_code": code}

    if status == 401:
        return AuthenticationError(
            f"{head}: the credentials were rejected. Reconnect {name} in Connectors.",
            **fields,
        )
    if is_rate_limited(response):
        wait = rate_limit_wait(response)
        after = f" Retry after {math.ceil(wait)} s." if wait is not None else ""
        return RateLimitExceededError(f"{head}: rate limited by the provider.{after}", **fields)
    if status == 403:
        return AuthenticationError(f"{head}: {_STATUS_HINTS[403]}.", **fields)
    if status in _STATUS_HINTS:
        return ConnectorError(f"{head}: {_STATUS_HINTS[status]}.", **fields)
    if status >= 500:
        wait = parse_retry_after(response.headers.get("retry-after"))
        after = f" Retry after {math.ceil(wait)} s." if wait is not None else ""
        return ConnectorError(f"{head}: provider error, try again later.{after}", **fields)
    if 300 <= status < 400:
        return ConnectorError(f"{head}: unexpected redirect.", **fields)
    return ConnectorError(f"{head}: the request was rejected.", **fields)


async def _buffered_error(response: httpx.Response) -> httpx.Response:
    """A closed, in-memory copy of a streamed non-2xx *response*.

    Reads at most ``MAX_ERROR_BODY_BYTES`` of the body (enough for a vendor
    error code) so ``http_error_for`` and the retry rules see the same
    status, headers and JSON they would on a normal request. A body that
    fails mid-read is dropped: the status alone is mapped.
    """
    body = bytearray()
    try:
        async for chunk in response.aiter_bytes():
            body += chunk
            if len(body) >= MAX_ERROR_BODY_BYTES:
                break
    except httpx.HTTPError:
        body.clear()
    finally:
        await response.aclose()
    # The copy holds decoded bytes, so the framing headers no longer apply.
    headers = [
        (key, value)
        for key, value in response.headers.multi_items()
        if key.lower() not in ("content-encoding", "content-length", "transfer-encoding")
    ]
    return httpx.Response(
        response.status_code,
        headers=headers,
        content=bytes(body[:MAX_ERROR_BODY_BYTES]),
        request=response.request,
    )


# ---------------------------------------------------------------------------
# Abstract base connector
# ---------------------------------------------------------------------------

class BaseConnector(ABC):
    """Abstract base class for all Crawler AI connectors.

    Subclasses MUST implement the abstract properties/methods.  The base
    class provides automatic content sanitization via ``PromptGuard``,
    sliding-window rate limiting, and ``httpx`` async client management
    with configurable timeout.
    """

    DEFAULT_TIMEOUT_S: float = 30.0
    DEFAULT_RATE_LIMIT: int = 60  # calls per minute
    # True when ``revoke`` really calls the provider. Deleting a connector
    # schedules a revoke only for these classes; the registry checks that a
    # class declaring it also overrides ``revoke``.
    SUPPORTS_REVOKE: bool = False

    def __init__(
        self,
        timeout_s: Optional[float] = None,
        rate_limit: Optional[int] = None,
    ) -> None:
        self._timeout = timeout_s or self.DEFAULT_TIMEOUT_S
        self._rate_limiter = RateLimiter(rate_limit or self.DEFAULT_RATE_LIMIT)
        self._authenticated = False
        self._http_client: httpx.AsyncClient | None = None
        self._network_policy_key: Optional[str] = None
        self._policy_extra_hosts: tuple[str, ...] = ()
        # (host, port) -> addresses the policy check validated; the pinned
        # transport dials only these. Bounded by the allowlist's origins.
        self._pins: PinTable = {}
        # Test seam: the httpcore socket layer under the pinned resolver.
        self._network_backend: Optional[httpcore.AsyncNetworkBackend] = None
        # Test seam: retries wait through this, so tests never sleep.
        self._sleep: Callable[[float], Awaitable[None]] = asyncio.sleep
        self._log = logger.bind(connector=self.name)

    # -- Network policy --------------------------------------------------------

    def set_network_policy(
        self, policy_key: str, *, extra_hosts: tuple[str, ...] = ()
    ) -> None:
        """Enable deny-by-default outbound filtering for this connector.

        Every HTTP request issued through ``_get_client()`` is validated
        against ``core.network_security.DEFAULT_POLICIES[policy_key]`` plus
        the SSRF ranges, and the socket is pinned to the addresses that
        check validated. Redirects are not followed unless a call opts in
        (``_request(..., follow_redirects=True)``); each hop then runs the
        same hook. Must be called before the first request: a connector
        with no policy refuses every request.

        ``extra_hosts`` are the hosts the user configured for this specific
        connector (a self-hosted Canvas domain, say). They widen the host
        allowlist by exactly those names and nothing else, and remain
        subject to the SSRF address policy.
        """
        self._network_policy_key = policy_key
        self._policy_extra_hosts = tuple(extra_hosts)

    def _credential_header_names(self) -> set[str]:
        """Lower-cased names of every header that carries our credentials.

        The fixed credential names, plus whatever ``_auth_headers()`` names,
        minus the generic headers in ``NON_CREDENTIAL_HEADERS``. httpx sends
        some of those (``Accept``) on every request, so counting one would
        refuse every download host even for an ``authorized=False`` call.
        ``_static_headers()`` names are never counted.
        """
        names = set(_ALWAYS_CREDENTIAL_HEADERS)
        try:
            names.update(key.lower() for key in self._auth_headers())
        except Exception:  # noqa: BLE001 - a half-configured connector
            # cannot name its headers; the fixed set above still applies.
            pass
        return names - NON_CREDENTIAL_HEADERS

    async def _enforce_network_policy(self, request: httpx.Request) -> None:
        """Request hook: allowlist check off the event loop, then pin.

        Fails closed when no policy key is set. The check (which resolves
        DNS) runs in a worker thread, and the addresses it validated become
        the only ones the pinned transport may dial for that origin. An
        origin this instance already pinned (the next page of a listing,
        the items of a fan-out) is not resolved again: the host, path and
        method rules still run on every request, and the socket still dials
        only the pinned addresses.
        """
        if not self._network_policy_key:
            self._log.warning("network_policy_missing", host=request.url.host)
            raise ConnectorError(
                f"Outbound request refused: no network policy is set for {self.name}."
            )
        from core.network_security import check_network_policy

        credential_headers = self._credential_header_names()
        has_authorization = any(name in request.headers for name in credential_headers)
        resolve = pin_key(request) not in self._pins
        check = functools.partial(
            check_network_policy,
            str(request.url),
            self._network_policy_key,
            extra_hosts=self._policy_extra_hosts,
            method=request.method,
            has_authorization=has_authorization,
            resolve=resolve,
        )
        result = await asyncio.to_thread(check) if resolve else check()
        if not result.safe:
            # Host and path only: a query string can carry a token.
            self._log.warning(
                "network_policy_blocked",
                host=request.url.host,
                path=request.url.path,
                method=request.method,
                policy=self._network_policy_key,
                reason=result.reason,
            )
            raise ConnectorError(
                f"Outbound request blocked by network policy: {result.reason}"
            )
        pin_for_request(self._pins, request, result.resolved_ips)

    # -- Properties (abstract) -----------------------------------------------

    @property
    @abstractmethod
    def name(self) -> str:
        """Human-readable connector name."""
        ...

    @property
    @abstractmethod
    def connector_type(self) -> str:
        """Category string, e.g. 'lms', 'email', 'finance'."""
        ...

    @property
    @abstractmethod
    def required_scopes(self) -> list[str]:
        """Minimum scopes needed for this connector to operate."""
        ...

    # -- Abstract methods ----------------------------------------------------

    @abstractmethod
    async def authenticate(self, credentials: dict[str, Any]) -> bool:
        """Authenticate against the third-party service.

        Must set ``self._authenticated = True`` on success and return True.
        """
        ...

    @abstractmethod
    async def _execute_action(self, action: str, params: dict[str, Any]) -> dict[str, Any]:
        """Connector-specific action dispatch (called by ``execute``)."""
        ...

    @abstractmethod
    async def health_check(self) -> bool:
        """Return True if the upstream service is reachable and healthy."""
        ...

    # -- Registry hooks --------------------------------------------------------
    #
    # The registry-driven factory (services/connectors/factory.py) builds
    # every connector through these, so a connector file needs no factory
    # edit. The defaults suit a connector that reads its token in
    # authenticate() and has nothing user-configured to validate.

    #: Action names ``_dispatch`` will route. A connector sets this from the
    #: same ToolSpec tuple its DEFINITION lists, so the catalog and the
    #: dispatch allow-map cannot drift apart.
    _ACTIONS: frozenset[str] = frozenset()

    @classmethod
    def from_credentials(
        cls, credentials: dict[str, Any], *, timeout_s: Optional[float] = None
    ) -> BaseConnector:
        """Build an instance from stored credentials (not yet authenticated)."""
        return cls(timeout_s=timeout_s)

    @classmethod
    def validate_credentials(cls, credentials: dict[str, Any]) -> list[str]:
        """Connector-specific credential problems beyond missing fields."""
        return []

    @property
    def policy_extra_hosts(self) -> tuple[str, ...]:
        """User-configured hosts to add to the network allowlist (Canvas)."""
        return ()

    def updated_credentials(self, original: dict[str, Any]) -> dict[str, Any] | None:
        """Credentials to persist when this session rotated a token, else None."""
        return None

    async def revoke(self) -> bool:
        """Best-effort revoke of the stored grant at the provider.

        Returns False when the provider offers no revoke endpoint. Called
        only after the connector row has been deleted and committed, and
        only for classes that set ``SUPPORTS_REVOKE``.
        """
        return False

    async def _dispatch(self, action: str, params: dict[str, Any]) -> dict[str, Any]:
        """Route *action* to the public coroutine of the same name.

        Only names in ``_ACTIONS`` are reachable, so a model-chosen action
        string can never call a private or inherited method. A list result
        is wrapped as ``{"items": [...], "count": n}`` so per-item
        redaction and the result budget treat every connector alike.
        """
        if action not in self._ACTIONS:
            raise ConnectorError(f"Unknown {self.name} action: {action}")
        result = await getattr(self, action)(**params)
        if isinstance(result, list):
            return {"items": result, "count": len(result)}
        return result

    # -- Concrete helpers ----------------------------------------------------

    # NOTE: scope enforcement is NOT done here. The authoritative check is
    # ConnectorToolExecutor._check_scope (services/agent/tool_registry.py),
    # which validates the catalog's short scope names (e.g. "gmail.read")
    # against the scopes granted on the ConnectorConfig row.

    async def execute(self, action: str, params: dict[str, Any]) -> ConnectorResponse:
        """Public entry point.  Enforces rate limiting, timeout, and
        sanitization around every action."""
        if not self._authenticated:
            raise AuthenticationError(f"Connector '{self.name}' is not authenticated.")

        self._rate_limiter.acquire()
        start = time.perf_counter()

        try:
            raw = await self._execute_action(action, params)
        except (UserConfirmationRequired, HardBlockError, AuthenticationError):
            # These three carry semantics the executor branches on
            # (ConnectorToolExecutor._dispatch): approval, permanent block,
            # and "re-auth needed". Collapsing them into ConnectorError would
            # strand the caller with an undifferentiated failure — an
            # AuthenticationError raised inside _execute_action (e.g. a
            # refresh attempted with no refresh token) must survive too.
            raise
        except httpx.TimeoutException:
            raise ConnectorError(f"Request timed out after {self._timeout}s")
        except httpx.HTTPStatusError as exc:
            # Legacy ``raise_for_status`` paths share the mapping _request
            # uses: status, vendor code and a fixed hint, never the body
            # (a vendor error body can echo a token). 401/403 stay
            # AuthenticationError so the UI can offer re-authorisation; 429
            # is RateLimitExceededError; an outage stays ConnectorError.
            # ``from None``: the httpx message carries the full URL, and a
            # query string can carry a token.
            raise http_error_for(
                self.name, exc.response, secrets=self._secret_values()
            ) from None
        except ConnectorError:
            # Already a safe, typed message (RateLimitExceededError from
            # _request, a policy refusal, ...). Re-wrapping would drop the
            # subclass the executor branches on.
            raise
        except Exception as exc:
            # Only the type: an unexpected error's text can quote a URL, a
            # header or a token, and this message reaches the model, the
            # audit trail and the chat.
            error_type = type(exc).__name__
            self._log.error("connector_execute_error", action=action, error_type=error_type)
            raise ConnectorError(f"{self.name} failed ({error_type}).") from exc

        elapsed_ms = (time.perf_counter() - start) * 1000.0

        sanitized_data, was_modified = PromptGuard.scan(raw)
        if was_modified:
            self._log.warning("content_sanitized", action=action)

        return ConnectorResponse(
            success=True,
            data=sanitized_data,
            sanitized=was_modified,
            execution_time_ms=round(elapsed_ms, 2),
        )

    # -- HTTP helpers ------------------------------------------------------------

    def _auth_headers(self) -> dict[str, str]:
        """Secret-bearing headers that authenticate a request. Connectors
        override this.

        Merged into every ``_request`` call made with ``authorized=True``.
        Put ONLY credentials here (``Authorization``, an API key header):
        every name returned counts as a credential for the network policy,
        so a request carrying one can never reach a download host, and the
        values are scrubbed from error codes. Non-secret per-request headers
        (``Accept``, ``X-GitHub-Api-Version``, ``Notion-Version``) belong in
        ``_static_headers()``; left here they would shut the download hosts
        a redirect-following call needs.
        """
        return {}

    def _static_headers(self) -> dict[str, str]:
        """Non-secret headers sent on EVERY ``_request`` call. Connectors
        override this.

        For API versions and media types (GitHub ``Accept`` and
        ``X-GitHub-Api-Version``, ``Notion-Version``). They are sent with
        ``authorized=False`` too, including to a pre-signed download host,
        and are never counted as credentials, so nothing secret may go here.
        """
        return {}

    def _secret_values(self) -> tuple[str, ...]:
        try:
            return tuple(
                str(value)
                for key, value in self._auth_headers().items()
                if value and key.lower() not in NON_CREDENTIAL_HEADERS
            )
        except Exception:  # noqa: BLE001 - nothing to scrub is a safe answer
            return ()

    async def _request(
        self,
        method: str,
        url: str,
        *,
        params: Any = None,
        json: Any = None,
        data: Any = None,
        content: Any = None,
        headers: Optional[dict[str, str]] = None,
        authorized: bool = True,
        follow_redirects: bool = False,
        stream: bool = False,
    ) -> httpx.Response:
        """Send one request through the policy-checked, pinned client.

        Returns only a 2xx response; anything else raises the mapped
        error (see ``http_error_for``). With ``stream=True`` the returned
        response's body is not read yet and the caller must close it
        (``_request_bytes`` is the only caller). At most one retry:

        - 429 (and a 403 that is really a rate limit): after ``Retry-After``
          when it is 10 s or less, else ``RateLimitExceededError`` naming
          the wait. A rate-limited request was not processed, so any
          method may retry.
        - 502, 503, 504, connect errors and connect timeouts: idempotent
          methods only (a POST that reached the provider must not run
          twice), after a short backoff or a short ``Retry-After``. A
          gateway error asking for a longer wait is reported as a provider
          error (naming the wait), not as a rate limit.
        - Every other status, and read timeouts, fail at once.

        Headers merge case-insensitively, later winning:
        ``_static_headers()``, then ``_auth_headers()`` (only when
        ``authorized``), then *headers*. ``authorized=False`` omits the
        credentials (pre-signed download URLs). ``follow_redirects=True``
        lets a download follow up to ``MAX_REDIRECTS`` redirects; every hop
        is re-checked by the policy hook.
        """
        verb = method.upper()
        request_headers = httpx.Headers(self._static_headers())
        if authorized:
            request_headers.update(self._auth_headers())
        if headers:
            request_headers.update(headers)

        client = self._get_client()
        for attempt in range(2):
            last_attempt = attempt == 1
            try:
                request = client.build_request(
                    verb,
                    url,
                    params=params,
                    json=json,
                    data=data,
                    content=content,
                    headers=request_headers,
                )
                response = await client.send(
                    request, stream=stream, follow_redirects=follow_redirects
                )
            except httpx.ConnectTimeout:
                if last_attempt or verb not in IDEMPOTENT_METHODS:
                    raise ConnectorError(
                        f"Could not connect to {self.name}: connection timed out."
                    ) from None
                await self._sleep(TRANSIENT_BACKOFF_S)
                continue
            except httpx.TimeoutException:
                raise ConnectorError(
                    f"Request to {self.name} timed out after {self._timeout}s."
                ) from None
            except httpx.ConnectError:
                if last_attempt or verb not in IDEMPOTENT_METHODS:
                    raise ConnectorError(f"Could not connect to {self.name}.") from None
                await self._sleep(TRANSIENT_BACKOFF_S)
                continue
            except httpx.TooManyRedirects:
                raise ConnectorError(f"Too many redirects from {self.name}.") from None
            except httpx.HTTPError as exc:
                # Protocol or transport failure. The type name is enough to
                # diagnose; httpx messages can quote the URL.
                raise ConnectorError(
                    f"Network error talking to {self.name} ({type(exc).__name__})."
                ) from None

            if response.is_success:
                return response
            if stream:
                response = await _buffered_error(response)
            wait = None if last_attempt else self._retry_wait(verb, response)
            if wait is None:
                raise http_error_for(self.name, response, secrets=self._secret_values())
            self._log.info(
                "connector_request_retry",
                status=response.status_code,
                method=verb,
                wait_s=round(wait, 2),
            )
            await self._sleep(wait)
        # Unreachable: the second attempt always returns or raises.
        raise ConnectorError(f"Request to {self.name} failed.")

    def _retry_wait(self, method: str, response: httpx.Response) -> Optional[float]:
        """Seconds to wait before the single retry, or ``None`` for no retry.

        ``None`` hands the response to ``http_error_for``, which picks the
        error type from the response alone: a real rate limit asking for
        more than ``MAX_RETRY_AFTER_S`` becomes ``RateLimitExceededError``
        naming the wait (stalling the turn is worse than telling the model
        when to try again), while a gateway error stays a provider error
        whatever its ``Retry-After`` and whatever the method.
        """
        if is_rate_limited(response):
            wait = rate_limit_wait(response)
            if wait is None:
                return DEFAULT_RATE_LIMIT_BACKOFF_S
            return wait if wait <= MAX_RETRY_AFTER_S else None
        if response.status_code not in (502, 503, 504) or method not in IDEMPOTENT_METHODS:
            return None
        wait = parse_retry_after(response.headers.get("retry-after"))
        if wait is None:
            return TRANSIENT_BACKOFF_S
        return wait if wait <= MAX_RETRY_AFTER_S else None

    async def _request_json(self, method: str, url: str, **kwargs: Any) -> Any:
        """``_request`` then decode JSON. 204 or an empty body gives ``{}``."""
        response = await self._request(method, url, **kwargs)
        if response.status_code == 204 or not response.content.strip():
            return {}
        try:
            return response.json()
        except ValueError:  # JSONDecodeError and UnicodeDecodeError both
            raise ConnectorError(f"Malformed response from {self.name}.") from None

    async def _request_bytes(
        self,
        method: str,
        url: str,
        *,
        max_bytes: int,
        tail: bool = False,
        params: Any = None,
        headers: Optional[dict[str, str]] = None,
        authorized: bool = True,
        follow_redirects: bool = False,
    ) -> BoundedBody:
        """``_request`` for a download of which only *max_bytes* are kept.

        The body is streamed, so a many-megabyte file or log never sits in
        memory whole. A head read (the default) stops downloading once it
        has more than *max_bytes*; a tail read (``tail=True``) keeps a
        rolling window of the last *max_bytes*. Same policy checks, retry
        and error mapping as ``_request``; a timeout or transport failure
        while reading the body is a ``ConnectorError`` too.
        """
        if max_bytes < 1:
            raise ValueError("max_bytes must be positive")
        response = await self._request(
            method,
            url,
            params=params,
            headers=headers,
            authorized=authorized,
            follow_redirects=follow_redirects,
            stream=True,
        )
        kept = bytearray()
        seen = 0
        try:
            async for chunk in response.aiter_bytes():
                seen += len(chunk)
                if tail:
                    kept += chunk
                    if len(kept) > 2 * max_bytes:
                        del kept[: len(kept) - max_bytes]
                else:
                    kept += chunk[: max_bytes + 1 - len(kept)]
                    if len(kept) > max_bytes:
                        break
        except httpx.TimeoutException:
            raise ConnectorError(
                f"Request to {self.name} timed out after {self._timeout}s."
            ) from None
        except httpx.HTTPError as exc:
            raise ConnectorError(
                f"Network error talking to {self.name} ({type(exc).__name__})."
            ) from None
        finally:
            await response.aclose()
        content = bytes(kept[-max_bytes:] if tail else kept[:max_bytes])
        return BoundedBody(
            content=content,
            truncated=seen > max_bytes,
            status_code=response.status_code,
            headers=response.headers,
        )

    # -- HTTP client management ----------------------------------------------

    #: Redirect hops a download may follow when a call opts in.
    MAX_REDIRECTS: int = 3

    def _get_client(self, **kwargs: Any) -> httpx.AsyncClient:
        """Return a shared ``httpx.AsyncClient``, lazily created.

        The client dials through ``PinnedHTTPTransport``: the request hook
        (``_enforce_network_policy``) validates each outbound URL, including
        every redirect hop of a call that opted into following them, and
        pins the addresses it validated, so DNS is resolved once per
        request and the socket lands on what was checked. Redirects are
        off by default and capped at ``MAX_REDIRECTS`` when a call turns
        them on. ``kwargs`` (``base_url``, extra ``event_hooks``,
        ``network_backend`` for tests) apply on first creation only. A
        client injected into ``_http_client`` (the test seam) is returned
        as is.
        """
        if self._http_client is None or self._http_client.is_closed:
            if "transport" in kwargs:
                raise ConnectorError(
                    "A custom transport would bypass DNS pinning; refusing it."
                )
            network_backend = kwargs.pop("network_backend", self._network_backend)
            try:
                transport = PinnedHTTPTransport(self._pins, network_backend)
            except PinningUnavailable as exc:
                # A refusal, never a fallback to an unpinned client.
                raise ConnectorError(f"Outbound request refused: {exc}") from None
            event_hooks = kwargs.pop("event_hooks", {})
            request_hooks = list(event_hooks.get("request", []))
            request_hooks.append(self._enforce_network_policy)
            event_hooks["request"] = request_hooks
            kwargs.setdefault("follow_redirects", False)
            kwargs.setdefault("max_redirects", self.MAX_REDIRECTS)
            self._http_client = httpx.AsyncClient(
                timeout=httpx.Timeout(self._timeout),
                transport=transport,
                event_hooks=event_hooks,
                **kwargs,
            )
        return self._http_client

    async def close(self) -> None:
        """Cleanly shut down the HTTP client."""
        if self._http_client and not self._http_client.is_closed:
            await self._http_client.aclose()
            self._http_client = None
