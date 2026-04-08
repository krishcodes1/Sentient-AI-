"""
Base connector framework for SentientAI.

Provides abstract base class with built-in content sanitization,
rate limiting, and timeout enforcement for all third-party connectors.
"""

from __future__ import annotations

import re
import time
from abc import ABC, abstractmethod
from collections import deque
from dataclasses import dataclass, field
from typing import Any, Optional

import httpx
import structlog

logger = structlog.get_logger(__name__)

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
    """Base exception for all connector errors."""


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


# ---------------------------------------------------------------------------
# Abstract base connector
# ---------------------------------------------------------------------------

class BaseConnector(ABC):
    """Abstract base class for all SentientAI connectors.

    Subclasses MUST implement the abstract properties/methods.  The base
    class provides automatic content sanitization via ``PromptGuard``,
    sliding-window rate limiting, and ``httpx`` async client management
    with configurable timeout.
    """

    DEFAULT_TIMEOUT_S: float = 30.0
    DEFAULT_RATE_LIMIT: int = 60  # calls per minute

    def __init__(
        self,
        timeout_s: Optional[float] = None,
        rate_limit: Optional[int] = None,
    ) -> None:
        self._timeout = timeout_s or self.DEFAULT_TIMEOUT_S
        self._rate_limiter = RateLimiter(rate_limit or self.DEFAULT_RATE_LIMIT)
        self._authenticated = False
        self._http_client: httpx.AsyncClient | None = None
        self._log = logger.bind(connector=self.name)

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

    # -- Concrete helpers ----------------------------------------------------

    async def validate_scopes(self, requested: list[str]) -> bool:
        """Return True when every *requested* scope is in ``required_scopes``."""
        allowed = set(self.required_scopes)
        return all(s in allowed for s in requested)

    async def execute(self, action: str, params: dict[str, Any]) -> ConnectorResponse:
        """Public entry point.  Enforces rate limiting, timeout, and
        sanitization around every action."""
        if not self._authenticated:
            raise AuthenticationError(f"Connector '{self.name}' is not authenticated.")

        self._rate_limiter.acquire()
        start = time.perf_counter()

        try:
            raw = await self._execute_action(action, params)
        except (UserConfirmationRequired, HardBlockError):
            raise
        except httpx.TimeoutException:
            raise ConnectorError(f"Request timed out after {self._timeout}s")
        except httpx.HTTPStatusError as exc:
            raise ConnectorError(
                f"HTTP {exc.response.status_code} from {self.name}: {exc.response.text[:300]}"
            )
        except Exception as exc:
            self._log.error("connector_execute_error", action=action, error=str(exc))
            raise ConnectorError(str(exc)) from exc

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

    # -- HTTP client management ----------------------------------------------

    def _get_client(self, **kwargs: Any) -> httpx.AsyncClient:
        """Return a shared ``httpx.AsyncClient``, lazily created."""
        if self._http_client is None or self._http_client.is_closed:
            self._http_client = httpx.AsyncClient(
                timeout=httpx.Timeout(self._timeout),
                **kwargs,
            )
        return self._http_client

    async def close(self) -> None:
        """Cleanly shut down the HTTP client."""
        if self._http_client and not self._http_client.is_closed:
            await self._http_client.aclose()
            self._http_client = None
