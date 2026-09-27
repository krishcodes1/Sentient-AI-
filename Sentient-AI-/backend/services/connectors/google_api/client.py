"""Shared plumbing for the Google Workspace connector: the stored tokens, token
refresh, the single request helper every action uses, argument validation and
text helpers.

Why it exists: every Gmail, Calendar, Drive, Docs, Sheets and People call must
carry the same bearer token, go through the base connector's pinned,
policy-checked ``_request`` (retry, redacted errors), and survive an expired
access token by refreshing it once. Keeping that here means the per-API mixins
(``gmail.py``, ``calendar.py``, ...) only describe endpoints and shaping.

External service: Google's OAuth token endpoint (https://oauth2.googleapis.com/token)
for refresh. Depends on ``services.connectors.base`` (HTTP helpers, errors) and
``shaping`` (text caps).
"""

from __future__ import annotations

import asyncio
import re
import time
from contextvars import ContextVar
from email.utils import getaddresses
from typing import Any, Optional

import httpx

from services.connectors.base import (
    AuthenticationError,
    BaseConnector,
    ConnectorError,
    RateLimitExceededError,
)
from services.connectors.shaping import cap_text

TOKEN_URL = "https://oauth2.googleapis.com/token"
REVOKE_URL = "https://oauth2.googleapis.com/revoke"
AUTHORIZE_URL = "https://accounts.google.com/o/oauth2/v2/auth"
GMAIL_API = "https://gmail.googleapis.com/gmail/v1/users/me"
CALENDAR_API = "https://www.googleapis.com/calendar/v3"
DRIVE_API = "https://www.googleapis.com/drive/v3"
DRIVE_UPLOAD_API = "https://www.googleapis.com/upload/drive/v3"
DOCS_API = "https://docs.googleapis.com/v1/documents"
SHEETS_API = "https://sheets.googleapis.com/v4/spreadsheets"
PEOPLE_API = "https://people.googleapis.com/v1"
SCOPE_BASE = "https://www.googleapis.com/auth/"

CONNECTOR_NAME = "Google Workspace"

# Refresh a token this many seconds before Google says it expires, so a
# request never races the expiry.
EXPIRY_SKEW_S = 60
# Longest scalar string (names, subjects, titles) kept from a provider payload.
SCALAR_CHARS = 300
# Longest free-text argument accepted (email bodies, document text).
MAX_INPUT_CHARS = 200_000

# 403 reasons that mean "usage limit reached", not "permission missing"
# (https://developers.google.com/workspace/gmail/api/guides/handle-errors and
# the Drive and Calendar equivalents).
_RATE_LIMIT_REASONS = frozenset(
    {
        "rateLimitExceeded",
        "userRateLimitExceeded",
        "dailyLimitExceeded",
        "quotaExceeded",
        "sharingRateLimitExceeded",
    }
)
# The reason a 403 of the current request was a usage limit. A ContextVar,
# not an attribute, so concurrent requests (separate tasks) never mix.
_RATE_LIMIT_REASON: ContextVar[Optional[str]] = ContextVar(
    "google_rate_limit_reason", default=None
)

_HTTP_STATUS_RE = re.compile(r"^HTTP (\d{3}) from ")
_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]")

# MIME types (besides text/*) whose bytes are readable text.
_TEXT_MIME_TYPES = frozenset(
    {
        "application/json",
        "application/xml",
        "application/csv",
        "application/x-yaml",
        "application/yaml",
        "application/javascript",
        "application/x-javascript",
        "application/sql",
        "application/x-sh",
        "application/ld+json",
        "application/rtf",
        "text/calendar",
    }
)
_TEXT_EXTENSIONS = (
    ".txt", ".csv", ".tsv", ".md", ".markdown", ".json", ".xml", ".yaml", ".yml",
    ".log", ".ics", ".html", ".htm", ".py", ".js", ".ts", ".sql", ".ini", ".cfg",
    ".toml", ".rst",
)


# ---------------------------------------------------------------------------
# Error helpers
# ---------------------------------------------------------------------------


def error_status(exc: BaseException) -> Optional[int]:
    """The HTTP status in a mapped connector error (``HTTP 401 from ...``)."""
    match = _HTTP_STATUS_RE.match(str(exc))
    return int(match.group(1)) if match else None


def is_precondition_failure(exc: BaseException) -> bool:
    """True for an etag / precondition conflict (People 400 FAILED_PRECONDITION,
    Calendar 412, or a 409)."""
    status = error_status(exc)
    return status in (409, 412) or (status == 400 and "(FAILED_PRECONDITION)" in str(exc))


def google_rate_limit_reason(response: httpx.Response) -> Optional[str]:
    """The usage-limit reason of a Google 403, or ``None`` for a real 403.

    Google answers most quota and rate limits with HTTP 403 (no
    ``Retry-After``) and a reason such as ``userRateLimitExceeded`` in
    ``error.errors[].reason``; newer APIs say ``error.status ==
    RESOURCE_EXHAUSTED``. Only a value from the fixed set is returned, so
    nothing else from the body can reach a message.
    """
    if response.status_code != 403:
        return None
    try:
        body = response.json()
    except (ValueError, UnicodeDecodeError, httpx.ResponseNotRead):
        return None
    error = as_dict(as_dict(body).get("error"))
    for item in as_list(error.get("errors"))[:5]:
        reason = as_dict(item).get("reason")
        if isinstance(reason, str) and reason in _RATE_LIMIT_REASONS:
            return reason
    return "RESOURCE_EXHAUSTED" if error.get("status") == "RESOURCE_EXHAUSTED" else None


def malformed() -> ConnectorError:
    return ConnectorError(f"Malformed response from {CONNECTOR_NAME}.")


def as_object(data: Any) -> dict[str, Any]:
    """*data* when it is a JSON object; anything else is a malformed reply."""
    if not isinstance(data, dict):
        raise malformed()
    return data


def as_dict(value: Any) -> dict[str, Any]:
    """A nested object, or ``{}`` when the provider sent another shape."""
    return value if isinstance(value, dict) else {}


def as_list(value: Any) -> list[Any]:
    """A nested list, or ``[]`` when the provider sent another shape."""
    return value if isinstance(value, list) else []


def scalar(value: Any, limit: int = SCALAR_CHARS) -> Optional[str]:
    """A provider string capped at *limit*; numbers become strings; else None."""
    if isinstance(value, bool) or value is None:
        return None
    if isinstance(value, (int, float)):
        return str(value)
    if isinstance(value, str):
        return value[:limit]
    return None


def scalar_fields(mapping: Any, **renames: str) -> dict[str, Any]:
    """``{new_name: scalar(mapping[old_name])}`` for present scalar values."""
    source = as_dict(mapping)
    out: dict[str, Any] = {}
    for new_name, old_name in renames.items():
        value = scalar(source.get(old_name))
        if value is not None:
            out[new_name] = value
    return out


# ---------------------------------------------------------------------------
# Argument validation (runs before any confirmation or request)
# ---------------------------------------------------------------------------


def require_text(value: Any, field: str, *, max_chars: int = MAX_INPUT_CHARS) -> str:
    """A non-empty string argument, at most *max_chars* long."""
    if not isinstance(value, str) or not value.strip():
        raise ConnectorError(f"'{field}' must be a non-empty string.")
    if len(value) > max_chars:
        raise ConnectorError(f"'{field}' is too long (at most {max_chars} characters).")
    return value


def optional_text(value: Any, field: str, *, max_chars: int = MAX_INPUT_CHARS) -> Optional[str]:
    """An optional string argument; ``None`` or blank gives ``None``."""
    if value is None or (isinstance(value, str) and not value.strip()):
        return None
    return require_text(value, field, max_chars=max_chars)


def require_line(value: Any, field: str, *, max_chars: int = 1000) -> str:
    """A single-line string (no control characters): ids, names, headers."""
    text = require_text(value, field, max_chars=max_chars).strip()
    if _CONTROL_RE.search(text):
        raise ConnectorError(f"'{field}' must be a single line without control characters.")
    return text


def optional_line(value: Any, field: str, *, max_chars: int = 1000) -> Optional[str]:
    if value is None or (isinstance(value, str) and not value.strip()):
        return None
    return require_line(value, field, max_chars=max_chars)


def require_id(value: Any, field: str) -> str:
    """A provider id for a URL path segment (the caller still applies
    ``path_segment``)."""
    return require_line(value, field, max_chars=512)


def optional_bool(value: Any, field: str, default: bool) -> bool:
    if value is None:
        return default
    if not isinstance(value, bool):
        raise ConnectorError(f"'{field}' must be true or false.")
    return value


def optional_offset(value: Any) -> int:
    """A character offset for paging through long text (default 0)."""
    if value is None:
        return 0
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ConnectorError("'offset' must be a whole number of characters, 0 or more.")
    return value


def string_list(value: Any, field: str, *, max_items: int = 50) -> list[str]:
    """An optional list of single-line strings."""
    if value is None:
        return []
    if not isinstance(value, list) or len(value) > max_items:
        raise ConnectorError(f"'{field}' must be a list of at most {max_items} strings.")
    return [require_line(item, field, max_chars=256) for item in value]


def require_addresses(value: Any, field: str) -> str:
    """A comma-separated list of email addresses, safe to put in a header."""
    text = require_line(value, field, max_chars=2000)
    pairs = getaddresses([text])
    if not pairs or any("@" not in address for _, address in pairs):
        raise ConnectorError(f"'{field}' must be one or more email addresses.")
    return text


def require_email(value: Any, field: str) -> str:
    """Exactly one bare email address."""
    text = require_line(value, field, max_chars=320)
    if not re.fullmatch(r"[^@\s,;<>]+@[^@\s,;<>]+\.[^@\s,;<>]+", text):
        raise ConnectorError(f"'{field}' must be a single email address.")
    return text


# ---------------------------------------------------------------------------
# Text helpers
# ---------------------------------------------------------------------------


def is_text_like(mime_type: Optional[str], filename: Optional[str] = None) -> bool:
    """True when a file of this MIME type (or name) holds readable text."""
    mime = (mime_type or "").split(";", 1)[0].strip().lower()
    if mime.startswith("text/") or mime in _TEXT_MIME_TYPES:
        return True
    if mime.endswith("+json") or mime.endswith("+xml"):
        return True
    name = (filename or "").lower()
    return bool(name) and name.endswith(_TEXT_EXTENSIONS) and mime in ("", "application/octet-stream")


def decode_text(data: bytes, encoding: Optional[str] = None) -> str:
    """Decode downloaded bytes as text, refusing binary content."""
    if b"\x00" in data[:8192]:
        raise ConnectorError("The file content is binary, not text; it cannot be read as text.")
    try:
        return data.decode(encoding or "utf-8", errors="replace")
    except LookupError:  # an unknown charset label from the provider
        return data.decode("utf-8", errors="replace")


def text_window(text: str, offset: int, max_chars: int, *, action: str) -> dict[str, Any]:
    """``text[offset:offset+max_chars]`` plus paging fields.

    ``truncated`` is set when more text follows; ``next_offset`` and a
    ``hint`` then tell the model how to read on with *action*.
    """
    window, cut = cap_text(text[offset:], max_chars)
    out: dict[str, Any] = {"text": window, "offset": offset, "truncated": cut}
    if cut:
        out["next_offset"] = offset + len(window)
        out["hint"] = (
            f"Text truncated at {max_chars} characters; call {action} with "
            f"offset={offset + len(window)} to read on."
        )
    return out


# ---------------------------------------------------------------------------
# The shared base class
# ---------------------------------------------------------------------------


class GoogleBase(BaseConnector):
    """Token state, refresh and the request helper shared by every mixin.

    Credentials come in two shapes: a legacy pasted token (``access_token``
    plus optional ``refresh_token``, ``client_id``, ``client_secret``) and a
    broker-made row (``access_token``, ``refresh_token``, ``expires_at``,
    ``granted_scopes``, ``oauth_provider``). Both refresh here with the
    client pair the instance was built with.
    """

    def __init__(
        self,
        client_id: str = "",
        client_secret: str = "",
        redirect_uri: Optional[str] = None,
        timeout_s: Optional[float] = None,
    ) -> None:
        super().__init__(timeout_s=timeout_s, rate_limit=60)
        self._client_id = client_id
        self._client_secret = client_secret
        # None means "derive from Settings when needed" (see redirect_uri).
        self._explicit_redirect_uri = redirect_uri
        self._access_token: Optional[str] = None
        self._refresh_token: Optional[str] = None
        self._expires_at: Optional[int] = None
        self._granted_scopes: set[str] = set()
        self._pkce_verifier: Optional[str] = None
        # One refresh at a time: concurrent requests that all saw the same
        # expired token share the single refresh the first one performs.
        self._refresh_lock = asyncio.Lock()

    @property
    def name(self) -> str:
        return CONNECTOR_NAME

    @property
    def connector_type(self) -> str:
        return "productivity"

    def _auth_headers(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {self._access_token}"} if self._access_token else {}

    # -- Token refresh ---------------------------------------------------------

    def _can_refresh(self) -> bool:
        return bool(self._refresh_token)

    def _expiring(self) -> bool:
        return self._expires_at is not None and self._expires_at - EXPIRY_SKEW_S <= time.time()

    async def _refresh_access_token(self) -> None:
        """Trade the refresh token for a new access token.

        Keeps a rotated refresh token and records ``expires_at`` so
        ``updated_credentials`` persists both. A rejected grant (Google
        answers 400 ``invalid_grant``) is an ``AuthenticationError`` asking
        the user to reconnect; an outage or rate limit stays what it is.
        """
        if not self._refresh_token:
            raise AuthenticationError("No refresh token available.")
        if not self._client_id:
            raise AuthenticationError(
                "Google token refresh needs an OAuth client id. "
                f"Reconnect {CONNECTOR_NAME} in Connectors."
            )
        form = {
            "grant_type": "refresh_token",
            "client_id": self._client_id,
            "refresh_token": self._refresh_token,
        }
        if self._client_secret:
            form["client_secret"] = self._client_secret
        try:
            payload = await self._request_json("POST", TOKEN_URL, data=form, authorized=False)
        except RateLimitExceededError:
            raise
        except ConnectorError as exc:
            status = error_status(exc)
            if status is None or status >= 500:
                raise
            raise AuthenticationError(
                f"Google token refresh failed: {exc} Reconnect {CONNECTOR_NAME} in Connectors."
            ) from None
        self._apply_token_payload(as_object(payload))

    def _apply_token_payload(self, payload: dict[str, Any]) -> None:
        """Store the tokens from a token-endpoint answer."""
        token = payload.get("access_token")
        if not isinstance(token, str) or not token:
            raise ConnectorError(f"Malformed token response from {CONNECTOR_NAME}.")
        self._access_token = token
        rotated = payload.get("refresh_token")
        if isinstance(rotated, str) and rotated:
            self._refresh_token = rotated
        expires_in = payload.get("expires_in")
        if isinstance(expires_in, (int, float)) and not isinstance(expires_in, bool) and expires_in > 0:
            self._expires_at = int(time.time()) + int(expires_in)
        scope = payload.get("scope")
        if isinstance(scope, str) and scope.strip():
            self._granted_scopes = set(scope.split())

    async def _refresh_if_stale(self, token_used: Optional[str]) -> None:
        """Refresh once under the lock unless another request already did."""
        async with self._refresh_lock:
            if self._access_token == token_used:
                await self._refresh_access_token()

    # -- Requests --------------------------------------------------------------

    def _retry_wait(self, method: str, response: httpx.Response) -> Optional[float]:
        """Base retry rule, plus: note a Google usage-limit 403 and do not
        retry it (Google asks for exponential backoff; the model waits
        instead). The base ``_request`` consults this for every failed first
        attempt, before it maps the response to an error."""
        reason = google_rate_limit_reason(response)
        if reason is None:
            return super()._retry_wait(method, response)
        _RATE_LIMIT_REASON.set(reason)
        return None

    async def _request(self, method: str, url: str, **kwargs: Any) -> httpx.Response:
        """The base ``_request``, with a Google usage-limit 403 raised as
        ``RateLimitExceededError`` (the base maps every 403 without
        ``Retry-After`` to a missing-scope ``AuthenticationError``). Only
        the fixed reason code reaches the message, never the body."""
        marker = _RATE_LIMIT_REASON.set(None)
        try:
            return await super()._request(method, url, **kwargs)
        except AuthenticationError as exc:
            reason = _RATE_LIMIT_REASON.get()
            if reason is None or error_status(exc) != 403:
                raise
            raise RateLimitExceededError(
                f"HTTP 403 from {self.name} ({reason}): Google usage limit reached, "
                "not a permission problem. Wait and try again later."
            ) from None
        finally:
            _RATE_LIMIT_REASON.reset(marker)

    async def _call(self, method: str, url: str, **kwargs: Any) -> httpx.Response:
        """``_request`` with Google's token lifecycle around it.

        A token known to be expiring is refreshed first (saving a doomed
        round trip); a 401 with a refresh token available refreshes once
        and retries once. Everything else is the base helper's behaviour.
        """
        if self._expiring() and self._can_refresh() and self._client_id:
            await self._refresh_if_stale(self._access_token)
        token_used = self._access_token
        try:
            return await self._request(method, url, **kwargs)
        except AuthenticationError as exc:
            if error_status(exc) != 401 or not self._can_refresh():
                raise
        await self._refresh_if_stale(token_used)
        return await self._request(method, url, **kwargs)

    async def _call_json(self, method: str, url: str, **kwargs: Any) -> Any:
        """``_call`` then decode JSON (204 or empty gives ``{}``)."""
        response = await self._call(method, url, **kwargs)
        if response.status_code == 204 or not response.content.strip():
            return {}
        try:
            return response.json()
        except ValueError:
            raise malformed() from None

    async def _call_object(self, method: str, url: str, **kwargs: Any) -> dict[str, Any]:
        """``_call_json`` that must answer with a JSON object."""
        return as_object(await self._call_json(method, url, **kwargs))
