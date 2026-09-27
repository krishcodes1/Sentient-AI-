"""Shared plumbing for the GitHub connector: argument validation, response
shaping and the request helpers every GitHub action mixin uses.

Why it exists: forty actions validate the same owner, repository, ref and
file-path arguments and shape the same user, label and body fields. Doing it
once keeps every URL built from model-chosen values safe (each id is one
encoded path segment; "/" in a file path stays a separator while "..",
absolute paths and empty segments are refused) and keeps hostile provider
payloads (wrong types, nulls, huge strings) from crashing an action.

Connects to: the GitHub REST API at api.github.com (through
``BaseConnector._request``). Depends on ``services.connectors.base`` (HTTP
helpers, errors, ``path_segment``) and ``services.connectors.shaping``.
"""

from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from typing import Any, Mapping, Optional

import httpx

# The runtime writes exactly these characters as \uXXXX escapes before it
# applies the per-result budget, so they count as escapes here too.
from services.agent.prompt_guard import _INVISIBLE_CHARS
from services.connectors.base import (
    MAX_RETRY_AFTER_S,
    BaseConnector,
    BoundedBody,
    ConnectorError,
    RateLimitExceededError,
    UserConfirmationRequired,
    path_segment,
    rate_limit_wait,
)
from services.connectors.shaping import cap_text

API = "https://api.github.com"
API_VERSION = "2022-11-28"

# Media types chosen per request (the default Accept is application/vnd.github+json).
ACCEPT_RAW = "application/vnd.github.raw+json"
ACCEPT_OBJECT = "application/vnd.github.object+json"
ACCEPT_DIFF = "application/vnd.github.diff"
ACCEPT_SHA = "application/vnd.github.sha"

MALFORMED = "Malformed response from GitHub."

# Files GitHub will only let a token with the "workflow" scope change.
WORKFLOWS_DIR = ".github/workflows/"
WORKFLOW_SCOPE_REFUSAL = (
    "Changing files under .github/workflows/ needs GitHub's workflow permission, which "
    "the GitHub device sign-in never requests (workflow files run with the repository's "
    "secrets). Edit the file on github.com, or connect GitHub with a fine-grained token "
    "that has the Workflows permission."
)

# Longest single string field (a title, a description) kept in a result.
MAX_FIELD_CHARS = 500
# Longest free-text argument (a comment, an issue body) accepted from the model.
MAX_TEXT_ARG_CHARS = 65_000

# What the model is shown of one tool result (services/agent/runtime.py):
# the executor's envelope around the result, as compact JSON, cut to the
# context manager's 2000-character default, or to the RESULT_CHAR_BUDGETS
# entry of a long-result action (github.get_pr_diff, github.get_failed_logs).
# A longer payload loses its MIDDLE, so actions returning one long body size
# it to fit whole. tests/connectors/test_github_budgets.py pins these to the
# runtime's values.
DEFAULT_RESULT_CHARS = 2_000
LONG_RESULT_CHARS = 12_000
# Room kept for the executor envelope ({"ok", "connector", "action",
# "sanitized", "execution_time_ms"}) around an action's own result.
ENVELOPE_RESERVE = 250

_OWNER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9-]{0,38}$")
_REPO_RE = re.compile(r"^[A-Za-z0-9._-]{1,100}$")
_SHA_RE = re.compile(r"^[0-9a-f]{40}$")
_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]")
# Characters git itself refuses in a ref name (git check-ref-format).
_BAD_REF_CHARS_RE = re.compile(r"[\x00-\x20\x7f~^:?*\[\\]")


# ---------------------------------------------------------------------------
# Argument validation
# ---------------------------------------------------------------------------


def owner_name(value: Any) -> str:
    """A GitHub user or organization login, validated."""
    text = value.strip() if isinstance(value, str) else ""
    if not _OWNER_RE.fullmatch(text):
        raise ConnectorError(
            "owner must be a GitHub user or organization login "
            "(letters, digits and hyphens, at most 39 characters)."
        )
    return text


def repo_name(value: Any) -> str:
    """A repository name (without the owner), validated."""
    text = value.strip() if isinstance(value, str) else ""
    if not _REPO_RE.fullmatch(text) or text in (".", ".."):
        raise ConnectorError(
            "repo must be a repository name without the owner "
            "(letters, digits, '.', '_' and '-', at most 100 characters)."
        )
    return text


def repo_path(owner: Any, repo: Any) -> str:
    """``/repos/<owner>/<repo>`` with both parts validated and encoded."""
    return f"/repos/{path_segment(owner_name(owner))}/{path_segment(repo_name(repo))}"


def positive_int(value: Any, label: str) -> int:
    """A positive integer id (issue number, run id), from an int or digits."""
    number: Optional[int] = None
    if isinstance(value, int) and not isinstance(value, bool):
        number = value
    elif isinstance(value, str) and value.strip().isdigit():
        number = int(value.strip())
    if number is None or number <= 0 or number >= 2**63:
        raise ConnectorError(f"{label} must be a positive whole number.")
    return number


def git_ref(value: Any, label: str = "ref") -> str:
    """A branch, tag or commit name that git itself would accept.

    Follows ``git check-ref-format``: no "..", no "@{", no control
    characters, spaces or ``~^:?*[\\``, no empty or dot-leading component,
    no leading or trailing "/", no trailing "." or ".lock". These rules also
    refuse every dot segment, so a ref can never climb out of its URL path.
    """
    text = value.strip() if isinstance(value, str) else ""
    problem = ""
    if not text or len(text) > 255:
        problem = "must be 1 to 255 characters"
    elif _BAD_REF_CHARS_RE.search(text) or ".." in text or "@{" in text or text == "@":
        problem = "contains characters git does not allow in a ref"
    elif text.endswith(".") or text.endswith(".lock"):
        problem = "must not end with '.' or '.lock'"
    elif any(not part or part.startswith(".") for part in text.split("/")):
        problem = "must not have empty components or components starting with '.'"
    if problem:
        raise ConnectorError(f"{label} {problem}.")
    return text


def ref_segments(value: Any, label: str = "branch") -> str:
    """A validated ref encoded segment by segment (``feature/x`` stays two
    segments), for endpoints that take the ref as a path suffix."""
    return "/".join(path_segment(part) for part in git_ref(value, label).split("/"))


def is_sha(value: str) -> bool:
    return bool(_SHA_RE.fullmatch(value))


def content_path(value: Any, *, allow_root: bool = False) -> str:
    """A repository file path encoded segment by segment.

    "/" separates segments; every segment is percent-encoded on its own.
    Absolute paths, backslashes, control characters, empty segments and
    "." or ".." segments are refused. Returns "" for the root only when
    *allow_root* is set and the value is empty or "/".
    """
    text = value if isinstance(value, str) else ""
    if allow_root and text.strip() in ("", "/"):
        return ""
    if allow_root:
        text = text.strip().strip("/")
    if not text or len(text) > 4096:
        raise ConnectorError("path must be a file path inside the repository, like 'src/app.py'.")
    if text.startswith("/"):
        raise ConnectorError("path must be relative to the repository root (no leading '/').")
    if "\\" in text or _CONTROL_RE.search(text):
        raise ConnectorError("path must not contain backslashes or control characters.")
    parts = text.split("/")
    if any(part in ("", ".", "..") for part in parts):
        raise ConnectorError("path must not contain empty, '.' or '..' segments.")
    return "/".join(path_segment(part) for part in parts)


def text_arg(
    value: Any, label: str, *, required: bool = True, max_chars: int = MAX_TEXT_ARG_CHARS
) -> Optional[str]:
    """A free-text argument: a string within *max_chars*, or None when optional."""
    if value is None and not required:
        return None
    if not isinstance(value, str) or (required and not value.strip()):
        raise ConnectorError(f"{label} must be a non-empty string.")
    if len(value) > max_chars:
        raise ConnectorError(
            f"{label} is too long ({len(value)} characters, the limit is {max_chars})."
        )
    return value


def choice(
    value: Any, label: str, allowed: tuple[str, ...], default: Optional[str] = None
) -> Optional[str]:
    """*value* when it is one of *allowed* (case-insensitive); None gives *default*."""
    if value is None:
        return default
    text = value.strip().lower() if isinstance(value, str) else ""
    if text not in allowed:
        raise ConnectorError(f"{label} must be one of: {', '.join(allowed)}.")
    return text


def string_list(value: Any, label: str, *, max_items: int = 50) -> Optional[list[str]]:
    """A list of non-empty strings (labels, logins), or None when absent."""
    if value is None:
        return None
    if not isinstance(value, list) or not all(isinstance(v, str) and v.strip() for v in value):
        raise ConnectorError(f"{label} must be a list of non-empty strings.")
    if len(value) > max_items:
        raise ConnectorError(f"{label} may hold at most {max_items} entries.")
    return [v.strip() for v in value]


def flag(value: Any, label: str) -> bool:
    if not isinstance(value, bool):
        raise ConnectorError(f"{label} must be true or false.")
    return value


def preview(text: Optional[str], limit: int = 200) -> str:
    """A one-line preview of *text* for a confirmation message."""
    if not text:
        return ""
    flat = " ".join(text.split())
    return flat if len(flat) <= limit else flat[:limit] + "..."


def require_confirmation(user_confirmed: bool, action: str, details: str) -> None:
    """Raise ``UserConfirmationRequired`` unless the user already approved."""
    if not user_confirmed:
        raise UserConfirmationRequired(action=action, details=details)


# ---------------------------------------------------------------------------
# Response shaping
# ---------------------------------------------------------------------------


def as_object(data: Any) -> dict[str, Any]:
    """*data* when GitHub answered with a JSON object, else a clean error."""
    if not isinstance(data, dict):
        raise ConnectorError(MALFORMED)
    return data


def as_list(data: Any) -> list[dict[str, Any]]:
    """The object entries of a JSON array (non-object entries are skipped)."""
    if not isinstance(data, list):
        raise ConnectorError(MALFORMED)
    return [item for item in data if isinstance(item, dict)]


def list_field(data: Any, key: str) -> list[dict[str, Any]]:
    """The object entries of ``data[key]`` (search results, workflow runs)."""
    return as_list(as_object(data).get(key))


def scalars(mapping: Any, *keys: str, max_chars: int = MAX_FIELD_CHARS) -> dict[str, Any]:
    """Only the scalar values of *keys* present in *mapping*.

    Strings are capped at *max_chars*; numbers, booleans and nulls pass;
    nested objects and lists are dropped (a hostile payload cannot smuggle
    a huge structure through a field meant to be a title).
    """
    if not isinstance(mapping, Mapping):
        return {}
    out: dict[str, Any] = {}
    for key in keys:
        if key not in mapping:
            continue
        value = mapping[key]
        if isinstance(value, str):
            out[key] = value[:max_chars]
        elif value is None or isinstance(value, (bool, int, float)):
            out[key] = value
    return out


def login(value: Any) -> Optional[str]:
    """``value["login"]`` of a GitHub user object, when it is a string."""
    if isinstance(value, Mapping) and isinstance(value.get("login"), str):
        return str(value["login"])[:100]
    return None


def names(value: Any, key: str = "name", *, max_items: int = 30) -> list[str]:
    """String ``key`` values of a list of objects (label names, logins)."""
    if not isinstance(value, list):
        return []
    found = [
        str(item[key])[:100]
        for item in value
        if isinstance(item, Mapping) and isinstance(item.get(key), str)
    ]
    return found[:max_items]


def nested(value: Any, *keys: str) -> Any:
    """``value[k1][k2]...`` or None when any level is missing or not an object."""
    current = value
    for key in keys:
        if not isinstance(current, Mapping):
            return None
        current = current.get(key)
    return current


def nested_str(value: Any, *keys: str, max_chars: int = MAX_FIELD_CHARS) -> Optional[str]:
    found = nested(value, *keys)
    return found[:max_chars] if isinstance(found, str) else None


def body_fields(text: Any, max_chars: int, hint: str) -> dict[str, Any]:
    """``{"body", "truncated"}`` (plus ``hint`` when cut) for a text body."""
    body, truncated = cap_text(text if isinstance(text, str) else "", max_chars)
    result: dict[str, Any] = {"body": body, "truncated": truncated}
    if truncated:
        result["hint"] = hint
    return result


_TWO_CHAR_ESCAPES = frozenset('"\\\n\r\t\b\f')


def json_char_cost(ch: str) -> int:
    """Characters *ch* takes in the JSON the model is shown (compact
    ``json.dumps`` with ``ensure_ascii=False``, then the runtime's escaping
    of invisible characters, 12 for an astral one as a surrogate pair)."""
    if ch in _TWO_CHAR_ESCAPES:
        return 2
    if ch < " ":
        return 6
    if ch > "~" and _INVISIBLE_CHARS.match(ch):
        return 12
    return 1


def json_text_cost(text: str) -> int:
    """Characters *text* takes inside a JSON string (quotes excluded).

    Computed in C (``json.dumps``) plus an upper bound for invisible
    characters, so a large log costs one pass, not a Python loop.
    """
    base = len(json.dumps(text, ensure_ascii=False)) - 2
    return base + 11 * len(_INVISIBLE_CHARS.findall(text))


def json_len(value: Any) -> int:
    """Length of *value* as the compact JSON the runtime serializes."""
    return len(json.dumps(value, ensure_ascii=False, separators=(",", ":"), default=str))


def fit_head(text: str, budget: int) -> tuple[str, bool]:
    """The longest start of *text* costing at most *budget* JSON characters.

    Returns ``(head, cut)``. When cut, the head ends after its last line
    break (when it has one), so it holds whole lines only.
    """
    used = 0
    for index, ch in enumerate(text):
        used += json_char_cost(ch)
        if used > budget:
            head = text[:index]
            newline = head.rfind("\n")
            return (head[: newline + 1] if newline >= 0 else head), True
    return text, False


def fit_tail(text: str, budget: int) -> tuple[str, bool]:
    """The longest end of *text* costing at most *budget* JSON characters.

    Returns ``(tail, cut)``. When cut, the tail starts at a line start when
    one is near (within 200 characters), so its first line is whole.
    """
    used = 0
    for index in range(len(text) - 1, -1, -1):
        used += json_char_cost(text[index])
        if used > budget:
            tail = text[index + 1 :]
            newline = tail.find("\n")
            if 0 <= newline < 200:
                tail = tail[newline + 1 :]
            return tail, True
    return text, False


def first_line(text: Any, max_chars: int = 200) -> str:
    if not isinstance(text, str):
        return ""
    return text.split("\n", 1)[0][:max_chars]


def decode_json(response: httpx.Response) -> Any:
    """The JSON body of a 2xx *response* (empty gives ``{}``)."""
    if response.status_code == 204 or not response.content.strip():
        return {}
    try:
        return response.json()
    except ValueError:
        raise ConnectorError(MALFORMED) from None


def parse_json_bytes(raw: bytes) -> Any:
    """JSON from a body read by ``_get_bytes`` (empty gives ``{}``)."""
    if not raw.strip():
        return {}
    try:
        return json.loads(raw)
    except ValueError:  # JSONDecodeError and UnicodeDecodeError both
        raise ConnectorError(MALFORMED) from None


def is_not_found(exc: ConnectorError) -> bool:
    """True for the mapped error of an HTTP 404 (``"HTTP 404 from ..."``)."""
    return type(exc) is ConnectorError and str(exc).startswith("HTTP 404 ")


def _primary_limit_message(response: httpx.Response) -> str:
    reset = response.headers.get("x-ratelimit-reset", "").strip()
    try:
        reset_at = datetime.fromtimestamp(float(reset), tz=timezone.utc)
    except (ValueError, OverflowError, OSError):
        return (
            f"HTTP {response.status_code} from GitHub: the API rate limit for this "
            "token is used up and GitHub did not say when it resets. Try again later."
        )
    minutes = max(1, round((reset_at - datetime.now(timezone.utc)).total_seconds() / 60))
    return (
        f"HTTP {response.status_code} from GitHub: the API rate limit for this token is "
        f"used up. It resets at {reset_at:%H:%M} UTC (in about {minutes} min); "
        "calls before then will fail."
    )


# ---------------------------------------------------------------------------
# Request helpers shared by every action mixin
# ---------------------------------------------------------------------------


class GitHubApiBase(BaseConnector):
    """Abstract base of the GitHub action mixins: request helpers only.

    ``GitHubConnector`` (services/connectors/github.py) supplies the token,
    headers and the abstract members of ``BaseConnector``.
    """

    #: Provider scopes of a device-flow OAuth token, set on authenticate.
    #: ``None`` for a pasted personal access token, whose permissions are
    #: not known here (GitHub itself refuses what it lacks).
    _oauth_scopes: Optional[frozenset[str]] = None

    def _check_workflow_path(self, path: str) -> None:
        """Refuse a change under .github/workflows/ that GitHub would reject.

        GitHub needs the "workflow" scope for it, and the device sign-in
        deliberately never asks for that scope, so the call could only fail
        with a bare HTTP error after the user approved it.
        """
        scopes = self._oauth_scopes
        if scopes is not None and "workflow" not in scopes and path.startswith(WORKFLOWS_DIR):
            raise ConnectorError(WORKFLOW_SCOPE_REFUSAL)

    async def _get_json(
        self, path: str, *, params: Optional[dict[str, Any]] = None, accept: Optional[str] = None
    ) -> Any:
        headers = {"Accept": accept} if accept else None
        return await self._request_json("GET", f"{API}{path}", params=params, headers=headers)

    async def _send_json(
        self, method: str, path: str, *, json: Any = None, params: Optional[dict[str, Any]] = None
    ) -> Any:
        return await self._request_json(method, f"{API}{path}", json=json, params=params)

    async def _get_text(
        self, path: str, *, accept: str, params: Optional[dict[str, Any]] = None
    ) -> httpx.Response:
        return await self._request("GET", f"{API}{path}", params=params, headers={"Accept": accept})

    async def _get_bytes(
        self,
        path: str,
        *,
        accept: str,
        max_bytes: int,
        params: Optional[dict[str, Any]] = None,
    ) -> BoundedBody:
        """GET a raw body (a file, a diff), keeping only its first *max_bytes*."""
        return await self._request_bytes(
            "GET", f"{API}{path}", max_bytes=max_bytes, params=params, headers={"Accept": accept}
        )

    def _retry_wait(self, method: str, response: httpx.Response) -> Optional[float]:
        """GitHub's primary rate limit (403 or 429 with
        ``x-ratelimit-remaining: 0`` and no ``Retry-After``) resets at a
        wall-clock time, often far away. A reset within 10 s is retried
        once by the base class; a later one is reported naming the reset
        time instead of a raw number of seconds. Secondary limits (which
        carry ``Retry-After``) keep the base behaviour.
        """
        headers = response.headers
        primary = (
            response.status_code in (403, 429)
            and headers.get("x-ratelimit-remaining", "").strip() == "0"
            and "retry-after" not in headers
        )
        if primary:
            wait = rate_limit_wait(response)
            if wait is None or wait > MAX_RETRY_AFTER_S:
                raise RateLimitExceededError(_primary_limit_message(response))
        return super()._retry_wait(method, response)


# ---------------------------------------------------------------------------
# Schema properties shared by the action declarations
# ---------------------------------------------------------------------------

OWNER_PROP: dict[str, Any] = {
    "type": "string",
    "description": "Repository owner: a user or organization login",
    "required": True,
}
REPO_PROP: dict[str, Any] = {
    "type": "string",
    "description": "Repository name, without the owner",
    "required": True,
}
LIMIT_PROP: dict[str, Any] = {
    "type": "integer",
    "description": "How many to return (default 10, max 50)",
}
NUMBER_PROP: dict[str, Any] = {
    "type": "integer",
    "description": "Issue or pull request number",
    "required": True,
}
