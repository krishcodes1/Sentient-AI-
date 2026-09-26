"""Shared plumbing for the Slack connector: the stored tokens, the single Web API
call helper, Slack's ``{"ok": false}`` error mapping, argument validation and
message shaping.

Why it exists: Slack answers HTTP 200 with ``{"ok": false, "error": ...}`` for
most failures, so every call must be checked the same way and turned into the
exception types the executor branches on (AuthenticationError,
RateLimitExceededError, ConnectorError) with the vendor code only. The READ and
WRITE mixins (``reads.py``, ``writes.py``) build on ``SlackBase``.

External service: the Slack Web API (https://slack.com/api/). Depends on
``services.connectors.base`` (HTTP helpers, errors) and ``shaping`` (text caps).
"""

from __future__ import annotations

import re
from typing import Any, Literal, Mapping, Optional

from services.connectors.base import (
    AuthenticationError,
    BaseConnector,
    ConnectorError,
    RateLimitExceededError,
)
from services.connectors.shaping import cap_text

API_BASE = "https://slack.com/api"
# files.getUploadURLExternal hands back https://files.slack.com/upload/v1/...
UPLOAD_HOST = "files.slack.com"
UPLOAD_PATH_PREFIX = "/upload/v1/"

TokenKind = Literal["bot", "user"]

# Token prefixes checked by validate_credentials (values are never echoed).
TOKEN_PREFIXES: Mapping[str, str] = {
    "bot_token": "xoxb-",
    "app_token": "xapp-",
    "user_token": "xoxp-",
}

# Longest message text returned per message in a list, and when reading a thread.
LIST_TEXT_CHARS = 2000
THREAD_TEXT_CHARS = 8000
# Longest scalar string (names, ids, titles) kept from a provider payload.
SCALAR_CHARS = 256
# Longest message text accepted for posting (Slack truncates beyond 40,000).
MAX_MESSAGE_CHARS = 40_000

_CODE_RE = re.compile(r"^[a-z0-9_]{1,64}$")
_SCOPE_LIST_RE = re.compile(r"^[a-z0-9_.:,]{1,200}$")
CHANNEL_ID_RE = re.compile(r"^[CDG][A-Z0-9]{1,30}$")
USER_ID_RE = re.compile(r"^[UW][A-Z0-9]{1,30}$")
FILE_ID_RE = re.compile(r"^F[A-Z0-9]{1,30}$")
TS_RE = re.compile(r"^\d{1,12}\.\d{1,9}$")

_AUTH_ERRORS = frozenset(
    {"invalid_auth", "not_authed", "token_revoked", "account_inactive", "token_expired"}
)
_NOT_FOUND_ERRORS = frozenset(
    {
        "channel_not_found",
        "user_not_found",
        "users_not_found",
        "message_not_found",
        "thread_not_found",
        "file_not_found",
    }
)
# Fixed, human hints for common codes. Nothing from the payload is echoed
# except the validated code itself.
_HINTS: Mapping[str, str] = {
    "not_in_channel": "the Crawler app is not a member of that channel; invite it first (/invite @Crawler)",
    "is_archived": "the channel is archived",
    "already_reacted": "that reaction is already on the message",
    "already_in_channel": "that user is already in the channel",
    "cant_invite_self": "the app cannot invite itself",
    "name_taken": "a channel with that name already exists",
    "invalid_name": "the channel name is not allowed",
    "cant_delete_message": "the app may delete only messages it posted",
    "cant_archive_general": "the general channel cannot be archived",
    "already_archived": "the channel is already archived",
    "time_in_past": "post_at must be in the future",
    "time_too_far": "post_at must be within 120 days",
    "msg_too_long": "the message is too long",
    "restricted_action": "a workspace setting blocks this action",
    "not_allowed_token_type": "this method needs a different kind of token",
}


def slack_error(payload: Mapping[str, Any]) -> ConnectorError:
    """The exception for a ``{"ok": false}`` Slack reply (vendor code only)."""
    raw = payload.get("error")
    code = raw if isinstance(raw, str) and _CODE_RE.fullmatch(raw) else "unknown_error"
    head = f"Slack error ({code})"
    if code in _AUTH_ERRORS:
        return AuthenticationError(
            f"{head}: the token was rejected. Reconnect Slack in Connectors."
        )
    if code == "missing_scope":
        needed = payload.get("needed")
        scope = (
            f"the '{needed}' scope"
            if isinstance(needed, str) and _SCOPE_LIST_RE.fullmatch(needed)
            else "a scope this action needs"
        )
        return AuthenticationError(
            f"{head}: the token lacks {scope}. Add it to the Slack app, reinstall the "
            "app, then reconnect Slack in Connectors. Do not retry until then."
        )
    if code == "ratelimited":
        return RateLimitExceededError(f"{head}: rate limited by Slack. Try again shortly.")
    if code in _NOT_FOUND_ERRORS:
        return ConnectorError(f"{head}: not found.")
    hint = _HINTS.get(code)
    return ConnectorError(f"{head}: {hint}." if hint else f"{head}.")


# -- Argument validation -------------------------------------------------------


def require_text(name: str, value: Any, *, max_chars: int, allow_empty: bool = False) -> str:
    """*value* as a stripped string of at most *max_chars* characters."""
    if not isinstance(value, str):
        raise ConnectorError(f"{name} must be a string.")
    text = value.strip()
    if not text and not allow_empty:
        raise ConnectorError(f"{name} must not be empty.")
    if len(text) > max_chars:
        raise ConnectorError(f"{name} is too long (at most {max_chars} characters).")
    return text


def optional_text(name: str, value: Any, *, max_chars: int) -> Optional[str]:
    """``None`` for a missing or blank value, else ``require_text``."""
    if value is None or (isinstance(value, str) and not value.strip()):
        return None
    return require_text(name, value, max_chars=max_chars)


def require_id(name: str, value: Any, pattern: re.Pattern[str], example: str, where: str) -> str:
    """A Slack id matching *pattern*; the error names an example and where to look."""
    if isinstance(value, str) and pattern.fullmatch(value.strip()):
        return value.strip()
    raise ConnectorError(f"{name} must be a Slack id like {example}; {where}.")


def channel_id(value: Any, name: str = "channel") -> str:
    return require_id(name, value, CHANNEL_ID_RE, "C0123ABCD", "call list_channels to find it")


def user_id(value: Any, name: str = "user_id") -> str:
    return require_id(name, value, USER_ID_RE, "U0123ABCD", "call list_users to find it")


def message_ts(value: Any, name: str = "ts") -> str:
    return require_id(
        name, value, TS_RE, "1712345678.123456", "use the ts of a message from get_history"
    )


def optional_ts(value: Any, name: str) -> Optional[str]:
    return None if value is None or value == "" else message_ts(value, name)


def optional_bool(name: str, value: Any) -> bool:
    if value is None:
        return False
    if not isinstance(value, bool):
        raise ConnectorError(f"{name} must be true or false.")
    return value


def preview(text: str, max_chars: int = 200) -> str:
    """Short, single-line quote of *text* for a confirmation description."""
    flat = " ".join(text.split())
    return flat if len(flat) <= max_chars else flat[: max_chars - 3] + "..."


# -- Shaping -------------------------------------------------------------------


def scalar(value: Any) -> Any:
    """*value* when it is a plain scalar (strings capped), else ``None``."""
    if isinstance(value, bool) or isinstance(value, (int, float)):
        return value
    if isinstance(value, str):
        return value[:SCALAR_CHARS]
    return None


def scalars(mapping: Any, *keys: str) -> dict[str, Any]:
    """Only those *keys* of *mapping* whose values are plain scalars."""
    if not isinstance(mapping, Mapping):
        return {}
    out: dict[str, Any] = {}
    for key in keys:
        value = scalar(mapping.get(key))
        if value is not None:
            out[key] = value
    return out


def items_of(payload: Mapping[str, Any], key: str) -> list[Any]:
    """The list under *key*: missing gives ``[]``, any other shape is malformed."""
    value = payload.get(key)
    if value is None:
        return []
    if not isinstance(value, list):
        raise ConnectorError("Malformed response from Slack.")
    return value


def next_cursor(payload: Mapping[str, Any]) -> Optional[str]:
    meta = payload.get("response_metadata")
    cursor = meta.get("next_cursor") if isinstance(meta, Mapping) else None
    return cursor if isinstance(cursor, str) and cursor else None


def shape_message(raw: Any, *, max_chars: int, hint: str) -> Optional[dict[str, Any]]:
    """The fields of a message the model needs; ``None`` for a non-object."""
    if not isinstance(raw, Mapping):
        return None
    text_value = raw.get("text")
    text, truncated = cap_text(text_value if isinstance(text_value, str) else "", max_chars)
    shaped = {
        **scalars(raw, "ts", "user", "bot_id", "subtype", "thread_ts", "reply_count"),
        "text": text,
    }
    files = raw.get("files")
    if isinstance(files, list):
        shaped["files"] = [
            scalars(item, "id", "name") for item in files[:10] if isinstance(item, Mapping)
        ]
    if truncated:
        shaped["truncated"] = True
        shaped["hint"] = hint
    return shaped


def shape_channel(raw: Any) -> Optional[dict[str, Any]]:
    if not isinstance(raw, Mapping):
        return None
    shaped = scalars(raw, "id", "name", "is_private", "is_archived", "is_member", "num_members")
    for key in ("topic", "purpose"):
        block = raw.get(key)
        value = block.get("value") if isinstance(block, Mapping) else None
        if isinstance(value, str) and value:
            shaped[key] = value[:SCALAR_CHARS]
    return shaped


def shape_user(raw: Any) -> Optional[dict[str, Any]]:
    if not isinstance(raw, Mapping):
        return None
    shaped = scalars(raw, "id", "name", "real_name", "is_bot", "deleted", "tz")
    profile = raw.get("profile")
    shaped.update(scalars(profile, "display_name", "title", "status_text", "status_emoji"))
    return shaped


# -- The connector base ----------------------------------------------------------


class SlackBase(BaseConnector):
    """Token storage and the Web API call helper shared by the action mixins."""

    def __init__(self, timeout_s: Optional[float] = None) -> None:
        # Slack's busiest tiers allow about 50 calls a minute per method.
        super().__init__(timeout_s=timeout_s, rate_limit=50)
        self._bot_token: Optional[str] = None
        self._user_token: Optional[str] = None
        self._app_token: Optional[str] = None

    def _store_tokens(self, credentials: Mapping[str, Any]) -> None:
        def clean(key: str) -> Optional[str]:
            value = credentials.get(key)
            if not isinstance(value, str):
                return None
            return value.strip() or None

        self._bot_token = clean("bot_token")
        self._user_token = clean("user_token")
        # Kept for the later Socket Mode DM channel; never sent by this connector.
        self._app_token = clean("app_token")

    def _auth_headers(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {self._bot_token}"} if self._bot_token else {}

    def _secret_values(self) -> tuple[str, ...]:
        # Every stored token, not only the bot header: a user-token call sends
        # its own Authorization header, and none may leak into an error.
        return tuple(t for t in (self._bot_token, self._user_token, self._app_token) if t)

    def _token_header(self, token: TokenKind, action: str) -> dict[str, str]:
        if token == "bot":
            return {}
        if not self._user_token:
            raise ConnectorError(
                f"{action} needs a Slack user token (xoxp-). Add one to the Slack "
                "connector in Connectors; the bot token cannot do this."
            )
        return {"Authorization": f"Bearer {self._user_token}"}

    async def _call(
        self,
        method: str,
        *,
        http: Literal["GET", "POST"] = "GET",
        params: Optional[dict[str, Any]] = None,
        json_body: Optional[dict[str, Any]] = None,
        form: Optional[dict[str, str]] = None,
        token: TokenKind = "bot",
        action: str = "",
    ) -> dict[str, Any]:
        """Call one Web API method and return its payload when ``ok`` is true.

        Reads go as GET with query parameters. Writes go as POST with a JSON
        body (``charset=utf-8``, as Slack asks) or, for the file upload
        methods, a form body. ``token="user"`` sends the user token instead
        of the bot token and fails before any request when there is none.
        """
        headers = self._token_header(token, action or method)
        if json_body is not None:
            headers["Content-Type"] = "application/json; charset=utf-8"
        data = await self._request_json(
            http,
            f"{API_BASE}/{method}",
            params=params,
            json=json_body,
            data=form,
            headers=headers or None,
        )
        if not isinstance(data, dict):
            raise ConnectorError("Malformed response from Slack.")
        if data.get("ok") is not True:
            raise slack_error(data)
        return data
