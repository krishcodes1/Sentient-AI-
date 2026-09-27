"""READ actions of the Slack connector: channels, message history, threads,
search, users and file details.

Why it exists: keeps ``services/connectors/slack.py`` small (large connectors
split into mixins). ``READ_ACTIONS`` declares the tools and
``SlackReadsMixin`` holds one coroutine per action. Lists are paginated with
Slack's ``response_metadata.next_cursor`` through ``collect_pages``; nothing is
resolved with extra per-item calls (messages carry user ids; ``list_users`` and
``get_user`` give names).

External service: the Slack Web API (conversations.*, search.messages,
users.*, files.info). Depends on ``slack_api.client`` and ``shaping``.
"""

from __future__ import annotations

from typing import Any, Callable, Optional

from services.agent.permissions import ActionCategory
from services.connectors.base import ConnectorError
from services.connectors.definition import ToolSpec, _schema
from services.connectors.shaping import cap_text, clamp_limit, collect_pages

from .client import (
    FILE_ID_RE,
    LIST_TEXT_CHARS,
    THREAD_TEXT_CHARS,
    SlackBase,
    channel_id,
    items_of,
    message_ts,
    next_cursor,
    optional_text,
    optional_ts,
    require_id,
    require_text,
    scalar,
    scalars,
    shape_channel,
    shape_message,
    shape_user,
)
from .client import user_id as parse_user_id

_LIMIT = {"type": "integer", "description": "How many (default 10, max 50)"}
_CHANNEL = {
    "type": "string",
    "description": "Channel id such as C0123ABCD (from list_channels)",
    "required": True,
}

READ_ACTIONS: tuple[ToolSpec, ...] = (
    ToolSpec(
        "list_channels",
        "List Slack channels: id, name, privacy, whether Crawler is a member, topic. "
        "Optional name filter. Crawler can read history only where it is a member.",
        ActionCategory.READ,
        _schema(
            query={"type": "string", "description": "Only channels whose name contains this"},
            types={
                "type": "string",
                "enum": ["public", "private", "all"],
                "description": "Which channels (default all)",
            },
            limit=_LIMIT,
        ),
        required_scope="channels.read",
        starter=True,
    ),
    ToolSpec(
        "get_history",
        "Recent messages of a channel, newest first (ts, user id, text). Long texts are "
        "truncated; call get_thread with the message ts to read one in full.",
        ActionCategory.READ,
        _schema(
            channel=_CHANNEL,
            limit=_LIMIT,
            oldest={"type": "string", "description": "Only messages after this ts"},
            latest={"type": "string", "description": "Only messages before this ts"},
        ),
        required_scope="messages.read",
        starter=True,
    ),
    ToolSpec(
        "get_thread",
        "A message and its thread replies, oldest first, with longer texts than get_history.",
        ActionCategory.READ,
        _schema(
            channel=_CHANNEL,
            ts={"type": "string", "description": "ts of the parent message", "required": True},
            limit=_LIMIT,
        ),
        required_scope="messages.read",
    ),
    ToolSpec(
        "search_messages",
        "Search messages the user can see (Slack search syntax, e.g. 'budget in:#finance'). "
        "Needs the optional user token.",
        ActionCategory.READ,
        _schema(
            query={"type": "string", "description": "Search query", "required": True},
            sort={
                "type": "string",
                "enum": ["score", "timestamp"],
                "description": "Best match (default) or newest first",
            },
            limit=_LIMIT,
        ),
        required_scope="search.read",
    ),
    ToolSpec(
        "list_users",
        "List workspace members (id, handle, real and display name). Optional name filter.",
        ActionCategory.READ,
        _schema(
            query={"type": "string", "description": "Only people whose name contains this"},
            limit=_LIMIT,
        ),
        required_scope="users.read",
        starter=True,
    ),
    ToolSpec(
        "get_user",
        "One member's profile: names, title, time zone and status.",
        ActionCategory.READ,
        _schema(
            user_id={"type": "string", "description": "User id such as U0123ABCD", "required": True}
        ),
        required_scope="users.read",
    ),
    ToolSpec(
        "get_file_info",
        "Details of a shared file: name, type, size, owner, where it is shared, and a short "
        "text preview when Slack has one.",
        ActionCategory.READ,
        _schema(
            file_id={"type": "string", "description": "File id such as F0123ABCD", "required": True}
        ),
        required_scope="files.read",
    ),
)

_CHANNEL_TYPES = {
    "public": "public_channel",
    "private": "private_channel",
    "all": "public_channel,private_channel",
}
_SORTS = frozenset({"score", "timestamp"})
# Page size for list endpoints that are filtered locally by name.
_FILTER_PAGE = 200
_HISTORY_HINT = "Text truncated; call get_thread with this channel and ts to read it in full."
_THREAD_HINT = "Text truncated; open the message in Slack to read the rest."
_PREVIEW_CHARS = 2000


def _matches(needle: Optional[str], *values: Any) -> bool:
    return needle is None or any(
        isinstance(value, str) and needle in value.lower() for value in values
    )


class SlackReadsMixin(SlackBase):
    """The READ actions (one public coroutine per ``READ_ACTIONS`` entry)."""

    async def _paged(
        self,
        method: str,
        key: str,
        params: dict[str, Any],
        shape: Callable[[Any], Optional[dict[str, Any]]],
        *,
        limit: int,
        keep: Callable[[Any], bool] = lambda _raw: True,
    ) -> list[dict[str, Any]]:
        """Cursor-paginated *method*: shaped items under *key*, up to *limit*."""

        async def fetch(cursor: Optional[str]) -> tuple[list[Any], Optional[str]]:
            page_params = {**params, **({"cursor": cursor} if cursor else {})}
            data = await self._call(method, params=page_params)
            shaped = [shape(raw) for raw in items_of(data, key) if keep(raw)]
            return [item for item in shaped if item], next_cursor(data)

        return await collect_pages(fetch, limit=limit)

    async def list_channels(
        self, query: Any = None, types: Any = None, limit: Any = None
    ) -> list[dict[str, Any]]:
        needle = optional_text("query", query, max_chars=80)
        kinds = _CHANNEL_TYPES.get(types if isinstance(types, str) else "", None)
        if types is None:
            kinds = _CHANNEL_TYPES["all"]
        elif kinds is None:
            raise ConnectorError("types must be one of: public, private, all.")
        lowered = needle.lower() if needle else None
        return await self._paged(
            "conversations.list",
            "channels",
            {"types": kinds, "exclude_archived": "true", "limit": _FILTER_PAGE},
            shape_channel,
            limit=clamp_limit(limit),
            keep=lambda raw: isinstance(raw, dict) and _matches(lowered, raw.get("name")),
        )

    async def get_history(
        self, channel: Any, limit: Any = None, oldest: Any = None, latest: Any = None
    ) -> list[dict[str, Any]]:
        count = clamp_limit(limit)
        params: dict[str, Any] = {"channel": channel_id(channel), "limit": count}
        for name, value in (("oldest", oldest), ("latest", latest)):
            ts = optional_ts(value, name)
            if ts:
                params[name] = ts
        return await self._paged(
            "conversations.history",
            "messages",
            params,
            lambda raw: shape_message(raw, max_chars=LIST_TEXT_CHARS, hint=_HISTORY_HINT),
            limit=count,
        )

    async def get_thread(self, channel: Any, ts: Any, limit: Any = None) -> list[dict[str, Any]]:
        count = clamp_limit(limit)
        params = {"channel": channel_id(channel), "ts": message_ts(ts), "limit": count}
        return await self._paged(
            "conversations.replies",
            "messages",
            params,
            lambda raw: shape_message(raw, max_chars=THREAD_TEXT_CHARS, hint=_THREAD_HINT),
            limit=count,
        )

    async def search_messages(
        self, query: Any, sort: Any = None, limit: Any = None
    ) -> list[dict[str, Any]]:
        text = require_text("query", query, max_chars=500)
        if sort is not None and sort not in _SORTS:
            raise ConnectorError("sort must be 'score' or 'timestamp'.")
        count = clamp_limit(limit)
        # One page: Slack returns up to 100 matches per page, above our cap.
        data = await self._call(
            "search.messages",
            params={
                "query": text,
                "count": count,
                "sort": sort or "score",
                "sort_dir": "desc",
                "highlight": "false",
            },
            token="user",
            action="search_messages",
        )
        block = data.get("messages")
        matches = items_of(block, "matches") if isinstance(block, dict) else []
        results: list[dict[str, Any]] = []
        for raw in matches[:count]:
            shaped = shape_message(raw, max_chars=LIST_TEXT_CHARS, hint=_HISTORY_HINT)
            if shaped is None:
                continue
            channel = raw.get("channel")
            if isinstance(channel, dict):
                shaped["channel"] = scalars(channel, "id", "name")
            for key in ("username", "permalink"):
                value = scalar(raw.get(key))
                if value is not None:
                    shaped[key] = value
            results.append(shaped)
        return results

    async def list_users(self, query: Any = None, limit: Any = None) -> list[dict[str, Any]]:
        needle = optional_text("query", query, max_chars=80)
        lowered = needle.lower() if needle else None

        def keep(raw: Any) -> bool:
            if not isinstance(raw, dict) or raw.get("deleted") is True:
                return False
            profile = raw.get("profile")
            if not isinstance(profile, dict):
                profile = {}
            return _matches(
                lowered, raw.get("name"), raw.get("real_name"), profile.get("display_name")
            )

        return await self._paged(
            "users.list",
            "members",
            {"limit": _FILTER_PAGE},
            shape_user,
            limit=clamp_limit(limit),
            keep=keep,
        )

    async def get_user(self, user_id: Any) -> dict[str, Any]:
        data = await self._call("users.info", params={"user": parse_user_id(user_id)})
        return shape_user(data.get("user")) or {}

    async def get_file_info(self, file_id: Any) -> dict[str, Any]:
        file_ref = require_id(
            "file_id", file_id, FILE_ID_RE, "F0123ABCD", "use a file id from get_history"
        )
        # count=1: files.info also pages the file's comments, which we skip.
        data = await self._call("files.info", params={"file": file_ref, "count": 1})
        raw = data.get("file")
        if not isinstance(raw, dict):
            raise ConnectorError("Malformed response from Slack.")
        shaped = scalars(
            raw,
            "id",
            "name",
            "title",
            "mimetype",
            "filetype",
            "size",
            "user",
            "created",
            "is_public",
            "permalink",
        )
        shared: list[str] = []
        for key in ("channels", "groups", "ims"):
            value = raw.get(key)
            if isinstance(value, list):
                shared.extend(v for v in value if isinstance(v, str))
        shaped["shared_in"] = [v[:32] for v in shared[:20]]
        text = raw.get("preview")
        if isinstance(text, str) and text:
            shaped["preview"], truncated = cap_text(text, _PREVIEW_CHARS)
            if truncated:
                shaped["truncated"] = True
                shaped["hint"] = "Preview truncated; open the permalink in Slack for the full file."
        return shaped
