"""Shared constants, argument checks and request helpers for the Notion
connector's action mixins.

Why it exists: the read and write action groups (``reads.py``, ``writes.py``)
both need the same id validation, cursor pagination, bounded block-tree
loading and batched appends. ``NotionApiBase`` holds those helpers once;
``services/connectors/notion.py`` combines the mixins with the credentials,
headers and ``DEFINITION``.

It talks to the Notion REST API (https://api.notion.com/v1) only through
``BaseConnector._request_json`` (policy-checked, pinned, mapped errors). It
depends on ``services.connectors.base``, ``services.connectors.shaping`` and
the sibling ``markdown`` and ``properties`` modules.
"""

from __future__ import annotations

import json
from typing import Any, Optional

import httpx

from services.connectors.base import BaseConnector, ConnectorError, path_segment
from services.connectors.shaping import cap_text, clamp_limit, collect_pages

from .markdown import ARRAY_MAX_ITEMS, NO_DESCEND_TYPES, markdown_to_rich_text
from .properties import is_notion_id

API = "https://api.notion.com/v1"
#: The API version this connector is written against (spec 5.3).
NOTION_VERSION = "2022-06-28"

#: Notion's largest page_size.
PAGE_SIZE_MAX = 100
#: Pages a list action may fetch in one call.
MAX_LIST_PAGES = 3
#: get_page reads at most this many blocks, in at most this many children
#: requests, and pages through the top level at most this many times.
TREE_MAX_BLOCKS = 200
TREE_MAX_REQUESTS = 10
TREE_ROOT_PAGES = 2
#: Text caps for titles.
TITLE_CHARS = 300
#: Input bounds on model-supplied values.
MAX_CURSOR_CHARS = 256
MAX_TEXT_CHARS = 20_000
MAX_JSON_ARG_CHARS = 10_000

ID_HINT = "a Notion id (32 hex characters, dashes optional, from the end of the page link)"

#: Schema fragments shared by the action declarations.
LIMIT_PARAM: dict[str, Any] = {
    "type": "integer",
    "description": "How many items (default 10, max 50)",
}
CURSOR_PARAM: dict[str, Any] = {
    "type": "string",
    "description": "next_cursor from a previous call, to read the next items",
}


def id_param(description: str, *, required: bool = True) -> dict[str, Any]:
    """Schema for an id argument."""
    spec: dict[str, Any] = {"type": "string", "description": f"{description}: {ID_HINT}"}
    if required:
        spec["required"] = True
    return spec


# ---------------------------------------------------------------------------
# Argument checks and result shaping
# ---------------------------------------------------------------------------


def json_object(data: Any) -> dict[str, Any]:
    """*data* when Notion answered with a JSON object, else a clean error."""
    if not isinstance(data, dict):
        raise ConnectorError("Malformed response from Notion.")
    return data


def results(data: dict[str, Any]) -> list[dict[str, Any]]:
    """The object items of a list response (copies, safe to annotate)."""
    items = data.get("results")
    if not isinstance(items, list):
        raise ConnectorError("Malformed response from Notion.")
    return [dict(item) for item in items if isinstance(item, dict)]


def next_cursor(data: dict[str, Any]) -> Optional[str]:
    cursor = data.get("next_cursor")
    if data.get("has_more") is True and isinstance(cursor, str) and cursor:
        return cursor
    return None


def require_id(value: Any, field: str) -> str:
    if not is_notion_id(value):
        raise ConnectorError(f"{field} must be {ID_HINT}.")
    return str(value)


def optional_id(value: Any, field: str) -> Optional[str]:
    return None if value is None or value == "" else require_id(value, field)


def cursor_arg(value: Any) -> Optional[str]:
    if value is None or value == "":
        return None
    if (
        not isinstance(value, str)
        or len(value) > MAX_CURSOR_CHARS
        or any(char.isspace() for char in value)
    ):
        raise ConnectorError("start_cursor must be the next_cursor text from a previous call.")
    return value


def require_text(value: Any, field: str, *, max_chars: int = MAX_TEXT_CHARS) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ConnectorError(f"{field} must be non-empty text.")
    if len(value) > max_chars:
        raise ConnectorError(f"{field} is longer than {max_chars} characters.")
    return value


def capped(value: Any, max_chars: int) -> Optional[str]:
    """*value* cut to *max_chars* (with "..." when cut), None when not text."""
    if not isinstance(value, str):
        return None
    text, truncated = cap_text(value, max_chars)
    return text + "..." if truncated else text


def preview(text: str, max_chars: int = 80) -> str:
    """A one-line excerpt for approval texts."""
    flat = " ".join(text.split())
    return flat if len(flat) <= max_chars else flat[: max_chars - 3] + "..."


def compact(mapping: dict[str, Any]) -> dict[str, Any]:
    """*mapping* without None values (keeps results small)."""
    return {key: value for key, value in mapping.items() if value is not None}


def text_field(data: dict[str, Any], key: str) -> Optional[str]:
    value = data.get(key)
    return value if isinstance(value, str) else None


def parent_ref(value: Any) -> Optional[dict[str, Any]]:
    """``{"type": "page"|"database"|"block", "id"}`` or ``{"type": "workspace"}``."""
    if not isinstance(value, dict):
        return None
    kind = value.get("type")
    if kind == "workspace":
        return {"type": "workspace"}
    if isinstance(kind, str) and isinstance(value.get(kind), str):
        return {"type": kind.removesuffix("_id"), "id": value[kind]}
    return None


def json_arg(value: Any, field: str, kind: type) -> Any:
    """A model-supplied JSON object or array, type- and size-checked."""
    if value is None:
        return None
    if not isinstance(value, kind):
        raise ConnectorError(f"{field} must be a JSON {'object' if kind is dict else 'array'}.")
    if len(json.dumps(value, default=str)) > MAX_JSON_ARG_CHARS:
        raise ConnectorError(f"{field} is too large.")
    return value


def rich_text_arg(text: str, field: str, *, formatting: bool = True) -> list[dict[str, Any]]:
    """*text* as one rich-text array, refused when too long for one field."""
    rich = markdown_to_rich_text(text, formatting=formatting)
    if len(rich) > ARRAY_MAX_ITEMS:
        raise ConnectorError(f"{field} is too long for one Notion text field.")
    return rich


def _created_ids(response: httpx.Response) -> list[str]:
    """Ids of the blocks an append created, in order; [] when the body does
    not list them (the append itself succeeded either way)."""
    if not response.content.strip():
        return []
    try:
        data = response.json()
    except ValueError:
        return []
    listed = data.get("results") if isinstance(data, dict) else None
    if not isinstance(listed, list):
        return []
    return [
        item["id"] for item in listed if isinstance(item, dict) and isinstance(item.get("id"), str)
    ]


def _partial(exc: ConnectorError, done: int, total: int, last_id: Optional[str]) -> ConnectorError:
    """*exc* as the same type, saying how much was already written."""
    where = f"; the last block added is {last_id}" if last_id else ""
    return type(exc)(f"{exc} Only {done} of {total} top-level blocks were added{where}.")


# ---------------------------------------------------------------------------
# Request helpers shared by the action mixins
# ---------------------------------------------------------------------------


class NotionApiBase(BaseConnector):
    """Abstract base of the Notion action mixins: request helpers only.

    ``NotionConnector`` (services/connectors/notion.py) supplies the token,
    headers and the abstract members of ``BaseConnector``.
    """

    async def _collect(
        self,
        method: str,
        path: str,
        *,
        limit: Any,
        start_cursor: Any,
        params: Optional[dict[str, Any]] = None,
        body: Optional[dict[str, Any]] = None,
    ) -> tuple[list[dict[str, Any]], Optional[str]]:
        """Up to *limit* results of a cursor-paginated endpoint, and the
        cursor to continue from (None when everything was read).

        Each request asks for exactly the items still wanted, so the cursor
        Notion returns is the exact place to resume. A cursor Notion repeats
        ends the listing instead of looping.
        """
        wanted = clamp_limit(limit)
        first = cursor_arg(start_cursor)
        got = 0
        following: Optional[str] = None
        used: set[str] = set()

        async def fetch(cursor: Optional[str]) -> tuple[list[Any], Optional[str]]:
            nonlocal got, following
            current = cursor or first
            size = max(1, min(PAGE_SIZE_MAX, wanted - got))
            if current:
                used.add(current)
            if method == "GET":
                query = {**(params or {}), "page_size": size}
                if current:
                    query["start_cursor"] = current
                data = await self._request_json("GET", f"{API}{path}", params=query)
            else:
                payload = {**(body or {}), "page_size": size}
                if current:
                    payload["start_cursor"] = current
                data = await self._request_json(method, f"{API}{path}", json=payload)
            page = json_object(data)
            items = results(page)
            following = next_cursor(page)
            if following in used:
                following = None
            got += len(items)
            return items, following

        items = await collect_pages(fetch, limit=wanted, max_pages=MAX_LIST_PAGES)
        return items, following

    @staticmethod
    def _listing(
        items: list[dict[str, Any]], following: Optional[str], action: str
    ) -> dict[str, Any]:
        """A list result: top-level ``items`` (per-item redaction works on
        them), plus the cursor and a hint when there is more."""
        listing: dict[str, Any] = {"items": items, "count": len(items)}
        if following:
            listing["next_cursor"] = following
            listing["hint"] = f"More results: call {action} again with start_cursor=next_cursor."
        return listing

    async def _children_page(
        self, block_id: str, cursor: Optional[str], size: int
    ) -> tuple[list[dict[str, Any]], Optional[str]]:
        """One page of a block's children and the cursor after it."""
        params: dict[str, Any] = {"page_size": max(1, min(PAGE_SIZE_MAX, size))}
        if cursor:
            params["start_cursor"] = cursor
        data = json_object(
            await self._request_json(
                "GET", f"{API}/blocks/{path_segment(block_id)}/children", params=params
            )
        )
        following = next_cursor(data)
        return results(data), None if following == cursor else following

    async def _load_tree(
        self, root_id: str
    ) -> tuple[list[dict[str, Any]], list[dict[str, Any]], bool]:
        """The page's blocks with nested children attached (depth 2 at most).

        Bounded: at most TREE_MAX_BLOCKS blocks through TREE_MAX_REQUESTS
        children requests, so one page never fans out into dozens of calls.
        Nested children ride in ``block["_children"]``. Returns (top-level
        blocks, continuation entries ``{"block_id", "start_cursor"?}``, True
        when anything was left unread).
        """
        blocks_left, requests_left = TREE_MAX_BLOCKS, TREE_MAX_REQUESTS
        top: list[dict[str, Any]] = []
        more: list[dict[str, Any]] = []
        cursor: Optional[str] = None
        pending: Optional[str] = None
        seen: set[str] = set()
        for page_number in range(TREE_ROOT_PAGES):
            items, pending = await self._children_page(root_id, cursor, blocks_left)
            requests_left -= 1
            kept = items[:blocks_left]
            top.extend(kept)
            blocks_left -= len(kept)
            if pending in seen:
                pending = None
            if not pending or blocks_left <= 0 or page_number == TREE_ROOT_PAGES - 1:
                break
            seen.add(pending)
            cursor = pending
        if pending:
            more.append({"block_id": root_id, "start_cursor": pending})

        incomplete = bool(pending)
        for block in top:
            block_id = block.get("id")
            if block.get("has_children") is not True or block.get("type") in NO_DESCEND_TYPES:
                continue
            if not isinstance(block_id, str) or not is_notion_id(block_id):
                continue
            if requests_left <= 0 or blocks_left <= 0:
                more.append({"block_id": block_id})
                incomplete = True
                continue
            children, child_more = await self._children_page(block_id, None, blocks_left)
            requests_left -= 1
            kept = children[:blocks_left]
            blocks_left -= len(kept)
            block["_children"] = kept
            if child_more or len(children) > len(kept):
                more.append(compact({"block_id": block_id, "start_cursor": child_more}))
                incomplete = True
            if any(
                child.get("has_children") is True and child.get("type") not in NO_DESCEND_TYPES
                for child in kept
            ):
                # Depth limit: grandchildren are marked in the Markdown.
                incomplete = True
        return top, more, incomplete

    async def _append_batches(
        self,
        block_id: str,
        batches: list[list[dict[str, Any]]],
        *,
        after: Optional[str],
        done_before: int,
        total: int,
    ) -> tuple[int, Optional[str], Optional[str]]:
        """Append *batches* in order; returns (top-level blocks added,
        first new block id, last new block id).

        A failure part way through says how much was already written. A 2xx
        answer means the batch is written even when its body is unusable, so
        an odd body only fails the call when the next batch must be placed
        after the new blocks (``after`` chaining) and their ids are missing.
        """
        done = done_before
        first_id: Optional[str] = None
        last_id: Optional[str] = None
        url = f"{API}/blocks/{path_segment(block_id)}/children"
        for index, batch in enumerate(batches):
            body: dict[str, Any] = {"children": batch}
            if after:
                body["after"] = after
            try:
                response = await self._request("PATCH", url, json=body)
            except ConnectorError as exc:
                if done == 0:
                    raise
                raise _partial(exc, done, total, last_id) from None
            done += len(batch)
            created_ids = _created_ids(response)
            if created_ids:
                first_id = first_id or created_ids[0]
                last_id = created_ids[-1]
            if after and index + 1 < len(batches):
                # The next batch goes after the one just written.
                if not created_ids:
                    raise _partial(
                        ConnectorError(
                            "Malformed response from Notion: it did not list the new "
                            "blocks, so the rest cannot be placed after them."
                        ),
                        done,
                        total,
                        last_id,
                    )
                after = created_ids[-1]
        return done - done_before, first_id, last_id
