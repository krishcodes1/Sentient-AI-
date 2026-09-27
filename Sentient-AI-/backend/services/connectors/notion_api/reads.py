"""The Notion connector's READ actions: search, get_page, get_block_children,
query_database, get_database, list_comments and list_users.

Why it exists: reads are most of what the agent does in Notion, and they
carry the output shaping (compact properties, Markdown content with caps and
truncation hints, cursor listings). Keeping them apart from the writes keeps
both files readable; ``services/connectors/notion.py`` assembles the class.

It talks to the Notion REST API (https://api.notion.com/v1) through
``NotionApiBase`` (``common.py``). It depends on the sibling ``markdown`` and
``properties`` modules, ``services.connectors.definition`` and
``services.connectors.shaping``.
"""

from __future__ import annotations

from typing import Any

from services.agent.permissions import ActionCategory
from services.connectors.base import ConnectorError, path_segment
from services.connectors.definition import ToolSpec, _schema
from services.connectors.shaping import cap_text

from .common import (
    API,
    CURSOR_PARAM,
    LIMIT_PARAM,
    TITLE_CHARS,
    NotionApiBase,
    capped,
    compact,
    id_param,
    json_arg,
    json_object,
    parent_ref,
    require_id,
    text_field,
)
from .markdown import render_block, render_blocks, rich_text_plain
from .properties import page_title, render_properties, render_schema

#: Longest search query accepted.
_MAX_QUERY_CHARS = 500
#: Markdown caps: a whole page, and one block in get_block_children.
_PAGE_MARKDOWN_CHARS = 12_000
_BLOCK_MARKDOWN_CHARS = 2_000
#: Text caps for property values and comments.
_PAGE_PROPERTY_CHARS = 1_000
_ROW_PROPERTY_CHARS = 200
_COMMENT_CHARS = 1_000
#: Continuation entries get_page lists when content was left unread.
_MAX_MORE_ENTRIES = 5

READ_ACTIONS: tuple[ToolSpec, ...] = (
    ToolSpec(
        "search",
        "Search the Notion pages and databases shared with Crawler by title. "
        "Returns ids, titles and links.",
        ActionCategory.READ,
        _schema(
            query={"type": "string", "description": "Words in the title (omit to list recent items)"},
            object_type={
                "type": "string",
                "enum": ["page", "database"],
                "description": "Only pages or only databases",
            },
            limit=LIMIT_PARAM,
            start_cursor=CURSOR_PARAM,
        ),
        required_scope="notion.read",
        starter=True,
    ),
    ToolSpec(
        "get_page",
        "Read a Notion page: its properties and its content as Markdown. Long or "
        "deeply nested pages are truncated; the result says so and names the "
        "blocks to read with get_block_children.",
        ActionCategory.READ,
        _schema(page_id=id_param("The page")),
        required_scope="notion.read",
        starter=True,
    ),
    ToolSpec(
        "get_block_children",
        "Read the child blocks of a page or block as Markdown, with each block's "
        "id and type (use the ids with update_block or delete_block).",
        ActionCategory.READ,
        _schema(
            block_id=id_param("The page or block"),
            start_cursor=CURSOR_PARAM,
            limit=LIMIT_PARAM,
        ),
        required_scope="notion.read",
    ),
    ToolSpec(
        "query_database",
        "List rows of a Notion database with their property values. Optional "
        "Notion filter and sorts objects narrow and order the rows.",
        ActionCategory.READ,
        _schema(
            database_id=id_param("The database"),
            filter={
                "type": "object",
                "description": "A Notion database filter object, e.g. "
                '{"property": "Status", "status": {"equals": "Done"}}',
            },
            sorts={
                "type": "array",
                "items": {"type": "object"},
                "description": "Notion sort objects, e.g. "
                '[{"property": "Due", "direction": "ascending"}]',
            },
            limit=LIMIT_PARAM,
            start_cursor=CURSOR_PARAM,
        ),
        required_scope="notion.read",
        starter=True,
    ),
    ToolSpec(
        "get_database",
        "Read a Notion database's title, description and property schema "
        "(names, types and select options).",
        ActionCategory.READ,
        _schema(database_id=id_param("The database")),
        required_scope="notion.read",
    ),
    ToolSpec(
        "list_comments",
        "List the open comments on a Notion page or block.",
        ActionCategory.READ,
        _schema(
            block_id=id_param("The page or block"),
            limit=LIMIT_PARAM,
            start_cursor=CURSOR_PARAM,
        ),
        required_scope="notion.read",
    ),
    ToolSpec(
        "list_users",
        "List the people and bots in the Notion workspace (ids and names, for "
        "people properties).",
        ActionCategory.READ,
        _schema(limit=LIMIT_PARAM, start_cursor=CURSOR_PARAM),
        required_scope="notion.read",
    ),
)


def _page_content(top: list[dict[str, Any]]) -> tuple[list[str], bool]:
    """Top-level blocks as Markdown strings within the page cap, and
    whether the cap cut anything."""
    parts = render_blocks(top)
    content: list[str] = []
    room = _PAGE_MARKDOWN_CHARS
    for index, part in enumerate(parts):
        text, truncated = cap_text(part, room)
        if text:
            content.append(text)
        room -= len(text)
        if truncated or (room <= 0 and index < len(parts) - 1):
            return content, True
    return content, False


class ReadsMixin(NotionApiBase):
    """READ actions. Never take ``user_confirmed``; never write."""

    async def search(
        self,
        query: Any = None,
        object_type: Any = None,
        limit: Any = None,
        start_cursor: Any = None,
    ) -> dict[str, Any]:
        body: dict[str, Any] = {}
        if query is not None and query != "":
            if not isinstance(query, str) or len(query) > _MAX_QUERY_CHARS:
                raise ConnectorError(f"query must be text up to {_MAX_QUERY_CHARS} characters.")
            body["query"] = query
        if object_type is not None and object_type != "":
            if object_type not in ("page", "database"):
                raise ConnectorError("object_type must be 'page' or 'database'.")
            body["filter"] = {"property": "object", "value": object_type}
        items, following = await self._collect(
            "POST", "/search", limit=limit, start_cursor=start_cursor, body=body
        )
        shaped = [
            compact(
                {
                    "id": item.get("id"),
                    "type": item.get("object"),
                    "title": capped(page_title(item), TITLE_CHARS),
                    "url": text_field(item, "url"),
                    "last_edited": item.get("last_edited_time"),
                }
            )
            for item in items
        ]
        return self._listing(shaped, following, "search")

    async def get_page(self, page_id: Any) -> dict[str, Any]:
        page_id = require_id(page_id, "page_id")
        page = json_object(await self._request_json("GET", f"{API}/pages/{path_segment(page_id)}"))
        top, more, incomplete = await self._load_tree(page_id)
        content, cut = _page_content(top)
        truncated = incomplete or cut
        result = compact(
            {
                "id": page.get("id"),
                "title": capped(page_title(page), TITLE_CHARS),
                "url": text_field(page, "url"),
                "last_edited": page.get("last_edited_time"),
                "archived": True if page.get("archived") is True else None,
                "parent": parent_ref(page.get("parent")),
                "properties": render_properties(
                    page.get("properties"), max_chars=_PAGE_PROPERTY_CHARS, skip_title=True
                ),
                "content": content,
                "truncated": truncated,
            }
        )
        if truncated:
            result["hint"] = (
                "Content was truncated. Read the rest with get_block_children, using a "
                "block_id (and start_cursor) from 'more' or from a 'nested content not "
                "loaded' line."
            )
        if more:
            result["more"] = more[:_MAX_MORE_ENTRIES]
        return result

    async def get_block_children(
        self, block_id: Any, start_cursor: Any = None, limit: Any = None
    ) -> dict[str, Any]:
        block_id = require_id(block_id, "block_id")
        items, following = await self._collect(
            "GET",
            f"/blocks/{path_segment(block_id)}/children",
            limit=limit,
            start_cursor=start_cursor,
        )
        shaped: list[dict[str, Any]] = []
        number = 0
        for block in items:
            raw_type = block.get("type")
            btype = raw_type if isinstance(raw_type, str) else "unknown"
            number = number + 1 if btype == "numbered_list_item" else 0
            markdown, truncated = cap_text(
                render_block(block, number=number, markers=False), _BLOCK_MARKDOWN_CHARS
            )
            shaped.append(
                compact(
                    {
                        "id": block.get("id"),
                        "type": btype,
                        "markdown": markdown,
                        "has_children": block.get("has_children") is True,
                        "truncated": True if truncated else None,
                    }
                )
            )
        listing = self._listing(shaped, following, "get_block_children")
        if any(entry.get("truncated") for entry in shaped):
            listing["note"] = (
                f"Blocks marked truncated were cut at {_BLOCK_MARKDOWN_CHARS} characters."
            )
        return listing

    async def query_database(
        self,
        database_id: Any,
        filter: Any = None,  # Notion's own name for it
        sorts: Any = None,
        limit: Any = None,
        start_cursor: Any = None,
    ) -> dict[str, Any]:
        database_id = require_id(database_id, "database_id")
        body: dict[str, Any] = {}
        checked_filter = json_arg(filter, "filter", dict)
        if checked_filter is not None:
            body["filter"] = checked_filter
        checked_sorts = json_arg(sorts, "sorts", list)
        if checked_sorts is not None:
            if not all(isinstance(item, dict) for item in checked_sorts):
                raise ConnectorError("sorts must be a list of Notion sort objects.")
            body["sorts"] = checked_sorts
        items, following = await self._collect(
            "POST",
            f"/databases/{path_segment(database_id)}/query",
            limit=limit,
            start_cursor=start_cursor,
            body=body,
        )
        shaped = [
            compact(
                {
                    "id": item.get("id"),
                    "properties": render_properties(
                        item.get("properties"), max_chars=_ROW_PROPERTY_CHARS
                    ),
                    "last_edited": item.get("last_edited_time"),
                }
            )
            for item in items
        ]
        return self._listing(shaped, following, "query_database")

    async def get_database(self, database_id: Any) -> dict[str, Any]:
        database_id = require_id(database_id, "database_id")
        data = json_object(
            await self._request_json("GET", f"{API}/databases/{path_segment(database_id)}")
        )
        return compact(
            {
                "id": data.get("id"),
                "title": capped(page_title(data), TITLE_CHARS),
                "description": capped(rich_text_plain(data.get("description")), 500) or None,
                "url": text_field(data, "url"),
                "properties": render_schema(data.get("properties")),
            }
        )

    async def list_comments(
        self, block_id: Any, limit: Any = None, start_cursor: Any = None
    ) -> dict[str, Any]:
        block_id = require_id(block_id, "block_id")
        items, following = await self._collect(
            "GET",
            "/comments",
            limit=limit,
            start_cursor=start_cursor,
            params={"block_id": block_id},
        )
        shaped = []
        for item in items:
            author = item.get("created_by")
            shaped.append(
                compact(
                    {
                        "id": item.get("id"),
                        "discussion_id": item.get("discussion_id"),
                        "created": item.get("created_time"),
                        "author_id": author.get("id") if isinstance(author, dict) else None,
                        "text": capped(rich_text_plain(item.get("rich_text")), _COMMENT_CHARS),
                    }
                )
            )
        return self._listing(shaped, following, "list_comments")

    async def list_users(self, limit: Any = None, start_cursor: Any = None) -> dict[str, Any]:
        items, following = await self._collect(
            "GET", "/users", limit=limit, start_cursor=start_cursor
        )
        shaped = [
            compact(
                {
                    "id": item.get("id"),
                    "name": capped(item.get("name"), 100),
                    "type": item.get("type"),
                }
            )
            for item in items
        ]
        return self._listing(shaped, following, "list_users")
