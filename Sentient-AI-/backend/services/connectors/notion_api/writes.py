"""The Notion connector's WRITE and DELETE actions: create_page,
append_blocks, update_page_properties, create_database_row, update_block,
add_comment, archive_page and delete_block.

Why it exists: every change to a user's Notion workspace goes through here,
and each one first raises ``UserConfirmationRequired`` (with a plain
description of exactly what will change) before any request is sent.
Markdown input is converted and chunked to Notion's limits (100 children
per request, 2000 characters per rich-text object) before approval, so a
call that cannot succeed fails at once.

It talks to the Notion REST API (https://api.notion.com/v1) through
``NotionApiBase`` (``common.py``). It depends on the sibling ``markdown`` and
``properties`` modules and ``services.connectors.definition``.
"""

from __future__ import annotations

from typing import Any, Optional

from services.agent.permissions import ActionCategory
from services.connectors.base import ConnectorError, UserConfirmationRequired, path_segment
from services.connectors.definition import ToolSpec, _schema
from services.connectors.shaping import cap_text

from .common import (
    API,
    MAX_TEXT_CHARS,
    TITLE_CHARS,
    NotionApiBase,
    capped,
    compact,
    id_param,
    json_object,
    optional_id,
    preview,
    require_id,
    require_text,
    rich_text_arg,
    text_field,
)
from .markdown import (
    MAX_MARKDOWN_CHARS,
    TEXT_BLOCK_TYPES,
    batch_blocks,
    markdown_to_blocks,
    render_block,
)
from .properties import (
    build_properties,
    is_notion_id,
    needs_schema,
    page_title,
    precheck_properties,
    render_properties,
    schema_types,
)

_BLOCK_MARKDOWN_CHARS = 2_000
_PROPERTY_CHARS = 200

WRITE_ACTIONS: tuple[ToolSpec, ...] = (
    ToolSpec(
        "create_page",
        "Create a Notion page inside a parent page, with optional Markdown content.",
        ActionCategory.WRITE,
        _schema(
            parent_page_id=id_param("The parent page"),
            title={"type": "string", "description": "Page title", "required": True},
            content={
                "type": "string",
                "description": "Markdown body: headings, paragraphs, lists, to-dos, "
                "quotes, code blocks, dividers",
            },
        ),
        required_scope="notion.write",
    ),
    ToolSpec(
        "append_blocks",
        "Append Markdown content (headings, paragraphs, bulleted and numbered "
        "lists, to-dos, quotes, code blocks, dividers) to a Notion page or block.",
        ActionCategory.WRITE,
        _schema(
            block_id=id_param("The page or block to add to"),
            markdown={"type": "string", "description": "The Markdown to add", "required": True},
            after=id_param("Insert after this child block instead of at the end", required=False),
        ),
        required_scope="notion.write",
    ),
    ToolSpec(
        "update_page_properties",
        "Set property values on a Notion page or database row. Values are plain "
        '(e.g. {"Status": "Done", "Due": "2026-10-01", "Tags": ["a"], "Done": true}) '
        'or typed (e.g. {"Status": {"select": "Done"}}).',
        ActionCategory.WRITE,
        _schema(
            page_id=id_param("The page or row"),
            properties={
                "type": "object",
                "description": "Property name to new value",
                "required": True,
            },
        ),
        required_scope="notion.write",
    ),
    ToolSpec(
        "create_database_row",
        "Add a row (page) to a Notion database with property values, and "
        "optional Markdown content.",
        ActionCategory.WRITE,
        _schema(
            database_id=id_param("The database"),
            properties={
                "type": "object",
                "description": "Property name to value (plain or typed, as in "
                "update_page_properties); include the title property",
                "required": True,
            },
            content={"type": "string", "description": "Optional Markdown body"},
        ),
        required_scope="notion.write",
    ),
    ToolSpec(
        "update_block",
        "Replace the text of one Notion block (paragraph, heading, list item, "
        "to-do, toggle, quote, callout or code). The block keeps its type.",
        ActionCategory.WRITE,
        _schema(
            block_id=id_param("The block"),
            text={
                "type": "string",
                "description": "New text; inline Markdown (bold, italic, code, links) is kept",
                "required": True,
            },
            checked={"type": "boolean", "description": "For a to-do: tick or untick it"},
        ),
        required_scope="notion.write",
    ),
    ToolSpec(
        "add_comment",
        "Post a comment on a Notion page, or reply in an existing discussion. "
        "Comments are visible to everyone with access to the page.",
        ActionCategory.WRITE,
        _schema(
            text={"type": "string", "description": "The comment", "required": True},
            page_id=id_param("The page to comment on", required=False),
            discussion_id=id_param(
                "A discussion to reply in (instead of page_id)", required=False
            ),
        ),
        required_scope="notion.comment",
        always_confirm=True,
    ),
)

DELETE_ACTIONS: tuple[ToolSpec, ...] = (
    ToolSpec(
        "archive_page",
        "Archive a Notion page (moves it and everything inside it to Notion's trash).",
        ActionCategory.DELETE,
        _schema(page_id=id_param("The page")),
        required_scope="notion.delete",
        always_confirm=True,
    ),
    ToolSpec(
        "delete_block",
        "Delete one Notion block and anything nested inside it (moves it to trash).",
        ActionCategory.DELETE,
        _schema(block_id=id_param("The block")),
        required_scope="notion.delete",
        always_confirm=True,
    ),
)


def _property_names(properties: dict[str, Any]) -> str:
    names = sorted(str(name) for name in properties)
    shown = ", ".join(preview(name, 40) for name in names[:10])
    return shown + (f" and {len(names) - 10} more" if len(names) > 10 else "")


class WritesMixin(NotionApiBase):
    """WRITE and DELETE actions. Each raises UserConfirmationRequired before
    any request unless ``user_confirmed`` is True."""

    async def _create_under(
        self, parent: dict[str, str], properties: dict[str, Any], blocks: list[dict[str, Any]]
    ) -> dict[str, Any]:
        """POST a page with the first batch of blocks, then append the rest.

        When a follow-up append fails, the page already exists: the error
        names it, so the model continues it with append_blocks instead of
        creating a duplicate.
        """
        batches = batch_blocks(blocks)
        body: dict[str, Any] = {"parent": parent, "properties": properties}
        if batches:
            body["children"] = batches[0]
        page = json_object(await self._request_json("POST", f"{API}/pages", json=body))
        if len(batches) > 1:
            new_id = page.get("id")
            if not is_notion_id(new_id):
                raise ConnectorError(
                    f"Malformed response from Notion: the page was probably created with "
                    f"only the first {len(batches[0])} of {len(blocks)} top-level blocks, "
                    "but its id is unknown. Find it with search before trying again."
                )
            try:
                await self._append_batches(
                    str(new_id),
                    batches[1:],
                    after=None,
                    done_before=len(batches[0]),
                    total=len(blocks),
                )
            except ConnectorError as exc:
                url = capped(text_field(page, "url"), TITLE_CHARS)
                link = f", {url}" if url else ""
                raise type(exc)(
                    f"{exc} The page was created (id {new_id}{link}); do not create it "
                    f"again, add the missing content with append_blocks block_id={new_id}."
                ) from None
        return page

    async def create_page(
        self,
        parent_page_id: Any,
        title: Any,
        content: Any = None,
        *,
        user_confirmed: bool = False,
    ) -> dict[str, Any]:
        parent = require_id(parent_page_id, "parent_page_id")
        title_text = require_text(title, "title", max_chars=2000)
        title_rich = rich_text_arg(title_text, "title", formatting=False)
        blocks = markdown_to_blocks(content) if content is not None else []
        if not user_confirmed:
            raise UserConfirmationRequired(
                action="create_page",
                details=(
                    f"Create a Notion page titled '{preview(title_text)}' inside page "
                    f"{parent} with {len(blocks)} top-level content blocks."
                ),
            )
        page = await self._create_under(
            {"page_id": parent}, {"title": {"title": title_rich}}, blocks
        )
        return compact(
            {
                "id": page.get("id"),
                "url": text_field(page, "url"),
                "title": preview(title_text, TITLE_CHARS),
                "blocks_added": len(blocks),
            }
        )

    async def append_blocks(
        self,
        block_id: Any,
        markdown: Any,
        after: Any = None,
        *,
        user_confirmed: bool = False,
    ) -> dict[str, Any]:
        target = require_id(block_id, "block_id")
        after_id = optional_id(after, "after")
        text = require_text(markdown, "markdown", max_chars=MAX_MARKDOWN_CHARS)
        blocks = markdown_to_blocks(text)
        if not blocks:
            raise ConnectorError("markdown produced no blocks to add.")
        if not user_confirmed:
            where = f"after block {after_id} in" if after_id else "at the end of"
            raise UserConfirmationRequired(
                action="append_blocks",
                details=(
                    f"Add {len(blocks)} top-level blocks {where} Notion page or block "
                    f"{target}, starting with '{preview(text)}'."
                ),
            )
        added, first_id, last_id = await self._append_batches(
            target, batch_blocks(blocks), after=after_id, done_before=0, total=len(blocks)
        )
        return compact(
            {
                "block_id": target,
                "appended": added,
                "first_block_id": first_id,
                "last_block_id": last_id,
            }
        )

    async def update_page_properties(
        self, page_id: Any, properties: Any, *, user_confirmed: bool = False
    ) -> dict[str, Any]:
        target = require_id(page_id, "page_id")
        precheck_properties(properties)
        if not user_confirmed:
            raise UserConfirmationRequired(
                action="update_page_properties",
                details=(
                    f"Change the properties {_property_names(properties)} on Notion page "
                    f"{target}."
                ),
            )
        schema: Optional[dict[str, str]] = None
        if needs_schema(properties):
            # Plain values take their type from the page's own properties.
            page = json_object(
                await self._request_json("GET", f"{API}/pages/{path_segment(target)}")
            )
            schema = schema_types(page.get("properties"))
        built = build_properties(properties, schema)
        data = json_object(
            await self._request_json(
                "PATCH", f"{API}/pages/{path_segment(target)}", json={"properties": built}
            )
        )
        rendered = render_properties(data.get("properties"), max_chars=_PROPERTY_CHARS)
        return compact(
            {
                "id": data.get("id"),
                "url": text_field(data, "url"),
                "properties": {name: rendered[name] for name in built if name in rendered},
            }
        )

    async def create_database_row(
        self,
        database_id: Any,
        properties: Any,
        content: Any = None,
        *,
        user_confirmed: bool = False,
    ) -> dict[str, Any]:
        target = require_id(database_id, "database_id")
        precheck_properties(properties)
        blocks = markdown_to_blocks(content) if content is not None else []
        if not user_confirmed:
            with_content = f", with {len(blocks)} content blocks" if blocks else ""
            raise UserConfirmationRequired(
                action="create_database_row",
                details=(
                    f"Add a row to Notion database {target} setting "
                    f"{_property_names(properties)}{with_content}."
                ),
            )
        schema: Optional[dict[str, str]] = None
        if needs_schema(properties):
            database = json_object(
                await self._request_json("GET", f"{API}/databases/{path_segment(target)}")
            )
            schema = schema_types(database.get("properties"))
        built = build_properties(properties, schema)
        page = await self._create_under({"database_id": target}, built, blocks)
        return compact(
            {
                "id": page.get("id"),
                "url": text_field(page, "url"),
                "title": capped(page_title(page), TITLE_CHARS) or None,
                "blocks_added": len(blocks) or None,
            }
        )

    async def update_block(
        self,
        block_id: Any,
        text: Any,
        checked: Any = None,
        *,
        user_confirmed: bool = False,
    ) -> dict[str, Any]:
        target = require_id(block_id, "block_id")
        if not isinstance(text, str) or len(text) > MAX_TEXT_CHARS:
            raise ConnectorError(f"text must be text up to {MAX_TEXT_CHARS} characters.")
        if checked is not None and not isinstance(checked, bool):
            raise ConnectorError("checked must be true or false.")
        rich_text_arg(text, "text")  # too long for one block fails before approval
        if not user_confirmed:
            tick = "" if checked is None else (" and tick it" if checked else " and untick it")
            raise UserConfirmationRequired(
                action="update_block",
                details=f"Replace the text of Notion block {target} with '{preview(text)}'{tick}.",
            )
        # The payload is keyed by the block's type, which only Notion knows.
        block = json_object(await self._request_json("GET", f"{API}/blocks/{path_segment(target)}"))
        btype = block.get("type")
        if not isinstance(btype, str) or btype not in TEXT_BLOCK_TYPES:
            raise ConnectorError(
                f"Block {target} is a '{btype}' block; only text blocks can be updated."
            )
        if checked is not None and btype != "to_do":
            raise ConnectorError("checked applies only to to-do blocks.")
        payload: dict[str, Any] = {
            "rich_text": rich_text_arg(text, "text", formatting=btype != "code")
        }
        if checked is not None:
            payload["checked"] = checked
        data = json_object(
            await self._request_json(
                "PATCH", f"{API}/blocks/{path_segment(target)}", json={btype: payload}
            )
        )
        markdown, _ = cap_text(render_block(data, markers=False), _BLOCK_MARKDOWN_CHARS)
        return compact({"id": data.get("id"), "type": data.get("type"), "markdown": markdown})

    async def add_comment(
        self,
        text: Any,
        page_id: Any = None,
        discussion_id: Any = None,
        *,
        user_confirmed: bool = False,
    ) -> dict[str, Any]:
        body_text = require_text(text, "text")
        page = optional_id(page_id, "page_id")
        discussion = optional_id(discussion_id, "discussion_id")
        if (page is None) == (discussion is None):
            raise ConnectorError("Give exactly one of page_id or discussion_id.")
        rich = rich_text_arg(body_text, "text")
        if not user_confirmed:
            where = f"on Notion page {page}" if page else f"in Notion discussion {discussion}"
            raise UserConfirmationRequired(
                action="add_comment",
                details=(
                    f"Post a comment {where}, visible to everyone with access to the page: "
                    f"'{preview(body_text, 200)}'."
                ),
            )
        body: dict[str, Any] = {"rich_text": rich}
        if page:
            body["parent"] = {"page_id": page}
        else:
            body["discussion_id"] = discussion
        data = json_object(await self._request_json("POST", f"{API}/comments", json=body))
        return compact({"id": data.get("id"), "discussion_id": data.get("discussion_id")})

    async def archive_page(self, page_id: Any, *, user_confirmed: bool = False) -> dict[str, Any]:
        target = require_id(page_id, "page_id")
        if not user_confirmed:
            raise UserConfirmationRequired(
                action="archive_page",
                details=(
                    f"Archive Notion page {target}: it and every page inside it move to "
                    "Notion's trash."
                ),
            )
        data = json_object(
            await self._request_json(
                "PATCH", f"{API}/pages/{path_segment(target)}", json={"archived": True}
            )
        )
        return {"id": text_field(data, "id") or target, "archived": data.get("archived") is True}

    async def delete_block(self, block_id: Any, *, user_confirmed: bool = False) -> dict[str, Any]:
        target = require_id(block_id, "block_id")
        if not user_confirmed:
            raise UserConfirmationRequired(
                action="delete_block",
                details=(
                    f"Delete Notion block {target} and anything nested inside it "
                    "(it moves to Notion's trash)."
                ),
            )
        data = json_object(
            await self._request_json("DELETE", f"{API}/blocks/{path_segment(target)}")
        )
        return {"id": text_field(data, "id") or target, "deleted": True}
