"""Behaviour, failure and security tests for the Notion connector.

Why it exists: pins every Notion action's request (method, host, raw path,
query and body) and shaped result, the approval gate on every write, the
failure matrix (401, 403, 404, 409, 429, 500, timeouts, malformed and hostile
payloads, pagination that ends early or repeats a cursor), the bounded
get_page block loading, the network allowlist and that the integration
secret never appears in a result or an error.
Connects to: services/connectors/notion.py and the notion_api package. All
HTTP goes to httpx.MockTransport; no network, no real credentials.
"""

from __future__ import annotations

import json
import time
from typing import Any, Callable

import httpx
import pytest

import core.network_security as netsec
from core.network_security import NetworkPolicy
from services.connectors.base import (
    AuthenticationError,
    ConnectorError,
    RateLimitExceededError,
    UserConfirmationRequired,
)
from services.connectors.notion import DEFINITION, NotionConnector
from services.connectors.registry import validate_registry

TOKEN = "ntn_test_fake_integration_secret_0000000000"  # obviously fake
PAGE = "1a2b3c4d5e6f47809a1b2c3d4e5f6a7b"
DB = "2b3c4d5e-6f70-4809-a1b2-c3d4e5f6a7b8"
BLOCK = "3c4d5e6f708149a0b1c2d3e4f5a6b7c8"
CHILD = "4d5e6f708192405ab1c2d3e4f5a6b7c9"
USER = "5e6f708192a3415bb1c2d3e4f5a6b7ca"

Handler = Callable[[httpx.Request], httpx.Response]


def _connector(handler: Handler) -> tuple[NotionConnector, list[httpx.Request]]:
    """An authenticated connector whose HTTP goes to *handler*; records requests."""
    seen: list[httpx.Request] = []

    def recording(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return handler(request)

    connector = NotionConnector()
    connector._authenticated = True
    connector._token = TOKEN
    connector._http_client = httpx.AsyncClient(transport=httpx.MockTransport(recording))

    async def no_sleep(_seconds: float) -> None:
        return None

    connector._sleep = no_sleep
    return connector, seen


def _routes(table: dict[tuple[str, str], Any]) -> Handler:
    """Route by (method, path); values are JSON bodies or callables."""

    def handler(request: httpx.Request) -> httpx.Response:
        key = (request.method, request.url.path)
        if key not in table:
            return httpx.Response(404, json={"object": "error", "code": "object_not_found"})
        value = table[key]
        if callable(value):
            return value(request)
        return httpx.Response(200, json=value)

    return handler


def _body(request: httpx.Request) -> dict[str, Any]:
    return json.loads(request.content)


def _text(text: str, **annotations: bool) -> dict[str, Any]:
    return {"type": "text", "plain_text": text, "text": {"content": text}, "annotations": annotations}


def _block(block_id: str, kind: str, text: str = "", *, has_children: bool = False, **extra: Any):
    return {
        "object": "block",
        "id": block_id,
        "type": kind,
        "has_children": has_children,
        kind: {"rich_text": [_text(text)] if text else [], **extra},
    }


def _listing(results: list[Any], next_cursor: str | None = None) -> dict[str, Any]:
    return {
        "object": "list",
        "results": results,
        "has_more": next_cursor is not None,
        "next_cursor": next_cursor,
    }


PAGE_OBJECT = {
    "object": "page",
    "id": PAGE,
    "url": "https://www.notion.so/Plan-" + PAGE,
    "last_edited_time": "2026-09-20T10:00:00.000Z",
    "parent": {"type": "workspace", "workspace": True},
    "properties": {
        "title": {"id": "title", "type": "title", "title": [_text("Plan")]},
        "Status": {"id": "s", "type": "status", "status": {"name": "Doing"}},
    },
}


def test_definition_passes_registry_validation():
    assert validate_registry([DEFINITION]) == []


def test_definition_declares_the_spec_contract():
    actions = {spec.action: spec for spec in DEFINITION.actions}
    assert set(actions) == {
        "search", "get_page", "get_block_children", "query_database", "get_database",
        "list_comments", "list_users", "create_page", "append_blocks",
        "update_page_properties", "create_database_row", "update_block", "add_comment",
        "archive_page", "delete_block",
    }  # fmt: skip
    assert {a for a, s in actions.items() if s.always_confirm} == {
        "add_comment",
        "archive_page",
        "delete_block",
    }
    assert {a for a, s in actions.items() if s.starter} == {"search", "get_page", "query_database"}
    assert DEFINITION.auth.methods == ("token",)
    (field,) = DEFINITION.auth.fields
    assert (field.key, field.type, field.required) == ("access_token", "password", True)
    assert field.label == "Internal integration secret"
    assert "share" in field.hint.lower()
    assert DEFINITION.network.https_only is True
    assert DEFINITION.network.redirect_hosts == {}
    assert DEFINITION.docs_url == "https://www.notion.so/profile/integrations"


# ---------------------------------------------------------------------------
# Headers, auth, health, revoke
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_requests_carry_bearer_token_and_pinned_notion_version():
    connector, seen = _connector(_routes({("GET", "/v1/users/me"): {"object": "user"}}))
    assert await connector.health_check() is True
    (request,) = seen
    assert request.url.host == "api.notion.com"
    assert request.url.raw_path == b"/v1/users/me"
    assert request.headers["Authorization"] == f"Bearer {TOKEN}"
    assert request.headers["Notion-Version"] == "2022-06-28"


@pytest.mark.asyncio
async def test_health_check_is_false_when_the_secret_is_rejected():
    connector, _ = _connector(lambda r: httpx.Response(401, json={"code": "unauthorized"}))
    assert await connector.health_check() is False


@pytest.mark.asyncio
async def test_revoke_returns_false_without_any_request():
    connector, seen = _connector(lambda r: httpx.Response(200, json={}))
    assert await connector.revoke() is False
    assert seen == []


@pytest.mark.asyncio
async def test_authenticate_needs_a_secret_and_never_calls_out():
    connector = NotionConnector()
    with pytest.raises(AuthenticationError, match="Reconnect Notion"):
        await connector.authenticate({"access_token": "  "})
    assert await connector.authenticate({"access_token": f" {TOKEN} "}) is True
    assert connector._auth_headers() == {"Authorization": f"Bearer {TOKEN}"}


def test_validate_credentials_rejects_a_secret_with_spaces():
    assert NotionConnector.validate_credentials({"access_token": "ntn_a b"}) != []
    assert NotionConnector.validate_credentials({"access_token": TOKEN}) == []


# ---------------------------------------------------------------------------
# READ actions
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_search_posts_query_filter_and_page_size_and_shapes_results():
    hit = {
        "object": "page",
        "id": PAGE,
        "url": "https://www.notion.so/x",
        "last_edited_time": "2026-09-01T00:00:00.000Z",
        "properties": {"Name": {"type": "title", "title": [_text("Roadmap")]}},
        "created_by": {"id": USER},
    }
    connector, seen = _connector(_routes({("POST", "/v1/search"): _listing([hit])}))
    result = await connector.search(query="road", object_type="page", limit=5)

    (request,) = seen
    assert request.method == "POST"
    assert request.url.raw_path == b"/v1/search"
    assert _body(request) == {
        "query": "road",
        "filter": {"property": "object", "value": "page"},
        "page_size": 5,
    }
    assert result["items"] == [
        {
            "id": PAGE,
            "type": "page",
            "title": "Roadmap",
            "url": "https://www.notion.so/x",
            "last_edited": "2026-09-01T00:00:00.000Z",
        }
    ]
    assert result["count"] == 1
    assert request.headers["Content-Type"] == "application/json"


@pytest.mark.asyncio
async def test_search_pages_until_the_limit_and_reports_the_cursor():
    pages = {
        None: _listing([{"object": "page", "id": PAGE}] * 3, "c1"),
        "c1": _listing([{"object": "page", "id": PAGE}] * 2, "c2"),
    }

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=pages[_body(request).get("start_cursor")])

    connector, seen = _connector(handler)
    result = await connector.search(limit=5)
    assert [_body(r)["page_size"] for r in seen] == [5, 2]
    assert result["count"] == 5
    assert result["next_cursor"] == "c2"
    assert "start_cursor" in result["hint"]


@pytest.mark.asyncio
async def test_search_clamps_the_limit_and_passes_a_start_cursor():
    connector, seen = _connector(_routes({("POST", "/v1/search"): _listing([])}))
    result = await connector.search(limit=500, start_cursor="abc-123")
    assert _body(seen[0]) == {"page_size": 50, "start_cursor": "abc-123"}
    assert result == {"items": [], "count": 0}


@pytest.mark.asyncio
async def test_pagination_ending_early_sends_one_request():
    connector, seen = _connector(
        _routes({("POST", "/v1/search"): _listing([{"object": "page", "id": PAGE}])})
    )
    result = await connector.search(limit=10)
    assert len(seen) == 1
    assert result["count"] == 1 and "next_cursor" not in result


@pytest.mark.asyncio
async def test_a_repeated_cursor_stops_pagination():
    connector, seen = _connector(
        _routes({("POST", "/v1/search"): _listing([{"object": "page", "id": PAGE}], "same")})
    )
    result = await connector.search(limit=10)
    assert len(seen) == 2  # the first page, then "same" once; never a third time
    assert "next_cursor" not in result


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("kwargs", "message"),
    [
        ({"object_type": "user"}, "object_type"),
        ({"query": "q" * 501}, "query"),
        ({"query": 5}, "query"),
        ({"start_cursor": "has space"}, "start_cursor"),
        ({"start_cursor": ["x"]}, "start_cursor"),
    ],
)
async def test_search_rejects_bad_arguments_before_any_request(kwargs, message):
    connector, seen = _connector(lambda r: httpx.Response(200, json=_listing([])))
    with pytest.raises(ConnectorError, match=message):
        await connector.search(**kwargs)
    assert seen == []


@pytest.mark.asyncio
async def test_get_page_renders_properties_and_nested_markdown():
    toggle = _block(BLOCK, "toggle", "Details", has_children=True)
    sub_page = {"id": CHILD, "type": "child_page", "child_page": {"title": "Sub"}, "has_children": True}
    routes = {
        ("GET", f"/v1/pages/{PAGE}"): PAGE_OBJECT,
        ("GET", f"/v1/blocks/{PAGE}/children"): _listing(
            [_block("b1", "heading_1", "Plan"), _block("b2", "paragraph", "Ship it"), toggle, sub_page]
        ),
        ("GET", f"/v1/blocks/{BLOCK}/children"): _listing(
            [_block("c1", "bulleted_list_item", "inner")]
        ),
    }
    connector, seen = _connector(_routes(routes))
    result = await connector.get_page(PAGE)

    assert [(r.method, r.url.raw_path) for r in seen] == [
        ("GET", f"/v1/pages/{PAGE}".encode()),
        ("GET", f"/v1/blocks/{PAGE}/children?page_size=100".encode()),
        ("GET", f"/v1/blocks/{BLOCK}/children?page_size=100".encode()),
    ]
    assert result["id"] == PAGE
    assert result["title"] == "Plan"
    assert result["properties"] == {"Status": "Doing"}  # the title is not repeated
    assert result["parent"] == {"type": "workspace"}
    assert result["content"] == [
        "# Plan",
        "Ship it",
        "▸ Details\n  - inner",
        f"[child page: Sub] (id {CHILD})",
    ]
    assert result["truncated"] is False
    assert "hint" not in result and "more" not in result


@pytest.mark.asyncio
async def test_get_page_bounds_requests_and_blocks_and_says_where_to_continue():
    many = [_block(f"{i:032x}", "toggle", f"t{i}", has_children=True) for i in range(100)]
    counts = {"children": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path == f"/v1/pages/{PAGE}":
            return httpx.Response(200, json=PAGE_OBJECT)
        if path == f"/v1/blocks/{PAGE}/children":
            counts["children"] += 1
            cursor = request.url.params.get("start_cursor")
            return httpx.Response(200, json=_listing(many, None if cursor else "next-page"))
        return httpx.Response(200, json=_listing([_block("x", "paragraph", "leaf")]))

    connector, seen = _connector(handler)
    result = await connector.get_page(PAGE)

    # 1 page read + at most 10 children requests, whatever the page holds.
    assert len(seen) <= 11
    assert result["truncated"] is True
    assert "get_block_children" in result["hint"]
    assert 1 <= len(result["more"]) <= 5
    assert all("block_id" in entry for entry in result["more"])


@pytest.mark.asyncio
async def test_get_page_reads_at_most_two_top_level_pages_and_reports_the_cursor():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == f"/v1/pages/{PAGE}":
            return httpx.Response(200, json=PAGE_OBJECT)
        cursor = request.url.params.get("start_cursor") or "0"
        return httpx.Response(
            200, json=_listing([_block("p", "paragraph", f"page {cursor}")], str(int(cursor) + 1))
        )

    connector, seen = _connector(handler)
    result = await connector.get_page(PAGE)
    assert len(seen) == 3  # the page, then two children pages
    assert result["content"] == ["page 0", "page 1"]
    assert result["more"] == [{"block_id": PAGE, "start_cursor": "2"}]
    assert result["truncated"] is True


@pytest.mark.asyncio
async def test_get_page_caps_the_markdown_and_flags_it():
    huge = _block("b", "paragraph", "z" * 50_000)
    connector, _ = _connector(
        _routes(
            {
                ("GET", f"/v1/pages/{PAGE}"): PAGE_OBJECT,
                ("GET", f"/v1/blocks/{PAGE}/children"): _listing([huge, huge]),
            }
        )
    )
    result = await connector.get_page(PAGE)
    assert sum(len(part) for part in result["content"]) <= 12_000
    assert result["truncated"] is True
    assert "get_block_children" in result["hint"]


@pytest.mark.asyncio
async def test_get_page_marks_grandchildren_it_did_not_load():
    inner = _block(CHILD, "toggle", "deeper", has_children=True)
    connector, seen = _connector(
        _routes(
            {
                ("GET", f"/v1/pages/{PAGE}"): PAGE_OBJECT,
                ("GET", f"/v1/blocks/{PAGE}/children"): _listing(
                    [_block(BLOCK, "toggle", "outer", has_children=True)]
                ),
                ("GET", f"/v1/blocks/{BLOCK}/children"): _listing([inner]),
            }
        )
    )
    result = await connector.get_page(PAGE)
    assert len(seen) == 3  # never a request for the grandchildren
    assert f"block_id={CHILD}" in result["content"][0]
    assert result["truncated"] is True


@pytest.mark.asyncio
async def test_get_page_rejects_non_id_values_before_any_request():
    connector, seen = _connector(lambda r: httpx.Response(200, json={}))
    for bad in ("../users/me", "a/b", PAGE + "?x=1", "", None):
        with pytest.raises(ConnectorError, match="Notion id"):
            await connector.get_page(bad)
    assert seen == []


@pytest.mark.asyncio
async def test_get_block_children_returns_ids_types_and_numbered_markdown():
    connector, seen = _connector(
        _routes(
            {
                ("GET", f"/v1/blocks/{BLOCK}/children"): _listing(
                    [
                        _block("n1", "numbered_list_item", "one"),
                        _block("n2", "numbered_list_item", "two", has_children=True),
                        _block("t1", "to_do", "task", checked=True),
                    ],
                    "cur-9",
                )
            }
        )
    )
    result = await connector.get_block_children(BLOCK, start_cursor="cur-1", limit=3)
    assert seen[0].url.raw_path == f"/v1/blocks/{BLOCK}/children?page_size=3&start_cursor=cur-1".encode()
    assert result["items"] == [
        {"id": "n1", "type": "numbered_list_item", "markdown": "1. one", "has_children": False},
        {"id": "n2", "type": "numbered_list_item", "markdown": "2. two", "has_children": True},
        {"id": "t1", "type": "to_do", "markdown": "- [x] task", "has_children": False},
    ]
    assert result["next_cursor"] == "cur-9"


@pytest.mark.asyncio
async def test_query_database_posts_filter_and_sorts_and_renders_rows():
    row = {
        "object": "page",
        "id": PAGE,
        "last_edited_time": "2026-09-02T00:00:00.000Z",
        "properties": {
            "Name": {"type": "title", "title": [_text("Task")]},
            "Due": {"type": "date", "date": {"start": "2026-10-01"}},
        },
    }
    connector, seen = _connector(
        _routes({("POST", f"/v1/databases/{DB}/query"): _listing([row])})
    )
    status_filter = {"property": "Status", "status": {"equals": "Done"}}
    sorts = [{"property": "Due", "direction": "ascending"}]
    result = await connector.query_database(DB, filter=status_filter, sorts=sorts, limit=20)

    (request,) = seen
    assert request.url.raw_path == f"/v1/databases/{DB}/query".encode()
    assert _body(request) == {"filter": status_filter, "sorts": sorts, "page_size": 20}
    assert result["items"] == [
        {
            "id": PAGE,
            "properties": {"Name": "Task", "Due": "2026-10-01"},
            "last_edited": "2026-09-02T00:00:00.000Z",
        }
    ]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("kwargs", "message"),
    [
        ({"filter": "Status = Done"}, "filter"),
        ({"sorts": {"property": "Due"}}, "sorts"),
        ({"sorts": ["Due"]}, "sorts"),
        ({"filter": {"x": "y" * 20_000}}, "too large"),
    ],
)
async def test_query_database_rejects_bad_filters_before_any_request(kwargs, message):
    connector, seen = _connector(lambda r: httpx.Response(200, json=_listing([])))
    with pytest.raises(ConnectorError, match=message):
        await connector.query_database(DB, **kwargs)
    assert seen == []


@pytest.mark.asyncio
async def test_get_database_renders_its_schema():
    database = {
        "object": "database",
        "id": DB,
        "url": "https://www.notion.so/db",
        "title": [_text("Tasks")],
        "description": [_text("All tasks")],
        "properties": {
            "Name": {"type": "title", "title": {}},
            "Status": {"type": "status", "status": {"options": [{"name": "Todo"}, {"name": "Done"}]}},
        },
    }
    connector, seen = _connector(_routes({("GET", f"/v1/databases/{DB}"): database}))
    result = await connector.get_database(DB)
    assert seen[0].url.raw_path == f"/v1/databases/{DB}".encode()
    assert result == {
        "id": DB,
        "title": "Tasks",
        "description": "All tasks",
        "url": "https://www.notion.so/db",
        "properties": {"Name": "title", "Status": {"type": "status", "options": ["Todo", "Done"]}},
    }


@pytest.mark.asyncio
async def test_list_comments_sends_the_block_id_as_a_query_parameter():
    comment = {
        "object": "comment",
        "id": "c1",
        "discussion_id": "d1",
        "created_time": "2026-09-03T00:00:00.000Z",
        "created_by": {"object": "user", "id": USER},
        "rich_text": [_text("Looks good")],
    }
    connector, seen = _connector(_routes({("GET", "/v1/comments"): _listing([comment])}))
    result = await connector.list_comments(PAGE)
    assert seen[0].url.raw_path == f"/v1/comments?block_id={PAGE}&page_size=10".encode()
    assert result["items"] == [
        {
            "id": "c1",
            "discussion_id": "d1",
            "created": "2026-09-03T00:00:00.000Z",
            "author_id": USER,
            "text": "Looks good",
        }
    ]


@pytest.mark.asyncio
async def test_list_users_returns_ids_names_and_types_only():
    person = {
        "object": "user",
        "id": USER,
        "name": "Ada",
        "type": "person",
        "avatar_url": "https://x",
        "person": {"email": "ada@example.com"},
    }
    connector, seen = _connector(_routes({("GET", "/v1/users"): _listing([person])}))
    result = await connector.list_users(limit=2)
    assert seen[0].url.raw_path == b"/v1/users?page_size=2"
    assert result["items"] == [{"id": USER, "name": "Ada", "type": "person"}]


# ---------------------------------------------------------------------------
# WRITE and DELETE actions
# ---------------------------------------------------------------------------

WRITE_CALLS = {
    "create_page": lambda c, **kw: c.create_page(PAGE, "New page", "Hello", **kw),
    "append_blocks": lambda c, **kw: c.append_blocks(PAGE, "- a\n- b", **kw),
    "update_page_properties": lambda c, **kw: c.update_page_properties(
        PAGE, {"Status": {"status": "Done"}}, **kw
    ),
    "create_database_row": lambda c, **kw: c.create_database_row(
        DB, {"Name": {"title": "Row"}}, **kw
    ),
    "update_block": lambda c, **kw: c.update_block(BLOCK, "new text", **kw),
    "add_comment": lambda c, **kw: c.add_comment("Nice work", page_id=PAGE, **kw),
    "archive_page": lambda c, **kw: c.archive_page(PAGE, **kw),
    "delete_block": lambda c, **kw: c.delete_block(BLOCK, **kw),
}


def test_every_non_read_action_is_covered_by_the_confirmation_tests():
    non_read = {s.action for s in DEFINITION.actions if s.category.value != "read"}
    assert non_read == set(WRITE_CALLS)


@pytest.mark.asyncio
@pytest.mark.parametrize("action", sorted(WRITE_CALLS))
async def test_writes_require_confirmation_before_any_request(action):
    connector, seen = _connector(lambda r: httpx.Response(200, json={}))
    with pytest.raises(UserConfirmationRequired) as exc:
        await WRITE_CALLS[action](connector)
    assert exc.value.action == action
    assert seen == []
    # The approval text names the target.
    assert PAGE in exc.value.details or DB in exc.value.details or BLOCK in exc.value.details


def _write_handler(request: httpx.Request) -> httpx.Response:
    path = request.url.path
    if request.method == "GET" and path.startswith("/v1/blocks/"):
        return httpx.Response(200, json=_block(BLOCK, "paragraph", "old"))
    if path.endswith("/children"):
        return httpx.Response(200, json=_listing([{"id": CHILD}]))
    if path == "/v1/comments":
        return httpx.Response(200, json={"object": "comment", "id": "c9", "discussion_id": "d9"})
    if request.method == "DELETE":
        return httpx.Response(200, json={"id": BLOCK, "archived": True})
    if path.startswith("/v1/blocks/"):
        return httpx.Response(200, json=_block(BLOCK, "paragraph", "new text"))
    return httpx.Response(200, json={**PAGE_OBJECT, "archived": True})


@pytest.mark.asyncio
@pytest.mark.parametrize("action", sorted(WRITE_CALLS))
async def test_writes_run_once_confirmed(action):
    connector, seen = _connector(_write_handler)
    result = await WRITE_CALLS[action](connector, user_confirmed=True)
    assert seen, "a confirmed write sends its request"
    assert isinstance(result, dict) and result
    assert TOKEN not in json.dumps(result)


@pytest.mark.asyncio
async def test_create_page_posts_parent_title_and_children_then_appends_the_rest():
    content = "\n\n".join(f"para {i}" for i in range(150))
    connector, seen = _connector(_write_handler)
    result = await connector.create_page(PAGE, "Weekly notes", content, user_confirmed=True)

    create, append = seen
    assert (create.method, create.url.raw_path) == ("POST", b"/v1/pages")
    body = _body(create)
    assert body["parent"] == {"page_id": PAGE}
    assert body["properties"] == {
        "title": {"title": [{"type": "text", "text": {"content": "Weekly notes"}}]}
    }
    assert len(body["children"]) == 100
    assert (append.method, append.url.raw_path) == ("PATCH", f"/v1/blocks/{PAGE}/children".encode())
    assert len(_body(append)["children"]) == 50
    assert result["id"] == PAGE and result["blocks_added"] == 150


@pytest.mark.asyncio
async def test_append_blocks_batches_by_100_and_chains_after():
    created = iter(range(10))

    def handler(request: httpx.Request) -> httpx.Response:
        count = len(_body(request)["children"])
        ids = [f"{next(created):032x}" for _ in range(1)] + [f"{99:032x}"] * (count - 1)
        return httpx.Response(200, json=_listing([{"id": i} for i in ids]))

    connector, seen = _connector(handler)
    markdown = "\n".join(f"- item {i}" for i in range(250))
    result = await connector.append_blocks(BLOCK, markdown, after=CHILD, user_confirmed=True)

    assert [len(_body(r)["children"]) for r in seen] == [100, 100, 50]
    assert all(r.method == "PATCH" for r in seen)
    assert all(r.url.raw_path == f"/v1/blocks/{BLOCK}/children".encode() for r in seen)
    assert [_body(r)["after"] for r in seen] == [CHILD, f"{99:032x}", f"{99:032x}"]
    assert result["appended"] == 250
    assert result["first_block_id"] == f"{0:032x}"


@pytest.mark.asyncio
async def test_append_blocks_failure_part_way_says_what_was_written():
    responses = [
        httpx.Response(200, json=_listing([{"id": CHILD}])),
        httpx.Response(500, json={"code": "internal_server_error"}),
    ]
    connector, seen = _connector(lambda r: responses.pop(0))
    markdown = "\n\n".join(f"p{i}" for i in range(150))
    with pytest.raises(ConnectorError, match=r"Only 100 of 150 top-level blocks were added") as exc:
        await connector.append_blocks(BLOCK, markdown, user_confirmed=True)
    assert CHILD in str(exc.value)
    assert len(seen) == 2  # a failed PATCH is never retried


@pytest.mark.asyncio
@pytest.mark.parametrize("action", ["create_page", "create_database_row"])
async def test_create_with_a_failed_follow_up_append_names_the_created_page(action):
    responses = [
        httpx.Response(200, json=PAGE_OBJECT),
        httpx.Response(500, json={"code": "internal_server_error"}),
    ]
    connector, seen = _connector(lambda r: responses.pop(0))
    content = "\n\n".join(f"p{i}" for i in range(150))
    with pytest.raises(ConnectorError) as exc:
        if action == "create_page":
            await connector.create_page(PAGE, "Notes", content, user_confirmed=True)
        else:
            await connector.create_database_row(
                DB, {"Name": {"title": "Row"}}, content, user_confirmed=True
            )
    message = str(exc.value)
    assert "HTTP 500 from Notion" in message
    assert "Only 100 of 150 top-level blocks were added" in message
    assert f"The page was created (id {PAGE}, {PAGE_OBJECT['url']})" in message
    assert f"append_blocks block_id={PAGE}" in message
    assert [(r.method, r.url.raw_path) for r in seen] == [
        ("POST", b"/v1/pages"),
        ("PATCH", f"/v1/blocks/{PAGE}/children".encode()),
    ]


@pytest.mark.asyncio
async def test_create_page_without_an_id_in_the_response_says_it_may_exist():
    connector, seen = _connector(lambda r: httpx.Response(200, json={"object": "page"}))
    content = "\n\n".join(f"p{i}" for i in range(150))
    with pytest.raises(ConnectorError, match="probably created with only the first 100 of 150"):
        await connector.create_page(PAGE, "Notes", content, user_confirmed=True)
    assert len(seen) == 1  # no append to an unknown page


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "first_body", [{"object": "list"}, {"results": []}, {"results": [{"x": 1}]}, [], None]
)
async def test_chained_append_without_new_ids_says_what_was_written(first_body):
    def handler(request: httpx.Request) -> httpx.Response:
        if first_body is None:
            return httpx.Response(200, content=b"<html>")
        return httpx.Response(200, json=first_body)

    connector, seen = _connector(handler)
    markdown = "\n\n".join(f"p{i}" for i in range(150))
    with pytest.raises(ConnectorError, match=r"Only 100 of 150 top-level blocks were added"):
        await connector.append_blocks(BLOCK, markdown, after=CHILD, user_confirmed=True)
    assert len(seen) == 1  # the second batch has no block to go after


@pytest.mark.asyncio
async def test_append_without_new_ids_still_completes_when_nothing_is_chained():
    connector, seen = _connector(lambda r: httpx.Response(200, content=b"not json"))
    markdown = "\n\n".join(f"p{i}" for i in range(150))
    result = await connector.append_blocks(BLOCK, markdown, user_confirmed=True)
    assert result == {"block_id": BLOCK, "appended": 150}
    assert [len(_body(r)["children"]) for r in seen] == [100, 50]


@pytest.mark.asyncio
async def test_chained_append_tolerates_a_last_batch_without_ids():
    responses = [
        httpx.Response(200, json=_listing([{"id": CHILD}])),
        httpx.Response(200, json={}),
    ]
    connector, seen = _connector(lambda r: responses.pop(0))
    markdown = "\n\n".join(f"p{i}" for i in range(150))
    result = await connector.append_blocks(BLOCK, markdown, after=BLOCK, user_confirmed=True)
    assert result["appended"] == 150 and result["last_block_id"] == CHILD
    assert [_body(r)["after"] for r in seen] == [BLOCK, CHILD]


@pytest.mark.asyncio
async def test_hostile_inline_markdown_fails_or_passes_fast_before_approval():
    connector, seen = _connector(lambda r: httpx.Response(200, json={}))
    started = time.perf_counter()
    calls = (
        lambda: connector.append_blocks(BLOCK, "_a " * 33000),
        lambda: connector.update_block(BLOCK, "_a " * 6666),
        lambda: connector.add_comment("**a " * 5000, page_id=PAGE),
        lambda: connector.update_page_properties(PAGE, {"Name": {"title": "~~a " * 4000}}),
    )
    for call in calls:
        with pytest.raises(UserConfirmationRequired):
            await call()
    with pytest.raises(ConnectorError, match="longer than"):
        await connector.update_page_properties(PAGE, {"Name": {"title": "_a " * 7000}})
    assert time.perf_counter() - started < 2.0
    assert seen == []


@pytest.mark.asyncio
async def test_append_blocks_rejects_empty_markdown_before_approval():
    connector, seen = _connector(lambda r: httpx.Response(200, json={}))
    for bad in ("", "   \n\n", None):
        with pytest.raises(ConnectorError):
            await connector.append_blocks(BLOCK, bad)
    assert seen == []


@pytest.mark.asyncio
async def test_update_page_properties_reads_the_schema_for_plain_values():
    connector, seen = _connector(_write_handler)
    result = await connector.update_page_properties(
        PAGE, {"Status": "Done"}, user_confirmed=True
    )
    read, patch = seen
    assert (read.method, read.url.raw_path) == ("GET", f"/v1/pages/{PAGE}".encode())
    assert (patch.method, patch.url.raw_path) == ("PATCH", f"/v1/pages/{PAGE}".encode())
    assert _body(patch) == {"properties": {"Status": {"status": {"name": "Done"}}}}
    assert result["properties"] == {"Status": "Doing"}  # what Notion now reports


@pytest.mark.asyncio
async def test_update_page_properties_skips_the_schema_read_for_typed_values():
    connector, seen = _connector(_write_handler)
    await connector.update_page_properties(
        PAGE, {"Due": {"date": "2026-10-01"}}, user_confirmed=True
    )
    (patch,) = seen
    assert _body(patch) == {"properties": {"Due": {"date": {"start": "2026-10-01"}}}}


@pytest.mark.asyncio
async def test_update_page_properties_names_unknown_properties():
    connector, seen = _connector(_write_handler)
    with pytest.raises(ConnectorError, match="Property 'Nope'.*Known properties: Status, title"):
        await connector.update_page_properties(PAGE, {"Nope": 1}, user_confirmed=True)
    assert [r.method for r in seen] == ["GET"]  # no PATCH was sent


@pytest.mark.asyncio
async def test_create_database_row_types_values_from_the_database_schema():
    database = {
        "object": "database",
        "id": DB,
        "properties": {
            "Name": {"type": "title", "title": {}},
            "Tags": {"type": "multi_select", "multi_select": {"options": []}},
        },
    }

    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "GET":
            return httpx.Response(200, json=database)
        return httpx.Response(200, json={**PAGE_OBJECT, "id": CHILD})

    connector, seen = _connector(handler)
    result = await connector.create_database_row(
        DB, {"Name": "Buy milk", "Tags": ["home"]}, content="- 2 litres", user_confirmed=True
    )
    read, create = seen
    assert read.url.raw_path == f"/v1/databases/{DB}".encode()
    body = _body(create)
    assert body["parent"] == {"database_id": DB}
    assert body["properties"] == {
        "Name": {"title": [{"type": "text", "text": {"content": "Buy milk"}}]},
        "Tags": {"multi_select": [{"name": "home"}]},
    }
    assert body["children"][0]["type"] == "bulleted_list_item"
    assert result["id"] == CHILD and result["blocks_added"] == 1


@pytest.mark.asyncio
async def test_update_block_keeps_the_block_type_and_sets_checked():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "GET":
            return httpx.Response(200, json=_block(BLOCK, "to_do", "old", checked=False))
        return httpx.Response(200, json=_block(BLOCK, "to_do", "done it", checked=True))

    connector, seen = _connector(handler)
    result = await connector.update_block(BLOCK, "done **it**", checked=True, user_confirmed=True)
    read, patch = seen
    assert read.url.raw_path == f"/v1/blocks/{BLOCK}".encode()
    assert patch.method == "PATCH"
    assert _body(patch) == {
        "to_do": {
            "rich_text": [
                {"type": "text", "text": {"content": "done "}},
                {"type": "text", "text": {"content": "it"}, "annotations": {"bold": True}},
            ],
            "checked": True,
        }
    }
    assert result == {"id": BLOCK, "type": "to_do", "markdown": "- [x] done it"}


@pytest.mark.asyncio
async def test_update_block_refuses_non_text_blocks_without_writing():
    connector, seen = _connector(
        lambda r: httpx.Response(200, json={"id": BLOCK, "type": "image", "image": {}})
    )
    with pytest.raises(ConnectorError, match="only text blocks"):
        await connector.update_block(BLOCK, "x", user_confirmed=True)
    assert [r.method for r in seen] == ["GET"]


@pytest.mark.asyncio
async def test_add_comment_on_a_page_and_in_a_discussion():
    connector, seen = _connector(_write_handler)
    await connector.add_comment("Hi", page_id=PAGE, user_confirmed=True)
    await connector.add_comment("Reply", discussion_id=DB, user_confirmed=True)
    first, second = (_body(r) for r in seen)
    assert first == {"rich_text": [{"type": "text", "text": {"content": "Hi"}}], "parent": {"page_id": PAGE}}
    assert second == {"rich_text": [{"type": "text", "text": {"content": "Reply"}}], "discussion_id": DB}
    assert all(r.url.raw_path == b"/v1/comments" and r.method == "POST" for r in seen)


@pytest.mark.asyncio
@pytest.mark.parametrize("kwargs", [{}, {"page_id": PAGE, "discussion_id": DB}])
async def test_add_comment_needs_exactly_one_target(kwargs):
    connector, seen = _connector(_write_handler)
    with pytest.raises(ConnectorError, match="exactly one"):
        await connector.add_comment("Hi", **kwargs)
    assert seen == []


@pytest.mark.asyncio
async def test_archive_page_patches_archived_true():
    connector, seen = _connector(_write_handler)
    result = await connector.archive_page(PAGE, user_confirmed=True)
    (request,) = seen
    assert (request.method, request.url.raw_path) == ("PATCH", f"/v1/pages/{PAGE}".encode())
    assert _body(request) == {"archived": True}
    assert result == {"id": PAGE, "archived": True}


@pytest.mark.asyncio
async def test_delete_block_sends_delete():
    connector, seen = _connector(_write_handler)
    result = await connector.delete_block(BLOCK, user_confirmed=True)
    (request,) = seen
    assert (request.method, request.url.raw_path) == ("DELETE", f"/v1/blocks/{BLOCK}".encode())
    assert result == {"id": BLOCK, "deleted": True}


# ---------------------------------------------------------------------------
# Failure matrix
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("status", "code", "error", "message"),
    [
        (401, "unauthorized", AuthenticationError, "Reconnect Notion"),
        (403, "restricted_resource", AuthenticationError, "missing permission or scope"),
        (404, "object_not_found", ConnectorError, "not found"),
        (409, "conflict_error", ConnectorError, "conflict"),
        (500, "internal_server_error", ConnectorError, "provider error"),
    ],
)
async def test_http_errors_map_to_typed_errors_with_the_vendor_code(status, code, error, message):
    body = {"object": "error", "status": status, "code": code, "message": f"bad {TOKEN}"}
    connector, seen = _connector(lambda r: httpx.Response(status, json=body))
    with pytest.raises(error, match=message) as exc:
        await connector.get_database(DB)
    assert f"({code})" in str(exc.value)
    assert TOKEN not in str(exc.value)
    assert len(seen) == 1


@pytest.mark.asyncio
async def test_409_on_a_write_is_a_conflict_error_and_not_retried():
    connector, seen = _connector(
        lambda r: httpx.Response(409, json={"object": "error", "code": "conflict_error"})
    )
    with pytest.raises(ConnectorError, match="conflict"):
        await connector.archive_page(PAGE, user_confirmed=True)
    assert len(seen) == 1


@pytest.mark.asyncio
async def test_429_with_short_retry_after_retries_once():
    responses = [
        httpx.Response(429, headers={"Retry-After": "1"}, json={"code": "rate_limited"}),
        httpx.Response(200, json=_listing([])),
    ]
    connector, seen = _connector(lambda r: responses.pop(0))
    assert (await connector.list_users())["count"] == 0
    assert len(seen) == 2


@pytest.mark.asyncio
async def test_429_with_long_retry_after_is_not_retried():
    connector, seen = _connector(
        lambda r: httpx.Response(429, headers={"Retry-After": "60"}, json={"code": "rate_limited"})
    )
    with pytest.raises(RateLimitExceededError, match="Retry after 60 s"):
        await connector.list_users()
    assert len(seen) == 1


@pytest.mark.asyncio
async def test_timeout_is_a_connector_error():
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ReadTimeout("timed out", request=request)

    connector, _ = _connector(handler)
    with pytest.raises(ConnectorError, match="timed out"):
        await connector.get_page(PAGE)


@pytest.mark.asyncio
async def test_malformed_json_is_a_connector_error():
    connector, _ = _connector(lambda r: httpx.Response(200, content=b"<html>oops"))
    with pytest.raises(ConnectorError, match="Malformed response from Notion"):
        await connector.search()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "payload",
    [[], "x", 7, {"object": "list"}, {"results": {"id": PAGE}}, {"results": None}],
)
async def test_listing_without_a_results_array_is_malformed(payload):
    connector, _ = _connector(lambda r: httpx.Response(200, json=payload))
    with pytest.raises(ConnectorError, match="Malformed response from Notion"):
        await connector.list_users()


@pytest.mark.asyncio
async def test_missing_fields_are_omitted_not_fatal():
    connector, _ = _connector(
        _routes(
            {
                ("GET", f"/v1/pages/{PAGE}"): {"object": "page"},
                ("GET", f"/v1/blocks/{PAGE}/children"): _listing([{"object": "block"}]),
            }
        )
    )
    result = await connector.get_page(PAGE)
    assert result["properties"] == {}
    assert result["content"] == ["[unknown]"]


HOSTILE_ITEM = {
    "object": ["page"],
    "id": {"$ne": 1},
    "url": 5,
    "title": "not-a-list",
    "properties": {"Name": {"type": "title", "title": [{"plain_text": None}]}, 3: None, "Bad": []},
    "rich_text": [None, {"plain_text": "q" * 100_000}],
    "created_by": "nobody",
    "type": None,
    "has_children": "yes",
}


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "call",
    [
        lambda c: c.search(),
        lambda c: c.get_block_children(BLOCK),
        lambda c: c.query_database(DB),
        lambda c: c.list_comments(PAGE),
        lambda c: c.list_users(),
    ],
)
async def test_hostile_list_payloads_do_not_crash(call):
    payload = _listing([HOSTILE_ITEM, None, 5, "x"])
    connector, _ = _connector(lambda r: httpx.Response(200, json=payload))
    result = await call(connector)
    json.dumps(result)
    assert len(json.dumps(result)) < 20_000


@pytest.mark.asyncio
async def test_hostile_page_payload_does_not_crash():
    connector, seen = _connector(
        _routes(
            {
                ("GET", f"/v1/pages/{PAGE}"): HOSTILE_ITEM,
                ("GET", f"/v1/blocks/{PAGE}/children"): _listing(
                    [HOSTILE_ITEM, {"type": "toggle", "has_children": True, "id": "../../x"}]
                ),
            }
        )
    )
    result = await connector.get_page(PAGE)
    json.dumps(result)
    # A child id that is not a Notion id is never requested.
    assert len(seen) == 2


# ---------------------------------------------------------------------------
# Network policy
# ---------------------------------------------------------------------------


@pytest.fixture
def notion_policy(monkeypatch):
    """The policy the registry derives from DEFINITION, with DNS stubbed."""
    net = DEFINITION.network
    monkeypatch.setitem(
        netsec.DEFAULT_POLICIES,
        net.policy_key,
        NetworkPolicy(
            connector_type=net.policy_key,
            allowed_hosts=list(net.hosts),
            allowed_paths={host: list(paths) for host, paths in net.hosts.items()},
            https_only=net.https_only,
            redirect_hosts={h: list(p) for h, p in net.redirect_hosts.items()},
        ),
    )
    monkeypatch.setattr(
        netsec,
        "check_ssrf",
        lambda url: netsec.SSRFCheckResult(
            safe=True, resolved_ip="93.184.216.34", resolved_ips=("93.184.216.34",)
        ),
    )
    connector = NotionConnector()
    connector.set_network_policy(net.policy_key)
    return connector


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("method", "path"),
    [
        ("POST", "/v1/search"),
        ("GET", f"/v1/pages/{PAGE}"),
        ("POST", "/v1/pages"),
        ("PATCH", f"/v1/pages/{PAGE}"),
        ("GET", f"/v1/blocks/{BLOCK}/children"),
        ("PATCH", f"/v1/blocks/{BLOCK}"),
        ("DELETE", f"/v1/blocks/{BLOCK}"),
        ("POST", f"/v1/databases/{DB}/query"),
        ("GET", f"/v1/databases/{DB}"),
        ("GET", "/v1/comments"),
        ("POST", "/v1/comments"),
        ("GET", "/v1/users"),
        ("GET", "/v1/users/me"),
    ],
)
async def test_every_declared_endpoint_is_allowed(notion_policy, method, path):
    await notion_policy._enforce_network_policy(
        httpx.Request(method, f"https://api.notion.com{path}")
    )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "url",
    [
        "https://evil.example.com/v1/search",
        "https://notion.so/v1/search",
        "https://api.notion.com/v1/oauth/token",
        "https://api.notion.com/v2/search",
        "http://api.notion.com/v1/search",
        "https://api.notion.com:8443/v1/search",
        "https://api.notion.com/v1/pages/../oauth/token",
        "https://api.notion.com/v1/blocks/%2e%2e/%2e%2e/oauth/token",
        "https://s3.us-west-2.amazonaws.com/secure.notion-static.com/file.pdf",
    ],
)
async def test_off_list_hosts_paths_and_schemes_are_refused(notion_policy, url):
    with pytest.raises(ConnectorError, match="blocked by network policy"):
        await notion_policy._enforce_network_policy(httpx.Request("GET", url))


# ---------------------------------------------------------------------------
# Secrets never leak
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_token_never_appears_in_results_or_errors():
    echo = {"object": "error", "code": TOKEN, "message": f"Bearer {TOKEN}"}
    for status in (400, 401, 403, 404, 429, 500):
        connector, _ = _connector(lambda r, s=status: httpx.Response(s, json=echo))
        with pytest.raises(ConnectorError) as exc:
            await connector.search()
        assert TOKEN not in str(exc.value)

    connector, _ = _connector(_routes({("POST", "/v1/search"): _listing([HOSTILE_ITEM])}))
    assert TOKEN not in json.dumps(await connector.search())


# ---------------------------------------------------------------------------
# Module headers stay accurate after the split into notion_api
# ---------------------------------------------------------------------------


def test_notion_api_headers_describe_the_current_layout():
    import services.connectors.notion_api as package
    from services.connectors.notion_api import markdown, properties

    doc = package.__doc__ or ""
    for module in ("common", "reads", "writes", "markdown", "properties"):
        assert f"``{module}``" in doc
    assert "api.notion.com" in doc
    assert "talks to no external" not in doc
    # The actions live in reads.py and writes.py, not in notion.py.
    for helper in (markdown, properties):
        header = helper.__doc__ or ""
        assert "reads.py" in header and "writes.py" in header
        assert "services/connectors/notion.py (" not in header
