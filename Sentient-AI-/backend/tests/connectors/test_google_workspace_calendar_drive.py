"""Tests for the Calendar and Drive actions of the Google Workspace connector.

Why it exists: pins every Calendar and Drive request (method, host, raw path,
query, body), result shaping (events, files, file text with paging and caps),
the confirmation gate on every write, Drive query escaping (a file name cannot
inject query clauses), the binary-file refusal, pagination that ends early or
repeats its cursor, and hostile payloads.

Connects to services/connectors/google_api/calendar.py and drive.py through
GoogleWorkspaceConnector. All HTTP goes to ``httpx.MockTransport`` with the
network-policy hook armed; no real network or credentials.
"""

from __future__ import annotations

import httpx
import pytest

from services.connectors.base import ConnectorError, UserConfirmationRequired
from tests.connectors.test_google_workspace_support import (
    body,
    make,
    no_dns,  # noqa: F401 - fixture
    ok,
    query,
)

pytestmark = pytest.mark.usefixtures("no_dns")


# ---------------------------------------------------------------------------
# Calendar
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_get_events_shapes_and_caps_events():
    items = [
        {
            "id": "e1", "summary": "Standup", "status": "confirmed", "etag": "x", "creator": {"email": "x"},
            "start": {"dateTime": "2026-09-25T10:00:00Z"}, "end": {"dateTime": "2026-09-25T10:15:00Z"},
            "description": "d" * 5000, "organizer": {"email": "boss@example.com"},
            "attendees": [{"email": "me@example.com", "responseStatus": "accepted", "self": True}],
        },
        "junk",
    ]
    connector, seen = make(ok({"items": items}))
    events = await connector.get_events("2026-09-25T00:00:00Z", "2026-09-26T00:00:00Z")
    assert seen[0].url.path == "/calendar/v3/calendars/primary/events"
    assert query(seen[0]) == {
        "timeMin": "2026-09-25T00:00:00Z", "timeMax": "2026-09-26T00:00:00Z",
        "singleEvents": "true", "orderBy": "startTime", "maxResults": "50",
    }
    (event,) = events
    assert event["summary"] == "Standup" and "etag" not in event and "creator" not in event
    assert len(event["description"]) == 1000 and event["description_truncated"] is True
    assert event["organizer"] == "boss@example.com"
    assert event["attendees"] == [{"email": "me@example.com", "response": "accepted"}]


@pytest.mark.asyncio
async def test_list_calendars():
    items = [{"id": "primary@example.com", "summary": "Me", "accessRole": "owner", "primary": True}, {"id": "c2"}]
    connector, seen = make(ok({"items": items}))
    result = await connector.list_calendars(limit=1)
    assert seen[0].url.raw_path == b"/calendar/v3/users/me/calendarList?maxResults=1"
    assert result == [{"id": "primary@example.com", "name": "Me", "access_role": "owner", "primary": True}]


@pytest.mark.asyncio
async def test_update_event_patches_only_given_fields():
    connector, seen = make(ok({"id": "e/1", "summary": "New"}))
    result = await connector.update_event(
        "e/1", calendar_id="team@group.calendar.google.com", summary="New", start="2026-09-26",
        end="2026-09-27", attendees=["a@example.com"], notify_attendees=False, user_confirmed=True,
    )
    (request,) = seen
    assert request.method == "PATCH"
    assert request.url.raw_path == (
        b"/calendar/v3/calendars/team%40group.calendar.google.com/events/e%2F1?sendUpdates=none"
    )
    assert body(request) == {
        "summary": "New", "start": {"date": "2026-09-26"}, "end": {"date": "2026-09-27"},
        "attendees": [{"email": "a@example.com"}],
    }
    assert result == {"id": "e/1", "summary": "New"}


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "kwargs,message",
    [
        ({}, "at least one field"),
        ({"start": "next tuesday"}, "'start' must be"),
        ({"attendees": ["not an email"]}, "single email"),
        ({"notify_attendees": "yes", "summary": "x"}, "true or false"),
    ],
)
async def test_update_event_validates_before_confirmation(kwargs, message):
    connector, seen = make(ok())
    with pytest.raises(ConnectorError, match=message) as exc:
        await connector.update_event("e1", **kwargs)
    assert not isinstance(exc.value, UserConfirmationRequired)
    assert seen == []


@pytest.mark.asyncio
async def test_respond_to_invite_changes_only_my_answer_with_if_match():
    event = {
        "id": "e1", "etag": '"123"',
        "attendees": [
            {"email": "boss@example.com", "responseStatus": "accepted", "organizer": True},
            {"email": "me@example.com", "responseStatus": "needsAction", "self": True},
        ],
    }

    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "GET":
            return httpx.Response(200, json=event)
        return httpx.Response(200, json={"id": "e1", "attendees": body(request)["attendees"]})

    connector, seen = make(handler)
    result = await connector.respond_to_invite("e1", "declined", user_confirmed=True)
    get, patch = seen
    assert get.url.raw_path == b"/calendar/v3/calendars/primary/events/e1"
    assert patch.method == "PATCH" and patch.headers["If-Match"] == '"123"'
    assert query(patch) == {"sendUpdates": "all"}
    assert body(patch)["attendees"][0]["responseStatus"] == "accepted"
    assert body(patch)["attendees"][1]["responseStatus"] == "declined"
    assert result["status"] == "declined"


@pytest.mark.asyncio
async def test_respond_to_invite_when_not_a_guest_and_bad_answer():
    connector, seen = make(ok({"id": "e1", "attendees": [{"email": "x@example.com"}]}))
    with pytest.raises(ConnectorError, match="not a guest"):
        await connector.respond_to_invite("e1", "accepted", user_confirmed=True)
    assert len(seen) == 1
    with pytest.raises(ConnectorError, match="must be one of"):
        await connector.respond_to_invite("e1", "maybe", user_confirmed=True)


@pytest.mark.asyncio
async def test_respond_to_invite_conflict_is_reported():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "GET":
            return httpx.Response(200, json={"etag": "e", "attendees": [{"self": True}]})
        return httpx.Response(412, json={"error": {"status": "FAILED_PRECONDITION"}})

    connector, _ = make(handler)
    with pytest.raises(ConnectorError, match="HTTP 412"):
        await connector.respond_to_invite("e1", "accepted", user_confirmed=True)


@pytest.mark.asyncio
async def test_delete_event():
    connector, seen = make(lambda r: httpx.Response(204))
    assert await connector.delete_event("e1", user_confirmed=True) == {
        "status": "deleted", "id": "e1", "calendar_id": "primary",
    }
    assert (seen[0].method, seen[0].url.raw_path) == (
        "DELETE", b"/calendar/v3/calendars/primary/events/e1?sendUpdates=all",
    )


# ---------------------------------------------------------------------------
# Drive
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_search_files_escapes_the_query_and_skips_order_for_full_text():
    files = [{"id": "f1", "name": "Q3", "mimeType": "text/plain", "owners": [{"x": 1}], "parents": ["p1"]}]
    connector, seen = make(ok({"files": files}))
    result = await connector.search_files("it's a \\ test", mime_type="text/plain", limit=5)
    params = query(seen[0])
    assert seen[0].url.path == "/drive/v3/files"
    assert params["q"] == (
        "trashed = false and (name contains 'it\\'s a \\\\ test' or fullText contains "
        "'it\\'s a \\\\ test') and mimeType = 'text/plain'"
    )
    assert "orderBy" not in params
    assert params["pageSize"] == "5" and params["supportsAllDrives"] == "true"
    assert result == [{"id": "f1", "name": "Q3", "mime_type": "text/plain", "parents": ["p1"]}]


@pytest.mark.asyncio
async def test_search_files_without_query_lists_newest_first():
    connector, seen = make(ok({"files": []}))
    assert await connector.search_files() == []
    assert query(seen[0])["q"] == "trashed = false"
    assert query(seen[0])["orderBy"] == "modifiedTime desc"
    with pytest.raises(ConnectorError, match="type/subtype"):
        await connector.search_files(mime_type="text/plain' or 'a'='a")


@pytest.mark.asyncio
async def test_pagination_stops_when_the_cursor_ends_or_repeats():
    pages = [
        {"files": [{"id": "a"}, {"id": "b"}], "nextPageToken": "t1"},
        {"files": [{"id": "c"}]},
    ]
    connector, seen = make(lambda r: httpx.Response(200, json=pages.pop(0)))
    assert [f["id"] for f in await connector.list_folder(limit=5)] == ["a", "b", "c"]
    assert "pageToken" not in query(seen[0]) and query(seen[1])["pageToken"] == "t1"
    assert query(seen[0])["q"] == "'root' in parents and trashed = false"

    connector, seen = make(ok({"files": [{"id": "x"}], "nextPageToken": "same"}))
    assert len(await connector.list_folder(limit=50)) == 2
    assert len(seen) == 2  # the repeated cursor stopped the loop


@pytest.mark.asyncio
async def test_list_folder_refuses_ids_that_could_inject_query_clauses():
    connector, seen = make(ok())
    with pytest.raises(ConnectorError, match="valid Drive id"):
        await connector.list_folder("x' in parents or '1'='1")
    assert seen == []


@pytest.mark.asyncio
async def test_get_file_text_exports_google_docs_and_pages():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/export"):
            return httpx.Response(200, content=("word " * 5000).encode(), headers={"Content-Type": "text/plain"})
        return httpx.Response(200, json={"id": "d1", "name": "Plan", "mimeType": "application/vnd.google-apps.document"})

    connector, seen = make(handler)
    result = await connector.get_file_text("d1")
    assert query(seen[0]) == {"fields": "id,name,mimeType,size", "supportsAllDrives": "true"}
    assert seen[1].url.raw_path == b"/drive/v3/files/d1/export?mimeType=text%2Fplain"
    assert result["name"] == "Plan" and len(result["text"]) == 12000
    assert result["truncated"] is True and result["next_offset"] == 12000
    assert "get_file_text" in result["hint"]


@pytest.mark.asyncio
async def test_get_file_text_exports_sheets_as_csv():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/export"):
            return httpx.Response(200, content=b"a,b\n1,2\n")
        return httpx.Response(200, json={"name": "S", "mimeType": "application/vnd.google-apps.spreadsheet"})

    connector, seen = make(handler)
    result = await connector.get_file_text("s1")
    assert seen[1].url.params["mimeType"] == "text/csv"
    assert result["text"] == "a,b\n1,2\n" and result["truncated"] is False


@pytest.mark.asyncio
async def test_get_file_text_downloads_text_files_with_a_range():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.params.get("alt") == "media":
            return httpx.Response(206, content="héllo".encode(), headers={"Content-Type": "text/plain; charset=utf-8"})
        return httpx.Response(200, json={"name": "notes.md", "mimeType": "text/markdown", "size": "5000000"})

    connector, seen = make(handler)
    result = await connector.get_file_text("f1")
    assert seen[1].headers["Range"] == "bytes=0-999999"
    assert query(seen[1]) == {"alt": "media", "supportsAllDrives": "true"}
    assert result["text"] == "héllo"
    assert result["truncated"] is True and "first 1000000 bytes" in result["hint"]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "meta,message",
    [
        ({"name": "photo.jpg", "mimeType": "image/jpeg"}, "binary file"),
        ({"name": "Folder", "mimeType": "application/vnd.google-apps.folder"}, "list_folder"),
        ({"name": "Form", "mimeType": "application/vnd.google-apps.form"}, "cannot be read"),
    ],
)
async def test_get_file_text_refuses_non_text(meta, message):
    connector, seen = make(ok(meta))
    with pytest.raises(ConnectorError, match=message):
        await connector.get_file_text("f1")
    assert len(seen) == 1


@pytest.mark.asyncio
async def test_get_file_text_refuses_binary_bytes_behind_a_text_type():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.params.get("alt") == "media":
            return httpx.Response(200, content=b"\x89PNG\x00\x00")
        return httpx.Response(200, json={"name": "x.txt", "mimeType": "text/plain"})

    connector, _ = make(handler)
    with pytest.raises(ConnectorError, match="binary"):
        await connector.get_file_text("f1")


@pytest.mark.asyncio
async def test_upload_file_sends_one_multipart_request():
    connector, seen = make(ok({"id": "n1", "name": "a.txt", "mimeType": "text/plain"}))
    result = await connector.upload_file("a.txt", "hello", folder_id="fold1", user_confirmed=True)
    (request,) = seen
    assert request.method == "POST" and request.url.host == "www.googleapis.com"
    assert request.url.path == "/upload/drive/v3/files"
    assert query(request)["uploadType"] == "multipart"
    content_type = request.headers["Content-Type"]
    assert content_type.startswith("multipart/related; boundary=")
    boundary = content_type.split("boundary=")[1]
    raw = request.content.decode()
    assert raw.count(f"--{boundary}") == 3
    assert '{"name": "a.txt", "mimeType": "text/plain", "parents": ["fold1"]}' in raw
    assert "\r\n\r\nhello\r\n" in raw
    assert result == {"id": "n1", "name": "a.txt", "mime_type": "text/plain"}


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "kwargs,message",
    [
        ({"name": "a", "content": "x", "mime_type": "application/pdf"}, "'mime_type'"),
        ({"name": "a\nb", "content": "x"}, "single line"),
        ({"name": "a", "content": 5}, "'content'"),
        ({"name": "a", "content": "x" * 5_000_001}, "too large"),
    ],
)
async def test_upload_file_validation(kwargs, message):
    connector, seen = make(ok())
    with pytest.raises(ConnectorError, match=message):
        await connector.upload_file(**kwargs, user_confirmed=True)
    assert seen == []


@pytest.mark.asyncio
async def test_create_folder_rename_share_and_trash():
    connector, seen = make(ok({"id": "d9", "name": "New", "mimeType": "application/vnd.google-apps.folder"}))
    await connector.create_folder("New", parent_id="p1", user_confirmed=True)
    assert body(seen[0]) == {"name": "New", "mimeType": "application/vnd.google-apps.folder", "parents": ["p1"]}
    assert seen[0].url.path == "/drive/v3/files"

    connector, seen = make(ok({"id": "f1", "name": "Renamed"}))
    assert await connector.rename_file("f1", "Renamed", user_confirmed=True) == {"id": "f1", "name": "Renamed"}
    assert (seen[0].method, seen[0].url.path, body(seen[0])) == ("PATCH", "/drive/v3/files/f1", {"name": "Renamed"})

    connector, seen = make(ok({"id": "perm1", "role": "reader", "type": "user", "emailAddress": "x@example.com"}))
    shared = await connector.share_file("f1", "x@example.com", "reader", notify=False, user_confirmed=True)
    assert seen[0].url.path == "/drive/v3/files/f1/permissions"
    assert query(seen[0])["sendNotificationEmail"] == "false"
    assert body(seen[0]) == {"type": "user", "role": "reader", "emailAddress": "x@example.com"}
    assert shared == {"file_id": "f1", "permission_id": "perm1", "role": "reader", "email": "x@example.com"}
    with pytest.raises(ConnectorError, match="'role'"):
        await connector.share_file("f1", "x@example.com", "owner", user_confirmed=True)

    connector, seen = make(ok({"id": "f1", "name": "Old", "trashed": True}))
    assert await connector.trash_file("f1", user_confirmed=True) == {"status": "trashed", "id": "f1", "name": "Old"}
    assert body(seen[0]) == {"trashed": True}


@pytest.mark.asyncio
async def test_move_file_reads_parents_then_moves_once():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "GET":
            return httpx.Response(200, json={"parents": ["old1", "old2", 3]})
        return httpx.Response(200, json={"id": "f1", "name": "F", "parents": ["new1"]})

    connector, seen = make(handler)
    result = await connector.move_file("f1", "new1", user_confirmed=True)
    assert query(seen[0])["fields"] == "parents"
    assert seen[1].method == "PATCH"
    assert query(seen[1])["addParents"] == "new1" and query(seen[1])["removeParents"] == "old1,old2"
    assert result["parents"] == ["new1"]


WRITES = [
    ("create_event", {"event_data": {"summary": "x"}}),
    ("update_event", {"event_id": "e1", "summary": "x"}),
    ("respond_to_invite", {"event_id": "e1", "response": "accepted"}),
    ("delete_event", {"event_id": "e1"}),
    ("upload_file", {"name": "a.txt", "content": "x"}),
    ("create_folder", {"name": "F"}),
    ("move_file", {"file_id": "f1", "folder_id": "p1"}),
    ("rename_file", {"file_id": "f1", "name": "N"}),
    ("share_file", {"file_id": "f1", "email": "a@example.com", "role": "writer"}),
    ("trash_file", {"file_id": "f1"}),
]


@pytest.mark.asyncio
@pytest.mark.parametrize("action,params", WRITES)
async def test_every_write_needs_confirmation_before_any_request(action, params):
    connector, seen = make(ok())
    with pytest.raises(UserConfirmationRequired) as exc:
        await getattr(connector, action)(**params)
    assert exc.value.action == action and exc.value.details
    assert seen == []


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "payload",
    [{"items": "nope"}, {"items": [None, 5, {"start": "x", "attendees": "y", "summary": ["a"]}]}, {}],
)
async def test_hostile_event_payloads_do_not_crash(payload):
    connector, _ = make(ok(payload))
    events = await connector.get_events()
    assert all(isinstance(e, dict) for e in events)


@pytest.mark.asyncio
async def test_hostile_file_payloads_do_not_crash():
    files = [{"id": 7, "name": None, "size": 12, "parents": "p"}, None, {"name": "n" * 10_000}]
    connector, _ = make(ok({"files": files, "nextPageToken": 5}))
    result = await connector.search_files("x")
    assert result == [{"id": "7", "size": "12"}, {"name": "n" * 300}]
