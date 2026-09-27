"""Tests for the Docs, Sheets and Contacts actions of the Google Workspace connector.

Why it exists: pins every Docs, Sheets and People request (method, host, raw
path, query, body), the plain-text extraction from Docs JSON, the value limits
and RAW-by-default writes in Sheets (typed-in parsing can run formulas that
reach outside URLs), the etag read-merge-write cycle of update_contact, the
confirmation gate on every write and hostile payloads.

Connects to services/connectors/google_api/docs.py, sheets.py and contacts.py
through GoogleWorkspaceConnector. All HTTP goes to ``httpx.MockTransport`` with
the network-policy hook armed; no real network or credentials.
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


def _para(text: str) -> dict:
    return {"paragraph": {"elements": [{"textRun": {"content": text}}, {"inlineObjectElement": {}}]}}


DOC = {
    "documentId": "doc1",
    "title": "Notes",
    "body": {
        "content": [
            {"sectionBreak": {}},
            _para("Hello world\n"),
            {
                "table": {
                    "tableRows": [
                        {"tableCells": [{"content": [_para("a\n")]}, {"content": [_para("b\n")]}]},
                    ]
                }
            },
            {"tableOfContents": {"content": [_para("Contents\n")]}},
        ]
    },
}

# ---------------------------------------------------------------------------
# Docs
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_get_document_extracts_plain_text():
    connector, seen = make(ok(DOC))
    result = await connector.get_document("doc/1")
    (request,) = seen
    assert request.url.host == "docs.googleapis.com"
    assert request.url.raw_path.startswith(b"/v1/documents/doc%2F1?")
    assert query(request) == {"fields": "documentId,title,revisionId,body"}
    assert result == {
        "document_id": "doc1", "title": "Notes", "text": "Hello world\na\tb\nContents\n",
        "offset": 0, "truncated": False,
    }


@pytest.mark.asyncio
async def test_get_document_pages_long_text():
    long_doc = {"documentId": "d", "body": {"content": [_para("x" * 30_000)]}}
    connector, _ = make(ok(long_doc))
    first = await connector.get_document("d")
    assert len(first["text"]) == 12000 and first["next_offset"] == 12000
    assert "get_document" in first["hint"]
    last = await connector.get_document("d", offset=24000)
    assert len(last["text"]) == 6000 and last["truncated"] is False
    with pytest.raises(ConnectorError, match="'offset'"):
        await connector.get_document("d", offset=-1)


@pytest.mark.asyncio
async def test_create_document_with_text_inserts_it():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/v1/documents":
            return httpx.Response(200, json={"documentId": "new1", "title": "T"})
        return httpx.Response(200, json={"replies": [{}]})

    connector, seen = make(handler)
    result = await connector.create_document("T", text="Body", user_confirmed=True)
    create, insert = seen
    assert (create.method, body(create)) == ("POST", {"title": "T"})
    assert insert.url.raw_path == b"/v1/documents/new1:batchUpdate"
    assert body(insert) == {"requests": [{"insertText": {"location": {"index": 1}, "text": "Body"}}]}
    assert result == {"document_id": "new1", "title": "T", "link": "https://docs.google.com/document/d/new1/edit"}


@pytest.mark.asyncio
async def test_create_document_without_text_is_one_request():
    connector, seen = make(ok({"documentId": "n2"}))
    await connector.create_document("T", user_confirmed=True)
    assert len(seen) == 1
    connector, _ = make(ok({"title": "no id"}))
    with pytest.raises(ConnectorError, match="Malformed"):
        await connector.create_document("T", user_confirmed=True)


@pytest.mark.asyncio
async def test_append_and_replace_text():
    connector, seen = make(ok({"replies": [{}]}))
    assert await connector.append_text("d1", "\nMore", user_confirmed=True) == {
        "status": "appended", "document_id": "d1", "characters": 5,
    }
    assert body(seen[0]) == {"requests": [{"insertText": {"endOfSegmentLocation": {}, "text": "\nMore"}}]}

    connector, seen = make(ok({"replies": [{"replaceAllText": {"occurrencesChanged": 3}}]}))
    result = await connector.replace_text("d1", "old", "new", match_case=True, user_confirmed=True)
    assert body(seen[0]) == {
        "requests": [{"replaceAllText": {"containsText": {"text": "old", "matchCase": True}, "replaceText": "new"}}]
    }
    assert result["occurrences_changed"] == 3

    connector, _ = make(ok({"replies": [{}]}))  # Docs omits the count when nothing matched
    assert (await connector.replace_text("d1", "x", "", user_confirmed=True))["occurrences_changed"] == 0


@pytest.mark.asyncio
async def test_hostile_document_payload_does_not_crash():
    nested: dict = _para("deep\n")
    for _ in range(50):
        nested = {"table": {"tableRows": [{"tableCells": [{"content": [nested]}]}]}}
    hostile = {"documentId": 5, "title": None, "body": {"content": [nested, None, "x", {"paragraph": "p"}]}}
    connector, _ = make(ok(hostile))
    result = await connector.get_document("d")
    assert isinstance(result["text"], str) and result["title"] == ""


# ---------------------------------------------------------------------------
# Sheets
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_get_values_encodes_the_range_and_caps_rows_and_cells():
    values = [[f"r{i}", "y" * 1000] for i in range(300)]
    connector, seen = make(ok({"range": "Sheet1!A1:B300", "values": values}))
    result = await connector.get_values("s1", "Sheet1!A1:B300")
    (request,) = seen
    assert request.url.host == "sheets.googleapis.com"
    assert request.url.raw_path.startswith(b"/v4/spreadsheets/s1/values/Sheet1%21A1%3AB300?")
    assert query(request) == {"majorDimension": "ROWS", "valueRenderOption": "FORMATTED_VALUE"}
    assert result["row_count"] == 200 and result["truncated"] is True
    assert len(result["values"][0][1]) == 500 and "get_values" in result["hint"]


@pytest.mark.asyncio
async def test_get_metadata_shapes_sheets():
    data = {
        "spreadsheetId": "s1", "spreadsheetUrl": "https://docs.google.com/spreadsheets/d/s1",
        "properties": {"title": "Budget", "timeZone": "UTC"},
        "sheets": [{"properties": {"sheetId": 0, "title": "Q1", "index": 0, "gridProperties": {"rowCount": 100, "columnCount": 26}}}],
    }
    connector, seen = make(ok(data))
    result = await connector.get_metadata("s1")
    assert seen[0].url.path == "/v4/spreadsheets/s1"
    assert "sheets(properties(" in query(seen[0])["fields"]
    assert result == {
        "spreadsheet_id": "s1", "title": "Budget", "time_zone": "UTC",
        "link": "https://docs.google.com/spreadsheets/d/s1",
        "sheets": [{"sheet_id": "0", "title": "Q1", "index": "0", "rows": "100", "columns": "26"}],
    }


@pytest.mark.asyncio
async def test_update_values_is_raw_unless_parsing_is_asked_for():
    connector, seen = make(ok({"updatedRange": "S!A1:B1", "updatedRows": 1, "updatedCells": 2}))
    result = await connector.update_values("s1", "S!A1:B1", [["=1+1", 2]], user_confirmed=True)
    (request,) = seen
    assert request.method == "PUT"
    assert query(request) == {"valueInputOption": "RAW"}
    assert body(request) == {"range": "S!A1:B1", "majorDimension": "ROWS", "values": [["=1+1", 2]]}
    assert result == {"updated_range": "S!A1:B1", "updated_rows": "1", "updated_cells": "2"}

    connector, seen = make(ok({}))
    await connector.update_values("s1", "S!A1", [["=SUM(A2:A9)"]], parse_input=True, user_confirmed=True)
    assert query(seen[0]) == {"valueInputOption": "USER_ENTERED"}


@pytest.mark.asyncio
async def test_parse_input_is_named_on_the_approval_card():
    connector, _ = make(ok())
    with pytest.raises(UserConfirmationRequired) as exc:
        await connector.append_rows("s1", "S!A1", [["=IMPORTDATA(1)"]], parse_input=True)
    assert "formulas run" in exc.value.details


@pytest.mark.asyncio
async def test_append_rows_add_sheet_and_clear_range():
    connector, seen = make(ok({"updates": {"updatedRange": "S!A5:B5", "updatedRows": 1}}))
    result = await connector.append_rows("s1", "S!A1", [["a", None, True]], user_confirmed=True)
    assert seen[0].method == "POST"
    assert seen[0].url.raw_path.startswith(b"/v4/spreadsheets/s1/values/S%21A1:append?")
    assert query(seen[0]) == {"valueInputOption": "RAW", "insertDataOption": "INSERT_ROWS"}
    assert body(seen[0]) == {"majorDimension": "ROWS", "values": [["a", None, True]]}
    assert result == {"updated_range": "S!A5:B5", "updated_rows": "1"}

    connector, seen = make(ok({"replies": [{"addSheet": {"properties": {"sheetId": 7, "title": "New", "index": 2}}}]}))
    assert await connector.add_sheet("s1", "New", user_confirmed=True) == {
        "spreadsheet_id": "s1", "sheet_id": "7", "title": "New", "index": "2",
    }
    assert seen[0].url.raw_path == b"/v4/spreadsheets/s1:batchUpdate"
    assert body(seen[0]) == {"requests": [{"addSheet": {"properties": {"title": "New"}}}]}

    connector, seen = make(ok({"clearedRange": "S!A1:Z9"}))
    assert await connector.clear_range("s1", "S!A1:Z9", user_confirmed=True) == {
        "status": "cleared", "cleared_range": "S!A1:Z9",
    }
    assert seen[0].url.raw_path == b"/v4/spreadsheets/s1/values/S%21A1%3AZ9:clear"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "values,message",
    [
        ([], "1 to 1000 rows"),
        ("a,b", "1 to 1000 rows"),
        (["a"], "list of rows"),
        ([[{"x": 1}]], "Cell values"),
        ([["x" * 50_001]], "longer than"),
        ([["x"] * 101] * 100, "more than 10000 cells"),
    ],
)
async def test_sheet_writes_validate_values_first(values, message):
    connector, seen = make(ok())
    with pytest.raises(ConnectorError, match=message):
        await connector.update_values("s1", "S!A1", values, user_confirmed=True)
    assert seen == []


# ---------------------------------------------------------------------------
# Contacts
# ---------------------------------------------------------------------------

PERSON = {
    "resourceName": "people/c1",
    "etag": "etag-1",
    "metadata": {"sources": [{"type": "CONTACT", "id": "c1", "etag": "src-etag", "updateTime": "x"}]},
    "names": [{"displayName": "Ann Lee", "givenName": "Ann", "familyName": "Lee"}],
    "emailAddresses": [{"value": "ann@old.example"}, {"value": "ann@home.example"}],
    "phoneNumbers": [{"value": "+1 555 0100"}],
    "organizations": [{"name": "Acme", "title": "CTO"}],
    "biographies": [{"value": "n" * 3000}],
}


@pytest.mark.asyncio
async def test_search_contacts_clamps_to_thirty():
    connector, seen = make(ok({"results": [{"person": PERSON}, "junk"]}))
    result = await connector.search_contacts("ann", limit=100)
    (request,) = seen
    assert request.url.host == "people.googleapis.com"
    assert request.url.path == "/v1/people:searchContacts"
    assert query(request) == {
        "query": "ann", "readMask": "names,emailAddresses,phoneNumbers,organizations,biographies", "pageSize": "30",
    }
    (person,) = result
    assert person["name"] == "Ann Lee" and person["emails"] == ["ann@old.example", "ann@home.example"]
    assert person["organization"] == "Acme" and person["title"] == "CTO"
    assert len(person["notes"]) == 1000 and person["notes_truncated"] is True
    assert "etag" not in person


@pytest.mark.asyncio
async def test_get_contact_accepts_resource_names_and_refuses_paths():
    connector, seen = make(ok(PERSON))
    await connector.get_contact("people/c1")
    await connector.get_contact("c1")
    assert [r.url.path for r in seen] == ["/v1/people/c1", "/v1/people/c1"]
    for bad in ("people/../me/connections", "people/c1/x", "contactGroups/1"):
        with pytest.raises(ConnectorError, match="people/c123456789"):
            await connector.get_contact(bad)
    assert len(seen) == 2


@pytest.mark.asyncio
async def test_create_contact():
    connector, seen = make(ok(PERSON))
    await connector.create_contact("Ann", family_name="Lee", email="ann@example.com", phone="+1", notes="hi", user_confirmed=True)
    assert seen[0].url.path == "/v1/people:createContact"
    assert body(seen[0]) == {
        "names": [{"givenName": "Ann", "familyName": "Lee"}],
        "emailAddresses": [{"value": "ann@example.com"}],
        "phoneNumbers": [{"value": "+1"}],
        "biographies": [{"value": "hi", "contentType": "TEXT_PLAIN"}],
    }
    with pytest.raises(ConnectorError, match="single email"):
        await connector.create_contact("Ann", email="nope", user_confirmed=True)


@pytest.mark.asyncio
async def test_update_contact_sends_the_etag_and_keeps_other_emails():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "GET":
            return httpx.Response(200, json=PERSON)
        return httpx.Response(200, json={**PERSON, "emailAddresses": body(request)["emailAddresses"]})

    connector, seen = make(handler)
    result = await connector.update_contact("people/c1", email="ann@home.example", family_name="Park", user_confirmed=True)
    get, patch = seen
    assert get.url.path == "/v1/people/c1"
    assert patch.method == "PATCH" and patch.url.path == "/v1/people/c1:updateContact"
    assert query(patch)["updatePersonFields"] == "names,emailAddresses"
    sent = body(patch)
    assert sent["etag"] == "etag-1"
    assert sent["metadata"] == {"sources": [{"type": "CONTACT", "id": "c1", "etag": "src-etag"}]}
    assert sent["names"] == [{"givenName": "Ann", "familyName": "Park"}]
    assert sent["emailAddresses"] == [{"value": "ann@home.example"}, {"value": "ann@old.example"}]
    assert result["emails"] == ["ann@home.example", "ann@old.example"]


@pytest.mark.asyncio
async def test_update_contact_retries_once_on_an_etag_conflict():
    patches = [
        httpx.Response(400, json={"error": {"code": 400, "status": "FAILED_PRECONDITION"}}),
        httpx.Response(200, json=PERSON),
    ]

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=PERSON) if request.method == "GET" else patches.pop(0)

    connector, seen = make(handler)
    await connector.update_contact("c1", phone="+1 555 0199", user_confirmed=True)
    assert [r.method for r in seen] == ["GET", "PATCH", "GET", "PATCH"]


@pytest.mark.asyncio
async def test_update_contact_gives_up_after_a_second_conflict():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "GET":
            return httpx.Response(200, json=PERSON)
        return httpx.Response(400, json={"error": {"status": "FAILED_PRECONDITION"}})

    connector, seen = make(handler)
    with pytest.raises(ConnectorError, match="kept changing"):
        await connector.update_contact("c1", notes="x", user_confirmed=True)
    assert len(seen) == 4


@pytest.mark.asyncio
async def test_update_contact_needs_a_field_and_other_400s_are_not_retried():
    connector, seen = make(ok())
    with pytest.raises(ConnectorError, match="at least one"):
        await connector.update_contact("c1", user_confirmed=True)
    assert seen == []

    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "GET":
            return httpx.Response(200, json=PERSON)
        return httpx.Response(400, json={"error": {"status": "INVALID_ARGUMENT"}})

    connector, seen = make(handler)
    with pytest.raises(ConnectorError, match="INVALID_ARGUMENT"):
        await connector.update_contact("c1", organization="X", user_confirmed=True)
    assert len(seen) == 2


@pytest.mark.asyncio
async def test_delete_contact():
    connector, seen = make(ok({}))
    assert await connector.delete_contact("people/c1", user_confirmed=True) == {
        "status": "deleted", "resource_name": "people/c1",
    }
    assert (seen[0].method, seen[0].url.path) == ("DELETE", "/v1/people/c1:deleteContact")


@pytest.mark.asyncio
async def test_hostile_person_payloads_do_not_crash():
    hostile = {"results": [{"person": {"names": "x", "emailAddresses": [None, {"value": 5}], "biographies": [{"value": None}]}}]}
    connector, _ = make(ok(hostile))
    assert await connector.search_contacts("x") == [
        {"resource_name": None, "emails": ["5"], "phones": []}
    ]


WRITES = [
    ("create_document", {"title": "T"}),
    ("append_text", {"document_id": "d", "text": "x"}),
    ("replace_text", {"document_id": "d", "find": "a", "replace_with": "b"}),
    ("update_values", {"spreadsheet_id": "s", "a1_range": "A1", "values": [["x"]]}),
    ("append_rows", {"spreadsheet_id": "s", "a1_range": "A1", "values": [["x"]]}),
    ("add_sheet", {"spreadsheet_id": "s", "title": "T"}),
    ("clear_range", {"spreadsheet_id": "s", "a1_range": "A1"}),
    ("create_contact", {"given_name": "A"}),
    ("update_contact", {"resource_name": "c1", "given_name": "B"}),
    ("delete_contact", {"resource_name": "c1"}),
]


@pytest.mark.asyncio
@pytest.mark.parametrize("action,params", WRITES)
async def test_every_write_needs_confirmation_before_any_request(action, params):
    connector, seen = make(ok())
    with pytest.raises(UserConfirmationRequired) as exc:
        await getattr(connector, action)(**params)
    assert exc.value.action == action and exc.value.details
    assert seen == []
