"""Tests for the Outlook bodies of the scam check's two READ actions
(services/connectors/microsoft_api/mail_security.py): they prove the inbox
listing works from Graph's delta query with this action's own cursor (a
first call and a forgotten delta token only record where the inbox is),
that removed items are skipped, that Graph's next and delta links are never
followed as given (only their token is kept, and a link to another host or
path is refused), that a message's facts are read from its HTML and its
internet headers without the text-body preference, that Safe Links are
unwrapped before hosts are read, and that a deleted message answers "gone".

Why it exists: the sweeper (S2b) trusts these answers to decide what to
read and when to start over, and Block sender is deferred (owner decision
8a), so these two READs are all S2 adds to the Microsoft connector.

Connects to services/connectors/microsoft_api/mail_security.py through the
assembled MicrosoftConnector. All HTTP goes to ``httpx.MockTransport``; the
"microsoft" network-policy hook is armed where a test says ``hooked``. No
real network or credentials.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Callable
from urllib.parse import quote

import httpx
import pytest

from services.agent.permissions import ActionCategory
from services.connectors.base import AuthenticationError, ConnectorError
from services.connectors.microsoft import ACTIONS
from services.connectors.microsoft_api import mail_security
from tests.connectors.test_microsoft import TOKEN, make_connector, no_dns, ok  # noqa: F401 - fixture

GRAPH = "https://graph.microsoft.com/v1.0/me"
DELTA = "/v1.0/me/mailFolders/inbox/messages/delta"
NOW = datetime(2026, 10, 14, 9, 12, 3, tzinfo=timezone.utc)


@pytest.fixture(autouse=True)
def fixed_now(monkeypatch):
    monkeypatch.setattr(mail_security, "_utc_now", lambda: NOW)


def _next(token: str, folder: str = "mailfolders('AQMkADNkNAAAgEMAAAA')") -> str:
    return f"https://graph.microsoft.com/v1.0/me/{folder}/messages/delta?$skiptoken={token}"


def _delta(token: str, folder: str = "mailfolders('AQMkADNkNAAAgEMAAAA')") -> str:
    return f"https://graph.microsoft.com/v1.0/me/{folder}/messages/delta?$deltatoken={token}"


def _page(items: list[Any], *, next_link: str = "", delta_link: str = "") -> dict[str, Any]:
    page: dict[str, Any] = {"value": items}
    if next_link:
        page["@odata.nextLink"] = next_link
    if delta_link:
        page["@odata.deltaLink"] = delta_link
    return page


def _by_token(pages: dict[str, dict[str, Any]]) -> Callable[[httpx.Request], httpx.Response]:
    """Answers each delta request by the token it carries ("" for the first)."""

    def handler(request: httpx.Request) -> httpx.Response:
        params = request.url.params
        key = params.get("$skiptoken") or params.get("$deltatoken") or ""
        return httpx.Response(200, json=pages[key])

    return handler


def _graph_error(status: int, code: str) -> httpx.Response:
    return httpx.Response(status, json={"error": {"code": code, "message": "nope"}})


# -- list_new_message_ids --------------------------------------------------------------------


@pytest.mark.asyncio
async def test_the_first_delta_call_filters_to_now_and_returns_only_a_cursor():
    pages = {
        "": _page([{"id": "old1", "receivedDateTime": "2026-10-14T09:10:00Z"}], next_link=_next("s1")),
        "s1": _page([{"id": "old2"}], delta_link=_delta("d1")),
    }
    connector, seen = make_connector(_by_token(pages), hooked=True)
    answer = await connector.list_new_message_ids("")

    first = seen[0]
    assert first.method == "GET" and first.url.host == "graph.microsoft.com" and first.url.path == DELTA
    assert dict(first.url.params) == {
        "$select": "id,receivedDateTime",
        "$filter": "receivedDateTime ge 2026-10-14T09:07:03Z",
    }
    assert {r.headers["Prefer"] for r in seen} == {"odata.maxpagesize=50"}
    assert all(r.headers["Authorization"] == f"Bearer {TOKEN}" for r in seen)
    assert answer == {
        "cursor": "o1:d:d1",
        "message_ids": [],
        "baseline": True,
        "reset": False,
        "more": False,
        "account_domain": None,
    }


@pytest.mark.asyncio
async def test_delta_items_removed_or_without_an_id_are_skipped():
    items = [
        {"id": "m1", "receivedDateTime": "2026-10-14T09:11:00Z"},
        {"id": "m2", "@removed": {"reason": "deleted"}},
        {"receivedDateTime": "2026-10-14T09:11:00Z"},
        {"id": ""},
        {"id": 7},
        {"id": "bad\nid"},
        {"id": "x" * 1025},
        "not an item",
        None,
        {"id": "m3"},
        {"id": "m1"},
    ]
    connector, seen = make_connector(_by_token({"d0": _page(items, delta_link=_delta("d1"))}), hooked=True)
    answer = await connector.list_new_message_ids("o1:d:d0")

    assert len(seen) == 1
    assert answer == {
        "cursor": "o1:d:d1",
        "message_ids": ["m1", "m3"],
        "baseline": False,
        "reset": False,
        "more": False,
        "account_domain": None,
    }


@pytest.mark.asyncio
async def test_delta_and_skip_tokens_are_kept_and_links_are_never_followed_as_given():
    token = "aGVsbG8%3D-_.~x"  # percent-encoded as Graph writes it: kept exactly
    pages = {
        "d0": _page([{"id": "m1"}], next_link=_next(token)),
        "aGVsbG8=-_.~x": _page([{"id": "m2"}], next_link=_next("s2", folder="mailFolders('inbox')")),
        "s2": _page([{"id": "m3"}], delta_link=_delta("d9", folder="mailFolders/Inbox")),
    }
    connector, seen = make_connector(_by_token(pages), hooked=True)
    answer = await connector.list_new_message_ids("o1:d:d0")

    # Every request is rebuilt on the inbox's own delta path from the token
    # alone; the folder Graph named in its link is never used.
    assert [r.url.raw_path for r in seen] == [
        f"{DELTA}?$deltatoken=d0".encode(),
        f"{DELTA}?$skiptoken={token}".encode(),
        f"{DELTA}?$skiptoken=s2".encode(),
    ]
    assert (answer["message_ids"], answer["cursor"], answer["more"]) == (["m1", "m2", "m3"], "o1:d:d9", False)


@pytest.mark.asyncio
async def test_a_long_listing_stops_after_six_pages_with_more_and_a_skip_cursor():
    pages = {"d0": _page([{"id": "m0"}], next_link=_next("s1"))}
    for number in range(1, 14):
        pages[f"s{number}"] = _page([{"id": f"m{number}"}], next_link=_next(f"s{number + 1}"))
    connector, seen = make_connector(_by_token(pages))
    first = await connector.list_new_message_ids("o1:d:d0")
    assert len(seen) == mail_security.MAX_LIST_PAGES
    assert (first["message_ids"], first["more"], first["cursor"]) == (
        ["m0", "m1", "m2", "m3", "m4", "m5"], True, "o1:s:s6"
    )

    seen.clear()
    second = await connector.list_new_message_ids(first["cursor"])
    assert seen[0].url.raw_path == f"{DELTA}?$skiptoken=s6".encode()
    assert second["message_ids"][0] == "m6"


@pytest.mark.asyncio
async def test_a_page_larger_than_asked_keeps_the_last_three_hundred_ids():
    # Graph may ignore the page-size preference; the cursor moves past the
    # page either way, so the newest changes are the ids kept.
    items = [{"id": f"m{number}"} for number in range(400)]
    connector, seen = make_connector(_by_token({"d0": _page(items, next_link=_next("s1"))}))
    answer = await connector.list_new_message_ids("o1:d:d0")
    assert len(seen) == 1
    assert answer["message_ids"] == [f"m{number}" for number in range(100, 400)]
    assert (answer["more"], answer["cursor"]) == (True, "o1:s:s1")


@pytest.mark.asyncio
async def test_a_delta_link_on_another_host_or_path_is_refused():
    bad_links = [
        "https://evil.example/v1.0/me/mailFolders/inbox/messages/delta?$deltatoken=d1",
        "http://graph.microsoft.com/v1.0/me/mailFolders/inbox/messages/delta?$deltatoken=d1",
        "https://graph.microsoft.com:8443/v1.0/me/mailFolders/inbox/messages/delta?$deltatoken=d1",
        "https://user:pw@graph.microsoft.com/v1.0/me/mailFolders/inbox/messages/delta?$deltatoken=d1",
        "https://graph.microsoft.com/v1.0/me/messages/delta?$deltatoken=d1",
        "https://graph.microsoft.com/v1.0/me/mailFolders/sentitems/messages/delta?$deltatoken=d1",
        "https://graph.microsoft.com/v1.0/users/x/mailFolders/inbox/messages/delta?$deltatoken=d1",
        "https://graph.microsoft.com/beta/me/mailFolders/inbox/messages/delta?$deltatoken=d1",
        "https://graph.microsoft.com/v1.0/me/mailFolders/inbox/messages/delta?$deltatoken=d1&$select=body",
        "https://graph.microsoft.com/v1.0/me/mailFolders/inbox/messages/delta?$skiptoken=d1",
        "https://graph.microsoft.com/v1.0/me/mailFolders/inbox/messages/delta?$deltatoken=a/b",
        "https://graph.microsoft.com/v1.0/me/mailFolders/inbox/messages/delta?$deltatoken=",
        "https://graph.microsoft.com/v1.0/me/mailFolders/inbox/messages/delta?$deltatoken=d1#x",
        "https://graph.microsoft.com/v1.0/me/mailFolders/inbox/messages/delta/../../../me?$deltatoken=d1",
        12,
        "x" * 9000,
    ]
    for link in bad_links:
        connector, seen = make_connector(_by_token({"d0": _page([{"id": "m1"}], delta_link=link)}))  # type: ignore[arg-type]
        with pytest.raises(ConnectorError, match="paging link"):
            await connector.list_new_message_ids("o1:d:d0")
        assert len(seen) == 1, link  # nothing was requested from the link
    # A delta link where a next link belongs (and the other way round) is refused too.
    connector, seen = make_connector(_by_token({"d0": _page([], next_link=_delta("d1"))}))
    with pytest.raises(ConnectorError, match="paging link"):
        await connector.list_new_message_ids("o1:d:d0")
    # A page with neither link is a malformed reply, not an empty inbox.
    connector, _ = make_connector(_by_token({"d0": _page([{"id": "m1"}])}))
    with pytest.raises(ConnectorError, match="Malformed"):
        await connector.list_new_message_ids("o1:d:d0")


@pytest.mark.asyncio
async def test_a_gone_delta_token_starts_over_with_reset_set():
    for status, code in ((410, "SyncStateNotFound"), (410, "resyncRequired"), (400, "syncStateNotFound")):
        def handler(request: httpx.Request, status=status, code=code) -> httpx.Response:
            if request.url.params.get("$deltatoken") == "old":
                return _graph_error(status, code)
            return httpx.Response(200, json=_page([{"id": "m1"}], delta_link=_delta("fresh")))

        connector, seen = make_connector(handler)
        answer = await connector.list_new_message_ids("o1:d:old")
        assert "$filter" in seen[-1].url.params  # a new five-minute baseline
        assert answer == {
            "cursor": "o1:d:fresh",
            "message_ids": [],
            "baseline": True,
            "reset": True,
            "more": False,
            "account_domain": None,
        }


@pytest.mark.asyncio
async def test_other_listing_errors_are_raised_not_read_as_a_reset():
    for status, code, error in ((401, "InvalidAuthenticationToken", AuthenticationError),
                                (403, "ErrorAccessDenied", AuthenticationError),
                                (500, "generalException", ConnectorError)):
        connector, seen = make_connector(lambda _request, s=status, c=code: _graph_error(s, c))
        with pytest.raises(error):
            await connector.list_new_message_ids("o1:d:d0")
        assert all("$filter" not in r.url.params for r in seen)


@pytest.mark.asyncio
async def test_a_cursor_this_action_did_not_make_is_refused():
    connector, seen = make_connector(ok({}))
    for cursor in ("d0", "o1:", "o1:d:", "o1:x:abc", "o1:d:a b", "o1:d:a/b", "o1:d:" + "a" * 4001,
                   "g1:12", "o1:d:abc\n", 5, ["o1:d:abc"]):
        with pytest.raises(ConnectorError, match="not one this action made"):
            await connector.list_new_message_ids(cursor)  # type: ignore[arg-type]
    assert seen == []


# -- get_message_security --------------------------------------------------------------------


AR_OUTLOOK = (
    "spf=pass (sender IP is 1.2.3.4) smtp.mailfrom=vendor.example; dkim=pass (signature was verified) "
    "header.d=vendor.example;dmarc=pass action=none header.from=vendor.example;compauth=pass reason=100"
)


def _graph_message(**overrides: Any) -> dict[str, Any]:
    message = {
        "id": "AAMkAGI2",
        "conversationId": "AAQkAGI2",
        "subject": "Invoice",
        "receivedDateTime": "2026-10-14T09:12:03Z",
        "hasAttachments": False,
        "parentFolderId": "INBOX-ID",
        "from": {"emailAddress": {"name": "Ann Vendor", "address": "ann@vendor.example"}},
        "sender": {"emailAddress": {"name": "Ann Vendor", "address": "ann@vendor.example"}},
        "replyTo": [{"emailAddress": {"address": "billing@vendor.example"}}],
        "toRecipients": [{"emailAddress": {"address": "me@owner.example"}}],
        "ccRecipients": [{"emailAddress": {"address": "team@owner.example"}}],
        "internetMessageHeaders": [
            {"name": "Authentication-Results", "value": AR_OUTLOOK},
            {"name": "Authentication-Results", "value": "spf=pass smtp.mailfrom=paypal.com; dmarc=pass header.from=paypal.com"},
            {"name": "From", "value": "Ann Vendor <ann@vendor.example>"},
            {"name": "Subject", "value": "Invoice"},
        ],
        "body": {"contentType": "html", "content": "<p>Please see the invoice.</p>"},
    }
    message.update(overrides)
    return message


def _message_handler(message: dict[str, Any], *, attachments: list[Any] = (), sent_id: Any = "SENT-ID",
                     sent_status: int = 200) -> Callable[[httpx.Request], httpx.Response]:
    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path.endswith("/attachments"):
            return httpx.Response(200, json={"value": list(attachments)})
        if path.endswith("/mailFolders/sentitems"):
            if sent_status != 200:
                return _graph_error(sent_status, "ErrorAccessDenied")
            return httpx.Response(200, json={"id": sent_id})
        return httpx.Response(200, json=message)

    return handler


@pytest.mark.asyncio
async def test_message_security_asks_for_html_and_headers_without_the_text_preference():
    connector, seen = make_connector(_message_handler(_graph_message()), hooked=True)
    facts = await connector.get_message_security("AAMkAGI2")

    request = seen[0]
    assert request.url.path == "/v1.0/me/messages/AAMkAGI2"
    selected = set(request.url.params["$select"].split(","))
    assert {"internetMessageHeaders", "body", "from", "sender", "replyTo", "subject", "receivedDateTime",
            "hasAttachments", "parentFolderId", "toRecipients", "ccRecipients", "conversationId"} <= selected
    assert "Prefer" not in request.headers  # get_message's text preference would drop the hrefs
    assert [r.url.path for r in seen] == ["/v1.0/me/messages/AAMkAGI2", "/v1.0/me/mailFolders/sentitems"]

    auth = facts["auth"]
    assert (auth["source"], auth["dmarc"], auth["compauth"], auth["header_from_domain"]) == (
        "authentication-results", "pass", "pass", "vendor.example"
    )
    assert facts["from"] == {"name": "Ann Vendor", "address": "ann@vendor.example", "domain": "vendor.example"}
    assert facts["reply_to"] == ["billing@vendor.example"]
    assert (facts["to"], facts["cc"], facts["sent_by_me"], facts["mailbox"]) == (
        ["me@owner.example"], ["team@owner.example"], False, ""
    )
    assert (facts["provider"], facts["folder"], facts["thread_id"], facts["received"]) == (
        "outlook", "inbox", "AAQkAGI2", "2026-10-14T09:12:03Z"
    )
    assert facts["attachments"] == [] and facts["gone"] is False


@pytest.mark.asyncio
async def test_internal_mail_without_headers_reads_as_internal_from_graphs_own_fields():
    message = _graph_message(internetMessageHeaders=None, body={"contentType": "text", "content": "Lunch?"})
    connector, _ = make_connector(_message_handler(message))
    facts = await connector.get_message_security("AAMkAGI2")
    assert facts["auth"]["source"] == "internal"
    assert facts["from"]["address"] == "ann@vendor.example"
    assert facts["subject"] == "Invoice" and facts["text"] == "Lunch?"


@pytest.mark.asyncio
async def test_sent_items_mail_is_marked_as_sent_and_an_unreadable_folder_is_not():
    connector, _ = make_connector(_message_handler(_graph_message(parentFolderId="SENT-ID")))
    facts = await connector.get_message_security("AAMkAGI2")
    assert (facts["sent_by_me"], facts["folder"]) == (True, "sent")

    connector, _ = make_connector(_message_handler(_graph_message(parentFolderId="SENT-ID"), sent_status=403))
    assert (await connector.get_message_security("AAMkAGI2"))["sent_by_me"] is False

    connector, seen = make_connector(_message_handler(_graph_message(parentFolderId=None)))
    assert (await connector.get_message_security("AAMkAGI2"))["sent_by_me"] is False
    assert len(seen) == 1  # no folder lookup without a parent folder


@pytest.mark.asyncio
async def test_attachments_are_listed_only_for_a_message_that_has_some():
    attachments = [
        {"id": "att-1", "name": "invoice.pdf.exe", "contentType": "application/octet-stream", "size": 48211,
         "isInline": False},
        {"id": "att-2", "name": "logo.png", "contentType": "image/png", "size": 10, "isInline": True},
        "junk",
    ]
    connector, seen = make_connector(_message_handler(_graph_message(hasAttachments=True), attachments=attachments))
    facts = await connector.get_message_security("AAMkAGI2")

    listing = next(r for r in seen if r.url.path.endswith("/attachments"))
    assert listing.url.path == "/v1.0/me/messages/AAMkAGI2/attachments"
    assert listing.url.params["$select"] == "id,name,contentType,size,isInline"
    assert listing.url.params["$top"] == str(mail_security.MAX_ATTACHMENTS)
    assert facts["attachments"] == [
        {"ref": "att-1", "filename": "invoice.pdf.exe", "mime_type": "application/octet-stream", "size": 48211,
         "is_inline": False},
        {"ref": "att-2", "filename": "logo.png", "mime_type": "image/png", "size": 10, "is_inline": True},
    ]


@pytest.mark.asyncio
async def test_safe_links_are_unwrapped_before_hosts_are_read():
    target = "https://evil.example/login?user=1"
    wrapped = (
        "https://nam12.safelinks.protection.outlook.com/?url=" + quote(target, safe="")
        + "&data=05%7C01%7C&reserved=0"
    )
    html = f'<p>Sign in:</p><a href="{wrapped}">https://www.paypal.com/signin</a>'
    message = _graph_message(body={"contentType": "html", "content": html})
    connector, _ = make_connector(_message_handler(message))
    response = await connector.execute("get_message_security", {"message_id": "AAMkAGI2"})

    links = response.data["links"]
    [link] = [link for link in links if link["wrapped"]]
    assert (link["host"], link["href"], link["wrapped"], link["text"]) == (
        "evil.example", target, "safelinks", "https://www.paypal.com/signin"
    )
    # No link keeps Microsoft's wrapper host: the checks read the real one.
    assert not any("safelinks" in link["host"] for link in links)


@pytest.mark.asyncio
async def test_a_deleted_message_answers_gone_not_an_error():
    for status, code in ((404, "ErrorItemNotFound"), (404, "itemNotFound"), (400, "ErrorItemNotFound")):
        connector, seen = make_connector(lambda _request, s=status, c=code: _graph_error(s, c))
        assert await connector.get_message_security("AAMkAGI2") == {"id": "AAMkAGI2", "gone": True}
        assert len(seen) == 1
    # Deleted between the message and its attachment list.
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/attachments"):
            return _graph_error(404, "ErrorItemNotFound")
        return httpx.Response(200, json=_graph_message(hasAttachments=True))

    connector, _ = make_connector(handler)
    response = await connector.execute("get_message_security", {"message_id": "AAMkAGI2"})
    assert response.data == {"id": "AAMkAGI2", "gone": True}


@pytest.mark.asyncio
async def test_other_message_errors_are_raised_not_read_as_gone():
    for status, code, error in ((401, "InvalidAuthenticationToken", AuthenticationError),
                                (403, "ErrorAccessDenied", AuthenticationError),
                                (500, "ErrorInternalServerError", ConnectorError),
                                (400, "ErrorInvalidIdMalformed", ConnectorError)):
        connector, _ = make_connector(lambda _request, s=status, c=code: _graph_error(s, c))
        with pytest.raises(error):
            await connector.get_message_security("AAMkAGI2")
    connector, seen = make_connector(ok({}))
    for bad in ("", "  ", None, "a\x00b"):
        with pytest.raises(ConnectorError):
            await connector.get_message_security(bad)  # type: ignore[arg-type]
    assert seen == []


# -- The declarations (owner decision 8a) ----------------------------------------------------


def test_the_new_actions_are_reads_with_the_read_scope_and_no_block_sender_exists():
    specs = {spec.action: spec for spec in ACTIONS}
    for name in ("list_new_message_ids", "get_message_security"):
        spec = specs[name]
        assert (spec.category, spec.required_scope, spec.always_confirm) == (ActionCategory.READ, "mail.read", False)
    assert "block_sender" not in specs
    assert not hasattr(mail_security, "block_sender")
    assert not any("settings" in (spec.required_scope or "") for spec in ACTIONS)
