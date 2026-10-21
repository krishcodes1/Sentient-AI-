"""Tests for the Gmail bodies of the scam check's two READ actions
(services/connectors/google_api/mail_security.py): they prove the inbox
listing works from Gmail's history with this action's own cursor (a first
call and a forgotten history id only record where the mailbox is), that new
mail skips Sent, Draft, Spam and Trash, that paging continues on the next
call, that a message's facts read every Authentication-Results header (only
the receiving provider's topmost counts), that a script link survives the
connector's PromptGuard as a code, and that a deleted message answers "gone".

Why it exists: the sweeper (S2b) trusts these answers to decide what to
read and when to start over, and Block sender is deferred (owner decision
8a), so these two READs are all S2 adds to the Google connector.

Connects to services/connectors/google_api/mail_security.py through the
assembled GoogleWorkspaceConnector. All HTTP goes to ``httpx.MockTransport``
with the "google" network-policy hook armed; no real network or credentials.
"""

from __future__ import annotations

import base64
import json
from typing import Any

import httpx
import pytest

from services.agent.permissions import ActionCategory
from services.connectors.base import AuthenticationError, ConnectorError
from services.connectors.google_api import mail_security
from services.connectors.google_workspace import ACTIONS
from tests.connectors.test_google_workspace_support import (
    make,
    no_dns,  # noqa: F401 - fixture
    no_secret_in,
    ok,
    query,
)

pytestmark = pytest.mark.usefixtures("no_dns")

GMAIL = "/gmail/v1/users/me"
GOOGLE_PASS = (
    "mx.google.com; dkim=pass header.i=@vendor.example header.s=s1 header.b=abc; "
    "spf=pass (google.com: domain of ann@vendor.example designates 1.2.3.4 as permitted sender) "
    "smtp.mailfrom=ann@vendor.example; dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=vendor.example"
)
GOOGLE_FAIL = (
    "mx.google.com; spf=fail smtp.mailfrom=service@paypa1-support.com; dkim=none; "
    "dmarc=fail (p=REJECT sp=REJECT dis=REJECT) header.from=paypa1-support.com"
)
FORGED_PASS = "evil.example; spf=pass smtp.mailfrom=paypal.com; dkim=pass header.d=paypal.com; dmarc=pass"


def _b64(data: str) -> str:
    return base64.urlsafe_b64encode(data.encode()).decode().rstrip("=")


def _message(
    *,
    message_id: str = "18c2f6b0a1d2e3f4",
    headers: list[tuple[str, str]] | None = None,
    html: str = "<p>Hello</p>",
    plain: str = "Hello",
    labels: list[str] | None = None,
    extra_parts: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """A Gmail format=full message; headers are a list, so a name may repeat."""
    header_list = headers if headers is not None else [
        ("Authentication-Results", GOOGLE_PASS),
        ("From", "Ann Vendor <ann@vendor.example>"),
        ("To", "me@owner.example"),
        ("Subject", "Hello"),
    ]
    parts = [
        {"partId": "0", "mimeType": "text/plain", "headers": [], "body": {"data": _b64(plain)}},
        {"partId": "1", "mimeType": "text/html", "headers": [], "body": {"data": _b64(html)}},
    ]
    return {
        "id": message_id,
        "threadId": "t1",
        "labelIds": labels if labels is not None else ["INBOX", "UNREAD"],
        "internalDate": "1791969123000",
        "payload": {
            "mimeType": "multipart/mixed",
            "headers": [{"name": name, "value": value} for name, value in header_list],
            "parts": [{"partId": "", "mimeType": "multipart/alternative", "parts": parts}, *(extra_parts or [])],
        },
    }


def _added(message_id: str, *labels: str) -> dict[str, Any]:
    return {"message": {"id": message_id, "threadId": "t", "labelIds": list(labels)}}


def _error(status: int) -> httpx.Response:
    return httpx.Response(status, json={"error": {"code": status, "status": "NOT_FOUND"}})


# -- list_new_message_ids --------------------------------------------------------------------


@pytest.mark.asyncio
async def test_the_first_listing_reads_the_profile_history_id_and_returns_no_mail():
    connector, seen = make(ok({"emailAddress": "Me@Northwind.example", "historyId": "4821"}))
    answer = await connector.list_new_message_ids("")

    assert [(r.method, r.url.path) for r in seen] == [("GET", f"{GMAIL}/profile")]
    assert answer == {
        "cursor": "g1:4821",
        "message_ids": [],
        "baseline": True,
        "reset": False,
        "more": False,
        "account_domain": "northwind.example",
    }
    # A consumer mailbox belongs to no organisation.
    connector, _ = make(ok({"emailAddress": "someone@gmail.com", "historyId": 7}))
    assert (await connector.list_new_message_ids())["account_domain"] is None
    # A profile without a usable history id is a malformed reply, not a cursor.
    connector, _ = make(ok({"emailAddress": "someone@gmail.com", "historyId": "12abc"}))
    with pytest.raises(ConnectorError, match="Malformed"):
        await connector.list_new_message_ids("")


@pytest.mark.asyncio
async def test_new_inbox_messages_come_from_history_with_message_added_only_and_skip_labels():
    page = {
        "historyId": "5000",
        "history": [
            {"id": "4822", "messagesAdded": [_added("a1", "INBOX", "UNREAD"), _added("s1", "SENT", "INBOX")]},
            {"id": "4823", "messages": [{"id": "x9"}], "labelsAdded": [_added("l1", "INBOX")]},
            {"id": "4824", "messagesAdded": [_added("d1", "DRAFT"), _added("p1", "SPAM"), _added("t1", "TRASH")]},
            {"id": "4825", "messagesAdded": [_added("a1", "INBOX"), _added("a2", "INBOX", "CATEGORY_UPDATES")]},
            {"id": "4826", "messagesAdded": [{"message": {"id": "../profile"}}, {"message": "x"}, "junk", None]},
            "not a record",
        ],
    }
    connector, seen = make(ok(page))
    answer = await connector.list_new_message_ids("g1:4821")

    assert len(seen) == 1 and seen[0].url.path == f"{GMAIL}/history"
    assert query(seen[0]) == {
        "startHistoryId": "4821",
        "historyTypes": "messageAdded",
        "labelId": "INBOX",
        "maxResults": "100",
    }
    assert answer == {
        "cursor": "g1:5000",
        "message_ids": ["a1", "a2"],
        "baseline": False,
        "reset": False,
        "more": False,
        "account_domain": None,
    }


@pytest.mark.asyncio
async def test_a_history_id_google_no_longer_has_starts_over_with_reset_set():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/history"):
            return _error(404)
        return httpx.Response(200, json={"emailAddress": "me@northwind.example", "historyId": "9000"})

    connector, seen = make(handler)
    answer = await connector.list_new_message_ids("g1:12")

    assert [r.url.path for r in seen] == [f"{GMAIL}/history", f"{GMAIL}/profile"]
    assert answer == {
        "cursor": "g1:9000",
        "message_ids": [],
        "baseline": True,
        "reset": True,
        "more": False,
        "account_domain": "northwind.example",
    }


@pytest.mark.asyncio
async def test_history_paging_returns_more_and_a_cursor_that_continues_the_page():
    pages = {
        "": {"historyId": "700", "nextPageToken": "p2", "history": [{"messagesAdded": [_added("m1", "INBOX")]}]},
        "p2": {"historyId": "700", "nextPageToken": "p3", "history": [{"messagesAdded": [_added("m2", "INBOX")]}]},
        "p3": {"historyId": "701", "nextPageToken": "p4", "history": [{"messagesAdded": [_added("m3", "INBOX")]}]},
        "p4": {"historyId": "702", "history": [{"messagesAdded": [_added("m4", "INBOX"), _added("m1", "INBOX")]}]},
    }

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=pages[request.url.params.get("pageToken", "")])

    connector, seen = make(handler)
    first = await connector.list_new_message_ids("g1:650")

    # Three pages per call, then the cursor keeps the start and the next page.
    assert [query(r).get("pageToken") for r in seen] == [None, "p2", "p3"]
    assert {query(r)["startHistoryId"] for r in seen} == {"650"}
    assert first["message_ids"] == ["m1", "m2", "m3"]
    assert (first["more"], first["cursor"], first["baseline"]) == (True, "g1:650:p4", False)

    seen.clear()
    second = await connector.list_new_message_ids(first["cursor"])
    assert [(query(r)["startHistoryId"], query(r)["pageToken"]) for r in seen] == [("650", "p4")]
    assert (second["message_ids"], second["more"], second["cursor"]) == (["m4", "m1"], False, "g1:702")


@pytest.mark.asyncio
async def test_a_page_token_the_cursor_cannot_carry_fails_instead_of_losing_mail():
    page = {"historyId": "800", "nextPageToken": "a b/c", "history": [{"messagesAdded": [_added("m1", "INBOX")]}]}
    connector, _ = make(ok(page))
    with pytest.raises(ConnectorError, match="Malformed"):
        await connector.list_new_message_ids("g1:799")


@pytest.mark.asyncio
async def test_a_cursor_this_action_did_not_make_is_refused():
    connector, seen = make(ok({}))
    for cursor in (
        "4821",
        "g1:",
        "g1:12x",
        "g1:" + "1" * 21,
        "g2:12",
        "o1:d:abc",
        "g1:12:",
        "g1:12:a/b",
        "g1:12:" + "a" * 513,
        "g1:12\n",
        " g1:12",
        12,
        ["g1:12"],
    ):
        with pytest.raises(ConnectorError, match="not one this action made"):
            await connector.list_new_message_ids(cursor)  # type: ignore[arg-type]
    assert seen == []  # nothing reached Gmail


@pytest.mark.asyncio
async def test_other_listing_errors_are_raised_not_read_as_a_reset():
    for status, error in ((403, AuthenticationError), (500, ConnectorError), (400, ConnectorError)):
        connector, seen = make(lambda _request, status=status: _error(status))
        with pytest.raises(error):
            await connector.list_new_message_ids("g1:12")
        assert [r.url.path for r in seen][-1] == f"{GMAIL}/history"
        assert not any(r.url.path.endswith("/profile") for r in seen)


# -- get_message_security --------------------------------------------------------------------


@pytest.mark.asyncio
async def test_message_security_reads_every_results_header_not_just_the_first():
    # A header from another server comes first (mime.header_map would keep
    # only it); the receiving Gmail's own topmost verdict is what counts, and
    # a forged pass further down is never read.
    headers = [
        ("Authentication-Results", "relay.example; spf=pass smtp.mailfrom=paypal.com; dmarc=pass header.from=paypal.com"),
        ("Authentication-Results", GOOGLE_FAIL),
        ("Authentication-Results", FORGED_PASS),
        ("From", "PayPal Service <service@paypa1-support.com>"),
        ("Reply-To", "billing.paypal@gmail.com"),
        ("To", "Me <me@owner.example>, other@owner.example"),
        ("Cc", "team@owner.example"),
        ("Subject", "Your account has been limited"),
        ("Return-Path", "<bounce@paypa1-support.com>"),
        ("Message-ID", "<abc@paypa1-support.com>"),
    ]
    connector, seen = make(ok(_message(headers=headers)))
    facts = await connector.get_message_security("18c2f6b0a1d2e3f4")

    assert len(seen) == 1
    assert seen[0].url.raw_path == f"{GMAIL}/messages/18c2f6b0a1d2e3f4?format=full".encode()
    auth = facts["auth"]
    assert (auth["source"], auth["spf"], auth["dkim"], auth["dmarc"]) == ("authentication-results", "fail", "none", "fail")
    assert (auth["dmarc_policy"], auth["header_from_domain"]) == ("reject", "paypa1-support.com")
    assert facts["from"] == {"name": "PayPal Service", "address": "service@paypa1-support.com", "domain": "paypa1-support.com"}
    assert facts["reply_to"] == ["billing.paypal@gmail.com"]
    # Scaffold A7 keys for S1.
    assert (facts["to"], facts["cc"]) == (["me@owner.example", "other@owner.example"], ["team@owner.example"])
    assert (facts["sent_by_me"], facts["mailbox"], facts["gone"]) == (False, "", False)
    assert (facts["provider"], facts["folder"], facts["thread_id"]) == ("gmail", "inbox", "t1")
    assert facts["received"] == "2026-10-14T09:12:03Z"


@pytest.mark.asyncio
async def test_mail_in_the_sent_label_is_marked_as_sent_by_the_mailbox():
    connector, _ = make(ok(_message(labels=["SENT"])))
    facts = await connector.get_message_security("18c2f6b0a1d2e3f4")
    assert (facts["sent_by_me"], facts["folder"]) == (True, "sent")


@pytest.mark.asyncio
async def test_javascript_links_arrive_as_codes_after_the_connector_guard():
    html = (
        '<p>Verify now:</p><a href="javascript:alert(document.cookie)">paypal.com/signin</a>'
        '<a href="https://evil.example/login?token=1">www.paypal.com</a>'
    )
    connector, _ = make(ok(_message(html=html, plain="")))
    response = await connector.execute("get_message_security", {"message_id": "18c2f6b0a1d2e3f4"})
    links = response.data["links"]

    script = next(link for link in links if link["code"])
    assert (script["code"], script["href"], script["scheme"], script["text"]) == (
        "script_link", "", "javascript", "paypal.com/signin"
    )
    real = next(link for link in links if link["host"])
    assert (real["host"], real["text"], real["href"]) == ("evil.example", "www.paypal.com", "https://evil.example/login?token=1")
    assert "javascript" not in json.dumps(links).replace('"scheme": "javascript"', "")
    assert no_secret_in(response.data)


@pytest.mark.asyncio
async def test_get_message_and_its_attachment_list_are_unchanged():
    attachment = {
        "partId": "2",
        "mimeType": "application/octet-stream",
        "filename": "invoice.pdf.exe",
        "headers": [{"name": "Content-Disposition", "value": 'attachment; filename="invoice.pdf.exe"'}],
        "body": {"attachmentId": "att-1", "size": 48211},
    }
    message = _message(extra_parts=[attachment])
    connector, _ = make(ok(message))

    plain = await connector.get_message("18c2f6b0a1d2e3f4")
    assert plain["attachments"] == [
        {"part_id": "2", "filename": "invoice.pdf.exe", "mime_type": "application/octet-stream", "size": 48211}
    ]
    assert set(plain) >= {"id", "thread_id", "subject", "from", "to", "body", "label_ids"}
    assert "auth" not in plain and "links" not in plain

    facts = await connector.get_message_security("18c2f6b0a1d2e3f4")
    assert facts["attachments"] == [
        {"ref": "2", "filename": "invoice.pdf.exe", "mime_type": "application/octet-stream", "size": 48211, "is_inline": False}
    ]


@pytest.mark.asyncio
async def test_a_deleted_message_answers_gone_not_an_error():
    connector, seen = make(lambda _request: _error(404))
    assert await connector.get_message_security("18c2f6b0a1d2e3f4") == {"id": "18c2f6b0a1d2e3f4", "gone": True}
    assert len(seen) == 1
    # Through the connector's front door too (the sweeper's path).
    response = await connector.execute("get_message_security", {"message_id": "18c2f6b0a1d2e3f4"})
    assert response.data == {"id": "18c2f6b0a1d2e3f4", "gone": True}


@pytest.mark.asyncio
async def test_other_message_errors_are_raised_not_read_as_gone():
    for status, error in ((401, AuthenticationError), (403, AuthenticationError), (500, ConnectorError), (400, ConnectorError)):
        connector, _ = make(lambda _request, status=status: _error(status))
        with pytest.raises(error) as raised:
            await connector.get_message_security("18c2f6b0a1d2e3f4")
        assert "gone" not in str(raised.value)
    connector, seen = make(ok({}))
    for bad in ("", "   ", None, "a\nb"):
        with pytest.raises(ConnectorError):
            await connector.get_message_security(bad)  # type: ignore[arg-type]
    assert seen == []


@pytest.mark.asyncio
async def test_a_hostile_message_payload_never_crashes_the_action():
    for payload in ({}, {"payload": "x"}, {"payload": {"headers": "x", "parts": [None, 3, {"parts": "y"}]}},
                    {"id": 5, "labelIds": "INBOX", "payload": {"headers": [{"name": 1}, "z"]}}):
        connector, _ = make(ok(payload))
        facts = await connector.get_message_security("m1")
        assert facts["gone"] is False and facts["links"] == [] and facts["attachments"] == []


# -- The declarations (owner decision 8a) ----------------------------------------------------


def test_the_new_actions_are_reads_with_the_read_scope_and_no_block_sender_exists():
    specs = {spec.action: spec for spec in ACTIONS}
    for name in ("list_new_message_ids", "get_message_security"):
        spec = specs[name]
        assert (spec.category, spec.required_scope, spec.policy_key, spec.always_confirm) == (
            ActionCategory.READ, "gmail.read", "gmail", False
        )
    # Block sender is deferred: no action, no body and no settings scope.
    assert "block_sender" not in specs
    assert not hasattr(mail_security, "block_sender")
    assert not any("settings" in (spec.required_scope or "") for spec in ACTIONS)
