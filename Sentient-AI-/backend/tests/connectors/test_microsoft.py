"""Tests for the Microsoft 365 connector: its definition, the Outlook mail
actions, the shared failure matrix, nextLink pagination, the network policy
and token hygiene.

Why it exists: the connector reads and sends mail on the user's behalf, so
every request it makes (method, host, raw path, query, body), every refusal
(confirmation before any request, off-list hosts, hostile next links) and
every error string (never a token) is pinned here.
It exercises ``services/connectors/microsoft.py`` and
``services/connectors/microsoft_api/`` through ``httpx.MockTransport`` only
(no network, no real credentials); ``check_ssrf`` is replaced where the policy
hook runs. The helpers here are reused by the other test_microsoft files.
"""

from __future__ import annotations

import json
from typing import Any, Callable

import httpx
import pytest

import core.network_security as netsec
from services.agent.permissions import ActionCategory
from services.connectors.base import (
    AuthenticationError,
    ConnectorError,
    RateLimitExceededError,
    UserConfirmationRequired,
)
from services.connectors.microsoft import ACTIONS, DEFINITION, MicrosoftConnector
from services.connectors.registry import get_definition, validate_registry

TOKEN = "EwB-test-access-token-not-real"  # obviously fake
GRAPH = "https://graph.microsoft.com/v1.0/me"
PUBLIC_IP = "20.190.151.68"

Handler = Callable[[httpx.Request], httpx.Response]


def make_connector(
    handler: Handler, *, hooked: bool = False
) -> tuple[MicrosoftConnector, list[httpx.Request]]:
    """An authenticated connector whose HTTP goes to *handler*.

    ``hooked=True`` keeps the real network-policy hook on the mock client
    (redirect tests); the caller must then stub ``check_ssrf``.
    """
    seen: list[httpx.Request] = []

    def recording(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return handler(request)

    connector = MicrosoftConnector()
    connector._authenticated = True
    connector._token = TOKEN
    kwargs: dict[str, Any] = {"transport": httpx.MockTransport(recording)}
    if hooked:
        connector.set_network_policy("microsoft")
        kwargs["event_hooks"] = {"request": [connector._enforce_network_policy]}
        kwargs["max_redirects"] = connector.MAX_REDIRECTS
    connector._http_client = httpx.AsyncClient(**kwargs)

    async def no_sleep(_seconds: float) -> None:
        return None

    connector._sleep = no_sleep
    return connector, seen


def ok(payload: Any, status: int = 200) -> Handler:
    return lambda request: httpx.Response(status, json=payload)


def body_of(request: httpx.Request) -> Any:
    return json.loads(request.content)


@pytest.fixture
def no_dns(monkeypatch):
    """Policy checks decide on the allowlist alone; no DNS lookups."""
    monkeypatch.setattr(
        netsec,
        "check_ssrf",
        lambda url: netsec.SSRFCheckResult(safe=True, resolved_ip=PUBLIC_IP, resolved_ips=(PUBLIC_IP,)),
    )


# ---------------------------------------------------------------------------
# Definition
# ---------------------------------------------------------------------------


def test_definition_passes_registry_validation_and_is_registered():
    assert validate_registry([DEFINITION]) == []
    assert get_definition("microsoft") is DEFINITION
    assert DEFINITION.key == "microsoft"


def test_actions_match_the_spec_table():
    expected = {
        "list_messages", "search_messages", "get_message", "get_attachment_text", "list_folders",
        "send_mail", "reply", "forward", "create_draft", "move_message", "flag_message",
        "delete_message", "list_events", "find_meeting_times", "list_calendars",
        "create_event", "update_event", "respond_to_invite", "delete_event",
        "search_files", "get_file_text", "list_folder", "upload_file", "create_folder",
        "move_file", "create_share_link", "delete_file", "list_task_lists", "list_tasks",
        "create_task", "update_task", "complete_task", "delete_task", "search_contacts",
    }
    assert {spec.action for spec in ACTIONS} == expected
    assert MicrosoftConnector._ACTIONS == frozenset(expected)


def test_always_confirm_and_starters():
    always = {spec.action for spec in ACTIONS if spec.always_confirm}
    assert always == {
        "send_mail", "reply", "forward", "delete_message", "delete_event",
        "create_share_link", "delete_file", "delete_task",
    }
    assert all(s.always_confirm for s in ACTIONS if s.category == ActionCategory.DELETE)
    starters = [s for s in ACTIONS if s.starter]
    assert 2 <= len(starters) <= 4
    assert all(s.category == ActionCategory.READ for s in starters)


def test_oauth_is_a_public_client_with_least_privilege_scopes():
    oauth = DEFINITION.auth.oauth
    assert oauth is not None
    assert DEFINITION.auth.methods == ("oauth", "device")
    assert DEFINITION.auth.fields == ()
    assert oauth.client_id_setting == "MICROSOFT_OAUTH_CLIENT_ID"
    assert oauth.client_secret_setting == ""
    assert oauth.revoke_url == ""
    assert oauth.base_scopes == ("offline_access",)
    assert oauth.provider_scopes(["mail.read"]) == ("offline_access", "Mail.Read")
    assert oauth.scope_map["mail.send"] == ("Mail.Send",)
    assert oauth.scope_map["files.write"] == ("Files.ReadWrite",)
    assert oauth.scope_map["contacts.read"] == ("Contacts.Read",)
    assert oauth.device_code_url.endswith("/common/oauth2/v2.0/devicecode")


# ---------------------------------------------------------------------------
# Auth, health, revoke, dispatch
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_authenticate_requires_an_access_token():
    connector = MicrosoftConnector()
    with pytest.raises(AuthenticationError, match="Reconnect Microsoft 365"):
        await connector.authenticate({"refresh_token": "r"})
    assert await connector.authenticate({"access_token": TOKEN, "granted_scopes": ["Files.Read"]})
    assert connector._auth_headers() == {"Authorization": f"Bearer {TOKEN}"}


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("granted", "raw_path"),
    [
        (["Mail.Read"], b"/v1.0/me/mailFolders/inbox?%24select=id"),
        (["Files.Read"], b"/v1.0/me/drive?%24select=id"),
        (["Tasks.Read"], b"/v1.0/me/todo/lists"),
        ([], b"/v1.0/me/mailFolders/inbox?%24select=id"),
        # Microsoft may answer with URL-form and lower-case scope values,
        # which the broker stores as returned.
        (["https://graph.microsoft.com/Files.Read"], b"/v1.0/me/drive?%24select=id"),
        (["offline_access", "files.read"], b"/v1.0/me/drive?%24select=id"),
        (["https://graph.microsoft.com/tasks.readwrite"], b"/v1.0/me/todo/lists"),
        (["CALENDARS.READ"], b"/v1.0/me/calendars?%24top=1&%24select=id"),
        (["Calendars.Read.Shared"], b"/v1.0/me/calendars?%24top=1&%24select=id"),
        (["contacts.read"], b"/v1.0/me/contacts?%24top=1&%24select=id"),
        (["https://graph.microsoft.com/mail.readwrite"], b"/v1.0/me/mailFolders/inbox?%24select=id"),
        # Mail.Send cannot read the inbox: another granted read wins.
        (["Mail.Send", "Files.Read"], b"/v1.0/me/drive?%24select=id"),
    ],
)
async def test_health_check_uses_one_cheap_get_the_grant_allows(granted, raw_path):
    connector, seen = make_connector(ok({"id": "x"}))
    connector._granted = tuple(granted)
    assert await connector.health_check() is True
    (request,) = seen
    assert request.method == "GET"
    assert request.url.host == "graph.microsoft.com"
    assert request.url.raw_path == raw_path


@pytest.mark.asyncio
async def test_health_check_is_false_on_error():
    connector, _ = make_connector(ok({"error": {"code": "InvalidAuthenticationToken"}}, 401))
    assert await connector.health_check() is False


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("granted", "status", "healthy"),
    [
        # Only Mail.Send: no GET can succeed, so a 403 (token accepted,
        # permission missing) is the healthy answer and a 401 is not.
        (["Mail.Send"], 403, True),
        (["https://graph.microsoft.com/mail.send", "offline_access"], 403, True),
        (["Mail.Send"], 401, False),
        (["Mail.Send"], 500, False),
        # A grant that can read must really succeed: its 403 is a failure.
        (["Mail.Read"], 403, False),
        (["https://graph.microsoft.com/Files.Read"], 403, False),
        # Unknown grant (older row, or only sign-in scopes): strict probe.
        ([], 403, False),
        (["offline_access", "openid"], 403, False),
    ],
)
async def test_health_check_with_a_grant_that_cannot_read(granted, status, healthy):
    connector, seen = make_connector(ok({"error": {"code": "ErrorAccessDenied"}}, status))
    connector._granted = tuple(granted)
    assert await connector.health_check() is healthy
    assert seen and all(r.method == "GET" for r in seen)
    assert len({r.url.raw_path for r in seen}) == 1


@pytest.mark.asyncio
async def test_health_check_reads_the_structured_status_not_the_message(monkeypatch):
    connector, seen = make_connector(ok({}))
    connector._granted = ("Mail.Send",)

    def refusing(message: str, status: int | None) -> Callable[..., Any]:
        async def request(*args: Any, **kwargs: Any) -> httpx.Response:
            raise AuthenticationError(message, status_code=status)

        return request

    # Worded like a 403 but carrying no status: not proof the token works.
    monkeypatch.setattr(
        connector, "_request",
        refusing("HTTP 403 from Microsoft 365: missing permission or scope.", None),
    )
    assert await connector.health_check() is False
    # A real 403 counts whatever its wording.
    monkeypatch.setattr(connector, "_request", refusing("Access denied.", 403))
    assert await connector.health_check() is True
    assert seen == []


@pytest.mark.asyncio
async def test_revoke_returns_false_without_any_request():
    connector, seen = make_connector(ok({}))
    assert await connector.revoke() is False
    assert seen == []
    assert connector.updated_credentials({"access_token": TOKEN}) is None


@pytest.mark.asyncio
async def test_dispatch_refuses_unknown_actions_and_wraps_lists():
    connector, _ = make_connector(ok({"value": [{"id": "f1", "displayName": "Inbox"}]}))
    with pytest.raises(ConnectorError, match="Unknown Microsoft 365 action"):
        await connector._dispatch("_request", {})
    result = await connector._dispatch("list_folders", {})
    assert result["count"] == 1 and result["items"][0]["name"] == "Inbox"


# ---------------------------------------------------------------------------
# Mail: reads
# ---------------------------------------------------------------------------

_MESSAGE = {
    "id": "m1",
    "subject": "Quarterly report",
    "from": {"emailAddress": {"name": "Ann", "address": "ann@contoso.com"}},
    "receivedDateTime": "2026-09-24T08:00:00Z",
    "isRead": False,
    "hasAttachments": False,
    "bodyPreview": "Hi, attached is",
    "flag": {"flagStatus": "notFlagged"},
    "internetMessageHeaders": [{"name": "X-Secret", "value": "leak"}],
}


@pytest.mark.asyncio
async def test_list_messages_sends_one_get_with_top_select_and_order():
    connector, seen = make_connector(ok({"value": [_MESSAGE]}))
    result = await connector.list_messages()

    (request,) = seen
    assert request.method == "GET"
    assert request.url.host == "graph.microsoft.com"
    assert request.url.raw_path.startswith(b"/v1.0/me/mailFolders/inbox/messages?")
    params = request.url.params
    assert params["$top"] == "10"
    assert params["$orderby"] == "receivedDateTime desc"
    assert "bodyPreview" in params["$select"] and "body," not in params["$select"]
    assert "$filter" not in params
    assert request.headers["Authorization"] == f"Bearer {TOKEN}"
    assert result == [
        {
            "id": "m1",
            "subject": "Quarterly report",
            "from": "Ann <ann@contoso.com>",
            "received": "2026-09-24T08:00:00Z",
            "is_read": False,
            "has_attachments": False,
            "flag": "notFlagged",
            "preview": "Hi, attached is",
        }
    ]


@pytest.mark.asyncio
async def test_list_messages_unread_in_a_named_folder_is_escaped_and_filtered():
    connector, seen = make_connector(ok({"value": []}))
    await connector.list_messages(folder="a/../b", unread_only=True, limit=500)
    (request,) = seen
    assert request.url.raw_path.startswith(b"/v1.0/me/mailFolders/a%2F..%2Fb/messages?")
    assert request.url.params["$top"] == "50"
    assert request.url.params["$filter"].endswith("isRead eq false")


@pytest.mark.asyncio
async def test_list_messages_rejects_a_non_boolean_unread_flag_before_any_request():
    connector, seen = make_connector(ok({"value": []}))
    with pytest.raises(ConnectorError, match="unread_only"):
        await connector.list_messages(unread_only="yes")
    assert seen == []


@pytest.mark.asyncio
async def test_search_messages_quotes_the_search_value_and_skips_orderby():
    connector, seen = make_connector(ok({"value": [_MESSAGE]}))
    await connector.search_messages('from:ann "q3" \\x', limit=3)
    (request,) = seen
    assert request.url.raw_path.startswith(b"/v1.0/me/messages?")
    assert request.url.params["$search"] == '"from:ann \\"q3\\" \\\\x"'
    assert request.url.params["$top"] == "3"
    assert "$orderby" not in request.url.params


@pytest.mark.asyncio
async def test_search_messages_requires_a_query():
    connector, seen = make_connector(ok({"value": []}))
    with pytest.raises(ConnectorError, match="'query' is required"):
        await connector.search_messages("  ")
    assert seen == []


@pytest.mark.asyncio
async def test_get_message_asks_for_text_bodies_and_skips_attachments_when_none():
    message = {**_MESSAGE, "toRecipients": [{"emailAddress": {"address": "me@contoso.com"}}],
               "body": {"contentType": "text", "content": "Hello"}, "webLink": "https://outlook.office.com/x"}
    connector, seen = make_connector(ok(message))
    result = await connector.get_message("m/1")

    (request,) = seen
    assert request.url.raw_path.startswith(b"/v1.0/me/messages/m%2F1?")
    assert request.headers["Prefer"] == 'outlook.body-content-type="text"'
    assert "body" in request.url.params["$select"]
    assert result["body"] == "Hello"
    assert result["truncated"] is False and "hint" not in result
    assert result["to"] == ["me@contoso.com"]
    assert result["attachments"] == []
    assert "internetMessageHeaders" not in result


@pytest.mark.asyncio
async def test_get_message_truncates_long_bodies_and_lists_attachments():
    message = {**_MESSAGE, "hasAttachments": True, "body": {"content": "x" * 20_000}}
    attachments = {"value": [{"id": "a1", "name": "notes.txt", "contentType": "text/plain",
                              "size": 12, "isInline": False, "contentBytes": "c2VjcmV0"}]}

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/attachments"):
            return httpx.Response(200, json=attachments)
        return httpx.Response(200, json=message)

    connector, seen = make_connector(handler)
    result = await connector.get_message("m1")

    assert len(seen) == 2
    assert seen[1].url.raw_path.startswith(b"/v1.0/me/messages/m1/attachments?")
    assert "contentBytes" not in seen[1].url.params["$select"]
    assert result["truncated"] is True
    assert len(result["body"]) == 8000
    assert "web_link" in result["hint"]
    assert result["attachments"] == [
        {"id": "a1", "name": "notes.txt", "content_type": "text/plain", "size": 12, "is_inline": False}
    ]


def _attachment_handler(meta: dict[str, Any], raw: bytes = b"a,b\n1,2\n") -> Handler:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/$value"):
            return httpx.Response(200, content=raw)
        return httpx.Response(200, json=meta)

    return handler


@pytest.mark.asyncio
async def test_get_attachment_text_reads_metadata_then_raw_value():
    meta = {"@odata.type": "#microsoft.graph.fileAttachment", "id": "a1", "name": "data.csv",
            "contentType": "text/csv", "size": 8}
    connector, seen = make_connector(_attachment_handler(meta))
    result = await connector.get_attachment_text("m1", "a1")

    assert [r.url.path for r in seen] == [
        "/v1.0/me/messages/m1/attachments/a1",
        "/v1.0/me/messages/m1/attachments/a1/$value",
    ]
    assert "contentBytes" not in seen[0].url.params["$select"]
    assert result["text"] == "a,b\n1,2\n"
    assert result["truncated"] is False
    assert result["name"] == "data.csv"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("meta", "message"),
    [
        ({"name": "photo.png", "contentType": "image/png", "size": 5}, "not a text file"),
        ({"name": "big.txt", "contentType": "text/plain", "size": 50_000_000}, "too large"),
        ({"@odata.type": "#microsoft.graph.itemAttachment", "name": "fwd"}, "attached item"),
    ],
)
async def test_get_attachment_text_refuses_before_downloading(meta, message):
    connector, seen = make_connector(_attachment_handler(meta))
    with pytest.raises(ConnectorError, match=message):
        await connector.get_attachment_text("m1", "a1")
    assert len(seen) == 1


@pytest.mark.asyncio
async def test_get_attachment_text_refuses_binary_bytes_and_caps_text():
    meta = {"name": "x.txt", "contentType": "text/plain", "size": 10}
    connector, _ = make_connector(_attachment_handler(meta, raw=b"MZ\x00\x00binary"))
    with pytest.raises(ConnectorError, match="not a text file"):
        await connector.get_attachment_text("m1", "a1")

    connector, _ = make_connector(_attachment_handler(meta, raw=b"y" * 30_000))
    result = await connector.get_attachment_text("m1", "a1")
    assert result["truncated"] is True and len(result["text"]) == 20_000 and "hint" in result


@pytest.mark.asyncio
async def test_list_folders_shapes_counts():
    folder = {"id": "f1", "displayName": "Inbox", "unreadItemCount": 3, "totalItemCount": "9",
              "childFolderCount": 0, "wellKnownName": "inbox"}
    connector, seen = make_connector(ok({"value": [folder]}))
    assert await connector.list_folders(limit=2) == [
        {"id": "f1", "name": "Inbox", "unread": 3, "total": None, "child_folders": 0}
    ]
    assert seen[0].url.path == "/v1.0/me/mailFolders"
    assert seen[0].url.params["$top"] == "2"


# ---------------------------------------------------------------------------
# Mail: writes (confirmation first, then the exact request)
# ---------------------------------------------------------------------------

_MAIL_WRITES = [
    ("send_mail", lambda c, **k: c.send_mail(["bob@contoso.com"], "Hi", "Body", **k)),
    ("reply", lambda c, **k: c.reply("m1", "Thanks", **k)),
    ("forward", lambda c, **k: c.forward("m1", ["bob@contoso.com"], **k)),
    ("create_draft", lambda c, **k: c.create_draft("Hi", "Body", **k)),
    ("move_message", lambda c, **k: c.move_message("m1", "archive", **k)),
    ("flag_message", lambda c, **k: c.flag_message("m1", **k)),
    ("delete_message", lambda c, **k: c.delete_message("m1", **k)),
]


@pytest.mark.asyncio
@pytest.mark.parametrize(("action", "call"), _MAIL_WRITES)
async def test_mail_writes_require_confirmation_before_any_request(action, call):
    connector, seen = make_connector(ok({"id": "x"}))
    with pytest.raises(UserConfirmationRequired) as exc:
        await call(connector)
    assert exc.value.action == action
    assert exc.value.details
    assert seen == []


@pytest.mark.asyncio
@pytest.mark.parametrize(("action", "call"), _MAIL_WRITES)
async def test_mail_writes_run_once_confirmed(action, call):
    connector, seen = make_connector(ok({"id": "new-id", "flag": {"flagStatus": "flagged"}}))
    result = await call(connector, user_confirmed=True)
    assert len(seen) == 1
    assert isinstance(result, dict)


@pytest.mark.asyncio
async def test_send_mail_posts_a_text_message_and_names_recipients_in_the_prompt():
    connector, seen = make_connector(lambda r: httpx.Response(202))
    with pytest.raises(UserConfirmationRequired) as exc:
        await connector.send_mail("bob@contoso.com; eve@contoso.com", "Plan", "See you", cc=["c@contoso.com"])
    assert "bob@contoso.com, eve@contoso.com" in exc.value.details
    assert "cc c@contoso.com" in exc.value.details and "'Plan'" in exc.value.details

    result = await connector.send_mail(
        ["bob@contoso.com"], "Plan", "See you", bcc=["hidden@contoso.com"], user_confirmed=True
    )
    (request,) = seen
    assert request.method == "POST"
    assert request.url.raw_path == b"/v1.0/me/sendMail"
    assert body_of(request) == {
        "message": {
            "subject": "Plan",
            "body": {"contentType": "Text", "content": "See you"},
            "toRecipients": [{"emailAddress": {"address": "bob@contoso.com"}}],
            "bccRecipients": [{"emailAddress": {"address": "hidden@contoso.com"}}],
        },
        "saveToSentItems": True,
    }
    assert result["sent"] is True and result["to"] == ["bob@contoso.com"]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("kwargs", "message"),
    [
        ({"to": [], "subject": "s", "body": "b"}, "at least one email"),
        ({"to": ["not-an-email"], "subject": "s", "body": "b"}, "invalid email"),
        ({"to": [7], "subject": "s", "body": "b"}, "only email address strings"),
        ({"to": ["a@b.co"], "subject": "", "body": "b"}, "'subject' is required"),
        ({"to": ["a@b.co"], "subject": "s", "body": None}, "'body' is required"),
        ({"to": ["a@b.co"] , "subject": "s", "body": "b", "cc": 5}, "'cc' must be a list"),
    ],
)
async def test_send_mail_validates_arguments_before_anything_else(kwargs, message):
    connector, seen = make_connector(ok({}))
    with pytest.raises(ConnectorError, match=message):
        await connector.send_mail(**kwargs)
    assert seen == []


@pytest.mark.asyncio
async def test_reply_all_forward_move_flag_delete_requests():
    connector, seen = make_connector(lambda r: httpx.Response(202 if r.method == "POST" else 200, json={"id": "n"}))
    await connector.reply("m/1", "ok", reply_all=True, user_confirmed=True)
    await connector.forward("m1", "bob@contoso.com", comment="fyi", user_confirmed=True)
    await connector.move_message("m1", "archive", user_confirmed=True)
    await connector.flag_message("m1", status="complete", user_confirmed=True)
    await connector.delete_message("m1", user_confirmed=True)

    assert [(r.method, r.url.raw_path) for r in seen] == [
        ("POST", b"/v1.0/me/messages/m%2F1/replyAll"),
        ("POST", b"/v1.0/me/messages/m1/forward"),
        ("POST", b"/v1.0/me/messages/m1/move"),
        ("PATCH", b"/v1.0/me/messages/m1"),
        ("DELETE", b"/v1.0/me/messages/m1"),
    ]
    assert body_of(seen[0]) == {"comment": "ok"}
    assert body_of(seen[1]) == {
        "toRecipients": [{"emailAddress": {"address": "bob@contoso.com"}}],
        "comment": "fyi",
    }
    assert body_of(seen[2]) == {"destinationId": "archive"}
    assert body_of(seen[3]) == {"flag": {"flagStatus": "complete"}}


@pytest.mark.asyncio
async def test_create_draft_posts_to_messages_and_returns_the_draft_id():
    connector, seen = make_connector(ok({"id": "d1", "subject": "Hi", "webLink": "https://o/x"}, 201))
    result = await connector.create_draft("Hi", "Body", to=["bob@contoso.com"], user_confirmed=True)
    assert seen[0].method == "POST" and seen[0].url.raw_path == b"/v1.0/me/messages"
    assert body_of(seen[0])["toRecipients"] == [{"emailAddress": {"address": "bob@contoso.com"}}]
    assert result == {"id": "d1", "subject": "Hi", "web_link": "https://o/x", "draft": True}


@pytest.mark.asyncio
async def test_flag_message_rejects_unknown_status():
    connector, seen = make_connector(ok({}))
    with pytest.raises(ConnectorError, match="status"):
        await connector.flag_message("m1", status="urgent", user_confirmed=True)
    assert seen == []


# ---------------------------------------------------------------------------
# Failure matrix (shared by every action through _request)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_401_is_an_authentication_error_that_says_reconnect():
    connector, _ = make_connector(ok({"error": {"code": "InvalidAuthenticationToken", "message": TOKEN}}, 401))
    with pytest.raises(AuthenticationError) as exc:
        await connector.list_messages()
    text = str(exc.value)
    assert "HTTP 401 from Microsoft 365 (InvalidAuthenticationToken)" in text
    assert "Reconnect Microsoft 365" in text
    assert TOKEN not in text


@pytest.mark.asyncio
async def test_403_missing_scope_names_the_vendor_code_only():
    connector, _ = make_connector(
        ok({"error": {"code": "ErrorAccessDenied", "message": f"Access is denied for {TOKEN}"}}, 403)
    )
    with pytest.raises(AuthenticationError) as exc:
        await connector.send_mail(["a@b.co"], "s", "b", user_confirmed=True)
    assert "ErrorAccessDenied" in str(exc.value)
    assert "missing permission or scope" in str(exc.value)
    assert TOKEN not in str(exc.value) and "Access is denied" not in str(exc.value)


@pytest.mark.asyncio
async def test_404_and_409_and_500_are_connector_errors():
    connector, _ = make_connector(ok({"error": {"code": "ErrorItemNotFound"}}, 404))
    with pytest.raises(ConnectorError, match="ErrorItemNotFound.*not found"):
        await connector.get_message("gone")

    connector, _ = make_connector(ok({"error": {"code": "nameAlreadyExists"}}, 409))
    with pytest.raises(ConnectorError, match="conflict"):
        await connector.create_folder("Reports", user_confirmed=True)

    connector, seen = make_connector(ok({"error": {"code": "generalException"}}, 500))
    with pytest.raises(ConnectorError, match="provider error"):
        await connector.list_messages()
    assert len(seen) == 1


@pytest.mark.asyncio
async def test_429_with_short_retry_after_is_retried_once():
    responses = [httpx.Response(429, headers={"Retry-After": "2"}), httpx.Response(200, json={"value": []})]
    waits: list[float] = []
    connector, seen = make_connector(lambda r: responses.pop(0))

    async def record(seconds: float) -> None:
        waits.append(seconds)

    connector._sleep = record
    assert await connector.list_messages() == []
    assert len(seen) == 2 and waits == [2.0]


@pytest.mark.asyncio
async def test_429_with_long_retry_after_is_not_retried():
    connector, seen = make_connector(lambda r: httpx.Response(429, headers={"Retry-After": "120"}))
    with pytest.raises(RateLimitExceededError, match="Retry after 120 s"):
        await connector.list_messages()
    assert len(seen) == 1


@pytest.mark.asyncio
async def test_timeout_is_a_clean_connector_error():
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ReadTimeout("timed out", request=request)

    connector, _ = make_connector(handler)
    with pytest.raises(ConnectorError, match="timed out"):
        await connector.search_messages("x")


@pytest.mark.asyncio
async def test_malformed_json_and_wrong_shapes_are_clean_errors():
    connector, _ = make_connector(lambda r: httpx.Response(200, content=b"<html>oops"))
    with pytest.raises(ConnectorError, match="Malformed response from Microsoft 365"):
        await connector.list_messages()
    for payload in ([1, 2], {"value": "nope"}, {"items": []}):
        connector, _ = make_connector(ok(payload))
        with pytest.raises(ConnectorError, match="Malformed response"):
            await connector.list_messages()
    connector, _ = make_connector(ok(["not", "an", "object"]))
    with pytest.raises(ConnectorError, match="Malformed response"):
        await connector.get_message("m1")


@pytest.mark.asyncio
async def test_missing_and_hostile_fields_do_not_crash():
    hostile = {
        "value": [
            {},
            "a string item",
            None,
            {
                "id": 12,
                "subject": "S" * 1_000_000,
                "from": "not an object",
                "isRead": "yes",
                "flag": [],
                "bodyPreview": {"x": 1},
                "hasAttachments": "true",
            },
        ]
    }
    connector, _ = make_connector(ok(hostile))
    result = await connector.list_messages()
    assert len(result) == 2
    assert result[0]["id"] is None and result[0]["preview"] == ""
    assert result[1]["id"] is None
    assert len(result[1]["subject"]) == 1000
    assert result[1]["from"] is None and result[1]["is_read"] is None
    assert result[1]["has_attachments"] is False and result[1]["flag"] is None

    connector, _ = make_connector(ok({"id": "m1", "body": "not an object", "toRecipients": {"a": 1}}))
    message = await connector.get_message("m1")
    assert message["body"] == "" and message["to"] == []


@pytest.mark.asyncio
async def test_no_token_in_any_result():
    connector, _ = make_connector(ok({"value": [_MESSAGE]}))
    result = await connector._dispatch("list_messages", {})
    assert TOKEN not in json.dumps(result)


# ---------------------------------------------------------------------------
# @odata.nextLink pagination
# ---------------------------------------------------------------------------


def _paged(pages: dict[str, dict[str, Any]]) -> Handler:
    """Serve page payloads keyed by the $skiptoken (first page: no token)."""

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=pages[request.url.params.get("$skiptoken", "")])

    return handler


def _msg(i: int) -> dict[str, Any]:
    return {"id": f"m{i}", "subject": f"s{i}"}


@pytest.mark.asyncio
async def test_next_link_on_the_same_collection_is_followed_up_to_the_limit():
    link = f"{GRAPH}/mailFolders/inbox/messages?$skiptoken=p2"
    connector, seen = make_connector(
        _paged({"": {"value": [_msg(1), _msg(2)], "@odata.nextLink": link},
                "p2": {"value": [_msg(3), _msg(4)], "@odata.nextLink": f"{GRAPH}/mailFolders/inbox/messages?$skiptoken=p3"}})
    )
    result = await connector.list_messages(limit=3)
    assert [m["id"] for m in result] == ["m1", "m2", "m3"]
    assert len(seen) == 2
    assert str(seen[1].url) == link
    assert seen[1].headers["Authorization"] == f"Bearer {TOKEN}"


@pytest.mark.asyncio
async def test_pagination_ending_early_stops():
    connector, seen = make_connector(_paged({"": {"value": [_msg(1)]}}))
    assert len(await connector.list_messages(limit=20)) == 1
    assert len(seen) == 1


@pytest.mark.asyncio
async def test_a_repeated_next_link_stops_paging():
    link = f"{GRAPH}/mailFolders/inbox/messages?$skiptoken=loop"
    connector, seen = make_connector(
        _paged({"": {"value": [_msg(1)], "@odata.nextLink": link},
                "loop": {"value": [_msg(2)], "@odata.nextLink": link}})
    )
    result = await connector.list_messages(limit=50)
    assert [m["id"] for m in result] == ["m1", "m2"]
    assert len(seen) == 2


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "link",
    [
        "https://evil.example.com/v1.0/me/mailFolders/inbox/messages?$skiptoken=x",
        "http://graph.microsoft.com/v1.0/me/mailFolders/inbox/messages?$skiptoken=x",
        "https://graph.microsoft.com:8443/v1.0/me/mailFolders/inbox/messages?$skiptoken=x",
        "https://user:pw@graph.microsoft.com/v1.0/me/mailFolders/inbox/messages?$skiptoken=x",
        "https://graph.microsoft.com/v1.0/users/ceo@contoso.com/messages?$skiptoken=x",
        "https://graph.microsoft.com/v1.0/me/drive/root/children?$skiptoken=x",
        "https://graph.microsoft.com/v1.0/me/mailFolders/inbox/messages/../../../users?$skiptoken=x",
        "/v1.0/me/mailFolders/inbox/messages?$skiptoken=x",
        12345,
        {"url": "x"},
    ],
)
async def test_a_next_link_off_the_collection_is_never_followed(link):
    connector, seen = make_connector(ok({"value": [_msg(1)], "@odata.nextLink": link}))
    result = await connector.list_messages(limit=10)
    assert [m["id"] for m in result] == ["m1"]
    assert len(seen) == 1


# ---------------------------------------------------------------------------
# Network policy
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "url",
    [
        f"{GRAPH}/messages",
        f"{GRAPH}/drive/root/search(q='x')",
        "https://login.microsoftonline.com/common/oauth2/v2.0/token",
        "https://login.microsoftonline.com/common/oauth2/v2.0/devicecode",
    ],
)
async def test_declared_hosts_and_paths_are_allowed(no_dns, url):
    connector = MicrosoftConnector()
    connector.set_network_policy("microsoft")
    await connector._enforce_network_policy(
        httpx.Request("GET", url, headers={"Authorization": "Bearer x"})
    )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "url",
    [
        "https://evil.example.com/v1.0/me/messages",
        "https://graph.microsoft.com/v1.0/users/ceo@contoso.com/messages",
        "https://graph.microsoft.com/beta/me/messages",
        "https://login.microsoftonline.com/common/oauth2/v2.0/authorize",
        "https://login.microsoftonline.com/contoso/oauth2/v2.0/token",
        "http://graph.microsoft.com/v1.0/me/messages",
        "https://graph.microsoft.com:444/v1.0/me/messages",
        "https://graph.microsoft.com/v1.0/me/%2e%2e/%2e%2e/users",
        "https://graph.microsoft.com/v1.0/me/messages/../../users",
    ],
)
async def test_off_list_hosts_paths_schemes_and_dot_segments_are_refused(no_dns, url):
    connector = MicrosoftConnector()
    connector.set_network_policy("microsoft")
    request = httpx.Request("GET", "https://graph.microsoft.com/v1.0/me/x")
    # Build from the raw string so httpx does not normalise the dot segments.
    request.url = httpx.URL(url)
    with pytest.raises(ConnectorError, match="blocked by network policy"):
        await connector._enforce_network_policy(request)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "url",
    [
        "https://contoso-my.sharepoint.com/personal/ann_contoso_com/_layouts/15/download.aspx?tempauth=x",
        "https://b0mpua-by3301.files.1drv.com/y23vmag",
        "https://public.bn1304.files.1drv.com/y4mabc",
        "https://my.microsoftpersonalcontent.com/personal/abc/_layouts/15/download.aspx?tempauth=x",
    ],
)
async def test_download_hosts_only_for_credential_free_gets(no_dns, url):
    connector = MicrosoftConnector()
    connector.set_network_policy("microsoft")
    await connector._enforce_network_policy(httpx.Request("GET", url))
    with pytest.raises(ConnectorError, match="without credentials"):
        await connector._enforce_network_policy(
            httpx.Request("GET", url, headers={"Authorization": f"Bearer {TOKEN}"})
        )
    with pytest.raises(ConnectorError, match="without credentials"):
        await connector._enforce_network_policy(httpx.Request("POST", url))


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "url",
    [
        "https://contoso.sharepoint.com/personal/x/file",
        "https://evil-my.sharepoint.com.attacker.test/personal/x",
        "https://files.1drv.com.attacker.test/x",
        "https://1drv.com/x",
        "https://contoso-my.sharepoint.com/sites/secret/file",
        "https://other.microsoftpersonalcontent.com/personal/x",
    ],
)
async def test_lookalike_download_hosts_are_refused(no_dns, url):
    connector = MicrosoftConnector()
    connector.set_network_policy("microsoft")
    with pytest.raises(ConnectorError, match="blocked by network policy"):
        await connector._enforce_network_policy(httpx.Request("GET", url))


@pytest.mark.asyncio
async def test_connector_without_a_policy_refuses():
    connector = MicrosoftConnector()
    with pytest.raises(ConnectorError, match="no network policy"):
        await connector._enforce_network_policy(httpx.Request("GET", f"{GRAPH}/messages"))


@pytest.mark.asyncio
async def test_hooked_next_link_is_rechecked_by_the_policy(no_dns):
    """A next link that passes the collection check still goes through the
    policy hook on the wire, with the token (graph host only)."""
    link = f"{GRAPH}/mailFolders/inbox/messages?$skiptoken=p2"
    connector, seen = make_connector(
        _paged({"": {"value": [_msg(1)], "@odata.nextLink": link}, "p2": {"value": [_msg(2)]}}),
        hooked=True,
    )
    assert len(await connector.list_messages()) == 2
    assert [r.url.host for r in seen] == ["graph.microsoft.com", "graph.microsoft.com"]
    await connector.close()
