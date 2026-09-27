"""Behaviour, failure and security tests for the Slack workspace tools connector.

Why it exists: pins every Slack action's request (method, host, raw path,
query or body) and shaped result, Slack's ``{"ok": false}`` error mapping, the
single unfurl-off choke point, confirmation before any write, the network
allowlist, and that no token ever appears in a result or an error.

It drives ``services/connectors/slack.py`` (and its ``slack_api`` mixins)
through ``httpx.MockTransport`` only: no network, no real credentials.
"""

from __future__ import annotations

import json
import time
from datetime import datetime, timezone
from typing import Any, Callable
from urllib.parse import parse_qs, unquote

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
from services.connectors.registry import validate_registry
from services.connectors.slack import (
    ACTIONS,
    DEFINITION,
    MANIFEST_PATH,
    MANIFEST_URL,
    SlackConnector,
)

BOT = "xoxb-test-token"
USER = "xoxp-test-token"
APP = "xapp-test-token"
TOKENS = (BOT, USER, APP)
UPLOAD_URL = "https://files.slack.com/upload/v1/ABCtest"

Handler = Callable[[httpx.Request], httpx.Response]


def ok(**payload: Any) -> httpx.Response:
    return httpx.Response(200, json={"ok": True, **payload})


def fail(error: str, **extra: Any) -> httpx.Response:
    return httpx.Response(200, json={"ok": False, "error": error, **extra})


def _connector(
    handler: Handler, *, user_token: bool = True
) -> tuple[SlackConnector, list[httpx.Request]]:
    """An authenticated connector whose HTTP goes to *handler*; records requests."""
    seen: list[httpx.Request] = []

    def recording(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return handler(request)

    connector = SlackConnector()
    credentials = {"bot_token": BOT, "app_token": APP}
    if user_token:
        credentials["user_token"] = USER
    connector._store_tokens(credentials)
    connector._authenticated = True
    connector._http_client = httpx.AsyncClient(transport=httpx.MockTransport(recording))

    async def no_sleep(_seconds: float) -> None:
        return None

    connector._sleep = no_sleep
    return connector, seen


def _json(request: httpx.Request) -> dict[str, Any]:
    assert request.headers["Content-Type"] == "application/json; charset=utf-8"
    return json.loads(request.content)


def _form(request: httpx.Request) -> dict[str, str]:
    assert request.headers["Content-Type"].startswith("application/x-www-form-urlencoded")
    return {k: v[0] for k, v in parse_qs(request.content.decode()).items()}


def _no_token(value: Any) -> None:
    text = json.dumps(value, default=str) if not isinstance(value, str) else value
    for token in TOKENS:
        assert token not in text


# ---------------------------------------------------------------------------
# Definition and manifest
# ---------------------------------------------------------------------------


def test_definition_passes_registry_validation():
    assert validate_registry([DEFINITION]) == []


def test_action_names_categories_and_confirm_flags_match_the_spec():
    by_name = {spec.action: spec for spec in ACTIONS}
    reads = {
        "list_channels",
        "get_history",
        "get_thread",
        "search_messages",
        "list_users",
        "get_user",
        "get_file_info",
    }
    writes = {
        "post_message",
        "reply_in_thread",
        "add_reaction",
        "upload_file",
        "set_status",
        "create_channel",
        "invite_to_channel",
        "schedule_message",
    }
    deletes = {"delete_message", "archive_channel"}
    assert set(by_name) == reads | writes | deletes
    assert {n for n, s in by_name.items() if s.category == ActionCategory.READ} == reads
    assert {n for n, s in by_name.items() if s.category == ActionCategory.WRITE} == writes
    assert {n for n, s in by_name.items() if s.category == ActionCategory.DELETE} == deletes
    assert {n for n, s in by_name.items() if s.always_confirm} == {
        "post_message",
        "reply_in_thread",
        "upload_file",
        "schedule_message",
        "delete_message",
        "archive_channel",
    }
    starters = {n for n, s in by_name.items() if s.starter}
    assert starters <= reads and 2 <= len(starters) <= 4
    assert SlackConnector._ACTIONS == frozenset(by_name)


def test_definition_auth_network_and_presentation():
    assert DEFINITION.key == "slack" and DEFINITION.label == "Slack"
    assert DEFINITION.icon == "slack"
    assert DEFINITION.auth.methods == ("token",)
    assert DEFINITION.auth.required_credentials == ("bot_token",)
    assert DEFINITION.auth.optional_credentials == ("app_token", "user_token")
    net = DEFINITION.network
    assert net.https_only is True
    assert dict(net.hosts) == {"slack.com": ("/api/",), "files.slack.com": ("/upload/v1/",)}
    assert net.ws_hosts == ("wss-primary.slack.com", "wss-backup.slack.com", "wss.slack.com")


def test_docs_url_is_the_create_app_link_carrying_the_manifest():
    prefix = "https://api.slack.com/apps?new_app=1&manifest_json="
    assert DEFINITION.docs_url == MANIFEST_URL and MANIFEST_URL.startswith(prefix)
    encoded = MANIFEST_URL[len(prefix) :]
    assert "&" not in encoded and " " not in encoded
    manifest = json.loads(unquote(encoded))
    assert manifest == json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))


def test_manifest_requests_exactly_the_needed_scopes_and_socket_mode():
    manifest = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
    scopes = manifest["oauth_config"]["scopes"]
    assert set(scopes["bot"]) == {
        "channels:read",
        "groups:read",
        "channels:history",
        "groups:history",
        "chat:write",
        "reactions:write",
        "users:read",
        "files:read",
        "files:write",
        "channels:manage",
        "groups:write",
        "im:read",
        "im:history",
        "im:write",
    }
    assert set(scopes["user"]) == {"search:read", "users.profile:write"}
    settings = manifest["settings"]
    assert settings["socket_mode_enabled"] is True
    assert settings["event_subscriptions"]["bot_events"] == ["message.im"]
    assert settings["interactivity"]["is_enabled"] is True
    assert manifest["features"]["app_home"]["messages_tab_enabled"] is True
    assert manifest["features"]["app_home"]["messages_tab_read_only_enabled"] is False


def test_validate_credentials_checks_prefixes_without_echoing_values():
    good = {"bot_token": BOT, "app_token": APP, "user_token": USER}
    assert SlackConnector.validate_credentials(good) == []
    assert SlackConnector.validate_credentials({"bot_token": BOT}) == []
    swapped = {"bot_token": USER, "app_token": BOT, "user_token": APP}
    problems = SlackConnector.validate_credentials(swapped)
    assert problems == [
        "bot_token must start with xoxb-",
        "app_token must start with xapp-",
        "user_token must start with xoxp-",
    ]
    _no_token(problems)
    assert SlackConnector.validate_credentials({"bot_token": 12}) == [
        "bot_token must start with xoxb-"
    ]


@pytest.mark.asyncio
async def test_authenticate_needs_a_bot_token_and_makes_no_request():
    connector = SlackConnector()
    with pytest.raises(AuthenticationError):
        await connector.authenticate({"user_token": USER})
    assert await connector.authenticate({"bot_token": f"  {BOT}  "}) is True
    assert connector._auth_headers() == {"Authorization": f"Bearer {BOT}"}


# ---------------------------------------------------------------------------
# READ actions
# ---------------------------------------------------------------------------


def _channel(cid: str, name: str, **extra: Any) -> dict[str, Any]:
    return {
        "id": cid,
        "name": name,
        "is_private": False,
        "is_archived": False,
        "is_member": True,
        "num_members": 4,
        "topic": {"value": "Topic"},
        "purpose": {"value": ""},
        "created": 1,
        "shared_team_ids": ["T1"],
        **extra,
    }


@pytest.mark.asyncio
async def test_list_channels_request_and_shape():
    connector, seen = _connector(lambda r: ok(channels=[_channel("C1", "general")]))
    result = await connector.list_channels()

    assert result == [
        {
            "id": "C1",
            "name": "general",
            "is_private": False,
            "is_archived": False,
            "is_member": True,
            "num_members": 4,
            "topic": "Topic",
        }
    ]
    (request,) = seen
    assert request.method == "GET"
    assert request.url.host == "slack.com"
    assert request.url.raw_path == (
        b"/api/conversations.list?types=public_channel%2Cprivate_channel"
        b"&exclude_archived=true&limit=200"
    )
    assert request.headers["Authorization"] == f"Bearer {BOT}"


@pytest.mark.asyncio
async def test_list_channels_filters_by_name_across_pages_until_the_limit():
    pages = {
        None: ok(
            channels=[_channel("C1", "general"), _channel("C2", "eng-team")],
            response_metadata={"next_cursor": "cur2"},
        ),
        "cur2": ok(
            channels=[_channel("C3", "random"), _channel("C4", "ENG-ops")],
            response_metadata={"next_cursor": "cur3"},
        ),
        "cur3": ok(channels=[_channel("C5", "eng-x")]),
    }
    connector, seen = _connector(lambda r: pages[r.url.params.get("cursor")])
    result = await connector.list_channels(query="ENG", types="public", limit=2)

    assert [c["id"] for c in result] == ["C2", "C4"]
    assert len(seen) == 2  # stopped once two matches were collected
    assert seen[0].url.params["types"] == "public_channel"
    assert seen[1].url.params["cursor"] == "cur2"


@pytest.mark.asyncio
async def test_list_channels_rejects_an_unknown_type_before_any_request():
    connector, seen = _connector(lambda r: ok())
    with pytest.raises(ConnectorError, match="types must be one of"):
        await connector.list_channels(types="dm")
    assert seen == []


@pytest.mark.asyncio
async def test_get_history_request_shape_and_truncation_without_user_lookups():
    long_text = "x" * 5000
    messages = [
        {
            "ts": "1712345678.000200",
            "user": "U1",
            "text": "hi",
            "type": "message",
            "blocks": [{"type": "rich_text"}],
            "reply_count": 2,
            "thread_ts": "1712345678.000200",
            "files": [{"id": "F1", "name": "a.txt", "url_private": "https://files.slack.com/x"}],
        },
        {"ts": "1712345677.000100", "user": "U2", "text": long_text},
    ]
    connector, seen = _connector(lambda r: ok(messages=messages, has_more=False))
    result = await connector.get_history("C0123ABCD", limit=5, oldest="1712000000.000000")

    (request,) = seen  # one call: user ids are returned, never resolved per message
    assert request.method == "GET"
    assert request.url.raw_path == (
        b"/api/conversations.history?channel=C0123ABCD&limit=5&oldest=1712000000.000000"
    )
    assert result[0] == {
        "ts": "1712345678.000200",
        "user": "U1",
        "thread_ts": "1712345678.000200",
        "reply_count": 2,
        "text": "hi",
        "files": [{"id": "F1", "name": "a.txt"}],
    }
    assert result[1]["truncated"] is True
    assert len(result[1]["text"]) == 2000
    assert "get_thread" in result[1]["hint"]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "kwargs, fragment",
    [
        ({"channel": "general"}, "channel must be a Slack id"),
        ({"channel": "#general"}, "channel must be a Slack id"),
        ({"channel": "C1/../x"}, "channel must be a Slack id"),
        ({"channel": 5}, "channel must be a Slack id"),
        ({"channel": "C0123ABCD", "latest": "yesterday"}, "latest must be a Slack id"),
    ],
)
async def test_get_history_validates_arguments_before_any_request(kwargs, fragment):
    connector, seen = _connector(lambda r: ok())
    with pytest.raises(ConnectorError, match=fragment):
        await connector.get_history(**kwargs)
    assert seen == []


@pytest.mark.asyncio
async def test_get_thread_request_and_longer_text_cap():
    messages = [{"ts": "1.1", "user": "U1", "text": "p" * 9000}, {"ts": "1.2", "text": "r"}]
    connector, seen = _connector(lambda r: ok(messages=messages))
    result = await connector.get_thread("C0123ABCD", "1712345678.000200")

    assert seen[0].url.raw_path == (
        b"/api/conversations.replies?channel=C0123ABCD&ts=1712345678.000200&limit=10"
    )
    assert len(result[0]["text"]) == 8000 and result[0]["truncated"] is True
    assert result[1] == {"ts": "1.2", "text": "r"}


@pytest.mark.asyncio
async def test_search_messages_uses_the_user_token():
    match = {
        "iid": "x",
        "ts": "1.1",
        "user": "U1",
        "username": "ana",
        "text": "budget",
        "permalink": "https://acme.slack.com/archives/C1/p11",
        "channel": {"id": "C1", "name": "finance", "is_private": False},
    }
    connector, seen = _connector(
        lambda r: ok(messages={"matches": [match], "total": 1, "pagination": {}})
    )
    result = await connector.search_messages("budget in:#finance", sort="timestamp", limit=3)

    (request,) = seen
    assert request.method == "GET"
    assert request.headers["Authorization"] == f"Bearer {USER}"
    assert request.url.path == "/api/search.messages"
    assert dict(request.url.params) == {
        "query": "budget in:#finance",
        "count": "3",
        "sort": "timestamp",
        "sort_dir": "desc",
        "highlight": "false",
    }
    assert result == [
        {
            "ts": "1.1",
            "user": "U1",
            "text": "budget",
            "channel": {"id": "C1", "name": "finance"},
            "username": "ana",
            "permalink": "https://acme.slack.com/archives/C1/p11",
        }
    ]


@pytest.mark.asyncio
async def test_search_messages_without_a_user_token_fails_clearly_before_any_request():
    connector, seen = _connector(lambda r: ok(), user_token=False)
    with pytest.raises(ConnectorError, match="user token"):
        await connector.search_messages("budget")
    assert seen == []


@pytest.mark.asyncio
async def test_search_messages_rejects_bad_sort_and_empty_query():
    connector, seen = _connector(lambda r: ok())
    with pytest.raises(ConnectorError):
        await connector.search_messages("x", sort="relevance")
    with pytest.raises(ConnectorError):
        await connector.search_messages("   ")
    assert seen == []


def _member(uid: str, name: str, **extra: Any) -> dict[str, Any]:
    return {
        "id": uid,
        "name": name,
        "real_name": name.title(),
        "is_bot": False,
        "deleted": False,
        "tz": "Europe/London",
        "profile": {
            "display_name": name,
            "title": "Eng",
            "email": "hidden@example.com",
            "image_512": "https://x",
        },
        **extra,
    }


@pytest.mark.asyncio
async def test_list_users_request_filter_and_shape():
    members = [
        _member("U1", "ana"),
        _member("U2", "bob"),
        _member("U3", "anabel", deleted=True),
    ]
    connector, seen = _connector(lambda r: ok(members=members))
    result = await connector.list_users(query="Ana")

    assert seen[0].url.raw_path == b"/api/users.list?limit=200"
    assert result == [
        {
            "id": "U1",
            "name": "ana",
            "real_name": "Ana",
            "is_bot": False,
            "deleted": False,
            "tz": "Europe/London",
            "display_name": "ana",
            "title": "Eng",
        }
    ]


@pytest.mark.asyncio
async def test_get_user_request_and_shape():
    connector, seen = _connector(lambda r: ok(user=_member("U1", "ana")))
    result = await connector.get_user("U1")
    assert seen[0].url.raw_path == b"/api/users.info?user=U1"
    assert result["id"] == "U1" and "email" not in result


@pytest.mark.asyncio
async def test_get_file_info_request_shape_and_preview_cap():
    file = {
        "id": "F0123ABCD",
        "name": "notes.md",
        "title": "Notes",
        "mimetype": "text/markdown",
        "filetype": "markdown",
        "size": 12,
        "user": "U1",
        "created": 1,
        "is_public": True,
        "permalink": "https://acme.slack.com/files/U1/F0123ABCD",
        "url_private": "https://files.slack.com/files-pri/x",
        "channels": ["C1"],
        "groups": ["G1"],
        "ims": [],
        "preview": "y" * 3000,
    }
    connector, seen = _connector(lambda r: ok(file=file, comments=[]))
    result = await connector.get_file_info("F0123ABCD")

    assert seen[0].url.raw_path == b"/api/files.info?file=F0123ABCD&count=1"
    assert result["shared_in"] == ["C1", "G1"]
    assert "url_private" not in result
    assert len(result["preview"]) == 2000 and result["truncated"] is True


@pytest.mark.asyncio
async def test_get_file_info_rejects_a_bad_id_before_any_request():
    connector, seen = _connector(lambda r: ok())
    with pytest.raises(ConnectorError, match="file_id"):
        await connector.get_file_info("../F1")
    assert seen == []


# ---------------------------------------------------------------------------
# WRITE and DELETE actions
# ---------------------------------------------------------------------------

_FUTURE = int(time.time()) + 3600

WRITE_CALLS: dict[str, Callable[..., Any]] = {
    "post_message": lambda c, **k: c.post_message("C0123ABCD", "hello", **k),
    "reply_in_thread": lambda c, **k: c.reply_in_thread("C0123ABCD", "1.2", "hi", **k),
    "add_reaction": lambda c, **k: c.add_reaction("C0123ABCD", "1.2", ":thumbsup:", **k),
    "upload_file": lambda c, **k: c.upload_file("C0123ABCD", "notes.md", "# hi", **k),
    "set_status": lambda c, **k: c.set_status("Lunch", emoji=":taco:", **k),
    "create_channel": lambda c, **k: c.create_channel("eng-ops", **k),
    "invite_to_channel": lambda c, **k: c.invite_to_channel("C0123ABCD", ["U1", "U2"], **k),
    "schedule_message": lambda c, **k: c.schedule_message("C0123ABCD", "later", _FUTURE, **k),
    "delete_message": lambda c, **k: c.delete_message("C0123ABCD", "1.2", **k),
    "archive_channel": lambda c, **k: c.archive_channel("C0123ABCD", **k),
}


def test_every_non_read_action_is_covered():
    assert set(WRITE_CALLS) == {s.action for s in ACTIONS if s.category != ActionCategory.READ}


@pytest.mark.asyncio
@pytest.mark.parametrize("action", sorted(WRITE_CALLS))
async def test_writes_require_confirmation_before_any_request(action):
    connector, seen = _connector(lambda r: ok())
    with pytest.raises(UserConfirmationRequired) as exc:
        await WRITE_CALLS[action](connector)
    assert exc.value.action == action
    target = {"set_status": "Lunch", "create_channel": "#eng-ops"}.get(action, "C0123ABCD")
    assert target in exc.value.details
    assert seen == []


def _utc(epoch_s: int) -> str:
    return f"{datetime.fromtimestamp(epoch_s, timezone.utc):%Y-%m-%d %H:%M} UTC"


@pytest.mark.asyncio
async def test_schedule_message_approval_text_shows_the_time_in_utc():
    connector, seen = _connector(lambda r: ok())
    with pytest.raises(UserConfirmationRequired) as exc:
        await WRITE_CALLS["schedule_message"](connector)
    assert f"at {_utc(_FUTURE)} (unix {_FUTURE})" in exc.value.details
    assert seen == []


@pytest.mark.asyncio
async def test_set_status_approval_text_names_the_expiry():
    connector, seen = _connector(lambda r: ok())
    before = int(time.time())
    with pytest.raises(UserConfirmationRequired) as exc:
        await connector.set_status("Lunch", emoji="taco", expires_in_minutes=90)
    after = int(time.time())
    labels = {f"until {_utc(t + 90 * 60)}." for t in range(before, after + 1)}
    assert any(exc.value.details.endswith(label) for label in labels), exc.value.details
    with pytest.raises(UserConfirmationRequired) as exc:
        await connector.set_status("Lunch")
    assert exc.value.details.endswith("with no expiry.")
    assert seen == []


def _write_handler(request: httpx.Request) -> httpx.Response:
    if request.url.host == "files.slack.com":
        return httpx.Response(200, text="OK - 4")
    method = request.url.path.rsplit("/", 1)[-1]
    replies = {
        "chat.postMessage": ok(channel="C0123ABCD", ts="9.9", message={"text": "x"}),
        "chat.scheduleMessage": ok(channel="C0123ABCD", scheduled_message_id="Q1", post_at=_FUTURE),
        "files.getUploadURLExternal": ok(upload_url=UPLOAD_URL, file_id="F0123ABCD"),
        "files.completeUploadExternal": ok(files=[{"id": "F0123ABCD", "title": "notes.md"}]),
        "conversations.create": ok(channel=_channel("C9", "eng-ops", is_private=True)),
    }
    return replies.get(method, ok())


@pytest.mark.asyncio
@pytest.mark.parametrize("action", sorted(WRITE_CALLS))
async def test_writes_run_once_confirmed(action):
    connector, seen = _connector(_write_handler)
    result = await WRITE_CALLS[action](connector, user_confirmed=True)
    assert isinstance(result, dict) and result
    assert seen and all(r.method == "POST" for r in seen)
    _no_token(result)


@pytest.mark.asyncio
async def test_post_message_request_forces_unfurl_off():
    connector, seen = _connector(_write_handler)
    result = await connector.post_message(
        "C0123ABCD", " hello https://intranet/x ", user_confirmed=True
    )
    (request,) = seen
    assert request.url.host == "slack.com"
    assert request.url.raw_path == b"/api/chat.postMessage"
    assert _json(request) == {
        "channel": "C0123ABCD",
        "text": "hello https://intranet/x",
        "unfurl_links": False,
        "unfurl_media": False,
    }
    assert result == {"channel": "C0123ABCD", "ts": "9.9", "posted": True}


@pytest.mark.asyncio
async def test_reply_in_thread_request_forces_unfurl_off():
    connector, seen = _connector(_write_handler)
    result = await connector.reply_in_thread(
        "C0123ABCD",
        "1712345678.000200",
        "on it",
        also_send_to_channel=True,
        user_confirmed=True,
    )
    assert _json(seen[0]) == {
        "channel": "C0123ABCD",
        "thread_ts": "1712345678.000200",
        "text": "on it",
        "reply_broadcast": True,
        "unfurl_links": False,
        "unfurl_media": False,
    }
    assert seen[0].url.raw_path == b"/api/chat.postMessage"
    assert result["thread_ts"] == "1712345678.000200"


@pytest.mark.asyncio
async def test_schedule_message_request_forces_unfurl_off():
    connector, seen = _connector(_write_handler)
    result = await connector.schedule_message(
        "C0123ABCD", "later", str(_FUTURE), thread_ts="1.5", user_confirmed=True
    )
    assert seen[0].url.raw_path == b"/api/chat.scheduleMessage"
    assert _json(seen[0]) == {
        "channel": "C0123ABCD",
        "text": "later",
        "post_at": _FUTURE,
        "thread_ts": "1.5",
        "unfurl_links": False,
        "unfurl_media": False,
    }
    assert result == {
        "channel": "C0123ABCD",
        "scheduled_message_id": "Q1",
        "post_at": _FUTURE,
        "scheduled": True,
    }


@pytest.mark.asyncio
async def test_the_choke_point_overrides_any_unfurl_value():
    connector, seen = _connector(_write_handler)
    await connector._send_chat(
        "chat.postMessage",
        {"channel": "C1", "text": "x", "unfurl_links": True, "unfurl_media": True},
        "post_message",
    )
    body = _json(seen[0])
    assert body["unfurl_links"] is False and body["unfurl_media"] is False


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "post_at", [int(time.time()) - 10, int(time.time()) + 200 * 86400, "soon", True, 1.5, None]
)
async def test_schedule_message_rejects_bad_times(post_at):
    connector, seen = _connector(_write_handler)
    with pytest.raises(ConnectorError):
        await connector.schedule_message("C0123ABCD", "x", post_at, user_confirmed=True)
    assert seen == []


@pytest.mark.asyncio
async def test_add_reaction_request():
    connector, seen = _connector(_write_handler)
    result = await connector.add_reaction("C0123ABCD", "1.2", ":thumbsup:", user_confirmed=True)
    assert seen[0].url.raw_path == b"/api/reactions.add"
    assert _json(seen[0]) == {"channel": "C0123ABCD", "timestamp": "1.2", "name": "thumbsup"}
    assert result == {"channel": "C0123ABCD", "ts": "1.2", "reaction": "thumbsup", "added": True}


@pytest.mark.asyncio
async def test_upload_file_three_steps_without_sending_the_token_to_the_upload_host():
    connector, seen = _connector(_write_handler)
    result = await connector.upload_file(
        "C0123ABCD",
        "notes.md",
        "# hié",
        title="Notes",
        thread_ts="1.2",
        user_confirmed=True,
    )
    ticket, upload, complete = seen
    assert ticket.url.raw_path == b"/api/files.getUploadURLExternal"
    assert _form(ticket) == {"filename": "notes.md", "length": "6"}
    assert ticket.headers["Authorization"] == f"Bearer {BOT}"

    assert upload.method == "POST"
    assert str(upload.url) == UPLOAD_URL
    assert upload.content == "# hié".encode()
    assert "Authorization" not in upload.headers

    assert complete.url.raw_path == b"/api/files.completeUploadExternal"
    form = _form(complete)
    assert json.loads(form.pop("files")) == [{"id": "F0123ABCD", "title": "Notes"}]
    assert form == {"channel_id": "C0123ABCD", "thread_ts": "1.2"}
    assert result == {
        "file_id": "F0123ABCD",
        "title": "Notes",
        "channel": "C0123ABCD",
        "shared": True,
    }


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "upload_url",
    [
        "https://evil.example.com/upload/v1/x",
        "http://files.slack.com/upload/v1/x",
        "https://files.slack.com/files-pri/x",
        "https://files.slack.com:8443/upload/v1/x",
        None,
        12,
    ],
)
async def test_upload_file_refuses_an_unexpected_upload_address(upload_url):
    connector, seen = _connector(lambda r: ok(upload_url=upload_url, file_id="F0123ABCD"))
    with pytest.raises(ConnectorError):
        await connector.upload_file("C0123ABCD", "a.txt", "x", user_confirmed=True)
    assert len(seen) == 1  # only the ticket request; nothing uploaded


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "filename, content",
    [
        ("../etc/passwd", "x"),
        ("a/b.txt", "x"),
        ("a.txt", ""),
        ("a.txt", b"bytes"),
        ("a.txt", "x" * 1_000_001),
    ],
    ids=["dot-dot", "slash", "empty", "bytes", "too-large"],
)
async def test_upload_file_validates_before_any_request(filename, content):
    connector, seen = _connector(_write_handler)
    with pytest.raises(ConnectorError):
        await connector.upload_file("C0123ABCD", filename, content, user_confirmed=True)
    assert seen == []


@pytest.mark.asyncio
async def test_set_status_uses_the_user_token():
    connector, seen = _connector(_write_handler)
    before = int(time.time())
    result = await connector.set_status(
        "Lunch", emoji="taco", expires_in_minutes=30, user_confirmed=True
    )
    (request,) = seen
    assert request.url.raw_path == b"/api/users.profile.set"
    assert request.headers["Authorization"] == f"Bearer {USER}"
    profile = _json(request)["profile"]
    assert profile["status_text"] == "Lunch" and profile["status_emoji"] == ":taco:"
    assert before + 1800 <= profile["status_expiration"] <= int(time.time()) + 1800
    assert result["status_text"] == "Lunch"


@pytest.mark.asyncio
async def test_set_status_empty_text_clears_it():
    connector, seen = _connector(_write_handler)
    with pytest.raises(UserConfirmationRequired, match="clear"):
        await connector.set_status("")
    await connector.set_status("", user_confirmed=True)
    assert _json(seen[0])["profile"] == {
        "status_text": "",
        "status_emoji": "",
        "status_expiration": 0,
    }


@pytest.mark.asyncio
async def test_set_status_without_a_user_token_fails_before_any_request():
    connector, seen = _connector(_write_handler, user_token=False)
    with pytest.raises(ConnectorError, match="user token"):
        await connector.set_status("Lunch", user_confirmed=True)
    assert seen == []


@pytest.mark.asyncio
async def test_create_channel_request_and_shape():
    connector, seen = _connector(_write_handler)
    result = await connector.create_channel("#eng-ops", is_private=True, user_confirmed=True)
    assert seen[0].url.raw_path == b"/api/conversations.create"
    assert _json(seen[0]) == {"name": "eng-ops", "is_private": True}
    assert result["id"] == "C9" and result["is_private"] is True


@pytest.mark.asyncio
@pytest.mark.parametrize("name", ["Eng Ops", "x" * 81, "", "a/b"])
async def test_create_channel_rejects_bad_names(name):
    connector, seen = _connector(_write_handler)
    with pytest.raises(ConnectorError):
        await connector.create_channel(name, user_confirmed=True)
    assert seen == []


@pytest.mark.asyncio
async def test_invite_to_channel_request_deduplicates_ids():
    connector, seen = _connector(_write_handler)
    result = await connector.invite_to_channel("C0123ABCD", ["U1", "W2", "U1"], user_confirmed=True)
    assert seen[0].url.raw_path == b"/api/conversations.invite"
    assert _json(seen[0]) == {"channel": "C0123ABCD", "users": "U1,W2"}
    assert result == {"channel": "C0123ABCD", "invited": ["U1", "W2"]}


@pytest.mark.asyncio
@pytest.mark.parametrize("users", [[], ["ana"], "U1,bob", ["U1"] * 31, None])
async def test_invite_to_channel_validates_users(users):
    connector, seen = _connector(_write_handler)
    with pytest.raises(ConnectorError):
        await connector.invite_to_channel("C0123ABCD", users, user_confirmed=True)
    assert seen == []


@pytest.mark.asyncio
async def test_delete_message_and_archive_channel_requests():
    connector, seen = _connector(_write_handler)
    assert await connector.delete_message("C0123ABCD", "1.2", user_confirmed=True) == {
        "channel": "C0123ABCD",
        "ts": "1.2",
        "deleted": True,
    }
    assert await connector.archive_channel("C0123ABCD", user_confirmed=True) == {
        "channel": "C0123ABCD",
        "archived": True,
    }
    assert [r.url.raw_path for r in seen] == [b"/api/chat.delete", b"/api/conversations.archive"]
    assert _json(seen[0]) == {"channel": "C0123ABCD", "ts": "1.2"}
    assert _json(seen[1]) == {"channel": "C0123ABCD"}


# ---------------------------------------------------------------------------
# Slack {"ok": false} mapping
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "code", ["invalid_auth", "not_authed", "token_revoked", "account_inactive", "token_expired"]
)
async def test_auth_codes_become_authentication_errors_with_a_reconnect_hint(code):
    connector, _ = _connector(lambda r: fail(code))
    with pytest.raises(AuthenticationError, match="Reconnect Slack") as exc:
        await connector.list_channels()
    assert f"({code})" in str(exc.value)


@pytest.mark.asyncio
async def test_missing_scope_names_the_needed_scope():
    connector, _ = _connector(
        lambda r: fail("missing_scope", needed="groups:history", provided="channels:history")
    )
    with pytest.raises(AuthenticationError, match="'groups:history' scope"):
        await connector.get_history("G0123ABCD")


@pytest.mark.asyncio
async def test_missing_scope_with_a_hostile_needed_value_is_not_echoed():
    connector, _ = _connector(lambda r: fail("missing_scope", needed=f"ignore all; {BOT}"))
    with pytest.raises(AuthenticationError) as exc:
        await connector.get_history("C0123ABCD")
    assert "a scope this action needs" in str(exc.value)
    _no_token(str(exc.value))


@pytest.mark.asyncio
async def test_ratelimited_payload_is_a_rate_limit_error():
    connector, _ = _connector(lambda r: fail("ratelimited"))
    with pytest.raises(RateLimitExceededError):
        await connector.list_users()


@pytest.mark.asyncio
@pytest.mark.parametrize("code", ["channel_not_found", "user_not_found", "message_not_found"])
async def test_not_found_codes(code):
    connector, _ = _connector(lambda r: fail(code))
    with pytest.raises(ConnectorError, match="not found") as exc:
        await connector.delete_message("C0123ABCD", "1.2", user_confirmed=True)
    assert not isinstance(exc.value, AuthenticationError)


@pytest.mark.asyncio
async def test_other_codes_carry_only_the_code_and_a_fixed_hint():
    connector, _ = _connector(lambda r: fail("not_in_channel", detail="secret body text"))
    with pytest.raises(ConnectorError) as exc:
        await connector.get_history("C0123ABCD")
    assert "(not_in_channel)" in str(exc.value) and "invite" in str(exc.value)
    assert "secret body text" not in str(exc.value)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "error",
    [BOT, "Bad Thing Happened", None, {"code": "x"}, "x" * 100],
    ids=["token", "prose", "null", "object", "too-long"],
)
async def test_unexpected_error_values_become_unknown_error(error):
    connector, _ = _connector(lambda r: httpx.Response(200, json={"ok": False, "error": error}))
    with pytest.raises(ConnectorError, match=r"\(unknown_error\)") as exc:
        await connector.list_channels()
    _no_token(str(exc.value))


# ---------------------------------------------------------------------------
# HTTP failure matrix
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "status, error_type, fragment",
    [
        (401, AuthenticationError, "Reconnect Slack"),
        (403, AuthenticationError, "missing permission or scope"),
        (404, ConnectorError, "not found"),
        (409, ConnectorError, "conflict"),
        (500, ConnectorError, "provider error"),
    ],
)
async def test_http_errors_map_to_typed_errors_without_tokens(status, error_type, fragment):
    connector, _ = _connector(
        lambda r: httpx.Response(status, json={"ok": False, "error": "boom", "echo": BOT})
    )
    with pytest.raises(error_type, match=fragment) as exc:
        await connector.list_channels()
    _no_token(str(exc.value))


@pytest.mark.asyncio
async def test_429_with_short_retry_after_retries_once():
    responses = [httpx.Response(429, headers={"Retry-After": "1"}), ok(channels=[])]
    connector, seen = _connector(lambda r: responses.pop(0))
    assert await connector.list_channels() == []
    assert len(seen) == 2


@pytest.mark.asyncio
async def test_429_without_retry_after_retries_once_after_a_short_backoff():
    responses = [httpx.Response(429), ok(channels=[])]
    connector, seen = _connector(lambda r: responses.pop(0))
    slept: list[float] = []

    async def record_sleep(seconds: float) -> None:
        slept.append(seconds)

    connector._sleep = record_sleep
    assert await connector.list_channels() == []
    assert len(seen) == 2
    assert len(slept) == 1 and 0 < slept[0] <= 10


@pytest.mark.asyncio
async def test_repeated_429_without_retry_after_raises_after_one_retry():
    connector, seen = _connector(lambda r: httpx.Response(429))
    with pytest.raises(RateLimitExceededError) as exc:
        await connector.list_channels()
    assert len(seen) == 2
    _no_token(str(exc.value))


@pytest.mark.asyncio
async def test_429_with_long_retry_after_is_not_retried():
    connector, seen = _connector(lambda r: httpx.Response(429, headers={"Retry-After": "30"}))
    with pytest.raises(RateLimitExceededError, match="30"):
        await connector.post_message("C0123ABCD", "x", user_confirmed=True)
    assert len(seen) == 1


@pytest.mark.asyncio
async def test_timeout_is_a_clean_connector_error():
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ReadTimeout("slow", request=request)

    connector, _ = _connector(handler)
    with pytest.raises(ConnectorError, match="timed out"):
        await connector.get_user("U1")


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "response",
    [
        httpx.Response(200, content=b"<html>oops</html>"),
        httpx.Response(200, json=["not", "an", "object"]),
        httpx.Response(200, json={"channels": []}),  # "ok" missing
        httpx.Response(200, json={"ok": "true", "channels": []}),  # not a real boolean
        httpx.Response(200, json={"ok": True, "channels": {"id": "C1"}}),
    ],
)
async def test_malformed_replies_are_clean_connector_errors(response):
    connector, _ = _connector(lambda r: response)
    with pytest.raises(ConnectorError):
        await connector.list_channels()


@pytest.mark.asyncio
async def test_missing_list_fields_give_empty_results():
    connector, _ = _connector(lambda r: ok())
    assert await connector.list_channels() == []
    assert await connector.get_history("C0123ABCD") == []
    assert await connector.search_messages("x") == []
    assert await connector.get_user("U1") == {}


@pytest.mark.asyncio
async def test_pagination_stops_when_the_cursor_is_empty():
    connector, seen = _connector(
        lambda r: ok(messages=[{"ts": "1.1", "text": "a"}], response_metadata={"next_cursor": ""})
    )
    assert len(await connector.get_history("C0123ABCD", limit=5)) == 1
    assert len(seen) == 1


@pytest.mark.asyncio
async def test_pagination_stops_on_a_repeated_cursor():
    connector, seen = _connector(
        lambda r: ok(members=[_member("U1", "ana")], response_metadata={"next_cursor": "same"})
    )
    result = await connector.list_users(query="nobody-matches")
    assert result == []
    assert len(seen) == 2  # first page, then the repeated cursor ends it


@pytest.mark.asyncio
async def test_pagination_is_capped_at_five_pages():
    counter = iter(range(100))
    connector, seen = _connector(
        lambda r: ok(channels=[], response_metadata={"next_cursor": f"c{next(counter)}"})
    )
    assert await connector.list_channels() == []
    assert len(seen) == 5


# ---------------------------------------------------------------------------
# Hostile provider payloads
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_hostile_list_payloads_do_not_crash_and_stay_small():
    huge = "z" * 1_000_000
    channels = [
        None,
        7,
        "C1",
        [],
        {
            "id": {"x": 1},
            "name": huge,
            "topic": "flat",
            "purpose": {"value": ["x"]},
            "num_members": "many",
        },
    ]
    connector, _ = _connector(lambda r: ok(channels=channels))
    result = await connector.list_channels()
    assert len(result) == 1
    assert len(result[0]["name"]) == 256 and "id" not in result[0]
    assert "topic" not in result[0] and "purpose" not in result[0]


@pytest.mark.asyncio
async def test_hostile_messages_do_not_crash():
    messages = [
        None,
        {"ts": 1, "text": {"a": 1}, "files": "F1", "user": ["U1"]},
        {"ts": "1.1", "text": None, "files": [None, {"id": "F1", "name": 3}]},
    ]
    connector, _ = _connector(lambda r: ok(messages=messages))
    result = await connector.get_history("C0123ABCD")
    assert result[0] == {"ts": 1, "text": ""}
    assert result[1] == {"ts": "1.1", "text": "", "files": [{"id": "F1", "name": 3}]}


@pytest.mark.asyncio
async def test_hostile_user_and_file_payloads_do_not_crash():
    connector, _ = _connector(lambda r: ok(user={"id": "U1", "profile": ["x"]}))
    assert await connector.get_user("U1") == {"id": "U1"}
    connector, _ = _connector(lambda r: ok(members=[{"id": "U1", "profile": None}, "x"]))
    assert await connector.list_users(query="u") == []
    connector, _ = _connector(lambda r: ok(file={"id": "F1", "channels": "C1", "preview": 5}))
    assert await connector.get_file_info("F0123ABCD") == {"id": "F1", "shared_in": []}
    connector, _ = _connector(lambda r: ok(file="F1"))
    with pytest.raises(ConnectorError):
        await connector.get_file_info("F0123ABCD")
    connector, _ = _connector(lambda r: ok(messages={"matches": [None, {"channel": "C1"}]}))
    assert await connector.search_messages("x") == [{"text": ""}]


# ---------------------------------------------------------------------------
# Health check and revoke
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_health_check_calls_auth_test():
    connector, seen = _connector(lambda r: ok(team="Acme", user_id="U1"))
    assert await connector.health_check() is True
    assert seen[0].method == "GET" and seen[0].url.raw_path == b"/api/auth.test"
    for response in (fail("invalid_auth"), httpx.Response(500)):
        connector, _ = _connector(lambda r, resp=response: resp)
        assert await connector.health_check() is False


@pytest.mark.asyncio
async def test_revoke_revokes_bot_and_user_tokens_but_never_sends_the_app_token():
    connector, seen = _connector(lambda r: ok(revoked=True))
    assert await connector.revoke() is True
    assert [r.url.raw_path for r in seen] == [b"/api/auth.revoke", b"/api/auth.revoke"]
    assert [r.headers["Authorization"] for r in seen] == [f"Bearer {BOT}", f"Bearer {USER}"]
    assert all(r.method == "POST" for r in seen)


@pytest.mark.asyncio
async def test_revoke_reports_a_partial_failure():
    responses = [ok(revoked=True), fail("invalid_auth")]
    connector, seen = _connector(lambda r: responses.pop(0))
    assert await connector.revoke() is False
    assert len(seen) == 2


@pytest.mark.asyncio
async def test_revoke_with_no_tokens_sends_nothing():
    connector = SlackConnector()
    assert await connector.revoke() is False


def test_from_credentials_stores_tokens_for_revoke():
    connector = SlackConnector.from_credentials({"bot_token": BOT, "user_token": USER})
    assert isinstance(connector, SlackConnector)
    assert connector._bot_token == BOT and connector._user_token == USER


# ---------------------------------------------------------------------------
# Network policy
# ---------------------------------------------------------------------------


@pytest.fixture
def no_dns(monkeypatch):
    monkeypatch.setattr(netsec, "check_ssrf", lambda url: netsec.SSRFCheckResult(safe=True))


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "method, url",
    [
        ("GET", "https://slack.com/api/conversations.list"),
        ("POST", "https://slack.com/api/chat.postMessage"),
        ("POST", "https://files.slack.com/upload/v1/ABCtest"),
    ],
)
async def test_policy_allows_the_declared_hosts_and_paths(no_dns, method, url):
    connector = SlackConnector()
    connector.set_network_policy("slack")
    await connector._enforce_network_policy(httpx.Request(method, url))


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "url",
    [
        "https://evil.example.com/api/chat.postMessage",
        "https://slack.com/oauth/v2/authorize",
        "https://files.slack.com/files-pri/T1-F1/secret.txt",
        "http://slack.com/api/auth.test",
        "https://slack.com:8443/api/auth.test",
        "https://slack.com/api/%2e%2e/admin",
        "https://api.slack.com/api/auth.test",
    ],
)
async def test_policy_refuses_off_list_hosts_paths_http_and_dot_segments(no_dns, url):
    connector = SlackConnector()
    connector.set_network_policy("slack")
    with pytest.raises(ConnectorError, match="blocked by network policy"):
        await connector._enforce_network_policy(httpx.Request("GET", url))


def test_policy_is_registered_with_the_websocket_hosts():
    policy = netsec.DEFAULT_POLICIES["slack"]
    assert policy.https_only is True
    assert list(policy.ws_hosts) == [
        "wss-primary.slack.com",
        "wss-backup.slack.com",
        "wss.slack.com",
    ]


# ---------------------------------------------------------------------------
# Dispatch
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_execute_wraps_lists_and_refuses_unknown_actions():
    connector, _ = _connector(lambda r: ok(channels=[_channel("C1", "general")]))
    response = await connector.execute("list_channels", {})
    assert response.data["count"] == 1 and response.data["items"][0]["id"] == "C1"
    with pytest.raises(ConnectorError, match="Unknown Slack action"):
        await connector.execute("_call", {})
    with pytest.raises(ConnectorError, match="Unknown Slack action"):
        await connector.execute("revoke", {})
