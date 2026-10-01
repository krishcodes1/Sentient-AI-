"""Tests for the Google Workspace connector's definition, sign-in state, token
refresh, health check, revoke, network allowlist, shared failure handling and
its path through the real tool pipeline.

Why it exists: Google is the connector with the most surfaces and the only one
that refreshes tokens itself for legacy pasted-token rows. These tests pin the
catalog (names, categories, always-confirm, starters, scopes), the refresh and
persistence rules (rotated refresh token, ``expires_at``), the failure matrix
and the executor round trip (READ, and an always-confirm action refused then
approved). The per-API actions are covered in the sibling
``test_google_workspace_<api>.py`` modules.

Connects to services/connectors/google_workspace.py, the registry, the
factory and services/agent/tool_registry.py. All HTTP goes to
``httpx.MockTransport``; no real network, DNS or credentials.
"""

from __future__ import annotations

import json
import time
from types import SimpleNamespace

import httpx
import pytest

from services.agent.permissions import ActionCategory
from services.connectors.base import (
    AuthenticationError,
    ConnectorError,
    RateLimitExceededError,
    UserConfirmationRequired,
)
from services.connectors.google_workspace import (
    DEFINITION,
    GoogleWorkspaceConnector,
)
from services.connectors.registry import validate_registry
from tests.connectors.test_google_workspace_support import (
    CLIENT_ID,
    CLIENT_SECRET,
    REFRESH,
    TOKEN,
    form,
    make,
    no_dns,  # noqa: F401 - fixture
    no_secret_in,
    ok,
)

pytestmark = pytest.mark.usefixtures("no_dns")

R, W, D = ActionCategory.READ, ActionCategory.WRITE, ActionCategory.DELETE

# Spec 5.1 table: every action, its category and whether it is always-confirm.
EXPECTED: dict[str, tuple[ActionCategory, bool]] = {
    "get_messages": (R, False), "get_message": (R, False), "search_emails": (R, False),
    "get_thread": (R, False), "list_labels": (R, False), "get_attachment_text": (R, False),
    "send_email": (W, True), "reply": (W, True), "forward": (W, True),
    "create_draft": (W, False), "send_draft": (W, True), "modify_labels": (W, False),
    "trash_message": (D, True),
    "get_events": (R, False), "check_availability": (R, False), "list_calendars": (R, False),
    # respond_to_invite answers the organizer: always-confirm (permission tiers).
    "create_event": (W, False), "update_event": (W, False), "respond_to_invite": (W, True),
    "delete_event": (D, True),
    "search_files": (R, False), "get_file_text": (R, False), "list_folder": (R, False),
    "upload_file": (W, False), "create_folder": (W, False), "move_file": (W, False),
    "rename_file": (W, False), "share_file": (W, True), "trash_file": (D, True),
    "get_document": (R, False), "create_document": (W, False), "append_text": (W, False),
    "replace_text": (W, False),
    "get_values": (R, False), "get_metadata": (R, False), "update_values": (W, False),
    "append_rows": (W, False), "add_sheet": (W, False), "clear_range": (D, True),
    "search_contacts": (R, False), "get_contact": (R, False), "create_contact": (W, False),
    "update_contact": (W, False), "delete_contact": (D, True),
}


# ---------------------------------------------------------------------------
# Definition
# ---------------------------------------------------------------------------


def test_definition_passes_registry_validation():
    assert validate_registry([DEFINITION]) == []


def test_every_spec_action_has_its_category_and_confirmation():
    actual = {s.action: (s.category, s.always_confirm) for s in DEFINITION.actions}
    assert actual == EXPECTED
    assert GoogleWorkspaceConnector._ACTIONS == frozenset(EXPECTED)


def test_starters_are_four_everyday_reads():
    starters = {s.action for s in DEFINITION.actions if s.starter}
    assert starters == {"get_messages", "search_emails", "get_events", "search_files"}


def test_policy_keys_and_catalog_scopes():
    assert DEFINITION.policy_keys() == (
        "gmail", "google_calendar", "google_drive", "google_docs", "google_sheets", "google_contacts",
    )
    scopes = DEFINITION.scopes()
    assert scopes["read"] == sorted(
        ["gmail.read", "calendar.read", "drive.read", "docs.read", "sheets.read", "contacts.read"]
    )
    assert scopes["write"] == sorted(
        ["gmail.send", "gmail.compose", "gmail.modify", "calendar.write", "drive.write",
         "docs.write", "sheets.write", "contacts.write"]
    )
    # send_email keeps gmail.send to itself (existing grants keep working).
    assert [s.action for s in DEFINITION.actions if s.required_scope == "gmail.send"] == ["send_email"]


def test_scope_map_is_least_privilege():
    oauth = DEFINITION.auth.oauth
    assert oauth is not None and oauth.provider == "google"
    base = "https://www.googleapis.com/auth/"
    assert dict(oauth.scope_map) == {
        "gmail.read": (f"{base}gmail.readonly",),
        "gmail.send": (f"{base}gmail.send",),
        "gmail.compose": (f"{base}gmail.compose",),
        "gmail.modify": (f"{base}gmail.modify",),
        "calendar.read": (f"{base}calendar.readonly",),
        "calendar.write": (f"{base}calendar.events",),
        "drive.read": (f"{base}drive.readonly",),
        "drive.write": (f"{base}drive",),
        "docs.read": (f"{base}documents.readonly",),
        "docs.write": (f"{base}documents",),
        "sheets.read": (f"{base}spreadsheets.readonly",),
        "sheets.write": (f"{base}spreadsheets",),
        "contacts.read": (f"{base}contacts.readonly",),
        "contacts.write": (f"{base}contacts",),
    }
    assert "https://mail.google.com/" not in {s for v in oauth.scope_map.values() for s in v}
    assert oauth.provider_scopes(["drive.read", "gmail.read"]) == (
        f"{base}drive.readonly", f"{base}gmail.readonly",
    )


def test_every_write_takes_keyword_only_confirmation_and_reads_do_not():
    import inspect

    for spec in DEFINITION.actions:
        params = inspect.signature(getattr(GoogleWorkspaceConnector, spec.action)).parameters
        if spec.category == R:
            assert "user_confirmed" not in params, spec.action
        else:
            assert params["user_confirmed"].kind is inspect.Parameter.KEYWORD_ONLY, spec.action
            assert params["user_confirmed"].default is False, spec.action


# ---------------------------------------------------------------------------
# Sign-in state and credentials
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_broker_shaped_credentials_are_accepted_without_network():
    connector = GoogleWorkspaceConnector.from_credentials(
        {"access_token": TOKEN, "refresh_token": REFRESH, "client_id": CLIENT_ID}
    )
    sent: list[httpx.Request] = []
    connector._http_client = httpx.AsyncClient(
        transport=httpx.MockTransport(lambda r: sent.append(r) or httpx.Response(500))
    )
    expires = int(time.time()) + 3600
    assert await connector.authenticate(
        {
            "access_token": TOKEN,
            "refresh_token": REFRESH,
            "expires_at": expires,
            "token_type": "Bearer",
            "granted_scopes": ["https://www.googleapis.com/auth/drive.readonly"],
            "oauth_provider": "google",
        }
    )
    assert sent == []
    assert connector._expires_at == expires
    assert connector._granted_scopes == {"https://www.googleapis.com/auth/drive.readonly"}
    assert connector._auth_headers() == {"Authorization": f"Bearer {TOKEN}"}
    await connector.close()


def test_broker_row_refreshes_with_the_installation_client(monkeypatch):
    import core.config

    monkeypatch.setattr(
        core.config,
        "settings",
        SimpleNamespace(GOOGLE_OAUTH_CLIENT_ID="install-id", GOOGLE_OAUTH_CLIENT_SECRET="install-secret"),
    )
    broker = GoogleWorkspaceConnector.from_credentials(
        {"access_token": TOKEN, "oauth_provider": "google"}
    )
    assert (broker._client_id, broker._client_secret) == ("install-id", "install-secret")
    # A pasted row keeps its own client; a row with neither has none.
    pasted = GoogleWorkspaceConnector.from_credentials(
        {"access_token": TOKEN, "client_id": "own-id", "client_secret": "own-secret"}
    )
    assert (pasted._client_id, pasted._client_secret) == ("own-id", "own-secret")
    bare = GoogleWorkspaceConnector.from_credentials({"access_token": TOKEN, "client_id": None})
    assert (bare._client_id, bare._client_secret) == ("", "")


def test_broker_row_on_an_unconfigured_server_gets_no_client(monkeypatch):
    import core.config

    monkeypatch.setattr(core.config, "settings", SimpleNamespace())
    broker = GoogleWorkspaceConnector.from_credentials({"access_token": TOKEN, "oauth_provider": "google"})
    assert (broker._client_id, broker._client_secret) == ("", "")


def test_redirect_uri_is_explicit_or_derived_from_settings(monkeypatch):
    import core.config

    explicit = GoogleWorkspaceConnector(redirect_uri="https://app.example/cb")
    assert explicit.redirect_uri == "https://app.example/cb"
    monkeypatch.setattr(core.config, "settings", SimpleNamespace(OAUTH_REDIRECT_BASE="https://crawler.example/"))
    derived = GoogleWorkspaceConnector(client_id=CLIENT_ID)
    assert derived.redirect_uri == "https://crawler.example/api/oauth/callback/google"
    url, verifier = derived.generate_auth_url()
    params = httpx.URL(url).params
    assert params["redirect_uri"] == "https://crawler.example/api/oauth/callback/google"
    assert params["code_challenge_method"] == "S256" and verifier
    assert "localhost:8000" not in url
    monkeypatch.setattr(core.config, "settings", SimpleNamespace())
    assert derived.redirect_uri == "http://127.0.0.1:3000/api/oauth/callback/google"


def test_updated_credentials_persists_rotation_and_expiry_and_drops_codes():
    connector = GoogleWorkspaceConnector(client_id=CLIENT_ID)
    original = {"access_token": "old", "refresh_token": "r1", "client_id": CLIENT_ID}
    connector._access_token, connector._refresh_token = "old", "r1"
    assert connector.updated_credentials(original) is None

    connector._access_token, connector._refresh_token, connector._expires_at = "new", "r2", 1_900_000_000
    updated = connector.updated_credentials({**original, "code": "c", "code_verifier": "v"})
    assert updated == {**original, "access_token": "new", "refresh_token": "r2", "expires_at": 1_900_000_000}

    connector._access_token = None
    assert connector.updated_credentials(original) is None


# ---------------------------------------------------------------------------
# Token refresh
# ---------------------------------------------------------------------------


def _refreshing(api_payload, *, token_payload=None, token_status=200):
    """Handler: the token endpoint answers *token_payload*; the API answers 401
    to the stale token and *api_payload* to the fresh one."""
    token_payload = token_payload or {
        "access_token": "fresh-access", "refresh_token": "rotated-refresh", "expires_in": 3599,
    }

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.host == "oauth2.googleapis.com":
            return httpx.Response(token_status, json=token_payload)
        if request.headers.get("Authorization") == "Bearer fresh-access":
            return httpx.Response(200, json=api_payload)
        return httpx.Response(401, json={"error": {"status": "UNAUTHENTICATED"}})

    return handler


@pytest.mark.asyncio
async def test_401_refreshes_once_keeps_the_rotated_token_and_records_expiry():
    connector, seen = make(_refreshing({"labels": []}), refresh=REFRESH)
    assert await connector.list_labels() == []

    assert [r.url.host for r in seen] == ["gmail.googleapis.com", "oauth2.googleapis.com", "gmail.googleapis.com"]
    token_request = seen[1]
    assert token_request.method == "POST" and token_request.url.path == "/token"
    assert "authorization" not in token_request.headers
    assert form(token_request) == {
        "grant_type": "refresh_token", "client_id": CLIENT_ID,
        "refresh_token": REFRESH, "client_secret": CLIENT_SECRET,
    }
    original = {"access_token": TOKEN, "refresh_token": REFRESH}
    updated = connector.updated_credentials(original)
    assert updated["access_token"] == "fresh-access"
    assert updated["refresh_token"] == "rotated-refresh"
    assert abs(updated["expires_at"] - (time.time() + 3599)) < 5


@pytest.mark.asyncio
async def test_a_token_known_to_be_expiring_is_refreshed_before_the_first_request():
    connector, seen = make(
        _refreshing({"labels": []}), refresh=REFRESH, expires_at=int(time.time()) + 10
    )
    await connector.list_labels()
    assert [r.url.host for r in seen] == ["oauth2.googleapis.com", "gmail.googleapis.com"]


@pytest.mark.asyncio
async def test_concurrent_401s_share_one_refresh():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.host == "oauth2.googleapis.com":
            return httpx.Response(200, json={"access_token": "fresh-access"})
        if request.url.path.endswith("/messages"):
            return httpx.Response(200, json={"messages": [{"id": "a"}, {"id": "b"}, {"id": "c"}]})
        if request.headers["Authorization"] == "Bearer fresh-access":
            return httpx.Response(200, json={"id": request.url.path.rsplit("/", 1)[-1]})
        return httpx.Response(401)

    connector, seen = make(handler, refresh=REFRESH)
    messages = await connector.get_messages()
    assert [m["id"] for m in messages] == ["a", "b", "c"]
    assert sum(r.url.host == "oauth2.googleapis.com" for r in seen) == 1


@pytest.mark.asyncio
async def test_a_second_401_after_refresh_is_not_retried_again():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.host == "oauth2.googleapis.com":
            return httpx.Response(200, json={"access_token": "also-bad"})
        return httpx.Response(401)

    connector, seen = make(handler, refresh=REFRESH)
    with pytest.raises(AuthenticationError, match="Reconnect Google Workspace"):
        await connector.list_labels()
    assert len(seen) == 3


@pytest.mark.asyncio
async def test_rejected_refresh_asks_to_reconnect_without_leaking_tokens():
    connector, _ = make(
        _refreshing({}, token_payload={"error": "invalid_grant"}, token_status=400), refresh=REFRESH
    )
    with pytest.raises(AuthenticationError, match="refresh failed") as exc:
        await connector.list_labels()
    assert "invalid_grant" in str(exc.value) and "Reconnect" in str(exc.value)
    assert no_secret_in(str(exc.value))


@pytest.mark.asyncio
async def test_token_endpoint_outage_is_not_a_reconnect_prompt():
    connector, _ = make(_refreshing({}, token_payload={}, token_status=500), refresh=REFRESH)
    with pytest.raises(ConnectorError) as exc:
        await connector.list_labels()
    assert not isinstance(exc.value, AuthenticationError)
    assert "HTTP 500" in str(exc.value)


@pytest.mark.asyncio
async def test_malformed_token_response_is_a_clean_error():
    connector, _ = make(_refreshing({}, token_payload={"token": "x"}), refresh=REFRESH)
    with pytest.raises(ConnectorError, match="Malformed token response"):
        await connector.list_labels()


@pytest.mark.asyncio
async def test_refresh_without_a_client_id_fails_before_any_token_request():
    connector, seen = make(lambda r: httpx.Response(401), refresh=REFRESH, client_id="")
    with pytest.raises(AuthenticationError, match="client id"):
        await connector.list_labels()
    assert [r.url.host for r in seen] == ["gmail.googleapis.com"]


# ---------------------------------------------------------------------------
# Health check and revoke
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_health_check_refreshes_once_on_401():
    connector, seen = make(_refreshing({"emailAddress": "me@example.com"}), refresh=REFRESH)
    assert await connector.health_check() is True
    assert [r.url.host for r in seen] == ["gmail.googleapis.com", "oauth2.googleapis.com", "gmail.googleapis.com"]
    assert connector.updated_credentials({"access_token": TOKEN})["access_token"] == "fresh-access"


@pytest.mark.asyncio
async def test_health_check_without_client_credentials_does_not_refresh():
    connector, seen = make(lambda r: httpx.Response(401), refresh=REFRESH, client_id="")
    assert await connector.health_check() is False
    assert len(seen) == 1


@pytest.mark.asyncio
async def test_health_check_probes_drive_for_a_drive_only_grant():
    connector, seen = make(ok({"user": {}}))
    connector._granted_scopes = {"https://www.googleapis.com/auth/drive.readonly"}
    assert await connector.health_check() is True
    assert [r.url.raw_path for r in seen] == [b"/drive/v3/about?fields=user"]


@pytest.mark.asyncio
@pytest.mark.parametrize("status,healthy", [(200, True), (403, True), (401, False), (500, False)])
async def test_health_check_for_a_docs_only_grant(status, healthy):
    connector, seen = make(ok({"error": {"status": "PERMISSION_DENIED"}}, status))
    connector._granted_scopes = {"https://www.googleapis.com/auth/documents.readonly"}
    assert await connector.health_check() is healthy
    assert len(seen) == 1


@pytest.mark.asyncio
async def test_revoke_posts_the_refresh_token_without_authorization():
    connector, seen = make(ok({}), refresh=REFRESH)
    assert await connector.revoke() is True
    (request,) = seen
    assert request.method == "POST"
    assert (request.url.host, request.url.path) == ("oauth2.googleapis.com", "/revoke")
    assert form(request) == {"token": REFRESH}
    assert "authorization" not in request.headers


@pytest.mark.asyncio
async def test_revoke_falls_back_to_the_access_token_and_reports_failure():
    connector, seen = make(ok({"error": "invalid_token"}, 400))
    assert await connector.revoke() is False
    assert form(seen[0]) == {"token": TOKEN}
    empty, none_sent = make(ok({}), token=None)
    assert await empty.revoke() is False
    assert none_sent == []


# ---------------------------------------------------------------------------
# Network allowlist
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_every_declared_host_and_path_is_allowed():
    connector, _ = make(ok())
    for host, prefixes in DEFINITION.network.hosts.items():
        for prefix in prefixes:
            await connector._enforce_network_policy(httpx.Request("GET", f"https://{host}{prefix}x"))


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "url",
    [
        "https://evil.example.com/drive/v3/files",
        "https://www.googleapis.com/storage/v1/b",
        "https://docs.googleapis.com/v1/other",
        "http://www.googleapis.com/drive/v3/files",
        "https://www.googleapis.com:8443/drive/v3/files",
        "https://www.googleapis.com/drive/v3/%2e%2e/%2e%2e/admin",
    ],
)
async def test_off_list_urls_are_refused(url):
    connector, _ = make(ok())
    with pytest.raises(ConnectorError, match="blocked by network policy"):
        await connector._enforce_network_policy(httpx.Request("GET", url))


# ---------------------------------------------------------------------------
# Failure matrix (shared request helper)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "status,payload,exc_type,text",
    [
        (401, {"error": {"status": "UNAUTHENTICATED"}}, AuthenticationError, "Reconnect Google Workspace"),
        (403, {"error": {"code": 403, "status": "PERMISSION_DENIED"}}, AuthenticationError, "missing permission or scope"),
        (404, {"error": {"status": "NOT_FOUND"}}, ConnectorError, "not found"),
        (500, {"error": {"status": "INTERNAL"}}, ConnectorError, "provider error"),
    ],
)
async def test_http_errors_map_to_typed_errors_without_bodies_or_tokens(status, payload, exc_type, text):
    payload = {**payload, "message": f"echo {TOKEN}"}
    connector, seen = make(ok(payload, status))
    with pytest.raises(exc_type, match=text) as exc:
        await connector.search_files("x")
    assert no_secret_in(str(exc.value))
    assert "echo" not in str(exc.value)
    assert len(seen) == 1  # none of these is retried


@pytest.mark.asyncio
async def test_409_on_a_write_is_a_conflict():
    connector, _ = make(ok({"error": {"status": "ABORTED"}}, 409))
    with pytest.raises(ConnectorError, match="conflict"):
        await connector.create_folder("Reports", user_confirmed=True)


@pytest.mark.asyncio
async def test_429_with_a_short_retry_after_is_retried_once():
    responses = [
        httpx.Response(429, headers={"Retry-After": "2"}),
        httpx.Response(200, json={"files": [{"id": "f1", "name": "A"}]}),
    ]
    connector, seen = make(lambda r: responses.pop(0))
    assert await connector.search_files("a") == [{"id": "f1", "name": "A"}]
    assert len(seen) == 2


@pytest.mark.asyncio
async def test_429_with_a_long_retry_after_is_reported_not_waited():
    connector, seen = make(lambda r: httpx.Response(429, headers={"Retry-After": "60"}))
    with pytest.raises(RateLimitExceededError, match="Retry after 60 s"):
        await connector.search_files("a")
    assert len(seen) == 1


def _usage_limit(reason: str) -> dict:
    """A Google usage-limit 403 body that also echoes a token (never surfaced)."""
    return {"error": {"code": 403, "status": "PERMISSION_DENIED", "message": f"echo {TOKEN}",
                      "errors": [{"domain": "usageLimits", "reason": reason, "message": "limit"}]}}


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "payload,reason",
    [
        (_usage_limit("rateLimitExceeded"), "rateLimitExceeded"),
        (_usage_limit("userRateLimitExceeded"), "userRateLimitExceeded"),
        (_usage_limit("dailyLimitExceeded"), "dailyLimitExceeded"),
        ({"error": {"code": 403, "status": "RESOURCE_EXHAUSTED"}}, "RESOURCE_EXHAUSTED"),
    ],
)
async def test_a_google_usage_limit_403_is_a_rate_limit_not_a_scope_problem(payload, reason):
    connector, seen = make(ok(payload, 403))
    with pytest.raises(RateLimitExceededError, match=reason) as exc:
        await connector.search_files("x")
    message = str(exc.value)
    assert message.startswith("HTTP 403 from Google Workspace")
    assert "scope" not in message and "echo" not in message
    assert no_secret_in(message)
    assert len(seen) == 1  # not retried: the model is told to wait


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "payload",
    [
        {"error": {"code": 403, "errors": [{"reason": "insufficientPermissions"}]}},
        {"error": {"code": 403, "errors": [{"reason": "x" * 5000}, None, "rateLimitExceeded"]}},
        {"error": {"code": 403, "errors": {"reason": "rateLimitExceeded"}}},
        {"error": "rateLimitExceeded"},
        ["rateLimitExceeded"],
    ],
)
async def test_other_or_malformed_403s_stay_permission_errors(payload):
    connector, _ = make(ok(payload, 403))
    with pytest.raises(AuthenticationError, match="missing permission or scope"):
        await connector.search_files("x")


@pytest.mark.asyncio
async def test_a_usage_limit_does_not_leak_into_the_next_request():
    responses = [ok(_usage_limit("userRateLimitExceeded"), 403), ok({"error": {"code": 403}}, 403)]
    connector, _ = make(lambda r: responses.pop(0)(r))
    with pytest.raises(RateLimitExceededError):
        await connector.search_files("x")
    with pytest.raises(AuthenticationError, match="missing permission or scope"):
        await connector.search_files("x")


@pytest.mark.asyncio
async def test_health_check_treats_a_usage_limit_as_a_working_token():
    connector, seen = make(ok(_usage_limit("rateLimitExceeded"), 403))
    assert await connector.health_check() is True
    assert len(seen) == 1  # stops at the first probe instead of trying other surfaces


@pytest.mark.asyncio
async def test_timeout_is_a_clean_connector_error():
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ReadTimeout("timed out", request=request)

    connector, _ = make(handler)
    with pytest.raises(ConnectorError, match="timed out"):
        await connector.list_labels()


@pytest.mark.asyncio
@pytest.mark.parametrize("content", [b"<html>oops</html>", b"[1, 2]", b'"text"'])
async def test_malformed_or_non_object_json_is_a_clean_error(content):
    connector, _ = make(lambda r: httpx.Response(200, content=content))
    with pytest.raises(ConnectorError, match="Malformed response from Google Workspace"):
        await connector.list_labels()


@pytest.mark.asyncio
async def test_unknown_action_is_refused_before_any_request():
    connector, seen = make(ok())
    with pytest.raises(ConnectorError, match="Unknown Google Workspace action"):
        await connector.execute("_refresh_access_token", {})
    assert seen == []


# ---------------------------------------------------------------------------
# Through the real pipeline: build_tools, permission adapter, executor
# ---------------------------------------------------------------------------

ALL_SCOPES = tuple(sorted({s.required_scope for s in DEFINITION.actions if s.required_scope}))


def test_build_tools_labels_starters_and_always_confirm():
    from services.agent.tool_registry import ConnectorSpec, build_tools

    for tier in ("user_confirm", "auto_approve"):
        tools = {
            t.name: t
            for t in build_tools(
                [ConnectorSpec("google_workspace", granted_scopes=ALL_SCOPES, permission_tier=tier)],
                user_default_tier=tier,
                include_builtins=False,
            )
        }
        assert set(tools) == {f"google_workspace.{a}" for a in EXPECTED}
        assert {n for n, t in tools.items() if t.starter} == {
            "google_workspace.get_messages", "google_workspace.search_emails",
            "google_workspace.get_events", "google_workspace.search_files",
        }
        for action, (category, confirm) in EXPECTED.items():
            tool = tools[f"google_workspace.{action}"]
            if confirm:
                assert tool.permission_tier == "approval", (tier, action)
            elif category == R:
                assert tool.permission_tier == "auto", (tier, action)
        # auto_approve relaxes an ordinary write, never an always-confirm one.
        expected_write = "auto" if tier == "auto_approve" else "approval"
        assert tools["google_workspace.create_folder"].permission_tier == expected_write


def test_build_tools_offers_only_granted_surfaces():
    from services.agent.tool_registry import ConnectorSpec, build_tools

    tools = build_tools(
        [ConnectorSpec("google_workspace", granted_scopes=("drive.read",))], include_builtins=False
    )
    assert {t.name for t in tools} == {
        "google_workspace.search_files", "google_workspace.get_file_text", "google_workspace.list_folder",
    }


@pytest.mark.asyncio
async def test_permission_adapter_decisions():
    from services.agent.tool_registry import RuntimePermissionAdapter

    adapter = RuntimePermissionAdapter()
    assert await adapter.check("u", "google_workspace.search_files", {}) == "approved"
    assert await adapter.check("u", "google_workspace.get_document", {}) == "approved"
    for action in ("trash_file", "share_file", "delete_contact", "clear_range", "reply", "delete_event"):
        assert await adapter.check("u", f"google_workspace.{action}", {}) == "requires_approval", action
    assert await adapter.check("u", "google_workspace.update_values", {}) == "requires_approval"


async def _google_row(session_factory, user_id, credentials, scopes):
    from core.security import encrypt_credentials
    from models.connector import AuthMethod, ConnectorConfig

    async with session_factory() as session:
        row = ConnectorConfig(
            user_id=user_id,
            connector_type="google_workspace",
            display_name="Work Google",
            auth_method=AuthMethod.oauth2,
            encrypted_credentials=encrypt_credentials(json.dumps(credentials)),
            granted_scopes=list(scopes),
            rate_limit_per_minute=30,
        )
        session.add(row)
        await session.commit()
        await session.refresh(row)
        return row


@pytest.fixture
def mocked_google(monkeypatch):
    """The real factory, with the connector's HTTP sent to a MockTransport
    that still runs the network-policy hook. Returns the request log and a
    slot for the handler."""
    import services.connectors.factory as factory_module

    real_create = factory_module.create_connector
    state: dict = {"requests": [], "handler": ok(), "created": 0}

    def wrapper(connector_type, credentials, **kwargs):
        connector = real_create(connector_type, credentials, **kwargs)
        state["created"] += 1

        def recording(request: httpx.Request) -> httpx.Response:
            state["requests"].append(request)
            return state["handler"](request)

        connector._http_client = httpx.AsyncClient(
            transport=httpx.MockTransport(recording),
            event_hooks={"request": [connector._enforce_network_policy]},
        )
        return connector

    monkeypatch.setattr(factory_module, "create_connector", wrapper)
    return state


def _broker_credentials() -> dict:
    return {
        "access_token": TOKEN,
        "refresh_token": REFRESH,
        "expires_at": int(time.time()) + 3600,
        "token_type": "Bearer",
        "granted_scopes": ["https://www.googleapis.com/auth/drive"],
        "oauth_provider": "google",
    }


@pytest.mark.asyncio
async def test_executor_runs_a_read_with_broker_credentials(session_factory, mocked_google):
    from services.agent.tool_registry import ConnectorToolExecutor
    from tests.conftest import make_user

    user, _ = await make_user(session_factory)
    await _google_row(session_factory, user.id, _broker_credentials(), ("drive.read", "drive.write"))
    mocked_google["handler"] = ok({"files": [{"id": "f1", "name": "Budget", "mimeType": "text/csv"}]})

    result = await ConnectorToolExecutor(session_factory=session_factory).execute(
        "google_workspace.search_files", {"query": "budget", "limit": 3}, str(user.id)
    )

    assert result["ok"] is True, result
    assert result["connector"] == "google_workspace"
    assert result["action"] == "search_files"
    assert result["result"] == {
        "items": [{"id": "f1", "name": "Budget", "mime_type": "text/csv"}], "count": 1,
    }
    (request,) = mocked_google["requests"]
    assert request.url.host == "www.googleapis.com" and request.url.path == "/drive/v3/files"
    assert request.headers["Authorization"] == f"Bearer {TOKEN}"
    assert no_secret_in(result)


@pytest.mark.asyncio
async def test_executor_refuses_then_runs_an_always_confirm_action(session_factory, mocked_google):
    from services.agent.tool_registry import ConnectorToolExecutor
    from tests.conftest import make_user

    user, _ = await make_user(session_factory)
    await _google_row(session_factory, user.id, _broker_credentials(), ("drive.read", "drive.write"))
    executor = ConnectorToolExecutor(session_factory=session_factory)

    refused = await executor.execute(
        "google_workspace.trash_file", {"file_id": "f1", "user_confirmed": True}, str(user.id)
    )
    assert refused["ok"] is False and refused["requires_approval"] is True
    assert mocked_google["requests"] == [] and mocked_google["created"] == 0

    mocked_google["handler"] = ok({"id": "f1", "name": "Old", "trashed": True})
    done = await executor.execute(
        "google_workspace.trash_file", {"file_id": "f1"}, str(user.id), approved=True
    )
    assert done["ok"] is True, done
    assert (done["connector"], done["action"]) == ("google_workspace", "trash_file")
    assert done["result"] == {"status": "trashed", "id": "f1", "name": "Old"}
    (request,) = mocked_google["requests"]
    assert request.method == "PATCH"
    assert request.url.path == "/drive/v3/files/f1"
    assert json.loads(request.content) == {"trashed": True}


@pytest.mark.asyncio
async def test_executor_write_without_confirmation_raises_before_any_request():
    connector, seen = make(ok())
    with pytest.raises(UserConfirmationRequired):
        await connector.execute("create_folder", {"name": "X"})
    assert seen == []
