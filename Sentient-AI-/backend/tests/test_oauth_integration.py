"""Integration tests for the OAuth broker wired into execution and the connector
lifecycle: the tool executor refreshes broker tokens before a call and once more
after a 401, the /test route refreshes and persists rotated tokens, and
deleting a connector (or a whole account) revokes the grant only after the
delete has committed.

Why it exists: the broker (services/connectors/oauth.py) is tested on its own
in test_oauth_broker.py; these tests prove its callers use it correctly, end to
end, with the real Microsoft 365 and Google Workspace connectors, the real
executor and the real routes.

Depends on services/agent/tool_registry.py (ConnectorToolExecutor),
api/routes/connectors.py, api/routes/auth.py and services/connectors/oauth.py.
Every provider endpoint (Microsoft Graph and login, Gmail, Google's token and
revoke endpoints) is an ``httpx.MockTransport`` behind the real policy-checked
clients; no network, no real credentials.
"""

from __future__ import annotations

import asyncio
import json
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Callable, Optional
from urllib.parse import parse_qs

import httpx
import pytest
import pytest_asyncio
from sqlalchemy import event, select
from sqlalchemy.orm import Session

import core.network_security as netsec
from api.routes import oauth as oauth_routes
from core.config import settings
from core.security import decrypt_credentials, encrypt_credentials
from main import app
from models.audit import AuditLog
from models.connector import AuthMethod, ConnectorConfig, PermissionTier
from services.agent.tool_registry import ConnectorToolExecutor
from services.connectors import factory
from services.connectors import oauth as broker
from services.connectors.base import BaseConnector
from services.connectors.definition import ConnectorDefinition
from tests.conftest import auth_headers, make_user

MS_CLIENT_ID = "ms-client-id-test"
GOOGLE_CLIENT_ID = "google-install-client-test"
GOOGLE_CLIENT_SECRET = "google-install-secret-test"

MS_TOKEN_PATH = "/common/oauth2/v2.0/token"
MS_INBOX_PATH = "/v1.0/me/mailFolders/inbox/messages"
MS_SEND_PATH = "/v1.0/me/sendMail"
GMAIL_LIST_PATH = "/gmail/v1/users/me/messages"
GOOGLE_TOKEN_PATH = "/token"
GOOGLE_REVOKE_PATH = "/revoke"

LIST_TOOL = "microsoft.list_messages"
SEND_TOOL = "microsoft.send_mail"
SEND_ARGS = {"to": ["bob@example.com"], "subject": "Hello", "body": "Hi Bob"}
RECONNECT = "Microsoft 365 needs to be reconnected. Reconnect it in Connectors."
MS_PROBE_PATH = "/v1.0/me/mailFolders/inbox"
CANVAS_CREDS = {"base_url": "https://school.instructure.com", "access_token": "canvas-token-test"}


# ---------------------------------------------------------------------------
# Mock provider
# ---------------------------------------------------------------------------


@dataclass
class FakeProvider:
    """Every provider endpoint, keyed by URL path. Each path holds a queue of
    response factories; the last one repeats."""

    routes: dict[str, list[Callable[[httpx.Request], httpx.Response]]] = field(default_factory=dict)
    requests: list[httpx.Request] = field(default_factory=list)

    def on(self, path: str, *responses: Callable[[httpx.Request], httpx.Response]) -> None:
        self.routes.setdefault(path, []).extend(responses)

    def handle(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        queue = self.routes.get(request.url.path)
        if not queue:
            return httpx.Response(404, json={"error": "not_found"})
        factory_fn = queue.pop(0) if len(queue) > 1 else queue[0]
        return factory_fn(request)

    def to(self, path: str) -> list[httpx.Request]:
        return [r for r in self.requests if r.url.path == path]

    def forms(self, path: str) -> list[dict[str, str]]:
        return [{k: v[0] for k, v in parse_qs(r.content.decode()).items()} for r in self.to(path)]

    def bearers(self, path: str) -> list[Optional[str]]:
        return [r.headers.get("authorization") for r in self.to(path)]


def reply(status: int = 200, body: Any = None) -> Callable[[httpx.Request], httpx.Response]:
    def factory_fn(_request: httpx.Request) -> httpx.Response:
        if body is None:
            return httpx.Response(status)
        return httpx.Response(status, json=body)

    return factory_fn


def ms_tokens(access: str = "ms-access-new-test", refresh: Optional[str] = "ms-refresh-rotated-test") -> dict[str, Any]:
    body: dict[str, Any] = {
        "access_token": access,
        "token_type": "Bearer",
        "expires_in": 3600,
        "scope": "Mail.Read Mail.Send offline_access",
    }
    if refresh:
        body["refresh_token"] = refresh
    return body


def _mock_client(connector: BaseConnector, provider: FakeProvider) -> httpx.AsyncClient:
    """The provider behind the connector's own network-policy request hook."""
    return httpx.AsyncClient(
        transport=httpx.MockTransport(provider.handle),
        event_hooks={"request": [connector._enforce_network_policy]},
    )


async def _no_sleep(_seconds: float) -> None:
    return None


@pytest.fixture
def provider(monkeypatch) -> FakeProvider:
    """One mock provider behind every connector the code under test builds
    (executor, /test, revoke) and behind the broker's token client."""
    fake = FakeProvider()
    monkeypatch.setattr(netsec, "check_ssrf", lambda url: netsec.SSRFCheckResult(safe=True))
    real_create = factory.create_connector

    def create(connector_type: str, credentials: dict[str, Any], **kwargs: Any) -> BaseConnector:
        connector = real_create(connector_type, credentials, **kwargs)
        connector._http_client = _mock_client(connector, fake)
        connector._sleep = _no_sleep
        return connector

    monkeypatch.setattr(factory, "create_connector", create)

    real_token_client = broker._token_client

    def token_client(definition: ConnectorDefinition) -> broker._TokenClient:
        client = real_token_client(definition)
        client._http_client = _mock_client(client, fake)
        client._sleep = _no_sleep
        return client

    monkeypatch.setattr(broker, "_token_client", token_client)
    return fake


@pytest.fixture
def configured(monkeypatch) -> None:
    monkeypatch.setattr(settings, "MICROSOFT_OAUTH_CLIENT_ID", MS_CLIENT_ID)
    monkeypatch.setattr(settings, "GOOGLE_OAUTH_CLIENT_ID", GOOGLE_CLIENT_ID)
    monkeypatch.setattr(settings, "GOOGLE_OAUTH_CLIENT_SECRET", GOOGLE_CLIENT_SECRET)


@pytest.fixture
def wired(client, session_factory):
    """Point the routes' broker session factory at the test database."""
    app.dependency_overrides[oauth_routes.session_factory_dependency] = lambda: session_factory
    return client


@pytest_asyncio.fixture(autouse=True)
async def _stop_background_tasks():
    yield
    await broker.shutdown_background_tasks()


# ---------------------------------------------------------------------------
# Rows
# ---------------------------------------------------------------------------


def ms_creds(*, expires_in: int = 3600, **overrides: Any) -> dict[str, Any]:
    creds: dict[str, Any] = {
        "access_token": "ms-access-old-test",
        "refresh_token": "ms-refresh-old-test",
        "expires_at": int(time.time()) + expires_in,
        "token_type": "Bearer",
        "granted_scopes": ["Mail.Read", "Mail.Send", "offline_access"],
        "oauth_provider": "microsoft",
    }
    creds.update(overrides)
    return {k: v for k, v in creds.items() if v is not None}


def google_broker_creds() -> dict[str, Any]:
    return {
        "access_token": "ya29.broker-access-test",
        "refresh_token": "1//broker-refresh-test",
        "expires_at": int(time.time()) + 3600,
        "token_type": "Bearer",
        "granted_scopes": ["https://www.googleapis.com/auth/gmail.readonly"],
        "oauth_provider": "google",
    }


def google_pasted_creds() -> dict[str, Any]:
    return {
        "access_token": "ya29.pasted-access-test",
        "refresh_token": "1//pasted-refresh-test",
        "client_id": "pasted-client-test",
        "client_secret": "pasted-secret-test",
    }


async def add_connector(
    session_factory,
    user_id: uuid.UUID,
    key: str,
    credentials: dict[str, Any],
    scopes: tuple[str, ...],
) -> uuid.UUID:
    async with session_factory() as s:
        row = ConnectorConfig(
            user_id=user_id,
            connector_type=key,
            display_name=f"{key} test",
            auth_method=AuthMethod.oauth2,
            encrypted_credentials=encrypt_credentials(json.dumps(credentials)),
            granted_scopes=list(scopes),
            permission_tier=PermissionTier.user_confirm,
            rate_limit_per_minute=60,
        )
        s.add(row)
        await s.commit()
        return row.id


async def stored(session_factory, config_id: uuid.UUID) -> Optional[dict[str, Any]]:
    async with session_factory() as s:
        row = await s.get(ConnectorConfig, config_id)
        return None if row is None else json.loads(decrypt_credentials(row.encrypted_credentials))


async def audit_rows(session_factory, user_id: uuid.UUID) -> list[tuple[str, str, Any, Any]]:
    async with session_factory() as s:
        rows = (
            await s.execute(select(AuditLog).where(AuditLog.user_id == user_id).order_by(AuditLog.seq))
        ).scalars()
        return [(r.action, r.status.value, r.response_summary, r.request_data) for r in rows]


async def ms_row(session_factory, creds: dict[str, Any]) -> tuple[uuid.UUID, uuid.UUID]:
    user, _ = await make_user(session_factory, f"ms-{uuid.uuid4().hex[:8]}@example.com")
    config_id = await add_connector(session_factory, user.id, "microsoft", creds, ("mail.read", "mail.send"))
    return user.id, config_id


# ---------------------------------------------------------------------------
# Executor: refresh before the call
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_expiring_broker_token_is_refreshed_once_before_the_call_and_persisted(
    session_factory, configured, provider
):
    user_id, config_id = await ms_row(session_factory, ms_creds(expires_in=30))
    provider.on(MS_TOKEN_PATH, reply(200, ms_tokens()))
    provider.on(MS_INBOX_PATH, reply(200, {"value": []}))

    result = await ConnectorToolExecutor(session_factory=session_factory).execute(
        LIST_TOOL, {}, str(user_id)
    )

    assert result["ok"] is True, result
    # Refresh first, then exactly one Graph call carrying the new token.
    assert [r.url.path for r in provider.requests] == [MS_TOKEN_PATH, MS_INBOX_PATH]
    assert provider.forms(MS_TOKEN_PATH) == [{
        "grant_type": "refresh_token",
        "refresh_token": "ms-refresh-old-test",
        "client_id": MS_CLIENT_ID,
    }]
    assert provider.bearers(MS_INBOX_PATH) == ["Bearer ms-access-new-test"]
    saved = await stored(session_factory, config_id)
    assert saved is not None
    assert saved["access_token"] == "ms-access-new-test"
    assert saved["refresh_token"] == "ms-refresh-rotated-test"
    assert saved["expires_at"] > int(time.time()) + 3000
    assert saved["oauth_provider"] == "microsoft"


@pytest.mark.asyncio
async def test_fresh_broker_token_is_used_as_is(session_factory, configured, provider):
    user_id, config_id = await ms_row(session_factory, ms_creds())
    provider.on(MS_INBOX_PATH, reply(200, {"value": []}))

    result = await ConnectorToolExecutor(session_factory=session_factory).execute(
        LIST_TOOL, {}, str(user_id)
    )

    assert result["ok"] is True
    assert provider.to(MS_TOKEN_PATH) == []
    assert provider.bearers(MS_INBOX_PATH) == ["Bearer ms-access-old-test"]
    assert (await stored(session_factory, config_id))["access_token"] == "ms-access-old-test"  # type: ignore[index]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "token_reply",
    [reply(400, {"error": "invalid_grant"}), reply(401, {})],
)
async def test_refresh_failure_asks_for_a_reconnect_and_makes_no_provider_call(
    session_factory, configured, provider, token_reply
):
    creds = ms_creds(expires_in=30)
    user_id, config_id = await ms_row(session_factory, creds)
    provider.on(MS_TOKEN_PATH, token_reply)
    provider.on(MS_INBOX_PATH, reply(200, {"value": []}))

    result = await ConnectorToolExecutor(session_factory=session_factory).execute(
        LIST_TOOL, {}, str(user_id)
    )

    assert result == {"ok": False, "error": RECONNECT}
    assert provider.to(MS_INBOX_PATH) == []
    assert len(provider.to(MS_TOKEN_PATH)) == 1
    assert "ms-refresh-old-test" not in json.dumps(result)
    assert await stored(session_factory, config_id) == {**creds, broker.NEEDS_RECONNECT_KEY: True}


@pytest.mark.asyncio
async def test_refresh_outage_is_a_retry_later_error_not_a_reconnect(session_factory, configured, provider):
    user_id, _ = await ms_row(session_factory, ms_creds(expires_in=30))
    provider.on(MS_TOKEN_PATH, reply(500, {"error": "server_error"}))

    result = await ConnectorToolExecutor(session_factory=session_factory).execute(
        LIST_TOOL, {}, str(user_id)
    )

    assert result["ok"] is False
    assert "Try again shortly" in result["error"]
    assert "Reconnect" not in result["error"]
    assert provider.to(MS_INBOX_PATH) == []


@pytest.mark.asyncio
async def test_unconfigured_client_id_yields_a_clear_error_without_a_call(
    session_factory, configured, provider, monkeypatch
):
    monkeypatch.setattr(settings, "MICROSOFT_OAUTH_CLIENT_ID", "")
    user_id, _ = await ms_row(session_factory, ms_creds(expires_in=30))

    result = await ConnectorToolExecutor(session_factory=session_factory).execute(
        LIST_TOOL, {}, str(user_id)
    )

    assert result["ok"] is False
    assert "MICROSOFT_OAUTH_CLIENT_ID" in result["error"]
    assert provider.requests == []


@pytest.mark.asyncio
async def test_concurrent_executions_refresh_exactly_once(session_factory, configured, provider):
    user_id, config_id = await ms_row(session_factory, ms_creds(expires_in=30))
    provider.on(MS_TOKEN_PATH, reply(200, ms_tokens()))
    provider.on(MS_INBOX_PATH, reply(200, {"value": []}))
    executor = ConnectorToolExecutor(session_factory=session_factory)

    results = await asyncio.gather(
        executor.execute(LIST_TOOL, {}, str(user_id)),
        executor.execute(LIST_TOOL, {}, str(user_id)),
    )

    assert [r["ok"] for r in results] == [True, True]
    assert len(provider.to(MS_TOKEN_PATH)) == 1
    assert provider.bearers(MS_INBOX_PATH) == ["Bearer ms-access-new-test"] * 2
    assert (await stored(session_factory, config_id))["refresh_token"] == "ms-refresh-rotated-test"  # type: ignore[index]


# ---------------------------------------------------------------------------
# Executor: 401 mid-call
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_401_mid_call_forces_one_refresh_and_retries_the_write_once(
    session_factory, configured, provider
):
    user_id, config_id = await ms_row(session_factory, ms_creds())
    provider.on(MS_SEND_PATH, reply(401, {"error": {"code": "InvalidAuthenticationToken"}}), reply(202))
    provider.on(MS_TOKEN_PATH, reply(200, ms_tokens()))

    result = await ConnectorToolExecutor(session_factory=session_factory).execute(
        SEND_TOOL, dict(SEND_ARGS), str(user_id), approved=True
    )

    assert result["ok"] is True, result
    assert [r.url.path for r in provider.requests] == [MS_SEND_PATH, MS_TOKEN_PATH, MS_SEND_PATH]
    assert provider.bearers(MS_SEND_PATH) == ["Bearer ms-access-old-test", "Bearer ms-access-new-test"]
    # The retried write is the same request, sent once more.
    first, second = provider.to(MS_SEND_PATH)
    assert first.method == second.method == "POST"
    assert json.loads(first.content) == json.loads(second.content)
    assert json.loads(second.content)["message"]["toRecipients"] == [
        {"emailAddress": {"address": "bob@example.com"}}
    ]
    saved = await stored(session_factory, config_id)
    assert saved is not None and saved["access_token"] == "ms-access-new-test"


@pytest.mark.asyncio
async def test_a_second_401_is_returned_without_another_refresh(session_factory, configured, provider):
    user_id, _ = await ms_row(session_factory, ms_creds())
    provider.on(MS_INBOX_PATH, reply(401, {"error": {"code": "InvalidAuthenticationToken"}}))
    provider.on(MS_TOKEN_PATH, reply(200, ms_tokens()))

    result = await ConnectorToolExecutor(session_factory=session_factory).execute(
        LIST_TOOL, {}, str(user_id)
    )

    assert result["ok"] is False
    assert result["error"].startswith("HTTP 401 from Microsoft 365")
    assert len(provider.to(MS_INBOX_PATH)) == 2
    assert len(provider.to(MS_TOKEN_PATH)) == 1
    assert "ms-access" not in result["error"]


@pytest.mark.asyncio
async def test_401_then_refused_refresh_asks_for_a_reconnect(session_factory, configured, provider):
    user_id, _ = await ms_row(session_factory, ms_creds())
    provider.on(MS_SEND_PATH, reply(401, {"error": {"code": "InvalidAuthenticationToken"}}))
    provider.on(MS_TOKEN_PATH, reply(400, {"error": "invalid_grant"}))

    result = await ConnectorToolExecutor(session_factory=session_factory).execute(
        SEND_TOOL, dict(SEND_ARGS), str(user_id), approved=True
    )

    assert result == {"ok": False, "error": RECONNECT}
    assert len(provider.to(MS_SEND_PATH)) == 1


@pytest.mark.asyncio
async def test_403_missing_scope_is_not_retried(session_factory, configured, provider):
    user_id, _ = await ms_row(session_factory, ms_creds())
    provider.on(MS_INBOX_PATH, reply(403, {"error": {"code": "ErrorAccessDenied"}}))

    result = await ConnectorToolExecutor(session_factory=session_factory).execute(
        LIST_TOOL, {}, str(user_id)
    )

    assert result["ok"] is False
    assert result["error"].startswith("HTTP 403 from Microsoft 365")
    assert provider.to(MS_TOKEN_PATH) == []
    assert len(provider.to(MS_INBOX_PATH)) == 1


def test_retry_decision_reads_the_structured_status_not_the_message():
    from services.connectors.base import AuthenticationError
    from services.connectors.microsoft import MicrosoftConnector

    creds = {"oauth_provider": "microsoft", "refresh_token": "ms-refresh-test", "access_token": "a"}
    decide = ConnectorToolExecutor._should_retry_auth
    connector = MicrosoftConnector()
    # A 403 is a missing scope whatever its wording: never retried.
    scope = AuthenticationError("Access to that mailbox was refused.", status_code=403)
    assert decide(connector, "microsoft", creds, scope) is False
    # A 401 and a status-less auth failure (a vendor 200 error payload) are.
    assert decide(connector, "microsoft", creds, AuthenticationError("x", status_code=401)) is True
    vendor = AuthenticationError("Microsoft 365 refused the sign-in (InvalidAuthenticationToken).")
    assert decide(connector, "microsoft", creds, vendor) is True
    # The structured status wins over the text: a 401 whose message reads
    # like a 403 is still retried.
    reworded = AuthenticationError("HTTP 403 look-alike text", status_code=401)
    assert decide(connector, "microsoft", creds, reworded) is True
    # A mapped 403 re-raised without its attributes (Gmail's scope hint)
    # keeps the "HTTP 403 " prefix, which is the narrow fallback.
    wrapped = AuthenticationError("HTTP 403 from Microsoft 365: missing permission or scope. More.")
    assert decide(connector, "microsoft", creds, wrapped) is False
    # Rows the broker cannot refresh are never retried.
    assert decide(connector, "microsoft", {**creds, "refresh_token": None}, vendor) is False
    assert decide(connector, "canvas", creds, vendor) is False


@pytest.mark.asyncio
async def test_wrapped_gmail_403_without_status_is_not_retried(session_factory, configured, provider):
    """Gmail's reply re-raises the 403 from reading the original as a new
    AuthenticationError (scope hint, no status_code); the executor must not
    force a refresh or run the action a second time for it."""
    user, _ = await make_user(session_factory, "gmail-scope@example.com")
    await add_connector(session_factory, user.id, "google_workspace", google_broker_creds(), ("gmail.compose",))
    original_path = f"{GMAIL_LIST_PATH}/msg-test-1"
    provider.on(original_path, reply(403, {"error": {"code": 403, "status": "PERMISSION_DENIED"}}))

    result = await ConnectorToolExecutor(session_factory=session_factory).execute(
        "google_workspace.reply", {"message_id": "msg-test-1", "body": "Thanks"}, str(user.id), approved=True
    )

    assert result["ok"] is False
    assert result["error"].startswith("HTTP 403 ") and "gmail.read" in result["error"]
    assert provider.to(GOOGLE_TOKEN_PATH) == []
    assert len(provider.to(original_path)) == 1
    assert "ya29.broker-access-test" not in result["error"]


@pytest.mark.asyncio
async def test_401_on_a_broker_row_without_refresh_token_is_not_retried(session_factory, configured, provider):
    user_id, _ = await ms_row(session_factory, ms_creds(refresh_token=None))
    provider.on(MS_INBOX_PATH, reply(401, {"error": {"code": "InvalidAuthenticationToken"}}))

    result = await ConnectorToolExecutor(session_factory=session_factory).execute(
        LIST_TOOL, {}, str(user_id)
    )

    assert result["ok"] is False and result["error"].startswith("HTTP 401 ")
    assert provider.to(MS_TOKEN_PATH) == []
    assert len(provider.to(MS_INBOX_PATH)) == 1


@pytest.mark.asyncio
async def test_unapproved_always_confirm_write_never_refreshes_or_calls(session_factory, configured, provider):
    user_id, _ = await ms_row(session_factory, ms_creds(expires_in=30))

    result = await ConnectorToolExecutor(session_factory=session_factory).execute(
        SEND_TOOL, dict(SEND_ARGS), str(user_id)
    )

    assert result["ok"] is False and result["requires_approval"] is True
    assert provider.requests == []


@pytest.mark.asyncio
async def test_unexpected_errors_never_echo_their_text(session_factory, configured, provider, monkeypatch):
    user_id, _ = await ms_row(session_factory, ms_creds())
    from services.connectors.microsoft import MicrosoftConnector

    # authenticate() runs outside BaseConnector.execute's own wrapping, so
    # this reaches the executor's generic fallback.
    async def boom(self, credentials: dict[str, Any]) -> bool:
        raise RuntimeError("https://graph.microsoft.com/?access_token=ms-leak-test")

    monkeypatch.setattr(MicrosoftConnector, "authenticate", boom)

    result = await ConnectorToolExecutor(session_factory=session_factory).execute(
        LIST_TOOL, {}, str(user_id)
    )

    assert result == {"ok": False, "error": "Connector failure (RuntimeError)."}


# ---------------------------------------------------------------------------
# Executor: legacy pasted-token Google rows keep their own refresh path
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_legacy_pasted_google_row_refreshes_with_its_own_client(session_factory, configured, provider):
    user, _ = await make_user(session_factory, "legacy@example.com")
    creds = google_pasted_creds()
    config_id = await add_connector(session_factory, user.id, "google_workspace", creds, ("gmail.read",))
    provider.on(GMAIL_LIST_PATH, reply(401, {"error": {"code": 401, "status": "UNAUTHENTICATED"}}),
                reply(200, {"messages": []}))
    provider.on(GOOGLE_TOKEN_PATH, reply(200, {"access_token": "ya29.pasted-new-test", "expires_in": 3599}))

    result = await ConnectorToolExecutor(session_factory=session_factory).execute(
        "google_workspace.get_messages", {}, str(user.id)
    )

    assert result["ok"] is True, result
    # One refresh, by the connector, with the row's own client (never the
    # installation's broker client), then the retried Gmail call.
    assert [r.url.path for r in provider.requests] == [GMAIL_LIST_PATH, GOOGLE_TOKEN_PATH, GMAIL_LIST_PATH]
    form = provider.forms(GOOGLE_TOKEN_PATH)[0]
    assert form["client_id"] == "pasted-client-test"
    assert form["client_secret"] == "pasted-secret-test"
    assert form["refresh_token"] == "1//pasted-refresh-test"
    assert provider.bearers(GMAIL_LIST_PATH) == ["Bearer ya29.pasted-access-test", "Bearer ya29.pasted-new-test"]
    saved = await stored(session_factory, config_id)
    assert saved is not None
    assert saved["access_token"] == "ya29.pasted-new-test"
    assert saved["client_id"] == "pasted-client-test"
    assert "oauth_provider" not in saved


# ---------------------------------------------------------------------------
# A provider 403 names the scope and where to grant it
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_provider_403_names_the_scope_and_grant_more_access_without_retrying(
    session_factory, configured, provider
):
    user_id, _ = await ms_row(session_factory, ms_creds())
    provider.on(MS_INBOX_PATH, reply(403, {"error": {"code": "ErrorAccessDenied"}}))

    result = await ConnectorToolExecutor(session_factory=session_factory).execute(
        LIST_TOOL, {}, str(user_id)
    )

    assert result["ok"] is False
    error = result["error"]
    assert "HTTP 403 from Microsoft 365" in error
    assert "'mail.read'" in error
    assert "Grant more access on the Microsoft 365 card" in error
    assert "Do not retry" in error
    # A 403 is not a dead token: no refresh, no second call.
    assert [r.url.path for r in provider.requests] == [MS_INBOX_PATH]
    assert "ms-access-old-test" not in error and "ms-refresh-old-test" not in error


@pytest.mark.asyncio
async def test_google_403_names_the_gmail_scope(session_factory, configured, provider):
    user, _ = await make_user(session_factory, "google-403@example.com")
    await add_connector(session_factory, user.id, "google_workspace", google_broker_creds(), ("gmail.read",))
    provider.on(GMAIL_LIST_PATH, reply(403, {"error": {"code": 403, "status": "PERMISSION_DENIED"}}))

    result = await ConnectorToolExecutor(session_factory=session_factory).execute(
        "google_workspace.get_messages", {}, str(user.id)
    )

    assert result["ok"] is False
    assert "'gmail.read'" in result["error"]
    assert "Grant more access on the Google Workspace card" in result["error"]
    assert "broker-access-test" not in result["error"]


def test_auth_refusal_for_a_pasted_token_and_for_a_401():
    from services.agent.tool_registry import CONNECTOR_CATALOG, ResolvedTool
    from services.connectors.base import AuthenticationError

    spec = next(s for s in CONNECTOR_CATALOG["github"] if s.action == "create_issue")
    resolved = ResolvedTool("github", "create_issue", spec)
    forbidden = AuthenticationError("HTTP 403 from GitHub: missing permission or scope.", status_code=403)

    text = ConnectorToolExecutor._auth_refusal(forbidden, resolved, {"access_token": "ghp_test"})
    assert f"'{spec.required_scope}'" in text
    assert "give the GitHub token that permission" in text and "Do not retry" in text
    assert "ghp_test" not in text

    expired = AuthenticationError("HTTP 401 from GitHub: Reconnect GitHub in Connectors.", status_code=401)
    assert ConnectorToolExecutor._auth_refusal(expired, resolved, {}) == str(expired)


# ---------------------------------------------------------------------------
# Commit and revoke ordering
# ---------------------------------------------------------------------------


@pytest.fixture
def db_events():
    """Record ORM deletes and commits in order, for every session."""
    recorded: list[str] = []

    def before_flush(session, _context, _instances) -> None:
        for obj in session.deleted:
            recorded.append(f"delete:{type(obj).__name__}")

    def after_commit(_session) -> None:
        recorded.append("commit")

    event.listen(Session, "before_flush", before_flush)
    event.listen(Session, "after_commit", after_commit)
    yield recorded
    event.remove(Session, "before_flush", before_flush)
    event.remove(Session, "after_commit", after_commit)


@pytest.fixture
def revoke_spy(monkeypatch, db_events):
    """Wrap schedule_revoke: note when it runs (relative to the commits)
    and keep the real task so a test can await it."""
    calls: list[dict[str, Any]] = []
    real = broker.schedule_revoke

    def spy(connector_type: str, credentials: dict[str, Any], **kwargs: Any):
        db_events.append(f"revoke:{connector_type}")
        task = real(connector_type, credentials, **kwargs)
        calls.append({"type": connector_type, "credentials": credentials, "task": task, **kwargs})
        return task

    monkeypatch.setattr(broker, "schedule_revoke", spy)
    return calls


def _commit_between(events: list[str], first: str, last: str) -> bool:
    start, end = events.index(first), events.index(last)
    return start < end and "commit" in events[start:end]


@pytest.mark.asyncio
async def test_delete_commits_then_revokes_then_audits(wired, session_factory, configured, provider,
                                                     revoke_spy, db_events):
    user, token = await make_user(session_factory, "delete-google@example.com")
    creds = google_broker_creds()
    config_id = await add_connector(session_factory, user.id, "google_workspace", creds, ("gmail.read",))
    provider.on(GOOGLE_REVOKE_PATH, reply(200, {}))
    db_events.clear()

    response = await wired.delete(f"/api/connectors/{config_id}", headers=auth_headers(token))

    assert response.status_code == 204
    assert _commit_between(db_events, "delete:ConnectorConfig", "revoke:google_workspace")
    assert await stored(session_factory, config_id) is None
    assert len(revoke_spy) == 1
    call = revoke_spy[0]
    assert call["credentials"] == creds and call["user_id"] == user.id
    assert call["session_factory"] is session_factory
    await call["task"]

    # The provider saw one revoke of the refresh token, with no bearer.
    revokes = provider.to(GOOGLE_REVOKE_PATH)
    assert len(revokes) == 1
    assert revokes[0].method == "POST" and "authorization" not in revokes[0].headers
    assert provider.forms(GOOGLE_REVOKE_PATH) == [{"token": "1//broker-refresh-test"}]

    rows = await audit_rows(session_factory, user.id)
    deleted = [r for r in rows if r[0] == "connector_deleted"]
    assert deleted == [(
        "connector_deleted",
        "approved",
        "revoke scheduled",
        {"connector_type": "google_workspace", "connector_id": str(config_id), "revoke": "scheduled"},
    )]
    assert [r[:3] for r in rows if r[0] == "oauth_revoked"] == [("oauth_revoked", "approved", "revoked")]
    assert "broker-refresh-test" not in json.dumps([r[3] for r in rows])


@pytest.mark.asyncio
async def test_delete_of_a_connector_without_revoke_only_audits(wired, session_factory, configured, provider,
                                                               revoke_spy):
    user, token = await make_user(session_factory, "delete-canvas@example.com")
    config_id = await add_connector(session_factory, user.id, "canvas", CANVAS_CREDS, ("courses.read",))

    response = await wired.delete(f"/api/connectors/{config_id}", headers=auth_headers(token))

    assert response.status_code == 204
    assert revoke_spy == []
    assert provider.requests == []
    rows = await audit_rows(session_factory, user.id)
    assert [(r[0], r[2]) for r in rows] == [("connector_deleted", "revoke not_supported")]


@pytest.mark.asyncio
async def test_failed_delete_commit_never_revokes(wired, session_factory, configured, provider,
                                                 revoke_spy, monkeypatch):
    from sqlalchemy.ext.asyncio import AsyncSession

    user, token = await make_user(session_factory, "delete-fail@example.com")
    config_id = await add_connector(session_factory, user.id, "google_workspace", google_broker_creds(),
                                    ("gmail.read",))

    async def failing_commit(self) -> None:
        raise RuntimeError("commit failed")

    monkeypatch.setattr(AsyncSession, "commit", failing_commit)
    with pytest.raises(RuntimeError, match="commit failed"):
        await wired.delete(f"/api/connectors/{config_id}", headers=auth_headers(token))
    monkeypatch.undo()

    assert revoke_spy == []
    assert provider.requests == []
    assert await stored(session_factory, config_id) is not None


@pytest.mark.asyncio
async def test_account_deletion_schedules_a_revoke_per_revocable_connector(
    wired, session_factory, configured, provider, revoke_spy, db_events
):
    user, token = await make_user(session_factory, "leaving@example.com")
    google = google_broker_creds()
    await add_connector(session_factory, user.id, "google_workspace", google, ("gmail.read",))
    await add_connector(session_factory, user.id, "canvas", CANVAS_CREDS, ("courses.read",))
    provider.on(GOOGLE_REVOKE_PATH, reply(200, {}))
    db_events.clear()

    response = await wired.request(
        "DELETE", "/api/auth/account", json={"current_password": "password-123"}, headers=auth_headers(token)
    )

    assert response.status_code == 204
    assert _commit_between(db_events, "delete:User", "revoke:google_workspace")
    # Canvas implements no revoke, so only Google is scheduled.
    assert [(c["type"], c["credentials"], c["user_id"]) for c in revoke_spy] == [
        ("google_workspace", google, user.id)
    ]
    await revoke_spy[0]["task"]
    assert provider.forms(GOOGLE_REVOKE_PATH) == [{"token": "1//broker-refresh-test"}]
    async with session_factory() as s:
        assert (await s.execute(select(ConnectorConfig))).scalars().all() == []


@pytest.mark.asyncio
async def test_account_deletion_is_not_blocked_by_unreadable_credentials(
    wired, session_factory, configured, provider, revoke_spy
):
    user, token = await make_user(session_factory, "garbled@example.com")
    async with session_factory() as s:
        s.add(ConnectorConfig(
            user_id=user.id,
            connector_type="google_workspace",
            display_name="Garbled",
            auth_method=AuthMethod.oauth2,
            encrypted_credentials=b"not-a-valid-ciphertext",
            granted_scopes=["gmail.read"],
            permission_tier=PermissionTier.user_confirm,
            rate_limit_per_minute=60,
        ))
        await s.commit()

    response = await wired.request(
        "DELETE", "/api/auth/account", json={"current_password": "password-123"}, headers=auth_headers(token)
    )

    assert response.status_code == 204
    assert revoke_spy == []


# ---------------------------------------------------------------------------
# Shared grants are never revoked out from under another connector
# ---------------------------------------------------------------------------


def deleted_audit(rows: list[tuple[str, str, Any, Any]]) -> list[tuple[str, Any]]:
    return [(r[2], r[3]["revoke"]) for r in rows if r[0] == "connector_deleted"]


@pytest.mark.asyncio
async def test_delete_skips_the_revoke_when_another_connector_holds_the_same_token(
    wired, session_factory, configured, provider, revoke_spy
):
    user, token = await make_user(session_factory, "shared-token@example.com")
    creds = google_pasted_creds()
    first = await add_connector(session_factory, user.id, "google_workspace", creds, ("gmail.read",))
    second = await add_connector(session_factory, user.id, "google_workspace", creds, ("gmail.read",))

    response = await wired.delete(f"/api/connectors/{first}", headers=auth_headers(token))

    assert response.status_code == 204
    assert revoke_spy == []
    assert provider.requests == []
    assert await stored(session_factory, second) == creds
    assert deleted_audit(await audit_rows(session_factory, user.id)) == [
        ("revoke skipped_shared", "skipped_shared")
    ]


@pytest.mark.asyncio
async def test_delete_skips_the_revoke_when_another_users_broker_row_may_share_the_grant(
    wired, session_factory, configured, provider, revoke_spy
):
    # Different refresh tokens, but both signed in through this install's
    # Google client: Google revokes per account and client, so revoking
    # one could kill the other.
    user, token = await make_user(session_factory, "broker-a@example.com")
    other, _ = await make_user(session_factory, "broker-b@example.com")
    mine = await add_connector(session_factory, user.id, "google_workspace", google_broker_creds(),
                               ("gmail.read",))
    theirs = {**google_broker_creds(), "access_token": "ya29.other-test", "refresh_token": "1//other-test"}
    await add_connector(session_factory, other.id, "google_workspace", theirs, ("gmail.read",))

    response = await wired.delete(f"/api/connectors/{mine}", headers=auth_headers(token))

    assert response.status_code == 204
    assert revoke_spy == []
    assert deleted_audit(await audit_rows(session_factory, user.id)) == [
        ("revoke skipped_shared", "skipped_shared")
    ]


@pytest.mark.asyncio
async def test_delete_still_revokes_when_no_other_connector_shares_the_grant(
    wired, session_factory, configured, provider, revoke_spy
):
    # A pasted token of a different grant, and a row of another type that
    # happens to hold the same token value, do not hold the revoke back.
    user, token = await make_user(session_factory, "unshared@example.com")
    mine = await add_connector(session_factory, user.id, "google_workspace", google_pasted_creds(),
                               ("gmail.read",))
    other = {**google_pasted_creds(), "access_token": "ya29.else-test", "refresh_token": "1//else-test"}
    await add_connector(session_factory, user.id, "google_workspace", other, ("gmail.read",))
    await add_connector(session_factory, user.id, "canvas",
                        {**CANVAS_CREDS, "access_token": "ya29.pasted-access-test"}, ("courses.read",))
    provider.on(GOOGLE_REVOKE_PATH, reply(200, {}))

    response = await wired.delete(f"/api/connectors/{mine}", headers=auth_headers(token))

    assert response.status_code == 204
    assert [c["type"] for c in revoke_spy] == ["google_workspace"]
    await revoke_spy[0]["task"]
    assert provider.forms(GOOGLE_REVOKE_PATH) == [{"token": "1//pasted-refresh-test"}]
    assert deleted_audit(await audit_rows(session_factory, user.id)) == [("revoke scheduled", "scheduled")]


@pytest.mark.asyncio
async def test_delete_of_a_connector_whose_provider_has_no_revoke_schedules_nothing(
    wired, session_factory, configured, provider, revoke_spy
):
    # GitHub, Notion and Microsoft keep a revoke() that returns False (no
    # usable provider endpoint): no background task, no oauth_revoked event.
    user, token = await make_user(session_factory, "no-revoke@example.com")
    config_id = await add_connector(session_factory, user.id, "github", {"access_token": "ghp_test"},
                                    ("repo.read",))

    response = await wired.delete(f"/api/connectors/{config_id}", headers=auth_headers(token))

    assert response.status_code == 204
    assert revoke_spy == []
    assert provider.requests == []
    rows = await audit_rows(session_factory, user.id)
    assert [(r[0], r[2]) for r in rows] == [("connector_deleted", "revoke not_supported")]


def test_only_connectors_with_a_real_provider_revoke_support_it():
    from api.routes.connectors import supports_revoke

    assert supports_revoke("google_workspace") and supports_revoke("slack")
    assert not any(supports_revoke(key) for key in ("github", "notion", "microsoft", "canvas", "mcp"))


def test_grant_markers_cover_every_token_and_the_broker_provider():
    from api.routes.connectors import grant_markers

    slack = grant_markers({"bot_token": "xoxb-test-token", "user_token": "xoxp-test", "app_token": "xapp-t"})
    assert slack == {("token", "xoxb-test-token"), ("token", "xoxp-test")}
    assert ("oauth_provider", "google") in grant_markers(google_broker_creds())
    assert grant_markers({"access_token": "", "refresh_token": None, "expires_at": 5}) == frozenset()


@pytest.mark.asyncio
async def test_account_deletion_skips_shared_grants_and_revokes_a_duplicated_token_once(
    wired, session_factory, configured, provider, revoke_spy
):
    user, token = await make_user(session_factory, "leaving-shared@example.com")
    other, _ = await make_user(session_factory, "staying@example.com")
    pasted = google_pasted_creds()
    # Two of the leaving user's rows hold one token: revoked once.
    await add_connector(session_factory, user.id, "google_workspace", pasted, ("gmail.read",))
    await add_connector(session_factory, user.id, "google_workspace", pasted, ("gmail.read",))
    # A broker grant another user's broker row may share: left alone.
    await add_connector(session_factory, user.id, "google_workspace", google_broker_creds(), ("gmail.read",))
    theirs = {**google_broker_creds(), "access_token": "ya29.stay-test", "refresh_token": "1//stay-test"}
    kept = await add_connector(session_factory, other.id, "google_workspace", theirs, ("gmail.read",))
    provider.on(GOOGLE_REVOKE_PATH, reply(200, {}))

    response = await wired.request(
        "DELETE", "/api/auth/account", json={"current_password": "password-123"}, headers=auth_headers(token)
    )

    assert response.status_code == 204
    assert [(c["type"], c["credentials"]) for c in revoke_spy] == [("google_workspace", pasted)]
    await revoke_spy[0]["task"]
    assert provider.forms(GOOGLE_REVOKE_PATH) == [{"token": "1//pasted-refresh-test"}]
    assert await stored(session_factory, kept) == theirs


# ---------------------------------------------------------------------------
# POST /connectors/{id}/test
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_connection_test_refreshes_and_persists_a_rotated_broker_token(
    wired, session_factory, configured, provider
):
    user, token = await make_user(session_factory, "test-ms@example.com")
    config_id = await add_connector(session_factory, user.id, "microsoft", ms_creds(expires_in=30),
                                    ("mail.read",))
    provider.on(MS_TOKEN_PATH, reply(200, ms_tokens()))
    provider.on(MS_PROBE_PATH, reply(200, {"id": "inbox-id"}))

    response = await wired.post(f"/api/connectors/{config_id}/test", headers=auth_headers(token))

    assert response.json() == {"ok": True, "detail": "Connection verified."}
    assert [r.url.path for r in provider.requests] == [MS_TOKEN_PATH, MS_PROBE_PATH]
    assert provider.bearers(MS_PROBE_PATH) == ["Bearer ms-access-new-test"]
    saved = await stored(session_factory, config_id)
    assert saved is not None
    assert saved["access_token"] == "ms-access-new-test"
    assert saved["refresh_token"] == "ms-refresh-rotated-test"


@pytest.mark.asyncio
async def test_connection_test_with_a_refused_refresh_reports_reconnect_without_probing(
    wired, session_factory, configured, provider
):
    user, token = await make_user(session_factory, "test-ms-dead@example.com")
    creds = ms_creds(expires_in=30)
    config_id = await add_connector(session_factory, user.id, "microsoft", creds, ("mail.read",))
    provider.on(MS_TOKEN_PATH, reply(400, {"error": "invalid_grant"}))

    response = await wired.post(f"/api/connectors/{config_id}/test", headers=auth_headers(token))

    assert response.json() == {"ok": False, "detail": f"Authentication failed: {RECONNECT}"}
    assert provider.to(MS_PROBE_PATH) == []
    assert await stored(session_factory, config_id) == {**creds, broker.NEEDS_RECONNECT_KEY: True}

    # The card reads the flag from the list; a pasted-token row never has it.
    listed = await wired.get("/api/connectors/", headers=auth_headers(token))
    assert [(c["id"], c["needs_reconnect"]) for c in listed.json()] == [(str(config_id), True)]
    single = await wired.get(f"/api/connectors/{config_id}", headers=auth_headers(token))
    assert single.json()["needs_reconnect"] is True
    for secret in ("ms-refresh-old-test", "ms-access-old-test"):
        assert secret not in listed.text



@pytest.mark.asyncio
async def test_connection_test_persists_a_legacy_google_refresh(wired, session_factory, configured, provider):
    user, token = await make_user(session_factory, "test-google@example.com")
    config_id = await add_connector(session_factory, user.id, "google_workspace", google_pasted_creds(),
                                    ("gmail.read",))
    provider.on("/gmail/v1/users/me/profile", reply(401, {"error": {"status": "UNAUTHENTICATED"}}),
                reply(200, {"emailAddress": "me@example.com"}))
    provider.on(GOOGLE_TOKEN_PATH, reply(200, {"access_token": "ya29.pasted-new-test", "expires_in": 3599}))

    response = await wired.post(f"/api/connectors/{config_id}/test", headers=auth_headers(token))

    assert response.json()["ok"] is True
    assert len(provider.to(GOOGLE_TOKEN_PATH)) == 1
    saved = await stored(session_factory, config_id)
    assert saved is not None and saved["access_token"] == "ya29.pasted-new-test"


@pytest.mark.asyncio
async def test_connection_test_never_loops_on_a_dead_token(wired, session_factory, configured, provider):
    user, token = await make_user(session_factory, "test-google-dead@example.com")
    creds = google_pasted_creds()
    config_id = await add_connector(session_factory, user.id, "google_workspace", creds, ("gmail.read",))
    provider.on("/gmail/v1/users/me/profile", reply(401, {"error": {"status": "UNAUTHENTICATED"}}))
    provider.on(GOOGLE_TOKEN_PATH, reply(400, {"error": "invalid_grant"}))

    response = await wired.post(f"/api/connectors/{config_id}/test", headers=auth_headers(token))

    assert response.json()["ok"] is False
    assert len(provider.to(GOOGLE_TOKEN_PATH)) == 1
    assert len(provider.to("/gmail/v1/users/me/profile")) == 1
    assert await stored(session_factory, config_id) == creds
