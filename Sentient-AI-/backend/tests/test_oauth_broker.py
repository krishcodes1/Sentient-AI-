"""Tests for the OAuth broker (services/connectors/oauth.py): state hashing and
PKCE, consent URLs per provider shape, strict token-response validation,
scope mapping, the device-flow poller, token refresh, revoke, the background
task set, the redirect-base setting and the access-log filter.

Why it exists: the broker is the only code that holds OAuth codes, verifiers,
device codes and refresh tokens. These tests pin its security rules (hashed
single-use state, fixed redirect URI, no secret in a URL or log, strict
parsing, refresh exactly once under concurrency) with fake connector
definitions, so they do not depend on the GitHub or Microsoft connectors
other packages are writing.

Depends on services/connectors/oauth.py, oauth_config.py, models.oauth_state,
core.config and core.logging_config. The provider endpoints are an
``httpx.MockTransport`` behind the real policy-checked token client; no
network, no real credentials.
"""

from __future__ import annotations

import asyncio
import json
import logging
import uuid
from dataclasses import dataclass, field
from typing import Any, Callable, Optional
from urllib.parse import parse_qs, urlsplit

import httpx
import pytest
import pytest_asyncio
from pydantic import ValidationError
from sqlalchemy import select

import core.network_security as netsec
from core.config import Settings, settings
from core.network_security import NetworkPolicy
from core.security import decrypt_credentials, encrypt_credentials
from models.audit import AuditLog
from models.connector import AuthMethod, ConnectorConfig, PermissionTier
from models.oauth_state import OAuthState
from services.agent.permissions import ActionCategory
from services.connectors import oauth as broker
from services.connectors import registry
from services.connectors.base import AuthenticationError, BaseConnector, ConnectorError
from services.connectors.definition import (
    AuthSpec,
    ConnectorDefinition,
    CredentialField,
    NetworkSpec,
    OAuthSpec,
    ToolSpec,
    _schema,
)
from services.connectors.oauth_config import OAuthNotConfigured, redirect_uri, resolve_client
from tests.conftest import make_user

START = 1_800_000_000.0
CLIENT_ID = "client-id-test"
CLIENT_SECRET = "client-secret-test"
ACCESS = "access-token-test-1"
REFRESH = "refresh-token-test-1"


# ---------------------------------------------------------------------------
# Fake connectors and definitions (Google-, Microsoft- and GitHub-shaped)
# ---------------------------------------------------------------------------


class FakeOAuthConnector(BaseConnector):
    """Connector class for the fake definitions; revoke() is observable."""

    _ACTIONS = frozenset({"list_mail", "send_mail"})
    revoke_calls: list[str] = []
    revoke_result: bool = True
    fail_authenticate: bool = False

    @property
    def name(self) -> str:
        return "Fake"

    @property
    def connector_type(self) -> str:
        return "test"

    @property
    def required_scopes(self) -> list[str]:
        return []

    async def authenticate(self, credentials: dict[str, Any]) -> bool:
        if type(self).fail_authenticate:
            raise AuthenticationError("missing token")
        self._token = credentials["access_token"]
        self._authenticated = True
        return True

    async def _execute_action(self, action: str, params: dict[str, Any]) -> dict[str, Any]:
        return await self._dispatch(action, params)

    async def health_check(self) -> bool:
        return True

    async def revoke(self) -> bool:
        type(self).revoke_calls.append(self._token)
        return type(self).revoke_result

    async def list_mail(self, limit: Any = None) -> list[dict[str, Any]]:
        return []

    async def send_mail(self, to: str, *, user_confirmed: bool = False) -> dict[str, Any]:
        return {}


_ACTIONS = (
    ToolSpec("list_mail", "List mail.", ActionCategory.READ, _schema(limit={"type": "integer"}),
             required_scope="mail.read", starter=True),
    ToolSpec("send_mail", "Send mail.", ActionCategory.WRITE,
             _schema(to={"type": "string", "required": True}),
             required_scope="mail.send", always_confirm=True),
)


def _definition(key: str, label: str, auth: AuthSpec, hosts: dict[str, tuple[str, ...]]) -> ConnectorDefinition:
    return ConnectorDefinition(
        key=key,
        label=label,
        description=f"{label} mail.",
        icon="mail",
        auth=auth,
        network=NetworkSpec(policy_key=key, hosts=hosts),
        actions=_ACTIONS,
        connector_class=FakeOAuthConnector,
    )


# Google-shaped: browser flow, PKCE, a client secret and extra consent params
# (including a redirect_uri that must NOT override ours).
ACME = _definition(
    "acme_mail",
    "Acme Mail",
    AuthSpec(
        methods=("oauth", "token"),
        fields=(CredentialField("access_token", "Access token"),),
        oauth=OAuthSpec(
            provider="acme",
            authorize_url="https://auth.acme.test/authorize",
            token_url="https://auth.acme.test/token",
            revoke_url="https://auth.acme.test/revoke",
            client_id_setting="GOOGLE_OAUTH_CLIENT_ID",
            client_secret_setting="GOOGLE_OAUTH_CLIENT_SECRET",
            scope_map={
                "mail.read": ("https://acme.test/auth/mail.readonly",),
                "mail.send": ("https://acme.test/auth/mail.send",),
            },
            authorize_params={
                "access_type": "offline",
                "include_granted_scopes": "true",
                "prompt": "consent",
                "redirect_uri": "https://evil.test/steal",
            },
        ),
        token_auth_method="oauth2",
    ),
    {"auth.acme.test": ("/authorize", "/token", "/revoke")},
)

# Microsoft-shaped: public client, offline_access base scope, browser + device.
MSFT = _definition(
    "msft_mail",
    "Msft Mail",
    AuthSpec(
        methods=("oauth", "device"),
        oauth=OAuthSpec(
            provider="msft",
            authorize_url="https://login.msft.test/common/oauth2/v2.0/authorize",
            token_url="https://login.msft.test/common/oauth2/v2.0/token",
            device_code_url="https://login.msft.test/common/oauth2/v2.0/devicecode",
            client_id_setting="MICROSOFT_OAUTH_CLIENT_ID",
            scope_map={"mail.read": ("Mail.Read",), "mail.send": ("Mail.Send",)},
            base_scopes=("offline_access", "User.Read"),
        ),
        token_auth_method="oauth2",
    ),
    {"login.msft.test": ("/common/oauth2/v2.0/",)},
)

# GitHub-shaped: device flow only, no PKCE, errors answered with HTTP 200.
GH = _definition(
    "gh_code",
    "Gh Code",
    AuthSpec(
        methods=("device",),
        oauth=OAuthSpec(
            provider="gh",
            token_url="https://gh.test/login/oauth/access_token",
            device_code_url="https://gh.test/login/device/code",
            client_id_setting="GITHUB_OAUTH_CLIENT_ID",
            scope_map={"mail.read": ("repo",), "mail.send": ("repo", "workflow")},
            pkce=False,
        ),
        token_auth_method="oauth2",
    ),
    {"gh.test": ("/login/",)},
)

FAKES = {d.auth.oauth.provider: d for d in (ACME, MSFT, GH)}  # type: ignore[union-attr]
FAKES_BY_KEY = {d.key: d for d in (ACME, MSFT, GH)}


@dataclass
class FakeClock:
    now: float = START

    def __call__(self) -> float:
        return self.now


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
        factory = queue.pop(0) if len(queue) > 1 else queue[0]
        return factory(request)

    def forms(self, path: str) -> list[dict[str, str]]:
        return [
            {k: v[0] for k, v in parse_qs(r.content.decode()).items()}
            for r in self.requests
            if r.url.path == path
        ]


def reply(status: int = 200, body: Any = None, *, raw: Optional[bytes] = None,
          headers: Optional[dict[str, str]] = None) -> Callable[[httpx.Request], httpx.Response]:
    def factory(_request: httpx.Request) -> httpx.Response:
        if raw is not None:
            return httpx.Response(status, content=raw, headers=headers)
        return httpx.Response(status, json=body, headers=headers)
    return factory


def token_body(**overrides: Any) -> dict[str, Any]:
    body: dict[str, Any] = {
        "access_token": ACCESS,
        "token_type": "Bearer",
        "expires_in": 3600,
        "refresh_token": REFRESH,
    }
    body.update(overrides)
    return {k: v for k, v in body.items() if v is not None}


@pytest.fixture
def clock(monkeypatch) -> FakeClock:
    fake = FakeClock()
    monkeypatch.setattr(broker, "_clock", fake)
    return fake


@pytest.fixture
def sleeps(monkeypatch, clock) -> list[float]:
    """The device poller's sleeps; each advances the fake clock."""
    recorded: list[float] = []

    async def fake_sleep(seconds: float) -> None:
        recorded.append(seconds)
        clock.now += seconds

    monkeypatch.setattr(broker, "_sleep", fake_sleep)
    return recorded


@pytest.fixture
def configured(monkeypatch):
    for name in ("GOOGLE_OAUTH_CLIENT_ID", "MICROSOFT_OAUTH_CLIENT_ID", "GITHUB_OAUTH_CLIENT_ID"):
        monkeypatch.setattr(settings, name, CLIENT_ID)
    monkeypatch.setattr(settings, "GOOGLE_OAUTH_CLIENT_SECRET", CLIENT_SECRET)
    monkeypatch.setattr(settings, "OAUTH_REDIRECT_BASE", "http://127.0.0.1:3000")


@pytest.fixture
def fakes(monkeypatch):
    """Serve the fake definitions from the registry lookups the broker uses."""
    real_provider = registry.definition_for_provider
    real_key = registry.get_definition
    monkeypatch.setattr(
        registry, "definition_for_provider", lambda p: FAKES.get(p) or real_provider(p)
    )
    monkeypatch.setattr(registry, "get_definition", lambda k: FAKES_BY_KEY.get(k) or real_key(k))
    for d in (ACME, MSFT, GH):
        net = d.network
        monkeypatch.setitem(
            netsec.DEFAULT_POLICIES,
            net.policy_key,
            NetworkPolicy(
                connector_type=net.policy_key,
                allowed_hosts=list(net.hosts),
                allowed_paths={h: list(p) for h, p in net.hosts.items()},
                https_only=True,
            ),
        )
    FakeOAuthConnector.revoke_calls = []
    FakeOAuthConnector.revoke_result = True
    FakeOAuthConnector.fail_authenticate = False


@pytest.fixture
def provider(monkeypatch, fakes) -> FakeProvider:
    """Mock provider behind the REAL token client: the network-policy hook
    still runs on every request (DNS answered as public)."""
    fake = FakeProvider()
    monkeypatch.setattr(netsec, "check_ssrf", lambda url: netsec.SSRFCheckResult(safe=True))
    real_factory = broker._token_client

    def factory(definition: ConnectorDefinition) -> broker._TokenClient:
        client = real_factory(definition)
        client._http_client = httpx.AsyncClient(
            transport=httpx.MockTransport(fake.handle),
            event_hooks={"request": [client._enforce_network_policy]},
        )

        async def no_sleep(_seconds: float) -> None:
            return None

        client._sleep = no_sleep
        return client

    monkeypatch.setattr(broker, "_token_client", factory)
    return fake


@pytest_asyncio.fixture(autouse=True)
async def _stop_background_tasks():
    yield
    await broker.shutdown_background_tasks()


async def _flow(session_factory, flow_id: uuid.UUID) -> OAuthState:
    async with session_factory() as s:
        row = await s.get(OAuthState, flow_id)
        assert row is not None
        return row


async def _connectors(session_factory, user_id: uuid.UUID) -> list[ConnectorConfig]:
    async with session_factory() as s:
        return list(
            (await s.execute(select(ConnectorConfig).where(ConnectorConfig.user_id == user_id))).scalars()
        )


async def _audit_actions(session_factory, user_id: uuid.UUID) -> list[tuple[str, str, Any]]:
    async with session_factory() as s:
        rows = (
            await s.execute(select(AuditLog).where(AuditLog.user_id == user_id).order_by(AuditLog.seq))
        ).scalars()
        return [(r.action, r.status.value, r.response_summary) for r in rows]


def _query(url: str) -> dict[str, str]:
    return {k: v[0] for k, v in parse_qs(urlsplit(url).query).items()}


# ---------------------------------------------------------------------------
# State, PKCE, client config, redirect URI
# ---------------------------------------------------------------------------


def test_state_hash_is_keyed_and_never_the_raw_value():
    state = broker.new_state()
    digest = broker.hash_state(state)
    assert len(state) >= 43 and digest != state and len(digest) == 64
    assert broker.hash_state(state) == digest
    assert broker.hash_state(state + "x") != digest
    import hashlib

    assert digest != hashlib.sha256(state.encode()).hexdigest()


def test_state_hash_depends_on_the_encryption_key(monkeypatch):
    state = "s" * 43
    before = broker.hash_state(state)
    import base64
    import os

    monkeypatch.setattr(settings, "ENCRYPTION_KEY", base64.urlsafe_b64encode(os.urandom(32)).decode())
    assert broker.hash_state(state) != before


def test_pkce_challenge_is_s256_of_the_verifier():
    import base64
    import hashlib

    verifier = broker.new_pkce_verifier()
    assert 43 <= len(verifier) <= 128
    expected = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    assert broker.pkce_challenge(verifier) == expected


def test_resolve_client_names_the_missing_setting(monkeypatch):
    spec = ACME.auth.oauth
    assert spec is not None
    monkeypatch.setattr(settings, "GOOGLE_OAUTH_CLIENT_ID", "")
    monkeypatch.setattr(settings, "GOOGLE_OAUTH_CLIENT_SECRET", "")
    with pytest.raises(OAuthNotConfigured, match="GOOGLE_OAUTH_CLIENT_ID"):
        resolve_client(spec, label="Acme Mail")
    monkeypatch.setattr(settings, "GOOGLE_OAUTH_CLIENT_ID", CLIENT_ID)
    with pytest.raises(OAuthNotConfigured, match="GOOGLE_OAUTH_CLIENT_SECRET") as info:
        resolve_client(spec)
    assert CLIENT_ID not in str(info.value)
    monkeypatch.setattr(settings, "GOOGLE_OAUTH_CLIENT_SECRET", CLIENT_SECRET)
    client = resolve_client(spec)
    assert (client.client_id, client.client_secret) == (CLIENT_ID, CLIENT_SECRET)
    assert CLIENT_SECRET not in repr(client)


def test_public_client_needs_no_secret(monkeypatch):
    monkeypatch.setattr(settings, "MICROSOFT_OAUTH_CLIENT_ID", CLIENT_ID)
    client = resolve_client(MSFT.auth.oauth)  # type: ignore[arg-type]
    assert client.client_secret == ""


def test_redirect_uri_comes_only_from_the_setting(monkeypatch):
    monkeypatch.setattr(settings, "OAUTH_REDIRECT_BASE", "https://crawler.example.test")
    assert redirect_uri("acme") == "https://crawler.example.test/api/oauth/callback/acme"


@pytest.mark.parametrize(
    "value,expected",
    [
        ("http://127.0.0.1:3000", "http://127.0.0.1:3000"),
        ("http://127.0.0.1:3000/", "http://127.0.0.1:3000"),
        ("HTTPS://Crawler.Example.Test", "https://crawler.example.test"),
    ],
)
def test_redirect_base_accepts_origins(value, expected):
    assert Settings(OAUTH_REDIRECT_BASE=value).OAUTH_REDIRECT_BASE == expected


@pytest.mark.parametrize(
    "value",
    [
        "",
        "127.0.0.1:3000",
        "ftp://127.0.0.1",
        "javascript:alert(1)",
        "http://127.0.0.1:3000/app",
        "http://127.0.0.1:3000/?next=x",
        "http://127.0.0.1:3000#frag",
        "https://user:pw@evil.test",
        "http://127.0.0.1:99999",
    ],
)
def test_redirect_base_rejects_anything_but_an_origin(value):
    with pytest.raises(ValidationError):
        Settings(OAUTH_REDIRECT_BASE=value)


def test_oauth_settings_default_to_empty():
    fields = Settings.model_fields
    for name in (
        "GOOGLE_OAUTH_CLIENT_ID",
        "GOOGLE_OAUTH_CLIENT_SECRET",
        "MICROSOFT_OAUTH_CLIENT_ID",
        "GITHUB_OAUTH_CLIENT_ID",
    ):
        assert fields[name].default == ""
    assert fields["OAUTH_REDIRECT_BASE"].default == "http://127.0.0.1:3000"


# ---------------------------------------------------------------------------
# Consent URLs
# ---------------------------------------------------------------------------


def test_google_shaped_consent_url(configured):
    spec = ACME.auth.oauth
    assert spec is not None
    verifier = broker.new_pkce_verifier()
    url = broker.build_authorization_url(
        spec,
        client=resolve_client(spec),
        catalog_scopes=["mail.read", "mail.send"],
        state="state-value-0123456789abcdef",
        verifier=verifier,
    )
    assert url.startswith("https://auth.acme.test/authorize?")
    q = _query(url)
    assert q["client_id"] == CLIENT_ID
    assert q["response_type"] == "code"
    # Ours wins over the spec's authorize_params.
    assert q["redirect_uri"] == "http://127.0.0.1:3000/api/oauth/callback/acme"
    assert q["scope"] == "https://acme.test/auth/mail.readonly https://acme.test/auth/mail.send"
    assert q["state"] == "state-value-0123456789abcdef"
    assert q["code_challenge"] == broker.pkce_challenge(verifier)
    assert q["code_challenge_method"] == "S256"
    assert q["access_type"] == "offline" and q["include_granted_scopes"] == "true"
    assert q["prompt"] == "consent"
    # Neither the secret nor the verifier ever travels in the URL.
    assert CLIENT_SECRET not in url and verifier not in url
    assert "%20" in url and "+" not in urlsplit(url).query


def test_microsoft_shaped_consent_url_carries_base_scopes(configured):
    spec = MSFT.auth.oauth
    assert spec is not None
    url = broker.build_authorization_url(
        spec, client=resolve_client(spec), catalog_scopes=["mail.read"], state="s" * 43, verifier="v" * 43
    )
    q = _query(url)
    assert q["scope"] == "offline_access User.Read Mail.Read"
    assert q["redirect_uri"] == "http://127.0.0.1:3000/api/oauth/callback/msft"
    assert "client_secret" not in q


def test_real_google_definition_builds_a_pkce_consent_url(configured):
    google = registry.definition_for_provider("google")
    assert google is not None and google.auth.oauth is not None
    spec = google.auth.oauth
    url = broker.build_authorization_url(
        spec, client=resolve_client(spec), catalog_scopes=["gmail.read"], state="s" * 43, verifier="v" * 43
    )
    q = _query(url)
    assert url.startswith("https://accounts.google.com/")
    assert q["redirect_uri"] == "http://127.0.0.1:3000/api/oauth/callback/google"
    assert "gmail.readonly" in q["scope"]
    assert q["code_challenge_method"] == "S256"
    assert q["access_type"] == "offline"
    assert CLIENT_SECRET not in url


# ---------------------------------------------------------------------------
# Token responses and scope mapping
# ---------------------------------------------------------------------------


def test_token_response_happy_path():
    tokens = broker.parse_token_response(token_body(scope="a b,c"))
    assert tokens.access_token == ACCESS and tokens.refresh_token == REFRESH
    assert tokens.expires_in == 3600 and tokens.token_type == "Bearer"
    assert tokens.scopes == ("a", "b", "c")


def test_token_response_optional_fields_absent():
    tokens = broker.parse_token_response({"access_token": ACCESS})
    assert tokens.refresh_token is None and tokens.expires_in is None
    assert tokens.scopes is None and tokens.token_type == "Bearer"
    assert broker.parse_token_response({"access_token": ACCESS, "scope": ""}).scopes is None


@pytest.mark.parametrize(
    "payload",
    [
        {},
        {"access_token": ""},
        {"access_token": 123},
        {"access_token": ["x"]},
        {"access_token": ACCESS, "expires_in": "3600"},
        {"access_token": ACCESS, "expires_in": True},
        {"access_token": ACCESS, "expires_in": 0},
        {"access_token": ACCESS, "expires_in": 12.5},
        {"access_token": ACCESS, "refresh_token": 5},
        {"access_token": ACCESS, "scope": ["a", "b"]},
        {"access_token": ACCESS, "token_type": {"x": 1}},
        {"access_token": "x" * 20_000},
    ],
)
def test_token_response_rejects_malformed_fields(payload):
    with pytest.raises(broker.TokenEndpointError) as info:
        broker.parse_token_response(payload)
    assert info.value.code == "invalid_token_response"


def test_granted_scopes_follow_what_the_provider_returned():
    spec = ACME.auth.oauth
    assert spec is not None
    requested = ["mail.read", "mail.send"]
    only_read = ("https://acme.test/auth/mail.readonly", "openid")
    assert broker.granted_catalog_scopes(spec, requested, only_read) == ["mail.read"]
    both = ("https://acme.test/auth/mail.send", "https://acme.test/auth/mail.readonly")
    assert broker.granted_catalog_scopes(spec, requested, both) == requested
    assert broker.granted_catalog_scopes(spec, requested, ()) == []
    # No scope list at all: the grant is what was requested.
    assert broker.granted_catalog_scopes(spec, requested, None) == requested


def test_granted_scopes_need_every_provider_scope_of_a_catalog_scope():
    spec = GH.auth.oauth
    assert spec is not None
    assert broker.granted_catalog_scopes(spec, ["mail.send"], ("repo",)) == []
    assert broker.granted_catalog_scopes(spec, ["mail.send"], ("repo", "workflow")) == ["mail.send"]


def test_granted_scopes_match_case_and_url_forms():
    spec = MSFT.auth.oauth
    assert spec is not None
    returned = ("https://graph.msft.test/mail.read", "profile")
    assert broker.granted_catalog_scopes(spec, ["mail.read", "mail.send"], returned) == ["mail.read"]
    assert broker.granted_catalog_scopes(spec, ["mail.read"], ("MAIL.READ",)) == ["mail.read"]


def test_stored_credentials_shape(clock):
    spec = ACME.auth.oauth
    assert spec is not None
    tokens = broker.parse_token_response(token_body(scope="https://acme.test/auth/mail.readonly"))
    creds = broker.credentials_from_tokens(spec, tokens, requested=["mail.read"])
    assert creds == {
        "access_token": ACCESS,
        "refresh_token": REFRESH,
        "token_type": "Bearer",
        "expires_at": int(START) + 3600,
        "granted_scopes": ["https://acme.test/auth/mail.readonly"],
        "oauth_provider": "acme",
    }
    no_list = broker.credentials_from_tokens(
        spec, broker.parse_token_response({"access_token": ACCESS}), requested=["mail.read"]
    )
    assert no_list["granted_scopes"] == ["https://acme.test/auth/mail.readonly"]
    assert "refresh_token" not in no_list and "expires_at" not in no_list


def test_scopeless_reconnect_records_what_it_requested_but_a_refresh_keeps_the_old_list(clock):
    spec = ACME.auth.oauth
    assert spec is not None
    previous = _broker_creds()  # granted mail.readonly only
    no_scope = broker.parse_token_response({"access_token": ACCESS})
    reconnect = broker.credentials_from_tokens(
        spec, no_scope, requested=["mail.read", "mail.send"], previous=previous
    )
    assert reconnect["granted_scopes"] == [
        "https://acme.test/auth/mail.readonly",
        "https://acme.test/auth/mail.send",
    ]
    assert reconnect["refresh_token"] == REFRESH
    refresh = broker.credentials_from_tokens(spec, no_scope, requested=[], previous=previous)
    assert refresh["granted_scopes"] == ["https://acme.test/auth/mail.readonly"]


# ---------------------------------------------------------------------------
# Token client: policy armed, errors parsed, no secrets leaked
# ---------------------------------------------------------------------------


def test_token_client_is_armed_with_the_connector_policy():
    client = broker._token_client(ACME)
    assert client._network_policy_key == "acme_mail"
    assert client.name == "acme sign-in"


@pytest.mark.parametrize("provider_name", ["acme", "acme-id", "Acme.Test", "odd (name) [x]"])
def test_token_client_error_details_come_from_structured_attributes(provider_name):
    """Status and vendor code are read from the attributes base.http_error_for
    sets, so no provider name or message wording can break them."""
    from services.connectors.base import ConnectorError, http_error_for

    client = broker._TokenClient(provider_name)
    coded = http_error_for(client.name, httpx.Response(400, json={"error": "invalid_grant"}))
    assert broker._http_error_details(coded) == (400, "invalid_grant")
    bare = http_error_for(client.name, httpx.Response(401, json={}))
    assert broker._http_error_details(bare) == (401, None)
    limited = http_error_for(client.name, httpx.Response(429, json={"error": "slow_down"}))
    assert broker._http_error_details(limited) == (429, "slow_down")
    # A network failure never reached a status, whatever its text says.
    network = ConnectorError("HTTP 400 from acme sign-in (invalid_grant)")
    assert broker._http_error_details(network) == (None, None)


@pytest.mark.asyncio
async def test_token_client_parses_error_codes(provider):
    provider.on("/token", reply(400, {"error": "invalid_grant", "error_description": "Bad " + REFRESH}))
    client = broker._token_client(ACME)
    with pytest.raises(broker.TokenEndpointError) as info:
        await client.post_form("https://auth.acme.test/token", {"a": "b"})
    assert (info.value.code, info.value.status) == ("invalid_grant", 400)
    assert REFRESH not in str(info.value)
    request = provider.requests[-1]
    assert request.method == "POST" and request.url.host == "auth.acme.test"
    assert request.url.raw_path == b"/token"
    assert request.headers["accept"] == "application/json"
    assert "authorization" not in request.headers


@pytest.mark.asyncio
async def test_token_client_maps_200_errors_and_malformed_bodies(provider):
    provider.on(
        "/token",
        reply(200, {"error": "authorization_pending"}),
        reply(200, raw=b"<html>oops</html>"),
        reply(200, ["not", "an", "object"]),
        reply(200, {"error": "has spaces and <b>html</b>"}),
    )
    client = broker._token_client(ACME)
    codes = []
    for _ in range(4):
        with pytest.raises(broker.TokenEndpointError) as info:
            await client.post_form("https://auth.acme.test/token", {})
        codes.append(info.value.code)
    assert codes == ["authorization_pending", "malformed_response", "malformed_response", "unknown_error"]


@pytest.mark.asyncio
async def test_token_client_refuses_an_off_allowlist_endpoint(provider):
    client = broker._token_client(ACME)
    with pytest.raises(broker.TokenEndpointError) as info:
        await client.post_form("https://evil.test/token", {"code": "abc"})
    assert info.value.code is None
    assert provider.requests == []


@pytest.mark.asyncio
async def test_token_client_retries_a_short_429_once(provider):
    provider.on("/token", reply(429, {"error": "slow"}, headers={"Retry-After": "1"}), reply(200, token_body()))
    client = broker._token_client(ACME)
    payload = await client.post_form("https://auth.acme.test/token", {})
    assert payload["access_token"] == ACCESS
    assert len(provider.requests) == 2


# ---------------------------------------------------------------------------
# Start and callback (broker level; the HTTP surface is in test_oauth_routes)
# ---------------------------------------------------------------------------


async def _start(session_factory, user_id, definition=ACME, **draft: Any) -> tuple[broker.StartedFlow, dict[str, str]]:
    started = await broker.start_authorization(
        session_factory, user_id=user_id, definition=definition, draft=broker.FlowDraft(**draft)
    )
    return started, _query(started.authorization_url)


@pytest.mark.asyncio
async def test_start_stores_only_the_state_hash_and_an_encrypted_verifier(
    session_factory, configured, fakes, clock
):
    user, _ = await make_user(session_factory)
    started, q = await _start(session_factory, user.id)
    row = await _flow(session_factory, started.flow_id)
    assert row.state_hash == broker.hash_state(q["state"])
    assert q["state"] not in json.dumps({"h": row.state_hash, "d": row.draft})
    assert row.encrypted_secret is not None
    verifier = decrypt_credentials(row.encrypted_secret)
    assert verifier.encode() not in row.encrypted_secret
    assert broker.pkce_challenge(verifier) == q["code_challenge"]
    assert (row.user_id, row.provider, row.kind, row.status) == (user.id, "acme", "oauth", "pending")
    assert row.requested_scopes == ["mail.read"]  # default: read scopes
    assert broker._as_utc(row.expires_at).timestamp() == pytest.approx(START + 600)


@pytest.mark.asyncio
async def test_start_rejects_unknown_and_financial_scopes(session_factory, configured, fakes):
    user, _ = await make_user(session_factory)
    for scopes in (("mail.delete",), ("crypto.trade",)):
        with pytest.raises(broker.OAuthFlowError) as info:
            await _start(session_factory, user.id, granted_scopes=scopes)
        assert info.value.status_code == 422


@pytest.mark.asyncio
async def test_start_deletes_old_flows_in_one_statement(session_factory, configured, fakes, clock):
    user, _ = await make_user(session_factory)
    old, _ = await _start(session_factory, user.id)
    clock.now += 2 * 3600
    fresh, _ = await _start(session_factory, user.id)
    async with session_factory() as s:
        ids = set((await s.execute(select(OAuthState.id))).scalars())
    assert ids == {fresh.flow_id}
    assert old.flow_id not in ids


@pytest.mark.asyncio
async def test_start_caps_flows_in_flight(session_factory, configured, fakes, clock):
    user, _ = await make_user(session_factory)
    for _ in range(broker.MAX_PENDING_FLOWS_PER_USER):
        await _start(session_factory, user.id)
    with pytest.raises(broker.OAuthFlowError) as info:
        await _start(session_factory, user.id)
    assert info.value.status_code == 429


async def _callback(session_factory, state: Optional[str], code: Optional[str] = "auth-code-test",
                    provider_name: str = "acme", error: Optional[str] = None) -> bool:
    return await broker.complete_callback(
        session_factory, provider=provider_name, code=code, state=state, provider_error=error
    )


@pytest.mark.asyncio
async def test_callback_exchanges_the_code_and_saves_the_connector(
    session_factory, configured, provider, clock
):
    user, _ = await make_user(session_factory)
    provider.on("/token", reply(200, token_body(scope="https://acme.test/auth/mail.readonly")))
    started, q = await _start(
        session_factory, user.id, display_name="Work mail",
        permission_tier=PermissionTier.auto_approve, rate_limit_per_minute=45,
    )
    assert await _callback(session_factory, q["state"]) is True

    form = provider.forms("/token")[0]
    row = await _flow(session_factory, started.flow_id)
    assert form == {
        "grant_type": "authorization_code",
        "code": "auth-code-test",
        "redirect_uri": "http://127.0.0.1:3000/api/oauth/callback/acme",
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET,
        "code_verifier": form["code_verifier"],
    }
    assert broker.pkce_challenge(form["code_verifier"]) == q["code_challenge"]
    [config] = await _connectors(session_factory, user.id)
    assert config.connector_type == "acme_mail" and config.display_name == "Work mail"
    assert config.auth_method == AuthMethod.oauth2 and config.granted_scopes == ["mail.read"]
    assert config.permission_tier == PermissionTier.auto_approve and config.rate_limit_per_minute == 45
    creds = json.loads(decrypt_credentials(config.encrypted_credentials))
    assert creds["access_token"] == ACCESS and creds["refresh_token"] == REFRESH
    assert creds["oauth_provider"] == "acme" and creds["expires_at"] == int(START) + 3600
    assert (row.status, row.connector_id, row.encrypted_secret) == ("complete", config.id, None)
    actions = await _audit_actions(session_factory, user.id)
    assert actions == [("oauth_connected", "approved", None)]


@pytest.mark.asyncio
async def test_callback_state_is_single_use(session_factory, configured, provider, clock):
    user, _ = await make_user(session_factory)
    provider.on("/token", reply(200, token_body()))
    _, q = await _start(session_factory, user.id)
    assert await _callback(session_factory, q["state"]) is True
    assert await _callback(session_factory, q["state"]) is False
    assert len(provider.forms("/token")) == 1
    assert len(await _connectors(session_factory, user.id)) == 1
    assert ("oauth_failed", "blocked", "state_reused") in await _audit_actions(session_factory, user.id)


@pytest_asyncio.fixture
async def race_session_factory():
    """In-memory database whose sessions interleave on one connection
    WITHOUT the pool's rollback-on-return.

    The shared fixture's StaticPool rolls the single connection back when
    any session closes, which would undo another session's uncommitted
    UPDATE and make a race test meaningless. Here every statement sees the
    others' writes, so only the ``WHERE status = 'pending'`` guard can stop
    a second callback (on Postgres the row lock makes the loser re-check
    that same condition after the winner commits).
    """
    import models  # noqa: F401 - registers every table
    from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
    from sqlalchemy.pool import StaticPool

    from core.database import Base

    engine = create_async_engine(
        "sqlite+aiosqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
        pool_reset_on_return=None,
    )
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield async_sessionmaker(bind=engine, expire_on_commit=False)
    await engine.dispose()


@pytest.mark.asyncio
async def test_concurrent_callbacks_exchange_once(race_session_factory, configured, provider, clock, monkeypatch):
    session_factory = race_session_factory
    # Hold every callback at the consume step until all three have read the
    # row as pending, so they really race on the conditional UPDATE.
    arrived = 0
    everyone_read = asyncio.Event()
    real_transition = broker._transition

    async def gated_transition(*args: Any, **kwargs: Any) -> bool:
        nonlocal arrived
        if kwargs.get("require_unexpired"):
            arrived += 1
            if arrived == 3:
                everyone_read.set()
            await everyone_read.wait()
        return await real_transition(*args, **kwargs)

    monkeypatch.setattr(broker, "_transition", gated_transition)
    user, _ = await make_user(session_factory)
    provider.on("/token", reply(200, token_body()))
    _, q = await _start(session_factory, user.id)
    results = await asyncio.gather(*(_callback(session_factory, q["state"]) for _ in range(3)))
    assert sorted(results) == [False, False, True]
    assert len(provider.forms("/token")) == 1
    assert len(await _connectors(session_factory, user.id)) == 1


@pytest.mark.asyncio
async def test_callback_refuses_an_expired_state(session_factory, configured, provider, clock):
    user, _ = await make_user(session_factory)
    started, q = await _start(session_factory, user.id)
    clock.now += 601
    assert await _callback(session_factory, q["state"]) is False
    assert provider.requests == []
    row = await _flow(session_factory, started.flow_id)
    assert row.status == "expired" and row.encrypted_secret is None
    assert ("oauth_failed", "blocked", "expired") in await _audit_actions(session_factory, user.id)


@pytest.mark.asyncio
async def test_callback_refuses_a_provider_mismatch(session_factory, configured, provider, clock):
    user, _ = await make_user(session_factory)
    started, q = await _start(session_factory, user.id)
    assert await _callback(session_factory, q["state"], provider_name="msft") is False
    assert provider.requests == []
    # The flow is untouched and still completes on its own provider.
    assert (await _flow(session_factory, started.flow_id)).status == "pending"
    provider.on("/token", reply(200, token_body()))
    assert await _callback(session_factory, q["state"]) is True


@pytest.mark.asyncio
@pytest.mark.parametrize("state", [None, "", "short", "has spaces in it 0123456789", "x" * 200])
async def test_callback_refuses_missing_or_malformed_state(session_factory, configured, provider, state):
    assert await _callback(session_factory, state) is False
    assert provider.requests == []


@pytest.mark.asyncio
async def test_callback_with_an_unknown_state_is_refused(session_factory, configured, provider, clock):
    user, _ = await make_user(session_factory)
    await _start(session_factory, user.id)
    assert await _callback(session_factory, broker.new_state()) is False
    assert provider.requests == []
    assert await _audit_actions(session_factory, user.id) == []


@pytest.mark.asyncio
async def test_a_state_completes_only_its_own_flow(session_factory, configured, provider, clock):
    """CSRF: a callback is bound to the flow whose state it carries, whoever
    delivers it. Alice's state can only ever create Alice's connector with
    Alice's draft; Bob's flow is untouched."""
    alice, _ = await make_user(session_factory, "alice@example.com")
    bob, _ = await make_user(session_factory, "bob@example.com")
    provider.on("/token", reply(200, token_body()))
    alice_flow, alice_q = await _start(session_factory, alice.id, display_name="Alice mail")
    bob_flow, _ = await _start(session_factory, bob.id, display_name="Bob mail")
    assert await _callback(session_factory, alice_q["state"]) is True
    assert [c.display_name for c in await _connectors(session_factory, alice.id)] == ["Alice mail"]
    assert await _connectors(session_factory, bob.id) == []
    assert (await _flow(session_factory, bob_flow.flow_id)).status == "pending"
    assert (await _flow(session_factory, alice_flow.flow_id)).status == "complete"


@pytest.mark.asyncio
async def test_callback_handles_access_denied(session_factory, configured, provider, clock):
    user, _ = await make_user(session_factory)
    started, q = await _start(session_factory, user.id)
    assert await _callback(session_factory, q["state"], code=None, error="access_denied") is False
    row = await _flow(session_factory, started.flow_id)
    assert (row.status, row.error, row.encrypted_secret) == ("error", broker.MSG_CANCELLED, None)
    assert provider.requests == []
    # The state is spent: a later "real" code cannot reuse it.
    assert await _callback(session_factory, q["state"]) is False


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "response",
    [
        reply(200, raw=b"not json"),
        reply(200, {"token_type": "Bearer"}),
        reply(200, {"access_token": 42}),
        reply(200, {"access_token": ACCESS, "expires_in": "soon"}),
        reply(400, {"error": "invalid_grant"}),
        reply(500, {"error": "server_error"}),
    ],
)
async def test_callback_fails_cleanly_on_a_bad_token_response(
    session_factory, configured, provider, clock, response
):
    user, _ = await make_user(session_factory)
    provider.on("/token", response)
    started, q = await _start(session_factory, user.id)
    assert await _callback(session_factory, q["state"]) is False
    row = await _flow(session_factory, started.flow_id)
    assert (row.status, row.error, row.encrypted_secret) == ("error", broker.MSG_FAILED, None)
    assert await _connectors(session_factory, user.id) == []
    [(action, status, reason)] = await _audit_actions(session_factory, user.id)
    assert (action, status) == ("oauth_failed", "blocked") and reason.startswith("exchange_failed")


@pytest.mark.asyncio
async def test_callback_with_no_granted_scope_saves_nothing(session_factory, configured, provider, clock):
    user, _ = await make_user(session_factory)
    provider.on("/token", reply(200, token_body(scope="openid email")))
    started, q = await _start(session_factory, user.id)
    assert await _callback(session_factory, q["state"]) is False
    assert await _connectors(session_factory, user.id) == []
    assert (await _flow(session_factory, started.flow_id)).error == broker.MSG_NO_SCOPES


@pytest.mark.asyncio
async def test_partial_grant_saves_only_the_granted_scopes(session_factory, configured, provider, clock):
    user, _ = await make_user(session_factory)
    provider.on("/token", reply(200, token_body(scope="https://acme.test/auth/mail.readonly")))
    _, q = await _start(session_factory, user.id, granted_scopes=("mail.read", "mail.send"))
    assert q["scope"].split() == ["https://acme.test/auth/mail.readonly", "https://acme.test/auth/mail.send"]
    assert await _callback(session_factory, q["state"]) is True
    [config] = await _connectors(session_factory, user.id)
    assert config.granted_scopes == ["mail.read"]


async def _add_connector(session_factory, user_id, *, key="acme_mail", scopes=("mail.read",),
                         credentials: Optional[dict[str, Any]] = None, name="Existing") -> uuid.UUID:
    async with session_factory() as s:
        row = ConnectorConfig(
            user_id=user_id,
            connector_type=key,
            display_name=name,
            auth_method=AuthMethod.bearer_token,
            encrypted_credentials=encrypt_credentials(json.dumps(credentials or {"access_token": "pasted-token"})),
            granted_scopes=list(scopes),
            permission_tier=PermissionTier.admin_only,
            rate_limit_per_minute=12,
        )
        s.add(row)
        await s.commit()
        return row.id


@pytest.mark.asyncio
async def test_reconnect_updates_the_existing_row_with_the_union_of_scopes(
    session_factory, configured, provider, clock
):
    user, _ = await make_user(session_factory)
    existing = await _add_connector(session_factory, user.id)
    provider.on("/token", reply(200, token_body()))
    _, q = await _start(session_factory, user.id, granted_scopes=("mail.send",), connector_id=existing)
    assert q["scope"].split() == ["https://acme.test/auth/mail.readonly", "https://acme.test/auth/mail.send"]
    assert await _callback(session_factory, q["state"]) is True
    [config] = await _connectors(session_factory, user.id)
    assert config.id == existing
    assert config.granted_scopes == ["mail.read", "mail.send"]
    assert config.auth_method == AuthMethod.oauth2
    # Unchanged when the draft did not name them.
    assert (config.display_name, config.permission_tier, config.rate_limit_per_minute) == (
        "Existing", PermissionTier.admin_only, 12,
    )
    creds = json.loads(decrypt_credentials(config.encrypted_credentials))
    assert creds["access_token"] == ACCESS and creds["oauth_provider"] == "acme"


@pytest.mark.asyncio
async def test_reconnect_clears_the_needs_reconnect_flag(session_factory, configured, provider, clock):
    user, _ = await make_user(session_factory)
    dead = {"access_token": "dead-access-test", "refresh_token": REFRESH, "oauth_provider": "acme",
            broker.NEEDS_RECONNECT_KEY: True}
    existing = await _add_connector(session_factory, user.id, credentials=dead)
    provider.on("/token", reply(200, token_body()))
    _, q = await _start(session_factory, user.id, connector_id=existing)
    assert await _callback(session_factory, q["state"]) is True
    [config] = await _connectors(session_factory, user.id)
    creds = json.loads(decrypt_credentials(config.encrypted_credentials))
    assert creds["access_token"] == ACCESS
    assert not broker.needs_reconnect(creds)


@pytest.mark.asyncio
async def test_scopeless_reconnect_stores_the_provider_scopes_of_the_union(
    session_factory, configured, provider, clock
):
    user, _ = await make_user(session_factory)
    existing = await _add_connector(session_factory, user.id, credentials=_broker_creds())
    provider.on("/token", reply(200, token_body(refresh_token=None)))  # no scope, no refresh token
    _, q = await _start(session_factory, user.id, granted_scopes=("mail.send",), connector_id=existing)
    assert await _callback(session_factory, q["state"]) is True
    [config] = await _connectors(session_factory, user.id)
    assert config.granted_scopes == ["mail.read", "mail.send"]
    creds = json.loads(decrypt_credentials(config.encrypted_credentials))
    assert creds["granted_scopes"] == [
        "https://acme.test/auth/mail.readonly",
        "https://acme.test/auth/mail.send",
    ]
    assert creds["refresh_token"] == REFRESH  # kept from the reconnected row


@pytest.mark.asyncio
async def test_reconnect_cannot_target_another_users_row(session_factory, configured, fakes):
    alice, _ = await make_user(session_factory, "alice@example.com")
    mallory, _ = await make_user(session_factory, "mallory@example.com")
    alices = await _add_connector(session_factory, alice.id)
    with pytest.raises(broker.OAuthFlowError) as info:
        await _start(session_factory, mallory.id, connector_id=alices)
    assert info.value.status_code == 404


@pytest.mark.asyncio
async def test_reconnect_cannot_target_a_row_of_another_type(session_factory, configured, fakes):
    user, _ = await make_user(session_factory)
    other = await _add_connector(session_factory, user.id, key="msft_mail")
    with pytest.raises(broker.OAuthFlowError) as info:
        await _start(session_factory, user.id, connector_id=other)
    assert info.value.status_code == 404


@pytest.mark.asyncio
async def test_reconnect_fails_when_the_row_was_deleted_meanwhile(session_factory, configured, provider, clock):
    user, _ = await make_user(session_factory)
    existing = await _add_connector(session_factory, user.id)
    provider.on("/token", reply(200, token_body()))
    started, q = await _start(session_factory, user.id, connector_id=existing)
    async with session_factory() as s:
        await s.delete(await s.get(ConnectorConfig, existing))
        await s.commit()
    assert await _callback(session_factory, q["state"]) is False
    assert await _connectors(session_factory, user.id) == []
    assert (await _flow(session_factory, started.flow_id)).error == broker.MSG_CONNECTOR_GONE


# ---------------------------------------------------------------------------
# Device flow
# ---------------------------------------------------------------------------

DEVICE_CODE = "device-code-test-secret"


def device_body(**overrides: Any) -> dict[str, Any]:
    body = {
        "device_code": DEVICE_CODE,
        "user_code": "WDJB-MJHT",
        "verification_uri": "https://gh.test/login/device",
        "expires_in": 900,
        "interval": 5,
    }
    body.update(overrides)
    return body


async def _device(session_factory, user_id, definition=GH, **draft: Any) -> broker.DeviceFlowStarted:
    return await broker.start_device_flow(
        session_factory, user_id=user_id, definition=definition, draft=broker.FlowDraft(**draft)
    )


async def _drain() -> None:
    tasks = broker.background_tasks()
    if tasks:
        await asyncio.wait_for(asyncio.gather(*tasks, return_exceptions=True), timeout=5)


@pytest.mark.asyncio
async def test_device_flow_polls_through_pending_and_slow_down_to_success(
    session_factory, configured, provider, sleeps
):
    user, _ = await make_user(session_factory)
    provider.on("/login/device/code", reply(200, device_body()))
    provider.on(
        "/login/oauth/access_token",
        reply(200, {"error": "authorization_pending"}),
        reply(200, {"error": "slow_down", "interval": 10}),
        reply(200, {"error": "authorization_pending"}),
        reply(200, {"access_token": "gho_test", "token_type": "bearer", "scope": "repo"}),
    )
    started = await _device(session_factory, user.id)
    assert (started.user_code, started.verification_uri, started.interval) == (
        "WDJB-MJHT", "https://gh.test/login/device", 5,
    )
    assert len(broker.background_tasks()) == 1
    row = await _flow(session_factory, started.flow_id)
    assert row.kind == "device" and row.state_hash is None
    assert decrypt_credentials(row.encrypted_secret) == DEVICE_CODE
    assert DEVICE_CODE not in json.dumps(row.device_info)

    await _drain()

    assert sleeps == [5, 5, 10, 10]
    device_form = provider.forms("/login/device/code")[0]
    assert device_form == {"client_id": CLIENT_ID, "scope": "repo"}
    polls = provider.forms("/login/oauth/access_token")
    assert len(polls) == 4
    assert polls[0] == {
        "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
        "device_code": DEVICE_CODE,
        "client_id": CLIENT_ID,
    }
    row = await _flow(session_factory, started.flow_id)
    [config] = await _connectors(session_factory, user.id)
    assert (row.status, row.connector_id, row.encrypted_secret) == ("complete", config.id, None)
    assert row.device_info["interval"] == 10
    assert config.connector_type == "gh_code" and config.granted_scopes == ["mail.read"]
    creds = json.loads(decrypt_credentials(config.encrypted_credentials))
    assert creds == {
        "access_token": "gho_test",
        "token_type": "bearer",
        "granted_scopes": ["repo"],
        "oauth_provider": "gh",
    }
    assert broker.background_tasks() == frozenset()


@pytest.mark.asyncio
async def test_device_flow_handles_rfc_400_errors(session_factory, configured, provider, sleeps):
    """Microsoft answers pending polls with HTTP 400 (RFC 8628)."""
    user, _ = await make_user(session_factory)
    provider.on("/common/oauth2/v2.0/devicecode", reply(200, device_body(
        verification_uri="https://msft.test/devicelogin", interval=3)))
    provider.on(
        "/common/oauth2/v2.0/token",
        reply(400, {"error": "authorization_pending"}),
        reply(400, {"error": "slow_down"}),
        reply(200, token_body(scope="Mail.Read offline_access")),
    )
    started = await _device(session_factory, user.id, definition=MSFT)
    await _drain()
    assert sleeps == [3, 3, 8]
    assert provider.forms("/common/oauth2/v2.0/devicecode")[0]["scope"] == "offline_access User.Read Mail.Read"
    row = await _flow(session_factory, started.flow_id)
    assert row.status == "complete"
    [config] = await _connectors(session_factory, user.id)
    assert json.loads(decrypt_credentials(config.encrypted_credentials))["refresh_token"] == REFRESH


@pytest.mark.asyncio
async def test_device_flow_stops_at_expiry(session_factory, configured, provider, sleeps):
    user, _ = await make_user(session_factory)
    provider.on("/login/device/code", reply(200, device_body(expires_in=60, interval=20)))
    provider.on("/login/oauth/access_token", reply(200, {"error": "authorization_pending"}))
    started = await _device(session_factory, user.id)
    await _drain()
    assert len(provider.forms("/login/oauth/access_token")) == 2
    row = await _flow(session_factory, started.flow_id)
    assert (row.status, row.encrypted_secret) == ("expired", None)
    assert await _connectors(session_factory, user.id) == []
    assert ("oauth_failed", "blocked", "expired") in await _audit_actions(session_factory, user.id)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "error,status,message",
    [
        ("expired_token", "expired", broker.MSG_EXPIRED),
        ("access_denied", "error", broker.MSG_CANCELLED),
        ("authorization_declined", "error", broker.MSG_CANCELLED),
        ("incorrect_client_credentials", "error", broker.MSG_FAILED),
    ],
)
async def test_device_flow_terminal_errors(session_factory, configured, provider, sleeps, error, status, message):
    user, _ = await make_user(session_factory)
    provider.on("/login/device/code", reply(200, device_body()))
    provider.on("/login/oauth/access_token", reply(200, {"error": "authorization_pending"}), reply(200, {"error": error}))
    started = await _device(session_factory, user.id)
    await _drain()
    assert len(provider.forms("/login/oauth/access_token")) == 2
    row = await _flow(session_factory, started.flow_id)
    assert (row.status, row.error, row.encrypted_secret) == (status, message, None)
    assert await _connectors(session_factory, user.id) == []


@pytest.mark.asyncio
async def test_device_flow_gives_up_after_repeated_outages(session_factory, configured, provider, sleeps):
    user, _ = await make_user(session_factory)
    provider.on("/login/device/code", reply(200, device_body()))
    provider.on("/login/oauth/access_token", reply(503, {}))
    started = await _device(session_factory, user.id)
    await _drain()
    assert len(provider.forms("/login/oauth/access_token")) == broker.MAX_POLL_FAILURES
    assert (await _flow(session_factory, started.flow_id)).status == "error"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "body",
    [
        {"user_code": "X", "verification_uri": "https://gh.test/d", "expires_in": 900},
        device_body(verification_uri="http://gh.test/d"),
        device_body(verification_uri="javascript:alert(1)"),
        device_body(expires_in="900"),
        device_body(user_code="x" * 100),
    ],
)
async def test_device_start_rejects_a_malformed_device_response(session_factory, configured, provider, body):
    user, _ = await make_user(session_factory)
    provider.on("/login/device/code", reply(200, body))
    with pytest.raises(broker.TokenEndpointError):
        await _device(session_factory, user.id)
    async with session_factory() as s:
        assert (await s.execute(select(OAuthState))).first() is None
    assert broker.background_tasks() == frozenset()


@pytest.mark.asyncio
async def test_device_start_refuses_a_browser_only_connector(session_factory, configured, fakes):
    user, _ = await make_user(session_factory)
    with pytest.raises(broker.OAuthFlowError) as info:
        await _device(session_factory, user.id, definition=ACME)
    assert info.value.status_code == 422


@pytest.mark.asyncio
async def test_browser_start_refuses_a_device_only_connector(session_factory, configured, fakes):
    user, _ = await make_user(session_factory)
    with pytest.raises(broker.OAuthFlowError):
        await _start(session_factory, user.id, definition=GH)


@pytest.mark.asyncio
async def test_status_reports_device_fields_and_expiry(session_factory, configured, provider, sleeps, clock):
    user, _ = await make_user(session_factory)
    other, _ = await make_user(session_factory, "other@example.com")
    provider.on("/login/device/code", reply(200, device_body()))
    provider.on("/login/oauth/access_token", reply(200, {"error": "authorization_pending"}))
    started = await _device(session_factory, user.id)
    body = await broker.flow_status(session_factory, user_id=user.id, provider="gh", flow_id=started.flow_id)
    assert body == {
        "status": "pending",
        "user_code": "WDJB-MJHT",
        "verification_uri": "https://gh.test/login/device",
        "expires_at": started.expires_at.isoformat(),
        "interval": 5,
    }
    assert await broker.flow_status(session_factory, user_id=other.id, provider="gh", flow_id=started.flow_id) is None
    assert await broker.flow_status(session_factory, user_id=user.id, provider="acme", flow_id=started.flow_id) is None
    await broker.shutdown_background_tasks()
    clock.now += 901
    body = await broker.flow_status(session_factory, user_id=user.id, provider="gh", flow_id=started.flow_id)
    assert body is not None and body["status"] == "expired"


# ---------------------------------------------------------------------------
# ensure_fresh_credentials
# ---------------------------------------------------------------------------


def _broker_creds(**overrides: Any) -> dict[str, Any]:
    creds: dict[str, Any] = {
        "access_token": "old-access-test",
        "refresh_token": REFRESH,
        "expires_at": int(START) + 60,
        "token_type": "Bearer",
        "granted_scopes": ["https://acme.test/auth/mail.readonly"],
        "oauth_provider": "acme",
    }
    creds.update(overrides)
    return {k: v for k, v in creds.items() if v is not None}


async def _stored(session_factory, config_id: uuid.UUID) -> dict[str, Any]:
    async with session_factory() as s:
        row = await s.get(ConnectorConfig, config_id)
        assert row is not None
        return json.loads(decrypt_credentials(row.encrypted_credentials))


async def _fresh(session_factory, config_id, creds, *, key="acme_mail", force=False) -> dict[str, Any]:
    return await broker.ensure_fresh_credentials(
        session_factory, config_id=config_id, connector_type=key, credentials=creds, force=force
    )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "creds,key",
    [
        (_broker_creds(expires_at=int(START) + 3600), "acme_mail"),  # not expiring yet
        (_broker_creds(refresh_token=None), "acme_mail"),  # nothing to refresh with
        (_broker_creds(oauth_provider=None), "acme_mail"),  # legacy pasted token
        (_broker_creds(oauth_provider="msft"), "acme_mail"),  # another provider's row
        (_broker_creds(expires_at=None), "acme_mail"),  # no expiry known
        (_broker_creds(), "canvas"),  # not an OAuth connector
        (_broker_creds(), "no_such_connector"),
    ],
)
async def test_ensure_fresh_is_a_no_op_outside_its_cases(session_factory, configured, provider, clock, creds, key):
    result = await _fresh(session_factory, uuid.uuid4(), creds, key=key)
    assert result is creds
    assert provider.requests == []


@pytest.mark.asyncio
async def test_legacy_pasted_google_row_is_untouched(session_factory, configured, provider, clock):
    user, _ = await make_user(session_factory)
    pasted = {"access_token": "ya29.pasted-test", "refresh_token": "1//pasted-test",
              "client_id": "x", "client_secret": "y"}
    config_id = await _add_connector(session_factory, user.id, key="google_workspace", credentials=pasted)
    assert await _fresh(session_factory, config_id, pasted, key="google_workspace", force=True) is pasted
    assert provider.requests == []
    assert await _stored(session_factory, config_id) == pasted


@pytest.mark.asyncio
async def test_ensure_fresh_refreshes_and_persists(session_factory, configured, provider, clock):
    user, _ = await make_user(session_factory)
    creds = _broker_creds()
    config_id = await _add_connector(session_factory, user.id, credentials=creds)
    provider.on("/token", reply(200, {"access_token": "new-access-test", "expires_in": 3599}))
    result = await _fresh(session_factory, config_id, creds)
    assert result["access_token"] == "new-access-test"
    assert result["refresh_token"] == REFRESH  # not returned, so kept
    assert result["expires_at"] == int(START) + 3599
    assert result["granted_scopes"] == creds["granted_scopes"]
    assert await _stored(session_factory, config_id) == result
    assert provider.forms("/token") == [{
        "grant_type": "refresh_token",
        "refresh_token": REFRESH,
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET,
    }]


@pytest.mark.asyncio
async def test_ensure_fresh_keeps_a_rotated_refresh_token(session_factory, configured, provider, clock):
    user, _ = await make_user(session_factory)
    creds = _broker_creds()
    config_id = await _add_connector(session_factory, user.id, credentials=creds)
    provider.on("/token", reply(200, token_body(access_token="new-access-test", refresh_token="rotated-test",
                                                scope="https://acme.test/auth/mail.readonly openid")))
    result = await _fresh(session_factory, config_id, creds)
    assert result["refresh_token"] == "rotated-test"
    assert result["granted_scopes"] == ["https://acme.test/auth/mail.readonly", "openid"]
    assert (await _stored(session_factory, config_id))["refresh_token"] == "rotated-test"


@pytest.mark.asyncio
async def test_ensure_fresh_force_refreshes_a_valid_token(session_factory, configured, provider, clock):
    user, _ = await make_user(session_factory)
    creds = _broker_creds(expires_at=int(START) + 3600)
    config_id = await _add_connector(session_factory, user.id, credentials=creds)
    provider.on("/token", reply(200, {"access_token": "new-access-test"}))
    result = await _fresh(session_factory, config_id, creds, force=True)
    assert result["access_token"] == "new-access-test"
    # No expiry returned: the stale one must not survive.
    assert "expires_at" not in result


@pytest.mark.asyncio
async def test_concurrent_callers_refresh_exactly_once(session_factory, configured, provider, clock):
    user, _ = await make_user(session_factory)
    creds = _broker_creds()
    config_id = await _add_connector(session_factory, user.id, credentials=creds)

    def slow_token(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"access_token": "new-access-test", "expires_in": 3600})

    provider.on("/token", slow_token)
    results = await asyncio.gather(*(_fresh(session_factory, config_id, dict(creds)) for _ in range(5)))
    assert len(provider.forms("/token")) == 1
    assert {r["access_token"] for r in results} == {"new-access-test"}


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "response",
    [reply(400, {"error": "invalid_grant"}), reply(401, {"error": "invalid_token"}), reply(401, {}),
     reply(400, {}), reply(200, {"error": "invalid_grant"})],
)
async def test_rejected_refresh_asks_for_a_reconnect(session_factory, configured, provider, clock, response):
    user, _ = await make_user(session_factory)
    creds = _broker_creds()
    config_id = await _add_connector(session_factory, user.id, credentials=creds)
    provider.on("/token", response)
    with pytest.raises(broker.ReconnectRequired) as info:
        await _fresh(session_factory, config_id, creds)
    assert str(info.value) == "Acme Mail needs to be reconnected. Reconnect it in Connectors."
    assert REFRESH not in str(info.value)
    # The tokens are kept as they were; only the UI flag is added.
    assert await _stored(session_factory, config_id) == {**creds, broker.NEEDS_RECONNECT_KEY: True}


@pytest.mark.asyncio
async def test_a_successful_refresh_clears_the_needs_reconnect_flag(session_factory, configured, provider, clock):
    user, _ = await make_user(session_factory)
    creds = _broker_creds(**{broker.NEEDS_RECONNECT_KEY: True})
    config_id = await _add_connector(session_factory, user.id, credentials=creds)
    provider.on("/token", reply(200, {"access_token": "new-access-test", "expires_in": 3599}))
    result = await _fresh(session_factory, config_id, creds)
    assert broker.NEEDS_RECONNECT_KEY not in result
    assert not broker.needs_reconnect(await _stored(session_factory, config_id))


@pytest.mark.asyncio
async def test_needs_reconnect_flag_never_overwrites_a_reconnect_that_landed_meanwhile(
    session_factory, configured, provider, clock
):
    user, _ = await make_user(session_factory)
    reconnected = _broker_creds(access_token="reconnected-access-test", refresh_token="reconnected-refresh-test")
    config_id = await _add_connector(session_factory, user.id, credentials=reconnected)
    # The refresh that failed used the old token; the row now holds a new one.
    await broker._mark_needs_reconnect(session_factory, config_id, REFRESH)
    assert await _stored(session_factory, config_id) == reconnected


@pytest.mark.asyncio
async def test_needs_reconnect_flag_failure_still_surfaces_the_reconnect_error(
    session_factory, configured, provider, clock, monkeypatch
):
    user, _ = await make_user(session_factory)
    creds = _broker_creds()
    config_id = await _add_connector(session_factory, user.id, credentials=creds)
    provider.on("/token", reply(400, {"error": "invalid_grant"}))
    real_encrypt = broker.encrypt_credentials

    def broken_encrypt(_value: str) -> bytes:
        raise RuntimeError("disk full")

    monkeypatch.setattr(broker, "encrypt_credentials", broken_encrypt)
    with pytest.raises(broker.ReconnectRequired):
        await _fresh(session_factory, config_id, creds)
    monkeypatch.setattr(broker, "encrypt_credentials", real_encrypt)
    assert await _stored(session_factory, config_id) == creds


def test_needs_reconnect_reads_only_a_true_flag():
    assert broker.needs_reconnect({broker.NEEDS_RECONNECT_KEY: True})
    for value in (False, "true", 1, None):
        assert not broker.needs_reconnect({broker.NEEDS_RECONNECT_KEY: value})
    assert not broker.needs_reconnect({})


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "response",
    [reply(401, {"error": "invalid_client"}), reply(400, {"error": "unauthorized_client"}),
     reply(400, {"error": "invalid_request"}), reply(200, {"error": "incorrect_client_credentials"})],
)
async def test_refresh_refused_for_our_client_blames_the_server_config(
    session_factory, configured, provider, clock, response
):
    user, _ = await make_user(session_factory)
    creds = _broker_creds()
    config_id = await _add_connector(session_factory, user.id, credentials=creds)
    provider.on("/token", response)
    with pytest.raises(AuthenticationError) as info:
        await _fresh(session_factory, config_id, creds)
    message = str(info.value)
    assert message == broker.client_config_message("Acme Mail")
    assert "needs to be reconnected" not in message
    for secret in (REFRESH, CLIENT_ID, CLIENT_SECRET):
        assert secret not in message
    assert await _stored(session_factory, config_id) == creds


@pytest.mark.asyncio
async def test_outage_during_refresh_is_not_a_reconnect(session_factory, configured, provider, clock):
    user, _ = await make_user(session_factory)
    creds = _broker_creds()
    config_id = await _add_connector(session_factory, user.id, credentials=creds)
    provider.on("/token", reply(500, {"error": "server_error"}))
    with pytest.raises(ConnectorError) as info:
        await _fresh(session_factory, config_id, creds)
    assert not isinstance(info.value, AuthenticationError)
    assert REFRESH not in str(info.value)


@pytest.mark.asyncio
async def test_refresh_of_a_deleted_row_asks_for_a_reconnect(session_factory, configured, provider, clock):
    with pytest.raises(AuthenticationError):
        await _fresh(session_factory, uuid.uuid4(), _broker_creds())
    assert provider.requests == []


@pytest.mark.asyncio
async def test_persist_credentials_encrypts(session_factory):
    user, _ = await make_user(session_factory)
    config_id = await _add_connector(session_factory, user.id)
    await broker.persist_credentials(session_factory, config_id, {"access_token": "persisted-test"})
    async with session_factory() as s:
        row = await s.get(ConnectorConfig, config_id)
        assert row is not None and b"persisted-test" not in row.encrypted_credentials
    assert await _stored(session_factory, config_id) == {"access_token": "persisted-test"}


# ---------------------------------------------------------------------------
# Revoke and background tasks
# ---------------------------------------------------------------------------


@pytest.fixture
def fake_factory(monkeypatch, fakes):
    from services.connectors import factory

    def create(connector_type: str, credentials: dict[str, Any], **_kw: Any) -> BaseConnector:
        assert connector_type in FAKES_BY_KEY
        return FakeOAuthConnector()

    monkeypatch.setattr(factory, "create_connector", create)


@pytest.mark.asyncio
async def test_schedule_revoke_revokes_and_audits(session_factory, fake_factory):
    user, _ = await make_user(session_factory)
    task = broker.schedule_revoke("acme_mail", {"access_token": "gone-test"}, user_id=user.id,
                                  session_factory=session_factory)
    assert task is not None and task in broker.background_tasks()
    await task
    assert FakeOAuthConnector.revoke_calls == ["gone-test"]
    assert await _audit_actions(session_factory, user.id) == [("oauth_revoked", "approved", "revoked")]


@pytest.mark.asyncio
async def test_schedule_revoke_never_raises(session_factory, fake_factory):
    user, _ = await make_user(session_factory)
    FakeOAuthConnector.fail_authenticate = True
    task = broker.schedule_revoke("acme_mail", {}, user_id=user.id, session_factory=session_factory)
    assert task is not None
    await task
    assert await _audit_actions(session_factory, user.id) == [("oauth_revoked", "blocked", "failed")]
    # A user already deleted (account deletion) cannot be audited: logged only.
    gone = broker.schedule_revoke("acme_mail", {"access_token": "t"}, user_id=uuid.uuid4(),
                                  session_factory=session_factory)
    assert gone is not None
    await gone
    assert gone.exception() is None


def test_schedule_revoke_without_a_loop_returns_none():
    assert broker.schedule_revoke("acme_mail", {}, user_id=uuid.uuid4()) is None


@pytest.mark.asyncio
async def test_shutdown_cancels_background_tasks():
    started = asyncio.Event()

    async def forever() -> None:
        started.set()
        await asyncio.sleep(3600)

    task = broker.spawn(forever(), name="test-forever")
    await started.wait()
    await broker.shutdown_background_tasks()
    assert task.cancelled()
    assert broker.background_tasks() == frozenset()


@pytest.mark.asyncio
async def test_a_failing_background_task_is_logged_and_forgotten(monkeypatch):
    events: list[tuple[str, dict[str, Any]]] = []
    monkeypatch.setattr(broker.logger, "error", lambda event, **kw: events.append((event, kw)))

    async def boom() -> None:
        raise RuntimeError("boom")

    task = broker.spawn(boom(), name="test-boom")
    await asyncio.gather(task, return_exceptions=True)
    await asyncio.sleep(0)
    assert task not in broker.background_tasks()
    assert events == [("oauth_background_task_failed", {"task": "test-boom", "error_type": "RuntimeError"})]


# ---------------------------------------------------------------------------
# Access log
# ---------------------------------------------------------------------------


def _access_record(path: str) -> logging.LogRecord:
    return logging.LogRecord(
        "uvicorn.access", logging.INFO, __file__, 1,
        '%s - "%s %s HTTP/%s" %d', ("203.0.113.9:5000", "GET", path, "1.1", 200), None,
    )


def test_access_log_filter_strips_the_callback_query():
    from core.logging_config import OAuthCallbackQueryFilter

    record = _access_record("/api/oauth/callback/google?code=4/secret-code&state=secret-state")
    assert OAuthCallbackQueryFilter().filter(record) is True
    line = record.getMessage()
    assert "secret-code" not in line and "secret-state" not in line
    assert "/api/oauth/callback/google" in line and '200' in line


def test_access_log_filter_leaves_other_paths_alone():
    from core.logging_config import OAuthCallbackQueryFilter

    record = _access_record("/api/connectors/?limit=5")
    OAuthCallbackQueryFilter().filter(record)
    assert "/api/connectors/?limit=5" in record.getMessage()


def test_access_log_filter_handles_preformatted_messages():
    from core.logging_config import OAuthCallbackQueryFilter

    record = logging.LogRecord(
        "uvicorn.access", logging.INFO, __file__, 1,
        '1.2.3.4 - "GET /api/oauth/callback/gh?code=abc&state=def HTTP/1.1" 400', None, None,
    )
    OAuthCallbackQueryFilter().filter(record)
    assert record.getMessage() == '1.2.3.4 - "GET /api/oauth/callback/gh?[redacted] HTTP/1.1" 400'


def test_configure_logging_installs_the_filter_once():
    from core.logging_config import OAuthCallbackQueryFilter, configure_logging

    configure_logging()
    configure_logging()
    filters = [f for f in logging.getLogger("uvicorn.access").filters if isinstance(f, OAuthCallbackQueryFilter)]
    assert len(filters) == 1


@pytest.mark.asyncio
async def test_reconnect_takes_back_the_rows_low_risk_grants(session_factory, configured, provider, clock):
    """New credentials are new consent: a reconnect ends the connection's
    low-risk grants (permission tiers), in the same transaction, audited."""
    from datetime import datetime, timedelta, timezone

    from sqlalchemy import select

    from models.audit import AuditLog
    from models.permission_grant import PermissionGrantRow

    user, _ = await make_user(session_factory)
    existing = await _add_connector(session_factory, user.id)
    now = datetime.now(timezone.utc)
    async with session_factory() as s:
        s.add(
            PermissionGrantRow(
                user_id=user.id,
                connector_id=existing,
                kind="low_risk",
                granted_at=now,
                expires_at=now + timedelta(days=7),
            )
        )
        await s.commit()
    provider.on("/token", reply(200, token_body()))
    _, q = await _start(session_factory, user.id, connector_id=existing)
    assert await _callback(session_factory, q["state"]) is True
    async with session_factory() as s:
        [grant] = (await s.execute(select(PermissionGrantRow))).scalars().all()
        chains = [
            r.reasoning_chain or {}
            for r in (await s.execute(select(AuditLog).where(AuditLog.user_id == user.id))).scalars()
        ]
    assert grant.revoked_at is not None
    [revoked] = [c for c in chains if c.get("event") == "permission_grant_revoked"]
    assert revoked["count"] == 1 and revoked["reason"] == "credentials replaced"
    from services.audit import _sanitize

    assert revoked["connector_id"] == _sanitize(str(existing))
