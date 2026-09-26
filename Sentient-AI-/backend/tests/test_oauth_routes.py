"""Tests for the OAuth broker's HTTP surface (api/routes/oauth.py): start,
callback, status and device routes through the real app and middleware.

Why it exists: the callback is the one connector route with no bearer token.
These tests prove it renders one static page with no script for every
failure, never echoes the code or state, carries ``Referrer-Policy:
no-referrer`` and ``Cache-Control: no-store``, shares the login rate-limit
bucket, that the authenticated routes answer 404 for unknown providers
and other users' flows and 503 when a client id is not configured, and that
on a server with a non-loopback redirect base only the browser that started
a flow (it holds the binding cookie) can finish it.

Depends on the conftest ``client``/``make_user``/``auth_headers`` fixtures
(ASGI, no lifespan) and the fake definitions and mock provider from
tests/test_oauth_broker.py. No network.
"""

from __future__ import annotations

import asyncio
import json
import uuid
from urllib.parse import parse_qs, urlsplit

import pytest
from sqlalchemy import select

from api.routes import oauth as oauth_routes
from core.config import settings
from core.security import decrypt_credentials
from main import app
from models.connector import ConnectorConfig
from services.connectors import oauth as broker
from services.connectors.oauth_config import redirect_base_is_loopback
from tests.conftest import auth_headers, make_user
from tests import test_oauth_broker as fx
from tests.test_oauth_broker import (
    ACCESS,
    CLIENT_ID,
    CLIENT_SECRET,
    device_body,
    reply,
    token_body,
)

# Shared fixtures (the fake definitions, mock provider, fake clock), bound
# here so pytest finds them for this module.
clock = fx.clock
configured = fx.configured
fakes = fx.fakes
provider = fx.provider
sleeps = fx.sleeps
_stop_background_tasks = fx._stop_background_tasks

CODE = "auth-code-route-test"


@pytest.fixture
def wired(client, session_factory):
    """Point the broker routes at the test database."""
    app.dependency_overrides[oauth_routes.session_factory_dependency] = lambda: session_factory
    return client


def _query(url: str) -> dict[str, str]:
    return {k: v[0] for k, v in parse_qs(urlsplit(url).query).items()}


async def _start(client, token: str, provider_name: str = "acme", **body):
    return await client.post(f"/api/oauth/{provider_name}/start", json=body, headers=auth_headers(token))


# ---------------------------------------------------------------------------
# Start
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_start_returns_a_consent_url_with_the_fixed_redirect(wired, session_factory, configured, fakes, clock):
    _, token = await make_user(session_factory)
    response = await wired.post(
        "/api/oauth/acme/start",
        json={"display_name": "Work", "granted_scopes": ["mail.read", "mail.send"]},
        headers={**auth_headers(token), "Host": "evil.test", "X-Forwarded-Host": "evil.test"},
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert set(body) == {"flow_id", "authorization_url", "expires_at"}
    q = _query(body["authorization_url"])
    assert q["redirect_uri"] == "http://127.0.0.1:3000/api/oauth/callback/acme"
    assert q["client_id"] == CLIENT_ID
    assert CLIENT_SECRET not in body["authorization_url"]
    uuid.UUID(body["flow_id"])
    # Loopback redirect base: nothing to bind, so no cookie.
    assert "set-cookie" not in response.headers


@pytest.mark.asyncio
async def test_start_answers_503_naming_the_missing_setting(wired, session_factory, fakes, monkeypatch):
    _, token = await make_user(session_factory)
    monkeypatch.setattr(settings, "GOOGLE_OAUTH_CLIENT_ID", "")
    response = await _start(wired, token)
    assert response.status_code == 503
    assert "GOOGLE_OAUTH_CLIENT_ID" in response.json()["detail"]
    monkeypatch.setattr(settings, "MICROSOFT_OAUTH_CLIENT_ID", "")
    response = await wired.post("/api/oauth/msft/device", json={}, headers=auth_headers(token))
    assert response.status_code == 503
    assert "MICROSOFT_OAUTH_CLIENT_ID" in response.json()["detail"]


@pytest.mark.asyncio
@pytest.mark.parametrize("path", ["/api/oauth/nope/start", "/api/oauth/nope/device"])
async def test_unknown_provider_is_404(wired, session_factory, configured, fakes, path):
    _, token = await make_user(session_factory)
    response = await wired.post(path, json={}, headers=auth_headers(token))
    assert response.status_code == 404
    assert response.json()["detail"] == "Unknown sign-in provider"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "path", ["/api/oauth/UPPER/start", "/api/oauth/UPPER/device", "/api/oauth/a/start", "/api/oauth/1acme/device"]
)
async def test_malformed_provider_is_422_before_any_lookup(wired, session_factory, configured, fakes, path, monkeypatch):
    """A segment that is not a registry-shaped name fails path validation."""
    _, token = await make_user(session_factory)
    looked_up: list[str] = []
    monkeypatch.setattr(broker, "oauth_definition", lambda provider: looked_up.append(provider))
    response = await wired.post(path, json={}, headers=auth_headers(token))
    assert response.status_code == 422
    assert looked_up == []


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "body",
    [
        {"granted_scopes": ["mail.delete"]},
        {"granted_scopes": ["x" * 500]},
        {"rate_limit_per_minute": 0},
        {"rate_limit_per_minute": 601},
        {"permission_tier": "root"},
        {"display_name": "a\x00b"},
        {"connector_id": "not-a-uuid"},
    ],
)
async def test_start_validates_the_draft(wired, session_factory, configured, fakes, body):
    _, token = await make_user(session_factory)
    response = await _start(wired, token, **body)
    assert response.status_code == 422


@pytest.mark.asyncio
async def test_start_for_another_users_connector_is_404(wired, session_factory, configured, fakes):
    alice, _ = await make_user(session_factory, "alice@example.com")
    _, mallory_token = await make_user(session_factory, "mallory@example.com")
    alices = await fx._add_connector(session_factory, alice.id)
    response = await _start(wired, mallory_token, connector_id=str(alices))
    assert response.status_code == 404


# ---------------------------------------------------------------------------
# Callback
# ---------------------------------------------------------------------------


def _assert_static_page(response) -> None:
    assert response.headers["content-type"].startswith("text/html")
    assert response.headers["referrer-policy"] == "no-referrer"
    assert response.headers["cache-control"] == "no-store"
    assert "script-src 'self'" in response.headers["content-security-policy"]
    text = response.text.lower()
    assert "<script" not in text and "javascript:" not in text and " on" + "load=" not in text
    assert "<style>" in text


@pytest.mark.asyncio
async def test_callback_success_page_and_status(wired, session_factory, configured, provider, clock):
    user, token = await make_user(session_factory)
    provider.on("/token", reply(200, token_body()))
    started = (await _start(wired, token, display_name="Mine")).json()
    state = _query(started["authorization_url"])["state"]

    response = await wired.get("/api/oauth/callback/acme", params={"code": CODE, "state": state})
    assert response.status_code == 200
    _assert_static_page(response)
    assert "Connected" in response.text
    assert CODE not in response.text and state not in response.text

    status = await wired.get(
        "/api/oauth/acme/status", params={"flow": started["flow_id"]}, headers=auth_headers(token)
    )
    assert status.status_code == 200
    body = status.json()
    async with session_factory() as s:
        config = (await s.execute(select(ConnectorConfig).where(ConnectorConfig.user_id == user.id))).scalar_one()
    assert body == {"status": "complete", "connector_id": str(config.id)}
    assert json.loads(decrypt_credentials(config.encrypted_credentials))["access_token"] == ACCESS


@pytest.mark.asyncio
async def test_every_callback_failure_renders_the_same_page(wired, session_factory, configured, provider, clock):
    _, token = await make_user(session_factory)
    provider.on("/token", reply(200, token_body()))
    started = (await _start(wired, token)).json()
    state = _query(started["authorization_url"])["state"]
    other_state = broker.new_state()

    failures = [
        {},  # nothing at all
        {"code": CODE},  # no state
        {"code": CODE, "state": other_state},  # unknown state (CSRF)
        {"error": "access_denied", "error_description": "<script>x</script>", "state": other_state},
    ]
    bodies = set()
    for params in failures:
        response = await wired.get("/api/oauth/callback/acme", params=params)
        assert response.status_code == 400
        _assert_static_page(response)
        assert CODE not in response.text and other_state not in response.text
        assert "<script>x" not in response.text
        bodies.add(response.text)
    # Replay after success, and a mismatched provider, look identical too.
    ok = await wired.get("/api/oauth/callback/acme", params={"code": CODE, "state": state})
    assert ok.status_code == 200
    for provider_name in ("acme", "msft"):
        replay = await wired.get(f"/api/oauth/callback/{provider_name}", params={"code": CODE, "state": state})
        assert replay.status_code == 400
        bodies.add(replay.text)
    unknown = await wired.get("/api/oauth/callback/nope", params={"code": CODE, "state": state})
    assert unknown.status_code == 404
    _assert_static_page(unknown)
    bodies.add(unknown.text)
    assert len(bodies) == 1
    assert bodies == {oauth_routes.FAILURE_PAGE}


@pytest.mark.asyncio
async def test_callback_handles_provider_denial(wired, session_factory, configured, provider, clock):
    _, token = await make_user(session_factory)
    started = (await _start(wired, token)).json()
    state = _query(started["authorization_url"])["state"]
    response = await wired.get("/api/oauth/callback/acme", params={"error": "access_denied", "state": state})
    assert response.status_code == 400
    assert response.text == oauth_routes.FAILURE_PAGE
    status = await wired.get(
        "/api/oauth/acme/status", params={"flow": started["flow_id"]}, headers=auth_headers(token)
    )
    assert status.json() == {"status": "error", "error": broker.MSG_CANCELLED}
    assert provider.requests == []


@pytest.mark.asyncio
async def test_callback_with_repeated_params_is_refused(wired, session_factory, configured, provider, clock):
    _, token = await make_user(session_factory)
    started = (await _start(wired, token)).json()
    state = _query(started["authorization_url"])["state"]
    response = await wired.get(f"/api/oauth/callback/acme?code=a&code=b&state={state}")
    assert response.status_code == 400
    assert provider.requests == []


@pytest.mark.asyncio
async def test_callback_never_logs_the_code_or_state(wired, session_factory, configured, provider, clock, monkeypatch):
    lines: list[str] = []
    for level in ("info", "warning", "error"):
        monkeypatch.setattr(
            broker.logger, level, lambda event, _l=level, **kw: lines.append(f"{event} {kw}")
        )
    _, token = await make_user(session_factory)
    provider.on("/token", reply(400, {"error": "invalid_grant"}))
    started = (await _start(wired, token)).json()
    state = _query(started["authorization_url"])["state"]
    await wired.get("/api/oauth/callback/acme", params={"code": CODE, "state": state})
    await wired.get("/api/oauth/callback/acme", params={"code": CODE, "state": state})
    await wired.get("/api/oauth/callback/acme", params={"code": CODE, "state": broker.new_state()})
    dumped = "\n".join(lines)
    assert lines and CODE not in dumped and state not in dumped


@pytest.mark.asyncio
async def test_callback_needs_no_bearer_token_but_is_rate_limited_like_login(
    wired, session_factory, configured, fakes
):
    """The auth bucket (AUTH_RATE_LIMIT_PER_MINUTE), not the general one,
    throttles the callback. Limiter state is process-wide (and in Redis when
    one is running), so the test only relies on the throttle engaging within
    the auth limit."""
    limit = settings.AUTH_RATE_LIMIT_PER_MINUTE
    assert limit < settings.RATE_LIMIT_PER_MINUTE
    seen = []
    for _ in range(limit + 1):
        response = await wired.get("/api/oauth/callback/acme", params={"state": broker.new_state()})
        seen.append(response.status_code)
        if response.status_code == 429:
            assert response.headers["Retry-After"]
            assert response.headers["referrer-policy"] == "no-referrer"
            break
    assert seen[-1] == 429
    assert set(seen[:-1]) <= {400}


# ---------------------------------------------------------------------------
# Browser binding (shared server with a routable redirect base)
# ---------------------------------------------------------------------------

SHARED_BASE = "http://crawler.example.test"


@pytest.fixture
def shared_server(configured, monkeypatch):
    monkeypatch.setattr(settings, "OAUTH_REDIRECT_BASE", SHARED_BASE)


@pytest.mark.parametrize(
    ("base", "loopback"),
    [
        ("http://127.0.0.1:3000", True),
        ("http://127.8.9.10", True),
        ("http://localhost:3000", True),
        ("http://crawler.localhost", True),
        ("http://[::1]:3000", True),
        ("https://crawler.example.com", False),
        ("http://192.168.1.20:3000", False),
        ("http://localhost.example.com", False),
        ("http://[2001:db8::1]", False),
    ],
)
def test_redirect_base_is_loopback(monkeypatch, base, loopback):
    monkeypatch.setattr(settings, "OAUTH_REDIRECT_BASE", base)
    assert redirect_base_is_loopback() is loopback
    assert broker.browser_binding_required() is (not loopback)


def test_binding_cookie_is_per_state_and_unforgeable_without_the_key():
    first, second = broker.new_state(), broker.new_state()
    a, b = broker.browser_binding(first), broker.browser_binding(second)
    assert a.name.startswith(broker.BINDING_COOKIE_PREFIX) and a.name != b.name
    assert a.value != b.value and len(a.value) == 48
    assert first not in a.name + a.value
    assert a.value not in repr(a)
    assert broker.browser_binding(first) == a


def _set_cookie_headers(response) -> list[str]:
    return response.headers.get_list("set-cookie")


@pytest.mark.asyncio
@pytest.mark.parametrize(("base", "secure"), [(SHARED_BASE, False), ("https://crawler.example.com", True)])
async def test_shared_server_start_sets_a_callback_scoped_binding_cookie(
    wired, session_factory, shared_server, fakes, clock, monkeypatch, base, secure
):
    monkeypatch.setattr(settings, "OAUTH_REDIRECT_BASE", base)
    _, token = await make_user(session_factory)
    response = await _start(wired, token)
    assert response.status_code == 200, response.text
    state = _query(response.json()["authorization_url"])["state"]
    binding = broker.browser_binding(state)
    (cookie,) = _set_cookie_headers(response)
    parts = [part.strip() for part in cookie.split(";")]
    assert parts[0] == f"{binding.name}={binding.value}"
    lowered = {part.lower() for part in parts[1:]}
    assert "httponly" in lowered
    assert "path=/api/oauth/callback/acme" in lowered
    assert "samesite=lax" in lowered
    assert "max-age=600" in lowered
    assert ("secure" in lowered) is secure
    assert state not in cookie


@pytest.mark.asyncio
async def test_shared_server_callback_from_the_starting_browser_completes(
    wired, session_factory, shared_server, provider, clock
):
    user, token = await make_user(session_factory)
    provider.on("/token", reply(200, token_body()))
    started = await _start(wired, token)
    state = _query(started.json()["authorization_url"])["state"]
    name = broker.browser_binding(state).name
    assert wired.cookies.get(name)  # the starting browser holds the cookie

    response = await wired.get("/api/oauth/callback/acme", params={"code": CODE, "state": state})
    assert response.status_code == 200
    _assert_static_page(response)
    (cleared,) = _set_cookie_headers(response)
    assert cleared.startswith(f'{name}=""') and "Path=/api/oauth/callback/acme" in cleared
    async with session_factory() as s:
        config = (await s.execute(select(ConnectorConfig).where(ConnectorConfig.user_id == user.id))).scalar_one()
    assert json.loads(decrypt_credentials(config.encrypted_credentials))["access_token"] == ACCESS


@pytest.mark.asyncio
@pytest.mark.parametrize("presented", [None, "0" * 48, "not-the-value"])
async def test_shared_server_callback_from_another_browser_ends_the_flow_unexchanged(
    wired, session_factory, shared_server, provider, clock, presented
):
    """The consent phishing case: someone else approves the starter's link.
    Their browser has no (or a wrong) binding cookie, so the code is never
    exchanged and the flow is closed for good."""
    user, token = await make_user(session_factory)
    provider.on("/token", reply(200, token_body()))
    started = (await _start(wired, token)).json()
    state = _query(started["authorization_url"])["state"]
    name = broker.browser_binding(state).name
    starter_cookie = wired.cookies.get(name)
    wired.cookies.clear()  # a different browser
    if presented is not None:
        wired.cookies.set(name, presented)

    response = await wired.get("/api/oauth/callback/acme", params={"code": CODE, "state": state})
    assert response.status_code == 400
    _assert_static_page(response)
    assert provider.forms("/token") == []

    status = await wired.get(
        "/api/oauth/acme/status", params={"flow": started["flow_id"]}, headers=auth_headers(token)
    )
    assert status.json() == {"status": "error", "error": broker.MSG_OTHER_BROWSER}
    # The starter's own browser cannot revive it afterwards.
    wired.cookies.clear()
    wired.cookies.set(name, starter_cookie)
    retry = await wired.get("/api/oauth/callback/acme", params={"code": CODE, "state": state})
    assert retry.status_code == 400
    assert provider.forms("/token") == []
    async with session_factory() as s:
        rows = (await s.execute(select(ConnectorConfig).where(ConnectorConfig.user_id == user.id))).all()
    assert rows == []


@pytest.mark.asyncio
async def test_shared_server_cookie_of_one_flow_does_not_finish_another(
    wired, session_factory, shared_server, provider, clock
):
    _, token = await make_user(session_factory)
    provider.on("/token", reply(200, token_body()))
    first = _query((await _start(wired, token)).json()["authorization_url"])["state"]
    second = _query((await _start(wired, token)).json()["authorization_url"])["state"]
    wired.cookies.clear()
    wired.cookies.set(broker.browser_binding(second).name, broker.browser_binding(first).value)
    response = await wired.get("/api/oauth/callback/acme", params={"code": CODE, "state": second})
    assert response.status_code == 400
    assert provider.forms("/token") == []


# ---------------------------------------------------------------------------
# Status
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_status_is_only_for_the_owner(wired, session_factory, configured, fakes, clock):
    _, alice_token = await make_user(session_factory, "alice@example.com")
    _, bob_token = await make_user(session_factory, "bob@example.com")
    flow_id = (await _start(wired, alice_token)).json()["flow_id"]
    mine = await wired.get("/api/oauth/acme/status", params={"flow": flow_id}, headers=auth_headers(alice_token))
    assert mine.status_code == 200 and mine.json() == {"status": "pending"}
    for token, provider_name, flow in (
        (bob_token, "acme", flow_id),
        (alice_token, "msft", flow_id),
        (alice_token, "acme", str(uuid.uuid4())),
        (alice_token, "acme", "not-a-uuid"),
    ):
        response = await wired.get(
            f"/api/oauth/{provider_name}/status", params={"flow": flow}, headers=auth_headers(token)
        )
        assert response.status_code == 404


@pytest.mark.asyncio
async def test_status_reports_expiry(wired, session_factory, configured, fakes, clock):
    _, token = await make_user(session_factory)
    flow_id = (await _start(wired, token)).json()["flow_id"]
    clock.now += 601
    response = await wired.get("/api/oauth/acme/status", params={"flow": flow_id}, headers=auth_headers(token))
    assert response.json() == {"status": "expired", "error": broker.MSG_EXPIRED}


# ---------------------------------------------------------------------------
# Device
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_device_route_starts_one_poller_and_completes(wired, session_factory, configured, provider, sleeps):
    user, token = await make_user(session_factory)
    provider.on("/login/device/code", reply(200, device_body()))
    provider.on(
        "/login/oauth/access_token",
        reply(200, {"error": "authorization_pending"}),
        reply(200, {"access_token": "gho_test", "token_type": "bearer"}),
    )
    response = await wired.post("/api/oauth/gh/device", json={"display_name": "Code"}, headers=auth_headers(token))
    assert response.status_code == 200, response.text
    body = response.json()
    assert set(body) == {"flow_id", "user_code", "verification_uri", "expires_at", "interval"}
    assert body["user_code"] == "WDJB-MJHT" and body["interval"] == 5
    assert "device_code" not in response.text
    tasks = broker.background_tasks()
    assert len(tasks) == 1
    await asyncio.wait_for(asyncio.gather(*tasks), timeout=5)

    status = await wired.get(
        "/api/oauth/gh/status", params={"flow": body["flow_id"]}, headers=auth_headers(token)
    )
    result = status.json()
    assert result["status"] == "complete" and result["user_code"] == "WDJB-MJHT"
    async with session_factory() as s:
        config = (await s.execute(select(ConnectorConfig).where(ConnectorConfig.user_id == user.id))).scalar_one()
    assert result["connector_id"] == str(config.id) and config.display_name == "Code"


@pytest.mark.asyncio
async def test_device_route_reports_a_provider_refusal_as_502(wired, session_factory, configured, provider):
    _, token = await make_user(session_factory)
    provider.on("/login/device/code", reply(404, {"error": "Not Found"}))
    response = await wired.post("/api/oauth/gh/device", json={}, headers=auth_headers(token))
    assert response.status_code == 502
    assert broker.background_tasks() == frozenset()


@pytest.mark.asyncio
async def test_device_route_refuses_a_browser_only_connector(wired, session_factory, configured, fakes):
    _, token = await make_user(session_factory)
    response = await wired.post("/api/oauth/acme/device", json={}, headers=auth_headers(token))
    assert response.status_code == 422
