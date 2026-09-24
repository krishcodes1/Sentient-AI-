"""The first-run setup API (/api/setup/*).

No real LLM or Telegram traffic: ``services.agent.providers.create_provider``
is replaced with a fake and ``httpx.AsyncClient.get`` answers Telegram's
``getMe`` itself (every other URL, i.e. the test client's own GETs, goes
through the real method). An autouse guard backs this up: any httpx
request that is not the test client's own ASGI call fails the test, and
the provider factory hands out a FakeLLM unless a test installs its own,
so a test that forgets to patch cannot reach the network.
"""

from __future__ import annotations

import base64
import os
import uuid
from types import SimpleNamespace

import httpx
import pytest
import pytest_asyncio
import structlog
from sqlalchemy import select

from api.routes import setup as setup_routes
from core.config import PROVIDER_KEY_FIELDS, settings
from models.audit import AuditLog
from services.agent import providers
from services.agent.providers import LLMResponse, ProviderError
from services.installation import UNREADABLE_KEYS_MESSAGE, InstallationService
from services.notifications.telegram_manager import TelegramManager
from tests.conftest import auth_headers, make_user

OWNER = {"email": "owner@example.com", "password": "password-123", "name": "Owner"}
BOT_TOKEN = "123456789:AAHdqTcvCH1vGWJxfSeofSAs0K5PALDsaw"
API_KEY = "sk-very-secret-key-0123456789"

ENV_MANAGED = "Provided by server configuration; remove it from .env to manage it here."

_real_get = httpx.AsyncClient.get
_real_send = httpx.AsyncClient.send


class FakeService:
    """Stands in for TelegramService under the manager (no polling)."""

    instances: list["FakeService"] = []

    def __init__(self, token, session_factory, decide=None, chat=None):
        self.token = token
        self.started = False
        self.stopped = False
        FakeService.instances.append(self)

    async def start(self):
        self.started = True

    async def stop(self):
        self.stopped = True

    async def notify_pending(self, action):
        pass

    async def send_text(self, user_id, text):
        return True

    async def bot_username(self):
        return "crawler_test_bot"


class FakeLLM:
    def __init__(self, *, error: Exception | None = None, reply: str = "OK"):
        self.error = error
        self.reply = reply
        self.closed = False
        self.calls: list[list[dict]] = []

    async def complete(self, messages, tools=None):
        self.calls.append(messages)
        if self.error is not None:
            raise self.error
        return LLMResponse(content=self.reply)

    async def aclose(self):
        self.closed = True


def _patch_provider(monkeypatch, llm: FakeLLM) -> list[dict]:
    seen: list[dict] = []

    def fake_create(provider_name, model, *, api_key=None, base_url="http://localhost:11434"):
        seen.append({"provider": provider_name, "model": model, "api_key": api_key})
        return llm

    monkeypatch.setattr(providers, "create_provider", fake_create)
    return seen


def _patch_telegram(monkeypatch, *, status_code: int = 200, username: str = "crawler_test_bot"):
    calls: list[str] = []

    async def fake_get(self, url, *args, **kwargs):
        text = str(url)
        if not text.startswith("https://api.telegram.org/"):
            return await _real_get(self, url, *args, **kwargs)
        calls.append(text)
        if status_code == 200:
            payload = {"ok": True, "result": {"id": 1, "is_bot": True, "username": username}}
        else:
            payload = {"ok": False, "error_code": status_code, "description": "Unauthorized"}
        return httpx.Response(status_code, json=payload, request=httpx.Request("GET", text))

    monkeypatch.setattr(httpx.AsyncClient, "get", fake_get)
    return calls


_MISSING = object()


@pytest.fixture(autouse=True)
def _no_network(monkeypatch):
    """Backstop for every test here: get, post and every other httpx verb
    end in AsyncClient.send, so guarding send refuses any request that is
    not the test client talking to the app. The provider factory returns a
    FakeLLM until a test installs its own with _patch_provider."""

    async def guarded_send(self, request, *args, **kwargs):
        if request.url.host != "testserver":
            # Host only: a Telegram URL carries the bot token in its path.
            raise AssertionError(f"network call to {request.url.host}")
        return await _real_send(self, request, *args, **kwargs)

    monkeypatch.setattr(httpx.AsyncClient, "send", guarded_send)
    monkeypatch.setattr(providers, "create_provider", lambda *args, **kwargs: FakeLLM())


@pytest_asyncio.fixture
async def env(client, session_factory, monkeypatch):
    """Wire the services the lifespan will own onto app.state, with a clean
    environment: no provider key or bot token from a developer .env."""
    from main import app

    for attr in PROVIDER_KEY_FIELDS.values():
        monkeypatch.setattr(settings, attr, "", raising=False)
    monkeypatch.setattr(settings, "TELEGRAM_BOT_TOKEN", "", raising=False)
    monkeypatch.setattr(settings, "LLM_PROVIDER", "anthropic", raising=False)
    monkeypatch.setattr(settings, "LLM_MODEL", "claude-sonnet-4-6", raising=False)
    monkeypatch.setattr(settings, "ALLOW_REGISTRATION", True, raising=False)
    FakeService.instances.clear()
    setup_routes._reset_rate_limits()

    installation = InstallationService(session_factory)
    manager = TelegramManager(session_factory, service_factory=FakeService)
    previous = {
        name: getattr(app.state, name, _MISSING) for name in ("installation", "telegram_manager")
    }
    app.state.installation = installation
    app.state.telegram_manager = manager

    async def _on_change(topic: str) -> None:
        # Mirrors main.wire_services: the routes never touch the poller;
        # a telegram or capabilities change re-applies the manager. Read
        # from app.state so a test can swap in a failing one.
        current = getattr(app.state, "telegram_manager", None)
        if current is not None and topic in ("telegram", "capabilities"):
            switches = await installation.capabilities()
            await current.apply(
                await installation.telegram_token(), switches.get("telegram", False)
            )

    installation.on_change(_on_change)
    try:
        yield SimpleNamespace(installation=installation, manager=manager, app=app)
    finally:
        await manager.stop()
        for name, value in previous.items():
            if value is _MISSING:
                if hasattr(app.state, name):
                    delattr(app.state, name)
            else:
                setattr(app.state, name, value)
        setup_routes._reset_rate_limits()


async def _owner_token(client) -> str:
    resp = await client.post("/api/setup/owner", json=OWNER)
    assert resp.status_code == 200, resp.text
    return resp.json()["access_token"]


async def _owner_id(client, token: str) -> uuid.UUID:
    me = await client.get("/api/auth/me", headers=auth_headers(token))
    return uuid.UUID(me.json()["id"])


async def _latest_audit(session_factory, action: str) -> AuditLog | None:
    async with session_factory() as s:
        rows = (
            (await s.execute(select(AuditLog).where(AuditLog.action == action))).scalars().all()
        )
    return rows[-1] if rows else None


# ---------------------------------------------------------------------------
# Status and the owner step
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_status_before_and_after_owner(client, env):
    before = await client.get("/api/setup/status")
    assert before.status_code == 200
    assert before.json() == {
        "needs_setup": True,
        "has_owner": False,
        "provider_configured": False,
        "setup_completed": False,
        "secrets_unreadable": False,
    }

    await _owner_token(client)

    after = (await client.get("/api/setup/status")).json()
    assert after["has_owner"] is True
    assert after["needs_setup"] is True  # the wizard is not finished yet
    assert after["setup_completed"] is False


@pytest.mark.asyncio
async def test_owner_returns_a_login_token_for_an_admin(client, env, session_factory):
    resp = await client.post("/api/setup/owner", json=OWNER)
    assert resp.status_code == 200
    body = resp.json()
    assert body["token_type"] == "bearer" and body["access_token"]
    assert body["user"]["is_admin"] is True
    assert body["user"]["email"] == "owner@example.com"
    assert "password" not in resp.text and "hashed_password" not in resp.text

    me = await client.get("/api/auth/me", headers=auth_headers(body["access_token"]))
    assert me.status_code == 200 and me.json()["is_admin"] is True

    row = await _latest_audit(session_factory, "account_created")
    assert row is not None and row.endpoint == "/api/setup/owner"
    # Signing the owner in is a login like any other, so the chain says so.
    login = await _latest_audit(session_factory, "login")
    assert login is not None and login.endpoint == "/api/setup/owner"


@pytest.mark.asyncio
async def test_second_owner_is_refused(client, env):
    await _owner_token(client)
    again = await client.post(
        "/api/setup/owner", json={**OWNER, "email": "intruder@example.com"}
    )
    assert again.status_code == 409


@pytest.mark.asyncio
async def test_owner_is_refused_once_any_account_exists(client, env, session_factory):
    await make_user(session_factory, "someone@example.com")
    resp = await client.post("/api/setup/owner", json=OWNER)
    assert resp.status_code == 409


@pytest.mark.asyncio
async def test_owner_enforces_the_password_policy(client, env):
    resp = await client.post("/api/setup/owner", json={**OWNER, "password": "short"})
    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_status_without_installation_service_is_503(client, env):
    delattr(env.app.state, "installation")
    resp = await client.get("/api/setup/status")
    assert resp.status_code == 503


# ---------------------------------------------------------------------------
# Admin gate
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_admin_routes_refuse_non_admins(client, env, session_factory):
    await _owner_token(client)
    _guest, guest_token = await make_user(session_factory, "guest@example.com")
    headers = auth_headers(guest_token)
    choice = {"provider": "gemini", "model": "gemini-2.5-flash", "api_key": "k"}

    calls = [
        client.get("/api/setup/providers", headers=headers),
        client.post("/api/setup/provider/test", json=choice, headers=headers),
        client.put("/api/setup/provider", json=choice, headers=headers),
        client.post("/api/setup/telegram/test", json={"token": BOT_TOKEN}, headers=headers),
        client.put("/api/setup/telegram", json={"token": BOT_TOKEN}, headers=headers),
        client.delete("/api/setup/telegram", headers=headers),
        client.delete("/api/setup/secrets", headers=headers),
        client.post("/api/setup/complete", json={"allow_registration": True}, headers=headers),
    ]
    for call in calls:
        resp = await call
        assert resp.status_code == 403, resp.request.url

    anonymous = await client.get("/api/setup/providers")
    assert anonymous.status_code in (401, 403)


# ---------------------------------------------------------------------------
# Provider
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_providers_lists_every_provider_without_values(client, env, monkeypatch):
    token = await _owner_token(client)
    monkeypatch.setattr(settings, "OPENAI_API_KEY", "env-openai-key", raising=False)
    owner_id = await _owner_id(client, token)
    await env.installation.set_llm("gemini", "gemini-2.5-flash", "stored-gemini-key", actor_id=owner_id)

    resp = await client.get("/api/setup/providers", headers=auth_headers(token))
    assert resp.status_code == 200
    body = resp.json()
    by_name = {p["name"]: p for p in body["providers"]}
    assert set(by_name) == {*PROVIDER_KEY_FIELDS, "ollama"}
    assert by_name["openai"]["key_from_env"] is True
    assert by_name["gemini"]["key_stored"] is True and by_name["gemini"]["key_from_env"] is False
    assert by_name["anthropic"]["key_from_env"] is False and by_name["anthropic"]["key_stored"] is False
    assert by_name["gemini"]["models"][0] == "gemini-2.5-flash"
    assert by_name["ollama"]["models"] == ["llama3.2"]
    assert all(p["models"] for p in body["providers"])
    assert body["current"] == {"provider": "gemini", "model": "gemini-2.5-flash"}
    assert "env-openai-key" not in resp.text and "stored-gemini-key" not in resp.text


@pytest.mark.asyncio
async def test_provider_test_ok(client, env, monkeypatch):
    token = await _owner_token(client)
    llm = FakeLLM()
    seen = _patch_provider(monkeypatch, llm)
    resp = await client.post(
        "/api/setup/provider/test",
        json={"provider": "gemini", "model": "gemini-2.5-flash", "api_key": "k"},
        headers=auth_headers(token),
    )
    assert resp.status_code == 200
    assert resp.json() == {"ok": True, "reply": "OK"}
    assert seen == [{"provider": "gemini", "model": "gemini-2.5-flash", "api_key": "k"}]
    assert llm.closed is True
    # Nothing is stored by a test.
    assert await env.installation.llm_api_key("gemini") is None


@pytest.mark.asyncio
async def test_provider_test_reports_provider_errors(client, env, monkeypatch):
    token = await _owner_token(client)
    llm = FakeLLM(error=ProviderError("gemini", 400, "API key not valid"))
    _patch_provider(monkeypatch, llm)
    resp = await client.post(
        "/api/setup/provider/test",
        json={"provider": "gemini", "model": "gemini-2.5-flash", "api_key": "k"},
        headers=auth_headers(token),
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["ok"] is False and "API key not valid" in body["error"]
    assert llm.closed is True


@pytest.mark.asyncio
async def test_provider_test_without_any_key_asks_for_one(client, env, monkeypatch):
    token = await _owner_token(client)
    seen = _patch_provider(monkeypatch, FakeLLM())
    resp = await client.post(
        "/api/setup/provider/test",
        json={"provider": "gemini", "model": "gemini-2.5-flash"},
        headers=auth_headers(token),
    )
    assert resp.json() == {"ok": False, "error": "Enter an API key."}
    assert seen == []


@pytest.mark.asyncio
async def test_provider_test_falls_back_to_the_configured_key(client, env, monkeypatch):
    token = await _owner_token(client)
    monkeypatch.setattr(settings, "GEMINI_API_KEY", "env-gemini-key", raising=False)
    seen = _patch_provider(monkeypatch, FakeLLM())
    resp = await client.post(
        "/api/setup/provider/test",
        json={"provider": "gemini", "model": "gemini-2.5-flash"},
        headers=auth_headers(token),
    )
    assert resp.json()["ok"] is True
    assert seen[-1]["api_key"] == "env-gemini-key"
    assert "env-gemini-key" not in resp.text


@pytest.mark.asyncio
async def test_provider_test_ollama_needs_no_key(client, env, monkeypatch):
    token = await _owner_token(client)
    seen = _patch_provider(monkeypatch, FakeLLM())
    resp = await client.post(
        "/api/setup/provider/test",
        json={"provider": "ollama", "model": "llama3.2"},
        headers=auth_headers(token),
    )
    assert resp.json()["ok"] is True
    assert seen[-1]["provider"] == "ollama"


@pytest.mark.asyncio
async def test_provider_test_rejects_unknown_provider_and_bad_model(client, env, monkeypatch):
    token = await _owner_token(client)
    _patch_provider(monkeypatch, FakeLLM())
    unknown = await client.post(
        "/api/setup/provider/test",
        json={"provider": "skynet", "model": "t-800"},
        headers=auth_headers(token),
    )
    assert unknown.status_code == 422
    bad_model = await client.post(
        "/api/setup/provider/test",
        json={"provider": "gemini", "model": "gemini flash; rm -rf"},
        headers=auth_headers(token),
    )
    assert bad_model.status_code == 422


@pytest.mark.asyncio
async def test_put_provider_refuses_on_failed_test_and_stores_on_success(
    client, env, monkeypatch, session_factory
):
    token = await _owner_token(client)
    choice = {"provider": "gemini", "model": "gemini-2.5-flash", "api_key": "k"}

    _patch_provider(monkeypatch, FakeLLM(error=ProviderError("gemini", 401, "unauthorized")))
    refused = await client.put("/api/setup/provider", json=choice, headers=auth_headers(token))
    assert refused.status_code == 400
    assert "unauthorized" in refused.json()["detail"]
    assert await env.installation.llm_api_key("gemini") is None

    _patch_provider(monkeypatch, FakeLLM())
    saved = await client.put("/api/setup/provider", json=choice, headers=auth_headers(token))
    assert saved.status_code == 200
    assert saved.json() == {"ok": True}
    assert await env.installation.llm_api_key("gemini") == "k"
    assert await env.installation.llm_defaults() == ("gemini", "gemini-2.5-flash")

    status_body = (await client.get("/api/setup/status")).json()
    assert status_body["provider_configured"] is True

    row = await _latest_audit(session_factory, "provider_updated")
    assert row is not None and row.connector_name == "installation"


@pytest.mark.asyncio
async def test_put_provider_never_copies_an_environment_key_into_the_database(
    client, env, monkeypatch
):
    token = await _owner_token(client)
    monkeypatch.setattr(settings, "GEMINI_API_KEY", "env-gemini-key", raising=False)
    seen = _patch_provider(monkeypatch, FakeLLM())
    resp = await client.put(
        "/api/setup/provider",
        json={"provider": "gemini", "model": "gemini-2.5-flash"},
        headers=auth_headers(token),
    )
    assert resp.status_code == 200
    assert seen[-1]["api_key"] == "env-gemini-key"
    assert "gemini" not in await env.installation.stored_provider_keys()


# ---------------------------------------------------------------------------
# Telegram
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_telegram_test_returns_the_bot_username(client, env, monkeypatch):
    token = await _owner_token(client)
    calls = _patch_telegram(monkeypatch)
    resp = await client.post(
        "/api/setup/telegram/test", json={"token": BOT_TOKEN}, headers=auth_headers(token)
    )
    assert resp.status_code == 200
    assert resp.json() == {"ok": True, "bot_username": "crawler_test_bot"}
    assert calls and calls[0].endswith("/getMe")
    assert BOT_TOKEN not in resp.text
    # A test stores nothing and starts nothing.
    assert await env.installation.telegram_token() is None
    assert env.manager.is_running is False


@pytest.mark.asyncio
async def test_telegram_test_reports_a_rejected_token(client, env, monkeypatch):
    token = await _owner_token(client)
    _patch_telegram(monkeypatch, status_code=401)
    resp = await client.post(
        "/api/setup/telegram/test", json={"token": BOT_TOKEN}, headers=auth_headers(token)
    )
    assert resp.json() == {"ok": False, "error": "Telegram rejected that token."}


@pytest.mark.asyncio
async def test_telegram_token_format_is_checked_without_echoing_it(client, env, monkeypatch):
    token = await _owner_token(client)
    calls = _patch_telegram(monkeypatch)
    malformed = "not-a-token-but-still-secret-ish"
    for method, path in (("post", "/api/setup/telegram/test"), ("put", "/api/setup/telegram")):
        resp = await getattr(client, method)(
            path, json={"token": malformed}, headers=auth_headers(token)
        )
        assert resp.status_code == 422
        assert malformed not in resp.text
    assert calls == []


@pytest.mark.asyncio
async def test_put_telegram_stores_the_token_and_starts_the_poller(
    client, env, monkeypatch, session_factory
):
    token = await _owner_token(client)
    _patch_telegram(monkeypatch)
    resp = await client.put(
        "/api/setup/telegram", json={"token": BOT_TOKEN}, headers=auth_headers(token)
    )
    assert resp.status_code == 200
    assert resp.json() == {"ok": True, "bot_username": "crawler_test_bot", "running": True}
    assert BOT_TOKEN not in resp.text
    assert await env.installation.telegram_token() == BOT_TOKEN
    assert env.manager.is_running is True
    assert FakeService.instances[-1].token == BOT_TOKEN and FakeService.instances[-1].started

    row = await _latest_audit(session_factory, "telegram_updated")
    assert row is not None


@pytest.mark.asyncio
async def test_put_telegram_refuses_a_token_telegram_rejects(client, env, monkeypatch):
    token = await _owner_token(client)
    _patch_telegram(monkeypatch, status_code=401)
    resp = await client.put(
        "/api/setup/telegram", json={"token": BOT_TOKEN}, headers=auth_headers(token)
    )
    assert resp.status_code == 400
    assert await env.installation.telegram_token() is None
    assert env.manager.is_running is False


@pytest.mark.asyncio
async def test_put_telegram_saves_but_does_not_start_when_the_capability_is_off(
    client, env, monkeypatch
):
    token = await _owner_token(client)
    owner_id = await _owner_id(client, token)
    await env.installation.set_capabilities({"telegram": False}, actor_id=owner_id)
    _patch_telegram(monkeypatch)
    resp = await client.put(
        "/api/setup/telegram", json={"token": BOT_TOKEN}, headers=auth_headers(token)
    )
    assert resp.status_code == 200
    assert resp.json()["running"] is False
    assert await env.installation.telegram_token() == BOT_TOKEN
    assert env.manager.is_running is False


@pytest.mark.asyncio
async def test_delete_telegram_clears_the_token_and_stops_the_poller(client, env, monkeypatch):
    token = await _owner_token(client)
    _patch_telegram(monkeypatch)
    await client.put("/api/setup/telegram", json={"token": BOT_TOKEN}, headers=auth_headers(token))
    assert env.manager.is_running is True

    resp = await client.delete("/api/setup/telegram", headers=auth_headers(token))
    assert resp.status_code == 204
    assert resp.content == b""
    assert await env.installation.telegram_token() is None
    assert env.manager.is_running is False
    assert FakeService.instances[-1].stopped is True


@pytest.mark.asyncio
async def test_telegram_routes_work_without_a_manager(client, env, monkeypatch):
    """Before the lifespan wires a manager the token is still saved."""
    delattr(env.app.state, "telegram_manager")
    token = await _owner_token(client)
    _patch_telegram(monkeypatch)
    resp = await client.put(
        "/api/setup/telegram", json={"token": BOT_TOKEN}, headers=auth_headers(token)
    )
    assert resp.status_code == 200
    assert await env.installation.telegram_token() == BOT_TOKEN


# ---------------------------------------------------------------------------
# Completion and the registration switch
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_complete_stamps_setup_and_closes_registration(client, env, session_factory):
    token = await _owner_token(client)
    resp = await client.post(
        "/api/setup/complete", json={"allow_registration": False}, headers=auth_headers(token)
    )
    assert resp.status_code == 200 and resp.json() == {"ok": True}

    status_body = (await client.get("/api/setup/status")).json()
    assert status_body["setup_completed"] is True
    assert status_body["needs_setup"] is False

    # The stored switch now governs /auth/register, whatever the env says.
    closed = await client.post(
        "/api/auth/register", json={"email": "late@example.com", "password": "password-123"}
    )
    assert closed.status_code == 403

    row = await _latest_audit(session_factory, "setup_completed")
    assert row is not None


@pytest.mark.asyncio
async def test_complete_can_leave_registration_open(client, env, monkeypatch):
    monkeypatch.setattr(settings, "ALLOW_REGISTRATION", False, raising=False)
    token = await _owner_token(client)  # the owner step ignores the switch
    await client.post(
        "/api/setup/complete", json={"allow_registration": True}, headers=auth_headers(token)
    )
    joined = await client.post(
        "/api/auth/register", json={"email": "friend@example.com", "password": "password-123"}
    )
    assert joined.status_code == 201
    assert joined.json()["is_admin"] is False


# ---------------------------------------------------------------------------
# Rate limit and secrecy
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_sixth_provider_test_in_a_minute_is_refused(client, env, monkeypatch):
    token = await _owner_token(client)
    _patch_provider(monkeypatch, FakeLLM())
    choice = {"provider": "gemini", "model": "gemini-2.5-flash", "api_key": "k"}
    for _ in range(5):
        ok = await client.post("/api/setup/provider/test", json=choice, headers=auth_headers(token))
        assert ok.status_code == 200
    sixth = await client.post("/api/setup/provider/test", json=choice, headers=auth_headers(token))
    assert sixth.status_code == 429
    assert int(sixth.headers["Retry-After"]) > 0


@pytest.mark.asyncio
async def test_telegram_tests_have_their_own_limit(client, env, monkeypatch):
    token = await _owner_token(client)
    _patch_telegram(monkeypatch)
    for _ in range(5):
        ok = await client.post(
            "/api/setup/telegram/test", json={"token": BOT_TOKEN}, headers=auth_headers(token)
        )
        assert ok.status_code == 200
    sixth = await client.post(
        "/api/setup/telegram/test", json={"token": BOT_TOKEN}, headers=auth_headers(token)
    )
    assert sixth.status_code == 429


@pytest.mark.asyncio
async def test_secrets_never_appear_in_any_response(client, env, monkeypatch):
    bodies: list[str] = []
    token = await _owner_token(client)
    headers = auth_headers(token)
    choice = {"provider": "openai", "model": "gpt-4o-mini", "api_key": API_KEY}

    # A provider that quotes the key back in its error must not leak it.
    _patch_provider(
        monkeypatch, FakeLLM(error=ProviderError("openai", 401, f"Incorrect API key provided: {API_KEY}"))
    )
    failed = await client.post("/api/setup/provider/test", json=choice, headers=headers)
    assert failed.json()["ok"] is False and "[redacted]" in failed.json()["error"]
    bodies.append(failed.text)
    refused = await client.put("/api/setup/provider", json=choice, headers=headers)
    assert refused.status_code == 400
    bodies.append(refused.text)

    _patch_provider(monkeypatch, FakeLLM())
    _patch_telegram(monkeypatch)
    for resp in (
        await client.post("/api/setup/provider/test", json=choice, headers=headers),
        await client.put("/api/setup/provider", json=choice, headers=headers),
        await client.get("/api/setup/providers", headers=headers),
        await client.post("/api/setup/telegram/test", json={"token": BOT_TOKEN}, headers=headers),
        await client.put("/api/setup/telegram", json={"token": BOT_TOKEN}, headers=headers),
        await client.get("/api/setup/status"),
        await client.post("/api/setup/complete", json={"allow_registration": False}, headers=headers),
        await client.delete("/api/setup/telegram", headers=headers),
    ):
        assert resp.status_code < 400, (resp.request.url, resp.text)
        bodies.append(resp.text)

    assert await env.installation.llm_api_key("openai") == API_KEY  # it was stored...
    for text in bodies:  # ...and never sent back
        assert API_KEY not in text
        assert BOT_TOKEN not in text


# ---------------------------------------------------------------------------
# Validation errors never echo the request
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_validation_errors_never_echo_the_request_body(client, env):
    """FastAPI's stock 422 repeats each failing field's input, and for a
    missing field that input is the whole body: the key or password that
    arrived next to it."""
    token = await _owner_token(client)
    missing_model = await client.put(
        "/api/setup/provider",
        json={"provider": "openai", "api_key": "sk-SECRET"},
        headers=auth_headers(token),
    )
    owner_without_email = await client.post(
        "/api/setup/owner", json={"password": "owner-password-SECRET"}
    )
    login_without_email = await client.post(
        "/api/auth/login", json={"password": "login-password-SECRET"}
    )

    for resp, secret in (
        (missing_model, "sk-SECRET"),
        (owner_without_email, "owner-password-SECRET"),
        (login_without_email, "login-password-SECRET"),
    ):
        assert resp.status_code == 422
        assert secret not in resp.text
        detail = resp.json()["detail"]
        assert detail and all(set(item) == {"type", "loc", "msg"} for item in detail)
    assert missing_model.json()["detail"] == [
        {"type": "missing", "loc": ["body", "model"], "msg": "Field required"}
    ]


# ---------------------------------------------------------------------------
# Open registration waits for the wizard
# ---------------------------------------------------------------------------

_LATE = {"email": "late@example.com", "password": "password-123"}


@pytest.mark.asyncio
async def test_registration_is_closed_before_any_owner_exists(client, env):
    """The first account comes from /setup/owner, never from open sign-up,
    even with ALLOW_REGISTRATION on."""
    resp = await client.post("/api/auth/register", json=_LATE)
    assert resp.status_code == 403
    assert resp.json()["detail"] == "Registration is disabled until setup is complete"
    assert await env.installation.has_users() is False


@pytest.mark.asyncio
async def test_registration_is_closed_while_the_wizard_is_unfinished(client, env):
    await _owner_token(client)
    resp = await client.post("/api/auth/register", json=_LATE)
    assert resp.status_code == 403
    assert resp.json()["detail"] == "Registration is disabled until setup is complete"


@pytest.mark.asyncio
async def test_registration_after_setup_follows_the_owners_switch(client, env):
    token = await _owner_token(client)
    headers = auth_headers(token)

    await client.post("/api/setup/complete", json={"allow_registration": True}, headers=headers)
    opened = await client.post("/api/auth/register", json=_LATE)
    assert opened.status_code == 201
    assert opened.json()["is_admin"] is False

    await client.post("/api/setup/complete", json={"allow_registration": False}, headers=headers)
    closed = await client.post(
        "/api/auth/register", json={**_LATE, "email": "later@example.com"}
    )
    assert closed.status_code == 403
    assert closed.json()["detail"] == "Registration is disabled on this server"


# ---------------------------------------------------------------------------
# Input shape: model ids, keys, bot tokens
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "model",
    [
        "a/../../v1/files",
        "gemini-2.5-flash/",
        "models//gemini",
        "/v1/files",
        "gemini-2.5-flаsh",  # Cyrillic a
        "gemini flash",
    ],
)
async def test_path_like_or_non_ascii_model_ids_are_refused_on_both_routes(
    client, env, monkeypatch, model
):
    token = await _owner_token(client)
    seen = _patch_provider(monkeypatch, FakeLLM())
    wizard = await client.post(
        "/api/setup/provider/test",
        json={"provider": "gemini", "model": model, "api_key": "k"},
        headers=auth_headers(token),
    )
    assert wizard.status_code == 422
    # With a provider, so the only thing wrong with the request is the id
    # (a model alone is refused anyway on an account that follows the
    # install default).
    per_user = await client.patch(
        "/api/auth/settings",
        json={"llm_provider": "gemini", "llm_model": model},
        headers=auth_headers(token),
    )
    assert per_user.status_code == 422
    assert seen == []


@pytest.mark.asyncio
async def test_ordinary_model_ids_are_still_accepted(client, env, monkeypatch):
    token = await _owner_token(client)
    _patch_provider(monkeypatch, FakeLLM())
    for model in ("openai/gpt-oss-120b", "llama3.2:latest", "claude-haiku-4-5-20251001"):
        wizard = await client.post(
            "/api/setup/provider/test",
            json={"provider": "groq", "model": model, "api_key": "k"},
            headers=auth_headers(token),
        )
        assert wizard.json()["ok"] is True, model
        per_user = await client.patch(
            "/api/auth/settings",
            json={"llm_provider": "groq", "llm_model": model},
            headers=auth_headers(token),
        )
        assert per_user.status_code == 200, model


@pytest.mark.asyncio
async def test_a_non_ascii_api_key_is_refused_without_echo(client, env, monkeypatch):
    token = await _owner_token(client)
    seen = _patch_provider(monkeypatch, FakeLLM())
    key = "sk-ключ-secret"
    resp = await client.post(
        "/api/setup/provider/test",
        json={"provider": "openai", "model": "gpt-4o-mini", "api_key": key},
        headers=auth_headers(token),
    )
    assert resp.status_code == 422
    assert key not in resp.text and "secret" not in resp.text
    assert seen == []


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "bot_token",
    [
        "١٢٣٤:" + "A" * 35,  # Arabic-Indic digits match \d
        "1" * 21 + ":" + "A" * 35,
        "123456:" + "A" * 29,
        "123456:" + "A" * 65,
        "123456:" + "A" * 34 + "é",
    ],
)
async def test_bot_tokens_outside_the_botfather_shape_are_refused(
    client, env, monkeypatch, bot_token
):
    token = await _owner_token(client)
    calls = _patch_telegram(monkeypatch)
    resp = await client.post(
        "/api/setup/telegram/test", json={"token": bot_token}, headers=auth_headers(token)
    )
    assert resp.status_code == 422
    assert bot_token not in resp.text
    assert calls == []


# ---------------------------------------------------------------------------
# Secrets the environment provides
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_a_key_from_the_environment_cannot_be_replaced_here(client, env, monkeypatch):
    token = await _owner_token(client)
    monkeypatch.setattr(settings, "GEMINI_API_KEY", "env-gemini-key", raising=False)
    seen = _patch_provider(monkeypatch, FakeLLM())
    choice = {"provider": "gemini", "model": "gemini-2.5-flash", "api_key": "typed-gemini-key"}
    for method, path in (("post", "/api/setup/provider/test"), ("put", "/api/setup/provider")):
        resp = await getattr(client, method)(path, json=choice, headers=auth_headers(token))
        assert resp.status_code == 409, path
        assert resp.json()["detail"] == ENV_MANAGED
        assert "typed-gemini-key" not in resp.text and "env-gemini-key" not in resp.text
    assert seen == []
    assert "gemini" not in await env.installation.stored_provider_keys()

    # Choosing the provider without a key is still allowed: the env key is used.
    ok = await client.put(
        "/api/setup/provider",
        json={"provider": "gemini", "model": "gemini-2.5-flash"},
        headers=auth_headers(token),
    )
    assert ok.status_code == 200


@pytest.mark.asyncio
async def test_a_bot_token_from_the_environment_cannot_be_replaced_here(
    client, env, monkeypatch, session_factory
):
    token = await _owner_token(client)
    env_token = "987654321:" + "E" * 35
    monkeypatch.setattr(settings, "TELEGRAM_BOT_TOKEN", env_token, raising=False)
    calls = _patch_telegram(monkeypatch)
    for method, path in (("post", "/api/setup/telegram/test"), ("put", "/api/setup/telegram")):
        resp = await getattr(client, method)(
            path, json={"token": BOT_TOKEN}, headers=auth_headers(token)
        )
        assert resp.status_code == 409, path
        assert resp.json()["detail"] == ENV_MANAGED
        assert BOT_TOKEN not in resp.text and env_token not in resp.text
    assert calls == []
    assert await _latest_audit(session_factory, "telegram_updated") is None


# ---------------------------------------------------------------------------
# Failures after or around the third-party call
# ---------------------------------------------------------------------------


class _ExplodingManager:
    """A TelegramManager whose poller cannot start (or stop)."""

    is_running = False

    async def apply(self, token, enabled):
        raise RuntimeError(f"poller failed for {token}")

    async def stop(self):
        pass


@pytest.mark.asyncio
async def test_put_telegram_keeps_the_saved_token_when_the_poller_fails(
    client, env, monkeypatch
):
    token = await _owner_token(client)
    _patch_telegram(monkeypatch)
    env.app.state.telegram_manager = _ExplodingManager()
    resp = await client.put(
        "/api/setup/telegram", json={"token": BOT_TOKEN}, headers=auth_headers(token)
    )
    assert resp.status_code == 200
    assert resp.json() == {"ok": True, "bot_username": "crawler_test_bot", "running": False}
    assert BOT_TOKEN not in resp.text
    assert await env.installation.telegram_token() == BOT_TOKEN

    cleared = await client.delete("/api/setup/telegram", headers=auth_headers(token))
    assert cleared.status_code == 204


@pytest.mark.asyncio
async def test_provider_init_failure_reports_only_the_exception_type(client, env, monkeypatch):
    token = await _owner_token(client)

    def exploding_create(*args, **kwargs):
        raise RuntimeError(f"client init failed for key {API_KEY}")

    monkeypatch.setattr(providers, "create_provider", exploding_create)
    choice = {"provider": "openai", "model": "gpt-4o-mini", "api_key": API_KEY}
    expected = "Could not initialise the openai provider (RuntimeError)."

    tested = await client.post("/api/setup/provider/test", json=choice, headers=auth_headers(token))
    assert tested.status_code == 200
    assert tested.json() == {"ok": False, "error": expected}
    saved = await client.put("/api/setup/provider", json=choice, headers=auth_headers(token))
    assert saved.status_code == 400
    assert saved.json()["detail"] == expected
    for resp in (tested, saved):
        assert API_KEY not in resp.text
    assert "openai" not in await env.installation.stored_provider_keys()


@pytest.mark.asyncio
async def test_an_environment_key_quoted_in_an_error_is_redacted(client, env, monkeypatch):
    token = await _owner_token(client)
    env_key = "sk-env-resolved-secret-9876543210"
    monkeypatch.setattr(settings, "OPENAI_API_KEY", env_key, raising=False)
    _patch_provider(
        monkeypatch,
        FakeLLM(error=ProviderError("openai", 401, f"Incorrect API key provided: {env_key}")),
    )
    choice = {"provider": "openai", "model": "gpt-4o-mini"}  # the key comes from the env
    tested = await client.post("/api/setup/provider/test", json=choice, headers=auth_headers(token))
    assert tested.json()["ok"] is False and "[redacted]" in tested.json()["error"]
    saved = await client.put("/api/setup/provider", json=choice, headers=auth_headers(token))
    assert saved.status_code == 400 and "[redacted]" in saved.json()["detail"]
    for resp in (tested, saved):
        assert env_key not in resp.text


@pytest.fixture
def captured_logs(monkeypatch):
    """structlog capture for the modules on these paths. The app sets
    cache_logger_on_first_use, and a module logger first used before
    main.configure_logging ran keeps the processors it was bound with, so
    each module gets a fresh logger bound inside the capture."""
    from services import installation as installation_module
    from services.notifications import telegram_manager as manager_module

    with structlog.testing.capture_logs() as logs:
        for module in (setup_routes, installation_module, manager_module):
            monkeypatch.setattr(module, "logger", structlog.get_logger(module.__name__))
        yield logs


class _FailingService(FakeService):
    async def start(self):
        raise RuntimeError(f"could not start the poller for {self.token}")


@pytest.mark.asyncio
async def test_failure_logs_never_carry_a_secret(
    client, env, monkeypatch, session_factory, captured_logs
):
    token = await _owner_token(client)
    headers = auth_headers(token)
    choice = {"provider": "openai", "model": "gpt-4o-mini", "api_key": API_KEY}

    # A vendor error that escaped the provider's own translation...
    _patch_provider(monkeypatch, FakeLLM(error=RuntimeError(f"401 for key {API_KEY}")))
    failed = await client.post("/api/setup/provider/test", json=choice, headers=headers)
    assert failed.json() == {"ok": False, "error": "The provider call failed (RuntimeError)."}

    # ...a client that cannot even be constructed...
    def exploding_create(*args, **kwargs):
        raise RuntimeError(f"client init failed for key {API_KEY}")

    monkeypatch.setattr(providers, "create_provider", exploding_create)
    await client.post("/api/setup/provider/test", json=choice, headers=headers)

    # ...and a poller that will not start with the token just saved.
    _patch_telegram(monkeypatch)
    env.app.state.telegram_manager = TelegramManager(
        session_factory, service_factory=_FailingService
    )
    saved = await client.put("/api/setup/telegram", json={"token": BOT_TOKEN}, headers=headers)
    assert saved.status_code == 200 and saved.json()["running"] is False

    events = {entry["event"]: entry for entry in captured_logs}
    assert events["setup_provider_test_failed"]["error_type"] == "RuntimeError"
    assert events["setup_provider_init_failed"]["error_type"] == "RuntimeError"
    assert "telegram_manager_start_failed" in events
    assert events["installation_listener_failed"]["error_type"] == "RuntimeError"
    dumped = repr(captured_logs)
    assert API_KEY not in dumped
    assert BOT_TOKEN not in dumped


def test_httpx_request_lines_are_not_logged():
    """httpx logs every request URL at INFO, and a Telegram URL carries the
    bot token in its path."""
    import logging

    from core.logging_config import configure_logging

    configure_logging()
    assert logging.getLogger("httpx").getEffectiveLevel() >= logging.WARNING
    assert logging.getLogger("httpcore").getEffectiveLevel() >= logging.WARNING


# ---------------------------------------------------------------------------
# Rate limit covers the saves too
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_saves_count_toward_the_same_limit_as_tests(client, env, monkeypatch):
    token = await _owner_token(client)
    headers = auth_headers(token)
    _patch_provider(monkeypatch, FakeLLM())
    _patch_telegram(monkeypatch)
    choice = {"provider": "gemini", "model": "gemini-2.5-flash", "api_key": "k"}

    for _ in range(5):
        saved = await client.put("/api/setup/provider", json=choice, headers=headers)
        assert saved.status_code == 200
    tested = await client.post("/api/setup/provider/test", json=choice, headers=headers)
    assert tested.status_code == 429
    again = await client.put("/api/setup/provider", json=choice, headers=headers)
    assert again.status_code == 429

    for _ in range(5):
        saved = await client.put("/api/setup/telegram", json={"token": BOT_TOKEN}, headers=headers)
        assert saved.status_code == 200
    tested = await client.post(
        "/api/setup/telegram/test", json={"token": BOT_TOKEN}, headers=headers
    )
    assert tested.status_code == 429


# ---------------------------------------------------------------------------
# Stored secrets the current ENCRYPTION_KEY cannot read
# ---------------------------------------------------------------------------


def _other_encryption_key() -> str:
    return base64.urlsafe_b64encode(os.urandom(32)).decode("utf-8")


@pytest.mark.asyncio
async def test_unreadable_stored_keys_block_a_save_until_cleared(
    client, env, monkeypatch, session_factory
):
    token = await _owner_token(client)
    headers = auth_headers(token)
    _patch_provider(monkeypatch, FakeLLM())
    choice = {"provider": "openai", "model": "gpt-4o-mini", "api_key": API_KEY}
    assert (await client.put("/api/setup/provider", json=choice, headers=headers)).status_code == 200
    assert (await client.get("/api/setup/status")).json()["secrets_unreadable"] is False

    # The key the blob was sealed with is gone (rotated, or a fresh .env).
    monkeypatch.setattr(settings, "ENCRYPTION_KEY", _other_encryption_key())
    env.installation.invalidate()
    assert (await client.get("/api/setup/status")).json()["secrets_unreadable"] is True

    new_choice = {"provider": "anthropic", "model": "claude-sonnet-5", "api_key": "sk-new-key-123"}
    refused = await client.put("/api/setup/provider", json=new_choice, headers=headers)
    assert refused.status_code == 409
    assert refused.json()["detail"] == UNREADABLE_KEYS_MESSAGE
    assert "sk-new-key-123" not in refused.text

    cleared = await client.delete("/api/setup/secrets", headers=headers)
    assert cleared.status_code == 204 and cleared.content == b""
    assert (await client.get("/api/setup/status")).json()["secrets_unreadable"] is False
    row = await _latest_audit(session_factory, "installation_secrets_cleared")
    assert row is not None and row.endpoint == "/api/setup/secrets"

    again = await client.put("/api/setup/provider", json=new_choice, headers=headers)
    assert again.status_code == 200
    assert await env.installation.llm_api_key("anthropic") == "sk-new-key-123"


@pytest.mark.asyncio
async def test_save_provider_maps_a_service_value_error_to_422(client, env, monkeypatch):
    token = await _owner_token(client)
    _patch_provider(monkeypatch, FakeLLM())

    async def refuse(*args, **kwargs):
        raise ValueError("A model is required")

    monkeypatch.setattr(env.installation, "set_llm", refuse)
    resp = await client.put(
        "/api/setup/provider",
        json={"provider": "gemini", "model": "gemini-2.5-flash", "api_key": "k"},
        headers=auth_headers(token),
    )
    assert resp.status_code == 422
    assert resp.json()["detail"] == "A model is required"


@pytest.mark.asyncio
async def test_clearing_secrets_stops_the_poller(client, env, monkeypatch):
    token = await _owner_token(client)
    _patch_telegram(monkeypatch)
    await client.put("/api/setup/telegram", json={"token": BOT_TOKEN}, headers=auth_headers(token))
    assert env.manager.is_running is True

    resp = await client.delete("/api/setup/secrets", headers=auth_headers(token))
    assert resp.status_code == 204
    assert await env.installation.telegram_token() is None
    assert env.manager.is_running is False
