"""Tests for app wiring: `main.wire_services` correctly hangs the installation
service, capability gates, the permissions prompt, and the Telegram manager
onto the app, and that a runtime construction error is surfaced rather than
swallowed.

Why it exists: The `client` fixture never runs the app lifespan, so these tests
call `wire_services` directly to guard the one place all of these services are
actually connected together in production.

App wiring: the installation service, capability gates, permissions
prompt and Telegram manager as main.wire_services hangs them on the app.

The `client` fixture never runs the lifespan, so these tests call
wire_services themselves against the test database, with a fake Telegram
service and no bot token from the developer's environment. app.state is
restored afterwards so no other test sees the wiring.
"""

from __future__ import annotations

import dataclasses
from typing import Any

import pytest
import pytest_asyncio

from core.config import settings
from services import capabilities as capability_registry
from services.agent.runtime import AgentResponse
from services.agent.tool_registry import BUILTIN_CONNECTOR_TYPES, ConnectorToolExecutor
from services.capabilities.base import ReportContext
from tests.conftest import auth_headers, make_user, use_provider
from tests.test_telegram_manager import FakeService

BOT_TOKEN = "123456:" + "x" * 30


@pytest_asyncio.fixture
async def wired_app(session_factory, monkeypatch):
    from main import app, wire_services

    monkeypatch.setattr(settings, "TELEGRAM_BOT_TOKEN", "", raising=False)
    FakeService.instances.clear()
    saved = dict(app.state._state)
    await wire_services(app, session_factory, telegram_service_factory=FakeService)
    try:
        yield app
    finally:
        await app.state.telegram_manager.stop()
        app.state._state.clear()
        app.state._state.update(saved)


# ── health and Telegram status ──────────────────────────────────────────


@pytest.mark.asyncio
async def test_health_is_still_ok(client):
    resp = await client.get("/api/health")
    assert resp.status_code == 200
    assert resp.json()["status"] == "healthy"


@pytest.mark.asyncio
async def test_telegram_status_follows_the_saved_token_without_restart(
    client, session_factory, wired_app
):
    user, token = await make_user(session_factory, "wiring-owner@example.com")
    installation = wired_app.state.installation

    resp = await client.get("/api/telegram/status", headers=auth_headers(token))
    assert resp.status_code == 200
    assert resp.json()["configured"] is False
    assert FakeService.instances == []

    await installation.set_telegram_token(BOT_TOKEN, actor_id=user.id)

    resp = await client.get("/api/telegram/status", headers=auth_headers(token))
    assert resp.json()["configured"] is True
    assert resp.json()["bot_username"] == "crawler_bot"
    service = FakeService.instances[-1]
    assert service.started and service.token == BOT_TOKEN
    # The manager's on_start hook wired the agent pipelines into the poller.
    assert callable(service.decide) and callable(service.chat)

    # Switching the capability off stops the poller, again with no restart.
    await installation.set_capabilities({"telegram": False}, actor_id=user.id)
    resp = await client.get("/api/telegram/status", headers=auth_headers(token))
    assert resp.json()["configured"] is False
    assert service.stopped


@pytest.mark.asyncio
async def test_reminder_channel_reports_not_delivered_while_stopped(wired_app):
    state = wired_app.state
    # The sweeper is wired to the manager once; stopped, it reports "not
    # delivered" instead of raising.
    assert await state.reminders.send("u1", "hello") is False


class CountingFactory:
    """The test session factory, counting how often it is opened."""

    def __init__(self, inner):
        self._inner = inner
        self.opened = 0

    def __call__(self):
        self.opened += 1
        return self._inner()


@pytest.mark.asyncio
async def test_telegram_pipelines_use_the_wired_session_factory(session_factory, monkeypatch):
    """The poller's approval and chat pipelines open the session factory
    wire_services was given, never the module-level default."""
    import api.routes.agent as agent_routes
    from main import app, wire_services

    def global_factory():
        raise AssertionError("a Telegram pipeline opened the global session factory")

    monkeypatch.setattr(agent_routes, "async_session", global_factory)
    monkeypatch.setattr(settings, "TELEGRAM_BOT_TOKEN", "", raising=False)
    FakeService.instances.clear()
    factory = CountingFactory(session_factory)
    saved = dict(app.state._state)
    await wire_services(app, factory, telegram_service_factory=FakeService)
    try:
        user, _ = await make_user(session_factory, "wiring-tg-factory@example.com")
        await app.state.installation.set_telegram_token(BOT_TOKEN, actor_id=user.id)
        service = FakeService.instances[-1]

        before = factory.opened
        denied = await service.decide(str(user.id), "no-such-action", False)
        assert "error" in denied
        assert factory.opened > before

        class Provider:
            async def complete(self, messages, tools=None):
                from services.agent.providers import LLMResponse

                return LLMResponse(content="hello from the model")

            async def aclose(self):
                pass

        use_provider(app.state.agent_runtime, Provider())
        before = factory.opened
        reply = await service.chat(str(user.id), "hi there")
        assert reply.get("content") == "hello from the model", reply
        assert factory.opened > before
    finally:
        await app.state.telegram_manager.stop()
        app.state._state.clear()
        app.state._state.update(saved)


@pytest.mark.asyncio
async def test_a_runtime_construction_error_is_not_swallowed(session_factory, monkeypatch):
    """No silent agent_runtime = None: a broken runtime fails startup
    instead of leaving /api/health reporting healthy with no agent."""
    import main

    class ConstructionBug(Exception):
        pass

    def broken_runtime(*_args, **_kwargs):
        raise ConstructionBug("runtime construction failed")

    monkeypatch.setattr(main, "AgentRuntime", broken_runtime)
    monkeypatch.setattr(settings, "TELEGRAM_BOT_TOKEN", "", raising=False)
    saved = dict(main.app.state._state)
    try:
        with pytest.raises(ConstructionBug):
            await main.wire_services(
                main.app, session_factory, telegram_service_factory=FakeService
            )
    finally:
        main.app.state._state.clear()
        main.app.state._state.update(saved)


# ── runtime wiring ──────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_llm_change_drops_cached_providers(session_factory, wired_app):
    user, _ = await make_user(session_factory, "wiring-llm@example.com")
    runtime = wired_app.state.agent_runtime

    class Provider:
        async def aclose(self):
            pass

    use_provider(runtime, Provider())
    assert runtime._provider_cache
    await wired_app.state.installation.set_llm(
        "anthropic", "claude-sonnet-4-6", "sk-test-not-real", actor_id=user.id
    )
    assert not runtime._provider_cache


@pytest.mark.asyncio
async def test_runtime_gates_follow_the_owner_switches(session_factory, wired_app, monkeypatch):
    user, _ = await make_user(session_factory, "wiring-gates@example.com")
    runtime = wired_app.state.agent_runtime
    installation = wired_app.state.installation

    # If the gate failed, web.search must hit a tripwire, not the network.
    async def tripwire(action, params, user_id, approved):
        raise AssertionError("the web gate let web.search reach the real toolkit")

    builtins = runtime._executor._builtins
    monkeypatch.setitem(builtins, "web", dataclasses.replace(builtins["web"], call=tripwire))

    assert await runtime._permissions.check("u1", "web.search", {}) == "approved"
    await installation.set_capabilities({"web_browsing": False}, actor_id=user.id)
    assert await runtime._permissions.check("u1", "web.search", {}) == "blocked"
    refused = await runtime._executor.execute("web.search", {"query": "x"}, "u1")
    assert refused["ok"] is False and refused["capability"] == "web_browsing"


@pytest.mark.asyncio
async def test_install_button_and_agent_share_one_installer(wired_app, monkeypatch):
    # The owner's Install button uses app.state.system_toolkit; the agent's
    # system.* calls must reach that same instance (and so its lock).
    toolkit = wired_app.state.system_toolkit

    async def marked():
        return {"ok": True, "same_instance": True}

    monkeypatch.setattr(toolkit, "capabilities", marked)
    result = await wired_app.state.agent_runtime._executor.execute(
        "system.capabilities", {}, "u1"
    )
    assert result == {"ok": True, "same_instance": True}


@pytest.mark.asyncio
async def test_system_capabilities_reports_the_permission_switches(wired_app):
    result = await wired_app.state.agent_runtime._executor.execute(
        "system.capabilities", {}, "u1"
    )
    assert result["ok"] is True
    assert [c["name"] for c in result["capabilities"]] == ["browser"]
    by_key = {p["key"]: p for p in result["permissions"]}
    assert set(by_key) == set(capability_registry.keys())
    assert by_key["screen"]["enabled"] is False
    assert by_key["screen"]["effective"] == "off"


# ── executor toolkit map ─────────────────────────────────────────────────


def test_every_builtin_type_has_a_toolkit():
    assert set(ConnectorToolExecutor()._builtins) == set(BUILTIN_CONNECTOR_TYPES)


class RecordingReminders:
    def __init__(self):
        self.calls: list[tuple[str, dict[str, Any], str]] = []

    async def execute(self, action, params, user_id):
        self.calls.append((action, params, user_id))
        return {"ok": True}


class RecordingSystem:
    def __init__(self):
        self.calls: list[tuple[str, dict[str, Any]]] = []

    async def execute(self, action, params):
        self.calls.append((action, params))
        return {"ok": True, "name": params.get("name")}


@pytest.mark.asyncio
async def test_reminders_run_under_the_caller_identity_only():
    reminders = RecordingReminders()
    ex = ConnectorToolExecutor(reminder_toolkit=reminders)
    result = await ex.execute(
        "reminders.list", {"user_id": "someone-else"}, user_id="caller"
    )
    assert result == {"ok": True}
    assert reminders.calls == [("list", {"user_id": "someone-else"}, "caller")]


@pytest.mark.asyncio
async def test_system_install_needs_approval_and_runs_with_it():
    system = RecordingSystem()
    ex = ConnectorToolExecutor(system_toolkit=system)

    refused = await ex.execute(
        "system.install_capability", {"name": "browser", "user_confirmed": True}, "u1"
    )
    assert refused == {
        "ok": False,
        "requires_approval": True,
        "error": (
            "Action requires user confirmation: system.install_capability "
            "installs software on this machine and runs only after the user "
            "approves it."
        ),
    }
    assert system.calls == []

    ran = await ex.execute("system.install_capability", {"name": "browser"}, "u1", approved=True)
    assert ran["ok"] is True
    assert system.calls == [("install_capability", {"name": "browser"})]


# ── route helpers: offer, permissions block, image delivery ──────────────


class FakeInstallation:
    """Screen switched on, on a platform where capture needs no OS grant,
    so the report is computed without touching the real display."""

    def __init__(self, **switches: bool):
        self._switches = {**capability_registry.default_switches(), **switches}

    async def report(self):
        ctx = ReportContext(
            in_container=False,
            platform="win32",
            telegram_configured=False,
            browser_installed=False,
        )
        return capability_registry.report(self._switches, ctx, use_cache=False)


@pytest.mark.asyncio
async def test_offer_and_permissions_block_come_from_one_report(session_factory):
    from api.routes.agent import _build_tools_and_memory

    user, _ = await make_user(session_factory, "wiring-offer@example.com")
    async with session_factory() as db:
        tools, _memory, permissions = await _build_tools_and_memory(
            None, user, db, FakeInstallation(screen=True, reminders=False)
        )
    offered = {t.name for t in tools}
    assert "desktop.screenshot" in offered
    assert not any(
        n.startswith("reminders.") and n not in capability_registry.ALWAYS_ON_TOOLS
        for n in offered
    )
    # Browser not installed: website screenshots are blocked, not offered.
    assert "web.screenshot" not in offered
    assert permissions.startswith("<permissions>")
    assert "- See my screen: on" in permissions
    assert "- Reminders: off" in permissions
    assert "- Screenshots of websites: blocked" in permissions


@pytest.mark.asyncio
async def test_unwired_offer_uses_registry_defaults(session_factory):
    from api.routes.agent import _build_tools_and_memory

    user, _ = await make_user(session_factory, "wiring-defaults@example.com")
    async with session_factory() as db:
        tools, _memory, permissions = await _build_tools_and_memory(None, user, db)
    assert "desktop.screenshot" not in {t.name for t in tools}
    assert "- See my screen: off" in permissions


def _image(tag: str) -> str:
    return "data:image/jpeg;base64," + tag


@pytest.mark.asyncio
async def test_channel_turn_delivers_tool_images_and_passes_permissions(
    client, session_factory
):
    from api.routes.agent import MAX_CHANNEL_IMAGES, build_chat_applier
    from main import app

    user, _ = await make_user(session_factory, "wiring-images@example.com")
    seen: dict[str, Any] = {}

    class FakeRuntime:
        async def chat(self, **kwargs):
            seen.update(kwargs)
            return AgentResponse(
                content="Here you go.",
                tool_calls=[
                    {"name": "web.fetch_page", "result": {"ok": True, "text": "page"}},
                    {
                        "name": "web.screenshot",
                        "result": {"ok": True, "image": _image("A"), "final_url": "https://example.com/"},
                    },
                    {"name": "desktop.screenshot", "result": {"ok": True, "image": _image("B")}},
                    {"name": "desktop.screenshot", "result": {"ok": False, "error": "denied"}},
                    {"name": "desktop.screenshot", "result": {"ok": True, "image": _image("C")}},
                    {"name": "desktop.screenshot", "result": {"ok": True, "image": _image("D")}},
                ],
            )

    saved = dict(app.state._state)
    app.state.agent_runtime = FakeRuntime()
    app.state.installation = FakeInstallation(screen=True)
    try:
        outcome = await build_chat_applier(app, session_factory=session_factory)(
            str(user.id), "show me my screen"
        )
    finally:
        app.state._state.clear()
        app.state._state.update(saved)

    assert "error" not in outcome
    assert len(outcome["images"]) == MAX_CHANNEL_IMAGES == 3
    assert outcome["images"] == [
        {"data_url": _image("A"), "caption": "https://example.com/"},
        {"data_url": _image("B"), "caption": "Your screen"},
        {"data_url": _image("C"), "caption": "Your screen"},
    ]
    assert "- See my screen: on" in seen["permissions_text"]
    assert "desktop.screenshot" in {t.name for t in seen["tools"]}


@pytest.mark.asyncio
async def test_channel_delivers_only_builtin_raster_images(client, session_factory):
    """A third-party (MCP) tool, a name that does not resolve, and a
    non-raster data URL (SVG can carry script; GIF is not a type the tools
    produce) are never forwarded to the person as photos."""
    from api.routes.agent import build_chat_applier
    from main import app

    user, _ = await make_user(session_factory, "wiring-image-filter@example.com")
    png = "data:image/png;base64,QUJD"
    webp = "data:image/webp;base64,QUJD"

    class FakeRuntime:
        async def chat(self, **kwargs):
            return AgentResponse(
                content="Here you go.",
                tool_calls=[
                    {"name": "mcp.photos.latest", "result": {"ok": True, "image": _image("M")}},
                    {"name": "made.up", "result": {"ok": True, "image": _image("U")}},
                    {"name": "desktop__deadbeef.screenshot", "result": {"ok": True, "image": _image("S")}},
                    {"name": "web.screenshot", "result": {"ok": True, "image": "data:image/svg+xml;base64,PHN2Zz4="}},
                    {"name": "web.screenshot", "result": {"ok": True, "image": "data:image/gif;base64,R0lG"}},
                    {"name": "web.screenshot", "result": {"ok": True, "image": "data:image/png,QUJD"}},
                    {"name": "web.screenshot", "result": {"ok": True, "image": png, "final_url": "https://a.example/"}},
                    {"name": "desktop.screenshot", "result": {"ok": True, "image": webp}},
                ],
            )

    saved = dict(app.state._state)
    app.state.agent_runtime = FakeRuntime()
    app.state.installation = FakeInstallation(screen=True)
    try:
        outcome = await build_chat_applier(app, session_factory=session_factory)(
            str(user.id), "show me"
        )
    finally:
        app.state._state.clear()
        app.state._state.update(saved)

    assert outcome["images"] == [
        {"data_url": png, "caption": "https://a.example/"},
        {"data_url": webp, "caption": "Your screen"},
    ]
