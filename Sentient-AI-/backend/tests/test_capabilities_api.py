"""The capabilities HTTP API (/api/capabilities).

Reading the report is open to every signed-in user (the chat UI explains
why a tool is unavailable); every write is the owner's alone. The routes
reach the InstallationService through app.state, which the lifespan sets
in production; these tests set it themselves because httpx's ASGI
transport never runs the lifespan.
"""

from __future__ import annotations

import asyncio
from typing import Any

import pytest
import pytest_asyncio
from sqlalchemy import select

from models.audit import AuditLog
from services import capabilities
from services.capabilities import screen
from services.capabilities.base import CapabilityStatus
from services.tools.system import SystemToolkit
from tests.conftest import auth_headers, make_user

STATUS_KEYS = set(CapabilityStatus.__dataclass_fields__)


@pytest_asyncio.fixture
async def installation(session_factory, monkeypatch):
    from api.routes import capabilities as capabilities_routes
    from main import app
    from services.installation import InstallationService

    service = InstallationService(session_factory)
    app.state.installation = service
    # The capabilities routes write audit rows through their own short-lived
    # sessions (core.database.async_session in production); the client
    # fixture only overrides get_db, so without this those rows would miss
    # the test's in-memory database.
    monkeypatch.setattr(capabilities_routes, "_session_factory", session_factory)
    capabilities.clear_probe_cache()
    yield service
    try:
        del app.state.installation
    except AttributeError:
        pass
    capabilities.clear_probe_cache()


@pytest_asyncio.fixture
async def owner(client, installation):
    """The owner comes from the wizard's first step, as on a real install:
    open registration stays closed until setup is complete."""
    created = await client.post(
        "/api/setup/owner",
        json={"email": "owner@example.com", "password": "password-123"},
    )
    assert created.status_code == 200, created.text
    body = created.json()
    return auth_headers(body["access_token"]), body["user"]["id"]


@pytest_asyncio.fixture
async def guest(owner, session_factory):
    """A second, non-admin account, created directly: /auth/register is
    closed while the wizard is unfinished."""
    _user, token = await make_user(session_factory, "guest@example.com")
    return auth_headers(token)


def _by_key(body: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {item["key"]: item for item in body["capabilities"]}


def _force_native_mac(monkeypatch, *, granted: bool) -> None:
    """Make screen available regardless of where the suite runs.

    ``default_context`` reads the names bound in the package namespace, so
    both those and the env module's originals are patched."""
    monkeypatch.delenv("CRAWLER_CONTAINER", raising=False)
    for target in (capabilities.env, capabilities):
        monkeypatch.setattr(target, "in_container", lambda: False)
        monkeypatch.setattr(target, "platform_name", lambda: "darwin")
    monkeypatch.setattr(screen.macos, "screen_capture_preflight", lambda: granted)


async def _audit_rows(session_factory, user_id: str) -> list[AuditLog]:
    import uuid

    async with session_factory() as session:
        result = await session.execute(
            select(AuditLog)
            .where(AuditLog.user_id == uuid.UUID(user_id))
            .where(AuditLog.connector_name == "installation")
            .order_by(AuditLog.seq)
        )
        return list(result.scalars())


# ── GET ──────────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_report_is_readable_by_any_user(client, guest):
    resp = await client.get("/api/capabilities", headers=guest)
    assert resp.status_code == 200
    statuses = _by_key(resp.json())
    assert set(statuses) == set(capabilities.keys())
    assert statuses["screen"]["effective"] == "off"
    assert statuses["screen"]["enabled"] is False


@pytest.mark.asyncio
async def test_report_requires_authentication(client, installation):
    resp = await client.get("/api/capabilities")
    assert resp.status_code in (401, 403)


@pytest.mark.asyncio
async def test_missing_installation_service_is_503(client, session_factory):
    """No installation fixture here: app.state.installation is unset, as it
    is before the lifespan wires it."""
    _user, token = await make_user(session_factory)
    resp = await client.get("/api/capabilities", headers=auth_headers(token))
    assert resp.status_code == 503


# ── PUT ──────────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_update_is_admin_only(client, guest):
    resp = await client.put(
        "/api/capabilities", json={"capabilities": {"web_browsing": False}}, headers=guest
    )
    assert resp.status_code == 403
    # And nothing changed.
    after = _by_key((await client.get("/api/capabilities", headers=guest)).json())
    assert after["web_browsing"]["enabled"] is True


@pytest.mark.asyncio
async def test_admin_enables_screen_but_container_blocks_it(
    client, owner, session_factory, monkeypatch
):
    monkeypatch.setenv("CRAWLER_CONTAINER", "1")
    headers, user_id = owner
    resp = await client.put(
        "/api/capabilities", json={"capabilities": {"screen": True}}, headers=headers
    )
    assert resp.status_code == 200, resp.text
    st = _by_key(resp.json())["screen"]
    assert st["enabled"] is True
    assert st["effective"] == "blocked"
    assert "container" in st["reason"].lower()

    # The switch persisted and the change is audited with the actor.
    again = _by_key((await client.get("/api/capabilities", headers=headers)).json())
    assert again["screen"]["enabled"] is True
    actions = [row.action for row in await _audit_rows(session_factory, user_id)]
    assert "capabilities_updated" in actions


@pytest.mark.asyncio
async def test_update_rejects_unknown_key(client, owner):
    headers, _ = owner
    resp = await client.put(
        "/api/capabilities", json={"capabilities": {"teleport": True}}, headers=headers
    )
    assert resp.status_code == 422
    assert "teleport" in resp.text


@pytest.mark.asyncio
async def test_update_rejects_non_boolean_values(client, owner):
    headers, _ = owner
    resp = await client.put(
        "/api/capabilities", json={"capabilities": {"screen": "yes"}}, headers=headers
    )
    assert resp.status_code == 422
    after = _by_key((await client.get("/api/capabilities", headers=headers)).json())
    assert after["screen"]["enabled"] is False


# ── POST /{key}/request-access ───────────────────────────────────────────────


@pytest.mark.asyncio
async def test_request_access_in_container_is_409(client, owner, monkeypatch):
    monkeypatch.setenv("CRAWLER_CONTAINER", "1")
    headers, _ = owner
    await client.put(
        "/api/capabilities", json={"capabilities": {"screen": True}}, headers=headers
    )
    resp = await client.post("/api/capabilities/screen/request-access", headers=headers)
    assert resp.status_code == 409
    assert "container" in resp.json()["detail"].lower()


@pytest.mark.asyncio
async def test_request_access_without_a_prompt_is_409(client, owner):
    headers, _ = owner
    resp = await client.post(
        "/api/capabilities/web_browsing/request-access", headers=headers
    )
    assert resp.status_code == 409


@pytest.mark.asyncio
async def test_request_access_runs_prompt_and_returns_fresh_status(
    client, owner, session_factory, monkeypatch
):
    headers, user_id = owner
    _force_native_mac(monkeypatch, granted=False)
    calls: list[str] = []
    granted = {"value": False}

    def fake_request() -> bool:
        calls.append("request")
        granted["value"] = True  # the user clicked Allow in the OS prompt
        return True

    def fake_open_settings(*_args: Any, **_kwargs: Any) -> bool:
        calls.append("settings")
        return True

    monkeypatch.setattr(screen.macos, "screen_capture_request", fake_request)
    monkeypatch.setattr(screen.macos, "open_settings", fake_open_settings)
    monkeypatch.setattr(screen.macos, "screen_capture_preflight", lambda: granted["value"])

    enabled = await client.put(
        "/api/capabilities", json={"capabilities": {"screen": True}}, headers=headers
    )
    before = _by_key(enabled.json())["screen"]
    assert before["effective"] == "blocked"
    assert before["probe_state"] == "denied"
    assert before["can_request_access"] is True

    resp = await client.post("/api/capabilities/screen/request-access", headers=headers)
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["ok"] is True
    assert calls == ["request", "settings"]  # request_access ran exactly once
    # The probe cache was cleared, so the answer reflects the new grant
    # instead of the denial cached a moment ago.
    assert body["status"]["key"] == "screen"
    assert body["status"]["probe_state"] == "granted"
    assert body["status"]["effective"] == "on"
    assert set(body["status"]) == STATUS_KEYS

    actions = [row.action for row in await _audit_rows(session_factory, user_id)]
    assert "capability_access_requested" in actions


@pytest.mark.asyncio
async def test_request_access_unknown_capability_is_404(client, owner):
    headers, _ = owner
    resp = await client.post("/api/capabilities/teleport/request-access", headers=headers)
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_request_access_when_switched_off_is_409_and_skips_request(
    client, owner, monkeypatch
):
    """A capability the owner never turned on has nothing to request, even
    though it is otherwise available: the old guard only checked
    ``available``, so it would have called request_access() here."""
    headers, _ = owner
    _force_native_mac(monkeypatch, granted=False)
    calls: list[str] = []
    monkeypatch.setattr(
        screen.macos, "screen_capture_request", lambda: calls.append("request") or True
    )
    monkeypatch.setattr(
        screen.macos, "open_settings", lambda *a, **k: calls.append("settings") or True
    )

    resp = await client.post("/api/capabilities/screen/request-access", headers=headers)
    assert resp.status_code == 409
    assert calls == []


@pytest.mark.asyncio
async def test_request_access_when_already_granted_is_409(client, owner, monkeypatch):
    headers, _ = owner
    _force_native_mac(monkeypatch, granted=True)
    calls: list[str] = []
    monkeypatch.setattr(
        screen.macos, "screen_capture_request", lambda: calls.append("request") or True
    )
    monkeypatch.setattr(
        screen.macos, "open_settings", lambda *a, **k: calls.append("settings") or True
    )

    await client.put(
        "/api/capabilities", json={"capabilities": {"screen": True}}, headers=headers
    )
    resp = await client.post("/api/capabilities/screen/request-access", headers=headers)
    assert resp.status_code == 409
    assert calls == []


@pytest.mark.asyncio
async def test_request_access_failure_is_audited_with_generic_error(
    client, owner, session_factory, monkeypatch
):
    headers, user_id = owner
    _force_native_mac(monkeypatch, granted=False)

    def boom() -> None:
        raise RuntimeError("permission daemon exploded")

    monkeypatch.setattr(screen.macos, "screen_capture_request", boom)

    await client.put(
        "/api/capabilities", json={"capabilities": {"screen": True}}, headers=headers
    )
    resp = await client.post("/api/capabilities/screen/request-access", headers=headers)
    assert resp.status_code == 500
    assert resp.json() == {"detail": "Could not open the permission prompt."}
    assert "exploded" not in resp.text

    failed = [
        row
        for row in await _audit_rows(session_factory, user_id)
        if row.action == "capability_access_request_failed"
    ]
    assert len(failed) == 1
    assert failed[0].request_data == {"capability": "screen", "error_type": "RuntimeError"}


# ── POST /{key}/install ──────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_install_runs_allowlisted_install_and_audits(
    client, owner, session_factory, monkeypatch
):
    headers, user_id = owner
    seen: list[str] = []
    result = {"ok": True, "name": "browser", "installed_now": True, "log_tail": "done"}

    async def fake_install(self, name: str) -> dict[str, Any]:
        seen.append(name)
        return dict(result)

    monkeypatch.setattr(SystemToolkit, "install_capability", fake_install)

    resp = await client.post("/api/capabilities/site_screenshots/install", headers=headers)
    assert resp.status_code == 200, resp.text
    assert resp.json() == result
    assert seen == ["browser"]

    rows = await _audit_rows(session_factory, user_id)
    by_action = {row.action: row for row in rows}
    assert "capability_install_started" in by_action
    finished = by_action["capability_install_finished"]
    assert finished.request_data == {
        "capability": "site_screenshots",
        "install": "browser",
        "ok": True,
    }
    assert finished.endpoint == "/api/capabilities/site_screenshots/install"
    assert finished.scope_used == "admin"
    actions = [row.action for row in rows]
    assert actions.index("capability_install_started") < actions.index(
        "capability_install_finished"
    )


@pytest.mark.asyncio
async def test_a_successful_install_shows_up_in_the_next_report(client, owner, monkeypatch):
    """The report is cached for a few seconds; a browser the owner just
    installed must not read as missing until that runs out."""
    import services.tools.system as system_module

    headers, _ = owner
    installed = {"value": False}
    monkeypatch.setattr(system_module, "browser_installed", lambda: installed["value"])

    before = _by_key((await client.get("/api/capabilities", headers=headers)).json())
    assert before["site_screenshots"]["effective"] == "blocked"

    async def fake_install(self, name: str) -> dict[str, Any]:
        installed["value"] = True
        return {"ok": True, "name": name, "installed_now": True}

    monkeypatch.setattr(SystemToolkit, "install_capability", fake_install)
    resp = await client.post("/api/capabilities/site_screenshots/install", headers=headers)
    assert resp.status_code == 200, resp.text

    after = _by_key((await client.get("/api/capabilities", headers=headers)).json())
    assert after["site_screenshots"]["effective"] == "on"


@pytest.mark.asyncio
async def test_install_failure_is_passed_through_and_audited(
    client, owner, session_factory, monkeypatch
):
    headers, user_id = owner

    async def fake_install(self, name: str) -> dict[str, Any]:
        return {"ok": False, "error": "'python -m pip install' exited with status 1."}

    monkeypatch.setattr(SystemToolkit, "install_capability", fake_install)

    resp = await client.post("/api/capabilities/site_screenshots/install", headers=headers)
    assert resp.status_code == 200
    assert resp.json()["ok"] is False
    finished = [
        row
        for row in await _audit_rows(session_factory, user_id)
        if row.action == "capability_install_finished"
    ]
    assert finished and finished[0].request_data["ok"] is False


@pytest.mark.asyncio
async def test_install_uses_app_state_system_toolkit_when_set(client, owner, monkeypatch):
    """A wired app hands the route a shared toolkit through app.state; the
    route must use that one instead of the module-level fallback."""
    from main import app

    headers, _ = owner
    calls: list[str] = []

    class FakeToolkit:
        async def install_capability(self, name: str) -> dict[str, Any]:
            calls.append(name)
            return {"ok": True, "name": name, "installed_now": True}

    async def must_not_run(self, name: str) -> dict[str, Any]:  # pragma: no cover
        raise AssertionError("the module-level toolkit must not be used")

    monkeypatch.setattr(SystemToolkit, "install_capability", must_not_run)
    app.state.system_toolkit = FakeToolkit()
    try:
        resp = await client.post("/api/capabilities/site_screenshots/install", headers=headers)
    finally:
        del app.state.system_toolkit

    assert resp.status_code == 200, resp.text
    assert calls == ["browser"]


@pytest.mark.asyncio
async def test_duplicate_install_is_rejected_without_audit_rows(
    client, owner, session_factory, monkeypatch
):
    headers, user_id = owner
    started = asyncio.Event()
    release = asyncio.Event()

    async def fake_install(self, name: str) -> dict[str, Any]:
        started.set()
        await release.wait()
        return {"ok": True, "name": name, "installed_now": True}

    monkeypatch.setattr(SystemToolkit, "install_capability", fake_install)

    first = asyncio.create_task(
        client.post("/api/capabilities/site_screenshots/install", headers=headers)
    )
    await asyncio.wait_for(started.wait(), timeout=1)

    second = await client.post("/api/capabilities/site_screenshots/install", headers=headers)
    assert second.status_code == 409
    assert second.json() == {"detail": "An install for this capability is already running."}

    release.set()
    first_resp = await first
    assert first_resp.status_code == 200, first_resp.text

    rows = await _audit_rows(session_factory, user_id)
    actions = [row.action for row in rows]
    # The rejected second request must not have added any audit rows.
    assert actions.count("capability_install_started") == 1
    assert actions.count("capability_install_finished") == 1


@pytest.mark.asyncio
async def test_install_crash_returns_generic_error_and_audits(
    client, owner, session_factory, monkeypatch
):
    headers, user_id = owner

    async def fake_install(self, name: str) -> dict[str, Any]:
        raise RuntimeError("pip exploded in a way nobody should see")

    monkeypatch.setattr(SystemToolkit, "install_capability", fake_install)

    resp = await client.post("/api/capabilities/site_screenshots/install", headers=headers)
    assert resp.status_code == 200
    assert resp.json() == {"ok": False, "error": "The install failed unexpectedly."}
    assert "exploded" not in resp.text

    finished = [
        row
        for row in await _audit_rows(session_factory, user_id)
        if row.action == "capability_install_finished"
    ]
    assert finished and finished[0].request_data == {
        "capability": "site_screenshots",
        "install": "browser",
        "ok": False,
    }


@pytest.mark.asyncio
async def test_install_without_an_install_is_409(client, owner, monkeypatch):
    headers, _ = owner

    async def must_not_run(self, name: str) -> dict[str, Any]:  # pragma: no cover
        raise AssertionError("nothing should be installed")

    monkeypatch.setattr(SystemToolkit, "install_capability", must_not_run)
    resp = await client.post("/api/capabilities/web_browsing/install", headers=headers)
    assert resp.status_code == 409


@pytest.mark.asyncio
async def test_install_unknown_capability_is_404(client, owner):
    headers, _ = owner
    resp = await client.post("/api/capabilities/teleport/install", headers=headers)
    assert resp.status_code == 404


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "path",
    [
        "/api/capabilities/screen/request-access",
        "/api/capabilities/site_screenshots/install",
    ],
)
async def test_actions_are_admin_only(client, guest, monkeypatch, path):
    async def must_not_run(self, name: str) -> dict[str, Any]:  # pragma: no cover
        raise AssertionError("a non-admin must not install anything")

    monkeypatch.setattr(SystemToolkit, "install_capability", must_not_run)
    resp = await client.post(path, headers=guest)
    assert resp.status_code == 403


# ── secrets ──────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_responses_carry_only_status_dicts_never_secrets(
    client, owner, installation
):
    import uuid

    headers, user_id = owner
    actor = uuid.UUID(user_id)
    bot_token = "123456789:SENTINEL-telegram-token-never-echo"
    api_key = "sk-ant-SENTINEL-provider-key-never-echo"
    await installation.set_telegram_token(bot_token, actor_id=actor)
    await installation.set_llm("anthropic", "claude-sonnet-4-6", api_key, actor_id=actor)

    got = await client.get("/api/capabilities", headers=headers)
    put = await client.put(
        "/api/capabilities", json={"capabilities": {"web_browsing": True}}, headers=headers
    )
    for resp in (got, put):
        assert resp.status_code == 200
        body = resp.json()
        assert set(body) == {"capabilities"}
        for item in body["capabilities"]:
            assert set(item) == STATUS_KEYS
        assert bot_token not in resp.text
        assert "SENTINEL" not in resp.text
        assert api_key not in resp.text
