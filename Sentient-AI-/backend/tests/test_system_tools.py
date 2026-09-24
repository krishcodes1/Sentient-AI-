"""Built-in system tools: the capability allowlist, the approval gate in
front of installing, and their wiring into the catalog, the permission
engine, the executor and the runtime's approval flow.

Nothing here runs pip or Playwright. The toolkit's subprocess seam is
replaced with a recorder and its installed-check with a stub, so what is
asserted is *which argv would run* and *when*. The runtime tests drive the
real ``AgentRuntime`` with a scripted model, so the path from permission
decision to pending action to approved re-execution is the production one.
"""

from __future__ import annotations

import asyncio
import json
import sys
from typing import Any, Optional

import pytest

from core.config import settings
from services.agent.approvals import InMemoryApprovalStore
from services.agent.permissions import ActionCategory, PermissionEngine, PermissionTier
from services.agent.providers import LLMResponse, ToolCall
from services.agent.runtime import AgentRuntime
from services.agent.tool_registry import (
    BUILTIN_CONNECTOR_TYPES,
    ConnectorToolExecutor,
    RuntimePermissionAdapter,
    build_tools,
)
from services.tools import system as system_module
from services.tools.system import ALLOWLIST, SystemToolkit, browser_installed
from services.tools.web import WebToolkit
from tests.conftest import use_provider

BROWSER_STEPS = [
    [sys.executable, "-m", "pip", "install", "playwright>=1.45,<2.0"],
    [sys.executable, "-m", "playwright", "install", "chromium"],
]
SYSTEM_TOOLS = {"system.capabilities", "system.install_capability"}
PUBLIC_ADDRESS = "93.184.216.34"


class FakeHost:
    """Stands in for the machine: records every argv the toolkit would run
    and flips ``installed`` when the browser download step "runs"."""

    def __init__(self, installed: bool = False, results: Optional[list[Any]] = None) -> None:
        self.installed = installed
        self.calls: list[tuple[list[str], float]] = []
        self._results = list(results or [])

    def detect(self, name: str) -> bool:
        assert name == "browser"
        return self.installed

    async def run(self, argv: list[str], timeout_s: float) -> tuple[int, str]:
        self.calls.append((list(argv), timeout_s))
        if self._results:
            scripted = self._results.pop(0)
            if isinstance(scripted, BaseException):
                raise scripted
            return scripted
        if argv[-2:] == ["install", "chromium"]:
            self.installed = True
        return 0, f"ran: {' '.join(argv[1:])}\n"

    def toolkit(self, **kwargs: Any) -> SystemToolkit:
        return SystemToolkit(runner=self.run, detector=self.detect, **kwargs)


# ---------------------------------------------------------------------------
# Allowlist
# ---------------------------------------------------------------------------


def test_allowlist_holds_fixed_argv_lists_and_nothing_else():
    assert set(ALLOWLIST) == {"browser"}
    browser = ALLOWLIST["browser"]
    assert [list(step) for step in browser.steps] == BROWSER_STEPS
    # Tuples of plain strings: nothing to format, nothing to append to.
    assert isinstance(browser.steps, tuple)
    assert all(isinstance(step, tuple) for step in browser.steps)
    assert all(isinstance(arg, str) for step in browser.steps for arg in step)
    assert browser.description and browser.size_hint


@pytest.mark.asyncio
async def test_install_rejects_unknown_names_without_running_anything():
    host = FakeHost()
    toolkit = host.toolkit()

    for name in ("curl", "browser; rm -rf /", "Browser", "", None, ["browser"]):
        result = await toolkit.execute("install_capability", {"name": name})
        assert result["ok"] is False
        assert result["error"] == "Unknown capability"
        assert result["allowed"] == ["browser"]
    assert host.calls == []


@pytest.mark.asyncio
async def test_install_takes_no_argument_but_the_name():
    host = FakeHost()
    toolkit = host.toolkit()

    result = await toolkit.execute(
        "install_capability", {"name": "browser", "package": "totally-legit"}
    )

    assert result["ok"] is False
    assert "Invalid arguments" in result["error"]
    assert host.calls == []


# ---------------------------------------------------------------------------
# install_capability
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_install_runs_exactly_the_allowlisted_argv():
    host = FakeHost()

    result = await host.toolkit().execute("install_capability", {"name": "browser"})

    assert result["ok"] is True
    assert result["name"] == "browser"
    assert result["installed_now"] is True
    assert "already_installed" not in result
    assert [argv for argv, _ in host.calls] == BROWSER_STEPS
    assert "install chromium" in result["log_tail"]
    # Each step got a real, positive share of the single overall budget.
    assert all(0 < timeout <= system_module.INSTALL_TIMEOUT_S for _, timeout in host.calls)


@pytest.mark.asyncio
async def test_install_short_circuits_when_already_installed():
    host = FakeHost(installed=True)

    result = await host.toolkit().execute("install_capability", {"name": "browser"})

    assert result == {"ok": True, "name": "browser", "already_installed": True}
    assert host.calls == []


@pytest.mark.asyncio
async def test_install_stops_at_the_first_failing_step():
    host = FakeHost(results=[(1, "ERROR: No matching distribution found\n")])

    result = await host.toolkit().execute("install_capability", {"name": "browser"})

    assert result["ok"] is False
    assert "status 1" in result["error"]
    assert "pip install" in result["error"]
    assert result["installed_now"] is False
    assert "No matching distribution" in result["log_tail"]
    assert len(host.calls) == 1  # the browser download never started


@pytest.mark.asyncio
async def test_install_reports_a_step_that_could_not_start():
    host = FakeHost(results=[FileNotFoundError(2, "No such file")])

    result = await host.toolkit().execute("install_capability", {"name": "browser"})

    assert result["ok"] is False
    assert "Could not start" in result["error"]
    assert result["installed_now"] is False
    assert len(host.calls) == 1


@pytest.mark.asyncio
async def test_install_has_one_hard_deadline_for_all_steps():
    # A runner that overran its share raises TimeoutError, as the real one
    # does after killing the process.
    overrun = FakeHost(results=[asyncio.TimeoutError()])
    result = await overrun.toolkit().execute("install_capability", {"name": "browser"})
    assert result["ok"] is False
    assert result["timed_out"] is True
    assert "minute limit" in result["error"]
    assert len(overrun.calls) == 1

    # With no budget left nothing is even started.
    exhausted = FakeHost()
    result = await exhausted.toolkit(timeout_s=0.0).execute(
        "install_capability", {"name": "browser"}
    )
    assert result["ok"] is False
    assert result["timed_out"] is True
    assert exhausted.calls == []


@pytest.mark.asyncio
async def test_install_caps_the_log_it_hands_back():
    host = FakeHost(results=[(0, "x" * 10_000), (0, "tail-marker")])

    result = await host.toolkit().execute("install_capability", {"name": "browser"})

    assert result["ok"] is True
    assert len(result["log_tail"]) <= 2048
    assert result["log_tail"].endswith("tail-marker")


@pytest.mark.asyncio
async def test_concurrent_installs_of_one_capability_run_once():
    gate = asyncio.Event()
    host = FakeHost()
    real_run = host.run

    async def slow_run(argv: list[str], timeout_s: float) -> tuple[int, str]:
        await gate.wait()
        return await real_run(argv, timeout_s)

    toolkit = SystemToolkit(runner=slow_run, detector=host.detect)
    first = asyncio.create_task(toolkit.install_capability("browser"))
    second = asyncio.create_task(toolkit.install_capability("browser"))
    await asyncio.sleep(0)
    gate.set()
    results = await asyncio.gather(first, second)

    assert [argv for argv, _ in host.calls] == BROWSER_STEPS  # two steps, not four
    assert sorted(r.get("installed_now", False) for r in results) == [False, True]
    assert any(r.get("already_installed") for r in results)


@pytest.mark.asyncio
async def test_install_says_so_when_the_probe_still_reports_missing():
    host = FakeHost(results=[(0, "ok"), (0, "ok")])  # scripted: never flips installed

    result = await host.toolkit().execute("install_capability", {"name": "browser"})

    assert result["ok"] is True
    assert result["installed_now"] is False
    assert "not detected" in result["note"]


# ---------------------------------------------------------------------------
# capabilities
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_capabilities_reports_installed_and_missing():
    missing = await FakeHost(installed=False).toolkit().execute("capabilities", {})
    present = await FakeHost(installed=True).toolkit().execute("capabilities", {})

    assert missing["ok"] is True and present["ok"] is True
    (entry,) = missing["capabilities"]
    assert entry["name"] == "browser"
    assert entry["installed"] is False
    assert "web.screenshot" in entry["description"]
    assert "MB" in entry["size_hint"]
    assert present["capabilities"][0]["installed"] is True


@pytest.mark.asyncio
async def test_a_broken_probe_reads_as_missing_not_as_a_crash():
    def exploding(name: str) -> bool:
        raise RuntimeError("probe broke")

    toolkit = SystemToolkit(runner=FakeHost().run, detector=exploding)
    result = await toolkit.execute("capabilities", {})

    assert result["capabilities"][0]["installed"] is False


@pytest.mark.asyncio
async def test_unknown_system_action_fails_closed():
    result = await FakeHost().toolkit().execute("uninstall", {"name": "browser"})
    assert result["ok"] is False


# ---------------------------------------------------------------------------
# Browser detection (filesystem probe, no Playwright involved)
# ---------------------------------------------------------------------------


def _fake_playwright(tmp_path, monkeypatch, manifest: Optional[dict[str, Any]]):
    """Lay out a Playwright package directory and a browsers cache under
    tmp_path and point the probe at both."""
    package = tmp_path / "site-packages" / "playwright"
    (package / "driver" / "package").mkdir(parents=True)
    if manifest is not None:
        (package / "driver" / "package" / "browsers.json").write_text(json.dumps(manifest))
    browsers = tmp_path / "ms-playwright"
    browsers.mkdir()
    monkeypatch.setattr(system_module, "_playwright_package_dir", lambda: package)
    monkeypatch.setenv("PLAYWRIGHT_BROWSERS_PATH", str(browsers))
    return package, browsers


def _complete(browsers, name: str) -> None:
    (browsers / name).mkdir()
    (browsers / name / "INSTALLATION_COMPLETE").write_text("")


MANIFEST = {
    "browsers": [
        {"name": "chromium", "revision": "1243", "installByDefault": True},
        {"name": "chromium-headless-shell", "revision": "1243", "installByDefault": True},
        {"name": "chromium-tip-of-tree", "revision": "1300", "installByDefault": False},
        {"name": "firefox", "revision": "1500", "installByDefault": True},
        {"name": "ffmpeg", "revision": "1011", "installByDefault": True},
    ]
}


def test_detection_needs_playwright_to_be_importable(monkeypatch):
    monkeypatch.setattr(system_module, "_playwright_package_dir", lambda: None)
    assert browser_installed() is False


def test_detection_requires_every_chromium_build_the_manifest_launches(tmp_path, monkeypatch):
    _, browsers = _fake_playwright(tmp_path, monkeypatch, MANIFEST)
    assert browser_installed() is False

    _complete(browsers, "chromium-1243")
    assert browser_installed() is False  # headless shell still missing

    _complete(browsers, "chromium_headless_shell-1243")
    assert browser_installed() is True


def test_detection_ignores_a_stale_revision_and_a_partial_download(tmp_path, monkeypatch):
    _, browsers = _fake_playwright(tmp_path, monkeypatch, MANIFEST)
    _complete(browsers, "chromium-1200")
    _complete(browsers, "chromium_headless_shell-1200")
    # Right revision, but the marker Playwright writes last is absent.
    (browsers / "chromium-1243").mkdir()
    (browsers / "chromium_headless_shell-1243").mkdir()

    assert browser_installed() is False


def test_detection_without_a_manifest_accepts_any_complete_chromium(tmp_path, monkeypatch):
    _, browsers = _fake_playwright(tmp_path, monkeypatch, manifest=None)
    assert browser_installed() is False
    _complete(browsers, "chromium-1100")
    assert browser_installed() is True


def test_detection_honours_browsers_path_zero_as_inside_the_package(tmp_path, monkeypatch):
    package, _ = _fake_playwright(tmp_path, monkeypatch, MANIFEST)
    monkeypatch.setenv("PLAYWRIGHT_BROWSERS_PATH", "0")
    local = package / "driver" / "package" / ".local-browsers"
    local.mkdir()

    assert browser_installed() is False
    _complete(local, "chromium-1243")
    _complete(local, "chromium_headless_shell-1243")
    assert browser_installed() is True


def test_default_browsers_path_follows_the_platform(tmp_path, monkeypatch):
    monkeypatch.delenv("PLAYWRIGHT_BROWSERS_PATH", raising=False)
    monkeypatch.setattr(system_module.Path, "home", classmethod(lambda cls: tmp_path))

    monkeypatch.setattr(system_module.sys, "platform", "darwin")
    assert system_module._browsers_path(tmp_path) == (
        tmp_path / "Library" / "Caches" / "ms-playwright"
    )

    monkeypatch.setattr(system_module.sys, "platform", "linux")
    monkeypatch.delenv("XDG_CACHE_HOME", raising=False)
    assert system_module._browsers_path(tmp_path) == tmp_path / ".cache" / "ms-playwright"
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path / "xdg"))
    assert system_module._browsers_path(tmp_path) == tmp_path / "xdg" / "ms-playwright"


# ---------------------------------------------------------------------------
# Wiring: permission engine, adapter, catalog, executor
# ---------------------------------------------------------------------------


def test_permission_engine_gates_system_writes_and_blocks_the_rest():
    engine = PermissionEngine()

    read = engine.check_permission("system", "capabilities", ActionCategory.READ)
    assert read.tier == PermissionTier.AUTO_APPROVE
    assert read.allowed is True and read.requires_approval is False

    write = engine.check_permission("system", "install_capability", ActionCategory.WRITE)
    assert write.tier == PermissionTier.USER_CONFIRM
    assert write.allowed is False and write.requires_approval is True

    for category in (ActionCategory.DELETE, ActionCategory.EXECUTE, ActionCategory.FINANCIAL):
        decision = engine.check_permission("system", "uninstall", category)
        assert decision.tier == PermissionTier.HARD_BLOCKED
        assert decision.allowed is False and decision.requires_approval is False


@pytest.mark.asyncio
async def test_runtime_adapter_parks_the_install_and_passes_the_read():
    adapter = RuntimePermissionAdapter()

    assert await adapter.check("u", "system.capabilities", {}) == "approved"
    assert (
        await adapter.check("u", "system.install_capability", {"name": "browser"})
        == "requires_approval"
    )
    assert await adapter.get_policy_name("u", "system.install_capability") == "system:write"
    assert "confirmation" in await adapter.get_block_reason(
        "u", "system.install_capability", {"name": "browser"}
    )


def test_catalog_offers_system_tools_to_a_user_with_no_connectors():
    assert "system" in BUILTIN_CONNECTOR_TYPES
    tools = {t.name: t for t in build_tools([])}

    assert SYSTEM_TOOLS <= set(tools)
    assert tools["system.capabilities"].permission_tier == "auto"
    assert tools["system.install_capability"].permission_tier == "approval"
    assert tools["system.install_capability"].connector_type == "system"

    schema = tools["system.install_capability"].parameters
    assert schema["required"] == ["name"]
    assert set(schema["properties"]) == {"name"}
    assert schema["properties"]["name"]["enum"] == ["browser"]

    description = tools["system.install_capability"].description
    assert "web.screenshot" in description
    assert "approve" in description
    assert "arbitrary" in description


def test_system_install_keeps_its_approval_card_under_an_auto_approve_account():
    tools = {t.name: t for t in build_tools([], user_default_tier="auto_approve")}
    # Standing consent covers the other built-ins' writes, never this one.
    assert tools["reminders.create"].permission_tier == "auto"
    assert tools["system.install_capability"].permission_tier == "approval"


def test_system_tools_are_still_floored_by_the_account_default():
    for tier in ("admin_only", "hard_blocked"):
        assert not any(t.name in SYSTEM_TOOLS for t in build_tools([], user_default_tier=tier))
    # The deployment admin keeps them, install still behind the card.
    admin = {t.name: t for t in build_tools([], user_default_tier="admin_only", is_admin=True)}
    assert admin["system.install_capability"].permission_tier == "approval"


@pytest.mark.asyncio
async def test_executor_refuses_the_install_unless_approved():
    host = FakeHost()
    executor = ConnectorToolExecutor(system_toolkit=host.toolkit())

    refused = await executor.execute(
        "system.install_capability", {"name": "browser"}, "u", approved=False
    )
    assert refused["ok"] is False
    assert refused["requires_approval"] is True
    assert "confirmation" in refused["error"]
    assert host.calls == []

    # The model cannot smuggle the approval through its own arguments.
    smuggled = await executor.execute(
        "system.install_capability", {"name": "browser", "user_confirmed": True}, "u"
    )
    assert smuggled["requires_approval"] is True
    assert host.calls == []

    approved = await executor.execute(
        "system.install_capability", {"name": "browser"}, "u", approved=True
    )
    assert approved["ok"] is True
    assert approved["installed_now"] is True
    assert [argv for argv, _ in host.calls] == BROWSER_STEPS


@pytest.mark.asyncio
async def test_executor_runs_the_read_without_approval_and_refuses_unknown_actions():
    host = FakeHost(installed=True)
    executor = ConnectorToolExecutor(system_toolkit=host.toolkit())

    listed = await executor.execute("system.capabilities", {}, "u")
    assert listed["ok"] is True
    assert listed["capabilities"][0]["installed"] is True

    unknown = await executor.execute("system.uninstall", {"name": "browser"}, "u", approved=True)
    assert unknown["ok"] is False
    assert host.calls == []


# ---------------------------------------------------------------------------
# End to end through the runtime: decision -> pending action -> approval
# ---------------------------------------------------------------------------


class RecordingAudit:
    def __init__(self) -> None:
        self.entries: list[dict[str, Any]] = []

    async def log(self, entry: dict[str, Any]) -> None:
        self.entries.append(entry)


class ScriptedProvider:
    def __init__(self, responses: list[LLMResponse]) -> None:
        self._responses = list(responses)

    async def complete(self, messages, tools=None) -> LLMResponse:
        if self._responses:
            return self._responses.pop(0)
        return LLMResponse(content="fallback")

    async def stream(self, messages, tools=None):
        yield "done"


def _runtime(host: FakeHost) -> tuple[AgentRuntime, RecordingAudit]:
    audit = RecordingAudit()
    runtime = AgentRuntime(
        config=settings,
        permission_engine=RuntimePermissionAdapter(),
        tool_executor=ConnectorToolExecutor(system_toolkit=host.toolkit()),
        audit_service=audit,
        approval_store=InMemoryApprovalStore(),
    )
    provider = ScriptedProvider(
        [
            LLMResponse(
                content="",
                tool_calls=[
                    ToolCall(
                        id="t1",
                        name="system.install_capability",
                        arguments={"name": "browser"},
                    )
                ],
            ),
            LLMResponse(content="I have asked you to approve the browser install."),
        ]
    )
    use_provider(runtime, provider)
    return runtime, audit


@pytest.mark.asyncio
async def test_runtime_parks_the_install_and_runs_it_only_after_approval():
    host = FakeHost()
    runtime, audit = _runtime(host)

    response = await runtime.chat(
        [{"role": "user", "content": "Take a screenshot of example.com"}],
        tools=build_tools([]),
        user_id="user-1",
    )

    (pending,) = response.pending_approvals
    assert pending.tool_name == "system.install_capability"
    assert pending.arguments == {"name": "browser"}
    assert host.calls == []  # nothing installed on the model's say-so
    assert response.blocked_actions == []
    assert "tool_pending_approval" in {e["event"] for e in audit.entries}

    result = await runtime.approve_action(pending.action_id, "user-1")

    assert "error" not in result
    assert [argv for argv, _ in host.calls] == BROWSER_STEPS
    assert host.installed is True
    events = [e["event"] for e in audit.entries]
    assert events.index("tool_approved") < events.index("tool_approved_and_executed")


@pytest.mark.asyncio
async def test_runtime_denial_never_installs_and_the_action_is_spent():
    host = FakeHost()
    runtime, _ = _runtime(host)

    response = await runtime.chat(
        [{"role": "user", "content": "Take a screenshot of example.com"}],
        tools=build_tools([]),
        user_id="user-1",
    )
    (pending,) = response.pending_approvals

    denied = await runtime.deny_action(pending.action_id, "user-1")
    assert denied["denied"] is True
    assert host.calls == []

    late = await runtime.approve_action(pending.action_id, "user-1")
    assert "error" in late
    assert host.calls == []


@pytest.mark.asyncio
async def test_another_user_cannot_approve_someones_install():
    host = FakeHost()
    runtime, _ = _runtime(host)
    response = await runtime.chat(
        [{"role": "user", "content": "Take a screenshot of example.com"}],
        tools=build_tools([]),
        user_id="owner",
    )
    (pending,) = response.pending_approvals

    result = await runtime.approve_action(pending.action_id, "intruder")

    assert "error" in result
    assert host.calls == []


# ---------------------------------------------------------------------------
# web.screenshot points at the installer
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_screenshot_missing_browser_error_names_the_capability():
    tools = WebToolkit(
        resolver=lambda url: (PUBLIC_ADDRESS,),
        playwright_loader=lambda: None,
    )

    result = await tools.execute("screenshot", {"url": "https://example.com/"})

    assert result["ok"] is False
    assert result["capability"] == "browser"
    assert "system.install_capability" in result["error"]
    assert "'browser'" in result["error"]
    assert "approve" in result["error"]
