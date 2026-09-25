"""Tests for wiring computer_control into the app: the desktop catalog offers
desktop.observe (READ) and desktop.act (WRITE), the policy sends every act to
the approval card under every account default, the capability is registered
and gated on the real platform name and backend, the executor routes observe
and act to the ComputerToolkit (screenshot stays with the screen toolkit), the
approval card reads the toolkit's facts, and main.wire_services builds the
toolkit for this platform.

Why it exists: desktop.act is the riskiest tool Crawler offers. Each wiring
seam here is one place a mistake would let it run unattended, run with the
capability off, or show the owner the model's words instead of what will
happen. Every test uses the in-memory fake desktop; nothing clicks, types or
reads the real screen.
"""

from __future__ import annotations

import re
from types import SimpleNamespace
from typing import Any

import pytest

from services import capabilities as capability_registry
from services.agent import cancel
from services.agent.permissions import ActionCategory, PermissionEngine, PermissionTier
from services.agent.tool_registry import (
    _BUILTIN_STANCE,
    CAPABILITY_OFF_POLICY,
    CONNECTOR_CATALOG,
    ConnectorToolExecutor,
    RuntimePermissionAdapter,
    build_tools,
    resolve_tool,
)
from services.capabilities import computer_control
from services.capabilities.base import ReportContext
from services.tools.computer import backend as computer_backend
from services.tools.computer.backend_fake import FakeApp, FakeBackend, FakeWindow, make_node
from services.tools.computer.outline import MAX_CHARS_LIMIT
from services.tools.computer.toolkit import ACT_ACTIONS, OBSERVE_ACTIONS, ComputerToolkit

U1 = "user-1"


# ── helpers ──────────────────────────────────────────────────────────────────


def mail_desktop() -> FakeBackend:
    return FakeBackend(
        [
            FakeApp(
                "Mail",
                101,
                [
                    FakeWindow(
                        "New Message",
                        (
                            make_node("text field", "Subject", handle="subject", value="Hi"),
                            make_node("button", "Send", handle="send"),
                            make_node("text field", "Password", handle="pw", secure=True),
                        ),
                    )
                ],
            ),
            FakeApp("Terminal", 103, [FakeWindow("bash", (make_node("text area", "Shell"),))]),
        ],
        frontmost="Mail",
        focused="subject",
        installed={"Calculator"},
    )


def toolkit(fake: FakeBackend) -> ComputerToolkit:
    return ComputerToolkit(fake, cancel_flag=cancel.is_cancelled)


def ref_of(result: dict[str, Any], needle: str) -> str:
    for line in result["outline"]:
        if needle in line:
            match = re.search(r"\[ref=(d\d+)\]", line)
            assert match is not None
            return match.group(1)
    raise AssertionError(f"{needle!r} not in {result['outline']}")


@pytest.fixture
def backend_ready(monkeypatch):
    """select_backend answers an available fake, so computer_control reports
    on; returns the platform names it was asked for."""
    asked: list[str] = []

    def select(name: str):
        asked.append(name)
        return FakeBackend(available=(True, ""))

    monkeypatch.setattr(computer_backend, "select_backend", select)
    return asked


@pytest.fixture(autouse=True)
def _no_stale_stop():
    cancel.clear(U1)
    yield
    cancel.clear(U1)


def _gate(*keys: str, **ctx_overrides: Any):
    """The owner's report with exactly *keys* switched on (win32 unless
    overridden: no OS permission is asked there)."""
    ctx = ReportContext(
        **{
            "in_container": False,
            "platform": "win32",
            "telegram_configured": True,
            "browser_installed": True,
            **ctx_overrides,
        }
    )
    switches = {k: k in keys for k in capability_registry.keys()}
    statuses = capability_registry.statuses_by_key(
        capability_registry.report(switches, ctx, use_cache=False)
    )

    async def gate():
        return statuses

    return gate


def executor(fake: FakeBackend, *keys: str) -> ConnectorToolExecutor:
    return ConnectorToolExecutor(
        session_factory=None,
        capability_gate=_gate(*keys),
        computer_toolkit=toolkit(fake),
    )


# ── 1. catalog ───────────────────────────────────────────────────────────────


def _spec(action: str):
    return next(s for s in CONNECTOR_CATALOG["desktop"] if s.action == action)


def test_desktop_catalog_has_screenshot_observe_and_act():
    assert [s.action for s in CONNECTOR_CATALOG["desktop"]] == ["screenshot", "observe", "act"]
    assert _spec("observe").category == ActionCategory.READ
    assert _spec("act").category == ActionCategory.WRITE
    assert resolve_tool("desktop.act").spec.category == ActionCategory.WRITE
    assert resolve_tool("desktop__deadbeef.act") is None


def test_observe_schema_is_flat_and_matches_the_toolkit():
    params = _spec("observe").parameters
    assert params["required"] == ["action"]
    assert params["properties"]["action"]["enum"] == list(OBSERVE_ACTIONS)
    assert set(params["properties"]) == {"action", "app", "max_chars"}
    assert str(MAX_CHARS_LIMIT) in params["properties"]["max_chars"]["description"]
    for prop in params["properties"].values():
        assert prop["type"] in ("string", "integer")  # flat: no nested objects


def test_act_schema_is_flat_and_matches_the_toolkit():
    params = _spec("act").parameters
    assert params["required"] == ["action"]
    assert params["properties"]["action"]["enum"] == list(ACT_ACTIONS)
    assert set(params["properties"]) == {
        "action", "ref", "x", "y", "text", "keys", "direction", "app", "index",
    }
    assert params["properties"]["direction"]["enum"] == ["up", "down"]
    for prop in params["properties"].values():
        assert prop["type"] in ("string", "integer")


def test_descriptions_say_observe_first_prefer_refs_and_every_act_is_approved():
    observe = _spec("observe").description
    act = _spec("act").description
    assert "desktop.act" in observe and "ref" in observe
    assert "desktop.observe" in act
    assert "ref" in act.lower() and "prefer" in act.lower()
    assert "approve" in act.lower()
    assert "password" in act.lower()


# ── 2. policy ────────────────────────────────────────────────────────────────


def test_desktop_write_is_user_confirm_not_hard_blocked():
    # Deliberate change (spec §6): desktop.act exists, so WRITE moves from
    # HARD_BLOCKED to the approval card. Everything else stays shut.
    engine = PermissionEngine()
    write = engine.check_permission("desktop", "act", ActionCategory.WRITE)
    assert write.tier == PermissionTier.USER_CONFIRM
    assert write.requires_approval is True and write.allowed is False
    read = engine.check_permission("desktop", "observe", ActionCategory.READ)
    assert read.tier == PermissionTier.AUTO_APPROVE


@pytest.mark.parametrize(
    "category", [ActionCategory.DELETE, ActionCategory.EXECUTE, ActionCategory.FINANCIAL]
)
def test_desktop_delete_execute_financial_stay_hard_blocked(category):
    decision = PermissionEngine().check_permission("desktop", "act", category)
    assert decision.tier == PermissionTier.HARD_BLOCKED
    assert decision.allowed is False and decision.requires_approval is False


def test_desktop_stance_stays_user_confirm():
    assert _BUILTIN_STANCE["desktop"] == "user_confirm"


@pytest.mark.parametrize("account_default", ["auto_approve", "user_confirm"])
def test_no_account_setting_auto_approves_act(account_default):
    offered = {
        t.name: t
        for t in build_tools(
            [],
            user_default_tier=account_default,
            enabled_capabilities=frozenset({"computer_control"}),
        )
    }
    assert offered["desktop.act"].permission_tier == "approval"
    assert offered["desktop.observe"].permission_tier == "auto"
    assert "desktop.screenshot" not in offered  # screen is its own switch


def test_act_and_observe_are_offered_only_with_computer_control_on():
    default = {t.name for t in build_tools([])}
    assert "desktop.observe" not in default and "desktop.act" not in default
    screen_only = {t.name for t in build_tools([], enabled_capabilities=frozenset({"screen"}))}
    assert "desktop.screenshot" in screen_only
    assert "desktop.observe" not in screen_only and "desktop.act" not in screen_only


@pytest.mark.asyncio
async def test_permission_adapter_parks_act_and_runs_observe(backend_ready):
    adapter = RuntimePermissionAdapter(capability_gate=_gate("computer_control"))
    assert await adapter.check(U1, "desktop.act", {}) == "requires_approval"
    assert await adapter.check(U1, "desktop.observe", {}) == "approved"
    off = RuntimePermissionAdapter(capability_gate=_gate("screen"))
    assert await off.check(U1, "desktop.act", {}) == "blocked"
    assert await off.get_policy_name(U1, "desktop.act") == CAPABILITY_OFF_POLICY


# ── 3. capability ────────────────────────────────────────────────────────────


def test_computer_control_is_registered_off_and_owns_observe_and_act():
    cap = capability_registry.get("computer_control")
    assert cap is computer_control.CAPABILITY
    assert capability_registry.default_switches()["computer_control"] is False
    assert capability_registry.capability_for_tool("desktop.observe").key == "computer_control"
    assert capability_registry.capability_for_tool("desktop.act").key == "computer_control"
    assert capability_registry.capability_for_tool("desktop.screenshot").key == "screen"


def ctx(platform: str = "darwin", host: str = "", **over: Any) -> ReportContext:
    return ReportContext(
        in_container=over.pop("in_container", False),
        platform=platform,
        telegram_configured=False,
        browser_installed=False,
        host_platform=host,
        **over,
    )


def test_report_context_carries_the_platform_layer_name_with_a_safe_default():
    assert ctx().host_platform == ""
    assert hash(ctx(host="mac"))  # stays a probe-cache key


def test_default_context_reads_the_platform_layer_name(monkeypatch):
    from services import platform as platform_pkg

    monkeypatch.setattr(
        platform_pkg,
        "current",
        lambda: SimpleNamespace(name="windows", browser_channel=lambda: "msedge"),
    )
    assert capability_registry.default_context().host_platform == "windows"


def test_availability_asks_the_backend_for_the_platform_layer_name(backend_ready):
    cap = computer_control.CAPABILITY
    assert cap.availability(ctx("darwin", host="mac")).available is True
    assert cap.availability(ctx("win32", host="windows")).available is True
    assert backend_ready == ["mac", "windows"]


def test_availability_falls_back_to_sys_platform_without_a_layer_name(backend_ready):
    assert computer_control.CAPABILITY.availability(ctx("darwin")).available is True
    assert backend_ready == ["mac"]


def test_the_container_and_linux_are_blocked_before_any_backend_is_asked(backend_ready):
    cap = computer_control.CAPABILITY
    # The platform layer says container even though the host OS is macOS
    # (CRAWLER_PLATFORM=container, or the container marker).
    boxed = cap.availability(ctx("darwin", host="container"))
    assert boxed.available is False and "container" in boxed.reason
    marked = cap.availability(ctx("darwin", host="mac", in_container=True))
    assert marked.available is False and "container" in marked.reason
    linux = cap.availability(ctx("linux", host="linux"))
    assert linux.available is False and "macOS and Windows" in linux.reason
    assert backend_ready == []


def test_availability_reports_the_backends_own_reason(monkeypatch):
    monkeypatch.setattr(
        computer_backend,
        "select_backend",
        lambda name: FakeBackend(available=(False, "pyobjc is not installed.")),
    )
    result = computer_control.CAPABILITY.availability(ctx("darwin", host="mac"))
    assert result.available is False and result.reason == "pyobjc is not installed."


def test_tests_never_reach_a_real_backend():
    # conftest's guard: select_backend answers an unavailable stand-in
    # unless a test injects a fake, so no report or wiring in the suite
    # loads pyobjc or UI Automation.
    backend = computer_backend.select_backend("mac")
    assert backend.available()[0] is False
    status = capability_registry.statuses_by_key(
        capability_registry.report({"computer_control": True}, ctx("darwin", host="mac"))
    )["computer_control"]
    assert status.effective == "blocked"


def test_report_blocks_computer_control_in_a_container(backend_ready):
    status = capability_registry.statuses_by_key(
        capability_registry.report(
            {"computer_control": True}, ctx("linux", host="container", in_container=True)
        )
    )["computer_control"]
    assert status.effective == "blocked" and "container" in status.reason


# ── 4. executor ──────────────────────────────────────────────────────────────


class RecordingDesktop:
    def __init__(self) -> None:
        self.calls: list[tuple[str, dict]] = []

    async def execute(self, action, params):
        self.calls.append((action, params))
        return {"ok": True, "image": "data:image/jpeg;base64,AA=="}


@pytest.mark.asyncio
async def test_screenshot_still_routes_to_the_screen_toolkit(backend_ready):
    screen_kit = RecordingDesktop()
    fake = mail_desktop()
    ex = ConnectorToolExecutor(
        session_factory=None,
        capability_gate=_gate("screen", "computer_control"),
        desktop_toolkit=screen_kit,
        computer_toolkit=toolkit(fake),
    )
    result = await ex.execute("desktop.screenshot", {}, user_id=U1)
    assert result["ok"] is True and screen_kit.calls == [("screenshot", {})]
    assert fake.reads == [] and fake.events == []


@pytest.mark.asyncio
async def test_observe_runs_on_the_computer_toolkit_as_the_caller(backend_ready):
    fake = mail_desktop()
    ex = executor(fake, "computer_control")
    result = await ex.execute("desktop.observe", {"action": "outline"}, user_id=U1)
    assert result["ok"] is True, result
    assert result["app"] == "Mail"
    assert any('button "Send"' in line for line in result["outline"])
    assert fake.events == []


@pytest.mark.asyncio
async def test_act_is_refused_unapproved_and_runs_once_approved(backend_ready):
    fake = mail_desktop()
    ex = executor(fake, "computer_control")
    outline = await ex.execute("desktop.observe", {"action": "outline"}, user_id=U1)
    send = ref_of(outline, 'button "Send"')

    refused = await ex.execute("desktop.act", {"action": "click", "ref": send}, user_id=U1)
    assert refused["ok"] is False and refused["requires_approval"] is True
    assert fake.events == []

    smuggled = await ex.execute(
        "desktop.act", {"action": "click", "ref": send, "user_confirmed": True}, user_id=U1
    )
    assert smuggled["requires_approval"] is True and fake.events == []

    done = await ex.execute("desktop.act", {"action": "click", "ref": send}, U1, approved=True)
    assert done["ok"] is True, done
    assert done["did"] == 'click button "Send" in Mail'
    assert fake.events == [("click", "send", False)]


@pytest.mark.asyncio
async def test_observe_and_act_are_refused_with_computer_control_off(backend_ready):
    fake = mail_desktop()
    ex = executor(fake, "screen")
    for tool, args in (
        ("desktop.observe", {"action": "outline"}),
        ("desktop.act", {"action": "open_app", "app": "Calculator"}),
    ):
        result = await ex.execute(tool, args, U1, approved=True)
        assert result["ok"] is False
        assert result["capability"] == "computer_control" and result["state"] == "off"
    assert fake.reads == [] and fake.events == []


@pytest.mark.asyncio
async def test_a_stop_request_refuses_the_next_act(backend_ready):
    fake = mail_desktop()
    ex = executor(fake, "computer_control")
    cancel.request_cancel(U1)
    result = await ex.execute("desktop.act", {"action": "open_app", "app": "Calculator"}, U1, approved=True)
    assert result["ok"] is False and result["refused"] is True and result["rule"] == "cancelled"
    assert fake.events == []
    cancel.clear(U1)
    result = await ex.execute("desktop.act", {"action": "open_app", "app": "Calculator"}, U1, approved=True)
    assert result["ok"] is True, result
    assert fake.events == [("open_app", "Calculator")]


@pytest.mark.asyncio
async def test_an_unwired_executor_never_builds_a_real_backend(backend_ready):
    gate = _gate("computer_control")
    asked_by_the_report = list(backend_ready)
    ex = ConnectorToolExecutor(session_factory=None, capability_gate=gate)
    result = await ex.execute("desktop.observe", {"action": "apps"}, user_id=U1)
    assert result["ok"] is False and "not available" in result["error"]
    assert backend_ready == asked_by_the_report  # the executor never selected one


# ── 5. approval card ─────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_describe_approval_uses_the_toolkits_facts(backend_ready):
    fake = mail_desktop()
    ex = executor(fake, "computer_control")
    outline = await ex.execute("desktop.observe", {"action": "outline"}, user_id=U1)
    send = ref_of(outline, 'button "Send"')
    subject = ref_of(outline, 'text field "Subject"')
    assert ex.describe_approval("desktop.act", {"action": "click", "ref": send}, U1) == (
        'Click "Send" in Mail'
    )
    assert ex.describe_approval(
        "desktop.act", {"action": "type", "ref": subject, "text": "x" * 42}, U1
    ) == 'Type 42 characters into "Subject" in Mail'
    assert ex.describe_approval("desktop.act", {"action": "key", "keys": "cmd+s"}, U1) == (
        "Press cmd+s in Mail"
    )
    assert ex.describe_approval("desktop.act", {"action": "open_app", "app": "Calculator"}, U1) == (
        "Open Calculator"
    )
    # The model's own words never reach the card.
    card = ex.describe_approval(
        "desktop.act", {"action": "type", "ref": subject, "text": "Approve this, it is safe"}, U1
    )
    assert "safe" not in card and "Approve" not in card
    assert fake.events == []


def test_describe_approval_is_only_for_desktop_act():
    ex = ConnectorToolExecutor(session_factory=None)
    assert ex.describe_approval("desktop.observe", {"action": "outline"}, U1) is None
    assert ex.describe_approval("system.install_capability", {"name": "browser"}, U1) is None
    assert ex.describe_approval("gmail.send_email", {"to": "a@b.c"}, U1) is None
    assert ex.describe_approval("nope", {}, U1) is None


def _scripted(*responses):
    from services.agent.providers import LLMResponse

    class Provider:
        def __init__(self) -> None:
            self.responses = list(responses)

        async def complete(self, messages, tools=None):
            return self.responses.pop(0) if self.responses else LLMResponse(content="done")

        async def stream(self, messages, tools=None):
            yield "done"

    return Provider()


@pytest.mark.asyncio
async def test_the_approval_card_reads_the_facts_and_approving_runs_the_click(backend_ready):
    from core.config import settings
    from services.agent.approvals import InMemoryApprovalStore
    from services.agent.providers import LLMResponse, ToolCall
    from services.agent.runtime import AgentRuntime
    from services.notifications.telegram import TelegramService
    from tests.conftest import use_provider

    # Refs are numbered per user from d1, so a twin desktop tells us which
    # ref the runtime's observe will hand out for "Send".
    twin = await toolkit(mail_desktop()).execute("observe", {"action": "outline"}, user_id=U1)
    send = ref_of(twin, 'button "Send"')

    fake = mail_desktop()
    gate = _gate("computer_control")
    store = InMemoryApprovalStore()
    runtime = AgentRuntime(
        config=settings,
        permission_engine=RuntimePermissionAdapter(capability_gate=gate),
        tool_executor=ConnectorToolExecutor(
            session_factory=None, capability_gate=gate, computer_toolkit=toolkit(fake)
        ),
        approval_store=store,
    )
    use_provider(
        runtime,
        _scripted(
            LLMResponse(
                content="",
                tool_calls=[ToolCall(id="t1", name="desktop.observe", arguments={"action": "outline"})],
            ),
            LLMResponse(
                content="",
                tool_calls=[
                    ToolCall(
                        id="t2",
                        name="desktop.act",
                        arguments={"action": "click", "ref": send},
                    )
                ],
            ),
            LLMResponse(content="Waiting for your approval."),
        ),
    )
    response = await runtime.chat(
        messages=[{"role": "user", "content": "Send the draft in Mail."}],
        tools=build_tools(
            [],
            user_default_tier="auto_approve",
            enabled_capabilities=frozenset({"computer_control"}),
        ),
        user_id=U1,
    )
    assert fake.events == []  # parked, not clicked
    [pending] = response.pending_approvals
    assert pending.tool_name == "desktop.act"
    assert pending.reason == 'Click "Send" in Mail'

    # The Telegram card shows the same sentence.
    service = TelegramService(token="123:fake", session_factory=None)
    sent: list[dict] = []

    async def linked(_user_id):
        return 42

    async def api(method, **params):
        sent.append({"method": method, **params})

    service.linked_chat_id = linked  # type: ignore[method-assign]
    service._api = api  # type: ignore[method-assign]
    [stored] = await store.list_pending(U1)
    await service.notify_pending(stored)
    await service._client.aclose()
    assert 'Click "Send" in Mail' in sent[0]["text"]

    outcome = await runtime.approve_action(pending.action_id, U1)
    assert outcome["result"]["ok"] is True, outcome
    assert fake.events == [("click", "send", False)]


@pytest.mark.asyncio
async def test_a_describer_that_fails_falls_back_to_the_generic_reason():
    from core.config import settings
    from services.agent.approvals import InMemoryApprovalStore
    from services.agent.providers import LLMResponse, ToolCall
    from services.agent.runtime import AgentRuntime, Tool, ToolExecutor
    from tests.conftest import use_provider

    class Broken(ToolExecutor):
        def describe_approval(self, tool_name, arguments, user_id):
            raise RuntimeError("boom")

    class Park:
        async def check(self, user_id, tool_name, arguments):
            return "requires_approval"

    runtime = AgentRuntime(
        config=settings,
        permission_engine=Park(),
        tool_executor=Broken(),
        approval_store=InMemoryApprovalStore(),
    )
    use_provider(
        runtime,
        _scripted(
            LLMResponse(
                content="",
                tool_calls=[ToolCall(id="t1", name="desktop.act", arguments={"action": "scroll", "direction": "down"})],
            ),
        ),
    )
    response = await runtime.chat(
        messages=[{"role": "user", "content": "scroll"}],
        tools=[Tool(name="desktop.act", description="act", parameters={}, permission_tier="approval")],
        user_id=U1,
    )
    [pending] = response.pending_approvals
    assert pending.reason == "Tool 'desktop.act' requires explicit user approval"


# ── result budget ────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_a_full_outline_fits_the_desktop_result_budget():
    """The runtime cuts each tool result to its budget before the model sees
    it (2000 chars by default). An outline cut there would lose most of its
    refs, so desktop results keep room for the toolkit's own caps."""
    import json

    from services.agent.runtime import result_char_budget

    crowded = FakeWindow(
        "Big",
        tuple(make_node("button", f"Button number {i} with a longer label") for i in range(600)),
    )
    fake = FakeBackend([FakeApp("Mail", 1, [crowded])], frontmost="Mail")
    kit = toolkit(fake)
    default = await kit.execute("observe", {"action": "outline"}, user_id=U1)
    widest = await kit.execute(
        "observe", {"action": "outline", "max_chars": MAX_CHARS_LIMIT}, user_id=U1
    )
    assert default["truncated"] is True and widest["truncated"] is True
    acted = await kit.execute("act", {"action": "scroll", "direction": "down"}, user_id=U1)
    assert acted["ok"] is True, acted

    def model_view(result):  # what _wrap_tool_results measures
        return len(json.dumps(result, indent=2))

    assert model_view(default) <= result_char_budget("desktop.observe", 2000)
    assert model_view(widest) <= result_char_budget("desktop.observe", 2000)
    assert model_view(acted) <= result_char_budget("desktop.act", 2000)
    assert result_char_budget("desktop.screenshot", 2000) == 2000  # unchanged


# ── 6. prompt ────────────────────────────────────────────────────────────────


def test_prompt_tells_the_model_how_to_operate_apps():
    from services.agent.runtime import SECURITY_SYSTEM_PROMPT

    section = SECURITY_SYSTEM_PROMPT.split("<capabilities>")[1].split("</capabilities>")[0]
    line = next(ln for ln in section.split("- ") if "desktop.observe" in ln)
    for fragment in ("desktop.observe", "ref", "one action per approval", "password"):
        assert fragment in " ".join(line.split()), fragment


# ── 7. main.wire_services ────────────────────────────────────────────────────


@pytest.mark.asyncio
@pytest.mark.parametrize("platform_name", ["mac", "windows", "container"])
async def test_wire_services_builds_the_toolkit_for_this_platform(
    session_factory, monkeypatch, platform_name
):
    import main as main_module
    from core.config import settings
    from main import app, wire_services
    from tests.test_telegram_manager import FakeService

    fake = mail_desktop()
    asked: list[str] = []

    def select(name: str):
        asked.append(name)
        return fake

    class Sessions:
        def __init__(self, **kwargs: Any) -> None:
            pass

        async def close_all(self) -> None:
            pass

    monkeypatch.setattr(computer_backend, "select_backend", select)
    monkeypatch.setattr(
        main_module,
        "current_platform",
        lambda: SimpleNamespace(name=platform_name, browser_channel=lambda: None),
    )
    monkeypatch.setattr(main_module, "BrowserSessionManager", Sessions)
    monkeypatch.setattr(settings, "TELEGRAM_BOT_TOKEN", "", raising=False)
    FakeService.instances.clear()
    saved = dict(app.state._state)
    await wire_services(app, session_factory, telegram_service_factory=FakeService)
    try:
        assert asked == [platform_name]
        kit = app.state.agent_runtime._executor._computer
        assert isinstance(kit, ComputerToolkit)
        assert kit._backend is fake
        assert kit._cancel_flag is cancel.is_cancelled
    finally:
        await app.state.telegram_manager.stop()
        app.state._state.clear()
        app.state._state.update(saved)
