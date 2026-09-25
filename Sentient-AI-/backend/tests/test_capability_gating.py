"""Tests for capability gating at the tool-offer, executor, and adapter
boundaries: a caller that forgets the enabled set falls back to registry
defaults, an off capability is refused at both the offer and the executor, and
gate errors or backstop refusals are always audited as blocked.

Why it exists: Off-by-default must hold without any explicit wiring at either
gate, and telling "off" (the owner's switch) apart from "blocked" (installed
but unusable here) is what the executor's refusal message and the audit trail
both depend on.

Off-by-default must hold at BOTH gates without any wiring: a caller that
forgets the enabled set gets the registry defaults, and the executor
refuses a tool whose capability is off.

The gates tell "off" (the owner's switch) from "blocked" (switched on but
unusable here: not installed, no OS permission), and refuse when the
owner's settings cannot be read at all.

The executor tests never touch a real display or network: every toolkit
the gate is meant to stop is a tripwire that fails the test if reached.
"""
from __future__ import annotations

import dataclasses

import pytest
from structlog.testing import capture_logs

from services import capabilities as capability_registry
from services.agent.runtime import (
    CAPABILITY_BLOCKED_POLICY,
    CAPABILITY_GATE_ERROR_POLICY,
    CAPABILITY_GATE_ERROR_REASON,
    _capability_refusal,
)
from services.agent.tool_registry import (
    BUILTIN_CONNECTOR_TYPES,
    CAPABILITY_OFF_POLICY,
    ConnectorToolExecutor,
    RuntimePermissionAdapter,
    build_tools,
    resolve_tool,
)
from services.capabilities.base import ProbeResult, ReportContext
from services.tools.desktop import DesktopToolkit


def names(tools):
    return {t.name for t in tools}


class Tripwire:
    """A grabber (or toolkit) the gate must stop before it is reached."""

    def __init__(self, result=None):
        self.calls = 0
        self._result = result

    def __call__(self, display):
        self.calls += 1
        if self._result is None:
            raise AssertionError("the capability gate let a refused tool run")
        return self._result


class TripwireWebToolkit:
    def __init__(self):
        self.calls = 0

    async def execute(self, action, params):
        self.calls += 1
        raise AssertionError("the capability gate let a refused web tool run")


def _desktop(grabber):
    return DesktopToolkit(grabber=grabber, probe=lambda: ProbeResult("granted"))


def _statuses(*keys, **ctx_overrides):
    """The owner's report with exactly *keys* switched on, in a context
    where everything is available unless *ctx_overrides* says otherwise
    (win32: screen capture needs no OS grant, so nothing asks the OS)."""
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
    return capability_registry.statuses_by_key(
        capability_registry.report(switches, ctx, use_cache=False)
    )


def _gate(*keys, **ctx_overrides):
    """A capability gate: the report's statuses by key, as
    InstallationService.capability_statuses returns them."""
    statuses = _statuses(*keys, **ctx_overrides)

    async def gate():
        return statuses

    return gate


# Deliberately secret-looking: none of it may reach the model, the user or
# the audit chain when the gate raises.
GATE_SECRET = "postgres://crawler:hunter2@db/crawler connection refused"


async def _raising_gate():
    raise RuntimeError(GATE_SECRET)


def test_desktop_is_a_builtin_type():
    assert "desktop" in BUILTIN_CONNECTOR_TYPES


def test_every_builtin_type_has_a_stance_and_an_executor_entry():
    """Step 2 of services/capabilities/README.md in one check: a new
    built-in family needs its tier stand-in (build_tools would KeyError on
    the offer without it) and its executor entry (dispatch would refuse
    it), and neither map may keep a family the catalog no longer has."""
    from services.agent.tool_registry import _BUILTIN_STANCE

    assert set(_BUILTIN_STANCE) == set(BUILTIN_CONNECTOR_TYPES)
    assert set(ConnectorToolExecutor()._builtins) == set(BUILTIN_CONNECTOR_TYPES)


def test_default_offer_excludes_screen_and_includes_web():
    offered = names(build_tools([]))
    assert "desktop.screenshot" not in offered
    assert {"web.search", "web.fetch_page", "reminders.create", "system.capabilities"} <= offered


def test_explicit_enabled_set_gates_the_offer():
    offered = names(build_tools([], enabled_capabilities=frozenset({"screen"})))
    assert "desktop.screenshot" in offered
    assert "web.search" not in offered and "reminders.create" not in offered
    assert "system.capabilities" in offered  # always-on


@pytest.mark.asyncio
async def test_executor_refuses_tool_of_off_capability():
    grabber = Tripwire()
    ex = ConnectorToolExecutor(
        session_factory=None,
        capability_gate=_gate("web_browsing"),
        desktop_toolkit=_desktop(grabber),
    )
    result = await ex.execute("desktop.screenshot", {}, user_id="u1")
    assert result["ok"] is False
    assert result.get("capability") == "screen"
    assert result.get("state") == "off"
    assert "turned off" in result["error"].lower()
    assert grabber.calls == 0


@pytest.mark.asyncio
async def test_executor_refusal_is_the_capabilitys_own_sentence():
    ex = ConnectorToolExecutor(session_factory=None, desktop_toolkit=_desktop(Tripwire()))
    result = await ex.execute("desktop.screenshot", {}, user_id="u1")
    assert result["error"] == capability_registry.get("screen").when_denied


@pytest.mark.asyncio
async def test_executor_default_gate_is_registry_defaults():
    grabber = Tripwire()
    ex = ConnectorToolExecutor(session_factory=None, desktop_toolkit=_desktop(grabber))
    result = await ex.execute("desktop.screenshot", {}, user_id="u1")
    assert result["ok"] is False and result.get("capability") == "screen"
    assert grabber.calls == 0


@pytest.mark.asyncio
async def test_executor_runs_the_tool_when_its_capability_is_on():
    # 2x2 black RGB frame.
    grabber = Tripwire(result=(b"\x00" * 12, 2, 2))
    ex = ConnectorToolExecutor(
        session_factory=None,
        capability_gate=_gate("screen"),
        desktop_toolkit=_desktop(grabber),
    )
    result = await ex.execute("desktop.screenshot", {}, user_id="u1")
    assert result["ok"] is True
    assert result["image"].startswith("data:image/jpeg;base64,")
    assert grabber.calls == 1


# ── slugged spellings of built-in tools ──────────────────────────────────
# Built-ins have no connector rows, so they are never offered under a
# slug. A slugged spelling must not resolve at all: if it did, a lookup
# keyed on the raw name would find no capability and wave it through.


@pytest.mark.parametrize(
    "name", ["desktop__deadbeef.screenshot", "web__0badf00d.search", "system__12345678.install_capability"]
)
def test_slugged_builtin_names_do_not_resolve(name):
    assert resolve_tool(name) is None


@pytest.mark.asyncio
async def test_slugged_desktop_name_cannot_bypass_the_screen_gate():
    grabber = Tripwire()
    ex = ConnectorToolExecutor(
        session_factory=None,
        capability_gate=_gate("web_browsing"),
        desktop_toolkit=_desktop(grabber),
    )
    result = await ex.execute("desktop__deadbeef.screenshot", {}, user_id="u1")
    assert result["ok"] is False
    assert grabber.calls == 0


@pytest.mark.asyncio
async def test_slugged_web_name_cannot_bypass_the_web_gate():
    web = TripwireWebToolkit()
    ex = ConnectorToolExecutor(
        session_factory=None, capability_gate=_gate(), web_toolkit=web
    )
    result = await ex.execute("web__0badf00d.search", {"query": "x"}, user_id="u1")
    assert result["ok"] is False
    assert web.calls == 0


@pytest.mark.asyncio
async def test_slugged_builtin_names_are_blocked_by_the_adapter():
    adapter = RuntimePermissionAdapter(capability_gate=_gate("screen", "web_browsing"))
    for name in ("desktop__deadbeef.screenshot", "web__0badf00d.search"):
        assert await adapter.check("u1", name, {}) == "blocked"


def test_offer_gate_uses_the_canonical_name():
    # A connector row can never be of a built-in type, so no slugged
    # built-in is ever offered; the capability decides by type.action.
    offered = names(build_tools([], enabled_capabilities=frozenset()))
    assert "system.capabilities" in offered
    assert offered <= capability_registry.ALWAYS_ON_TOOLS


# ── the permission adapter blocks before anything runs ───────────────────


@pytest.mark.asyncio
async def test_adapter_blocks_a_tool_whose_capability_is_off():
    adapter = RuntimePermissionAdapter(capability_gate=_gate("web_browsing"))
    screen = capability_registry.get("screen")
    assert await adapter.check("u1", "desktop.screenshot", {}) == "blocked"
    assert await adapter.get_block_reason("u1", "desktop.screenshot", {}) == screen.when_denied
    assert await adapter.get_policy_name("u1", "desktop.screenshot") == CAPABILITY_OFF_POLICY


@pytest.mark.asyncio
async def test_adapter_default_gate_is_registry_defaults():
    adapter = RuntimePermissionAdapter()
    assert await adapter.check("u1", "desktop.screenshot", {}) == "blocked"
    assert await adapter.check("u1", "web.search", {}) == "approved"


@pytest.mark.asyncio
async def test_adapter_defers_to_policy_when_the_capability_is_on():
    adapter = RuntimePermissionAdapter(capability_gate=_gate("screen", "installs"))
    assert await adapter.check("u1", "desktop.screenshot", {}) == "approved"
    # Capability on does not bypass the approval card for an install.
    assert await adapter.check("u1", "system.install_capability", {"name": "browser"}) == "requires_approval"
    assert await adapter.get_policy_name("u1", "desktop.screenshot") != CAPABILITY_OFF_POLICY


@pytest.mark.asyncio
async def test_always_on_tools_ignore_the_gate():
    adapter = RuntimePermissionAdapter(capability_gate=_gate())
    assert await adapter.check("u1", "system.capabilities", {}) == "approved"


# ── blocked is not off ───────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_switched_on_but_not_installed_is_blocked_not_off():
    """Website screenshots switched on, browser missing: the refusal says
    why (not installed) and how to fix it, under capability_blocked — never
    the "turned off" sentence, which would send the owner to a switch that
    is already on."""
    gate = _gate("site_screenshots", "web_browsing", browser_installed=False)
    cap = capability_registry.get("site_screenshots")

    adapter = RuntimePermissionAdapter(capability_gate=gate)
    assert await adapter.check("u1", "web.screenshot", {}) == "blocked"
    reason = await adapter.get_block_reason("u1", "web.screenshot", {})
    assert "not installed" in reason
    assert reason != cap.when_denied and "turned off" not in reason.lower()
    assert reason.endswith("The owner can install it from Settings → Permissions.")
    assert await adapter.get_policy_name("u1", "web.screenshot") == CAPABILITY_BLOCKED_POLICY

    web = TripwireWebToolkit()
    ex = ConnectorToolExecutor(session_factory=None, capability_gate=gate, web_toolkit=web)
    result = await ex.execute("web.screenshot", {"url": "https://example.com/"}, user_id="u1")
    assert result == {
        "ok": False,
        "capability": "site_screenshots",
        "state": "blocked",
        "error": reason,
    }
    assert web.calls == 0


@pytest.mark.asyncio
async def test_switched_off_is_capability_off():
    gate = _gate("web_browsing")
    adapter = RuntimePermissionAdapter(capability_gate=gate)
    assert await adapter.check("u1", "desktop.screenshot", {}) == "blocked"
    assert await adapter.get_policy_name("u1", "desktop.screenshot") == CAPABILITY_OFF_POLICY

    ex = ConnectorToolExecutor(
        session_factory=None, capability_gate=gate, desktop_toolkit=_desktop(Tripwire())
    )
    result = await ex.execute("desktop.screenshot", {}, user_id="u1")
    assert result["state"] == "off"
    assert result["error"] == capability_registry.get("screen").when_denied


@pytest.mark.asyncio
async def test_blocked_reason_carries_the_first_fix_step():
    statuses = dict(_statuses("screen"))
    statuses["screen"] = dataclasses.replace(
        statuses["screen"],
        effective="blocked",
        reason="macOS has not granted Screen Recording to /usr/bin/python3.",
        fix_steps=("Open System Settings → Privacy & Security → Screen Recording.", "Restart."),
    )

    async def gate():
        return statuses

    adapter = RuntimePermissionAdapter(capability_gate=gate)
    assert await adapter.check("u1", "desktop.screenshot", {}) == "blocked"
    assert await adapter.get_block_reason("u1", "desktop.screenshot", {}) == (
        "macOS has not granted Screen Recording to /usr/bin/python3. "
        "To fix: Open System Settings → Privacy & Security → Screen Recording."
    )
    assert await adapter.get_policy_name("u1", "desktop.screenshot") == CAPABILITY_BLOCKED_POLICY


@pytest.mark.asyncio
async def test_a_report_missing_the_capability_refuses():
    statuses = dict(_statuses("screen"))
    del statuses["screen"]

    async def gate():
        return statuses

    adapter = RuntimePermissionAdapter(capability_gate=gate)
    assert await adapter.check("u1", "desktop.screenshot", {}) == "blocked"
    ex = ConnectorToolExecutor(
        session_factory=None, capability_gate=gate, desktop_toolkit=_desktop(Tripwire())
    )
    assert (await ex.execute("desktop.screenshot", {}, user_id="u1"))["ok"] is False


# ── a gate that cannot answer refuses (fail closed) ──────────────────────


@pytest.mark.asyncio
async def test_adapter_refuses_when_the_gate_raises():
    adapter = RuntimePermissionAdapter(capability_gate=_raising_gate)
    with capture_logs() as logs:
        assert await adapter.check("u1", "web.search", {}) == "blocked"
    assert await adapter.get_block_reason("u1", "web.search", {}) == CAPABILITY_GATE_ERROR_REASON
    assert await adapter.get_policy_name("u1", "web.search") == CAPABILITY_GATE_ERROR_POLICY

    failed = [e for e in logs if e["event"] == "capability_gate_failed"]
    assert failed and failed[0]["error_type"] == "RuntimeError"
    assert GATE_SECRET not in repr(logs)
    # A tool no capability gates never consults the gate.
    assert await adapter.check("u1", "system.capabilities", {}) == "approved"


@pytest.mark.asyncio
async def test_executor_refuses_when_the_gate_raises():
    web = TripwireWebToolkit()
    ex = ConnectorToolExecutor(session_factory=None, capability_gate=_raising_gate, web_toolkit=web)
    with capture_logs() as logs:
        result = await ex.execute("web.search", {"query": "x"}, user_id="u1")
    assert result == {
        "ok": False,
        "capability": "web_browsing",
        "state": "error",
        "error": CAPABILITY_GATE_ERROR_REASON,
    }
    assert web.calls == 0
    assert any(
        e["event"] == "capability_gate_failed" and e["error_type"] == "RuntimeError"
        for e in logs
    )
    assert GATE_SECRET not in repr(logs)


@pytest.mark.asyncio
async def test_a_gate_on_the_old_contract_refuses():
    """A gate still answering a bare key set is not a report: refuse rather
    than guess which keys are on."""

    async def old_gate():
        return frozenset({"screen"})

    adapter = RuntimePermissionAdapter(capability_gate=old_gate)
    assert await adapter.check("u1", "desktop.screenshot", {}) == "blocked"
    assert await adapter.get_policy_name("u1", "desktop.screenshot") == CAPABILITY_GATE_ERROR_POLICY


# ── one decision per check sequence ──────────────────────────────────────


@pytest.mark.asyncio
async def test_reason_and_policy_come_from_the_decision_check_made():
    """The report refreshes between check() and the reason/policy calls
    (screen switched on mid-sequence): the audit row must still carry the
    capability refusal check() made, not the engine's reason for an
    allowed call."""
    answers = [_statuses("web_browsing"), _statuses("screen", "web_browsing")]

    async def flipping_gate():
        return answers.pop(0) if len(answers) > 1 else answers[0]

    adapter = RuntimePermissionAdapter(capability_gate=flipping_gate)
    assert await adapter.check("u1", "desktop.screenshot", {}) == "blocked"
    assert (
        await adapter.get_block_reason("u1", "desktop.screenshot", {})
        == capability_registry.get("screen").when_denied
    )
    assert await adapter.get_policy_name("u1", "desktop.screenshot") == CAPABILITY_OFF_POLICY
    # The next check decides afresh.
    assert await adapter.check("u1", "desktop.screenshot", {}) == "approved"


# ── the runtime backstop reads the executor's refusal ────────────────────


def test_backstop_maps_the_refusal_state_to_its_policy():
    off = {"ok": False, "capability": "screen", "state": "off", "error": "off text"}
    blocked = {"ok": False, "capability": "screen", "state": "blocked", "error": "why"}
    error = {"ok": False, "capability": "screen", "state": "error", "error": GATE_SECRET}
    assert _capability_refusal("desktop.screenshot", off) == ("off text", CAPABILITY_OFF_POLICY)
    assert _capability_refusal("desktop.screenshot", blocked) == ("why", CAPABILITY_BLOCKED_POLICY)
    # The fixed sentence, whatever text the result carries.
    assert _capability_refusal("desktop.screenshot", error) == (
        CAPABILITY_GATE_ERROR_REASON,
        CAPABILITY_GATE_ERROR_POLICY,
    )


@pytest.mark.parametrize(
    "name",
    [
        "mcp.desktop.screenshot",  # a third-party tool returning the same shape
        "desktop__deadbeef.screenshot",  # a spelling that does not resolve
        "desktop.no_such_action",
        "canvas.get_courses",  # resolves, but no capability gates it
    ],
)
def test_backstop_only_honours_the_capability_that_gates_the_resolved_tool(name):
    result = {"ok": False, "capability": "screen", "state": "off", "error": "x"}
    assert _capability_refusal(name, result) is None


# ── audit: a refusal is recorded as tool_blocked / capability_off ────────


class ScriptedProvider:
    def __init__(self, responses):
        self._responses = list(responses)
        # Everything the model was sent, call by call.
        self.seen: list = []

    async def complete(self, messages, tools=None):
        from services.agent.providers import LLMResponse

        self.seen.append(messages)
        return self._responses.pop(0) if self._responses else LLMResponse(content="done")

    async def stream(self, messages, tools=None):
        yield "done"


class RecordingAudit:
    def __init__(self, fail_on=()):
        self.entries = []
        self._fail_on = set(fail_on)

    async def log(self, entry):
        if entry.get("event") in self._fail_on:
            raise RuntimeError("audit store down")
        self.entries.append(entry)

    def events(self):
        return [e["event"] for e in self.entries]


def _calls_screenshot():
    from services.agent.providers import LLMResponse, ToolCall

    return ScriptedProvider(
        [
            LLMResponse(
                content="Let me look.",
                tool_calls=[ToolCall(id="t1", name="desktop.screenshot", arguments={})],
            ),
            LLMResponse(content="done"),
        ]
    )


def _runtime(permission_gate, executor_gate, grabber, audit, store=None, session_factory=None):
    from core.config import settings
    from services.agent.approvals import InMemoryApprovalStore
    from services.agent.runtime import AgentRuntime

    return AgentRuntime(
        config=settings,
        permission_engine=RuntimePermissionAdapter(capability_gate=permission_gate),
        tool_executor=ConnectorToolExecutor(
            session_factory=session_factory,
            capability_gate=executor_gate,
            desktop_toolkit=_desktop(grabber),
        ),
        audit_service=audit,
        approval_store=store or InMemoryApprovalStore(),
    )


@pytest.mark.asyncio
async def test_off_tool_is_audited_as_blocked_before_any_intent_row(session_factory):
    """The model names desktop.screenshot with screen off: the adapter
    blocks it, the chain gets a tool_blocked row with policy capability_off
    and never a tool_executing intent row, and nothing is captured."""
    from sqlalchemy import select

    from models.audit import AuditLog, AuditStatus
    from services.audit import RuntimeAuditLogger
    from tests.conftest import make_user, use_provider

    user, _ = await make_user(session_factory, "gate-audit@example.com")
    grabber = Tripwire()
    gate = _gate("web_browsing")
    runtime = _runtime(
        gate,
        gate,
        grabber,
        RuntimeAuditLogger(session_factory=session_factory),
        session_factory=session_factory,
    )
    use_provider(runtime, _calls_screenshot())

    response = await runtime.chat(
        messages=[{"role": "user", "content": "What is on my screen right now?"}],
        tools=build_tools([]),
        user_id=str(user.id),
    )

    assert grabber.calls == 0
    assert [(b.tool_name, b.policy) for b in response.blocked_actions] == [
        ("desktop.screenshot", CAPABILITY_OFF_POLICY)
    ]
    async with session_factory() as s:
        rows = (
            await s.execute(
                select(AuditLog).where(AuditLog.user_id == user.id).order_by(AuditLog.seq)
            )
        ).scalars().all()
    events = [r.reasoning_chain["event"] for r in rows]
    assert "tool_executing" not in events and "tool_executed" not in events
    blocked = [r for r in rows if r.reasoning_chain["event"] == "tool_blocked"]
    assert len(blocked) == 1
    row = blocked[0]
    assert (row.connector_name, row.action, row.status) == (
        "desktop",
        "screenshot",
        AuditStatus.blocked,
    )
    assert row.reasoning_chain["policy"] == CAPABILITY_OFF_POLICY
    assert row.reasoning_chain["reason"] == capability_registry.get("screen").when_denied


@pytest.mark.asyncio
async def test_executor_backstop_refusal_is_audited_as_capability_off():
    """The switch flips between the permission check and dispatch: the
    executor refuses, and the runtime records and shows it as blocked
    rather than as an executed tool."""
    from tests.conftest import use_provider

    grabber = Tripwire()
    audit = RecordingAudit()
    runtime = _runtime(_gate("screen"), _gate(), grabber, audit)
    use_provider(runtime, _calls_screenshot())

    response = await runtime.chat(
        messages=[{"role": "user", "content": "What is on my screen right now?"}],
        tools=build_tools([], enabled_capabilities=frozenset({"screen"})),
        user_id="u1",
    )

    assert grabber.calls == 0
    assert "tool_executed" not in audit.events()
    blocked = [e for e in audit.entries if e["event"] == "tool_blocked"]
    assert len(blocked) == 1 and blocked[0]["policy"] == CAPABILITY_OFF_POLICY
    assert [b.policy for b in response.blocked_actions] == [CAPABILITY_OFF_POLICY]


@pytest.mark.asyncio
async def test_backstop_refusal_stands_when_its_audit_write_fails():
    from tests.conftest import use_provider

    grabber = Tripwire()
    audit = RecordingAudit(fail_on={"tool_blocked"})
    runtime = _runtime(_gate("screen"), _gate(), grabber, audit)
    use_provider(runtime, _calls_screenshot())

    response = await runtime.chat(
        messages=[{"role": "user", "content": "What is on my screen right now?"}],
        tools=build_tools([], enabled_capabilities=frozenset({"screen"})),
        user_id="u1",
    )

    assert grabber.calls == 0
    assert "tool_executed" not in audit.events()
    assert [b.policy for b in response.blocked_actions] == [CAPABILITY_OFF_POLICY]


@pytest.mark.asyncio
async def test_approved_action_refused_by_the_gate_is_audited_as_blocked():
    """An install parked for approval, then the owner switches installs
    off: approving it must not run it, and the chain says tool_blocked
    (capability_off), not tool_approved_and_executed."""
    from services.agent.approvals import InMemoryApprovalStore

    store = InMemoryApprovalStore()
    audit = RecordingAudit()
    runtime = _runtime(_gate(), _gate(), Tripwire(), audit, store=store)
    parked = await store.create(
        user_id="u1",
        tool_name="system.install_capability",
        arguments={"name": "browser"},
        reason="needs approval",
    )

    outcome = await runtime.approve_action(parked.action_id, "u1")

    assert outcome["result"]["ok"] is False
    assert outcome["result"]["capability"] == "installs"
    assert "tool_approved_and_executed" not in audit.events()
    blocked = [e for e in audit.entries if e["event"] == "tool_blocked"]
    assert len(blocked) == 1
    assert blocked[0]["policy"] == CAPABILITY_OFF_POLICY
    assert blocked[0]["action_id"] == parked.action_id


@pytest.mark.asyncio
async def test_executor_backstop_records_a_blocked_capability_as_blocked():
    """On when the permission check ran, unusable by dispatch (the probe
    now says denied): the backstop records capability_blocked with the
    executor's reason, not capability_off."""
    from tests.conftest import use_provider

    statuses = dict(_statuses("screen"))
    statuses["screen"] = dataclasses.replace(
        statuses["screen"], effective="blocked", reason="Screen Recording is not granted."
    )

    async def blocked_gate():
        return statuses

    grabber = Tripwire()
    audit = RecordingAudit()
    runtime = _runtime(_gate("screen"), blocked_gate, grabber, audit)
    use_provider(runtime, _calls_screenshot())

    response = await runtime.chat(
        messages=[{"role": "user", "content": "What is on my screen right now?"}],
        tools=build_tools([], enabled_capabilities=frozenset({"screen"})),
        user_id="u1",
    )

    assert grabber.calls == 0
    assert "tool_executed" not in audit.events()
    blocked = [e for e in audit.entries if e["event"] == "tool_blocked"]
    assert [(e["policy"], e["reason"]) for e in blocked] == [
        (CAPABILITY_BLOCKED_POLICY, "Screen Recording is not granted.")
    ]
    assert [b.policy for b in response.blocked_actions] == [CAPABILITY_BLOCKED_POLICY]


def _assert_secret_never_left(provider, audit, response):
    assert GATE_SECRET not in repr(provider.seen)
    assert GATE_SECRET not in repr(audit.entries)
    assert GATE_SECRET not in repr(response)


@pytest.mark.asyncio
async def test_permission_gate_error_blocks_before_any_intent_row():
    from tests.conftest import use_provider

    grabber = Tripwire()
    audit = RecordingAudit()
    runtime = _runtime(_raising_gate, _gate("screen"), grabber, audit)
    provider = _calls_screenshot()
    use_provider(runtime, provider)

    response = await runtime.chat(
        messages=[{"role": "user", "content": "What is on my screen right now?"}],
        tools=build_tools([], enabled_capabilities=frozenset({"screen"})),
        user_id="u1",
    )

    assert grabber.calls == 0
    assert "tool_executing" not in audit.events() and "tool_executed" not in audit.events()
    blocked = [e for e in audit.entries if e["event"] == "tool_blocked"]
    assert [(e["policy"], e["reason"]) for e in blocked] == [
        (CAPABILITY_GATE_ERROR_POLICY, CAPABILITY_GATE_ERROR_REASON)
    ]
    assert [b.policy for b in response.blocked_actions] == [CAPABILITY_GATE_ERROR_POLICY]
    _assert_secret_never_left(provider, audit, response)


@pytest.mark.asyncio
async def test_executor_gate_error_is_recorded_by_the_backstop():
    from tests.conftest import use_provider

    grabber = Tripwire()
    audit = RecordingAudit()
    runtime = _runtime(_gate("screen"), _raising_gate, grabber, audit)
    provider = _calls_screenshot()
    use_provider(runtime, provider)

    response = await runtime.chat(
        messages=[{"role": "user", "content": "What is on my screen right now?"}],
        tools=build_tools([], enabled_capabilities=frozenset({"screen"})),
        user_id="u1",
    )

    assert grabber.calls == 0
    assert "tool_executed" not in audit.events()
    blocked = [e for e in audit.entries if e["event"] == "tool_blocked"]
    assert [(e["policy"], e["reason"]) for e in blocked] == [
        (CAPABILITY_GATE_ERROR_POLICY, CAPABILITY_GATE_ERROR_REASON)
    ]
    assert [b.policy for b in response.blocked_actions] == [CAPABILITY_GATE_ERROR_POLICY]
    _assert_secret_never_left(provider, audit, response)


@pytest.mark.asyncio
async def test_approval_whose_gate_errors_is_audited_as_blocked():
    from services.agent.approvals import InMemoryApprovalStore

    store = InMemoryApprovalStore()
    audit = RecordingAudit()
    runtime = _runtime(_gate("installs"), _raising_gate, Tripwire(), audit, store=store)
    parked = await store.create(
        user_id="u1",
        tool_name="system.install_capability",
        arguments={"name": "browser"},
        reason="needs approval",
    )

    outcome = await runtime.approve_action(parked.action_id, "u1")

    assert outcome["result"]["state"] == "error"
    assert "tool_approved_and_executed" not in audit.events()
    blocked = [e for e in audit.entries if e["event"] == "tool_blocked"]
    assert [(e["policy"], e["reason"]) for e in blocked] == [
        (CAPABILITY_GATE_ERROR_POLICY, CAPABILITY_GATE_ERROR_REASON)
    ]
    assert GATE_SECRET not in repr(outcome) and GATE_SECRET not in repr(audit.entries)


# ── browser.read ─────────────────────────────────────────────────────────


class RecordingBrowserToolkit:
    def __init__(self) -> None:
        self.calls: list[tuple] = []

    async def execute(self, action, params, *, user_id, task_id):
        self.calls.append((action, params, user_id, task_id))
        return {"ok": True}


def test_browser_is_a_builtin_type_with_a_stance():
    from services.agent.tool_registry import _BUILTIN_STANCE

    assert "browser" in BUILTIN_CONNECTOR_TYPES
    assert _BUILTIN_STANCE["browser"] == "user_confirm"


def test_browser_read_is_offered_only_with_browser_control_on():
    from services.tools.browser.actions import ACTIONS

    assert "browser.read" not in names(build_tools([]))
    offered = build_tools([], enabled_capabilities=frozenset({"browser_control"}))
    tool = next(t for t in offered if t.name == "browser.read")
    assert tool.permission_tier == "auto"
    assert tool.parameters["required"] == ["action"]
    assert tool.parameters["properties"]["action"]["enum"] == list(ACTIONS)
    assert set(tool.parameters["properties"]) == {
        "action", "url", "ref", "text", "query", "full", "direction", "index", "ms", "for_model", "reason",
    }


def test_browser_read_resolves_as_a_read():
    resolved = resolve_tool("browser.read")
    assert resolved is not None and resolved.spec.category.value == "read"
    assert resolve_tool("browser__deadbeef.read") is None


@pytest.mark.asyncio
async def test_executor_hands_the_browser_toolkit_the_action_user_and_task():
    kit = RecordingBrowserToolkit()
    ex = ConnectorToolExecutor(
        session_factory=None,
        capability_gate=_gate("browser_control", playwright_installed=True, browser_channel="chrome"),
        browser_toolkit=kit,
    )
    result = await ex.execute(
        "browser.read",
        {"action": "open", "url": "https://example.com/", "user_confirmed": True},
        user_id="u1",
        task_id="conv-9",
    )
    assert result == {"ok": True}
    assert kit.calls == [("open", {"url": "https://example.com/"}, "u1", "conv-9")]


@pytest.mark.asyncio
async def test_executor_task_id_falls_back_to_the_user():
    kit = RecordingBrowserToolkit()
    ex = ConnectorToolExecutor(
        session_factory=None,
        capability_gate=_gate("browser_control", playwright_installed=True, browser_channel="chrome"),
        browser_toolkit=kit,
    )
    await ex.execute("browser.read", {"action": "tabs"}, user_id="u1")
    assert kit.calls == [("tabs", {}, "u1", "u1")]


@pytest.mark.asyncio
async def test_executor_refuses_browser_read_when_browser_control_is_off_or_blocked():
    kit = RecordingBrowserToolkit()
    off = ConnectorToolExecutor(session_factory=None, capability_gate=_gate("web_browsing"), browser_toolkit=kit)
    result = await off.execute("browser.read", {"action": "open", "url": "x"}, user_id="u1")
    assert result["ok"] is False and result["capability"] == "browser_control" and result["state"] == "off"
    blocked = ConnectorToolExecutor(
        session_factory=None,
        capability_gate=_gate("browser_control", playwright_installed=False),
        browser_toolkit=kit,
    )
    result = await blocked.execute("browser.read", {"action": "open", "url": "x"}, user_id="u1")
    assert result["state"] == "blocked" and "Playwright" in result["error"]
    assert kit.calls == []


@pytest.mark.asyncio
async def test_permission_adapter_blocks_browser_read_until_the_owner_turns_it_on():
    adapter = RuntimePermissionAdapter(capability_gate=_gate("web_browsing"))
    assert await adapter.check("u1", "browser.read", {}) == "blocked"
    assert await adapter.get_policy_name("u1", "browser.read") == CAPABILITY_OFF_POLICY
    on = RuntimePermissionAdapter(
        capability_gate=_gate("browser_control", playwright_installed=True, browser_channel="chrome")
    )
    assert await on.check("u1", "browser.read", {}) == "approved"
