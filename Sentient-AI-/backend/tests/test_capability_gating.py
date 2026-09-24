"""Off-by-default must hold at BOTH gates without any wiring: a caller that
forgets the enabled set gets the registry defaults, and the executor
refuses a tool whose capability is off.

The executor tests never touch a real display or network: every toolkit
the gate is meant to stop is a tripwire that fails the test if reached.
"""
from __future__ import annotations

import pytest

from services import capabilities as capability_registry
from services.agent.tool_registry import (
    BUILTIN_CONNECTOR_TYPES,
    CAPABILITY_OFF_POLICY,
    ConnectorToolExecutor,
    RuntimePermissionAdapter,
    build_tools,
    resolve_tool,
)
from services.capabilities.base import ProbeResult
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


def _gate(*keys):
    async def gate():
        return frozenset(keys)

    return gate


def test_desktop_is_a_builtin_type():
    assert "desktop" in BUILTIN_CONNECTOR_TYPES


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


# ── audit: a refusal is recorded as tool_blocked / capability_off ────────


class ScriptedProvider:
    def __init__(self, responses):
        self._responses = list(responses)

    async def complete(self, messages, tools=None):
        from services.agent.providers import LLMResponse

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
