"""Off-by-default must hold at BOTH gates without any wiring: a caller that
forgets the enabled set gets the registry defaults, and the executor
refuses a tool whose capability is off."""
from __future__ import annotations

import pytest

from services.agent.tool_registry import (
    BUILTIN_CONNECTOR_TYPES,
    ConnectorToolExecutor,
    build_tools,
)


def names(tools):
    return {t.name for t in tools}


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
    async def gate():
        return frozenset({"web_browsing"})
    ex = ConnectorToolExecutor(session_factory=None, capability_gate=gate)
    result = await ex.execute("desktop.screenshot", {}, user_id="u1")
    assert result["ok"] is False
    assert result.get("capability") == "screen"
    assert "turned off" in result["error"].lower()


@pytest.mark.asyncio
async def test_executor_default_gate_is_registry_defaults():
    ex = ConnectorToolExecutor(session_factory=None)
    result = await ex.execute("desktop.screenshot", {}, user_id="u1")
    assert result["ok"] is False and result.get("capability") == "screen"
