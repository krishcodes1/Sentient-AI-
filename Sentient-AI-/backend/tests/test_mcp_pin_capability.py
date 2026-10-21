"""Tests for the "mcp_pinning" capability (security S5): they prove it is a
policy switch that claims no tool, is always available, is on by default,
and that the <permissions> block tells the model what being off means.

Why it exists: the switch decides whether a changed MCP tool is held for the
owner's review. Being on by default and never "blocked" is what makes the
integrity gate the normal state of every install; the off sentence is what
the model says when the owner asks why a changed tool was still offered.
"""

from __future__ import annotations

from services import capabilities
from services.capabilities import mcp_pinning
from services.capabilities.base import ReportContext
from services.capabilities.prompt import render_permissions_block


def _ctx() -> ReportContext:
    return ReportContext(
        in_container=False, platform="win32", telegram_configured=False, browser_installed=False
    )


def test_mcp_pinning_is_an_always_available_policy_switch_on_by_default():
    capability = capabilities.get("mcp_pinning")
    assert capability is mcp_pinning.CAPABILITY
    assert capability.label == "Hold changed MCP tools for review"
    assert capability.tools == ()
    assert capability.default_enabled is True
    assert capability.risk == "low"
    assert capability.install is None
    assert "Security page" in capability.description
    assert capabilities.default_switches()["mcp_pinning"] is True
    # No settings: nothing here needs owner tuning.
    assert capabilities.settings_defaults("mcp_pinning") == {}

    # Always available: on with no facts at all, off only when switched off.
    statuses = capabilities.statuses_by_key(capabilities.report({"mcp_pinning": True}, _ctx()))
    assert statuses["mcp_pinning"].effective == "on"
    off = capabilities.statuses_by_key(capabilities.report({"mcp_pinning": False}, _ctx()))
    assert off["mcp_pinning"].effective == "off"


def test_the_permissions_block_says_when_mcp_pinning_is_off():
    block = render_permissions_block(capabilities.report({"mcp_pinning": False}, _ctx()))
    line = next(row for row in block.splitlines() if row.startswith("- Hold changed MCP tools"))
    assert "off" in line
    assert "offered even if the server changed what they say they do" in line
    assert "Settings → Permissions" in line

    on = render_permissions_block(capabilities.report({"mcp_pinning": True}, _ctx()))
    assert "- Hold changed MCP tools for review: on" in on.splitlines()
