"""Tests for the "tool_rules" capability (services/capabilities/tool_rules.py): it proves the
switch is an always-available policy switch that claims no tools, is on by default (an install
whose stored switches predate it reads it as on), takes no capability settings, sits in the
registry in the security wave's order, and that the model's <permissions> block shows its
``when_denied`` line once the owner turns it off.

Why it exists: decisions.md item 3. The switch is the owner's one way to stop every tool rule;
a default of off, a claimed tool, or a settings entry (sent to every account, numbers only)
would each change what Crawler asks before without the owner choosing it.
"""

from __future__ import annotations

from services import capabilities
from services.capabilities import tool_rules
from services.capabilities.base import ReportContext
from services.capabilities.prompt import render_permissions_block

_CTX = ReportContext(in_container=True, platform="linux", telegram_configured=False, browser_installed=False)


def test_tool_rules_is_an_always_available_policy_switch_on_by_default():
    cap = capabilities.get("tool_rules")
    assert cap is tool_rules.CAPABILITY and cap.key == tool_rules.KEY == "tool_rules"
    assert cap.label == "Ask before calls that break a tool rule"
    assert cap.description.startswith("Before Crawler runs an action, check it against a few built-in")
    assert "the card names the rule" in cap.description
    assert cap.tools == () and cap.default_enabled is True and cap.risk == "low"
    assert cap.install is None and cap.probe is None and not cap.requires
    assert capabilities.default_switches()["tool_rules"] is True
    # No capability settings: rules live in their own tables (migration 0031).
    assert capabilities.settings_defaults("tool_rules") == {}
    # It claims no tool, so no tool call is ever gated off by it.
    for tool in ("google_workspace.send_email", "mcp.stripe.refund", "tools.find"):
        found = capabilities.capability_for_tool(tool)
        assert found is None or found.key != "tool_rules"

    # The security wave's registry order (scaffold A25): after the site rules, before files.
    keys = [c.key for c in capabilities.REGISTRY]
    assert keys.index("browser_site_rules") < keys.index("tool_rules") < keys.index("file_reputation")

    # An install whose stored switches predate it reads the default: on, and always available.
    assert "tool_rules" in capabilities.enabled_keys({}, _CTX)
    status = capabilities.statuses_by_key(capabilities.report({}, _CTX))["tool_rules"]
    assert status.enabled and status.effective
    on = render_permissions_block(capabilities.report({}, _CTX))
    assert "- Ask before calls that break a tool rule: on" in on
    off = render_permissions_block(capabilities.report({"tool_rules": False}, _CTX))
    assert f"- Ask before calls that break a tool rule: off. {cap.when_denied}" in off
    assert "tool_rules" not in capabilities.enabled_keys({"tool_rules": False}, _CTX)
    # The model is never told what the rules are, only that they are off.
    assert "Settings → Permissions" in cap.when_denied
