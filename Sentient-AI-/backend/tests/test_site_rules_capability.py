"""Tests for the ``browser_site_rules`` capability: they prove it is an
always-available policy switch (no tools, no install, no probe, no
settings), on by default and low risk, that an install whose stored
switches predate it reads it as on, and that the Permissions block the
model reads says what "off" means.

Why it exists: the switch is the owner's one control over every site rule
(owner rules, category overrides and the built-in list); if it silently
defaulted off, or claimed a tool, banks and blocked sites would lose their
protection on every install. Pure: no database, no browser.
"""

from __future__ import annotations

from services import capabilities
from services.capabilities import browser_site_rules
from services.capabilities.base import ReportContext
from services.capabilities.prompt import render_permissions_block

KEY = "browser_site_rules"


def _context() -> ReportContext:
    return ReportContext(
        in_container=True, platform="linux", telegram_configured=False, browser_installed=False
    )


def test_browser_site_rules_is_an_always_available_policy_switch_on_by_default():
    cap = capabilities.get(KEY)
    assert cap is browser_site_rules.CAPABILITY
    assert cap.label == "Site rules for Crawler's browser"
    assert cap.tools == () and cap.default_enabled is True and cap.risk == "low"
    assert cap.install is None and cap.probe is None and not cap.requires
    assert capabilities.default_switches()[KEY] is True
    assert capabilities.settings_defaults(KEY) == {}
    # No browser tool is claimed: the rules also govern the web toolkit, so
    # the switch is useful with "Control a browser" off.
    assert not cap.claims("browser.read") and not cap.claims("web.fetch_page")
    # An install whose stored switches predate it reads the default: on.
    assert KEY in capabilities.enabled_keys({}, _context())
    assert KEY not in capabilities.enabled_keys({KEY: False}, _context())


def test_the_permissions_block_says_what_off_means():
    cap = capabilities.get(KEY)
    on = render_permissions_block(capabilities.report({}, _context()))
    assert "- Site rules for Crawler's browser: on" in on
    off = render_permissions_block(capabilities.report({KEY: False}, _context()))
    assert f"- Site rules for Crawler's browser: off. {cap.when_denied}" in off
    assert "Site rules are off" in cap.when_denied and "Settings" in cap.when_denied
