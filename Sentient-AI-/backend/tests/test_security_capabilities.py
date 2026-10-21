"""Tests for the security wave's nine capabilities and the security.* built-in
family: they prove the nine follow video_transcripts in skill order, every one
is on by default, the three key-gated ones read blocked until their own key
exists, their settings defaults are registered and inside the owner-editable
bounds, every security tool is claimed by exactly one capability, the family
has its stance, its four policy tiers and an executor entry, and the new mail
security READs never push a starter, a lead or a core tool out of the offer.

Why it exists: WAVE 0 registers all nine before any skill is built, and each
skill then owns its capability file. A slip here (a capability off by
default, a key-gated one that reads on without a key, an upload that could run
unattended, a connector read that crowds out the tools the playbooks rely on)
would change production behaviour silently, so the structure is pinned once.
"""

from __future__ import annotations

import pytest

from services import capabilities as registry
from services.agent.context_manager import core_tool_names, select_offered_tools
from services.agent.permissions import (
    ActionCategory,
    PermissionEngine,
    PermissionTier,
)
from services.agent.runtime import AgentRuntime
from services.agent.tool_registry import (
    _BUILTIN_STANCE,
    BUILTIN_CONNECTOR_TYPES,
    CONNECTOR_CATALOG,
    LEAD_STARTER_TOOLS,
    RUNTIME_BUILTIN_TYPES,
    ConnectorSpec,
    ConnectorToolExecutor,
    build_tools,
    connector_scopes,
)
from services.capabilities.base import ReportContext
from services.installation import SETTING_MAX, SETTING_MIN

SECURITY_KEYS = (
    "outbound_checks",
    "mail_scam_scan",
    "scam_check",
    "link_reputation",
    "mcp_pinning",
    "breach_monitor",
    "browser_site_rules",
    "tool_rules",
    "file_reputation",
)
# The capabilities with settings, and the key each key-gated one waits for.
WITH_SETTINGS = ("mail_scam_scan", "scam_check", "link_reputation", "file_reputation")
KEY_GATED = {
    "link_reputation": ("safe_browsing", "web_risk"),
    "breach_monitor": ("hibp",),
    "file_reputation": ("virustotal",),
}
SECURITY_TOOLS = (
    "security.check_scam",
    "security.check_file",
    "security.upload_to_virustotal",
)
# The mail READs the security wave added (Block sender is deferred,
# decisions 8a, so there is no block_sender action).
MAIL_SECURITY_READS = (
    "get_draft",
    "get_attachment_hash",
    "list_new_message_ids",
    "get_message_security",
)


def _context(service_keys: frozenset[str] = frozenset()) -> ReportContext:
    return ReportContext(
        in_container=False,
        platform="linux",
        telegram_configured=False,
        browser_installed=False,
        service_keys=service_keys,
    )


def _effective(service_keys: frozenset[str]) -> dict[str, str]:
    statuses = registry.report(registry.default_switches(), _context(service_keys), use_cache=False)
    return {s.key: s.effective for s in statuses if s.key in SECURITY_KEYS}


def test_the_nine_security_capabilities_follow_video_transcripts_in_skill_order():
    keys = registry.keys()
    start = keys.index("video_transcripts") + 1
    assert keys[start : start + len(SECURITY_KEYS)] == SECURITY_KEYS


def test_every_security_capability_is_on_by_default():
    switches = registry.default_switches()
    assert all(switches[key] is True for key in SECURITY_KEYS)
    # Without any key, everything that needs none is on.
    effective = _effective(frozenset())
    for key in SECURITY_KEYS:
        if key not in KEY_GATED:
            assert effective[key] == "on", key


def test_the_key_gated_ones_are_blocked_until_their_own_key_exists():
    without_keys = _effective(frozenset())
    assert {key: without_keys[key] for key in KEY_GATED} == dict.fromkeys(KEY_GATED, "blocked")
    for key, names in KEY_GATED.items():
        for name in names:
            effective = _effective(frozenset({name}))
            assert effective[key] == "on", (key, name)
            # Another service's key never unblocks it.
            for other, other_names in KEY_GATED.items():
                if other != key and name not in other_names:
                    assert effective[other] == "blocked", (other, name)
    reason = next(
        s.reason
        for s in registry.report(registry.default_switches(), _context(), use_cache=False)
        if s.key == "file_reputation"
    )
    assert "VirusTotal API key" in reason


def test_their_settings_defaults_are_registered_and_within_bounds():
    for key in SECURITY_KEYS:
        defaults = registry.settings_defaults(key)
        if key not in WITH_SETTINGS:
            assert defaults == {}, key
            continue
        assert defaults, key
        for name, value in defaults.items():
            assert isinstance(value, int) and not isinstance(value, bool), (key, name)
            assert SETTING_MIN <= value <= SETTING_MAX, (key, name, value)
    assert registry.settings_defaults("scam_check") == {"checks_per_day": 30}
    assert registry.settings_defaults("file_reputation") == {
        "lookups_per_minute": 4,
        "lookups_per_day": 500,
        "automatic_lookups_per_day": 100,
        "lookups_per_user_per_day": 100,
    }


def test_every_security_tool_is_claimed_by_exactly_one_capability():
    catalog = {f"security.{spec.action}" for spec in CONNECTOR_CATALOG["security"]}
    assert catalog == set(SECURITY_TOOLS)
    owners = {}
    for name in SECURITY_TOOLS:
        claimed = [c.key for c in registry.REGISTRY if c.claims(name)]
        assert len(claimed) == 1, (name, claimed)
        owners[name] = claimed[0]
    assert owners == {
        "security.check_scam": "scam_check",
        "security.check_file": "file_reputation",
        "security.upload_to_virustotal": "file_reputation",
    }


def test_the_security_family_has_a_stance_policy_rows_and_an_executor_entry():
    assert "security" in BUILTIN_CONNECTOR_TYPES
    assert "security" not in RUNTIME_BUILTIN_TYPES
    assert _BUILTIN_STANCE["security"] == "user_confirm"
    engine = PermissionEngine()

    def tier(category: ActionCategory) -> PermissionTier:
        return engine.check_permission("security", "any_action", category).tier

    assert tier(ActionCategory.READ) == PermissionTier.AUTO_APPROVE
    assert tier(ActionCategory.WRITE) == PermissionTier.USER_CONFIRM
    for blocked in (ActionCategory.DELETE, ActionCategory.EXECUTE, ActionCategory.FINANCIAL):
        assert tier(blocked) == PermissionTier.HARD_BLOCKED
    builtin = ConnectorToolExecutor()._builtins["security"]
    assert builtin.allowed == frozenset({ActionCategory.READ, ActionCategory.WRITE})
    assert builtin.confirm == frozenset({ActionCategory.WRITE})
    assert builtin.confirm_note == "sends a file to VirusTotal"
    categories = {spec.action: spec for spec in CONNECTOR_CATALOG["security"]}
    assert categories["check_scam"].category == ActionCategory.READ
    assert categories["check_file"].category == ActionCategory.READ
    upload = categories["upload_to_virustotal"]
    assert upload.category == ActionCategory.WRITE and upload.always_confirm is True
    # The upload keeps its card under an auto_approve account default.
    tools = {
        t.name: t
        for t in build_tools(
            [],
            user_default_tier="auto_approve",
            enabled_capabilities=frozenset({"file_reputation", "scam_check"}),
        )
    }
    assert tools["security.check_scam"].permission_tier == "auto"
    assert tools["security.check_file"].permission_tier == "auto"
    assert tools["security.upload_to_virustotal"].permission_tier == "approval"


@pytest.mark.parametrize("connector_type", ["google_workspace", "microsoft"])
def test_the_new_mail_security_reads_never_displace_a_starter_or_a_lead(connector_type):
    """Every scope granted and every capability on (the most crowded offer):
    the security wave's mail READs and security.* tools are neither starters
    nor leads, and every core tool, lead and starter the offer kept without
    them is still offered with them. (With everything on, the cap already
    leaves some starters out; that is not this wave's doing.)"""
    scopes = connector_scopes(connector_type)
    spec = ConnectorSpec(
        connector_type,
        granted_scopes=tuple(scopes["read"] + scopes["write"]),
        connector_id="row-0",
    )
    every_capability = frozenset(c.key for c in registry.REGISTRY)
    tools = build_tools([spec], enabled_capabilities=every_capability)
    by_name = {t.name: t for t in tools}
    new_reads = {f"{connector_type}.{action}" for action in MAIL_SECURITY_READS} & set(by_name)
    assert new_reads, "the mail security reads are offered when their scope is granted"
    added = new_reads | (set(SECURITY_TOOLS) & set(by_name))
    for name in added:
        assert not by_name[name].starter and not by_name[name].lead, name
        assert name not in core_tool_names() and name not in LEAD_STARTER_TOOLS, name

    def offered(candidates: list) -> set[str]:
        schema = AgentRuntime._tools_to_schema(candidates)
        return {t["name"] for t in select_offered_tools(schema, [connector_type])}

    with_new = offered(tools)
    without_new = offered([t for t in tools if t.name not in added])
    kept_first = {
        name
        for name in without_new
        if name in core_tool_names() or by_name[name].lead or by_name[name].starter
    }
    assert kept_first <= with_new, sorted(kept_first - with_new)
    assert core_tool_names() & set(by_name) <= with_new
