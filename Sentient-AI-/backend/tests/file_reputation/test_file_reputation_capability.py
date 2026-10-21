"""Tests for the file_reputation capability and the security.* family it gates
(services/capabilities/file_reputation.py, the executor's security entry and the upload's
policy names): they prove the switch is on by default but blocked until a VirusTotal key exists
(and only that key unblocks it), its four limits default to VirusTotal's public ones and match
the quota's own defaults, it claims exactly the two file tools, the family has its stance,
policy rows and executor entry (the upload always behind a card), check_file is refused by the
adapter and the executor without a key, and the upload's refusal policy is one name everywhere.

Why it exists: nothing may leave the machine before the owner adds a key (decisions 2), and an
upload must keep its card under every account default; these are registry and executor facts
that a later edit could quietly change.
"""

from __future__ import annotations

import pytest

from services import capabilities as registry
from services.agent import runtime as agent_runtime
from services.agent import tool_registry
from services.agent.permissions import ActionCategory
from services.agent.tool_registry import (
    BUILTIN_CONNECTOR_TYPES,
    CAPABILITY_OFF_POLICY,
    ConnectorToolExecutor,
    RuntimePermissionAdapter,
)
from services.automation.fence import NEVER_TOOLS
from services.capabilities import file_reputation
from services.capabilities.base import ReportContext
from services.file_reputation import quota, toolkit
from services.tools.security_checks import SecurityToolkit


def _context(service_keys: frozenset[str] = frozenset()) -> ReportContext:
    return ReportContext(
        in_container=False,
        platform="linux",
        telegram_configured=False,
        browser_installed=False,
        service_keys=service_keys,
    )


def _status(service_keys: frozenset[str] = frozenset(), *, switched_on: bool = True):
    switches = registry.default_switches()
    switches["file_reputation"] = switched_on
    statuses = registry.statuses_by_key(registry.report(switches, _context(service_keys), use_cache=False))
    return statuses["file_reputation"], statuses


class Tripwire:
    """A file toolkit the gate must stop before it is reached."""

    def __init__(self) -> None:
        self.calls = 0

    async def execute(self, action, params, user_id, *, approved=False):
        self.calls += 1
        raise AssertionError("the capability gate let a file tool run without a key")


def test_file_reputation_is_on_by_default_but_blocked_until_a_virustotal_key_exists():
    assert file_reputation.CAPABILITY.default_enabled is True
    assert registry.default_switches()["file_reputation"] is True
    blocked, _ = _status()
    assert blocked.effective == "blocked"
    assert blocked.reason.startswith("Add a VirusTotal API key in Security")
    on, _ = _status(frozenset({"virustotal"}))
    assert on.effective == "on"
    off, _ = _status(frozenset({"virustotal"}), switched_on=False)
    assert off.effective == "off"


def test_another_services_key_alone_does_not_unblock_it():
    others = frozenset({"safe_browsing", "web_risk", "hibp"})
    status, _ = _status(others)
    assert status.effective == "blocked"


def test_its_settings_default_to_virustotals_public_limits():
    assert file_reputation.FILE_REPUTATION_SETTINGS_DEFAULTS == {
        "lookups_per_minute": 4,
        "lookups_per_day": 500,
        "automatic_lookups_per_day": 100,
        "lookups_per_user_per_day": 100,
    }
    assert registry.settings_defaults("file_reputation") == file_reputation.FILE_REPUTATION_SETTINGS_DEFAULTS
    # The quota's own fallback (used when the settings cannot be read) is the same.
    assert quota.limits_from_settings(file_reputation.FILE_REPUTATION_SETTINGS_DEFAULTS) == quota.DEFAULT_LIMITS
    assert set(quota.SETTING_KEYS.values()) == set(file_reputation.FILE_REPUTATION_SETTINGS_DEFAULTS)


def test_it_claims_exactly_check_file_and_upload_to_virustotal():
    assert file_reputation.CAPABILITY.tools == ("security.check_file", "security.upload_to_virustotal")
    assert file_reputation.CAPABILITY.risk == "medium"
    claimers = {
        tool: [cap.key for cap in registry.REGISTRY if tool in cap.tools]
        for tool in file_reputation.CAPABILITY.tools
    }
    assert claimers == {
        "security.check_file": ["file_reputation"],
        "security.upload_to_virustotal": ["file_reputation"],
    }


def test_the_security_family_has_a_stance_policy_rows_and_an_executor_entry():
    assert "security" in BUILTIN_CONNECTOR_TYPES
    assert tool_registry._BUILTIN_STANCE["security"] == "user_confirm"
    specs = {spec.action: spec for spec in tool_registry.CONNECTOR_CATALOG["security"]}
    assert specs["check_file"].category == ActionCategory.READ and not specs["check_file"].always_confirm
    assert specs["upload_to_virustotal"].category == ActionCategory.WRITE
    assert specs["upload_to_virustotal"].always_confirm is True
    builtin = ConnectorToolExecutor()._builtins["security"]
    assert ActionCategory.WRITE in builtin.confirm
    # Never offered to an unattended run; the lookup stays an allowed read.
    assert "security.upload_to_virustotal" in NEVER_TOOLS
    assert "security.check_file" not in NEVER_TOOLS
    # The family routes both actions to the file toolkit once it is wired.
    family = SecurityToolkit()
    marker = object()
    family.use_file_reputation(marker)
    assert family.file_reputation is marker


@pytest.mark.asyncio
async def test_check_file_is_refused_at_the_adapter_and_the_executor_without_a_key():
    _, statuses = _status()

    async def gate():
        return statuses

    adapter = RuntimePermissionAdapter(capability_gate=gate)
    assert await adapter.check("u1", "security.check_file", {"sha256": "a" * 64}) == "blocked"
    reason = await adapter.get_block_reason("u1", "security.check_file", {})
    assert "VirusTotal API key" in reason
    assert await adapter.get_policy_name("u1", "security.check_file") != CAPABILITY_OFF_POLICY

    family = SecurityToolkit()
    tripwire = Tripwire()
    family.use_file_reputation(tripwire)
    executor = ConnectorToolExecutor(session_factory=None, capability_gate=gate, security_toolkit=family)
    for tool in ("security.check_file", "security.upload_to_virustotal"):
        result = await executor.execute(tool, {"sha256": "a" * 64}, user_id="u1", approved=True)
        assert result["ok"] is False and result["capability"] == "file_reputation"
        assert result["state"] == "blocked"
    assert tripwire.calls == 0


def test_the_bind_refusal_policy_matches_the_toolkits_rule_policy():
    assert toolkit.FILE_REPUTATION_RULE_POLICY == "file_reputation_rule"
    assert tool_registry.FILE_REPUTATION_RULE_POLICY == toolkit.FILE_REPUTATION_RULE_POLICY
    assert (
        agent_runtime._BIND_REFUSAL_POLICIES["security.upload_to_virustotal"]
        == toolkit.FILE_REPUTATION_RULE_POLICY
    )
    assert toolkit.UPLOAD_CARD_KEY == "_upload"
