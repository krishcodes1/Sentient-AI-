"""Tests for how the mail scam scan is declared (services/capabilities/
mail_scam_scan.py): the "mail_scam_scan" switch is registered on by default,
medium risk, gating no tool; its two settings default to 20 AI reviews a
day and 30 days kept and stay whole numbers within the shared bounds; it is
available with no chat channel (alerts also reach the Security page); and
the sweeper's gate reads as off when the owner's report cannot be read.

Why it exists: the capability recipe (services/capabilities/README.md) is
what keeps a background check from running, spending or alerting outside
the owner's switch; these pin each step for this one.
"""

from __future__ import annotations

import pytest

from services import capabilities as registry
from services.capabilities import mail_scam_scan
from services.capabilities.base import ReportContext
from services.notifications.sweeper import capability_gate, gate_open


def ctx(**facts) -> ReportContext:
    return ReportContext(in_container=True, platform="linux", telegram_configured=False, browser_installed=False, **facts)


def test_mail_scam_scan_is_registered_on_by_default_medium_risk_with_no_tools():
    cap = registry.get("mail_scam_scan")
    assert cap is mail_scam_scan.CAPABILITY
    assert cap.label == "Check new email for scams"
    assert cap.tools == () and cap.default_enabled is True and cap.risk == "medium"
    assert cap.description.endswith("Nothing is moved without your approval.")
    assert "block" not in cap.description.lower()  # owner decision 8a: Block sender is deferred
    assert cap.when_denied == (
        "Automatic scam checks on new email are turned off. The owner can turn on 'Check new email for "
        "scams' in Settings \u2192 Permissions."
    )
    # On by default for an install that never stored the switch.
    assert "mail_scam_scan" in registry.enabled_keys({}, ctx())
    assert "mail_scam_scan" not in registry.enabled_keys({"mail_scam_scan": False}, ctx())


def test_its_settings_default_to_twenty_reviews_a_day_and_thirty_days_kept():
    assert registry.settings_defaults("mail_scam_scan") == {"ai_reviews_per_day": 20, "keep_alerts_days": 30}
    assert mail_scam_scan.MAIL_SCAN_SETTINGS_DEFAULTS == {"ai_reviews_per_day": 20, "keep_alerts_days": 30}


@pytest.mark.asyncio
async def test_its_settings_are_whole_numbers_within_the_shared_bounds(session_factory):
    import uuid

    from services.installation import InstallationService

    installation = InstallationService(session_factory)
    actor = uuid.uuid4()
    assert await installation.capability_settings("mail_scam_scan") == {"ai_reviews_per_day": 20, "keep_alerts_days": 30}
    for bad in ({"ai_reviews_per_day": 0}, {"keep_alerts_days": 1.5}, {"ai_reviews_per_day": True}, {"other": 3}):
        with pytest.raises(ValueError):
            await installation.set_capability_settings("mail_scam_scan", bad, actor_id=actor)


def test_it_is_available_without_any_chat_channel():
    cap = registry.get("mail_scam_scan")
    alone = cap.availability(ctx())
    assert alone.available is True
    assert cap.availability(ctx(telegram_enabled=True)).available is True
    statuses = {s.key: s for s in registry.report({}, ctx())}
    assert statuses["mail_scam_scan"].effective == "on"


@pytest.mark.asyncio
async def test_the_gate_reads_as_off_when_the_report_cannot_be_read():
    class Broken:
        async def enabled_keys(self):
            raise RuntimeError("settings blob unreadable")

    class On:
        async def enabled_keys(self):
            return {"mail_scam_scan"}

    class Off:
        async def enabled_keys(self):
            return set()

    assert await gate_open(capability_gate(Broken(), "mail_scam_scan"), "mail_scam_scan") is False
    assert await gate_open(capability_gate(Off(), "mail_scam_scan"), "mail_scam_scan") is False
    assert await gate_open(capability_gate(On(), "mail_scam_scan"), "mail_scam_scan") is True
