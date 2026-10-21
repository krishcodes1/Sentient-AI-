"""Declares the "mail_scam_scan" capability: Crawler checks every new email in
each connected Gmail and Outlook account for signs of a scam, asks the AI
provider about the ones that look wrong, and alerts the person.

Why it exists: phishing arrives by mail, usually before anyone asks Crawler
about it. The checks that need no network run on every new message; only
flagged mail is sent (pseudonymised) to an AI provider, under its own daily
cap, never the shared unattended budget. The sweeper
(services/notifications/mail_scan.py) re-reads this switch before every check
and every alert (a gate that cannot answer counts as off). Nothing is moved or
labelled without an approval card. It gates no tool (tools=()).
"""

from __future__ import annotations

from services.capabilities.base import Capability

# AI reviews per person per UTC day (flagged mail past it is alerted on
# Crawler's own checks only), and days an alert is kept.
MAIL_SCAN_SETTINGS_DEFAULTS = {"ai_reviews_per_day": 20, "keep_alerts_days": 30}

CAPABILITY = Capability(
    key="mail_scam_scan",
    label="Check new email for scams",
    description=(
        "Check every new email in your connected Gmail and Outlook for signs of phishing "
        "(forged or look-alike senders, links that hide where they go, risky attachments) on "
        "this computer, ask your AI provider about the ones that look wrong, and alert you on "
        "Telegram, Slack or the Security page. Nothing is moved without your approval."
    ),
    tools=(),
    default_enabled=True,
    risk="medium",
    when_denied=(
        "Automatic scam checks on new email are turned off. The owner can turn on 'Check new "
        "email for scams' in Settings → Permissions."
    ),
)
