"""Declares the "browser_site_rules" capability: the owner's switch for the
site rules Crawler's own browser and its web reads follow (Blocked, Always
ask, Trusted, and the built-in sensitive-sites list).

Why it exists: some sites should never be opened by an agent (the owner
says so), and on banks, brokers, crypto exchanges and tax portals every
step deserves a second look. A policy switch, not a toolkit: it claims no
tools, is always available, and is read per call by the site-rules call
check (services/site_rules/check.py), which refreshes the in-memory rules
the browser guard reads. On by default; a gate error counts as on.
"""

from __future__ import annotations

from services.capabilities.base import Capability

CAPABILITY = Capability(
    key="browser_site_rules",
    label="Site rules for Crawler's browser",
    description=(
        "Never open sites you block, and warn on every approval for banks, brokers, crypto "
        "exchanges, tax and government sites (or any site you mark Always ask). Manage the "
        "list on the Security page."
    ),
    tools=(),
    default_enabled=True,
    risk="low",
    when_denied=(
        "Site rules are off: Crawler's browser may open any public site and adds no warning "
        "on banking, crypto or government sites. The owner can turn on Site rules for "
        "Crawler's browser in Settings → Permissions."
    ),
)
