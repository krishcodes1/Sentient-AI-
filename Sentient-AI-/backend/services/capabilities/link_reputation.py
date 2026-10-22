"""Declares the "link_reputation" capability: the owner's switch for looking links up in Google's
list of dangerous sites (Safe Browsing or Web Risk) with the owner's own key, and the lookup limits
the owner can change.

Why it exists: a lookup sends a link to Google, so the owner decides, and nothing is sent until
they add a key (decisions 2). It is on by default but reads blocked until a Safe Browsing or Web
Risk key exists (ReportContext.service_keys), so adding the key is the only step. Local link checks
(services/security/link_checks.py) need no switch and always run. The lookup service
(services/reputation/links.py) reads this switch per call through the capability gate; the limits
reach it through InstallationService.capability_settings("link_reputation").
"""

from __future__ import annotations

from services.capabilities.base import Availability, Capability, ReportContext

# The key-store names a Google lookup can use (an HIBP or VirusTotal key
# alone does not unblock it).
GOOGLE_KEY_NAMES = frozenset({"safe_browsing", "web_risk"})

LINK_REPUTATION_SETTINGS_DEFAULTS = {
    "lookups_per_minute": 60,
    "lookups_per_day": 2000,
}


def availability(ctx: ReportContext) -> Availability:
    if not (ctx.service_keys & GOOGLE_KEY_NAMES):
        return Availability(
            False,
            "Add a Google Safe Browsing or Web Risk key in Security → Service keys.",
        )
    return Availability(True)


CAPABILITY = Capability(
    key="link_reputation",
    label="Check links with Google Safe Browsing",
    description=(
        "Look up links in your mail alerts, scam checks, outgoing messages and the pages the "
        "browser opens in Google's list of dangerous sites, using your own Google key. Only the "
        "link is sent (for the browser, only the site's address). Nothing is sent without a key."
    ),
    tools=(),
    default_enabled=True,
    risk="low",
    when_denied=(
        "Links are checked on this computer only (look-alike letters, bare IP addresses, link "
        "shorteners), not against Google's list of dangerous sites, so never describe a link as "
        "safe. The owner can turn on Check links with Google Safe Browsing in Settings → "
        "Permissions."
    ),
    availability=availability,
)
