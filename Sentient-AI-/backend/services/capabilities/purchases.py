"""Declares the "purchases" capability ("Buy things for me") behind
browser.checkout, with its availability rule and the spending caps the owner
can set.

Why it exists: Paying for something is the one thing a personal assistant must
never do on its own say-so, yet refusing it outright makes the assistant
useless for tickets and small orders. Declaring buying as an owner-enabled
capability, off by default and native only (the card vault needs the macOS
Keychain or Windows DPAPI), lets the registry, the Permissions page and the
tool gates explain a refusal instead of the model saying "not allowed".

Buy things for me: browser.checkout (FINANCIAL, one approval card per
purchase). The tool also needs browser_control on (the checkout page is
reached through browser.read / browser.act), which the tool registry's
``_REQUIRED_CAPABILITIES`` enforces.

Settings (owner-editable in Permissions, stored in
``installation.capability_settings``): ``per_purchase_cap_usd`` and
``per_day_cap_usd``, each a whole number of dollars from 1 to 10,000. The
checkout toolkit enforces both from the larger of the total read from the
page and the amount the model states; the per-day total is the sum, over
the last 24 hours, of every purchase audit row on which the card was sent
(``checkout.ledger``), never of a declined one.

Availability reads only the report context: a container has no OS key
store, and Linux has neither Keychain nor DPAPI in v1.
"""

from __future__ import annotations

from services.capabilities.base import Availability, Capability, ReportContext
from services.capabilities.computer_control import platform_of

# The owner's spending caps and their defaults (USD). The keys are the whole
# of what ``InstallationService.set_capability_settings`` accepts for this
# capability; a value must be a number above 0 and at most 10000.
PURCHASE_SETTINGS_DEFAULTS: dict[str, float] = {
    "per_purchase_cap_usd": 25,
    "per_day_cap_usd": 50,
}

CONTAINER_REASON = (
    "Not available in this environment (container). Buying needs the card vault, "
    "which works when Crawler runs directly on your Mac or PC."
)
PLATFORM_REASON = "Buying needs the card vault, which is available on macOS and Windows only."


def availability(ctx: ReportContext) -> Availability:
    """Native Mac or Windows only: the vault key lives in the Keychain or
    the Windows account (DPAPI), and neither exists in a container."""
    platform = platform_of(ctx)
    if ctx.in_container or platform == "container":
        return Availability(False, CONTAINER_REASON)
    if platform not in ("mac", "windows"):
        return Availability(False, PLATFORM_REASON)
    return Availability(True)


CAPABILITY = Capability(
    key="purchases",
    label="Buy things for me",
    description=(
        "Book tickets and make small purchases in Crawler's browser with the card "
        "you stored, within the spending caps you set; every purchase is approved "
        "by you first."
    ),
    tools=("browser.checkout",),
    default_enabled=False,
    risk="high",
    when_denied="Buying things is off. Turn on 'Buy things for me' in Permissions.",
    availability=availability,
)
