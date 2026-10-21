"""Declares the "breach_monitor" capability: once a week, ask Have I Been Pwned
(with the owner's own key) whether the owners' sign-in addresses, and the
addresses they add, appear in a new data breach, and allow the password check
on the Security page.

Why it exists: the breach lookup sends an owner's email address to a third
party, so it gets one install-wide switch, and it is blocked until the owner
saves their own HIBP key (decisions.md item 2: nothing is sent without a key).
The sweeper re-reads the switch before every lookup (capability_gate, fail
closed). The keyless Pwned Passwords check reads only the switch's owner
setting, not this availability, so it keeps working without a key unless the
owner turns breach checks off.
"""

from __future__ import annotations

from services.capabilities.base import Availability, Capability, ReportContext

HIBP_SERVICE = "hibp"  # the name in the owner key store (services/reputation/keys.py)


def availability(ctx: ReportContext) -> Availability:
    if HIBP_SERVICE in ctx.service_keys:
        return Availability(True)
    return Availability(
        False,
        "Breach checks use your own Have I Been Pwned key, and none is saved yet. "
        "Add one in Security → Service keys.",
    )


CAPABILITY = Capability(
    key="breach_monitor",
    label="Watch my email addresses for data breaches",
    description=(
        "Once a week, ask Have I Been Pwned (with your own key) whether your sign-in "
        "address, and any addresses you add, appear in a new data breach, and tell you "
        "on Telegram, Slack and the Security page. Also allows the password check on "
        "the Security page, which never sends your password."
    ),
    tools=(),
    default_enabled=True,
    risk="low",
    when_denied=(
        "Breach monitoring is off. The owner can turn on 'Watch my email addresses for "
        "data breaches' in Settings → Permissions; it needs their own Have I Been "
        "Pwned key."
    ),
    availability=availability,
)
