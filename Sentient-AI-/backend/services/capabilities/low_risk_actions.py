"""Declares the "low_risk_actions" capability: the owner's install-wide switch
for letting chosen accounts make small, undoable changes without an approval
card.

Why it exists: permission tiers (top10) adds a per-connection tier, "Allow
low-risk changes", and 7-day low-risk grants offered on approval cards. This
switch gates both for every user of the install: while it is off no low-risk
tier run and no grant run happens, and no card offers a grant. It loosens
nothing by itself (an account still needs that tier or a grant), so it is on
by default (owner decision). The auto_approve tier does not depend on it.

A policy switch, not a toolkit: it claims no tools (tools=()), is always
available, and is read by the runtime (RuntimePermissionAdapter.low_risk_enabled)
and by the executor's backstop through the owner's capability report.
"""

from __future__ import annotations

from services.capabilities.base import Capability

KEY = "low_risk_actions"

CAPABILITY = Capability(
    key=KEY,
    label="Make low-risk changes without asking",
    description=(
        "Let the accounts you choose make small, undoable changes (starring, labels, "
        "drafts, private events and to-dos) without an approval card. Sends, deletes, "
        "sharing and anything other people see still ask."
    ),
    tools=(),
    default_enabled=True,
    risk="medium",
    when_denied=(
        "Low-risk changes without asking are turned off, so every change needs an "
        "approval card. The owner can turn this on in Settings → Permissions."
    ),
)
