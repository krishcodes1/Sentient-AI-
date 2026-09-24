"""Declares the "installs" capability that gates the system.install_capability
tool.

Why it exists: The registry lists it so the owner can switch software installs
off entirely; when it is on, every install still passes through the approval
card.

Install optional software: lets the agent offer, and after approval run,
an install from the fixed ALLOWLIST in services/tools/system.py (such as
the hidden browser). Every install still goes through the approval card.
"""

from __future__ import annotations

from services.capabilities.base import Capability

CAPABILITY = Capability(
    key="installs",
    label="Install optional software (asks first)",
    description="Install optional components from a fixed list, such as the hidden browser, after asking you each time.",
    tools=("system.install_capability",),
    default_enabled=True,
    risk="medium",
    when_denied="Installing software is turned off. The owner can turn it on in Settings → Permissions.",
)
