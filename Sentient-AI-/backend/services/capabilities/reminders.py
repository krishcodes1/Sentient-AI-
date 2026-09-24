"""Declares the "reminders" capability that gates the reminders.create, list and
cancel tools.

Why it exists: The registry lists it so the owner can switch reminders off in
one place; reminders.now stays always-on because the model uses it as its
clock.

Reminders: the reminders.* tools (create, list, cancel).

reminders.now is not gated by this capability: it is the model's clock
and is listed in ALWAYS_ON_TOOLS, which wins over the family prefix.
"""

from __future__ import annotations

from services.capabilities.base import Capability

CAPABILITY = Capability(
    key="reminders",
    label="Reminders",
    description="Set, list and cancel reminders that are delivered to you (Telegram when linked).",
    tools=("reminders.",),
    default_enabled=True,
    risk="low",
    when_denied="Reminders are turned off. The owner can turn them on in Settings → Permissions.",
)
