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
