"""Telegram chat and approvals: a channel, not a toolkit, so it claims no
tools. Unavailable until a bot token is configured."""

from __future__ import annotations

from services.capabilities.base import Availability, Capability, ReportContext


def availability(ctx: ReportContext) -> Availability:
    if ctx.telegram_configured:
        return Availability(True)
    return Availability(False, "No Telegram bot token is configured yet. Add one in Settings → Telegram.")


CAPABILITY = Capability(
    key="telegram",
    label="Telegram chat and approvals",
    description="Chat with Crawler from Telegram and approve actions from your phone.",
    tools=(),
    default_enabled=True,
    risk="medium",
    when_denied="Telegram is turned off. The owner can turn it on in Settings → Permissions.",
    availability=availability,
)
