"""Declares the "page_watch" capability that gates the watch.create, list and
delete tools, available only while Telegram can deliver its alerts: a bot token
is configured and the owner's Telegram switch is on.

Why it exists: A watch is standing background egress (the sweeper fetches the
page on a schedule), so the owner gets one switch for it, off by default, and
the report shows it as unavailable while there is no Telegram to deliver the
alerts; the sweeper re-reads the same switch every sweep.

Page watch: "tell me on Telegram when this page changes".
"""

from __future__ import annotations

from services.capabilities.base import Availability, Capability, ReportContext


def availability(ctx: ReportContext) -> Availability:
    if not ctx.telegram_configured:
        return Availability(
            False,
            "Page change alerts go out over Telegram, and no Telegram bot token is "
            "configured yet. Add one in Settings → Telegram.",
        )
    if not ctx.telegram_enabled:
        return Availability(
            False,
            "Page change alerts go out over Telegram, which is turned off. Turn on "
            '"Telegram chat and approvals" in Settings → Permissions.',
        )
    return Availability(True)


CAPABILITY = Capability(
    key="page_watch",
    label="Watch web pages for changes",
    description=(
        "Check pages you name on a schedule (no more often than every 30 "
        "minutes) and message you on Telegram when their text changes."
    ),
    tools=("watch.",),
    default_enabled=False,
    risk="medium",
    when_denied="Page watching is turned off. The owner can turn it on in Settings → Permissions.",
    availability=availability,
)
