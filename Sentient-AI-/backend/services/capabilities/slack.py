"""Declares the "slack" capability: the owner's switch for the Slack DM chat and
approvals channel. A channel, not a toolkit, so it claims no tools.

Why it exists: the Slack DM channel (services/notifications/slack.py) runs on
the tokens of each user's Slack connector, and the owner needs one switch to
turn it off for the whole install, like Telegram's. The Slack workspace tools
(``slack.*``) stay governed by the connector's own policy, so this capability
must never claim ``slack.``.

Connects to the capability registry (services/capabilities/__init__.py) and
reads ``ReportContext.slack_configured`` (true while at least one Slack
channel is running). Talks to no external service.
"""

from __future__ import annotations

from services.capabilities.base import Availability, Capability, ReportContext


def availability(ctx: ReportContext) -> Availability:
    if ctx.slack_configured:
        return Availability(True)
    return Availability(
        False,
        "No Slack DM channel is running. Add an app-level token (xapp-) to a Slack "
        "connector in Connectors.",
    )


CAPABILITY = Capability(
    key="slack",
    label="Slack chat and approvals",
    description="Chat with Crawler in a Slack DM and approve actions from Slack.",
    tools=(),
    default_enabled=True,
    risk="medium",
    when_denied="Slack DMs are turned off. The owner can turn them on in Settings, Permissions.",
    availability=availability,
)
