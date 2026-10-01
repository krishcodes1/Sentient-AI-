"""Declares the "event_triggers" capability that gates the triggers.* tools and
the trigger sweeper: "Tell me when something happens in my apps", available
only while Telegram or Slack can deliver the alerts.

Why it exists: a trigger reads a connected app on a schedule and messages the
owner for as long as it exists, so the owner gets one switch for it, off by
default. The sweeper re-reads the same switch before every check and every
message (a gate that cannot answer counts as off), and the report shows it
unavailable while there is no chat channel to deliver to. Running a task when
a trigger fires is a second switch, "trigger_runs".
"""

from __future__ import annotations

from services.capabilities.base import Availability, Capability, ReportContext


def availability(ctx: ReportContext) -> Availability:
    if ctx.telegram_enabled or ctx.slack_configured:
        return Availability(True)
    return Availability(
        False,
        "Trigger alerts go out over Telegram or Slack, and neither is set up. Connect one "
        "in Settings → Telegram or add the Slack connector.",
    )


CAPABILITY = Capability(
    key="event_triggers",
    label="Tell me when something happens in my apps",
    description=(
        "Check your connected apps on a schedule (new mail from people you name, Canvas "
        "posts and grades, meetings about to start, new files in a folder) and message "
        "you on Telegram or Slack."
    ),
    tools=("triggers.",),
    default_enabled=False,
    risk="medium",
    when_denied=(
        "App triggers are turned off. The owner can turn on 'Tell me when something "
        "happens in my apps' in Settings → Permissions."
    ),
    availability=availability,
)
