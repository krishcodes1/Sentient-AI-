"""Declares the "scheduled_tasks" capability that gates the schedule.* tools and
the schedule sweeper's prompt and briefing runs, and the owner-editable
budgets every unattended run shares.

Why it exists: a scheduled task runs a prompt with nobody watching, so the
owner gets one switch for it, off by default. It is always available: the
results always reach the web app, and Telegram and Slack are extra channels.
The sweeper re-reads the switch before it claims anything and again before
every run. The budgets (in cents, whole numbers from 1 to 10000, like every
capability setting) cap one run, one user's day of runs and how many runs a
day may hold; event triggers (wave 2) run under the same numbers.
"""

from __future__ import annotations

from services.capabilities.base import Availability, Capability, ReportContext

# Per run 5 cents, per user per day 25 cents, at most 24 runs a day.
SCHEDULE_SETTINGS_DEFAULTS = {"run_cap_cents": 5, "day_cap_cents": 25, "runs_per_day": 24}


def availability(ctx: ReportContext) -> Availability:
    return Availability(True)


CAPABILITY = Capability(
    key="scheduled_tasks",
    label="Scheduled tasks and daily briefing",
    description=(
        "Run prompts you approve on a schedule (like every weekday at 8am) and get a "
        "daily briefing of Canvas, calendar and mail on Telegram, Slack and in the web "
        "app. Scheduled runs only read, and ask you before changing anything."
    ),
    tools=("schedule.",),
    default_enabled=False,
    risk="medium",
    when_denied=(
        "Scheduled tasks are off. The owner can turn on 'Scheduled tasks and daily "
        "briefing' in Settings → Permissions."
    ),
    availability=availability,
)
