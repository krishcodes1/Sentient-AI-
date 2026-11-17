"""Declares the "calendar_errands" capability ("Do errands from my calendar
notes") and what reading the calendar for them may cost a day.

Why it exists: the owner's goal is that a note on their own calendar ("order
this perfume for my girlfriend", with a name and a link) becomes an errand
with no further work from them. Reading every note on their calendar and
asking the AI service about the ones that look like a purchase is its own
decision, so it gets its own switch, off by default, that needs "Do errands
for me in the background" (errand_runs) on: a planned errand only ever runs
through that switch.

A policy switch: it claims no tools (tools=()); the calendar finder
(services/errands/finder.py) reads it before every scan, and the errand
sweeper (services/automation/errands.py) starts no errand from the calendar
while it is off, even one planned before. Its one setting, ``day_cap_cents``,
caps what the AI reads of the calendar cost a day (a whole number of cents,
like every capability setting), across restarts.

Connects to: services/errands/finder.py (the reader), services/capabilities/
errand_runs.py (the switch it needs), services/capabilities/__init__.py.
"""

from __future__ import annotations

from services.capabilities.base import Capability

KEY = "calendar_errands"

CALENDAR_ERRANDS_SETTINGS_DEFAULTS = {"day_cap_cents": 10}

CAPABILITY = Capability(
    key=KEY,
    label="Do errands from my calendar notes",
    description=(
        "Each day Crawler reads your own calendar notes for the next six months. When one "
        "says to order or buy something (like \"order this perfume for Anna\"), it plans "
        "the order for a week before that day (you can change how early) and tells you. "
        "On a Mac it reads the Calendar app, which asks your permission the first time."
    ),
    tools=(),
    default_enabled=False,
    risk="medium",
    when_denied=(
        "Errands from calendar notes are off. The owner can turn on 'Do errands from my "
        "calendar notes' in Settings, under Permissions."
    ),
    requires=("errand_runs",),
)
