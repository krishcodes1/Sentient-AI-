"""Declares the "goals" capability: the user's goals with milestones and a
progress log, and the goals.* tools that read and change them.

Why it exists: a goal the user states in chat is saved, planned and checked on
over weeks through the goals.* tools, so the owner gets one switch for the
agent's side of it, on by default: the tools write only to the user's own
bounded store (services/goals/store.py), send nothing anywhere and schedule
nothing (a check-in is a scheduled task the user approves on its own card),
and deleting a goal is always a card. With it off no goals.* tool is offered,
so every request is byte-identical to one on an install without the feature,
apart from its <permissions> line. It is always available: it needs no
program, no OS permission and no channel.
"""

from __future__ import annotations

from services.capabilities.base import Availability, Capability, ReportContext


def availability(ctx: ReportContext) -> Availability:
    return Availability(True)


CAPABILITY = Capability(
    key="goals",
    label="Goals and plans",
    description=(
        "Let Crawler save the goals you tell it about with a plan of milestones, log your "
        "progress and check how each one is going. Goals stay in your account; deleting one "
        "always asks you first."
    ),
    tools=("goals.",),
    default_enabled=True,
    risk="low",
    when_denied="Goals are turned off. The owner can turn them on in Settings → Permissions.",
    availability=availability,
)
