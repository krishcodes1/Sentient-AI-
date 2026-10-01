"""Declares the "trigger_runs" capability: "Run a task when something happens
in my apps". It gates an argument, not a tool: triggers.create and
triggers.update may set mode "run_task" only while it is on.

Why it exists: a trigger that runs a task starts an agent turn nobody is
watching every time a connected app changes, so it needs its own switch, off
by default and high risk, on top of "event_triggers" (``requires``). The
toolkit refuses run_task before any card while it is off, and the sweeper
re-reads it before every run: while it is off a run_task trigger sends its
plain notice instead, saying task runs are off. Runs use the one unattended
runner and budget the scheduled tasks share.
"""

from __future__ import annotations

from services.capabilities.base import Capability

CAPABILITY = Capability(
    key="trigger_runs",
    label="Run a task when something happens in my apps",
    description=(
        "When a trigger fires, Crawler runs the task you wrote with read-only access to "
        "that app, within a daily limit; anything it wants to change waits for your "
        "approval."
    ),
    tools=(),
    default_enabled=False,
    risk="high",
    when_denied=(
        "Running tasks from triggers is off. The owner can turn on 'Run a task when "
        "something happens in my apps' in Settings → Permissions."
    ),
    requires=("event_triggers",),
)
