"""App-event triggers: owner-approved rules of the form "when X happens in a
connected app, tell me, or run this task".

Why it exists: the pieces are split by what they may touch. ``sources`` knows
each source (which connector action it polls, its filters and intervals) and
turns a connector's answer into new items; ``facts`` shapes those items into
capped facts and builds every message the owner is sent, with no model;
``commands`` serves /triggers on Telegram and Slack. The sweeper lives in
services/notifications/event_triggers.py and the triggers.* tools in
services/tools/triggers.py.
"""

from __future__ import annotations

# The policy a triggers.* call refused before its card is filed under (the
# toolkit's precheck, or its async bind). Kept here, with no imports, so the
# runtime, the registry and the toolkit share one spelling.
TRIGGER_RULE_POLICY = "trigger_rule"
# The capability keys the feature is gated by.
CAPABILITY = "event_triggers"
RUNS_CAPABILITY = "trigger_runs"
