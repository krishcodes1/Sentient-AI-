"""Declares the "skills" capability: the bundled SKILL.md playbooks, the
skills.* tools that read them and the <available_skills> block that lists
them.

Why it exists: a skill teaches Crawler how to do a kind of task well (plan a
goal, triage an inbox, research widely) with its own tools, so the owner
gets one switch for the whole feature, on by default: the skills are text
the team reviewed and pinned by hash, they never run code, install anything,
grant a tool or change an approval, and every action a playbook leads to
still goes through the same permission checks and cards. With it off no
skills.* tool is offered and the system prompt has no <available_skills>
block, so the system message is byte-identical to one on an install without
the feature, apart from its <permissions> line (the offered-tool cap is 25
either way; spec §4.3). Each skill also has its own switch in Settings →
Skills (api/routes/skills.py). It is always available: it needs no program,
no OS permission and no channel.
"""

from __future__ import annotations

from services.capabilities.base import Availability, Capability, ReportContext


def availability(ctx: ReportContext) -> Availability:
    return Availability(True)


CAPABILITY = Capability(
    key="skills",
    label="Skills (built-in playbooks)",
    description=(
        "Let Crawler follow short built-in playbooks for tasks such as planning a goal, "
        "researching a topic or triaging email. Skills only guide Crawler's own tools: they "
        "never run code, install anything or skip an approval."
    ),
    tools=("skills.",),
    default_enabled=True,
    risk="low",
    when_denied="Skills are turned off. The owner can turn them on in Settings → Permissions.",
    availability=availability,
)
