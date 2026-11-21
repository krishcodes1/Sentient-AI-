"""Declares the "skills" capability that gates skills.read and the prompt's
list of each user's skills.

Why it exists: the registry lists it so the owner can turn every user's
skills off in one place. Low risk and on by default: a skill is the user's
own text from the Skills page, screened when saved, and reading one changes
nothing. Needs nothing from the environment: skills live in Crawler's own
database.
"""

from __future__ import annotations

from services.capabilities.base import Capability

CAPABILITY = Capability(
    key="skills",
    label="Use your skills",
    description=(
        "Follow the playbooks you write on the Skills page. Crawler sees each skill's name "
        "and description, and reads the full instructions when a task needs them."
    ),
    tools=("skills.",),
    default_enabled=True,
    risk="low",
    when_denied="Skills are turned off. You can turn them on in Settings → Permissions.",
)
