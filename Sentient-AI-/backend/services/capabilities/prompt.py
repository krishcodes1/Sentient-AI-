"""Renders a capability report as the <permissions> block the runtime appends to
the system prompt.

Why it exists: The agent route builds this block from the owner's report each
turn so the model can say why a tool is off or blocked, and offer an install,
instead of guessing.

The <permissions> block the runtime appends to the system prompt so the
agent explains what is off instead of guessing or claiming it cannot.
"""

from __future__ import annotations

from typing import Iterable

from services.capabilities.base import CapabilityStatus

# The capability that gates system.install_capability. An install is only
# worth offering when that tool would actually be offered and run.
_INSTALLS_KEY = "installs"


def render_permissions_block(statuses: Iterable[CapabilityStatus]) -> str:
    """Render one line per capability: on, off (with what to tell the user)
    or blocked (with why, and how to fix it when there is a fix)."""
    statuses = list(statuses)
    installs_on = any(s.key == _INSTALLS_KEY and s.effective == "on" for s in statuses)
    lines: list[str] = []
    for s in statuses:
        if s.effective == "on":
            lines.append(f"- {s.label}: on")
        elif s.effective == "off":
            lines.append(f"- {s.label}: off — {s.when_denied}")
        else:
            extra = f" To fix: {s.fix_steps[0]}" if s.fix_steps else ""
            if s.install and installs_on:
                extra += f" You may offer system.install_capability(name='{s.install}')."
            lines.append(f"- {s.label}: blocked — {s.reason}{extra}")
    return "<permissions>\n" + "\n".join(lines) + "\n</permissions>"
