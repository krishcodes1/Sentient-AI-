"""The <permissions> block the runtime appends to the system prompt so the
agent explains what is off instead of guessing or claiming it cannot."""

from __future__ import annotations

from typing import Iterable

from services.capabilities.base import CapabilityStatus


def render_permissions_block(statuses: Iterable[CapabilityStatus]) -> str:
    lines: list[str] = []
    for s in statuses:
        if s.effective == "on":
            lines.append(f"- {s.label}: on")
        elif s.effective == "off":
            lines.append(f"- {s.label}: off — {s.when_denied}")
        else:
            extra = f" To fix: {s.fix_steps[0]}" if s.fix_steps else ""
            if s.install:
                extra += f" You may offer system.install_capability(name='{s.install}')."
            lines.append(f"- {s.label}: blocked — {s.reason}{extra}")
    return "<permissions>\n" + "\n".join(lines) + "\n</permissions>"
