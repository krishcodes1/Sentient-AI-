"""Renders a capability report as the <permissions> block the runtime appends to
the system prompt.

Why it exists: The agent route builds this block from the owner's report each
turn so the model can say why a tool is off or blocked, and offer an install,
instead of guessing.

The <permissions> block the runtime appends to the system prompt so the
agent explains what is off instead of guessing or claiming it cannot.

The block is model-facing, but the model repeats what it reads, so it is
written the way the person should hear it: no em or en dashes (models
mirror their prompt's punctuation), and an install offer names the tool
the model must call while telling it to ask in plain words. Never "I can
run system.install_capability(name='browser')" in a reply: the person
sees "I need to add a web browser first. It's a one-time download of
about 150 to 300 MB. Okay?" (docs/bot-message-style.md).
"""

from __future__ import annotations

import re
from typing import Any, Iterable

from services.capabilities.base import CapabilityStatus

# The capability that gates system.install_capability. An install is only
# worth offering when that tool would actually be offered and run.
_INSTALLS_KEY = "installs"

# "~150-300 MB download" (the ALLOWLIST size hint) as "150 to 300 MB".
_SIZE_RANGE_RE = re.compile("(\\d)\\s*[-\u2013\u2014]\\s*(\\d)")
_SIZE_SUFFIX_RE = re.compile(r"\s*download\s*$", re.IGNORECASE)


def _plain_size(hint: Any) -> str:
    """An install's size hint in plain words ("about 150 to 300 MB"), or ""
    when there is none. Never raises."""
    if not isinstance(hint, str):
        return ""
    text = _SIZE_SUFFIX_RE.sub("", hint.strip().lstrip("~").strip())
    text = _SIZE_RANGE_RE.sub(r"\1 to \2", text).strip()
    return f"about {text}" if text else ""


def _install_offer(install: str, size_hint: Any) -> str:
    """The sentence after a blocked line whose fix is an install: which tool
    to call (the model needs the exact name and value) and how to ask the
    person (plain words, never the tool name or what is passed to it)."""
    size = _plain_size(size_hint)
    download = f", that it's a one-time download of {size}" if size else ""
    return (
        f" You may offer to install it: call system.install_capability with "
        f"name='{install}', and the person approves it first. Ask them in plain "
        f"words, saying what it adds{download} and whether to go ahead. Never show "
        "them the tool name or what you pass to it."
    )


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
            lines.append(f"- {s.label}: off. {s.when_denied}")
        else:
            extra = f" To fix: {s.fix_steps[0]}" if s.fix_steps else ""
            if s.install and installs_on:
                extra += _install_offer(s.install, getattr(s, "install_size_hint", None))
            lines.append(f"- {s.label}: blocked. {s.reason}{extra}")
    return "<permissions>\n" + "\n".join(lines) + "\n</permissions>"
