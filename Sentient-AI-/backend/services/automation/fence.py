"""Decides which tools an unattended run may be given: which names count as a
read or a write at all (``classify_tool``), and the fenced tool list for one
run (``build_fence``).

Why it exists: a scheduled task or trigger runs with nobody watching, so the
tools it gets are cut down before the model sees them, and the runtime's own
fence (services/agent/unattended.py) refuses anything else that is named.
Some families are never given to an unattended run, whatever the owner
listed: acting on the computer or in a browser, installing software, saving
memories, watches, schedules and triggers (no self-replication), the tool
finder, skills, the tutor and third-party MCP tools. Every DELETE, EXECUTE
and FINANCIAL action is out too.
"""

from __future__ import annotations

import re
from typing import Any, Literal, Optional, Sequence

from services.agent.unattended import UnattendedRun

NEVER_TYPES: frozenset[str] = frozenset(
    {
        "desktop",
        "browser",
        "system",
        "memory",
        "watch",
        "schedule",
        "triggers",
        "tools",
        "skills",
        "learnings",
        "graph",
        "tutor",
        "mcp",
    }
)
NEVER_TOOLS: frozenset[str] = frozenset({"web.screenshot", "files.view_page", "files.forget"})
# Given to every unattended run: the model's clock.
ALWAYS_READS: frozenset[str] = frozenset({"reminders.now"})
FIND_TOOL = "tools.find"

# "<type>__<8 hex>.<action>": a tool of one of two accounts of a type.
_SLUGGED = re.compile(r"([a-z0-9_]+?)__([0-9a-f]{8})(\..+)")

ToolKind = Literal["read", "write"]


def canonical_name(name: str) -> str:
    """*name* without a per-account slug (``github__1a2b3c4d.list_issues`` is
    ``github.list_issues``)."""
    match = _SLUGGED.fullmatch(name)
    return f"{match.group(1)}{match.group(3)}" if match else name


def _slug_of(name: str) -> Optional[str]:
    match = _SLUGGED.fullmatch(name)
    return match.group(2) if match else None


def classify_tool(name: Any) -> Optional[ToolKind]:
    """'read' or 'write' for a tool an unattended run may be given, else
    None: unknown names, the families and tools above, and every DELETE,
    EXECUTE and FINANCIAL action."""
    if not isinstance(name, str) or "." not in name:
        return None
    canonical = canonical_name(name.strip())
    if canonical in NEVER_TOOLS or canonical.split(".", 1)[0] in NEVER_TYPES:
        return None
    # Deferred: the registry imports the runtime, which imports the fence's
    # contract (services.agent.unattended).
    from services.agent.permissions import ActionCategory
    from services.agent.tool_registry import resolve_tool

    resolved = resolve_tool(canonical)
    if resolved is None or resolved.connector_type in NEVER_TYPES:
        return None
    if resolved.spec.category == ActionCategory.READ:
        return "read"
    if resolved.spec.category == ActionCategory.WRITE:
        return "write"
    return None


def build_fence(tools: Sequence[Any], run: UnattendedRun) -> tuple[list[Any], list[str]]:
    """The tools one run is offered, and the listed ones that are missing.

    Keeps a tool only when its canonical name is one of the run's reads
    (plus ``ALWAYS_READS``) classified as a read, or one of its writes
    classified as a write; ``tools.find`` never. With ``run.connector_id``
    set, a tool of one of several accounts of a type (a slugged name) is
    kept only for that connector's row; a type with one account has
    unslugged names, and that one account is the connector's. ``missing``
    lists the run's reads and writes this turn could not offer (a service
    not connected, a capability off), for the "Not available this run" line.
    """
    from services.agent.tool_registry import connector_slug

    reads = run.reads | ALWAYS_READS
    wanted_slug = connector_slug(run.connector_id) if run.connector_id else None
    kept: list[Any] = []
    present: set[str] = set()
    for tool in tools:
        name = str(getattr(tool, "name", ""))
        canonical = canonical_name(name)
        if canonical == FIND_TOOL:
            continue
        kind = classify_tool(canonical)
        if kind == "read" and canonical not in reads:
            continue
        if kind == "write" and canonical not in run.writes:
            continue
        if kind is None:
            continue
        slug = _slug_of(name)
        if wanted_slug is not None and slug is not None and slug != wanted_slug:
            continue
        kept.append(tool)
        present.add(canonical)
    missing = sorted((run.reads | run.writes) - present)
    return kept, missing
