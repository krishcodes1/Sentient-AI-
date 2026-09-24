"""Capability declarations.

A capability is the unit the owner switches on or off. One declaration
drives four things at once: the Permissions page and setup wizard, the
tool gates (offer and dispatch), the agent's own <permissions> block, and
`system.capabilities`. Keep this module free of OS and database access.

The two callables differ on purpose:

- ``availability(ctx)`` reads only the ReportContext it is given — never
  the OS. Environment facts are gathered once, in ``default_context()``,
  which is what makes every availability rule testable without a display.
- ``probe(ctx)`` may query the OS (e.g. the macOS Screen Recording
  preflight). It runs only when the capability is on and available, its
  answer is cached for 10 s per context, and one that raises reads as
  ``denied``.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Literal, Optional

ProbeState = Literal["granted", "denied", "not_required", "unknown"]
Effective = Literal["on", "off", "blocked"]
Risk = Literal["low", "medium", "high"]


@dataclass(frozen=True)
class ReportContext:
    """Facts about the running environment, gathered once per report by
    ``default_context()``.

    Also part of the probe-cache key, so every field must stay hashable.
    New fields need a default, so existing callers keep working.
    """

    in_container: bool
    platform: str
    telegram_configured: bool
    browser_installed: bool
    executable: str = ""


@dataclass(frozen=True)
class Availability:
    available: bool
    reason: str = ""


@dataclass(frozen=True)
class ProbeResult:
    state: ProbeState
    detail: str = ""
    fix_url: Optional[str] = None
    fix_steps: tuple[str, ...] = ()


def always_available(_ctx: ReportContext) -> Availability:
    return Availability(True)


@dataclass(frozen=True)
class Capability:
    key: str
    label: str
    description: str
    tools: tuple[str, ...]
    default_enabled: bool
    risk: Risk
    when_denied: str
    availability: Callable[[ReportContext], Availability] = always_available
    probe: Optional[Callable[[ReportContext], ProbeResult]] = None
    request_access: Optional[Callable[[], None]] = None
    install: Optional[str] = None

    def claims(self, tool_name: str) -> bool:
        """True when this capability gates *tool_name*. A pattern ending in
        "." matches a whole family ("reminders." → reminders.create …)."""
        for pattern in self.tools:
            if pattern.endswith("."):
                if tool_name.startswith(pattern):
                    return True
            elif tool_name == pattern:
                return True
        return False


@dataclass(frozen=True)
class CapabilityStatus:
    key: str
    label: str
    description: str
    risk: Risk
    enabled: bool
    default_enabled: bool
    available: bool
    availability_reason: str
    probe_state: ProbeState
    probe_detail: str
    fix_url: Optional[str]
    fix_steps: tuple[str, ...]
    effective: Effective
    reason: str
    can_request_access: bool
    install: Optional[str]
    when_denied: str
    tools: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "key": self.key,
            "label": self.label,
            "description": self.description,
            "risk": self.risk,
            "enabled": self.enabled,
            "default_enabled": self.default_enabled,
            "available": self.available,
            "availability_reason": self.availability_reason,
            "probe_state": self.probe_state,
            "probe_detail": self.probe_detail,
            "fix_url": self.fix_url,
            "fix_steps": list(self.fix_steps),
            "effective": self.effective,
            "reason": self.reason,
            "can_request_access": self.can_request_access,
            "install": self.install,
            "when_denied": self.when_denied,
            "tools": list(self.tools),
        }
