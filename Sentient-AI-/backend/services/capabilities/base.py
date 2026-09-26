"""Defines the frozen dataclasses a capability is declared with and the status
record a report produces.

Why it exists: Every capability module, the registry, the tool registry and the
capabilities route share these types; keeping them free of OS and database
access is what lets availability rules be tested without a display.

Capability declarations.

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
from types import MappingProxyType
from typing import Any, Callable, Literal, Mapping, Optional

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
    # For browser_control: the Playwright package (the bundled Chromium is
    # ``browser_installed``) and the installed browser the platform layer
    # would drive ("chrome" / "msedge"; "" when there is none).
    playwright_installed: bool = False
    browser_channel: str = ""
    # For computer_control: ``services.platform.current().name`` ("mac" |
    # "windows" | "linux" | "container"), which honours CRAWLER_PLATFORM
    # and the container marker. "" when not gathered; a rule that needs it
    # then derives it from ``platform`` and ``in_container``.
    host_platform: str = ""


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
    # Capabilities that must be on for this one to work (browser_act needs
    # browser_control). The report shows this one as blocked, with a plain
    # reason, while any of them is not on.
    requires: tuple[str, ...] = ()

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
    # The download the Install button would start ("~150-300 MB download"),
    # from the ALLOWLIST entry behind ``install``; None when there is none.
    install_size_hint: Optional[str] = None
    # The owner-editable settings this capability carries, defaults merged
    # with what is stored (``purchases``: the spending caps). Empty for a
    # capability that has none. Read-only: the report is shared.
    settings: Mapping[str, Any] = MappingProxyType({})

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
            "install_size_hint": self.install_size_hint,
            "when_denied": self.when_denied,
            "tools": list(self.tools),
            "settings": dict(self.settings),
        }
