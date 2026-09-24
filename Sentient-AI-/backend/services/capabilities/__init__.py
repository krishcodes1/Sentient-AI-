"""The capability registry. See README.md for how to add one."""

from __future__ import annotations

import os
import sys
import time
from typing import Iterable, Mapping, Optional

import structlog

from services.capabilities import (
    installs,
    reminders,
    screen,
    site_screenshots,
    telegram,
    web_browsing,
)
from services.capabilities.base import (
    Availability,
    Capability,
    CapabilityStatus,
    ProbeResult,
    ReportContext,
)
from services.capabilities.env import in_container, platform_name

logger = structlog.get_logger(__name__)

REGISTRY: tuple[Capability, ...] = (
    web_browsing.CAPABILITY,
    site_screenshots.CAPABILITY,
    screen.CAPABILITY,
    reminders.CAPABILITY,
    installs.CAPABILITY,
    telegram.CAPABILITY,
)

# Tools no capability gates. Listed explicitly so that a new built-in tool
# nobody claimed fails the registry test instead of being silently always-on.
# An entry here wins over a capability's family prefix: reminders.now is the
# model's clock, which it needs whether or not Reminders is switched on.
ALWAYS_ON_TOOLS: frozenset[str] = frozenset({"system.capabilities", "reminders.now"})

_BY_KEY: dict[str, Capability] = {c.key: c for c in REGISTRY}

_PROBE_TTL_S = 10.0
# Keyed by (capability, context), not capability alone: a probe reads the
# context (platform, executable), and the context is not constant — a
# report built for one environment (a test, a different executable) must
# never be served for another. ReportContext is part of the key, so every
# field it gains must stay hashable. In a running process this stays a
# couple of entries per capability (the report's context, and the minimal
# one a tool builds at call time).
_probe_cache: dict[tuple[str, ReportContext], tuple[float, ProbeResult]] = {}

_UNCHECKED = ProbeResult("unknown", "Not checked while off or unavailable.")
_AVAILABILITY_FAILED = Availability(False, "Could not check whether this is available.")
_PROBE_FAILED = ProbeResult("denied", "The permission check failed.")


def get(key: str) -> Capability:
    """The capability registered under *key*. Raises KeyError if none is."""
    return _BY_KEY[key]


def keys() -> tuple[str, ...]:
    """Every registered capability key, in registry (display) order."""
    return tuple(_BY_KEY)


def capability_for_tool(tool_name: str) -> Optional[Capability]:
    """The capability that gates *tool_name*, or None when nothing does.

    A tool in ALWAYS_ON_TOOLS is never gated, even when a capability's
    family prefix would otherwise cover it.
    """
    if tool_name in ALWAYS_ON_TOOLS:
        return None
    for cap in REGISTRY:
        if cap.claims(tool_name):
            return cap
    return None


def default_switches() -> dict[str, bool]:
    """The owner switches a fresh install starts with."""
    return {c.key: c.default_enabled for c in REGISTRY}


def default_context(*, telegram_configured: bool = False) -> ReportContext:
    """Gather the environment facts for one report. This is the only place
    that touches the OS for availability; availability() reads the result."""
    from services.tools.system import browser_installed

    return ReportContext(
        in_container=in_container(),
        platform=platform_name(),
        telegram_configured=telegram_configured,
        browser_installed=browser_installed(),
        # macOS attaches permission grants to the real binary, not to the
        # venv symlink sys.executable usually is; name the one to toggle.
        executable=os.path.realpath(sys.executable),
    )


def clear_probe_cache() -> None:
    """Forget every cached probe answer (after a grant, and in tests)."""
    _probe_cache.clear()


def _availability(cap: Capability, ctx: ReportContext) -> Availability:
    try:
        return cap.availability(ctx)
    except Exception as exc:  # a broken check must block, never crash the report
        logger.warning("capability_availability_failed", capability=cap.key, error=str(exc))
        return _AVAILABILITY_FAILED


def _run_probe(cap: Capability, ctx: ReportContext) -> ProbeResult:
    assert cap.probe is not None
    try:
        return cap.probe(ctx)
    except Exception as exc:  # "unknown" would count as on; a failure must not
        logger.warning("capability_probe_failed", capability=cap.key, error=str(exc))
        return _PROBE_FAILED


def _cached_probe(cap: Capability, ctx: ReportContext, use_cache: bool) -> ProbeResult:
    now = time.monotonic()
    cache_key = (cap.key, ctx)
    if use_cache:
        hit = _probe_cache.get(cache_key)
        if hit is not None and now - hit[0] < _PROBE_TTL_S:
            return hit[1]
    result = _run_probe(cap, ctx)
    _probe_cache[cache_key] = (now, result)
    return result


def cached_probe(key: str, ctx: ReportContext) -> ProbeResult:
    """Run capability *key*'s probe through the shared TTL cache.

    For a tool re-checking its permission at call time. It does not check
    availability: a caller that could run somewhere the capability is
    unavailable must check ``availability(ctx)`` first. A capability with
    no probe answers ``not_required``.
    """
    cap = get(key)
    if cap.probe is None:
        return ProbeResult("not_required")
    return _cached_probe(cap, ctx, use_cache=True)


def _status(cap: Capability, enabled: bool, ctx: ReportContext, use_cache: bool) -> CapabilityStatus:
    avail = _availability(cap, ctx)
    if cap.probe is None:
        probe = ProbeResult("not_required")
    elif enabled and avail.available:
        probe = _cached_probe(cap, ctx, use_cache)
    else:
        # Not run: an off or unavailable capability has nothing to ask the
        # OS about, and a prompt-free preflight is still an OS call.
        probe = _UNCHECKED

    if not enabled:
        effective, reason = "off", "Turned off by the owner."
    elif not avail.available:
        effective, reason = "blocked", avail.reason
    elif probe.state == "denied":
        effective, reason = "blocked", probe.detail
    else:
        effective, reason = "on", ""

    return CapabilityStatus(
        key=cap.key,
        label=cap.label,
        description=cap.description,
        risk=cap.risk,
        enabled=enabled,
        default_enabled=cap.default_enabled,
        available=avail.available,
        availability_reason=avail.reason,
        probe_state=probe.state,
        probe_detail=probe.detail,
        fix_url=probe.fix_url,
        fix_steps=probe.fix_steps,
        effective=effective,  # type: ignore[arg-type]
        reason=reason,
        can_request_access=bool(cap.request_access) and avail.available and probe.state == "denied",
        install=cap.install,
        when_denied=cap.when_denied,
        tools=cap.tools,
    )


def _enabled(cap: Capability, switches: Mapping[str, object]) -> bool:
    # Switches come from storage and the API. bool("false") is True, so only
    # a real True turns a capability on; a missing or null switch means the
    # default.
    value = switches.get(cap.key)
    return cap.default_enabled if value is None else (value is True)


def report(
    switches: Mapping[str, object], ctx: ReportContext, *, use_cache: bool = True
) -> list[CapabilityStatus]:
    """One status per registered capability, in registry order.

    Effective state: ``off`` when the owner switch is off; otherwise
    ``blocked`` when the capability is unavailable here or its probe says
    ``denied``; otherwise ``on`` (a probe answering ``unknown`` or
    ``not_required`` counts as on). An availability check or probe that
    raises reads as blocked. The probe runs only for a capability that is
    on and available, and its answer is cached for 10 s per context unless
    *use_cache* is False.
    """
    return [_status(cap, _enabled(cap, switches), ctx, use_cache) for cap in REGISTRY]


def enabled_keys(switches: Mapping[str, object], ctx: ReportContext) -> frozenset[str]:
    """Keys whose effective state is ``on`` — the only set the tool gates use."""
    return frozenset(s.key for s in report(switches, ctx) if s.effective == "on")


def statuses_by_key(statuses: Iterable[CapabilityStatus]) -> dict[str, CapabilityStatus]:
    """Index a report by capability key."""
    return {s.key: s for s in statuses}
