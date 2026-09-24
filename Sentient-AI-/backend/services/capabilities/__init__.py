"""The capability registry. See README.md for how to add one."""

from __future__ import annotations

import sys
import time
from typing import Iterable, Mapping, Optional

from services.capabilities import (
    installs,
    reminders,
    screen,
    site_screenshots,
    telegram,
    web_browsing,
)
from services.capabilities.base import (
    Capability,
    CapabilityStatus,
    ProbeResult,
    ReportContext,
)
from services.capabilities.env import in_container, platform_name

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
ALWAYS_ON_TOOLS: frozenset[str] = frozenset({"system.capabilities"})

_BY_KEY: dict[str, Capability] = {c.key: c for c in REGISTRY}

_PROBE_TTL_S = 10.0
# Keyed by (capability, context), not capability alone: a probe reads the
# context (platform, executable), so an answer computed for one context
# must never be served for another. In a running process the context is
# effectively constant, so this stays a couple of entries per capability
# (the report's context, and the minimal one a tool builds at call time).
_probe_cache: dict[tuple[str, ReportContext], tuple[float, ProbeResult]] = {}


def get(key: str) -> Capability:
    return _BY_KEY[key]


def keys() -> tuple[str, ...]:
    return tuple(_BY_KEY)


def capability_for_tool(tool_name: str) -> Optional[Capability]:
    for cap in REGISTRY:
        if cap.claims(tool_name):
            return cap
    return None


def default_switches() -> dict[str, bool]:
    return {c.key: c.default_enabled for c in REGISTRY}


def default_context(*, telegram_configured: bool = False) -> ReportContext:
    from services.tools.system import browser_installed

    return ReportContext(
        in_container=in_container(),
        platform=platform_name(),
        telegram_configured=telegram_configured,
        browser_installed=browser_installed(),
        executable=sys.executable,
    )


def clear_probe_cache() -> None:
    _probe_cache.clear()


def _cached_probe(cap: Capability, ctx: ReportContext, use_cache: bool) -> ProbeResult:
    assert cap.probe is not None
    now = time.monotonic()
    cache_key = (cap.key, ctx)
    if use_cache:
        hit = _probe_cache.get(cache_key)
        if hit is not None and now - hit[0] < _PROBE_TTL_S:
            return hit[1]
    result = cap.probe(ctx)
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
    avail = cap.availability(ctx)
    probe = ProbeResult("not_required")
    if enabled and avail.available and cap.probe is not None:
        probe = _cached_probe(cap, ctx, use_cache)

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


def report(
    switches: Mapping[str, bool], ctx: ReportContext, *, use_cache: bool = True
) -> list[CapabilityStatus]:
    return [
        _status(cap, bool(switches.get(cap.key, cap.default_enabled)), ctx, use_cache)
        for cap in REGISTRY
    ]


def enabled_keys(switches: Mapping[str, bool], ctx: ReportContext) -> frozenset[str]:
    return frozenset(s.key for s in report(switches, ctx) if s.effective == "on")


def statuses_by_key(statuses: Iterable[CapabilityStatus]) -> dict[str, CapabilityStatus]:
    return {s.key: s for s in statuses}
