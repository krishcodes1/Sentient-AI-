"""The capability registry. See README.md for how to add one."""

from __future__ import annotations

import dataclasses
import time
from typing import Any, Iterable, Mapping, Optional

import structlog

from services.capabilities import (
    browser_act,
    browser_control,
    computer_control,
    installs,
    page_watch,
    purchases,
    reminders,
    save_memories,
    screen,
    site_screenshots,
    slack,
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
from services.capabilities.env import crawler_executable, in_container, platform_name

# Each top10 skill adds its imports under its own anchor. isort is off
# here so they stay there and parallel branches merge cleanly.
# isort: off
# top10:secret_pii_redaction
from services.capabilities import hide_personal_details

# top10:file_extraction
from services.capabilities import file_reading

# top10:scheduler_briefing
from services.capabilities import scheduled_tasks

# top10:tutor_mode
from services.capabilities import tutor_mode

# top10:knowledge_base
from services.capabilities import knowledge_base, knowledge_semantic

# top10:flashcards_quizzes
from services.capabilities import study

# top10:event_triggers
from services.capabilities import event_triggers, trigger_runs

# top10:permission_tiers
from services.capabilities import low_risk_actions

# top10:voice_notes
from services.capabilities import voice_notes, voice_notes_cloud

# top10:video_transcripts
from services.capabilities import video_transcripts

# isort: on

logger = structlog.get_logger(__name__)

REGISTRY: tuple[Capability, ...] = (
    web_browsing.CAPABILITY,
    site_screenshots.CAPABILITY,
    screen.CAPABILITY,
    reminders.CAPABILITY,
    save_memories.CAPABILITY,
    installs.CAPABILITY,
    telegram.CAPABILITY,
    slack.CAPABILITY,
    browser_control.CAPABILITY,
    browser_act.CAPABILITY,
    computer_control.CAPABILITY,
    purchases.CAPABILITY,
    page_watch.CAPABILITY,
    # top10:secret_pii_redaction
    hide_personal_details.CAPABILITY,

    # top10:file_extraction
    file_reading.CAPABILITY,

    # top10:scheduler_briefing
    scheduled_tasks.CAPABILITY,

    # top10:tutor_mode
    tutor_mode.CAPABILITY,

    # top10:knowledge_base
    knowledge_base.CAPABILITY,
    knowledge_semantic.CAPABILITY,

    # top10:flashcards_quizzes
    study.CAPABILITY,

    # top10:event_triggers
    event_triggers.CAPABILITY,
    trigger_runs.CAPABILITY,

    # top10:permission_tiers
    low_risk_actions.CAPABILITY,

    # top10:voice_notes
    voice_notes.CAPABILITY,
    voice_notes_cloud.CAPABILITY,

    # top10:video_transcripts
    video_transcripts.CAPABILITY,

)

# Owner-editable settings a capability carries, by key, with their defaults
# (``InstallationService.capability_settings`` merges the stored values over
# them). A capability absent here has no settings: the Permissions page
# shows only its switch, and the settings route refuses it.
_SETTINGS_DEFAULTS: Mapping[str, Mapping[str, Any]] = {
    purchases.CAPABILITY.key: purchases.PURCHASE_SETTINGS_DEFAULTS,
    # top10:secret_pii_redaction

    # top10:file_extraction

    # top10:scheduler_briefing
    scheduled_tasks.CAPABILITY.key: scheduled_tasks.SCHEDULE_SETTINGS_DEFAULTS,

    # top10:tutor_mode

    # top10:knowledge_base
    knowledge_base.CAPABILITY.key: knowledge_base.KNOWLEDGE_SETTINGS_DEFAULTS,

    # top10:flashcards_quizzes

    # top10:event_triggers

    # top10:permission_tiers

    # top10:voice_notes

    # top10:video_transcripts
    video_transcripts.CAPABILITY.key: video_transcripts.VIDEO_SETTINGS_DEFAULTS,

}


def settings_defaults(key: str) -> dict[str, Any]:
    """The default settings of capability *key* ({} when it has none)."""
    return dict(_SETTINGS_DEFAULTS.get(key, {}))


# Tools no capability gates. Listed explicitly so that a new built-in tool
# nobody claimed fails the registry test instead of being silently always-on.
# An entry here wins over a capability's family prefix: reminders.now is the
# model's clock, which it needs whether or not Reminders is switched on.
# tools.find only searches tools the user can already use, so no switch
# gates it.
ALWAYS_ON_TOOLS: frozenset[str] = frozenset(
    {"system.capabilities", "reminders.now", "tools.find"}
)

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


def default_context(
    *,
    telegram_configured: bool = False,
    slack_configured: bool = False,
    telegram_enabled: bool = False,
    default_provider: str = "",
    embedding_backend: Optional[str] = None,
) -> ReportContext:
    """Gather the environment facts for one report. This is the only place
    that touches the OS for availability; availability() reads the result.
    *telegram_enabled* is the owner's Telegram switch; it counts only with a
    token configured. *default_provider* is the install's default AI
    provider, as the caller read it. *embedding_backend* defaults to the
    knowledge base's rule for that provider and KB_EMBEDDINGS
    (top10:knowledge_base)."""
    # Both deferred, like browser_installed: the registry stays importable
    # without the toolkit or the platform package.
    from services import platform as platform_layer
    from services.agent.providers import provider_hears_audio
    from services.tools.system import browser_installed, playwright_installed
    from services.tools.transcribe import local_engine_installed

    layer = platform_layer.current()
    return ReportContext(
        in_container=in_container(),
        platform=platform_name(),
        telegram_configured=telegram_configured,
        browser_installed=browser_installed(),
        executable=crawler_executable(),
        playwright_installed=playwright_installed(),
        browser_channel=layer.browser_channel() or "",
        host_platform=layer.name,
        slack_configured=slack_configured,
        telegram_enabled=telegram_configured and telegram_enabled,
        default_provider=default_provider,
        embedding_backend=(
            _embedding_backend(default_provider) if embedding_backend is None else embedding_backend
        ),
        # Voice notes (top10 voice_notes): the local engine on disk, and
        # whether the default provider hears audio.
        speech_local_installed=local_engine_installed(),
        default_provider_audio=provider_hears_audio(default_provider),
    )


def _embedding_backend(default_provider: str) -> str:
    """top10:knowledge_base: the meaning index's backend for this provider
    (services.knowledge.embeddings.backend_name), "" when unreadable."""
    try:
        from core.config import settings
        from services.knowledge.embeddings import backend_name

        return backend_name(default_provider, getattr(settings, "KB_EMBEDDINGS", None))
    except Exception as exc:  # a broken fact blocks the switch, never the report
        logger.warning("embedding_backend_unreadable", error_type=type(exc).__name__)
        return ""


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
        install_size_hint=_install_size_hint(cap.install),
    )


def _install_size_hint(install: Optional[str]) -> Optional[str]:
    """The download size of the ALLOWLIST entry behind *install*, if any."""
    if not install:
        return None
    # Deferred like browser_installed above: the registry stays importable
    # without the toolkit module.
    from services.tools.system import ALLOWLIST

    entry = ALLOWLIST.get(install)
    return entry.size_hint if entry is not None else None


def _enabled(cap: Capability, switches: Mapping[str, object]) -> bool:
    # Switches come from storage and the API. bool("false") is True, so only
    # a real True turns a capability on; a missing or null switch means the
    # default.
    value = switches.get(cap.key)
    return cap.default_enabled if value is None else (value is True)


def _required_reason(cap: Capability, statuses: Mapping[str, CapabilityStatus]) -> str:
    """Why *cap* cannot work while a capability it ``requires`` is not on,
    or "" when every one of them is on. A required key nobody registered
    counts as not on (fail closed)."""
    for key in cap.requires:
        needed = statuses.get(key)
        if needed is None:
            return "It needs a permission this install does not have."
        if needed.effective == "off":
            return f"Needs '{needed.label}' on in Permissions."
        if needed.effective == "blocked":
            return f"Needs '{needed.label}', which is blocked here: {needed.reason}"
    return ""


def report(
    switches: Mapping[str, object], ctx: ReportContext, *, use_cache: bool = True
) -> list[CapabilityStatus]:
    """One status per registered capability, in registry order.

    Effective state: ``off`` when the owner switch is off; otherwise
    ``blocked`` when the capability is unavailable here, its probe says
    ``denied``, or a capability it ``requires`` is not on (browser_act
    without browser_control: "Needs 'Control a browser' on in
    Permissions."); otherwise ``on`` (a probe answering ``unknown`` or
    ``not_required`` counts as on). An availability check or probe that
    raises reads as blocked. The probe runs only for a capability that is
    on and available, and its answer is cached for 10 s per context unless
    *use_cache* is False.
    """
    statuses = [_status(cap, _enabled(cap, switches), ctx, use_cache) for cap in REGISTRY]
    by_key = {s.key: s for s in statuses}
    for index, cap in enumerate(REGISTRY):
        status = statuses[index]
        if not cap.requires or status.effective != "on":
            continue
        reason = _required_reason(cap, by_key)
        if reason:
            statuses[index] = by_key[cap.key] = dataclasses.replace(
                status, effective="blocked", reason=reason
            )
    return statuses


def enabled_keys(switches: Mapping[str, object], ctx: ReportContext) -> frozenset[str]:
    """Keys whose effective state is ``on``: the set the offer
    (``build_tools``) filters by. The dispatch gates read the report by key
    instead (``InstallationService.capability_statuses``), so they can say
    off from blocked."""
    return frozenset(s.key for s in report(switches, ctx) if s.effective == "on")


def statuses_by_key(statuses: Iterable[CapabilityStatus]) -> dict[str, CapabilityStatus]:
    """Index a report by capability key."""
    return {s.key: s for s in statuses}
