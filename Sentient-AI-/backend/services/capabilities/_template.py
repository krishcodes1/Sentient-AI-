"""Copy this file to services/capabilities/<key>.py, fill it in, and add
CAPABILITY to REGISTRY in __init__.py. Every field is explained here.
This file is NOT registered; the registry test checks that."""

from __future__ import annotations

from services.capabilities.base import Availability, Capability, ProbeResult, ReportContext


def availability(ctx: ReportContext) -> Availability:
    """Can this environment do it at all? Read ctx only — no OS calls here."""
    return Availability(True)


def probe(ctx: ReportContext) -> ProbeResult:
    """OS permission check (native installs only). Return "denied" with a
    fix_url and fix_steps when the user has to flip a switch themselves."""
    return ProbeResult("not_required")


def request_access() -> None:
    """Trigger the OS prompt and/or open the right settings pane."""


CAPABILITY = Capability(
    key="example",                      # snake_case, stable: used in storage and the API
    label="Example capability",         # shown in the wizard and Settings
    description="One sentence: what the agent can do when this is on.",
    tools=("example.read", "example."), # exact names or a family prefix ending in "."
    default_enabled=False,              # high-risk capabilities start off
    risk="medium",                      # low | medium | high — shown as a badge
    when_denied="Example is turned off. The owner can turn it on in Settings → Permissions.",
    availability=availability,
    probe=probe,                        # omit when nothing to check
    request_access=request_access,      # omit when nothing to request
    install=None,                       # or an ALLOWLIST key from services/tools/system.py
)
