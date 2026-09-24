"""Annotated example of a capability module for contributors to copy; it is never
registered.

Why it exists: A new capability needs every field explained once, next to
working code; the registry test imports it to prove a copy was edited rather
than registered as-is.

Copy this file to services/capabilities/<key>.py, fill it in, and add
CAPABILITY to REGISTRY in __init__.py. Every field is explained here.
This file is NOT registered; the registry test checks that.
"""

from __future__ import annotations

from services.capabilities.base import Availability, Capability, ProbeResult, ReportContext


def availability(ctx: ReportContext) -> Availability:
    """Can this environment do it at all? Read ctx only — no OS calls here.
    Need a fact ctx does not have? Add it to ReportContext (see README.md)."""
    return Availability(True)


def probe(ctx: ReportContext) -> ProbeResult:
    """OS permission check (native installs only). May call the OS; the
    answer is cached for 10 s. Return "denied" with a fix_url and fix_steps
    when the user has to flip a switch themselves, "unknown" when the OS
    cannot be asked. Raising reads as "denied"."""
    return ProbeResult("not_required")


def request_access() -> None:
    """Trigger the OS prompt and/or open the right settings pane."""


CAPABILITY = Capability(
    key="example",                      # snake_case, stable: used in storage and the API
    label="Example capability",         # shown in the wizard and Settings; must be your own
    description="One sentence: what the agent can do when this is on.",
    tools=("example.read",),            # exact names, or a family prefix ending in "." ("example.")
    default_enabled=False,              # high-risk capabilities start off
    risk="medium",                      # low | medium | high — shown as a badge
    when_denied="Example is turned off. The owner can turn it on in Settings → Permissions.",
    availability=availability,
    # Wire these only when there is a real OS permission to check and a real
    # prompt or settings pane to open. A probe that can answer "denied" plus
    # a request_access that does nothing gives the owner a "Grant access"
    # button that does nothing.
    # probe=probe,
    # request_access=request_access,
    install=None,                       # or an ALLOWLIST key from services/tools/system.py
)
