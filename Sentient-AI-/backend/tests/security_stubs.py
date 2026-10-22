"""Tells tests which security-wave modules are still WAVE 0 stubs: the list of
every stub module (``STUB_MODULES``), ``is_stub`` and the ``requires_real``
marker for a test that needs another skill's real code.

Why it exists: the ten security skills are built in parallel, each against
the WAVE 0 stubs of the others, so a test that needs another skill's real
behaviour cannot pass until that skill is integrated. ``requires_real``
skips such a test while a module it names still says ``SCAFFOLD_STUB =
True`` (or does not exist yet), and runs it once the module is real. After
integration the integrator sets ``INTEGRATED = True``: from then on a test
whose module is still a stub fails instead of skipping, so nothing is
skipped silently in the shipped tree (scaffold H1, H3, F76).

Integrator-only in WAVE 1 (no skill builder edits this file).

Connects to: every stub module of scaffold F67-F75 (the ``SCAFFOLD_STUB``
marker each carries), tests/test_security_scaffold.py.
Used by: the skills' cross-skill tests (``@requires_real("<module>")``).
"""

from __future__ import annotations

import importlib
from types import ModuleType
from typing import Optional, Sequence

import pytest

# Set to True by the integrator in the integration-fix session: a test that
# needs a module still marked as a stub then fails instead of skipping.
INTEGRATED: bool = True

# Every module WAVE 0 created as a stub for a skill (scaffold F24, F67-F75),
# by skill. A package's docstring-only __init__ is not a stub and is not
# listed. A builder removes the marker from its module when the real code
# lands; the list itself never shrinks, so after integration it still names
# every module that must have become real.
STUB_MODULES: tuple[str, ...] = (
    # S1 outbound message checks
    "services.security.outbound",
    "services.security.outbound_store",
    # S2 mail scam scan
    "services.security.mail_facts",
    "services.mail_scan.actions",
    "services.notifications.mail_scan",
    "services.connectors.google_api.mail_security",
    "services.connectors.microsoft_api.mail_security",
    # S3 on-demand scam check
    "services.scam_check.service",
    "services.scam_check.channels",
    "services.scam_check.web",
    # S4 link reputation
    "services.security.link_checks",
    "services.reputation.links",
    # S5 MCP tool pinning
    "services.mcp.pin_store",
    "services.mcp.pin_check",
    # S6 breach monitor
    "services.breach.hibp",
    "services.breach.store",
    "services.notifications.breach_monitor",
    # S7 browser site rules
    "services.site_rules.service",
    "services.site_rules.check",
    # S9 tool rules
    "services.security.tool_rules.store",
    "services.security.tool_rules.check",
    # S10 file reputation
    "services.file_reputation.service",
    "services.file_reputation.verdicts",
    "services.file_reputation.toolkit",
    "services.file_reputation.sweeper",
    "services.file_reputation.call_check",
    "services.file_reputation.virustotal",
    "services.connectors.google_api.attachment_hash",
    "services.connectors.microsoft_api.attachment_hash",
)


def _load(module: str) -> Optional[ModuleType]:
    """The module, or None when it (or its own package) does not exist yet.
    An import error inside a module that does exist is a real failure and is
    raised."""
    try:
        return importlib.import_module(module)
    except ModuleNotFoundError as exc:
        missing = exc.name or ""
        if missing and (module == missing or module.startswith(missing + ".")):
            return None
        raise


def is_stub(module: str) -> bool:
    """True while *module* is still a WAVE 0 stub: it carries
    ``SCAFFOLD_STUB = True``, or it does not exist yet."""
    loaded = _load(module)
    return loaded is None or getattr(loaded, "SCAFFOLD_STUB", False) is True


def still_stubs(modules: Sequence[str]) -> list[str]:
    """The ones of *modules* that are still stubs, in the order given."""
    return [module for module in modules if is_stub(module)]


def fail_stubs_after_integration(modules: Sequence[str]) -> bool:
    """Fails the test being set up: after integration no module a test needs
    may still be a stub. Reached through ``requires_real``'s skip condition,
    which pytest evaluates when the test is set up."""
    pytest.fail(
        "still a WAVE 0 stub after integration: " + ", ".join(modules),
        pytrace=False,
    )


def requires_real(*modules: str) -> pytest.MarkDecorator:
    """Mark a test that needs the real code of *modules* (another skill's).
    While any of them is still a stub: skipped before integration, failed
    once ``INTEGRATED`` is True. When all are real, the test runs as usual."""
    if not modules:
        raise ValueError("requires_real needs at least one module name")
    stubs = still_stubs(modules)
    if not stubs:
        return pytest.mark.skipif(False, reason="every module it needs is real")
    reason = "needs the real " + ", ".join(stubs) + " (still a WAVE 0 stub)"
    if not INTEGRATED:
        return pytest.mark.skipif(True, reason=reason)
    # A string condition is evaluated at setup; this one fails the test with
    # a plain message instead of skipping it.
    condition = (
        "__import__('tests.security_stubs', fromlist=['fail_stubs_after_integration'])"
        f".fail_stubs_after_integration({tuple(stubs)!r})"
    )
    return pytest.mark.skipif(condition, reason=reason)
