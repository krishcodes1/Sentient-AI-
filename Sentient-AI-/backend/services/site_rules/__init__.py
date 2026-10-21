"""Site rules for Crawler's own browser and its web reads (security S7): the
owner marks sites Blocked, Always ask or Trusted, and a built-in list of
sensitive sites (banks, brokers, crypto exchanges, tax and government
portals) is Always ask by default.

Why it exists: some sites should never be opened by an agent, and on money
and government sites every step deserves a second look. Site rules are
browser policy, not secret detection, so they live in their own package
rather than in services/security. Everything here is local: no network, no
model, no key.

Modules: ``patterns`` (what a typed site means, and which host a pattern
covers), ``sensitive_sites`` (the built-in list and the protected sign-in,
CAPTCHA and payment hosts), ``snapshot`` (the immutable rules view the
guard, the call check and observe read), ``messages`` (every sentence a
person or the model reads), ``store`` (the rows and their audit rows),
``service`` (the cached snapshot, its refresh and the recent hits),
``hooks`` (the guard hook and the web resolver wrapper) and ``check`` (the
pipeline check).

The four names below are re-exported lazily, so importing ``patterns`` or
``snapshot`` alone never imports the service, the database or the browser.

Connects to: services/tools/browser/guard.py (``EgressHooks.site_rules``),
services/tools/web.py (the wrapped resolver), services/security/
call_checks.py (slot 3), api/routes/security_site_rules.py, main.py.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from services.site_rules.patterns import KINDS
    from services.site_rules.service import SiteRulesService
    from services.site_rules.snapshot import SiteRuleSnapshot, SiteVerdict

__all__ = ["KINDS", "SiteRuleSnapshot", "SiteRulesService", "SiteVerdict"]

_EXPORTS = {
    "KINDS": "services.site_rules.patterns",
    "SiteRulesService": "services.site_rules.service",
    "SiteRuleSnapshot": "services.site_rules.snapshot",
    "SiteVerdict": "services.site_rules.snapshot",
}


def __getattr__(name: str) -> Any:
    module = _EXPORTS.get(name)
    if module is None:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    import importlib

    return getattr(importlib.import_module(module), name)
