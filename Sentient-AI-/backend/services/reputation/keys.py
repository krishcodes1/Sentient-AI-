"""The owner key registry: one row per outside security service a key can be
saved for (Google Safe Browsing, Google Web Risk, Have I Been Pwned,
VirusTotal), with the text the Service keys tab shows, the format a key must
have, and the check that proves a key works before it is stored.

Why it exists: three skills (link reputation, breach monitor, file
reputation) each need one owner key, and the owner should manage all of them
in one place with one set of routes (api/routes/security_keys.py) and one
encrypted column (InstallationService.service_key). Keeping every row here,
in one module the skills do not edit, means a skill only supplies its
tester. Each tester is imported lazily, on first use, so this module (and
the key routes) import without any skill's network client.

A tester takes the typed key and answers a ``KeyTestResult``: ``ok`` and one
plain sentence. It never quotes the key, never stores anything, and uses no
cache or limiter. Until a skill's module exists, its tester answers "<Service>
keys cannot be checked yet." (not ok), so no key can be saved before the
skill that uses it lands.
"""

from __future__ import annotations

import importlib
import re
from dataclasses import dataclass
from typing import Awaitable, Callable, Optional

from core.config import SERVICE_KEY_FIELDS


@dataclass(frozen=True)
class KeyTestResult:
    ok: bool
    # One plain sentence; never quotes the key.
    detail: str


KeyTester = Callable[[str], Awaitable[KeyTestResult]]


@dataclass(frozen=True)
class ServiceKeySpec:
    # "safe_browsing" | "web_risk" | "hibp" | "virustotal" (SERVICE_KEY_FIELDS).
    name: str
    label: str
    used_for: str
    note: str
    console_url: str
    key_hint: str
    key_pattern: re.Pattern[str]
    # The 422 answer for a key that does not match key_pattern; never echoes it.
    format_message: str
    # Lazy wrapper: imports the skill's tester on first call.
    tester: KeyTester


def _lazy_tester(
    module: str, function: str, *, leading: tuple[str, ...] = (), not_built: str
) -> KeyTester:
    """A tester that imports ``module.function`` when first called and runs
    it as ``function(*leading, key)``. While the skill's module does not exist
    yet (WAVE 0, or a checkout without that skill), it answers *not_built*
    and refuses: a missing tester must never let a key be stored. Only the
    module itself (or its own package) missing counts; an import error inside
    an existing module is a real failure and is raised."""

    async def tester(key: str) -> KeyTestResult:
        try:
            target = importlib.import_module(module)
        except ModuleNotFoundError as exc:
            missing = exc.name or ""
            if missing and (module == missing or module.startswith(missing + ".")):
                return KeyTestResult(False, not_built)
            raise
        result: KeyTestResult = await getattr(target, function)(*leading, key)
        return result

    return tester


# Google API keys start with AIza and are 39 characters long.
_GOOGLE_KEY = re.compile(r"^AIza[0-9A-Za-z_-]{35}$")
_GOOGLE_FORMAT = (
    "That does not look like a Google API key (they start with AIza and are 39 characters long)."
)
_GOOGLE_NOT_BUILT = "Google keys cannot be checked yet."

_SPECS: tuple[ServiceKeySpec, ...] = (
    ServiceKeySpec(
        name="safe_browsing",
        label="Google Safe Browsing",
        used_for=(
            "Checking links in mail alerts, scam checks, outgoing messages and pages the "
            "browser opens."
        ),
        note=(
            "Free for non-commercial use. If you use Crawler for a business, use Google Web "
            "Risk instead."
        ),
        console_url="https://console.cloud.google.com/apis/library/safebrowsing.googleapis.com",
        key_hint="Starts with AIza, 39 characters",
        key_pattern=_GOOGLE_KEY,
        format_message=_GOOGLE_FORMAT,
        tester=_lazy_tester(
            "services.reputation.links",
            "test_google_key",
            leading=("safe_browsing",),
            not_built=_GOOGLE_NOT_BUILT,
        ),
    ),
    ServiceKeySpec(
        name="web_risk",
        label="Google Web Risk",
        used_for="The same link checks, under Google's commercial terms.",
        note=(
            "Billed by Google past its free tier. When both Google keys are saved, Web Risk "
            "is used."
        ),
        console_url="https://console.cloud.google.com/apis/library/webrisk.googleapis.com",
        key_hint="Starts with AIza, 39 characters",
        key_pattern=_GOOGLE_KEY,
        format_message=_GOOGLE_FORMAT,
        tester=_lazy_tester(
            "services.reputation.links",
            "test_google_key",
            leading=("web_risk",),
            not_built=_GOOGLE_NOT_BUILT,
        ),
    ),
    ServiceKeySpec(
        name="hibp",
        label="Have I Been Pwned",
        used_for="Watching the owners' email addresses for new data breaches (Breach monitor).",
        note=(
            "Have I Been Pwned charges a monthly subscription for an API key. The password "
            "check works without one."
        ),
        console_url="https://haveibeenpwned.com/API/Key",
        key_hint="32 characters, 0-9 and a-f",
        key_pattern=re.compile(r"^[0-9A-Fa-f]{32}$"),
        format_message="A Have I Been Pwned key is 32 characters, 0-9 and a-f.",
        tester=_lazy_tester(
            "services.breach.hibp",
            "check_key",
            not_built="Have I Been Pwned keys cannot be checked yet.",
        ),
    ),
    ServiceKeySpec(
        name="virustotal",
        label="VirusTotal",
        used_for=(
            "Checking the fingerprint of files people send Crawler and of email attachments."
        ),
        note=(
            "Free public API: 4 lookups a minute, 500 a day, non-commercial use only. Files "
            "are uploaded only after you approve a card for each one."
        ),
        console_url="https://www.virustotal.com/gui/my-apikey",
        key_hint="64 hex characters",
        key_pattern=re.compile(r"^[0-9A-Fa-f]{64}$"),
        format_message="A VirusTotal key is 64 characters, 0-9 and a-f.",
        tester=_lazy_tester(
            "services.file_reputation.virustotal",
            "test_key",
            not_built="VirusTotal keys cannot be checked yet.",
        ),
    ),
)

# One row per SERVICE_KEY_FIELDS name, in that order (checked at import, so
# a service added to the config without a row fails at once).
if tuple(spec.name for spec in _SPECS) != tuple(SERVICE_KEY_FIELDS):
    raise RuntimeError("services/reputation/keys.py rows are out of step with SERVICE_KEY_FIELDS")

_BY_NAME: dict[str, ServiceKeySpec] = {spec.name: spec for spec in _SPECS}


def service_key_specs() -> tuple[ServiceKeySpec, ...]:
    """Every service a key can be saved for, in SERVICE_KEY_FIELDS order."""
    return _SPECS


def spec_for(name: str) -> Optional[ServiceKeySpec]:
    """The row for service *name*, or None for a name nobody registered."""
    return _BY_NAME.get(name)
