"""Declares the "file_reputation" capability: looking files up in VirusTotal by their SHA-256 with
the owner's own key (security.check_file and the automatic checks of uploads and email
attachments), and sending a file VirusTotal does not know after its own approval card
(security.upload_to_virustotal).

Why it exists: the owner decides once whether fingerprints of files people send Crawler may be
looked up at all. It is on by default but blocked until a VirusTotal key exists (the shared key
store, ReportContext.service_keys), so nothing leaves the machine before the owner adds a key. The
limits are whole numbers 1..10000 like every capability setting; the public key's limits are the
defaults, and an owner with a premium key can raise them.
"""

from __future__ import annotations

from services.capabilities.base import Availability, Capability, ReportContext

FILE_REPUTATION_SETTINGS_DEFAULTS = {
    "lookups_per_minute": 4,
    "lookups_per_day": 500,
    "automatic_lookups_per_day": 100,
    "lookups_per_user_per_day": 100,
}


def availability(ctx: ReportContext) -> Availability:
    if "virustotal" in ctx.service_keys:
        return Availability(True)
    return Availability(
        False, "Add a VirusTotal API key in Security → Service keys (the owner can do this)."
    )


CAPABILITY = Capability(
    key="file_reputation",
    label="Check files with VirusTotal",
    description=(
        "Look up the fingerprint (SHA-256) of files people send Crawler and of email attachments "
        "in VirusTotal, with your own key. Only the fingerprint is sent; a file is uploaded only "
        "after you approve a card for it."
    ),
    tools=("security.check_file", "security.upload_to_virustotal"),
    default_enabled=True,
    risk="medium",
    when_denied=(
        "Checking files with VirusTotal is turned off. The owner can turn it on in Settings → "
        "Permissions."
    ),
    availability=availability,
)
