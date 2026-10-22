"""Declares the "scam_check" capability: on-demand "is this a scam?" checks of a message, link,
screenshot or QR code the person asks about (/scam in Telegram, "scam ..." in a Slack DM, /scam in a
web chat, the Security page's Check for scams box, and the security.check_scam tool in a chat turn).

Why it exists: people get phishing texts and emails daily and ask whether to trust them. A pasted scam
often carries look-alike letters or hidden characters that PromptGuard blocks in a normal turn, so the
check runs outside the turn (services/scam_check) and fences the content as someone else's words.
The account's own AI provider reads it (the same one its chats use); links go to the link reputation
service (Google's list only with the owner's key). Low risk and on by default: it only reads and
answers, and the switch also gates the security.check_scam tool. Always available: the local checks
need nothing, and a missing key or a provider that cannot see pictures only narrows what is checked,
which every answer says.
"""

from __future__ import annotations

from typing import Any, Mapping

from services.capabilities.base import Capability

# Owner-editable (Settings → Permissions): out-of-turn checks one person may run per rolling 24 hours.
# Validated like every capability setting (whole numbers 1..10000, installation.py:390-400).
SCAM_CHECK_SETTINGS_DEFAULTS: Mapping[str, Any] = {"checks_per_day": 30}

CAPABILITY = Capability(
    key="scam_check",
    label="Check messages for scams when asked",
    description=(
        "When someone asks (/scam in Telegram, \"scam\" in Slack, the Security page or a chat), check a "
        "message, link, screenshot or QR code for signs of a scam: look-alike and known-bad links, "
        "hidden characters, pressure and payment tricks, and a look by your AI provider. Links go to "
        "Google Safe Browsing only when the owner added a key."
    ),
    tools=("security.check_scam",),
    default_enabled=True,
    risk="low",
    when_denied=(
        "Scam checks are turned off. The owner can turn on \"Check messages for scams when asked\" in "
        "Settings → Permissions."
    ),
)
