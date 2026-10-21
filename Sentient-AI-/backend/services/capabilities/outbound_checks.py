"""Declares the "outbound_checks" capability: the owner's switch for checking what Crawler is about
to send (who it goes to, links that could carry data out) and noting it on the approval card.

Why it exists: an injected instruction's goal is usually to get Crawler to send something
somewhere (security S1). Every send already asks, but a card that only says "send_email requires
approval" is easy to rubber-stamp; this switch puts the facts on it (first time, outside your
organisation, look-alike address, the real reply recipients, data-carrying links) and gives a card
to a flagged call that would have run without one (a low-risk draft, an auto-approved post).

A policy switch, not a toolkit: it claims no tools (tools=()), is always available, and is read by
services/security/outbound.py once per checked call. It loosens nothing, so it is on by default
(owner decision, resolutions). Removing hidden characters (Unicode tag characters, bidi overrides,
long zero-width runs) is a floor in services/security that stays on whatever this switch says.
"""

from __future__ import annotations

from services.capabilities.base import Capability

KEY = "outbound_checks"

CAPABILITY = Capability(
    key=KEY,
    label="Check messages before they go out",
    description=(
        "Before Crawler sends an email, posts a message or comments, check who it goes to (first "
        "time, outside your organisation, look-alike addresses) and what it carries (links that "
        "could carry your data out), and show what was found on the approval card. Anything "
        "flagged that would have run without asking gets a card."
    ),
    tools=(),
    default_enabled=True,
    risk="low",
    when_denied=(
        "Outgoing messages are not checked for new or look-alike recipients or for data-carrying "
        "links (hidden characters are still removed). The owner can turn on Check messages before "
        "they go out in Settings → Permissions."
    ),
)
