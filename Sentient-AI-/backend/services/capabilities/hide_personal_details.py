"""Declares the "hide_personal_details" capability: the owner's switch for
swapping contact details for placeholders before a cloud AI provider sees them.

Why it exists: Gemini's free tier and other cloud providers may keep or learn
from what they are sent. With this on, email addresses, phone numbers, street
addresses and birth dates reach the provider as [[EMAIL_1@uni.edu]]-style
placeholders, and Crawler puts the real values back in its replies and in the
actions the owner approves (services/security/egress.py and pseudonyms.py).

A policy switch, not a channel or a toolkit: it claims no tools (tools=()), is
always available, and is read once per turn through the runtime's
``personal_details_hidden`` hook (main.py). It has no effect when the turn runs
on an Ollama on this computer. On by default (owner decision): the
placeholders are restored for the person, so the cost is only the occasional
task where a model mangles one. Keys, passwords, card, bank and ID numbers are
always hidden from every provider, whatever this switch says.
"""

from __future__ import annotations

from services.capabilities.base import Capability

CAPABILITY = Capability(
    key="hide_personal_details",
    label="Hide personal details from the AI provider",
    description=(
        "Before anything goes to a cloud AI provider, replace email addresses, phone "
        "numbers, street addresses and birth dates with placeholders. Crawler puts the "
        "real values back in its replies and in the actions you approve."
    ),
    tools=(),
    default_enabled=True,
    risk="low",
    when_denied=(
        "Personal details (emails, phone numbers, addresses) are sent to the AI provider "
        "as written. The owner can turn on Hide personal details from the AI provider in "
        "Settings → Permissions."
    ),
)
