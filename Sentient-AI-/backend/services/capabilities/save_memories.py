"""Declares the "save_memories" capability that gates the memory.remember tool.

Why it exists: The registry lists it so the owner can stop the assistant from
proposing memories at all; when it is on, every memory still passes through
an approval card that shows its exact text.

Save memories (asks first): lets the agent save a durable fact the user
stated about themselves ("remember that I prefer morning meetings") to their
saved memories, tagged "proposed by assistant" on the Memory page.

On by default, medium risk. A memory is replayed into every future prompt as
trusted context, which is why it is not low: a wrong or poisoned one steers
every later turn. It is still on by default because nothing is saved without
the owner approving the exact text and category on the card, the tool can
only add (never read, edit or delete), the toolkit refuses injection-shaped
text, secrets and saves past the memory limit, and each user keeps a second
switch of their own (Memory page, "Use memory in conversations"); off by
default, "remember that ..." would simply fail for everyone.

Needs nothing from the environment: memories live in Crawler's own database.
"""

from __future__ import annotations

from services.capabilities.base import Capability

CAPABILITY = Capability(
    key="save_memories",
    label="Save memories (asks first)",
    description=(
        "Save facts you tell the assistant about yourself (a preference, your "
        "role, an ongoing project) to your memories, after you approve the exact text."
    ),
    tools=("memory.remember",),
    default_enabled=True,
    risk="medium",
    when_denied=(
        "Saving memories is turned off. The owner can turn it on in Settings → "
        "Permissions; you can still add a memory yourself on the Memory page."
    ),
)
