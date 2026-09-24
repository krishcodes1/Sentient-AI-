"""Declares the "web_browsing" capability that gates the web.search and
web.fetch_page tools.

Why it exists: The registry lists it so the owner can switch public-web access
off in one place; the tool gates and the prompt read the switch by this key.

Browse the web: search the public web and read pages as text.
"""

from __future__ import annotations

from services.capabilities.base import Capability

CAPABILITY = Capability(
    key="web_browsing",
    label="Browse the web",
    description="Search the public web and read pages as text to answer questions and research tasks.",
    tools=("web.search", "web.fetch_page"),
    default_enabled=True,
    risk="low",
    when_denied="Web browsing is turned off. The owner can turn it on in Settings → Permissions.",
)
