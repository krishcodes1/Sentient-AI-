"""Declares the "mcp_pinning" capability: the owner's switch for holding an MCP
tool whose definition changed, or that newly appeared on a server already in use,
until the owner reviews it.

Why it exists: MCP servers are third-party code and can change what a tool says
it does at any moment (a "rug pull"). With this on, Crawler remembers a
fingerprint of every tool's raw definition (services/mcp/pinning.py) and stops
offering or running a tool whose fingerprint changed until the owner approves
the new version on the Security page.

A policy switch: it claims no tools, is always available, and is read through
the ``enabled`` hook main.py hands to McpPinService (a read error counts as on).
On by default: the cost is a review now and then; the risk it closes is an
approved server quietly turning hostile.
"""

from __future__ import annotations

from services.capabilities.base import Capability

CAPABILITY = Capability(
    key="mcp_pinning",
    label="Hold changed MCP tools for review",
    description=(
        "Remember exactly what each tool from your MCP servers says it does. If a server "
        "later changes a tool's description or inputs, or adds a new tool, Crawler stops "
        "offering it to the AI until you review the change on the Security page."
    ),
    tools=(),
    default_enabled=True,
    risk="low",
    when_denied=(
        "MCP tool pinning is off: tools from MCP servers are offered even if the server "
        "changed what they say they do since they were added. The owner can turn on Hold "
        "changed MCP tools for review in Settings → Permissions."
    ),
)
