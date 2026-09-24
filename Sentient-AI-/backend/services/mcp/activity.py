"""Keeps an in-process record of the last success and last error per MCP connector
id.

Why it exists: Audit rows file every MCP call under one connector name, so the
health endpoint could not otherwise say which server failed; the catalog,
dispatcher and connection tests write here and GET /connectors/health reads it.

In-process activity record for MCP servers.

The runtime audit logger stores every MCP row under
``connector_name="mcp"`` (derived from the ``mcp.<label>.<tool>`` name),
so the connector health endpoint cannot attribute audit activity to a
specific MCP connector row. This registry closes that gap: discovery,
dispatch, and connection tests record their outcome per connector id,
and ``GET /connectors/health`` consults it for MCP rows.

In-process only by design (mirrors the executor's in-process rate
limiters): after a restart a server simply reports "no activity yet",
exactly like any other never-used connector.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional


@dataclass
class MCPActivity:
    """Latest observed activity for one MCP server connector."""

    last_success: Optional[datetime] = None
    last_error: Optional[datetime] = None
    last_error_message: Optional[str] = None


class MCPActivityRegistry:
    """Records last-successful-call / last-error per MCP connector id."""

    def __init__(self) -> None:
        self._entries: dict[uuid.UUID, MCPActivity] = {}

    def record_success(self, connector_id: uuid.UUID) -> None:
        entry = self._entries.setdefault(connector_id, MCPActivity())
        entry.last_success = datetime.now(timezone.utc)

    def record_error(self, connector_id: uuid.UUID, message: str) -> None:
        entry = self._entries.setdefault(connector_id, MCPActivity())
        entry.last_error = datetime.now(timezone.utc)
        entry.last_error_message = str(message)[:500]

    def get(self, connector_id: uuid.UUID) -> Optional[MCPActivity]:
        return self._entries.get(connector_id)

    def reset(self) -> None:
        """Clear all recorded activity (test hygiene)."""
        self._entries.clear()


# Process-wide singleton used by the MCP catalog/dispatcher and the
# connector routes.
mcp_activity = MCPActivityRegistry()
