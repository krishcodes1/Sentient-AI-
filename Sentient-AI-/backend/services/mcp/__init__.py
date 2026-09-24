"""Model Context Protocol (MCP) integration.

Lets users register external MCP servers as connectors. Discovered tools
are offered to the agent under the ``mcp.<server>.<tool>`` namespace with
conservative defaults: every MCP tool requires explicit user approval,
and tools whose names look financial are never offered at all.
"""

from services.mcp.client import HttpMCPTransport, MCPClient, MCPError, MCPToolInfo
from services.mcp.integration import (
    MCPConnectorLoader,
    MCPDispatcher,
    MCPToolCatalog,
    classify_mcp_tool,
    invalidate_mcp_connector,
    is_financial_action,
    is_mcp_tool,
    slugify_label,
    split_mcp_tool,
)

__all__ = [
    "HttpMCPTransport",
    "MCPClient",
    "MCPConnectorLoader",
    "MCPDispatcher",
    "MCPError",
    "MCPToolCatalog",
    "MCPToolInfo",
    "classify_mcp_tool",
    "invalidate_mcp_connector",
    "is_financial_action",
    "is_mcp_tool",
    "slugify_label",
    "split_mcp_tool",
]
