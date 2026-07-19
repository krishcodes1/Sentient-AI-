"""Connector instantiation from stored credentials.

Maps a ``ConnectorConfig.connector_type`` to its connector class, builds
the instance from decrypted credentials, and arms the deny-by-default
network policy before any request can be issued. This is the only place
connector classes are constructed for tool execution, so policy
enforcement cannot be skipped by a new call site.
"""

from __future__ import annotations

from typing import Any, Optional

from services.connectors.base import BaseConnector, ConnectorError
from services.connectors.canvas import CanvasConnector
from services.connectors.google_workspace import GoogleWorkspaceConnector
from services.connectors.robinhood import RobinhoodConnector


class CredentialError(ConnectorError):
    """Raised when stored credentials are missing required fields."""


# connector_type (ConnectorType enum value) -> network policy key in
# core.network_security.DEFAULT_POLICIES.
NETWORK_POLICY_KEYS: dict[str, str] = {
    "canvas": "canvas",
    "google_workspace": "google",
    "robinhood": "robinhood",
}


# Human-readable credential requirements per connector type. Used both for
# server-side validation and for the connector setup UI hints.
CREDENTIAL_REQUIREMENTS: dict[str, dict[str, Any]] = {
    "canvas": {
        "required": ["base_url", "access_token"],
        "optional": ["client_id", "client_secret", "refresh_token"],
        "notes": "base_url is your school's Canvas instance, e.g. https://myschool.instructure.com",
    },
    "google_workspace": {
        "required": ["access_token"],
        "optional": ["refresh_token", "client_id", "client_secret"],
        "notes": "OAuth access token with the Gmail/Calendar scopes you intend to grant.",
    },
    "robinhood": {
        "required": ["api_key", "api_secret"],
        "optional": [],
        "notes": "Read-only API credentials. Trading is permanently blocked by the platform.",
    },
    "mcp": {
        "required": ["url"],
        "optional": ["headers"],
        "notes": (
            "Streamable-HTTP MCP endpoint, e.g. https://example.com/mcp. "
            "Every MCP tool call requires your approval."
        ),
    },
}


def validate_credentials(connector_type: str, credentials: dict[str, Any]) -> list[str]:
    """Return a list of human-readable problems (empty when valid)."""
    requirements = CREDENTIAL_REQUIREMENTS.get(connector_type)
    if requirements is None:
        return [f"Unsupported connector type '{connector_type}'"]
    problems = [
        f"Missing required credential field '{field_name}'"
        for field_name in requirements["required"]
        if not str(credentials.get(field_name, "")).strip()
    ]
    if connector_type == "canvas":
        base_url = str(credentials.get("base_url", ""))
        if base_url and not base_url.startswith(("http://", "https://")):
            problems.append("base_url must start with http:// or https://")
    if connector_type == "mcp":
        url = str(credentials.get("url", ""))
        if url and not url.startswith(("http://", "https://")):
            problems.append("url must start with http:// or https://")
    return problems


def create_connector(
    connector_type: str,
    credentials: dict[str, Any],
    *,
    rate_limit: Optional[int] = None,
    timeout_s: Optional[float] = None,
) -> BaseConnector:
    """Build a connector instance with the network policy armed.

    Raises ``CredentialError`` for unknown types or missing fields; the
    caller turns that into a structured tool error rather than a crash.
    """
    problems = validate_credentials(connector_type, credentials)
    if problems:
        raise CredentialError("; ".join(problems))

    connector: BaseConnector
    if connector_type == "canvas":
        connector = CanvasConnector(
            base_url=str(credentials["base_url"]),
            client_id=str(credentials.get("client_id", "")),
            client_secret=str(credentials.get("client_secret", "")),
            timeout_s=timeout_s,
        )
    elif connector_type == "google_workspace":
        connector = GoogleWorkspaceConnector(
            client_id=str(credentials.get("client_id", "")),
            client_secret=str(credentials.get("client_secret", "")),
            timeout_s=timeout_s,
        )
    elif connector_type == "robinhood":
        connector = RobinhoodConnector(timeout_s=timeout_s)
    else:
        raise CredentialError(f"Unsupported connector type '{connector_type}'")

    # Arm deny-by-default outbound filtering before any request is possible.
    connector.set_network_policy(NETWORK_POLICY_KEYS[connector_type])

    if rate_limit is not None:
        # The per-config limiter in the executor is authoritative; this just
        # keeps the connector's internal limiter consistent with it.
        connector._rate_limiter.max_calls = rate_limit

    return connector
