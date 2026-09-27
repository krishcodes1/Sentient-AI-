"""Builds a connector instance from a stored connector type and its decrypted
credentials, and arms its network policy.

Why it exists: The tool executor, the MCP integration and the connector routes
must construct connectors the same way; one constructor means the deny-by-
default policy cannot be skipped by a new call site.

Connector instantiation from stored credentials.

Maps a ``ConnectorConfig.connector_type`` to its connector class, builds
the instance from decrypted credentials, and arms the deny-by-default
network policy before any request can be issued. This is the only place
connector classes are constructed for tool execution, so policy
enforcement cannot be skipped by a new call site.
"""

from __future__ import annotations

from typing import Any, Optional

from services.connectors import registry as _registry
from services.connectors.base import BaseConnector, ConnectorError


class CredentialError(ConnectorError):
    """Raised when stored credentials are missing required fields."""


# connector_type -> network policy key in core.network_security.DEFAULT_POLICIES.
# Derived from each connector's DEFINITION (services/connectors/registry.py).
NETWORK_POLICY_KEYS: dict[str, str] = _registry.network_policy_keys()


# MCP servers are dispatched by services.mcp, not built here, so their
# requirements are the one entry kept by hand.
_MCP_REQUIREMENTS: dict[str, Any] = {
    "required": ["url"],
    "optional": ["headers"],
    "notes": (
        "Streamable-HTTP MCP endpoint, e.g. https://example.com/mcp. "
        "Every MCP tool call requires your approval."
    ),
}

# Human-readable credential requirements per connector type. Used both for
# server-side validation and for the connector setup UI hints.
CREDENTIAL_REQUIREMENTS: dict[str, dict[str, Any]] = {
    **_registry.credential_requirements(),
    "mcp": _MCP_REQUIREMENTS,
}


def coerce_header_map(value: Any) -> Optional[dict[str, str]]:
    """``value`` as a ``{str: str}`` header map, or ``None`` if it is not one.

    Credentials are user-supplied JSON, so ``headers`` can be a string, a
    list, or a dict of nested objects. ``dict(value)`` on any of those
    raises deep inside the MCP loader, and that loader runs on every chat
    send — one malformed connector took down every turn for that user.
    Callers turn ``None`` into "this connector is misconfigured".
    """
    if value is None:
        return {}
    if not isinstance(value, dict):
        return None
    headers: dict[str, str] = {}
    for key, item in value.items():
        if not isinstance(key, str) or not isinstance(item, (str, int, float)):
            return None
        if isinstance(item, bool):
            return None
        headers[key] = str(item)
    return headers


def canvas_instance_host(base_url: str) -> str:
    """Hostname of a Canvas base URL, normalized for allowlist matching."""
    from core.network_security import normalize_policy_host

    return normalize_policy_host(base_url)


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
    definition = _registry.get_definition(connector_type)
    if definition is not None:
        problems.extend(definition.connector_class.validate_credentials(credentials))
    if connector_type == "mcp":
        url = str(credentials.get("url", ""))
        if url and not url.startswith(("http://", "https://")):
            problems.append("url must start with http:// or https://")
        if coerce_header_map(credentials.get("headers")) is None:
            problems.append("headers must be an object of header name -> value")
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

    definition = _registry.get_definition(connector_type)
    if definition is None:
        # 'mcp' passes validation but is dispatched by services.mcp.
        raise CredentialError(f"Unsupported connector type '{connector_type}'")
    connector = definition.connector_class.from_credentials(
        credentials, timeout_s=timeout_s
    )

    # Arm deny-by-default outbound filtering before any request is possible.
    # policy_extra_hosts carries a host the user configured (a self-hosted
    # Canvas); it is held to the policy's instance paths and the SSRF
    # address policy still applies to it.
    connector.set_network_policy(
        definition.network.policy_key, extra_hosts=connector.policy_extra_hosts
    )

    if rate_limit is not None:
        # The per-config limiter in the executor is authoritative; this just
        # keeps the connector's internal limiter consistent with it.
        connector._rate_limiter.max_calls = rate_limit

    return connector
