"""
Network security module inspired by NVIDIA NemoClaw.

Provides:
- SSRF protection: validates URLs against private/internal IP ranges
- Deny-by-default network policy: only allowlisted endpoints are reachable
- URL scheme enforcement: only http/https allowed
"""

from __future__ import annotations

import ipaddress
import socket
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import urlparse

import structlog

logger = structlog.get_logger(__name__)

# Private/reserved IP ranges that agents must never reach
_BLOCKED_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),        # RFC 1918
    ipaddress.ip_network("172.16.0.0/12"),      # RFC 1918
    ipaddress.ip_network("192.168.0.0/16"),     # RFC 1918
    ipaddress.ip_network("127.0.0.0/8"),        # Loopback
    ipaddress.ip_network("169.254.0.0/16"),     # Link-local
    ipaddress.ip_network("100.64.0.0/10"),      # CGN (Carrier-grade NAT)
    ipaddress.ip_network("0.0.0.0/8"),          # Current network
    ipaddress.ip_network("224.0.0.0/4"),        # Multicast
    ipaddress.ip_network("240.0.0.0/4"),        # Reserved
    ipaddress.ip_network("255.255.255.255/32"), # Broadcast
    # IPv6
    ipaddress.ip_network("::1/128"),            # Loopback
    ipaddress.ip_network("fc00::/7"),           # Unique local
    ipaddress.ip_network("fe80::/10"),          # Link-local
    ipaddress.ip_network("::ffff:0:0/96"),      # IPv4-mapped IPv6
]

_ALLOWED_SCHEMES = {"http", "https"}


@dataclass
class NetworkPolicy:
    """Defines what endpoints a connector is allowed to reach."""
    connector_type: str
    allowed_hosts: list[str] = field(default_factory=list)
    allowed_paths: dict[str, list[str]] = field(default_factory=dict)
    # host -> list of allowed path prefixes


# Default network policies per connector (deny-by-default)
DEFAULT_POLICIES: dict[str, NetworkPolicy] = {
    "canvas": NetworkPolicy(
        connector_type="canvas",
        allowed_hosts=["*.instructure.com"],
        allowed_paths={
            "*.instructure.com": ["/api/v1/"],
        },
    ),
    "google": NetworkPolicy(
        connector_type="google",
        allowed_hosts=[
            "www.googleapis.com",
            "gmail.googleapis.com",
            "oauth2.googleapis.com",
            "accounts.google.com",
        ],
        allowed_paths={
            "www.googleapis.com": ["/calendar/", "/gmail/"],
            "gmail.googleapis.com": ["/gmail/v1/"],
            "oauth2.googleapis.com": ["/token", "/tokeninfo"],
            "accounts.google.com": ["/o/oauth2/"],
        },
    ),
    "robinhood": NetworkPolicy(
        connector_type="robinhood",
        allowed_hosts=["api.robinhood.com"],
        allowed_paths={
            "api.robinhood.com": ["/api/crypto/"],
        },
    ),
}


@dataclass
class SSRFCheckResult:
    """Result of an SSRF validation check."""
    safe: bool
    reason: Optional[str] = None
    resolved_ip: Optional[str] = None


def check_ssrf(url: str) -> SSRFCheckResult:
    """
    Validate a URL is safe from SSRF attacks.

    Resolves DNS and checks the resulting IP against blocked ranges.
    Rejects private IPs, loopback, link-local, and IPv4-mapped IPv6.
    """
    try:
        parsed = urlparse(url)
    except Exception:
        return SSRFCheckResult(safe=False, reason="Malformed URL")

    # Scheme check
    if parsed.scheme not in _ALLOWED_SCHEMES:
        return SSRFCheckResult(
            safe=False,
            reason=f"Scheme '{parsed.scheme}' not allowed. Only http/https permitted.",
        )

    hostname = parsed.hostname
    if not hostname:
        return SSRFCheckResult(safe=False, reason="No hostname in URL")

    # DNS resolution
    try:
        addrinfo = socket.getaddrinfo(hostname, parsed.port or 443)
    except socket.gaierror:
        return SSRFCheckResult(safe=False, reason=f"DNS resolution failed for '{hostname}'")

    for family, _, _, _, sockaddr in addrinfo:
        ip_str = sockaddr[0]
        try:
            ip = ipaddress.ip_address(ip_str)
        except ValueError:
            continue

        # Handle IPv4-mapped IPv6 addresses (::ffff:192.168.1.1)
        if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
            ip = ip.ipv4_mapped

        for network in _BLOCKED_NETWORKS:
            if ip in network:
                logger.warning(
                    "ssrf_blocked",
                    url=url,
                    hostname=hostname,
                    resolved_ip=ip_str,
                    blocked_network=str(network),
                )
                return SSRFCheckResult(
                    safe=False,
                    reason=f"Resolved IP {ip_str} is in blocked range {network}",
                    resolved_ip=ip_str,
                )

    return SSRFCheckResult(safe=True, resolved_ip=addrinfo[0][4][0] if addrinfo else None)


def check_network_policy(url: str, connector_type: str) -> SSRFCheckResult:
    """
    Check if a URL is allowed by the connector's network policy.

    Enforces deny-by-default: only explicitly allowlisted hosts and
    path prefixes are permitted.
    """
    # First, run SSRF check
    ssrf_result = check_ssrf(url)
    if not ssrf_result.safe:
        return ssrf_result

    policy = DEFAULT_POLICIES.get(connector_type)
    if not policy:
        # Unknown connector type — deny by default
        return SSRFCheckResult(
            safe=False,
            reason=f"No network policy defined for connector '{connector_type}'",
        )

    parsed = urlparse(url)
    hostname = parsed.hostname or ""
    path = parsed.path or "/"

    # Check host allowlist (supports wildcard prefix matching)
    host_allowed = False
    matched_host = None
    for allowed_host in policy.allowed_hosts:
        if allowed_host.startswith("*."):
            suffix = allowed_host[1:]  # e.g., ".instructure.com"
            if hostname.endswith(suffix) or hostname == allowed_host[2:]:
                host_allowed = True
                matched_host = allowed_host
                break
        elif hostname == allowed_host:
            host_allowed = True
            matched_host = allowed_host
            break

    if not host_allowed:
        return SSRFCheckResult(
            safe=False,
            reason=f"Host '{hostname}' not in allowlist for {connector_type}",
        )

    # Check path allowlist
    allowed_paths = policy.allowed_paths.get(matched_host, [])
    if allowed_paths:
        path_allowed = any(path.startswith(prefix) for prefix in allowed_paths)
        if not path_allowed:
            return SSRFCheckResult(
                safe=False,
                reason=f"Path '{path}' not in allowed paths for {hostname}",
            )

    return SSRFCheckResult(safe=True, resolved_ip=ssrf_result.resolved_ip)
