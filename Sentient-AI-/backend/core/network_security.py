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
    ipaddress.ip_network("::/128"),             # Unspecified — connect(2) to
                                                # this reaches loopback
    ipaddress.ip_network("::1/128"),            # Loopback
    ipaddress.ip_network("fc00::/7"),           # Unique local
    ipaddress.ip_network("fe80::/10"),          # Link-local
    ipaddress.ip_network("ff00::/8"),           # Multicast
    ipaddress.ip_network("::ffff:0:0/96"),      # IPv4-mapped IPv6
    # Transition mechanisms that tunnel an IPv4 address. Blocked wholesale
    # rather than unwrapped-and-allowed: nothing here needs to reach the
    # internet through one, and each is a spelling of an IPv4 address that
    # an IPv4-shaped blocklist does not recognise.
    ipaddress.ip_network("64:ff9b::/96"),       # NAT64
    ipaddress.ip_network("64:ff9b:1::/48"),     # NAT64 (local-use)
    ipaddress.ip_network("2002::/16"),          # 6to4
    ipaddress.ip_network("2001::/32"),          # Teredo
]

# Checked directly when unwrapping, since ipaddress has no `nat64` helper
# the way it has `sixtofour` and `teredo`.
_NAT64_PREFIX = ipaddress.ip_network("64:ff9b::/96")

_ALLOWED_SCHEMES = {"http", "https"}

_DEFAULT_PORTS = {"http": 80, "https": 443}


def default_port_for_scheme(scheme: str) -> int:
    """Port a URL of *scheme* connects to when none is spelled out.

    Callers that pin an address key their table by (host, port) and must
    derive the port the same way httpcore does, or the pin lookup misses
    and a legitimate request fails closed.
    """
    return _DEFAULT_PORTS.get(scheme, 443)


class SSRFBlocked(Exception):
    """Raised when a destination fails the public-only address policy.

    ``str(exc)`` is deliberately generic. Naming the offending address
    back to the caller turns a connector "test" button into a DNS /
    internal-network resolution oracle, so the detail goes to the log
    and only ``resolved_ip`` (already recorded server-side) is carried
    on the exception for internal use.
    """

    def __init__(self, reason: str, resolved_ip: Optional[str] = None) -> None:
        super().__init__(reason)
        self.reason = reason
        self.resolved_ip = resolved_ip


def _embedded_ipv4(
    ip: ipaddress.IPv6Address,
) -> Optional[ipaddress.IPv4Address]:
    """The IPv4 address *ip* carries, for the IPv6 forms that embed one.

    Each of these reaches the same host as the IPv4 address inside it, so
    each must be judged as that address — otherwise ``64:ff9b::7f00:1``
    and ``2002:7f00:1::`` are just spellings of 127.0.0.1 that walk past a
    blocklist written in IPv4 terms.
    """
    if ip.ipv4_mapped:
        return ip.ipv4_mapped
    if ip.sixtofour:  # 2002::/16
        return ip.sixtofour
    if ip.teredo:  # 2001::/32 — (server, client); the client is the host
        return ip.teredo[1]
    if ip in _NAT64_PREFIX:  # 64:ff9b::/96
        return ipaddress.IPv4Address(int(ip) & 0xFFFFFFFF)
    return None


def _blocked_network_for(
    ip: ipaddress.IPv4Address | ipaddress.IPv6Address,
) -> Optional[ipaddress.IPv4Network | ipaddress.IPv6Network]:
    """The blocked range *ip* falls inside, or ``None`` if it is public."""
    if isinstance(ip, ipaddress.IPv6Address):
        embedded = _embedded_ipv4(ip)
        if embedded is not None:
            # Judge the tunnelled address, but keep checking the outer one
            # too: the wrapper prefixes are themselves not routable.
            inner = _blocked_network_for(embedded)
            if inner is not None:
                return inner

    for network in _BLOCKED_NETWORKS:
        if ip in network:
            return network

    # Deny by default on routability. The list above states intent and
    # pins the well-known ranges, but enumerating every non-routable block
    # by hand is how `::`, NAT64 and 6to4 were missed — each of them
    # reaches loopback and each passed the list. Anything the stdlib does
    # not consider globally routable, or marks reserved (NAT64 lives
    # there), is refused.
    if not ip.is_global or ip.is_reserved:
        return ipaddress.ip_network(ip)
    return None


def resolve_public_addresses(
    hostname: str, port: int, *, url: Optional[str] = None
) -> tuple[str, ...]:
    """Resolve *hostname* once and return every address it maps to.

    Raises ``SSRFBlocked`` unless **all** of them are public. One private
    record among several is a DNS-rebinding vector, not a partial pass:
    the validator would happen to look at the public record while the
    connection lands on the private one. Refusing the whole name is the
    only answer that does not depend on which record gets picked.

    The returned tuple is what callers must connect to. Resolving again
    at connect time re-opens the TOCTOU window this function exists to
    close.
    """
    try:
        addrinfo = socket.getaddrinfo(hostname, port)
    except socket.gaierror as exc:
        raise SSRFBlocked(f"DNS resolution failed for '{hostname}'") from exc

    addresses: list[str] = []
    for *_, sockaddr in addrinfo:
        ip_str = str(sockaddr[0])
        try:
            ip = ipaddress.ip_address(ip_str)
        except ValueError:
            continue

        blocked = _blocked_network_for(ip)
        if blocked is not None:
            # Full detail (which hostname resolved to which internal IP in
            # which blocked CIDR) is server-log-only; see SSRFBlocked.
            logger.warning(
                "ssrf_blocked",
                url=url or hostname,
                hostname=hostname,
                resolved_ip=ip_str,
                blocked_network=str(blocked),
            )
            raise SSRFBlocked(
                "Destination is not permitted by the network security "
                "policy (resolves to a private or internal address).",
                resolved_ip=ip_str,
            )

        if ip_str not in addresses:
            addresses.append(ip_str)

    if not addresses:
        # getaddrinfo succeeded but produced nothing usable (e.g. only
        # AF_UNIX-ish or unparseable sockaddrs). Treat as unresolvable
        # rather than as an empty allowlist that silently passes.
        raise SSRFBlocked(f"DNS resolution failed for '{hostname}'")
    return tuple(addresses)


@dataclass
class NetworkPolicy:
    """Defines what endpoints a connector is allowed to reach."""
    connector_type: str
    allowed_hosts: list[str] = field(default_factory=list)
    allowed_paths: dict[str, list[str]] = field(default_factory=dict)
    # host -> list of allowed path prefixes
    instance_paths: list[str] = field(default_factory=list)
    # Path prefixes applied to a host the *user* configured (see the
    # ``extra_hosts`` argument of ``check_network_policy``). Empty means
    # the connector has no notion of a self-hosted instance, and a caller
    # passing extra hosts for it gets nothing.


# /api/v1/ is the Canvas REST surface; /login/oauth2/token is the OAuth
# code-exchange + refresh endpoint used by CanvasConnector. The
# interactive /login/oauth2/auth page is browser-side and stays blocked.
# Shared between the hosted (*.instructure.com) and self-hosted cases so
# a self-hosted instance is never reachable at paths the hosted one is
# not.
_CANVAS_PATHS = ["/api/v1/", "/login/oauth2/token"]

# Default network policies per connector (deny-by-default)
DEFAULT_POLICIES: dict[str, NetworkPolicy] = {
    "canvas": NetworkPolicy(
        connector_type="canvas",
        allowed_hosts=["*.instructure.com"],
        allowed_paths={"*.instructure.com": list(_CANVAS_PATHS)},
        instance_paths=list(_CANVAS_PATHS),
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
        # Robinhood's Crypto API lives at trading.robinhood.com under
        # /api/v1/crypto/. Only the read-only endpoints the connector
        # actually uses are allowlisted; trading/order endpoints
        # (e.g. /api/v1/crypto/trading/orders/) are deliberately NOT
        # listed — the financial hard block is enforced at the network
        # layer too.
        allowed_hosts=["trading.robinhood.com"],
        allowed_paths={
            "trading.robinhood.com": [
                "/api/v1/crypto/trading/accounts/",
                "/api/v1/crypto/trading/holdings/",
                "/api/v1/crypto/marketdata/",
            ],
        },
    ),
}


@dataclass
class SSRFCheckResult:
    """Result of an SSRF validation check."""
    safe: bool
    reason: Optional[str] = None
    resolved_ip: Optional[str] = None
    # Every address the hostname resolved to during *this* check, all of
    # which passed the policy. Callers that pin (see ``HttpMCPTransport``)
    # connect to exactly these instead of resolving a second time.
    resolved_ips: tuple[str, ...] = ()


def check_ssrf(url: str) -> SSRFCheckResult:
    """
    Validate a URL is safe from SSRF attacks.

    Resolves DNS and checks the resulting IPs against blocked ranges.
    Rejects private IPs, loopback, link-local, and IPv4-mapped IPv6.

    The resolution is returned in ``resolved_ips`` so the caller can
    connect to what was validated. A caller that ignores it and lets the
    HTTP stack resolve the hostname again is still rebindable.
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

    try:
        port = parsed.port or default_port_for_scheme(parsed.scheme)
    except ValueError:
        # urlparse only validates the port lazily, on attribute access.
        return SSRFCheckResult(safe=False, reason="Malformed URL")

    try:
        addresses = resolve_public_addresses(hostname, port, url=url)
    except SSRFBlocked as exc:
        return SSRFCheckResult(
            safe=False, reason=exc.reason, resolved_ip=exc.resolved_ip
        )

    return SSRFCheckResult(
        safe=True, resolved_ip=addresses[0], resolved_ips=addresses
    )


def normalize_policy_host(host: str) -> str:
    """Lowercased, punycode hostname for allowlist comparison.

    A host typed by the user ("MySchool.Instructure.com", an IDN, or a
    whole URL) has to reduce to exactly the form ``urlparse().hostname``
    produces, or an allowlist entry added for it never matches what the
    connector actually requests. Returns "" when nothing usable is left.
    """
    candidate = host.strip()
    if "://" in candidate:
        candidate = urlparse(candidate).hostname or ""
    candidate = candidate.strip().strip(".").lower()
    if not candidate:
        return ""
    try:
        return candidate.encode("idna").decode("ascii")
    except UnicodeError:
        # Not encodable as IDNA (over-long label, empty label, ...). It
        # cannot match a resolvable host either, so leave it as-is and let
        # the allowlist comparison fail.
        return candidate


def check_network_policy(
    url: str,
    connector_type: str,
    *,
    extra_hosts: tuple[str, ...] = (),
) -> SSRFCheckResult:
    """
    Check if a URL is allowed by the connector's network policy.

    Enforces deny-by-default: only explicitly allowlisted hosts and
    path prefixes are permitted.

    ``extra_hosts`` carries the hosts the *user* configured for this
    connector — a self-hosted Canvas domain, for instance, which no
    static allowlist can know. They are matched exactly (never as
    wildcards, so one configured host can never open a whole domain) and
    are held to the policy's ``instance_paths``, so a self-hosted
    instance is reachable at the same endpoints as the hosted one and no
    others. The SSRF check above still applies to them unchanged:
    a configured host that resolves into a private range is refused.
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
    allowed_paths: list[str] = []
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

    if matched_host is not None:
        allowed_paths = policy.allowed_paths.get(matched_host, [])
    elif policy.instance_paths:
        for configured in extra_hosts:
            if hostname and hostname == normalize_policy_host(configured):
                host_allowed = True
                allowed_paths = policy.instance_paths
                break

    if not host_allowed:
        return SSRFCheckResult(
            safe=False,
            reason=f"Host '{hostname}' not in allowlist for {connector_type}",
        )

    # Check path allowlist
    if allowed_paths:
        path_allowed = any(path.startswith(prefix) for prefix in allowed_paths)
        if not path_allowed:
            return SSRFCheckResult(
                safe=False,
                reason=f"Path '{path}' not in allowed paths for {hostname}",
            )

    return SSRFCheckResult(
        safe=True,
        resolved_ip=ssrf_result.resolved_ip,
        resolved_ips=ssrf_result.resolved_ips,
    )
