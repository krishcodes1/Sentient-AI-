"""Builds the address resolver the breach monitor hands to the SSRF-guarded
client (``services.tools.net.build_guarded_client``) for its two fixed vendors,
Have I Been Pwned and Pwned Passwords.

Why it exists: the HIBP lookup URL carries the owner's email address in its
path, and the stock resolvers would put that URL into log lines and exception
text: ``net.validated_addresses`` logs ``web_tool_egress_blocked`` with the
URL, ``check_ssrf`` logs ``ssrf_blocked`` with the URL, and a policy refusal's
reason quotes the path ("Path '...' not in allowed paths"). This resolver
checks the full URL against the vendor's network policy without DNS and
without logging, then runs the SSRF check (DNS, every record public) on the
origin only (``https://host/``), so the only thing that can reach a log is
the vendor's host. Any refusal raises ``EgressBlocked`` with the caller's
fixed sentence, never the policy's reason.
"""

from __future__ import annotations

from typing import Callable
from urllib.parse import urlsplit

import core.network_security as netsec
from services.tools.net import EgressBlocked

AddressResolver = Callable[[str], tuple[str, ...]]


def _origin(url: str) -> str:
    """'https://host/' (with ':port' when one is given) for *url*; '' when it has no host."""
    parts = urlsplit(url)
    host = parts.hostname or ""
    if not host:
        return ""
    if ":" in host:  # an IPv6 literal keeps its brackets
        host = f"[{host}]"
    try:
        port = parts.port
    except ValueError:
        return ""
    return f"{parts.scheme}://{host}{f':{port}' if port else ''}/"


def policy_resolver(policy_key: str, refusal: str) -> AddressResolver:
    """A resolver for build_guarded_client (net.py). It runs
    check_network_policy(url, policy_key, resolve=False) on the full URL (host, path, https,
    no credentials; no DNS, no logging), then core.network_security.check_ssrf on the ORIGIN
    only ('https://host/'), looked up as a module global at call time so tests can replace it.
    Any refusal raises EgressBlocked(refusal), a fixed sentence. Why: the HIBP path holds the
    owner's address, and both the policy's reason ('Path ... not in allowed paths') and the
    ssrf_blocked log line (url=...) would otherwise carry it."""

    def resolve(url: str) -> tuple[str, ...]:
        decision = netsec.check_network_policy(url, policy_key, resolve=False)
        if not decision.safe:
            raise EgressBlocked(refusal)
        origin = _origin(url)
        if not origin:
            raise EgressBlocked(refusal)
        # Looked up on the module at call time: tests replace check_ssrf.
        result = netsec.check_ssrf(origin)
        if not result.safe or not result.resolved_ips:
            raise EgressBlocked(refusal)
        return tuple(result.resolved_ips)

    return resolve
