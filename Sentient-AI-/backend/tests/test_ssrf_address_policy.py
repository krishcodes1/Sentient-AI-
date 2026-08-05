"""Address-level SSRF policy.

The blocklist was written in IPv4 terms and enumerated IPv6 ranges by
hand, which let three spellings of "localhost" through: the unspecified
address ``::`` (connect(2) to it reaches loopback), NAT64
``64:ff9b::7f00:1``, and 6to4 ``2002:7f00:1::``. All three were driven to
a real socket before this was fixed.

Enumerating ranges by hand is what failed, so the policy is now
deny-by-default on routability, with the explicit list kept to state
intent and pin the well-known cases. These tests cover both halves: the
spellings that must never resolve to a reachable internal host, and the
ordinary public addresses that must keep working.
"""

from __future__ import annotations

import ipaddress

import pytest

from core.network_security import _blocked_network_for


def _blocked(address: str) -> bool:
    return _blocked_network_for(ipaddress.ip_address(address)) is not None


@pytest.mark.parametrize(
    "address",
    [
        "127.0.0.1",
        "10.0.0.1",
        "172.16.0.1",
        "192.168.1.1",
        "169.254.169.254",  # cloud instance metadata
        "0.0.0.0",
        "100.64.0.1",
        "255.255.255.255",
        "224.0.0.1",
    ],
)
def test_ipv4_private_and_reserved_are_blocked(address):
    assert _blocked(address)


@pytest.mark.parametrize(
    "address",
    [
        "::1",
        "fc00::1",
        "fd00::1",
        "fe80::1",
        "ff02::1",
    ],
)
def test_ipv6_private_and_reserved_are_blocked(address):
    assert _blocked(address)


@pytest.mark.parametrize(
    ("address", "why"),
    [
        ("::", "unspecified — connect(2) to it reaches loopback"),
        ("::ffff:127.0.0.1", "IPv4-mapped loopback"),
        ("::ffff:169.254.169.254", "IPv4-mapped metadata service"),
        ("64:ff9b::7f00:1", "NAT64-encoded 127.0.0.1"),
        ("64:ff9b::a00:1", "NAT64-encoded 10.0.0.1"),
        ("2002:7f00:0001::", "6to4-encoded 127.0.0.1"),
        ("2002:0a00:0001::", "6to4-encoded 10.0.0.1"),
        ("2002:a9fe:a9fe::", "6to4-encoded 169.254.169.254"),
        ("2001:0:1::", "Teredo"),
    ],
)
def test_ipv6_spellings_of_internal_addresses_are_blocked(address, why):
    assert _blocked(address), f"{address} reached the network ({why})"


@pytest.mark.parametrize(
    "address",
    [
        "8.8.8.8",
        "1.1.1.1",
        "93.184.216.34",
        "140.82.121.4",  # github
        "2606:4700:4700::1111",
        "2001:4860:4860::8888",
    ],
)
def test_ordinary_public_addresses_are_allowed(address):
    """Deny-by-default must not quietly break real destinations."""
    assert not _blocked(address)


def test_nat64_prefix_is_refused_even_when_it_wraps_a_public_address():
    """Nothing here needs to reach the internet through a translator, and
    allowing the prefix would mean trusting the wrapper to be honest about
    what it wraps."""
    assert _blocked("64:ff9b::8.8.8.8")


def test_blocked_reason_never_names_the_address_back_to_the_caller():
    """The exception message is an oracle if it echoes what resolved —
    a connector 'test' button would map the internal network."""
    from core.network_security import SSRFBlocked

    message = str(SSRFBlocked("blocked"))
    for leak in ("127.0.0.1", "10.0.0", "169.254", "::1"):
        assert leak not in message
