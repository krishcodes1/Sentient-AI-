"""Tests for the shared fixtures of tests/file_reputation: they prove no file-reputation test can
resolve a name or open a socket.

Why it exists: the VirusTotal client runs every request through the real network policy
(``check_network_policy``), which ends in ``core.network_security.check_ssrf`` and a DNS lookup.
Replacing ``check_ssrf`` here (the pattern of tests/connectors/test_canvas_schools.py) keeps the
policy's host and path rules real while answering the address check with a documentation
address, and records every URL that reached it so a test can assert a request never got that
far. The answers themselves come from ``httpx.MockTransport`` (fakevt.FakeVirusTotal).
"""

from __future__ import annotations

from collections.abc import Iterator

import pytest

import core.network_security as netsec
from tests.file_reputation.fakevt import PUBLIC_IP


@pytest.fixture(autouse=True)
def ssrf_urls(monkeypatch) -> Iterator[list[str]]:
    """The URLs that reached the (stubbed) DNS and address check, in order."""
    urls: list[str] = []

    def fake_check_ssrf(url: str) -> netsec.SSRFCheckResult:
        urls.append(url)
        return netsec.SSRFCheckResult(safe=True, resolved_ip=PUBLIC_IP, resolved_ips=(PUBLIC_IP,))

    monkeypatch.setattr(netsec, "check_ssrf", fake_check_ssrf)
    yield urls
