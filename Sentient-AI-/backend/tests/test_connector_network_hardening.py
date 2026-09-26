"""Tests for the hardened connector network policy: fail closed without a
policy, HTTPS only, exact hosts before wildcards, the leftmost-label glob,
download-only redirect hosts, and the WebSocket policy.

Why it exists: the network policy is the last line between a model-chosen
request and the internet. These tests pin each rule at the policy function
and at the connector's request hook, so a later edit cannot quietly reopen
plain HTTP, a wildcard shadowing an exact host, or a credentialed request to
a pre-signed download host.
Connects to: core/network_security.py (check_network_policy,
check_websocket_policy, host_matches) and services/connectors/base.py
(_enforce_network_policy, _request). No real network or DNS: check_ssrf and
socket.getaddrinfo are replaced, and HTTP goes to an httpx.MockTransport.
"""

from __future__ import annotations

import socket
import threading
from typing import Any

import httpx
import pytest

import core.network_security as netsec
from core.network_security import (
    NetworkPolicy,
    check_network_policy,
    check_websocket_policy,
    host_matches,
    match_host_pattern,
)
from services.connectors.base import BaseConnector, ConnectorError

PUBLIC_IP = "93.184.216.34"
API = "https://api.acme.test"
BLOB = "https://results1.blob.acme-cdn.test"


def _acme_policy(**overrides: Any) -> NetworkPolicy:
    fields: dict[str, Any] = {
        "connector_type": "acme",
        "allowed_hosts": ["api.acme.test"],
        "allowed_paths": {"api.acme.test": ["/v1/"]},
        "https_only": True,
        "redirect_hosts": {"results*.blob.acme-cdn.test": ["/"]},
        "ws_hosts": ["wss-primary.acme.test"],
    }
    fields.update(overrides)
    return NetworkPolicy(**fields)


@pytest.fixture
def ssrf_calls(monkeypatch) -> list[tuple[str, str]]:
    """DNS-free SSRF check that records the URL and the calling thread."""
    calls: list[tuple[str, str]] = []

    def fake_check(url: str) -> netsec.SSRFCheckResult:
        calls.append((url, threading.current_thread().name))
        return netsec.SSRFCheckResult(
            safe=True, resolved_ip=PUBLIC_IP, resolved_ips=(PUBLIC_IP,)
        )

    monkeypatch.setattr(netsec, "check_ssrf", fake_check)
    return calls


@pytest.fixture
def acme(monkeypatch, ssrf_calls) -> NetworkPolicy:
    policy = _acme_policy()
    monkeypatch.setitem(netsec.DEFAULT_POLICIES, "acme", policy)
    return policy


class _Acme(BaseConnector):
    def __init__(self, *, extra_auth_header: str | None = None) -> None:
        super().__init__(timeout_s=5)
        self._extra = extra_auth_header

        async def _no_sleep(_seconds: float) -> None:
            return None

        self._sleep = _no_sleep

    @property
    def name(self) -> str:
        return "Acme"

    @property
    def connector_type(self) -> str:
        return "test"

    @property
    def required_scopes(self) -> list[str]:
        return []

    async def authenticate(self, credentials: dict[str, Any]) -> bool:
        self._authenticated = True
        return True

    def _auth_headers(self) -> dict[str, str]:
        if self._extra:
            return {self._extra: "key-test-value"}
        return {"Authorization": "Bearer acme-test-token"}

    async def _execute_action(self, action: str, params: dict[str, Any]) -> dict[str, Any]:
        return {}

    async def health_check(self) -> bool:
        return True


def _hooked(connector: BaseConnector, handler) -> None:
    """Mock transport that still runs the connector's policy hook."""
    connector._http_client = httpx.AsyncClient(
        transport=httpx.MockTransport(handler),
        event_hooks={"request": [connector._enforce_network_policy]},
        max_redirects=connector.MAX_REDIRECTS,
    )


def test_literal_default_policies_survive():
    for key in ("canvas", "google", "robinhood"):
        assert key in netsec.DEFAULT_POLICIES


# ---------------------------------------------------------------------------
# Fail closed, off the event loop, no DNS for off-list hosts
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_connector_without_a_policy_refuses_every_request(ssrf_calls):
    connector = _Acme()
    with pytest.raises(ConnectorError, match="no network policy is set for Acme"):
        await connector._enforce_network_policy(httpx.Request("GET", f"{API}/v1/x"))

    sent: list[httpx.Request] = []
    _hooked(connector, lambda request: sent.append(request) or httpx.Response(200))
    with pytest.raises(ConnectorError, match="no network policy"):
        await connector._request("GET", f"{API}/v1/x")
    assert sent == []
    assert ssrf_calls == []
    await connector.close()


@pytest.mark.asyncio
async def test_unknown_policy_key_is_refused(ssrf_calls):
    connector = _Acme()
    connector.set_network_policy("no-such-policy")
    with pytest.raises(ConnectorError, match="No network policy defined"):
        await connector._enforce_network_policy(httpx.Request("GET", f"{API}/v1/x"))


@pytest.mark.asyncio
async def test_policy_check_runs_in_a_worker_thread(acme, ssrf_calls):
    connector = _Acme()
    connector.set_network_policy("acme")

    await connector._enforce_network_policy(httpx.Request("GET", f"{API}/v1/x"))

    assert len(ssrf_calls) == 1
    assert ssrf_calls[0][1] != threading.main_thread().name


def test_off_list_host_is_refused_before_any_dns_lookup(acme, ssrf_calls):
    result = check_network_policy("https://evil.test/v1/x", "acme")
    assert result.safe is False
    assert "not in allowlist" in (result.reason or "")
    assert ssrf_calls == []


def test_host_with_no_path_list_allows_nothing(monkeypatch, ssrf_calls):
    monkeypatch.setitem(
        netsec.DEFAULT_POLICIES,
        "acme",
        _acme_policy(allowed_paths={}),
    )
    result = check_network_policy(f"{API}/anything", "acme")
    assert result.safe is False
    assert "not in allowed paths" in (result.reason or "")


def test_allowed_request_returns_the_validated_addresses(acme):
    result = check_network_policy(f"{API}/v1/things", "acme")
    assert result.safe is True
    assert result.resolved_ips == (PUBLIC_IP,)


def test_ssrf_failure_still_refuses_an_allowlisted_host(monkeypatch, acme):
    monkeypatch.setattr(
        netsec,
        "check_ssrf",
        lambda url: netsec.SSRFCheckResult(safe=False, reason="private address"),
    )
    assert check_network_policy(f"{API}/v1/x", "acme").safe is False


def test_resolve_false_skips_dns_but_keeps_every_policy_rule(monkeypatch, acme):
    """For an origin the caller already pinned: no lookup, no addresses,
    and the host, path and scheme rules still decide."""

    def no_dns(url: str) -> netsec.SSRFCheckResult:
        raise AssertionError("resolved a pinned origin")

    monkeypatch.setattr(netsec, "check_ssrf", no_dns)
    ok = check_network_policy(f"{API}/v1/things", "acme", resolve=False)
    assert ok.safe is True and ok.resolved_ips == ()
    assert check_network_policy(f"{API}/admin", "acme", resolve=False).safe is False
    assert check_network_policy("https://evil.test/v1/x", "acme", resolve=False).safe is False
    assert check_network_policy("http://api.acme.test/v1/x", "acme", resolve=False).safe is False


# ---------------------------------------------------------------------------
# HTTPS only
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("url", "reason"),
    [
        ("http://api.acme.test/v1/x", "HTTPS only"),
        ("https://api.acme.test:8443/v1/x", "Port 8443"),
        ("https://api.acme.test:80/v1/x", "Port 80"),
        ("https://user:pw@api.acme.test/v1/x", "Credentials in the URL"),
        ("https://api.acme.test:99999/v1/x", "Malformed URL"),
    ],
)
def test_https_only_refusals(acme, ssrf_calls, url, reason):
    result = check_network_policy(url, "acme")
    assert result.safe is False
    assert reason in (result.reason or "")
    assert ssrf_calls == []


def test_explicit_port_443_is_accepted(acme):
    assert check_network_policy("https://api.acme.test:443/v1/x", "acme").safe is True


@pytest.mark.asyncio
async def test_hook_refuses_plain_http(acme):
    connector = _Acme()
    connector.set_network_policy("acme")
    with pytest.raises(ConnectorError, match="HTTPS only"):
        await connector._enforce_network_policy(httpx.Request("GET", "http://api.acme.test/v1/x"))


def test_policy_without_https_only_keeps_http(monkeypatch, ssrf_calls):
    """Canvas stays unflagged (self-hosted instances may be plain http)."""
    assert netsec.DEFAULT_POLICIES["canvas"].https_only is False
    assert check_network_policy("http://school.instructure.com/api/v1/courses", "canvas").safe


# ---------------------------------------------------------------------------
# Dot segments (encoded path traversal)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "path",
    [
        "/v1/%2e%2e/admin",
        "/v1/%2E%2E/admin",
        "/v1/%2e%2E/admin",
        "/v1/.%2e/admin",
        "/v1/%2e/x",
        "/v1/..%2fadmin",
        "/v1/..%2Fadmin",
        "/v1/..%5cadmin",
        "/v1/%252e%252e/admin",
        "/v1/..;/admin",
        "/v1/%2e%2e;jsessionid=1/admin",
        "/v1/../admin",
        "/v1/./x",
        "/v1/x/..",
    ],
)
def test_dot_segments_are_refused_in_any_spelling(acme, ssrf_calls, path):
    result = check_network_policy(f"{API}{path}", "acme")
    assert result.safe is False
    assert "dot segment" in (result.reason or "")
    assert ssrf_calls == []


@pytest.mark.parametrize(
    "path",
    ["/v1/a..b/file.txt", "/v1/.well-known", "/v1/report%2520final", "/v1/%2e%2efoo", "/v1/.../x"],
)
def test_dotted_names_that_are_not_dot_segments_pass(acme, path):
    assert check_network_policy(f"{API}{path}", "acme").safe is True


def test_dot_segments_are_refused_for_a_policy_without_https_only(monkeypatch, ssrf_calls):
    monkeypatch.setitem(netsec.DEFAULT_POLICIES, "acme", _acme_policy(https_only=False))
    result = check_network_policy("http://api.acme.test/v1/%2e%2e/admin", "acme")
    assert result.safe is False
    assert "dot segment" in (result.reason or "")


def test_robinhood_read_prefix_cannot_climb_to_the_order_endpoints(ssrf_calls):
    base = "https://trading.robinhood.com/api/v1/crypto"
    escape = f"{base}/marketdata/%2e%2e/%2e%2e/trading/orders/"
    result = check_network_policy(escape, "robinhood")
    assert result.safe is False
    assert "dot segment" in (result.reason or "")
    assert check_network_policy(f"{base}/trading/orders/", "robinhood").safe is False
    assert check_network_policy(f"{base}/marketdata/best_bid_ask/", "robinhood").safe is True


@pytest.mark.asyncio
async def test_hook_refuses_an_encoded_dot_segment_before_sending(acme):
    connector = _Acme()
    connector.set_network_policy("acme")
    sent: list[httpx.Request] = []
    _hooked(connector, lambda request: sent.append(request) or httpx.Response(200))

    with pytest.raises(ConnectorError, match="dot segment"):
        await connector._request("GET", f"{API}/v1/%2e%2e/admin")
    assert sent == []
    await connector.close()


# ---------------------------------------------------------------------------
# Host matching: exact first, then the most specific wildcard
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "hosts",
    [["*.acme.test", "api.acme.test"], ["api.acme.test", "*.acme.test"]],
)
def test_exact_host_wins_over_wildcard_in_any_order(monkeypatch, ssrf_calls, hosts):
    monkeypatch.setitem(
        netsec.DEFAULT_POLICIES,
        "acme",
        _acme_policy(
            allowed_hosts=hosts,
            allowed_paths={"*.acme.test": ["/public/"], "api.acme.test": ["/v1/"]},
        ),
    )
    assert check_network_policy(f"{API}/v1/x", "acme").safe is True
    # The wildcard's broader paths do not apply to the exact host.
    assert check_network_policy(f"{API}/public/x", "acme").safe is False
    # Other subdomains still use the wildcard entry.
    assert check_network_policy("https://cdn.acme.test/public/x", "acme").safe is True


def test_narrower_wildcard_wins_over_broader_one():
    patterns = ["*.acme.test", "*.files.acme.test"]
    assert match_host_pattern("a.files.acme.test", patterns) == "*.files.acme.test"
    assert match_host_pattern("a.other.acme.test", patterns) == "*.acme.test"
    assert match_host_pattern("evil.test", patterns) is None


@pytest.mark.parametrize(
    ("host", "pattern", "expected"),
    [
        # Exact
        ("api.github.com", "api.github.com", True),
        ("API.GitHub.com", "api.github.com", True),
        ("api.github.com.evil.com", "api.github.com", False),
        # *.suffix: any depth plus the apex
        ("public.xx.files.1drv.com", "*.files.1drv.com", True),
        ("files.1drv.com", "*.files.1drv.com", True),
        ("evilfiles.1drv.com", "*.files.1drv.com", False),
        ("files.1drv.com.evil.com", "*.files.1drv.com", False),
        # Leftmost-label glob, star at the start of the label
        ("contoso-my.sharepoint.com", "*-my.sharepoint.com", True),
        ("contoso-my.sharepoint.com.", "*-my.sharepoint.com", True),
        ("a.contoso-my.sharepoint.com", "*-my.sharepoint.com", False),
        ("contoso-my.sharepoint.com.evil.com", "*-my.sharepoint.com", False),
        ("contoso-my.sharepoint.comevil.com", "*-my.sharepoint.com", False),
        ("evil.com-my.sharepoint.com", "*-my.sharepoint.com", False),
        ("contoso_x-my.sharepoint.com", "*-my.sharepoint.com", False),
        ("contoso-my.evil.com", "*-my.sharepoint.com", False),
        # Leftmost-label glob, star at the end of the label
        ("productionresultssa12.blob.core.windows.net", "productionresultssa*.blob.core.windows.net", True),
        ("productionresultssa.blob.core.windows.net", "productionresultssa*.blob.core.windows.net", True),
        ("xproductionresultssa1.blob.core.windows.net", "productionresultssa*.blob.core.windows.net", False),
        ("productionresultssa1.evil.blob.core.windows.net", "productionresultssa*.blob.core.windows.net", False),
        ("productionresultssa1.blob.core.windows.net.evil.com", "productionresultssa*.blob.core.windows.net", False),
        ("evil.com.blob.core.windows.net", "productionresultssa*.blob.core.windows.net", False),
        # Malformed patterns fail closed
        ("api.x.acme.test", "api.*.acme.test", False),
        ("anything", "*", False),
        ("ab", "a*b", False),
        ("a.acme.test", "", False),
        ("", "*.acme.test", False),
        # Regex metacharacters in a pattern are literal
        ("aab1.acme.test", "a+b*.acme.test", False),
    ],
)
def test_host_matches(host, pattern, expected):
    assert host_matches(host, pattern) is expected


# ---------------------------------------------------------------------------
# Redirect (download) hosts
# ---------------------------------------------------------------------------


def test_redirect_host_allowed_only_for_get_without_credentials(acme):
    url = f"{BLOB}/logs/1.txt?sig=abc"
    ok = check_network_policy(url, "acme", method="GET", has_authorization=False)
    assert ok.safe is True
    assert ok.resolved_ips == (PUBLIC_IP,)

    for method, authorized in (("POST", False), ("PUT", False), ("GET", True), (None, False), ("GET", None)):
        result = check_network_policy(url, "acme", method=method, has_authorization=authorized)
        assert result.safe is False, (method, authorized)
        assert "reachable only by GET without credentials" in (result.reason or "")


def test_redirect_host_is_still_https_only_and_glob_bound(acme):
    assert (
        check_network_policy(
            "http://results1.blob.acme-cdn.test/x", "acme", method="GET", has_authorization=False
        ).safe
        is False
    )
    assert (
        check_network_policy(
            "https://other.blob.acme-cdn.test/x", "acme", method="GET", has_authorization=False
        ).safe
        is False
    )


@pytest.mark.asyncio
async def test_hook_treats_the_connectors_own_auth_header_as_credentials(acme):
    connector = _Acme(extra_auth_header="X-Api-Key")
    connector.set_network_policy("acme")

    await connector._enforce_network_policy(httpx.Request("GET", f"{BLOB}/f"))
    with pytest.raises(ConnectorError, match="without credentials"):
        await connector._enforce_network_policy(
            httpx.Request("GET", f"{BLOB}/f", headers={"X-Api-Key": "key-test-value"})
        )
    with pytest.raises(ConnectorError, match="without credentials"):
        await connector._enforce_network_policy(
            httpx.Request("GET", f"{BLOB}/f", headers={"Authorization": "Bearer x"})
        )
    with pytest.raises(ConnectorError, match="without credentials"):
        await connector._enforce_network_policy(httpx.Request("POST", f"{BLOB}/f"))


def _redirecting(status: int, location: str):
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        if request.url.host == "api.acme.test":
            return httpx.Response(status, headers={"Location": location})
        return httpx.Response(200, content=b"log line")

    return handler, seen


@pytest.mark.asyncio
async def test_download_redirect_is_followed_without_authorization(acme):
    connector = _Acme()
    connector.set_network_policy("acme")
    handler, seen = _redirecting(302, f"{BLOB}/logs/1.txt?sig=abc")
    _hooked(connector, handler)

    response = await connector._request("GET", f"{API}/v1/logs", follow_redirects=True)

    assert response.content == b"log line"
    assert [r.url.host for r in seen] == ["api.acme.test", "results1.blob.acme-cdn.test"]
    assert seen[0].headers["Authorization"] == "Bearer acme-test-token"
    assert "authorization" not in seen[1].headers
    await connector.close()


@pytest.mark.asyncio
async def test_redirects_are_not_followed_unless_the_call_opts_in(acme):
    connector = _Acme()
    connector.set_network_policy("acme")
    handler, seen = _redirecting(302, f"{BLOB}/logs/1.txt")
    _hooked(connector, handler)

    with pytest.raises(ConnectorError, match="HTTP 302 from Acme"):
        await connector._request("GET", f"{API}/v1/logs")
    assert len(seen) == 1
    await connector.close()


@pytest.mark.asyncio
async def test_redirect_keeping_post_is_refused_at_the_download_host(acme):
    connector = _Acme()
    connector.set_network_policy("acme")
    handler, seen = _redirecting(307, f"{BLOB}/upload")
    _hooked(connector, handler)

    with pytest.raises(ConnectorError, match="without credentials"):
        await connector._request("POST", f"{API}/v1/logs", json={}, follow_redirects=True)
    assert len(seen) == 1
    await connector.close()


@pytest.mark.asyncio
async def test_same_host_redirect_carrying_a_custom_key_is_refused_at_download_host(acme):
    """httpx strips Authorization cross-origin but keeps other headers, so
    a connector's custom key header must still close the download host."""
    connector = _Acme(extra_auth_header="X-Api-Key")
    connector.set_network_policy("acme")
    handler, seen = _redirecting(302, f"{BLOB}/logs/1.txt")
    _hooked(connector, handler)

    with pytest.raises(ConnectorError, match="without credentials"):
        await connector._request("GET", f"{API}/v1/logs", follow_redirects=True)
    assert len(seen) == 1
    await connector.close()


class _GitHubStyle(_Acme):
    """Version headers in _static_headers(), the token in _auth_headers()."""

    def _static_headers(self) -> dict[str, str]:
        return {
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "Notion-Version": "2022-06-28",
        }


class _MisplacedAccept(_Acme):
    """A connector that put a generic header next to its token."""

    def _auth_headers(self) -> dict[str, str]:
        return {"Authorization": "Bearer acme-test-token", "Accept": "application/json"}


@pytest.mark.asyncio
@pytest.mark.parametrize("connector_class", [_GitHubStyle, _MisplacedAccept])
async def test_logs_redirect_is_followed_with_version_headers(acme, connector_class):
    connector = connector_class()
    connector.set_network_policy("acme")
    handler, seen = _redirecting(302, f"{BLOB}/logs/1.txt?sig=abc")
    _hooked(connector, handler)

    response = await connector._request("GET", f"{API}/v1/logs", follow_redirects=True)

    assert response.content == b"log line"
    assert [r.url.host for r in seen] == ["api.acme.test", "results1.blob.acme-cdn.test"]
    assert seen[0].headers["Authorization"] == "Bearer acme-test-token"
    assert "authorization" not in seen[1].headers
    await connector.close()


@pytest.mark.asyncio
@pytest.mark.parametrize("connector_class", [_GitHubStyle, _MisplacedAccept])
async def test_unauthorized_download_works_with_version_headers(acme, connector_class):
    connector = connector_class()
    connector.set_network_policy("acme")
    handler, seen = _redirecting(302, "unused")
    _hooked(connector, handler)

    response = await connector._request("GET", f"{BLOB}/logs/1.txt?sig=abc", authorized=False)

    assert response.content == b"log line"
    assert len(seen) == 1
    assert "authorization" not in seen[0].headers
    if connector_class is _GitHubStyle:
        assert seen[0].headers["x-github-api-version"] == "2022-11-28"
    await connector.close()


@pytest.mark.asyncio
async def test_static_headers_never_open_the_download_host_to_a_credential(acme):
    connector = _GitHubStyle()
    connector.set_network_policy("acme")
    handler, seen = _redirecting(302, "unused")
    _hooked(connector, handler)

    # authorized=True on the download host still carries the token: refused.
    with pytest.raises(ConnectorError, match="without credentials"):
        await connector._request("GET", f"{BLOB}/logs/1.txt")
    assert seen == []
    await connector.close()


@pytest.mark.asyncio
async def test_redirect_to_an_off_list_host_is_refused(acme):
    connector = _Acme()
    connector.set_network_policy("acme")
    handler, seen = _redirecting(302, "https://evil.test/steal")
    _hooked(connector, handler)

    with pytest.raises(ConnectorError, match="not in allowlist"):
        await connector._request("GET", f"{API}/v1/logs", follow_redirects=True)
    assert len(seen) == 1
    await connector.close()


@pytest.mark.asyncio
async def test_redirect_loop_stops_at_the_cap(acme):
    connector = _Acme()
    connector.set_network_policy("acme")
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(302, headers={"Location": f"{API}/v1/loop{len(seen)}"})

    _hooked(connector, handler)
    with pytest.raises(ConnectorError, match="Too many redirects from Acme"):
        await connector._request("GET", f"{API}/v1/loop", follow_redirects=True)
    assert len(seen) == connector.MAX_REDIRECTS + 1
    await connector.close()


@pytest.mark.asyncio
async def test_real_client_caps_redirects(acme):
    connector = _Acme()
    connector.set_network_policy("acme")
    client = connector._get_client()
    try:
        assert client.max_redirects == 3
        assert client.follow_redirects is False
    finally:
        await connector.close()


@pytest.mark.asyncio
async def test_custom_transport_is_refused(acme):
    connector = _Acme()
    connector.set_network_policy("acme")
    with pytest.raises(ConnectorError, match="bypass DNS pinning"):
        connector._get_client(transport=httpx.MockTransport(lambda r: httpx.Response(200)))


# ---------------------------------------------------------------------------
# WebSocket policy
# ---------------------------------------------------------------------------


@pytest.fixture
def ws_dns(monkeypatch):
    """Scripted getaddrinfo: records lookups, answers with *answer*."""
    state: dict[str, Any] = {"answer": [PUBLIC_IP], "calls": []}

    def fake(host: str, port: int, *args: Any, **kwargs: Any) -> list[Any]:
        state["calls"].append((host, port))
        return [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, port)) for ip in state["answer"]
        ]

    monkeypatch.setattr(socket, "getaddrinfo", fake)
    return state


def test_websocket_policy_accepts_listed_wss_host(acme, ws_dns):
    result = check_websocket_policy("wss://wss-primary.acme.test/link?ticket=t", "acme")
    assert result.safe is True
    assert result.resolved_ips == (PUBLIC_IP,)
    assert ws_dns["calls"] == [("wss-primary.acme.test", 443)]
    assert check_websocket_policy("wss://wss-primary.acme.test:443/", "acme").safe is True


@pytest.mark.parametrize(
    ("url", "reason"),
    [
        ("ws://wss-primary.acme.test/link", "Only wss"),
        ("https://wss-primary.acme.test/link", "Only wss"),
        ("wss://wss-primary.acme.test:8443/link", "Port 8443"),
        ("wss://wss-backup.acme.test/link", "not in allowlist"),
        ("wss://api.acme.test/link", "not in allowlist"),
        ("wss://u:p@wss-primary.acme.test/link", "Credentials"),
        ("wss://wss-primary.acme.test:notaport/", "Malformed"),
    ],
)
def test_websocket_policy_refusals_never_resolve(acme, ws_dns, url, reason):
    result = check_websocket_policy(url, "acme")
    assert result.safe is False
    assert reason in (result.reason or "")
    assert ws_dns["calls"] == []


def test_websocket_policy_refuses_private_resolution(acme, ws_dns):
    ws_dns["answer"] = ["10.0.0.5"]
    result = check_websocket_policy("wss://wss-primary.acme.test/link", "acme")
    assert result.safe is False
    assert "private or internal" in (result.reason or "")
    assert result.resolved_ips == ()


def test_websocket_policy_unknown_key_is_refused(ws_dns):
    result = check_websocket_policy("wss://wss-primary.acme.test/", "nope")
    assert result.safe is False
    assert ws_dns["calls"] == []
