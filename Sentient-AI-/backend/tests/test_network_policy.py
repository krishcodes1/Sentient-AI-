"""Network-policy regression tests.

The deny-by-default allowlists must match the URLs the connectors
actually request — the original Robinhood policy allowlisted a host and
path prefix the connector never used, making it 100% non-functional.
These tests drive the REAL connector methods over a mock HTTP transport,
capture every outbound URL, and feed each one through
``check_network_policy``.
"""

from __future__ import annotations

import httpx
import pytest

import core.network_security as netsec
from core.network_security import check_network_policy


@pytest.fixture
def no_dns(monkeypatch):
    """Make policy checks DNS-independent: SSRF resolution always passes,
    so the host/path allowlists are what decide."""
    monkeypatch.setattr(
        netsec, "check_ssrf", lambda url: netsec.SSRFCheckResult(safe=True)
    )


# ---------------------------------------------------------------------------
# Robinhood
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_robinhood_real_request_urls_all_pass_policy(no_dns):
    """Every URL the connector actually requests is allowlisted."""
    from services.connectors.robinhood import RobinhoodConnector

    seen: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(str(request.url))
        return httpx.Response(200, json={})

    connector = RobinhoodConnector(api_key="k", api_secret="s")
    connector._http_client = httpx.AsyncClient(
        transport=httpx.MockTransport(handler), base_url=connector.BASE_URL
    )

    try:
        # Exercises the credential-check URL too.
        await connector.authenticate({"api_key": "k", "api_secret": "s"})
        await connector.get_crypto_portfolio(user_confirmed=True)
        await connector.get_crypto_prices(["BTC", "ETH"], user_confirmed=True)
        await connector.get_crypto_holdings(user_confirmed=True)
        assert await connector.health_check() is True
    finally:
        await connector.close()

    # authenticate + portfolio + 2 prices + holdings + health check
    assert len(seen) >= 6
    for url in seen:
        result = check_network_policy(url, "robinhood")
        assert result.safe, f"{url} blocked: {result.reason}"


def test_robinhood_policy_blocks_trading_and_stale_endpoints(no_dns):
    """Read-only stays read-only: order/trading endpoints are NOT
    allowlisted, and the stale pre-fix host stays dead."""
    for url in (
        # Order placement / trading endpoints: the financial hard block
        # must hold at the network layer too.
        "https://trading.robinhood.com/api/v1/crypto/trading/orders/",
        "https://trading.robinhood.com/api/v1/crypto/trading/orders/123/cancel/",
        # Bare root and non-crypto API surfaces.
        "https://trading.robinhood.com/",
        "https://trading.robinhood.com/api/v1/accounts/",
        # The old (wrong) allowlist host must not have survived.
        "https://api.robinhood.com/api/crypto/accounts/",
        # Foreign host.
        "https://evil.example.com/api/v1/crypto/trading/accounts/",
    ):
        assert check_network_policy(url, "robinhood").safe is False, url


# ---------------------------------------------------------------------------
# Canvas
# ---------------------------------------------------------------------------


def test_canvas_policy_allows_api_and_token_endpoint_only(no_dns):
    for url in (
        "https://school.instructure.com/api/v1/courses",
        # OAuth code exchange + refresh endpoint used by the connector.
        "https://school.instructure.com/login/oauth2/token",
    ):
        result = check_network_policy(url, "canvas")
        assert result.safe, f"{url} blocked: {result.reason}"

    for url in (
        # Interactive login surfaces stay blocked.
        "https://school.instructure.com/login/oauth2/auth",
        "https://school.instructure.com/login/session",
        "https://school.instructure.com/files/1/download",
        # Token path on a foreign host.
        "https://evil.example.com/login/oauth2/token",
    ):
        assert check_network_policy(url, "canvas").safe is False, url


@pytest.mark.asyncio
async def test_canvas_stores_refresh_token_and_refreshes_on_401():
    """A stored refresh_token is kept from credentials and used to renew
    an expired bearer token mid-session."""
    from services.connectors.canvas import CanvasConnector

    calls: list[tuple[str, str]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append((request.method, request.url.path))
        if request.url.path == "/login/oauth2/token":
            return httpx.Response(
                200, json={"access_token": "new-token", "refresh_token": "r2"}
            )
        if request.headers.get("Authorization") == "Bearer stale-token":
            return httpx.Response(401, json={"errors": "token expired"})
        return httpx.Response(200, json=[{"id": 1}])

    connector = CanvasConnector(
        base_url="https://school.instructure.com",
        client_id="cid",
        client_secret="secret",
    )
    connector._http_client = httpx.AsyncClient(transport=httpx.MockTransport(handler))

    try:
        await connector.authenticate(
            {"access_token": "stale-token", "refresh_token": "r1"}
        )
        assert connector._refresh_token == "r1"

        courses = await connector.get_courses()
        assert courses == [{"id": 1}]
        # 401 triggered a refresh through /login/oauth2/token, then a retry.
        assert ("POST", "/login/oauth2/token") in calls
        assert connector._access_token == "new-token"
        assert connector._refresh_token == "r2"
    finally:
        await connector.close()


@pytest.mark.asyncio
async def test_canvas_without_refresh_token_does_not_attempt_refresh():
    from services.connectors.canvas import CanvasConnector

    calls: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request.url.path)
        return httpx.Response(401, json={"errors": "token expired"})

    connector = CanvasConnector(
        base_url="https://school.instructure.com",
        client_id="",
        client_secret="",
    )
    connector._http_client = httpx.AsyncClient(transport=httpx.MockTransport(handler))

    try:
        await connector.authenticate({"access_token": "stale-token"})
        assert connector._refresh_token is None

        with pytest.raises(httpx.HTTPStatusError):
            await connector.get_courses()
        assert "/login/oauth2/token" not in calls
    finally:
        await connector.close()
