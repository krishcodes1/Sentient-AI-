"""Unit tests for the RobinhoodConnector signing flow.

These tests use ``httpx.MockTransport`` to intercept outbound calls so we
can re-derive the expected HMAC signature from the path/method/body that
httpx actually sent and assert it matches the ``x-signature`` header.
That's the only way to lock down the P0 signing-vs-actual-URL drift.

NOTE: ``respx`` is not currently in ``requirements-dev.txt``. If you want
to switch to respx for richer matching, add it to that file (a separate
agent owns dependency management).
"""

from __future__ import annotations

import hashlib
import hmac
from typing import Any

import httpx
import pytest

from services.connectors.base import HardBlockError, UserConfirmationRequired
from services.connectors.robinhood import RobinhoodConnector


pytestmark = pytest.mark.integration


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


class CallRecorder:
    """Capture every request that hits the mock transport."""

    def __init__(self, status: int = 200, json_body: dict[str, Any] | None = None) -> None:
        self.calls: list[httpx.Request] = []
        self._status = status
        self._json = json_body or {"ok": True}

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.calls.append(request)
        return httpx.Response(self._status, json=self._json)


def _make_connector(
    recorder: CallRecorder,
    *,
    api_key: str = "kk",
    api_secret: str = "ss",
) -> RobinhoodConnector:
    conn = RobinhoodConnector(api_key=api_key, api_secret=api_secret)
    conn._authenticated = True
    transport = httpx.MockTransport(recorder)
    # Use base_url so client.get("/api/...") hits the right host.
    conn._http_client = httpx.AsyncClient(
        transport=transport,
        base_url=RobinhoodConnector.BASE_URL,
    )
    return conn


def _expected_signature(
    api_key: str,
    api_secret: str,
    timestamp: str,
    full_path: str,
    method: str,
    body: str,
) -> str:
    msg = f"{api_key}{timestamp}{full_path}{method.upper()}{body}"
    return hmac.new(
        api_secret.encode(), msg.encode(), hashlib.sha256
    ).hexdigest()


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_signature_matches_actual_url() -> None:
    """The x-signature header must verify against the URL httpx actually sends."""
    rec = CallRecorder()
    conn = _make_connector(rec)

    await conn._api_get(
        "/api/v1/crypto/marketdata/best_bid_ask/",
        params={"symbol": "BTC-USD"},
        user_confirmed=True,
    )

    assert len(rec.calls) == 1
    req = rec.calls[0]
    # The URL hit by httpx must be exactly the path-with-query we built.
    assert req.url.path == "/api/v1/crypto/marketdata/best_bid_ask/"
    assert req.url.query.decode() == "symbol=BTC-USD"

    # Reconstruct what we signed and compare.
    full_path = "/api/v1/crypto/marketdata/best_bid_ask/?symbol=BTC-USD"
    expected = _expected_signature(
        "kk", "ss", req.headers["x-timestamp"], full_path, "GET", ""
    )
    assert req.headers["x-signature"] == expected


@pytest.mark.asyncio
async def test_signature_deterministic_with_param_order() -> None:
    """Signature must be identical regardless of the dict insertion order."""
    rec_a = CallRecorder()
    conn_a = _make_connector(rec_a)
    await conn_a._api_get(
        "/api/v1/orders/", params={"a": "1", "b": "2"}, user_confirmed=True
    )

    rec_b = CallRecorder()
    conn_b = _make_connector(rec_b)
    await conn_b._api_get(
        "/api/v1/orders/", params={"b": "2", "a": "1"}, user_confirmed=True
    )

    sig_a = rec_a.calls[0].headers["x-signature"]
    ts_a = rec_a.calls[0].headers["x-timestamp"]
    sig_b = rec_b.calls[0].headers["x-signature"]
    ts_b = rec_b.calls[0].headers["x-timestamp"]

    # If the timestamps drift across the two calls, recompute one
    # signature with the other's timestamp; equal canonical-form means
    # equal signatures at the same instant.
    expected_b_at_a_ts = _expected_signature(
        "kk", "ss", ts_a, "/api/v1/orders/?a=1&b=2", "GET", ""
    )
    expected_a_at_b_ts = _expected_signature(
        "kk", "ss", ts_b, "/api/v1/orders/?a=1&b=2", "GET", ""
    )
    assert sig_a == expected_b_at_a_ts
    assert sig_b == expected_a_at_b_ts

    # Both calls used the same canonical query string.
    assert rec_a.calls[0].url.query.decode() == "a=1&b=2"
    assert rec_b.calls[0].url.query.decode() == "a=1&b=2"


@pytest.mark.asyncio
async def test_post_body_signing_includes_json() -> None:
    """POST: body bytes must be in the signature and in the actual request."""
    rec = CallRecorder()
    conn = _make_connector(rec)

    await conn._api_post(
        "/api/v1/something/",
        body={"x": 1, "y": "z"},
        user_confirmed=True,
    )

    req = rec.calls[0]
    body_str = req.content.decode()
    assert body_str == '{"x":1,"y":"z"}'

    expected = _expected_signature(
        "kk", "ss", req.headers["x-timestamp"], "/api/v1/something/", "POST", body_str
    )
    assert req.headers["x-signature"] == expected


@pytest.mark.asyncio
async def test_403_response_propagates_as_connector_error() -> None:
    """A 403 from upstream surfaces as an HTTP error from the helper."""
    rec = CallRecorder(status=403, json_body={"detail": "forbidden"})
    conn = _make_connector(rec)

    with pytest.raises(httpx.HTTPStatusError):
        await conn._api_get(
            "/api/v1/crypto/trading/accounts/", user_confirmed=True
        )


@pytest.mark.asyncio
async def test_user_confirmation_required_when_not_confirmed() -> None:
    """Read calls without explicit confirmation must raise UserConfirmationRequired."""
    rec = CallRecorder()
    conn = _make_connector(rec)

    with pytest.raises(UserConfirmationRequired):
        await conn._api_get("/api/v1/crypto/trading/accounts/")

    # No actual HTTP call was made.
    assert rec.calls == []


@pytest.mark.asyncio
async def test_hard_block_actions_never_called() -> None:
    """All trading verbs must raise HardBlockError before any HTTP call.

    This applies both to the dispatcher (``_execute_action``) and to the
    explicit ``execute_trade`` method.
    """
    rec = CallRecorder()
    conn = _make_connector(rec)

    blocked = ["execute_trade", "place_order", "cancel_order",
               "buy", "sell", "withdraw", "transfer", "deposit"]
    for action in blocked:
        with pytest.raises(HardBlockError):
            await conn._execute_action(action, {})

    with pytest.raises(HardBlockError):
        await conn.execute_trade(symbol="BTC", qty=1)

    # No HTTP call was issued for any blocked action.
    assert rec.calls == []
