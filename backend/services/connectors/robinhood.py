"""
Robinhood Crypto connector for SentientAI.

READ-ONLY access to Robinhood's official Crypto Trading API.
All financial actions (trades, transfers, withdrawals) are
permanently hard-blocked and cannot be overridden.
"""

from __future__ import annotations

import hashlib
import hmac
import time
import uuid
from typing import Any
from urllib.parse import urlencode

import httpx
import structlog

from .base import (
    AuthenticationError,
    BaseConnector,
    ConnectorError,
    HardBlockError,
    UserConfirmationRequired,
)

logger = structlog.get_logger(__name__)

# Actions that are permanently blocked -- no override possible.
_HARD_BLOCKED_ACTIONS: frozenset[str] = frozenset(
    {
        "execute_trade",
        "place_order",
        "cancel_order",
        "withdraw",
        "transfer",
        "deposit",
        "sell",
        "buy",
    }
)


class RobinhoodConnector(BaseConnector):
    """Connector for the Robinhood Crypto Trading API.

    Uses API key + secret authentication (HMAC-SHA256 request signing).
    Strictly read-only -- every API call still requires ``USER_CONFIRM``,
    and all trade/transfer actions raise ``HardBlockError``.
    """

    BASE_URL = "https://trading.robinhood.com"

    _ACTION_MAP: dict[str, str] = {
        "get_crypto_portfolio": "get_crypto_portfolio",
        "get_crypto_prices": "get_crypto_prices",
        "get_crypto_holdings": "get_crypto_holdings",
    }

    def __init__(
        self,
        api_key: str | None = None,
        api_secret: str | None = None,
        timeout_s: float | None = None,
    ) -> None:
        # Very conservative rate limit for financial API
        super().__init__(timeout_s=timeout_s or 30.0, rate_limit=30)
        self._api_key = api_key or ""
        self._api_secret = api_secret or ""

    # -- Properties ----------------------------------------------------------

    @property
    def name(self) -> str:
        return "Robinhood Crypto"

    @property
    def connector_type(self) -> str:
        return "finance"

    @property
    def required_scopes(self) -> list[str]:
        return ["crypto.read"]

    # -- Authentication (API key + HMAC signing) -----------------------------

    async def authenticate(self, credentials: dict[str, Any]) -> bool:
        """Authenticate with API key and secret.

        Required keys: ``api_key``, ``api_secret``.
        """
        api_key = credentials.get("api_key")
        api_secret = credentials.get("api_secret")
        if not api_key or not api_secret:
            raise AuthenticationError(
                "Robinhood connector requires 'api_key' and 'api_secret'."
            )

        self._api_key = api_key
        self._api_secret = api_secret

        # Validate credentials by making a lightweight API call
        try:
            client = self._get_client(base_url=self.BASE_URL)
            resp = await client.get(
                "/api/v1/crypto/trading/accounts/",
                headers=self._build_headers("GET", "/api/v1/crypto/trading/accounts/"),
            )
            if resp.status_code == 401:
                raise AuthenticationError("Invalid Robinhood API credentials.")
            resp.raise_for_status()
        except AuthenticationError:
            raise
        except httpx.HTTPStatusError as exc:
            raise AuthenticationError(
                f"Robinhood auth check failed: {exc.response.status_code}"
            ) from exc

        self._authenticated = True
        self._log.info("authenticated_with_api_key")
        return True

    def _build_headers(
        self,
        method: str,
        path: str,
        body: str = "",
        query: str = "",
    ) -> dict[str, str]:
        """Build signed request headers using HMAC-SHA256.

        Robinhood Crypto API requires:
        - ``x-api-key``
        - ``x-timestamp`` (Unix epoch)
        - ``x-signature`` (HMAC of ``{api_key}{timestamp}{path}{method}{body}``)
        """
        timestamp = str(int(time.time()))
        message = f"{self._api_key}{timestamp}{path}{method.upper()}{body}"
        signature = hmac.new(
            self._api_secret.encode("utf-8"),
            message.encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()

        return {
            "x-api-key": self._api_key,
            "x-timestamp": timestamp,
            "x-signature": signature,
            "Content-Type": "application/json; charset=utf-8",
        }

    # -- Internal HTTP helpers -----------------------------------------------

    async def _api_get(
        self,
        path: str,
        params: dict[str, Any] | None = None,
        *,
        user_confirmed: bool = False,
    ) -> Any:
        """Every single API call requires USER_CONFIRM."""
        if not user_confirmed:
            raise UserConfirmationRequired(
                action=f"GET {path}",
                details=(
                    "Reading financial data from Robinhood. "
                    "Please confirm this data access."
                ),
            )

        query = urlencode(params) if params else ""
        full_path = f"{path}?{query}" if query else path
        headers = self._build_headers("GET", full_path)
        client = self._get_client(base_url=self.BASE_URL)
        resp = await client.get(path, headers=headers, params=params)
        resp.raise_for_status()
        return resp.json()

    # -- Public data methods (all READ-ONLY) ---------------------------------

    async def get_crypto_portfolio(
        self, *, user_confirmed: bool = False
    ) -> dict[str, Any]:
        """Fetch the user's crypto portfolio overview.

        **Requires USER_CONFIRM** for every call.
        """
        data = await self._api_get(
            "/api/v1/crypto/trading/accounts/",
            user_confirmed=user_confirmed,
        )
        return {
            "account": data,
            "note": "Read-only view. Trading is permanently disabled.",
        }

    async def get_crypto_prices(
        self,
        symbols: list[str],
        *,
        user_confirmed: bool = False,
    ) -> dict[str, Any]:
        """Fetch current prices for the given crypto symbols.

        **Requires USER_CONFIRM** for every call.
        """
        prices: dict[str, Any] = {}
        for symbol in symbols:
            pair = f"{symbol.upper()}-USD"
            data = await self._api_get(
                f"/api/v1/crypto/marketdata/best_bid_ask/",
                params={"symbol": pair},
                user_confirmed=user_confirmed,
            )
            prices[symbol.upper()] = data
        return {"prices": prices, "symbols": symbols}

    async def get_crypto_holdings(
        self, *, user_confirmed: bool = False
    ) -> dict[str, Any]:
        """Fetch current crypto holdings.

        **Requires USER_CONFIRM** for every call.
        """
        data = await self._api_get(
            "/api/v1/crypto/trading/holdings/",
            user_confirmed=user_confirmed,
        )
        return {
            "holdings": data,
            "note": "Read-only view. Trading is permanently disabled.",
        }

    # -- Hard-blocked trade action -------------------------------------------

    async def execute_trade(self, **kwargs: Any) -> None:
        """PERMANENTLY BLOCKED. Raises ``HardBlockError`` unconditionally.

        This method exists solely to provide a clear, auditable rejection
        point.  It cannot be overridden, bypassed, or monkey-patched in
        any subclass -- the ``execute`` dispatcher also checks the
        hard-block list independently.
        """
        raise HardBlockError(
            action="execute_trade",
            reason=(
                "Executing trades via the AI agent is permanently blocked. "
                "This restriction cannot be overridden. "
                "Please use the Robinhood app directly for all trading."
            ),
        )

    # -- execute dispatch ----------------------------------------------------

    async def _execute_action(self, action: str, params: dict[str, Any]) -> dict[str, Any]:
        # Hard-block check BEFORE any dispatch
        if action in _HARD_BLOCKED_ACTIONS:
            raise HardBlockError(
                action=action,
                reason=(
                    f"Action '{action}' is permanently blocked on the Robinhood "
                    "connector. Financial transactions cannot be executed by the "
                    "AI agent under any circumstances."
                ),
            )

        method_name = self._ACTION_MAP.get(action)
        if not method_name:
            raise ConnectorError(f"Unknown Robinhood action: {action}")
        method = getattr(self, method_name)
        result = await method(**params)
        if isinstance(result, list):
            return {"items": result, "count": len(result)}
        return result

    # -- Health check --------------------------------------------------------

    async def health_check(self) -> bool:
        """Check Robinhood API reachability (unauthenticated ping)."""
        try:
            client = self._get_client(base_url=self.BASE_URL)
            resp = await client.get("/")
            return resp.status_code < 500
        except Exception:
            return False
