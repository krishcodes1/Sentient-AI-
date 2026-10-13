"""Implements the read-only Robinhood Crypto connector with Ed25519 request
signing and a permanent block on every trading action.

Why it exists: The factory constructs it for tool execution; keeping the hard-
block list beside the API code guarantees no trade, transfer or withdrawal can
be issued whatever the permission engine decides.

Robinhood Crypto connector for Crawler AI.

READ-ONLY access to Robinhood's official Crypto Trading API.
All financial actions (trades, transfers, withdrawals) are
permanently hard-blocked and cannot be overridden.

Authentication (https://docs.robinhood.com/crypto/trading/): the user makes
an Ed25519 key pair, registers the public key as an API credential at
robinhood.com/account/crypto and gets an API key back. Every request carries
that key, a Unix timestamp (valid for 30 seconds) and the base64 Ed25519
signature of ``{api_key}{timestamp}{path}{method}{body}``.
"""

from __future__ import annotations

import base64
import binascii
import time
import uuid
from typing import Any, Optional

import httpx
import structlog
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from services.agent.permissions import ActionCategory, PermissionTier

from .base import (
    AuthenticationError,
    BaseConnector,
    ConnectorError,
    HardBlockError,
    UserConfirmationRequired,
)
from .definition import (
    AuthSpec,
    ConnectorDefinition,
    CredentialField,
    NetworkSpec,
    ToolSpec,
    _schema,
)

logger = structlog.get_logger(__name__)


# The tool catalog for Robinhood. execute_trade is declared (FINANCIAL) so
# every layer can recognise and refuse it; it is never offered or run.
ACTIONS: tuple[ToolSpec, ...] = (
    ToolSpec(
        "get_crypto_portfolio",
        "View the Robinhood crypto portfolio (read-only).",
        ActionCategory.READ,
        required_scope="crypto.read",
        starter=True,
    ),
    ToolSpec(
        "get_crypto_prices",
        "Get current prices for crypto symbols (read-only).",
        ActionCategory.READ,
        _schema(symbols={"type": "array", "items": {"type": "string"}, "required": True}),
        required_scope="crypto.read",
    ),
    ToolSpec(
        "get_crypto_holdings",
        "View current crypto holdings (read-only).",
        ActionCategory.READ,
        required_scope="crypto.read",
        starter=True,
    ),
    ToolSpec(
        "execute_trade",
        "Execute a crypto trade. Permanently blocked by platform policy.",
        ActionCategory.FINANCIAL,
        _schema(symbol={"type": "string", "required": True}, side={"type": "string", "required": True}),
        required_scope="crypto.trade",
    ),
)

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

# An Ed25519 private key is a 32-byte seed. Robinhood's key script prints
# it base64-encoded, and that is what the user stores as ``api_secret``.
_SEED_BYTES = 32

# Fixed text, so no message built from it can echo the stored value.
_BAD_PRIVATE_KEY = (
    "api_secret must be the base64 Ed25519 private key (a 32-byte seed) "
    "whose public key is registered with Robinhood."
)


def load_private_key(secret: str) -> Ed25519PrivateKey:
    """Decode the base64 private key seed stored as ``api_secret``.

    Raises ``ValueError`` with a fixed message for anything else,
    including a secret from before the switch to Ed25519.
    """
    try:
        seed = base64.b64decode(secret.strip(), validate=True)
    except (binascii.Error, ValueError):
        raise ValueError(_BAD_PRIVATE_KEY) from None
    if len(seed) != _SEED_BYTES:
        raise ValueError(_BAD_PRIVATE_KEY)
    return Ed25519PrivateKey.from_private_bytes(seed)


def public_key_b64(private_key: Ed25519PrivateKey) -> str:
    """The base64 public key Robinhood holds for *private_key*."""
    raw = private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    return base64.b64encode(raw).decode("ascii")


class RobinhoodConnector(BaseConnector):
    """Connector for the Robinhood Crypto Trading API.

    Authenticates with an API key and an Ed25519 private key that signs
    every request; Robinhood checks the signature against the public key
    registered with that API key. Strictly read-only -- every API call
    still requires ``USER_CONFIRM``, and all trade/transfer actions raise
    ``HardBlockError``.
    """

    BASE_URL = "https://trading.robinhood.com"

    _ACTION_MAP: dict[str, str] = {
        "get_crypto_portfolio": "get_crypto_portfolio",
        "get_crypto_prices": "get_crypto_prices",
        "get_crypto_holdings": "get_crypto_holdings",
    }

    def __init__(
        self,
        api_key: Optional[str] = None,
        api_secret: Optional[str] = None,
        timeout_s: Optional[float] = None,
    ) -> None:
        # Very conservative rate limit for financial API
        super().__init__(timeout_s=timeout_s or 30.0, rate_limit=30)
        self._api_key = api_key or ""
        self._private_key: Optional[Ed25519PrivateKey] = (
            load_private_key(api_secret) if api_secret else None
        )

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

    @classmethod
    def from_credentials(
        cls, credentials: dict[str, Any], *, timeout_s: Optional[float] = None
    ) -> RobinhoodConnector:
        """Build an instance; the key pair is read in ``authenticate``."""
        return cls(timeout_s=timeout_s)

    @classmethod
    def validate_credentials(cls, credentials: dict[str, Any]) -> list[str]:
        """Check that ``api_secret`` decodes to a key; never echo it."""
        secret = credentials.get("api_secret")
        if secret is None or (isinstance(secret, str) and not secret.strip()):
            return []  # missing required fields are reported by the factory
        if not isinstance(secret, str):
            return [_BAD_PRIVATE_KEY]
        try:
            load_private_key(secret)
        except ValueError as exc:
            return [str(exc)]
        return []

    # -- Authentication (API key + Ed25519 signing) --------------------------

    async def authenticate(self, credentials: dict[str, Any]) -> bool:
        """Authenticate with the API key and the base64 Ed25519 private key.

        Required keys: ``api_key``, ``api_secret`` (the private key; the
        name is kept so connectors stored before Ed25519 still load).
        """
        api_key = credentials.get("api_key")
        api_secret = credentials.get("api_secret")
        if not api_key or not api_secret:
            raise AuthenticationError(
                "Robinhood connector requires 'api_key' and 'api_secret'."
            )
        try:
            private_key = load_private_key(str(api_secret))
        except ValueError as exc:
            raise AuthenticationError(
                f"{exc} Reconnect Robinhood in Connectors."
            ) from None

        self._api_key = str(api_key).strip()
        self._private_key = private_key

        # Validate credentials by making a lightweight API call
        try:
            resp = await self._send_signed("GET", "/api/v1/crypto/trading/accounts/")
            if resp.status_code == 401:
                raise AuthenticationError(
                    "Robinhood rejected the API key or its signature. Check that "
                    "the API credential at robinhood.com/account/crypto was "
                    f"created with this public key: {public_key_b64(private_key)}"
                )
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
    ) -> dict[str, str]:
        """Build signed request headers using Ed25519.

        Robinhood Crypto API requires:
        - ``x-api-key``
        - ``x-timestamp`` (Unix epoch, valid for 30 seconds)
        - ``x-signature`` (base64 Ed25519 signature of
          ``{api_key}{timestamp}{path}{method}{body}``)

        *path* must be the path-and-query exactly as it goes on the wire;
        see ``_send_signed``, which is the only caller that can guarantee
        that.
        """
        if self._private_key is None:
            raise AuthenticationError("Robinhood connector is not authenticated.")
        timestamp = str(int(time.time()))
        message = f"{self._api_key}{timestamp}{path}{method.upper()}{body}"
        signature = self._private_key.sign(message.encode("utf-8"))

        return {
            "x-api-key": self._api_key,
            "x-timestamp": timestamp,
            "x-signature": base64.b64encode(signature).decode("ascii"),
            "Content-Type": "application/json; charset=utf-8",
        }

    # -- Internal HTTP helpers -----------------------------------------------

    async def _send_signed(
        self,
        method: str,
        path: str,
        params: dict[str, Any] | None = None,
    ) -> httpx.Response:
        """Sign and send one request, over the exact bytes being sent.

        The signature covers the path-and-query, so the string signed and
        the string transmitted have to be identical byte for byte. Building
        the query twice (once with ``urlencode`` for the signature and once by
        handing ``params`` to httpx) meant trusting two encoders to agree;
        they do not (booleans, ``None``, and repeated keys all differ), and
        every disagreement is an opaque 401 from Robinhood. Building the
        request first and signing ``raw_path`` off that same object removes
        the second encoder entirely.
        """
        client = self._get_client(base_url=self.BASE_URL)
        request = client.build_request(method, path, params=params)
        signed_path = request.url.raw_path.decode("ascii")
        request.headers.update(self._build_headers(method, signed_path))
        return await client.send(request)

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

        resp = await self._send_signed("GET", path, params=params)
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
                "/api/v1/crypto/marketdata/best_bid_ask/",
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
        """Check Robinhood API reachability (unauthenticated ping).

        Pings a read-only market-data endpoint that is inside the
        connector's network-policy allowlist ("/" is not). An auth
        error (401/403) still proves the service is reachable.
        """
        try:
            client = self._get_client(base_url=self.BASE_URL)
            resp = await client.get("/api/v1/crypto/marketdata/best_bid_ask/")
            return resp.status_code < 500
        except Exception:
            return False


DEFINITION = ConnectorDefinition(
    key="robinhood",
    label="Robinhood (read-only)",
    description="Read-only view of your Robinhood crypto portfolio, holdings and prices. Trading is permanently blocked.",
    icon="trending-up",
    auth=AuthSpec(
        methods=("token",),
        fields=(
            CredentialField(
                "api_key",
                "API key",
                placeholder="rh-api-...",
                hint="Robinhood shows it after you add the public key as an API credential.",
            ),
            # The key stays "api_secret" so connectors stored before the
            # switch to Ed25519 still load; the value is now the private key.
            CredentialField(
                "api_secret",
                "Private key (base64)",
                placeholder="Base64 Ed25519 private key",
                hint="Stored encrypted and never sent to Robinhood; only its public key is registered there.",
            ),
        ),
        token_auth_method="api_key",
        notes=(
            "Requests to Robinhood are signed with an Ed25519 key pair. Generate one "
            "below (or with the script in Robinhood's docs), add the public key as "
            "a new API credential at robinhood.com/account/crypto (web classic, "
            "US only), then paste the API key Robinhood gives you. Trading is "
            "permanently blocked by the platform."
        ),
        token_url="https://robinhood.com/account/crypto",
        token_url_label="Open Robinhood crypto API keys",
    ),
    network=NetworkSpec(
        policy_key="robinhood",
        # Only the read-only endpoints the connector uses. Trading and order
        # endpoints (e.g. /api/v1/crypto/trading/orders/) are deliberately
        # absent, so the financial hard block holds at the network layer too.
        hosts={
            "trading.robinhood.com": (
                "/api/v1/crypto/trading/accounts/",
                "/api/v1/crypto/trading/holdings/",
                "/api/v1/crypto/marketdata/",
            ),
        },
        https_only=True,
    ),
    actions=ACTIONS,
    connector_class=RobinhoodConnector,
    docs_url="https://docs.robinhood.com/crypto/trading/",
    financial_ok=True,
    # Every Robinhood read shows financial data, so it keeps the approval
    # card the hand-written policy row has always required.
    policy_overrides={("robinhood", ActionCategory.READ): PermissionTier.USER_CONFIRM},
)
