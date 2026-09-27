"""The shared OAuth broker: signs a user in to a connector's provider with the
authorization-code flow (PKCE) or the device flow, stores the tokens on a
connector row, refreshes them before they expire and revokes them after a
disconnect.

Why it exists: every OAuth connector (Google, Microsoft, GitHub) needs the
same state handling, code exchange, device polling, refresh and revoke. One
broker, driven by each connector's ``OAuthSpec``, keeps those security rules
in one place: the state is stored only as an HMAC and is single use, the
redirect URI is fixed by configuration, tokens are validated strictly and
stored encrypted, and nothing secret is ever logged.

Connects ``api/routes/oauth.py`` (the HTTP surface), the tool executor and the
connector routes (``ensure_fresh_credentials``, ``persist_credentials``,
``schedule_revoke``) to ``models.oauth_state.OAuthState`` and
``models.connector.ConnectorConfig``. Talks to each provider's token, device
and revoke endpoints through a policy-armed ``BaseConnector``
(``_TokenClient``), so the connector's network allowlist, DNS pinning, retry
and error redaction apply. Depends on ``services.connectors.registry``,
``oauth_config``, ``core.security`` and ``services.audit``.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import json
import re
import secrets
import time
import uuid
import weakref
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Awaitable, Callable, Coroutine, Mapping, Optional
from urllib.parse import quote, urlencode

import structlog
from sqlalchemy import delete, func, or_, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from core.config import settings
from core.security import decrypt_credentials, encrypt_credentials
from models.audit import AuditStatus
from models.connector import AuthMethod, ConnectorConfig, PermissionTier
from models.oauth_state import OAuthFlowKind, OAuthFlowStatus, OAuthState
from services.audit import append_auth_event
from services.connectors import registry as connector_registry
from services.connectors.base import (
    AuthenticationError,
    BaseConnector,
    ConnectorError,
)
from services.connectors.definition import ConnectorDefinition, OAuthSpec
from services.connectors.oauth_config import (
    OAuthClient,
    OAuthNotConfigured,
    redirect_base_is_loopback,
    redirect_uri,
    resolve_client,
)

logger = structlog.get_logger(__name__)

SessionFactory = Callable[[], AsyncSession]

# How long a browser consent flow stays usable (spec 4.3).
FLOW_TTL = timedelta(minutes=10)
# Device codes live as long as the provider says, within these bounds.
DEVICE_MIN_TTL_S = 60
DEVICE_MAX_TTL_S = 30 * 60
# Finished and expired rows are deleted once they are this old. Every flow
# lives at most DEVICE_MAX_TTL_S, so a row this old is always finished.
CLEANUP_AFTER = timedelta(hours=1)
# Sign-ins one user may have in flight at once (each can own a poller).
MAX_PENDING_FLOWS_PER_USER = 10
# Refresh an access token this close to its expiry.
REFRESH_MARGIN_S = 120
# Device polling interval bounds and the RFC 8628 slow_down step.
DEFAULT_POLL_INTERVAL_S = 5
MAX_POLL_INTERVAL_S = 120
SLOW_DOWN_STEP_S = 5
# Transient token-endpoint failures in a row before a device flow gives up.
MAX_POLL_FAILURES = 3
DEVICE_GRANT_TYPE = "urn:ietf:params:oauth:grant-type:device_code"

# Size limits for values a provider hands back, so a hostile or broken
# response cannot bloat the row or the page.
_MAX_TOKEN_CHARS = 16_384
_MAX_SCOPE_CHARS = 8_192
_MAX_USER_CODE_CHARS = 64
_MAX_URI_CHARS = 512
_MAX_CODE_CHARS = 4_096
_STATE_RE = re.compile(r"^[A-Za-z0-9_-]{16,128}$")
_CODE_RE = re.compile(r"^[\x21-\x7e]+$")
_ERROR_CODE_RE = re.compile(r"^[A-Za-z0-9_.:-]{1,64}$")

# Token endpoint error codes that mean the refresh token is dead (RFC 6749
# 5.2), and those that mean OUR client registration is wrong (RFC 6749 5.2
# plus GitHub's ``incorrect_client_credentials``). A reconnect cannot fix
# the second kind, so it gets its own message.
_DEAD_GRANT_CODES = frozenset({"invalid_grant"})
_CLIENT_CONFIG_CODES = frozenset(
    {
        "invalid_client",
        "unauthorized_client",
        "incorrect_client_credentials",
        "invalid_request",
        "invalid_scope",
        "unsupported_grant_type",
    }
)

_STATE_KEY_DOMAIN = b"sentientai.oauth.state.v1:"
# The browser binding cookie (see ``complete_callback``): its name and value
# are an HMAC of the state under this label, so only the server can mint it.
_BINDING_DOMAIN = b"browser-binding:"
BINDING_COOKIE_PREFIX = "crawler_oauth_"

# Messages stored on a flow and shown by the status route. Generic on
# purpose: a provider's error text is never relayed.
MSG_CANCELLED = "Sign-in was cancelled."
MSG_FAILED = "Sign-in did not complete. Start it again from Connectors."
MSG_EXPIRED = "The sign-in expired before it finished. Start it again from Connectors."
MSG_NO_SCOPES = "None of the requested permissions were granted. Start again and allow access."
MSG_CONNECTOR_GONE = "The connector to reconnect no longer exists."
MSG_OTHER_BROWSER = (
    "Sign-in has to finish in the browser that started it. Start it again "
    "from Connectors and approve it in that same browser."
)

# Test seams: the clock (epoch seconds) and the poller's sleep.
_clock: Callable[[], float] = time.time
_sleep: Callable[[float], Awaitable[None]] = asyncio.sleep


def _utcnow() -> datetime:
    return datetime.fromtimestamp(_clock(), timezone.utc)


def _as_utc(value: datetime) -> datetime:
    """SQLite returns naive datetimes for timezone-aware columns."""
    return value if value.tzinfo else value.replace(tzinfo=timezone.utc)


def _default_session_factory() -> SessionFactory:
    from core.database import async_session

    return async_session


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class OAuthFlowError(Exception):
    """A start or device request the broker refuses; ``status_code`` and the
    message are safe to return to the caller as is."""

    def __init__(self, status_code: int, detail: str) -> None:
        super().__init__(detail)
        self.status_code = status_code
        self.detail = detail


class TokenEndpointError(Exception):
    """The token, device or revoke endpoint refused or failed.

    ``code`` is the provider's short OAuth error code (``invalid_grant``,
    ``authorization_pending``) or one of ours (``malformed_response``,
    ``invalid_token_response``); ``status`` the HTTP status when there was
    one. The message never carries a response body.
    """

    def __init__(self, code: Optional[str], status: Optional[int] = None) -> None:
        self.code = code
        self.status = status
        super().__init__(f"token endpoint error ({code or status or 'network'})")


class _FlowAborted(Exception):
    """Completing a flow failed for a reason stored on the flow row."""

    def __init__(self, message: str, reason: str) -> None:
        super().__init__(reason)
        self.message = message
        self.reason = reason


# ---------------------------------------------------------------------------
# State and PKCE
# ---------------------------------------------------------------------------


def _state_key() -> bytes:
    """HMAC key for state hashes, domain-separated from every other use of
    ENCRYPTION_KEY (the idiom of ``core.security._get_audit_hmac_key``)."""
    return hashlib.sha256(_STATE_KEY_DOMAIN + settings.ENCRYPTION_KEY.encode("utf-8")).digest()


def hash_state(state: str) -> str:
    """HMAC-SHA256 hex of a ``state`` value; the only form ever stored."""
    return hmac.new(_state_key(), state.encode("utf-8"), hashlib.sha256).hexdigest()


def new_state() -> str:
    """32 random bytes, URL-safe."""
    return secrets.token_urlsafe(32)


def new_pkce_verifier() -> str:
    """A 86-character RFC 7636 code verifier (64 random bytes)."""
    return secrets.token_urlsafe(64)


def pkce_challenge(verifier: str) -> str:
    """The S256 code challenge for *verifier*."""
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


@dataclass(frozen=True)
class BrowserBinding:
    """The cookie a browser flow's start response sets and its callback must
    bring back. ``repr`` hides the value."""

    name: str
    value: str = field(repr=False)


def browser_binding(state: str) -> BrowserBinding:
    """The binding cookie for *state*: 16 hex characters of an HMAC name it
    (so concurrent flows do not overwrite each other) and the other 48 are
    the value."""
    digest = hmac.new(_state_key(), _BINDING_DOMAIN + state.encode("utf-8"), hashlib.sha256).hexdigest()
    return BrowserBinding(name=BINDING_COOKIE_PREFIX + digest[:16], value=digest[16:])


def browser_binding_required() -> bool:
    """True on a server whose redirect base is not loopback, where a consent
    link could be finished from anyone's browser."""
    return not redirect_base_is_loopback()


def _binding_matches(state: str, cookies: Optional[Mapping[str, str]]) -> bool:
    expected = browser_binding(state)
    presented = (cookies or {}).get(expected.name) or ""
    return hmac.compare_digest(presented.encode("utf-8"), expected.value.encode("utf-8"))


def build_authorization_url(
    spec: OAuthSpec,
    *,
    client: OAuthClient,
    catalog_scopes: list[str],
    state: str,
    verifier: Optional[str],
) -> str:
    """The provider consent URL. Our parameters win over ``authorize_params``
    so a spec cannot override the redirect URI, state or challenge."""
    params: dict[str, str] = dict(spec.authorize_params)
    params.update(
        {
            "client_id": client.client_id,
            "response_type": "code",
            "redirect_uri": redirect_uri(spec.provider),
            "scope": " ".join(spec.provider_scopes(catalog_scopes)),
            "state": state,
        }
    )
    if spec.pkce and verifier:
        params["code_challenge"] = pkce_challenge(verifier)
        params["code_challenge_method"] = "S256"
    separator = "&" if "?" in spec.authorize_url else "?"
    return f"{spec.authorize_url}{separator}{urlencode(params, quote_via=quote)}"


# ---------------------------------------------------------------------------
# Token endpoint client
# ---------------------------------------------------------------------------


class _TokenClient(BaseConnector):
    """A minimal connector used only to talk to a provider's OAuth endpoints.

    It is armed with the owning connector's network policy, so the token,
    device and revoke URLs must be in that connector's allowlist, and every
    request is DNS-pinned, retried at most once (429 only, since token
    requests are POSTs) and mapped to errors that never contain a body.
    Requests carry no Authorization header (``authorized=False``); the
    client credentials travel in the form body.
    """

    def __init__(self, provider: str, timeout_s: Optional[float] = None) -> None:
        self._provider = provider
        super().__init__(timeout_s=timeout_s or 20.0, rate_limit=600)

    @property
    def name(self) -> str:
        return f"{self._provider} sign-in"

    @property
    def connector_type(self) -> str:
        return "oauth"

    @property
    def required_scopes(self) -> list[str]:
        return []

    async def authenticate(self, credentials: dict[str, Any]) -> bool:
        self._authenticated = True
        return True

    async def _execute_action(self, action: str, params: dict[str, Any]) -> dict[str, Any]:
        raise ConnectorError("The OAuth token client has no actions.")

    async def health_check(self) -> bool:
        return False

    async def post_form(self, url: str, data: Mapping[str, str]) -> dict[str, Any]:
        """POST *data* as a form; the decoded JSON object on success.

        Raises ``TokenEndpointError``: for a non-2xx status (with the
        vendor code when the body had one), for a 2xx body carrying an
        ``error`` field (GitHub answers device polling that way), and for a
        body that is not a JSON object.
        """
        try:
            response = await self._request(
                "POST",
                url,
                data=dict(data),
                headers={"Accept": "application/json"},
                authorized=False,
            )
        except ConnectorError as exc:
            status, code = _http_error_details(exc)
            raise TokenEndpointError(code, status) from None
        try:
            payload = response.json()
        except ValueError:
            raise TokenEndpointError("malformed_response", response.status_code) from None
        if not isinstance(payload, dict):
            raise TokenEndpointError("malformed_response", response.status_code)
        error = payload.get("error")
        if error is not None:
            code = error if isinstance(error, str) and _ERROR_CODE_RE.match(error) else "unknown_error"
            raise TokenEndpointError(code, response.status_code)
        return payload


def _http_error_details(exc: ConnectorError) -> tuple[Optional[int], Optional[str]]:
    """Status and vendor code of a ``BaseConnector`` error, read from the
    structured attributes ``base.http_error_for`` sets (``None, None`` for
    a network failure or a policy refusal, which never reached a status)."""
    return exc.status_code, exc.vendor_code


def _token_client(definition: ConnectorDefinition) -> _TokenClient:
    """A token client armed with *definition*'s network policy. Tests
    replace this to inject a mock transport."""
    oauth = definition.auth.oauth
    assert oauth is not None
    client = _TokenClient(oauth.provider)
    client.set_network_policy(definition.network.policy_key)
    return client


# ---------------------------------------------------------------------------
# Token responses and scopes
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class TokenSet:
    """A validated token response."""

    access_token: str
    token_type: str = "Bearer"
    refresh_token: Optional[str] = None
    expires_in: Optional[int] = None
    scopes: Optional[tuple[str, ...]] = None


def _optional_str(payload: Mapping[str, Any], key: str, limit: int) -> Optional[str]:
    value = payload.get(key)
    if value is None:
        return None
    if not isinstance(value, str) or len(value) > limit:
        raise TokenEndpointError("invalid_token_response")
    return value.strip() or None


def parse_token_response(payload: Mapping[str, Any]) -> TokenSet:
    """Validate a token endpoint's JSON strictly.

    ``access_token`` must be a non-empty string; ``expires_in`` a positive
    integer when present; ``refresh_token`` and ``token_type`` strings when
    present; ``scope`` a string of space- or comma-separated scopes when
    present (an empty one counts as absent). Anything else raises
    ``TokenEndpointError("invalid_token_response")``.
    """
    access_token = _optional_str(payload, "access_token", _MAX_TOKEN_CHARS)
    if not access_token:
        raise TokenEndpointError("invalid_token_response")
    refresh_token = _optional_str(payload, "refresh_token", _MAX_TOKEN_CHARS)
    token_type = _optional_str(payload, "token_type", 64) or "Bearer"
    expires_in = payload.get("expires_in")
    if expires_in is not None and (
        isinstance(expires_in, bool) or not isinstance(expires_in, int) or expires_in <= 0
    ):
        raise TokenEndpointError("invalid_token_response")
    raw_scope = _optional_str(payload, "scope", _MAX_SCOPE_CHARS)
    scopes = tuple(s for s in re.split(r"[\s,]+", raw_scope) if s) if raw_scope else None
    return TokenSet(
        access_token=access_token,
        token_type=token_type,
        refresh_token=refresh_token,
        expires_in=expires_in,
        scopes=scopes or None,
    )


def _scope_key(scope: str) -> str:
    return scope.strip().lower()


def _scope_granted(wanted: str, returned: set[str]) -> bool:
    """True when *wanted* is in the returned set. Case-insensitive, and a
    URL-form scope matches its short form either way round (Microsoft may
    answer ``https://graph.microsoft.com/mail.read`` for ``Mail.Read``)."""
    key = _scope_key(wanted)
    if key in returned:
        return True
    return any(r.endswith("/" + key) or key.endswith("/" + r) for r in returned)


def granted_catalog_scopes(
    spec: OAuthSpec,
    requested: list[str],
    returned: Optional[tuple[str, ...]],
) -> list[str]:
    """Requested catalog scopes whose provider scopes were all granted.

    When the provider returns no scope list, the grant is taken to be what
    was requested (RFC 6749 5.1: scope is omitted when unchanged).
    """
    if returned is None:
        return list(requested)
    have = {_scope_key(s) for s in returned}
    granted: list[str] = []
    for scope in requested:
        wanted = spec.scope_map.get(scope, ())
        if wanted and all(_scope_granted(w, have) for w in wanted):
            granted.append(scope)
    return granted


def credentials_from_tokens(
    spec: OAuthSpec,
    tokens: TokenSet,
    *,
    requested: list[str],
    previous: Optional[Mapping[str, Any]] = None,
) -> dict[str, Any]:
    """The credentials dict an OAuth connector row stores: ``access_token``,
    ``refresh_token`` (when the provider issued one), ``expires_at`` (epoch
    seconds), ``token_type``, ``granted_scopes`` (provider scopes) and
    ``oauth_provider``.

    ``previous`` is the row being refreshed or reconnected: its refresh
    token is kept when the response carries none. When the response has no
    scope list, a sign-in (``requested`` non-empty, including a reconnect
    that asks for more) records the provider scopes of what it requested,
    so the list matches the row's granted catalog scopes; only a refresh
    (``requested`` empty) keeps the previous provider scopes.
    """
    previous = previous or {}
    if tokens.scopes is not None:
        provider_scopes = list(tokens.scopes)
    elif requested or not previous.get("granted_scopes"):
        provider_scopes = list(spec.provider_scopes(requested))
    else:
        provider_scopes = list(previous["granted_scopes"])
    credentials: dict[str, Any] = {
        "access_token": tokens.access_token,
        "token_type": tokens.token_type,
        "granted_scopes": provider_scopes,
        "oauth_provider": spec.provider,
    }
    refresh_token = tokens.refresh_token or previous.get("refresh_token")
    if refresh_token:
        credentials["refresh_token"] = refresh_token
    if tokens.expires_in is not None:
        credentials["expires_at"] = int(_clock()) + tokens.expires_in
    return credentials


# ---------------------------------------------------------------------------
# Drafts
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class FlowDraft:
    """The connector fields a sign-in will save. ``None`` means "the
    default" for a new connector and "unchanged" for a reconnect."""

    display_name: Optional[str] = None
    granted_scopes: Optional[tuple[str, ...]] = None
    permission_tier: Optional[PermissionTier] = None
    rate_limit_per_minute: Optional[int] = None
    connector_id: Optional[uuid.UUID] = None


def oauth_definition(provider: str) -> Optional[ConnectorDefinition]:
    """The registered connector whose broker segment is *provider*."""
    definition = connector_registry.definition_for_provider(provider)
    if definition is None or definition.auth.oauth is None:
        return None
    return definition


async def _prepare_draft(
    session: AsyncSession,
    *,
    user_id: uuid.UUID,
    definition: ConnectorDefinition,
    draft: FlowDraft,
) -> tuple[list[str], dict[str, Any]]:
    """Validate *draft*; return the catalog scopes to request and the JSON
    draft to store. A reconnect must name the caller's own row of this
    connector type, and asks for the union of its scopes and the new ones."""
    catalog = definition.scopes()
    known = set(catalog["read"]) | set(catalog["write"])
    chosen = list(draft.granted_scopes) if draft.granted_scopes else list(catalog["read"])
    unknown = sorted({s for s in chosen if s not in known})
    if unknown:
        raise OAuthFlowError(
            422,
            f"Unknown scope(s) for {definition.key}: {', '.join(unknown)}. "
            f"Allowed: {', '.join(sorted(known))}.",
        )
    if draft.rate_limit_per_minute is not None and not 1 <= draft.rate_limit_per_minute <= 600:
        raise OAuthFlowError(422, "rate_limit_per_minute must be between 1 and 600.")
    requested = list(dict.fromkeys(chosen))
    if draft.connector_id is not None:
        row = (
            await session.execute(
                select(ConnectorConfig.granted_scopes).where(
                    ConnectorConfig.id == draft.connector_id,
                    ConnectorConfig.user_id == user_id,
                    ConnectorConfig.connector_type == definition.key,
                )
            )
        ).first()
        if row is None:
            raise OAuthFlowError(404, "Connector not found")
        current = [s for s in (row.granted_scopes or []) if s in known]
        requested = list(dict.fromkeys([*current, *requested]))
    if not requested:
        raise OAuthFlowError(422, "Choose at least one permission to grant.")
    stored = {
        "display_name": draft.display_name,
        "permission_tier": draft.permission_tier.value if draft.permission_tier else None,
        "rate_limit_per_minute": draft.rate_limit_per_minute,
        "connector_id": str(draft.connector_id) if draft.connector_id else None,
    }
    return requested, stored


async def _cleanup_and_check_capacity(session: AsyncSession, user_id: uuid.UUID) -> None:
    """Delete old flows (one statement) and refuse a user with too many
    sign-ins still in flight."""
    now = _utcnow()
    cutoff = now - CLEANUP_AFTER
    await session.execute(
        delete(OAuthState)
        .where(or_(OAuthState.created_at < cutoff, OAuthState.expires_at < cutoff))
        .execution_options(synchronize_session=False)
    )
    in_flight = (
        await session.execute(
            select(func.count())
            .select_from(OAuthState)
            .where(
                OAuthState.user_id == user_id,
                OAuthState.status == OAuthFlowStatus.pending.value,
                OAuthState.expires_at > now,
            )
        )
    ).scalar_one()
    if in_flight >= MAX_PENDING_FLOWS_PER_USER:
        raise OAuthFlowError(
            429, "Too many sign-ins are in progress. Finish one or wait a few minutes."
        )


# ---------------------------------------------------------------------------
# Authorization-code flow
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class StartedFlow:
    flow_id: uuid.UUID
    authorization_url: str
    expires_at: datetime
    # Set only when ``browser_binding_required()``; the route sends it as a
    # cookie scoped to the callback path.
    binding: Optional[BrowserBinding] = None


async def start_authorization(
    session_factory: SessionFactory,
    *,
    user_id: uuid.UUID,
    definition: ConnectorDefinition,
    draft: FlowDraft,
) -> StartedFlow:
    """Create a pending flow row and return the provider consent URL.

    Raises ``OAuthNotConfigured`` (client id or secret unset) and
    ``OAuthFlowError`` (a bad draft, a method the connector lacks).
    """
    spec = definition.auth.oauth
    if spec is None or "oauth" not in definition.auth.methods or not spec.authorize_url:
        raise OAuthFlowError(422, f"{definition.label} does not support browser sign-in.")
    client = resolve_client(spec, label=definition.label)
    state = new_state()
    verifier = new_pkce_verifier()
    now = _utcnow()
    expires_at = now + FLOW_TTL
    flow_id = uuid.uuid4()
    async with session_factory() as session:
        requested, stored = await _prepare_draft(
            session, user_id=user_id, definition=definition, draft=draft
        )
        await _cleanup_and_check_capacity(session, user_id)
        session.add(
            OAuthState(
                id=flow_id,
                user_id=user_id,
                provider=spec.provider,
                connector_type=definition.key,
                kind=OAuthFlowKind.oauth.value,
                state_hash=hash_state(state),
                encrypted_secret=encrypt_credentials(verifier),
                requested_scopes=requested,
                draft=stored,
                status=OAuthFlowStatus.pending.value,
                expires_at=expires_at,
                created_at=now,
            )
        )
        await session.commit()
    url = build_authorization_url(
        spec,
        client=client,
        catalog_scopes=requested,
        state=state,
        verifier=verifier if spec.pkce else None,
    )
    logger.info("oauth_flow_started", provider=spec.provider, flow_id=str(flow_id))
    binding = browser_binding(state) if browser_binding_required() else None
    return StartedFlow(flow_id=flow_id, authorization_url=url, expires_at=expires_at, binding=binding)


@dataclass(frozen=True)
class _FlowSnapshot:
    """What completing a flow needs, read before any network call."""

    id: uuid.UUID
    user_id: uuid.UUID
    provider: str
    requested: list[str]
    draft: dict[str, Any]
    kind: str


def _snapshot(row: OAuthState) -> _FlowSnapshot:
    return _FlowSnapshot(
        id=row.id,
        user_id=row.user_id,
        provider=row.provider,
        requested=list(row.requested_scopes or []),
        draft=dict(row.draft or {}),
        kind=row.kind,
    )


async def complete_callback(
    session_factory: SessionFactory,
    *,
    provider: str,
    code: Optional[str],
    state: Optional[str],
    provider_error: Optional[str],
    cookies: Optional[Mapping[str, str]] = None,
) -> bool:
    """Finish a browser flow from the provider's redirect. True on success.

    Never raises for a bad request: every failure is logged (without the
    code or state) and, when the state matched a flow, recorded on that
    flow and audited to its user.

    The state ties the callback to the user who STARTED the flow. Without
    more, whoever approves a consent link would link THEIR provider account
    to the starter's connector, so a user on a shared server could send
    their link to someone else and receive that person's tokens. Two things
    stop that. With a loopback ``OAUTH_REDIRECT_BASE`` (the default, and
    the desktop app, whose consent opens in the system browser) the
    provider can only redirect to a browser on the server's own machine.
    With any other base the start response set a binding cookie (see
    ``browser_binding``) and *cookies* must carry it back: a callback from
    another browser ends the flow before the code is exchanged.
    """
    definition = oauth_definition(provider)
    if definition is None or definition.auth.oauth is None:
        logger.warning("oauth_callback_rejected", provider=provider[:32], reason="unknown_provider")
        return False
    spec = definition.auth.oauth
    if not state or not _STATE_RE.match(state):
        logger.warning("oauth_callback_rejected", provider=provider, reason="missing_state")
        return False

    async with session_factory() as session:
        row = (
            await session.execute(select(OAuthState).where(OAuthState.state_hash == hash_state(state)))
        ).scalar_one_or_none()
        if row is None:
            logger.warning("oauth_callback_rejected", provider=provider, reason="unknown_state")
            return False
        flow = _snapshot(row)
        reason = _callback_row_problem(row, provider)
        verifier_blob = row.encrypted_secret
    if reason is None and browser_binding_required() and not _binding_matches(state, cookies):
        reason = "other_browser"
    if reason is not None:
        if reason == "expired":
            await _end_flow(session_factory, flow.id, OAuthFlowStatus.expired, MSG_EXPIRED)
        elif reason == "other_browser":
            await _end_flow(session_factory, flow.id, OAuthFlowStatus.error, MSG_OTHER_BROWSER)
        await _audit(session_factory, flow, definition, success=False, reason=reason)
        logger.warning("oauth_callback_rejected", provider=provider, reason=reason, flow_id=str(flow.id))
        return False

    # Consume the state: exactly one callback can move it out of pending.
    if not await _transition(
        session_factory, flow.id, OAuthFlowStatus.pending, OAuthFlowStatus.exchanging, require_unexpired=True
    ):
        await _audit(session_factory, flow, definition, success=False, reason="state_reused")
        logger.warning("oauth_callback_rejected", provider=provider, reason="state_reused", flow_id=str(flow.id))
        return False

    if provider_error is not None or not code:
        denied = provider_error == "access_denied"
        reason = "access_denied" if denied else ("provider_error" if provider_error else "missing_code")
        await _end_flow(
            session_factory, flow.id, OAuthFlowStatus.error, MSG_CANCELLED if denied else MSG_FAILED,
            from_status=OAuthFlowStatus.exchanging,
        )
        await _audit(session_factory, flow, definition, success=False, reason=reason)
        return False
    if len(code) > _MAX_CODE_CHARS or not _CODE_RE.match(code):
        await _end_flow(
            session_factory, flow.id, OAuthFlowStatus.error, MSG_FAILED, from_status=OAuthFlowStatus.exchanging
        )
        await _audit(session_factory, flow, definition, success=False, reason="malformed_code")
        return False

    try:
        client = resolve_client(spec, label=definition.label)
        verifier = decrypt_credentials(verifier_blob) if verifier_blob else ""
        data = {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": redirect_uri(spec.provider),
            "client_id": client.client_id,
        }
        if client.client_secret:
            data["client_secret"] = client.client_secret
        if spec.pkce and verifier:
            data["code_verifier"] = verifier
        token_client = _token_client(definition)
        try:
            tokens = parse_token_response(await token_client.post_form(spec.token_url, data))
        finally:
            await token_client.close()
    except Exception as exc:  # noqa: BLE001 - token errors, config, an unreadable verifier
        failure = exc.code if isinstance(exc, TokenEndpointError) else type(exc).__name__
        await _end_flow(
            session_factory, flow.id, OAuthFlowStatus.error, MSG_FAILED, from_status=OAuthFlowStatus.exchanging
        )
        await _audit(session_factory, flow, definition, success=False, reason=f"exchange_failed:{failure}")
        logger.warning("oauth_exchange_failed", provider=provider, flow_id=str(flow.id), reason=failure)
        return False

    return await _finish_or_fail(
        session_factory, flow, definition, tokens, from_status=OAuthFlowStatus.exchanging
    )


def _callback_row_problem(row: OAuthState, provider: str) -> Optional[str]:
    """Why this flow row cannot be completed by a callback, or None."""
    if row.provider != provider:
        return "provider_mismatch"
    if row.kind != OAuthFlowKind.oauth.value:
        return "not_a_browser_flow"
    if row.status != OAuthFlowStatus.pending.value:
        return "state_reused"
    if _as_utc(row.expires_at) <= _utcnow():
        return "expired"
    return None


# ---------------------------------------------------------------------------
# Completion (shared by the callback and the device poller)
# ---------------------------------------------------------------------------


async def _transition(
    session_factory: SessionFactory,
    flow_id: uuid.UUID,
    from_status: OAuthFlowStatus,
    to_status: OAuthFlowStatus,
    *,
    require_unexpired: bool = False,
) -> bool:
    """Conditional status change; True when this caller made it. The
    ``WHERE status = from_status`` is what makes a state single use even
    when two callbacks race."""
    conditions = [OAuthState.id == flow_id, OAuthState.status == from_status.value]
    if require_unexpired:
        conditions.append(OAuthState.expires_at > _utcnow())
    async with session_factory() as session:
        result = await session.execute(
            update(OAuthState)
            .where(*conditions)
            .values(status=to_status.value)
            .execution_options(synchronize_session=False)
        )
        await session.commit()
        return (getattr(result, "rowcount", 0) or 0) == 1


async def _end_flow(
    session_factory: SessionFactory,
    flow_id: uuid.UUID,
    status: OAuthFlowStatus,
    message: str,
    *,
    from_status: OAuthFlowStatus = OAuthFlowStatus.pending,
) -> None:
    """Mark a flow failed or expired and wipe its secret."""
    async with session_factory() as session:
        await session.execute(
            update(OAuthState)
            .where(OAuthState.id == flow_id, OAuthState.status == from_status.value)
            .values(status=status.value, error=message, encrypted_secret=None)
            .execution_options(synchronize_session=False)
        )
        await session.commit()


async def _finish_or_fail(
    session_factory: SessionFactory,
    flow: _FlowSnapshot,
    definition: ConnectorDefinition,
    tokens: TokenSet,
    *,
    from_status: OAuthFlowStatus,
) -> bool:
    """Complete the flow, or record why it failed. Never raises."""
    try:
        await _finish_flow(session_factory, flow, definition, tokens, from_status=from_status)
        return True
    except _FlowAborted as exc:
        message, reason = exc.message, exc.reason
    except Exception as exc:  # noqa: BLE001 - a DB failure must still close the flow
        message, reason = MSG_FAILED, f"save_failed:{type(exc).__name__}"
    try:
        await _end_flow(session_factory, flow.id, OAuthFlowStatus.error, message, from_status=from_status)
    except Exception as exc:  # noqa: BLE001 - the flow then simply expires
        logger.error("oauth_flow_close_failed", flow_id=str(flow.id), error_type=type(exc).__name__)
    await _audit(session_factory, flow, definition, success=False, reason=reason)
    logger.warning("oauth_flow_failed", provider=flow.provider, flow_id=str(flow.id), reason=reason)
    return False


async def _finish_flow(
    session_factory: SessionFactory,
    flow: _FlowSnapshot,
    definition: ConnectorDefinition,
    tokens: TokenSet,
    *,
    from_status: OAuthFlowStatus,
) -> uuid.UUID:
    """Save the connector and close the flow in ONE transaction.

    Creates the ConnectorConfig, or updates the reconnect row (which must
    still belong to the flow's user), marks the flow complete with the
    connector id and a wiped secret, and audits the connection. The flow
    update is conditional on *from_status*; if another task got there
    first, everything rolls back.

    Deliberate deviation from spec 4.3 ("the row is deleted in the same
    transaction"): the row is kept, closed (status ``complete``, secret
    wiped) in that transaction, and deleted by the cleanup of any later
    start or device request once it is an hour old. Single use is unchanged: only a ``pending`` row
    can be consumed. Keeping it lets the UI's status poll by flow id see
    the result, and keeping the state HMAC lets a replayed callback be
    audited to the flow's user as ``state_reused`` instead of vanishing as
    an unknown state. The HMAC of a spent one-time state reveals nothing.
    """
    spec = definition.auth.oauth
    assert spec is not None
    granted = granted_catalog_scopes(spec, flow.requested, tokens.scopes)
    if not granted:
        raise _FlowAborted(MSG_NO_SCOPES, "no_scopes_granted")
    draft = flow.draft
    async with session_factory() as session:
        reconnect_id = draft.get("connector_id")
        if reconnect_id:
            config = (
                await session.execute(
                    select(ConnectorConfig).where(
                        ConnectorConfig.id == uuid.UUID(str(reconnect_id)),
                        ConnectorConfig.user_id == flow.user_id,
                        ConnectorConfig.connector_type == definition.key,
                    )
                )
            ).scalar_one_or_none()
            if config is None:
                raise _FlowAborted(MSG_CONNECTOR_GONE, "reconnect_target_missing")
            previous = _decrypt_row(config.encrypted_credentials)
            credentials = credentials_from_tokens(
                spec,
                tokens,
                requested=flow.requested,
                previous=previous if previous.get("oauth_provider") == spec.provider else None,
            )
            config.encrypted_credentials = encrypt_credentials(json.dumps(credentials))
            config.auth_method = AuthMethod.oauth2
            config.granted_scopes = granted
            config.is_active = True
            if draft.get("display_name"):
                config.display_name = draft["display_name"]
            if draft.get("permission_tier"):
                config.permission_tier = PermissionTier(draft["permission_tier"])
            if draft.get("rate_limit_per_minute"):
                config.rate_limit_per_minute = int(draft["rate_limit_per_minute"])
        else:
            credentials = credentials_from_tokens(spec, tokens, requested=flow.requested)
            config = ConnectorConfig(
                user_id=flow.user_id,
                connector_type=definition.key,
                display_name=draft.get("display_name") or definition.label,
                auth_method=AuthMethod.oauth2,
                encrypted_credentials=encrypt_credentials(json.dumps(credentials)),
                granted_scopes=granted,
                permission_tier=PermissionTier(draft.get("permission_tier") or PermissionTier.user_confirm.value),
                rate_limit_per_minute=int(draft.get("rate_limit_per_minute") or 30),
            )
            session.add(config)
        await session.flush()
        connector_id = config.id
        result = await session.execute(
            update(OAuthState)
            .where(OAuthState.id == flow.id, OAuthState.status == from_status.value)
            .values(
                status=OAuthFlowStatus.complete.value,
                connector_id=connector_id,
                encrypted_secret=None,
                error=None,
            )
            .execution_options(synchronize_session=False)
        )
        if (getattr(result, "rowcount", 0) or 0) != 1:
            await session.rollback()
            logger.warning("oauth_flow_already_closed", flow_id=str(flow.id))
            raise _FlowAborted(MSG_FAILED, "flow_already_closed")
        await append_auth_event(
            session,
            user_id=flow.user_id,
            action="oauth_connected",
            status=AuditStatus.approved,
            endpoint=_audit_endpoint(flow),
            details={
                "connector_type": definition.key,
                "connector_id": str(connector_id),
                "flow": flow.kind,
                "granted_scopes": granted,
                "reconnect": bool(reconnect_id),
            },
        )
        await session.commit()
    logger.info(
        "oauth_flow_complete",
        provider=flow.provider,
        flow_id=str(flow.id),
        connector_id=str(connector_id),
        granted=granted,
    )
    return connector_id


def _decrypt_row(blob: bytes) -> dict[str, Any]:
    try:
        value = json.loads(decrypt_credentials(blob))
    except Exception:  # noqa: BLE001 - an unreadable old row is simply replaced
        return {}
    return value if isinstance(value, dict) else {}


def _audit_endpoint(flow: _FlowSnapshot) -> str:
    if flow.kind == OAuthFlowKind.device.value:
        return f"/api/oauth/{flow.provider}/device"
    return f"/api/oauth/callback/{flow.provider}"


async def _audit(
    session_factory: SessionFactory,
    flow: _FlowSnapshot,
    definition: ConnectorDefinition,
    *,
    success: bool,
    reason: str,
) -> None:
    """Record a failed (or other non-connect) outcome to the flow's user.
    An audit failure is logged, never raised: the page must still render."""
    try:
        async with session_factory() as session:
            await append_auth_event(
                session,
                user_id=flow.user_id,
                action="oauth_connected" if success else "oauth_failed",
                status=AuditStatus.approved if success else AuditStatus.blocked,
                endpoint=_audit_endpoint(flow),
                reason=reason,
                details={"connector_type": definition.key, "flow": flow.kind},
            )
            await session.commit()
    except Exception as exc:  # noqa: BLE001 - see docstring
        logger.error("oauth_audit_failed", flow_id=str(flow.id), error_type=type(exc).__name__)


# ---------------------------------------------------------------------------
# Device flow
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class DeviceFlowStarted:
    flow_id: uuid.UUID
    user_code: str
    verification_uri: str
    expires_at: datetime
    interval: int


@dataclass(frozen=True)
class _DeviceCode:
    device_code: str
    user_code: str
    verification_uri: str
    expires_in: int
    interval: int


def parse_device_response(payload: Mapping[str, Any]) -> _DeviceCode:
    """Validate a device authorization response (RFC 8628 3.2)."""
    device_code = payload.get("device_code")
    user_code = payload.get("user_code")
    # Google names it verification_url.
    uri = payload.get("verification_uri") or payload.get("verification_url")
    expires_in = payload.get("expires_in")
    interval = payload.get("interval", DEFAULT_POLL_INTERVAL_S)
    if (
        not isinstance(device_code, str)
        or not device_code
        or len(device_code) > _MAX_TOKEN_CHARS
        or not isinstance(user_code, str)
        or not user_code
        or len(user_code) > _MAX_USER_CODE_CHARS
        or not isinstance(uri, str)
        or not uri.startswith("https://")
        or len(uri) > _MAX_URI_CHARS
        or isinstance(expires_in, bool)
        or not isinstance(expires_in, int)
        or isinstance(interval, bool)
        or not isinstance(interval, int)
    ):
        raise TokenEndpointError("invalid_device_response")
    return _DeviceCode(
        device_code=device_code,
        user_code=user_code,
        verification_uri=uri,
        expires_in=max(DEVICE_MIN_TTL_S, min(expires_in, DEVICE_MAX_TTL_S)),
        interval=max(1, min(interval, MAX_POLL_INTERVAL_S)),
    )


async def start_device_flow(
    session_factory: SessionFactory,
    *,
    user_id: uuid.UUID,
    definition: ConnectorDefinition,
    draft: FlowDraft,
) -> DeviceFlowStarted:
    """Ask the provider for a device code, store the flow, start its poller.

    Raises ``OAuthNotConfigured``, ``OAuthFlowError`` (bad draft, no device
    support) and ``TokenEndpointError`` (the provider refused).

    Unlike a browser flow, a device code cannot be bound to a browser: any
    person who types ``user_code`` on the provider's page links their
    account to this user's connector (RFC 8628 section 5.4). The code is
    shown only to the user who started the flow; SECURITY.md lists the
    shared-server risk.
    """
    spec = definition.auth.oauth
    if spec is None or "device" not in definition.auth.methods or not spec.device_code_url:
        raise OAuthFlowError(422, f"{definition.label} does not support device sign-in.")
    client = resolve_client(spec, label=definition.label)
    async with session_factory() as session:
        requested, stored = await _prepare_draft(
            session, user_id=user_id, definition=definition, draft=draft
        )
        await _cleanup_and_check_capacity(session, user_id)
        await session.commit()

    request = {"client_id": client.client_id, "scope": " ".join(spec.provider_scopes(requested))}
    flow_id = uuid.uuid4()
    # The poller reuses this client (one per flow) and closes it; until the
    # poller owns it, any failure here closes it.
    token_client = _token_client(definition)
    try:
        device = parse_device_response(await token_client.post_form(spec.device_code_url, request))
        now = _utcnow()
        expires_at = now + timedelta(seconds=device.expires_in)
        async with session_factory() as session:
            session.add(
                OAuthState(
                    id=flow_id,
                    user_id=user_id,
                    provider=spec.provider,
                    connector_type=definition.key,
                    kind=OAuthFlowKind.device.value,
                    state_hash=None,
                    encrypted_secret=encrypt_credentials(device.device_code),
                    requested_scopes=requested,
                    draft=stored,
                    device_info={
                        "user_code": device.user_code,
                        "verification_uri": device.verification_uri,
                        "interval": device.interval,
                    },
                    status=OAuthFlowStatus.pending.value,
                    expires_at=expires_at,
                    created_at=now,
                )
            )
            await session.commit()
    except BaseException:
        await token_client.close()
        raise

    flow = _FlowSnapshot(
        id=flow_id,
        user_id=user_id,
        provider=spec.provider,
        requested=requested,
        draft=stored,
        kind=OAuthFlowKind.device.value,
    )
    spawn(
        _poll_device_flow(
            session_factory,
            flow=flow,
            definition=definition,
            client=client,
            token_client=token_client,
            device_code=device.device_code,
            interval=device.interval,
            deadline=_clock() + device.expires_in,
        ),
        name=f"oauth-device-{flow_id}",
    )
    logger.info("oauth_device_flow_started", provider=spec.provider, flow_id=str(flow_id))
    return DeviceFlowStarted(
        flow_id=flow_id,
        user_code=device.user_code,
        verification_uri=device.verification_uri,
        expires_at=expires_at,
        interval=device.interval,
    )


async def _poll_device_flow(
    session_factory: SessionFactory,
    *,
    flow: _FlowSnapshot,
    definition: ConnectorDefinition,
    client: OAuthClient,
    token_client: _TokenClient,
    device_code: str,
    interval: int,
    deadline: float,
) -> None:
    """Poll the token endpoint until the user approves, denies, or the code
    expires (RFC 8628 3.4 and 3.5). Owns and closes *token_client*."""
    spec = definition.auth.oauth
    assert spec is not None
    request = {"grant_type": DEVICE_GRANT_TYPE, "device_code": device_code, "client_id": client.client_id}
    if client.client_secret:
        request["client_secret"] = client.client_secret
    failures = 0
    try:
        while True:
            await _sleep(interval)
            if _clock() >= deadline:
                await _device_failed(session_factory, flow, definition, OAuthFlowStatus.expired, MSG_EXPIRED, "expired")
                return
            try:
                tokens = parse_token_response(await token_client.post_form(spec.token_url, request))
            except TokenEndpointError as exc:
                if exc.code == "authorization_pending":
                    failures = 0
                    continue
                if exc.code == "slow_down":
                    failures = 0
                    interval = min(interval + SLOW_DOWN_STEP_S, MAX_POLL_INTERVAL_S)
                    await _store_interval(session_factory, flow.id, interval)
                    continue
                if exc.code == "expired_token":
                    await _device_failed(session_factory, flow, definition, OAuthFlowStatus.expired, MSG_EXPIRED, "expired")
                    return
                if exc.code in ("access_denied", "authorization_declined"):
                    await _device_failed(session_factory, flow, definition, OAuthFlowStatus.error, MSG_CANCELLED, "access_denied")
                    return
                transient = exc.code is None and (exc.status is None or exc.status >= 500 or exc.status == 429)
                failures += 1
                if transient and failures < MAX_POLL_FAILURES:
                    continue
                await _device_failed(
                    session_factory, flow, definition, OAuthFlowStatus.error, MSG_FAILED,
                    f"token_error:{exc.code or exc.status or 'network'}",
                )
                return
            await _finish_or_fail(session_factory, flow, definition, tokens, from_status=OAuthFlowStatus.pending)
            return
    finally:
        await token_client.close()


async def _device_failed(
    session_factory: SessionFactory,
    flow: _FlowSnapshot,
    definition: ConnectorDefinition,
    status: OAuthFlowStatus,
    message: str,
    reason: str,
) -> None:
    await _end_flow(session_factory, flow.id, status, message)
    await _audit(session_factory, flow, definition, success=False, reason=reason)
    logger.info("oauth_device_flow_ended", provider=flow.provider, flow_id=str(flow.id), reason=reason)


async def _store_interval(session_factory: SessionFactory, flow_id: uuid.UUID, interval: int) -> None:
    async with session_factory() as session:
        row = await session.get(OAuthState, flow_id)
        if row is not None and row.device_info:
            row.device_info = {**row.device_info, "interval": interval}
            await session.commit()


# ---------------------------------------------------------------------------
# Status
# ---------------------------------------------------------------------------


async def flow_status(
    session_factory: SessionFactory,
    *,
    user_id: uuid.UUID,
    provider: str,
    flow_id: uuid.UUID,
) -> Optional[dict[str, Any]]:
    """The UI's view of a flow, or None when it is not this user's flow for
    this provider (the route answers 404 either way)."""
    async with session_factory() as session:
        row = (
            await session.execute(
                select(OAuthState).where(
                    OAuthState.id == flow_id,
                    OAuthState.user_id == user_id,
                    OAuthState.provider == provider,
                )
            )
        ).scalar_one_or_none()
        if row is None:
            return None
        status = row.status
        expires_at = _as_utc(row.expires_at)
        body: dict[str, Any] = {}
        if status in (OAuthFlowStatus.pending.value, OAuthFlowStatus.exchanging.value):
            status = OAuthFlowStatus.expired.value if expires_at <= _utcnow() else OAuthFlowStatus.pending.value
        body["status"] = status
        if status == OAuthFlowStatus.complete.value and row.connector_id is not None:
            body["connector_id"] = str(row.connector_id)
        if status == OAuthFlowStatus.error.value:
            body["error"] = row.error or MSG_FAILED
        if status == OAuthFlowStatus.expired.value:
            body["error"] = MSG_EXPIRED
        if row.kind == OAuthFlowKind.device.value and row.device_info:
            body.update(
                {
                    "user_code": row.device_info.get("user_code"),
                    "verification_uri": row.device_info.get("verification_uri"),
                    "expires_at": expires_at.isoformat(),
                    "interval": row.device_info.get("interval"),
                }
            )
        return body


# ---------------------------------------------------------------------------
# Refresh
# ---------------------------------------------------------------------------

# One lock per connector row. Weak values: a lock disappears once no
# refresh holds it, so the map never grows with rows long gone.
_refresh_locks: "weakref.WeakValueDictionary[str, asyncio.Lock]" = weakref.WeakValueDictionary()


def _refresh_lock(config_id: uuid.UUID | str) -> asyncio.Lock:
    key = str(config_id)
    lock = _refresh_locks.get(key)
    if lock is None:
        lock = asyncio.Lock()
        _refresh_locks[key] = lock
    return lock


def _needs_refresh(credentials: Mapping[str, Any], *, force: bool) -> bool:
    if force:
        return True
    expires_at = credentials.get("expires_at")
    if isinstance(expires_at, bool) or not isinstance(expires_at, (int, float)):
        return False
    return expires_at - _clock() <= REFRESH_MARGIN_S


def _is_broker_row(credentials: Mapping[str, Any], spec: Optional[OAuthSpec]) -> bool:
    return (
        spec is not None
        and credentials.get("oauth_provider") == spec.provider
        and bool(credentials.get("refresh_token"))
    )


async def persist_credentials(
    session_factory: SessionFactory,
    config_id: uuid.UUID | str,
    credentials: Mapping[str, Any],
) -> None:
    """Encrypt and store *credentials* on connector row *config_id*."""
    row_id = config_id if isinstance(config_id, uuid.UUID) else uuid.UUID(str(config_id))
    async with session_factory() as session:
        await session.execute(
            update(ConnectorConfig)
            .where(ConnectorConfig.id == row_id)
            .values(encrypted_credentials=encrypt_credentials(json.dumps(dict(credentials))))
            .execution_options(synchronize_session=False)
        )
        await session.commit()


async def _load_credentials(
    session_factory: SessionFactory, config_id: uuid.UUID | str
) -> Optional[dict[str, Any]]:
    row_id = config_id if isinstance(config_id, uuid.UUID) else uuid.UUID(str(config_id))
    async with session_factory() as session:
        blob = (
            await session.execute(
                select(ConnectorConfig.encrypted_credentials).where(ConnectorConfig.id == row_id)
            )
        ).scalar_one_or_none()
    if blob is None:
        return None
    return _decrypt_row(blob)


def reconnect_message(label: str) -> str:
    return f"{label} needs to be reconnected. Reconnect it in Connectors."


# Set on a row's stored credentials when the provider refused its refresh
# token, so the Connectors card can say "Needs reconnect". A reconnect or a
# pasted token replaces the whole blob, and a later successful refresh drops
# it, so it clears itself.
NEEDS_RECONNECT_KEY = "needs_reconnect"


class ReconnectRequired(AuthenticationError):
    """The provider refused the stored refresh token (a dead grant)."""


def needs_reconnect(credentials: Mapping[str, Any]) -> bool:
    """True when the row's last refresh was refused by the provider."""
    return credentials.get(NEEDS_RECONNECT_KEY) is True


async def _mark_needs_reconnect(
    session_factory: SessionFactory, config_id: uuid.UUID | str, refresh_token: Any
) -> None:
    """Flag the row, unless it changed since the refused refresh.

    The update is a compare-and-swap on the stored blob, so a reconnect that
    lands meanwhile (the callback does not take the refresh lock) is never
    overwritten with the dead tokens. Best effort: the flag only drives the
    UI, so a failure here is logged and the caller's error still surfaces.
    """
    row_id = config_id if isinstance(config_id, uuid.UUID) else uuid.UUID(str(config_id))
    try:
        async with session_factory() as session:
            blob = (
                await session.execute(
                    select(ConnectorConfig.encrypted_credentials).where(ConnectorConfig.id == row_id)
                )
            ).scalar_one_or_none()
            if blob is None:
                return
            stored = _decrypt_row(blob)
            if stored.get("refresh_token") != refresh_token or needs_reconnect(stored):
                return
            stored[NEEDS_RECONNECT_KEY] = True
            await session.execute(
                update(ConnectorConfig)
                .where(ConnectorConfig.id == row_id, ConnectorConfig.encrypted_credentials == blob)
                .values(encrypted_credentials=encrypt_credentials(json.dumps(stored)))
                .execution_options(synchronize_session=False)
            )
            await session.commit()
    except Exception as exc:  # noqa: BLE001 - a UI hint must not mask the auth error
        logger.warning("oauth_needs_reconnect_not_saved", config_id=str(row_id), error_type=type(exc).__name__)


def client_config_message(label: str) -> str:
    """The provider refused this server's OAuth client (not the user's
    grant). Names no setting value."""
    return (
        f"{label} refused this server's sign-in configuration (OAuth client id or secret). "
        "Ask the administrator to check it; reconnecting will not help until it is fixed."
    )


async def ensure_fresh_credentials(
    session_factory: SessionFactory,
    *,
    config_id: uuid.UUID | str,
    connector_type: str,
    credentials: dict[str, Any],
    force: bool = False,
) -> dict[str, Any]:
    """Credentials whose access token is good for at least 120 s more.

    Acts only on broker rows (``oauth_provider`` equals the connector's
    provider and a refresh token is stored); every other row, including a
    pasted token, is returned unchanged. The refresh runs under a
    per-row lock and re-reads the row inside it, so concurrent callers
    refresh once and the rest pick up the stored result. The new tokens are
    persisted before they are returned; a rotated refresh token replaces
    the old one, a missing one keeps it.

    Raises ``ReconnectRequired`` (an ``AuthenticationError``, "<Label> needs
    to be reconnected ...") when the provider refuses the refresh token, and
    flags the row with ``NEEDS_RECONNECT_KEY`` for the UI; ``AuthenticationError``
    naming the server's sign-in configuration when it refuses our OAuth
    client (``invalid_client`` and similar, which a reconnect cannot fix),
    and ``ConnectorError`` for a transient failure.
    """
    definition = connector_registry.get_definition(connector_type)
    spec = definition.auth.oauth if definition is not None else None
    if definition is None or spec is None or not _is_broker_row(credentials, spec):
        return credentials
    if not _needs_refresh(credentials, force=force):
        return credentials

    async with _refresh_lock(config_id):
        current = await _load_credentials(session_factory, config_id)
        if current is None:
            raise AuthenticationError(reconnect_message(definition.label))
        if not _is_broker_row(current, spec):
            return current
        already_refreshed = current.get("access_token") != credentials.get("access_token")
        if already_refreshed and not _needs_refresh(current, force=False):
            return current
        try:
            refreshed = await _refresh(definition, spec, current)
        except ReconnectRequired:
            await _mark_needs_reconnect(session_factory, config_id, current.get("refresh_token"))
            raise
        await persist_credentials(session_factory, config_id, refreshed)
        logger.info("oauth_token_refreshed", connector_type=connector_type, config_id=str(config_id))
        return refreshed


async def _refresh(
    definition: ConnectorDefinition, spec: OAuthSpec, current: dict[str, Any]
) -> dict[str, Any]:
    try:
        client = resolve_client(spec, label=definition.label)
    except OAuthNotConfigured as exc:
        raise AuthenticationError(str(exc)) from None
    data = {
        "grant_type": "refresh_token",
        "refresh_token": str(current["refresh_token"]),
        "client_id": client.client_id,
    }
    if client.client_secret:
        data["client_secret"] = client.client_secret
    token_client = _token_client(definition)
    try:
        tokens = parse_token_response(await token_client.post_form(spec.token_url, data))
    except TokenEndpointError as exc:
        if exc.code in _CLIENT_CONFIG_CODES:
            # Our client id or secret is wrong or rotated: sending the user
            # to reconnect would fail the same way.
            logger.error("oauth_refresh_client_rejected", connector_type=definition.key, code=exc.code)
            raise AuthenticationError(client_config_message(definition.label)) from None
        if exc.code in _DEAD_GRANT_CODES or exc.status in (400, 401):
            logger.warning("oauth_refresh_rejected", connector_type=definition.key, code=exc.code)
            raise ReconnectRequired(reconnect_message(definition.label)) from None
        logger.warning("oauth_refresh_failed", connector_type=definition.key, code=exc.code, status=exc.status)
        raise ConnectorError(
            f"Could not refresh the {definition.label} sign-in right now. Try again shortly."
        ) from None
    finally:
        await token_client.close()
    fresh = credentials_from_tokens(spec, tokens, requested=[], previous=current)
    refreshed = {**current, **fresh}
    refreshed.pop(NEEDS_RECONNECT_KEY, None)
    if "expires_at" not in fresh:
        # A stale expiry would make every later call refresh again.
        refreshed.pop("expires_at", None)
    return refreshed


# ---------------------------------------------------------------------------
# Revoke
# ---------------------------------------------------------------------------


def schedule_revoke(
    connector_type: str,
    credentials: dict[str, Any],
    *,
    user_id: uuid.UUID | str,
    session_factory: Optional[SessionFactory] = None,
) -> Optional[asyncio.Task[None]]:
    """Revoke a deleted connector's grant at the provider, in the background.

    Call only AFTER the delete has committed. Best effort: builds the
    connector, authenticates and calls ``revoke()``; the outcome is
    audited to *user_id* (when that user still exists) and logged. Never
    raises; returns the task (None when no event loop is running).
    """
    try:
        return spawn(
            _revoke(connector_type, dict(credentials), user_id=str(user_id), session_factory=session_factory),
            name=f"oauth-revoke-{connector_type}",
        )
    except RuntimeError:
        logger.warning("oauth_revoke_not_scheduled", connector_type=connector_type)
        return None


async def _revoke(
    connector_type: str,
    credentials: dict[str, Any],
    *,
    user_id: str,
    session_factory: Optional[SessionFactory],
) -> None:
    from services.connectors.factory import create_connector

    outcome = "failed"
    try:
        connector = create_connector(connector_type, credentials)
        try:
            await connector.authenticate(credentials)
            outcome = "revoked" if await connector.revoke() else "not_supported"
        finally:
            await connector.close()
    except Exception as exc:  # noqa: BLE001 - best effort by design
        logger.warning("oauth_revoke_failed", connector_type=connector_type, error_type=type(exc).__name__)
    logger.info("oauth_revoke_outcome", connector_type=connector_type, outcome=outcome)
    factory = session_factory or _default_session_factory()
    try:
        async with factory() as session:
            await append_auth_event(
                session,
                user_id=user_id,
                action="oauth_revoked",
                status=AuditStatus.blocked if outcome == "failed" else AuditStatus.approved,
                endpoint="/api/connectors",
                reason=outcome,
                details={"connector_type": connector_type},
            )
            await session.commit()
    except Exception as exc:  # noqa: BLE001 - the user may be gone (account deletion)
        logger.info("oauth_revoke_audit_skipped", connector_type=connector_type, error_type=type(exc).__name__)


# ---------------------------------------------------------------------------
# Background tasks
# ---------------------------------------------------------------------------

_background_tasks: set[asyncio.Task[None]] = set()


def _task_done(task: asyncio.Task[None]) -> None:
    _background_tasks.discard(task)
    if task.cancelled():
        return
    exc = task.exception()
    if exc is not None:
        logger.error("oauth_background_task_failed", task=task.get_name(), error_type=type(exc).__name__)


def spawn(coro: Coroutine[Any, Any, None], *, name: str) -> asyncio.Task[None]:
    """Run *coro* as a tracked background task (kept referenced, logged on
    failure, cancelled at shutdown). Raises RuntimeError with no loop."""
    try:
        task = asyncio.get_running_loop().create_task(coro, name=name)
    except RuntimeError:
        coro.close()
        raise
    _background_tasks.add(task)
    task.add_done_callback(_task_done)
    return task


def background_tasks() -> frozenset[asyncio.Task[None]]:
    """The broker's running tasks (for tests and diagnostics)."""
    return frozenset(_background_tasks)


async def shutdown_background_tasks() -> None:
    """Cancel every poller and revoke task and wait for them to stop."""
    tasks = list(_background_tasks)
    for task in tasks:
        task.cancel()
    if tasks:
        await asyncio.gather(*tasks, return_exceptions=True)
    _background_tasks.clear()
