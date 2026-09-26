"""Implements the Google Workspace connector: Gmail, Calendar, Drive, Docs, Sheets
and Contacts actions, token refresh, health check and revoke, plus its
``DEFINITION`` for the connector registry.

Why it exists: the registry-driven factory builds this class for every Google
tool call; the OAuth broker (services/connectors/oauth.py) signs users in with
the ``OAuthSpec`` declared here, and legacy rows keep working with a pasted
access token (plus optional refresh token and client pair). The per-API action
groups live in ``services/connectors/google_api/`` (one mixin per API); this
module assembles them, owns sign-in state and declares scopes, network reach
and permission keys.

External services: Google's OAuth endpoints (oauth2.googleapis.com,
accounts.google.com) and the Gmail, Calendar, Drive, Docs, Sheets and People
REST APIs. Depends on ``base``, ``definition`` and ``google_api``.
"""

from __future__ import annotations

import base64
import hashlib
import secrets
from typing import Any, Optional
from urllib.parse import urlencode

import structlog

from .base import AuthenticationError, ConnectorError, RateLimitExceededError
from .definition import (
    AuthSpec,
    ConnectorDefinition,
    CredentialField,
    NetworkSpec,
    OAuthSpec,
    ToolSpec,
)
from .google_api.calendar import CALENDAR_ACTIONS, CalendarActions
from .google_api.client import (
    AUTHORIZE_URL,
    CALENDAR_API,
    DRIVE_API,
    GMAIL_API,
    PEOPLE_API,
    REVOKE_URL,
    SCOPE_BASE,
    TOKEN_URL,
    error_status,
)
from .google_api.contacts import CONTACTS_ACTIONS, ContactsActions
from .google_api.docs import DOCS_ACTIONS, DocsActions
from .google_api.drive import DRIVE_ACTIONS, DriveActions
from .google_api.gmail import GMAIL_ACTIONS, GmailActions
from .google_api.sheets import SHEETS_ACTIONS, SheetsActions

logger = structlog.get_logger(__name__)

# The tool catalog. Each Google surface keeps its own permission key (gmail,
# google_calendar, google_drive, google_docs, google_sheets, google_contacts)
# so each has its own policy rows. The legacy Gmail and Calendar actions come
# first, in their original order.
ACTIONS: tuple[ToolSpec, ...] = (
    GMAIL_ACTIONS + CALENDAR_ACTIONS + DRIVE_ACTIONS + DOCS_ACTIONS + SHEETS_ACTIONS + CONTACTS_ACTIONS
)

# Catalog scope -> least-privilege Google scopes.
# - gmail.send only sends new mail (send_email); drafts, replies and
#   forwards use gmail.compose ("manage drafts and send"); label changes
#   and trash need gmail.modify (never the full https://mail.google.com/).
# - drive.write is the full "drive" scope on purpose: drive.file only
#   reaches files this app created or the user opened with a picker, so
#   moving, renaming, sharing or trashing the user's existing files would
#   fail with "not found".
SCOPE_MAP: dict[str, tuple[str, ...]] = {
    "gmail.read": (f"{SCOPE_BASE}gmail.readonly",),
    "gmail.send": (f"{SCOPE_BASE}gmail.send",),
    "gmail.compose": (f"{SCOPE_BASE}gmail.compose",),
    "gmail.modify": (f"{SCOPE_BASE}gmail.modify",),
    "calendar.read": (f"{SCOPE_BASE}calendar.readonly",),
    "calendar.write": (f"{SCOPE_BASE}calendar.events",),
    "drive.read": (f"{SCOPE_BASE}drive.readonly",),
    "drive.write": (f"{SCOPE_BASE}drive",),
    "docs.read": (f"{SCOPE_BASE}documents.readonly",),
    "docs.write": (f"{SCOPE_BASE}documents",),
    "sheets.read": (f"{SCOPE_BASE}spreadsheets.readonly",),
    "sheets.write": (f"{SCOPE_BASE}spreadsheets",),
    "contacts.read": (f"{SCOPE_BASE}contacts.readonly",),
    "contacts.write": (f"{SCOPE_BASE}contacts",),
}

OAUTH = OAuthSpec(
    provider="google",
    authorize_url=AUTHORIZE_URL,
    token_url=TOKEN_URL,
    revoke_url=REVOKE_URL,
    client_id_setting="GOOGLE_OAUTH_CLIENT_ID",
    client_secret_setting="GOOGLE_OAUTH_CLIENT_SECRET",
    scope_map=SCOPE_MAP,
    authorize_params={
        "access_type": "offline",
        "include_granted_scopes": "true",
        "prompt": "consent",
    },
)

_DEFAULT_REDIRECT_BASE = "http://127.0.0.1:3000"


def _broker_client() -> tuple[str, str]:
    """The installation's Google OAuth client pair, for broker-made rows.

    Broker rows store no client pair: the refresh must use the client that
    issued the grant, which is the installation's (read through the broker's
    resolver). An unconfigured server gives empty values, so a refresh then
    fails with a clear "reconnect" message instead of a crash.
    """
    from services.connectors.oauth_config import OAuthNotConfigured, resolve_client

    try:
        client = resolve_client(OAUTH, label="Google")
    except OAuthNotConfigured:
        logger.info("google_oauth_client_not_configured")
        return "", ""
    return client.client_id, client.client_secret


class GoogleWorkspaceConnector(
    GmailActions, CalendarActions, DriveActions, DocsActions, SheetsActions, ContactsActions
):
    """Connector for the Google Workspace APIs (one instance per tool call)."""

    # Scopes the legacy generate_auth_url requests when given none.
    GMAIL_SCOPES = [
        f"{SCOPE_BASE}gmail.readonly",
        f"{SCOPE_BASE}gmail.compose",
    ]
    CALENDAR_SCOPES = [
        f"{SCOPE_BASE}calendar.readonly",
        f"{SCOPE_BASE}calendar.events",
    ]

    # The dispatch allow-map comes from ACTIONS, so they cannot drift apart.
    _ACTIONS = frozenset(spec.action for spec in ACTIONS)
    SUPPORTS_REVOKE = True

    @property
    def required_scopes(self) -> list[str]:
        return self.GMAIL_SCOPES + self.CALENDAR_SCOPES

    @classmethod
    def from_credentials(
        cls, credentials: dict[str, Any], *, timeout_s: Optional[float] = None
    ) -> GoogleWorkspaceConnector:
        """Build an instance; the client pair is only used for refresh.

        A pasted-token row carries its own client pair (the client that
        issued its refresh token). A broker row (``oauth_provider`` google)
        carries none and refreshes with the installation's client.
        """
        client_id = str(credentials.get("client_id") or "")
        client_secret = str(credentials.get("client_secret") or "")
        if not client_id and credentials.get("oauth_provider") == OAUTH.provider:
            client_id, client_secret = _broker_client()
        return cls(client_id=client_id, client_secret=client_secret, timeout_s=timeout_s)

    # -- OAuth 2.0 + PKCE (legacy helpers; the broker owns new sign-ins) --------

    @property
    def redirect_uri(self) -> str:
        """The explicit redirect URI, else the broker's callback for Google."""
        if self._explicit_redirect_uri:
            return self._explicit_redirect_uri
        from core.config import settings

        base = str(getattr(settings, "OAUTH_REDIRECT_BASE", "") or _DEFAULT_REDIRECT_BASE)
        return f"{base.rstrip('/')}/api/oauth/callback/google"

    def generate_auth_url(self, scopes: list[str] | None = None) -> tuple[str, str]:
        """Build a Google consent URL with PKCE; returns ``(url, code_verifier)``.

        Supports incremental authorization: pass a subset of scopes to
        request only what is needed now.
        """
        requested = scopes or self.required_scopes
        self._pkce_verifier = secrets.token_urlsafe(64)
        digest = hashlib.sha256(self._pkce_verifier.encode()).digest()
        code_challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode()
        params = {
            "client_id": self._client_id,
            "response_type": "code",
            "redirect_uri": self.redirect_uri,
            "scope": " ".join(requested),
            "code_challenge": code_challenge,
            "code_challenge_method": "S256",
            **OAUTH.authorize_params,
            "state": secrets.token_urlsafe(32),
        }
        return f"{AUTHORIZE_URL}?{urlencode(params)}", self._pkce_verifier

    async def authenticate(self, credentials: dict[str, Any]) -> bool:
        """Accept stored tokens, or exchange a one-time code.

        Accepted keys: ``access_token`` (+ optional ``refresh_token``,
        ``expires_at``, ``granted_scopes``), or ``code`` + ``code_verifier``
        for a PKCE exchange. No network call for stored tokens.
        """
        token = credentials.get("access_token")
        if isinstance(token, str) and token:
            self._access_token = token
            refresh = credentials.get("refresh_token")
            self._refresh_token = refresh if isinstance(refresh, str) and refresh else None
            expires_at = credentials.get("expires_at")
            if isinstance(expires_at, (int, float)) and not isinstance(expires_at, bool):
                self._expires_at = int(expires_at)
            granted = credentials.get("granted_scopes")
            if isinstance(granted, list):
                self._granted_scopes = {s for s in granted if isinstance(s, str)}
            self._authenticated = True
            self._log.info("authenticated_with_token")
            return True

        code = credentials.get("code")
        verifier = credentials.get("code_verifier") or self._pkce_verifier
        if not code or not verifier:
            raise AuthenticationError("Provide 'access_token' or 'code'+'code_verifier'.")
        form = {
            "grant_type": "authorization_code",
            "client_id": self._client_id,
            "redirect_uri": self.redirect_uri,
            "code": code,
            "code_verifier": verifier,
        }
        if self._client_secret:
            form["client_secret"] = self._client_secret
        try:
            payload = await self._request_json("POST", TOKEN_URL, data=form, authorized=False)
        except ConnectorError as exc:
            raise AuthenticationError(f"Google OAuth token exchange failed: {exc}") from None
        if not isinstance(payload, dict):
            raise AuthenticationError("Google OAuth token exchange failed: malformed response.")
        self._apply_token_payload(payload)
        self._authenticated = True
        self._log.info("authenticated_via_oauth", scopes=sorted(self._granted_scopes))
        return True

    def updated_credentials(self, original: dict[str, Any]) -> dict[str, Any] | None:
        """Credentials to persist when this session produced new tokens (a
        refresh, possibly rotating the refresh token, or a code exchange);
        ``None`` when nothing changed."""
        if not self._access_token:
            return None
        if self._access_token == original.get("access_token") and (
            self._refresh_token or None
        ) == (original.get("refresh_token") or None):
            return None
        updated = dict(original)
        updated["access_token"] = self._access_token
        if self._refresh_token:
            updated["refresh_token"] = self._refresh_token
        if self._expires_at is not None:
            updated["expires_at"] = self._expires_at
        if "code" in original and self._granted_scopes:
            updated["granted_scopes"] = sorted(self._granted_scopes)
        # A consumed one-time authorization code must never be replayed.
        updated.pop("code", None)
        updated.pop("code_verifier", None)
        return updated

    async def _execute_action(self, action: str, params: dict[str, Any]) -> dict[str, Any]:
        return await self._dispatch(action, params)

    # -- Health check ------------------------------------------------------------

    # (scope prefix, probe URL, query), cheapest first. The connector is
    # healthy when the token reaches any surface it was granted: probing
    # Gmail alone failed every calendar-only (incrementally granted) row.
    _HEALTH_PROBES: tuple[tuple[str, str, Optional[dict[str, Any]]], ...] = (
        (f"{SCOPE_BASE}gmail", f"{GMAIL_API}/profile", None),
        (f"{SCOPE_BASE}calendar", f"{CALENDAR_API}/users/me/calendarList", {"maxResults": 1}),
        (f"{SCOPE_BASE}drive", f"{DRIVE_API}/about", {"fields": "user"}),
        (
            f"{SCOPE_BASE}contacts",
            f"{PEOPLE_API}/people/me/connections",
            {"personFields": "names", "pageSize": 1},
        ),
    )

    def _ordered_health_probes(self) -> tuple[tuple[str, str, Optional[dict[str, Any]]], ...]:
        """Probes to try: the granted surfaces when the grant is known, else all."""
        if not self._granted_scopes:
            return self._HEALTH_PROBES
        granted = tuple(
            probe
            for probe in self._HEALTH_PROBES
            if any(s.startswith(probe[0]) for s in self._granted_scopes)
        )
        return granted or self._HEALTH_PROBES

    def _probe_less_grant(self) -> bool:
        """A known grant with no probe surface (only Docs or Sheets)."""
        return bool(self._granted_scopes) and not any(
            s.startswith(p[0]) for p in self._HEALTH_PROBES for s in self._granted_scopes
        )

    async def _probe(self) -> bool:
        """True when a probe answers 200. A 403 (the token lacks that API's
        scope) tries the next surface; any other failure raises.

        A usage limit (``RateLimitExceededError``, including Google's
        rate-limit 403s) also counts as healthy: Google meters an
        authenticated caller, so the token was accepted, and "re-enter
        your credentials" would be the wrong advice.
        """
        if self._probe_less_grant():
            # Docs and Sheets have no id-free GET. Drive's /about answers
            # 403 for a valid token without Drive scopes, and 401 for a bad
            # one, so a 403 here still proves the token works.
            try:
                await self._request("GET", f"{DRIVE_API}/about", params={"fields": "user"})
            except RateLimitExceededError:
                pass
            except AuthenticationError as exc:
                if error_status(exc) != 403:
                    raise
            return True
        for _, url, params in self._ordered_health_probes():
            try:
                await self._request("GET", url, params=params)
                return True
            except RateLimitExceededError:
                return True
            except AuthenticationError as exc:
                if error_status(exc) != 403:
                    raise
        return False

    async def health_check(self) -> bool:
        """One cheap authenticated GET (per granted surface until one answers).

        A 401 with a refresh token and client id refreshes once and probes
        again; the refreshed token is then persisted by the caller through
        ``updated_credentials``.
        """
        try:
            return await self._probe()
        except AuthenticationError as exc:
            if error_status(exc) != 401 or not (self._can_refresh() and self._client_id):
                return False
        except ConnectorError:
            return False
        try:
            await self._refresh_access_token()
            return await self._probe()
        except ConnectorError:
            return False

    async def revoke(self) -> bool:
        """Revoke the grant at Google (the refresh token revokes all of it).

        Google's revoke endpoint needs no client secret: a form POST of the
        token, without our Authorization header. True on 200.
        """
        token = self._refresh_token or self._access_token
        if not token:
            return False
        try:
            await self._request("POST", REVOKE_URL, data={"token": token}, authorized=False)
        except ConnectorError:
            return False
        return True


DEFINITION = ConnectorDefinition(
    key="google_workspace",
    label="Google Workspace",
    description=(
        "Gmail, Google Calendar, Drive, Docs, Sheets and Contacts: read and send mail, "
        "manage events, find and edit files, documents, spreadsheets and contacts."
    ),
    icon="mail",
    auth=AuthSpec(
        methods=("oauth", "token"),
        fields=(
            CredentialField(
                "access_token",
                "OAuth access token",
                placeholder="ya29....",
                hint="Token with the Google scopes you grant below.",
            ),
            CredentialField(
                "refresh_token",
                "Refresh token (strongly recommended)",
                required=False,
                placeholder="Without this, the connection stops working in about 1 hour",
                hint=(
                    "Google access tokens expire after about an hour. With a refresh "
                    "token + client credentials, Crawler AI renews and saves tokens "
                    "automatically; without them you must paste a fresh token every hour."
                ),
            ),
            CredentialField(
                "client_id",
                "OAuth client ID (needed for auto-refresh)",
                type="text",
                required=False,
                placeholder="Required for automatic renewal",
            ),
            CredentialField(
                "client_secret",
                "OAuth client secret (needed for auto-refresh)",
                required=False,
                placeholder="Required for automatic renewal",
            ),
        ),
        oauth=OAUTH,
        # The value the connector form has always stored for a pasted
        # Google token.
        token_auth_method="oauth2",
        notes="OAuth access token with the Gmail/Calendar scopes you intend to grant.",
    ),
    network=NetworkSpec(
        policy_key="google",
        hosts={
            # "/gmail/" on www and "/tokeninfo" stay because the narrower
            # literal backstop in core/network_security.py lists them, and
            # the registry policy must stay a superset of it.
            "www.googleapis.com": ("/calendar/", "/gmail/", "/drive/v3/", "/upload/drive/v3/"),
            "gmail.googleapis.com": ("/gmail/v1/",),
            "docs.googleapis.com": ("/v1/documents",),
            "sheets.googleapis.com": ("/v4/spreadsheets",),
            "people.googleapis.com": ("/v1/people",),
            "oauth2.googleapis.com": ("/token", "/tokeninfo", "/revoke"),
            "accounts.google.com": ("/o/oauth2/",),
        },
        https_only=True,
    ),
    actions=ACTIONS,
    connector_class=GoogleWorkspaceConnector,
    docs_url="https://developers.google.com/identity/protocols/oauth2",
)
