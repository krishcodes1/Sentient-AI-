"""Defines the Microsoft 365 connector: Outlook mail and calendar, OneDrive,
Microsoft To Do and Outlook contacts through Microsoft Graph.

Why it exists: backlog item C3 and spec section 5.5. This module assembles
the per-area mixins in ``services/connectors/microsoft_api/`` into one
``MicrosoftConnector`` and declares its ``DEFINITION`` (actions, OAuth sign-in,
network reach), which ``services/connectors/registry.py`` turns into the
tool catalog, permission rows and allowlist.
Talks to Microsoft Graph (graph.microsoft.com/v1.0/me/...), OneDrive download
hosts (redirect targets only) and, through the OAuth broker
(``services/connectors/oauth.py``), login.microsoftonline.com. Sign-in is a
public client with PKCE or the device flow; the broker stores and rotates the
tokens, so this class only reads ``access_token``. Depends on ``base``,
``definition`` and the ``microsoft_api`` package.
"""

from __future__ import annotations

from typing import Any, Optional

from .base import AuthenticationError, ConnectorError
from .definition import (
    AuthSpec,
    ConnectorDefinition,
    NetworkSpec,
    OAuthSpec,
    ToolSpec,
)
from .microsoft_api.calendar import CALENDAR_ACTIONS, CalendarActions
from .microsoft_api.common import CONNECTOR_NAME, ME, GraphBase
from .microsoft_api.drive import DRIVE_ACTIONS, DriveActions
from .microsoft_api.mail import MAIL_ACTIONS, MailActions
from .microsoft_api.todo import CONTACT_ACTIONS, TODO_ACTIONS, ContactActions, TodoActions

ACTIONS: tuple[ToolSpec, ...] = (
    MAIL_ACTIONS + CALENDAR_ACTIONS + DRIVE_ACTIONS + TODO_ACTIONS + CONTACT_ACTIONS
)

# Cheapest authenticated GET per granted Graph permission, in preference
# order. The connector requests no User.Read (it needs none), so /me itself
# is not reachable; the probe must use a permission the user granted. Each
# probe lists the normalised (lower-case, short-form) permissions that can
# READ it: Mail.Send alone, for example, cannot read the inbox.
_HEALTH_PROBES: tuple[tuple[frozenset[str], str, dict[str, Any]], ...] = (
    (
        frozenset({"mail.read", "mail.readwrite", "mail.readbasic"}),
        "/mailFolders/inbox",
        {"$select": "id"},
    ),
    (
        frozenset({
            "calendars.read", "calendars.readwrite",
            "calendars.read.shared", "calendars.readwrite.shared",
        }),
        "/calendars",
        {"$top": 1, "$select": "id"},
    ),
    (
        frozenset({"files.read", "files.readwrite", "files.read.all", "files.readwrite.all"}),
        "/drive",
        {"$select": "id"},
    ),
    (frozenset({"tasks.read", "tasks.readwrite"}), "/todo/lists", {}),
    (
        frozenset({"contacts.read", "contacts.readwrite"}),
        "/contacts",
        {"$top": 1, "$select": "id"},
    ),
)
# Sign-in scopes that say nothing about Graph data access.
_IDENTITY_SCOPES = frozenset({"offline_access", "openid", "profile", "email"})


class MicrosoftConnector(
    MailActions, CalendarActions, DriveActions, TodoActions, ContactActions, GraphBase
):
    """Microsoft 365 through Microsoft Graph with a delegated OAuth token.

    The OAuth broker keeps the token fresh (Microsoft rotates the refresh
    token on every refresh and the broker persists each rotation), so this
    class never refreshes and ``updated_credentials`` stays the default
    (nothing to persist).
    """

    # The dispatch allow-map comes from ACTIONS, so they cannot drift apart.
    _ACTIONS = frozenset(spec.action for spec in ACTIONS)

    def __init__(self, timeout_s: Optional[float] = None) -> None:
        super().__init__(timeout_s=timeout_s, rate_limit=60)
        self._token: Optional[str] = None
        self._granted: tuple[str, ...] = ()

    @property
    def name(self) -> str:
        return CONNECTOR_NAME

    @property
    def connector_type(self) -> str:
        return "productivity"

    @property
    def required_scopes(self) -> list[str]:
        return sorted({spec.required_scope for spec in ACTIONS if spec.required_scope})

    async def authenticate(self, credentials: dict[str, Any]) -> bool:
        """Store the access token. No network here; health_check proves it."""
        token = credentials.get("access_token")
        if not isinstance(token, str) or not token.strip():
            raise AuthenticationError(
                f"{CONNECTOR_NAME} has no access token. Reconnect {CONNECTOR_NAME} in Connectors."
            )
        self._token = token.strip()
        granted = credentials.get("granted_scopes")
        if isinstance(granted, list):
            self._granted = tuple(scope for scope in granted if isinstance(scope, str))
        self._authenticated = True
        return True

    def _auth_headers(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {self._token}"} if self._token else {}

    async def _execute_action(self, action: str, params: dict[str, Any]) -> dict[str, Any]:
        return await self._dispatch(action, params)

    async def health_check(self) -> bool:
        """One cheap GET the granted permissions allow; False on any error.

        When the grant holds no read permission at all (only Mail.Send),
        no GET can succeed, so the inbox probe runs anyway and a 403 counts
        as healthy: Graph answers 401 for a rejected token and 403 only
        after it accepted the token and found the permission missing.
        """
        path, params, denied_is_healthy = _health_probe(self._granted)
        try:
            await self._request("GET", f"{ME}{path}", params=params)
            return True
        except AuthenticationError as exc:
            return denied_is_healthy and exc.status_code == 403
        except ConnectorError:
            return False

    async def revoke(self) -> bool:
        """Microsoft offers no endpoint that revokes one app's grant.

        The only token revocation in Graph is ``revokeSignInSessions``, which
        signs the user out of every app and device, far more than removing
        this connector should do. The consent itself stays listed at
        https://myapps.microsoft.com (work accounts) or
        https://account.live.com/consent/Manage (personal accounts), where
        the user can remove it. So there is nothing to call here.
        """
        return False


def _normalise_scope(scope: str) -> str:
    """``https://graph.microsoft.com/Files.Read`` and ``files.read`` both
    become ``files.read``: the broker stores the token response's scope
    values as Microsoft returned them (URL form and case vary)."""
    return scope.strip().lower().rsplit("/", 1)[-1]


def _health_probe(granted: tuple[str, ...]) -> tuple[str, dict[str, Any], bool]:
    """The probe path, its query, and whether a 403 still means healthy."""
    have = {_normalise_scope(scope) for scope in granted} - _IDENTITY_SCOPES
    for readers, path, params in _HEALTH_PROBES:
        if have & readers:
            return path, params, False
    inbox_path, inbox_params = _HEALTH_PROBES[0][1], _HEALTH_PROBES[0][2]
    # A known grant with no read permission (Mail.Send only): a 403 is the
    # expected answer for a valid token. An unknown grant (an older row with
    # no scope list) gets the plain inbox probe, the most common one.
    return inbox_path, inbox_params, bool(have)


DEFINITION = ConnectorDefinition(
    key="microsoft",
    label="Microsoft 365",
    description=(
        "Outlook mail and calendar, OneDrive files, Microsoft To Do and contacts: "
        "read, search, draft and send, schedule, and manage files and tasks."
    ),
    icon="briefcase",
    auth=AuthSpec(
        methods=("oauth", "device"),
        oauth=OAuthSpec(
            provider="microsoft",
            authorize_url="https://login.microsoftonline.com/common/oauth2/v2.0/authorize",
            token_url="https://login.microsoftonline.com/common/oauth2/v2.0/token",
            device_code_url="https://login.microsoftonline.com/common/oauth2/v2.0/devicecode",
            client_id_setting="MICROSOFT_OAUTH_CLIENT_ID",
            # Public client: no secret (MICROSOFT_OAUTH_CLIENT_ID only).
            base_scopes=("offline_access",),
            scope_map={
                "mail.read": ("Mail.Read",),
                "mail.write": ("Mail.ReadWrite",),
                "mail.send": ("Mail.Send",),
                # Also covers find_meeting_times: getSchedule accepts
                # Calendars.Read (its least privileged permission,
                # Calendars.ReadBasic, is implied by it).
                "calendar.read": ("Calendars.Read",),
                "calendar.write": ("Calendars.ReadWrite",),
                "files.read": ("Files.Read",),
                "files.write": ("Files.ReadWrite",),
                "tasks.read": ("Tasks.Read",),
                "tasks.write": ("Tasks.ReadWrite",),
                "contacts.read": ("Contacts.Read",),
            },
        ),
        token_auth_method="oauth2",
        notes=(
            "Sign in with a Microsoft work, school or personal account. On a machine "
            "without a browser, use the device code option."
        ),
    ),
    network=NetworkSpec(
        policy_key="microsoft",
        hosts={
            "graph.microsoft.com": ("/v1.0/me/",),
            "login.microsoftonline.com": (
                "/common/oauth2/v2.0/token",
                "/common/oauth2/v2.0/devicecode",
            ),
        },
        https_only=True,
        # Pre-authenticated OneDrive downloads that /content redirects to:
        # work and school drives (<tenant>-my.sharepoint.com), and personal
        # drives (both host families Microsoft uses; "*.files.1drv.com" is a
        # suffix wildcard because regional hosts have several labels).
        # GET only, never with our Authorization header.
        redirect_hosts={
            "*-my.sharepoint.com": ("/personal/",),
            "*.files.1drv.com": ("/",),
            "my.microsoftpersonalcontent.com": ("/personal/",),
        },
    ),
    actions=ACTIONS,
    connector_class=MicrosoftConnector,
    docs_url=(
        "https://learn.microsoft.com/en-us/entra/identity-platform/"
        "quickstart-register-app"
    ),
)
