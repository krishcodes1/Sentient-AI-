"""Declares the data types a connector module uses to describe itself: its
actions, credentials, sign-in method and network reach.

Why it exists: every connector file ends with one ``DEFINITION`` built from
these types, and ``services/connectors/registry.py`` derives every table the
platform used to hand-write from them (the tool catalog, credential rules,
network allowlists and permission rows). One declaration per connector means a
new connector cannot forget one of those tables.

It connects the connector modules to the tool registry, the permission engine,
the network policy (``core/network_security.py``) and the OAuth broker
(``services/connectors/oauth.py``). It is a leaf module: it imports only
``services.agent.permissions`` (stdlib only) and, for typing, the connector
base class.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Callable, Literal, Mapping, Optional

from services.agent.permissions import ActionCategory, PermissionTier

if TYPE_CHECKING:
    from services.connectors.base import BaseConnector


# An action's argument check (``ToolSpec.risk_check``): given the call's
# arguments, ``(level, reason)`` to escalate its risk grade ("medium" or
# "high", with a fixed reason that never quotes an argument), or None. It
# can only raise the grade (services/agent/risk.py); a check that raises
# grades the call HIGH.
RiskCheck = Callable[[Mapping[str, Any]], Optional[tuple[str, str]]]


# ---------------------------------------------------------------------------
# Actions
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ToolSpec:
    """Declarative description of one connector action.

    ``policy_key`` is the key the permission engine is keyed by, which for
    Google differs per action (gmail vs google_calendar). It defaults to the
    owning connector's key.

    ``required_scope`` is the connector scope a user must have granted for
    this action to be offered and executed. ``None`` means the action has
    no scope gate beyond its permission tier.

    ``always_confirm`` puts the action on an approval card under every
    tier, including an account whose default is auto-approve. It is for
    actions that cannot be taken back or that speak for the user: every
    delete, every message that leaves the account, merges, publishes and
    sharing changes.

    ``starter`` marks an everyday read that is offered to the model up
    front; every other action is reachable through ``tools.find``.

    Risk grading (services/agent/risk.py; permission tiers):

    - ``risk="low"`` opts a WRITE into the LOW grade: a small, undoable
      change to the owner's own account that nobody else sees (a draft, a
      star, a private event). Only a WRITE without ``always_confirm`` may
      declare it, and it needs ``low_risk_note``. Every other WRITE is
      MEDIUM; reads are LOW; deletes, runs, payments and always-confirm
      actions are HIGH.
    - ``risk_check`` reads the arguments and can only escalate the grade
      (TRASH on a Gmail label change, guests on an event). One that raises
      grades the call HIGH.
    - ``ref_args`` names the arguments that carry an object id (a message
      id). On a LOW call, an id the same connection returned this turn is
      not treated as copied from untrusted content.
    - ``low_risk_note`` says in a few words what the LOW action does, for
      the tier's help text and the grant card (at most 80 characters).
    """

    action: str
    description: str
    category: ActionCategory
    parameters: dict[str, Any] = field(default_factory=dict)
    policy_key: Optional[str] = None
    required_scope: Optional[str] = None
    always_confirm: bool = False
    starter: bool = False
    risk: Optional[str] = None
    risk_check: Optional[RiskCheck] = None
    ref_args: tuple[str, ...] = ()
    low_risk_note: str = ""


def _schema(**props: dict[str, Any]) -> dict[str, Any]:
    """Build a minimal JSON-schema object for tool parameters.

    A property carrying ``"required": True`` is listed in the schema's
    ``required`` array; the flag itself is stripped from the property.
    """
    required = [k for k, v in props.items() if v.get("required")]
    return {
        "type": "object",
        "properties": {
            k: {key: val for key, val in v.items() if key != "required"}
            for k, v in props.items()
        },
        "required": required,
    }


# ---------------------------------------------------------------------------
# Credentials and sign-in
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class CredentialField:
    """One value the user pastes when connecting with a token.

    ``type`` tells the UI how to render the input: ``password`` values are
    masked and never echoed back, ``url`` values are validated as URLs.
    """

    key: str
    label: str
    type: Literal["text", "password", "url"] = "password"
    required: bool = True
    placeholder: str = ""
    hint: str = ""


AuthKind = Literal["token", "oauth", "device"]


@dataclass(frozen=True)
class OAuthSpec:
    """How the shared OAuth broker signs a user in to one provider.

    ``provider`` is the URL segment of the broker routes
    (``/api/oauth/<provider>/...``). ``authorize_url`` is used by the
    authorization-code flow with PKCE (``oauth``); ``device_code_url`` by
    the device flow (``device``). Both exchange at ``token_url``.

    ``client_id_setting`` and ``client_secret_setting`` name attributes of
    ``core.config.Settings``. Only public client ids are expected; the
    secret is for Google's Desktop client, which Google treats as
    non-confidential. Neither value ever lives in source code.

    ``scope_map`` maps each catalog scope (``drive.read``) to the provider
    scopes that grant it. ``base_scopes`` are always requested (for example
    ``offline_access`` so Microsoft returns a refresh token).
    ``authorize_params`` are extra consent-URL parameters.
    """

    provider: str
    token_url: str
    authorize_url: str = ""
    device_code_url: str = ""
    revoke_url: str = ""
    client_id_setting: str = ""
    client_secret_setting: str = ""
    scope_map: Mapping[str, tuple[str, ...]] = field(default_factory=dict)
    base_scopes: tuple[str, ...] = ()
    authorize_params: Mapping[str, str] = field(default_factory=dict)
    pkce: bool = True

    def provider_scopes(self, catalog_scopes: tuple[str, ...] | list[str]) -> tuple[str, ...]:
        """Provider scopes for the given catalog scopes, in a stable order.

        Unknown catalog scopes contribute nothing; the connector routes have
        already rejected them against the catalog.
        """
        ordered: dict[str, None] = dict.fromkeys(self.base_scopes)
        for scope in catalog_scopes:
            ordered.update(dict.fromkeys(self.scope_map.get(scope, ())))
        return tuple(ordered)


@dataclass(frozen=True)
class AuthSpec:
    """The sign-in methods a connector supports, in UI preference order.

    ``token`` means the user pastes the ``fields``; ``oauth`` and ``device``
    go through the OAuth broker described by ``oauth``.
    ``token_auth_method`` is the ``AuthMethod`` value stored on a
    pasted-token row (``api_key`` or ``bearer_token``); broker-created rows
    are always ``oauth2``.
    """

    methods: tuple[AuthKind, ...]
    fields: tuple[CredentialField, ...] = ()
    oauth: Optional[OAuthSpec] = None
    token_auth_method: Literal["api_key", "bearer_token", "oauth2"] = "bearer_token"
    notes: str = ""

    @property
    def required_credentials(self) -> tuple[str, ...]:
        """Credential keys a stored row must carry.

        A connector with pasted-token fields requires its required fields.
        A broker-only connector stores an ``access_token``, so that is what
        its rows must carry.
        """
        if self.fields:
            return tuple(f.key for f in self.fields if f.required)
        return ("access_token",)

    @property
    def optional_credentials(self) -> tuple[str, ...]:
        if self.fields:
            return tuple(f.key for f in self.fields if not f.required)
        return ("refresh_token",)


# ---------------------------------------------------------------------------
# Network reach
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class NetworkSpec:
    """Where the connector may send requests (deny by default).

    ``hosts`` maps an exact host, a ``*.suffix`` wildcard or a leftmost-label
    glob (``productionresultssa*.blob.core.windows.net``) to the path
    prefixes allowed on it. Every host lists at least one prefix; a host
    with no prefixes would otherwise allow every path.

    ``redirect_hosts`` are pre-signed download hosts a request may be
    redirected to: GET only, and never with our Authorization header.
    ``ws_hosts`` are exact WebSocket hosts (Slack Socket Mode).
    ``instance_paths`` apply to a host the user configured (a self-hosted
    Canvas). ``https_only`` refuses plain HTTP and any port but 443.
    """

    policy_key: str
    hosts: Mapping[str, tuple[str, ...]]
    https_only: bool = True
    redirect_hosts: Mapping[str, tuple[str, ...]] = field(default_factory=dict)
    ws_hosts: tuple[str, ...] = ()
    instance_paths: tuple[str, ...] = ()


# ---------------------------------------------------------------------------
# The definition
# ---------------------------------------------------------------------------


# Default permission tier per action category for rows the registry
# generates. New rows never use ADMIN_ONLY: the runtime permission adapter
# runs as a standard user, so ADMIN_ONLY would block the action for everyone.
CATEGORY_TIERS: Mapping[ActionCategory, PermissionTier] = {
    ActionCategory.READ: PermissionTier.AUTO_APPROVE,
    ActionCategory.WRITE: PermissionTier.USER_CONFIRM,
    ActionCategory.DELETE: PermissionTier.USER_CONFIRM,
    ActionCategory.EXECUTE: PermissionTier.USER_CONFIRM,
    ActionCategory.FINANCIAL: PermissionTier.HARD_BLOCKED,
}


@dataclass(frozen=True)
class ConnectorDefinition:
    """Everything the platform needs to know about one connector.

    ``key`` is the ``connector_type`` stored in the database and the first
    segment of every tool name (``github.list_issues``). ``icon`` is a
    frontend icon name; unknown names fall back to a generic plug.
    ``financial_ok`` is set only by a connector whose FINANCIAL actions are
    declared so they can stay hard-blocked (Robinhood).
    ``policy_overrides`` replaces generated permission rows where an
    existing connector's behaviour must be preserved.
    """

    key: str
    label: str
    description: str
    icon: str
    auth: AuthSpec
    network: NetworkSpec
    actions: tuple[ToolSpec, ...]
    connector_class: type[BaseConnector]
    docs_url: str = ""
    financial_ok: bool = False
    policy_overrides: Mapping[tuple[str, ActionCategory], PermissionTier] = field(
        default_factory=dict
    )

    def policy_keys(self) -> tuple[str, ...]:
        """Permission keys this connector's actions use, in first-use order."""
        return tuple(dict.fromkeys(a.policy_key or self.key for a in self.actions))

    def scopes(self) -> dict[str, list[str]]:
        """Catalog scopes grouped by risk; FINANCIAL actions are never grantable."""
        read: set[str] = set()
        write: set[str] = set()
        for spec in self.actions:
            if not spec.required_scope or spec.category == ActionCategory.FINANCIAL:
                continue
            (read if spec.category == ActionCategory.READ else write).add(spec.required_scope)
        return {"read": sorted(read), "write": sorted(write)}
