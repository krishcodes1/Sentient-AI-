"""Lists every connector the platform ships and derives, from their
declarations, every table that used to be written by hand.

Why it exists: a connector is one module ending in a ``DEFINITION``. This
registry validates those definitions at import (a bad one stops the app with
a list of every problem) and turns them into the tool catalog, credential
rules, network allowlists, permission rows and the connector-types payload
the Connectors page renders.

It connects ``services/connectors/definition.py`` (the declaration types) to
``services/connectors/factory.py``, ``services/agent/tool_registry.py``,
``services/agent/permissions.py`` and ``core/network_security.py``. It talks
to no external service. It must never import ``tool_registry`` (cycle).
"""

from __future__ import annotations

import importlib
import inspect
import re
from typing import Any, Iterable, Mapping, Optional
from urllib.parse import urlparse

from core.network_security import DEFAULT_POLICIES, NetworkPolicy, match_host_pattern
from services.agent.permissions import (
    ActionCategory,
    PermissionTier,
    is_hard_blocked_action,
    register_default_policies,
)
from services.connectors.base import BaseConnector
from services.connectors.definition import (
    CATEGORY_TIERS,
    ConnectorDefinition,
    ToolSpec,
)


def _load(module_name: str) -> ConnectorDefinition:
    """The ``DEFINITION`` of ``services.connectors.<module_name>``."""
    module = importlib.import_module(f"services.connectors.{module_name}")
    definition = getattr(module, "DEFINITION", None)
    if not isinstance(definition, ConnectorDefinition):
        raise ValueError(
            f"services.connectors.{module_name} has no ConnectorDefinition named DEFINITION"
        )
    return definition


# One line per connector. To add one, copy _template.py to <key>.py, fill it
# in, and append a line here (see README.md in this directory).
REGISTRY: tuple[ConnectorDefinition, ...] = (
    _load("canvas"),
    _load("google_workspace"),
    _load("robinhood"),
    _load("slack"),
    _load("microsoft"),
    _load("github"),
    _load("notion"),
)


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------

# Keys a connector may never take: built-in tool families (present and
# planned), plus the two connector types that are not registry connectors.
RESERVED_KEYS: frozenset[str] = frozenset(
    {
        "web",
        "reminders",
        "system",
        "desktop",
        "browser",
        "skills",
        "learnings",
        "graph",
        "tools",
        "memory",
        "mcp",
        "custom",
    }
)

# Connectors allowed to reach plain-http hosts. Canvas only: a self-hosted
# Canvas on http:// has always been accepted. Every other connector is
# https-only.
HTTP_ALLOWED_KEYS: frozenset[str] = frozenset({"canvas"})

# Parameter names the progress events echo from tool arguments
# (tool_call_facts), plus the confirmation flag the executor owns.
FORBIDDEN_PARAMS: frozenset[str] = frozenset({"url", "action", "user_confirmed"})

# Most starter tools a single connector may declare (spec section 4.5).
MAX_STARTERS = 4

_KEY_RE = re.compile(r"^[a-z][a-z0-9_]{1,31}$")
_NAME_RE = re.compile(r"^[a-z][a-z0-9_]{0,63}$")
_SCOPE_RE = re.compile(r"^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+$")
_PARAM_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_HOST_LABEL_RE = re.compile(r"^[a-z0-9]([a-z0-9-]*[a-z0-9])?$")
_GLOB_LABEL_RE = re.compile(r"^[a-z0-9-]*\*[a-z0-9-]*$")
_AUTH_KINDS = frozenset({"token", "oauth", "device"})
_FIELD_TYPES = frozenset({"text", "password", "url"})
_TOKEN_AUTH_METHODS = frozenset({"api_key", "bearer_token", "oauth2"})

# delete > execute > write > read, for the scope risk shown in the UI.
_CATEGORY_RISK: Mapping[ActionCategory, int] = {
    ActionCategory.READ: 0,
    ActionCategory.WRITE: 1,
    ActionCategory.EXECUTE: 2,
    ActionCategory.DELETE: 3,
    ActionCategory.FINANCIAL: 4,
}


def validate_registry(
    definitions: Iterable[ConnectorDefinition] = REGISTRY,
) -> list[str]:
    """Every problem with *definitions*, as readable lines (empty when valid).

    Runs at import (a problem raises) and in tests/test_connector_registry.py.
    Rules (connectors design spec section 3.4): key shape and uniqueness,
    reserved keys, per-action scope, category, name and parameter rules,
    method parity with the connector class, network and OAuth rules.
    """
    defs = tuple(definitions)
    problems: list[str] = []
    seen_keys: dict[str, int] = {}
    policy_owner: dict[str, str] = {}
    network_owner: dict[str, str] = {}
    provider_owner: dict[str, str] = {}
    for definition in defs:
        seen_keys[definition.key] = seen_keys.get(definition.key, 0) + 1
        problems.extend(_definition_problems(definition))
        for policy_key in definition.policy_keys():
            owner = policy_owner.setdefault(policy_key, definition.key)
            if owner != definition.key:
                problems.append(
                    f"{definition.key}: permission key '{policy_key}' is already used by '{owner}'"
                )
        net_key = definition.network.policy_key
        owner = network_owner.setdefault(net_key, definition.key)
        if owner != definition.key:
            problems.append(
                f"{definition.key}: network policy key '{net_key}' is already used by '{owner}'"
            )
        oauth = definition.auth.oauth
        if oauth is not None:
            owner = provider_owner.setdefault(oauth.provider, definition.key)
            if owner != definition.key:
                problems.append(
                    f"{definition.key}: OAuth provider '{oauth.provider}' is already used by '{owner}'"
                )
    for key, count in seen_keys.items():
        if count > 1:
            problems.append(f"{key}: key is registered {count} times")
    return problems


def _definition_problems(d: ConnectorDefinition) -> list[str]:
    problems: list[str] = []
    problems.extend(_key_problems(d))
    problems.extend(_presentation_problems(d))
    problems.extend(_action_problems(d))
    problems.extend(_dispatch_problems(d))
    problems.extend(_network_problems(d))
    problems.extend(_auth_problems(d))
    problems.extend(_policy_problems(d))
    return [f"{d.key}: {problem}" for problem in problems]


def _key_problems(d: ConnectorDefinition) -> list[str]:
    problems: list[str] = []
    if not _KEY_RE.match(d.key):
        problems.append("key must match ^[a-z][a-z0-9_]{1,31}$")
    if "__" in d.key:
        problems.append("key must not contain '__' (it separates tool-name slugs)")
    if d.key in RESERVED_KEYS:
        problems.append("key is reserved for a built-in tool family")
    return problems


def _presentation_problems(d: ConnectorDefinition) -> list[str]:
    problems = [
        f"{name} must not be empty"
        for name, value in (("label", d.label), ("description", d.description), ("icon", d.icon))
        if not str(value).strip()
    ]
    if d.docs_url and not d.docs_url.startswith("https://"):
        problems.append("docs_url must be an https:// URL")
    if not d.actions:
        problems.append("declares no actions")
    return problems


def _schema_properties(spec: ToolSpec) -> tuple[dict[str, Any], list[str], list[str]]:
    """(properties, required names, shape problems) of an action's schema."""
    params = spec.parameters
    if not params:
        return {}, [], []
    problems: list[str] = []
    if params.get("type") != "object":
        problems.append(f"action '{spec.action}': parameters must be a JSON-schema object")
    properties = params.get("properties", {})
    if not isinstance(properties, dict):
        return {}, [], problems + [f"action '{spec.action}': 'properties' must be an object"]
    required = params.get("required", [])
    if not isinstance(required, list):
        return properties, [], problems + [f"action '{spec.action}': 'required' must be a list"]
    unknown = [name for name in required if name not in properties]
    if unknown:
        problems.append(
            f"action '{spec.action}': required names {sorted(unknown)} are not properties"
        )
    return properties, list(required), problems


def _action_problems(d: ConnectorDefinition) -> list[str]:
    problems: list[str] = []
    names: set[str] = set()
    scope_kinds: dict[str, set[bool]] = {}
    financial_scopes: set[str] = set()
    starters = 0
    for spec in d.actions:
        name = spec.action
        if name in names:
            problems.append(f"action '{name}' is declared twice")
        names.add(name)
        if not _NAME_RE.match(name):
            problems.append(f"action '{name}' must match ^[a-z][a-z0-9_]{{0,63}}$")
        if not spec.description.strip():
            problems.append(f"action '{name}' has no description")
        if not spec.required_scope:
            problems.append(f"action '{name}' has no required_scope")
        elif not _SCOPE_RE.match(spec.required_scope):
            problems.append(
                f"action '{name}': scope '{spec.required_scope}' must look like 'area.read'"
            )
        is_financial = spec.category == ActionCategory.FINANCIAL
        if is_financial and not d.financial_ok:
            problems.append(f"action '{name}' is FINANCIAL but the connector is not financial_ok")
        if is_hard_blocked_action(name) and not d.financial_ok:
            problems.append(
                f"action '{name}' is on the financial hard-block list and would be silently dropped"
            )
        if spec.category == ActionCategory.DELETE and not spec.always_confirm:
            problems.append(f"action '{name}' is a DELETE and must set always_confirm")
        if spec.starter:
            starters += 1
            if spec.category != ActionCategory.READ:
                problems.append(f"action '{name}': only READ actions may be starters")
        if spec.policy_key is not None and (
            not _KEY_RE.match(spec.policy_key) or spec.policy_key in RESERVED_KEYS
        ):
            problems.append(
                f"action '{name}': policy_key '{spec.policy_key}' is invalid or reserved"
            )
        properties, _, shape = _schema_properties(spec)
        problems.extend(shape)
        for param in properties:
            if param in FORBIDDEN_PARAMS:
                problems.append(f"action '{name}': parameter name '{param}' is not allowed")
            elif not _PARAM_RE.match(param):
                problems.append(f"action '{name}': parameter '{param}' is not an identifier")
        if spec.required_scope:
            if is_financial:
                financial_scopes.add(spec.required_scope)
            else:
                scope_kinds.setdefault(spec.required_scope, set()).add(
                    spec.category == ActionCategory.READ
                )
    if starters > MAX_STARTERS:
        problems.append(f"declares {starters} starter actions (at most {MAX_STARTERS})")
    for scope, kinds in sorted(scope_kinds.items()):
        if len(kinds) > 1:
            problems.append(
                f"scope '{scope}' is shared by READ and non-READ actions; split it into read and write scopes"
            )
    # A FINANCIAL action behind a grantable scope would lose the scope layer
    # of defence: granting the read or write scope would also pass the
    # executor's scope check for it, leaving only the hard block.
    for scope in sorted(financial_scopes & set(scope_kinds)):
        problems.append(
            f"scope '{scope}' is shared by FINANCIAL and non-FINANCIAL actions; give the FINANCIAL action its own scope"
        )
    return problems


def _dispatch_problems(d: ConnectorDefinition) -> list[str]:
    """Allow-map and method-parity rules.

    FINANCIAL actions (financial_ok connectors only) are refused before any
    dispatch, so they need no dispatch entry or parity; everything else must
    route to a public coroutine whose keyword parameters are exactly the
    schema properties (plus ``user_confirmed``).
    """
    cls = d.connector_class
    if not (inspect.isclass(cls) and issubclass(cls, BaseConnector)):
        return ["connector_class must be a BaseConnector subclass"]
    problems: list[str] = []
    if inspect.isabstract(cls):
        problems.append(f"connector_class {cls.__name__} is abstract")
    dispatchable = {s.action for s in d.actions if s.category != ActionCategory.FINANCIAL}
    legacy_map = getattr(cls, "_ACTION_MAP", None)
    if isinstance(legacy_map, dict):
        if set(legacy_map) != dispatchable:
            problems.append(
                f"_ACTION_MAP keys {sorted(legacy_map)} differ from the actions {sorted(dispatchable)}"
            )
        renamed = sorted(k for k, v in legacy_map.items() if k != v)
        if renamed:
            problems.append(f"_ACTION_MAP must map each action to its own name: {renamed}")
    elif set(cls._ACTIONS) != dispatchable:
        problems.append(
            f"_ACTIONS {sorted(cls._ACTIONS)} differ from the actions {sorted(dispatchable)}"
        )
    for spec in d.actions:
        if spec.category != ActionCategory.FINANCIAL:
            problems.extend(_parity_problems(cls, spec))
    if cls.SUPPORTS_REVOKE and cls.revoke is BaseConnector.revoke:
        problems.append(f"{cls.__name__} sets SUPPORTS_REVOKE but does not override revoke()")
    return problems


def _parity_problems(cls: type[BaseConnector], spec: ToolSpec) -> list[str]:
    name = spec.action
    method = getattr(cls, name, None)
    if name.startswith("_") or method is None or not inspect.iscoroutinefunction(method):
        return [f"action '{name}' has no public coroutine {cls.__name__}.{name}"]
    problems: list[str] = []
    params = list(inspect.signature(method).parameters.values())[1:]  # drop self
    keyword: dict[str, inspect.Parameter] = {}
    for param in params:
        if param.kind in (param.VAR_POSITIONAL, param.VAR_KEYWORD):
            problems.append(f"action '{name}': method must not take *args or **kwargs")
        elif param.kind == param.POSITIONAL_ONLY:
            problems.append(f"action '{name}': parameter '{param.name}' is positional-only")
        else:
            keyword[param.name] = param
    confirm = keyword.pop("user_confirmed", None)
    if spec.category != ActionCategory.READ:
        if confirm is None:
            problems.append(f"action '{name}' is not READ and its method lacks user_confirmed")
        elif confirm.kind != confirm.KEYWORD_ONLY or confirm.default is not False:
            problems.append(
                f"action '{name}': user_confirmed must be keyword-only and default to False"
            )
    properties, required, _ = _schema_properties(spec)
    if set(keyword) != set(properties):
        problems.append(
            f"action '{name}': method parameters {sorted(keyword)} differ from schema "
            f"properties {sorted(properties)}"
        )
    must_supply = sorted(
        p for p, param in keyword.items() if param.default is param.empty and p in properties
    )
    missing_required = [p for p in must_supply if p not in required]
    if missing_required:
        problems.append(
            f"action '{name}': parameters {missing_required} have no default but are not required in the schema"
        )
    return problems


def _host_problems(host: str, *, allow_glob: bool) -> list[str]:
    if host != host.strip().lower() or any(c in host for c in "/:@ ") or not host:
        return [f"host '{host}' must be a bare lowercase hostname"]
    labels = host.split(".")
    if len(labels) < 2:
        return [f"host '{host}' must have at least two labels"]
    first, rest = labels[0], labels[1:]
    if "*" in "".join(rest):
        return [f"host '{host}': '*' is only allowed in the leftmost label"]
    if "*" in first:
        if not allow_glob:
            return [f"host '{host}' must be exact (no wildcard)"]
        if not _GLOB_LABEL_RE.match(first) or first.count("*") > 1:
            return [f"host '{host}': invalid leftmost-label wildcard"]
    elif not _HOST_LABEL_RE.match(first):
        return [f"host '{host}' has an invalid label"]
    if not all(_HOST_LABEL_RE.match(label) for label in rest):
        return [f"host '{host}' has an invalid label"]
    return []


def _paths_problems(where: str, host: str, paths: tuple[str, ...]) -> list[str]:
    if not paths:
        return [f"{where} host '{host}' lists no path prefix (it would allow every path)"]
    return [
        f"{where} host '{host}': path prefix '{p}' must start with '/'"
        for p in paths
        if not isinstance(p, str) or not p.startswith("/")
    ]


def _url_in_network(url: str, hosts: Mapping[str, tuple[str, ...]]) -> bool:
    """True when the runtime policy check would accept *url* under *hosts*.

    Uses the same matcher as ``core.network_security.check_network_policy``
    (``match_host_pattern``: case and trailing-dot normalisation, exact
    entries before wildcards, most specific wildcard first) and then that
    entry's own path prefixes, so this prediction cannot drift from the
    real check.
    """
    parsed = urlparse(url)
    if parsed.scheme != "https" or not parsed.hostname:
        return False
    entry = match_host_pattern(parsed.hostname, hosts)
    if entry is None:
        return False
    path = parsed.path or "/"
    return any(path.startswith(prefix) for prefix in hosts[entry])


def _network_problems(d: ConnectorDefinition) -> list[str]:
    net = d.network
    problems: list[str] = []
    if not _KEY_RE.match(net.policy_key) or net.policy_key in RESERVED_KEYS:
        problems.append(f"network policy_key '{net.policy_key}' is invalid or reserved")
    if not net.hosts:
        problems.append("network lists no hosts")
    for host, paths in net.hosts.items():
        problems.extend(_host_problems(host, allow_glob=True))
        problems.extend(_paths_problems("network", host, tuple(paths)))
    for host, paths in net.redirect_hosts.items():
        problems.extend(_host_problems(host, allow_glob=True))
        problems.extend(_paths_problems("redirect", host, tuple(paths)))
    for host in net.ws_hosts:
        problems.extend(_host_problems(host, allow_glob=False))
    problems.extend(
        f"instance path '{p}' must start with '/'" for p in net.instance_paths if not p.startswith("/")
    )
    if not net.https_only and d.key not in HTTP_ALLOWED_KEYS:
        problems.append("network must set https_only=True")
    oauth = d.auth.oauth
    if oauth is not None:
        for label, url in (
            ("token_url", oauth.token_url),
            ("device_code_url", oauth.device_code_url),
            ("revoke_url", oauth.revoke_url),
        ):
            if url and not _url_in_network(url, net.hosts):
                problems.append(f"OAuth {label} {url} is not an https URL inside the network spec")
    return problems


def _auth_problems(d: ConnectorDefinition) -> list[str]:
    auth = d.auth
    problems: list[str] = []
    methods = tuple(auth.methods)
    if not methods:
        problems.append("auth declares no sign-in method")
    if len(set(methods)) != len(methods) or not set(methods) <= _AUTH_KINDS:
        problems.append(f"auth methods {list(methods)} must be distinct values of {sorted(_AUTH_KINDS)}")
    if auth.token_auth_method not in _TOKEN_AUTH_METHODS:
        problems.append(f"token_auth_method '{auth.token_auth_method}' is not an AuthMethod")
    if "token" in methods and not auth.fields:
        problems.append("the 'token' method needs at least one credential field")
    keys = [f.key for f in auth.fields]
    if len(set(keys)) != len(keys):
        problems.append("credential field keys must be unique")
    for credential in auth.fields:
        if not _PARAM_RE.match(credential.key) or not credential.label.strip():
            problems.append(f"credential field '{credential.key}' needs an identifier key and a label")
        if credential.type not in _FIELD_TYPES:
            problems.append(f"credential field '{credential.key}' has unknown type '{credential.type}'")
    if auth.fields and not any(f.required for f in auth.fields):
        problems.append("at least one credential field must be required")
    wants_broker = bool({"oauth", "device"} & set(methods))
    oauth = auth.oauth
    if wants_broker and oauth is None:
        problems.append("the 'oauth'/'device' methods need an OAuthSpec")
    if oauth is None:
        return problems
    if not wants_broker:
        problems.append("an OAuthSpec is declared but neither 'oauth' nor 'device' is a method")
    if not _KEY_RE.match(oauth.provider):
        problems.append(f"OAuth provider '{oauth.provider}' is not a valid URL segment")
    if not oauth.client_id_setting:
        problems.append("OAuthSpec needs client_id_setting (the Settings attribute name)")
    if "oauth" in methods and not oauth.authorize_url.startswith("https://"):
        problems.append("the 'oauth' method needs an https authorize_url")
    if "device" in methods and not oauth.device_code_url:
        problems.append("the 'device' method needs a device_code_url")
    catalog_scopes = {
        s.required_scope
        for s in d.actions
        if s.required_scope and s.category != ActionCategory.FINANCIAL
    }
    unmapped = sorted(scope for scope in catalog_scopes if not oauth.scope_map.get(scope))
    if unmapped:
        problems.append(f"OAuth scope_map does not map catalog scopes {unmapped}")
    stale = sorted(set(oauth.scope_map) - catalog_scopes)
    if stale:
        problems.append(f"OAuth scope_map maps scopes no action uses: {stale}")
    return problems


def _policy_problems(d: ConnectorDefinition) -> list[str]:
    problems: list[str] = []
    own = set(d.policy_keys())
    for (policy_key, category), tier in d.policy_overrides.items():
        if policy_key not in own:
            problems.append(f"policy override for '{policy_key}' names a key no action uses")
        if tier == PermissionTier.ADMIN_ONLY:
            problems.append(
                f"policy override ({policy_key}, {category.value}) must not be ADMIN_ONLY "
                "(the runtime adapter would block it for everyone)"
            )
        if category == ActionCategory.FINANCIAL and tier != PermissionTier.HARD_BLOCKED:
            problems.append(f"policy override ({policy_key}, financial) must stay HARD_BLOCKED")
    return problems


# ---------------------------------------------------------------------------
# Lookups
# ---------------------------------------------------------------------------

_BY_KEY: dict[str, ConnectorDefinition] = {d.key: d for d in REGISTRY}


def get_definition(key: str) -> Optional[ConnectorDefinition]:
    """The definition registered under *key*, or None."""
    return _BY_KEY.get(key)


def is_registered(key: str) -> bool:
    """True when *key* is a registry connector (``mcp``/``custom`` are not)."""
    return key in _BY_KEY


def definition_for_provider(provider: str) -> Optional[ConnectorDefinition]:
    """The definition whose OAuth broker segment is *provider*, or None."""
    for definition in REGISTRY:
        oauth = definition.auth.oauth
        if oauth is not None and oauth.provider == provider:
            return definition
    return None


# ---------------------------------------------------------------------------
# Derived tables
# ---------------------------------------------------------------------------


def catalog_entries() -> dict[str, list[ToolSpec]]:
    """Connector entries of ``tool_registry.CONNECTOR_CATALOG`` (fresh lists)."""
    return {d.key: list(d.actions) for d in REGISTRY}


def credential_requirements() -> dict[str, dict[str, Any]]:
    """Registry entries of ``factory.CREDENTIAL_REQUIREMENTS`` (required/optional/notes)."""
    return {
        d.key: {
            "required": list(d.auth.required_credentials),
            "optional": list(d.auth.optional_credentials),
            "notes": d.auth.notes,
        }
        for d in REGISTRY
    }


def network_policy_keys() -> dict[str, str]:
    """connector key -> network policy key (``factory.NETWORK_POLICY_KEYS``)."""
    return {d.key: d.network.policy_key for d in REGISTRY}


def network_policies() -> dict[str, NetworkPolicy]:
    """network policy key -> ``NetworkPolicy`` built from each NetworkSpec."""
    policies: dict[str, NetworkPolicy] = {}
    for d in REGISTRY:
        net = d.network
        policies[net.policy_key] = NetworkPolicy(
            connector_type=net.policy_key,
            allowed_hosts=list(net.hosts),
            allowed_paths={host: list(paths) for host, paths in net.hosts.items()},
            instance_paths=list(net.instance_paths),
            https_only=net.https_only,
            redirect_hosts={host: list(paths) for host, paths in net.redirect_hosts.items()},
            ws_hosts=list(net.ws_hosts),
        )
    return policies


def permission_rows() -> dict[tuple[str, ActionCategory], PermissionTier]:
    """Default permission rows for every policy key and category.

    Generated from ``CATEGORY_TIERS`` and then each definition's
    ``policy_overrides``. FINANCIAL is always HARD_BLOCKED.
    """
    rows: dict[tuple[str, ActionCategory], PermissionTier] = {}
    for d in REGISTRY:
        for policy_key in d.policy_keys():
            for category in ActionCategory:
                tier = d.policy_overrides.get((policy_key, category), CATEGORY_TIERS[category])
                if category == ActionCategory.FINANCIAL:
                    tier = PermissionTier.HARD_BLOCKED
                rows[(policy_key, category)] = tier
    return rows


def _oauth_configured(d: ConnectorDefinition) -> bool:
    """True when sign-in can start: the same check the broker makes, so the
    card never offers a sign-in that then fails for a missing client id or
    (Google) client secret."""
    oauth = d.auth.oauth
    if oauth is None:
        return False
    from services.connectors.oauth_config import OAuthNotConfigured, resolve_client

    try:
        resolve_client(oauth)
    except OAuthNotConfigured:
        return False
    return True


def _scope_payload(d: ConnectorDefinition) -> dict[str, list[dict[str, Any]]]:
    by_scope: dict[str, list[ToolSpec]] = {}
    for spec in d.actions:
        if spec.required_scope and spec.category != ActionCategory.FINANCIAL:
            by_scope.setdefault(spec.required_scope, []).append(spec)
    grouped: dict[str, list[dict[str, Any]]] = {"read": [], "write": []}
    for scope in sorted(by_scope):
        specs = by_scope[scope]
        category = max((s.category for s in specs), key=_CATEGORY_RISK.__getitem__)
        grouped["read" if category == ActionCategory.READ else "write"].append(
            {
                "scope": scope,
                "category": category.value,
                "always_confirm": any(s.always_confirm for s in specs),
                "actions": [s.action for s in specs],
            }
        )
    return grouped


def connector_types_payload() -> list[dict[str, Any]]:
    """The body of ``GET /api/connectors/types``: one entry per connector.

    Shape (the frontend Connectors page consumes it)::

        {
          "key": "google_workspace", "label": str, "description": str,
          "icon": str (frontend icon name), "docs_url": str, "creatable": True,
          "auth": {
            "methods": ["oauth", "token"],   # UI preference order
            "fields": [{"key", "label", "type": "text"|"password"|"url",
                        "required": bool, "placeholder", "hint"}],
            "provider": "google" | None,     # OAuth broker URL segment
            "oauth_configured": bool,        # client id (and any secret) set
            "token_auth_method": "bearer_token"|"api_key"|"oauth2",
            "notes": str,
          },
          "scopes": {
            "read":  [{"scope", "category": "read", "always_confirm": bool,
                       "actions": [action names]}],
            "write": [{"scope", "category": "write"|"execute"|"delete",
                       "always_confirm": bool, "actions": [...]}],
          },
        }

    A scope's ``category`` is the most dangerous category among the actions
    requiring it (delete > execute > write > read) and ``always_confirm`` is
    true when any of them is. FINANCIAL actions and their scopes never
    appear: they cannot be granted. ``token_auth_method`` is the
    ``auth_method`` to send when creating a pasted-token connector.
    """
    return [
        {
            "key": d.key,
            "label": d.label,
            "description": d.description,
            "icon": d.icon,
            "docs_url": d.docs_url,
            "creatable": True,
            "auth": {
                "methods": list(d.auth.methods),
                "fields": [
                    {
                        "key": f.key,
                        "label": f.label,
                        "type": f.type,
                        "required": f.required,
                        "placeholder": f.placeholder,
                        "hint": f.hint,
                    }
                    for f in d.auth.fields
                ],
                "provider": d.auth.oauth.provider if d.auth.oauth else None,
                "oauth_configured": _oauth_configured(d),
                "token_auth_method": d.auth.token_auth_method,
                "notes": d.auth.notes,
            },
            "scopes": _scope_payload(d),
        }
        for d in REGISTRY
    ]


# ---------------------------------------------------------------------------
# Import-time registration
# ---------------------------------------------------------------------------


def _register() -> None:
    """Validate, then arm the derived network policies and permission rows.

    Registry policies replace the literal entries in network_security.py
    (they are a superset of them; the literals stay as a narrower backstop
    for code that never imports the registry). Permission rows use
    setdefault, so hand-written rows win.
    """
    problems = validate_registry(REGISTRY)
    if problems:
        raise ValueError(
            "Connector registry is invalid:\n- " + "\n- ".join(problems)
        )
    DEFAULT_POLICIES.update(network_policies())
    register_default_policies(permission_rows())


_register()
