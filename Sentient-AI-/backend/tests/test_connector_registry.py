"""Tests for the connector registry: every validation rule, the tables derived
from it, import-time registration and the always-confirm enforcement layers.

Why it exists: the registry replaced hand-written tables (tool catalog,
credential rules, network allowlists, permission rows). These tests pin the
derived values to what was hand-written before, prove each validation rule
fires on a crafted bad definition (and only that rule), and prove an
always-confirm action gets an approval card at build_tools, the runtime
permission adapter and the executor.

Depends on services/connectors/registry.py, factory.py, definition.py,
services/agent/tool_registry.py and permissions.py. No network.
"""

from __future__ import annotations

import dataclasses
import importlib.util
import json
import sys
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Callable, Optional

import pytest

import core.config
from core.network_security import DEFAULT_POLICIES
from services.agent import permissions
from services.agent.permissions import ActionCategory, PermissionEngine, PermissionTier
from services.agent.tool_registry import (
    CONNECTOR_CATALOG,
    ConnectorSpec,
    ConnectorToolExecutor,
    RuntimePermissionAdapter,
    build_tools,
    connector_scopes,
)
from services.connectors import factory, registry
from services.connectors.base import BaseConnector, UserConfirmationRequired
from services.connectors.canvas import CanvasConnector
from services.connectors.definition import (
    AuthSpec,
    ConnectorDefinition,
    CredentialField,
    NetworkSpec,
    OAuthSpec,
    ToolSpec,
    _schema,
)
from services.connectors.google_workspace import GoogleWorkspaceConnector
from services.connectors.robinhood import RobinhoodConnector

# The connectors that existed before the registry. Later packages append
# connectors (and Google gains actions), so checks against the hand-written
# tables are limited to these keys and treat the old values as a floor.
LEGACY_KEYS = ["canvas", "google_workspace", "robinhood"]

R, W, D, X, F = (
    ActionCategory.READ,
    ActionCategory.WRITE,
    ActionCategory.DELETE,
    ActionCategory.EXECUTE,
    ActionCategory.FINANCIAL,
)


# ---------------------------------------------------------------------------
# A known-good crafted definition, and helpers to break it one rule at a time
# ---------------------------------------------------------------------------


class _AcmeConnector(BaseConnector):
    _ACTIONS = frozenset({"list_things", "delete_thing"})

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

    async def _execute_action(self, action: str, params: dict[str, Any]) -> dict[str, Any]:
        return await self._dispatch(action, params)

    async def health_check(self) -> bool:
        return True

    async def list_things(self, limit: Any = None) -> list[dict[str, Any]]:
        return []

    async def delete_thing(self, thing_id: str, *, user_confirmed: bool = False) -> dict[str, Any]:
        return {}


_LIST = ToolSpec(
    "list_things",
    "List things.",
    R,
    _schema(limit={"type": "integer"}),
    required_scope="things.read",
    starter=True,
)
_DELETE = ToolSpec(
    "delete_thing",
    "Delete a thing.",
    D,
    _schema(thing_id={"type": "string", "required": True}),
    required_scope="things.write",
    always_confirm=True,
)

GOOD = ConnectorDefinition(
    key="acme",
    label="Acme",
    description="Things in Acme.",
    icon="plug",
    auth=AuthSpec(methods=("token",), fields=(CredentialField("access_token", "Access token"),)),
    network=NetworkSpec(policy_key="acme", hosts={"api.acme.test": ("/v1/",)}),
    actions=(_LIST, _DELETE),
    connector_class=_AcmeConnector,
    docs_url="https://acme.test/docs",
)

OAUTH_GOOD = dataclasses.replace(
    GOOD,
    auth=AuthSpec(
        methods=("oauth", "token"),
        fields=(CredentialField("access_token", "Access token"),),
        oauth=OAuthSpec(
            provider="acme",
            authorize_url="https://auth.acme.test/authorize",
            token_url="https://auth.acme.test/token",
            revoke_url="https://auth.acme.test/revoke",
            client_id_setting="ACME_OAUTH_CLIENT_ID",
            scope_map={"things.read": ("read",), "things.write": ("write",)},
        ),
    ),
    network=NetworkSpec(
        policy_key="acme",
        hosts={"api.acme.test": ("/v1/",), "auth.acme.test": ("/token", "/revoke")},
    ),
)


def _with(
    actions: tuple[ToolSpec, ...],
    methods: Optional[dict[str, Callable[..., Any]]] = None,
    *,
    base: ConnectorDefinition = GOOD,
    dispatch: Optional[frozenset[str]] = None,
    **changes: Any,
) -> ConnectorDefinition:
    """GOOD with other actions; a class is generated whose _ACTIONS match them."""
    names = frozenset(a.action for a in actions if a.category != F)
    attrs: dict[str, Any] = {"_ACTIONS": names if dispatch is None else dispatch}
    attrs.update(methods or {})
    cls = type("_Generated", (_AcmeConnector,), attrs)
    return dataclasses.replace(base, actions=actions, connector_class=cls, **changes)


async def _read_noargs(self):  # a READ method with no parameters
    return {}


async def _read_url(self, url):
    return {}


async def _read_action(self, action):
    return {}


def _only(problems: list[str], fragment: str) -> None:
    assert len(problems) == 1, problems
    assert fragment in problems[0], problems


# ---------------------------------------------------------------------------
# Positive: the shipped registry and the crafted fixtures are valid
# ---------------------------------------------------------------------------


def test_shipped_registry_is_valid():
    assert registry.validate_registry() == []
    # New connectors append lines; the three legacy ones stay first, in order.
    assert [d.key for d in registry.REGISTRY][:3] == LEGACY_KEYS


def test_crafted_fixtures_are_valid():
    assert registry.validate_registry([GOOD]) == []
    assert registry.validate_registry([OAUTH_GOOD]) == []


def test_template_definition_is_valid_and_not_registered():
    from services.connectors import _template

    assert registry.validate_registry([_template.DEFINITION]) == []
    assert not registry.is_registered(_template.DEFINITION.key)


def test_financial_ok_connector_may_declare_blocked_financial_actions():
    trade = ToolSpec("execute_trade", "Trade.", F, required_scope="things.trade")
    assert registry.validate_registry([_with((_LIST, trade), financial_ok=True)]) == []


def test_read_method_may_accept_user_confirmed():
    async def list_things(self, limit=None, *, user_confirmed=False):
        return []

    assert registry.validate_registry([_with((_LIST,), {"list_things": list_things})]) == []


# ---------------------------------------------------------------------------
# Negative: each crafted bad definition triggers exactly its own problem
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "key,fragment",
    [
        ("Acme", "must match"),
        ("a", "must match"),
        ("ac__me", "'__'"),
        ("1acme", "must match"),
    ],
)
def test_key_shape_rules(key, fragment):
    _only(registry.validate_registry([dataclasses.replace(GOOD, key=key)]), fragment)


@pytest.mark.parametrize("key", sorted(registry.RESERVED_KEYS))
def test_reserved_keys_are_refused(key):
    _only(registry.validate_registry([dataclasses.replace(GOOD, key=key)]), "reserved")


def test_duplicate_keys_are_refused():
    _only(registry.validate_registry([GOOD, GOOD]), "registered 2 times")


def test_every_action_needs_a_required_scope():
    unscoped = dataclasses.replace(_LIST, required_scope=None)
    _only(registry.validate_registry([_with((unscoped, _DELETE))]), "no required_scope")


def test_scope_must_look_like_area_dot_level():
    bad = dataclasses.replace(_LIST, required_scope="things")
    _only(registry.validate_registry([_with((bad, _DELETE))]), "must look like")


def test_financial_action_needs_financial_ok():
    trade = ToolSpec("get_payment", "Pay.", F, required_scope="things.pay")
    _only(registry.validate_registry([_with((_LIST, trade))]), "not financial_ok")


def test_financial_action_must_not_share_a_grantable_scope():
    trade = ToolSpec("execute_trade", "Trade.", F, required_scope="things.read")
    _only(
        registry.validate_registry([_with((_LIST, trade), financial_ok=True)]),
        "shared by FINANCIAL and non-FINANCIAL",
    )


def test_hard_blocked_name_is_refused_without_financial_ok():
    transfer = ToolSpec("transfer", "Move.", R, required_scope="things.read")
    problems = registry.validate_registry([_with((transfer,), {"transfer": _read_noargs})])
    _only(problems, "hard-block list")
    ok = _with((transfer,), {"transfer": _read_noargs}, financial_ok=True)
    assert registry.validate_registry([ok]) == []


def test_delete_must_be_always_confirm():
    loose = dataclasses.replace(_DELETE, always_confirm=False)
    _only(registry.validate_registry([_with((_LIST, loose))]), "must set always_confirm")


def test_only_reads_may_be_starters():
    starter_delete = dataclasses.replace(_DELETE, starter=True)
    _only(registry.validate_registry([_with((_LIST, starter_delete))]), "only READ actions")


def test_at_most_four_starters():
    specs = tuple(
        ToolSpec(f"read_{i}", "Read.", R, required_scope="things.read", starter=True)
        for i in range(5)
    )
    methods = {s.action: _read_noargs for s in specs}
    _only(registry.validate_registry([_with(specs, methods)]), "5 starter actions")


@pytest.mark.parametrize("param,method", [("url", _read_url), ("action", _read_action)])
def test_url_and_action_parameters_are_refused(param, method):
    spec = ToolSpec(
        "fetch_thing", "Fetch.", R, _schema(**{param: {"type": "string", "required": True}}),
        required_scope="things.read",
    )
    problems = registry.validate_registry([_with((spec,), {"fetch_thing": method})])
    _only(problems, f"parameter name '{param}' is not allowed")


def test_user_confirmed_is_never_a_schema_parameter():
    async def fetch_thing(self, *, user_confirmed=False):
        return {}

    spec = ToolSpec(
        "fetch_thing", "Fetch.", R, _schema(user_confirmed={"type": "boolean"}),
        required_scope="things.read",
    )
    problems = registry.validate_registry([_with((spec,), {"fetch_thing": fetch_thing})])
    assert any("'user_confirmed' is not allowed" in p for p in problems), problems


def test_reserved_policy_key_is_refused():
    web = dataclasses.replace(_LIST, policy_key="web")
    _only(registry.validate_registry([_with((web, _DELETE))]), "policy_key 'web'")


def test_scope_shared_by_read_and_write_is_refused():
    shared = dataclasses.replace(_DELETE, required_scope="things.read")
    _only(registry.validate_registry([_with((_LIST, shared))]), "shared by READ and non-READ")


def test_schema_required_names_must_be_properties():
    spec = ToolSpec(
        "count_things", "Count.", R,
        {"type": "object", "properties": {}, "required": ["ghost"]},
        required_scope="things.read",
    )
    problems = registry.validate_registry([_with((spec,), {"count_things": _read_noargs})])
    _only(problems, "are not properties")


def test_duplicate_action_names_are_refused():
    _only(registry.validate_registry([_with((_LIST, _LIST, _DELETE))]), "declared twice")


def test_dispatch_allow_map_must_equal_the_actions():
    problems = registry.validate_registry(
        [_with((_LIST, _DELETE), dispatch=frozenset({"list_things"}))]
    )
    _only(problems, "_ACTIONS")


def test_legacy_action_map_must_equal_the_actions():
    legacy = type(
        "_Legacy", (_AcmeConnector,), {"_ACTION_MAP": {"list_things": "list_things"}}
    )
    problems = registry.validate_registry([dataclasses.replace(GOOD, connector_class=legacy)])
    _only(problems, "_ACTION_MAP keys")


def test_legacy_action_map_must_not_rename():
    legacy = type(
        "_Legacy",
        (_AcmeConnector,),
        {"_ACTION_MAP": {"list_things": "delete_thing", "delete_thing": "delete_thing"}},
    )
    problems = registry.validate_registry([dataclasses.replace(GOOD, connector_class=legacy)])
    _only(problems, "its own name")


def test_every_action_needs_a_public_coroutine():
    ghost = ToolSpec("ghost_thing", "Ghost.", R, required_scope="things.read")
    _only(registry.validate_registry([_with((_LIST, ghost))]), "no public coroutine")


def test_sync_method_is_refused():
    def list_things(self, limit=None):
        return []

    problems = registry.validate_registry([_with((_LIST,), {"list_things": list_things})])
    _only(problems, "no public coroutine")


def test_method_parameters_must_equal_schema_properties():
    async def list_things(self, limit=None, cursor=None):
        return []

    problems = registry.validate_registry([_with((_LIST,), {"list_things": list_things})])
    _only(problems, "differ from schema properties")


def test_var_keyword_methods_are_refused():
    async def list_things(self, limit=None, **extra):
        return []

    problems = registry.validate_registry([_with((_LIST,), {"list_things": list_things})])
    _only(problems, "*args or **kwargs")


def test_non_read_method_needs_user_confirmed():
    async def delete_thing(self, thing_id):
        return {}

    problems = registry.validate_registry([_with((_DELETE,), {"delete_thing": delete_thing})])
    _only(problems, "lacks user_confirmed")


def test_user_confirmed_must_be_keyword_only_false():
    async def delete_thing(self, thing_id, user_confirmed=False):
        return {}

    problems = registry.validate_registry([_with((_DELETE,), {"delete_thing": delete_thing})])
    _only(problems, "keyword-only")


def test_parameter_without_default_must_be_required_in_schema():
    async def list_things(self, limit):
        return []

    problems = registry.validate_registry([_with((_LIST,), {"list_things": list_things})])
    _only(problems, "not required in the schema")


def test_connector_class_must_be_a_base_connector():
    problems = registry.validate_registry([dataclasses.replace(GOOD, connector_class=object)])
    _only(problems, "BaseConnector subclass")


def test_supports_revoke_needs_a_real_revoke():
    claims = type("_Claims", (_AcmeConnector,), {"SUPPORTS_REVOKE": True})
    problems = registry.validate_registry([dataclasses.replace(GOOD, connector_class=claims)])
    _only(problems, "SUPPORTS_REVOKE")

    async def revoke(self) -> bool:
        return True

    revokes = type("_Revokes", (_AcmeConnector,), {"SUPPORTS_REVOKE": True, "revoke": revoke})
    assert registry.validate_registry([dataclasses.replace(GOOD, connector_class=revokes)]) == []


def test_abstract_connector_class_is_refused():
    abstract = type(
        "_Abstract",
        (BaseConnector,),
        {
            "_ACTIONS": frozenset({"list_things", "delete_thing"}),
            "list_things": _AcmeConnector.list_things,
            "delete_thing": _AcmeConnector.delete_thing,
        },
    )
    problems = registry.validate_registry([dataclasses.replace(GOOD, connector_class=abstract)])
    _only(problems, "abstract")


@pytest.mark.parametrize(
    "network,fragment",
    [
        (NetworkSpec("acme", {"api.acme.test": ()}), "no path prefix"),
        (NetworkSpec("acme", {"api.acme.test": ("v1/",)}), "must start with '/'"),
        (NetworkSpec("acme", {"api.acme.test": ("/v1/",)}, https_only=False), "https_only"),
        (NetworkSpec("acme", {"API.acme.test": ("/v1/",)}), "bare lowercase hostname"),
        (NetworkSpec("acme", {"api.acme.test/x": ("/v1/",)}), "bare lowercase hostname"),
        (NetworkSpec("acme", {"api.*.test": ("/v1/",)}), "leftmost label"),
        (NetworkSpec("acme", {"localhost": ("/v1/",)}), "at least two labels"),
        (NetworkSpec("acme", {}), "lists no hosts"),
        (
            NetworkSpec("acme", {"api.acme.test": ("/v1/",)}, ws_hosts=("*.acme.test",)),
            "exact (no wildcard)",
        ),
        (
            NetworkSpec("acme", {"api.acme.test": ("/v1/",)}, redirect_hosts={"dl.acme.test": ()}),
            "redirect host",
        ),
        (NetworkSpec("web", {"api.acme.test": ("/v1/",)}), "invalid or reserved"),
    ],
)
def test_network_rules(network, fragment):
    _only(registry.validate_registry([dataclasses.replace(GOOD, network=network)]), fragment)


def test_canvas_alone_may_allow_plain_http():
    assert not registry.get_definition("canvas").network.https_only
    assert "canvas" in registry.HTTP_ALLOWED_KEYS
    assert registry.HTTP_ALLOWED_KEYS == frozenset({"canvas"})


def test_duplicate_network_policy_key_is_refused():
    other = dataclasses.replace(GOOD, key="acme_two")
    problems = registry.validate_registry([GOOD, other])
    _only(problems, "network policy key 'acme' is already used")


def test_permission_key_shared_across_connectors_is_refused():
    gmail_list = dataclasses.replace(_LIST, policy_key="gmail")
    other = _with(
        (gmail_list, _DELETE),
        key="acme_two",
        network=NetworkSpec("acme_two", {"api.acme.test": ("/v1/",)}),
    )
    problems = registry.validate_registry([registry.get_definition("google_workspace"), other])
    _only(problems, "permission key 'gmail' is already used")


def _oauth(**changes: Any) -> ConnectorDefinition:
    assert OAUTH_GOOD.auth.oauth is not None
    oauth = dataclasses.replace(OAUTH_GOOD.auth.oauth, **changes)
    return dataclasses.replace(OAUTH_GOOD, auth=dataclasses.replace(OAUTH_GOOD.auth, oauth=oauth))


@pytest.mark.parametrize(
    "definition,fragment",
    [
        (_oauth(token_url="https://evil.test/token"), "token_url"),
        (_oauth(revoke_url="http://auth.acme.test/revoke"), "revoke_url"),
        (_oauth(revoke_url="https://auth.acme.test/other"), "revoke_url"),
        (_oauth(scope_map={"things.read": ("read",)}), "does not map catalog scopes"),
        (
            _oauth(scope_map={"things.read": ("r",), "things.write": ("w",), "old.read": ("o",)}),
            "no action uses",
        ),
        (_oauth(client_id_setting=""), "client_id_setting"),
        (_oauth(authorize_url=""), "authorize_url"),
        (_oauth(provider="Acme!"), "URL segment"),
    ],
)
def test_oauth_rules(definition, fragment):
    _only(registry.validate_registry([definition]), fragment)


def test_device_method_needs_a_device_code_url():
    auth = dataclasses.replace(OAUTH_GOOD.auth, methods=("device", "token"))
    _only(
        registry.validate_registry([dataclasses.replace(OAUTH_GOOD, auth=auth)]),
        "device_code_url",
    )


def test_duplicate_oauth_provider_is_refused():
    other = dataclasses.replace(
        OAUTH_GOOD,
        key="acme_two",
        network=dataclasses.replace(OAUTH_GOOD.network, policy_key="acme_two"),
    )
    _only(registry.validate_registry([OAUTH_GOOD, other]), "OAuth provider 'acme'")


@pytest.mark.parametrize(
    "auth,fragment",
    [
        (AuthSpec(methods=()), "no sign-in method"),
        (AuthSpec(methods=("magic",), fields=(CredentialField("k", "K"),)), "distinct values"),  # type: ignore[arg-type]
        (AuthSpec(methods=("token", "token"), fields=(CredentialField("k", "K"),)), "distinct values"),
        (AuthSpec(methods=("token",)), "at least one credential field"),
        (AuthSpec(methods=("oauth",)), "need an OAuthSpec"),
        (
            AuthSpec(methods=("token",), fields=(CredentialField("k", "K"), CredentialField("k", "K2"))),
            "unique",
        ),
        (
            AuthSpec(methods=("token",), fields=(CredentialField("k", "K", type="blob"),)),  # type: ignore[arg-type]
            "unknown type",
        ),
        (
            AuthSpec(methods=("token",), fields=(CredentialField("k", "K", required=False),)),
            "must be required",
        ),
        (
            AuthSpec(
                methods=("token",),
                fields=(CredentialField("k", "K"),),
                token_auth_method="password",  # type: ignore[arg-type]
            ),
            "not an AuthMethod",
        ),
    ],
)
def test_auth_rules(auth, fragment):
    _only(registry.validate_registry([dataclasses.replace(GOOD, auth=auth)]), fragment)


def test_oauth_spec_without_a_broker_method_is_refused():
    auth = dataclasses.replace(OAUTH_GOOD.auth, methods=("token",))
    _only(
        registry.validate_registry([dataclasses.replace(OAUTH_GOOD, auth=auth)]),
        "neither 'oauth' nor 'device'",
    )


@pytest.mark.parametrize(
    "overrides,fragment",
    [
        ({("acme", R): PermissionTier.ADMIN_ONLY}, "must not be ADMIN_ONLY"),
        ({("other", R): PermissionTier.USER_CONFIRM}, "names a key no action uses"),
        ({("acme", F): PermissionTier.USER_CONFIRM}, "must stay HARD_BLOCKED"),
    ],
)
def test_policy_override_rules(overrides, fragment):
    problems = registry.validate_registry([dataclasses.replace(GOOD, policy_overrides=overrides)])
    _only(problems, fragment)


@pytest.mark.parametrize(
    "changes,fragment",
    [
        ({"label": " "}, "label must not be empty"),
        ({"icon": ""}, "icon must not be empty"),
        ({"docs_url": "http://acme.test/docs"}, "docs_url"),
    ],
)
def test_presentation_rules(changes, fragment):
    _only(registry.validate_registry([dataclasses.replace(GOOD, **changes)]), fragment)


def test_empty_action_list_is_refused():
    problems = registry.validate_registry([_with(())])
    _only(problems, "declares no actions")


def test_import_time_registration_raises_listing_every_problem(monkeypatch):
    bad = dataclasses.replace(GOOD, key="web", label="")
    monkeypatch.setattr(registry, "REGISTRY", (bad,))
    with pytest.raises(ValueError) as exc:
        registry._register()
    message = str(exc.value)
    assert "reserved" in message and "label must not be empty" in message


# ---------------------------------------------------------------------------
# Derived tables equal the values that were hand-written before the registry
# ---------------------------------------------------------------------------

OLD_CREDENTIAL_REQUIREMENTS = {
    "canvas": {
        "required": ["base_url", "access_token"],
        "optional": ["client_id", "client_secret", "refresh_token"],
        "notes": "base_url is your school's Canvas instance, e.g. https://myschool.instructure.com",
    },
    "google_workspace": {
        "required": ["access_token"],
        "optional": ["refresh_token", "client_id", "client_secret"],
        "notes": "OAuth access token with the Gmail/Calendar scopes you intend to grant.",
    },
    "robinhood": {
        "required": ["api_key", "api_secret"],
        "optional": [],
        "notes": "Read-only API credentials. Trading is permanently blocked by the platform.",
    },
    "mcp": {
        "required": ["url"],
        "optional": ["headers"],
        "notes": (
            "Streamable-HTTP MCP endpoint, e.g. https://example.com/mcp. "
            "Every MCP tool call requires your approval."
        ),
    },
}

OLD_NETWORK_POLICY_KEYS = {"canvas": "canvas", "google_workspace": "google", "robinhood": "robinhood"}

_COURSE = {"type": "string", "description": "Canvas course id"}
# (action, category, required_scope, policy_key, properties, required)
OLD_CATALOG: dict[str, list[tuple[str, ActionCategory, str, Optional[str], dict, list]]] = {
    "canvas": [
        ("get_courses", R, "courses.read", None, {}, []),
        ("get_assignments", R, "assignments.read", None, {"course_id": _COURSE}, ["course_id"]),
        ("get_grades", R, "grades.read", None, {"course_id": _COURSE}, ["course_id"]),
        ("get_calendar_events", R, "calendar.read", None, {}, []),
        (
            "get_submissions", R, "submissions.read", None,
            {"course_id": {"type": "string"}, "assignment_id": {"type": "string"}},
            ["course_id", "assignment_id"],
        ),
        (
            "submit_assignment", W, "submissions.write", None,
            {
                "course_id": {"type": "string"},
                "assignment_id": {"type": "string"},
                "submission_data": {"type": "object"},
            },
            ["course_id", "assignment_id", "submission_data"],
        ),
    ],
    "google_workspace": [
        (
            "get_messages", R, "gmail.read", "gmail",
            {"query": {"type": "string"}, "max_results": {"type": "integer"}}, [],
        ),
        ("get_message", R, "gmail.read", "gmail", {"message_id": {"type": "string"}}, ["message_id"]),
        ("search_emails", R, "gmail.read", "gmail", {"query": {"type": "string"}}, ["query"]),
        (
            "send_email", W, "gmail.send", "gmail",
            {"to": {"type": "string"}, "subject": {"type": "string"}, "body": {"type": "string"}},
            ["to", "subject", "body"],
        ),
        (
            "get_events", R, "calendar.read", "google_calendar",
            {"time_min": {"type": "string"}, "time_max": {"type": "string"}}, [],
        ),
        (
            "check_availability", R, "calendar.read", "google_calendar",
            {"time_min": {"type": "string"}, "time_max": {"type": "string"}}, [],
        ),
        (
            "create_event", W, "calendar.write", "google_calendar",
            {
                "event_data": {
                    "type": "object",
                    "description": "Google Calendar event resource (summary, start, end, ...)",
                }
            },
            ["event_data"],
        ),
    ],
    "robinhood": [
        ("get_crypto_portfolio", R, "crypto.read", None, {}, []),
        (
            "get_crypto_prices", R, "crypto.read", None,
            {"symbols": {"type": "array", "items": {"type": "string"}}}, ["symbols"],
        ),
        ("get_crypto_holdings", R, "crypto.read", None, {}, []),
        (
            "execute_trade", F, "crypto.trade", None,
            {"symbol": {"type": "string"}, "side": {"type": "string"}}, ["symbol", "side"],
        ),
    ],
}

OLD_DESCRIPTIONS = {
    "canvas.get_courses": "List the user's active Canvas courses.",
    "google_workspace.send_email": "Send an email via Gmail.",
    "robinhood.execute_trade": "Execute a crypto trade. Permanently blocked by platform policy.",
}


def test_credential_requirements_equal_the_old_table():
    table = factory.CREDENTIAL_REQUIREMENTS
    assert {k: table[k] for k in OLD_CREDENTIAL_REQUIREMENTS} == OLD_CREDENTIAL_REQUIREMENTS
    # The old keys keep their relative order (registry connectors, then mcp).
    assert [k for k in table if k in OLD_CREDENTIAL_REQUIREMENTS] == list(OLD_CREDENTIAL_REQUIREMENTS)
    assert list(table)[-1] == "mcp"
    # Every registry connector has an entry, not only the legacy ones.
    assert set(registry.credential_requirements()) == {d.key for d in registry.REGISTRY}


def test_network_policy_keys_equal_the_old_table():
    for derived in (factory.NETWORK_POLICY_KEYS, registry.network_policy_keys()):
        assert {k: derived[k] for k in OLD_NETWORK_POLICY_KEYS} == OLD_NETWORK_POLICY_KEYS
        assert [k for k in derived if k in OLD_NETWORK_POLICY_KEYS] == list(OLD_NETWORK_POLICY_KEYS)


def _catalog_tuple(spec: ToolSpec) -> tuple[Any, ...]:
    return (
        spec.action,
        spec.category,
        spec.required_scope,
        spec.policy_key,
        spec.parameters.get("properties", {}),
        spec.parameters.get("required", []),
    )


def test_connector_catalog_entries_equal_the_old_catalog():
    for key, expected in OLD_CATALOG.items():
        by_name = {s.action: s for s in CONNECTOR_CATALOG[key]}
        # Every old action is still there, unchanged (Google may gain more).
        for old in expected:
            spec = by_name.get(old[0])
            assert spec is not None, (key, old[0])
            assert _catalog_tuple(spec) == old, (key, old[0])
            # Actions without parameters keep the empty-dict form build_tools
            # expands to the empty schema.
            assert spec.parameters or not old[4], (key, old[0])
        # The old actions keep their relative order.
        old_names = [old[0] for old in expected]
        assert [n for n in by_name if n in old_names] == old_names, key
    # Canvas and Robinhood are not extended by the connectors plan.
    for key in ("canvas", "robinhood"):
        assert [s.action for s in CONNECTOR_CATALOG[key]] == [o[0] for o in OLD_CATALOG[key]]
    for name, description in OLD_DESCRIPTIONS.items():
        key, action = name.split(".")
        assert next(s for s in CONNECTOR_CATALOG[key] if s.action == action).description == description


def test_catalog_is_registry_first_then_builtins_unchanged():
    keys = list(CONNECTOR_CATALOG)
    assert keys[:3] == ["canvas", "google_workspace", "robinhood"]
    for builtin in ("web", "reminders", "system", "desktop", "browser"):
        assert builtin in CONNECTOR_CATALOG
    assert CONNECTOR_CATALOG["canvas"] == list(registry.get_definition("canvas").actions)


def test_toolspec_and_schema_are_reexported_from_definition():
    from services.agent import tool_registry
    from services.connectors import definition

    assert tool_registry.ToolSpec is definition.ToolSpec
    assert tool_registry._schema is definition._schema


def test_always_confirm_and_starter_flags():
    flags = {
        f"{d.key}.{s.action}": (s.always_confirm, s.starter)
        for d in registry.REGISTRY
        for s in d.actions
    }
    assert flags["google_workspace.send_email"] == (True, False)
    # Every DELETE is always_confirm (owner decision 6).
    for d in registry.REGISTRY:
        for s in d.actions:
            if s.category == D:
                assert s.always_confirm, f"{d.key}.{s.action}"
    # Nothing in Canvas or Robinhood, nor Google's calendar write, needs it.
    for name, (confirm, _) in flags.items():
        if name.split(".")[0] in ("canvas", "robinhood") or name == "google_workspace.create_event":
            assert not confirm, name
    for d in registry.REGISTRY:
        starters = [s for s in d.actions if s.starter]
        assert 2 <= len(starters) <= 4, d.key
        assert all(s.category == R for s in starters)


def _literal_network_policies(monkeypatch) -> dict[str, Any]:
    """DEFAULT_POLICIES exactly as written in network_security.py.

    The live dict has been updated by the registry, so a private copy of
    the module is executed (registered only for the test) to read the
    literal entries.
    """
    import core.network_security as live

    name = "_network_security_literal"
    spec = importlib.util.spec_from_file_location(name, live.__file__)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    monkeypatch.setitem(sys.modules, name, module)
    spec.loader.exec_module(module)
    return module.DEFAULT_POLICIES


def test_literal_network_policies_are_subsets_of_the_registry_ones(monkeypatch):
    literal = _literal_network_policies(monkeypatch)
    derived = registry.network_policies()
    assert set(literal) <= set(derived)
    for key, old in literal.items():
        new = derived[key]
        assert set(old.allowed_hosts) <= set(new.allowed_hosts), key
        for host, paths in old.allowed_paths.items():
            assert set(paths) <= set(new.allowed_paths[host]), (key, host)
        assert old.instance_paths == new.instance_paths, key


def test_registry_network_policies_are_armed_at_import():
    google = DEFAULT_POLICIES["google"]
    assert "/revoke" in google.allowed_paths["oauth2.googleapis.com"]
    assert google.https_only is True
    assert DEFAULT_POLICIES["canvas"].https_only is False
    assert DEFAULT_POLICIES["canvas"].instance_paths == ["/api/v1/", "/login/oauth2/token"]
    robinhood_paths = DEFAULT_POLICIES["robinhood"].allowed_paths["trading.robinhood.com"]
    assert not any("orders" in path for path in robinhood_paths)


def test_every_oauth_endpoint_the_backend_calls_is_inside_the_network_spec():
    for d in registry.REGISTRY:
        oauth = d.auth.oauth
        if oauth is None:
            continue
        for url in (oauth.token_url, oauth.revoke_url, oauth.device_code_url):
            if url:
                assert registry._url_in_network(url, d.network.hosts), url


@pytest.mark.parametrize(
    "pattern,host,expected",
    [
        ("api.acme.test", "api.acme.test", True),
        ("api.acme.test", "API.Acme.test", True),  # case-insensitive, like the runtime
        ("api.acme.test", "x.api.acme.test", False),
        ("*.instructure.com", "school.instructure.com", True),
        ("*.instructure.com", "instructure.com", True),
        ("*.instructure.com", "evilinstructure.com", False),
        ("res*.blob.test", "res123.blob.test", True),
        ("res*.blob.test", "res1.x.blob.test", False),
        ("res*.blob.test", "other.blob.test", False),
    ],
)
def test_oauth_url_check_uses_the_runtime_host_matcher(pattern, host, expected):
    from core.network_security import host_matches

    assert registry._url_in_network(f"https://{host}/v1/token", {pattern: ("/v1/",)}) is expected
    assert host_matches(host, pattern) is expected  # the same verdict as the runtime
    assert not hasattr(registry, "host_matches")  # no second, reversed-argument copy


def test_oauth_url_check_uses_the_most_specific_entry_paths():
    # Exact entries win over wildcards, as in check_network_policy: the
    # wildcard's broader path list must not rescue a path the exact host lacks.
    hosts = {"*.acme.test": ("/",), "auth.acme.test": ("/token",)}
    assert registry._url_in_network("https://auth.acme.test/token", hosts)
    assert not registry._url_in_network("https://auth.acme.test/other", hosts)
    assert registry._url_in_network("https://api.acme.test/anything", hosts)
    assert not registry._url_in_network("http://auth.acme.test/token", hosts)


# ---------------------------------------------------------------------------
# Permission rows
# ---------------------------------------------------------------------------


def test_generated_permission_rows_follow_category_tiers():
    rows = registry.permission_rows()
    for key in ("canvas", "gmail", "google_calendar"):
        assert rows[(key, R)] == PermissionTier.AUTO_APPROVE
        assert rows[(key, W)] == PermissionTier.USER_CONFIRM
        assert rows[(key, D)] == PermissionTier.USER_CONFIRM
        assert rows[(key, X)] == PermissionTier.USER_CONFIRM
        assert rows[(key, F)] == PermissionTier.HARD_BLOCKED
    # Robinhood's override keeps reads on the approval card.
    assert rows[("robinhood", R)] == PermissionTier.USER_CONFIRM
    assert PermissionTier.ADMIN_ONLY not in rows.values()
    assert all(tier == PermissionTier.HARD_BLOCKED for (_, c), tier in rows.items() if c == F)


def test_hand_written_rows_win_over_generated_ones():
    live = permissions._DEFAULT_POLICIES
    assert live[("robinhood", R)] == PermissionTier.USER_CONFIRM
    # Pinned by test_admin_role.py; generated rows must not replace it.
    assert live[("google", D)] == PermissionTier.ADMIN_ONLY
    assert live[("google", X)] == PermissionTier.ADMIN_ONLY


@pytest.mark.parametrize("key", ["gmail", "google_calendar", "github"])
def test_delete_rows_are_user_confirm_now(key):
    assert permissions._DEFAULT_POLICIES[(key, D)] == PermissionTier.USER_CONFIRM


def test_register_default_policies_uses_setdefault(monkeypatch):
    table = {("acme", R): PermissionTier.USER_CONFIRM}
    monkeypatch.setattr(permissions, "_DEFAULT_POLICIES", table)
    permissions.register_default_policies(
        {("acme", R): PermissionTier.AUTO_APPROVE, ("Acme", W): PermissionTier.USER_CONFIRM}
    )
    assert table == {
        ("acme", R): PermissionTier.USER_CONFIRM,
        ("acme", W): PermissionTier.USER_CONFIRM,
    }


def test_register_default_policies_refuses_loosening_financial(monkeypatch):
    monkeypatch.setattr(permissions, "_DEFAULT_POLICIES", {})
    with pytest.raises(ValueError, match="FINANCIAL"):
        permissions.register_default_policies({("acme", F): PermissionTier.AUTO_APPROVE})
    assert permissions._DEFAULT_POLICIES == {}


# ---------------------------------------------------------------------------
# Lookups and the factory
# ---------------------------------------------------------------------------


def test_lookups():
    assert registry.get_definition("canvas").connector_class is CanvasConnector
    assert registry.get_definition("mcp") is None
    assert registry.is_registered("google_workspace")
    assert not registry.is_registered("mcp")
    assert not registry.is_registered("custom")
    assert registry.definition_for_provider("google").key == "google_workspace"
    assert registry.definition_for_provider("nope") is None


@pytest.mark.parametrize(
    "key,credentials,cls,policy",
    [
        ("canvas", {"base_url": "https://s.instructure.com", "access_token": "t"}, CanvasConnector, "canvas"),
        ("google_workspace", {"access_token": "t", "client_id": "cid"}, GoogleWorkspaceConnector, "google"),
        ("robinhood", {"api_key": "k", "api_secret": "s"}, RobinhoodConnector, "robinhood"),
    ],
)
def test_create_connector_uses_the_definition(key, credentials, cls, policy):
    connector = factory.create_connector(key, credentials, timeout_s=2.0)
    assert type(connector) is cls
    assert connector._network_policy_key == policy
    assert connector._timeout == 2.0


def test_create_connector_reproduces_constructor_arguments():
    google = factory.create_connector(
        "google_workspace", {"access_token": "t", "client_id": "cid", "client_secret": "cs"}
    )
    assert (google._client_id, google._client_secret) == ("cid", "cs")
    canvas = factory.create_connector(
        "canvas", {"base_url": "https://s.instructure.com/", "access_token": "t"}
    )
    assert canvas._base_url == "https://s.instructure.com"
    assert (canvas._client_id, canvas._client_secret) == ("", "")
    robinhood = factory.create_connector("robinhood", {"api_key": "k", "api_secret": "s"})
    assert robinhood._api_key == "" and robinhood._timeout == 30.0


def test_self_hosted_canvas_host_is_the_only_extra_host():
    connector = factory.create_connector(
        "canvas", {"base_url": "https://Canvas.MySchool.edu", "access_token": "t"}
    )
    assert connector._policy_extra_hosts == ("canvas.myschool.edu",)
    google = factory.create_connector("google_workspace", {"access_token": "t"})
    assert google._policy_extra_hosts == ()


@pytest.mark.parametrize(
    "base_url,problem",
    [
        ("school.instructure.com", "base_url must start with http:// or https://"),
        ("https://", "base_url must include a hostname"),
        ("", "Missing required credential field 'base_url'"),
    ],
)
def test_canvas_credential_validation_moved_to_the_class(base_url, problem):
    creds = {"base_url": base_url, "access_token": "t"}
    assert factory.validate_credentials("canvas", creds) == [problem]


def test_mcp_validation_stays_in_the_factory():
    assert factory.validate_credentials("mcp", {"url": "ftp://x", "headers": "bad"}) == [
        "url must start with http:// or https://",
        "headers must be an object of header name -> value",
    ]
    with pytest.raises(factory.CredentialError, match="Unsupported connector type"):
        factory.create_connector("mcp", {"url": "https://mcp.example.com/rpc"})


def test_canvas_persists_a_rotated_token_and_drops_a_used_code():
    connector = CanvasConnector(base_url="https://s.instructure.com", client_id="", client_secret="")
    original = {"base_url": "https://s.instructure.com", "access_token": "old", "refresh_token": "r1"}
    connector._access_token, connector._refresh_token = "old", "r1"
    assert connector.updated_credentials(original) is None

    connector._access_token, connector._refresh_token = "new", "r2"
    updated = connector.updated_credentials({**original, "code": "c", "code_verifier": "v"})
    assert updated == {**original, "access_token": "new", "refresh_token": "r2"}

    connector._access_token = None
    assert connector.updated_credentials(original) is None


# ---------------------------------------------------------------------------
# connector_types_payload
# ---------------------------------------------------------------------------


def test_payload_shape():
    payload = registry.connector_types_payload()
    assert [entry["key"] for entry in payload] == [d.key for d in registry.REGISTRY]
    assert [entry["key"] for entry in payload][:3] == LEGACY_KEYS
    for entry in payload:
        assert set(entry) == {"key", "label", "description", "icon", "docs_url", "creatable", "auth", "scopes"}
        assert entry["creatable"] is True
        assert set(entry["auth"]) == {
            "methods", "fields", "provider", "oauth_configured", "token_auth_method", "notes",
        }
        for field in entry["auth"]["fields"]:
            assert set(field) == {"key", "label", "type", "required", "placeholder", "hint"}
        for group in ("read", "write"):
            for scope in entry["scopes"][group]:
                assert set(scope) == {"scope", "category", "always_confirm", "actions"}
    json.dumps(payload)  # serialisable as-is

    by_key = {entry["key"]: entry for entry in payload}
    assert {k: by_key[k]["icon"] for k in LEGACY_KEYS} == {
        "canvas": "graduation-cap", "google_workspace": "mail", "robinhood": "trending-up",
    }
    assert {k: by_key[k]["auth"]["token_auth_method"] for k in LEGACY_KEYS} == {
        "canvas": "bearer_token", "google_workspace": "oauth2", "robinhood": "api_key",
    }
    google = by_key["google_workspace"]
    assert google["auth"]["methods"] == ["oauth", "token"]
    assert google["auth"]["provider"] == "google"
    fields = {f["key"]: f for f in google["auth"]["fields"]}
    assert google["auth"]["fields"][0]["key"] == "access_token"
    assert fields["access_token"]["required"] is True
    assert {"refresh_token", "client_id", "client_secret"} <= set(fields)
    assert not any(fields[k]["required"] for k in ("refresh_token", "client_id", "client_secret"))
    assert {"calendar.read", "gmail.read"} <= {s["scope"] for s in google["scopes"]["read"]}
    send = next(s for s in google["scopes"]["write"] if s["scope"] == "gmail.send")
    assert send == {"scope": "gmail.send", "category": "write", "always_confirm": True, "actions": ["send_email"]}
    canvas = by_key["canvas"]
    assert canvas["auth"]["provider"] is None and canvas["auth"]["oauth_configured"] is False
    assert canvas["auth"]["fields"][0]["type"] == "url"


def test_payload_oauth_configured_reads_the_named_setting(monkeypatch):
    monkeypatch.setattr(core.config, "settings", SimpleNamespace(GOOGLE_OAUTH_CLIENT_ID=""))
    google = next(e for e in registry.connector_types_payload() if e["key"] == "google_workspace")
    assert google["auth"]["oauth_configured"] is False

    # Google also needs its client secret: with only the id the broker's
    # start would fail, so the card must not offer sign-in.
    monkeypatch.setattr(
        core.config, "settings",
        SimpleNamespace(GOOGLE_OAUTH_CLIENT_ID="test-client-id", GOOGLE_OAUTH_CLIENT_SECRET=""),
    )
    google = next(e for e in registry.connector_types_payload() if e["key"] == "google_workspace")
    assert google["auth"]["oauth_configured"] is False

    monkeypatch.setattr(
        core.config, "settings",
        SimpleNamespace(
            GOOGLE_OAUTH_CLIENT_ID="test-client-id", GOOGLE_OAUTH_CLIENT_SECRET="test-client-secret"
        ),
    )
    google = next(e for e in registry.connector_types_payload() if e["key"] == "google_workspace")
    assert google["auth"]["oauth_configured"] is True

    # Microsoft is a public client: the id alone is enough.
    monkeypatch.setattr(
        core.config, "settings", SimpleNamespace(MICROSOFT_OAUTH_CLIENT_ID="test-ms-client-id")
    )
    microsoft = next(e for e in registry.connector_types_payload() if e["key"] == "microsoft")
    assert microsoft["auth"]["oauth_configured"] is True

    monkeypatch.setattr(core.config, "settings", SimpleNamespace())  # setting not defined yet
    google = next(e for e in registry.connector_types_payload() if e["key"] == "google_workspace")
    assert google["auth"]["oauth_configured"] is False


def test_payload_scope_category_is_the_most_dangerous_action():
    write = ToolSpec("edit_thing", "Edit.", W, required_scope="things.write")
    run = ToolSpec("run_thing", "Run.", X, required_scope="things.run")
    write_run = ToolSpec("patch_thing", "Patch.", W, required_scope="things.run")
    definition = dataclasses.replace(GOOD, actions=(_LIST, write, _DELETE, run, write_run))
    scopes = registry._scope_payload(definition)
    assert scopes["read"] == [
        {"scope": "things.read", "category": "read", "always_confirm": False, "actions": ["list_things"]}
    ]
    assert scopes["write"] == [
        {"scope": "things.run", "category": "execute", "always_confirm": False,
         "actions": ["run_thing", "patch_thing"]},
        {"scope": "things.write", "category": "delete", "always_confirm": True,
         "actions": ["edit_thing", "delete_thing"]},
    ]


def test_payload_google_oauth_spec():
    oauth = registry.get_definition("google_workspace").auth.oauth
    assert oauth is not None
    assert oauth.provider_scopes(["gmail.read", "calendar.write"]) == (
        "https://www.googleapis.com/auth/gmail.readonly",
        "https://www.googleapis.com/auth/calendar.events",
    )
    assert dict(oauth.authorize_params) == {
        "access_type": "offline", "include_granted_scopes": "true", "prompt": "consent",
    }
    assert (oauth.client_id_setting, oauth.client_secret_setting) == (
        "GOOGLE_OAUTH_CLIENT_ID", "GOOGLE_OAUTH_CLIENT_SECRET",
    )


# ---------------------------------------------------------------------------
# FINANCIAL is never grantable
# ---------------------------------------------------------------------------


def test_financial_scope_is_never_grantable_or_offered():
    assert "crypto.trade" not in connector_scopes("robinhood")["read"]
    assert "crypto.trade" not in connector_scopes("robinhood")["write"]
    robinhood = next(e for e in registry.connector_types_payload() if e["key"] == "robinhood")
    assert robinhood["scopes"] == {
        "read": [{"scope": "crypto.read", "category": "read", "always_confirm": False,
                  "actions": ["get_crypto_portfolio", "get_crypto_prices", "get_crypto_holdings"]}],
        "write": [],
    }
    tools = build_tools(
        [ConnectorSpec("robinhood", granted_scopes=("crypto.read", "crypto.trade"),
                       permission_tier="auto_approve")],
        user_default_tier="auto_approve",
        include_builtins=False,
    )
    assert "robinhood.execute_trade" not in {t.name for t in tools}


@pytest.mark.parametrize("key", [d.key for d in registry.REGISTRY])
@pytest.mark.parametrize("override", [PermissionTier.AUTO_APPROVE, PermissionTier.USER_CONFIRM])
def test_no_override_can_unblock_a_financial_action(key, override):
    # The category check comes before overrides and before the name list, so
    # even an action name that is not on the hard-block list, under an
    # override that tries to loosen FINANCIAL, stays hard-blocked.
    engine = PermissionEngine(policy_overrides={(key, ActionCategory.FINANCIAL): override})
    decision = engine.check_permission(key, "move_funds_somewhere", ActionCategory.FINANCIAL)
    assert decision.allowed is False
    assert decision.tier == PermissionTier.HARD_BLOCKED
    assert decision.requires_approval is False


# ---------------------------------------------------------------------------
# always_confirm at all three layers
# ---------------------------------------------------------------------------

_LOOSE_GMAIL = PermissionEngine(policy_overrides={("gmail", W): PermissionTier.AUTO_APPROVE})


def test_layer1_build_tools_never_offers_always_confirm_as_auto():
    auto = [ConnectorSpec("google_workspace", permission_tier="auto_approve")]
    for engine in (None, _LOOSE_GMAIL):
        tools = {t.name: t for t in build_tools(auto, user_default_tier="auto_approve", engine=engine)}
        assert tools["google_workspace.send_email"].permission_tier == "approval"
        assert tools["google_workspace.create_event"].permission_tier == "auto"


@pytest.mark.asyncio
async def test_layer2_adapter_requires_approval_even_when_policy_auto_approves():
    adapter = RuntimePermissionAdapter(engine=_LOOSE_GMAIL)
    assert await adapter.check("u1", "google_workspace.send_email", {}) == "requires_approval"
    assert "always requires your approval" in await adapter.get_block_reason(
        "u1", "google_workspace.send_email", {}
    )
    # A read under the same engine is unaffected.
    assert await adapter.check("u1", "google_workspace.get_messages", {}) == "approved"


@pytest.mark.asyncio
async def test_layer2_blocked_stays_blocked():
    engine = PermissionEngine(policy_overrides={("gmail", W): PermissionTier.HARD_BLOCKED})
    adapter = RuntimePermissionAdapter(engine=engine)
    assert await adapter.check("u1", "google_workspace.send_email", {}) == "blocked"


class _RecordingConnector(BaseConnector):
    instances: list[_RecordingConnector] = []
    # Actions that, like a real connector's write methods, raise
    # UserConfirmationRequired unless called with user_confirmed=True.
    confirm_actions: frozenset[str] = frozenset()

    def __init__(self) -> None:
        super().__init__()
        self.executed: list[tuple[str, dict[str, Any]]] = []
        _RecordingConnector.instances.append(self)

    @property
    def name(self) -> str:
        return "Recording"

    @property
    def connector_type(self) -> str:
        return "test"

    @property
    def required_scopes(self) -> list[str]:
        return []

    async def authenticate(self, credentials: dict[str, Any]) -> bool:
        self._authenticated = True
        return True

    async def _execute_action(self, action: str, params: dict[str, Any]) -> dict[str, Any]:
        if action in self.confirm_actions and not params.get("user_confirmed"):
            raise UserConfirmationRequired(action=action, details=f"Run {action}?")
        self.executed.append((action, dict(params)))
        return {"status": "sent"}

    async def health_check(self) -> bool:
        return True


@pytest.fixture
def fake_factory(monkeypatch):
    """Route the executor's connector construction to _RecordingConnector."""
    _RecordingConnector.instances = []
    monkeypatch.setattr(_RecordingConnector, "confirm_actions", frozenset())

    def _fake_create(connector_type, credentials, *, rate_limit=None, timeout_s=None):
        connector = _RecordingConnector()
        connector.set_network_policy(factory.NETWORK_POLICY_KEYS.get(connector_type, connector_type))
        return connector

    monkeypatch.setattr(factory, "create_connector", _fake_create)


async def _google_row(
    session_factory,
    user_id,
    *,
    rate_limit=30,
    scopes=("gmail.read", "gmail.send"),
) -> None:
    from core.security import encrypt_credentials
    from models.connector import AuthMethod, ConnectorConfig

    async with session_factory() as session:
        session.add(
            ConnectorConfig(
                user_id=user_id,
                connector_type="google_workspace",
                display_name="Mail",
                auth_method=AuthMethod.oauth2,
                encrypted_credentials=encrypt_credentials(json.dumps({"access_token": "ya29.test"})),
                granted_scopes=list(scopes),
                rate_limit_per_minute=rate_limit,
            )
        )
        await session.commit()


@pytest.mark.asyncio
async def test_layer3_executor_refuses_unapproved_always_confirm(session_factory, fake_factory):
    from tests.conftest import make_user

    user, _ = await make_user(session_factory)
    # One call per minute: a refused call must not spend the slot.
    await _google_row(session_factory, user.id, rate_limit=1)
    executor = ConnectorToolExecutor(session_factory=session_factory)
    args = {"to": "a@example.com", "subject": "s", "body": "b"}

    refused = await executor.execute("google_workspace.send_email", args, str(user.id))
    assert refused["ok"] is False and refused["requires_approval"] is True
    assert "always needs your approval" in refused["error"]
    assert _RecordingConnector.instances == []  # nothing was built or sent

    approved = await executor.execute("google_workspace.send_email", args, str(user.id), approved=True)
    assert approved["ok"] is True, approved
    assert _RecordingConnector.instances[0].executed == [("send_email", args)]


@pytest.mark.asyncio
async def test_layer3_does_not_touch_ordinary_writes(session_factory, fake_factory, monkeypatch):
    from tests.conftest import make_user

    monkeypatch.setattr(_RecordingConnector, "confirm_actions", frozenset({"create_event"}))
    user, _ = await make_user(session_factory)
    await _google_row(session_factory, user.id, scopes=("calendar.write",))
    executor = ConnectorToolExecutor(session_factory=session_factory)
    args = {"event_data": {"summary": "Standup"}}

    # Unapproved: L3 lets it through to the connector, whose own
    # UserConfirmationRequired produces the approval request.
    pending = await executor.execute("google_workspace.create_event", args, str(user.id))
    assert pending["ok"] is False and pending["requires_approval"] is True
    assert "always needs your approval" not in pending["error"]
    assert "Run create_event?" in pending["error"]
    assert len(_RecordingConnector.instances) == 1  # the connector was built
    assert _RecordingConnector.instances[0].executed == []  # but nothing ran

    approved = await executor.execute(
        "google_workspace.create_event", args, str(user.id), approved=True
    )
    assert approved["ok"] is True, approved
    assert _RecordingConnector.instances[-1].executed == [
        ("create_event", {**args, "user_confirmed": True})
    ]


@pytest.mark.asyncio
async def test_layer3_does_not_touch_reads(session_factory, fake_factory):
    from tests.conftest import make_user

    user, _ = await make_user(session_factory)
    await _google_row(session_factory, user.id)
    executor = ConnectorToolExecutor(session_factory=session_factory)
    result = await executor.execute("google_workspace.get_messages", {}, str(user.id))
    assert result["ok"] is True, result


@pytest.mark.asyncio
async def test_executor_accepts_a_plain_string_or_enum_connector_type(session_factory):
    from models.connector import ConnectorType
    from tests.conftest import make_user

    user, _ = await make_user(session_factory)
    await _google_row(session_factory, user.id)
    executor = ConnectorToolExecutor(session_factory=session_factory)
    for value in ("google_workspace", ConnectorType.google_workspace):
        config = await executor._load_config(value, str(user.id))
        assert config is not None and config["credentials"] == {"access_token": "ya29.test"}
    assert await executor._load_config("mcp", str(user.id)) is None
    assert await executor._load_config("not_a_connector", str(user.id)) is None


def test_readme_documents_the_registry_steps():
    readme = Path(registry.__file__).with_name("README.md").read_text(encoding="utf-8")
    for needle in ("_template.py", "REGISTRY", "_template_test.py", "test_connector_registry.py"):
        assert needle in readme
    # House style: no em or en dashes (U+2014, U+2013).
    assert chr(0x2014) not in readme and chr(0x2013) not in readme
