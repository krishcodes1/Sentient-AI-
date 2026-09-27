"""Tests for the connector catalog endpoint and the string connector type:
``GET /api/connectors/types`` (auth, payload shape, route order), create-time
validation of ``connector_type`` against the registry, and that a stored row
whose type is no longer registered never breaks a reader.

Why it exists: ``connector_configs.connector_type`` stopped being a database
ENUM in revision 0011, so the API is now the only thing standing between a
typo and a stored row, and a removed connector leaves rows no code knows.

Connects to: ``api/routes/connectors.py``, ``api/routes/agent.py``
(``_build_tools_and_memory``), ``api/routes/auth.py`` (account export) and
``services/connectors/registry.py``. No external service is contacted.
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from typing import Any

import pytest

from tests.conftest import auth_headers, make_user

_RETIRED = "retired_service"
_LEGACY_TYPES = ("canvas", "google_workspace", "robinhood")
_ENTRY_KEYS = {
    "key",
    "label",
    "description",
    "icon",
    "docs_url",
    "creatable",
    "auth",
    "scopes",
}
_AUTH_KEYS = {
    "methods",
    "fields",
    "provider",
    "oauth_configured",
    "token_auth_method",
    "notes",
}
_FIELD_KEYS = {"key", "label", "type", "required", "placeholder", "hint"}
_CANVAS_CREDENTIALS = {
    "base_url": "https://canvas.example.edu",
    "access_token": "canvas-test-token",
}


def _canvas_payload(**overrides: Any) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "connector_type": "canvas",
        "display_name": "My Canvas",
        "auth_method": "bearer_token",
        "credentials": dict(_CANVAS_CREDENTIALS),
    }
    payload.update(overrides)
    return payload


async def _insert_row(session_factory, user_id: uuid.UUID, connector_type: str) -> uuid.UUID:
    """Write a connector row with raw SQL, the way a row written by an older
    build (whose connector has since been removed) sits in the database."""
    from sqlalchemy import insert

    from core.security import encrypt_credentials
    from models.connector import ConnectorConfig

    row_id = uuid.uuid4()
    now = datetime.now(timezone.utc)
    async with session_factory() as session:
        await session.execute(
            insert(ConnectorConfig.__table__).values(
                id=row_id,
                user_id=user_id,
                connector_type=connector_type,
                display_name=f"Old {connector_type}",
                is_active=True,
                auth_method="bearer_token",
                encrypted_credentials=encrypt_credentials(
                    json.dumps({"access_token": "retired-test-token"})
                ),
                granted_scopes=["things.read"],
                permission_tier="user_confirm",
                rate_limit_per_minute=30,
                created_at=now,
                updated_at=now,
            )
        )
        await session.commit()
    return row_id


# ---------------------------------------------------------------------------
# GET /api/connectors/types
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_types_requires_authentication(client):
    missing = await client.get("/api/connectors/types")
    assert missing.status_code in (401, 403)
    garbage = await client.get("/api/connectors/types", headers=auth_headers("not-a-jwt"))
    assert garbage.status_code == 401


@pytest.mark.asyncio
async def test_types_serves_the_registry_payload_verbatim(client, session_factory):
    from services.connectors.registry import connector_types_payload

    _, token = await make_user(session_factory, "types-verbatim@example.com")
    response = await client.get("/api/connectors/types", headers=auth_headers(token))

    assert response.status_code == 200
    assert response.json() == json.loads(json.dumps(connector_types_payload()))


@pytest.mark.asyncio
@pytest.mark.parametrize("key", _LEGACY_TYPES)
async def test_types_entry_shape(client, session_factory, key):
    _, token = await make_user(session_factory, f"types-{key}@example.com")
    body = (await client.get("/api/connectors/types", headers=auth_headers(token))).json()
    entry = next(e for e in body if e["key"] == key)

    assert _ENTRY_KEYS <= set(entry)
    assert entry["label"] and entry["description"] and entry["icon"]
    assert entry["creatable"] is True
    assert _AUTH_KEYS <= set(entry["auth"])
    assert entry["auth"]["methods"]
    assert set(entry["auth"]["methods"]) <= {"token", "oauth", "device"}
    for field in entry["auth"]["fields"]:
        assert set(field) == _FIELD_KEYS
        assert field["type"] in {"text", "password", "url"}
    assert set(entry["scopes"]) == {"read", "write"}
    for risk, scopes in entry["scopes"].items():
        for scope in scopes:
            assert {"scope", "category", "always_confirm", "actions"} <= set(scope)
            assert scope["actions"], f"{key} scope {scope['scope']} has no actions"
            if risk == "read":
                assert scope["category"] == "read"
            else:
                assert scope["category"] in {"write", "execute", "delete"}


@pytest.mark.asyncio
async def test_types_payload_matches_the_existing_connectors(client, session_factory):
    """The three connectors that predate the registry keep their fields and
    scope catalog, and the payload agrees with the scope validator."""
    from services.agent.tool_registry import connector_scopes

    _, token = await make_user(session_factory, "types-legacy@example.com")
    body = (await client.get("/api/connectors/types", headers=auth_headers(token))).json()
    by_key = {e["key"]: e for e in body}
    assert set(_LEGACY_TYPES) <= set(by_key)
    # Not registry keys: MCP keeps its own UI entry, custom is not creatable.
    assert "mcp" not in by_key and "custom" not in by_key

    canvas_fields = {f["key"]: f for f in by_key["canvas"]["auth"]["fields"]}
    assert canvas_fields["base_url"]["required"] is True
    assert canvas_fields["access_token"]["required"] is True
    assert canvas_fields["access_token"]["type"] == "password"
    assert "oauth" in by_key["google_workspace"]["auth"]["methods"]
    assert by_key["google_workspace"]["auth"]["provider"] == "google"

    for key in _LEGACY_TYPES:
        catalog = connector_scopes(key)
        payload_scopes = by_key[key]["scopes"]
        assert sorted(s["scope"] for s in payload_scopes["read"]) == sorted(catalog["read"])
        assert sorted(s["scope"] for s in payload_scopes["write"]) == sorted(catalog["write"])

    # Financial scopes can never be granted, so they are never offered.
    robinhood_scopes = {
        s["scope"] for group in by_key["robinhood"]["scopes"].values() for s in group
    }
    assert "crypto.trade" not in robinhood_scopes
    assert "crypto.read" in robinhood_scopes


@pytest.mark.asyncio
async def test_types_is_declared_before_the_connector_id_route(client, session_factory):
    """``/types`` must not be swallowed by ``/{connector_id}`` (which would
    answer 422 for a non-UUID id)."""
    from api.routes.connectors import router

    paths = [getattr(route, "path", "") for route in router.routes]
    assert paths.index("/connectors/types") < paths.index("/connectors/{connector_id}")

    _, token = await make_user(session_factory, "types-order@example.com")
    response = await client.get("/api/connectors/types", headers=auth_headers(token))
    assert response.status_code == 200
    assert isinstance(response.json(), list)
    # A real id still reaches the id route.
    missing = await client.get(f"/api/connectors/{uuid.uuid4()}", headers=auth_headers(token))
    assert missing.status_code == 404


# ---------------------------------------------------------------------------
# POST /api/connectors/ type validation
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_create_with_a_registered_type(client, session_factory):
    _, token = await make_user(session_factory, "create-registered@example.com")
    response = await client.post(
        "/api/connectors/", headers=auth_headers(token), json=_canvas_payload()
    )

    assert response.status_code == 201, response.text
    body = response.json()
    assert body["connector_type"] == "canvas"
    assert body["available"] is True
    # Least-privilege default grant is unchanged.
    assert "submissions.write" not in body["granted_scopes"]
    assert "courses.read" in body["granted_scopes"]
    assert "canvas-test-token" not in response.text

    listed = await client.get("/api/connectors/", headers=auth_headers(token))
    assert [(c["connector_type"], c["available"]) for c in listed.json()] == [("canvas", True)]


@pytest.mark.asyncio
async def test_create_stores_the_plain_key(client, session_factory):
    """The column holds the key itself, never ``ConnectorType.canvas``."""
    from sqlalchemy import text

    _, token = await make_user(session_factory, "create-plain@example.com")
    response = await client.post(
        "/api/connectors/", headers=auth_headers(token), json=_canvas_payload()
    )
    assert response.status_code == 201

    async with session_factory() as session:
        stored = (
            await session.execute(text("SELECT connector_type FROM connector_configs"))
        ).scalar_one()
    assert stored == "canvas"


@pytest.mark.asyncio
async def test_create_with_an_unknown_type_is_422(client, session_factory):
    _, token = await make_user(session_factory, "create-unknown@example.com")
    response = await client.post(
        "/api/connectors/",
        headers=auth_headers(token),
        json=_canvas_payload(connector_type="not_a_connector"),
    )

    assert response.status_code == 422
    detail = response.json()["detail"]
    assert "Unknown connector type 'not_a_connector'" in detail
    for key in (*_LEGACY_TYPES, "mcp"):
        assert key in detail
    assert "custom" not in detail

    listed = await client.get("/api/connectors/", headers=auth_headers(token))
    assert listed.json() == []


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "bad_type",
    [
        "",
        "Canvas",
        "canvas; DROP TABLE users",
        "../canvas",
        "a" * 65,
        "9lives",
    ],
)
async def test_create_with_a_malformed_type_is_422(client, session_factory, bad_type):
    _, token = await make_user(session_factory, f"create-bad-{uuid.uuid4().hex[:8]}@example.com")
    response = await client.post(
        "/api/connectors/",
        headers=auth_headers(token),
        json=_canvas_payload(connector_type=bad_type),
    )
    assert response.status_code == 422


@pytest.mark.asyncio
async def test_create_custom_keeps_its_422(client, session_factory):
    _, token = await make_user(session_factory, "create-custom@example.com")
    response = await client.post(
        "/api/connectors/",
        headers=auth_headers(token),
        json=_canvas_payload(connector_type="custom", credentials={}),
    )
    assert response.status_code == 422
    assert response.json()["detail"] == "custom connectors are not yet supported"


@pytest.mark.asyncio
async def test_create_mcp_is_still_allowed(client, session_factory):
    _, token = await make_user(session_factory, "create-mcp@example.com")
    response = await client.post(
        "/api/connectors/",
        headers=auth_headers(token),
        json={
            "connector_type": "mcp",
            "display_name": "Notes Server",
            "auth_method": "bearer_token",
            "credentials": {"url": "https://mcp.example.com/mcp", "headers": {}},
        },
    )
    assert response.status_code == 201, response.text
    assert response.json()["connector_type"] == "mcp"
    assert response.json()["available"] is True


# ---------------------------------------------------------------------------
# A stored row whose type is no longer registered
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_unregistered_row_is_listed_as_unavailable(client, session_factory):
    user, token = await make_user(session_factory, "stale-list@example.com")
    await client.post("/api/connectors/", headers=auth_headers(token), json=_canvas_payload())
    stale_id = await _insert_row(session_factory, user.id, _RETIRED)

    listed = await client.get("/api/connectors/", headers=auth_headers(token))
    assert listed.status_code == 200
    by_type = {c["connector_type"]: c for c in listed.json()}
    assert by_type[_RETIRED]["available"] is False
    assert by_type[_RETIRED]["id"] == str(stale_id)
    assert by_type["canvas"]["available"] is True

    one = await client.get(f"/api/connectors/{stale_id}", headers=auth_headers(token))
    assert one.status_code == 200
    assert one.json()["connector_type"] == _RETIRED
    assert one.json()["available"] is False


@pytest.mark.asyncio
async def test_unregistered_row_reads_unhealthy(client, session_factory):
    user, token = await make_user(session_factory, "stale-health@example.com")
    await client.post("/api/connectors/", headers=auth_headers(token), json=_canvas_payload())
    stale_id = await _insert_row(session_factory, user.id, _RETIRED)

    response = await client.get("/api/connectors/health", headers=auth_headers(token))
    assert response.status_code == 200
    entries = {e["id"]: e for e in response.json()}
    stale = entries[str(stale_id)]
    assert stale["type"] == _RETIRED
    assert stale["available"] is False
    assert stale["status"] == "unhealthy"
    assert "no longer available" in stale["detail"]
    canvas = next(e for e in response.json() if e["type"] == "canvas")
    assert canvas["available"] is True
    assert canvas["status"] == "healthy"


@pytest.mark.asyncio
async def test_legacy_custom_row_keeps_its_health_but_is_unavailable(client, session_factory):
    user, token = await make_user(session_factory, "stale-custom@example.com")
    custom_id = await _insert_row(session_factory, user.id, "custom")

    entries = (await client.get("/api/connectors/health", headers=auth_headers(token))).json()
    custom = next(e for e in entries if e["id"] == str(custom_id))
    assert custom["type"] == "custom"
    assert custom["available"] is False
    assert custom["status"] == "healthy"


@pytest.mark.asyncio
async def test_unregistered_row_test_refuses_without_network(client, session_factory, monkeypatch):
    import services.connectors.factory as factory_module

    def _no_factory(*_args, **_kwargs):
        raise AssertionError("create_connector must not run for an unknown type")

    monkeypatch.setattr(factory_module, "create_connector", _no_factory)
    user, token = await make_user(session_factory, "stale-test@example.com")
    stale_id = await _insert_row(session_factory, user.id, _RETIRED)

    response = await client.post(f"/api/connectors/{stale_id}/test", headers=auth_headers(token))
    assert response.status_code == 200
    assert response.json()["ok"] is False
    assert "no longer available" in response.json()["detail"]
    assert "retired-test-token" not in response.text


@pytest.mark.asyncio
async def test_unregistered_row_can_be_renamed_disabled_and_deleted(client, session_factory):
    user, token = await make_user(session_factory, "stale-patch@example.com")
    stale_id = await _insert_row(session_factory, user.id, _RETIRED)
    url = f"/api/connectors/{stale_id}"

    renamed = await client.patch(
        url,
        headers=auth_headers(token),
        json={"display_name": "Old thing", "is_active": False},
    )
    assert renamed.status_code == 200
    assert renamed.json()["display_name"] == "Old thing"
    assert renamed.json()["is_active"] is False
    assert renamed.json()["available"] is False

    # Nothing to validate scopes or credentials against: refused.
    scopes = await client.patch(
        url, headers=auth_headers(token), json={"granted_scopes": ["anything.goes"]}
    )
    assert scopes.status_code == 422
    creds = await client.patch(
        url, headers=auth_headers(token), json={"credentials": {"access_token": "x"}}
    )
    assert creds.status_code == 422

    deleted = await client.delete(url, headers=auth_headers(token))
    assert deleted.status_code == 204
    gone = await client.get(url, headers=auth_headers(token))
    assert gone.status_code == 404


@pytest.mark.asyncio
async def test_unregistered_row_survives_the_account_export(client, session_factory):
    user, token = await make_user(session_factory, "stale-export@example.com")
    await client.post("/api/connectors/", headers=auth_headers(token), json=_canvas_payload())
    await _insert_row(session_factory, user.id, _RETIRED)

    response = await client.get("/api/auth/export", headers=auth_headers(token))
    assert response.status_code == 200
    data = json.loads(response.text)
    assert sorted(c["connector_type"] for c in data["connectors"]) == [
        "canvas",
        _RETIRED,
    ]
    assert "retired-test-token" not in response.text
    assert "canvas-test-token" not in response.text


@pytest.mark.asyncio
async def test_unregistered_row_is_never_offered_to_the_agent(session_factory):
    from api.routes.agent import _build_tools_and_memory

    user, _ = await make_user(session_factory, "stale-tools@example.com")
    from core.security import encrypt_credentials
    from models.connector import AuthMethod, ConnectorConfig

    async with session_factory() as session:
        session.add(
            ConnectorConfig(
                user_id=user.id,
                connector_type="canvas",
                display_name="Canvas",
                auth_method=AuthMethod.bearer_token,
                encrypted_credentials=encrypt_credentials(json.dumps(_CANVAS_CREDENTIALS)),
                granted_scopes=["courses.read"],
            )
        )
        await session.commit()
    await _insert_row(session_factory, user.id, _RETIRED)
    await _insert_row(session_factory, user.id, "custom")

    async with session_factory() as db:
        tools, _memory, _permissions = await _build_tools_and_memory(None, user, db)

    names = {t.name for t in tools}
    assert "canvas.get_courses" in names
    assert not any(n.startswith(f"{_RETIRED}.") for n in names)
    assert not any(n.startswith("custom.") for n in names)
    assert not any(t.connector_type in (_RETIRED, "custom") for t in tools)


@pytest.mark.asyncio
async def test_only_unregistered_rows_still_build_a_turn(session_factory):
    from api.routes.agent import _build_tools_and_memory

    user, _ = await make_user(session_factory, "stale-only@example.com")
    await _insert_row(session_factory, user.id, _RETIRED)

    async with session_factory() as db:
        tools, _memory, permissions = await _build_tools_and_memory(None, user, db)

    assert permissions.startswith("<permissions>")
    assert not any(t.connector_type == _RETIRED for t in tools)


def test_connector_type_available_rules():
    from api.routes.connectors import connector_type_available
    from models.connector import ConnectorType

    assert connector_type_available("canvas") is True
    assert connector_type_available(ConnectorType.google_workspace) is True
    assert connector_type_available("mcp") is True
    assert connector_type_available("custom") is False
    assert connector_type_available(_RETIRED) is False
    assert connector_type_available("") is False


def test_model_normalises_enum_members_to_plain_keys():
    from models.connector import ConnectorConfig, ConnectorType, connector_type_key

    row = ConnectorConfig(connector_type=ConnectorType.robinhood)
    assert row.connector_type == "robinhood"
    assert type(row.connector_type) is str
    assert connector_type_key(ConnectorType.mcp) == "mcp"
    assert connector_type_key("github") == "github"
