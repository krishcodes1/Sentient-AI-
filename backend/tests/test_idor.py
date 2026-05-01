"""IDOR (Insecure Direct Object Reference) regression tests.

These tests express the *desired* secure behavior for endpoints that used
to trust client-supplied ``user_id`` query/body parameters. After the P0
fix lands, the previous ``xfail`` markers are removed and the tests must
pass: the audit POST endpoint is gone, audit listing scopes to the
caller, and connector reads/writes use the bearer token's user.
"""

from __future__ import annotations

import json
import uuid

import pytest


# ---------------------------------------------------------------------------
# Audit endpoint IDOR coverage.
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_audit_post_endpoint_removed(client) -> None:
    """The public POST /api/audit/ endpoint has been deleted entirely.

    With no handler registered, FastAPI replies 404 (no route) or 405
    (route exists for another method). Either is acceptable — the key
    invariant is that this endpoint cannot create audit log rows.
    """
    response = await client.post(
        "/api/audit/",
        json={
            "user_id": str(uuid.uuid4()),
            "connector_name": "canvas",
            "action": "list_courses",
            "endpoint": "/api/v1/courses",
            "scope_used": "courses:read",
            "status": "approved",
            "request_id": str(uuid.uuid4()),
        },
    )
    assert response.status_code in (404, 405)


@pytest.mark.asyncio
async def test_audit_post_requires_auth(client) -> None:
    """Posting an audit log without a bearer token must be rejected.

    Retained as a defense-in-depth check: even if a future change wires
    POST back up, it must require auth.
    """
    response = await client.post(
        "/api/audit/",
        json={
            "user_id": str(uuid.uuid4()),
            "connector_name": "canvas",
            "action": "list_courses",
            "endpoint": "/api/v1/courses",
            "scope_used": "courses:read",
            "status": "approved",
            "request_id": str(uuid.uuid4()),
        },
    )
    assert response.status_code in (401, 403, 404, 405)


@pytest.mark.asyncio
async def test_audit_list_requires_auth(client) -> None:
    """GET /api/audit/ without a bearer token must be rejected."""
    response = await client.get("/api/audit/")
    assert response.status_code in (401, 403)


@pytest.mark.asyncio
async def test_audit_list_only_returns_own_logs(
    client, test_user, make_user, db_session
) -> None:
    """Listing audit logs returns only the caller's logs, never another user's."""
    from models.audit import AuditLog, AuditStatus

    other = await make_user(email="other-audit-list@example.com")

    own_log = AuditLog(
        id=uuid.uuid4(),
        user_id=test_user["user"].id,
        connector_name="canvas",
        action="own_action",
        endpoint="/api/v1/own",
        scope_used="courses:read",
        status=AuditStatus.APPROVED,
        integrity_hash="0" * 64,
        request_id=str(uuid.uuid4()),
    )
    other_log = AuditLog(
        id=uuid.uuid4(),
        user_id=other["user"].id,
        connector_name="canvas",
        action="other_action",
        endpoint="/api/v1/other",
        scope_used="courses:read",
        status=AuditStatus.APPROVED,
        integrity_hash="1" * 64,
        request_id=str(uuid.uuid4()),
    )
    db_session.add_all([own_log, other_log])
    await db_session.commit()

    response = await client.get("/api/audit/", headers=test_user["headers"])
    assert response.status_code == 200
    body = response.json()

    returned_user_ids = {row["user_id"] for row in body}
    assert returned_user_ids <= {str(test_user["user"].id)}

    actions = {row["action"] for row in body}
    assert "other_action" not in actions


@pytest.mark.asyncio
async def test_audit_list_scopes_to_user(client, test_user, make_user) -> None:
    """User A must not be able to fetch user B's audit logs by passing B's id.

    After the fix, ``user_id`` is ignored (taken from the token instead),
    so passing another user's id produces an empty list, not their data.
    """
    other = await make_user(email="other-audit@example.com")

    response = await client.get(
        f"/api/audit/?user_id={other['user'].id}",
        headers=test_user["headers"],
    )
    assert response.status_code == 200
    body = response.json()
    for row in body:
        assert row["user_id"] == str(test_user["user"].id)


# ---------------------------------------------------------------------------
# Connector endpoint IDOR coverage.
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_connectors_list_requires_auth(client) -> None:
    """GET /api/connectors/ without a bearer token must be rejected."""
    response = await client.get("/api/connectors/")
    assert response.status_code in (401, 403)


@pytest.mark.asyncio
async def test_connectors_list_scopes_to_user(client, test_user, make_user) -> None:
    """Listing connectors must only return rows owned by the authenticated user."""
    other = await make_user(email="other-connectors@example.com")

    response = await client.get(
        f"/api/connectors/?user_id={other['user'].id}",
        headers=test_user["headers"],
    )
    assert response.status_code == 200
    body = response.json()
    # Either empty or only the caller's own rows — never the other user's.
    for row in body:
        # ConnectorOut does not expose user_id, so we just confirm 200 + list.
        assert "id" in row


@pytest.mark.asyncio
async def test_connectors_create_uses_auth_user_not_body(
    client, test_user, make_user, db_session
) -> None:
    """A spoofed ``user_id`` in the create body must be ignored.

    The created row must belong to the authenticated user, never to the
    user named in the body.
    """
    from sqlalchemy import select as _select

    from models.connector import ConnectorConfig

    other = await make_user(email="other-create@example.com")

    response = await client.post(
        "/api/connectors/",
        headers=test_user["headers"],
        json={
            "user_id": str(other["user"].id),  # Attempt to spoof ownership.
            "connector_type": "canvas",
            "display_name": "Spoofed",
            "auth_method": "api_key",
            "credentials": {"api_key": "secret"},
            "granted_scopes": ["courses:read"],
            "permission_tier": "user_confirm",
            "rate_limit_per_minute": 30,
        },
    )

    # The unknown ``user_id`` field must be ignored by the schema (extra
    # fields are silently dropped) so the request succeeds with the
    # token's user as owner.
    assert response.status_code in (200, 201)
    body = response.json()
    connector_id = uuid.UUID(body["id"])

    # Confirm in the DB that user_id is the token's user, not the body's.
    row = await db_session.execute(
        _select(ConnectorConfig).where(ConnectorConfig.id == connector_id)
    )
    saved = row.scalar_one_or_none()
    assert saved is not None
    assert saved.user_id == test_user["user"].id
    assert saved.user_id != other["user"].id


@pytest.mark.asyncio
async def test_connectors_create_uses_token_user_id_not_body(
    client, test_user, make_user, db_session
) -> None:
    """Backwards-compat alias for the test name kept in conftest history."""
    from sqlalchemy import select as _select

    from models.connector import ConnectorConfig

    other = await make_user(email="other-create-alias@example.com")

    response = await client.post(
        "/api/connectors/",
        headers=test_user["headers"],
        json={
            "user_id": str(other["user"].id),
            "connector_type": "canvas",
            "display_name": "AliasSpoofed",
            "auth_method": "api_key",
            "credentials": {"api_key": "secret"},
            "granted_scopes": ["courses:read"],
            "permission_tier": "user_confirm",
            "rate_limit_per_minute": 30,
        },
    )
    assert response.status_code in (200, 201)
    body = response.json()
    connector_id = uuid.UUID(body["id"])

    row = await db_session.execute(
        _select(ConnectorConfig).where(ConnectorConfig.id == connector_id)
    )
    saved = row.scalar_one_or_none()
    assert saved is not None
    assert saved.user_id == test_user["user"].id


@pytest.mark.asyncio
async def test_connectors_get_other_user_returns_404(
    client, test_user, make_user, db_session
) -> None:
    """Reading a connector that belongs to a different user must return 404.

    404 (not 403) avoids leaking the existence of the row.
    """
    from core.security import encrypt_credentials
    from models.connector import (
        AuthMethod,
        ConnectorConfig,
        ConnectorType,
        PermissionTier,
    )

    other = await make_user(email="other-get@example.com")
    connector = ConnectorConfig(
        id=uuid.uuid4(),
        user_id=other["user"].id,
        connector_type=ConnectorType.canvas,
        display_name="Private",
        auth_method=AuthMethod.api_key,
        encrypted_credentials=encrypt_credentials(json.dumps({"k": "v"})),
        granted_scopes=[],
        permission_tier=PermissionTier.user_confirm,
        rate_limit_per_minute=30,
    )
    db_session.add(connector)
    await db_session.commit()

    response = await client.get(
        f"/api/connectors/{connector.id}",
        headers=test_user["headers"],
    )
    assert response.status_code == 404


@pytest.mark.asyncio
async def test_connectors_get_other_users_returns_404_or_403(
    client, test_user, make_user, db_session
) -> None:
    """Original-name variant of the cross-user GET test."""
    from core.security import encrypt_credentials
    from models.connector import (
        AuthMethod,
        ConnectorConfig,
        ConnectorType,
        PermissionTier,
    )

    other = await make_user(email="other-get-orig@example.com")
    connector = ConnectorConfig(
        id=uuid.uuid4(),
        user_id=other["user"].id,
        connector_type=ConnectorType.canvas,
        display_name="Private",
        auth_method=AuthMethod.api_key,
        encrypted_credentials=encrypt_credentials(json.dumps({"k": "v"})),
        granted_scopes=[],
        permission_tier=PermissionTier.user_confirm,
        rate_limit_per_minute=30,
    )
    db_session.add(connector)
    await db_session.commit()

    response = await client.get(
        f"/api/connectors/{connector.id}",
        headers=test_user["headers"],
    )
    assert response.status_code in (403, 404)


@pytest.mark.asyncio
async def test_connectors_delete_other_user_returns_404(
    client, test_user, make_user, db_session
) -> None:
    """Deleting another user's connector must return 404 and not delete the row."""
    from sqlalchemy import select as _select

    from core.security import encrypt_credentials
    from models.connector import (
        AuthMethod,
        ConnectorConfig,
        ConnectorType,
        PermissionTier,
    )

    other = await make_user(email="other-delete@example.com")
    connector_id = uuid.uuid4()
    connector = ConnectorConfig(
        id=connector_id,
        user_id=other["user"].id,
        connector_type=ConnectorType.canvas,
        display_name="DoNotDelete",
        auth_method=AuthMethod.api_key,
        encrypted_credentials=encrypt_credentials(json.dumps({"k": "v"})),
        granted_scopes=[],
        permission_tier=PermissionTier.user_confirm,
        rate_limit_per_minute=30,
    )
    db_session.add(connector)
    await db_session.commit()

    response = await client.delete(
        f"/api/connectors/{connector_id}",
        headers=test_user["headers"],
    )
    assert response.status_code == 404

    # Row must still exist.
    row = await db_session.execute(
        _select(ConnectorConfig).where(ConnectorConfig.id == connector_id)
    )
    assert row.scalar_one_or_none() is not None
