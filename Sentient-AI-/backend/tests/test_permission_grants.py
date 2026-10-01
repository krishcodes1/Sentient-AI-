"""Tests for the low-risk grant stores (services/agent/permission_grants.py):
allow and renew, lookups, expiry on an injected clock, use counts, revoking one,
a connection's or all, per-user isolation, and the database store's check of
the connector row.

Why it exists: a live grant lets one account's small changes run with no card
for 7 days. It must end when it expires or is revoked, never answer for another
user, and never be made for a connection that is not the user's own, not
active, or admin_only / hard_blocked. The database store runs on in-memory
SQLite (naive timestamps) exactly as it does on Postgres.
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any

import pytest
from sqlalchemy import delete, select

from services.agent.permission_grants import (
    GRANT_TTL,
    KIND_LOW_RISK,
    DbPermissionGrantStore,
    InMemoryPermissionGrantStore,
    account_label,
    revoke_grants_in_session,
    scopes_widened,
)

U1 = "11111111-1111-4111-8111-111111111111"
U2 = "22222222-2222-4222-8222-222222222222"
C1 = "c1c1c1c1-1111-4111-8111-111111111111"
C2 = "c2c2c2c2-2222-4222-8222-222222222222"
T0 = datetime(2026, 9, 30, 12, 0, tzinfo=timezone.utc)


class Clock:
    def __init__(self) -> None:
        self.now = T0

    def __call__(self) -> datetime:
        return self.now


# ── in-memory store ─────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_allow_find_and_renew():
    clock = Clock()
    store = InMemoryPermissionGrantStore(now=clock)
    grant = await store.allow(user_id=U1, connector_id=C1, granted_from="telegram", source_action_id="a1")
    assert grant is not None
    assert (grant.kind, grant.granted_from, grant.source_action_id) == (KIND_LOW_RISK, "telegram", "a1")
    assert grant.expires_at == T0 + GRANT_TTL
    assert await store.find_live(user_id=U1, connector_id=C1) == grant
    # Allowing again renews the same grant rather than stacking a second one.
    clock.now = T0 + timedelta(days=3)
    renewed = await store.allow(user_id=U1, connector_id=C1, granted_from="bogus")
    assert renewed is not None and renewed.id == grant.id
    assert renewed.expires_at == clock.now + GRANT_TTL
    assert renewed.granted_from is None  # only known channels are recorded
    assert len(await store.list_live(U1)) == 1


@pytest.mark.asyncio
async def test_a_grant_expires_after_seven_days():
    clock = Clock()
    store = InMemoryPermissionGrantStore(now=clock)
    await store.allow(user_id=U1, connector_id=C1)
    clock.now = T0 + GRANT_TTL - timedelta(seconds=1)
    assert await store.find_live(user_id=U1, connector_id=C1) is not None
    clock.now = T0 + GRANT_TTL
    assert await store.find_live(user_id=U1, connector_id=C1) is None
    assert await store.list_live(U1) == []


@pytest.mark.asyncio
async def test_grants_are_per_user_and_per_connection():
    store = InMemoryPermissionGrantStore()
    grant = await store.allow(user_id=U1, connector_id=C1)
    assert grant is not None
    assert await store.find_live(user_id=U2, connector_id=C1) is None
    assert await store.find_live(user_id=U1, connector_id=C2) is None
    # Another user's id revokes nothing.
    assert await store.revoke(user_id=U2, grant_id=grant.id) is None
    assert await store.find_live(user_id=U1, connector_id=C1) is not None


@pytest.mark.asyncio
async def test_revoke_one_a_connection_or_all():
    store = InMemoryPermissionGrantStore()
    a = await store.allow(user_id=U1, connector_id=C1)
    await store.allow(user_id=U1, connector_id=C2)
    await store.allow(user_id=U2, connector_id=C1)
    assert a is not None
    revoked = await store.revoke(user_id=U1, grant_id=a.id)
    assert revoked is not None and revoked.revoked_at is not None
    assert await store.revoke(user_id=U1, grant_id=a.id) is None  # once
    assert await store.revoke_connector(user_id=U1, connector_id=C2) == 1
    assert await store.list_live(U1) == []
    assert await store.revoke_all(user_id=U2) == 1
    assert await store.list_live(U2) == []


@pytest.mark.asyncio
async def test_record_use_counts_and_stamps():
    clock = Clock()
    store = InMemoryPermissionGrantStore(now=clock)
    grant = await store.allow(user_id=U1, connector_id=C1)
    assert grant is not None
    clock.now = T0 + timedelta(hours=1)
    await store.record_use(grant.id)
    await store.record_use(grant.id)
    live = await store.find_live(user_id=U1, connector_id=C1)
    assert live is not None and live.uses == 2 and live.last_used_at == clock.now


@pytest.mark.asyncio
async def test_a_refused_connection_gets_no_grant():
    store = InMemoryPermissionGrantStore(connection=lambda user, connector: connector == C1)
    assert await store.allow(user_id=U1, connector_id=C2) is None
    assert await store.allow(user_id=U1, connector_id=C1) is not None


def test_scope_widening_and_account_labels():
    assert scopes_widened(["gmail.read"], ["gmail.read", "gmail.send"])
    assert not scopes_widened(["gmail.read", "gmail.send"], ["gmail.read"])
    assert not scopes_widened(None, [])
    assert account_label("School\nGmail  ", "google_workspace") == "School Gmail"
    assert account_label("", "google_workspace") == "Google Workspace"
    assert account_label(None, "") == "this account"


# ── database store ──────────────────────────────────────────────────────────


async def _connector(session_factory, user_id, **overrides: Any) -> str:
    from core.security import encrypt_credentials
    from models.connector import AuthMethod, ConnectorConfig, PermissionTier

    fields: dict[str, Any] = {
        "user_id": user_id,
        "connector_type": "google_workspace",
        "display_name": "School Gmail",
        "auth_method": AuthMethod.oauth2,
        "encrypted_credentials": encrypt_credentials(json.dumps({"access_token": "t"})),
        "granted_scopes": ["gmail.read", "gmail.modify"],
        "permission_tier": PermissionTier.user_confirm,
    }
    fields.update(overrides)
    async with session_factory() as session:
        row = ConnectorConfig(**fields)
        session.add(row)
        await session.commit()
        return str(row.id)


@pytest.mark.asyncio
async def test_db_store_round_trip_with_naive_timestamps(session_factory):
    from tests.conftest import make_user

    user, _ = await make_user(session_factory)
    connector_id = await _connector(session_factory, user.id)
    clock = Clock()
    store = DbPermissionGrantStore(session_factory, now=clock)

    grant = await store.allow(
        user_id=str(user.id), connector_id=connector_id, granted_from="web", source_action_id=str(uuid.uuid4())
    )
    assert grant is not None
    assert grant.account == "School Gmail" and grant.connector_type == "google_workspace"
    assert grant.expires_at == T0 + GRANT_TTL
    found = await store.find_live(user_id=str(user.id), connector_id=connector_id)
    assert found is not None and found.id == grant.id
    # SQLite hands timestamps back naive; the store reads them as UTC.
    assert found.expires_at.tzinfo is not None

    clock.now = T0 + timedelta(days=2)
    renewed = await store.allow(user_id=str(user.id), connector_id=connector_id)
    assert renewed is not None and renewed.id == grant.id
    assert renewed.expires_at == clock.now + GRANT_TTL

    await store.record_use(grant.id)
    [listed] = await store.list_live(str(user.id))
    assert listed.uses == 1 and listed.last_used_at == clock.now and listed.account == "School Gmail"

    clock.now = T0 + timedelta(days=2) + GRANT_TTL
    assert await store.find_live(user_id=str(user.id), connector_id=connector_id) is None
    assert await store.list_live(str(user.id)) == []


@pytest.mark.asyncio
async def test_db_store_refuses_foreign_inactive_and_admin_only_connections(session_factory):
    from models.connector import PermissionTier
    from models.user import User
    from tests.conftest import make_user

    user, _ = await make_user(session_factory, "one@example.com")
    other, _ = await make_user(session_factory, "two@example.com")
    theirs = await _connector(session_factory, other.id)
    inactive = await _connector(session_factory, user.id, is_active=False)
    admin_only = await _connector(session_factory, user.id, permission_tier=PermissionTier.admin_only)
    blocked = await _connector(session_factory, user.id, permission_tier=PermissionTier.hard_blocked)
    fine = await _connector(session_factory, user.id)
    store = DbPermissionGrantStore(session_factory)

    for connector_id in (theirs, inactive, admin_only, blocked, "not-a-uuid"):
        assert await store.allow(user_id=str(user.id), connector_id=connector_id) is None
    assert await store.allow(user_id=str(user.id), connector_id=fine) is not None

    # An account default of admin_only wins over the row's own tier.
    async with session_factory() as session:
        row = (await session.execute(select(User).where(User.id == user.id))).scalar_one()
        row.default_permission_tier = "admin_only"
        await session.commit()
    assert await store.allow(user_id=str(user.id), connector_id=fine) is None


@pytest.mark.asyncio
async def test_db_store_isolation_and_revocation(session_factory):
    from tests.conftest import make_user

    user, _ = await make_user(session_factory, "a@example.com")
    other, _ = await make_user(session_factory, "b@example.com")
    c1 = await _connector(session_factory, user.id)
    c2 = await _connector(session_factory, user.id, display_name="Personal Outlook", connector_type="microsoft")
    theirs = await _connector(session_factory, other.id)
    store = DbPermissionGrantStore(session_factory)
    g1 = await store.allow(user_id=str(user.id), connector_id=c1)
    await store.allow(user_id=str(user.id), connector_id=c2)
    g3 = await store.allow(user_id=str(other.id), connector_id=theirs)
    assert g1 is not None and g3 is not None

    assert await store.revoke(user_id=str(user.id), grant_id=g3.id) is None
    assert await store.find_live(user_id=str(user.id), connector_id=theirs) is None
    revoked = await store.revoke(user_id=str(user.id), grant_id=g1.id)
    assert revoked is not None and revoked.account == "School Gmail"
    assert await store.revoke(user_id=str(user.id), grant_id=g1.id) is None
    assert [g.account for g in await store.list_live(str(user.id))] == ["Personal Outlook"]
    assert await store.revoke_connector(user_id=str(user.id), connector_id=c2) == 1
    assert await store.revoke_all(user_id=str(other.id)) == 1
    assert await store.list_live(str(other.id)) == []


@pytest.mark.asyncio
async def test_grants_die_with_their_connector(session_factory):
    from models.connector import ConnectorConfig
    from models.permission_grant import PermissionGrantRow
    from tests.conftest import make_user

    user, _ = await make_user(session_factory)
    connector_id = await _connector(session_factory, user.id)
    store = DbPermissionGrantStore(session_factory)
    assert await store.allow(user_id=str(user.id), connector_id=connector_id) is not None
    async with session_factory() as session:
        await session.execute(delete(ConnectorConfig).where(ConnectorConfig.id == uuid.UUID(connector_id)))
        await session.commit()
        rows = (await session.execute(select(PermissionGrantRow))).scalars().all()
    assert rows == []


@pytest.mark.asyncio
async def test_revoke_in_session_counts_only_live_rows(session_factory):
    from tests.conftest import make_user

    user, _ = await make_user(session_factory)
    connector_id = await _connector(session_factory, user.id)
    store = DbPermissionGrantStore(session_factory)
    await store.allow(user_id=str(user.id), connector_id=connector_id)
    async with session_factory() as session:
        assert await revoke_grants_in_session(session, user.id, connector_uuid=uuid.UUID(connector_id)) == 1
        await session.commit()
    async with session_factory() as session:
        assert await revoke_grants_in_session(session, user.id) == 0
