"""Tests for authentication events in the audit chain: login, logout,
password/email changes, lockouts, and refused deletions are all recorded,
chained, keyed, owner-scoped, and visible through the audit API.

Why it exists: Guards against the compliance audit trail silently omitting
authentication activity (previously only agent tool actions were recorded) and
against a rolled-back HTTPException path losing an audit row exactly when it
matters.

Authentication events land in the tamper-evident audit chain.

Before this, the chain recorded only agent tool activity: an account could
be signed into, have its password rotated and its email moved, and the
compliance artifact the product is built around would show nothing. The
events here are the ones a reviewer reaches for first — who signed in,
which attempts failed, when credentials changed.

The failure paths get their own coverage because they are the easy ones to
lose: every one of them ends in an HTTPException, and the request session
is rolled back when that propagates, so an audit row written but not
committed would disappear exactly when it matters.
"""

from __future__ import annotations

import httpx
import pytest
import pytest_asyncio
from sqlalchemy import select

from models.audit import AuditLog, AuditStatus
from services.auth import login_lockout
from tests.conftest import auth_headers


@pytest_asyncio.fixture(autouse=True)
async def _isolate_lockout_state():
    await login_lockout.clear()
    yield
    await login_lockout.clear()


async def _auth_rows(session_factory) -> list[AuditLog]:
    """Every account event, oldest first."""
    async with session_factory() as session:
        query = (
            select(AuditLog)
            .where(AuditLog.connector_name == "auth")
            .order_by(AuditLog.seq.asc())
        )
        return list((await session.execute(query)).scalars().all())


def _actions(rows: list[AuditLog]) -> list[str]:
    return [row.action for row in rows]


async def _register(client: httpx.AsyncClient, email: str, password="password-123"):
    resp = await client.post(
        "/api/auth/register", json={"email": email, "password": password}
    )
    assert resp.status_code == 201, resp.text


async def _login(client: httpx.AsyncClient, email: str, password="password-123"):
    return await client.post(
        "/api/auth/login", json={"email": email, "password": password}
    )


# ---------------------------------------------------------------------------
# Successful events
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_registration_and_login_are_recorded(client, session_factory):
    await _register(client, "audited@example.com")
    assert (await _login(client, "audited@example.com")).status_code == 200

    rows = await _auth_rows(session_factory)
    assert _actions(rows) == ["account_created", "login"]
    assert all(row.status is AuditStatus.approved for row in rows)
    assert rows[0].endpoint == "/api/auth/register"
    assert rows[1].endpoint == "/api/auth/login"


@pytest.mark.asyncio
async def test_logout_is_recorded(client, session_factory):
    await _register(client, "bookend@example.com")
    token = (await _login(client, "bookend@example.com")).json()["access_token"]

    resp = await client.post("/api/auth/logout", headers=auth_headers(token))
    assert resp.status_code == 204

    assert _actions(await _auth_rows(session_factory))[-1] == "logout"


@pytest.mark.asyncio
async def test_password_change_is_recorded(client, session_factory):
    await _register(client, "rotate@example.com")
    token = (await _login(client, "rotate@example.com")).json()["access_token"]

    resp = await client.post(
        "/api/auth/password",
        headers=auth_headers(token),
        json={"current_password": "password-123", "new_password": "password-456"},
    )
    assert resp.status_code == 204

    rows = await _auth_rows(session_factory)
    assert _actions(rows)[-1] == "password_changed"
    assert "revoked" in (rows[-1].response_summary or "")


@pytest.mark.asyncio
async def test_email_change_records_both_addresses(client, session_factory):
    await _register(client, "before@example.com")
    token = (await _login(client, "before@example.com")).json()["access_token"]

    resp = await client.patch(
        "/api/auth/profile",
        headers=auth_headers(token),
        json={"email": "after@example.com", "current_password": "password-123"},
    )
    assert resp.status_code == 200

    row = (await _auth_rows(session_factory))[-1]
    assert row.action == "email_changed"
    # Both sides of the move, or the trail cannot answer "moved from what?"
    assert "before@example.com" in (row.response_summary or "")
    assert "after@example.com" in (row.response_summary or "")


# ---------------------------------------------------------------------------
# Refusals — the rows that must survive their own exception
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_failed_login_is_recorded(client, session_factory):
    await _register(client, "bruted@example.com")
    assert (await _login(client, "bruted@example.com", "wrong")).status_code == 401

    rows = await _auth_rows(session_factory)
    assert _actions(rows) == ["account_created", "login_failed"]
    assert rows[-1].status is AuditStatus.blocked


@pytest.mark.asyncio
async def test_lockout_is_recorded_distinctly_from_an_ordinary_failure(
    client, session_factory, monkeypatch
):
    from core.config import settings

    monkeypatch.setattr(settings, "LOCKOUT_THRESHOLD", 2)
    await _register(client, "locked@example.com")

    await _login(client, "locked@example.com", "wrong")
    await _login(client, "locked@example.com", "wrong")
    assert (await _login(client, "locked@example.com", "wrong")).status_code == 429

    actions = _actions(await _auth_rows(session_factory))
    assert actions == [
        "account_created",
        "login_failed",
        "login_locked_out",  # the attempt that tripped the threshold
        "login_locked_out",  # and the one refused while locked
    ]


@pytest.mark.asyncio
async def test_failed_password_change_is_recorded(client, session_factory):
    await _register(client, "wrongcurrent@example.com")
    token = (await _login(client, "wrongcurrent@example.com")).json()["access_token"]

    resp = await client.post(
        "/api/auth/password",
        headers=auth_headers(token),
        json={"current_password": "not-it", "new_password": "password-456"},
    )
    assert resp.status_code == 400

    row = (await _auth_rows(session_factory))[-1]
    assert row.action == "password_change_failed"
    assert row.status is AuditStatus.blocked


@pytest.mark.asyncio
async def test_refused_account_deletion_is_recorded(client, session_factory):
    await _register(client, "keepme@example.com")
    token = (await _login(client, "keepme@example.com")).json()["access_token"]

    resp = await client.request(
        "DELETE",
        "/api/auth/account",
        headers=auth_headers(token),
        json={"current_password": "not-it"},
    )
    assert resp.status_code == 403

    row = (await _auth_rows(session_factory))[-1]
    assert row.action == "account_delete_denied"
    assert row.status is AuditStatus.blocked


@pytest.mark.asyncio
async def test_login_attempt_on_an_unknown_address_writes_no_row(
    client, session_factory
):
    """There is no account to chain the row to, and inventing one would let
    anyone grow the table by POSTing addresses."""
    assert (await _login(client, "nobody@example.com", "guess")).status_code == 401
    assert await _auth_rows(session_factory) == []


# ---------------------------------------------------------------------------
# The events join the same chain, with the same guarantee
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_auth_events_are_chained_and_keyed(client, session_factory):
    await _register(client, "chained@example.com")
    await _login(client, "chained@example.com", "wrong")
    token = (await _login(client, "chained@example.com")).json()["access_token"]

    rows = await _auth_rows(session_factory)
    assert [row.seq for row in rows] == [1, 2, 3]
    # Each row pins its predecessor, so removing the failed attempt between
    # the account's creation and its first successful sign-in is detectable.
    assert rows[0].previous_hash is None
    assert rows[1].previous_hash == rows[0].integrity_hash
    assert rows[2].previous_hash == rows[1].integrity_hash

    for row in rows:
        verify = await client.get(
            f"/api/audit/{row.id}/verify", headers=auth_headers(token)
        )
        assert verify.json() == {"id": str(row.id), "valid": True, "legacy": False}


@pytest.mark.asyncio
async def test_auth_events_are_visible_through_the_audit_api(client, session_factory):
    await _register(client, "visible@example.com")
    token = (await _login(client, "visible@example.com")).json()["access_token"]

    listed = await client.get(
        "/api/audit/", params={"connector_name": "auth"}, headers=auth_headers(token)
    )
    assert listed.status_code == 200
    assert {entry["action"] for entry in listed.json()} == {
        "account_created",
        "login",
    }


@pytest.mark.asyncio
async def test_auth_events_stay_owner_scoped(client, session_factory):
    await _register(client, "mine@example.com")
    mine = (await _login(client, "mine@example.com")).json()["access_token"]
    await _register(client, "theirs@example.com")
    await _login(client, "theirs@example.com")

    listed = await client.get(
        "/api/audit/", params={"connector_name": "auth"}, headers=auth_headers(mine)
    )
    assert listed.status_code == 200
    assert len(listed.json()) == 2  # only this account's own two events
