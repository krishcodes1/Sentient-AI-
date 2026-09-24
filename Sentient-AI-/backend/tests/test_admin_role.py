"""The admin role and the `admin_only` connector tier.

`admin_only` was offered in the UI but had no role to check against, so it
silently meant "this connector is disabled for everyone" — a control that
did not do what its label said. The first registered account now owns the
deployment, and `admin_only` means "usable only by that account".

The security direction matters: this must never make a connector reachable
by a NON-admin that was previously unreachable.
"""

from __future__ import annotations

import pytest
from sqlalchemy import select, update

from services.agent.permissions import PermissionEngine, UserTier
from services.agent.tool_registry import ConnectorSpec, build_tools, effective_tier
from tests.conftest import auth_headers


# ---------------------------------------------------------------------------
# Who becomes admin
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_first_registered_account_is_admin(client):
    first = await client.post(
        "/api/auth/register",
        json={"email": "owner@example.com", "password": "password-123"},
    )
    assert first.status_code == 201
    assert first.json()["is_admin"] is True


@pytest.mark.asyncio
async def test_subsequent_accounts_are_not_admin(client):
    await client.post(
        "/api/auth/register",
        json={"email": "owner@example.com", "password": "password-123"},
    )
    second = await client.post(
        "/api/auth/register",
        json={"email": "guest@example.com", "password": "password-123"},
    )
    assert second.status_code == 201
    assert second.json()["is_admin"] is False


@pytest.mark.asyncio
async def test_admin_flag_is_reported_on_me(client):
    await client.post(
        "/api/auth/register",
        json={"email": "owner@example.com", "password": "password-123"},
    )
    login = await client.post(
        "/api/auth/login",
        json={"email": "owner@example.com", "password": "password-123"},
    )
    me = await client.get(
        "/api/auth/me", headers=auth_headers(login.json()["access_token"])
    )
    assert me.json()["is_admin"] is True


@pytest.mark.asyncio
async def test_existing_accounts_are_not_promoted_by_the_column_backfill(
    client, session_factory
):
    """The is_admin backfill must land a real boolean, not a truthy string.

    A ``server_default="false"`` renders as the TEXT literal 'false' on
    SQLite, so every row the ADD COLUMN backfilled read back as truthy and
    silently became an admin. Caught only by running a real upgrade against
    a database that already had users.
    """
    from sqlalchemy import text

    await client.post(
        "/api/auth/register",
        json={"email": "owner@example.com", "password": "password-123"},
    )
    await client.post(
        "/api/auth/register",
        json={"email": "guest@example.com", "password": "password-123"},
    )

    async with session_factory() as session:
        rows = (
            await session.execute(
                text("SELECT email, is_admin FROM users ORDER BY created_at")
            )
        ).all()

    by_email = dict(rows)
    assert bool(by_email["owner@example.com"]) is True
    assert bool(by_email["guest@example.com"]) is False
    # The string 'false' is truthy in Python — assert the stored value is
    # not one, independently of how the ORM coerces it.
    assert by_email["guest@example.com"] not in ("false", "true")


@pytest.mark.asyncio
async def test_admin_flag_cannot_be_self_assigned_through_settings(client):
    """No endpoint should let a standard account promote itself."""
    await client.post(
        "/api/auth/register",
        json={"email": "owner@example.com", "password": "password-123"},
    )
    await client.post(
        "/api/auth/register",
        json={"email": "guest@example.com", "password": "password-123"},
    )
    login = await client.post(
        "/api/auth/login",
        json={"email": "guest@example.com", "password": "password-123"},
    )
    headers = auth_headers(login.json()["access_token"])

    for payload in (
        {"is_admin": True},
        {"default_permission_tier": "admin_only", "is_admin": True},
    ):
        await client.patch("/api/auth/settings", json=payload, headers=headers)
    for payload in ({"is_admin": True}, {"name": "x", "is_admin": True}):
        await client.patch("/api/auth/profile", json=payload, headers=headers)

    me = await client.get("/api/auth/me", headers=headers)
    assert me.json()["is_admin"] is False


# ---------------------------------------------------------------------------
# What admin_only now means when building the tool list
# ---------------------------------------------------------------------------


def _canvas(tier: str) -> ConnectorSpec:
    return ConnectorSpec(
        "canvas",
        granted_scopes=("courses.read", "assignments.read"),
        permission_tier=tier,
    )


# These three are about what a *connector* contributes, so they build
# without the built-in web tools, which every user gets regardless of any
# connector's tier (the account-level floor over those is covered by
# test_user_account_default_still_narrows_an_admin).
def test_admin_only_connector_offers_no_tools_to_a_standard_user():
    tools = build_tools([_canvas("admin_only")], is_admin=False, include_builtins=False)
    assert tools == []


def test_admin_only_connector_offers_tools_to_an_admin():
    tools = build_tools([_canvas("admin_only")], is_admin=True, include_builtins=False)
    assert [t.name for t in tools], "admin_only was still dead policy for an admin"
    assert all(t.connector_type == "canvas" for t in tools)


def test_hard_blocked_stays_blocked_even_for_an_admin():
    """The tier that exists to be absolute must not gain an exception."""
    assert (
        build_tools([_canvas("hard_blocked")], is_admin=True, include_builtins=False)
        == []
    )


def test_admin_does_not_widen_the_other_tiers():
    """Being admin changes who may use an admin_only connector — it must not
    quietly change what a normal connector offers."""
    standard = build_tools([_canvas("user_confirm")], is_admin=False)
    admin = build_tools([_canvas("user_confirm")], is_admin=True)
    assert {t.name for t in standard} == {t.name for t in admin}
    assert {t.name: t.permission_tier for t in standard} == {
        t.name: t.permission_tier for t in admin
    }


def test_financial_actions_stay_blocked_for_an_admin():
    """Money never moves — the platform-level guarantee outranks any role."""
    robinhood = ConnectorSpec(
        "robinhood",
        granted_scopes=("crypto.read", "crypto.trade"),
        permission_tier="admin_only",
    )
    names = {t.name for t in build_tools([robinhood], is_admin=True)}
    assert not any("trade" in n or "buy" in n or "sell" in n for n in names)


def test_user_account_default_still_narrows_an_admin():
    """effective_tier takes the stricter of connector and account default,
    and that is unchanged by the role."""
    assert effective_tier("auto_approve", "admin_only") == "admin_only"
    tools = build_tools(
        [_canvas("auto_approve")], user_default_tier="hard_blocked", is_admin=True
    )
    assert tools == []


# ---------------------------------------------------------------------------
# The static policy's own ADMIN_ONLY actions
# ---------------------------------------------------------------------------


def test_policy_admin_only_action_requires_confirmation_for_an_admin():
    from services.agent.permissions import ActionCategory

    engine = PermissionEngine()
    as_admin = engine.check_permission(
        connector_type="google",
        action="delete_file",
        scope=ActionCategory.DELETE,
        user_tier=UserTier.ADMIN,
    )
    as_standard = engine.check_permission(
        connector_type="google",
        action="delete_file",
        scope=ActionCategory.DELETE,
        user_tier=UserTier.STANDARD,
    )
    assert as_admin.requires_approval is True
    assert as_standard.requires_approval is False  # refused outright


# ---------------------------------------------------------------------------
# The install always keeps an owner
# ---------------------------------------------------------------------------


async def _signed_up(client, email: str) -> dict[str, str]:
    created = await client.post(
        "/api/auth/register", json={"email": email, "password": "password-123"}
    )
    assert created.status_code == 201, created.text
    login = await client.post(
        "/api/auth/login", json={"email": email, "password": "password-123"}
    )
    return auth_headers(login.json()["access_token"])


async def _delete_own_account(client, headers):
    return await client.request(
        "DELETE",
        "/api/auth/account",
        headers=headers,
        json={"current_password": "password-123"},
    )


@pytest.mark.asyncio
async def test_the_last_owner_cannot_delete_their_account(client, session_factory):
    """With no admin left, nobody could run setup, change capabilities or
    use an admin_only connector again, and /setup/owner stays closed while
    other accounts exist."""
    from models.audit import AuditLog, AuditStatus

    owner = await _signed_up(client, "owner@example.com")
    await _signed_up(client, "guest@example.com")

    resp = await _delete_own_account(client, owner)
    assert resp.status_code == 409
    assert resp.json()["detail"] == "Transfer ownership before deleting the last owner account"
    assert (await client.get("/api/auth/me", headers=owner)).status_code == 200

    async with session_factory() as session:
        rows = (
            (await session.execute(select(AuditLog).order_by(AuditLog.seq))).scalars().all()
        )
    assert rows[-1].action == "account_delete_denied"
    assert rows[-1].status is AuditStatus.blocked


@pytest.mark.asyncio
async def test_a_sole_owner_with_no_other_accounts_is_refused_too(client):
    owner = await _signed_up(client, "owner@example.com")
    resp = await _delete_own_account(client, owner)
    assert resp.status_code == 409


@pytest.mark.asyncio
async def test_a_non_admin_can_still_delete_their_account(client):
    await _signed_up(client, "owner@example.com")
    guest = await _signed_up(client, "guest@example.com")

    resp = await _delete_own_account(client, guest)
    assert resp.status_code == 204
    assert (await client.get("/api/auth/me", headers=guest)).status_code == 401


@pytest.mark.asyncio
async def test_an_owner_may_leave_while_another_active_admin_remains(client, session_factory):
    from models.user import User

    owner = await _signed_up(client, "owner@example.com")
    await _signed_up(client, "second@example.com")
    async with session_factory() as session:
        await session.execute(
            update(User).where(User.email == "second@example.com").values(is_admin=True)
        )
        await session.commit()

    resp = await _delete_own_account(client, owner)
    assert resp.status_code == 204


@pytest.mark.asyncio
async def test_a_deactivated_admin_does_not_count_as_a_remaining_owner(
    client, session_factory
):
    from models.user import User

    owner = await _signed_up(client, "owner@example.com")
    await _signed_up(client, "second@example.com")
    async with session_factory() as session:
        await session.execute(
            update(User)
            .where(User.email == "second@example.com")
            .values(is_admin=True, is_active=False)
        )
        await session.commit()

    resp = await _delete_own_account(client, owner)
    assert resp.status_code == 409
