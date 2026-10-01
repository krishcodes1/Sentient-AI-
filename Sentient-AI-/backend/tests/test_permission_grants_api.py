"""Tests for the web side of permission tiers: listing and revoking low-risk
grants (GET and DELETE /api/agent/permission-grants), the approvals route's
``remember="low_risk"``, the card's ``low_risk_account``, the connectors PATCH
that audits tier changes and takes grants back when credentials change or a
scope is added, and the account setting that now accepts ``low_risk``.

Why it exists: a grant runs changes without a card for a week, so the owner
must see and end each one, another user must never see or end it, and new
credentials or wider access must never inherit it. The app runs in-process
against in-memory SQLite with the test's own runtime on app.state; the
connector talks to an ``httpx.MockTransport`` fake. No network, no model.
"""

from __future__ import annotations

import json
from datetime import timedelta
from typing import Any

import httpx
import pytest
from sqlalchemy import select

import core.network_security as netsec
from core.config import settings
from services import capabilities as capability_registry
from services.agent.approvals import InMemoryApprovalStore
from services.agent.permission_grants import GRANT_TTL, DbPermissionGrantStore
from services.agent.runtime import AgentRuntime
from services.agent.tool_registry import ConnectorToolExecutor, RuntimePermissionAdapter
from services.audit import _sanitize
from services.capabilities.base import ReportContext
from tests.conftest import auth_headers, make_user
from tests.test_computer_precheck import RecordingAudit

STAR = "google_workspace.modify_labels"


def _gate():
    ctx = ReportContext(in_container=False, platform="win32", telegram_configured=True, browser_installed=True)
    statuses = capability_registry.statuses_by_key(
        capability_registry.report(dict.fromkeys(capability_registry.keys(), True), ctx, use_cache=False)
    )

    async def gate():
        return statuses

    return gate


@pytest.fixture
def gmail(monkeypatch) -> list[httpx.Request]:
    import services.connectors.factory as factory_module

    monkeypatch.setattr(netsec, "check_ssrf", lambda url: netsec.SSRFCheckResult(safe=True))
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(200, json={"id": "m1", "labelIds": ["STARRED"]})

    real_create = factory_module.create_connector

    def _create(connector_type, credentials, *, rate_limit=None, timeout_s=None):
        connector = real_create(connector_type, credentials, rate_limit=rate_limit, timeout_s=timeout_s)
        connector._http_client = httpx.AsyncClient(
            transport=httpx.MockTransport(handler),
            event_hooks={"request": [connector._enforce_network_policy]},
        )
        return connector

    monkeypatch.setattr(factory_module, "create_connector", _create)
    return seen


class Installed:
    """A runtime of the test's own on app.state for the duration."""

    def __init__(self, session_factory: Any) -> None:
        self.grants = DbPermissionGrantStore(session_factory)
        self.approvals = InMemoryApprovalStore()
        self.audit = RecordingAudit()
        gate = _gate()
        self.runtime = AgentRuntime(
            config=settings,
            permission_engine=RuntimePermissionAdapter(capability_gate=gate),
            tool_executor=ConnectorToolExecutor(
                session_factory=session_factory, capability_gate=gate, permission_grants=self.grants
            ),
            audit_service=self.audit,
            approval_store=self.approvals,
            permission_grant_store=self.grants,
        )

    def __enter__(self) -> "Installed":
        from main import app

        self._saved = getattr(app.state, "agent_runtime", None)
        app.state.agent_runtime = self.runtime
        return self

    def __exit__(self, *_exc: Any) -> None:
        from main import app

        app.state.agent_runtime = self._saved


async def _connector(session_factory, user_id, *, tier: str = "user_confirm", scopes=("gmail.read", "gmail.modify"), name="School Gmail") -> str:
    from core.security import encrypt_credentials
    from models.connector import AuthMethod, ConnectorConfig, PermissionTier

    async with session_factory() as session:
        row = ConnectorConfig(
            user_id=user_id,
            connector_type="google_workspace",
            display_name=name,
            auth_method=AuthMethod.oauth2,
            encrypted_credentials=encrypt_credentials(json.dumps({"access_token": "tok"})),
            granted_scopes=list(scopes),
            permission_tier=PermissionTier(tier),
        )
        session.add(row)
        await session.commit()
        return str(row.id)


async def _chains(session_factory, user_id) -> list[dict[str, Any]]:
    from models.audit import AuditLog

    async with session_factory() as session:
        rows = (await session.execute(select(AuditLog).where(AuditLog.user_id == user_id))).scalars().all()
    return [r.reasoning_chain or {} for r in rows]


# ── list and revoke ─────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_list_and_revoke_grants_and_another_user_cannot(client, session_factory):
    user, token = await make_user(session_factory, "grants-owner@example.com")
    other, other_token = await make_user(session_factory, "grants-other@example.com")
    connector_id = await _connector(session_factory, user.id)
    with Installed(session_factory) as installed:
        grant = await installed.grants.allow(user_id=str(user.id), connector_id=connector_id, granted_from="telegram")
        assert grant is not None
        listed = (await client.get("/api/agent/permission-grants", headers=auth_headers(token))).json()
        assert listed == [
            {
                "id": grant.id,
                "connector_id": connector_id,
                "account": "School Gmail",
                "connector_type": "google_workspace",
                "kind": "low_risk",
                "granted_from": "telegram",
                "granted_at": grant.granted_at.isoformat(),
                "expires_at": grant.expires_at.isoformat(),
                "last_used_at": None,
                "uses": 0,
            }
        ]
        # Another user sees nothing and cannot revoke it.
        assert (await client.get("/api/agent/permission-grants", headers=auth_headers(other_token))).json() == []
        foreign = await client.delete(f"/api/agent/permission-grants/{grant.id}", headers=auth_headers(other_token))
        assert foreign.status_code == 404
        assert (await client.delete(f"/api/agent/permission-grants/{grant.id}", headers=auth_headers(token))).status_code == 204
        again = await client.delete(f"/api/agent/permission-grants/{grant.id}", headers=auth_headers(token))
        assert again.status_code == 404
        assert (await client.get("/api/agent/permission-grants", headers=auth_headers(token))).json() == []
    [revoked] = [c for c in await _chains(session_factory, user.id) if c.get("event") == "permission_grant_revoked"]
    # Ids pass the audit sanitizer like every other value.
    assert revoked["revoked_from"] == "web" and revoked["grant_id"] == _sanitize(grant.id)
    assert revoked["connector_id"] == _sanitize(connector_id)
    assert await _chains(session_factory, other.id) == []


@pytest.mark.asyncio
async def test_grants_need_a_signed_in_user(client):
    assert (await client.get("/api/agent/permission-grants")).status_code in (401, 403)


# ── the approvals route ─────────────────────────────────────────────────────


async def _park_card(installed: Installed, user_id: str, connector_id: str, offer: bool = True) -> str:
    stored = await installed.approvals.create(
        user_id=user_id,
        tool_name=STAR,
        arguments={"message_id": "m1", "add_label_ids": ["STARRED"]},
        reason="Tool 'google_workspace.modify_labels' requires explicit user approval",
        grant_offer={"kind": "low_risk", "connector_id": connector_id, "account": "School Gmail"} if offer else None,
    )
    return stored.action_id


@pytest.mark.asyncio
async def test_the_approvals_route_carries_the_offer_and_takes_remember_low_risk(client, session_factory, gmail):
    user, token = await make_user(session_factory, "grants-approve@example.com")
    connector_id = await _connector(session_factory, user.id)
    with Installed(session_factory) as installed:
        action_id = await _park_card(installed, str(user.id), connector_id)
        [card] = (await client.get("/api/agent/approvals", headers=auth_headers(token))).json()
        assert card["low_risk_account"] == "School Gmail"

        bad = await client.post(
            f"/api/agent/approvals/{action_id}", headers=auth_headers(token), json={"approved": True, "remember": "forever"}
        )
        assert bad.status_code == 422
        decided = await client.post(
            f"/api/agent/approvals/{action_id}", headers=auth_headers(token), json={"approved": True, "remember": "low_risk"}
        )
        assert decided.status_code == 200, decided.text
        body = decided.json()
        assert body["low_risk"]["account"] == "School Gmail"
        [grant] = await installed.grants.list_live(str(user.id))
        assert body["low_risk"]["expires_at"] == grant.expires_at.isoformat()
        assert grant.expires_at - grant.granted_at == GRANT_TTL
        assert grant.granted_from is None  # no device header: not recorded
    assert len(gmail) == 1  # the approved star ran once
    assert [e["event"] for e in installed.audit.entries if e["event"] == "permission_grant_granted"] == [
        "permission_grant_granted"
    ]


@pytest.mark.asyncio
async def test_a_plain_approval_makes_no_grant(client, session_factory, gmail):
    user, token = await make_user(session_factory, "grants-plain@example.com")
    connector_id = await _connector(session_factory, user.id)
    with Installed(session_factory) as installed:
        action_id = await _park_card(installed, str(user.id), connector_id)
        decided = await client.post(
            f"/api/agent/approvals/{action_id}", headers=auth_headers(token), json={"approved": True}
        )
        assert decided.status_code == 200 and decided.json()["low_risk"] is None
        assert await installed.grants.list_live(str(user.id)) == []


# ── connectors PATCH ────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_new_credentials_or_a_new_scope_take_back_grants_and_tier_changes_are_audited(client, session_factory):
    user, token = await make_user(session_factory, "grants-patch@example.com")
    connector_id = await _connector(session_factory, user.id, scopes=("gmail.read", "gmail.modify"))
    store = DbPermissionGrantStore(session_factory)
    headers = auth_headers(token)

    async def live() -> int:
        return len(await store.list_live(str(user.id)))

    await store.allow(user_id=str(user.id), connector_id=connector_id)
    # Renaming, narrowing the scopes and changing the tier keep the grant.
    response = await client.patch(
        f"/api/connectors/{connector_id}",
        headers=headers,
        json={"display_name": "Uni Gmail", "granted_scopes": ["gmail.modify"], "permission_tier": "low_risk"},
    )
    assert response.status_code == 200, response.text
    assert response.json()["permission_tier"] == "low_risk"
    assert await live() == 1
    # A scope the connection did not have: the grant ends.
    response = await client.patch(
        f"/api/connectors/{connector_id}", headers=headers, json={"granted_scopes": ["gmail.modify", "gmail.send"]}
    )
    assert response.status_code == 200, response.text
    assert await live() == 0
    # New credentials: the grant ends too.
    await store.allow(user_id=str(user.id), connector_id=connector_id)
    response = await client.patch(
        f"/api/connectors/{connector_id}", headers=headers, json={"credentials": {"access_token": "new-token"}}
    )
    assert response.status_code == 200, response.text
    assert await live() == 0

    chains = await _chains(session_factory, user.id)
    [tier] = [c for c in chains if c.get("event") == "connector_tier_changed"]
    assert (tier["from"], tier["to"], tier["connector_id"]) == ("user_confirm", "low_risk", _sanitize(connector_id))
    revoked = [c for c in chains if c.get("event") == "permission_grant_revoked"]
    assert [(r["reason"], r["count"], r["revoked_from"]) for r in revoked] == [
        ("scope added", 1, "connector_change"),
        ("credentials replaced", 1, "connector_change"),
    ]


# ── the account setting ─────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_the_account_default_accepts_low_risk_and_is_audited(client, session_factory):
    user, token = await make_user(session_factory, "grants-settings@example.com")
    headers = auth_headers(token)
    response = await client.patch("/api/auth/settings", headers=headers, json={"default_permission_tier": "low_risk"})
    assert response.status_code == 200, response.text
    assert response.json()["default_permission_tier"] == "low_risk"
    # The same value again changes nothing and writes no row.
    await client.patch("/api/auth/settings", headers=headers, json={"default_permission_tier": "low_risk"})
    bad = await client.patch("/api/auth/settings", headers=headers, json={"default_permission_tier": "yolo"})
    assert bad.status_code == 422
    changed = [c for c in await _chains(session_factory, user.id) if c.get("event") == "account_tier_changed"]
    assert [(c["from"], c["to"]) for c in changed] == [("user_confirm", "low_risk")]


def test_grant_ttl_is_seven_days():
    assert GRANT_TTL == timedelta(days=7)
