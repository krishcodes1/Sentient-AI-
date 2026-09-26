"""Tests for the Slack DM link routes (api/routes/slack.py) and the Slack
reconcile hook in the connector routes (api/routes/connectors.py).

Why it exists: the link code is what binds a Slack account to a Crawler
account, so only the owner of an active Slack connector may mint one, only its
HMAC may be stored, and a new code must replace the old one. Connector changes
must reach the Slack manager after they are committed, without ever failing
the request.
"""

from __future__ import annotations

import json
import uuid
from typing import Any

import pytest
from sqlalchemy import event, select

from core.security import encrypt_credentials
from models.connector import AuthMethod, ConnectorConfig
from models.slack_link import SlackChannelLink
from services.notifications import slack as slack_mod
from tests.conftest import auth_headers, make_user

BOT = "xoxb-test-token-routes"
APP = "xapp-test-token-routes"


async def add_connector(
    session_factory: Any,
    user_id: uuid.UUID,
    *,
    connector_type: str = "slack",
    credentials: dict[str, Any] | None = None,
    active: bool = True,
) -> uuid.UUID:
    creds = credentials if credentials is not None else {"bot_token": BOT, "app_token": APP}
    async with session_factory() as session:
        row = ConnectorConfig(
            user_id=user_id,
            connector_type=connector_type,
            display_name=connector_type,
            auth_method=AuthMethod.bearer_token,
            encrypted_credentials=encrypt_credentials(json.dumps(creds)),
            granted_scopes=[],
            is_active=active,
        )
        session.add(row)
        await session.commit()
        return row.id


async def link_row(session_factory: Any, connector_id: uuid.UUID) -> SlackChannelLink | None:
    async with session_factory() as session:
        return await session.get(SlackChannelLink, connector_id)


def path(connector_id: Any) -> str:
    return f"/api/connectors/{connector_id}/slack/link"


class FakeManager:
    def __init__(self, session_factory: Any = None, running: bool = False) -> None:
        self.session_factory = session_factory
        self.running = running
        self.reconciles = 0
        self.problem: str | None = None

    def channel_running(self, connector_id: str) -> bool:
        return self.running

    def channel_problem(self, connector_id: str) -> str | None:
        return self.problem

    def schedule_reconcile(self) -> None:
        self.reconciles += 1
        return None


@pytest.fixture
def app_state():
    from main import app

    saved = dict(app.state._state)
    try:
        yield app.state
    finally:
        app.state._state.clear()
        app.state._state.update(saved)


@pytest.mark.asyncio
async def test_owner_mints_a_code_and_only_its_hash_is_stored(client, session_factory):
    user, token = await make_user(session_factory, "slack-route-a@example.com")
    connector_id = await add_connector(session_factory, user.id)
    resp = await client.post(path(connector_id), headers=auth_headers(token))
    assert resp.status_code == 200, resp.text
    assert "no-store" in resp.headers["cache-control"]
    body = resp.json()
    code = body["code"]
    assert len(code) >= 24 and body["expires_at"]

    link = await link_row(session_factory, connector_id)
    assert link is not None and link.user_id == user.id
    assert link.link_code_hash == slack_mod.hash_link_code(code)
    stored = json.dumps(
        {c: str(getattr(link, c)) for c in ("team_id", "slack_user_id", "link_code_hash")}
    )
    assert code not in stored
    assert slack_mod.code_matches(link, code)


@pytest.mark.asyncio
async def test_a_new_code_replaces_the_pending_one(client, session_factory):
    user, token = await make_user(session_factory, "slack-route-single@example.com")
    connector_id = await add_connector(session_factory, user.id)
    first = (await client.post(path(connector_id), headers=auth_headers(token))).json()["code"]
    second = (await client.post(path(connector_id), headers=auth_headers(token))).json()["code"]
    link = await link_row(session_factory, connector_id)
    assert first != second
    assert not slack_mod.code_matches(link, first)
    assert slack_mod.code_matches(link, second)


@pytest.mark.asyncio
async def test_a_connector_without_an_app_token_is_a_conflict(client, session_factory):
    user, token = await make_user(session_factory, "slack-route-409@example.com")
    connector_id = await add_connector(session_factory, user.id, credentials={"bot_token": BOT})
    resp = await client.post(path(connector_id), headers=auth_headers(token))
    assert resp.status_code == 409
    assert await link_row(session_factory, connector_id) is None
    # The status says so up front, so the card can hide the link action.
    status = (await client.get(path(connector_id), headers=auth_headers(token))).json()
    assert status["has_app_token"] is False


@pytest.mark.asyncio
@pytest.mark.parametrize("method", ["POST", "GET", "DELETE"])
async def test_only_the_owners_active_slack_connector_is_found(client, session_factory, method):
    owner, _ = await make_user(session_factory, f"slack-route-owner-{method}@example.com")
    intruder, intruder_token = await make_user(
        session_factory, f"slack-route-intruder-{method}@example.com"
    )
    theirs = await add_connector(session_factory, owner.id)
    not_slack = await add_connector(
        session_factory, intruder.id, connector_type="canvas", credentials={"api_key": "k"}
    )
    inactive = await add_connector(session_factory, intruder.id, active=False)
    for connector_id in (theirs, not_slack, inactive, uuid.uuid4()):
        resp = await client.request(
            method, path(connector_id), headers=auth_headers(intruder_token)
        )
        assert resp.status_code == 404, (connector_id, resp.status_code)
    assert await link_row(session_factory, theirs) is None


@pytest.mark.asyncio
async def test_status_reports_link_pending_code_and_channel(client, session_factory, app_state):
    user, token = await make_user(session_factory, "slack-route-status@example.com")
    connector_id = await add_connector(session_factory, user.id)

    status = (await client.get(path(connector_id), headers=auth_headers(token))).json()
    assert status == {
        "linked": False,
        "team_id": None,
        "slack_user_id": None,
        "channel_running": False,
        "channel_error": None,
        "pending_code_expires_at": None,
        "has_app_token": True,
    }

    await client.post(path(connector_id), headers=auth_headers(token))
    app_state.slack_manager = FakeManager(running=True)
    status = (await client.get(path(connector_id), headers=auth_headers(token))).json()
    assert status["pending_code_expires_at"] and status["channel_running"] is True
    assert status["channel_error"] is None

    # A connector held back because its Slack app already runs a channel
    # for another connector says so, so the card can explain it.
    app_state.slack_manager = FakeManager(running=False)
    app_state.slack_manager.problem = "app_token_in_use"
    status = (await client.get(path(connector_id), headers=auth_headers(token))).json()
    assert status["channel_running"] is False
    assert status["channel_error"] == "app_token_in_use"

    async with session_factory() as session:
        link = await session.get(SlackChannelLink, connector_id)
        link.team_id, link.slack_user_id = "T0TEAM001", "U0LINKED1"
        link.link_code_hash, link.link_expires_at = None, None
        await session.commit()
    status = (await client.get(path(connector_id), headers=auth_headers(token))).json()
    assert status["linked"] is True
    assert (status["team_id"], status["slack_user_id"]) == ("T0TEAM001", "U0LINKED1")
    assert status["pending_code_expires_at"] is None


@pytest.mark.asyncio
async def test_unlink_removes_the_link_and_the_pending_code(client, session_factory):
    user, token = await make_user(session_factory, "slack-route-unlink@example.com")
    connector_id = await add_connector(session_factory, user.id)
    await client.post(path(connector_id), headers=auth_headers(token))
    resp = await client.delete(path(connector_id), headers=auth_headers(token))
    assert resp.status_code == 204
    assert await link_row(session_factory, connector_id) is None
    # Unlinking with nothing linked is fine too.
    assert (await client.delete(path(connector_id), headers=auth_headers(token))).status_code == 204


@pytest.mark.asyncio
async def test_code_minting_is_rate_limited(client, session_factory):
    from api.routes.slack import LINK_CODES_PER_MINUTE

    user, token = await make_user(session_factory, "slack-route-rate@example.com")
    connector_id = await add_connector(session_factory, user.id)
    for _ in range(LINK_CODES_PER_MINUTE):
        assert (
            await client.post(path(connector_id), headers=auth_headers(token))
        ).status_code == 200
    assert (await client.post(path(connector_id), headers=auth_headers(token))).status_code == 429


@pytest.mark.asyncio
async def test_link_rows_cascade_with_their_connector(session_factory):
    user, _ = await make_user(session_factory, "slack-route-cascade@example.com")
    connector_id = await add_connector(session_factory, user.id)
    async with session_factory() as session:
        session.add(SlackChannelLink(connector_id=connector_id, user_id=user.id))
        await session.commit()
    async with session_factory() as session:
        await session.delete(await session.get(ConnectorConfig, connector_id))
        await session.commit()
    assert await link_row(session_factory, connector_id) is None


class StatementLog:
    """Records the SQL the test engine runs (to prove an explicit delete,
    which a SQLite database without foreign keys would otherwise skip)."""

    def __init__(self, session_factory: Any) -> None:
        self.engine = session_factory.kw["bind"].sync_engine
        self.statements: list[str] = []

    def _record(self, conn, cursor, statement, parameters, context, executemany) -> None:
        self.statements.append(" ".join(statement.split()).upper())

    def __enter__(self) -> "StatementLog":
        event.listen(self.engine, "before_cursor_execute", self._record)
        return self

    def __exit__(self, *exc: Any) -> None:
        event.remove(self.engine, "before_cursor_execute", self._record)

    def deleted_links(self) -> list[str]:
        return [s for s in self.statements if s.startswith("DELETE FROM SLACK_CHANNEL_LINKS")]


@pytest.mark.asyncio
async def test_deleting_a_slack_connector_deletes_its_link_explicitly(
    client, session_factory, app_state, monkeypatch
):
    import api.routes.connectors as connector_routes

    monkeypatch.setattr(connector_routes.oauth_broker, "schedule_revoke", lambda *a, **k: None)
    manager = FakeManager()
    app_state.slack_manager = manager
    user, token = await make_user(session_factory, "slack-route-del-link@example.com")
    connector_id = await add_connector(session_factory, user.id)
    await client.post(path(connector_id), headers=auth_headers(token))
    with StatementLog(session_factory) as log:
        resp = await client.delete(f"/api/connectors/{connector_id}", headers=auth_headers(token))
    assert resp.status_code == 204
    assert len(log.deleted_links()) == 1
    assert await link_row(session_factory, connector_id) is None
    assert manager.reconciles == 1


@pytest.mark.asyncio
async def test_deleting_the_account_drops_its_links_and_reconciles_slack(
    client, session_factory, app_state, monkeypatch
):
    import api.routes.auth as auth_routes

    monkeypatch.setattr(auth_routes.oauth_broker, "schedule_revoke", lambda *a, **k: None)
    manager = FakeManager()
    app_state.slack_manager = manager
    user, token = await make_user(session_factory, "slack-route-del-account@example.com")
    connector_id = await add_connector(session_factory, user.id)
    await client.post(path(connector_id), headers=auth_headers(token))
    with StatementLog(session_factory) as log:
        resp = await client.request(
            "DELETE",
            "/api/auth/account",
            headers=auth_headers(token),
            json={"current_password": "password-123"},
        )
    assert resp.status_code == 204, resp.text
    assert len(log.deleted_links()) == 1
    assert await link_row(session_factory, connector_id) is None
    # The deleted user's channel is stopped in the background, not awaited.
    assert manager.reconciles == 1


@pytest.mark.asyncio
async def test_account_deletion_without_a_slack_manager_still_succeeds(
    client, session_factory, app_state
):
    app_state.slack_manager = None
    user, token = await make_user(session_factory, "slack-route-del-nomgr@example.com")
    resp = await client.request(
        "DELETE",
        "/api/auth/account",
        headers=auth_headers(token),
        json={"current_password": "password-123"},
    )
    assert resp.status_code == 204, resp.text


# ── the reconcile hook in the connector routes ───────────────────────────


@pytest.mark.asyncio
async def test_slack_connector_changes_reconcile_after_commit(
    client, session_factory, app_state, monkeypatch
):
    import api.routes.connectors as connector_routes

    monkeypatch.setattr(connector_routes.oauth_broker, "schedule_revoke", lambda *a, **k: None)

    from sqlalchemy.ext.asyncio import AsyncSession

    events: list[str] = []
    real_commit = AsyncSession.commit

    async def commit(self: AsyncSession) -> None:
        events.append("commit")
        await real_commit(self)

    monkeypatch.setattr(AsyncSession, "commit", commit)

    class OrderCheck(FakeManager):
        def schedule_reconcile(self) -> None:
            super().schedule_reconcile()
            events.append("reconcile")

    manager = OrderCheck(session_factory)
    app_state.slack_manager = manager
    user, token = await make_user(session_factory, "slack-route-hook@example.com")
    body = {
        "connector_type": "slack",
        "display_name": "Work Slack",
        "auth_method": "bearer_token",
        "credentials": {"bot_token": BOT, "app_token": APP},
    }
    created = await client.post("/api/connectors/", json=body, headers=auth_headers(token))
    assert created.status_code == 201, created.text
    connector_id = created.json()["id"]
    assert manager.reconciles == 1
    # Committed before the manager was asked: it reads with its own session.
    first = events.index("reconcile")
    assert first > 0 and events[first - 1] == "commit"
    async with session_factory() as session:
        found = (
            await session.execute(
                select(ConnectorConfig).where(ConnectorConfig.id == uuid.UUID(connector_id))
            )
        ).scalar_one_or_none()
    assert found is not None

    patched = await client.patch(
        f"/api/connectors/{connector_id}", json={"is_active": False}, headers=auth_headers(token)
    )
    assert patched.status_code == 200 and manager.reconciles == 2
    deleted = await client.delete(f"/api/connectors/{connector_id}", headers=auth_headers(token))
    assert deleted.status_code == 204 and manager.reconciles == 3


@pytest.mark.asyncio
async def test_other_connector_types_do_not_reconcile(client, session_factory, app_state):
    manager = FakeManager()
    app_state.slack_manager = manager
    user, token = await make_user(session_factory, "slack-route-other@example.com")
    body = {
        "connector_type": "canvas",
        "display_name": "Canvas",
        "auth_method": "bearer_token",
        "credentials": {
            "access_token": "canvas-test-token",
            "base_url": "https://canvas.instructure.com",
        },
    }
    resp = await client.post("/api/connectors/", json=body, headers=auth_headers(token))
    assert resp.status_code == 201, resp.text
    assert manager.reconciles == 0


@pytest.mark.asyncio
async def test_a_failing_reconcile_request_never_fails_the_change(
    client, session_factory, app_state
):
    class Broken(FakeManager):
        def schedule_reconcile(self) -> None:
            raise RuntimeError("manager is gone")

    app_state.slack_manager = Broken()
    user, token = await make_user(session_factory, "slack-route-broken@example.com")
    body = {
        "connector_type": "slack",
        "display_name": "Slack",
        "auth_method": "bearer_token",
        "credentials": {"bot_token": BOT},
    }
    resp = await client.post("/api/connectors/", json=body, headers=auth_headers(token))
    assert resp.status_code == 201, resp.text
