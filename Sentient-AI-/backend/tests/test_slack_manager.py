"""Tests for SlackManager (services/notifications/slack_manager.py) and the
composite approval notifier and reminder sender in main.py.

Why it exists: the manager decides which Slack DM channels run (one per active
Slack connector with an app-level token), so a token change must restart a
channel, a deletion or the owner's switch must stop it, and the database must
be read in one query. The composites must keep Telegram and Slack independent:
one channel failing can never cost the other its card or reminder.
"""

from __future__ import annotations

import asyncio
import json
import uuid
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from typing import Any

import pytest
from sqlalchemy import event, update

from core.security import encrypt_credentials
from models.connector import AuthMethod, ConnectorConfig
from models.user import User
from services.notifications.slack_manager import PROBLEM_APP_TOKEN_IN_USE, SlackManager
from tests.conftest import make_user

BOT = "xoxb-test-token-one"
APP = "xapp-test-token-one"


class FakeChannel:
    instances: list["FakeChannel"] = []

    def __init__(self, *, connector_id, user_id, bot_token, app_token, session_factory):
        self.connector_id = connector_id
        self.user_id = user_id
        self.bot_token = bot_token
        self.app_token = app_token
        self.started = False
        self.stopped = False
        self.notified: list[Any] = []
        self.texts: list[tuple[str, str]] = []
        self.fail = False
        self.connected = False
        self.last_error: str | None = None
        FakeChannel.instances.append(self)

    @property
    def running(self) -> bool:
        return self.started and not self.stopped

    async def start(self) -> None:
        await asyncio.sleep(0)
        self.started = True

    async def stop(self) -> None:
        await asyncio.sleep(0)
        self.stopped = True

    async def notify_pending(self, action: Any) -> bool:
        if self.fail:
            raise RuntimeError("slack down")
        self.notified.append(action)
        return True

    async def send_text(self, user_id: str, text: str) -> bool:
        if self.fail:
            raise RuntimeError("slack down")
        self.texts.append((user_id, text))
        return True


@pytest.fixture(autouse=True)
def _reset():
    FakeChannel.instances.clear()


async def add_connector(
    session_factory: Any,
    user_id: uuid.UUID,
    *,
    connector_type: str = "slack",
    credentials: dict[str, Any] | None = None,
    active: bool = True,
) -> str:
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
        return str(row.id)


async def set_credentials(
    session_factory: Any, connector_id: str, credentials: dict[str, Any]
) -> None:
    async with session_factory() as session:
        await session.execute(
            update(ConnectorConfig)
            .where(ConnectorConfig.id == uuid.UUID(connector_id))
            .values(encrypted_credentials=encrypt_credentials(json.dumps(credentials)))
        )
        await session.commit()


def manager(session_factory: Any, **kwargs: Any) -> SlackManager:
    return SlackManager(session_factory, channel_factory=FakeChannel, **kwargs)


@pytest.mark.asyncio
async def test_reconcile_starts_one_channel_per_eligible_connector(session_factory):
    user, _ = await make_user(session_factory, "slack-mgr-a@example.com")
    idle, _ = await make_user(session_factory, "slack-mgr-idle@example.com")
    wanted = await add_connector(session_factory, user.id)
    await add_connector(session_factory, user.id, credentials={"bot_token": BOT})  # no app token
    await add_connector(session_factory, user.id, active=False)
    await add_connector(
        session_factory, user.id, credentials={"bot_token": BOT, "app_token": "not-xapp"}
    )
    await add_connector(
        session_factory, user.id, connector_type="canvas", credentials={"api_key": "k"}
    )
    await add_connector(session_factory, idle.id)
    async with session_factory() as session:
        await session.execute(update(User).where(User.id == idle.id).values(is_active=False))
        await session.commit()

    hooked: list[str] = []
    changes: list[str] = []
    mgr = manager(
        session_factory,
        on_start=lambda ch: hooked.append(ch.connector_id),
        on_change=lambda: changes.append("x"),
    )
    summary = await mgr.reconcile()
    assert summary["started"] == [wanted]
    assert list(mgr.channels) == [wanted]
    channel = FakeChannel.instances[-1]
    assert channel.started and channel.user_id == str(user.id)
    assert (channel.bot_token, channel.app_token) == (BOT, APP)
    assert hooked == [wanted] and changes == ["x"]
    assert mgr.is_running and mgr.channel_running(wanted)

    # Nothing changed: nothing restarts and no change is announced.
    assert await mgr.reconcile() == {"started": [], "restarted": [], "stopped": []}
    assert len(FakeChannel.instances) == 1 and changes == ["x"]


@pytest.mark.asyncio
async def test_reconcile_reads_the_database_in_one_query(session_factory):
    user, _ = await make_user(session_factory, "slack-mgr-q@example.com")
    for _ in range(3):
        await add_connector(session_factory, user.id)
    engine = session_factory.kw["bind"]
    statements: list[str] = []

    def count(conn, cursor, statement, parameters, context, executemany):
        statements.append(statement)

    event.listen(engine.sync_engine, "before_cursor_execute", count)
    try:
        await manager(session_factory).reconcile()
    finally:
        event.remove(engine.sync_engine, "before_cursor_execute", count)
    selects = [s for s in statements if s.lstrip().upper().startswith("SELECT")]
    assert len(selects) == 1
    assert "connector_configs" in selects[0] and "users" in selects[0]


@pytest.mark.asyncio
async def test_a_token_change_restarts_and_a_deletion_stops(session_factory):
    user, _ = await make_user(session_factory, "slack-mgr-r@example.com")
    connector_id = await add_connector(session_factory, user.id)
    mgr = manager(session_factory)
    await mgr.reconcile()
    first = FakeChannel.instances[-1]

    await set_credentials(
        session_factory, connector_id, {"bot_token": BOT, "app_token": "xapp-test-token-two"}
    )
    summary = await mgr.reconcile()
    assert summary["restarted"] == [connector_id]
    second = FakeChannel.instances[-1]
    assert first.stopped and second.running and second.app_token == "xapp-test-token-two"

    async with session_factory() as session:
        row = await session.get(ConnectorConfig, uuid.UUID(connector_id))
        await session.delete(row)
        await session.commit()
    summary = await mgr.reconcile()
    assert summary["stopped"] == [connector_id]
    assert second.stopped and mgr.channels == {} and not mgr.is_running


@pytest.mark.asyncio
async def test_a_dead_channel_is_restarted(session_factory):
    user, _ = await make_user(session_factory, "slack-mgr-dead@example.com")
    connector_id = await add_connector(session_factory, user.id)
    mgr = manager(session_factory)
    await mgr.reconcile()
    FakeChannel.instances[-1].stopped = True  # its loop ended on its own
    summary = await mgr.reconcile()
    assert summary["restarted"] == [connector_id]
    assert FakeChannel.instances[-1].running


@pytest.mark.asyncio
async def test_the_owner_switch_stops_everything(session_factory):
    user, _ = await make_user(session_factory, "slack-mgr-off@example.com")
    connector_id = await add_connector(session_factory, user.id)
    enabled = {"on": True}

    async def is_enabled() -> bool:
        return enabled["on"]

    mgr = manager(session_factory, enabled=is_enabled)
    await mgr.reconcile()
    enabled["on"] = False
    assert (await mgr.reconcile())["stopped"] == [connector_id]
    assert not mgr.is_running
    enabled["on"] = True
    assert (await mgr.reconcile())["started"] == [connector_id]


@pytest.mark.asyncio
async def test_a_failing_start_is_contained(session_factory):
    user, _ = await make_user(session_factory, "slack-mgr-fail@example.com")
    await add_connector(session_factory, user.id)

    def broken_hook(channel: Any) -> None:
        raise RuntimeError("wiring failed")

    mgr = manager(session_factory, on_start=broken_hook)
    summary = await mgr.reconcile()
    assert summary == {"started": [], "restarted": [], "stopped": []}
    assert mgr.channels == {} and FakeChannel.instances[-1].stopped


@pytest.mark.asyncio
async def test_concurrent_reconciles_start_one_channel(session_factory):
    user, _ = await make_user(session_factory, "slack-mgr-race@example.com")
    await add_connector(session_factory, user.id)
    mgr = manager(session_factory)
    await asyncio.gather(mgr.reconcile(), mgr.reconcile(), mgr.reconcile())
    assert len(FakeChannel.instances) == 1


@pytest.mark.asyncio
async def test_scheduled_reconcile_and_stop(session_factory):
    user, _ = await make_user(session_factory, "slack-mgr-sched@example.com")
    await add_connector(session_factory, user.id)
    mgr = manager(session_factory)
    task = mgr.schedule_reconcile()
    assert task is not None
    await mgr.wait_idle()
    assert mgr.is_running
    await mgr.stop()
    assert not mgr.is_running and FakeChannel.instances[-1].stopped
    assert mgr.schedule_reconcile() is None
    assert await mgr.reconcile() == {"started": [], "restarted": [], "stopped": []}


@pytest.mark.asyncio
async def test_notify_and_send_route_to_the_owner_channels_only(session_factory):
    alice, _ = await make_user(session_factory, "slack-mgr-alice@example.com")
    bob, _ = await make_user(session_factory, "slack-mgr-bob@example.com")
    await add_connector(session_factory, alice.id)
    await add_connector(
        session_factory,
        alice.id,
        credentials={"bot_token": "xoxb-test-second", "app_token": "xapp-test-second"},
    )
    await add_connector(
        session_factory,
        bob.id,
        credentials={"bot_token": "xoxb-test-bob", "app_token": "xapp-test-bob"},
    )
    mgr = manager(session_factory)
    await mgr.reconcile()
    by_owner = {c.app_token: c for c in FakeChannel.instances}
    alice_one, alice_two, bob_channel = (
        by_owner[APP],
        by_owner["xapp-test-second"],
        by_owner["xapp-test-bob"],
    )

    alice_one.fail = True
    action = SimpleNamespace(user_id=str(alice.id), action_id="a1")
    await mgr.notify_pending(action)
    assert alice_two.notified == [action] and bob_channel.notified == []

    assert await mgr.send_text(str(alice.id), "reminder") is True
    assert alice_two.texts == [(str(alice.id), "reminder")] and bob_channel.texts == []
    alice_two.fail = True
    assert await mgr.send_text(str(alice.id), "again") is False
    assert await mgr.send_text(str(uuid.uuid4()), "nobody") is False


async def set_created_at(session_factory: Any, connector_id: str, when: datetime) -> None:
    async with session_factory() as session:
        await session.execute(
            update(ConnectorConfig)
            .where(ConnectorConfig.id == uuid.UUID(connector_id))
            .values(created_at=when)
        )
        await session.commit()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "second_credentials",
    [
        # One Slack app, the same tokens pasted by two Crawler users.
        {"bot_token": BOT, "app_token": APP},
        # The same app installation (bot token) with another app-level token
        # of that app: Slack still splits events across both sockets.
        {"bot_token": BOT, "app_token": "xapp-test-token-other"},
        # The same app-level token with another bot token.
        {"bot_token": "xoxb-test-token-other", "app_token": APP},
    ],
)
async def test_connectors_sharing_a_slack_app_run_one_socket(session_factory, second_credentials):
    """Slack hands each event to any one open connection of an app, so two
    sockets for one app would drop each other's DMs and presses. Only the
    oldest connector runs; the other reports why, and takes over when the
    first goes away."""
    alice, _ = await make_user(session_factory, "slack-mgr-share-a@example.com")
    bob, _ = await make_user(session_factory, "slack-mgr-share-b@example.com")
    older = await add_connector(session_factory, alice.id)
    newer = await add_connector(session_factory, bob.id, credentials=second_credentials)
    now = datetime.now(timezone.utc)
    await set_created_at(session_factory, older, now - timedelta(days=1))
    await set_created_at(session_factory, newer, now)

    mgr = manager(session_factory)
    summary = await mgr.reconcile()
    assert summary["started"] == [older]
    assert list(mgr.channels) == [older] and len(FakeChannel.instances) == 1
    assert mgr.channel_running(older) and not mgr.channel_running(newer)
    assert mgr.channel_problem(newer) == PROBLEM_APP_TOKEN_IN_USE
    assert mgr.channel_problem(older) is None

    # Stable: nothing restarts, the running channel keeps the app.
    assert await mgr.reconcile() == {"started": [], "restarted": [], "stopped": []}

    async with session_factory() as session:
        await session.delete(await session.get(ConnectorConfig, uuid.UUID(older)))
        await session.commit()
    summary = await mgr.reconcile()
    assert summary == {"started": [newer], "restarted": [], "stopped": [older]}
    assert FakeChannel.instances[0].stopped and FakeChannel.instances[-1].running
    assert FakeChannel.instances[-1].user_id == str(bob.id)
    assert mgr.channel_problem(newer) is None


@pytest.mark.asyncio
async def test_the_running_channel_keeps_its_app_over_an_older_connector(session_factory):
    """A connector re-enabled later is older, but the channel already
    serving that app is not torn down for it."""
    user, _ = await make_user(session_factory, "slack-mgr-keep@example.com")
    first = await add_connector(session_factory, user.id, active=False)
    second = await add_connector(session_factory, user.id)
    now = datetime.now(timezone.utc)
    await set_created_at(session_factory, first, now - timedelta(days=1))
    await set_created_at(session_factory, second, now)
    mgr = manager(session_factory)
    await mgr.reconcile()
    assert list(mgr.channels) == [second]
    async with session_factory() as session:
        await session.execute(
            update(ConnectorConfig)
            .where(ConnectorConfig.id == uuid.UUID(first))
            .values(is_active=True)
        )
        await session.commit()
    assert await mgr.reconcile() == {"started": [], "restarted": [], "stopped": []}
    assert list(mgr.channels) == [second]
    assert mgr.channel_problem(first) == PROBLEM_APP_TOKEN_IN_USE


@pytest.mark.asyncio
async def test_channel_problem_reports_the_last_connection_error(session_factory):
    user, _ = await make_user(session_factory, "slack-mgr-problem@example.com")
    connector_id = await add_connector(session_factory, user.id)
    mgr = manager(session_factory)
    await mgr.reconcile()
    channel = FakeChannel.instances[-1]
    assert mgr.channel_problem(connector_id) is None
    channel.last_error = "socket_refused"
    assert mgr.channel_problem(connector_id) == "socket_refused"
    # Once Slack greets the socket, a stale error is not reported.
    channel.connected = True
    assert mgr.channel_problem(connector_id) is None
    assert mgr.channel_problem(str(uuid.uuid4())) is None


@pytest.mark.asyncio
async def test_switching_slack_off_clears_the_held_back_connectors(session_factory):
    user, _ = await make_user(session_factory, "slack-mgr-off-held@example.com")
    running = await add_connector(session_factory, user.id)
    held = await add_connector(session_factory, user.id)
    enabled = {"on": True}

    async def is_enabled() -> bool:
        return enabled["on"]

    mgr = manager(session_factory, enabled=is_enabled)
    await mgr.reconcile()
    problems = {c: mgr.channel_problem(c) for c in (running, held)}
    assert sorted(problems.values(), key=lambda v: v is None) == [PROBLEM_APP_TOKEN_IN_USE, None]
    enabled["on"] = False
    await mgr.reconcile()
    assert mgr.channel_problem(running) is None and mgr.channel_problem(held) is None


@pytest.mark.asyncio
async def test_proxies_are_noops_with_no_channels(session_factory):
    mgr = manager(session_factory)
    await mgr.notify_pending(SimpleNamespace(user_id="u1"))
    assert await mgr.send_text("u1", "hi") is False
    assert mgr.channel_running("anything") is False


# ── composites in main.py ────────────────────────────────────────────────


@pytest.mark.asyncio
@pytest.mark.parametrize("broken", ["telegram", "slack"])
async def test_one_channel_failing_never_blocks_the_other_card(broken):
    from main import fan_out_notify

    delivered: list[str] = []

    def channel(name: str):
        async def notify(action: Any) -> None:
            if name == broken:
                raise RuntimeError(f"{name} down")
            delivered.append(name)

        return notify

    notify = fan_out_notify({"telegram": channel("telegram"), "slack": channel("slack")})
    await notify(SimpleNamespace(action_id="a"))
    assert delivered == [n for n in ("telegram", "slack") if n != broken]


@pytest.mark.asyncio
async def test_a_hung_channel_does_not_delay_the_other_card():
    from main import fan_out_notify

    delivered = asyncio.Event()
    release = asyncio.Event()

    async def hung(action: Any) -> None:
        await release.wait()

    async def fast(action: Any) -> None:
        delivered.set()

    task = asyncio.create_task(fan_out_notify({"telegram": hung, "slack": fast})(object()))
    await asyncio.wait_for(delivered.wait(), timeout=2)
    release.set()
    await task


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "telegram,slack,expected",
    [
        (True, False, True),
        (False, True, True),
        (False, False, False),
        ("raise", True, True),
        (True, "raise", True),
        ("raise", "raise", False),
    ],
)
async def test_reminder_fan_out_is_true_when_any_channel_delivered(telegram, slack, expected):
    from main import fan_out_send

    sent: list[str] = []

    def channel(name: str, result: Any):
        async def send(user_id: str, text: str) -> bool:
            sent.append(name)
            if result == "raise":
                raise RuntimeError(f"{name} down")
            return result

        return send

    send = fan_out_send(
        {"telegram": channel("telegram", telegram), "slack": channel("slack", slack)}
    )
    assert await send("u1", "hello") is expected
    assert sorted(sent) == ["slack", "telegram"]
