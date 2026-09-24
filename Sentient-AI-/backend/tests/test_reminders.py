"""Reminder CRUD ownership and sweeper delivery semantics."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import select

from tests.conftest import auth_headers, make_user


def _iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat()


@pytest.mark.asyncio
async def test_create_list_and_cancel_reminder(client, session_factory):
    _, token = await make_user(session_factory, email="rem-owner@example.com")
    due = datetime.now(timezone.utc) + timedelta(days=3)

    resp = await client.post(
        "/api/reminders/",
        headers=auth_headers(token),
        json={
            "title": "Ergotron HX delivery",
            "note": "Check the porch.",
            "due_at": _iso(due),
        },
    )
    assert resp.status_code == 201
    created = resp.json()
    assert created["title"] == "Ergotron HX delivery"
    assert created["status"] == "scheduled"
    assert created["source"] == "user"

    resp = await client.get("/api/reminders/", headers=auth_headers(token))
    assert [r["id"] for r in resp.json()] == [created["id"]]

    resp = await client.delete(
        f"/api/reminders/{created['id']}", headers=auth_headers(token)
    )
    assert resp.status_code == 204

    # Cancelled rows drop out of the default listing but still exist.
    resp = await client.get("/api/reminders/", headers=auth_headers(token))
    assert resp.json() == []
    resp = await client.get(
        "/api/reminders/?include_delivered=true", headers=auth_headers(token)
    )
    assert resp.json()[0]["status"] == "cancelled"


@pytest.mark.asyncio
async def test_reminders_are_owner_scoped(client, session_factory):
    _, token_a = await make_user(session_factory, email="rem-a@example.com")
    _, token_b = await make_user(session_factory, email="rem-b@example.com")
    due = datetime.now(timezone.utc) + timedelta(days=1)

    created = (
        await client.post(
            "/api/reminders/",
            headers=auth_headers(token_a),
            json={"title": "A's reminder", "due_at": _iso(due)},
        )
    ).json()

    # B cannot see or cancel A's reminder, and gets 404 (not 403) so the
    # endpoint never confirms the row exists.
    assert (await client.get("/api/reminders/", headers=auth_headers(token_b))).json() == []
    resp = await client.delete(
        f"/api/reminders/{created['id']}", headers=auth_headers(token_b)
    )
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_create_rejects_absurd_due_date(client, session_factory):
    _, token = await make_user(session_factory, email="rem-far@example.com")
    resp = await client.post(
        "/api/reminders/",
        headers=auth_headers(token),
        json={"title": "heat death", "due_at": "9999-01-01T00:00:00+00:00"},
    )
    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_sweeper_delivers_due_reminders_once(session_factory):
    from models.reminder import Reminder, ReminderSource, ReminderStatus
    from services.notifications.reminders import ReminderService

    user, _ = await make_user(session_factory, email="rem-sweep@example.com")
    now = datetime.now(timezone.utc)
    async with session_factory() as session:
        session.add_all(
            [
                Reminder(
                    user_id=user.id,
                    title="due now",
                    due_at=now - timedelta(minutes=1),
                    source=ReminderSource.agent,
                ),
                Reminder(
                    user_id=user.id,
                    title="not yet",
                    due_at=now + timedelta(days=1),
                ),
            ]
        )
        await session.commit()

    sent: list[tuple[str, str]] = []

    async def send(user_id: str, text: str) -> None:
        sent.append((user_id, text))

    service = ReminderService(session_factory, send=send)
    assert await service.sweep_once() == 1
    assert sent[0][0] == str(user.id)
    assert "due now" in sent[0][1]

    # A second sweep must not re-deliver: the claim is the idempotency guard.
    assert await service.sweep_once() == 0
    assert len(sent) == 1

    async with session_factory() as session:
        rows = {
            r.title: r
            for r in (await session.execute(select(Reminder))).scalars().all()
        }
        assert rows["due now"].status == ReminderStatus.delivered
        assert rows["due now"].delivered_at is not None
        assert rows["not yet"].status == ReminderStatus.scheduled


@pytest.mark.asyncio
async def test_sweeper_claims_but_skips_long_stale_reminders(session_factory):
    """A reminder that came due while the server was off for days is
    retired silently rather than pinging the user about a stale date."""
    from models.reminder import Reminder, ReminderStatus
    from services.notifications.reminders import ReminderService

    user, _ = await make_user(session_factory, email="rem-stale@example.com")
    async with session_factory() as session:
        session.add(
            Reminder(
                user_id=user.id,
                title="ancient",
                due_at=datetime.now(timezone.utc) - timedelta(days=5),
            )
        )
        await session.commit()

    sent: list[tuple[str, str]] = []

    async def send(user_id: str, text: str) -> None:
        sent.append((user_id, text))

    service = ReminderService(session_factory, send=send)
    assert await service.sweep_once() == 0
    assert sent == []
    async with session_factory() as session:
        row = (await session.execute(select(Reminder))).scalar_one()
        assert row.status == ReminderStatus.delivered


@pytest.mark.asyncio
async def test_delivery_failure_does_not_resurrect_the_reminder(session_factory):
    from models.reminder import Reminder, ReminderStatus
    from services.notifications.reminders import ReminderService

    user, _ = await make_user(session_factory, email="rem-fail@example.com")
    async with session_factory() as session:
        session.add(
            Reminder(
                user_id=user.id,
                title="channel down",
                due_at=datetime.now(timezone.utc) - timedelta(minutes=1),
            )
        )
        await session.commit()

    async def send(user_id: str, text: str) -> None:
        raise RuntimeError("telegram unreachable")

    service = ReminderService(session_factory, send=send)
    assert await service.sweep_once() == 0
    async with session_factory() as session:
        row = (await session.execute(select(Reminder))).scalar_one()
        # Already claimed: a broken channel must not turn into a retry storm.
        assert row.status == ReminderStatus.delivered
