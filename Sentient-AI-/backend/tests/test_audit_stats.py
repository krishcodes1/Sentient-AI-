"""GET /api/audit/stats — owner-scoped SQL aggregates for the dashboard.

The response shape is a frontend contract:
{total_actions_24h, blocked_24h, pending_approvals, approved_24h,
 by_day: [{date, approved, blocked, pending}] x 7}
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from tests.conftest import auth_headers, make_user


async def _seed_audit(session_factory, user_id, status, when=None):
    from services.audit import append_audit_log

    async with session_factory() as session:
        row = await append_audit_log(
            session,
            user_id=user_id,
            connector_name="canvas",
            action="get_courses",
            endpoint="agent.tool_executed",
            scope_used="courses.read",
            status=status,
        )
        if when is not None:
            row.timestamp = when
            await session.flush()
        await session.commit()


async def _seed_pending(session_factory, user_id, status, expires_delta):
    from models.pending_action import PendingAction

    async with session_factory() as session:
        session.add(
            PendingAction(
                user_id=user_id,
                tool_name="canvas.submit_assignment",
                arguments={},
                reason="test",
                status=status,
                expires_at=datetime.now(timezone.utc) + expires_delta,
            )
        )
        await session.flush()
        await session.commit()


@pytest.mark.asyncio
async def test_audit_stats_requires_auth(client):
    response = await client.get("/api/audit/stats")
    assert response.status_code in (401, 403)


@pytest.mark.asyncio
async def test_audit_stats_shape_and_counts(client, session_factory):
    from models.audit import AuditStatus
    from models.pending_action import PendingActionStatus

    user, token = await make_user(session_factory)
    other, _ = await make_user(session_factory, "other@example.com")
    now = datetime.now(timezone.utc)

    # Inside 24h: 2 approved + 1 blocked for the owner.
    await _seed_audit(session_factory, user.id, AuditStatus.approved)
    await _seed_audit(session_factory, user.id, AuditStatus.approved)
    await _seed_audit(session_factory, user.id, AuditStatus.blocked)
    # Another user's activity must never leak into the stats.
    await _seed_audit(session_factory, other.id, AuditStatus.approved)
    # 3 days ago: outside 24h, inside the 7-day window.
    await _seed_audit(
        session_factory, user.id, AuditStatus.blocked, when=now - timedelta(days=3)
    )
    # 10 days ago: outside the 7-day window entirely.
    await _seed_audit(
        session_factory, user.id, AuditStatus.approved, when=now - timedelta(days=10)
    )

    # Pending approvals: one live, one expired, one already decided.
    await _seed_pending(
        session_factory, user.id, PendingActionStatus.pending, timedelta(minutes=30)
    )
    await _seed_pending(
        session_factory, user.id, PendingActionStatus.pending, timedelta(minutes=-30)
    )
    await _seed_pending(
        session_factory, user.id, PendingActionStatus.approved, timedelta(minutes=30)
    )

    response = await client.get("/api/audit/stats", headers=auth_headers(token))
    assert response.status_code == 200
    body = response.json()

    # Exact contract shape.
    assert set(body) == {
        "total_actions_24h",
        "blocked_24h",
        "pending_approvals",
        "approved_24h",
        "by_day",
    }
    assert body["total_actions_24h"] == 3
    assert body["approved_24h"] == 2
    assert body["blocked_24h"] == 1
    assert body["pending_approvals"] == 1

    by_day = body["by_day"]
    assert len(by_day) == 7
    for day in by_day:
        assert set(day) == {"date", "approved", "blocked", "pending"}

    # Oldest first; today is the last entry.
    assert by_day[-1]["date"] == now.date().isoformat()
    assert by_day[-1]["approved"] == 2
    assert by_day[-1]["blocked"] == 1

    # The 3-days-ago blocked row lands in its bucket.
    three_days_ago = (now.date() - timedelta(days=3)).isoformat()
    bucket = next(d for d in by_day if d["date"] == three_days_ago)
    assert bucket["blocked"] == 1

    # The 10-day-old row is excluded from every bucket.
    assert sum(d["approved"] for d in by_day) == 2
    assert sum(d["blocked"] for d in by_day) == 2


@pytest.mark.asyncio
async def test_audit_stats_empty_for_fresh_user(client, session_factory):
    _, token = await make_user(session_factory)

    response = await client.get("/api/audit/stats", headers=auth_headers(token))
    assert response.status_code == 200
    body = response.json()
    assert body["total_actions_24h"] == 0
    assert body["blocked_24h"] == 0
    assert body["approved_24h"] == 0
    assert body["pending_approvals"] == 0
    assert len(body["by_day"]) == 7
    assert all(
        d["approved"] == 0 and d["blocked"] == 0 and d["pending"] == 0
        for d in body["by_day"]
    )
