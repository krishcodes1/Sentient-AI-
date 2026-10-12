"""Tests for the database lock append_audit_log takes on the user's row
(services/audit.py): it is FOR NO KEY UPDATE, so a row the caller inserted
earlier in the same transaction (a goal, a milestone, a progress note, whose
foreign key to users holds FOR KEY SHARE until commit) never blocks another
writer's audit append, while two appenders for one user still run one after
the other.

Why it exists: append_audit_log waits for that row while it holds the
in-process per-user audit lock. With FOR UPDATE, a Goals page route that had
inserted a goal and then waited for the audit lock, while a chat turn's
audit row held that lock and waited for the route's FOR KEY SHARE, hung for
good: PostgreSQL cannot see the in-process half of that cycle. The lock
clause is checked on every run; the hang and the serialisation need a real
PostgreSQL and run only when TEST_DATABASE_URL points at one (the
backend-postgres CI job).
"""

from __future__ import annotations

import asyncio
import os

import pytest
from sqlalchemy import event, select
from sqlalchemy.dialects import postgresql

from models.audit import AuditLog, AuditStatus
from scripts.verify_audit_log import verify_rows
from services import audit
from services.audit import RuntimeAuditLogger, append_audit_log
from services.goals import store
from tests.conftest import make_user

TEST_DATABASE_URL = os.environ.get("TEST_DATABASE_URL", "")

_POSTGRES_ONLY = pytest.mark.skipif(
    "postgresql" not in TEST_DATABASE_URL,
    reason=(
        "row-lock conflicts exist only on Postgres; SQLite has no FOR UPDATE and "
        "serialises writers. Set TEST_DATABASE_URL to an asyncpg URL (the "
        "backend-postgres CI job does) to exercise this."
    ),
)

# Long enough for an unblocked append on a loaded CI runner; a blocked one
# never finishes, so the exact figure only bounds how long a failure takes.
_WAIT_SECONDS = 5


async def _append(session, user_id, action: str) -> AuditLog:
    return await append_audit_log(
        session,
        user_id=user_id,
        connector_name="goals",
        action=action,
        endpoint="/api/goals",
        scope_used="goals",
        status=AuditStatus.approved,
    )


async def _chain(session_factory, user_id) -> list[AuditLog]:
    async with session_factory() as session:
        return list(
            (
                await session.execute(
                    select(AuditLog).where(AuditLog.user_id == user_id).order_by(AuditLog.seq)
                )
            )
            .scalars()
            .all()
        )


@pytest.mark.asyncio
async def test_the_user_row_is_locked_for_no_key_update(session_factory):
    user, _ = await make_user(session_factory)
    seen = []
    async with session_factory() as session:
        event.listen(
            session.sync_session, "do_orm_execute", lambda state: seen.append(state.statement)
        )
        await _append(session, user.id, "goal_created")
        await session.commit()
    compiled = [
        " ".join(str(statement.compile(dialect=postgresql.dialect())).split()) for statement in seen
    ]
    [lock] = [sql for sql in compiled if "FROM users" in sql]
    assert lock.startswith("SELECT users.id FROM users WHERE users.id =")
    assert lock.endswith("FOR NO KEY UPDATE")


@_POSTGRES_ONLY
@pytest.mark.asyncio
async def test_an_open_goal_insert_never_blocks_another_audit_append(session_factory):
    user, _ = await make_user(session_factory)
    chat = RuntimeAuditLogger(session_factory)
    async with session_factory() as route:
        # The Goals page's create: the goal's INSERT holds FOR KEY SHARE on
        # the user's row until this transaction ends.
        await store.create_goal(route, user.id, {"title": "Run a 5k"}, source="user")
        # A chat turn's audit row for the same user takes the in-process
        # audit lock and then waits for the user's row.
        turn = asyncio.ensure_future(
            chat.log({"event": "tool_executing", "user_id": str(user.id), "tool": "memory.recall"})
        )
        try:
            done, _ = await asyncio.wait({turn}, timeout=_WAIT_SECONDS)
            assert turn in done, "an audit append waited on another transaction's goal insert"
            turn.result()
            # The route's own audit row then gets the lock at once.
            await asyncio.wait_for(_append(route, user.id, "goal_created"), _WAIT_SECONDS)
            await route.commit()
        finally:
            if not turn.done():
                await route.rollback()
                await asyncio.wait({turn}, timeout=_WAIT_SECONDS)
    rows = await _chain(session_factory, user.id)
    assert [(row.seq, row.action) for row in rows] == [(1, "recall"), (2, "goal_created")]
    report = verify_rows(rows)
    assert report.ok, report.failures


@_POSTGRES_ONLY
@pytest.mark.asyncio
async def test_the_row_lock_still_serialises_appenders(session_factory, monkeypatch):
    # Two workers share no in-process lock: give every call its own, so only
    # the database lock on the user's row keeps the chain linear.
    async def _own_lock(_user_id: str) -> asyncio.Lock:
        return asyncio.Lock()

    monkeypatch.setattr(audit, "_lock_for_user", _own_lock)
    user, _ = await make_user(session_factory)

    async def _second() -> None:
        async with session_factory() as session:
            await _append(session, user.id, "goal_updated")
            await session.commit()

    async with session_factory() as first:
        await _append(first, user.id, "goal_created")
        second = asyncio.ensure_future(_second())
        done, _ = await asyncio.wait({second}, timeout=1)
        assert not done, "a second appender ran while the first one's row was uncommitted"
        await first.commit()
    await asyncio.wait_for(second, _WAIT_SECONDS)
    rows = await _chain(session_factory, user.id)
    assert [(row.seq, row.action) for row in rows] == [(1, "goal_created"), (2, "goal_updated")]
    assert rows[1].previous_hash == rows[0].integrity_hash
    report = verify_rows(rows)
    assert report.ok, report.failures
