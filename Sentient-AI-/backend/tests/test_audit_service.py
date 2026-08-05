"""Audit service tests: chained writes, sanitization, the runtime
adapter's event mapping, and chain integrity under concurrency.
"""

from __future__ import annotations

import asyncio

import pytest

from core.security import compute_audit_hash
from models.audit import AuditStatus
from services.audit import RuntimeAuditLogger, append_audit_log, build_hash_payload


@pytest.mark.asyncio
async def test_append_chains_rows_per_user(session_factory):
    from tests.conftest import make_user

    user, _ = await make_user(session_factory)

    async with session_factory() as session:
        first = await append_audit_log(
            session,
            user_id=user.id,
            connector_name="canvas",
            action="get_courses",
            endpoint="agent.tool_executed",
            scope_used="courses.read",
            status=AuditStatus.approved,
        )
        second = await append_audit_log(
            session,
            user_id=user.id,
            connector_name="canvas",
            action="get_grades",
            endpoint="agent.tool_executed",
            scope_used="grades.read",
            status=AuditStatus.approved,
        )
        await session.commit()

    assert first.previous_hash is None  # genesis
    assert second.previous_hash == first.integrity_hash

    # Stored hash matches the canonical recomputation (same formula the
    # /verify route and the CLI verifier use).
    payload = build_hash_payload(
        user_id=str(second.user_id),
        connector_name=second.connector_name,
        action=second.action,
        endpoint=second.endpoint,
        scope_used=second.scope_used,
        status_value=second.status.value,
        request_id=second.request_id,
        request_data=second.request_data,
        response_summary=second.response_summary,
        previous_hash=second.previous_hash,
    )
    assert compute_audit_hash(payload) == second.integrity_hash


@pytest.mark.asyncio
async def test_append_sanitizes_sensitive_request_data(session_factory):
    from tests.conftest import make_user

    user, _ = await make_user(session_factory)

    async with session_factory() as session:
        row = await append_audit_log(
            session,
            user_id=user.id,
            connector_name="gmail",
            action="send_email",
            endpoint="agent.tool_pending_approval",
            scope_used="gmail.send",
            status=AuditStatus.pending,
            request_data={"to": "x@y.com", "api_key": "sk-supersecret12345678901234"},
        )
        await session.commit()

    assert row.request_data["to"] == "x@y.com"
    assert row.request_data["api_key"] == "***REDACTED***"
    assert "supersecret" not in str(row.request_data)


@pytest.mark.asyncio
async def test_runtime_logger_maps_events(session_factory):
    from sqlalchemy import select

    from models.audit import AuditLog
    from tests.conftest import make_user

    user, _ = await make_user(session_factory)
    audit_logger = RuntimeAuditLogger(session_factory=session_factory)

    await audit_logger.log(
        {
            "event": "tool_executed",
            "user_id": str(user.id),
            "tool": "canvas.get_courses",
            "arguments": {"per_page": 10},
            "result_summary": "3 courses",
        }
    )
    await audit_logger.log(
        {
            "event": "tool_blocked",
            "user_id": str(user.id),
            "tool": "robinhood.execute_trade",
            "reason": "hard blocked",
            "policy": "robinhood:financial",
        }
    )

    async with session_factory() as session:
        result = await session.execute(
            select(AuditLog).where(AuditLog.user_id == user.id).order_by(AuditLog.timestamp)
        )
        rows = list(result.scalars().all())

    assert len(rows) == 2
    executed, blocked = rows
    assert executed.connector_name == "canvas"
    assert executed.action == "get_courses"
    assert executed.status == AuditStatus.approved
    assert blocked.connector_name == "robinhood"
    assert blocked.status == AuditStatus.blocked
    assert blocked.reasoning_chain["policy"] == "robinhood:financial"
    # Adapter rows chain like any other write.
    assert blocked.previous_hash == executed.integrity_hash


@pytest.mark.asyncio
async def test_concurrent_appends_keep_chain_intact(session_factory):
    """Five concurrent writers for the same user must produce one linear
    chain (no forks), which is exactly what the verifier checks."""
    from sqlalchemy import select

    from models.audit import AuditLog
    from scripts.verify_audit_log import verify_rows
    from tests.conftest import make_user

    user, _ = await make_user(session_factory)
    audit_logger = RuntimeAuditLogger(session_factory=session_factory)

    await asyncio.gather(
        *[
            audit_logger.log(
                {
                    "event": "tool_executed",
                    "user_id": str(user.id),
                    "tool": f"canvas.action_{i}",
                }
            )
            for i in range(5)
        ]
    )

    async with session_factory() as session:
        result = await session.execute(
            select(AuditLog)
            .where(AuditLog.user_id == user.id)
            .order_by(AuditLog.timestamp.asc())
        )
        rows = list(result.scalars().all())

    assert len(rows) == 5
    report = verify_rows(rows)
    assert report.ok, report.failures


@pytest.mark.asyncio
async def test_concurrent_appends_assign_unique_sequence_numbers(session_factory):
    """No two rows in a user's chain may share a seq.

    The in-process asyncio lock cannot provide this on its own: it is
    released when append_audit_log returns, but the row it wrote stays
    invisible to other sessions until the caller commits. Two sessions
    therefore read the same head and compute the same next seq — a fork
    that makes the verifier report tampering where there was only
    concurrency. The database row lock is what actually serializes it.

    Sixty writers rather than five: the race is a timing window, and the
    existing five-writer test only caught it about one run in ten — the
    difference between a regression net and a coin flip. At sixty it was
    measured catching the unfixed code 8 times out of 8, and still runs in
    well under a second. SQLite cannot exhibit this at all (it serializes
    writers), so this really exercises Postgres; it stays valid on both.
    """
    from sqlalchemy import select

    from models.audit import AuditLog
    from scripts.verify_audit_log import verify_rows
    from tests.conftest import make_user

    user, _ = await make_user(session_factory)
    audit_logger = RuntimeAuditLogger(session_factory=session_factory)

    writers = 60
    await asyncio.gather(
        *[
            audit_logger.log(
                {
                    "event": "tool_executed",
                    "user_id": str(user.id),
                    "tool": f"canvas.action_{i}",
                }
            )
            for i in range(writers)
        ]
    )

    async with session_factory() as session:
        rows = list(
            (
                await session.execute(
                    select(AuditLog)
                    .where(AuditLog.user_id == user.id)
                    .order_by(AuditLog.seq.asc())
                )
            )
            .scalars()
            .all()
        )

    assert len(rows) == writers
    seqs = [r.seq for r in rows]
    assert seqs == list(range(1, writers + 1)), (
        f"sequence numbers are not a gapless 1..{writers} run: {seqs}"
    )
    assert len(set(seqs)) == writers, f"duplicate seq assigned: {seqs}"

    # And the chain the verifier walks must still be linear.
    report = verify_rows(rows)
    assert report.ok, report.failures
