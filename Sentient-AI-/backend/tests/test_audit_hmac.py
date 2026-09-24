"""Tests for the HMAC audit-hash upgrade: a forged row that recomputes the old
unkeyed hash is rejected, HMAC rows verify cleanly, legacy unkeyed rows still
verify and are labeled legacy, and `seq` reordering or duplication is detected.

Why it exists: Guards the fix for a forgeable ~20-line unkeyed SHA-256 chain
and the migration path that must keep pre-upgrade audit rows verifiable instead
of tripping a false tamper alarm.

HMAC audit-hash upgrade tests.

Covers the properties the keyed upgrade must provide:

- a forged row whose author recomputed the historical *unkeyed* SHA-256
  is REJECTED (the ~20-line forgery the upgrade exists to close);
- rows written by ``append_audit_log`` (HMAC) verify cleanly;
- pre-upgrade rows (unkeyed hash, ``seq`` NULL) still verify and are
  labeled ``legacy`` instead of tripping a tamper alarm;
- ``seq`` is monotonic per user and independent across users;
- reordering two same-timestamp rows (the ambiguity ``seq`` removes) is
  detected, whether the attacker swaps seq values or duplicates them.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from types import SimpleNamespace
from typing import Any, Optional

import pytest

from core.security import compute_audit_hash, compute_audit_hash_legacy
from models.audit import AuditStatus
from scripts.verify_audit_log import classify_row, verify_row, verify_rows
from services.audit import append_audit_log


# ---------------------------------------------------------------------------
# Pure-python row helpers (mirror scripts.verify_audit_log.build_payload)
# ---------------------------------------------------------------------------


def make_row(
    *,
    user_id: Optional[uuid.UUID] = None,
    action: str = "list_assignments",
    previous_hash: Optional[str] = None,
    seq: Optional[int] = None,
    scheme: str = "hmac",
    timestamp: Optional[datetime] = None,
    request_data: Optional[dict[str, Any]] = None,
) -> SimpleNamespace:
    """Build a row hashed with either the keyed ("hmac") or historical
    unkeyed ("legacy") digest, so tests can construct both eras of rows.
    """
    user_id = user_id or uuid.uuid4()
    request_id = str(uuid.uuid4())
    payload = {
        "user_id": str(user_id),
        "connector_name": "canvas",
        "action": action,
        "endpoint": "GET /api/v1/courses",
        "scope_used": "courses.read",
        "status": "approved",
        "request_id": request_id,
        "request_data": request_data,
        "response_summary": None,
        "reasoning_chain": None,
        "detection_method": None,
        "confidence_score": None,
        "previous_hash": previous_hash,
    }
    hasher = compute_audit_hash if scheme == "hmac" else compute_audit_hash_legacy
    return SimpleNamespace(
        id=uuid.uuid4(),
        user_id=user_id,
        connector_name="canvas",
        action=action,
        endpoint="GET /api/v1/courses",
        scope_used="courses.read",
        status="approved",
        request_id=request_id,
        request_data=request_data,
        response_summary=None,
        reasoning_chain=None,
        detection_method=None,
        confidence_score=None,
        timestamp=timestamp or datetime.now(timezone.utc),
        integrity_hash=hasher(payload),
        previous_hash=previous_hash,
        seq=seq,
    )


def make_hmac_chain(user_id: uuid.UUID, length: int) -> list[SimpleNamespace]:
    rows: list[SimpleNamespace] = []
    prev: Optional[str] = None
    for i in range(length):
        row = make_row(user_id=user_id, action=f"action_{i}", previous_hash=prev, seq=i + 1)
        rows.append(row)
        prev = row.integrity_hash
    return rows


# ---------------------------------------------------------------------------
# The forgery the upgrade closes
# ---------------------------------------------------------------------------


def test_forged_row_with_recomputed_unkeyed_hash_is_rejected():
    """A database-write adversary rewrites a row and recomputes the old
    unkeyed SHA-256 (the pre-upgrade forgery). Under HMAC verification the
    row must be invalid, not silently accepted."""
    user = uuid.uuid4()
    rows = make_hmac_chain(user, length=3)

    # Forge the middle row: change the action and recompute the unkeyed
    # digest over the (otherwise consistent) payload — exactly what an
    # attacker without the HMAC key can do.
    victim = rows[1]
    victim.action = "execute_trade"
    forged_payload = {
        "user_id": str(victim.user_id),
        "connector_name": victim.connector_name,
        "action": victim.action,
        "endpoint": victim.endpoint,
        "scope_used": victim.scope_used,
        "status": victim.status,
        "request_id": victim.request_id,
        "request_data": victim.request_data,
        "response_summary": victim.response_summary,
        "reasoning_chain": victim.reasoning_chain,
        "detection_method": victim.detection_method,
        "confidence_score": victim.confidence_score,
        "previous_hash": victim.previous_hash,
    }
    victim.integrity_hash = compute_audit_hash_legacy(forged_payload)

    valid, _expected, scheme = classify_row(victim)
    assert valid is False
    assert scheme == "invalid"

    report = verify_rows(rows)
    assert report.ok is False
    assert any(f.id == str(victim.id) for f in report.failures)


def test_forged_full_unkeyed_chain_is_rejected():
    """Recomputing the ENTIRE chain unkeyed (the 20-line forgery script)
    must invalidate every post-upgrade row, not launder the rewrite."""
    user = uuid.uuid4()
    rows = make_hmac_chain(user, length=4)

    # Rebuild the whole chain with unkeyed hashes, seq kept intact.
    prev: Optional[str] = None
    for row in rows:
        row.previous_hash = prev
        payload = {
            "user_id": str(row.user_id),
            "connector_name": row.connector_name,
            "action": row.action,
            "endpoint": row.endpoint,
            "scope_used": row.scope_used,
            "status": row.status,
            "request_id": row.request_id,
            "request_data": row.request_data,
            "response_summary": row.response_summary,
            "reasoning_chain": row.reasoning_chain,
            "detection_method": row.detection_method,
            "confidence_score": row.confidence_score,
            "previous_hash": row.previous_hash,
        }
        row.integrity_hash = compute_audit_hash_legacy(payload)
        prev = row.integrity_hash

    report = verify_rows(rows)
    assert report.ok is False
    # Every seq-bearing row is rejected: the legacy fallback only applies
    # to rows that predate the seq column.
    assert report.invalid == 4
    assert report.legacy == 0


# ---------------------------------------------------------------------------
# HMAC rows verify; legacy rows verify and are labeled
# ---------------------------------------------------------------------------


def test_hmac_rows_verify_pure():
    user = uuid.uuid4()
    rows = make_hmac_chain(user, length=5)
    report = verify_rows(rows)
    assert report.ok is True
    assert report.valid == 5
    assert report.legacy == 0
    for row in rows:
        assert classify_row(row)[2] == "hmac"


@pytest.mark.asyncio
async def test_append_writes_hmac_rows_that_verify(session_factory):
    """Rows written through the real append path verify under the keyed
    scheme and are not counted as legacy."""
    from sqlalchemy import select

    from models.audit import AuditLog
    from tests.conftest import make_user

    user, _ = await make_user(session_factory)

    async with session_factory() as session:
        for i in range(3):
            await append_audit_log(
                session,
                user_id=user.id,
                connector_name="canvas",
                action=f"action_{i}",
                endpoint="agent.tool_executed",
                scope_used="courses.read",
                status=AuditStatus.approved,
            )
        await session.commit()

    async with session_factory() as session:
        result = await session.execute(
            select(AuditLog)
            .where(AuditLog.user_id == user.id)
            .order_by(AuditLog.seq.asc().nullsfirst(), AuditLog.timestamp.asc())
        )
        rows = list(result.scalars().all())

    report = verify_rows(rows)
    assert report.ok is True
    assert report.legacy == 0
    assert [classify_row(r)[2] for r in rows] == ["hmac", "hmac", "hmac"]


def test_legacy_unkeyed_rows_still_verify_and_are_labeled():
    """Rows written before the upgrade (unkeyed hash, seq NULL) must not
    be reported as tampered — they are valid, labeled legacy."""
    user = uuid.uuid4()
    first = make_row(user_id=user, action="legacy_0", scheme="legacy", seq=None)
    second = make_row(
        user_id=user,
        action="legacy_1",
        scheme="legacy",
        seq=None,
        previous_hash=first.integrity_hash,
    )

    valid, _expected, scheme = classify_row(first)
    assert valid is True
    assert scheme == "legacy"
    assert verify_row(second)[0] is True

    report = verify_rows([first, second])
    assert report.ok is True
    assert report.legacy == 2
    assert report.valid == 2


def test_mixed_legacy_then_hmac_chain_verifies_across_boundary():
    """An existing deployment upgrades mid-chain: legacy rows first, then
    HMAC rows whose first link pins the last legacy hash."""
    user = uuid.uuid4()
    legacy = make_row(user_id=user, action="legacy_0", scheme="legacy", seq=None)
    upgraded = make_row(
        user_id=user,
        action="post_upgrade",
        scheme="hmac",
        seq=1,
        previous_hash=legacy.integrity_hash,
    )
    report = verify_rows([legacy, upgraded])
    assert report.ok is True
    assert report.legacy == 1
    # Tampering the legacy row is still caught by the (unkeyed) recompute.
    legacy.action = "tampered"
    report = verify_rows([legacy, upgraded])
    assert report.ok is False


# ---------------------------------------------------------------------------
# seq: monotonic per user, independent across users, deterministic order
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_seq_monotonic_per_user_and_independent_across_users(session_factory):
    from sqlalchemy import select

    from models.audit import AuditLog
    from tests.conftest import make_user

    user_a, _ = await make_user(session_factory, email="a@example.com")
    user_b, _ = await make_user(session_factory, email="b@example.com")

    async with session_factory() as session:
        for i in range(3):
            await append_audit_log(
                session,
                user_id=user_a.id,
                connector_name="canvas",
                action=f"a_{i}",
                endpoint="agent.tool_executed",
                scope_used="courses.read",
                status=AuditStatus.approved,
            )
        for i in range(2):
            await append_audit_log(
                session,
                user_id=user_b.id,
                connector_name="gmail",
                action=f"b_{i}",
                endpoint="agent.tool_executed",
                scope_used="gmail.read",
                status=AuditStatus.approved,
            )
        await session.commit()

    async with session_factory() as session:
        result = await session.execute(
            select(AuditLog.user_id, AuditLog.seq).order_by(AuditLog.seq.asc())
        )
        pairs = result.all()

    seqs_a = sorted(seq for uid, seq in pairs if uid == user_a.id)
    seqs_b = sorted(seq for uid, seq in pairs if uid == user_b.id)
    # Each user's chain numbers from 1 with no gaps; user B is not shifted
    # by user A's writes.
    assert seqs_a == [1, 2, 3]
    assert seqs_b == [1, 2]


@pytest.mark.asyncio
async def test_reordering_same_timestamp_rows_is_detected(session_factory):
    """Two rows written in the same millisecond used to sort ambiguously.
    With seq as the order key, an attacker's only reordering move is to
    rewrite seq values — swapping them breaks a chain link."""
    from sqlalchemy import select

    from models.audit import AuditLog
    from tests.conftest import make_user

    user, _ = await make_user(session_factory)

    async with session_factory() as session:
        first = await append_audit_log(
            session,
            user_id=user.id,
            connector_name="canvas",
            action="first",
            endpoint="agent.tool_executed",
            scope_used="courses.read",
            status=AuditStatus.approved,
        )
        second = await append_audit_log(
            session,
            user_id=user.id,
            connector_name="canvas",
            action="second",
            endpoint="agent.tool_executed",
            scope_used="courses.read",
            status=AuditStatus.approved,
        )
        await session.commit()
        first_id, second_id = first.id, second.id

    # Attacker with raw DB write access: force identical timestamps and
    # swap the seq values (seq is not hash-covered, so per-row hashes
    # remain valid — the chain must still catch the reorder).
    collision = datetime.now(timezone.utc)
    async with session_factory() as session:
        rows = {
            row.id: row
            for row in (
                await session.execute(
                    select(AuditLog).where(AuditLog.user_id == user.id)
                )
            ).scalars()
        }
        rows[first_id].timestamp = collision
        rows[second_id].timestamp = collision
        rows[first_id].seq, rows[second_id].seq = (
            rows[second_id].seq,
            rows[first_id].seq,
        )
        await session.commit()

    async with session_factory() as session:
        result = await session.execute(
            select(AuditLog)
            .where(AuditLog.user_id == user.id)
            .order_by(AuditLog.seq.asc().nullsfirst(), AuditLog.timestamp.asc())
        )
        reordered = list(result.scalars().all())

    assert [r.id for r in reordered] == [second_id, first_id]
    report = verify_rows(reordered)
    assert report.ok is False
    assert any(f.kind == "chain_link" for f in report.failures)


def test_duplicate_seq_is_flagged():
    """Duplicating a seq recreates the exact ordering ambiguity seq exists
    to remove, so it is flagged even when chain links happen to match."""
    user = uuid.uuid4()
    rows = make_hmac_chain(user, length=3)
    rows[2].seq = rows[1].seq  # attacker duplicates; hashes untouched
    report = verify_rows(rows)
    assert report.ok is False
    assert any(f.kind == "seq_order" and f.id == str(rows[2].id) for f in report.failures)


# ---------------------------------------------------------------------------
# The residual hole in grandfathering, and the flag that closes it
# ---------------------------------------------------------------------------


def _relegacy(row, previous_hash):
    """Rewrite one row the way a database-write adversary would: clear seq
    and stamp the historical unkeyed digest, so it is grandfathered in."""
    from scripts.verify_audit_log import build_payload

    row.previous_hash = previous_hash
    row.seq = None
    row.integrity_hash = compute_audit_hash_legacy(build_payload(row))
    return row.integrity_hash


def test_whole_chain_rewritten_as_unkeyed_passes_default_but_fails_require_hmac():
    """The limit of grandfathering: nothing in the database records that the
    deployment upgraded, so an attacker who rewrites EVERY row as unkeyed
    with seq cleared verifies clean in permissive mode. --require-hmac is
    what turns that laundering attack into a non-zero exit.
    """
    user = uuid.uuid4()
    rows = make_hmac_chain(user, length=5)
    rows[2].action = "wire_transfer"  # the lie the attacker is inserting
    prev: Optional[str] = None
    for row in rows:
        prev = _relegacy(row, prev)

    permissive = verify_rows(rows)
    assert permissive.ok is True  # documents the hole, deliberately
    assert permissive.legacy == 5

    strict = verify_rows(rows, require_hmac=True)
    assert strict.ok is False
    assert strict.invalid == 5
    assert {f.kind for f in strict.failures} == {"unkeyed_hash"}


def test_require_hmac_accepts_a_fully_keyed_chain():
    """The strict gate must not cry wolf on a chain that is entirely keyed."""
    user = uuid.uuid4()
    rows = make_hmac_chain(user, length=4)
    report = verify_rows(rows, require_hmac=True)
    assert report.ok is True
    assert report.legacy == 0
    assert report.failures == []


def test_require_hmac_reports_unkeyed_rows_distinctly_from_tampering():
    """A genuine legacy row and a tampered row must not be conflated: the
    former is 'unkeyed_hash' (no protection), the latter 'row_hash'."""
    user = uuid.uuid4()
    legacy = make_row(user_id=user, action="legacy_0", scheme="legacy", seq=None)
    tampered = make_row(user_id=user, action="post", scheme="hmac", seq=1,
                        previous_hash=legacy.integrity_hash)
    tampered.action = "mutated_without_rehash"

    report = verify_rows([legacy, tampered], require_hmac=True)
    kinds = {f.id: f.kind for f in report.failures}
    assert kinds[str(legacy.id)] == "unkeyed_hash"
    assert kinds[str(tampered.id)] == "row_hash"


def test_single_forged_row_with_cleared_seq_still_breaks_the_chain():
    """Clearing seq on ONE row to get it grandfathered does not work: the
    row sorts into the legacy prefix and its neighbours' chain links break."""
    user = uuid.uuid4()
    rows = make_hmac_chain(user, length=4)
    victim = rows[1]
    victim.action = "wire_transfer"
    _relegacy(victim, victim.previous_hash)

    # Re-sort the way the verifier's SQL does: NULL seq first.
    ordered = sorted(rows, key=lambda r: (r.seq is not None, r.seq or 0))
    report = verify_rows(ordered)
    assert report.ok is False
    assert any(f.kind == "chain_link" for f in report.failures)


# ---------------------------------------------------------------------------
# Key handling
# ---------------------------------------------------------------------------


def test_hmac_differs_from_legacy_and_dedicated_key_changes_hash(monkeypatch):
    payload = {"user_id": "u", "action": "a", "previous_hash": None}
    derived = compute_audit_hash(payload)
    assert derived != compute_audit_hash_legacy(payload)

    from core.config import settings

    monkeypatch.setattr(settings, "AUDIT_HMAC_KEY", "dedicated-test-key")
    dedicated = compute_audit_hash(payload)
    assert dedicated != derived
    # Deterministic under a fixed key.
    assert compute_audit_hash(payload) == dedicated


# ---------------------------------------------------------------------------
# GET /audit/{id}/verify must not false-alarm on pre-upgrade rows
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_verify_endpoint_accepts_legacy_unkeyed_row(client, session_factory):
    """A row written before the keyed-hash upgrade carries an unkeyed
    SHA-256. The endpoint must distinguish it from both a keyed-verified
    row and a tampered one: it reports ``legacy`` (intact as far as an
    unkeyed digest can show) without claiming ``valid``, which only the
    keyed HMAC earns."""
    from core.security import compute_audit_hash_legacy
    from models.audit import AuditLog, AuditStatus
    from services.audit import build_hash_payload
    from tests.conftest import auth_headers, make_user

    user, token = await make_user(session_factory, "legacyverify@example.com")

    payload = build_hash_payload(
        user_id=str(user.id),
        connector_name="canvas",
        action="get_courses",
        endpoint="/api/v1/courses",
        scope_used="courses.read",
        status_value="approved",
        request_id="req-legacy-1",
        request_data=None,
        response_summary="3 courses",
        previous_hash=None,
    )
    async with session_factory() as session:
        row = AuditLog(
            user_id=user.id,
            connector_name="canvas",
            action="get_courses",
            endpoint="/api/v1/courses",
            scope_used="courses.read",
            status=AuditStatus.approved,
            request_id="req-legacy-1",
            request_data=None,
            response_summary="3 courses",
            previous_hash=None,
            # Pre-upgrade rows: unkeyed digest, no seq.
            integrity_hash=compute_audit_hash_legacy(payload),
        )
        session.add(row)
        await session.commit()
        row_id = str(row.id)

    resp = await client.get(f"/api/audit/{row_id}/verify", headers=auth_headers(token))
    assert resp.status_code == 200
    body = resp.json()
    assert body["legacy"] is True, "legacy row was reported as tampered"
    assert body["valid"] is False, "an unkeyed digest must not count as verified"


@pytest.mark.asyncio
async def test_verify_endpoint_rejects_a_forged_row_with_a_recomputed_unkeyed_hash(
    client, session_factory
):
    """The downgrade that mattered: an adversary with database write access
    invents a row, computes its UNKEYED digest (no key needed), and the
    endpoint blesses it as verified history. The unkeyed path is gated on
    ``seq IS NULL`` and never sets ``valid``, so neither shape passes."""
    from core.security import compute_audit_hash_legacy
    from models.audit import AuditLog, AuditStatus
    from services.audit import build_hash_payload
    from tests.conftest import auth_headers, make_user

    user, token = await make_user(session_factory, "forger@example.com")

    def _forged(seq, request_id):
        payload = build_hash_payload(
            user_id=str(user.id),
            connector_name="canvas",
            action="wire_transfer",
            endpoint="/api/v1/transfer",
            scope_used="courses.read",
            status_value="approved",
            request_id=request_id,
            request_data=None,
            response_summary="approved by owner",
            previous_hash=None,
        )
        return AuditLog(
            user_id=user.id,
            connector_name="canvas",
            action="wire_transfer",
            endpoint="/api/v1/transfer",
            scope_used="courses.read",
            status=AuditStatus.approved,
            request_id=request_id,
            request_data=None,
            response_summary="approved by owner",
            previous_hash=None,
            seq=seq,
            integrity_hash=compute_audit_hash_legacy(payload),
        )

    # Two shapes: one that looks post-upgrade (has a seq) and one that
    # clears seq to reach the legacy fallback.
    async with session_factory() as session:
        numbered = _forged(1, "req-forged-seq")
        cleared = _forged(None, "req-forged-noseq")
        session.add_all([numbered, cleared])
        await session.commit()
        numbered_id, cleared_id = str(numbered.id), str(cleared.id)

    numbered_body = (
        await client.get(
            f"/api/audit/{numbered_id}/verify", headers=auth_headers(token)
        )
    ).json()
    assert numbered_body == {"id": numbered_id, "valid": False, "legacy": False}

    cleared_body = (
        await client.get(f"/api/audit/{cleared_id}/verify", headers=auth_headers(token))
    ).json()
    # Reachable, but only as "cannot be verified by key" — never as valid.
    assert cleared_body["valid"] is False
    assert cleared_body["legacy"] is True


@pytest.mark.asyncio
async def test_verify_endpoint_still_detects_tampering(client, session_factory):
    """The legacy fallback must not become a way to pass verification with
    an arbitrary hash."""
    from models.audit import AuditLog, AuditStatus
    from tests.conftest import auth_headers, make_user

    user, token = await make_user(session_factory, "tamperverify@example.com")
    async with session_factory() as session:
        row = AuditLog(
            user_id=user.id,
            connector_name="canvas",
            action="get_courses",
            endpoint="/api/v1/courses",
            scope_used="courses.read",
            status=AuditStatus.approved,
            request_id="req-tamper-1",
            request_data=None,
            response_summary="3 courses",
            previous_hash=None,
            integrity_hash="deadbeef" * 8,
        )
        session.add(row)
        await session.commit()
        row_id = str(row.id)

    body = (
        await client.get(f"/api/audit/{row_id}/verify", headers=auth_headers(token))
    ).json()
    assert body["valid"] is False
    assert body["legacy"] is False
