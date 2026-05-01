"""Tests for the tamper-evident audit log subsystem."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import delete, select

from core.security import compute_audit_hash
from models.audit import AuditLog, AuditStatus
from services.audit import AuditService, _compute_params_hash


# ----------------------------------------------------------------------
# Pure helpers
# ----------------------------------------------------------------------


def test_compute_audit_hash_deterministic() -> None:
    """The same payload must always produce the same SHA-256 digest."""
    payload = {
        "user_id": "user-1",
        "action": "list_courses",
        "endpoint": "/api/v1/courses",
        "status": "approved",
    }
    h1 = compute_audit_hash(payload)
    h2 = compute_audit_hash(payload)
    assert h1 == h2
    assert len(h1) == 64
    assert all(c in "0123456789abcdef" for c in h1)


def test_compute_audit_hash_changes_with_field() -> None:
    """Modifying any field must change the digest."""
    base = {"user_id": "u", "action": "a", "endpoint": "/e"}
    tampered = {"user_id": "u", "action": "tampered", "endpoint": "/e"}
    assert compute_audit_hash(base) != compute_audit_hash(tampered)


def test_compute_params_hash_redacts_secrets() -> None:
    """Secret-key values must be redacted before hashing."""
    secret_params = {
        "api_key": "sk-real-secret-aaaaaaaaaaaa",
        "endpoint": "/things",
    }
    redacted_equiv = {
        "api_key": "<REDACTED>",
        "endpoint": "/things",
    }

    # The hash of the raw secret must equal the hash of the same dict with
    # the secret value replaced by ``<REDACTED>`` — the helper must redact
    # before hashing.
    assert _compute_params_hash(secret_params) == _compute_params_hash(redacted_equiv)

    # And it must not equal the hash of an unrelated value for the same key
    # (sanity check that the redaction itself is what's collapsing the two).
    different_secret = {"api_key": "different", "endpoint": "/things"}
    assert _compute_params_hash(different_secret) == _compute_params_hash(secret_params)

    # Non-secret keys still affect the hash.
    other_endpoint = {"api_key": "anything", "endpoint": "/other"}
    assert _compute_params_hash(other_endpoint) != _compute_params_hash(secret_params)

    # All recognised secret keys are redacted.
    all_secrets = {
        "api_key": "x",
        "token": "x",
        "password": "x",
        "secret": "x",
        "authorization": "x",
    }
    all_redacted = {k: "<REDACTED>" for k in all_secrets}
    assert _compute_params_hash(all_secrets) == _compute_params_hash(all_redacted)


# ----------------------------------------------------------------------
# Chain construction
# ----------------------------------------------------------------------


@pytest.mark.asyncio
async def test_chain_integrity_genesis_log(db_session, test_user) -> None:
    """The first log in a user's chain has previous_hash=None and sequence=0."""
    service = AuditService(db_session)
    user_id = str(test_user["user"].id)

    log = await service.log_action(
        user_id=user_id,
        connector_name="canvas",
        action="list_courses",
        endpoint="/api/v1/courses",
        scope_used="courses:read",
        status=AuditStatus.APPROVED,
    )

    assert log.previous_hash is None
    assert log.sequence == 0
    assert log.integrity_hash and len(log.integrity_hash) == 64


@pytest.mark.asyncio
async def test_chain_integrity_subsequent_log(db_session, test_user) -> None:
    """The second log's previous_hash chains to the first; sequence increments."""
    service = AuditService(db_session)
    user_id = str(test_user["user"].id)

    log_a = await service.log_action(
        user_id=user_id,
        connector_name="canvas",
        action="list_courses",
        endpoint="/api/v1/courses",
        scope_used="courses:read",
        status=AuditStatus.APPROVED,
    )
    log_b = await service.log_action(
        user_id=user_id,
        connector_name="canvas",
        action="list_assignments",
        endpoint="/api/v1/assignments",
        scope_used="assignments:read",
        status=AuditStatus.APPROVED,
    )

    assert log_b.previous_hash == log_a.integrity_hash
    assert log_b.sequence == 1
    assert log_b.integrity_hash != log_a.integrity_hash


# ----------------------------------------------------------------------
# verify_integrity
# ----------------------------------------------------------------------


@pytest.mark.asyncio
async def test_verify_integrity_clean_chain(db_session, test_user) -> None:
    """A pristine chain of logs must verify ok."""
    service = AuditService(db_session)
    user_id = str(test_user["user"].id)

    for action in ("a", "b", "c"):
        await service.log_action(
            user_id=user_id,
            connector_name="canvas",
            action=action,
            endpoint=f"/api/v1/{action}",
            scope_used="courses:read",
            status=AuditStatus.APPROVED,
        )

    result = await service.verify_integrity(user_id)
    assert result == {
        "ok": True,
        "total": 3,
        "broken_at": None,
        "broken_field": None,
    }


@pytest.mark.asyncio
async def test_verify_integrity_detects_tampered_action(db_session, test_user) -> None:
    """Mutating ``action`` on a stored row must invalidate the integrity hash."""
    service = AuditService(db_session)
    user_id = str(test_user["user"].id)

    log = await service.log_action(
        user_id=user_id,
        connector_name="canvas",
        action="list_courses",
        endpoint="/api/v1/courses",
        scope_used="courses:read",
        status=AuditStatus.APPROVED,
    )

    log.action = "delete_everything"
    db_session.add(log)
    await db_session.flush()

    result = await service.verify_integrity(user_id)
    assert result["ok"] is False
    assert result["broken_field"] == "integrity_hash"
    assert result["broken_at"] == log.id


@pytest.mark.asyncio
async def test_verify_integrity_detects_tampered_timestamp(
    db_session, test_user
) -> None:
    """Mutating the timestamp must invalidate the integrity hash."""
    service = AuditService(db_session)
    user_id = str(test_user["user"].id)

    log = await service.log_action(
        user_id=user_id,
        connector_name="canvas",
        action="list_courses",
        endpoint="/api/v1/courses",
        scope_used="courses:read",
        status=AuditStatus.APPROVED,
    )

    log.timestamp = datetime(2099, 1, 1, tzinfo=timezone.utc)
    db_session.add(log)
    await db_session.flush()

    result = await service.verify_integrity(user_id)
    assert result["ok"] is False
    assert result["broken_field"] == "integrity_hash"


@pytest.mark.asyncio
async def test_verify_integrity_detects_deleted_log(db_session, test_user) -> None:
    """Deleting a middle log must produce a sequence gap."""
    service = AuditService(db_session)
    user_id = str(test_user["user"].id)

    a = await service.log_action(
        user_id=user_id,
        connector_name="canvas",
        action="a",
        endpoint="/a",
        scope_used="courses:read",
        status=AuditStatus.APPROVED,
    )
    b = await service.log_action(
        user_id=user_id,
        connector_name="canvas",
        action="b",
        endpoint="/b",
        scope_used="courses:read",
        status=AuditStatus.APPROVED,
    )
    c = await service.log_action(
        user_id=user_id,
        connector_name="canvas",
        action="c",
        endpoint="/c",
        scope_used="courses:read",
        status=AuditStatus.APPROVED,
    )

    # Sanity — the chain must verify before deletion.
    pre = await service.verify_integrity(user_id)
    assert pre["ok"] is True

    # Excise the middle row and commit so the verifier sees the gap.
    await db_session.execute(delete(AuditLog).where(AuditLog.id == b.id))
    await db_session.flush()

    result = await service.verify_integrity(user_id)
    assert result["ok"] is False
    # The first row at the wrong sequence is row C (sequence=2 instead of 1)
    # *or* row C tripping the previous_hash check first; either way the chain
    # fails and the broken_at points at C.
    assert result["broken_at"] == c.id
    assert result["broken_field"] in {"sequence", "previous_hash"}
    # And A is untouched in the surviving rows.
    surviving = (
        await db_session.execute(
            select(AuditLog.id).where(AuditLog.user_id == user_id)
        )
    ).scalars().all()
    assert a.id in surviving
    assert b.id not in surviving


@pytest.mark.asyncio
async def test_verify_integrity_detects_swapped_logs(db_session, test_user) -> None:
    """Swapping the sequence values of two logs breaks the chain hash."""
    service = AuditService(db_session)
    user_id = str(test_user["user"].id)

    a = await service.log_action(
        user_id=user_id,
        connector_name="canvas",
        action="a",
        endpoint="/a",
        scope_used="courses:read",
        status=AuditStatus.APPROVED,
    )
    b = await service.log_action(
        user_id=user_id,
        connector_name="canvas",
        action="b",
        endpoint="/b",
        scope_used="courses:read",
        status=AuditStatus.APPROVED,
    )

    # Swap their sequence values without recomputing hashes.
    a.sequence, b.sequence = b.sequence, a.sequence
    db_session.add_all([a, b])
    await db_session.flush()

    result = await service.verify_integrity(user_id)
    assert result["ok"] is False
    assert result["broken_field"] in {"previous_hash", "integrity_hash"}


# ----------------------------------------------------------------------
# get_stats — exercises the previously-broken ``AuditStatus.APPROVED`` path
# ----------------------------------------------------------------------


@pytest.mark.asyncio
async def test_get_stats_uses_correct_enum_values(db_session, test_user) -> None:
    """``get_stats`` must run without ``AttributeError`` and return counts."""
    service = AuditService(db_session)
    user_id = str(test_user["user"].id)

    await service.log_action(
        user_id=user_id,
        connector_name="canvas",
        action="approved-1",
        endpoint="/a",
        scope_used="courses:read",
        status=AuditStatus.APPROVED,
    )
    await service.log_action(
        user_id=user_id,
        connector_name="canvas",
        action="approved-2",
        endpoint="/b",
        scope_used="courses:read",
        status=AuditStatus.APPROVED,
    )
    await service.log_action(
        user_id=user_id,
        connector_name="canvas",
        action="blocked-1",
        endpoint="/c",
        scope_used="courses:read",
        status=AuditStatus.BLOCKED,
    )
    await service.log_action(
        user_id=user_id,
        connector_name="canvas",
        action="pending-1",
        endpoint="/d",
        scope_used="courses:read",
        status=AuditStatus.PENDING,
    )

    stats = await service.get_stats(user_id)
    assert stats["total"] == 4
    assert stats["approved"] == 2
    assert stats["blocked"] == 1
    assert stats["pending"] == 1
    assert stats["escalated"] == 0
    # All four logs are within the past 24h.
    assert stats["last_24h_count"] == 4


# ----------------------------------------------------------------------
# Internal helpers — sanity checks
# ----------------------------------------------------------------------


def test_compute_chain_hash_factors_in_previous_hash() -> None:
    """``_compute_chain_hash`` must change when the previous hash changes."""
    canonical = AuditService._canonical_fields_json(
        user_id="u",
        action="a",
        endpoint="/e",
        status="approved",
        timestamp_isoformat="2025-01-01T00:00:00+00:00",
        params_hash="0" * 64,
        reasoning=None,
        confidence_score=None,
    )
    h1 = AuditService._compute_chain_hash(canonical, None)
    h2 = AuditService._compute_chain_hash(canonical, "deadbeef" * 8)
    assert h1 != h2
