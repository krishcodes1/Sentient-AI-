"""Tests for the audit-log verifier.

Pure-Python tests that build AuditLog-like SimpleNamespace objects and
exercise the verifier helpers directly. No database is required.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from typing import Any, Optional

from core.security import compute_audit_hash
from scripts.verify_audit_log import (
    build_payload,
    verify_row,
    verify_rows,
)


def make_row(
    *,
    user_id: Optional[uuid.UUID] = None,
    connector_name: str = "canvas",
    action: str = "list_assignments",
    endpoint: str = "GET /api/v1/courses",
    scope_used: str = "courses.read",
    status: str = "approved",
    request_id: Optional[str] = None,
    request_data: Optional[dict[str, Any]] = None,
    response_summary: Optional[str] = None,
    timestamp: Optional[datetime] = None,
    previous_hash: Optional[str] = None,
) -> SimpleNamespace:
    """Build a row with a *valid* integrity_hash for the given fields,
    including the chain link to ``previous_hash``.
    """
    user_id = user_id or uuid.uuid4()
    request_id = request_id or str(uuid.uuid4())
    timestamp = timestamp or datetime.now(timezone.utc)
    payload = {
        "user_id": str(user_id),
        "connector_name": connector_name,
        "action": action,
        "endpoint": endpoint,
        "scope_used": scope_used,
        "status": status,
        "request_id": request_id,
        "request_data": request_data,
        "response_summary": response_summary,
        "previous_hash": previous_hash,
    }
    return SimpleNamespace(
        id=uuid.uuid4(),
        user_id=user_id,
        connector_name=connector_name,
        action=action,
        endpoint=endpoint,
        scope_used=scope_used,
        status=status,
        request_id=request_id,
        request_data=request_data,
        response_summary=response_summary,
        timestamp=timestamp,
        integrity_hash=compute_audit_hash(payload),
        previous_hash=previous_hash,
    )


def make_chain(user_id: uuid.UUID, length: int) -> list[SimpleNamespace]:
    """Build a valid chain of ``length`` rows for one user, each linked
    to the previous one's integrity_hash.
    """
    rows: list[SimpleNamespace] = []
    prev_hash: Optional[str] = None
    base = datetime.now(timezone.utc) - timedelta(minutes=length)
    for i in range(length):
        row = make_row(
            user_id=user_id,
            action=f"action_{i}",
            timestamp=base + timedelta(minutes=i),
            previous_hash=prev_hash,
        )
        rows.append(row)
        prev_hash = row.integrity_hash
    return rows


# ---------------------------------------------------------------------------
# build_payload contract
# ---------------------------------------------------------------------------


def test_build_payload_includes_previous_hash():
    user_id = uuid.uuid4()
    row = make_row(user_id=user_id, previous_hash="abc123")
    payload = build_payload(row)
    assert payload["previous_hash"] == "abc123"
    assert payload["user_id"] == str(user_id)
    assert payload["action"] == row.action


def test_build_payload_none_previous_hash_for_genesis():
    row = make_row(previous_hash=None)
    payload = build_payload(row)
    assert payload["previous_hash"] is None


# ---------------------------------------------------------------------------
# verify_row (per-row hash only)
# ---------------------------------------------------------------------------


def test_verify_row_passes_when_hash_matches():
    row = make_row()
    is_valid, expected = verify_row(row)
    assert is_valid
    assert expected == row.integrity_hash


def test_verify_row_fails_when_field_tampered():
    row = make_row()
    row.action = "execute_trade"
    is_valid, expected = verify_row(row)
    assert is_valid is False
    assert expected != row.integrity_hash


def test_verify_row_fails_when_status_tampered():
    row = make_row(status="blocked")
    row.status = "approved"
    is_valid, _ = verify_row(row)
    assert is_valid is False


def test_verify_row_fails_when_previous_hash_tampered():
    """previous_hash is bound into the per-row hash, so changing it
    after-the-fact must invalidate the row."""
    row = make_row(previous_hash="aaaa")
    row.previous_hash = "bbbb"
    is_valid, _ = verify_row(row)
    assert is_valid is False


# ---------------------------------------------------------------------------
# verify_rows (chain semantics)
# ---------------------------------------------------------------------------


def test_verify_rows_clean_chain():
    user = uuid.uuid4()
    rows = make_chain(user, length=5)
    report = verify_rows(rows)
    assert report.total == 5
    assert report.valid == 5
    assert report.invalid == 0
    assert report.failures == []
    assert report.ok is True


def test_verify_rows_detects_mid_chain_field_tampering():
    user = uuid.uuid4()
    rows = make_chain(user, length=10)
    # Tamper with the middle of the chain
    rows[4].scope_used = "crypto.trade"
    report = verify_rows(rows)
    assert report.ok is False
    assert report.invalid >= 1
    # The tampered row should appear in failures with kind row_hash
    row_hash_failures = [f for f in report.failures if f.kind == "row_hash"]
    assert any(f.id == str(rows[4].id) for f in row_hash_failures)


def test_verify_rows_detects_row_deletion_via_chain_break():
    """Deleting a row from the middle of the chain must be detected:
    the row after the deleted one will have a previous_hash that no
    longer matches the new predecessor's integrity_hash.
    """
    user = uuid.uuid4()
    rows = make_chain(user, length=6)
    # Simulate row 3 being deleted by dropping it from the list
    deleted = rows.pop(3)

    report = verify_rows(rows)

    assert report.ok is False
    chain_failures = [f for f in report.failures if f.kind == "chain_link"]
    # The row that originally followed the deleted one is now seeing a
    # mismatched previous_hash
    assert len(chain_failures) >= 1
    expected_failed_row = rows[3]  # was originally rows[4] before pop
    assert any(f.id == str(expected_failed_row.id) for f in chain_failures)
    assert deleted.id != expected_failed_row.id


def test_verify_rows_detects_reordering_via_chain_break():
    """Swapping two adjacent rows breaks the chain on both."""
    user = uuid.uuid4()
    rows = make_chain(user, length=5)
    rows[2], rows[3] = rows[3], rows[2]
    report = verify_rows(rows)
    assert report.ok is False
    chain_failures = [f for f in report.failures if f.kind == "chain_link"]
    assert len(chain_failures) >= 1


def test_verify_rows_per_user_chains_isolated():
    """A user with a clean chain should still verify even when another
    user's chain is broken.
    """
    user_a = uuid.uuid4()
    user_b = uuid.uuid4()
    chain_a = make_chain(user_a, length=3)
    chain_b = make_chain(user_b, length=3)
    chain_b[1].action = "tampered"  # break user B's chain

    # Interleave: A0, B0, A1, B1, A2, B2 (timestamps still in order)
    rows = sorted(chain_a + chain_b, key=lambda r: r.timestamp)

    report = verify_rows(rows)
    assert report.ok is False
    bad_ids = {f.id for f in report.failures}
    assert str(chain_b[1].id) in bad_ids
    # No A row should be reported as failed
    for r in chain_a:
        assert str(r.id) not in bad_ids


def test_verify_rows_fail_fast_stops_at_first_failure():
    user = uuid.uuid4()
    rows = make_chain(user, length=10)
    rows[2].action = "tampered_first"
    rows[7].action = "tampered_second"

    report = verify_rows(rows, fail_fast=True)
    # Should have stopped after processing index 2 (the first bad row)
    assert report.total == 3
    assert report.invalid == 1
    bad_ids = {f.id for f in report.failures}
    assert str(rows[2].id) in bad_ids
    assert str(rows[7].id) not in bad_ids


def test_verify_rows_legacy_rows_with_null_previous_hash():
    """Rows from before the chain was introduced have previous_hash=None
    on every row. The verifier should still per-row verify them and
    treat each as the first in its 'chain' (no chain check on the first
    row per user).
    """
    user = uuid.uuid4()
    # Two legacy rows, each hashed without a chain link
    rows = [
        make_row(user_id=user, action="legacy_0", previous_hash=None),
        make_row(user_id=user, action="legacy_1", previous_hash=None),
    ]
    rows[0].timestamp = datetime.now(timezone.utc) - timedelta(minutes=2)
    rows[1].timestamp = datetime.now(timezone.utc) - timedelta(minutes=1)

    report = verify_rows(rows)
    # row 1's previous_hash is None but the verifier expects rows[0].integrity_hash
    # So the chain check fails for row 1. This is intentional: once chains
    # exist, NULL previous_hash on a non-genesis row is a tampering signal.
    # The verifier reports it as a chain_link failure.
    assert report.ok is False
    chain_failures = [f for f in report.failures if f.kind == "chain_link"]
    assert any(f.id == str(rows[1].id) for f in chain_failures)


def test_verify_rows_handles_enum_status():
    class FakeStatus:
        value = "approved"

    payload = {
        "user_id": "00000000-0000-0000-0000-000000000001",
        "connector_name": "x",
        "action": "y",
        "endpoint": "z",
        "scope_used": "s",
        "status": "approved",
        "request_id": "rid",
        "request_data": None,
        "response_summary": None,
        "previous_hash": None,
    }
    row = SimpleNamespace(
        id=uuid.uuid4(),
        user_id=uuid.UUID("00000000-0000-0000-0000-000000000001"),
        connector_name="x",
        action="y",
        endpoint="z",
        scope_used="s",
        status=FakeStatus(),
        request_id="rid",
        request_data=None,
        response_summary=None,
        timestamp=datetime.now(timezone.utc),
        integrity_hash=compute_audit_hash(payload),
        previous_hash=None,
    )
    is_valid, _ = verify_row(row)
    assert is_valid is True
