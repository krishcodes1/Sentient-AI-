"""Tests for the audit-log verifier.

These tests are pure-Python: they build AuditLog-like SimpleNamespace
objects and run the verifier helpers directly. No database is required,
so the suite runs anywhere Python and the project deps are installed.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from types import SimpleNamespace
from typing import Any, Optional

import pytest

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
) -> SimpleNamespace:
    """Build a row with a *valid* integrity_hash for the given fields."""
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
    )


def test_build_payload_matches_route_contract():
    """build_payload must serialize exactly the same fields the API hashes."""
    user_id = uuid.uuid4()
    row = make_row(user_id=user_id, request_data={"a": 1}, response_summary="ok")
    payload = build_payload(row)

    assert payload == {
        "user_id": str(user_id),
        "connector_name": row.connector_name,
        "action": row.action,
        "endpoint": row.endpoint,
        "scope_used": row.scope_used,
        "status": row.status,
        "request_id": row.request_id,
        "request_data": {"a": 1},
        "response_summary": "ok",
    }


def test_verify_row_passes_when_hash_matches():
    row = make_row()
    is_valid, expected = verify_row(row)
    assert is_valid
    assert expected == row.integrity_hash


def test_verify_row_fails_when_field_tampered():
    row = make_row()
    # Tamper with a hashed field after the hash was computed
    row.action = "execute_trade"  # was: list_assignments
    is_valid, expected = verify_row(row)
    assert is_valid is False
    assert expected != row.integrity_hash


def test_verify_row_fails_when_status_tampered():
    row = make_row(status="blocked")
    row.status = "approved"  # flip blocked into approved without rehashing
    is_valid, _ = verify_row(row)
    assert is_valid is False


def test_verify_rows_clean_report():
    rows = [make_row(action=f"action_{i}") for i in range(5)]
    report = verify_rows(rows)
    assert report.total == 5
    assert report.valid == 5
    assert report.invalid == 0
    assert report.failures == []
    assert report.ok is True


def test_verify_rows_detects_tampering_in_the_middle():
    rows = [make_row(action=f"action_{i}") for i in range(10)]
    # Tamper with row index 4 (the 5th entry)
    target = rows[4]
    target.scope_used = "crypto.trade"  # was something safe
    report = verify_rows(rows)

    assert report.total == 10
    assert report.valid == 9
    assert report.invalid == 1
    assert report.ok is False
    assert len(report.failures) == 1
    failure = report.failures[0]
    assert failure.id == str(target.id)
    assert failure.action == target.action
    assert failure.stored_hash == target.integrity_hash
    assert failure.expected_hash != target.integrity_hash


def test_verify_rows_fail_fast_stops_at_first_failure():
    rows = [make_row(action=f"action_{i}") for i in range(10)]
    # Tamper with two rows
    rows[2].action = "tampered_first"
    rows[7].action = "tampered_second"

    report = verify_rows(rows, fail_fast=True)
    # Should have stopped after the first failure (row index 2)
    # so we processed rows 0, 1, 2 and stopped.
    assert report.total == 3
    assert report.valid == 2
    assert report.invalid == 1
    assert len(report.failures) == 1
    assert report.failures[0].id == str(rows[2].id)


def test_verify_rows_handles_enum_status():
    """Backend's status is an Enum on the live model; the verifier must
    handle both the enum object and the plain string."""
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
    )
    is_valid, _ = verify_row(row)
    assert is_valid is True
