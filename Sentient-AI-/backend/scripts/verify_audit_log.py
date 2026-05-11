"""Audit log integrity verifier.

Walks every row of the ``audit_logs`` table and runs two checks:

1. Per-row integrity: the row's ``integrity_hash`` matches a freshly
   computed hash over its stored fields (including ``previous_hash``).
2. Chain link: the row's ``previous_hash`` matches the ``integrity_hash``
   of the previous row in that user's chain.

Together these detect single-field tampering, row deletion, and chain
rotation.

Legacy rows with ``previous_hash = NULL`` predate the chain feature; the
verifier only does the per-row check on them, which is the same behavior
the verifier had before the chain landed.

Usage::

    python -m scripts.verify_audit_log
    python -m scripts.verify_audit_log --user-id <uuid>
    python -m scripts.verify_audit_log --json
    python -m scripts.verify_audit_log --fail-fast

Exits with code 0 if every row verifies, 1 if any row was tampered with,
2 if the verifier could not run (database error, etc.).
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime
from typing import Any, Iterable, Optional

from core.security import compute_audit_hash

# Heavy DB imports (sqlalchemy + engine creation) and the AuditLog model
# itself are deferred to ``run()`` so the pure verification helpers below
# can be imported without spinning up a database connection. Tests rely
# on this. The type annotations below use string forms (thanks to
# ``from __future__ import annotations``) and accept any object that
# exposes the expected attributes.


# ---------------------------------------------------------------------------
# Pure helpers (no I/O — these are what the unit tests exercise)
# ---------------------------------------------------------------------------


def build_payload(row: "AuditLog") -> dict[str, Any]:
    """Reconstruct the canonical payload used to compute ``row.integrity_hash``.

    Must stay in sync with the payload built in
    ``api/routes/audit.py::_build_hash_payload``. Includes
    ``previous_hash`` so the row's hash is bound to its position in the
    chain.
    """
    status_value = row.status.value if hasattr(row.status, "value") else row.status
    return {
        "user_id": str(row.user_id),
        "connector_name": row.connector_name,
        "action": row.action,
        "endpoint": row.endpoint,
        "scope_used": row.scope_used,
        "status": status_value,
        "request_id": row.request_id,
        "request_data": row.request_data,
        "response_summary": row.response_summary,
        "previous_hash": getattr(row, "previous_hash", None),
    }


def verify_row(row: "AuditLog") -> tuple[bool, str]:
    """Return ``(is_valid, expected_hash)`` for one audit row."""
    expected = compute_audit_hash(build_payload(row))
    return row.integrity_hash == expected, expected


@dataclass
class RowFailure:
    id: str
    timestamp: str
    connector_name: str
    action: str
    kind: str  # "row_hash" or "chain_link"
    stored_hash: str
    expected_hash: str
    # Only populated for chain_link failures
    stored_previous_hash: Optional[str] = None
    expected_previous_hash: Optional[str] = None


@dataclass
class VerifyReport:
    total: int
    valid: int
    invalid: int
    failures: list[RowFailure] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return self.invalid == 0


def _row_failure(row: "AuditLog", expected: str) -> RowFailure:
    return RowFailure(
        id=str(row.id),
        timestamp=row.timestamp.isoformat() if isinstance(row.timestamp, datetime) else str(row.timestamp),
        connector_name=row.connector_name,
        action=row.action,
        kind="row_hash",
        stored_hash=row.integrity_hash,
        expected_hash=expected,
    )


def _chain_failure(row: "AuditLog", expected_previous: Optional[str]) -> RowFailure:
    return RowFailure(
        id=str(row.id),
        timestamp=row.timestamp.isoformat() if isinstance(row.timestamp, datetime) else str(row.timestamp),
        connector_name=row.connector_name,
        action=row.action,
        kind="chain_link",
        stored_hash=row.integrity_hash,
        expected_hash=row.integrity_hash,
        stored_previous_hash=getattr(row, "previous_hash", None),
        expected_previous_hash=expected_previous,
    )


def verify_rows(rows: Iterable["AuditLog"], fail_fast: bool = False) -> VerifyReport:
    """Walk rows in arrival order, check per-row hash and chain links.

    Rows must be sorted by ``timestamp`` ascending (the CLI does this in
    the SQL query; tests pass already-sorted iterables).

    Chain checking is per-user. The first row seen for any user starts
    a fresh chain. A row can fail one check, the other, or both; it is
    still counted as one invalid row in the report.
    """
    failures: list[RowFailure] = []
    bad_row_ids: set[str] = set()
    processed = 0

    # Track the last integrity_hash we saw for each user's chain
    last_hash_for_user: dict[str, Optional[str]] = {}

    for row in rows:
        processed += 1
        user_key = str(row.user_id)
        row_id = str(row.id)
        is_valid, expected = verify_row(row)
        stored_prev = getattr(row, "previous_hash", None)

        chain_ok = True
        if user_key in last_hash_for_user:
            expected_prev = last_hash_for_user[user_key]
            if stored_prev != expected_prev:
                chain_ok = False
                failures.append(_chain_failure(row, expected_prev))
                bad_row_ids.add(row_id)
        # First row for a user: no chain check possible (we cannot
        # distinguish a true genesis from deletion of earlier rows).
        # The previous_hash field is still bound into the per-row hash,
        # so tampering with it trips the row_hash check.

        if not is_valid:
            failures.append(_row_failure(row, expected))
            bad_row_ids.add(row_id)

        last_hash_for_user[user_key] = row.integrity_hash

        if fail_fast and (not is_valid or not chain_ok):
            break

    invalid = len(bad_row_ids)
    valid = processed - invalid

    return VerifyReport(
        total=processed,
        valid=valid,
        invalid=invalid,
        failures=failures,
    )


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


async def run(
    user_id: Optional[uuid.UUID],
    fail_fast: bool,
) -> VerifyReport:
    """Fetch every audit row (or just one user's) and verify it.

    DB imports are deferred to this function so unit tests can import the
    pure helpers above without pulling in the SQLAlchemy engine.
    """
    from sqlalchemy import select
    from core.database import async_session
    from models.audit import AuditLog

    async with async_session() as db:
        query = select(AuditLog).order_by(AuditLog.timestamp.asc())
        if user_id is not None:
            query = query.where(AuditLog.user_id == user_id)
        result = await db.execute(query)
        rows = list(result.scalars().all())
    return verify_rows(rows, fail_fast=fail_fast)


def _format_human(report: VerifyReport) -> str:
    lines = []
    lines.append("Audit log verification")
    lines.append(f"  total rows checked: {report.total}")
    lines.append(f"  valid: {report.valid}")
    lines.append(f"  invalid: {report.invalid}")
    if report.invalid > 0:
        lines.append("")
        lines.append("TAMPER DETECTED:")
        for f in report.failures:
            if f.kind == "row_hash":
                lines.append(f"  - row {f.id} ({f.connector_name}/{f.action}) at {f.timestamp}: hash mismatch")
                lines.append(f"      stored:   {f.stored_hash}")
                lines.append(f"      expected: {f.expected_hash}")
            else:
                lines.append(f"  - row {f.id} ({f.connector_name}/{f.action}) at {f.timestamp}: chain link broken")
                lines.append(f"      stored previous_hash:   {f.stored_previous_hash}")
                lines.append(f"      expected previous_hash: {f.expected_previous_hash}")
    else:
        lines.append("")
        lines.append("OK. Every audit row hashes correctly and the chain is intact.")
    return "\n".join(lines)


def _format_json(report: VerifyReport) -> str:
    return json.dumps(
        {
            "ok": report.ok,
            "total": report.total,
            "valid": report.valid,
            "invalid": report.invalid,
            "failures": [asdict(f) for f in report.failures],
        },
        indent=2,
    )


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Verify the integrity of audit_log rows and the hash chain.",
    )
    parser.add_argument(
        "--user-id",
        type=str,
        default=None,
        help="Only verify rows for this user UUID.",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Emit JSON instead of human-readable text.",
    )
    parser.add_argument(
        "--fail-fast",
        action="store_true",
        help="Stop at the first row that fails to verify.",
    )
    args = parser.parse_args()

    user_id: Optional[uuid.UUID] = None
    if args.user_id:
        try:
            user_id = uuid.UUID(args.user_id)
        except ValueError:
            print(f"error: --user-id must be a valid UUID, got {args.user_id!r}", file=sys.stderr)
            return 2

    try:
        report = asyncio.run(run(user_id, args.fail_fast))
    except Exception as exc:
        print(f"error: verifier could not run: {exc}", file=sys.stderr)
        return 2

    output = _format_json(report) if args.json else _format_human(report)
    print(output)
    return 0 if report.ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
