"""Audit log integrity verifier.

Walks every row of the ``audit_logs`` table, recomputes its SHA-256
integrity hash from the same canonical payload the API uses when the row
is created, and reports any row whose stored hash no longer matches.

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
from dataclasses import asdict, dataclass
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


def build_payload(row: AuditLog) -> dict[str, Any]:
    """Reconstruct the canonical payload used to compute ``row.integrity_hash``.

    Must stay in sync with the payload built in
    ``api/routes/audit.py::create_audit_log``.
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
    }


def verify_row(row: AuditLog) -> tuple[bool, str]:
    """Return ``(is_valid, expected_hash)`` for one audit row."""
    expected = compute_audit_hash(build_payload(row))
    return row.integrity_hash == expected, expected


@dataclass
class RowFailure:
    id: str
    timestamp: str
    connector_name: str
    action: str
    stored_hash: str
    expected_hash: str


@dataclass
class VerifyReport:
    total: int
    valid: int
    invalid: int
    failures: list[RowFailure]

    @property
    def ok(self) -> bool:
        return self.invalid == 0


def verify_rows(rows: Iterable[AuditLog], fail_fast: bool = False) -> VerifyReport:
    """Walk an iterable of rows, return a report. Pure function, no DB."""
    total = 0
    valid = 0
    failures: list[RowFailure] = []
    for row in rows:
        total += 1
        is_valid, expected = verify_row(row)
        if is_valid:
            valid += 1
            continue
        failures.append(
            RowFailure(
                id=str(row.id),
                timestamp=row.timestamp.isoformat() if isinstance(row.timestamp, datetime) else str(row.timestamp),
                connector_name=row.connector_name,
                action=row.action,
                stored_hash=row.integrity_hash,
                expected_hash=expected,
            )
        )
        if fail_fast:
            break
    return VerifyReport(
        total=total,
        valid=valid,
        invalid=len(failures),
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
    lines.append(f"Audit log verification")
    lines.append(f"  total rows checked: {report.total}")
    lines.append(f"  valid: {report.valid}")
    lines.append(f"  invalid: {report.invalid}")
    if report.invalid > 0:
        lines.append("")
        lines.append("TAMPER DETECTED. The following rows have hashes that do not match their stored payload:")
        for f in report.failures:
            lines.append(f"  - row {f.id} ({f.connector_name}/{f.action}) at {f.timestamp}")
            lines.append(f"      stored:   {f.stored_hash}")
            lines.append(f"      expected: {f.expected_hash}")
    else:
        lines.append("")
        lines.append("OK. Every audit row hashes correctly.")
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
        description="Verify the integrity of audit_log rows.",
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
