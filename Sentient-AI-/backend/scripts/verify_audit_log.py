"""Audit log integrity verifier.

Walks every row of the ``audit_logs`` table (ordered by per-user ``seq``,
with pre-seq rows first) and runs three checks:

1. Per-row integrity: the row's ``integrity_hash`` matches a freshly
   computed HMAC-SHA256 over its stored fields (including
   ``previous_hash``). The hash is keyed so a database-write adversary
   cannot recompute the chain and forge history — that requires the
   AUDIT_HMAC_KEY (or the ENCRYPTION_KEY it is derived from), which lives
   outside the database.
2. Chain link: the row's ``previous_hash`` matches the ``integrity_hash``
   of the previous row in that user's chain.
3. Seq order: once assigned, a user's ``seq`` must strictly increase;
   duplicates or decreases are a reordering/renumbering signal.

Together these detect single-field tampering, row deletion, reordering,
and chain rotation.

Backward compatibility: rows written before the HMAC upgrade carry the
historical *unkeyed* SHA-256 and a NULL ``seq``. Those rows are still
validated (unkeyed recompute) and reported as ``legacy`` rather than
tampered — but the unkeyed fallback applies ONLY to seq-less rows, so a
forged post-upgrade row with a recomputed unkeyed hash is rejected.
Legacy rows carry no forgery protection; everything written since the
upgrade does.

That grandfathering is itself an attack surface, and the tool says so
rather than hiding it: nothing in the database records that a deployment
upgraded, so an adversary with write access can rewrite an entire chain
into unkeyed rows with ``seq`` cleared and the default (permissive) run
will report it clean. ``--require-hmac`` rejects unkeyed rows outright
and is what deployments should gate on once every row is keyed.

Rows with ``previous_hash = NULL`` predate the chain feature; the
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
from pathlib import Path
from typing import Any, Iterable, Optional

# Allow both ``python -m scripts.verify_audit_log`` and a direct
# ``python scripts/verify_audit_log.py`` from the backend directory.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.security import compute_audit_hash, compute_audit_hash_legacy

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
    ``services/audit.py::build_hash_payload`` (which the verify route also
    uses). Includes ``previous_hash`` so the row's hash is bound to its
    position in the chain. ``seq`` is deliberately NOT part of the payload
    (see the note in ``build_hash_payload``); it is the order key for the
    walk, and the seq-order check below flags manipulation of it.
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
        "reasoning_chain": getattr(row, "reasoning_chain", None),
        "detection_method": getattr(row, "detection_method", None),
        "confidence_score": getattr(row, "confidence_score", None),
        "previous_hash": getattr(row, "previous_hash", None),
    }


def classify_row(row: "AuditLog") -> tuple[bool, str, str]:
    """Return ``(is_valid, expected_hmac, scheme)`` for one audit row.

    ``scheme`` is ``"hmac"`` for rows matching the keyed hash, ``"legacy"``
    for pre-upgrade rows matching the historical unkeyed SHA-256, and
    ``"invalid"`` otherwise. The unkeyed fallback is restricted to rows
    with ``seq IS NULL``: every row written since the HMAC upgrade carries
    a seq, so an attacker who recomputes unkeyed hashes for forged
    post-upgrade rows is rejected instead of being grandfathered in.
    """
    payload = build_payload(row)
    expected = compute_audit_hash(payload)
    if row.integrity_hash == expected:
        return True, expected, "hmac"
    if (
        getattr(row, "seq", None) is None
        and row.integrity_hash == compute_audit_hash_legacy(payload)
    ):
        return True, expected, "legacy"
    return False, expected, "invalid"


def verify_row(row: "AuditLog") -> tuple[bool, str]:
    """Return ``(is_valid, expected_hash)`` for one audit row.

    ``expected_hash`` is always the keyed (HMAC) digest; a legacy row is
    reported valid even though its stored unkeyed hash differs from it.
    """
    is_valid, expected, _scheme = classify_row(row)
    return is_valid, expected


@dataclass
class RowFailure:
    id: str
    timestamp: str
    connector_name: str
    action: str
    kind: str  # "row_hash", "chain_link", "seq_order", or "unkeyed_hash"
    stored_hash: str
    expected_hash: str
    # Only populated for chain_link failures
    stored_previous_hash: Optional[str] = None
    expected_previous_hash: Optional[str] = None
    # Only populated for seq_order failures
    stored_seq: Optional[int] = None
    previous_seq: Optional[int] = None


@dataclass
class VerifyReport:
    total: int
    valid: int
    invalid: int
    # Rows that verified against the pre-HMAC unkeyed SHA-256. Valid, but
    # forgeable by a database-write adversary — surfaced separately so the
    # keyed guarantee is never silently overstated.
    legacy: int = 0
    # True when the walk ran under --require-hmac, i.e. those legacy rows
    # were counted as failures rather than tolerated.
    require_hmac: bool = False
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


def _seq_failure(row: "AuditLog", previous_seq: Optional[int]) -> RowFailure:
    return RowFailure(
        id=str(row.id),
        timestamp=row.timestamp.isoformat() if isinstance(row.timestamp, datetime) else str(row.timestamp),
        connector_name=row.connector_name,
        action=row.action,
        kind="seq_order",
        stored_hash=row.integrity_hash,
        expected_hash=row.integrity_hash,
        stored_seq=getattr(row, "seq", None),
        previous_seq=previous_seq,
    )


def _unkeyed_failure(row: "AuditLog", expected: str) -> RowFailure:
    """A self-consistent but *unkeyed* (pre-HMAC) row, rejected under
    ``--require-hmac``."""
    return RowFailure(
        id=str(row.id),
        timestamp=row.timestamp.isoformat() if isinstance(row.timestamp, datetime) else str(row.timestamp),
        connector_name=row.connector_name,
        action=row.action,
        kind="unkeyed_hash",
        stored_hash=row.integrity_hash,
        expected_hash=expected,
        stored_seq=getattr(row, "seq", None),
    )


def verify_rows(
    rows: Iterable["AuditLog"],
    fail_fast: bool = False,
    require_hmac: bool = False,
) -> VerifyReport:
    """Walk rows in chain order, check per-row hash, chain links, and seq.

    Rows must be sorted by ``seq`` ascending with NULLs (legacy pre-seq
    rows) first, then ``timestamp`` ascending (the CLI does this in the
    SQL query; tests pass already-sorted iterables).

    Chain checking is per-user. The first row seen for any user starts
    a fresh chain. A row can fail several checks; it is still counted as
    one invalid row in the report. Rows carrying the pre-HMAC unkeyed
    hash are counted in ``report.legacy`` — valid but explicitly labeled,
    because they predate the keyed guarantee.

    ``require_hmac`` turns that label into a failure. This matters more
    than it looks: grandfathering unkeyed rows means a database-write
    adversary can rewrite an ENTIRE chain as unkeyed rows with ``seq``
    cleared and it verifies clean, because nothing in the database says
    the deployment ever upgraded. The default (permissive) mode exists
    only for the migration window; once every row is keyed, operators
    should gate on ``--require-hmac`` so that laundering attack turns
    into a non-zero exit.
    """
    failures: list[RowFailure] = []
    bad_row_ids: set[str] = set()
    processed = 0
    legacy = 0

    # Track the last integrity_hash and seq we saw for each user's chain
    last_hash_for_user: dict[str, Optional[str]] = {}
    last_seq_for_user: dict[str, Optional[int]] = {}

    for row in rows:
        processed += 1
        user_key = str(row.user_id)
        row_id = str(row.id)
        is_valid, expected, scheme = classify_row(row)
        unkeyed_rejected = False
        if scheme == "legacy":
            legacy += 1
            if require_hmac:
                # The row's stored unkeyed hash is self-consistent, so this
                # is not a "hash mismatch" — it is a row that carries no
                # forgery protection at all, which under --require-hmac is a
                # failure rather than a footnote.
                unkeyed_rejected = True
                failures.append(_unkeyed_failure(row, expected))
                bad_row_ids.add(row_id)
        stored_prev = getattr(row, "previous_hash", None)
        row_seq = getattr(row, "seq", None)

        chain_ok = True
        if user_key in last_hash_for_user:
            expected_prev = last_hash_for_user[user_key]
            if stored_prev != expected_prev:
                chain_ok = False
                failures.append(_chain_failure(row, expected_prev))
                bad_row_ids.add(row_id)
            # seq is not covered by the row hash (the read-only verify
            # route predates it), so cross-check it against the chain:
            # once assigned it must strictly increase. A duplicate seq
            # would make ORDER BY seq ambiguous again — exactly the
            # ambiguity seq exists to remove — so it is flagged even when
            # the chain links happen to match.
            prev_seq = last_seq_for_user.get(user_key)
            if row_seq is not None and prev_seq is not None and row_seq <= prev_seq:
                chain_ok = False
                failures.append(_seq_failure(row, prev_seq))
                bad_row_ids.add(row_id)
        # First row for a user: no chain check possible (we cannot
        # distinguish a true genesis from deletion of earlier rows).
        # The previous_hash field is still bound into the per-row hash,
        # so tampering with it trips the row_hash check.

        if not is_valid:
            failures.append(_row_failure(row, expected))
            bad_row_ids.add(row_id)

        last_hash_for_user[user_key] = row.integrity_hash
        if row_seq is not None:
            last_seq_for_user[user_key] = row_seq

        if fail_fast and (not is_valid or not chain_ok or unkeyed_rejected):
            break

    invalid = len(bad_row_ids)
    valid = processed - invalid

    return VerifyReport(
        total=processed,
        valid=valid,
        invalid=invalid,
        legacy=legacy,
        require_hmac=require_hmac,
        failures=failures,
    )


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


async def run(
    user_id: Optional[uuid.UUID],
    fail_fast: bool,
    require_hmac: bool = False,
) -> VerifyReport:
    """Fetch every audit row (or just one user's) and verify it.

    DB imports are deferred to this function so unit tests can import the
    pure helpers above without pulling in the SQLAlchemy engine.
    """
    from sqlalchemy import select
    from core.database import async_session
    from models.audit import AuditLog

    async with async_session() as db:
        # seq is the deterministic chain order; legacy pre-seq rows (NULL)
        # come first, ordered by timestamp — the best key that existed when
        # they were written.
        query = select(AuditLog).order_by(
            AuditLog.seq.asc().nullsfirst(), AuditLog.timestamp.asc()
        )
        if user_id is not None:
            query = query.where(AuditLog.user_id == user_id)
        result = await db.execute(query)
        rows = list(result.scalars().all())
    return verify_rows(rows, fail_fast=fail_fast, require_hmac=require_hmac)


def _format_human(report: VerifyReport) -> str:
    lines = []
    lines.append("Audit log verification")
    lines.append(f"  total rows checked: {report.total}")
    lines.append(f"  valid: {report.valid}")
    if report.legacy and report.require_hmac:
        lines.append(
            f"  legacy (pre-HMAC, unkeyed SHA-256): {report.legacy} — "
            "rejected because --require-hmac was set"
        )
    elif report.legacy:
        lines.append(
            f"  legacy (pre-HMAC, unkeyed SHA-256): {report.legacy} — "
            "valid, but forgeable by a database-write adversary; only rows "
            "written since the HMAC upgrade carry the keyed guarantee"
        )
        lines.append(
            "      WARNING: nothing in the database records that this "
            "deployment upgraded, so an attacker with write access can "
            "rewrite rows into this unkeyed form (clearing seq) and they "
            "will verify clean. Once every row is keyed, gate on "
            "--require-hmac."
        )
    lines.append(f"  invalid: {report.invalid}")
    if report.invalid > 0:
        lines.append("")
        lines.append("TAMPER DETECTED:")
        for f in report.failures:
            if f.kind == "row_hash":
                lines.append(f"  - row {f.id} ({f.connector_name}/{f.action}) at {f.timestamp}: hash mismatch")
                lines.append(f"      stored:   {f.stored_hash}")
                lines.append(f"      expected: {f.expected_hash}")
            elif f.kind == "unkeyed_hash":
                lines.append(f"  - row {f.id} ({f.connector_name}/{f.action}) at {f.timestamp}: unkeyed (pre-HMAC) hash")
                lines.append("      row carries no forgery protection and --require-hmac was set")
            elif f.kind == "seq_order":
                lines.append(f"  - row {f.id} ({f.connector_name}/{f.action}) at {f.timestamp}: seq out of order")
                lines.append(f"      seq {f.stored_seq} follows seq {f.previous_seq}")
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
            "legacy": report.legacy,
            "require_hmac": report.require_hmac,
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
    parser.add_argument(
        "--require-hmac",
        action="store_true",
        help=(
            "Reject pre-HMAC (unkeyed, seq-less) rows instead of accepting "
            "them as legacy. Use this once every row has been written since "
            "the HMAC upgrade: without it, an attacker with database write "
            "access can rewrite the whole chain into unkeyed form and the "
            "verifier still exits 0."
        ),
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
        report = asyncio.run(run(user_id, args.fail_fast, args.require_hmac))
    except Exception as exc:
        print(f"error: verifier could not run: {exc}", file=sys.stderr)
        return 2

    output = _format_json(report) if args.json else _format_human(report)
    print(output)
    return 0 if report.ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
