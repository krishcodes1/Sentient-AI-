"""
Tamper-evident audit logging service for SentientAI.

Uses the canonical AuditLog model from models.audit. Every agent action
is recorded with a SHA-256 integrity hash chained to the previous entry
via ``previous_hash`` plus a monotonic per-user ``sequence`` so that
deletions and reorderings are detectable.
"""

from __future__ import annotations

import hashlib
import json
import re
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession

from models.audit import AuditLog, AuditStatus


# ------------------------------------------------------------------ #
# Sensitive-data sanitizer
# ------------------------------------------------------------------ #

_SENSITIVE_KEYS = re.compile(
    r"(token|password|passwd|secret|api[_-]?key|access[_-]?key|"
    r"authorization|credential|private[_-]?key|client[_-]?secret|"
    r"session[_-]?id|cookie|bearer|refresh[_-]?token|ssn|"
    r"credit[_-]?card|card[_-]?number|cvv|cvc)",
    re.IGNORECASE,
)

_SENSITIVE_VALUE_PATTERNS = re.compile(
    r"(?:eyJ[A-Za-z0-9_-]{10,}\.)|"               # JWT prefix
    r"(?:sk-[A-Za-z0-9]{20,})|"                    # OpenAI-style keys
    r"(?:ghp_[A-Za-z0-9]{36})|"                    # GitHub PATs
    r"(?:AKIA[A-Z0-9]{16})|"                       # AWS access keys
    r"(?:\b[0-9]{13,19}\b)",                        # Credit card numbers
    re.ASCII,
)

# Keys whose values must be redacted before being fingerprinted in audit rows.
_PARAM_HASH_REDACT_KEYS = frozenset(
    {"api_key", "token", "password", "secret", "authorization"}
)


def _sanitize(data: Any) -> Any:
    """Recursively strip sensitive values from data before storage."""
    if isinstance(data, dict):
        sanitized = {}
        for key, value in data.items():
            if _SENSITIVE_KEYS.search(str(key)):
                sanitized[key] = "***REDACTED***"
            else:
                sanitized[key] = _sanitize(value)
        return sanitized
    if isinstance(data, list):
        return [_sanitize(item) for item in data]
    if isinstance(data, str):
        return _SENSITIVE_VALUE_PATTERNS.sub("***REDACTED***", data)
    return data


def sanitize_request_data(data: Any) -> str:
    """Sanitize and serialize request data for audit storage."""
    if data is None:
        return "{}"
    sanitized = _sanitize(data)
    try:
        return json.dumps(sanitized, default=str)
    except (TypeError, ValueError):
        return json.dumps({"raw": str(sanitized)})


def _redact_for_params_hash(data: Any) -> Any:
    """Walk *data* and replace values for known-secret keys with ``<REDACTED>``.

    Used by :func:`_compute_params_hash` so the audit row stores a fingerprint
    of params without preserving raw secret values.
    """
    if isinstance(data, dict):
        out: dict[str, Any] = {}
        for key, value in data.items():
            if str(key).lower() in _PARAM_HASH_REDACT_KEYS:
                out[key] = "<REDACTED>"
            else:
                out[key] = _redact_for_params_hash(value)
        return out
    if isinstance(data, list):
        return [_redact_for_params_hash(item) for item in data]
    return data


def _compute_params_hash(params: Optional[dict[str, Any]]) -> str:
    """Return a stable SHA-256 fingerprint of *params* with secrets redacted.

    Obvious secret keys (``api_key``, ``token``, ``password``, ``secret``,
    ``authorization``) have their values replaced with ``<REDACTED>`` before
    hashing so the audit row can include a deterministic fingerprint of the
    request shape without storing raw secrets.
    """
    redacted = _redact_for_params_hash(params or {})
    canonical = json.dumps(
        redacted, sort_keys=True, separators=(",", ":"), default=str
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


# ------------------------------------------------------------------ #
# Audit Service
# ------------------------------------------------------------------ #


class AuditService:
    """Chain-linked, tamper-evident audit logging backed by async SQLAlchemy."""

    def __init__(self, db: AsyncSession) -> None:
        self._db = db

    # --------------------------------------------------------------
    # Chain helpers
    # --------------------------------------------------------------
    async def _get_last_log(self, user_id: str) -> Optional[AuditLog]:
        """Return the user's most recent log, ordered by ``sequence`` DESC."""
        stmt = (
            select(AuditLog)
            .where(AuditLog.user_id == user_id)
            .order_by(AuditLog.sequence.desc())
            .limit(1)
        )
        result = await self._db.execute(stmt)
        return result.scalar_one_or_none()

    @staticmethod
    def _canonical_fields_json(
        *,
        user_id: str,
        action: str,
        endpoint: str,
        status: str,
        timestamp_isoformat: str,
        params_hash: str,
        reasoning: Optional[str],
        confidence_score: Optional[float],
    ) -> str:
        """Produce the deterministic canonical JSON used in the chain hash."""
        payload = {
            "user_id": str(user_id),
            "action": action,
            "endpoint": endpoint,
            "status": status,
            "timestamp_isoformat": timestamp_isoformat,
            "params_hash": params_hash,
            "reasoning": reasoning,
            "confidence_score": confidence_score,
        }
        return json.dumps(payload, sort_keys=True, separators=(",", ":"))

    @staticmethod
    def _compute_chain_hash(canonical_fields_json: str, previous_hash: Optional[str]) -> str:
        """SHA-256 chain hash: H(canonical_fields_json || (previous_hash or "GENESIS"))."""
        prev = previous_hash if previous_hash is not None else "GENESIS"
        payload = canonical_fields_json + prev
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()

    # --------------------------------------------------------------
    # Public API
    # --------------------------------------------------------------
    async def log_action(
        self,
        user_id: str,
        connector_name: str,
        action: str,
        endpoint: str,
        scope_used: str,
        status: AuditStatus,
        reasoning_chain: Any = None,
        request_data: Any = None,
        response_summary: Optional[str] = None,
        detection_method: Optional[str] = None,
        confidence_score: Optional[float] = None,
        request_id: Optional[str] = None,
    ) -> AuditLog:
        """Record an auditable action with chain integrity guarantees."""
        # 1. Freeze the timestamp before hashing so the on-disk row matches the
        #    value that was hashed.
        now = datetime.now(timezone.utc)
        timestamp_str = now.isoformat()

        # 2. Fetch the previous log for this user to chain into.
        last_log = await self._get_last_log(str(user_id))
        previous_hash = last_log.integrity_hash if last_log else None
        sequence = (last_log.sequence + 1) if (last_log and last_log.sequence is not None) else 0

        # 3. Compute params_hash (used as a tamper-evident fingerprint of the
        #    request_data that doesn't store raw secrets).
        params_hash = _compute_params_hash(
            request_data if isinstance(request_data, dict) else None
        )

        status_value = status.value if isinstance(status, AuditStatus) else str(status)

        # 4. Build canonical fields JSON and the chain hash.
        reasoning_repr: Optional[str]
        if reasoning_chain is None:
            reasoning_repr = None
        elif isinstance(reasoning_chain, str):
            reasoning_repr = reasoning_chain
        else:
            try:
                reasoning_repr = json.dumps(
                    reasoning_chain, sort_keys=True, separators=(",", ":"), default=str
                )
            except (TypeError, ValueError):
                reasoning_repr = str(reasoning_chain)

        canonical = self._canonical_fields_json(
            user_id=str(user_id),
            action=action,
            endpoint=endpoint,
            status=status_value,
            timestamp_isoformat=timestamp_str,
            params_hash=params_hash,
            reasoning=reasoning_repr,
            confidence_score=confidence_score,
        )
        integrity_hash = self._compute_chain_hash(canonical, previous_hash)

        sanitized_data = sanitize_request_data(request_data)

        record = AuditLog(
            user_id=user_id,
            timestamp=now,
            connector_name=connector_name,
            action=action,
            endpoint=endpoint,
            scope_used=scope_used,
            status=status,
            reasoning_chain=reasoning_chain,
            request_data=json.loads(sanitized_data) if sanitized_data else None,
            response_summary=response_summary,
            detection_method=detection_method,
            confidence_score=confidence_score,
            request_id=request_id or str(uuid.uuid4()),
            integrity_hash=integrity_hash,
            previous_hash=previous_hash,
            sequence=sequence,
        )

        self._db.add(record)
        await self._db.flush()
        await self._db.refresh(record)
        return record

    async def get_logs(
        self,
        user_id: str,
        filters: Optional[dict[str, Any]] = None,
    ) -> list[AuditLog]:
        """Retrieve audit logs with optional filtering."""
        stmt = (
            select(AuditLog)
            .where(AuditLog.user_id == user_id)
            .order_by(AuditLog.timestamp.desc())
        )

        if filters:
            if "connector_name" in filters:
                stmt = stmt.where(AuditLog.connector_name == filters["connector_name"])
            if "status" in filters:
                stmt = stmt.where(AuditLog.status == filters["status"])
            if "since" in filters:
                stmt = stmt.where(AuditLog.timestamp >= filters["since"])
            if "until" in filters:
                stmt = stmt.where(AuditLog.timestamp <= filters["until"])
            if "search" in filters:
                search_term = f"%{filters['search']}%"
                stmt = stmt.where(
                    AuditLog.action.ilike(search_term)
                    | AuditLog.connector_name.ilike(search_term)
                    | AuditLog.endpoint.ilike(search_term)
                )
            stmt = stmt.limit(filters.get("limit", 100))
        else:
            stmt = stmt.limit(100)

        result = await self._db.execute(stmt)
        return list(result.scalars().all())

    async def get_stats(self, user_id: str) -> dict[str, Any]:
        """Get aggregate audit statistics for dashboard."""
        # Compare against ``.value`` strings — the column stores the lowercase
        # string form of each enum member regardless of the Python attribute
        # name (which is now uppercase per the model).
        base = select(func.count()).where(AuditLog.user_id == user_id)

        total = (await self._db.execute(base)).scalar() or 0
        approved = (
            await self._db.execute(
                base.where(AuditLog.status == AuditStatus.APPROVED.value)
            )
        ).scalar() or 0
        blocked = (
            await self._db.execute(
                base.where(AuditLog.status == AuditStatus.BLOCKED.value)
            )
        ).scalar() or 0
        pending = (
            await self._db.execute(
                base.where(AuditLog.status == AuditStatus.PENDING.value)
            )
        ).scalar() or 0
        escalated = (
            await self._db.execute(
                base.where(AuditLog.status == AuditStatus.ESCALATED.value)
            )
        ).scalar() or 0

        cutoff = datetime.now(timezone.utc) - timedelta(hours=24)
        last_24h_count = (
            await self._db.execute(base.where(AuditLog.timestamp >= cutoff))
        ).scalar() or 0

        return {
            "total": total,
            "approved": approved,
            "blocked": blocked,
            "pending": pending,
            "escalated": escalated,
            "last_24h_count": last_24h_count,
        }

    async def verify_integrity(self, user_id: str) -> dict[str, Any]:
        """Walk the user's chain and verify hashes + sequence contiguity.

        Returns a dict with::

            {
                "ok": bool,
                "total": int,
                "broken_at": <log id or None>,
                "broken_field": "previous_hash" | "integrity_hash" | "sequence" | None,
            }
        """
        stmt = (
            select(AuditLog)
            .where(AuditLog.user_id == user_id)
            .order_by(AuditLog.sequence.asc())
        )
        result = await self._db.execute(stmt)
        logs = list(result.scalars().all())

        prev_hash: Optional[str] = None
        expected_sequence = 0
        for log in logs:
            # Sequence must be contiguous starting at 0.
            if log.sequence != expected_sequence:
                return {
                    "ok": False,
                    "total": len(logs),
                    "broken_at": log.id,
                    "broken_field": "sequence",
                }

            # previous_hash must match the prior row's integrity_hash.
            if log.previous_hash != prev_hash:
                return {
                    "ok": False,
                    "total": len(logs),
                    "broken_at": log.id,
                    "broken_field": "previous_hash",
                }

            # integrity_hash must equal the recomputed hash from the row's
            # canonical fields plus the recorded previous_hash.
            params_hash = _compute_params_hash(
                log.request_data if isinstance(log.request_data, dict) else None
            )
            status_value = (
                log.status.value if isinstance(log.status, AuditStatus) else str(log.status)
            )
            reasoning_repr: Optional[str]
            if log.reasoning_chain is None:
                reasoning_repr = None
            elif isinstance(log.reasoning_chain, str):
                reasoning_repr = log.reasoning_chain
            else:
                try:
                    reasoning_repr = json.dumps(
                        log.reasoning_chain,
                        sort_keys=True,
                        separators=(",", ":"),
                        default=str,
                    )
                except (TypeError, ValueError):
                    reasoning_repr = str(log.reasoning_chain)

            canonical = self._canonical_fields_json(
                user_id=str(log.user_id),
                action=log.action,
                endpoint=log.endpoint,
                status=status_value,
                timestamp_isoformat=log.timestamp.isoformat(),
                params_hash=params_hash,
                reasoning=reasoning_repr,
                confidence_score=log.confidence_score,
            )
            expected_hash = self._compute_chain_hash(canonical, log.previous_hash)
            if expected_hash != log.integrity_hash:
                return {
                    "ok": False,
                    "total": len(logs),
                    "broken_at": log.id,
                    "broken_field": "integrity_hash",
                }

            prev_hash = log.integrity_hash
            expected_sequence += 1

        return {
            "ok": True,
            "total": len(logs),
            "broken_at": None,
            "broken_field": None,
        }
