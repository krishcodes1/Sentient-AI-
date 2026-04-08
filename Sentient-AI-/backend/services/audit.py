"""
Tamper-evident audit logging service for SentientAI.

Uses the canonical AuditLog model from models.audit. Every agent action
is recorded with a SHA-256 integrity hash chained to the previous entry.
"""

from __future__ import annotations

import hashlib
import json
import re
import uuid
from datetime import datetime, timezone
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


# ------------------------------------------------------------------ #
# Audit Service
# ------------------------------------------------------------------ #

_GENESIS_HASH = "0" * 64


class AuditService:
    """Chain-linked, tamper-evident audit logging backed by async SQLAlchemy."""

    def __init__(self, db: AsyncSession) -> None:
        self._db = db

    async def _get_last_hash(self, user_id: str) -> str:
        """Retrieve the most recent integrity hash for this user's log chain."""
        stmt = (
            select(AuditLog.integrity_hash)
            .where(AuditLog.user_id == user_id)
            .order_by(AuditLog.timestamp.desc())
            .limit(1)
        )
        result = await self._db.execute(stmt)
        row = result.scalar_one_or_none()
        return row if row else _GENESIS_HASH

    @staticmethod
    def _compute_hash(
        timestamp: str,
        user_id: str,
        action: str,
        endpoint: str,
        previous_hash: str,
    ) -> str:
        """SHA-256 chain hash: H(timestamp + user_id + action + endpoint + prev_hash)."""
        payload = f"{timestamp}{user_id}{action}{endpoint}{previous_hash}"
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()

    async def log_action(
        self,
        user_id: str,
        connector_name: str,
        action: str,
        endpoint: str,
        scope_used: str,
        status: AuditStatus,
        reasoning_chain: Optional[str] = None,
        request_data: Any = None,
        response_summary: Optional[str] = None,
        detection_method: Optional[str] = None,
        confidence_score: Optional[float] = None,
        request_id: Optional[str] = None,
    ) -> AuditLog:
        """Record an auditable action with integrity chaining."""
        now = datetime.now(timezone.utc)
        timestamp_str = now.isoformat()

        previous_hash = await self._get_last_hash(str(user_id))
        integrity_hash = self._compute_hash(
            timestamp_str, str(user_id), action, endpoint, previous_hash
        )
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
        base = select(func.count()).where(AuditLog.user_id == user_id)

        total = (await self._db.execute(base)).scalar() or 0
        approved = (
            await self._db.execute(
                base.where(AuditLog.status == AuditStatus.APPROVED)
            )
        ).scalar() or 0
        blocked = (
            await self._db.execute(
                base.where(AuditLog.status == AuditStatus.BLOCKED)
            )
        ).scalar() or 0
        pending = (
            await self._db.execute(
                base.where(AuditLog.status == AuditStatus.PENDING)
            )
        ).scalar() or 0

        return {
            "total": total,
            "approved": approved,
            "blocked": blocked,
            "pending": pending,
        }

    def verify_integrity(self, log_entry: AuditLog, previous_hash: str = _GENESIS_HASH) -> bool:
        """Verify that a log entry's integrity hash is correct."""
        expected = self._compute_hash(
            log_entry.timestamp.isoformat(),
            str(log_entry.user_id),
            log_entry.action,
            log_entry.endpoint,
            previous_hash,
        )
        return expected == log_entry.integrity_hash
