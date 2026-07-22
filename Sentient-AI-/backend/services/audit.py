"""
Tamper-evident audit logging service for SentientAI.

Single write path for the ``audit_logs`` table. Every row is chained to
the previous row in the same user's log via ``previous_hash``, and the
chain link is bound into the row's own SHA-256 ``integrity_hash``, so
field tampering, row deletion, and reordering are all detectable.

Three layers live here:

- ``sanitize_request_data`` / ``_sanitize``: strip credentials and other
  sensitive values before anything is persisted.
- ``build_hash_payload`` + ``append_audit_log``: the canonical hash
  payload (shared with ``api/routes/audit.py`` verification and
  ``scripts/verify_audit_log.py``) and the chained insert.
- ``RuntimeAuditLogger``: adapter implementing the agent runtime's audit
  protocol (``log(entry: dict)``); opens its own short-lived sessions so
  the singleton runtime never holds a request-scoped session.
"""

from __future__ import annotations

import asyncio
import json
import re
import uuid
from typing import Any, Callable, Optional

import structlog
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from core.security import compute_audit_hash
from models.audit import AuditLog, AuditStatus

logger = structlog.get_logger(__name__)


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
# Canonical hash payload + chained writes
# ------------------------------------------------------------------ #


def build_hash_payload(
    *,
    user_id: str,
    connector_name: str,
    action: str,
    endpoint: str,
    scope_used: str,
    status_value: str,
    request_id: str,
    request_data: Any,
    response_summary: Any,
    previous_hash: Optional[str],
    reasoning_chain: Any = None,
    detection_method: Optional[str] = None,
    confidence_score: Optional[float] = None,
) -> dict[str, Any]:
    """Canonical payload that gets hashed for one audit row.

    Must stay in sync with ``scripts/verify_audit_log.py::build_payload``.
    Including ``previous_hash`` chains each row to its predecessor, so
    deleting or reordering rows is detectable, not just per-row tampering.

    ``reasoning_chain``, ``detection_method``, and ``confidence_score`` carry
    the security semantics of the event (why an action was blocked, how a
    threat was detected, the detector's confidence). They are covered by the
    hash so a database-write adversary cannot rewrite a "blocked, critical
    threat" row into a benign one without invalidating the integrity hash.
    ``timestamp`` is deliberately excluded: it is assigned by the database and
    can be re-serialised with different precision on read-back, which would
    produce false tamper positives; row ordering is instead protected by the
    ``previous_hash`` chain.
    """
    return {
        "user_id": user_id,
        "connector_name": connector_name,
        "action": action,
        "endpoint": endpoint,
        "scope_used": scope_used,
        "status": status_value,
        "request_id": request_id,
        "request_data": request_data,
        "response_summary": response_summary,
        "reasoning_chain": reasoning_chain,
        "detection_method": detection_method,
        "confidence_score": confidence_score,
        "previous_hash": previous_hash,
    }


# Serializes chain writes per user within this process so two concurrent
# tool executions cannot both read the same head and fork the chain.
# NOTE: this guards a single process only. Multi-worker deployments need a
# DB-level guard (e.g. SELECT ... FOR UPDATE on the chain head, or a
# serialized writer); documented in SECURITY.md as a deployment constraint.
_chain_locks: dict[str, asyncio.Lock] = {}
_chain_locks_guard = asyncio.Lock()


async def _lock_for_user(user_id: str) -> asyncio.Lock:
    async with _chain_locks_guard:
        lock = _chain_locks.get(user_id)
        if lock is None:
            lock = asyncio.Lock()
            _chain_locks[user_id] = lock
        return lock


async def append_audit_log(
    db: AsyncSession,
    *,
    user_id: uuid.UUID | str,
    connector_name: str,
    action: str,
    endpoint: str,
    scope_used: str,
    status: AuditStatus,
    reasoning_chain: Any = None,
    detection_method: Optional[str] = None,
    confidence_score: Optional[float] = None,
    request_data: Any = None,
    response_summary: Optional[str] = None,
    request_id: Optional[str] = None,
) -> AuditLog:
    """Append one chained, sanitized row to the user's audit log.

    This is the only sanctioned way to write audit rows. Request data and
    the response summary are sanitized before hashing so the stored values
    and the hash always agree.
    """
    user_uuid = user_id if isinstance(user_id, uuid.UUID) else uuid.UUID(str(user_id))
    rid = request_id or str(uuid.uuid4())

    sanitized_request = json.loads(sanitize_request_data(request_data)) if request_data is not None else None
    sanitized_summary = _sanitize(response_summary) if response_summary is not None else None
    # Sanitise once and hash exactly what is stored, so the row and its hash
    # always agree on the reasoning chain.
    sanitized_reasoning = _sanitize(reasoning_chain) if reasoning_chain is not None else None

    lock = await _lock_for_user(str(user_uuid))
    async with lock:
        prev_result = await db.execute(
            select(AuditLog)
            .where(AuditLog.user_id == user_uuid)
            .order_by(AuditLog.timestamp.desc())
            .limit(1)
        )
        prev = prev_result.scalar_one_or_none()
        previous_hash = prev.integrity_hash if prev is not None else None

        payload = build_hash_payload(
            user_id=str(user_uuid),
            connector_name=connector_name,
            action=action,
            endpoint=endpoint,
            scope_used=scope_used,
            status_value=status.value,
            request_id=rid,
            request_data=sanitized_request,
            response_summary=sanitized_summary,
            previous_hash=previous_hash,
            reasoning_chain=sanitized_reasoning,
            detection_method=detection_method,
            confidence_score=confidence_score,
        )
        integrity_hash = compute_audit_hash(payload)

        entry = AuditLog(
            user_id=user_uuid,
            connector_name=connector_name,
            action=action,
            endpoint=endpoint,
            scope_used=scope_used,
            status=status,
            reasoning_chain=sanitized_reasoning,
            detection_method=detection_method,
            confidence_score=confidence_score,
            request_data=sanitized_request,
            response_summary=sanitized_summary,
            integrity_hash=integrity_hash,
            previous_hash=previous_hash,
            request_id=rid,
        )
        db.add(entry)
        await db.flush()
        await db.refresh(entry)
        return entry


# ------------------------------------------------------------------ #
# Runtime adapter
# ------------------------------------------------------------------ #

# Maps runtime event names to the audit row status they should record.
_EVENT_STATUS: dict[str, AuditStatus] = {
    "tool_executed": AuditStatus.approved,
    "tool_approved_and_executed": AuditStatus.approved,
    "tool_pending_approval": AuditStatus.pending,
    "tool_blocked": AuditStatus.blocked,
    "tool_denied": AuditStatus.blocked,
    "tool_expired": AuditStatus.blocked,
    "input_blocked": AuditStatus.blocked,
    "output_blocked": AuditStatus.blocked,
}


class RuntimeAuditLogger:
    """DB-backed implementation of the agent runtime's audit protocol.

    The runtime is a process-wide singleton, so this adapter opens its own
    short-lived session per entry instead of borrowing a request session.
    Failures propagate to the caller: a tool action whose audit row cannot
    be written should fail loudly rather than execute unrecorded.
    """

    def __init__(
        self,
        session_factory: Optional[Callable[[], AsyncSession]] = None,
    ) -> None:
        if session_factory is None:
            from core.database import async_session

            session_factory = async_session
        self._session_factory = session_factory

    async def log(self, entry: dict[str, Any]) -> None:
        event = str(entry.get("event", "unknown"))
        user_id = entry.get("user_id")
        if not user_id:
            logger.warning("audit_entry_missing_user", event=event)
            return

        tool = str(entry.get("tool", ""))
        if "." in tool:
            connector_name, _, action = tool.partition(".")
        else:
            connector_name, action = "agent", (tool or event)

        status = _EVENT_STATUS.get(event, AuditStatus.blocked)

        reasoning: dict[str, Any] = {"event": event}
        for key in ("reason", "policy", "action_id", "threat_level"):
            if entry.get(key) is not None:
                reasoning[key] = entry[key]

        async with self._session_factory() as session:
            await append_audit_log(
                session,
                user_id=str(user_id),
                connector_name=connector_name,
                action=action,
                endpoint=str(entry.get("endpoint", f"agent.{event}")),
                scope_used=str(entry.get("scope", connector_name)),
                status=status,
                reasoning_chain=reasoning,
                detection_method=entry.get("detection_method"),
                confidence_score=entry.get("confidence_score"),
                request_data=entry.get("arguments"),
                response_summary=entry.get("result_summary") or entry.get("reason"),
                request_id=entry.get("request_id"),
            )
            await session.commit()
