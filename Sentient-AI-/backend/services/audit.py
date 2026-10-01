"""Writes hash-chained, HMAC-signed rows to the audit_logs table and strips
sensitive values before they are persisted.

Why it exists: Routes, the installation service and the agent runtime all need
tamper-evident audit rows built from one canonical hash payload; a second write
path would break chain verification.

Tamper-evident audit logging service for Crawler AI.

Single write path for the ``audit_logs`` table. Every row is chained to
the previous row in the same user's log via ``previous_hash``, and the
chain link is bound into the row's own keyed (HMAC-SHA256)
``integrity_hash``, so field tampering, row deletion, and reordering are
all detectable. The hash is keyed because an unkeyed digest is only
tamper-evident against accidents: a database-write adversary could
recompute an unkeyed chain and forge history. Rows written before the
HMAC upgrade carry unkeyed hashes; the verifier still validates them but
labels them 'legacy' (see ``scripts/verify_audit_log.py``).

Chain order is the per-user monotonic ``seq`` column, assigned here under
the per-user lock. Timestamps are not a reliable order key (two rows in
the same millisecond sort ambiguously, weakening verification and causing
spurious chain failures), so head selection and verification order by
``seq``.

Four layers live here:

- ``sanitize_request_data`` / ``_sanitize``: strip credentials and other
  sensitive values before anything is persisted; ``redact_tool_arguments``
  keeps only the length of what some tools take (the text desktop.act types,
  the text memory.remember saves).
- ``build_hash_payload`` + ``append_audit_log``: the canonical hash
  payload (shared with ``api/routes/audit.py`` verification and
  ``scripts/verify_audit_log.py``) and the chained insert.
- ``append_auth_event``: the same chain for account-level events —
  sign-ins, failed sign-ins, lockouts, credential changes, deletion.
- ``RuntimeAuditLogger``: adapter implementing the agent runtime's audit
  protocol (``log(entry: dict)``); opens its own short-lived sessions so
  the singleton runtime never holds a request-scoped session.
"""

from __future__ import annotations

import asyncio
import json
import uuid
from typing import Any, Callable, Optional

import structlog
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from core.security import compute_audit_hash
from models.audit import AuditLog, AuditStatus
from models.user import User
from services.security.policies import AUDIT
from services.security.redact import contains, redact_obj

logger = structlog.get_logger(__name__)


# ------------------------------------------------------------------ #
# Sensitive-data sanitizer
# ------------------------------------------------------------------ #

# The token formats and the key-name rule this sanitizer applies live in
# services/security (secrets.RULES and policies.AUDIT_KEY_NAMES), shared with
# memory, the logs, the chat channels, tool arguments and the model request,
# so each format is defined once (backlog F6).


def contains_sensitive_value(text: str) -> bool:
    """True when *text* holds a value ``_sanitize`` would redact: a JWT, an
    API or access key, a card-length number, a stated password, an ID
    number. For a writer that must refuse such a value outright rather than
    store it redacted. A detector error counts as True."""
    return contains(text, AUDIT)


def _sanitize(data: Any) -> Any:
    """Recursively strip sensitive values from data before storage: the
    whole value of a sensitive key name, and every key, token, card, bank
    or ID number inside a string (policy AUDIT; fails closed per string)."""
    return redact_obj(data, AUDIT)


def sanitize_request_data(data: Any) -> str:
    """Sanitize and serialize request data for audit storage."""
    if data is None:
        return "{}"
    sanitized = _sanitize(data)
    try:
        return json.dumps(sanitized, default=str)
    except (TypeError, ValueError):
        return json.dumps({"raw": str(sanitized)})


# Tool arguments an audit row keeps as their length only, by (connector
# type, action). What desktop.act types can be a password (a call aimed at a
# password field is refused, but its row is still written) or a private
# message, and this log is append-only: nothing written here can be taken
# back. The approval store keeps the real text, since an approved call
# needs it to run. browser.act's fill text and fill_form fields are the
# same kind of thing (a message, an address); browser.checkout's arguments
# carry nothing sensitive (the card label on its card is masked, and the
# card itself never leaves the vault). A memory the agent saves is personal
# text the owner can later delete from the Memory page; a copy here could
# never be deleted, so its row keeps the length and category only (the
# memory row has the text).
_LENGTH_ONLY_ARGUMENTS: dict[tuple[str, str], frozenset[str]] = {
    ("desktop", "act"): frozenset({"text"}),
    ("browser", "act"): frozenset({"text", "fields"}),
    ("memory", "remember"): frozenset({"content"}),
    # top10:secret_pii_redaction

    # top10:file_extraction

    # top10:scheduler_briefing
    # A scheduled prompt and a briefing's topic are the owner's own text,
    # kept in the task row they can delete; the log keeps their length.
    ("schedule", "create"): frozenset({"prompt"}),
    ("schedule", "briefing"): frozenset({"topic"}),

    # top10:tutor_mode

    # top10:knowledge_base
    # A note saved to the knowledge base is the user's own text, kept in the
    # knowledge base they can delete; the log keeps its length.
    ("knowledge", "add"): frozenset({"text"}),

    # top10:flashcards_quizzes
    # Card text comes from the user's study material and is kept in the deck
    # they can edit or delete; the log keeps how many items a save held and the
    # length of each edited text field.
    ("study", "save"): frozenset({"items"}),
    ("study", "edit"): frozenset(
        {"title", "course", "front", "back", "choices", "explanation", "choice_notes", "tags"}
    ),

    # top10:event_triggers
    # A trigger's prompt is the owner's own text and its sender and subject
    # filters name people and mail; the trigger row (which they can delete)
    # keeps them, the log keeps their length. A change card's snapshot of the
    # trigger (_trigger) holds the same, so it is not kept at all.
    ("triggers", "create"): frozenset({"prompt", "senders", "subject_contains"}),
    ("triggers", "update"): frozenset({"prompt", "senders", "subject_contains", "_trigger"}),
    ("triggers", "delete"): frozenset({"_trigger"}),

    # top10:permission_tiers

    # top10:voice_notes

    # top10:video_transcripts

}


def _tool_key(tool: str) -> tuple[str, str]:
    """(connector type, action) of a tool name however it was spelled:
    case, stray spaces or dots, and a per-connector ``__slug`` are
    ignored, so a spelling the registry refuses is redacted too."""
    connector, _, action = tool.strip().lower().rpartition(".")
    return connector.split("__", 1)[0].strip(" ."), action.strip()


def _length_marker(value: Any, *, count: bool = False) -> str:
    if count and isinstance(value, list):
        return "<1 item>" if len(value) == 1 else f"<{len(value)} items>"
    if not isinstance(value, str):
        return "***REDACTED***"
    return "<1 character>" if len(value) == 1 else f"<{len(value)} characters>"


# Length-only fields that are lists of records, kept as their item count
# ("<12 items>") rather than hidden outright (top10:flashcards_quizzes:
# study.save's items).
_COUNT_ONLY_ARGUMENTS: dict[tuple[str, str], frozenset[str]] = {
    ("study", "save"): frozenset({"items"}),
}


def redact_tool_arguments(tool: str, arguments: Any) -> Any:
    """*arguments* of a call to *tool* as an audit row stores them: the
    fields in ``_LENGTH_ONLY_ARGUMENTS`` replaced by their length
    (``"<14 characters>"``, or ``"<3 items>"`` for a list in
    ``_COUNT_ONLY_ARGUMENTS``), everything else untouched."""
    key_of_tool = _tool_key(tool)
    fields = _LENGTH_ONLY_ARGUMENTS.get(key_of_tool)
    if not fields or not isinstance(arguments, dict):
        return arguments
    counted = _COUNT_ONLY_ARGUMENTS.get(key_of_tool, frozenset())
    return {
        key: _length_marker(value, count=key in counted) if key in fields else value
        for key, value in arguments.items()
    }


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
    ``seq`` is likewise excluded: the read-only verify route reconstructs
    this payload from stored columns through this same function and predates
    the column, so adding it here would flag every post-upgrade row as
    tampered there. Order integrity does not depend on it — each row pins
    its predecessor's keyed hash, so any reordering breaks a chain link —
    ``seq`` is only the deterministic order key for head selection and
    verification, and the verifier separately flags non-increasing seq.
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


# Fast path only. The asyncio lock keeps concurrent tasks in THIS process
# from piling onto the same database row lock; it is not what makes the
# chain correct. It cannot be: the lock is released when this function
# returns, but the row it wrote is invisible to other sessions until the
# caller commits, so two sessions could still read the same head and assign
# the same seq. The real serialization is the row lock taken below.
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
    and the hash always agree. Request data is first passed through
    ``redact_tool_arguments`` for the tool *connector_name*.*action*, so no
    writer can store the text a desktop.act types.
    """
    user_uuid = user_id if isinstance(user_id, uuid.UUID) else uuid.UUID(str(user_id))
    rid = request_id or str(uuid.uuid4())

    request_data = redact_tool_arguments(f"{connector_name}.{action}", request_data)
    sanitized_request = json.loads(sanitize_request_data(request_data)) if request_data is not None else None
    sanitized_summary = _sanitize(response_summary) if response_summary is not None else None
    # Sanitise once and hash exactly what is stored, so the row and its hash
    # always agree on the reasoning chain.
    sanitized_reasoning = _sanitize(reasoning_chain) if reasoning_chain is not None else None

    lock = await _lock_for_user(str(user_uuid))
    async with lock:
        # Serialize appends for this user AT THE DATABASE, holding the lock
        # until the caller's transaction commits. Without it, two sessions
        # read the same head — an in-process asyncio lock cannot help,
        # because a flushed-but-uncommitted row is invisible to the other
        # session under READ COMMITTED, so both compute the same next seq
        # and fork the chain. That corrupts the tamper-evidence signal with
        # ordinary concurrency, which is worse than useless: the verifier
        # reports failures that have nothing to do with tampering.
        #
        # The USER row is the lock target rather than the chain head: the
        # head does not exist for a user's first append, so there would be
        # nothing to lock exactly when two first-appends race. This also
        # covers multi-worker deployments, which an in-process lock never
        # could. SQLite has no FOR UPDATE — SQLAlchemy omits it there — but
        # SQLite serializes writers anyway, so the guarantee holds on both.
        await db.execute(
            select(User.id).where(User.id == user_uuid).with_for_update()
        )

        # seq is the deterministic order key; timestamp alone is ambiguous
        # within a millisecond. NULLS LAST keeps legacy (pre-seq) rows from
        # shadowing a numbered head; timestamp breaks ties for a chain that
        # is still all-legacy. Only the two columns the chain needs are
        # selected: loading the full ORM row dragged the head's JSON
        # request_data/reasoning_chain and Text response_summary across the
        # wire on every append, inside the per-user critical section.
        prev_result = await db.execute(
            select(AuditLog.integrity_hash, AuditLog.seq)
            .where(AuditLog.user_id == user_uuid)
            .order_by(AuditLog.seq.desc().nullslast(), AuditLog.timestamp.desc())
            .limit(1)
        )
        prev = prev_result.first()
        previous_hash = prev.integrity_hash if prev is not None else None
        # max(seq)+1 under the per-user lock; a legacy head (seq NULL)
        # starts the numbered chain at 1.
        next_seq = 1 if prev is None or prev.seq is None else prev.seq + 1

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
            seq=next_seq,
            request_id=rid,
        )
        db.add(entry)
        await db.flush()
        await db.refresh(entry)
        return entry


# ------------------------------------------------------------------ #
# Authentication events
# ------------------------------------------------------------------ #

# Audit rows for account-level events are filed under this pseudo-connector
# so the UI's connector filter can separate "what the agent did on my
# behalf" from "what happened to my account".
AUTH_CONNECTOR = "auth"


async def append_auth_event(
    db: AsyncSession,
    *,
    user_id: uuid.UUID | str,
    action: str,
    status: AuditStatus,
    endpoint: str,
    reason: Optional[str] = None,
    details: Optional[dict[str, Any]] = None,
    request_id: Optional[str] = None,
) -> AuditLog:
    """Record an authentication or account event in the user's hash chain.

    Who signed in, which attempts failed, when credentials changed, and
    when the account was deleted are the events a compliance reviewer
    reaches for first, and they were the ones this log did not carry: only
    agent tool activity was chained. Putting them in the same chain gives
    them the same property — an adversary with database write access cannot
    quietly remove the failed logins that preceded a successful one without
    breaking the chain.

    Failure events are recorded as ``blocked`` so they read the same way as
    a refused tool call: the platform declined to act.
    """
    return await append_audit_log(
        db,
        user_id=user_id,
        connector_name=AUTH_CONNECTOR,
        action=action,
        endpoint=endpoint,
        scope_used=AUTH_CONNECTOR,
        status=status,
        reasoning_chain={"event": action, **({"reason": reason} if reason else {})},
        request_data=details,
        response_summary=reason,
        request_id=request_id,
    )


# ------------------------------------------------------------------ #
# Runtime adapter
# ------------------------------------------------------------------ #

# Maps runtime event names to the audit row status they should record.
# Anything absent falls back to `blocked` (see the lookup below): an
# unrecognized event is recorded conservatively rather than as a success.
# That default makes it essential to register every new event here —
# `tool_executing`/`tool_approved` record INTENT before a side effect and
# are the fail-closed half of the audit pair, so filing them as "blocked"
# would misreport successful actions as refusals in the audit UI.
_EVENT_STATUS: dict[str, AuditStatus] = {
    "tool_executing": AuditStatus.pending,
    "tool_executed": AuditStatus.approved,
    "tool_approved": AuditStatus.pending,
    "tool_approved_and_executed": AuditStatus.approved,
    "tool_pending_approval": AuditStatus.pending,
    "tool_taint_escalated": AuditStatus.pending,
    "tool_blocked": AuditStatus.blocked,
    # The model named a tool that does not exist: denied by default, so
    # nothing ran, and it was told the right name (not a policy refusal).
    "tool_unknown": AuditStatus.blocked,
    "tool_denied": AuditStatus.blocked,
    "tool_expired": AuditStatus.blocked,
    "input_blocked": AuditStatus.blocked,
    "output_blocked": AuditStatus.blocked,
    # The user's stop ended a turn before it finished (policy user_stopped).
    "turn_stopped": AuditStatus.blocked,
    # The owner allowed an app for a week from an approval card, or ended
    # that approval (services.agent.app_approvals).
    "app_approval_granted": AuditStatus.approved,
    "app_approval_revoked": AuditStatus.approved,
    # top10:secret_pii_redaction
    # Keys, card or ID numbers, or contact details were hidden from the AI
    # provider this turn (services.security.guard.record_hidden): counts only.
    "sensitive_data_hidden": AuditStatus.approved,

    # top10:file_extraction
    # A file a person sent was read and stored, or refused (with its code
    # only; services.files.intake). Never a name or any text.
    "file_uploaded": AuditStatus.approved,
    "file_upload_refused": AuditStatus.blocked,

    # top10:scheduler_briefing

    # top10:tutor_mode
    # Tutor mode changed for a conversation, or an owner lock engaged in
    # one; the owner created or deleted a tutor lock (services/tutor).
    "tutor_mode_changed": AuditStatus.approved,
    "tutor_lock_engaged": AuditStatus.approved,
    "tutor_lock_created": AuditStatus.approved,
    "tutor_lock_deleted": AuditStatus.approved,

    # top10:knowledge_base
    # A document saved from Telegram ("/kb <collection>" on a file): the
    # document id, source kind and counts only, never a title or any text.
    "knowledge_document_added": AuditStatus.approved,

    # top10:flashcards_quizzes

    # top10:event_triggers
    # What the trigger sweeper and the owner's /triggers commands did on
    # their own (services/notifications/event_triggers.py,
    # services/triggers/commands.py): ids, counts and costs only.
    "trigger_fired": AuditStatus.approved,
    "trigger_run": AuditStatus.approved,
    "trigger_suppressed": AuditStatus.blocked,
    "trigger_stopped": AuditStatus.blocked,
    "trigger_paused": AuditStatus.approved,
    "trigger_resumed": AuditStatus.approved,
    "trigger_deleted": AuditStatus.approved,

    # top10:permission_tiers
    # A 7-day low-risk grant was made from a card or taken back, and a
    # connection's or the account's permission tier changed
    # (services.agent.permission_grants).
    "permission_grant_granted": AuditStatus.approved,
    "permission_grant_revoked": AuditStatus.approved,
    "connector_tier_changed": AuditStatus.approved,
    "account_tier_changed": AuditStatus.approved,

    # top10:voice_notes
    # A Telegram voice note was transcribed, or refused before or after its
    # download (services/notifications/voice.py): facts only, never the text.
    "voice_note_transcribed": AuditStatus.approved,
    "voice_note_refused": AuditStatus.blocked,

    # top10:video_transcripts
    # A YouTube video was read by the turn's own AI provider for
    # video.transcript: the window, tokens and estimated cost only.
    "video_provider_read": AuditStatus.approved,

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
        # "rule" names the tool's own hard rule when a call was refused
        # before its approval card (policy computer_rule: blocked_app ...).
        # "approval" is "weekly" on an act a weekly app approval ran, with
        # that approval's id, app, channel and expiry; "tier", "low_risk" or
        # "low_risk_grant" on a call standing consent ran, with its risk
        # grade, the grade's fixed reason and the grant's id (permission
        # tiers), which a permission_grant_granted row also carries with the
        # connection and the kind.
        for key in (
            "reason",
            "policy",
            "rule",
            "action_id",
            "threat_level",
            "approval",
            "app_approval_id",
            "app",
            "channel",
            "expires_at",
            "risk",
            "risk_reason",
            "grant_id",
            "connector_id",
            "kind",
        ):
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
