"""The purchase ledger: what Crawler spent in the last 24 hours, and the
audit rows every purchase event writes (purchases spec §6).

Why over the audit log and not a table of its own: the daily cap must
survive a restart and be as tamper-evident as the rest of what Crawler
did, and ``audit_logs`` already is (hash-chained, append-only, written
through one sanctioned path). A purchase is a handful of rows a day, so
the 24-hour sum is done in Python over every row where the card was
sent: completed, waiting on a person after the submit (3-D Secure), or
submitted with no confirmation Crawler could read. Money may have moved
on each of those, so each counts against the cap; only a purchase the
merchant declined, or one refused before the card left the vault, does
not. An approval whose outcome never reached the log (the process died
after the card was filled, or the outcome's write failed) counts too:
the approval row is written before the card leaves the vault, and a
checkout counts once, by its outcome row or, until one exists, by its
approval. A row carries the merchant, the amount, how many item lines
and the checkout it belongs to: never a card number, a brand, a last4 or
a label, so the append-only log can never become a card record.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone
from decimal import Decimal, InvalidOperation
from typing import Any, Callable, Optional

import structlog
from sqlalchemy import select

from models.audit import AuditLog, AuditStatus
from services.audit import append_audit_log
from services.tools.browser.checkout.amounts import fmt_usd

logger = structlog.get_logger(__name__)

CONNECTOR = "purchases"
PURCHASE_EVENTS: tuple[str, ...] = (
    "purchase_requested",
    "purchase_approved",
    "purchase_completed",
    "purchase_refused",
    "purchase_pending_human",
)
# The status each event is filed under: money moved (or was cleared to)
# is approved, a card still on its way is pending, a refusal is blocked.
_STATUS: dict[str, AuditStatus] = {
    "purchase_requested": AuditStatus.pending,
    "purchase_approved": AuditStatus.approved,
    "purchase_completed": AuditStatus.approved,
    "purchase_refused": AuditStatus.blocked,
    "purchase_pending_human": AuditStatus.pending,
}
WINDOW = timedelta(hours=24)
# What counts as spent: every event after which the card had been sent.
# A refusal counts only for the reasons recorded after a submit whose
# outcome Crawler could not read: no confirmation it recognised, a button
# that failed after the fill, or a submit the network guard stopped (the
# guard cannot always tell whether the merchant read the card before the
# stop, so it counts). Never ``declined``, never a rule that stopped the
# checkout before the card was filled.
_SPENT_EVENTS: frozenset[str] = frozenset({"purchase_completed", "purchase_pending_human"})
_SPENT_REFUSAL_REASONS: frozenset[str] = frozenset({"no_confirmation", "submit_failed", "submit_blocked"})
# The rows that settle an approval: whatever happened to that checkout
# after Approve. Until one is on the record the approval itself counts.
_OUTCOME_EVENTS: tuple[str, ...] = ("purchase_completed", "purchase_refused", "purchase_pending_human")
_MERCHANT_CHARS = 200
_REASON_CHARS = 300


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _amount_of(request_data: Any) -> Optional[Decimal]:
    if not isinstance(request_data, dict):
        return None
    raw = request_data.get("amount_usd")
    if raw is None or isinstance(raw, bool):
        return None
    try:
        amount = Decimal(str(raw))
    except InvalidOperation:
        return None
    return amount if amount.is_finite() and amount >= 0 else None


def _checkout_key(request_data: Any) -> Optional[tuple[str, str]]:
    """Which checkout a row belongs to: its checkout id, or, for a row
    written without one, its task (an approval there is settled by the
    next outcome row of the same task, in the order the rows were
    written). None when the row names neither."""
    if not isinstance(request_data, dict):
        return None
    for kind in ("checkout_id", "task_id"):
        value = request_data.get(kind)
        if isinstance(value, str) and value:
            return kind, value
    return None


def _sent_before_refusal(reasoning: Any) -> bool:
    """Was the card already on its way when this refusal was recorded?"""
    if not isinstance(reasoning, dict):
        return False
    return str(reasoning.get("reason") or "") in _SPENT_REFUSAL_REASONS


class PurchaseLedger:
    def __init__(
        self, session_factory: Callable[[], Any], *, now: Callable[[], datetime] = _utcnow
    ) -> None:
        self._session_factory = session_factory
        self._now = now

    async def spent_last_24h(self, user_id: str) -> Decimal:
        """The USD sum of *user_id*'s purchases of the last 24 hours on
        which the card was, or may have been, sent: completed, pending a
        person, refused after the submit for ``no_confirmation``/
        ``submit_failed``/``submit_blocked``, and approved with no outcome
        on the record yet (fail closed). A checkout counts once: its
        approval is settled by its outcome row (same ``checkout_id``), and
        from then on only the outcome can count. Rows whose amount cannot
        be read count as nothing rather than failing the cap check, but an
        unreadable user id raises: the caller must not treat "unknown" as
        "nothing spent"."""
        user_uuid = uuid.UUID(str(user_id))
        since = self._now() - WINDOW
        async with self._session_factory() as session:
            rows = (
                await session.execute(
                    select(
                        AuditLog.timestamp, AuditLog.request_data, AuditLog.action,
                        AuditLog.reasoning_chain,
                    )
                    .where(
                        AuditLog.user_id == user_uuid,
                        AuditLog.connector_name == CONNECTOR,
                        AuditLog.action.in_(["purchase_approved", *_OUTCOME_EVENTS]),
                    )
                    .order_by(AuditLog.seq, AuditLog.timestamp)
                )
            ).all()
        counted: list[tuple[Optional[datetime], Any]] = []  # (when, request_data) of each row that counts
        unsettled: dict[tuple[str, str], tuple[Optional[datetime], Any]] = {}
        for stamp, data, action, reasoning in rows:
            key = _checkout_key(data)
            if action == "purchase_approved":
                if key is None:
                    counted.append((stamp, data))
                    continue
                earlier = unsettled.pop(key, None)
                if earlier is not None:  # an earlier approval of the task that no outcome followed
                    counted.append(earlier)
                unsettled[key] = (stamp, data)
                continue
            if key is not None:
                unsettled.pop(key, None)
            if action in _SPENT_EVENTS or (action == "purchase_refused" and _sent_before_refusal(reasoning)):
                counted.append((stamp, data))
        counted.extend(unsettled.values())
        total = Decimal("0")
        for stamp, data in counted:
            if stamp is None:
                continue
            if stamp.tzinfo is None:
                stamp = stamp.replace(tzinfo=timezone.utc)  # SQLite stores naive UTC
            if stamp < since:
                continue
            amount = _amount_of(data)
            if amount is not None:
                total += amount
        return total

    async def record(
        self,
        user_id: str,
        event: str,
        *,
        merchant: str,
        amount_usd: Optional[Decimal],
        currency: str,
        items: int,
        task_id: str,
        action_id: Optional[str] = None,
        reason: Optional[str] = None,
        checkout_id: Optional[str] = None,
    ) -> None:
        """Append one purchase row. Only the facts of the purchase go in:
        the host, the amount as ``"23.40"``, the currency, the number of
        item lines, the task and the checkout (the random id its approval
        card carries, which pairs an approval with its outcome);
        ``reason`` names a rule or a failure in the toolkit's words, never
        page text."""
        if event not in PURCHASE_EVENTS:
            raise ValueError(f"unknown purchase event {event!r}")
        request_data: dict[str, Any] = {
            "merchant": str(merchant)[:_MERCHANT_CHARS],
            "amount_usd": fmt_usd(amount_usd) if amount_usd is not None else None,
            "currency": str(currency)[:8],
            "items": int(items),
            "task_id": str(task_id)[:120],
        }
        if action_id:
            request_data["action_id"] = str(action_id)[:120]
        if checkout_id:
            request_data["checkout_id"] = str(checkout_id)[:120]
        reasoning: dict[str, Any] = {"event": event}
        if reason:
            reasoning["reason"] = str(reason)[:_REASON_CHARS]
        async with self._session_factory() as session:
            await append_audit_log(
                session,
                user_id=str(user_id),
                connector_name=CONNECTOR,
                action=event,
                endpoint=f"agent.{event}",
                scope_used=CONNECTOR,
                status=_STATUS[event],
                reasoning_chain=reasoning,
                request_data=request_data,
                response_summary=str(reason)[:_REASON_CHARS] if reason else None,
            )
            await session.commit()
        logger.info(
            "purchase_event",
            purchase_event=event,
            merchant=request_data["merchant"],
            amount_usd=request_data["amount_usd"],
            items=request_data["items"],
        )
