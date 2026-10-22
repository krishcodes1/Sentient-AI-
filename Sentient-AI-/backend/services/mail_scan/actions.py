"""Mail alert actions (security S2): the approval card a flagged email can
get (Move to Spam/Junk), whether an alert offers it, and the account export
of a user's findings.

Why it exists: every action on a mail goes through an approval card
(decisions 1). A card is parked with ``AgentRuntime.park_card`` (scaffold
A13, D9), so it gets the same permission check, secret guard, precheck,
bind, call checks and ``tool_pending_approval`` row as a turn's card, and
approving it runs the one call and never resumes a turn (origin
``mailcheck:<finding id>``). The card names a real pinned catalog tool on
the account the mail came from: Gmail ``modify_labels`` (add SPAM, remove
INBOX) or Outlook ``move_message`` to ``junkemail``. Both are graded HIGH
by their own risk checks, so no card ever offers standing consent. Its
arguments are ASCII ids and fixed label names only, so the approve-time
PromptGuard re-scan has nothing an attacker wrote to read.

Block sender is not offered in this wave (owner decision 8a: it needs new
OAuth scopes and a re-consent; docs/BACKLOG.md F9). ``ACTION_KINDS`` holds
the one action there is.

The export lists what Crawler concluded about each flagged message (its
verdict, levels, signal codes, display facts and the review), never the
provider's message reference, attachment references or the review input.

Connects to: api/routes/auth.py (``mail_export``),
services/notifications/mail_scan.py (plans and cards),
services/agent/runtime.py (``park_card``), services/mail_scan/messages.py.
"""

from __future__ import annotations

import re
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Mapping, Optional, Sequence, Union

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from services.mail_scan import ORIGIN_PREFIX, PROVIDER_OF
from services.mail_scan import messages as text

CARD_TTL_MINUTES = 1440
MOVE_TO_SPAM = "move_to_spam"
ACTION_KINDS: tuple[str, ...] = (MOVE_TO_SPAM,)
NOT_OFFERED = "That action is not offered for mail alerts."
BAD_REFERENCE = "This email's reference cannot be used for a card."
# A provider message id as the card may carry it: printable ASCII with no
# space, quote or backslash (Gmail ids are hex, Graph ids URL-safe base64).
_MESSAGE_REF_RE = re.compile(r"[A-Za-z0-9!#$%&*+\-./:;=?@^_`{|}~]{1,255}")

# The action each connector type moves mail to Spam/Junk with, its scope
# (the executor's authoritative check uses the same), and its arguments.
_MOVE_ACTION: Mapping[str, tuple[str, str]] = {
    "google_workspace": ("modify_labels", "gmail.modify"),
    "microsoft": ("move_message", "mail.write"),
}


@dataclass(frozen=True)
class CardPlan:
    kind: str
    tool_name: str  # "<type>__<slug>.<action>", as sources.tool_name builds it
    arguments: dict[str, Any]
    reason: str


def valid_message_ref(value: Any) -> bool:
    return isinstance(value, str) and _MESSAGE_REF_RE.fullmatch(value) is not None


def _has_scope(granted_scopes: Optional[Sequence[str]], scope: str) -> bool:
    # A legacy row with no scopes may only READ (tool_registry._check_scope),
    # so it cannot move mail either.
    return bool(granted_scopes) and scope in (granted_scopes or ())


def offered(
    display: Mapping[str, Any], *, connector_type: str, granted_scopes: Optional[Sequence[str]]
) -> tuple[list[str], Optional[str]]:
    """(kinds offered now, hint for the first one that is not): Move to
    Spam/Junk when the account may change mail, else the sentence saying how
    to allow it."""
    move = _MOVE_ACTION.get(connector_type)
    provider = PROVIDER_OF.get(connector_type, "gmail")
    if move is None:
        return [], NOT_OFFERED
    if not _has_scope(granted_scopes, move[1]):
        return [], text.missing_scope_hint(provider)
    return [MOVE_TO_SPAM], None


def plan_card(
    kind: str,
    *,
    connector_type: str,
    connector_id: str,
    granted_scopes: Optional[Sequence[str]],
    message_ref: str,
    display: Mapping[str, Any],
) -> Union[CardPlan, str]:
    """A card plan, or the sentence saying why this action is not offered
    (an unknown kind, the scope is missing, the reference is unusable)."""
    if kind not in ACTION_KINDS or connector_type not in _MOVE_ACTION:
        return NOT_OFFERED
    kinds, hint = offered(display, connector_type=connector_type, granted_scopes=granted_scopes)
    if kind not in kinds:
        return hint or NOT_OFFERED
    if not valid_message_ref(message_ref):
        return BAD_REFERENCE
    from services.triggers.sources import tool_name

    action, _scope = _MOVE_ACTION[connector_type]
    provider = PROVIDER_OF[connector_type]
    if connector_type == "google_workspace":
        arguments: dict[str, Any] = {
            "message_id": message_ref,
            "add_label_ids": ["SPAM"],
            "remove_label_ids": ["INBOX"],
        }
    else:
        arguments = {"message_id": message_ref, "destination_folder": "junkemail"}
    return CardPlan(
        kind=kind,
        tool_name=tool_name(connector_type, str(connector_id), action),
        arguments=arguments,
        reason=text.card_reason(kind, provider),
    )


async def create_card(
    runtime: Any,
    *,
    user_id: str,
    finding_id: str,
    plan: CardPlan,
    security_note: Mapping[str, str],
) -> Any:
    """``runtime.park_card(...)`` with the mailcheck origin, a day to answer,
    the fixed reason and risk note and the finding's security note (scaffold
    A13, D9). Returns the ``StoredAction``, or the ``PrecheckRefusal`` that
    means no card was made (the tab offers the button again). Raises what
    park_card raises."""
    return await runtime.park_card(
        user_id=str(user_id),
        tool_name=plan.tool_name,
        arguments=dict(plan.arguments),
        origin=f"{ORIGIN_PREFIX}{finding_id}",
        ttl_minutes=CARD_TTL_MINUTES,
        reason=plan.reason,
        risk_note=text.card_note(),
        security_notes=[dict(security_note)],
    )


def _iso(moment: Optional[datetime]) -> Optional[str]:
    if moment is None:
        return None
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=timezone.utc)
    return moment.astimezone(timezone.utc).isoformat()


def _export_facts(facts: Any) -> Optional[dict[str, Any]]:
    """The display facts without provider references (attachment refs, the
    file-check refs the sweeper keeps for S10)."""
    if not isinstance(facts, Mapping):
        return None
    shaped = {k: v for k, v in facts.items() if k != "check_files"}
    attachments = shaped.get("attachments")
    if isinstance(attachments, list):
        shaped["attachments"] = [
            {k: v for k, v in a.items() if k != "ref"} for a in attachments if isinstance(a, Mapping)
        ]
    return shaped


async def mail_export(db: AsyncSession, user_id: uuid.UUID) -> list[dict[str, Any]]:
    """The account export's "mail_scam_findings" section: each finding's
    verdict, levels, signal codes, facts and review (never the message
    reference, attachment references or the review input)."""
    from models.mail_security import MailScamFinding

    rows = (
        (
            await db.execute(
                select(MailScamFinding)
                .where(MailScamFinding.user_id == user_id)
                .order_by(MailScamFinding.detected_at, MailScamFinding.id)
            )
        )
        .scalars()
        .all()
    )
    return [
        {
            "id": str(row.id),
            "provider": row.provider,
            "verdict": row.verdict,
            "local_level": row.local_level,
            "score": row.score,
            "signals": list(row.signals or []),
            "facts": _export_facts(row.facts),
            "review": dict(row.review) if isinstance(row.review, Mapping) else None,
            "review_note": row.review_note,
            "detected_at": _iso(row.detected_at),
            "received_at": _iso(row.received_at),
            "alerted_at": _iso(row.alerted_at),
            "dismissed_at": _iso(row.dismissed_at),
            "status": row.status,
        }
        for row in rows
    ]
