"""Gmail bodies of the automatic scam check's two READ actions (security S2):
``list_new_message_ids`` (what arrived in the inbox since a cursor) and
``get_message_security`` (a message's authentication results, senders, links
and attachment names).

Why it exists: ``gmail.py`` is shared by every skill, so the scam check's own
parsing lives here, owned by its skill; ``GmailActions`` keeps one-line
delegations that pass itself as *actions* (its ``_call_object`` does the
requests). The answers are built so the sweeper can trust them:

- The cursor is this action's own (``g1:<historyId>`` or
  ``g1:<historyId>:<pageToken>``); anything else is refused, so a value the
  model or a stored row made up never reaches Gmail.
- An empty cursor only records where the mailbox is (no backlog flood), and
  a history id Gmail no longer has starts over the same way (``reset``).
- New mail comes from the history of messages added to the inbox, without
  Sent, Draft, Spam and Trash (the trigger sources' rule), deduplicated, at
  most three pages (300 ids) per call.
- A message Gmail says no longer exists answers ``{"id", "gone": true}``
  instead of an error (review FEA-SF3), so the sweeper can tell "gone" from
  "broken".
- The facts themselves come from ``services/security/mail_facts.py``, which
  turns every script, data or file link into a code before
  ``BaseConnector.execute``'s PromptGuard sees the answer.

Block sender is deferred (owner decision 8a): there is no settings scope and
no write here. ``get_message`` and ``mime.attachments`` are not changed.

Connects to: services/connectors/google_api/gmail.py (the delegations and the
ToolSpecs), services/security/mail_facts.py (the answer's shape),
services/triggers/sources.py (the labels new mail never carries).
"""

from __future__ import annotations

import re
from typing import Any, Optional

from services.connectors.base import ConnectorError, path_segment
from services.security import mail_facts
from services.security.lookalike import CONSUMER_MAIL_DOMAINS
from services.triggers.sources import SKIP_LABELS

from .client import GMAIL_API, as_dict, as_list, error_status, malformed, require_id

CURSOR_PREFIX = "g1"
# A cursor this action made: the history id, plus Gmail's page token while a
# listing continues on the next call.
_CURSOR_RE = re.compile(r"g1:([0-9]{1,20})(?::([A-Za-z0-9_\-.~]{1,512}))?")
_HISTORY_ID_RE = re.compile(r"[0-9]{1,20}")
_PAGE_TOKEN_RE = re.compile(r"[A-Za-z0-9_\-.~]{1,512}")
# Gmail message ids are short hex strings; anything else in a history entry
# is not an id this action passes on.
_MESSAGE_ID_RE = re.compile(r"[A-Za-z0-9_\-]{1,256}")
HISTORY_PAGE_SIZE = 100
MAX_HISTORY_PAGES = 3  # at most 300 ids per call; the rest comes on the next call
REFUSED_CURSOR = "'cursor' is not one this action made."


def _status(exc: BaseException) -> Optional[int]:
    """The HTTP status of a mapped connector error."""
    status = getattr(exc, "status_code", None)
    return status if isinstance(status, int) else error_status(exc)


def _parse_cursor(cursor: Any) -> Optional[tuple[str, str]]:
    """(history id, page token or "") of a cursor this action made; None for
    the empty cursor. Anything else raises ConnectorError."""
    if cursor is None or cursor == "":
        return None
    if not isinstance(cursor, str):
        raise ConnectorError(REFUSED_CURSOR)
    match = _CURSOR_RE.fullmatch(cursor)
    if match is None:
        raise ConnectorError(REFUSED_CURSOR)
    return match.group(1), match.group(2) or ""


def _history_id(value: Any) -> str:
    """Gmail's history id (a decimal string); a malformed reply otherwise."""
    if isinstance(value, int) and not isinstance(value, bool) and value >= 0:
        value = str(value)
    if not isinstance(value, str) or not _HISTORY_ID_RE.fullmatch(value):
        raise malformed()
    return value


def _account_domain(email_address: Any) -> Optional[str]:
    """The mailbox's own domain, or None for a consumer domain (gmail.com is
    nobody's organisation) or an address that cannot be read."""
    _, address = mail_facts.address_parts(email_address if isinstance(email_address, str) else "")
    domain = address.rpartition("@")[2] if "@" in address else ""
    if not domain or domain in CONSUMER_MAIL_DOMAINS:
        return None
    return domain


async def _baseline(actions: Any, *, reset: bool) -> dict[str, Any]:
    """Where the mailbox is now: the profile's history id, and no mail."""
    profile = await actions._call_object("GET", f"{GMAIL_API}/profile")
    return {
        "cursor": f"{CURSOR_PREFIX}:{_history_id(profile.get('historyId'))}",
        "message_ids": [],
        "baseline": True,
        "reset": reset,
        "more": False,
        "account_domain": _account_domain(profile.get("emailAddress")),
    }


def _added_ids(page: dict[str, Any], seen: set[str], out: list[str]) -> None:
    """Appends the ids of messages added to the inbox on one history page,
    in order, skipping mail labelled Sent, Draft, Spam or Trash and ids
    already listed."""
    for record in as_list(page.get("history")):
        for added in as_list(as_dict(record).get("messagesAdded")):
            message = as_dict(as_dict(added).get("message"))
            message_id = message.get("id")
            if not isinstance(message_id, str) or not _MESSAGE_ID_RE.fullmatch(message_id):
                continue
            labels = {label for label in as_list(message.get("labelIds")) if isinstance(label, str)}
            if labels & SKIP_LABELS or message_id in seen:
                continue
            seen.add(message_id)
            out.append(message_id)


async def list_new_message_ids(actions: Any, cursor: str = "") -> dict[str, Any]:
    """Ids of mail newly added to the inbox since *cursor* (an empty cursor
    answers the current position only).

    Answer: ``{"cursor", "message_ids" (<= 300), "baseline", "reset",
    "more", "account_domain"}``. ``more`` is True when Gmail has another
    page; the cursor then continues that page."""
    parsed = _parse_cursor(cursor)
    if parsed is None:
        return await _baseline(actions, reset=False)
    start, page_token = parsed
    seen: set[str] = set()
    ids: list[str] = []
    latest = start
    for _ in range(MAX_HISTORY_PAGES):
        params: dict[str, Any] = {
            "startHistoryId": start,
            "historyTypes": "messageAdded",
            "labelId": "INBOX",
            "maxResults": HISTORY_PAGE_SIZE,
        }
        if page_token:
            params["pageToken"] = page_token
        try:
            page = await actions._call_object("GET", f"{GMAIL_API}/history", params=params)
        except ConnectorError as exc:
            # Gmail keeps history for about a week; an older id is a 404. The
            # check starts over from where the mailbox is now.
            if _status(exc) != 404:
                raise
            return await _baseline(actions, reset=True)
        _added_ids(page, seen, ids)
        latest = _history_id(page.get("historyId", latest))
        next_token = page.get("nextPageToken")
        if not next_token:
            return {
                "cursor": f"{CURSOR_PREFIX}:{latest}",
                "message_ids": ids,
                "baseline": False,
                "reset": False,
                "more": False,
                "account_domain": None,
            }
        if not isinstance(next_token, str) or not _PAGE_TOKEN_RE.fullmatch(next_token):
            # A token this action could not hand back would lose the rest of
            # the listing, so the call fails and the next check retries.
            raise malformed()
        page_token = next_token
    return {
        "cursor": f"{CURSOR_PREFIX}:{start}:{page_token}",
        "message_ids": ids,
        "baseline": False,
        "reset": False,
        "more": True,
        "account_domain": None,
    }


async def get_message_security(actions: Any, message_id: str) -> dict[str, Any]:
    """One message's security facts (services/security/mail_facts.py), or
    ``{"id", "gone": true}`` when the message no longer exists."""
    mid = require_id(message_id, "message_id")
    try:
        raw = await actions._call_object(
            "GET",
            f"{GMAIL_API}/messages/{path_segment(mid)}",
            params={"format": "full"},
        )
    except ConnectorError as exc:
        if _status(exc) != 404:
            raise
        return mail_facts.gone_answer(mid)
    return mail_facts.facts_from_gmail(raw)
