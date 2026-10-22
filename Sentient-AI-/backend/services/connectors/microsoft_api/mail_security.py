"""Outlook bodies of the automatic scam check's two READ actions (security S2):
``list_new_message_ids`` (what arrived in the inbox since a delta cursor) and
``get_message_security`` (a message's authentication results, senders, links
and attachment names).

Why it exists: ``mail.py`` is shared by every skill, so the scam check's own
parsing lives here, owned by its skill; ``MailActions`` keeps one-line
delegations that pass itself as *actions* (its Graph helpers do the
requests). The answers are built so the sweeper can trust them:

- The cursor is this action's own (``o1:d:<deltatoken>`` or
  ``o1:s:<skiptoken>``); anything else is refused.
- An empty cursor only records where the inbox is: a delta round over the
  last five minutes, followed to its delta link, with no ids (no backlog
  flood). A delta token Graph no longer knows starts over the same way
  (``reset``).
- Graph's next and delta links are never followed as given: each must be
  https on graph.microsoft.com, on the inbox's delta path, with exactly one
  token parameter, and the request is rebuilt from that token alone.
- A message Graph says no longer exists answers ``{"id", "gone": true}``
  instead of an error (review FEA-SF3).
- ``get_message_security`` asks for the HTML body (no text preference), so
  the links' real destinations survive, and for the internet headers, so the
  provider's own Authentication-Results can be read.

Block sender is deferred (owner decision 8a): there is no settings scope and
no write here.

Connects to: services/connectors/microsoft_api/mail.py (the delegations and
the ToolSpecs), services/security/mail_facts.py (the answer's shape).
"""

from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone
from typing import Any, Optional
from urllib.parse import unquote, urlsplit

from services.connectors.base import ConnectorError, path_segment
from services.security import mail_facts

from .common import GRAPH_HOST, ME, json_object, malformed, require_id

CURSOR_PREFIX = "o1"
_TOKEN_CHARS = r"[A-Za-z0-9_\-.~%]{1,4000}"
_CURSOR_RE = re.compile(r"o1:([ds]):(" + _TOKEN_CHARS + ")")
_TOKEN_RE = re.compile(_TOKEN_CHARS)
# The inbox's delta path as Graph writes it in its links: the well-known
# name, or the folder in OData key form (mailfolders('inbox') or the folder's
# id). Matched without regard to case on the decoded path.
_DELTA_PATH_RE = re.compile(
    r"/v1\.0/me/mailfolders(?:/inbox|\('[A-Za-z0-9_\-=+.]{1,512}'\))/messages/delta",
    re.IGNORECASE,
)
_TOKEN_PARAMS = {"$deltatoken": "d", "$skiptoken": "s"}
_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]")
DELTA_PATH = "/mailFolders/inbox/messages/delta"
PAGE_SIZE = 50
# A baseline follows its pages to the delta link; a listing reads at most
# six pages (300 ids) and continues on the next call.
MAX_BASELINE_PAGES = 10
MAX_LIST_PAGES = 6
MAX_IDS = 300
BASELINE_WINDOW = timedelta(minutes=5)
MAX_ATTACHMENTS = mail_facts.MAX_ATTACHMENTS
REFUSED_CURSOR = "'cursor' is not one this action made."
REFUSED_LINK = "Microsoft 365 answered with a paging link this check does not follow."
_RESET_CODES = frozenset({"syncstatenotfound"})
_PREFER_PAGES = {"Prefer": f"odata.maxpagesize={PAGE_SIZE}"}
# The message fields the facts need: the internet headers (absent on mail
# sent inside the organisation), the senders, the HTML body, and the A7 keys
# for S1 (recipients, thread, folder).
_SECURITY_FIELDS = (
    "id,internetMessageHeaders,from,sender,replyTo,toRecipients,ccRecipients,subject,"
    "receivedDateTime,hasAttachments,body,parentFolderId,conversationId"
)
_ATTACHMENT_FIELDS = "id,name,contentType,size,isInline"


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _parse_cursor(cursor: Any) -> Optional[tuple[str, str]]:
    """("d" or "s", token) of a cursor this action made; None for the empty
    cursor. Anything else raises ConnectorError."""
    if cursor is None or cursor == "":
        return None
    if not isinstance(cursor, str):
        raise ConnectorError(REFUSED_CURSOR)
    match = _CURSOR_RE.fullmatch(cursor)
    if match is None:
        raise ConnectorError(REFUSED_CURSOR)
    return match.group(1), match.group(2)


def _delta_url(kind: str, token: str) -> str:
    """The delta request rebuilt from a token alone (never from Graph's
    link). The token is used exactly as Graph wrote it, already
    percent-encoded."""
    name = "$deltatoken" if kind == "d" else "$skiptoken"
    return f"{ME}{DELTA_PATH}?{name}={token}"


def _link_token(actions: Any, link: Any, kind: str) -> str:
    """The token of a next link (*kind* "s") or delta link ("d") Graph
    returned, when the link is one this action follows: https on
    graph.microsoft.com's default port, no user info, the inbox's delta
    path, and exactly one query parameter carrying a token of that kind.
    Anything else raises ConnectorError (logged by host and path only)."""
    if not isinstance(link, str) or len(link) > 8192:
        raise ConnectorError(REFUSED_LINK)
    try:
        parsed = urlsplit(link)
        port = parsed.port
    except ValueError:
        raise ConnectorError(REFUSED_LINK) from None
    pieces = parsed.query.split("&")
    key, _, token = pieces[0].partition("=")
    if (
        parsed.scheme != "https"
        or (parsed.hostname or "").lower() != GRAPH_HOST
        or port not in (None, 443)
        or parsed.username is not None
        or parsed.password is not None
        or parsed.fragment
        or not _DELTA_PATH_RE.fullmatch(unquote(parsed.path))
        or len(pieces) != 1
        or _TOKEN_PARAMS.get(unquote(key).lower()) != kind
        or not _TOKEN_RE.fullmatch(token)
    ):
        log = getattr(actions, "_log", None)
        if log is not None:
            log.warning("mail_security_link_refused", host=parsed.hostname, path=parsed.path[:200])
        raise ConnectorError(REFUSED_LINK)
    return token


async def _delta_page(actions: Any, url: str, params: Optional[dict[str, Any]] = None) -> dict[str, Any]:
    data = await actions._request_json("GET", url, params=params, headers=dict(_PREFER_PAGES))
    page = json_object(data)
    if not isinstance(page.get("value"), list):
        raise malformed()
    return page


def _is_reset(exc: ConnectorError) -> bool:
    """Graph forgot the delta state: a 410, or its syncStateNotFound code."""
    code = getattr(exc, "vendor_code", None)
    return getattr(exc, "status_code", None) == 410 or (
        isinstance(code, str) and code.lower() in _RESET_CODES
    )


async def _baseline(actions: Any, *, reset: bool) -> dict[str, Any]:
    """Where the inbox is now: one delta round over the last five minutes,
    followed to its delta link, and no mail."""
    since = (_utc_now() - BASELINE_WINDOW).strftime("%Y-%m-%dT%H:%M:%SZ")
    page = await _delta_page(
        actions,
        f"{ME}{DELTA_PATH}",
        {"$select": "id,receivedDateTime", "$filter": f"receivedDateTime ge {since}"},
    )
    for _ in range(MAX_BASELINE_PAGES):
        if page.get("@odata.deltaLink"):
            token = _link_token(actions, page["@odata.deltaLink"], "d")
            return _answer(f"{CURSOR_PREFIX}:d:{token}", [], baseline=True, reset=reset, more=False)
        if not page.get("@odata.nextLink"):
            raise malformed()
        token = _link_token(actions, page["@odata.nextLink"], "s")
        page = await _delta_page(actions, _delta_url("s", token))
    # Still paging after ten pages: the next call continues from here (the
    # mail on those pages arrived during the baseline's five minutes).
    if page.get("@odata.deltaLink"):
        token = _link_token(actions, page["@odata.deltaLink"], "d")
        return _answer(f"{CURSOR_PREFIX}:d:{token}", [], baseline=True, reset=reset, more=False)
    token = _link_token(actions, page.get("@odata.nextLink"), "s")
    return _answer(f"{CURSOR_PREFIX}:s:{token}", [], baseline=True, reset=reset, more=True)


def _answer(cursor: str, ids: list[str], *, baseline: bool, reset: bool, more: bool) -> dict[str, Any]:
    # The Microsoft connector asks for no User.Read, so the mailbox's own
    # domain is not known here.
    return {
        "cursor": cursor,
        "message_ids": ids,
        "baseline": baseline,
        "reset": reset,
        "more": more,
        "account_domain": None,
    }


def _page_ids(page: dict[str, Any], seen: set[str], out: list[str]) -> None:
    """Appends the ids of one delta page in order: an item Graph marks
    @removed, one without a usable id, and an id already listed are
    skipped."""
    for item in page["value"]:
        if not isinstance(item, dict) or "@removed" in item:
            continue
        message_id = item.get("id")
        if (
            not isinstance(message_id, str)
            or not message_id
            or len(message_id) > 1024
            or _CONTROL_RE.search(message_id)
            or message_id in seen
        ):
            continue
        seen.add(message_id)
        out.append(message_id)


async def list_new_message_ids(actions: Any, cursor: str = "") -> dict[str, Any]:
    """Ids of mail newly added to the inbox since *cursor* (an empty cursor
    answers a new baseline only).

    Answer: ``{"cursor", "message_ids" (<= 300), "baseline", "reset",
    "more", "account_domain"}``; ``more`` is True when Graph has another
    page, and the cursor then continues it."""
    parsed = _parse_cursor(cursor)
    if parsed is None:
        return await _baseline(actions, reset=False)
    kind, token = parsed
    seen: set[str] = set()
    ids: list[str] = []
    for _ in range(MAX_LIST_PAGES):
        try:
            page = await _delta_page(actions, _delta_url(kind, token))
        except ConnectorError as exc:
            if not _is_reset(exc):
                raise
            return await _baseline(actions, reset=True)
        _page_ids(page, seen, ids)
        if page.get("@odata.deltaLink"):
            token = _link_token(actions, page["@odata.deltaLink"], "d")
            return _answer(f"{CURSOR_PREFIX}:d:{token}", _capped(ids), baseline=False, reset=False, more=False)
        if not page.get("@odata.nextLink"):
            raise malformed()
        kind, token = "s", _link_token(actions, page["@odata.nextLink"], "s")
        if len(ids) >= MAX_IDS:
            break
    return _answer(f"{CURSOR_PREFIX}:s:{token}", _capped(ids), baseline=False, reset=False, more=True)


def _capped(ids: list[str]) -> list[str]:
    """At most MAX_IDS ids. Six pages of fifty never pass it; when Graph
    ignores the page size, the cursor has already moved past the page, so
    the last ids listed (the newest changes) are the ones kept, as the
    sweeper keeps the newest pending mail (review SEC-F7)."""
    return ids[-MAX_IDS:]


def _is_gone(exc: ConnectorError) -> bool:
    """The message no longer exists: a 404, or Graph's ErrorItemNotFound."""
    code = getattr(exc, "vendor_code", None)
    return getattr(exc, "status_code", None) == 404 or code == "ErrorItemNotFound"


async def _sent_items_id(actions: Any) -> str:
    """The Sent Items folder's id, or "" when it cannot be read (the facts
    then say the message was not sent by the mailbox)."""
    try:
        folder = await actions._graph_object("GET", "/mailFolders/sentitems", params={"$select": "id"})
    except ConnectorError:
        return ""
    folder_id = folder.get("id")
    return folder_id if isinstance(folder_id, str) else ""


async def get_message_security(actions: Any, message_id: str) -> dict[str, Any]:
    """One message's security facts (services/security/mail_facts.py), or
    ``{"id", "gone": true}`` when the message no longer exists."""
    mid = require_id(message_id, "message_id")
    path = f"/messages/{path_segment(mid)}"
    try:
        # No text-body preference: the HTML keeps each link's real address.
        message = await actions._graph_object("GET", path, params={"$select": _SECURITY_FIELDS})
        attachments: list[dict[str, Any]] = []
        if message.get("hasAttachments") is True:
            attachments = await actions._graph_list(
                f"{path}/attachments",
                {"$select": _ATTACHMENT_FIELDS, "$top": MAX_ATTACHMENTS},
                limit=MAX_ATTACHMENTS,
            )
    except ConnectorError as exc:
        if not _is_gone(exc):
            raise
        return mail_facts.gone_answer(mid)
    # Scaffold A7: sent_by_me means the message sits in Sent Items, whose id
    # Graph only gives through its well-known name. The scan itself lists the
    # inbox, so any other message reads as inbox mail.
    parent = message.get("parentFolderId")
    sent_by_me = False
    if isinstance(parent, str) and parent:
        sent_by_me = parent == await _sent_items_id(actions)
    return mail_facts.facts_from_graph(
        message,
        attachments,
        sent_by_me=sent_by_me,
        folder="sent" if sent_by_me else "inbox",
    )
