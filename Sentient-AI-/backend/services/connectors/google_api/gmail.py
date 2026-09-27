"""Gmail actions of the Google Workspace connector: list, read and search mail,
threads, labels and text attachments, plus send, reply, forward, drafts, label
changes and trash.

Why it exists: the Gmail surface is the largest part of the Google connector;
keeping its MIME parsing, message shaping and composing here keeps
``google_workspace.py`` small. Email bodies are untrusted input, so every body
is capped and passed through PromptGuard before it reaches the model.

External service: the Gmail REST API (https://gmail.googleapis.com/gmail/v1/).
Depends on ``google_api.client`` (GoogleBase, validation), ``google_api.mime``
(MIME parsing and composing), ``base`` (PromptGuard, errors, path_segment) and
``definition`` (ToolSpec).
"""

from __future__ import annotations

import asyncio
import base64
import binascii
import re
from typing import Any, Optional

from services.agent.permissions import ActionCategory
from services.connectors.base import (
    AuthenticationError,
    ConnectorError,
    PromptGuard,
    UserConfirmationRequired,
    path_segment,
)
from services.connectors.definition import ToolSpec, _schema
from services.connectors.shaping import cap_text, clamp_limit

from .client import (
    GMAIL_API,
    GoogleBase,
    as_dict,
    as_list,
    decode_text,
    error_status,
    is_text_like,
    optional_bool,
    optional_offset,
    optional_text,
    require_addresses,
    require_id,
    require_line,
    require_text,
    scalar,
    string_list,
    text_window,
)
from .mime import (
    address_list,
    attachments,
    body_part,
    build_raw,
    decode_part_data,
    extract_body,
    header_map,
    header_safe,
    reply_to_elsewhere,
    walk_parts,
)

# Body characters returned by get_message, and per message in a list or thread.
MESSAGE_BODY_CHARS = 8000
LIST_BODY_CHARS = 1500
# Most recent messages of a thread returned by get_thread.
THREAD_MESSAGES = 20
# Characters of attachment text returned per call.
ATTACHMENT_TEXT_CHARS = 12000
# Attachments larger than this are not downloaded as text.
MAX_ATTACHMENT_BYTES = 5_000_000
# Parallel message fetches when expanding a listing.
_FETCH_CONCURRENCY = 5
_PREVIEW_CHARS = 500
_MESSAGE_ID_RE = re.compile(r"^<[^<>\s]{1,500}>$")
# Gmail MIME part ids look like "0", "1.2", "0.0.1".
_PART_ID_RE = re.compile(r"^[0-9]{1,4}(\.[0-9]{1,4}){0,20}$")
_REPLY_HEADERS = ["Subject", "From", "To", "Cc", "Reply-To", "Message-ID", "References"]
# Who a reply goes to, as the approval card states it.
_REPLY_TARGET = (
    "to the original's Reply-To address, or its From address if it has none "
    "(for mail you sent, to its original To recipients)"
)

_MESSAGE_ID = {"type": "string", "description": "Gmail message id", "required": True}

GMAIL_ACTIONS: tuple[ToolSpec, ...] = (
    ToolSpec(
        "get_messages",
        "List recent Gmail messages, optionally filtered by query.",
        ActionCategory.READ,
        _schema(query={"type": "string"}, max_results={"type": "integer"}),
        policy_key="gmail",
        required_scope="gmail.read",
        starter=True,
    ),
    ToolSpec(
        "get_message",
        "Fetch a single Gmail message by id.",
        ActionCategory.READ,
        # Schema pinned by the legacy catalog (tests/test_connector_registry.py):
        # a long body is paged through get_attachment_text (body_part_id).
        _schema(message_id={"type": "string", "required": True}),
        policy_key="gmail",
        required_scope="gmail.read",
    ),
    ToolSpec(
        "search_emails",
        "Search Gmail messages with a query string.",
        ActionCategory.READ,
        _schema(query={"type": "string", "required": True}),
        policy_key="gmail",
        required_scope="gmail.read",
        starter=True,
    ),
    ToolSpec(
        "send_email",
        "Send an email via Gmail.",
        ActionCategory.WRITE,
        _schema(
            to={"type": "string", "required": True},
            subject={"type": "string", "required": True},
            body={"type": "string", "required": True},
        ),
        policy_key="gmail",
        required_scope="gmail.send",
        # An email leaves the user's account and cannot be recalled, so it
        # gets an approval card under every tier (spec section 4.4).
        always_confirm=True,
    ),
    ToolSpec(
        "get_thread",
        "Read a Gmail conversation (thread) by id: its most recent messages with short bodies.",
        ActionCategory.READ,
        _schema(thread_id={"type": "string", "description": "Gmail thread id", "required": True}),
        policy_key="gmail",
        required_scope="gmail.read",
    ),
    ToolSpec(
        "list_labels",
        "List Gmail labels (id, name, type). Label ids are what modify_labels takes.",
        ActionCategory.READ,
        _schema(limit={"type": "integer", "description": "How many (default 50, max 50)"}),
        policy_key="gmail",
        required_scope="gmail.read",
    ),
    ToolSpec(
        "get_attachment_text",
        "Read a text attachment (txt, csv, json, ...) of a Gmail message. Use the part_id "
        "from get_message's attachments list, or its body_part_id and next_offset to read "
        "on in a long body. Binary files (PDF, images) are refused.",
        ActionCategory.READ,
        _schema(
            message_id=_MESSAGE_ID,
            part_id={"type": "string", "description": "Attachment part_id", "required": True},
            offset={"type": "integer", "description": "Character offset to continue reading"},
        ),
        policy_key="gmail",
        required_scope="gmail.read",
    ),
    ToolSpec(
        "reply",
        "Reply in the same thread to a Gmail message (to its Reply-To address, or its "
        "From address if it has none; everyone else too with reply_all). Reading the "
        "original also needs the gmail.read scope.",
        ActionCategory.WRITE,
        _schema(
            message_id=_MESSAGE_ID,
            body={"type": "string", "description": "Plain-text reply", "required": True},
            reply_all={"type": "boolean", "description": "Also reply to To and Cc recipients"},
        ),
        policy_key="gmail",
        # Replies, forwards and drafts share gmail.compose (Google's "manage
        # drafts and send" scope); gmail.send stays for send_email alone.
        required_scope="gmail.compose",
        always_confirm=True,
    ),
    ToolSpec(
        "forward",
        "Forward a Gmail message's text to new recipients, with an optional note. "
        "Attachments are not forwarded. Reading the original also needs gmail.read.",
        ActionCategory.WRITE,
        _schema(
            message_id=_MESSAGE_ID,
            to={"type": "string", "description": "Recipient address(es)", "required": True},
            note={"type": "string", "description": "Text placed above the forwarded message"},
        ),
        policy_key="gmail",
        required_scope="gmail.compose",
        always_confirm=True,
    ),
    ToolSpec(
        "create_draft",
        "Save a Gmail draft (nothing is sent).",
        ActionCategory.WRITE,
        _schema(
            to={"type": "string", "required": True},
            subject={"type": "string", "required": True},
            body={"type": "string", "required": True},
        ),
        policy_key="gmail",
        required_scope="gmail.compose",
    ),
    ToolSpec(
        "send_draft",
        "Send an existing Gmail draft by its draft id.",
        ActionCategory.WRITE,
        _schema(draft_id={"type": "string", "description": "Gmail draft id", "required": True}),
        policy_key="gmail",
        required_scope="gmail.compose",
        always_confirm=True,
    ),
    ToolSpec(
        "modify_labels",
        "Add or remove labels on a Gmail message (label ids from list_labels, e.g. "
        "UNREAD, STARRED, INBOX to un-archive).",
        ActionCategory.WRITE,
        _schema(
            message_id=_MESSAGE_ID,
            add_label_ids={"type": "array", "items": {"type": "string"}},
            remove_label_ids={"type": "array", "items": {"type": "string"}},
        ),
        policy_key="gmail",
        required_scope="gmail.modify",
    ),
    ToolSpec(
        "trash_message",
        "Move a Gmail message to Trash (Gmail deletes it for good after 30 days).",
        ActionCategory.DELETE,
        _schema(message_id=_MESSAGE_ID),
        policy_key="gmail",
        required_scope="gmail.modify",
        always_confirm=True,
    ),
)


def _preview(text: str) -> str:
    return text if len(text) <= _PREVIEW_CHARS else text[:_PREVIEW_CHARS] + "..."


def _continuation(part: Optional[dict[str, Any]], body_chars: int, shown: int) -> dict[str, Any]:
    """Where a cut body continues: get_message for a short listing body,
    get_attachment_text on the body part for a full get_message body."""
    if body_chars < MESSAGE_BODY_CHARS:
        return {
            "hint": f"Body truncated at {body_chars} characters; call get_message with this id "
            "for more."
        }
    part_id = scalar(as_dict(part).get("partId"))
    if part_id and _PART_ID_RE.match(part_id):
        return {
            "body_part_id": part_id,
            "next_offset": shown,
            "hint": (
                f"Body truncated at {body_chars} characters; call get_attachment_text with "
                f"this message id, part_id='{part_id}' and offset={shown} to read on."
            ),
        }
    # A single-part message keeps its body on the unnamed root part, which
    # get_attachment_text cannot address.
    return {
        "hint": f"Body truncated at {body_chars} characters; open the message in Gmail "
        "for the rest."
    }


class GmailActions(GoogleBase):
    """Gmail action coroutines (mixed into GoogleWorkspaceConnector)."""

    def _shape_message(self, raw: Any, body_chars: int) -> dict[str, Any]:
        """The fields the model needs from a ``format=full`` message.

        A cut listing body points at get_message. A cut get_message body
        points at get_attachment_text on the body's own MIME part (the same
        decoded text, so ``next_offset`` lines up); get_message's schema is
        pinned by the legacy catalog, so it cannot take an offset itself.
        """
        message = as_dict(raw)
        payload = as_dict(message.get("payload"))
        headers = header_map(payload)
        part = body_part(payload)
        body, truncated = cap_text(decode_part_data(part) if part else "", body_chars)
        sanitized_body, _ = PromptGuard.scan(body)
        shaped: dict[str, Any] = {
            "id": scalar(message.get("id")),
            "thread_id": scalar(message.get("threadId")),
            "subject": headers.get("subject", "")[:1000],
            "from": headers.get("from", "")[:1000],
            "to": headers.get("to", "")[:2000],
            "date": headers.get("date", "")[:200],
            "snippet": scalar(message.get("snippet"), 500) or "",
            "body": sanitized_body,
            "label_ids": [x for x in as_list(message.get("labelIds")) if isinstance(x, str)][:50],
        }
        if "cc" in headers:
            shaped["cc"] = headers["cc"][:2000]
        found = attachments(payload)
        if found:
            shaped["attachments"] = found
        if truncated:
            shaped["truncated"] = True
            shaped.update(_continuation(part, body_chars, len(body)))
        return shaped

    async def _fetch_message(self, message_id: str, body_chars: int) -> dict[str, Any]:
        raw = await self._call_object(
            "GET",
            f"{GMAIL_API}/messages/{path_segment(message_id)}",
            params={"format": "full"},
        )
        return self._shape_message(raw, body_chars)

    async def _fetch_many(self, ids: list[str]) -> list[dict[str, Any]]:
        """Fetch message details in parallel (bounded), keeping order."""
        gate = asyncio.Semaphore(_FETCH_CONCURRENCY)

        async def one(message_id: str) -> dict[str, Any]:
            async with gate:
                return await self._fetch_message(message_id, LIST_BODY_CHARS)

        results = await asyncio.gather(*(one(i) for i in ids), return_exceptions=True)
        for result in results:
            if isinstance(result, BaseException):
                raise result
        return [r for r in results if isinstance(r, dict)]

    # -- READ ------------------------------------------------------------------

    async def get_messages(self, query: str = "", max_results: int = 20) -> list[dict[str, Any]]:
        """List Gmail messages matching *query* (Gmail search syntax).

        Gmail's list endpoint returns only ids, so each message is fetched
        (in parallel, a few at a time) with a short body.
        """
        if query is not None and not isinstance(query, str):
            raise ConnectorError("'query' must be a string.")
        params: dict[str, Any] = {"maxResults": clamp_limit(max_results, default=20)}
        if query and query.strip():
            params["q"] = query
        data = await self._call_object("GET", f"{GMAIL_API}/messages", params=params)
        ids = [
            stub["id"]
            for stub in as_list(data.get("messages"))
            if isinstance(stub, dict) and isinstance(stub.get("id"), str) and stub["id"]
        ][: params["maxResults"]]
        return await self._fetch_many(ids)

    async def get_message(self, message_id: str) -> dict[str, Any]:
        """Fetch a single Gmail message by ID with content sanitization."""
        return await self._fetch_message(require_id(message_id, "message_id"), MESSAGE_BODY_CHARS)

    async def search_emails(self, query: str) -> list[dict[str, Any]]:
        """Search Gmail using Gmail search syntax."""
        return await self.get_messages(query=require_text(query, "query", max_chars=2000), max_results=25)

    async def get_thread(self, thread_id: str) -> dict[str, Any]:
        thread = await self._call_object(
            "GET",
            f"{GMAIL_API}/threads/{path_segment(require_id(thread_id, 'thread_id'))}",
            params={"format": "full"},
        )
        messages = [m for m in as_list(thread.get("messages")) if isinstance(m, dict)]
        recent = messages[-THREAD_MESSAGES:]
        result: dict[str, Any] = {
            "id": scalar(thread.get("id")),
            "message_count": len(messages),
            "messages": [self._shape_message(m, LIST_BODY_CHARS) for m in recent],
            "truncated": len(messages) > len(recent),
        }
        if result["truncated"]:
            result["hint"] = (
                f"Only the {THREAD_MESSAGES} most recent messages are shown; call get_message "
                "with an older message id to read it."
            )
        return result

    async def list_labels(self, limit: Any = None) -> list[dict[str, Any]]:
        data = await self._call_object("GET", f"{GMAIL_API}/labels")
        labels = [
            {"id": scalar(item.get("id")), "name": scalar(item.get("name")), "type": scalar(item.get("type"))}
            for item in as_list(data.get("labels"))
            if isinstance(item, dict) and isinstance(item.get("id"), str)
        ]
        # The user's own labels first: system labels are well known.
        labels.sort(key=lambda label: label["type"] != "user")
        return labels[: clamp_limit(limit, default=50)]

    async def get_attachment_text(
        self, message_id: str, part_id: str, offset: Any = None
    ) -> dict[str, Any]:
        """Text of one attachment, refusing binary files.

        The message is read first: Gmail attachment ids change between
        reads, so the part id (stable) selects the attachment and the
        fresh attachment id from this same read downloads it.
        """
        mid = require_id(message_id, "message_id")
        pid = require_id(part_id, "part_id")
        start = optional_offset(offset)
        message = await self._call_object(
            "GET", f"{GMAIL_API}/messages/{path_segment(mid)}", params={"format": "full"}
        )
        part = next(
            (p for p in walk_parts(as_dict(message.get("payload"))) if p.get("partId") == pid),
            None,
        )
        if part is None:
            raise ConnectorError(f"Message {mid} has no part '{pid}'; use get_message to list attachments.")
        filename = scalar(part.get("filename")) or ""
        mime_type = scalar(part.get("mimeType")) or ""
        if not is_text_like(mime_type, filename):
            raise ConnectorError(
                f"Attachment '{filename or pid}' is {mime_type or 'an unknown type'}, not text; "
                "only text attachments can be read."
            )
        body = as_dict(part.get("body"))
        size = body.get("size")
        if isinstance(size, int) and size > MAX_ATTACHMENT_BYTES:
            raise ConnectorError(f"Attachment '{filename}' is too large to read as text.")
        encoded = body.get("data")
        if not isinstance(encoded, str) or not encoded:
            attachment_id = body.get("attachmentId")
            if not isinstance(attachment_id, str) or not attachment_id:
                raise ConnectorError(f"Attachment '{filename or pid}' has no content.")
            fetched = await self._call_object(
                "GET",
                f"{GMAIL_API}/messages/{path_segment(mid)}/attachments/{path_segment(attachment_id)}",
            )
            encoded = fetched.get("data")
            if not isinstance(encoded, str):
                raise ConnectorError(f"Attachment '{filename or pid}' has no content.")
        try:
            raw = base64.urlsafe_b64decode(encoded + "==")
        except (binascii.Error, ValueError):
            raise ConnectorError(f"Attachment '{filename or pid}' could not be decoded.") from None
        text = decode_text(raw[:MAX_ATTACHMENT_BYTES])
        return {
            "message_id": mid,
            "part_id": pid,
            "filename": filename,
            "mime_type": mime_type,
            **text_window(text, start, ATTACHMENT_TEXT_CHARS, action="get_attachment_text"),
        }

    # -- WRITE -----------------------------------------------------------------

    async def send_email(
        self,
        to: str,
        subject: str,
        body: str,
        *,
        user_confirmed: bool = False,
    ) -> dict[str, Any]:
        """Send an email, gated behind explicit user confirmation.

        No Gmail draft is staged for the preview, deliberately: the approval
        flow re-invokes this method with the same arguments plus
        ``user_confirmed=True``, so a draft id minted here could not survive
        the round trip, and on denial nothing would clean it up.
        """
        to = require_addresses(to, "to")
        subject = require_line(subject, "subject")
        body = require_text(body, "body")
        if not user_confirmed:
            raise UserConfirmationRequired(
                action="send_email",
                details=(
                    f"Send email to '{to}' with subject '{subject}'?\n"
                    f"Body:\n{_preview(body)}\n"
                    "Nothing has been created or sent yet; confirm to send."
                ),
            )
        sent = await self._call_object(
            "POST", f"{GMAIL_API}/messages/send", json={"raw": build_raw(to, subject, body)}
        )
        return {
            "status": "sent",
            "message_id": scalar(sent.get("id")),
            "thread_id": scalar(sent.get("threadId")),
        }

    async def _read_original(self, message_id: str, *, fmt: str) -> dict[str, Any]:
        """The message a reply or forward is based on (needs gmail.read)."""
        params: dict[str, Any] = {"format": fmt}
        if fmt == "metadata":
            params["metadataHeaders"] = _REPLY_HEADERS
        try:
            return await self._call_object(
                "GET", f"{GMAIL_API}/messages/{path_segment(message_id)}", params=params
            )
        except AuthenticationError as exc:
            if error_status(exc) != 403:
                raise
            raise AuthenticationError(
                f"{exc} Reading the original message needs the gmail.read scope; "
                "grant it on the Google Workspace connector."
            ) from None

    async def reply(
        self,
        message_id: str,
        body: str,
        reply_all: Optional[bool] = None,
        *,
        user_confirmed: bool = False,
    ) -> dict[str, Any]:
        mid = require_id(message_id, "message_id")
        text = require_text(body, "body")
        everyone = optional_bool(reply_all, "reply_all", False)
        if not user_confirmed:
            # The address is not known before the original is read, and
            # nothing may be requested before approval, so the card states
            # the rule that picks it (the sender controls Reply-To).
            who = _REPLY_TARGET + (", plus every other To and Cc recipient" if everyone else "")
            raise UserConfirmationRequired(
                action="reply",
                details=(
                    f"Reply to Gmail message {mid} in the same thread, sent {who}?\n"
                    f"Body:\n{_preview(text)}\nNothing has been sent yet; confirm to send."
                ),
            )
        original = await self._read_original(mid, fmt="metadata")
        headers = header_map(as_dict(original.get("payload")))
        labels = as_list(original.get("labelIds"))
        own_mail = "SENT" in labels
        primary = headers.get("to") if own_mail else (headers.get("reply-to") or headers.get("from"))
        to_list = address_list(primary)
        if not to_list:
            raise ConnectorError(f"Message {mid} has no address to reply to.")
        cc_list: list[str] = []
        if everyone:
            profile = await self._call_object("GET", f"{GMAIL_API}/profile")
            me = str(profile.get("emailAddress") or "").lower()
            skip = {a.lower() for a in to_list} | {me}
            cc_list = [
                a for a in address_list(headers.get("to"), headers.get("cc")) if a.lower() not in skip
            ]
        subject = header_safe(headers.get("subject", ""), 900)
        if not subject.lower().startswith("re:"):
            subject = f"Re: {subject}".strip()
        extra: dict[str, str] = {}
        original_id = header_safe(headers.get("message-id", ""), 600)
        if _MESSAGE_ID_RE.match(original_id):
            references = header_safe(headers.get("references", ""), 1500)
            extra["In-Reply-To"] = original_id
            extra["References"] = f"{references} {original_id}".strip()
        raw = build_raw(
            ", ".join(to_list), subject, text, cc=", ".join(cc_list) or None, extra_headers=extra
        )
        payload: dict[str, Any] = {"raw": raw}
        thread_id = scalar(original.get("threadId"))
        if thread_id:
            payload["threadId"] = thread_id
        sent = await self._call_object("POST", f"{GMAIL_API}/messages/send", json=payload)
        result: dict[str, Any] = {
            "status": "sent",
            "message_id": scalar(sent.get("id")),
            "thread_id": scalar(sent.get("threadId")),
            "to": to_list,
            "cc": cc_list,
        }
        if not own_mail and reply_to_elsewhere(headers):
            result["warning"] = (
                "The original's Reply-To address is on a different domain than its From "
                "address; the reply went to the Reply-To address listed in 'to'."
            )
        return result

    async def forward(
        self,
        message_id: str,
        to: str,
        note: Optional[str] = None,
        *,
        user_confirmed: bool = False,
    ) -> dict[str, Any]:
        mid = require_id(message_id, "message_id")
        recipients = require_addresses(to, "to")
        intro = optional_text(note, "note") or ""
        if not user_confirmed:
            raise UserConfirmationRequired(
                action="forward",
                details=(
                    f"Forward Gmail message {mid} (its text, without attachments) to "
                    f"'{recipients}'?"
                    + (f"\nNote:\n{_preview(intro)}" if intro else "")
                    + "\nNothing has been sent yet; confirm to send."
                ),
            )
        original = await self._read_original(mid, fmt="full")
        payload = as_dict(original.get("payload"))
        headers = header_map(payload)
        subject = header_safe(headers.get("subject", ""), 900)
        if not subject.lower().startswith(("fwd:", "fw:")):
            subject = f"Fwd: {subject}".strip()
        quoted, _ = cap_text(extract_body(payload), 100_000)
        body = (
            f"{intro}\n\n---------- Forwarded message ---------\n"
            f"From: {header_safe(headers.get('from', ''))}\n"
            f"Date: {header_safe(headers.get('date', ''))}\n"
            f"Subject: {header_safe(headers.get('subject', ''))}\n"
            f"To: {header_safe(headers.get('to', ''))}\n\n{quoted}"
        ).lstrip("\n")
        sent = await self._call_object(
            "POST", f"{GMAIL_API}/messages/send", json={"raw": build_raw(recipients, subject, body)}
        )
        return {
            "status": "sent",
            "message_id": scalar(sent.get("id")),
            "thread_id": scalar(sent.get("threadId")),
            "to": recipients,
        }

    async def create_draft(
        self, to: str, subject: str, body: str, *, user_confirmed: bool = False
    ) -> dict[str, Any]:
        to = require_addresses(to, "to")
        subject = require_line(subject, "subject")
        body = require_text(body, "body")
        if not user_confirmed:
            raise UserConfirmationRequired(
                action="create_draft",
                details=(
                    f"Save a Gmail draft to '{to}' with subject '{subject}' (it is not sent)?\n"
                    f"Body:\n{_preview(body)}"
                ),
            )
        draft = await self._call_object(
            "POST", f"{GMAIL_API}/drafts", json={"message": {"raw": build_raw(to, subject, body)}}
        )
        return {
            "status": "draft_created",
            "draft_id": scalar(draft.get("id")),
            "message_id": scalar(as_dict(draft.get("message")).get("id")),
        }

    async def send_draft(self, draft_id: str, *, user_confirmed: bool = False) -> dict[str, Any]:
        did = require_id(draft_id, "draft_id")
        if not user_confirmed:
            raise UserConfirmationRequired(
                action="send_draft",
                details=f"Send Gmail draft {did} to its recipients now? This cannot be undone.",
            )
        sent = await self._call_object("POST", f"{GMAIL_API}/drafts/send", json={"id": did})
        return {
            "status": "sent",
            "message_id": scalar(sent.get("id")),
            "thread_id": scalar(sent.get("threadId")),
        }

    async def modify_labels(
        self,
        message_id: str,
        add_label_ids: Optional[list[str]] = None,
        remove_label_ids: Optional[list[str]] = None,
        *,
        user_confirmed: bool = False,
    ) -> dict[str, Any]:
        mid = require_id(message_id, "message_id")
        add = string_list(add_label_ids, "add_label_ids")
        remove = string_list(remove_label_ids, "remove_label_ids")
        if not add and not remove:
            raise ConnectorError("Give add_label_ids or remove_label_ids (label ids from list_labels).")
        if not user_confirmed:
            raise UserConfirmationRequired(
                action="modify_labels",
                details=(
                    f"Change labels on Gmail message {mid}: add {add or 'none'}, "
                    f"remove {remove or 'none'}?"
                ),
            )
        result = await self._call_object(
            "POST",
            f"{GMAIL_API}/messages/{path_segment(mid)}/modify",
            json={"addLabelIds": add, "removeLabelIds": remove},
        )
        return {
            "id": scalar(result.get("id")) or mid,
            "label_ids": [x for x in as_list(result.get("labelIds")) if isinstance(x, str)][:50],
        }

    # -- DELETE ----------------------------------------------------------------

    async def trash_message(self, message_id: str, *, user_confirmed: bool = False) -> dict[str, Any]:
        mid = require_id(message_id, "message_id")
        if not user_confirmed:
            raise UserConfirmationRequired(
                action="trash_message",
                details=f"Move Gmail message {mid} to Trash? Gmail deletes it for good after 30 days.",
            )
        await self._call_json("POST", f"{GMAIL_API}/messages/{path_segment(mid)}/trash")
        return {"status": "trashed", "id": mid}
