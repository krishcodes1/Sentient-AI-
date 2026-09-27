"""Outlook mail actions of the Microsoft 365 connector: list, search and read
messages and text attachments, list folders, send, reply, forward, draft,
move, flag and delete.

Why it exists: spec section 5.5 (Mail row). Kept apart from the other
Microsoft areas so each module stays small; ``services/connectors/microsoft.py``
mixes ``MailActions`` into ``MicrosoftConnector`` and lists ``MAIL_ACTIONS``
in its ``DEFINITION``.
Talks to Microsoft Graph ``/v1.0/me/messages``, ``/me/mailFolders`` and
``/me/sendMail``. Depends on ``common.py`` (validation, shaping, paging),
``services/connectors/base.py`` (errors, ``path_segment``) and
``services/connectors/definition.py``.
"""

from __future__ import annotations

from typing import Any, Optional

from services.agent.permissions import ActionCategory

from ..base import ConnectorError, UserConfirmationRequired, path_segment
from ..definition import ToolSpec, _schema
from ..shaping import clamp_limit
from .common import (
    MAX_LONG_TEXT,
    PREFER_TEXT_BODY,
    GraphBase,
    address_of,
    addresses_of,
    capped_text,
    choice,
    decode_text,
    email_list,
    is_text_like,
    optional_bool,
    optional_text,
    recipients,
    require_id,
    require_text,
    search_phrase,
    sub,
    text_of,
)

# Longest message body returned by get_message.
MAX_BODY_CHARS = 8000
# Longest attachment text returned by get_attachment_text.
MAX_ATTACHMENT_CHARS = 20_000
# Larger attachments are refused before download.
MAX_ATTACHMENT_BYTES = 2_000_000
_PREVIEW_CHARS = 300
_SUBJECT_IN_PROMPT = 200

_SUMMARY_FIELDS = "id,subject,from,receivedDateTime,isRead,hasAttachments,bodyPreview,flag"
_MESSAGE_FIELDS = (
    "id,subject,from,toRecipients,ccRecipients,receivedDateTime,sentDateTime,"
    "body,hasAttachments,conversationId,isRead,flag,webLink"
)
_ATTACHMENT_FIELDS = "id,name,contentType,size,isInline"
_FILE_ATTACHMENT = "#microsoft.graph.fileAttachment"
_FLAG_STATES = ("flagged", "complete", "notFlagged")

_LIMIT = {"type": "integer", "description": "How many (default 10, max 50)"}
_MESSAGE_ID = {"type": "string", "description": "Message id from list_messages or search_messages", "required": True}
_ADDRESSES = {"type": "array", "items": {"type": "string"}}

MAIL_ACTIONS: tuple[ToolSpec, ...] = (
    ToolSpec(
        "list_messages",
        "List recent Outlook messages in a folder (default inbox), newest first: sender, subject, date, preview.",
        ActionCategory.READ,
        _schema(
            folder={
                "type": "string",
                "description": "Folder id or well-known name: inbox (default), sentitems, drafts, archive, deleteditems, junkemail",
            },
            unread_only={"type": "boolean", "description": "Only unread messages (default false)"},
            limit=_LIMIT,
        ),
        required_scope="mail.read",
        starter=True,
    ),
    ToolSpec(
        "search_messages",
        "Search Outlook mail across folders by words, sender or subject (KQL such as from:ann or subject:invoice).",
        ActionCategory.READ,
        _schema(
            query={"type": "string", "description": "Search text", "required": True},
            limit=_LIMIT,
        ),
        required_scope="mail.read",
        starter=True,
    ),
    ToolSpec(
        "get_message",
        "Read one Outlook message as plain text, with recipients and attachment names. Long bodies are truncated.",
        ActionCategory.READ,
        _schema(message_id=_MESSAGE_ID),
        required_scope="mail.read",
    ),
    ToolSpec(
        "get_attachment_text",
        "Read a text attachment (txt, csv, json, md, html...) of an Outlook message. Binary files are refused.",
        ActionCategory.READ,
        _schema(
            message_id=_MESSAGE_ID,
            attachment_id={"type": "string", "description": "Attachment id from get_message", "required": True},
        ),
        required_scope="mail.read",
    ),
    ToolSpec(
        "list_folders",
        "List the Outlook mail folders with their unread and total counts.",
        ActionCategory.READ,
        _schema(limit=_LIMIT),
        required_scope="mail.read",
    ),
    ToolSpec(
        "send_mail",
        "Send a new email from the user's Outlook account. Always asks the user first.",
        ActionCategory.WRITE,
        _schema(
            to={**_ADDRESSES, "description": "Recipient email addresses", "required": True},
            subject={"type": "string", "required": True},
            body={"type": "string", "description": "Plain-text body", "required": True},
            cc={**_ADDRESSES, "description": "Cc email addresses"},
            bcc={**_ADDRESSES, "description": "Bcc email addresses"},
        ),
        required_scope="mail.send",
        always_confirm=True,
    ),
    ToolSpec(
        "reply",
        "Reply to an Outlook message (optionally to all recipients). Always asks the user first.",
        ActionCategory.WRITE,
        _schema(
            message_id=_MESSAGE_ID,
            comment={"type": "string", "description": "Plain-text reply", "required": True},
            reply_all={"type": "boolean", "description": "Reply to everyone on the thread (default false)"},
        ),
        required_scope="mail.send",
        always_confirm=True,
    ),
    ToolSpec(
        "forward",
        "Forward an Outlook message to new recipients with an optional note. Always asks the user first.",
        ActionCategory.WRITE,
        _schema(
            message_id=_MESSAGE_ID,
            to={**_ADDRESSES, "description": "Recipient email addresses", "required": True},
            comment={"type": "string", "description": "Optional plain-text note above the forwarded message"},
        ),
        required_scope="mail.send",
        always_confirm=True,
    ),
    ToolSpec(
        "create_draft",
        "Save a new email as a draft in Outlook (nothing is sent).",
        ActionCategory.WRITE,
        _schema(
            subject={"type": "string", "required": True},
            body={"type": "string", "description": "Plain-text body", "required": True},
            to={**_ADDRESSES, "description": "Recipient email addresses"},
            cc={**_ADDRESSES, "description": "Cc email addresses"},
        ),
        required_scope="mail.write",
    ),
    ToolSpec(
        "move_message",
        "Move an Outlook message to another folder (folder id or well-known name such as archive).",
        ActionCategory.WRITE,
        _schema(
            message_id=_MESSAGE_ID,
            destination_folder={"type": "string", "description": "Folder id or well-known name", "required": True},
        ),
        required_scope="mail.write",
    ),
    ToolSpec(
        "flag_message",
        "Flag an Outlook message for follow-up, mark the flag complete, or clear it.",
        ActionCategory.WRITE,
        _schema(
            message_id=_MESSAGE_ID,
            status={"type": "string", "enum": list(_FLAG_STATES), "description": "Default flagged"},
        ),
        required_scope="mail.write",
    ),
    ToolSpec(
        "delete_message",
        "Delete an Outlook message. Always asks the user first.",
        ActionCategory.DELETE,
        _schema(message_id=_MESSAGE_ID),
        required_scope="mail.write",
        always_confirm=True,
    ),
)


def _flag_of(message: dict[str, Any]) -> Optional[str]:
    return text_of(sub(message, "flag").get("flagStatus"), 32)


def _message_summary(message: dict[str, Any]) -> dict[str, Any]:
    preview = text_of(message.get("bodyPreview"), _PREVIEW_CHARS)
    return {
        "id": text_of(message.get("id")),
        "subject": text_of(message.get("subject")),
        "from": address_of(message.get("from")),
        "received": text_of(message.get("receivedDateTime"), 64),
        "is_read": message.get("isRead") if isinstance(message.get("isRead"), bool) else None,
        "has_attachments": message.get("hasAttachments") is True,
        "flag": _flag_of(message),
        "preview": preview or "",
    }


def _attachment_summary(attachment: dict[str, Any]) -> dict[str, Any]:
    size = attachment.get("size")
    return {
        "id": text_of(attachment.get("id")),
        "name": text_of(attachment.get("name"), 300),
        "content_type": text_of(attachment.get("contentType"), 200),
        "size": size if isinstance(size, int) and not isinstance(size, bool) else None,
        "is_inline": attachment.get("isInline") is True,
    }


def _subject_for_prompt(subject: str) -> str:
    return subject if len(subject) <= _SUBJECT_IN_PROMPT else subject[:_SUBJECT_IN_PROMPT] + "..."


def _message_path(message_id: str) -> str:
    return f"/messages/{path_segment(message_id)}"


class MailActions(GraphBase):
    """Outlook mail action coroutines (mixed into ``MicrosoftConnector``)."""

    # -- READ -------------------------------------------------------------

    async def list_messages(
        self, folder: Any = None, unread_only: Any = None, limit: Any = None
    ) -> list[dict[str, Any]]:
        folder_id = require_id(folder, "folder") if folder not in (None, "") else "inbox"
        unread = optional_bool(unread_only, "unread_only", default=False)
        top = clamp_limit(limit)
        params: dict[str, Any] = {
            "$top": top,
            "$select": _SUMMARY_FIELDS,
            "$orderby": "receivedDateTime desc",
        }
        if unread:
            # Graph wants the $orderby property in the $filter too, first.
            params["$filter"] = "receivedDateTime ge 1900-01-01T00:00:00Z and isRead eq false"
        items = await self._graph_list(
            f"/mailFolders/{path_segment(folder_id)}/messages", params, limit=top
        )
        return [_message_summary(item) for item in items]

    async def search_messages(self, query: Any, limit: Any = None) -> list[dict[str, Any]]:
        text = require_text(query, "query", max_chars=500)
        top = clamp_limit(limit)
        # $search cannot be combined with $orderby; Graph sorts by date.
        params = {"$search": search_phrase(text), "$top": top, "$select": _SUMMARY_FIELDS}
        items = await self._graph_list("/messages", params, limit=top)
        return [_message_summary(item) for item in items]

    async def get_message(self, message_id: Any) -> dict[str, Any]:
        mid = require_id(message_id, "message_id")
        message = await self._graph_object(
            "GET",
            _message_path(mid),
            params={"$select": _MESSAGE_FIELDS},
            headers=PREFER_TEXT_BODY,
        )
        body = capped_text(
            sub(message, "body").get("content"),
            MAX_BODY_CHARS,
            hint="Body truncated; open the message in Outlook (web_link) to read the rest.",
        )
        result: dict[str, Any] = {
            "id": text_of(message.get("id")),
            "subject": text_of(message.get("subject")),
            "from": address_of(message.get("from")),
            "to": addresses_of(message.get("toRecipients")),
            "cc": addresses_of(message.get("ccRecipients")),
            "received": text_of(message.get("receivedDateTime"), 64),
            "is_read": message.get("isRead") if isinstance(message.get("isRead"), bool) else None,
            "flag": _flag_of(message),
            "conversation_id": text_of(message.get("conversationId")),
            "web_link": text_of(message.get("webLink"), 2048),
            "body": body["text"],
            "truncated": body["truncated"],
            "attachments": [],
        }
        if "hint" in body:
            result["hint"] = body["hint"]
        if message.get("hasAttachments") is True:
            # Names and ids only (no content): get_attachment_text reads one.
            attachments = await self._graph_list(
                f"{_message_path(mid)}/attachments",
                {"$select": _ATTACHMENT_FIELDS},
                limit=50,
            )
            result["attachments"] = [_attachment_summary(item) for item in attachments]
        return result

    async def get_attachment_text(self, message_id: Any, attachment_id: Any) -> dict[str, Any]:
        mid = require_id(message_id, "message_id")
        aid = require_id(attachment_id, "attachment_id")
        path = f"{_message_path(mid)}/attachments/{path_segment(aid)}"
        meta = await self._graph_object("GET", path, params={"$select": _ATTACHMENT_FIELDS})
        info = _attachment_summary(meta)
        kind = meta.get("@odata.type")
        if kind is not None and kind != _FILE_ATTACHMENT:
            raise ConnectorError("That attachment is an attached item or link, not a file; it cannot be read as text.")
        if not is_text_like(info["name"], info["content_type"]):
            raise ConnectorError(
                f"Attachment '{info['name'] or aid}' is not a text file "
                f"({info['content_type'] or 'unknown type'}); only text attachments can be read."
            )
        if info["size"] is not None and info["size"] > MAX_ATTACHMENT_BYTES:
            raise ConnectorError(
                f"Attachment '{info['name']}' is too large to read ({info['size']} bytes, "
                f"limit {MAX_ATTACHMENT_BYTES})."
            )
        response = await self._graph_response("GET", f"{path}/$value")
        raw = response.content[: MAX_ATTACHMENT_BYTES + 1]
        text = capped_text(
            decode_text(raw, what=f"Attachment '{info['name'] or aid}'"),
            MAX_ATTACHMENT_CHARS,
            hint="Attachment text truncated; open it in Outlook to read the rest.",
        )
        return {
            "message_id": mid,
            "attachment_id": aid,
            "name": info["name"],
            "content_type": info["content_type"],
            "size": info["size"],
            **text,
        }

    async def list_folders(self, limit: Any = None) -> list[dict[str, Any]]:
        top = clamp_limit(limit)
        params = {
            "$top": top,
            "$select": "id,displayName,unreadItemCount,totalItemCount,childFolderCount",
        }
        items = await self._graph_list("/mailFolders", params, limit=top)
        return [
            {
                "id": text_of(item.get("id")),
                "name": text_of(item.get("displayName")),
                "unread": _count(item.get("unreadItemCount")),
                "total": _count(item.get("totalItemCount")),
                "child_folders": _count(item.get("childFolderCount")),
            }
            for item in items
        ]

    # -- WRITE (send-like actions are always_confirm) ----------------------

    async def send_mail(
        self,
        to: Any,
        subject: Any,
        body: Any,
        cc: Any = None,
        bcc: Any = None,
        *,
        user_confirmed: bool = False,
    ) -> dict[str, Any]:
        to_list = email_list(to, "to", required=True)
        cc_list = email_list(cc, "cc", required=False)
        bcc_list = email_list(bcc, "bcc", required=False)
        title = require_text(subject, "subject", max_chars=998)
        text = _long_text(body, "body", required=True)
        if not user_confirmed:
            copies = "".join(
                f", {label} {', '.join(values)}"
                for label, values in (("cc", cc_list), ("bcc", bcc_list))
                if values
            )
            raise UserConfirmationRequired(
                action="send_mail",
                details=(
                    f"Send an email from your Microsoft 365 account to {', '.join(to_list)}"
                    f"{copies} with subject '{_subject_for_prompt(title)}'."
                ),
            )
        message: dict[str, Any] = {
            "subject": title,
            "body": {"contentType": "Text", "content": text},
            "toRecipients": recipients(to_list),
        }
        if cc_list:
            message["ccRecipients"] = recipients(cc_list)
        if bcc_list:
            message["bccRecipients"] = recipients(bcc_list)
        await self._graph("POST", "/sendMail", json={"message": message, "saveToSentItems": True})
        return {"sent": True, "to": to_list, "cc": cc_list, "bcc": bcc_list, "subject": title}

    async def reply(
        self,
        message_id: Any,
        comment: Any,
        reply_all: Any = None,
        *,
        user_confirmed: bool = False,
    ) -> dict[str, Any]:
        mid = require_id(message_id, "message_id")
        text = _long_text(comment, "comment", required=True)
        everyone = optional_bool(reply_all, "reply_all", default=False)
        if not user_confirmed:
            who = "everyone on" if everyone else "the sender of"
            raise UserConfirmationRequired(
                action="reply",
                details=f"Send a reply from your Microsoft 365 account to {who} message {mid}.",
            )
        verb = "replyAll" if everyone else "reply"
        await self._graph("POST", f"{_message_path(mid)}/{verb}", json={"comment": text})
        return {"sent": True, "message_id": mid, "reply_all": everyone}

    async def forward(
        self,
        message_id: Any,
        to: Any,
        comment: Any = None,
        *,
        user_confirmed: bool = False,
    ) -> dict[str, Any]:
        mid = require_id(message_id, "message_id")
        to_list = email_list(to, "to", required=True)
        note = _long_text(comment, "comment", required=False)
        if not user_confirmed:
            raise UserConfirmationRequired(
                action="forward",
                details=(
                    f"Forward message {mid} from your Microsoft 365 account to "
                    f"{', '.join(to_list)}."
                ),
            )
        payload: dict[str, Any] = {"toRecipients": recipients(to_list)}
        if note:
            payload["comment"] = note
        await self._graph("POST", f"{_message_path(mid)}/forward", json=payload)
        return {"sent": True, "message_id": mid, "to": to_list}

    async def create_draft(
        self,
        subject: Any,
        body: Any,
        to: Any = None,
        cc: Any = None,
        *,
        user_confirmed: bool = False,
    ) -> dict[str, Any]:
        title = require_text(subject, "subject", max_chars=998)
        text = _long_text(body, "body", required=True)
        to_list = email_list(to, "to", required=False)
        cc_list = email_list(cc, "cc", required=False)
        if not user_confirmed:
            addressed = f" addressed to {', '.join(to_list)}" if to_list else ""
            raise UserConfirmationRequired(
                action="create_draft",
                details=(
                    f"Save a draft email '{_subject_for_prompt(title)}'{addressed} in your "
                    "Outlook Drafts folder (it is not sent)."
                ),
            )
        payload: dict[str, Any] = {
            "subject": title,
            "body": {"contentType": "Text", "content": text},
        }
        if to_list:
            payload["toRecipients"] = recipients(to_list)
        if cc_list:
            payload["ccRecipients"] = recipients(cc_list)
        draft = await self._graph_object("POST", "/messages", json=payload)
        return {
            "id": text_of(draft.get("id")),
            "subject": text_of(draft.get("subject")) or title,
            "web_link": text_of(draft.get("webLink"), 2048),
            "draft": True,
        }

    async def move_message(
        self, message_id: Any, destination_folder: Any, *, user_confirmed: bool = False
    ) -> dict[str, Any]:
        mid = require_id(message_id, "message_id")
        destination = require_id(destination_folder, "destination_folder")
        if not user_confirmed:
            raise UserConfirmationRequired(
                action="move_message",
                details=f"Move Outlook message {mid} to the folder '{destination}'.",
            )
        moved = await self._graph_object(
            "POST", f"{_message_path(mid)}/move", json={"destinationId": destination}
        )
        # Graph gives the moved message a new id.
        return {"moved": True, "id": text_of(moved.get("id")), "destination_folder": destination}

    async def flag_message(
        self, message_id: Any, status: Any = None, *, user_confirmed: bool = False
    ) -> dict[str, Any]:
        mid = require_id(message_id, "message_id")
        state = choice(status, "status", _FLAG_STATES, default="flagged")
        if not user_confirmed:
            raise UserConfirmationRequired(
                action="flag_message",
                details=f"Set the follow-up flag of Outlook message {mid} to '{state}'.",
            )
        updated = await self._graph_object(
            "PATCH", _message_path(mid), json={"flag": {"flagStatus": state}}
        )
        return {"id": text_of(updated.get("id")) or mid, "flag": _flag_of(updated) or state}

    # -- DELETE --------------------------------------------------------------

    async def delete_message(
        self, message_id: Any, *, user_confirmed: bool = False
    ) -> dict[str, Any]:
        mid = require_id(message_id, "message_id")
        if not user_confirmed:
            raise UserConfirmationRequired(
                action="delete_message",
                details=f"Delete Outlook message {mid} from your mailbox.",
            )
        await self._graph_response("DELETE", _message_path(mid))
        return {"deleted": True, "id": mid}



def _count(value: Any) -> Optional[int]:
    return value if isinstance(value, int) and not isinstance(value, bool) else None


def _long_text(value: Any, field: str, *, required: bool) -> str:
    """A body or comment: required ones must be non-empty; capped in size."""
    if required:
        require_text(value, field, max_chars=MAX_LONG_TEXT)
        return str(value)
    return optional_text(value, field, max_chars=MAX_LONG_TEXT) or ""


__all__ = ["MAIL_ACTIONS", "MailActions"]
