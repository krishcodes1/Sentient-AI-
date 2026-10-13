"""WRITE and DELETE actions of the Slack connector: posting, replying, scheduling,
reactions, text file uploads, status, channel creation, invites, message
deletion and channel archiving.

Why it exists: keeps ``services/connectors/slack.py`` small.
``WRITE_ACTIONS`` declares the tools and ``SlackWritesMixin`` holds one
coroutine per action. Every method takes keyword-only ``user_confirmed`` and
raises ``UserConfirmationRequired`` before any request. Every message goes
through ONE choke point (``_send_chat``) that forces ``unfurl_links`` and
``unfurl_media`` off, so Slack never fetches a URL the model put in a message.

External service: the Slack Web API (chat.*, reactions.add, files upload,
users.profile.set, conversations.*) and the upload host files.slack.com.
Depends on ``slack_api.client`` and ``services.connectors.base``.
"""

from __future__ import annotations

import json
import re
import time
from datetime import datetime, timezone
from typing import Any, Literal

import httpx

from services.agent.permissions import ActionCategory
from services.connectors.base import ConnectorError, UserConfirmationRequired
from services.connectors.definition import ToolSpec, _schema

from .client import (
    FILE_ID_RE,
    MAX_MESSAGE_CHARS,
    UPLOAD_HOST,
    UPLOAD_PATH_PREFIX,
    SlackBase,
    channel_id,
    message_ts,
    optional_bool,
    optional_text,
    optional_ts,
    preview,
    require_text,
    scalars,
    shape_channel,
)
from .client import user_id as parse_user_id

_CHANNEL = {
    "type": "string",
    "description": "Channel id such as C0123ABCD (from list_channels)",
    "required": True,
}
_TEXT = {"type": "string", "description": "Message text (Slack mrkdwn)", "required": True}
_TS = {"type": "string", "description": "ts of the message", "required": True}

WRITE_ACTIONS: tuple[ToolSpec, ...] = (
    ToolSpec(
        "post_message",
        "Post a message to a channel as the Crawler app. Link previews are always off.",
        ActionCategory.WRITE,
        _schema(channel=_CHANNEL, text=_TEXT),
        required_scope="messages.send",
        always_confirm=True,
    ),
    ToolSpec(
        "reply_in_thread",
        "Reply in a message's thread as the Crawler app.",
        ActionCategory.WRITE,
        _schema(
            channel=_CHANNEL,
            thread_ts={
                "type": "string",
                "description": "ts of the parent message",
                "required": True,
            },
            text=_TEXT,
            also_send_to_channel={
                "type": "boolean",
                "description": "Also show the reply in the channel (default false)",
            },
        ),
        required_scope="messages.send",
        always_confirm=True,
    ),
    ToolSpec(
        "add_reaction",
        "Add an emoji reaction to a message.",
        ActionCategory.WRITE,
        _schema(
            channel=_CHANNEL,
            ts=_TS,
            name={"type": "string", "description": "Emoji name, e.g. thumbsup", "required": True},
        ),
        required_scope="reactions.write",
    ),
    ToolSpec(
        "upload_file",
        "Upload a text file (up to 1 MB) and share it in a channel.",
        ActionCategory.WRITE,
        _schema(
            channel=_CHANNEL,
            filename={
                "type": "string",
                "description": "File name, e.g. notes.md",
                "required": True,
            },
            content={"type": "string", "description": "The file's text", "required": True},
            title={"type": "string", "description": "Title shown in Slack"},
            thread_ts={"type": "string", "description": "Share in this message's thread"},
        ),
        required_scope="files.write",
        always_confirm=True,
    ),
    ToolSpec(
        "set_status",
        "Set or clear the user's Slack status (empty text clears it). Needs the user token.",
        ActionCategory.WRITE,
        _schema(
            text={"type": "string", "description": "Status text (empty clears)", "required": True},
            emoji={"type": "string", "description": "Emoji, e.g. :palm_tree:"},
            expires_in_minutes={"type": "integer", "description": "Clear it after this long"},
        ),
        required_scope="status.write",
    ),
    ToolSpec(
        "create_channel",
        "Create a channel (lowercase letters, numbers, - and _).",
        ActionCategory.WRITE,
        _schema(
            name={"type": "string", "description": "Channel name", "required": True},
            is_private={"type": "boolean", "description": "Private channel (default false)"},
        ),
        required_scope="channels.write",
    ),
    ToolSpec(
        "invite_to_channel",
        "Invite members (user ids) to a channel.",
        ActionCategory.WRITE,
        _schema(
            channel=_CHANNEL,
            users={
                "type": "array",
                "items": {"type": "string"},
                "description": "User ids such as U0123ABCD (at most 30)",
                "required": True,
            },
        ),
        required_scope="channels.write",
        # Other people are added and told: it speaks for the user.
        always_confirm=True,
    ),
    ToolSpec(
        "schedule_message",
        "Schedule a message to a channel for a future time (unix seconds, within 120 days).",
        ActionCategory.WRITE,
        _schema(
            channel=_CHANNEL,
            text=_TEXT,
            post_at={"type": "integer", "description": "Unix time to post at", "required": True},
            thread_ts={"type": "string", "description": "Post as a reply in this thread"},
        ),
        required_scope="messages.send",
        always_confirm=True,
    ),
    ToolSpec(
        "delete_message",
        "Delete a message the Crawler app posted. Cannot be undone.",
        ActionCategory.DELETE,
        _schema(channel=_CHANNEL, ts=_TS),
        required_scope="messages.write",
        always_confirm=True,
    ),
    ToolSpec(
        "archive_channel",
        "Archive a channel. Members lose it from their sidebar.",
        ActionCategory.DELETE,
        _schema(channel=_CHANNEL),
        required_scope="channels.write",
        always_confirm=True,
    ),
)

MAX_UPLOAD_BYTES = 1_000_000
MAX_INVITES = 30
MAX_SCHEDULE_AHEAD_S = 120 * 24 * 3600
MAX_STATUS_MINUTES = 60 * 24 * 365
_EMOJI_RE = re.compile(r"^[a-z0-9_+'-]{1,100}$")
_CHANNEL_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,79}$")
_BAD_FILENAME_CHARS = re.compile(r"[\\/\x00-\x1f]")

ChatMethod = Literal["chat.postMessage", "chat.scheduleMessage"]


def _emoji_name(value: Any, name: str) -> str:
    text = require_text(name, value, max_chars=102).strip(":")
    if not _EMOJI_RE.fullmatch(text):
        raise ConnectorError(f"{name} must be an emoji name such as thumbsup.")
    return text


def _whole_number(name: str, value: Any) -> int:
    if isinstance(value, bool) or not isinstance(value, (int, float, str)):
        raise ConnectorError(f"{name} must be a whole number.")
    try:
        number = float(value)
    except ValueError:
        raise ConnectorError(f"{name} must be a whole number.") from None
    if number != number or number in (float("inf"), float("-inf")) or number != int(number):
        raise ConnectorError(f"{name} must be a whole number.")
    return int(number)


def _utc_label(epoch_s: int) -> str:
    """A unix time as a human readable UTC time for approval texts."""
    return f"{datetime.fromtimestamp(epoch_s, timezone.utc):%Y-%m-%d %H:%M} UTC"


class SlackWritesMixin(SlackBase):
    """The WRITE and DELETE actions (one public coroutine per ``WRITE_ACTIONS`` entry)."""

    async def _send_chat(
        self, method: ChatMethod, body: dict[str, Any], action: str
    ) -> dict[str, Any]:
        """The ONE place messages are sent. Link and media unfurling are forced
        off whatever *body* says, so Slack never fetches a URL the model wrote."""
        return await self._call(
            method,
            http="POST",
            json_body={**body, "unfurl_links": False, "unfurl_media": False},
            action=action,
        )

    async def _post_json(
        self, method: str, body: dict[str, Any], action: str, **kw: Any
    ) -> dict[str, Any]:
        return await self._call(method, http="POST", json_body=body, action=action, **kw)

    async def post_message(
        self, channel: Any, text: Any, *, user_confirmed: bool = False
    ) -> dict[str, Any]:
        target = channel_id(channel)
        body = require_text("text", text, max_chars=MAX_MESSAGE_CHARS)
        if not user_confirmed:
            raise UserConfirmationRequired(
                action="post_message",
                details=f'Post this message to Slack channel {target}: "{preview(body)}"',
            )
        data = await self._send_chat(
            "chat.postMessage", {"channel": target, "text": body}, "post_message"
        )
        return {**scalars(data, "channel", "ts"), "posted": True}

    async def reply_in_thread(
        self,
        channel: Any,
        thread_ts: Any,
        text: Any,
        also_send_to_channel: Any = None,
        *,
        user_confirmed: bool = False,
    ) -> dict[str, Any]:
        target = channel_id(channel)
        parent = message_ts(thread_ts, "thread_ts")
        body = require_text("text", text, max_chars=MAX_MESSAGE_CHARS)
        broadcast = optional_bool("also_send_to_channel", also_send_to_channel)
        if not user_confirmed:
            where = " and also to the channel" if broadcast else ""
            raise UserConfirmationRequired(
                action="reply_in_thread",
                details=(
                    f"Reply in the thread {parent} of Slack channel {target}{where}: "
                    f'"{preview(body)}"'
                ),
            )
        data = await self._send_chat(
            "chat.postMessage",
            {"channel": target, "thread_ts": parent, "text": body, "reply_broadcast": broadcast},
            "reply_in_thread",
        )
        return {**scalars(data, "channel", "ts"), "thread_ts": parent, "posted": True}

    async def schedule_message(
        self,
        channel: Any,
        text: Any,
        post_at: Any,
        thread_ts: Any = None,
        *,
        user_confirmed: bool = False,
    ) -> dict[str, Any]:
        target = channel_id(channel)
        body = require_text("text", text, max_chars=MAX_MESSAGE_CHARS)
        when = _whole_number("post_at", post_at)
        now = int(time.time())
        if not now < when <= now + MAX_SCHEDULE_AHEAD_S:
            raise ConnectorError("post_at must be a future unix time within 120 days.")
        parent = optional_ts(thread_ts, "thread_ts")
        if not user_confirmed:
            in_thread = f" (in thread {parent})" if parent else ""
            raise UserConfirmationRequired(
                action="schedule_message",
                details=(
                    f"Schedule this message to Slack channel {target}{in_thread} at "
                    f'{_utc_label(when)} (unix {when}): "{preview(body)}"'
                ),
            )
        payload: dict[str, Any] = {"channel": target, "text": body, "post_at": when}
        if parent:
            payload["thread_ts"] = parent
        data = await self._send_chat("chat.scheduleMessage", payload, "schedule_message")
        return {**scalars(data, "channel", "scheduled_message_id", "post_at"), "scheduled": True}

    async def add_reaction(
        self, channel: Any, ts: Any, name: Any, *, user_confirmed: bool = False
    ) -> dict[str, Any]:
        target = channel_id(channel)
        message = message_ts(ts)
        emoji = _emoji_name(name, "name")
        if not user_confirmed:
            raise UserConfirmationRequired(
                action="add_reaction",
                details=f"React with :{emoji}: to message {message} in Slack channel {target}.",
            )
        await self._post_json(
            "reactions.add",
            {"channel": target, "timestamp": message, "name": emoji},
            "add_reaction",
        )
        return {"channel": target, "ts": message, "reaction": emoji, "added": True}

    async def upload_file(
        self,
        channel: Any,
        filename: Any,
        content: Any,
        title: Any = None,
        thread_ts: Any = None,
        *,
        user_confirmed: bool = False,
    ) -> dict[str, Any]:
        target = channel_id(channel)
        name = require_text("filename", filename, max_chars=255)
        if _BAD_FILENAME_CHARS.search(name):
            raise ConnectorError("filename must be a plain name without slashes.")
        if not isinstance(content, str) or not content:
            raise ConnectorError("content must be non-empty text.")
        data = content.encode("utf-8")
        if len(data) > MAX_UPLOAD_BYTES:
            raise ConnectorError("content is too large (at most 1 MB of text).")
        label = optional_text("title", title, max_chars=255) or name
        parent = optional_ts(thread_ts, "thread_ts")
        if not user_confirmed:
            raise UserConfirmationRequired(
                action="upload_file",
                details=(
                    f"Upload the text file '{name}' ({len(data)} bytes) and share it in Slack "
                    f"channel {target}" + (f", thread {parent}" if parent else "") + "."
                ),
            )
        # 1. Ask Slack where to upload (form body, as the upload methods expect).
        ticket = await self._call(
            "files.getUploadURLExternal",
            http="POST",
            form={"filename": name, "length": str(len(data))},
            action="upload_file",
        )
        upload_url, file_id = self._upload_target(ticket)
        # 2. Send the bytes. The address is pre-signed: no token goes with it.
        await self._request(
            "POST",
            upload_url,
            content=data,
            headers={"Content-Type": "text/plain; charset=utf-8"},
            authorized=False,
        )
        # 3. Finish the upload and share it.
        form = {"files": json.dumps([{"id": file_id, "title": label}]), "channel_id": target}
        if parent:
            form["thread_ts"] = parent
        await self._call(
            "files.completeUploadExternal", http="POST", form=form, action="upload_file"
        )
        return {"file_id": file_id, "title": label, "channel": target, "shared": True}

    @staticmethod
    def _upload_target(ticket: dict[str, Any]) -> tuple[str, str]:
        """The upload address and file id, refusing anything but files.slack.com."""
        raw_url, file_id = ticket.get("upload_url"), ticket.get("file_id")
        if not isinstance(file_id, str) or not FILE_ID_RE.fullmatch(file_id):
            raise ConnectorError("Malformed response from Slack.")
        try:
            url = httpx.URL(raw_url) if isinstance(raw_url, str) else None
        except httpx.InvalidURL:
            url = None
        if (
            url is None
            or url.scheme != "https"
            or url.host != UPLOAD_HOST
            or url.port not in (None, 443)
            or not url.path.startswith(UPLOAD_PATH_PREFIX)
        ):
            raise ConnectorError("Slack returned an unexpected upload address; nothing was sent.")
        return str(url), file_id

    async def set_status(
        self,
        text: Any,
        emoji: Any = None,
        expires_in_minutes: Any = None,
        *,
        user_confirmed: bool = False,
    ) -> dict[str, Any]:
        status = require_text("text", text, max_chars=100, allow_empty=True)
        icon = f":{_emoji_name(emoji, 'emoji')}:" if emoji not in (None, "") else ""
        expires_at = 0
        if expires_in_minutes is not None:
            minutes = _whole_number("expires_in_minutes", expires_in_minutes)
            if not 1 <= minutes <= MAX_STATUS_MINUTES:
                raise ConnectorError("expires_in_minutes must be between 1 and 525600.")
            expires_at = int(time.time()) + minutes * 60
        if not user_confirmed:
            what = f'to "{status}" {icon}'.rstrip() if status or icon else "to empty (clear it)"
            until = f" until {_utc_label(expires_at)}" if expires_at else " with no expiry"
            raise UserConfirmationRequired(
                action="set_status", details=f"Set your Slack status {what}{until}."
            )
        profile = {"status_text": status, "status_emoji": icon, "status_expiration": expires_at}
        await self._post_json("users.profile.set", {"profile": profile}, "set_status", token="user")
        return {"status_text": status, "status_emoji": icon, "expires_at": expires_at or None}

    async def create_channel(
        self, name: Any, is_private: Any = None, *, user_confirmed: bool = False
    ) -> dict[str, Any]:
        channel_name = require_text("name", name, max_chars=80).lstrip("#")
        if not _CHANNEL_NAME_RE.fullmatch(channel_name):
            raise ConnectorError(
                "name must use lowercase letters, numbers, - and _ (at most 80 characters)."
            )
        private = optional_bool("is_private", is_private)
        if not user_confirmed:
            kind = "private" if private else "public"
            raise UserConfirmationRequired(
                action="create_channel",
                details=f"Create the {kind} Slack channel #{channel_name}.",
            )
        data = await self._post_json(
            "conversations.create",
            {"name": channel_name, "is_private": private},
            "create_channel",
        )
        channel = shape_channel(data.get("channel"))
        if not channel:
            raise ConnectorError("Malformed response from Slack.")
        return channel

    async def invite_to_channel(
        self, channel: Any, users: Any, *, user_confirmed: bool = False
    ) -> dict[str, Any]:
        target = channel_id(channel)
        if isinstance(users, str):
            users = [part for part in users.split(",") if part.strip()]
        if not isinstance(users, list) or not users:
            raise ConnectorError("users must be a non-empty list of user ids.")
        if len(users) > MAX_INVITES:
            raise ConnectorError(f"users may list at most {MAX_INVITES} people per call.")
        ids = list(dict.fromkeys(parse_user_id(u, "users") for u in users))
        if not user_confirmed:
            raise UserConfirmationRequired(
                action="invite_to_channel",
                details=f"Invite {', '.join(ids)} to Slack channel {target}.",
            )
        await self._post_json(
            "conversations.invite",
            {"channel": target, "users": ",".join(ids)},
            "invite_to_channel",
        )
        return {"channel": target, "invited": ids}

    async def delete_message(
        self, channel: Any, ts: Any, *, user_confirmed: bool = False
    ) -> dict[str, Any]:
        target = channel_id(channel)
        message = message_ts(ts)
        if not user_confirmed:
            raise UserConfirmationRequired(
                action="delete_message",
                details=(
                    f"Delete message {message} from Slack channel {target}. This cannot be undone."
                ),
            )
        await self._post_json("chat.delete", {"channel": target, "ts": message}, "delete_message")
        return {"channel": target, "ts": message, "deleted": True}

    async def archive_channel(
        self, channel: Any, *, user_confirmed: bool = False
    ) -> dict[str, Any]:
        target = channel_id(channel)
        if not user_confirmed:
            raise UserConfirmationRequired(
                action="archive_channel",
                details=f"Archive Slack channel {target}. Members will no longer be able to post in it.",
            )
        await self._post_json("conversations.archive", {"channel": target}, "archive_channel")
        return {"channel": target, "archived": True}
