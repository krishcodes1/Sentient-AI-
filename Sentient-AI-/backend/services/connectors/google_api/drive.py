"""Google Drive actions of the Google Workspace connector: search, list folders,
read file text, upload text files, create folders, move, rename, share and
trash files.

Why it exists: keeps Drive's query building, export rules and multipart upload
out of ``google_workspace.py``. File text is untrusted input: it is capped and
returned as plain text, and binary files are refused instead of dumped.

External service: the Google Drive API v3 (https://www.googleapis.com/drive/v3/
and the upload endpoint https://www.googleapis.com/upload/drive/v3/). Depends
on ``google_api.client`` (GoogleBase, validation, text helpers), ``base``
(errors, path_segment), ``definition`` and ``shaping``.
"""

from __future__ import annotations

import json
import re
import secrets
from typing import Any, Optional

from services.agent.permissions import ActionCategory
from services.connectors.base import ConnectorError, UserConfirmationRequired, path_segment
from services.connectors.definition import ToolSpec, _schema
from services.connectors.shaping import clamp_limit, collect_pages

from .client import (
    DRIVE_API,
    DRIVE_UPLOAD_API,
    GoogleBase,
    as_dict,
    as_list,
    decode_text,
    is_text_like,
    optional_bool,
    optional_line,
    optional_offset,
    require_email,
    require_id,
    require_line,
    scalar,
    scalar_fields,
    text_window,
)

# Characters of file text returned per get_file_text call.
FILE_TEXT_CHARS = 12000
# Bytes downloaded for a plain file (a Range request; the rest is not fetched).
MAX_DOWNLOAD_BYTES = 1_000_000
# Largest text accepted by upload_file.
MAX_UPLOAD_BYTES = 5_000_000
FOLDER_MIME = "application/vnd.google-apps.folder"
# Google-native files have no bytes of their own; they are exported.
EXPORT_MIME = {
    "application/vnd.google-apps.document": "text/plain",
    "application/vnd.google-apps.spreadsheet": "text/csv",
    "application/vnd.google-apps.presentation": "text/plain",
}
UPLOAD_MIME_TYPES = (
    "text/plain", "text/csv", "text/markdown", "text/html", "application/json",
)
SHARE_ROLES = ("reader", "commenter", "writer")
_FILE_FIELDS = "id,name,mimeType,modifiedTime,size,webViewLink,parents"
_LIST_FIELDS = f"nextPageToken,files({_FILE_FIELDS})"
# Drive ids (and the "root" alias) only ever use these characters; anything
# else is refused before it can be spliced into a Drive query string.
_DRIVE_ID_RE = re.compile(r"^[A-Za-z0-9_-]{1,200}$")
_MIME_RE = re.compile(r"^[a-z]+/[A-Za-z0-9.+_-]{1,100}$")
_COMMON = {"supportsAllDrives": "true"}

_FILE_ID = {"type": "string", "description": "Drive file id", "required": True}
_LIMIT = {"type": "integer", "description": "How many (default 10, max 50)"}

DRIVE_ACTIONS: tuple[ToolSpec, ...] = (
    ToolSpec(
        "search_files",
        "Search Google Drive by words in the file name or content (newest first when no "
        "query). Returns ids for get_file_text.",
        ActionCategory.READ,
        _schema(
            query={"type": "string", "description": "Words to look for"},
            mime_type={"type": "string", "description": "Only this MIME type, optional"},
            limit=_LIMIT,
        ),
        policy_key="google_drive",
        required_scope="drive.read",
        starter=True,
    ),
    ToolSpec(
        "get_file_text",
        "Read a Drive file as plain text: Google Docs and Slides as text, Sheets as CSV "
        "(first sheet), text files as they are. Binary files are refused.",
        ActionCategory.READ,
        _schema(
            file_id=_FILE_ID,
            offset={"type": "integer", "description": "Character offset to continue reading"},
        ),
        policy_key="google_drive",
        required_scope="drive.read",
    ),
    ToolSpec(
        "list_folder",
        "List the files in a Drive folder (default: My Drive root), folders first.",
        ActionCategory.READ,
        _schema(folder_id={"type": "string", "description": "Folder id or root"}, limit=_LIMIT),
        policy_key="google_drive",
        required_scope="drive.read",
    ),
    ToolSpec(
        "upload_file",
        "Create a text file in Google Drive.",
        ActionCategory.WRITE,
        _schema(
            name={"type": "string", "required": True},
            content={"type": "string", "required": True},
            mime_type={"type": "string", "enum": list(UPLOAD_MIME_TYPES)},
            folder_id={"type": "string", "description": "Parent folder id (default: root)"},
        ),
        policy_key="google_drive",
        required_scope="drive.write",
    ),
    ToolSpec(
        "create_folder",
        "Create a folder in Google Drive.",
        ActionCategory.WRITE,
        _schema(
            name={"type": "string", "required": True},
            parent_id={"type": "string", "description": "Parent folder id (default: root)"},
        ),
        policy_key="google_drive",
        required_scope="drive.write",
    ),
    ToolSpec(
        "move_file",
        "Move a Drive file into another folder.",
        ActionCategory.WRITE,
        _schema(file_id=_FILE_ID, folder_id={"type": "string", "required": True}),
        policy_key="google_drive",
        required_scope="drive.write",
    ),
    ToolSpec(
        "rename_file",
        "Rename a Drive file.",
        ActionCategory.WRITE,
        _schema(file_id=_FILE_ID, name={"type": "string", "required": True}),
        policy_key="google_drive",
        required_scope="drive.write",
    ),
    ToolSpec(
        "share_file",
        "Share a Drive file with one person (reader, commenter or writer).",
        ActionCategory.WRITE,
        _schema(
            file_id=_FILE_ID,
            email={"type": "string", "required": True},
            role={"type": "string", "enum": list(SHARE_ROLES), "required": True},
            notify={"type": "boolean", "description": "Email the person (default true)"},
        ),
        policy_key="google_drive",
        required_scope="drive.write",
        always_confirm=True,
    ),
    ToolSpec(
        "trash_file",
        "Move a Drive file to the trash (Drive empties it after 30 days).",
        ActionCategory.DELETE,
        _schema(file_id=_FILE_ID),
        policy_key="google_drive",
        required_scope="drive.write",
        always_confirm=True,
    ),
)


def _drive_id(value: Any, field: str) -> str:
    text = require_id(value, field)
    if not _DRIVE_ID_RE.match(text):
        raise ConnectorError(f"'{field}' is not a valid Drive id.")
    return text


def _quote(value: str) -> str:
    """A Drive query string literal: backslash and quote escaped."""
    return "'" + value.replace("\\", "\\\\").replace("'", "\\'") + "'"


def _shape_file(raw: Any) -> dict[str, Any]:
    shaped = scalar_fields(
        raw, id="id", name="name", mime_type="mimeType", modified="modifiedTime",
        size="size", link="webViewLink",
    )
    parents = [p for p in as_list(as_dict(raw).get("parents")) if isinstance(p, str)][:5]
    if parents:
        shaped["parents"] = parents
    return shaped


class DriveActions(GoogleBase):
    """Google Drive action coroutines (mixed into GoogleWorkspaceConnector)."""

    def _file_url(self, file_id: str, suffix: str = "") -> str:
        return f"{DRIVE_API}/files/{path_segment(file_id)}{suffix}"

    async def _list_files(self, q: str, limit: int, order_by: Optional[str]) -> list[dict[str, Any]]:
        async def fetch(cursor: Optional[str]) -> tuple[list[Any], Optional[str]]:
            params: dict[str, Any] = {
                "q": q,
                "pageSize": limit,
                "fields": _LIST_FIELDS,
                "includeItemsFromAllDrives": "true",
                **_COMMON,
            }
            if order_by:
                params["orderBy"] = order_by
            if cursor:
                params["pageToken"] = cursor
            data = await self._call_object("GET", f"{DRIVE_API}/files", params=params)
            token = data.get("nextPageToken")
            return (
                [f for f in as_list(data.get("files")) if isinstance(f, dict)],
                token if isinstance(token, str) else None,
            )

        return [_shape_file(f) for f in await collect_pages(fetch, limit=limit, max_pages=3)]

    # -- READ ------------------------------------------------------------------

    async def search_files(
        self, query: Optional[str] = None, mime_type: Optional[str] = None, limit: Any = None
    ) -> list[dict[str, Any]]:
        words = optional_line(query, "query", max_chars=500)
        clauses = ["trashed = false"]
        if words:
            literal = _quote(words)
            clauses.append(f"(name contains {literal} or fullText contains {literal})")
        kind = optional_line(mime_type, "mime_type", max_chars=120)
        if kind:
            if not _MIME_RE.match(kind):
                raise ConnectorError("'mime_type' must look like type/subtype.")
            clauses.append(f"mimeType = {_quote(kind)}")
        # Drive refuses orderBy on fullText queries (results come by relevance).
        order = None if words else "modifiedTime desc"
        return await self._list_files(" and ".join(clauses), clamp_limit(limit), order)

    async def list_folder(self, folder_id: Optional[str] = None, limit: Any = None) -> list[dict[str, Any]]:
        folder = _drive_id(folder_id, "folder_id") if folder_id else "root"
        q = f"{_quote(folder)} in parents and trashed = false"
        return await self._list_files(q, clamp_limit(limit), "folder,name")

    async def get_file_text(self, file_id: str, offset: Any = None) -> dict[str, Any]:
        """A file's text: two requests (metadata to pick the route, then the
        export or download)."""
        fid = require_id(file_id, "file_id")
        start = optional_offset(offset)
        meta = await self._call_object(
            "GET", self._file_url(fid), params={"fields": "id,name,mimeType,size", **_COMMON}
        )
        mime = scalar(meta.get("mimeType")) or ""
        name = scalar(meta.get("name")) or ""
        download_cut = False
        if mime in EXPORT_MIME:
            response = await self._call(
                "GET", self._file_url(fid, "/export"), params={"mimeType": EXPORT_MIME[mime]}
            )
            data = response.content
        elif mime == FOLDER_MIME:
            raise ConnectorError(f"'{name}' is a folder; use list_folder to see what is inside.")
        elif mime.startswith("application/vnd.google-apps."):
            raise ConnectorError(f"'{name}' is a {mime} file, which cannot be read as text.")
        elif is_text_like(mime, name):
            response = await self._call(
                "GET",
                self._file_url(fid),
                params={"alt": "media", **_COMMON},
                headers={"Range": f"bytes=0-{MAX_DOWNLOAD_BYTES - 1}"},
            )
            data = response.content[:MAX_DOWNLOAD_BYTES]
            size = scalar(meta.get("size"))
            download_cut = bool(size and size.isdigit() and int(size) > MAX_DOWNLOAD_BYTES)
        else:
            raise ConnectorError(
                f"'{name}' is {mime or 'an unknown type'}, a binary file; only Google Docs, "
                "Sheets, Slides and text files can be read."
            )
        window = text_window(decode_text(data, response.charset_encoding), start, FILE_TEXT_CHARS, action="get_file_text")
        if download_cut and not window["truncated"]:
            window["truncated"] = True
            window["hint"] = f"Only the first {MAX_DOWNLOAD_BYTES} bytes of this file can be read."
        return {"id": fid, "name": name, "mime_type": mime, **window}

    # -- WRITE -----------------------------------------------------------------

    async def upload_file(
        self,
        name: str,
        content: str,
        mime_type: Optional[str] = None,
        folder_id: Optional[str] = None,
        *,
        user_confirmed: bool = False,
    ) -> dict[str, Any]:
        """Create a text file with one multipart upload request."""
        title = require_line(name, "name", max_chars=255)
        if not isinstance(content, str):
            raise ConnectorError("'content' must be a string.")
        body = content.encode("utf-8")
        if len(body) > MAX_UPLOAD_BYTES:
            raise ConnectorError(f"'content' is too large (at most {MAX_UPLOAD_BYTES} bytes).")
        kind = mime_type or "text/plain"
        if kind not in UPLOAD_MIME_TYPES:
            raise ConnectorError(f"'mime_type' must be one of {', '.join(UPLOAD_MIME_TYPES)}.")
        parent = _drive_id(folder_id, "folder_id") if folder_id else None
        if not user_confirmed:
            raise UserConfirmationRequired(
                action="upload_file",
                details=(
                    f"Create the {kind} file '{title}' ({len(body)} bytes) in Google Drive "
                    f"folder '{parent or 'root'}'?"
                ),
            )
        metadata: dict[str, Any] = {"name": title, "mimeType": kind}
        if parent:
            metadata["parents"] = [parent]
        boundary = f"crawler-{secrets.token_hex(12)}"
        multipart = (
            f"--{boundary}\r\nContent-Type: application/json; charset=UTF-8\r\n\r\n"
            f"{json.dumps(metadata)}\r\n--{boundary}\r\nContent-Type: {kind}; charset=UTF-8\r\n\r\n"
        ).encode() + body + f"\r\n--{boundary}--\r\n".encode()
        created = await self._call_object(
            "POST",
            f"{DRIVE_UPLOAD_API}/files",
            params={"uploadType": "multipart", "fields": _FILE_FIELDS, **_COMMON},
            content=multipart,
            headers={"Content-Type": f"multipart/related; boundary={boundary}"},
        )
        return _shape_file(created)

    async def create_folder(
        self, name: str, parent_id: Optional[str] = None, *, user_confirmed: bool = False
    ) -> dict[str, Any]:
        title = require_line(name, "name", max_chars=255)
        parent = _drive_id(parent_id, "parent_id") if parent_id else None
        if not user_confirmed:
            raise UserConfirmationRequired(
                action="create_folder",
                details=f"Create the folder '{title}' in Google Drive folder '{parent or 'root'}'?",
            )
        metadata: dict[str, Any] = {"name": title, "mimeType": FOLDER_MIME}
        if parent:
            metadata["parents"] = [parent]
        created = await self._call_object(
            "POST", f"{DRIVE_API}/files", params={"fields": _FILE_FIELDS, **_COMMON}, json=metadata
        )
        return _shape_file(created)

    async def move_file(
        self, file_id: str, folder_id: str, *, user_confirmed: bool = False
    ) -> dict[str, Any]:
        fid = require_id(file_id, "file_id")
        target = _drive_id(folder_id, "folder_id")
        if not user_confirmed:
            raise UserConfirmationRequired(
                action="move_file", details=f"Move Drive file {fid} into folder {target}?"
            )
        current = await self._call_object(
            "GET", self._file_url(fid), params={"fields": "parents", **_COMMON}
        )
        old = [p for p in as_list(current.get("parents")) if isinstance(p, str) and p != target]
        params: dict[str, Any] = {"addParents": target, "fields": _FILE_FIELDS, **_COMMON}
        if old:
            params["removeParents"] = ",".join(old)
        moved = await self._call_object("PATCH", self._file_url(fid), params=params, json={})
        return _shape_file(moved)

    async def rename_file(
        self, file_id: str, name: str, *, user_confirmed: bool = False
    ) -> dict[str, Any]:
        fid = require_id(file_id, "file_id")
        title = require_line(name, "name", max_chars=255)
        if not user_confirmed:
            raise UserConfirmationRequired(
                action="rename_file", details=f"Rename Drive file {fid} to '{title}'?"
            )
        renamed = await self._call_object(
            "PATCH", self._file_url(fid), params={"fields": _FILE_FIELDS, **_COMMON}, json={"name": title}
        )
        return _shape_file(renamed)

    async def share_file(
        self,
        file_id: str,
        email: str,
        role: str,
        notify: Optional[bool] = None,
        *,
        user_confirmed: bool = False,
    ) -> dict[str, Any]:
        fid = require_id(file_id, "file_id")
        address = require_email(email, "email")
        if role not in SHARE_ROLES:
            raise ConnectorError(f"'role' must be one of {', '.join(SHARE_ROLES)}.")
        send_mail = optional_bool(notify, "notify", True)
        if not user_confirmed:
            raise UserConfirmationRequired(
                action="share_file",
                details=(
                    f"Give {address} {role} access to Drive file {fid}"
                    f"{' and email them' if send_mail else ''}?"
                ),
            )
        permission = await self._call_object(
            "POST",
            self._file_url(fid, "/permissions"),
            params={
                "sendNotificationEmail": "true" if send_mail else "false",
                "fields": "id,role,type,emailAddress",
                **_COMMON,
            },
            json={"type": "user", "role": role, "emailAddress": address},
        )
        return {
            "file_id": fid,
            **scalar_fields(permission, permission_id="id", role="role", email="emailAddress"),
        }

    # -- DELETE ----------------------------------------------------------------

    async def trash_file(self, file_id: str, *, user_confirmed: bool = False) -> dict[str, Any]:
        fid = require_id(file_id, "file_id")
        if not user_confirmed:
            raise UserConfirmationRequired(
                action="trash_file",
                details=f"Move Drive file {fid} to the trash? Drive deletes it for good after 30 days.",
            )
        trashed = await self._call_object(
            "PATCH", self._file_url(fid), params={"fields": "id,name,trashed", **_COMMON}, json={"trashed": True}
        )
        return {"status": "trashed", **scalar_fields(trashed, id="id", name="name")}

