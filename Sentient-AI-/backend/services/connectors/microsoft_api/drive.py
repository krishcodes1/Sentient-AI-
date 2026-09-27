"""OneDrive actions of the Microsoft 365 connector: search files, read a text
file, list a folder, upload a small text file, create folders, move files,
create share links and delete files.

Why it exists: spec section 5.5 (OneDrive row). ``services/connectors/microsoft.py``
mixes ``DriveActions`` into ``MicrosoftConnector`` and lists ``DRIVE_ACTIONS``
in its ``DEFINITION``.
Talks to Microsoft Graph ``/v1.0/me/drive/...``. ``get_file_text`` follows the
``/content`` redirect to a pre-authenticated download host (``*-my.sharepoint.com``,
``*.files.1drv.com``, ``my.microsoftpersonalcontent.com``); httpx drops our
Authorization header on that cross-origin hop and the network policy only
lets a credential-free GET reach those hosts. Depends on ``common.py``,
``services/connectors/base.py`` and ``services/connectors/definition.py``.
"""

from __future__ import annotations

import re
from typing import Any, Optional
from urllib.parse import quote

from services.agent.permissions import ActionCategory

from ..base import ConnectorError, UserConfirmationRequired, path_segment
from ..definition import ToolSpec, _schema
from ..shaping import clamp_limit
from .common import (
    GraphBase,
    capped_text,
    choice,
    decode_text,
    is_text_like,
    odata_string,
    optional_bool,
    optional_id,
    require_id,
    require_text,
    sub,
    text_of,
)

# Longest file text returned by get_file_text.
MAX_FILE_CHARS = 20_000
# Files larger than this are refused before download.
MAX_DOWNLOAD_BYTES = 2_000_000
# Largest text upload_file accepts (UTF-8 bytes); simple upload allows far
# more, but this action is for notes and small text files.
MAX_UPLOAD_BYTES = 1_000_000

_ITEM_FIELDS = "id,name,size,file,folder,lastModifiedDateTime,webUrl,parentReference"
# Characters OneDrive forbids in a name, plus control characters.
_BAD_NAME_RE = re.compile(r'[\\/:*?"<>|\x00-\x1f\x7f]')
_LINK_TYPES = ("view", "edit")
_LINK_SCOPES = ("organization", "anonymous")

_ITEM_ID = {"type": "string", "description": "File or folder id from search_files or list_folder", "required": True}
_LIMIT = {"type": "integer", "description": "How many (default 10, max 50)"}

DRIVE_ACTIONS: tuple[ToolSpec, ...] = (
    ToolSpec(
        "search_files",
        "Search the user's OneDrive for files and folders by name or content.",
        ActionCategory.READ,
        _schema(
            query={"type": "string", "description": "Search text", "required": True},
            limit=_LIMIT,
        ),
        required_scope="files.read",
        starter=True,
    ),
    ToolSpec(
        "get_file_text",
        "Read a text file (txt, md, csv, json, code...) from OneDrive. Office and binary files are refused; long files are truncated.",
        ActionCategory.READ,
        _schema(file_id=_ITEM_ID),
        required_scope="files.read",
    ),
    ToolSpec(
        "list_folder",
        "List the files and folders in a OneDrive folder (default: the root).",
        ActionCategory.READ,
        _schema(
            folder_id={"type": "string", "description": "Folder id (default: OneDrive root)"},
            limit=_LIMIT,
        ),
        required_scope="files.read",
    ),
    ToolSpec(
        "upload_file",
        "Save a small text file (up to 1 MB) to OneDrive. Fails if the name exists unless overwrite is true.",
        ActionCategory.WRITE,
        _schema(
            name={"type": "string", "description": "File name, e.g. notes.txt", "required": True},
            content={"type": "string", "description": "Text content", "required": True},
            folder_id={"type": "string", "description": "Parent folder id (default: OneDrive root)"},
            overwrite={"type": "boolean", "description": "Replace an existing file of that name (default false)"},
        ),
        required_scope="files.write",
    ),
    ToolSpec(
        "create_folder",
        "Create a folder in OneDrive (default: in the root).",
        ActionCategory.WRITE,
        _schema(
            name={"type": "string", "required": True},
            parent_folder_id={"type": "string", "description": "Parent folder id (default: OneDrive root)"},
        ),
        required_scope="files.write",
    ),
    ToolSpec(
        "move_file",
        "Move a OneDrive file or folder into another folder, optionally renaming it.",
        ActionCategory.WRITE,
        _schema(
            item_id=_ITEM_ID,
            destination_folder_id={"type": "string", "description": "Target folder id", "required": True},
            new_name={"type": "string", "description": "Optional new name"},
        ),
        required_scope="files.write",
    ),
    ToolSpec(
        "create_share_link",
        "Create a sharing link for a OneDrive file or folder. Always asks the user first.",
        ActionCategory.WRITE,
        _schema(
            item_id=_ITEM_ID,
            link_type={"type": "string", "enum": list(_LINK_TYPES), "description": "view (default) or edit"},
            scope={
                "type": "string",
                "enum": list(_LINK_SCOPES),
                "description": "organization (default, work accounts) or anonymous (anyone with the link)",
            },
        ),
        required_scope="files.write",
        always_confirm=True,
    ),
    ToolSpec(
        "delete_file",
        "Delete a OneDrive file or folder (it goes to the OneDrive recycle bin). Always asks the user first.",
        ActionCategory.DELETE,
        _schema(item_id=_ITEM_ID),
        required_scope="files.write",
        always_confirm=True,
    ),
)


def _size(value: Any) -> Optional[int]:
    return value if isinstance(value, int) and not isinstance(value, bool) else None


def _item_summary(item: dict[str, Any]) -> dict[str, Any]:
    folder = item.get("folder")
    summary: dict[str, Any] = {
        "id": text_of(item.get("id")),
        "name": text_of(item.get("name"), 400),
        "is_folder": isinstance(folder, dict),
        "size": _size(item.get("size")),
        "modified": text_of(item.get("lastModifiedDateTime"), 64),
        "web_url": text_of(item.get("webUrl"), 2048),
        "parent_id": text_of(sub(item, "parentReference").get("id")),
    }
    if isinstance(folder, dict):
        summary["child_count"] = _size(folder.get("childCount"))
    else:
        summary["mime_type"] = text_of(sub(item, "file").get("mimeType"), 200)
    return summary


def _file_name(value: Any, field: str = "name") -> str:
    name = require_text(value, field, max_chars=255)
    if _BAD_NAME_RE.search(name) or name in (".", "..") or name.endswith("."):
        raise ConnectorError(
            f"'{field}' is not a valid OneDrive name (no \\ / : * ? \" < > | or trailing dot)."
        )
    return name


def _item_path(item_id: str) -> str:
    return f"/drive/items/{path_segment(item_id)}"


def _folder_path(folder_id: Optional[str]) -> str:
    return _item_path(folder_id) if folder_id else "/drive/root"


class DriveActions(GraphBase):
    """OneDrive action coroutines (mixed into ``MicrosoftConnector``)."""

    # -- READ -------------------------------------------------------------

    async def search_files(self, query: Any, limit: Any = None) -> list[dict[str, Any]]:
        text = require_text(query, "query", max_chars=255)
        top = clamp_limit(limit)
        # The search term is a function parameter inside the path: an OData
        # string literal whose content is percent-encoded (so "/", "?" or
        # "#" cannot change the path); only its own quotes stay literal.
        term = quote(odata_string(text), safe="'")
        path = f"/drive/root/search(q={term})"
        items = await self._graph_list(path, {"$top": top, "$select": _ITEM_FIELDS}, limit=top)
        return [_item_summary(item) for item in items]

    async def get_file_text(self, file_id: Any) -> dict[str, Any]:
        fid = require_id(file_id, "file_id")
        meta = await self._graph_object("GET", _item_path(fid), params={"$select": _ITEM_FIELDS})
        info = _item_summary(meta)
        label = f"'{info['name'] or fid}'"
        if info["is_folder"] or not isinstance(meta.get("file"), dict):
            raise ConnectorError(f"{label} is a folder, not a file; use list_folder to see inside it.")
        if not is_text_like(info["name"], info.get("mime_type")):
            raise ConnectorError(
                f"{label} is not a plain-text file ({info.get('mime_type') or 'unknown type'}); "
                "only text files can be read. Share its web_url with the user instead."
            )
        if info["size"] is not None and info["size"] > MAX_DOWNLOAD_BYTES:
            raise ConnectorError(
                f"{label} is too large to read ({info['size']} bytes, limit {MAX_DOWNLOAD_BYTES})."
            )
        # /content answers 302 to a pre-authenticated download URL. httpx
        # drops Authorization on the cross-origin hop, and the policy hook
        # admits the download host only for a credential-free GET.
        response = await self._graph_response(
            "GET", f"{_item_path(fid)}/content", follow_redirects=True
        )
        raw = response.content[: MAX_DOWNLOAD_BYTES + 1]
        text = capped_text(
            decode_text(raw, what=f"File {label}"),
            MAX_FILE_CHARS,
            hint="File text truncated; open it in OneDrive (web_url) to read the rest.",
        )
        return {
            "id": info["id"] or fid,
            "name": info["name"],
            "mime_type": info.get("mime_type"),
            "size": info["size"],
            "web_url": info["web_url"],
            **text,
        }

    async def list_folder(self, folder_id: Any = None, limit: Any = None) -> list[dict[str, Any]]:
        folder = optional_id(folder_id, "folder_id")
        top = clamp_limit(limit)
        items = await self._graph_list(
            f"{_folder_path(folder)}/children", {"$top": top, "$select": _ITEM_FIELDS}, limit=top
        )
        return [_item_summary(item) for item in items]

    # -- WRITE ------------------------------------------------------------

    async def upload_file(
        self,
        name: Any,
        content: Any,
        folder_id: Any = None,
        overwrite: Any = None,
        *,
        user_confirmed: bool = False,
    ) -> dict[str, Any]:
        file_name = _file_name(name)
        if not isinstance(content, str):
            raise ConnectorError("'content' must be a string of text.")
        data = content.encode("utf-8")
        if len(data) > MAX_UPLOAD_BYTES:
            raise ConnectorError(
                f"'content' is too large ({len(data)} bytes, limit {MAX_UPLOAD_BYTES})."
            )
        folder = optional_id(folder_id, "folder_id")
        replace = optional_bool(overwrite, "overwrite", default=False)
        if not user_confirmed:
            where = f"folder {folder}" if folder else "the OneDrive root"
            mode = ", replacing any existing file of that name" if replace else ""
            raise UserConfirmationRequired(
                action="upload_file",
                details=f"Save '{file_name}' ({len(data)} bytes) to {where}{mode}.",
            )
        created = await self._graph_object(
            "PUT",
            f"{_folder_path(folder)}:/{path_segment(file_name)}:/content",
            params={"@microsoft.graph.conflictBehavior": "replace" if replace else "fail"},
            content=data,
            headers={"Content-Type": "text/plain; charset=utf-8"},
        )
        return _item_summary(created)

    async def create_folder(
        self, name: Any, parent_folder_id: Any = None, *, user_confirmed: bool = False
    ) -> dict[str, Any]:
        folder_name = _file_name(name)
        parent = optional_id(parent_folder_id, "parent_folder_id")
        if not user_confirmed:
            where = f"folder {parent}" if parent else "the OneDrive root"
            raise UserConfirmationRequired(
                action="create_folder",
                details=f"Create the folder '{folder_name}' in {where}.",
            )
        created = await self._graph_object(
            "POST",
            f"{_folder_path(parent)}/children",
            json={
                "name": folder_name,
                "folder": {},
                "@microsoft.graph.conflictBehavior": "fail",
            },
        )
        return _item_summary(created)

    async def move_file(
        self,
        item_id: Any,
        destination_folder_id: Any,
        new_name: Any = None,
        *,
        user_confirmed: bool = False,
    ) -> dict[str, Any]:
        iid = require_id(item_id, "item_id")
        destination = require_id(destination_folder_id, "destination_folder_id")
        rename = _file_name(new_name, "new_name") if new_name not in (None, "") else None
        if not user_confirmed:
            renamed = f" and rename it to '{rename}'" if rename else ""
            raise UserConfirmationRequired(
                action="move_file",
                details=f"Move OneDrive item {iid} into folder {destination}{renamed}.",
            )
        payload: dict[str, Any] = {"parentReference": {"id": destination}}
        if rename:
            payload["name"] = rename
        moved = await self._graph_object("PATCH", _item_path(iid), json=payload)
        return _item_summary(moved)

    async def create_share_link(
        self,
        item_id: Any,
        link_type: Any = None,
        scope: Any = None,
        *,
        user_confirmed: bool = False,
    ) -> dict[str, Any]:
        iid = require_id(item_id, "item_id")
        kind = choice(link_type, "link_type", _LINK_TYPES, default="view")
        audience = choice(scope, "scope", _LINK_SCOPES, default="organization")
        if not user_confirmed:
            who = "anyone who has the link" if audience == "anonymous" else "people in your organization"
            raise UserConfirmationRequired(
                action="create_share_link",
                details=f"Create a {kind} link to OneDrive item {iid} that {who} can open.",
            )
        permission = await self._graph_object(
            "POST", f"{_item_path(iid)}/createLink", json={"type": kind, "scope": audience}
        )
        link = sub(permission, "link")
        return {
            "item_id": iid,
            "link": text_of(link.get("webUrl"), 2048),
            "type": text_of(link.get("type"), 32) or kind,
            "scope": text_of(link.get("scope"), 32) or audience,
        }

    # -- DELETE -----------------------------------------------------------

    async def delete_file(self, item_id: Any, *, user_confirmed: bool = False) -> dict[str, Any]:
        iid = require_id(item_id, "item_id")
        if not user_confirmed:
            raise UserConfirmationRequired(
                action="delete_file",
                details=f"Delete OneDrive item {iid} (it moves to the OneDrive recycle bin).",
            )
        await self._graph_response("DELETE", _item_path(iid))
        return {"deleted": True, "id": iid}


__all__ = ["DRIVE_ACTIONS", "DriveActions"]
