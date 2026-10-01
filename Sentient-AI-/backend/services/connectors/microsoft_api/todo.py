"""Microsoft To Do and Outlook contacts actions of the Microsoft 365
connector: list task lists and tasks, create, update, complete and delete
tasks, and search contacts.

Why it exists: spec section 5.5 (To Do and Contacts rows). The two areas are
small, so they share this module. ``services/connectors/microsoft.py`` mixes
``TodoActions`` and ``ContactActions`` into ``MicrosoftConnector`` and lists
``TODO_ACTIONS`` and ``CONTACT_ACTIONS`` in its ``DEFINITION``.
Talks to Microsoft Graph ``/v1.0/me/todo/lists`` and ``/v1.0/me/contacts``.
Depends on ``common.py``, ``services/connectors/base.py`` and
``services/connectors/definition.py``.
"""

from __future__ import annotations

from typing import Any

from services.agent import risk
from services.agent.permissions import ActionCategory

from ..base import ConnectorError, UserConfirmationRequired, path_segment
from ..definition import ToolSpec, _schema
from ..shaping import cap_text, clamp_limit
from .common import (
    MAX_LONG_TEXT,
    GraphBase,
    choice,
    due_date,
    odata_string,
    optional_text,
    require_id,
    require_text,
    sub,
    text_of,
    when_of,
)

_TASK_NOTE_CHARS = 500
_IMPORTANCE = ("low", "normal", "high")
_STATUS_FILTERS = ("open", "completed", "all")

_LIST_ID = {"type": "string", "description": "Task list id from list_task_lists", "required": True}
_NEW_TASK_LIST_ID = {
    "type": "string",
    "description": "Task list id from list_task_lists (default: your default To Do list)",
}
# The default list ("Tasks") is the one To Do marks with this name.
_DEFAULT_LIST = "defaultList"
_LIST_SCAN = 50
_TASK_ID = {"type": "string", "description": "Task id from list_tasks", "required": True}
_LIMIT = {"type": "integer", "description": "How many (default 10, max 50)"}

TODO_ACTIONS: tuple[ToolSpec, ...] = (
    ToolSpec(
        "list_task_lists",
        "List the user's Microsoft To Do task lists.",
        ActionCategory.READ,
        _schema(limit=_LIMIT),
        required_scope="tasks.read",
    ),
    ToolSpec(
        "list_tasks",
        "List tasks in a Microsoft To Do list (default: open tasks only).",
        ActionCategory.READ,
        _schema(
            list_id=_LIST_ID,
            status={"type": "string", "enum": list(_STATUS_FILTERS), "description": "open (default), completed or all"},
            limit=_LIMIT,
        ),
        required_scope="tasks.read",
    ),
    ToolSpec(
        "create_task",
        "Add a task to a Microsoft To Do list (default: the user's default list).",
        ActionCategory.WRITE,
        _schema(
            list_id=_NEW_TASK_LIST_ID,
            title={"type": "string", "required": True},
            note={"type": "string", "description": "Optional plain-text note"},
            due_date={"type": "string", "description": "Optional due date, YYYY-MM-DD"},
            importance={"type": "string", "enum": list(_IMPORTANCE)},
        ),
        required_scope="tasks.write",
        risk="low",
        # To Do lists can be shared with other people: a named list asks
        # first, like a calendar or a Drive folder (standing consent never
        # covers writing where others may read it).
        risk_check=risk.when_given("list_id", "medium", "it writes to a list that may be shared"),
        ref_args=("list_id",),
        low_risk_note="add tasks to your default To Do list",
    ),
    ToolSpec(
        "update_task",
        "Change the title, note, due date or importance of a Microsoft To Do task.",
        ActionCategory.WRITE,
        _schema(
            list_id=_LIST_ID,
            task_id=_TASK_ID,
            title={"type": "string"},
            note={"type": "string"},
            due_date={"type": "string", "description": "YYYY-MM-DD"},
            importance={"type": "string", "enum": list(_IMPORTANCE)},
        ),
        required_scope="tasks.write",
    ),
    ToolSpec(
        "complete_task",
        "Mark a Microsoft To Do task as completed.",
        ActionCategory.WRITE,
        _schema(list_id=_LIST_ID, task_id=_TASK_ID),
        required_scope="tasks.write",
        risk="low",
        ref_args=("list_id", "task_id"),
        low_risk_note="mark To Do tasks done",
    ),
    ToolSpec(
        "delete_task",
        "Delete a Microsoft To Do task. Always asks the user first.",
        ActionCategory.DELETE,
        _schema(list_id=_LIST_ID, task_id=_TASK_ID),
        required_scope="tasks.write",
        always_confirm=True,
    ),
)

CONTACT_ACTIONS: tuple[ToolSpec, ...] = (
    ToolSpec(
        "search_contacts",
        "Find Outlook contacts whose name starts with the query, or by exact email address.",
        ActionCategory.READ,
        _schema(
            query={"type": "string", "description": "Start of a name, or a full email address", "required": True},
            limit=_LIMIT,
        ),
        required_scope="contacts.read",
    ),
)


def _task_summary(task: dict[str, Any]) -> dict[str, Any]:
    note, truncated = cap_text(text_of(sub(task, "body").get("content"), MAX_LONG_TEXT), _TASK_NOTE_CHARS)
    summary: dict[str, Any] = {
        "id": text_of(task.get("id")),
        "title": text_of(task.get("title")),
        "status": text_of(task.get("status"), 32),
        "importance": text_of(task.get("importance"), 16),
        "due": when_of(task.get("dueDateTime")),
        "completed": when_of(task.get("completedDateTime")),
        "note": note,
    }
    if truncated:
        summary["note_truncated"] = True
    return summary


def _task_path(list_id: str, task_id: str | None = None) -> str:
    path = f"/todo/lists/{path_segment(list_id)}/tasks"
    return f"{path}/{path_segment(task_id)}" if task_id else path


def _task_fields(title: Any, note: Any, due: Any, importance: Any, *, creating: bool) -> dict[str, Any]:
    fields: dict[str, Any] = {}
    if creating or title is not None:
        fields["title"] = require_text(title, "title", max_chars=255)
    if note is not None:
        fields["body"] = {"content": optional_text(note, "note", max_chars=MAX_LONG_TEXT) or "", "contentType": "text"}
    deadline = due_date(due)
    if deadline:
        fields["dueDateTime"] = deadline
    if importance is not None:
        fields["importance"] = choice(importance, "importance", _IMPORTANCE, default="normal")
    return fields


class TodoActions(GraphBase):
    """Microsoft To Do action coroutines (mixed into ``MicrosoftConnector``)."""

    async def list_task_lists(self, limit: Any = None) -> list[dict[str, Any]]:
        top = clamp_limit(limit)
        # No $top: the lists endpoint does not document it, and a user has
        # few lists; collect_pages stops at the limit.
        items = await self._graph_list("/todo/lists", {}, limit=top)
        return [
            {
                "id": text_of(item.get("id")),
                "name": text_of(item.get("displayName")),
                "is_owner": item.get("isOwner") is True,
                "well_known_name": text_of(item.get("wellknownListName"), 64),
            }
            for item in items
        ]

    async def list_tasks(self, list_id: Any, status: Any = None, limit: Any = None) -> list[dict[str, Any]]:
        lid = require_id(list_id, "list_id")
        which = choice(status, "status", _STATUS_FILTERS, default="open")
        top = clamp_limit(limit)
        params: dict[str, Any] = {"$top": top}
        if which == "open":
            params["$filter"] = "status ne 'completed'"
        elif which == "completed":
            params["$filter"] = "status eq 'completed'"
        items = await self._graph_list(_task_path(lid), params, limit=top)
        return [_task_summary(item) for item in items]

    async def _default_list_id(self) -> str:
        """The id of the user's default To Do list (To Do's "Tasks")."""
        items = await self._graph_list("/todo/lists", {}, limit=_LIST_SCAN)
        for item in items:
            list_id = text_of(item.get("id"))
            if text_of(item.get("wellknownListName"), 64) == _DEFAULT_LIST and list_id:
                return list_id
        raise ConnectorError("Your default To Do list was not found. Name a list from list_task_lists.")

    async def create_task(
        self,
        list_id: Any = None,
        title: Any = None,
        note: Any = None,
        due_date: Any = None,
        importance: Any = None,
        *,
        user_confirmed: bool = False,
    ) -> dict[str, Any]:
        lid = require_id(list_id, "list_id") if list_id not in (None, "") else None
        fields = _task_fields(title, note, due_date, importance, creating=True)
        if not user_confirmed:
            where = f"To Do list {lid}" if lid else "your default To Do list"
            raise UserConfirmationRequired(
                action="create_task",
                details=f"Add the task '{fields['title']}' to {where}.",
            )
        if lid is None:
            lid = await self._default_list_id()
        created = await self._graph_object("POST", _task_path(lid), json=fields)
        return _task_summary(created)

    async def update_task(
        self,
        list_id: Any,
        task_id: Any,
        title: Any = None,
        note: Any = None,
        due_date: Any = None,
        importance: Any = None,
        *,
        user_confirmed: bool = False,
    ) -> dict[str, Any]:
        lid = require_id(list_id, "list_id")
        tid = require_id(task_id, "task_id")
        fields = _task_fields(title, note, due_date, importance, creating=False)
        if not fields:
            raise ConnectorError("Nothing to update: give at least one of title, note, due_date, importance.")
        if not user_confirmed:
            names = {"body": "note", "dueDateTime": "due date"}
            changed = ", ".join(names.get(key, key) for key in fields)
            raise UserConfirmationRequired(
                action="update_task",
                details=f"Change the {changed} of To Do task {tid} in list {lid}.",
            )
        updated = await self._graph_object("PATCH", _task_path(lid, tid), json=fields)
        return _task_summary(updated)

    async def complete_task(
        self, list_id: Any, task_id: Any, *, user_confirmed: bool = False
    ) -> dict[str, Any]:
        lid = require_id(list_id, "list_id")
        tid = require_id(task_id, "task_id")
        if not user_confirmed:
            raise UserConfirmationRequired(
                action="complete_task",
                details=f"Mark To Do task {tid} in list {lid} as completed.",
            )
        updated = await self._graph_object("PATCH", _task_path(lid, tid), json={"status": "completed"})
        return _task_summary(updated)

    async def delete_task(
        self, list_id: Any, task_id: Any, *, user_confirmed: bool = False
    ) -> dict[str, Any]:
        lid = require_id(list_id, "list_id")
        tid = require_id(task_id, "task_id")
        if not user_confirmed:
            raise UserConfirmationRequired(
                action="delete_task",
                details=f"Delete To Do task {tid} from list {lid}. This cannot be undone.",
            )
        await self._graph_response("DELETE", _task_path(lid, tid))
        return {"deleted": True, "id": tid, "list_id": lid}


def _contact_summary(contact: dict[str, Any]) -> dict[str, Any]:
    emails = contact.get("emailAddresses")
    phones = contact.get("businessPhones")
    mobile = text_of(contact.get("mobilePhone"), 64)
    numbers = [text_of(p, 64) for p in (phones if isinstance(phones, list) else [])[:5]]
    return {
        "id": text_of(contact.get("id")),
        "name": text_of(contact.get("displayName")),
        "emails": [
            address
            for address in (
                text_of(entry.get("address"), 320)
                for entry in (emails if isinstance(emails, list) else [])[:10]
                if isinstance(entry, dict)
            )
            if address
        ],
        "phones": [number for number in [mobile, *numbers] if number],
        "company": text_of(contact.get("companyName")),
        "job_title": text_of(contact.get("jobTitle")),
    }


class ContactActions(GraphBase):
    """Outlook contacts action coroutine (mixed into ``MicrosoftConnector``)."""

    async def search_contacts(self, query: Any, limit: Any = None) -> list[dict[str, Any]]:
        text = require_text(query, "query", max_chars=255)
        top = clamp_limit(limit)
        literal = odata_string(text)
        if "@" in text and " " not in text:
            # The only documented filter on addresses: exact match.
            condition = f"emailAddresses/any(a:a/address eq {literal})"
        else:
            condition = " or ".join(
                f"startswith({field},{literal})" for field in ("displayName", "givenName", "surname")
            )
        params = {
            "$filter": condition,
            "$top": top,
            "$select": "id,displayName,emailAddresses,businessPhones,mobilePhone,companyName,jobTitle",
        }
        items = await self._graph_list("/contacts", params, limit=top)
        return [_contact_summary(item) for item in items]
