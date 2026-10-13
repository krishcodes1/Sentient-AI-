"""Google Docs actions of the Google Workspace connector: read a document as
plain text, create a document, append text and replace text.

Why it exists: keeps the Docs API's structural JSON (paragraphs, tables, tables
of contents) and its batchUpdate requests out of ``google_workspace.py``.
Document text is untrusted input, so it is flattened to plain text and capped.

External service: the Google Docs API v1 (https://docs.googleapis.com/v1/documents).
Depends on ``google_api.client`` (GoogleBase, validation, text helpers),
``base`` (errors, path_segment) and ``definition``.
"""

from __future__ import annotations

from typing import Any, Optional

from services.agent.permissions import ActionCategory
from services.connectors.base import ConnectorError, UserConfirmationRequired, path_segment
from services.connectors.definition import ToolSpec, _schema

from .client import (
    DOCS_API,
    GoogleBase,
    as_dict,
    as_list,
    optional_bool,
    optional_offset,
    optional_text,
    require_id,
    require_line,
    require_text,
    scalar,
    text_window,
)

# Characters of document text returned per get_document call.
DOCUMENT_TEXT_CHARS = 12000
# Text collected from a document before paging (bounds hostile documents).
_MAX_COLLECT_CHARS = 2_000_000
# Deepest table-in-table nesting walked.
_MAX_DEPTH = 10

_DOCUMENT_ID = {"type": "string", "description": "Google Docs document id", "required": True}

DOCS_ACTIONS: tuple[ToolSpec, ...] = (
    ToolSpec(
        "get_document",
        "Read a Google Doc as plain text (paragraphs and tables).",
        ActionCategory.READ,
        _schema(
            document_id=_DOCUMENT_ID,
            offset={"type": "integer", "description": "Character offset to continue reading"},
        ),
        policy_key="google_docs",
        required_scope="docs.read",
    ),
    ToolSpec(
        "create_document",
        "Create a Google Doc with a title and optional starting text.",
        ActionCategory.WRITE,
        _schema(title={"type": "string", "required": True}, text={"type": "string"}),
        policy_key="google_docs",
        required_scope="docs.write",
        risk="low",
        low_risk_note="create new Google Docs",
    ),
    ToolSpec(
        "append_text",
        "Add text at the end of a Google Doc (start it with a newline for a new paragraph).",
        ActionCategory.WRITE,
        _schema(document_id=_DOCUMENT_ID, text={"type": "string", "required": True}),
        policy_key="google_docs",
        required_scope="docs.write",
    ),
    ToolSpec(
        "replace_text",
        "Replace every occurrence of some text in a Google Doc.",
        ActionCategory.WRITE,
        _schema(
            document_id=_DOCUMENT_ID,
            find={"type": "string", "required": True},
            replace_with={"type": "string", "required": True},
            match_case={"type": "boolean", "description": "Default false"},
        ),
        policy_key="google_docs",
        required_scope="docs.write",
    ),
)


def _collect(elements: Any, out: list[str], budget: list[int], depth: int = 0) -> None:
    """Append the text of structural *elements* to *out* (bounded)."""
    if depth > _MAX_DEPTH:
        return
    for element in as_list(elements):
        if budget[0] <= 0:
            return
        element = as_dict(element)
        paragraph = as_dict(element.get("paragraph"))
        for run in as_list(paragraph.get("elements")):
            content = as_dict(as_dict(run).get("textRun")).get("content")
            if isinstance(content, str):
                out.append(content[: budget[0]])
                budget[0] -= len(content)
        for row in as_list(as_dict(element.get("table")).get("tableRows")):
            cells = []
            for cell in as_list(as_dict(row).get("tableCells")):
                cell_text: list[str] = []
                _collect(as_dict(cell).get("content"), cell_text, budget, depth + 1)
                cells.append("".join(cell_text).strip())
            out.append("\t".join(cells) + "\n")
        _collect(as_dict(element.get("tableOfContents")).get("content"), out, budget, depth + 1)


def document_text(document: dict[str, Any]) -> str:
    """Plain text of a Docs API document resource (body only)."""
    out: list[str] = []
    _collect(as_dict(document.get("body")).get("content"), out, [_MAX_COLLECT_CHARS])
    return "".join(out)


class DocsActions(GoogleBase):
    """Google Docs action coroutines (mixed into GoogleWorkspaceConnector)."""

    async def _batch_update(self, document_id: str, requests: list[dict[str, Any]]) -> dict[str, Any]:
        return await self._call_object(
            "POST", f"{DOCS_API}/{path_segment(document_id)}:batchUpdate", json={"requests": requests}
        )

    # -- READ ------------------------------------------------------------------

    async def get_document(self, document_id: str, offset: Any = None) -> dict[str, Any]:
        doc_id = require_id(document_id, "document_id")
        start = optional_offset(offset)
        document = await self._call_object(
            "GET",
            f"{DOCS_API}/{path_segment(doc_id)}",
            params={"fields": "documentId,title,revisionId,body"},
        )
        return {
            "document_id": scalar(document.get("documentId")) or doc_id,
            "title": scalar(document.get("title")) or "",
            **text_window(document_text(document), start, DOCUMENT_TEXT_CHARS, action="get_document"),
        }

    # -- WRITE -----------------------------------------------------------------

    async def create_document(
        self, title: str, text: Optional[str] = None, *, user_confirmed: bool = False
    ) -> dict[str, Any]:
        name = require_line(title, "title", max_chars=500)
        body = optional_text(text, "text")
        if not user_confirmed:
            raise UserConfirmationRequired(
                action="create_document",
                details=(
                    f"Create the Google Doc '{name}'"
                    + (f" with {len(body)} characters of text?" if body else "?")
                ),
            )
        created = await self._call_object("POST", DOCS_API, json={"title": name})
        doc_id = scalar(created.get("documentId"))
        if not doc_id:
            raise ConnectorError("Malformed response from Google Workspace.")
        if body:
            await self._batch_update(doc_id, [{"insertText": {"location": {"index": 1}, "text": body}}])
        return {
            "document_id": doc_id,
            "title": scalar(created.get("title")) or name,
            "link": f"https://docs.google.com/document/d/{path_segment(doc_id)}/edit",
        }

    async def append_text(
        self, document_id: str, text: str, *, user_confirmed: bool = False
    ) -> dict[str, Any]:
        doc_id = require_id(document_id, "document_id")
        body = require_text(text, "text")
        if not user_confirmed:
            preview = body if len(body) <= 300 else body[:300] + "..."
            raise UserConfirmationRequired(
                action="append_text",
                details=f"Add this text at the end of Google Doc {doc_id}?\n{preview}",
            )
        await self._batch_update(
            doc_id, [{"insertText": {"endOfSegmentLocation": {}, "text": body}}]
        )
        return {"status": "appended", "document_id": doc_id, "characters": len(body)}

    async def replace_text(
        self,
        document_id: str,
        find: str,
        replace_with: str,
        match_case: Optional[bool] = None,
        *,
        user_confirmed: bool = False,
    ) -> dict[str, Any]:
        doc_id = require_id(document_id, "document_id")
        needle = require_text(find, "find", max_chars=5000)
        if not isinstance(replace_with, str) or len(replace_with) > 50_000:
            raise ConnectorError("'replace_with' must be a string of at most 50000 characters.")
        exact = optional_bool(match_case, "match_case", False)
        if not user_confirmed:
            raise UserConfirmationRequired(
                action="replace_text",
                details=(
                    f"In Google Doc {doc_id}, replace every '{needle[:200]}' with "
                    f"'{replace_with[:200]}'{' (case-sensitive)' if exact else ''}?"
                ),
            )
        result = await self._batch_update(
            doc_id,
            [
                {
                    "replaceAllText": {
                        "containsText": {"text": needle, "matchCase": exact},
                        "replaceText": replace_with,
                    }
                }
            ],
        )
        replies = as_list(result.get("replies"))
        changed = as_dict(as_dict(replies[0] if replies else {}).get("replaceAllText")).get(
            "occurrencesChanged"
        )
        count = changed if isinstance(changed, int) and not isinstance(changed, bool) else 0
        return {"status": "replaced", "document_id": doc_id, "occurrences_changed": count}
