"""What an audit row keeps of a knowledge.* result: citations, ids and counts,
never a passage's text.

Why it exists: the audit log is append-only and can never be deleted, while
the knowledge base itself can. A search or read result carries the user's
saved text; its audit row keeps only which passages were cited (the
citation, the document id, the passage number), whether they were withheld,
and the counts, so the owner can see what the assistant looked at without
the log becoming a second, undeletable copy of their documents.

Stdlib only.
"""

from __future__ import annotations

from typing import Any

_KEEP = (
    "ok",
    "mode",
    "withheld_count",
    "error",
    "code",
    "rule",
    "next_start",
    "count",
    "collection_id",
    "collection_created",
    "document_id",
    "passages_removed",
    "documents_removed",
)


def _ref_facts(row: Any) -> Any:
    if not isinstance(row, dict):
        return None
    kept = {k: row[k] for k in ("ref", "citation", "document_id", "passage", "withheld") if k in row}
    return kept or None


def knowledge_result_for_audit(tool_name: Any, result: Any) -> Any:
    """*result* reduced to its facts when *tool_name* is a knowledge.* tool;
    anything else comes back unchanged."""
    if not isinstance(tool_name, str) or not tool_name.split("__", 1)[0].startswith("knowledge."):
        return result
    if not isinstance(result, dict):
        return result
    facts: dict[str, Any] = {k: result[k] for k in _KEEP if k in result}
    if isinstance(result.get("results"), list):
        facts["results"] = [f for f in (_ref_facts(r) for r in result["results"]) if f]
    if isinstance(result.get("passages"), list):
        facts["passages"] = [
            {k: p[k] for k in ("passage", "locator", "withheld") if k in p}
            for p in result["passages"]
            if isinstance(p, dict)
        ]
    if isinstance(result.get("items"), list):
        facts["items"] = [
            {k: item[k] for k in ("document_id", "status", "pages", "passages", "withheld", "redacted") if k in item}
            for item in result["items"]
            if isinstance(item, dict)
        ]
    for key in ("collections", "documents"):
        if isinstance(result.get(key), list):
            facts[key] = len(result[key])
    return facts
