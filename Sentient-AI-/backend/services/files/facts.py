"""Reduces a document result to facts: what an audit row and a stored
transcript keep of a files.* call or any result that carries sections.

Why it exists: the audit log is append-only and the transcript is kept for
months, but a document's text lives only in the encrypted store (uploads) or
in memory for 30 minutes (opened documents). So what is written about a
read is its facts: ids, kind, counts, characters, which section numbers and
pages were shown, an error code; never the text, a slide title, a sheet
name or a file name.

Stdlib only.
"""

from __future__ import annotations

from typing import Any

_KEEP = (
    "ok",
    "file_id",
    "doc_id",
    "kind",
    "source",
    "pages_total",
    "sections_total",
    "start",
    "next_start",
    "truncated",
    "ocr_pages",
    "code",
    "count",
    "refused",
    "rule",
    "forgotten",
    "redacted",
)


def is_files_tool(name: Any) -> bool:
    return isinstance(name, str) and name.startswith("files.")


def _section_facts(sections: list[Any]) -> list[dict[str, Any]]:
    facts: list[dict[str, Any]] = []
    for item in sections[:100]:
        if not isinstance(item, dict):
            continue
        entry: dict[str, Any] = {}
        for key in ("n", "page"):
            value = item.get(key)
            if isinstance(value, int) and not isinstance(value, bool):
                entry[key] = value
        text = item.get("text")
        entry["chars"] = len(text) if isinstance(text, str) else 0
        if item.get("redacted") is True:
            entry["redacted"] = True
        facts.append(entry)
    return facts


def document_facts(result: dict[str, Any], *, keep_error: bool) -> dict[str, Any]:
    """*result* with its text replaced by counts (see the module doc)."""
    facts: dict[str, Any] = {k: result[k] for k in _KEEP if k in result and not isinstance(result[k], (dict, list))}
    sections = result.get("sections")
    if isinstance(sections, list):
        facts["sections"] = _section_facts(sections)
        facts["chars"] = sum(s.get("chars", 0) for s in facts["sections"])
    unread = result.get("scanned_pages_unread")
    if isinstance(unread, list):
        facts["scanned_pages_unread"] = len(unread)
    files = result.get("files")
    if isinstance(files, list):
        facts["files"] = len(files)
    warnings = result.get("warnings")
    if isinstance(warnings, list):
        facts["warnings"] = [w for w in warnings if isinstance(w, str)][:20]
    error = result.get("error")
    if keep_error and isinstance(error, str):
        facts["error"] = error[:300]
    elif isinstance(error, str):
        facts["error"] = True
    return facts


def _carries_sections(value: Any) -> bool:
    return isinstance(value, dict) and isinstance(value.get("sections"), list)


def result_facts(tool_name: Any, result: Any) -> Any:
    """What may be written down about one call's *result*: files.* results
    and any result carrying ``sections`` (a web or connector document,
    directly or as a connector's ``result``) as facts; anything else
    unchanged."""
    if not isinstance(result, dict):
        return result
    if is_files_tool(tool_name):
        return document_facts(result, keep_error=True)
    if _carries_sections(result):
        return document_facts(result, keep_error=False)
    inner = result.get("result")
    if isinstance(inner, dict) and _carries_sections(inner):
        return {**{k: v for k, v in result.items() if k != "result"}, "result": document_facts(inner, keep_error=False)}
    return result


def stored_tool_calls(tool_calls: Any) -> Any:
    """A turn's tool calls as the transcript keeps them: files.* results as
    facts only (the text is in the encrypted store); others unchanged."""
    if not isinstance(tool_calls, list):
        return tool_calls
    out: list[Any] = []
    for call in tool_calls:
        if isinstance(call, dict) and is_files_tool(call.get("name")) and isinstance(call.get("result"), dict):
            out.append({**call, "result": document_facts(call["result"], keep_error=True)})
        else:
            out.append(call)
    return out
