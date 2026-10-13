"""What an audit row keeps of a video.* result: metadata and counts, never a
passage, a title or any other publisher text.

Why it exists: the runtime stores the first 500 characters of every tool
result in its tool_executed row, and the audit log is append-only. A
transcript is publisher text (and can be long, personal or poisoned), so
runtime.result_for_audit hands video results here and the row keeps what the
call did, not what the video said.
"""

from __future__ import annotations

from typing import Any

from services.tools.video.sources import host_of

_KEPT = (
    "ok",
    "source",
    "method",
    "detail",
    "engine",
    "language",
    "duration",
    "covered",
    "cached",
    "next_start",
    "code",
    "needs_choice",
    "count",
)


def audit_facts(result: Any) -> Any:
    """*result* reduced to its facts: the keys above, the host of its url,
    how many passages (and characters of them), candidates or transcripts
    it held, and an error's own text (Crawler's words, at most 200
    characters)."""
    if not isinstance(result, dict):
        return result
    facts: dict[str, Any] = {k: result[k] for k in _KEPT if k in result}
    if isinstance(result.get("url"), str):
        facts["host"] = host_of(result["url"])
    passages = result.get("passages")
    if isinstance(passages, list):
        facts["passages"] = len(passages)
        facts["chars"] = sum(
            len(p.get("text") or "") for p in passages if isinstance(p, dict) and isinstance(p.get("text"), str)
        )
    for key in ("candidates", "transcripts"):
        if isinstance(result.get(key), list):
            facts[key] = len(result[key])
    if isinstance(result.get("error"), str):
        facts["error"] = result["error"][:200]
    return facts
