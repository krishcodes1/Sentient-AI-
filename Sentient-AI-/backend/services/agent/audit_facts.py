"""What an audit row keeps of a tool result, by allowlist: numbers and flags,
strings only under keys a toolkit names as ids or Crawler's own words, lists
of short names (tool names, channels, changed fields) where it names them,
nested rows reduced by their own rules, and every other list as its length.

Why it exists: the runtime stores the first 500 characters of every tool
result in its tool_executed row (runtime.result_for_audit), and the audit log
is append-only. Some toolkits return the owner's own text (a scheduled task's
prompt, a flashcard) or someone else's (a mail subject a trigger saw), which
the owner can delete from the app but never from the log. A toolkit lists what
is safe to keep (services/scheduler/audit_facts.py and its neighbours); a field
nobody listed is dropped or counted, so a new text field stays out of the log
until someone adds it here on purpose.

Stdlib only.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Mapping

# An error is the toolkit's own sentence (a field name, a count, a limit),
# kept short.
ERROR_CHARS = 200
# A kept string (an id, a status, a schedule such as "every day at 07:30").
TEXT_CHARS = 120
# One entry of a kept list of names.
NAME_CHARS = 60


@dataclass(frozen=True)
class FactRules:
    """What one level of a result keeps.

    ``text``: keys whose string value is kept (ids, statuses, Crawler's own
    descriptions). ``names``: keys whose list of strings is kept (tool names,
    channels, changed field names). ``rows``: keys whose dict, or list of
    dicts, is reduced by the rules given for it. ``errors``: whether an
    ``error`` sentence is kept (ERROR_CHARS of it); off for a toolkit whose
    errors may quote what the caller sent (an invalid sender address)."""

    text: frozenset[str] = frozenset()
    names: frozenset[str] = frozenset()
    rows: Mapping[str, "FactRules"] = field(default_factory=dict)
    errors: bool = True


def _number(value: Any) -> bool:
    return value is None or isinstance(value, (bool, int, float))


def keep_facts(value: Any, rules: FactRules) -> Any:
    """*value* reduced by *rules*: see the module docstring. Anything that
    is not a dict comes back as its type name, never its content."""
    if not isinstance(value, Mapping):
        return value if _number(value) else f"<{type(value).__name__}>"
    facts: dict[str, Any] = {}
    for key, item in value.items():
        if not isinstance(key, str):
            continue
        if _number(item):
            facts[key] = item
        elif isinstance(item, str):
            if key == "error":
                if rules.errors:
                    facts[key] = item[:ERROR_CHARS]
            elif key in rules.text:
                facts[key] = item[:TEXT_CHARS]
        elif isinstance(item, Mapping):
            if key in rules.rows:
                facts[key] = keep_facts(item, rules.rows[key])
        elif isinstance(item, (list, tuple)):
            if key in rules.rows:
                facts[key] = [
                    keep_facts(row, rules.rows[key]) for row in item if isinstance(row, Mapping)
                ]
            elif key in rules.names and all(isinstance(name, str) for name in item):
                facts[key] = [name[:NAME_CHARS] for name in item]
            elif all(_number(entry) for entry in item):
                facts[key] = list(item)
            else:
                facts[key] = len(item)
    return facts
