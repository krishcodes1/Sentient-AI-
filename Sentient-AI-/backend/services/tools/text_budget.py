"""Measures text the way the runtime shows it to the model, and clips text to
fit a budget measured that way.

Why it exists: a tool result reaches the model as JSON, where a line break or
a quote takes two characters and an invisible character is written out as a
six- or twelve-character escape (runtime._wrap_tool_results). A window sized
in raw characters overruns the runtime's result budget and loses its middle
there instead. web.fetch_page, the document windows (services/files/window.py)
and any later reader share this one measure, so their budgets agree.

Stdlib plus the guard's invisible-character pattern only, so the file worker
and other light modules can import it.
"""

from __future__ import annotations

import json
from typing import Any

# The characters the runtime writes out as visible \uXXXX escapes before it
# shows a result to the model; a stdlib-only module, so importing it pulls
# nothing else from the agent package.
from services.agent.prompt_guard import _INVISIBLE_CHARS as _HIDDEN_CHARS


def shown_length(value: Any) -> int:
    """How many characters *value* takes in the JSON the runtime shows the
    model. A string is measured as the contents of its JSON string (no
    quotes); anything else as its whole JSON encoding. An invisible
    character counts as the escape the runtime writes it out as."""
    if isinstance(value, str):
        shown = json.dumps(value, ensure_ascii=False)[1:-1]
    else:
        shown = json.dumps(value, ensure_ascii=False, default=str)
    return len(_HIDDEN_CHARS.sub(lambda m: json.dumps(m.group())[1:-1], shown))


def clip_as_shown(text: str, limit: int) -> str:
    """The longest start of *text* whose shown length is at most *limit*.

    Counting raw characters let a page of short lines (a table, a list)
    come out a third longer than *limit* once escaped, overrun the
    runtime's budget and lose its middle there instead.
    """
    if limit <= 0:
        return ""
    # Every character shows as at least one, so a text longer than the
    # limit cannot fit, and the whole of a 2 MB page is never escaped.
    if len(text) <= limit and shown_length(text) <= limit:
        return text
    low, high = 0, min(len(text), limit)
    while low < high:
        middle = (low + high + 1) // 2
        if shown_length(text[:middle]) <= limit:
            low = middle
        else:
            high = middle - 1
    return text[:low]
