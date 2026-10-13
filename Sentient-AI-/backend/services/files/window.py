"""Picks the part of a document one read returns: whole sections, from a
starting section or page, up to a budget measured the way the model sees it.

Why it exists: files.read, web.fetch_page and the connector readers all hand
the model a document a window at a time, with ``next_start`` to continue.
Sizing the window by the text as shown (JSON escapes included, via
services/tools/text_budget) keeps a full window inside the runtime's result
budget, so the model never gets a section cut out of the middle of the
payload. Sections are whole (a section never exceeds 4000 characters); only
when one section alone is over a small ``max_chars`` is it clipped, and the
item says so.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Optional, Sequence

from services.files.limits import WINDOW_DEFAULT_CHARS, WINDOW_MAX_CHARS, WINDOW_MIN_CHARS
from services.files.sections import Section
from services.tools.text_budget import clip_as_shown, shown_length

# ", " between list items as the runtime renders the list.
_ITEM_GAP = 2


@dataclass(frozen=True)
class Window:
    """One read's sections as the model gets them (dicts with ``n``,
    ``label``, ``page`` and ``text``; ``clipped`` when the one section was
    cut to fit), the section number it starts at, where the next read
    starts (None at the end) and whether the window stops before the end."""

    sections: tuple[dict[str, Any], ...]
    start: int
    next_start: Optional[int]
    truncated: bool


def clamp_max_chars(value: Any, default: int = WINDOW_DEFAULT_CHARS) -> int:
    """*value* as a window size in [WINDOW_MIN_CHARS, WINDOW_MAX_CHARS];
    *default* when it is not a number."""
    try:
        number = int(value)
    except (TypeError, ValueError, OverflowError):
        return default
    return max(WINDOW_MIN_CHARS, min(number, WINDOW_MAX_CHARS))


def _item(n: int, section: Section) -> dict[str, Any]:
    return {"n": n, "label": section.label, "page": section.page, "text": section.text}


def window(
    sections: Sequence[Section],
    *,
    start: int = 1,
    page: Optional[int] = None,
    max_chars: int = WINDOW_DEFAULT_CHARS,
) -> Window:
    """Sections from *start* (1-based), or from the first section of *page*
    when *start* is not given past 1, until *max_chars* as shown. Always at
    least one section when any is left."""
    total = len(sections)
    first = max(1, int(start))
    if page is not None and first == 1:
        found = next((i + 1 for i, s in enumerate(sections) if s.page is not None and s.page >= page), None)
        first = found if found is not None else total + 1
    items: list[dict[str, Any]] = []
    used = 2  # the list's brackets
    index = first
    while index <= total:
        item = _item(index, sections[index - 1])
        size = shown_length(item) + (_ITEM_GAP if items else 0)
        if items and used + size > max_chars:
            break
        if not items and used + size > max_chars:
            # One section on its own is over a small budget: clip its text.
            overhead = shown_length({**item, "text": "", "clipped": True}) + 2
            item = {**item, "text": clip_as_shown(item["text"], max(0, max_chars - overhead)), "clipped": True}
            items.append(item)
            index += 1
            break
        items.append(item)
        used += size
        index += 1
    next_start = index if index <= total else None
    return Window(sections=tuple(items), start=first, next_start=next_start, truncated=next_start is not None)
