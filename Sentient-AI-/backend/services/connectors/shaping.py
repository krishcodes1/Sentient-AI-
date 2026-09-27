"""Output-shaping helpers shared by the connectors: list limits, text caps,
bounded pagination and field picking.

Why it exists: every connector must return only what the model needs, with
lists defaulting to 10 items (hard maximum 50), long bodies capped with a
"truncated" flag, and pagination that can never loop or run away. One copy
keeps those limits identical across GitHub, Notion, Slack, Google and
Microsoft instead of each connector reinventing them.
Connects to: the connector modules in services/connectors/ (their public
action coroutines). No network access of its own.
Depends on: services.connectors.base (ConnectorError).
"""

from __future__ import annotations

import math
from collections.abc import Awaitable, Callable, Mapping
from typing import Any, Optional

from services.connectors.base import ConnectorError

#: Items a list action returns when the model does not ask for a number.
DEFAULT_LIMIT = 10
#: Hard ceiling on items a list action returns, whatever the model asks.
MAX_LIMIT = 50

PageFetcher = Callable[[Optional[str]], Awaitable[tuple[list[Any], Optional[str]]]]


def clamp_limit(value: Any, *, default: int = DEFAULT_LIMIT, maximum: int = MAX_LIMIT) -> int:
    """Coerce a model-supplied item count into ``1..maximum``.

    ``None``, booleans, non-numeric strings, NaN and infinities fall back
    to *default* (itself clamped). Numbers and numeric strings are
    truncated to an int and clamped, so ``0`` or ``-5`` give 1 and
    ``1000`` gives *maximum*.
    """
    ceiling = max(1, int(maximum))
    fallback = min(max(1, int(default)), ceiling)
    if value is None or isinstance(value, bool):
        return fallback
    number: float
    if isinstance(value, (int, float)):
        number = float(value)
    elif isinstance(value, str):
        try:
            number = float(value.strip())
        except ValueError:
            return fallback
    else:
        return fallback
    if math.isnan(number) or math.isinf(number):
        return fallback
    return min(max(1, int(number)), ceiling)


def cap_text(text: Optional[str], max_chars: int) -> tuple[str, bool]:
    """Return ``(text cut to max_chars, was_truncated)``.

    ``None`` is treated as empty. A non-positive cap returns an empty
    string, flagged as truncated when there was anything to cut.
    """
    value = "" if text is None else str(text)
    limit = max(0, int(max_chars))
    if len(value) <= limit:
        return value, False
    return value[:limit], True


async def collect_pages(
    fetch: PageFetcher, *, limit: int, max_pages: int = 5
) -> list[Any]:
    """Gather up to *limit* items from a cursor-paginated endpoint.

    ``fetch(cursor)`` returns ``(items, next_cursor)``; the first call gets
    ``None``. Collection stops at *limit* items, at an empty or missing
    cursor, at a cursor already seen (a provider bug or a hostile server
    would otherwise loop forever), or after *max_pages* fetches. A page
    that is not a list raises ``ConnectorError``.
    """
    if limit <= 0 or max_pages <= 0:
        return []
    items: list[Any] = []
    cursor: Optional[str] = None
    seen: set[str] = set()
    for _ in range(max_pages):
        page, next_cursor = await fetch(cursor)
        if not isinstance(page, list):
            raise ConnectorError("Unexpected response shape: a page of results was not a list.")
        items.extend(page[: limit - len(items)])
        if len(items) >= limit or not next_cursor:
            break
        token = str(next_cursor)
        if token in seen:
            break
        seen.add(token)
        cursor = token
    return items


def pick(mapping: Any, *keys: str) -> dict[str, Any]:
    """A new dict holding only those of *keys* present in *mapping*.

    A non-mapping input (a provider answering with an unexpected shape)
    gives ``{}`` rather than raising.
    """
    if not isinstance(mapping, Mapping):
        return {}
    return {key: mapping[key] for key in keys if key in mapping}
