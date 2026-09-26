"""Tests for the connector output-shaping helpers: clamp_limit, cap_text,
collect_pages and pick.

Why it exists: these helpers enforce the list limits (default 10, maximum
50), the body caps and the pagination bounds every connector relies on, so a
model-supplied limit or a misbehaving provider cursor can never produce an
oversized result or an endless loop.
Connects to: services/connectors/shaping.py. No network.
"""

from __future__ import annotations

from typing import Any, Optional

import pytest

from services.connectors.base import ConnectorError
from services.connectors.shaping import cap_text, clamp_limit, collect_pages, pick

# ---------------------------------------------------------------------------
# clamp_limit
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (None, 10),
        (5, 5),
        (50, 50),
        (51, 50),
        (10_000, 50),
        (0, 1),
        (-5, 1),
        (7.9, 7),
        ("12", 12),
        (" 3 ", 3),
        ("abc", 10),
        ("", 10),
        (True, 10),
        (False, 10),
        (float("nan"), 10),
        (float("inf"), 10),
        ("1e9", 50),
        ([5], 10),
        ({"n": 5}, 10),
    ],
)
def test_clamp_limit(value, expected):
    assert clamp_limit(value) == expected


def test_clamp_limit_custom_bounds_and_default_is_clamped_too():
    assert clamp_limit(None, default=3, maximum=5) == 3
    assert clamp_limit(99, default=3, maximum=5) == 5
    assert clamp_limit(None, default=100, maximum=20) == 20
    assert clamp_limit(None, default=0, maximum=20) == 1


# ---------------------------------------------------------------------------
# cap_text
# ---------------------------------------------------------------------------


def test_cap_text():
    assert cap_text("hello", 10) == ("hello", False)
    assert cap_text("hello", 5) == ("hello", False)
    assert cap_text("hello world", 5) == ("hello", True)
    assert cap_text(None, 5) == ("", False)
    assert cap_text("", 0) == ("", False)
    assert cap_text("abc", 0) == ("", True)
    assert cap_text("abc", -1) == ("", True)


# ---------------------------------------------------------------------------
# collect_pages
# ---------------------------------------------------------------------------


class _Pages:
    """Scripted page fetcher recording the cursors it was called with."""

    def __init__(self, pages: list[tuple[Any, Optional[str]]]) -> None:
        self._pages = pages
        self.cursors: list[Optional[str]] = []

    async def __call__(self, cursor: Optional[str]) -> tuple[Any, Optional[str]]:
        self.cursors.append(cursor)
        return self._pages[min(len(self.cursors), len(self._pages)) - 1]


@pytest.mark.asyncio
async def test_collect_pages_stops_at_the_limit_mid_page():
    fetch = _Pages([([1, 2, 3], "c1"), ([4, 5, 6], "c2"), ([7], None)])
    assert await collect_pages(fetch, limit=5) == [1, 2, 3, 4, 5]
    assert fetch.cursors == [None, "c1"]


@pytest.mark.asyncio
@pytest.mark.parametrize("end", [None, ""])
async def test_collect_pages_stops_on_empty_cursor(end):
    fetch = _Pages([([1], "c1"), ([2], end), ([3], "c3")])
    assert await collect_pages(fetch, limit=10) == [1, 2]
    assert fetch.cursors == [None, "c1"]


@pytest.mark.asyncio
async def test_collect_pages_stops_on_a_repeated_cursor():
    fetch = _Pages([([1], "c1"), ([2], "c2"), ([3], "c1"), ([4], "c9")])
    assert await collect_pages(fetch, limit=10) == [1, 2, 3]
    assert fetch.cursors == [None, "c1", "c2"]


@pytest.mark.asyncio
async def test_collect_pages_stops_when_the_cursor_does_not_advance():
    fetch = _Pages([([1], "same")])
    assert await collect_pages(fetch, limit=10) == [1, 1]
    assert fetch.cursors == [None, "same"]


@pytest.mark.asyncio
async def test_collect_pages_respects_max_pages():
    counter = iter(range(100))
    fetch = _Pages([([0], f"c{next(counter)}") for _ in range(20)])
    items = await collect_pages(fetch, limit=50, max_pages=3)
    assert len(items) == 3
    assert len(fetch.cursors) == 3


@pytest.mark.asyncio
async def test_collect_pages_rejects_a_non_list_page():
    fetch = _Pages([({"items": [1]}, None)])
    with pytest.raises(ConnectorError, match="not a list"):
        await collect_pages(fetch, limit=5)


@pytest.mark.asyncio
async def test_collect_pages_with_nothing_to_collect_never_fetches():
    fetch = _Pages([([1], None)])
    assert await collect_pages(fetch, limit=0) == []
    assert await collect_pages(fetch, limit=5, max_pages=0) == []
    assert fetch.cursors == []


@pytest.mark.asyncio
async def test_collect_pages_handles_empty_pages():
    fetch = _Pages([([], "c1"), ([], None)])
    assert await collect_pages(fetch, limit=5) == []
    assert fetch.cursors == [None, "c1"]


# ---------------------------------------------------------------------------
# pick
# ---------------------------------------------------------------------------


def test_pick_keeps_only_present_keys_in_order():
    source = {"id": 1, "title": "t", "secret": "s", "url": None}
    assert pick(source, "id", "url", "missing") == {"id": 1, "url": None}
    assert "secret" not in pick(source, "id", "title")


@pytest.mark.parametrize("value", [None, [], "text", 5])
def test_pick_on_a_non_mapping_is_empty(value):
    assert pick(value, "id") == {}
