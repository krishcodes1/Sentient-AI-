"""Tests that a web.fetch_page result reaches the model whole: the toolkit clips
page text by the length the runtime will show (JSON escapes and the visible
form of invisible characters included), the runtime's web.fetch_page budget
passes the largest such result through uncut, and the tool's "request a larger
max_chars" note only promises what a retry can deliver.

Why it exists: The runtime used to cut every fetched page to a 2000-character
head and tail whatever max_chars the model asked for, so the middle of any long
article was invisible and the tool's own hint prompted retries that could not
help. Nothing failed; the answers were just quietly worse.
"""

from __future__ import annotations

from typing import Any

import httpx
import pytest

from core.config import settings
from services.agent.approvals import InMemoryApprovalStore
from services.agent.providers import LLMResponse, ToolCall
from services.agent.runtime import (
    RESULT_CHAR_BUDGETS,
    AgentRuntime,
    PermissionEngine,
    Tool,
    result_char_budget,
)
from services.agent.tool_registry import CONNECTOR_CATALOG
from services.tools import web
from services.tools.html_text import extract_readable_text
from services.tools.web import DEFAULT_PAGE_CHARS, MAX_PAGE_CHARS
from tests.conftest import use_provider
from tests.test_agent_runtime_vision import RecordingAudit, RecordingGuard, RecordingProvider
from tests.test_web_tools import PUBLIC_ADDRESS, toolkit

FETCH_TOOL = Tool(
    name="web.fetch_page",
    description="fetch",
    parameters={"type": "object", "properties": {"url": {"type": "string"}}},
    connector_type="web",
    permission_tier="auto",
)

# Every kind of character that shows longer than it is: a quote and a
# backslash (two each), a line break (two), a soft hyphen and a zero-width
# non-joiner (six each, as ­ / ‌) and a Unicode tag letter (twelve,
# as a surrogate-pair escape). Pages in German (soft hyphens), Persian
# (ZWNJ) or with emoji sequences (ZWJ) are full of the invisible ones.
_NASTY = 'say "hi" \\ Straße Ge­schich­te zw‌nj‌‌‌ tag\U000e0041'


def _page(lines: int = 2000) -> str:
    rows = "".join(f"<p>row {i:04d} {_NASTY}</p>" for i in range(lines))
    return f"<html><head><title>{'&quot;' * 400}</title></head><body>{rows}</body></html>"


# A long final URL, which the result echoes back to the model.
_LONG_URL = "https://example.com/" + "a/" * 400 + "article"


def _fetcher():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, html=_page())

    return toolkit(handler, {"example.com": (PUBLIC_ADDRESS,)})


class _Executor:
    def __init__(self, result: dict[str, Any]) -> None:
        self._result = result

    async def execute(self, tool_name, arguments, user_id, approved=False, *, task_id=None):
        return self._result


async def _what_the_model_sees(result: dict[str, Any]) -> str:
    provider = RecordingProvider(
        [
            LLMResponse(
                content="",
                tool_calls=[ToolCall(id="c1", name="web.fetch_page", arguments={"url": _LONG_URL})],
            ),
            LLMResponse(content="done"),
        ]
    )
    runtime = AgentRuntime(
        config=settings,
        permission_engine=PermissionEngine(),
        prompt_guard=RecordingGuard(),
        audit_service=RecordingAudit(),
        approval_store=InMemoryApprovalStore(),
        tool_executor=_Executor(result),
    )
    use_provider(runtime, provider)
    await runtime.chat(
        messages=[{"role": "user", "content": "read it"}], tools=[FETCH_TOOL], user_id="u1"
    )
    return provider.calls[1]["messages"][-1]["content"]


def _rows(text: str) -> list[str]:
    return [line.split()[1] for line in text.splitlines() if line.startswith("row ")]


@pytest.mark.asyncio
async def test_the_largest_fetch_reaches_the_model_whole():
    """max_chars at its ceiling on a page far longer than that, full of
    characters that escape long: the runtime still shows every row the tool
    returned, the middle ones included, and cuts nothing."""
    import json

    result = await _fetcher().fetch_page(_LONG_URL, max_chars=10_000_000)
    assert result["ok"] is True and result["truncated"] is True
    rows = _rows(result["text"])
    assert len(rows) > 20
    # Precondition: the old 2000-char default would have cut most of it.
    assert len(json.dumps(result, ensure_ascii=False)) > 4 * 2000

    sent = await _what_the_model_sees(result)

    assert "chars truncated" not in sent
    for row in (rows[0], rows[len(rows) // 2], rows[-1]):
        assert f"row {row}" in sent


@pytest.mark.asyncio
async def test_the_toolkit_clips_by_what_the_model_is_shown_and_no_shorter():
    result = await _fetcher().fetch_page(_LONG_URL, max_chars=MAX_PAGE_CHARS)
    full = extract_readable_text(_page())[1]
    clipped = web._clip_as_shown(full, MAX_PAGE_CHARS)

    assert result["text"] == clipped.rstrip()
    assert web._shown_length(clipped) <= MAX_PAGE_CHARS
    # Maximal: one more character of the page would not have fitted.
    assert web._shown_length(full[: len(clipped) + 1]) > MAX_PAGE_CHARS
    # This page shows far longer than it is: clipped by raw length, its
    # text alone would overrun the runtime's budget and lose its middle.
    assert web._shown_length(full[:MAX_PAGE_CHARS]) > RESULT_CHAR_BUDGETS["web.fetch_page"]


def test_shown_length_matches_the_runtimes_rendering():
    """The same count the runtime's envelope produces for a string value:
    compact JSON, non-ASCII kept, invisible characters escaped."""
    import json

    from services.agent.runtime import _HIDDEN_CHARS

    for sample in (_NASTY, "plain", "", "line\nbreak\ttab", "‍" * 7, "\U000e0041\U000e007f"):
        rendered = json.dumps(sample, ensure_ascii=False, separators=(",", ":"))
        rendered = _HIDDEN_CHARS.sub(lambda m: json.dumps(m.group())[1:-1], rendered)
        assert web._shown_length(sample) == len(rendered) - 2


@pytest.mark.asyncio
async def test_the_note_only_promises_what_a_retry_delivers():
    fetcher = _fetcher()
    default = await fetcher.fetch_page(_LONG_URL)
    assert default["truncated"] is True
    assert f"up to {MAX_PAGE_CHARS}" in default["note"]

    # Following the note: the retry returns more of the page, and the
    # runtime shows the model all of it (previous test).
    retried = await fetcher.fetch_page(_LONG_URL, max_chars=MAX_PAGE_CHARS)
    assert len(retried["text"]) > len(default["text"])
    assert retried["text"].startswith(default["text"])
    assert "Request a larger" not in retried["note"]
    assert "will not show more" in retried["note"]

    # And that note is true: asking past the ceiling returns the same text.
    beyond = await fetcher.fetch_page(_LONG_URL, max_chars=MAX_PAGE_CHARS * 10)
    assert beyond["text"] == retried["text"]


@pytest.mark.asyncio
async def test_a_short_page_has_no_note():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, html="<title>T</title><p>Short page.</p>")

    result = await toolkit(handler, {"example.com": (PUBLIC_ADDRESS,)}).fetch_page(
        "https://example.com/short"
    )
    assert result["truncated"] is False and "note" not in result


def test_the_budget_covers_the_ceiling_and_only_page_fetches():
    budget = RESULT_CHAR_BUDGETS["web.fetch_page"]
    assert budget >= MAX_PAGE_CHARS + 2000  # room for url, title, note and keys
    assert result_char_budget("web.fetch_page", 2000) == budget
    # Search results and screenshots keep the default; a new web.* tool
    # with long results needs its own entry.
    assert result_char_budget("web.search", 2000) == 2000
    assert result_char_budget("web.screenshot", 2000) == 2000


def test_the_catalog_states_the_real_limits():
    spec = next(s for s in CONNECTOR_CATALOG["web"] if s.action == "fetch_page")
    description = spec.parameters["properties"]["max_chars"]["description"]
    assert f"default {DEFAULT_PAGE_CHARS}" in description
    assert f"at most {MAX_PAGE_CHARS}" in description
