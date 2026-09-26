"""Tests that the GitHub actions returning one long body (get_file,
get_pr_diff, get_failed_logs) fit what the runtime shows the model.

Why it exists: the runtime serializes each tool result as compact JSON and
keeps only the head and tail of anything over the action's budget
(``services/agent/runtime.py`` RESULT_CHAR_BUDGETS, the context manager's
2000-character default otherwise). A result sized past that loses its
middle: the error lines of all but the last failed job, or file lines that
a start_line hint then skips. These tests run the shaped results through
the same serialization and ``compress_tool_result`` with the real budgets,
and check that the downloads behind them are streamed so only the kept
window of a huge file, diff or log is ever read or held in memory.
Exercises ``services/connectors/github_api/`` (common, repos, pulls,
workflows) through ``httpx.MockTransport`` only.
"""

from __future__ import annotations

import json
import random
import tracemalloc
from typing import Any

import httpx
import pytest

from services.agent.context_manager import ContextManager, compress_tool_result
from services.agent.prompt_guard import _INVISIBLE_CHARS
from services.agent.runtime import result_char_budget
from services.connectors.base import AuthenticationError, ConnectorError
from services.connectors.github_api.common import (
    DEFAULT_RESULT_CHARS,
    LONG_RESULT_CHARS,
    fit_head,
    fit_tail,
    json_text_cost,
)
from services.connectors.github_api.pulls import DIFF_WINDOW_BYTES
from services.connectors.github_api.repos import MAX_FILE_BYTES
from services.connectors.github_api.workflows import LOG_WINDOW, log_tail, share_budget
from tests.connectors.test_github import TOKEN, make_connector

TRUNCATION_MARK = "chars truncated"


def model_view(action: str, result: Any, *, connector: str = "github") -> str:
    """What the model is shown of *result*: the executor's envelope, as the
    runtime serializes it, cut to the action's real budget."""
    envelope = {
        "ok": True,
        "connector": connector,
        "action": action,
        "result": result,
        "sanitized": False,
        "execution_time_ms": 12345.67,
    }
    payload = json.dumps(envelope, default=str, ensure_ascii=False, separators=(",", ":"))
    payload = _INVISIBLE_CHARS.sub(lambda m: json.dumps(m.group())[1:-1], payload)
    default = ContextManager().max_tool_result_chars
    return compress_tool_result(payload, result_char_budget(f"github.{action}", default))


def assert_whole(view: str) -> None:
    assert TRUNCATION_MARK not in view, "the runtime cut the middle of the result"


# ---------------------------------------------------------------------------
# The connector's budgets are the runtime's
# ---------------------------------------------------------------------------


def test_budget_constants_match_the_runtime():
    default = ContextManager().max_tool_result_chars
    assert default == DEFAULT_RESULT_CHARS
    assert result_char_budget("github.get_file", default) == DEFAULT_RESULT_CHARS
    assert result_char_budget("github.get_pr_diff", default) == LONG_RESULT_CHARS
    assert result_char_budget("github.get_failed_logs", default) == LONG_RESULT_CHARS
    # A second account's slugged tool name gets the same budget.
    assert result_char_budget("github__1a2b3c4d.get_failed_logs", default) == LONG_RESULT_CHARS


# ---------------------------------------------------------------------------
# JSON cost helpers
# ---------------------------------------------------------------------------

_ALPHABET = 'ab c"\\\n\t\x01\x1b\u00e9\u4e2d\u200b\U000e0041\U0001f600'


def _escaped_len(text: str) -> int:
    """Characters *text* takes in the runtime's payload (quotes excluded)."""
    body = json.dumps(text, ensure_ascii=False)[1:-1]
    return len(_INVISIBLE_CHARS.sub(lambda m: json.dumps(m.group())[1:-1], body))


@pytest.mark.parametrize("seed", range(20))
def test_fit_head_and_tail_never_exceed_the_budget(seed: int):
    rng = random.Random(seed)
    text = "".join(rng.choice(_ALPHABET) for _ in range(3000))
    for budget in (0, 1, 7, 150, 1000):
        head, head_cut = fit_head(text, budget)
        tail, tail_cut = fit_tail(text, budget)
        assert _escaped_len(head) <= budget and _escaped_len(tail) <= budget
        assert text.startswith(head) and text.endswith(tail)
        assert head_cut and tail_cut
        assert json_text_cost(text) >= _escaped_len(text)
    assert fit_head(text, 10**6) == (text, False) and fit_tail(text, 10**6) == (text, False)


def test_fit_head_keeps_whole_lines_and_fit_tail_starts_at_a_line():
    text = "".join(f"row {i}\n" for i in range(100))
    head, _ = fit_head(text, 50)
    assert head.endswith("\n") and head == "".join(f"row {i}\n" for i in range(head.count("\n")))
    tail, _ = fit_tail(text, 50)
    assert tail.startswith("row ") and tail.endswith("row 99\n")


def test_share_budget_gives_small_items_what_they_need_and_the_rest_to_the_others():
    assert share_budget([100, 5000, 5000], 6100) == [100, 3000, 3000]
    assert share_budget([10, 20], 1000) == [10, 20]
    assert share_budget([900, 900, 900], 900) == [300, 300, 300]
    assert share_budget([5, 5], -40) == [0, 0]
    assert share_budget([], 100) == []


# ---------------------------------------------------------------------------
# get_failed_logs: every job's error line reaches the model
# ---------------------------------------------------------------------------


def _hostile_log(job: int, lines: int = 3000) -> str:
    """A long log with timestamps, colour codes, quotes and backslashes (all
    of which cost extra JSON characters), ending in the job's error line."""
    body = "".join(
        f'2026-09-25T10:00:{i % 60:02d}.1234567Z \x1b[36;1mstep {i}: "C:\\\\path\\\\{i}"\x1b[0m\n'
        for i in range(lines)
    )
    return body + f"2026-09-25T10:59:59.0000000Z ERROR_IN_JOB_{job}\n"


def _failed_jobs_handler(logs: dict[int, Any]) -> Any:
    jobs = {
        "jobs": [
            {
                "id": job_id,
                "name": f"job {job_id}",
                "status": "completed",
                "conclusion": "failure",
                "html_url": f"https://github.com/o/r/actions/runs/42/job/{job_id}",
                "steps": [{"name": "Run tests", "conclusion": "failure"}],
            }
            for job_id in logs
        ]
    }

    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.raw_path.decode()
        if "/runs/42/jobs" in path:
            return httpx.Response(200, json=jobs)
        job_id = int(path.split("/jobs/")[1].split("/")[0])
        log = logs[job_id]
        if isinstance(log, int):
            return httpx.Response(log, json={"message": "Gone"})
        return httpx.Response(200, content=log if isinstance(log, bytes) else log.encode())

    return handler


@pytest.mark.asyncio
@pytest.mark.parametrize("jobs", [3, 5])
async def test_failed_logs_of_every_job_survive_the_runtime_budget(jobs: int):
    logs: dict[int, Any] = {job: _hostile_log(job) for job in range(1, jobs + 1)}
    connector, seen = make_connector(_failed_jobs_handler(logs))
    result = await connector.get_failed_logs("o", "r", 42, limit=jobs)
    assert len(seen) == jobs + 1
    view = model_view("get_failed_logs", result)
    assert_whole(view)
    for job in range(1, jobs + 1):
        assert f"ERROR_IN_JOB_{job}" in view
    for entry in result["failed_jobs"]:
        assert entry["truncated"] is True and "html_url" in entry["hint"]
        # Clean text: no timestamps, no colour codes, a whole first line.
        assert "\x1b" not in entry["log_tail"] and "2026-09-25T" not in entry["log_tail"]
        assert entry["log_tail"].startswith("step ")


@pytest.mark.asyncio
async def test_a_short_log_is_shown_whole_and_leaves_its_share_to_the_others():
    logs: dict[int, Any] = {
        1: "2026-09-25T10:00:00Z short failure\nERROR_IN_JOB_1\n",
        2: _hostile_log(2),
        3: 410,  # expired logs: reported, not fetched
        4: _hostile_log(4),
    }
    connector, _ = make_connector(_failed_jobs_handler(logs))
    result = await connector.get_failed_logs("o", "r", 42, limit=4)
    short, long_a, gone, long_b = result["failed_jobs"]
    assert short["log_tail"] == "short failure\nERROR_IN_JOB_1\n"
    assert short["truncated"] is False and "hint" not in short
    assert "HTTP 410 from GitHub" in gone["log_error"] and "log_tail" not in gone
    # Two long logs share what the short one left: more than a quarter each.
    assert len(long_a["log_tail"]) > 3_000 and len(long_b["log_tail"]) > 3_000
    view = model_view("get_failed_logs", result)
    assert_whole(view)
    assert "ERROR_IN_JOB_2" in view and "ERROR_IN_JOB_4" in view


@pytest.mark.asyncio
async def test_a_huge_log_is_decoded_from_its_end_only():
    # 8 MB: the start (with a marker and bytes that are not UTF-8) lies far
    # outside the decoded window; the window starts mid-line.
    head = b"\xff\xfe START_MARKER " + b"x" * 1000 + b"\n"
    body = b"".join(b"filler line %d with some text\n" % i for i in range(300_000))
    log = head + body + b"ERROR_IN_JOB_1\n"
    assert len(log) > 8_000_000
    connector, _ = make_connector(_failed_jobs_handler({1: log}))
    result = await connector.get_failed_logs("o", "r", 42)
    (entry,) = result["failed_jobs"]
    assert entry["truncated"] is True
    assert entry["log_tail"].endswith("ERROR_IN_JOB_1\n")
    assert entry["log_tail"].startswith("filler line ")
    assert "START_MARKER" not in entry["log_tail"]
    assert_whole(model_view("get_failed_logs", result))


def test_log_tail_cleans_only_a_window_and_drops_its_partial_first_line():
    text = "A" * (LOG_WINDOW * 3) + "\n" + "".join(f"line {i}\n" for i in range(20_000))
    tail, truncated = log_tail(text, 500)
    assert truncated is True and tail.startswith("line ") and tail.endswith("line 19999\n")
    # A window cut in the middle of a line never shows that partial line.
    one_long_line = "B" * (LOG_WINDOW + 10) + "\nlast\n"
    assert log_tail(one_long_line, 500) == ("last\n", True)


# ---------------------------------------------------------------------------
# get_file: the start_line hint follows the last line the model saw
# ---------------------------------------------------------------------------


def _source_file(lines: int = 2000) -> str:
    return "".join(f'    value_{i} = "text \\"{i}\\""\t# line {i + 1}\n' for i in range(lines))


def _raw_file_handler(text: str) -> Any:
    return lambda request: httpx.Response(
        200, content=text.encode(), headers={"content-type": "application/vnd.github.raw"}
    )


def _next_start_line(result: dict[str, Any]) -> int:
    hint = result["hint"]
    return int(hint.split("start_line=")[1].split(" ")[0])


@pytest.mark.asyncio
async def test_get_file_page_fits_the_default_budget_and_the_hint_follows_the_last_line():
    text = _source_file()
    connector, _ = make_connector(_raw_file_handler(text))
    response = await connector.execute("get_file", {"owner": "o", "repo": "r", "path": "a.py"})
    result = response.data
    view = model_view("get_file", result)
    assert_whole(view)
    assert result["truncated"] is True and result["total_lines"] == 2000
    content = result["content"]
    last_line = content.count("\n")
    assert content.endswith(f"# line {last_line}\n")
    assert _next_start_line(result) == last_line + 1
    assert f"Showing lines 1 to {last_line}." in result["hint"]


@pytest.mark.asyncio
async def test_following_the_get_file_hints_reads_the_whole_file_exactly_once():
    text = _source_file()
    connector, _ = make_connector(_raw_file_handler(text))
    pages: list[str] = []
    start = 1
    while True:
        result = await connector.get_file("o", "r", "a.py", start_line=start)
        assert_whole(model_view("get_file", result))
        assert result["start_line"] == start
        assert result["content"].startswith(f"    value_{start - 1} = ")
        pages.append(result["content"])
        if not result["truncated"]:
            break
        start = _next_start_line(result)
        assert start == result["start_line"] + result["content"].count("\n")
    assert "".join(pages) == text and len(pages) > 10


@pytest.mark.asyncio
async def test_get_file_with_one_over_long_line_shows_its_start_and_skips_to_the_next():
    text = "x" * 50_000 + "\nsecond\n"
    connector, _ = make_connector(_raw_file_handler(text))
    first = await connector.get_file("o", "r", "min.js")
    assert first["truncated"] is True and first["content"] == first["content"].strip("\n")
    assert "Line 1 is too long" in first["hint"] and _next_start_line(first) == 2
    assert_whole(model_view("get_file", first))
    second = await connector.get_file("o", "r", "min.js", start_line=2)
    assert second["content"] == "second\n" and second["truncated"] is False


@pytest.mark.asyncio
async def test_get_file_non_ascii_and_invisible_characters_still_fit():
    text = "".join(f"\u4e2d\u6587 {i} \u200b\U000e0041 \u00e9\n" for i in range(2000))
    connector, _ = make_connector(_raw_file_handler(text))
    result = await connector.get_file("o", "r", "zh.txt")
    assert result["truncated"] is True
    assert_whole(model_view("get_file", result))


@pytest.mark.asyncio
async def test_get_file_start_line_past_the_end():
    connector, _ = make_connector(_raw_file_handler("a\nb\n"))
    result = await connector.get_file("o", "r", "a.txt", start_line=9)
    assert result["content"] == "" and result["truncated"] is False
    assert "past the end of the file (2 lines)" in result["hint"]


@pytest.mark.asyncio
async def test_get_file_on_a_large_folder_keeps_the_entries_that_fit():
    sha = "0123456789abcdef0123456789abcdef01234567"
    listing = [
        {"type": "file", "path": f"src/module_{i:03d}.py", "sha": sha, "size": i} for i in range(80)
    ]
    connector, _ = make_connector(lambda r: httpx.Response(200, json=listing))
    result = await connector.get_file("o", "r", "src")
    assert result["type"] == "dir" and result["total_entries"] == 80
    assert 1 <= len(result["entries"]) < 50 and "list_tree" in result["hint"]
    assert result["entries"][0]["path"] == "src/module_000.py"
    assert_whole(model_view("get_file", result))


# ---------------------------------------------------------------------------
# get_pr_diff: the capped diff arrives whole
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_get_pr_diff_fits_its_budget_and_ends_at_a_line():
    diff = "diff --git a/x.py b/x.py\n" + "".join(
        f'+    call("arg {i}", path="C:\\\\dir\\\\{i}")\n' for i in range(20_000)
    )
    connector, _ = make_connector(lambda r: httpx.Response(200, text=diff))
    result = await connector.get_pr_diff("o", "r", 4)
    view = model_view("get_pr_diff", result)
    assert_whole(view)
    assert result["truncated"] is True and result["diff"].endswith("\n")
    assert diff.startswith(result["diff"])
    lines = result["diff"].count("\n")
    assert f"Diff cut after {lines} lines." in result["hint"]
    assert "compare" in result["hint"] and "get_file" in result["hint"]
    # Most of the budget is used, not a timid fraction of it.
    assert len(view) > LONG_RESULT_CHARS * 0.9


@pytest.mark.asyncio
async def test_get_pr_diff_small_diff_is_returned_whole():
    diff = "diff --git a/x b/x\n+one\n"
    connector, _ = make_connector(lambda r: httpx.Response(200, text=diff))
    result = await connector.get_pr_diff("o", "r", 4)
    assert result == {"number": 4, "diff": diff, "truncated": False}


# ---------------------------------------------------------------------------
# Downloads are streamed: only the kept window is ever read or held
# ---------------------------------------------------------------------------

_CHUNK = b"abcdefghi\n" * 6554  # 65,540 bytes of 10-byte lines


class _CountingStream(httpx.AsyncByteStream):
    """A response body produced chunk by chunk that records how much of it
    was pulled and whether it was closed. *fail_after* raises a read
    timeout before that chunk."""

    def __init__(
        self, chunks: int, chunk: bytes = _CHUNK, last: bytes = b"", fail_after: int = -1
    ) -> None:
        self.chunks, self.chunk, self.last, self.fail_after = chunks, chunk, last, fail_after
        self.sent = 0
        self.closed = False

    async def __aiter__(self) -> Any:
        for index in range(self.chunks):
            if index == self.fail_after:
                raise httpx.ReadTimeout("slow body")
            self.sent += len(self.chunk)
            yield self.chunk
        if self.last:
            self.sent += len(self.last)
            yield self.last

    async def aclose(self) -> None:
        self.closed = True


def _streaming(stream: _CountingStream, content_type: str = "text/plain") -> Any:
    return lambda request: httpx.Response(
        200, stream=stream, headers={"content-type": content_type}
    )


@pytest.mark.asyncio
async def test_get_pr_diff_stops_downloading_after_its_window():
    stream = _CountingStream(chunks=200)  # about 13 MB
    connector, _ = make_connector(_streaming(stream))
    result = await connector.get_pr_diff("o", "r", 4)
    assert stream.sent <= DIFF_WINDOW_BYTES + len(_CHUNK) and stream.closed
    assert result["truncated"] is True and result["diff"].startswith("abcdefghi\n")
    assert_whole(model_view("get_pr_diff", result))


@pytest.mark.asyncio
async def test_get_file_on_a_huge_file_reads_only_the_cap_and_says_so():
    stream = _CountingStream(chunks=320)  # about 21 MB
    connector, _ = make_connector(_streaming(stream, "application/vnd.github.raw"))
    result = await connector.get_file("o", "r", "big.log")
    assert stream.sent <= MAX_FILE_BYTES + len(_CHUNK) and stream.closed
    assert result["partial_file"] is True and result["truncated"] is True
    assert "size" not in result and "total_lines" not in result
    assert result["content"].startswith("abcdefghi\n")
    assert_whole(model_view("get_file", result))


@pytest.mark.asyncio
async def test_get_file_pages_up_to_the_last_whole_line_read_then_explains_the_limit():
    lines_read = MAX_FILE_BYTES // 10  # the cut line after them is dropped
    connector, _ = make_connector(lambda r: _streaming(_CountingStream(chunks=40))(r))
    last = await connector.get_file("o", "r", "big.log", start_line=lines_read)
    assert last["content"] == "abcdefghi\n" and last["truncated"] is True
    assert f"start_line={lines_read + 1}" in last["hint"]
    past = await connector.get_file("o", "r", "big.log", start_line=lines_read + 1)
    assert past["content"] == "" and past["partial_file"] is True
    assert f"past line {lines_read}, as far as get_file reads" in past["hint"]


@pytest.mark.asyncio
async def test_get_file_on_a_huge_binary_file_has_no_size():
    stream = _CountingStream(chunks=100, chunk=b"\x89PNG\x00" * 10_000)
    connector, _ = make_connector(_streaming(stream, "application/vnd.github.raw"))
    result = await connector.get_file("o", "r", "big.png")
    assert result["binary"] is True and "size" not in result and "content" not in result
    assert stream.sent <= MAX_FILE_BYTES + len(stream.chunk)


@pytest.mark.asyncio
async def test_get_file_with_a_malformed_folder_listing_is_a_clean_error():
    connector, _ = make_connector(
        lambda r: httpx.Response(
            200, content=b"[{not json", headers={"content-type": "application/json"}
        )
    )
    with pytest.raises(ConnectorError, match="Malformed response from GitHub"):
        await connector.get_file("o", "r", "src")


@pytest.mark.asyncio
async def test_a_huge_log_is_streamed_keeping_only_its_tail_in_memory():
    stream = _CountingStream(chunks=320, last=b"ERROR_IN_JOB_1\n")  # about 21 MB
    jobs = {"jobs": [{"id": 1, "name": "job 1", "conclusion": "failure"}]}

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/runs/42/jobs"):
            return httpx.Response(200, json=jobs)
        return httpx.Response(200, stream=stream)

    connector, _ = make_connector(handler)
    tracemalloc.start()
    try:
        result = await connector.get_failed_logs("o", "r", 42)
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    assert stream.closed and stream.sent > 20_000_000
    assert peak < 4 * LOG_WINDOW + 2_000_000, peak  # never the whole 21 MB
    (entry,) = result["failed_jobs"]
    assert entry["truncated"] is True and entry["log_tail"].endswith("ERROR_IN_JOB_1\n")


@pytest.mark.asyncio
async def test_a_streamed_download_retries_a_short_rate_limit_once():
    calls: list[int] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(1)
        if len(calls) == 1:
            return httpx.Response(429, headers={"retry-after": "1"}, json={"message": "slow"})
        return httpx.Response(200, text="diff --git a/x b/x\n+one\n")

    connector, _ = make_connector(handler)
    result = await connector.get_pr_diff("o", "r", 4)
    assert len(calls) == 2 and result["truncated"] is False


@pytest.mark.asyncio
async def test_a_streamed_401_is_mapped_without_the_body_or_token():
    connector, _ = make_connector(
        lambda r: httpx.Response(401, json={"message": f"Bad credentials {TOKEN}"})
    )
    with pytest.raises(AuthenticationError) as info:
        await connector.get_pr_diff("o", "r", 4)
    assert "HTTP 401 from GitHub" in str(info.value)
    assert TOKEN not in str(info.value) and "Bad credentials" not in str(info.value)


@pytest.mark.asyncio
async def test_a_timeout_while_reading_a_download_is_a_clean_error():
    stream = _CountingStream(chunks=10, chunk=b"+line\n" * 100, fail_after=2)
    connector, _ = make_connector(_streaming(stream))
    with pytest.raises(ConnectorError, match="timed out"):
        await connector.get_pr_diff("o", "r", 4)
    assert stream.closed
