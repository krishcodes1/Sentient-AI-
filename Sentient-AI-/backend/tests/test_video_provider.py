"""Tests for reading YouTube through the turn's own provider: what the call
carries (the canonical URL, the window's offsets, 0.25 fps, the fixed
instruction, the schema, the find words with keys masked), usage recorded
into the turn and an audit row of numbers only, the answer validated (bad
JSON, times outside the window, clip-relative times, the 200-passage and
1200-character caps), a non-Gemini turn answered with the hint and no
network call, an oEmbed 404 stopping before any spend, the per-call and
per-day minute caps, a provider 400 or 429, Stop, and an unattended run's
budget.

Why it exists: this is the one path that spends provider tokens on a video,
and it must use only the turn's own Gemini, within the owner's caps. The
provider is a fake read_video_url; YouTube is an httpx.MockTransport.
"""

from __future__ import annotations

import json
from typing import Any

import httpx
import pytest

from services.agent import turn_context
from services.agent.providers import LLMResponse, ProviderError
from services.tools.video import provider_video
from services.tools.video.provider_video import (
    READER_INSTRUCTION,
    RESPONSE_SCHEMA,
    VideoOutputError,
    validate_output,
)
from services.tools.video.store import TranscriptStore
from services.tools.video.toolkit import VideoToolkit
from tests.conftest import make_user

ID = "dQw4w9WgXcQ"
URL = f"https://www.youtube.com/watch?v={ID}"


def passages_json(*items: tuple[str, str], **extra: Any) -> str:
    return json.dumps({"passages": [{"start": s, "text": t} for s, t in items], **extra})


class FakeGemini:
    def __init__(self, answers: list[Any] | None = None):
        self.calls: list[dict[str, Any]] = []
        self.answers = answers or []

    async def read_video_url(self, **kwargs: Any) -> LLMResponse:
        self.calls.append(kwargs)
        answer = self.answers.pop(0) if self.answers else passages_json(("0:05", "Intro."))
        if isinstance(answer, Exception):
            raise answer
        return LLMResponse(
            content=answer, usage={"input_tokens": 1000, "output_tokens": 50}, served_model="gemini-3.5-flash-lite-001"
        )


class YouTube:
    def __init__(self, status: int = 200):
        self.status = status
        self.requests: list[httpx.Request] = []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        if self.status != 200:
            return httpx.Response(self.status)
        return httpx.Response(200, json={"title": "Linear Algebra 5", "author_name": "Prof. Ada"})


class Audit:
    def __init__(self) -> None:
        self.entries: list[dict[str, Any]] = []

    async def log(self, entry: dict[str, Any]) -> None:
        self.entries.append(entry)


def public(_url: str) -> tuple[str, ...]:
    return ("93.184.216.34",)


def turn(gemini: FakeGemini | None, recorded: list, provider: str = "gemini", usd_left=None) -> turn_context.TurnModel:
    return turn_context.TurnModel(
        provider=provider,
        model="gemini-3.5-flash-lite",
        read_video_url=gemini.read_video_url if gemini else None,
        record_usage=recorded.append,
        usd_left=usd_left,
    )


def kit(youtube: YouTube, store: Any = None, audit: Audit | None = None, settings: Any = None) -> VideoToolkit:
    return VideoToolkit(
        store=store,
        resolver=public,
        transport=httpx.MockTransport(youtube),
        audit=audit.log if audit else None,
        settings=settings,
    )


@pytest.mark.asyncio
async def test_the_call_the_usage_and_the_audit_row():
    gemini = FakeGemini([passages_json(("1:35", "Intro."), ("12:00", "Eigen values explained."), ("20:00", "Other."))])
    youtube, audit, recorded = YouTube(), Audit(), []
    toolkit = kit(youtube, audit=audit)
    with turn_context.bound(turn(gemini, recorded)):
        result = await toolkit.execute(
            "transcript",
            {"url": f"https://youtu.be/{ID}?t=90", "find": "eigen\nvalues ghp_" + "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8"},
            "u",
        )
    assert result["ok"] is True, result
    [call] = gemini.calls
    assert call["url"] == URL
    assert (call["start_s"], call["end_s"], call["fps"]) == (90, 90 + 45 * 60, 0.25)
    assert call["instruction"] == READER_INSTRUCTION and call["response_schema"] == RESPONSE_SCHEMA
    assert call["max_output_tokens"] == provider_video.NOTES_MAX_OUTPUT_TOKENS
    assert "The user is interested in: eigen values" in call["prompt"]
    assert "ghp_" not in call["prompt"] and "GitHub token" in call["prompt"]
    assert recorded == [{"input_tokens": 1000, "output_tokens": 50}]
    [row] = audit.entries
    assert row["event"] == "video_provider_read" and row["tool"] == "video.transcript"
    assert set(row["arguments"]) == {"start_s", "end_s", "seconds", "input_tokens", "output_tokens", "est_usd"}
    assert all(isinstance(v, (int, float)) for v in row["arguments"].values())
    assert (result["title"], result["by"], result["engine"]) == ("Linear Algebra 5", "Prof. Ada", "gemini-3.5-flash-lite-001")
    assert result["link"] == f"https://youtu.be/{ID}?t=" and result["next_start"] == "46:30"
    # find: the matching passage and its neighbours, from the window read.
    assert [p["at"] for p in result["passages"]] == ["1:35", "12:00", "20:00"]
    assert result["passages"][1] == {"at": "12:00", "s": 720, "text": "Eigen values explained."}


@pytest.mark.asyncio
async def test_a_non_gemini_turn_gets_the_hint_and_no_request_is_made():
    youtube, recorded = YouTube(), []
    toolkit = kit(youtube)
    with turn_context.bound(turn(None, recorded, provider="anthropic")):
        result = await toolkit.execute("transcript", {"url": URL}, "u")
    assert result["ok"] is False and result["code"] == "provider"
    assert "Show transcript" in result["hint"] and "Gemini" in result["hint"]
    assert youtube.requests == []
    # Outside any turn too.
    assert (await toolkit.execute("transcript", {"url": URL}, "u"))["code"] == "provider"
    # A Gemini-named turn whose provider has no reader, and a reader on
    # another provider, are both refused.
    gemini = FakeGemini()
    with turn_context.bound(turn(gemini, recorded, provider="openai")):
        assert (await toolkit.execute("transcript", {"url": URL}, "u"))["code"] == "provider"
    assert gemini.calls == [] and youtube.requests == []


@pytest.mark.asyncio
async def test_an_oembed_404_or_private_video_stops_before_any_spend():
    for status, code in ((404, "not_found"), (401, "private"), (403, "private"), (429, "rate_limited")):
        gemini, recorded = FakeGemini(), []
        youtube = YouTube(status)
        with turn_context.bound(turn(gemini, recorded)):
            result = await kit(youtube).execute("transcript", {"url": URL}, "u")
        assert result["ok"] is False and result["code"] == code
        assert gemini.calls == [] and recorded == []
        assert len(youtube.requests) == 1


@pytest.mark.asyncio
async def test_provider_errors_map_to_plain_messages():
    for error, code in (
        (ProviderError("gemini", 400, "private"), "unreadable"),
        (ProviderError("gemini", 403, "denied"), "unreadable"),
        (ProviderError("gemini", 429, "quota"), "rate_limited"),
        (ProviderError("gemini", 500, "boom"), "provider_error"),
        (ProviderError("gemini", None, "could not reach"), "provider_error"),
    ):
        gemini, recorded = FakeGemini([error]), []
        with turn_context.bound(turn(gemini, recorded)):
            result = await kit(YouTube()).execute("transcript", {"url": URL}, "u")
        assert result["code"] == code
        assert "boom" not in str(result) and recorded == []


@pytest.mark.asyncio
async def test_stop_before_the_call_makes_no_call():
    gemini, recorded, youtube = FakeGemini(), [], YouTube()
    with turn_context.bound(turn(gemini, recorded)):
        result = await kit(youtube).execute("transcript", {"url": URL}, "u", cancelled=lambda: True)
    assert result["code"] == "stopped" and gemini.calls == [] and youtube.requests == []


@pytest.mark.asyncio
async def test_an_unattended_runs_budget_is_checked_before_the_call():
    gemini, recorded = FakeGemini(), []
    with turn_context.bound(turn(gemini, recorded, usd_left=lambda: 0.0001)):
        result = await kit(YouTube()).execute("transcript", {"url": URL}, "u")
    assert result["code"] == "budget" and gemini.calls == []


@pytest.mark.asyncio
async def test_verbatim_reads_a_third_and_the_owners_per_call_cap_applies():
    class Settings:
        async def video_limits(self):
            return {"video_minutes_per_call": 30, "video_minutes_per_day": 240, "keep_transcripts_days": 14}

    gemini, recorded = FakeGemini(), []
    with turn_context.bound(turn(gemini, recorded)):
        await kit(YouTube(), settings=Settings()).execute(
            "transcript", {"url": URL, "detail": "verbatim"}, "u"
        )
        await kit(YouTube(), settings=Settings()).execute(
            "transcript", {"url": URL, "start": "10:00", "end": "2:00:00"}, "u"
        )
    assert (gemini.calls[0]["start_s"], gemini.calls[0]["end_s"]) == (0, 600)
    assert gemini.calls[0]["max_output_tokens"] == provider_video.VERBATIM_MAX_OUTPUT_TOKENS
    assert (gemini.calls[1]["start_s"], gemini.calls[1]["end_s"]) == (600, 600 + 1800)


@pytest.mark.asyncio
async def test_unreadable_settings_refuse_the_provider_path():
    class Broken:
        async def video_limits(self):
            raise RuntimeError("db down")

    gemini, recorded = FakeGemini(), []
    with turn_context.bound(turn(gemini, recorded)):
        result = await kit(YouTube(), settings=Broken()).execute("transcript", {"url": URL}, "u")
    assert result["code"] == "limits" and gemini.calls == []


@pytest.mark.asyncio
async def test_the_per_day_cap_counts_stored_seconds(session_factory):
    user, _token = await make_user(session_factory, "video-cap@example.com")
    store = TranscriptStore(session_factory)

    class Settings:
        async def video_limits(self):
            return {"video_minutes_per_call": 45, "video_minutes_per_day": 60, "keep_transcripts_days": 14}

    gemini, recorded = FakeGemini(), []
    toolkit = kit(YouTube(), store=store, settings=Settings())
    with turn_context.bound(turn(gemini, recorded)):
        first = await toolkit.execute("transcript", {"url": URL}, str(user.id))
        assert first["ok"] is True
        # 45 of 60 minutes used: the next read is cut to the 15 left.
        second = await toolkit.execute("transcript", {"url": URL, "start": "45:00"}, str(user.id))
        assert second["ok"] is True, second
        assert (gemini.calls[1]["start_s"], gemini.calls[1]["end_s"]) == (2700, 3600)
        assert "15 minutes" in second["note"]
        third = await toolkit.execute("transcript", {"url": URL, "start": "1:00:00"}, str(user.id))
    assert third["code"] == "daily_cap" and len(gemini.calls) == 2
    assert await store.provider_seconds_today(str(user.id)) == 3600


@pytest.mark.asyncio
async def test_a_cached_window_costs_nothing_and_a_later_window_is_read_next(session_factory):
    user, _token = await make_user(session_factory, "video-cache@example.com")
    gemini = FakeGemini(
        [
            passages_json(("0:10", "Part one."), ("30:00", "Middle.")),
            passages_json(("50:00", "Part two."), ends_before_window_end=True),
        ]
    )
    recorded: list = []
    toolkit = kit(YouTube(), store=TranscriptStore(session_factory))
    with turn_context.bound(turn(gemini, recorded)):
        first = await toolkit.execute("transcript", {"url": URL}, str(user.id))
        again = await toolkit.execute("transcript", {"url": URL, "start": "20:00"}, str(user.id))
        nxt = await toolkit.execute("transcript", {"url": URL, "start": first["next_start"]}, str(user.id))
    assert first["cached"] is False and again["cached"] is True
    # The passage that holds 20:00 (from 0:10) and the one after; the saved
    # part ends at 45:00, where next_start picks up.
    assert [p["text"] for p in again["passages"]] == ["Part one.", "Middle."]
    assert again["next_start"] == "45:00"
    assert len(gemini.calls) == 2 and gemini.calls[1]["start_s"] == 2700
    assert nxt["next_start"] is None and nxt["duration"] == "50:01"
    assert nxt["covered"] == "0:00-50:01"


def test_validation_parses_sorts_clamps_and_caps():
    text = passages_json(("12:00", "b"), ("1:00", "a"), ("99:00", "late"), ("bad", "x"), ("0:30", "​hid\x07den"))
    result = validate_output(text, start_s=0, end_s=45 * 60)
    assert [(p.start_s, p.text) for p in result.passages] == [(30.0, "hidden"), (60.0, "a"), (720.0, "b"), (2700.0, "late")]
    many = passages_json(*[(f"{i // 60}:{i % 60:02d}", "x" * 2000) for i in range(300)])
    capped = validate_output(many, start_s=0, end_s=45 * 60)
    assert len(capped.passages) == 200 and all(len(p.text) == 1200 for p in capped.passages)
    fenced = "```json\n" + passages_json(("0:01", "ok")) + "\n```"
    assert validate_output(fenced, start_s=0, end_s=60).passages[0].text == "ok"
    for bad in ("not json", "[]", '{"passages": 3}'):
        with pytest.raises(VideoOutputError):
            validate_output(bad, start_s=0, end_s=60)


def test_clip_relative_times_are_shifted_by_the_start():
    # A window from 45:00: the model counted from the clip's start.
    relative = passages_json(("0:10", "a"), ("5:00", "b"))
    shifted = validate_output(relative, start_s=2700, end_s=5400)
    assert [p.start_s for p in shifted.passages] == [2710.0, 3000.0]
    absolute = passages_json(("46:00", "a"), ("50:00", "b"))
    assert [p.start_s for p in validate_output(absolute, start_s=2700, end_s=5400).passages] == [2760.0, 3000.0]


def test_the_cost_estimate():
    tokens = provider_video.estimate_tokens(2700, "notes")
    assert tokens == {"input_tokens": int(2700 * (66 * 0.25 + 32)), "output_tokens": 8192}
    model = turn_context.TurnModel("gemini", "gemini-3.5-flash-lite", None, lambda u: None)
    assert 0 < provider_video.estimate_cost(model, 2700, "notes") < 1
