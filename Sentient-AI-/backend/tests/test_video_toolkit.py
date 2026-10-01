"""Tests for the video.* toolkit's contract: unknown actions and bad arguments
are ok false, a user_id in the arguments is ignored, result keys come in
their fixed order, an answer is capped at 16000 characters as shown with
next_start continuing it (for an untimed transcript too), find returns only
matching passages with a neighbour each (at most 12), the cached flag, Stop
between fetches, the publisher deadline, video.list's metadata-only rows,
and what the audit keeps of a result.

Why it exists: the runtime shows the model at most the video.transcript
budget, so a cut must happen here at a passage boundary with a way to go on,
and the audit must keep metadata, never transcript text. The network is an
httpx.MockTransport with a fake resolver; the store is the real one on
SQLite where it matters.
"""

from __future__ import annotations

import asyncio

import httpx
import pytest

from services.agent.runtime import RESULT_CHAR_BUDGETS, result_for_audit
from services.tools.text_budget import shown_length
from services.tools.video.store import TranscriptStore
from services.tools.video.toolkit import RESULT_SHOWN_CHARS, VideoToolkit
from tests.conftest import make_user

KEYS = [
    "ok", "title", "by", "source", "url", "method", "detail", "engine", "language",
    "duration", "link", "covered", "cached", "next_start", "note", "passages",
]  # fmt: skip


def public(_url: str) -> tuple[str, ...]:
    return ("93.184.216.34",)


def vtt(cues: int, words: int = 45, topic: str = "matrix") -> bytes:
    lines = ["WEBVTT", ""]
    for i in range(cues):
        start = i * 30
        text = f"Cue {i} about {topic if i % 17 else 'eigenvalues'} " + " ".join(["lorem"] * words)
        lines += [f"{start // 3600:02d}:{start // 60 % 60:02d}:{start % 60:02d}.000 --> "
                  f"{(start + 29) // 3600:02d}:{(start + 29) // 60 % 60:02d}:{(start + 29) % 60:02d}.000", text, ""]
    return "\n".join(lines).encode()


class Site:
    def __init__(self, pages: dict[str, tuple[str, bytes]]):
        self.pages = pages
        self.seen: list[str] = []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        url = str(request.url)
        self.seen.append(url)
        if url in self.pages:
            kind, body = self.pages[url]
            return httpx.Response(200, headers={"content-type": kind}, content=body)
        return httpx.Response(404)


def kit(site: Site, store=None, **kwargs) -> VideoToolkit:
    return VideoToolkit(store=store, resolver=public, transport=httpx.MockTransport(site), **kwargs)


CAPTIONS = "https://cdn.example.org/lecture.vtt"


@pytest.mark.asyncio
async def test_unknown_actions_and_bad_arguments_fail_closed():
    toolkit = kit(Site({}))
    assert (await toolkit.execute("download", {}, "u"))["ok"] is False
    for params in (
        {},
        {"url": CAPTIONS, "unexpected": 1},
        {"url": CAPTIONS, "start": "soon"},
        {"url": CAPTIONS, "start": "10:00", "end": "5:00"},
        {"url": CAPTIONS, "find": "x" * 101},
        {"url": CAPTIONS, "find": ["list"]},
        {"url": CAPTIONS, "episode": 5},
        {"url": CAPTIONS, "episode": "e" * 201},
        {"url": CAPTIONS, "language": "english please"},
        {"url": CAPTIONS, "detail": "summary"},
        {"url": 42},
    ):
        result = await toolkit.execute("transcript", params, "u")
        assert result["ok"] is False and result["error"], params
    for params in ({"limit": "ten"}, {"limit": True}, {"other": 1}):
        assert (await toolkit.execute("list", params, "u"))["ok"] is False


@pytest.mark.asyncio
async def test_a_user_id_in_the_arguments_is_ignored(session_factory):
    alice, _ = await make_user(session_factory, "alice-kit@example.com")
    bob, _ = await make_user(session_factory, "bob-kit@example.com")
    site = Site({CAPTIONS: ("text/vtt", vtt(3))})
    toolkit = kit(site, store=TranscriptStore(session_factory))
    result = await toolkit.execute("transcript", {"url": CAPTIONS, "user_id": str(bob.id)}, str(alice.id))
    assert result["ok"] is True
    assert await toolkit.execute("list", {"user_id": str(alice.id)}, str(bob.id)) == {
        "ok": True,
        "count": 0,
        "transcripts": [],
        "note": (await toolkit.execute("list", {}, str(bob.id)))["note"],
    }
    listed = await toolkit.execute("list", {}, str(alice.id))
    assert listed["count"] == 1


@pytest.mark.asyncio
async def test_the_keys_come_in_order_and_the_answer_is_capped_as_shown(session_factory):
    user, _ = await make_user(session_factory, "cap-kit@example.com")
    site = Site({CAPTIONS: ("text/vtt", vtt(400))})
    toolkit = kit(site, store=TranscriptStore(session_factory))
    first = await toolkit.execute("transcript", {"url": CAPTIONS}, str(user.id))
    assert list(first) == KEYS
    assert first["source"] == "captions" and first["method"] == "publisher_captions"
    assert first["cached"] is False and first["engine"] == "publisher"
    assert shown_length(first) <= RESULT_SHOWN_CHARS
    assert RESULT_CHAR_BUDGETS["video.transcript"] == RESULT_SHOWN_CHARS + 4000
    assert all(len(p["text"]) <= 700 for p in first["passages"])
    assert first["next_start"] == first["passages"][-1]["at"] or first["next_start"] > first["passages"][-1]["at"]
    assert first["next_start"] in first["note"]

    second = await toolkit.execute("transcript", {"url": CAPTIONS, "start": first["next_start"]}, str(user.id))
    assert second["cached"] is True and site.seen.count(CAPTIONS) == 1
    assert second["passages"][0]["at"] == first["next_start"]
    assert second["passages"][0]["s"] > first["passages"][-1]["s"]
    tail = await toolkit.execute("transcript", {"url": CAPTIONS, "start": "3:15:00"}, str(user.id))
    assert tail["next_start"] is None and tail["passages"]
    window = await toolkit.execute("transcript", {"url": CAPTIONS, "start": "10:00", "end": "12:00"}, str(user.id))
    assert window["next_start"] is None
    assert all(600 - 90 <= p["s"] < 720 for p in window["passages"])


@pytest.mark.asyncio
async def test_find_returns_matches_with_one_neighbour_each_at_most_12():
    site = Site({CAPTIONS: ("text/vtt", vtt(400))})
    toolkit = kit(site)
    result = await toolkit.execute("transcript", {"url": CAPTIONS, "find": "eigenvalues"}, "u")
    assert result["ok"] is True
    texts = [p["text"] for p in result["passages"]]
    assert 0 < len(texts) <= 12
    assert any("eigenvalues" in t for t in texts)
    assert result["next_start"] is None and "mention the find words" in result["note"]
    missing = await toolkit.execute("transcript", {"url": CAPTIONS, "find": "quaternion"}, "u")
    assert missing["passages"] == [] and "No passage" in missing["note"]


@pytest.mark.asyncio
async def test_an_untimed_transcript_continues_by_passage_number():
    text = "\n\n".join(f"Paragraph {i}. " + "words " * 120 for i in range(60))
    site = Site({"https://cdn.example.org/t.txt": ("text/plain", text.encode())})
    toolkit = kit(site)
    first = await toolkit.execute("transcript", {"url": "https://cdn.example.org/t.txt"}, "u")
    assert first["passages"][0]["at"] is None and first["next_start"].startswith("#")
    assert "no timestamps" in first["note"]
    second = await toolkit.execute(
        "transcript", {"url": "https://cdn.example.org/t.txt", "start": first["next_start"]}, "u"
    )
    assert second["passages"][0]["text"] not in [p["text"] for p in first["passages"]]


@pytest.mark.asyncio
async def test_stop_between_fetches_is_honoured():
    feed = (
        '<?xml version="1.0"?><rss xmlns:podcast="https://podcastindex.org/namespace/1.0"><channel>'
        '<title>S</title><item><title>E</title><guid>g</guid>'
        '<podcast:transcript url="https://cdn.example.org/e.vtt" type="text/vtt"/></item></channel></rss>'
    ).encode()
    site = Site({"https://cdn.example.org/f.xml": ("application/rss+xml", feed), "https://cdn.example.org/e.vtt": ("text/vtt", vtt(2))})
    checks: list[int] = []

    def stop_after_first() -> bool:
        checks.append(1)
        return len(checks) > 1

    result = await kit(site).execute("transcript", {"url": "https://cdn.example.org/f.xml"}, "u", cancelled=stop_after_first)
    assert result["code"] == "stopped"
    assert site.seen == ["https://cdn.example.org/f.xml"]


@pytest.mark.asyncio
async def test_the_publisher_deadline():
    async def slow(request: httpx.Request) -> httpx.Response:
        await asyncio.sleep(5)
        return httpx.Response(200, content=b"WEBVTT\n")

    toolkit = VideoToolkit(resolver=public, transport=httpx.MockTransport(slow), deadline_s=0.05)
    result = await toolkit.execute("transcript", {"url": CAPTIONS}, "u")
    assert result["code"] == "timeout"


@pytest.mark.asyncio
async def test_list_is_metadata_only_and_bounded(session_factory):
    user, _ = await make_user(session_factory, "list-kit@example.com")
    site = Site({CAPTIONS: ("text/vtt", vtt(5))})
    toolkit = kit(site, store=TranscriptStore(session_factory))
    await toolkit.execute("transcript", {"url": CAPTIONS}, str(user.id))
    listed = await toolkit.execute("list", {"limit": 50}, str(user.id))
    assert listed["ok"] is True and listed["count"] == 1
    [row] = listed["transcripts"]
    assert set(row) == {
        "id", "title", "source", "host", "url", "method", "detail", "language", "covered", "duration", "saved", "expires",
    }  # fmt: skip
    assert row["host"] == "cdn.example.org" and row["covered"].startswith("0:00-")
    assert "lorem" not in str(listed)
    assert shown_length(listed) <= RESULT_CHAR_BUDGETS["video.list"]


@pytest.mark.asyncio
async def test_the_audit_keeps_facts_never_passages():
    site = Site({CAPTIONS: ("text/vtt", vtt(5))})
    result = await kit(site).execute("transcript", {"url": CAPTIONS}, "u")
    facts = result_for_audit("video.transcript", result)
    assert "lorem" not in str(facts) and "passages" in facts and facts["host"] == "cdn.example.org"
    assert facts["passages"] == len(result["passages"]) and facts["chars"] > 0
    listed = result_for_audit("video.list", {"ok": True, "count": 2, "transcripts": [{"title": "t"}] * 2})
    assert listed == {"ok": True, "count": 2, "transcripts": 2}
    assert result_for_audit("video.transcript", {"ok": False, "error": "e" * 300})["error"] == "e" * 200


@pytest.mark.asyncio
async def test_a_transcript_too_long_to_keep_whole_says_only_its_first_part_was_kept(session_factory, monkeypatch):
    from services.tools.video import store as store_module
    from services.tools.video import toolkit as toolkit_module

    # A small store cap stands in for 400,000 characters.
    monkeypatch.setattr(store_module, "MAX_ROW_CHARS", 5000)
    monkeypatch.setattr(toolkit_module, "MAX_ROW_CHARS", 5000)
    user, _ = await make_user(session_factory, "video-cut@example.com")
    site = Site({CAPTIONS: ("text/vtt", vtt(60))})
    toolkit = kit(site, store=TranscriptStore(session_factory))
    first = await toolkit.execute("transcript", {"url": CAPTIONS}, str(user.id))
    assert first["ok"] is True and first["cached"] is False
    kept_end = first["covered"].split("-")[1]
    assert f"Only the first {kept_end} of this transcript was kept" in first["note"]
    assert first["duration"] == "29:59"  # the whole file's length, not the kept part's
    again = await toolkit.execute("transcript", {"url": CAPTIONS, "start": "1:00"}, str(user.id))
    assert again["cached"] is True and f"Only the first {kept_end}" in again["note"]
    assert site.seen.count(CAPTIONS) == 1


@pytest.mark.asyncio
async def test_a_file_cut_at_the_byte_cap_says_so_and_a_whole_one_does_not(monkeypatch):
    from services.tools.video import captions as captions_module

    small = vtt(3)
    monkeypatch.setattr(captions_module, "MAX_CAPTION_BYTES", len(small) - 40)
    cut = await kit(Site({CAPTIONS: ("text/vtt", small)})).execute("transcript", {"url": CAPTIONS}, "u")
    assert cut["ok"] is True and "was kept; the rest was too long" in cut["note"]
    monkeypatch.setattr(captions_module, "MAX_CAPTION_BYTES", 4 * 1024 * 1024)
    whole = await kit(Site({CAPTIONS: ("text/vtt", small)})).execute("transcript", {"url": CAPTIONS}, "u")
    assert whole["ok"] is True and "too long" not in whole["note"]


@pytest.mark.asyncio
async def test_an_untimed_transcript_cut_short_counts_the_passages_kept(monkeypatch):
    from services.tools.video import captions as captions_module

    text = "\n\n".join(f"Paragraph {i} of the lecture notes, with no times at all." for i in range(40)).encode()
    monkeypatch.setattr(captions_module, "MAX_CAPTION_BYTES", len(text) // 2)
    url = "https://cdn.example.org/notes.txt"
    result = await kit(Site({url: ("text/plain", text)})).execute("transcript", {"url": url}, "u")
    assert result["ok"] is True and result["covered"] is None
    assert "This transcript has no timestamps." in result["note"]
    assert "passages of this transcript were kept; the rest was too long" in result["note"]
