"""Tests for the saved-transcript cache and the language argument of
video.transcript: a page read in one captions language never answers a call
for another (the live smoke read the MDN demo page in German, then asked for
English and got the cached German), the same for a podcast episode's
transcripts and a YouTube reading (the provider writes the passages in the
asked language), and a reading saved without a language is reused when it is
already in the asked one.

Why it exists: the cache key used to leave the language out, so for the 14
days a transcript is kept the other track could not be read at all. The
network is an httpx.MockTransport, the provider a fake, the store in-memory
SQLite; nothing reaches the internet or a model.
"""

from __future__ import annotations

import httpx
import pytest

from services.agent import turn_context
from services.tools.video.sources import same_language, url_key, youtube_key
from services.tools.video.store import TranscriptStore
from services.tools.video.toolkit import VideoToolkit
from tests.conftest import make_user
from tests.test_video_provider import URL as YOUTUBE_URL
from tests.test_video_provider import FakeGemini, YouTube, passages_json, turn

PUBLIC = ("93.184.216.34",)
PAGE_URL = "https://course.example.edu/week5/"
PAGE = b"""<!doctype html><html><head><title>Week 5</title></head><body>
<video controls src="/media/week5.mp4">
<track kind="captions" src="week5.en.vtt" srclang="en" label="English">
<track kind="subtitles" src="week5.de.vtt" srclang="de" label="Deutsch">
<track kind="subtitles" src="week5.es.vtt" srclang="es" label="Espanol">
</video></body></html>"""


def vtt(text: str) -> bytes:
    return f"WEBVTT\n\n00:00:02.000 --> 00:00:06.000\n{text}\n\n00:01:00.000 --> 00:01:04.000\nThat is all for today.\n".encode()


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


def kit(site, store: TranscriptStore) -> VideoToolkit:
    return VideoToolkit(
        store=store, resolver=lambda _url: PUBLIC, transport=httpx.MockTransport(site)
    )


def first_text(result: dict) -> str:
    assert result["ok"] is True, result
    return result["passages"][0]["text"]


def test_keys_and_language_matching():
    assert url_key(PAGE_URL) != url_key(PAGE_URL, language="de") != url_key(PAGE_URL, language="en")
    assert url_key(PAGE_URL, language="DE") == url_key(PAGE_URL, language="de")
    assert url_key(PAGE_URL, "ep-1", language="de") != url_key(PAGE_URL, "ep-1")
    assert len(url_key(PAGE_URL, "ep-1", language="pt-BR")) <= 80  # the column is String(80)
    assert youtube_key("dQw4w9WgXcQ") == "yt:dQw4w9WgXcQ"
    assert youtube_key("dQw4w9WgXcQ", language="pt-BR") == "yt:dQw4w9WgXcQ:pt-br"
    assert (
        same_language("de", "de") and same_language("de", "de-DE") and same_language("en-US", "en")
    )
    assert same_language("EN", "en")
    assert not same_language("pt-BR", "pt-PT") and not same_language("de", "en")
    assert not same_language("de", None) and not same_language(None, "de")


@pytest.mark.asyncio
async def test_a_page_read_in_one_language_never_answers_another(session_factory):
    user, _ = await make_user(session_factory, "video-lang-page@example.com")
    site = Site(
        {
            PAGE_URL: ("text/html", PAGE),
            PAGE_URL + "week5.en.vtt": ("text/vtt", vtt("Hello class")),
            PAGE_URL + "week5.de.vtt": ("text/vtt", vtt("Hallo Klasse")),
            PAGE_URL + "week5.es.vtt": ("text/vtt", vtt("Hola clase")),
        }
    )
    toolkit = kit(site, TranscriptStore(session_factory))
    uid = str(user.id)

    async def read(language=None) -> dict:
        params = {"url": PAGE_URL}
        if language:
            params["language"] = language
        return await toolkit.execute("transcript", params, uid)

    german = await read("de")
    assert (
        first_text(german).startswith("Hallo Klasse")
        and german["language"] == "de"
        and german["cached"] is False
    )
    english = await read("en")
    assert (
        first_text(english).startswith("Hello class")
        and english["language"] == "en"
        and english["cached"] is False
    )
    again = await read("de-DE")
    assert (
        first_text(again).startswith("Hallo Klasse") and again["cached"] is False
    )  # its own key: read once more
    assert (
        first_text(await read("de")).startswith("Hallo Klasse")
        and (await read("de"))["cached"] is True
    )
    # No language asked: the page's default track (captions first), saved
    # under the page's own key, and reused for a later "en".
    default = await read()
    assert first_text(default).startswith("Hello class") and default["cached"] is False
    assert (await read())["cached"] is True
    spanish = await read("es")
    assert first_text(spanish).startswith("Hola clase") and spanish["cached"] is False
    assert first_text(await read("es")).startswith("Hola clase")
    reads_of_english = site.seen.count(PAGE_URL + "week5.en.vtt")
    reused = await read("en")
    assert first_text(reused).startswith("Hello class") and reused["cached"] is True
    assert site.seen.count(PAGE_URL + "week5.en.vtt") == reads_of_english


@pytest.mark.asyncio
async def test_a_podcast_episode_keeps_one_transcript_per_language(session_factory):
    user, _ = await make_user(session_factory, "video-lang-feed@example.com")
    feed_url = "https://show.example.org/feed.xml"
    feed = (
        '<?xml version="1.0"?><rss version="2.0" xmlns:podcast="https://podcastindex.org/namespace/1.0">'
        "<channel><title>Study Hall</title><item><title>Eigenvalues</title><guid>ep-2</guid>"
        "<pubDate>Tue, 29 Sep 2026 08:00:00 GMT</pubDate>"
        '<enclosure url="https://media.example.org/ep-2.mp3" type="audio/mpeg"/>'
        '<podcast:transcript url="https://t.example.org/ep2.en.vtt" type="text/vtt" language="en" rel="captions"/>'
        '<podcast:transcript url="https://t.example.org/ep2.es.vtt" type="text/vtt" language="es" rel="captions"/>'
        "</item></channel></rss>"
    ).encode()
    site = Site(
        {
            feed_url: ("application/rss+xml", feed),
            "https://t.example.org/ep2.en.vtt": ("text/vtt", vtt("Welcome back")),
            "https://t.example.org/ep2.es.vtt": ("text/vtt", vtt("Bienvenidos")),
        }
    )
    toolkit = kit(site, TranscriptStore(session_factory))
    uid = str(user.id)
    spanish = await toolkit.execute("transcript", {"url": feed_url, "language": "es"}, uid)
    assert first_text(spanish).startswith("Bienvenidos") and spanish["cached"] is False
    english = await toolkit.execute("transcript", {"url": feed_url, "language": "en"}, uid)
    assert first_text(english).startswith("Welcome back") and english["cached"] is False
    listed = await toolkit.execute("list", {}, uid)
    assert sorted(row["language"] for row in listed["transcripts"]) == ["en", "es"]
    again = await toolkit.execute("transcript", {"url": feed_url, "language": "es"}, uid)
    assert first_text(again).startswith("Bienvenidos") and again["cached"] is True


@pytest.mark.asyncio
async def test_a_youtube_reading_in_one_language_never_answers_another(session_factory):
    user, _ = await make_user(session_factory, "video-lang-yt@example.com")
    uid = str(user.id)
    gemini = FakeGemini(
        [
            passages_json(("0:10", "Hallo zusammen."), language="de"),
            passages_json(("0:10", "Hello everyone."), language="en"),
            passages_json(("0:10", "Hello everyone, plain."), language="en"),
        ]
    )
    toolkit = VideoToolkit(
        store=TranscriptStore(session_factory),
        resolver=lambda _url: PUBLIC,
        transport=httpx.MockTransport(YouTube()),
    )
    recorded: list = []
    with turn_context.bound(turn(gemini, recorded)):
        german = await toolkit.execute("transcript", {"url": YOUTUBE_URL, "language": "de"}, uid)
        english = await toolkit.execute("transcript", {"url": YOUTUBE_URL, "language": "en"}, uid)
        german_again = await toolkit.execute(
            "transcript", {"url": YOUTUBE_URL, "language": "de"}, uid
        )
        plain = await toolkit.execute("transcript", {"url": YOUTUBE_URL}, uid)
        plain_again = await toolkit.execute("transcript", {"url": YOUTUBE_URL}, uid)
    assert first_text(german).startswith("Hallo zusammen.") and german["cached"] is False
    assert first_text(english).startswith("Hello everyone.") and english["cached"] is False
    assert first_text(german_again).startswith("Hallo zusammen.") and german_again["cached"] is True
    assert first_text(plain).startswith("Hello everyone, plain.") and plain["cached"] is False
    assert plain_again["cached"] is True
    assert [
        c.get("prompt", "").count("Write the passages in this language") for c in gemini.calls
    ] == [1, 1, 0]
    assert len(gemini.calls) == 3
