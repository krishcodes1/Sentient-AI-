"""Tests for podcast feeds in video.transcript: the <podcast:transcript>
preference (captions VTT/SRT, then JSON, then VTT/SRT, then HTML, then plain)
and language order, choosing the episode by guid, title words or newest (and
asking when several fit), Apple Podcasts links resolved through the iTunes
lookup, the phase-1 answer for an episode with no transcript, DTD and entity
feeds (billion laughs) refused, and a feed over 8 MB still yielding its first
episodes.

Why it exists: a feed is hostile XML fetched from anywhere, and choosing the
wrong episode or transcript silently answers about something else. The
network is an httpx.MockTransport with a fake resolver.
"""

from __future__ import annotations

from typing import Any

import httpx
import pytest

from services.tools.video import podcast
from services.tools.video.podcast import (
    Ambiguous,
    Chosen,
    FeedRefused,
    TranscriptRef,
    choose_episode,
    parse_feed,
    pick_transcript,
)
from services.tools.video.toolkit import NO_TRANSCRIPT, VideoToolkit

NS = 'xmlns:podcast="https://podcastindex.org/namespace/1.0" xmlns:itunes="http://www.itunes.com/dtds/podcast-1.0.dtd"'


def item(guid: str, title: str, date: str, transcripts: str = "", link: str = "") -> str:
    return (
        f"<item><title>{title}</title><guid>{guid}</guid><pubDate>{date}</pubDate>"
        f"<link>{link}</link><itunes:duration>52:10</itunes:duration>"
        f'<enclosure url="https://media.example.org/{guid}.mp3" type="audio/mpeg"/>{transcripts}</item>'
    )


def feed(*items: str, title: str = "Study Hall") -> bytes:
    return (
        f'<?xml version="1.0"?><rss version="2.0" {NS}><channel><title>{title}</title>'
        f"<itunes:author>Campus Radio</itunes:author>{''.join(items)}</channel></rss>"
    ).encode()


TRANSCRIPTS = (
    '<podcast:transcript url="https://t.example.org/ep2.html" type="text/html"/>'
    '<podcast:transcript url="https://t.example.org/ep2.json" type="application/json" language="en"/>'
    '<podcast:transcript url="https://t.example.org/ep2.vtt" type="text/vtt" language="en"/>'
    '<podcast:transcript url="https://t.example.org/ep2.es.vtt" type="text/vtt" language="es" rel="captions"/>'
    '<podcast:transcript url="https://t.example.org/ep2.en.srt" type="application/x-subrip" language="en" rel="captions"/>'
)
FEED = feed(
    item("ep-2", "Eigenvalues and eigenvectors", "Tue, 29 Sep 2026 08:00:00 GMT", TRANSCRIPTS,
         link="https://show.example.org/ep2"),
    item("ep-1", "Limits and continuity", "Tue, 22 Sep 2026 08:00:00 GMT"),
    item("ep-0", "Limits: a second look", "Tue, 15 Sep 2026 08:00:00 GMT"),
)


def test_episodes_are_read_newest_first_with_their_transcripts():
    parsed = parse_feed(FEED)
    assert parsed.title == "Study Hall" and parsed.author == "Campus Radio"
    assert [e.guid for e in parsed.episodes] == ["ep-2", "ep-1", "ep-0"]
    newest = parsed.episodes[0]
    assert newest.duration_s == 3130 and newest.date == "2026-09-29"
    assert len(newest.transcripts) == 5
    assert newest.enclosure_url.endswith("ep-2.mp3")


def test_the_transcript_preference_and_language_order():
    refs = parse_feed(FEED).episodes[0].transcripts
    assert pick_transcript(refs).url.endswith("ep2.es.vtt")  # captions VTT/SRT first
    assert pick_transcript(refs, "en").url.endswith("ep2.en.srt")  # then the asked language
    without_captions = tuple(r for r in refs if r.rel != "captions")
    assert pick_transcript(without_captions).url.endswith("ep2.json")  # JSON before VTT
    only_vtt_html = tuple(r for r in without_captions if not r.url.endswith(".json"))
    assert pick_transcript(only_vtt_html).url.endswith("ep2.vtt")
    html_plain = (
        TranscriptRef("https://t/x.txt", "text/plain", "", ""),
        TranscriptRef("https://t/x.html", "text/html", "", ""),
    )
    assert pick_transcript(html_plain).url.endswith(".html")
    assert pick_transcript((TranscriptRef("https://t/x.pdf", "application/pdf", "", ""),)) is None


def test_choosing_an_episode():
    parsed = parse_feed(FEED)
    assert choose_episode(parsed) == Chosen(parsed.episodes[0])
    assert choose_episode(parsed, "ep-1") == Chosen(parsed.episodes[1])
    assert choose_episode(parsed, "eigenvalues") == Chosen(parsed.episodes[0])
    assert choose_episode(parsed, page_url="https://www.show.example.org/ep2/") == Chosen(parsed.episodes[0])
    several = choose_episode(parsed, "limits")
    assert isinstance(several, Ambiguous) and [e.guid for e in several.candidates] == ["ep-1", "ep-0"]
    none = choose_episode(parsed, "quantum chromodynamics")
    assert isinstance(none, Ambiguous) and len(none.candidates) == 3


def test_billion_laughs_and_external_entities_are_refused():
    laughs = b"""<?xml version="1.0"?>
<!DOCTYPE lolz [<!ENTITY lol "lol"><!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
<!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">]>
<rss><channel><title>&lol3;</title></channel></rss>"""
    with pytest.raises(FeedRefused, match="safely"):
        parse_feed(laughs)
    external = b"""<?xml version="1.0"?>
<!DOCTYPE rss [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><rss><channel><title>&xxe;</title></channel></rss>"""
    with pytest.raises(FeedRefused):
        parse_feed(external)
    with pytest.raises(FeedRefused):
        parse_feed(b"<html><body>not a feed</body></html>")


def test_a_feed_over_8_mb_still_yields_its_first_episodes():
    items = "".join(
        item(f"g{i}", f"Episode {i}", "Tue, 29 Sep 2026 08:00:00 GMT") for i in range(3)
    )
    huge = feed(items).replace(b"</channel></rss>", b"") + (b"<item><title>" + b"x" * (podcast.MAX_FEED_BYTES + 1000))
    parsed = parse_feed(huge)
    assert parsed.truncated is True
    assert [e.guid for e in parsed.episodes][:3] == ["g0", "g1", "g2"]


def test_apple_lookup_answers():
    show = b'{"resultCount": 1, "results": [{"collectionName": "Study Hall", "feedUrl": "https://feeds.example.org/study.xml"}]}'
    episodes = b'{"results": [{"wrapperType": "track"}, {"trackId": 1000654321, "trackName": "Eigenvalues", "episodeGuid": "ep-2"}]}'
    found = podcast.read_apple_lookup(show, episodes, "1000654321")
    assert (found.feed_url, found.episode_guid, found.episode_title) == (
        "https://feeds.example.org/study.xml",
        "ep-2",
        "Eigenvalues",
    )
    with pytest.raises(FeedRefused):
        podcast.read_apple_lookup(b'{"results": [{"feedUrl": "javascript:x"}]}', None, None)


# -- end to end through the toolkit ------------------------------------------------

VTT = b"WEBVTT\n\n00:00:01.000 --> 00:00:05.000\nWelcome to Study Hall.\n\n00:12:00.000 --> 00:12:05.000\nAn eigenvalue scales its eigenvector.\n"


def public(_url: str) -> tuple[str, ...]:
    return ("93.184.216.34",)


class Site:
    def __init__(self, pages: dict[str, tuple[int, str, bytes]]):
        self.pages = pages
        self.seen: list[str] = []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        url = str(request.url)
        self.seen.append(url)
        for prefix, (status, kind, body) in self.pages.items():
            if url.startswith(prefix):
                return httpx.Response(status, headers={"content-type": kind}, content=body)
        return httpx.Response(404)


def toolkit(site: Site) -> VideoToolkit:
    return VideoToolkit(resolver=public, transport=httpx.MockTransport(site))


@pytest.mark.asyncio
async def test_a_feed_link_reads_the_newest_episodes_preferred_transcript():
    site = Site(
        {
            "https://feeds.example.org/study.xml": (200, "application/rss+xml", FEED),
            "https://t.example.org/ep2.es.vtt": (200, "text/vtt", VTT),
        }
    )
    result = await toolkit(site).execute("transcript", {"url": "https://feeds.example.org/study.xml"}, "u")
    assert result["ok"] is True, result
    assert (result["source"], result["method"], result["title"], result["by"]) == (
        "podcast",
        "publisher_captions",
        "Eigenvalues and eigenvectors",
        "Study Hall",
    )
    assert result["duration"] == "52:10" and result["language"] == "es"
    assert [p["at"] for p in result["passages"]] == ["0:01", "12:00"]


@pytest.mark.asyncio
async def test_an_ambiguous_episode_asks_for_a_choice():
    site = Site({"https://feeds.example.org/study.xml": (200, "application/rss+xml", FEED)})
    result = await toolkit(site).execute(
        "transcript", {"url": "https://feeds.example.org/study.xml", "episode": "limits"}, "u"
    )
    assert result["ok"] is True and result["needs_choice"] is True
    assert [c["guid"] for c in result["candidates"]] == ["ep-1", "ep-0"]
    assert result["candidates"][0] == {"title": "Limits and continuity", "date": "2026-09-22", "guid": "ep-1"}


@pytest.mark.asyncio
async def test_an_episode_with_no_transcript_answers_the_phase_one_message():
    site = Site({"https://feeds.example.org/study.xml": (200, "application/rss+xml", FEED)})
    result = await toolkit(site).execute(
        "transcript", {"url": "https://feeds.example.org/study.xml", "episode": "ep-1"}, "u"
    )
    assert result["ok"] is False and result["error"] == NO_TRANSCRIPT
    assert not any(u.endswith(".mp3") for u in site.seen)


@pytest.mark.asyncio
async def test_an_apple_podcasts_link_is_resolved_through_the_itunes_lookup():
    show = b'{"results": [{"collectionName": "Study Hall", "feedUrl": "https://feeds.example.org/study.xml"}]}'
    episodes = b'{"results": [{"trackId": 1000654321, "trackName": "Eigenvalues and eigenvectors", "episodeGuid": "ep-2"}]}'

    class Apple(Site):
        def __call__(self, request: httpx.Request) -> httpx.Response:
            url = str(request.url)
            if url.startswith("https://itunes.apple.com/lookup"):
                self.seen.append(url)
                body = episodes if "podcastEpisode" in url else show
                return httpx.Response(200, headers={"content-type": "application/json"}, content=body)
            return super().__call__(request)

    site = Apple(
        {
            "https://feeds.example.org/study.xml": (200, "application/rss+xml", FEED),
            "https://t.example.org/ep2.es.vtt": (200, "text/vtt", VTT),
        }
    )
    result = await toolkit(site).execute(
        "transcript",
        {"url": "https://podcasts.apple.com/us/podcast/study-hall/id1234567890?i=1000654321"},
        "u",
    )
    assert result["ok"] is True, result
    assert result["title"] == "Eigenvalues and eigenvectors"
    lookups = [u for u in site.seen if "itunes.apple.com" in u]
    assert len(lookups) == 2 and all("id=1234567890" in u for u in lookups)


@pytest.mark.asyncio
async def test_a_billion_laughs_feed_is_refused_end_to_end():
    laughs = b"""<?xml version="1.0"?><!DOCTYPE lolz [<!ENTITY lol "lol"><!ENTITY lol2 "&lol;&lol;&lol;">]>
<rss><channel><title>&lol2;</title></channel></rss>"""
    site = Site({"https://feeds.example.org/bad.xml": (200, "application/rss+xml", laughs)})
    result: dict[str, Any] = await toolkit(site).execute(
        "transcript", {"url": "https://feeds.example.org/bad.xml"}, "u"
    )
    assert result["ok"] is False and "safely" in result["error"]
