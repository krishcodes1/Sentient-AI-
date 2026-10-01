"""Tests for lecture and episode pages in video.transcript: <track> captions
with relative links and a language choice, one embedded YouTube video read on
the YouTube path and several listed back, a page's RSS alternate link read as
a podcast, a transcript written into the page, audio with no text, a bot
check reported and never retried, nothing found, and a track whose host
resolves to a private address refused by the egress guard without naming the
address.

Why it exists: a course page points at its captions rather than being them,
and every link on it is attacker-controlled. The network is an
httpx.MockTransport; DNS is a fake that applies the real policy to anything
it does not know.
"""

from __future__ import annotations

from urllib.parse import urlparse

import httpx
import pytest

from services.tools.net import validated_addresses
from services.tools.video.page import discover, pick_track
from services.tools.video.toolkit import NO_TRANSCRIPT, VideoToolkit

ID = "dQw4w9WgXcQ"
PAGE = f"""<!doctype html><html><head><title>Week 5: Eigenvalues</title>
<link rel="alternate" type="application/rss+xml" href="/feed.xml"></head>
<body><video controls src="/media/week5.mp4">
<track kind="subtitles" src="captions/week5.es.vtt" srclang="es" label="Español">
<track kind="captions" src="captions/week5.en.vtt" srclang="en" label="English">
<track kind="chapters" src="captions/chapters.vtt">
<track kind="metadata" src="javascript:alert(1)">
</video>
<iframe src="https://www.youtube-nocookie.com/embed/{ID}?start=30"></iframe>
<a href="/downloads/week5.srt">Download captions</a></body></html>"""
VTT = b"WEBVTT\n\n00:00:02.000 --> 00:00:06.000\nToday: eigenvalues.\n\n00:50:00.000 --> 00:50:04.000\nHomework: problems 3 to 7.\n"


def test_discovery_resolves_links_and_keeps_only_captions_and_subtitles():
    found = discover(PAGE, "https://course.example.edu/week5/")
    assert found.title == "Week 5: Eigenvalues"
    assert [t.url for t in found.tracks] == [
        "https://course.example.edu/week5/captions/week5.es.vtt",
        "https://course.example.edu/week5/captions/week5.en.vtt",
        "https://course.example.edu/downloads/week5.srt",
    ]
    assert [(y.video_id, y.start_s) for y in found.youtube] == [(ID, 30)]
    assert found.feeds == ["https://course.example.edu/feed.xml"]
    assert found.media == ["https://course.example.edu/media/week5.mp4"]
    assert pick_track(found.tracks).kind == "captions"
    assert pick_track(found.tracks, "es").language == "es"
    assert pick_track(found.tracks, "en-US").language == "en"


def resolver_for(hosts: dict[str, tuple[str, ...]]):
    def resolve(url: str) -> tuple[str, ...]:
        host = urlparse(url).hostname
        if host in hosts:
            return hosts[host]
        return validated_addresses(url)

    return resolve


class Site:
    def __init__(self, pages: dict[str, tuple[int, str, bytes]]):
        self.pages = pages
        self.seen: list[str] = []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        url = str(request.url)
        self.seen.append(url)
        if url in self.pages:
            status, kind, body = self.pages[url]
            return httpx.Response(status, headers={"content-type": kind}, content=body)
        return httpx.Response(404)


PUBLIC = ("93.184.216.34",)


def toolkit(site: Site, hosts: dict[str, tuple[str, ...]] | None = None) -> VideoToolkit:
    return VideoToolkit(
        resolver=resolver_for(hosts or {"course.example.edu": PUBLIC, "cdn.example.edu": PUBLIC}),
        transport=httpx.MockTransport(site),
    )


@pytest.mark.asyncio
async def test_a_page_track_is_read_in_the_asked_language():
    site = Site(
        {
            "https://course.example.edu/week5/": (200, "text/html", PAGE.encode()),
            "https://course.example.edu/week5/captions/week5.en.vtt": (200, "text/vtt", VTT),
        }
    )
    result = await toolkit(site).execute(
        "transcript", {"url": "https://course.example.edu/week5/", "language": "en"}, "u"
    )
    assert result["ok"] is True, result
    assert (result["source"], result["title"], result["language"]) == ("page", "Week 5: Eigenvalues", "en")
    assert result["passages"][-1] == {"at": "50:00", "s": 3000, "text": "Homework: problems 3 to 7."}
    assert not any("youtube" in u for u in site.seen)


@pytest.mark.asyncio
async def test_one_youtube_embed_routes_to_the_youtube_path_and_several_are_listed():
    one = f'<html><body><iframe src="https://www.youtube.com/embed/{ID}"></iframe></body></html>'
    site = Site({"https://course.example.edu/one": (200, "text/html", one.encode())})
    result = await toolkit(site).execute("transcript", {"url": "https://course.example.edu/one"}, "u")
    # No turn is bound: the YouTube path answers the provider hint, and no
    # YouTube host was ever asked.
    assert result["ok"] is False and result["code"] == "provider"
    assert site.seen == ["https://course.example.edu/one"]

    other = "abcdefghijk"
    two = (
        f'<iframe src="https://www.youtube.com/embed/{ID}"></iframe>'
        f'<iframe src="https://www.youtube.com/embed/{other}"></iframe>'
    )
    site = Site({"https://course.example.edu/two": (200, "text/html", two.encode())})
    result = await toolkit(site).execute("transcript", {"url": "https://course.example.edu/two"}, "u")
    assert result["ok"] is True and result["needs_choice"] is True
    assert [c["url"] for c in result["candidates"]] == [
        f"https://www.youtube.com/watch?v={ID}",
        f"https://www.youtube.com/watch?v={other}",
    ]


@pytest.mark.asyncio
async def test_an_rss_alternate_link_routes_to_the_podcast_path():
    page = '<html><head><link rel="alternate" type="application/rss+xml" href="https://cdn.example.edu/show.xml"></head><body>Episode 4</body></html>'
    feed = (
        '<?xml version="1.0"?><rss xmlns:podcast="https://podcastindex.org/namespace/1.0"><channel><title>Show</title>'
        "<item><title>Episode 4</title><guid>e4</guid><link>https://course.example.edu/ep4</link>"
        '<podcast:transcript url="https://cdn.example.edu/e4.vtt" type="text/vtt"/></item>'
        "<item><title>Episode 5</title><guid>e5</guid></item></channel></rss>"
    ).encode()
    site = Site(
        {
            "https://course.example.edu/ep4": (200, "text/html", page.encode()),
            "https://cdn.example.edu/show.xml": (200, "application/rss+xml", feed),
            "https://cdn.example.edu/e4.vtt": (200, "text/vtt", VTT),
        }
    )
    result = await toolkit(site).execute("transcript", {"url": "https://course.example.edu/ep4"}, "u")
    assert result["ok"] is True, result
    assert (result["source"], result["title"]) == ("podcast", "Episode 4")


@pytest.mark.asyncio
async def test_a_transcript_written_into_the_page_is_read():
    lines = "".join(f"<p>[00:0{i}:00] Speaker: point number {i}.</p>" for i in range(6))
    page = f"<html><head><title>Transcript</title></head><body><article>{lines}</article></body></html>"
    site = Site({"https://course.example.edu/t": (200, "text/html", page.encode())})
    result = await toolkit(site).execute("transcript", {"url": "https://course.example.edu/t"}, "u")
    assert result["ok"] is True and len(result["passages"]) >= 1
    assert result["passages"][0]["at"] == "0:00"


@pytest.mark.asyncio
async def test_audio_with_no_text_nothing_found_and_a_bot_check():
    audio = '<html><body><audio src="/ep.mp3"></audio></body></html>'
    site = Site(
        {
            "https://course.example.edu/audio": (200, "text/html", audio.encode()),
            "https://course.example.edu/empty": (200, "text/html", b"<html><body>Hello</body></html>"),
            "https://course.example.edu/check": (
                200,
                "text/html",
                b"<html><head><title>Just a moment...</title></head><body>cf-chl</body></html>",
            ),
            "https://course.example.edu/ep.mp3": (200, "audio/mpeg", b"ID3"),
            "https://course.example.edu/blocked": (403, "text/html", b"no"),
            "https://course.example.edu/slow": (429, "text/html", b"no"),
        }
    )
    kit = toolkit(site)
    audio_result = await kit.execute("transcript", {"url": "https://course.example.edu/audio"}, "u")
    assert audio_result["error"] == NO_TRANSCRIPT
    direct = await kit.execute("transcript", {"url": "https://course.example.edu/ep.mp3"}, "u")
    assert direct["error"] == NO_TRANSCRIPT
    empty = await kit.execute("transcript", {"url": "https://course.example.edu/empty"}, "u")
    assert empty["code"] == "nothing_found" and empty["hint"]
    check = await kit.execute("transcript", {"url": "https://course.example.edu/check"}, "u")
    assert check["code"] == "challenge"
    refused = await kit.execute("transcript", {"url": "https://course.example.edu/blocked"}, "u")
    assert refused["code"] == "refused" and "browser" in refused["hint"]
    limited = await kit.execute("transcript", {"url": "https://course.example.edu/slow"}, "u")
    assert limited["code"] == "rate_limited"
    assert site.seen.count("https://course.example.edu/blocked") == 1  # never retried


@pytest.mark.asyncio
async def test_a_track_on_a_private_address_is_refused_without_naming_it():
    page = '<html><body><video><track kind="captions" src="https://intranet.example.edu/c.vtt"></video></body></html>'
    site = Site({"https://course.example.edu/p": (200, "text/html", page.encode())})
    kit = toolkit(site, {"course.example.edu": PUBLIC, "intranet.example.edu": ("10.1.2.3",)})

    def resolve(url: str) -> tuple[str, ...]:
        host = urlparse(url).hostname
        if host == "intranet.example.edu":
            # The real policy judging the private answer DNS gave.
            return validated_addresses("http://10.1.2.3/c.vtt")
        return PUBLIC

    kit._resolver = resolve
    result = await kit.execute("transcript", {"url": "https://course.example.edu/p"}, "u")
    assert result["ok"] is False and result.get("blocked") is True
    assert "10.1.2.3" not in str(result)
    assert site.seen == ["https://course.example.edu/p"]
