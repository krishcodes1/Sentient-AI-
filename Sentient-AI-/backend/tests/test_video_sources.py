"""Tests for how video.transcript classifies links and the YouTube host rule:
every YouTube URL form maps to its video id and start time, playlists,
channels, search and live pages and look-alike hosts are refused, Spotify is
unsupported, Apple Podcasts ids are read, the display URL drops anything
credential-like, the cache key is a stable hash, across a whole YouTube read
the only request a YouTube host sees is /oembed, and a link that redirects to
a YouTube video is never followed there but read on the provider path.

Why it exists: Crawler must never fetch YouTube pages or caption tracks
(robots.txt, the terms, captions.download's edit rights), and a link's query
string is where tokens hide. The network is an httpx.MockTransport with a
fake resolver; the provider is a fake.
"""

from __future__ import annotations

from typing import Any

import httpx
import pytest

from services.agent import turn_context
from services.agent.providers import LLMResponse
from services.tools.net import EgressBlocked
from services.tools.video import sources
from services.tools.video.sources import (
    ApplePodcastLink,
    Refused,
    WebLink,
    YouTubeLink,
    classify,
    display_url,
    url_key,
    youtube_key,
    youtube_request_allowed,
)
from services.tools.video.toolkit import VideoToolkit

ID = "dQw4w9WgXcQ"


@pytest.mark.parametrize(
    "url, start",
    [
        (f"https://www.youtube.com/watch?v={ID}", None),
        (f"https://youtube.com/watch?v={ID}&list=PL123&index=2", None),
        (f"https://m.youtube.com/watch?v={ID}&t=754", 754),
        (f"https://music.youtube.com/watch?v={ID}&t=1h2m3s", 3723),
        (f"https://www.youtube.com/shorts/{ID}", None),
        (f"https://www.youtube.com/live/{ID}?si=abc", None),
        (f"https://www.youtube.com/embed/{ID}?start=90", 90),
        (f"https://youtu.be/{ID}?t=12m", 720),
        (f"https://youtu.be/{ID}#t=1m30s", 90),
        (f"https://www.youtube-nocookie.com/embed/{ID}", None),
        (f"HTTPS://WWW.YOUTUBE.COM/watch?v={ID}&time_continue=42", 42),
    ],
)
def test_every_youtube_form_maps_to_its_id(url, start):
    link = classify(url)
    assert link == YouTubeLink(video_id=ID, start_s=start)


@pytest.mark.parametrize(
    "url, code",
    [
        ("https://www.youtube.com/playlist?list=PL123", "playlist"),
        ("https://www.youtube.com/watch?list=PL123", "playlist"),
        ("https://www.youtube.com/embed/videoseries?list=PL123", "playlist"),
        ("https://www.youtube.com/@somechannel", "not_a_video"),
        ("https://www.youtube.com/channel/UC123/videos", "not_a_video"),
        ("https://www.youtube.com/c/Name", "not_a_video"),
        ("https://www.youtube.com/@somechannel/live", "live"),
        ("https://www.youtube.com/results?search_query=linear+algebra", "not_a_video"),
        ("https://www.youtube.com/", "not_a_video"),
        ("https://www.youtube.com/watch?v=short", "not_a_video"),
        ("https://rr3---sn-abc.googlevideo.com/videoplayback?expire=1", "unsupported"),
    ],
)
def test_playlists_channels_search_and_media_servers_are_refused(url, code):
    link = classify(url)
    assert isinstance(link, Refused) and link.code == code
    assert link.hint


@pytest.mark.parametrize(
    "url",
    [
        f"https://youtube.com.evil.test/watch?v={ID}",
        f"https://youtu.be.evil.test/{ID}",
        f"https://www-youtube.com/watch?v={ID}",
    ],
)
def test_look_alike_hosts_are_refused(url):
    link = classify(url)
    assert isinstance(link, Refused) and link.code == "lookalike"


@pytest.mark.parametrize(
    "url",
    [
        f"https://youtu.be@evil.test/{ID}",
        f"https://user:pass@www.youtube.com/watch?v={ID}",
        f"https://evil.test\\@www.youtube.com/watch?v={ID}",
        "javascript:alert(1)",
        "ftp://example.org/a.vtt",
        "https://exa mple.org/a.vtt",
        "https://example.org/‮a.vtt",
        "https://" + "a" * 600 + ".org/",
        None,
        "",
    ],
)
def test_userinfo_backslashes_bad_schemes_and_junk_are_refused(url):
    assert isinstance(classify(url), Refused)


def test_spotify_is_unsupported_and_apple_ids_are_read():
    spotify = classify("https://open.spotify.com/episode/abc123")
    assert isinstance(spotify, Refused) and spotify.code == "unsupported"
    apple = classify("https://podcasts.apple.com/us/podcast/some-show/id1234567890?i=1000654321")
    assert apple == ApplePodcastLink(
        podcast_id="1234567890",
        episode_id="1000654321",
        url="https://podcasts.apple.com/us/podcast/some-show/id1234567890?i=1000654321",
    )
    assert isinstance(classify("https://podcasts.apple.com/us/browse"), Refused)
    assert classify("https://feeds.example.org/show.xml") == WebLink("https://feeds.example.org/show.xml")


def test_display_url_drops_credential_like_queries_and_keeps_youtube_v():
    assert display_url("https://cdn.example.org/a.vtt?token=abc123") == "https://cdn.example.org/a.vtt"
    assert display_url("https://cdn.example.org/a.vtt?auth=x&lang=en") == "https://cdn.example.org/a.vtt"
    assert display_url("https://s3.example.org/a.vtt?X-Amz-Signature=abc&X-Amz-Expires=60") == (
        "https://s3.example.org/a.vtt"
    )
    assert display_url("https://cdn.example.org/a.vtt?sig=abc") == "https://cdn.example.org/a.vtt"
    assert display_url("https://cdn.example.org/a.vtt?lang=en#frag") == "https://cdn.example.org/a.vtt?lang=en"
    assert display_url("https://feeds.example.org/p?id=" + "ghp_" + "A1b2C3d4" * 5) == (
        "https://feeds.example.org/p"
    )
    assert display_url("", video_id=ID) == f"https://www.youtube.com/watch?v={ID}"
    assert "@" not in display_url("https://example.org:8443/path?x=1")


def test_the_cache_key_is_a_stable_hash_that_never_holds_the_query():
    key = url_key("https://Feeds.Example.org/private.xml?token=SECRET#x")
    assert key == url_key("https://feeds.example.org/private.xml?token=SECRET")
    assert key.startswith("url:") and "SECRET" not in key and len(key) <= 80
    assert key != url_key("https://feeds.example.org/private.xml?token=OTHER")
    assert url_key("https://f.example/x.xml", "guid-1") != url_key("https://f.example/x.xml", "guid-2")
    assert youtube_key(ID) == f"yt:{ID}"


def test_only_oembed_may_be_requested_on_a_youtube_host():
    assert youtube_request_allowed("https://www.youtube.com/oembed?url=x&format=json")
    assert youtube_request_allowed("https://example.org/anything")
    for url in (
        f"https://www.youtube.com/watch?v={ID}",
        "https://www.youtube.com/api/timedtext?v=x",
        "https://www.youtube.com/youtubei/v1/player",
        "http://www.youtube.com/oembed",
        f"https://youtu.be/{ID}",
        "https://m.youtube.com/oembed",
        "https://rr1.googlevideo.com/videoplayback",
    ):
        assert not youtube_request_allowed(url), url
    assert sources.is_youtube_host("music.youtube.com")
    assert not sources.is_youtube_host("notyoutube.org")


class Recorder:
    def __init__(self, responder):
        self.requests: list[httpx.Request] = []
        self._responder = responder

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        return self._responder(request)


def public(_url: str) -> tuple[str, ...]:
    return ("93.184.216.34",)


class FakeGemini:
    def __init__(self):
        self.calls: list[dict[str, Any]] = []

    async def read_video_url(self, **kwargs: Any) -> LLMResponse:
        self.calls.append(kwargs)
        return LLMResponse(
            content='{"passages": [{"start": "0:05", "text": "Intro to eigenvalues."}]}',
            usage={"input_tokens": 100, "output_tokens": 20},
        )


@pytest.mark.asyncio
async def test_a_whole_youtube_read_asks_youtube_for_oembed_only():
    def respond(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/oembed":
            return httpx.Response(200, json={"title": "Lecture 1", "author_name": "Prof"})
        return httpx.Response(404)

    recorder = Recorder(respond)
    toolkit = VideoToolkit(resolver=public, transport=httpx.MockTransport(recorder))
    gemini = FakeGemini()
    model = turn_context.TurnModel(
        provider="gemini",
        model="gemini-3.5-flash-lite",
        read_video_url=gemini.read_video_url,
        record_usage=lambda usage: None,
    )
    with turn_context.bound(model):
        result = await toolkit.execute("transcript", {"url": f"https://youtu.be/{ID}"}, "not-a-uuid")
    assert result["ok"] is True, result
    youtube = [r for r in recorder.requests if sources.is_youtube_host(r.url.host)]
    assert [r.url.path for r in youtube] == ["/oembed"]
    assert len(recorder.requests) == 1
    assert gemini.calls[0]["url"] == f"https://www.youtube.com/watch?v={ID}"


@pytest.mark.asyncio
async def test_a_redirect_to_a_youtube_video_is_never_followed_and_goes_to_the_provider_path():
    # A shortened link (bit.ly, t.co) to a video: the hop is refused before
    # it is requested, and the video is read the way a YouTube link is.
    def respond(request: httpx.Request) -> httpx.Response:
        if request.url.host == "short.example":
            return httpx.Response(302, headers={"location": f"https://www.youtube.com/watch?v={ID}&t=90"})
        if request.url.path == "/oembed":
            return httpx.Response(200, json={"title": "Lecture 1", "author_name": "Prof"})
        return httpx.Response(404)

    recorder = Recorder(respond)
    toolkit = VideoToolkit(resolver=public, transport=httpx.MockTransport(recorder))
    # No Gemini turn: the same answer a YouTube link gets, and YouTube was
    # never asked anything.
    result = await toolkit.execute("transcript", {"url": "https://short.example/abc"}, "not-a-uuid")
    assert result["ok"] is False and result["code"] == "provider"
    assert "video.transcript" not in result["error"]
    assert [r.url.host for r in recorder.requests] == ["short.example"]

    gemini = FakeGemini()
    model = turn_context.TurnModel(
        provider="gemini",
        model="gemini-3.5-flash-lite",
        read_video_url=gemini.read_video_url,
        record_usage=lambda usage: None,
    )
    with turn_context.bound(model):
        read = await toolkit.execute("transcript", {"url": "https://short.example/abc"}, "not-a-uuid")
    assert read["ok"] is True, read
    assert read["title"] == "Lecture 1" and read["passages"][0]["text"] == "Intro to eigenvalues."
    [call] = gemini.calls
    assert call["url"] == f"https://www.youtube.com/watch?v={ID}" and call["start_s"] == 90
    youtube = [r for r in recorder.requests if sources.is_youtube_host(r.url.host)]
    assert [r.url.path for r in youtube] == ["/oembed"]


@pytest.mark.asyncio
async def test_a_redirect_to_another_youtube_page_is_refused_with_why():
    def respond(request: httpx.Request) -> httpx.Response:
        return httpx.Response(302, headers={"location": "https://www.youtube.com/playlist?list=PL123"})

    recorder = Recorder(respond)
    toolkit = VideoToolkit(resolver=public, transport=httpx.MockTransport(recorder))
    result = await toolkit.execute("transcript", {"url": "https://short.example/abc"}, "not-a-uuid")
    assert result["ok"] is False and result.get("blocked") is True
    assert result["error"].startswith("That link leads to YouTube: ") and result["code"] != "provider"
    assert [r.url.host for r in recorder.requests] == ["short.example"]


@pytest.mark.asyncio
async def test_a_captions_link_on_a_page_that_redirects_to_youtube_names_the_video():
    page = b'<html><body><video><track kind="captions" src="/c.vtt" srclang="en"></video></body></html>'

    def respond(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/c.vtt":
            return httpx.Response(302, headers={"location": f"https://youtu.be/{ID}"})
        return httpx.Response(200, headers={"content-type": "text/html"}, content=page)

    recorder = Recorder(respond)
    toolkit = VideoToolkit(resolver=public, transport=httpx.MockTransport(recorder))
    result = await toolkit.execute("transcript", {"url": "https://course.example/week1"}, "not-a-uuid")
    assert result["ok"] is False and result["code"] == "youtube_link" and result["blocked"] is True
    assert f"https://www.youtube.com/watch?v={ID}" in result["error"]
    assert "video.transcript with that YouTube link" in result["hint"]
    assert not any(sources.is_youtube_host(r.url.host) for r in recorder.requests)


def test_the_rule_is_an_egress_refusal():
    from services.tools.video.toolkit import _youtube_rule

    resolve = _youtube_rule(public)
    assert resolve("https://www.youtube.com/oembed?url=x") == ("93.184.216.34",)
    with pytest.raises(EgressBlocked):
        resolve(f"https://www.youtube.com/watch?v={ID}")
