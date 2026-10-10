"""Finds what a lecture or episode page offers video.transcript: caption
tracks (``<track kind=captions|subtitles>`` and links to caption files),
embedded YouTube videos, the page's podcast feed (``<link rel=alternate>``)
and plain audio or video players.

Why it exists: a course page or an episode page rarely is the transcript; it
points at one. Discovery reads the page with the stdlib HTMLParser (no
script runs, nothing is fetched here), resolves relative links against the
page's final URL, keeps http(s) links only, and caps every list. The toolkit
then fetches the chosen track through the guarded client, or reads an
embedded YouTube video by its id (never by fetching YouTube).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from html.parser import HTMLParser
from typing import Optional
from urllib.parse import urljoin, urlsplit

from services.tools.video.captions import clean_text
from services.tools.video.sources import WebLink, YouTubeLink, classify

MAX_ITEMS = 50
_CAPTION_SUFFIXES = (".vtt", ".srt", ".sbv", ".ttml", ".dfxp")
_FEED_TYPES = ("application/rss+xml", "application/atom+xml", "application/xml", "text/xml")


@dataclass(frozen=True)
class Track:
    url: str
    kind: str
    language: str
    label: str


@dataclass
class PageFindings:
    title: str = ""
    tracks: list[Track] = field(default_factory=list)
    youtube: list[YouTubeLink] = field(default_factory=list)
    feeds: list[str] = field(default_factory=list)
    media: list[str] = field(default_factory=list)


class _Discovery(HTMLParser):
    def __init__(self, base_url: str) -> None:
        super().__init__(convert_charrefs=True)
        self.base = base_url
        self.found = PageFindings()
        self._in_title = False
        self._title: list[str] = []
        self._seen: set[str] = set()

    def _resolve(self, raw: Optional[str]) -> Optional[str]:
        if not raw or len(raw) > 2000:
            return None
        try:
            url = urljoin(self.base, raw.strip())
        except ValueError:
            return None
        if urlsplit(url).scheme.lower() not in ("http", "https"):
            return None
        return url

    def _add(self, bucket: list, item: object, key: str) -> None:
        if key in self._seen or len(bucket) >= MAX_ITEMS:
            return
        self._seen.add(key)
        bucket.append(item)

    def handle_starttag(self, tag: str, attrs: list[tuple[str, Optional[str]]]) -> None:
        values = {name.lower(): (value or "") for name, value in attrs}
        if tag == "title":
            self._in_title = True
        elif tag == "track":
            kind = (values.get("kind") or "subtitles").strip().lower()
            url = self._resolve(values.get("src"))
            if url and kind in ("captions", "subtitles"):
                track = Track(
                    url=url,
                    kind=kind,
                    language=values.get("srclang", "").strip().lower()[:16],
                    label=clean_text(values.get("label", ""))[:80],
                )
                self._add(self.found.tracks, track, "track:" + url)
        elif tag in ("iframe", "embed"):
            url = self._resolve(values.get("src"))
            if url:
                link = classify(url)
                if isinstance(link, YouTubeLink):
                    self._add(self.found.youtube, link, "yt:" + link.video_id)
        elif tag == "link":
            rel = values.get("rel", "").lower().split()
            kind = values.get("type", "").lower()
            url = self._resolve(values.get("href"))
            if url and "alternate" in rel and kind.startswith(_FEED_TYPES):
                self._add(self.found.feeds, url, "feed:" + url)
        elif tag in ("audio", "video", "source"):
            url = self._resolve(values.get("src"))
            if url:
                link = classify(url)
                if isinstance(link, YouTubeLink):
                    self._add(self.found.youtube, link, "yt:" + link.video_id)
                elif isinstance(link, WebLink):
                    self._add(self.found.media, url, "media:" + url)
        elif tag == "a":
            url = self._resolve(values.get("href"))
            if not url:
                return
            path = urlsplit(url).path.lower()
            if path.endswith(_CAPTION_SUFFIXES):
                track = Track(url=url, kind="captions", language=values.get("hreflang", "").lower()[:16], label="")
                self._add(self.found.tracks, track, "track:" + url)

    def handle_endtag(self, tag: str) -> None:
        if tag == "title":
            self._in_title = False

    def handle_data(self, data: str) -> None:
        if self._in_title and len(self._title) < 50:
            self._title.append(data)

    def close(self) -> None:
        super().close()
        self.found.title = clean_text(" ".join(self._title))[:200]


def discover(html: str, base_url: str) -> PageFindings:
    """What *html* (served from *base_url*, the final URL) links to. Never
    raises: a page the parser cannot finish yields what was found before."""
    parser = _Discovery(base_url)
    try:
        parser.feed(html)
        parser.close()
    except Exception:  # noqa: BLE001 - malformed markup: keep what was found
        parser.found.title = clean_text(" ".join(parser._title))[:200]
    return parser.found


def pick_track(tracks: list[Track], language: Optional[str] = None) -> Optional[Track]:
    """The track to read: one in *language* first, then captions before
    subtitles, then page order."""
    if not tracks:
        return None
    wanted = (language or "").lower().split("-")[0]

    def rank(indexed: tuple[int, Track]) -> tuple[int, int, int]:
        index, track = indexed
        lang = 0 if wanted and track.language.split("-")[0] == wanted else 1
        return (lang if wanted else 0, 0 if track.kind == "captions" else 1, index)

    return min(enumerate(tracks), key=rank)[1]
