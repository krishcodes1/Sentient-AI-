"""Classifies a link given to video.transcript (a YouTube video, an Apple
Podcasts episode, anything else on the web, or a refusal), and holds the URL
rules the family lives by: the YouTube host rule, the display URL and the
cache key.

Why it exists: every YouTube URL form must map to its video id (watch,
shorts, live, embed, youtu.be, youtube-nocookie, m., music.) while look-alike
hosts, playlists, channels and search pages are refused before anything is
fetched. Crawler never fetches YouTube pages or caption tracks: robots.txt
disallows /api/ and /youtubei/, the terms forbid automated access, and
captions.download needs edit rights. The one request allowed to a YouTube
host is https://www.youtube.com/oembed (YOUTUBE_ALLOWED_PATHS), which the
toolkit's client enforces on every hop (``youtube_request_allowed``). A
link's query string often carries a token, so ``display_url`` keeps it only
when nothing in it looks like a credential, and the cache key of a non-YouTube
link is a hash, so a private feed's token is never stored.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from typing import Optional, Union
from urllib.parse import parse_qsl, urlsplit, urlunsplit

MAX_URL_CHARS = 500

# Registrable domains whose hosts (and every subdomain) are YouTube's.
YOUTUBE_DOMAINS: tuple[str, ...] = (
    "youtube.com",
    "youtu.be",
    "youtube-nocookie.com",
    "googlevideo.com",
)
# The only paths Crawler requests on a YouTube host (www.youtube.com, https).
YOUTUBE_ALLOWED_PATHS: frozenset[str] = frozenset({"/oembed"})
OEMBED_URL = "https://www.youtube.com/oembed"
_OEMBED_HOSTS = frozenset({"www.youtube.com", "youtube.com"})

SPOTIFY_DOMAINS: tuple[str, ...] = ("spotify.com", "spotify.link", "spoti.fi")
APPLE_PODCAST_HOSTS: frozenset[str] = frozenset({"podcasts.apple.com", "itunes.apple.com"})

_VIDEO_ID = re.compile(r"[A-Za-z0-9_-]{11}")
_APPLE_ID = re.compile(r"/id(\d{3,15})(?:/|$)")
_DIGITS = re.compile(r"\d{1,15}")
# A host that names YouTube without being it: youtube.com.evil.test,
# youtu.be.example, www-youtube.com.
_LOOKALIKE = re.compile(r"youtube|youtu\.be|youtu-be", re.IGNORECASE)
_CONTROL = re.compile(r"[\x00-\x20\x7f-\x9f​-‏ -‮⁠-⁤﻿]")
_OFFSET = re.compile(r"^(?:(\d{1,3})h)?(?:(\d{1,4})m)?(?:(\d{1,6})s?)?$")

# Query keys whose value is a credential or a signature, on top of the audit
# log's key names (services/security/policies.AUDIT_KEY_NAMES).
_SENSITIVE_QUERY_KEY = re.compile(
    r"auth|key|sig|signature|expires|policy|token|secret|passw|credential|session|"
    r"^x-amz-|^x-goog-|^s$|^st$|^sid$",
    re.IGNORECASE,
)
# A query value this long is treated as a signed token whatever it looks like.
_LONG_QUERY_VALUE = 40

NOT_A_VIDEO = "That YouTube link is not a single video."
NOT_A_VIDEO_HINT = "Send the link of one video (youtube.com/watch?v=… or youtu.be/…)."


@dataclass(frozen=True)
class Refused:
    """A link video.transcript does not read, with what to do instead."""

    error: str
    hint: str
    code: str


@dataclass(frozen=True)
class YouTubeLink:
    video_id: str
    start_s: Optional[int]


@dataclass(frozen=True)
class ApplePodcastLink:
    podcast_id: str
    episode_id: Optional[str]
    url: str


@dataclass(frozen=True)
class WebLink:
    """Any other http(s) link: a feed, a captions file or a page, told apart
    by what it serves."""

    url: str


Classified = Union[Refused, YouTubeLink, ApplePodcastLink, WebLink]


def _refused(error: str, hint: str, code: str) -> Refused:
    return Refused(error=error, hint=hint, code=code)


def _on_domain(host: str, domains: tuple[str, ...]) -> bool:
    return any(host == d or host.endswith("." + d) for d in domains)


def host_of(url: str) -> str:
    try:
        return (urlsplit(url).hostname or "").lower().rstrip(".")
    except ValueError:
        return ""


def is_youtube_host(host: str) -> bool:
    """True for youtube.com, youtu.be, youtube-nocookie.com and
    googlevideo.com and every subdomain of them (www., m., music.)."""
    return _on_domain((host or "").lower().rstrip("."), YOUTUBE_DOMAINS)


def is_youtube_url(url: str) -> bool:
    return is_youtube_host(host_of(url))


def youtube_request_allowed(url: str) -> bool:
    """Whether Crawler may request *url*: anything that is not a YouTube
    host, and on a YouTube host only https://www.youtube.com/oembed."""
    try:
        parts = urlsplit(url)
    except ValueError:
        return False
    host = (parts.hostname or "").lower().rstrip(".")
    if not is_youtube_host(host):
        return True
    return (
        parts.scheme.lower() == "https"
        and host in _OEMBED_HOSTS
        and parts.path in YOUTUBE_ALLOWED_PATHS
    )


def watch_url(video_id: str) -> str:
    """The canonical watch URL, rebuilt from the parsed id (never a string
    the model or a page wrote)."""
    return f"https://www.youtube.com/watch?v={video_id}"


def short_link(video_id: str) -> str:
    """The link a reply cites: append the seconds (``…?t=754``)."""
    return f"https://youtu.be/{video_id}?t="


def parse_offset(value: str) -> Optional[int]:
    """Seconds from a t= / start= value: ``754``, ``754s``, ``12m``,
    ``1h2m3s``; None when it is not one."""
    text = (value or "").strip().lower()
    if not text:
        return None
    match = _OFFSET.fullmatch(text)
    if match is None or not any(match.groups()):
        return None
    hours, minutes, seconds = (int(g) if g else 0 for g in match.groups())
    return hours * 3600 + minutes * 60 + seconds


def classify(raw: object) -> Classified:
    """What *raw* (the model's ``url`` argument) is. Refused: not a string,
    over 500 characters, not http(s), carrying a user name or password or a
    backslash, a YouTube look-alike, a YouTube playlist, channel, search or
    live page, a Spotify link."""
    if not isinstance(raw, str) or not raw.strip():
        return _refused("A 'url' is required.", "Pass the link the user sent.", "bad_url")
    url = raw.strip()
    if len(url) > MAX_URL_CHARS:
        return _refused(
            f"That link is longer than {MAX_URL_CHARS} characters.",
            "Send the page's plain link without tracking parameters.",
            "bad_url",
        )
    if _CONTROL.search(url) or "\\" in url:
        return _refused(
            "That link has spaces, a backslash or hidden characters in it.",
            "Send the link exactly as the site shows it.",
            "bad_url",
        )
    try:
        parts = urlsplit(url)
        port = parts.port
    except ValueError:
        return _refused("That link is malformed.", "Send the link exactly as the site shows it.", "bad_url")
    del port
    if parts.scheme.lower() not in ("http", "https"):
        return _refused("Only http(s) links can be read.", "Send a web link.", "bad_url")
    if "@" in parts.netloc or parts.username is not None or parts.password is not None:
        return _refused(
            "Links with a user name or password in them are not read.",
            "Send the link without the part before '@'.",
            "bad_url",
        )
    host = (parts.hostname or "").lower().rstrip(".")
    if not host:
        return _refused("That link has no host.", "Send a full link.", "bad_url")
    if is_youtube_host(host):
        return _youtube(parts, host)
    if _LOOKALIKE.search(host):
        return _refused(
            "That is not a YouTube address; it only looks like one.",
            "Send the video's real youtube.com or youtu.be link.",
            "lookalike",
        )
    if _on_domain(host, SPOTIFY_DOMAINS):
        return _refused(
            "Spotify episodes can't be read: Spotify does not publish transcripts to other apps.",
            "If the show has its own RSS feed or website, send that link instead.",
            "unsupported",
        )
    if host in APPLE_PODCAST_HOSTS:
        return _apple(parts, url)
    return WebLink(url=url)


def _youtube(parts, host: str) -> Classified:
    if _on_domain(host, ("googlevideo.com",)):
        return _refused(
            "That is a YouTube media-server link, which Crawler does not read.",
            "Send the video's own YouTube link instead.",
            "unsupported",
        )
    query = dict(parse_qsl(parts.query, keep_blank_values=True))
    segments = [s for s in parts.path.split("/") if s]
    video_id: Optional[str] = None
    if _on_domain(host, ("youtu.be",)):
        video_id = segments[0] if segments else None
    elif _on_domain(host, ("youtube-nocookie.com",)):
        if len(segments) >= 2 and segments[0] == "embed":
            video_id = segments[1]
    else:
        head = segments[0].lower() if segments else ""
        if head == "watch":
            video_id = query.get("v")
            if not video_id and query.get("list"):
                return _playlist()
        elif head == "playlist" or (
            head == "embed" and len(segments) >= 2 and segments[1] == "videoseries"
        ):
            return _playlist()
        elif head in ("shorts", "live", "embed", "v", "e") and len(segments) >= 2:
            video_id = segments[1]
        elif head in ("results", "search", "feed", "hashtag"):
            return _refused(
                "That is a YouTube search or feed page, not a video.",
                NOT_A_VIDEO_HINT,
                "not_a_video",
            )
        elif head in ("channel", "c", "user") or head.startswith("@"):
            if segments[-1].lower() in ("live", "streams"):
                return _refused(
                    "That is a channel's live page. Live streams can't be read while they are live.",
                    "Once the stream has ended, send the link of its recording.",
                    "live",
                )
            return _refused(
                "That is a YouTube channel, not a single video.",
                NOT_A_VIDEO_HINT,
                "not_a_video",
            )
    if not video_id or not _VIDEO_ID.fullmatch(video_id):
        return _refused(NOT_A_VIDEO, NOT_A_VIDEO_HINT, "not_a_video")
    start: Optional[int] = None
    for key in ("t", "start", "time_continue"):
        if key in query:
            start = parse_offset(query[key])
            if start is not None:
                break
    if start is None and parts.fragment.startswith("t="):
        start = parse_offset(parts.fragment[2:])
    return YouTubeLink(video_id=video_id, start_s=start)


def _playlist() -> Refused:
    return _refused(
        "That is a YouTube playlist. Crawler reads one video at a time.",
        "Send the link of the one video you want (open it from the playlist and copy its link).",
        "playlist",
    )


def _apple(parts, url: str) -> Classified:
    match = _APPLE_ID.search(parts.path)
    if match is None:
        return _refused(
            "That Apple Podcasts link doesn't name a show.",
            "Open the episode in Apple Podcasts and share its link, or send the show's RSS feed.",
            "bad_url",
        )
    episode = dict(parse_qsl(parts.query)).get("i")
    episode_id = episode if episode and _DIGITS.fullmatch(episode) else None
    return ApplePodcastLink(podcast_id=match.group(1), episode_id=episode_id, url=url)


def _query_is_sensitive(query: str) -> bool:
    from services.security.policies import AUDIT, AUDIT_KEY_NAMES
    from services.security.redact import contains
    from services.security.secrets import looks_like_credential

    for key, value in parse_qsl(query, keep_blank_values=True):
        if AUDIT_KEY_NAMES.search(key) or _SENSITIVE_QUERY_KEY.search(key):
            return True
        if len(value) >= _LONG_QUERY_VALUE or looks_like_credential(value) or contains(value, AUDIT):
            return True
    return False


def display_url(url: str, *, video_id: Optional[str] = None) -> str:
    """The URL a result and a cached row show: scheme, host and path, and
    the query only when no key or value in it looks like a credential. A
    YouTube link is shown as its canonical watch URL (the v= parameter
    kept). Never a fragment or a user name. At most 500 characters."""
    if video_id is not None:
        return watch_url(video_id)
    try:
        parts = urlsplit(url)
        port = parts.port
    except ValueError:
        return ""
    host = (parts.hostname or "").lower().rstrip(".")
    netloc = host if port is None else f"{host}:{port}"
    query = "" if not parts.query or _query_is_sensitive(parts.query) else parts.query
    shown = urlunsplit((parts.scheme.lower(), netloc, parts.path or "/", query, ""))
    if len(shown) > MAX_URL_CHARS:
        shown = urlunsplit((parts.scheme.lower(), netloc, parts.path or "/", "", ""))[:MAX_URL_CHARS]
    return shown


def normalised(url: str) -> str:
    """*url* with its scheme and host lower-cased, a default port and the
    fragment dropped: what the cache key hashes."""
    parts = urlsplit(url)
    scheme = parts.scheme.lower()
    host = (parts.hostname or "").lower().rstrip(".")
    port = parts.port
    if port is not None and (scheme, port) not in (("http", 80), ("https", 443)):
        host = f"{host}:{port}"
    return urlunsplit((scheme, host, parts.path or "/", parts.query, ""))


def youtube_key(video_id: str, *, language: Optional[str] = None) -> str:
    """``yt:<video id>``, plus ``:<language>`` for a reading asked for in a
    language (the provider writes the passages in it), so one language's
    reading never answers a call for another."""
    return f"yt:{video_id}" + (f":{language.lower()}" if language else "")


def url_key(url: str, part: str = "", *, language: Optional[str] = None) -> str:
    """``url:<sha256>`` of the normalised URL (plus *part*, an episode's
    guid, and *language*, the captions or transcript language a call asked
    for): the query is hashed, never stored."""
    material = normalised(url) + ("\n" + part if part else "")
    if language:
        material += "\nlang:" + language.lower()
    return "url:" + hashlib.sha256(material.encode("utf-8")).hexdigest()


def same_language(asked: Optional[str], held: Optional[str]) -> bool:
    """Whether a transcript saved in *held* answers a call that asked for
    *asked*: the same tag, or the same language where one side names no
    region (``de`` and ``de-DE``; never ``pt-BR`` and ``pt-PT``)."""
    if not asked or not held:
        return False
    a, h = asked.lower(), held.lower()
    if a == h:
        return True
    a_base, h_base = a.split("-")[0], h.split("-")[0]
    return a_base == h_base and (a == a_base or h == h_base)
