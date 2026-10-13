"""Implements the video.* built-in tools: transcript (timestamped passages of a
YouTube video, lecture page, podcast episode or captions file) and list (the
user's saved transcripts, metadata only).

Why it exists: students ask Crawler to summarise lectures and podcasts and to
find where something was said. Sources are tried cheapest and most faithful
first: text the publisher provides (a feed's ``<podcast:transcript>``, a
page's ``<track>`` captions, a captions file), then, for YouTube only, the
turn's own Gemini watching the video (provider_video.py). Crawler never
fetches YouTube pages or caption tracks and has no browser fallback: every
request goes through the guarded client (SSRF check and DNS pin on every hop,
at most 5 redirects, an honest user agent, a 45 s deadline for the publisher
path), and that client refuses any YouTube request but oEmbed. A 403, 429 or
bot-check page is reported, never retried. Results are a top-level list of
passages of at most 700 characters (the runtime redacts a poisoned one alone)
capped at 16000 characters as shown, with ``next_start`` to continue and
``find`` to return only the passages that mention some words. Whole
transcripts are cached per user (store.py). Audio transcription is phase 2:
media with no published text is answered with NO_TRANSCRIPT.
"""

from __future__ import annotations

import asyncio
import math
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Awaitable, Callable, Mapping, Optional, Protocol, Union
from urllib.parse import urljoin, urlsplit

import httpx
import structlog

from services.agent import turn_context
from services.tools.net import (
    AddressResolver,
    EgressBlocked,
    build_guarded_client,
    validated_addresses,
)
from services.tools.text_budget import shown_length
from services.tools.video import podcast as podcasts
from services.tools.video.captions import (
    MAX_CAPTION_BYTES,
    PASSAGE_MAX_CHARS,
    Cue,
    _split_long,
    build_passages,
    decode,
    fmt_time,
    parse_captions_cut,
    parse_clock,
    parse_timed_text,
    sniff,
)
from services.tools.video.page import discover, pick_track
from services.tools.video.provider_video import (
    NOT_GEMINI_ERROR,
    NOT_GEMINI_HINT,
    OEmbed,
    ProviderReading,
    ProviderVideoReader,
    error,
    oembed,
    valid_language,
)
from services.tools.video.sources import (
    ApplePodcastLink,
    Refused,
    WebLink,
    YouTubeLink,
    classify,
    display_url,
    host_of,
    same_language,
    short_link,
    url_key,
    watch_url,
    youtube_key,
    youtube_request_allowed,
)
from services.tools.video.store import (
    KEEP_DAYS_DEFAULT,
    MAX_ROW_CHARS,
    Segment,
    TranscriptRecord,
    TranscriptStore,
    covers,
)

logger = structlog.get_logger(__name__)

ACTIONS = ("transcript", "list")
# The most one video.transcript answer shows the model, measured as shown
# (text_budget.shown_length). runtime.RESULT_CHAR_BUDGETS["video.transcript"]
# is this plus 4000; raise both together.
RESULT_SHOWN_CHARS = 16000
_FIT_MARGIN = 600
# video.list rows, as shown; its runtime budget is 6000.
LIST_ROWS_CHARS = 5200
PUBLISHER_DEADLINE_S = 45.0
MAX_REDIRECTS = 5
MAX_FEED_BYTES = podcasts.MAX_FEED_BYTES
FIND_MAX_CHARS = 100
EPISODE_MAX_CHARS = 200
FIND_MAX_PASSAGES = 12
LIST_DEFAULT = 10
LIST_MAX = 20
DETAILS = ("notes", "verbatim")
PUBLISHER = "publisher_captions"
PROVIDER = "provider_video"

NO_TRANSCRIPT = "This episode has no published transcript; transcribing audio is not available yet."
NO_TRANSCRIPT_HINT = "If the user has a transcript or captions file for it, they can send that link instead."
YOUTUBE_ONLY_OEMBED = (
    "Crawler never fetches YouTube pages; a YouTube video is read with video.transcript "
    "through the AI provider only."
)
_ARGUMENTS = frozenset({"url", "start", "end", "find", "episode", "language", "detail"})
_DROPPED = frozenset({"user_id", "user_confirmed"})
_CAPTION_KINDS = frozenset({"vtt", "srt", "sbv", "ttml", "json", "text"})
_MEDIA_TYPES = ("audio/", "video/")
_STREAM_TYPES = frozenset(
    {"application/vnd.apple.mpegurl", "application/x-mpegurl", "application/dash+xml"}
)
_CHALLENGE = re.compile(
    r"cf-chl|challenge-platform|captcha|verify you are (a )?human|are you a robot|"
    r"<title>\s*just a moment",
    re.IGNORECASE,
)
_WORDS = re.compile(r"\w+", re.UNICODE)
_INDEX_START = re.compile(r"#(\d{1,5})")


class VideoSettings(Protocol):
    """Where the toolkit reads the owner's video limits
    (InstallationService implements it): video_minutes_per_call,
    video_minutes_per_day and keep_transcripts_days."""

    async def video_limits(self) -> Mapping[str, int]: ...


AuditLog = Callable[[dict[str, Any]], Awaitable[None]]


@dataclass(frozen=True)
class _Args:
    url: Any
    start: Optional[float]
    start_index: Optional[int]
    end: Optional[float]
    find: Optional[str]
    episode: Optional[str]
    language: Optional[str]
    detail: str


@dataclass(frozen=True)
class _Fetched:
    url: str
    media_type: str
    data: bytes
    media: bool
    # The body went on past max_bytes; only the first max_bytes were read.
    cut: bool = False


@dataclass(frozen=True)
class _ToYouTube:
    """A page whose one video is on YouTube, or a link that redirects to a
    YouTube video: read it on the provider path, outside the publisher
    deadline."""

    link: YouTubeLink


class _YouTubeHop(EgressBlocked):
    """A request (a redirect hop) to a YouTube host, refused before any
    socket opens. It keeps the hop's URL so the toolkit can say which video
    the link leads to; nothing at that URL is ever fetched."""

    def __init__(self, url: str) -> None:
        super().__init__(YOUTUBE_ONLY_OEMBED)
        self.url = url


def _youtube_hop(url: str) -> Union[YouTubeLink, dict[str, Any]]:
    """Where a refused hop to YouTube leads: the video (read on the provider
    path), or a refusal that says what the link is."""
    target = classify(url)
    if isinstance(target, YouTubeLink):
        return target
    if isinstance(target, Refused):
        return error(f"That link leads to YouTube: {target.error}", target.hint, code=target.code, blocked=True)
    return error(YOUTUBE_ONLY_OEMBED, blocked=True, code="blocked")


def _youtube_hop_refusal(link: YouTubeLink) -> dict[str, Any]:
    """A captions, feed or transcript link inside a page or feed that leads
    to a YouTube video: Crawler does not follow it there, and says which
    video it is."""
    return error(
        f"That link leads to the YouTube video {watch_url(link.video_id)}, which Crawler "
        "never fetches; it reads YouTube videos only through the AI provider.",
        "Call video.transcript with that YouTube link.",
        code="youtube_link",
        blocked=True,
    )


def _defaults() -> dict[str, int]:
    from services.capabilities.video_transcripts import VIDEO_SETTINGS_DEFAULTS

    return dict(VIDEO_SETTINGS_DEFAULTS)


def _stopped(what: str) -> dict[str, Any]:
    return error(f"Stopped before {what}.", code="stopped")


def _youtube_rule(resolver: AddressResolver) -> AddressResolver:
    """*resolver* behind the YouTube host rule: a request to a YouTube host
    other than https://www.youtube.com/oembed is refused before any socket
    is opened, on every redirect hop."""

    def resolve(url: str) -> tuple[str, ...]:
        if not youtube_request_allowed(url):
            raise _YouTubeHop(url)
        return resolver(url)

    return resolve


def _http_refusal(status: int) -> dict[str, Any]:
    if status in (401, 403, 407):
        return error(
            f"The site refused the request (HTTP {status}).",
            "Crawler doesn't retry in the browser. If the page needs a sign-in, the user can "
            "download the captions or transcript and send that file.",
            code="refused",
            status_code=status,
        )
    if status == 429:
        return error(
            "The site is rate limiting requests (HTTP 429).",
            "Try again later; Crawler doesn't retry in the browser.",
            code="rate_limited",
            status_code=status,
        )
    if status == 404:
        return error("Nothing was found at that link (HTTP 404).", "Check the link.", code="not_found", status_code=status)
    return error(f"The site answered HTTP {status}.", code="http_error", status_code=status)


class VideoToolkit:
    """The video.* toolkit. ``session_factory`` backs the transcript store;
    ``settings`` (the owner's limits), ``audit`` (the runtime's audit log)
    and the network seams (``resolver``, ``transport``) are injectable, and
    main.py hands in the first two with ``use``."""

    def __init__(
        self,
        session_factory: Optional[Callable[[], Any]] = None,
        *,
        settings: Optional[VideoSettings] = None,
        audit: Optional[AuditLog] = None,
        store: Optional[TranscriptStore] = None,
        resolver: AddressResolver = validated_addresses,
        transport: Optional[httpx.AsyncBaseTransport] = None,
        deadline_s: float = PUBLISHER_DEADLINE_S,
    ) -> None:
        self.store = store if store is not None else TranscriptStore(session_factory)
        self._settings = settings
        self.reader = ProviderVideoReader(audit=audit)
        self._resolver = resolver
        self._transport = transport
        self._deadline_s = deadline_s

    def use(self, *, settings: Optional[VideoSettings] = None, audit: Optional[AuditLog] = None) -> None:
        """Wire the owner's limits and the audit log after construction
        (main.py, once the installation service exists)."""
        if settings is not None:
            self._settings = settings
        if audit is not None:
            self.reader.audit = audit

    # -- dispatch ----------------------------------------------------------

    async def execute(
        self,
        action: str,
        params: dict[str, Any],
        user_id: str,
        *,
        cancelled: Optional[Callable[[], bool]] = None,
    ) -> dict[str, Any]:
        """Run one video.* action for *user_id* (the executor's; any user_id
        in *params* is dropped). *cancelled* is the executor's Stop check.
        Unknown actions and bad arguments are ``ok: False`` results."""
        stop = cancelled or (lambda: False)
        params = dict(params or {})
        if action == "transcript":
            args = self._arguments(params)
            if isinstance(args, dict):
                return args
            return await self._transcript(args, str(user_id), stop)
        if action == "list":
            return await self._list(params, str(user_id))
        return error(f"Unknown video action '{action}'.")

    def _arguments(self, params: dict[str, Any]) -> Union[_Args, dict[str, Any]]:
        for key in _DROPPED:
            params.pop(key, None)
        unknown = sorted(str(k) for k in params if k not in _ARGUMENTS)
        if unknown:
            return error(f"Unknown argument(s) for video.transcript: {', '.join(unknown)}.")
        start: Optional[float] = None
        start_index: Optional[int] = None
        raw_start = params.get("start")
        if raw_start is not None and raw_start != "":
            index = _INDEX_START.fullmatch(raw_start.strip()) if isinstance(raw_start, str) else None
            if index:
                start_index = max(1, int(index.group(1)))
            else:
                start = parse_clock(raw_start)
                if start is None:
                    return error("start must be a time like 12:34 or 1:02:03 (or next_start from the last answer).")
        end: Optional[float] = None
        if params.get("end") is not None and params.get("end") != "":
            end = parse_clock(params.get("end"))
            if end is None:
                return error("end must be a time like 45:00 or 1:30:00.")
            if end <= (start or 0):
                return error("end must come after start.")
        find = params.get("find")
        if find is not None:
            if not isinstance(find, str):
                return error("find must be text: the words to look for.")
            find = find.strip() or None
            if find and len(find) > FIND_MAX_CHARS:
                return error(f"find is limited to {FIND_MAX_CHARS} characters; use a few key words.")
        episode = params.get("episode")
        if episode is not None:
            if not isinstance(episode, str):
                return error("episode must be text: words from the episode title, or its guid.")
            episode = episode.strip() or None
            if episode and len(episode) > EPISODE_MAX_CHARS:
                return error(f"episode is limited to {EPISODE_MAX_CHARS} characters.")
        language = params.get("language")
        if language is not None and language != "":
            language = valid_language(language)
            if language is None:
                return error("language must be a language code such as en, es or pt-BR.")
        else:
            language = None
        detail = params.get("detail") or "notes"
        if detail not in DETAILS:
            return error("detail must be 'notes' or 'verbatim'.")
        return _Args(params.get("url"), start, start_index, end, find, episode, language, str(detail))

    async def _limits(self) -> dict[str, int]:
        """The owner's limits (defaults when no settings source is wired).
        Raises when the settings cannot be read: the caller fails closed."""
        limits = _defaults()
        if self._settings is None:
            return limits
        stored = await self._settings.video_limits()
        for key in limits:
            value = stored.get(key)
            if isinstance(value, (int, float)) and not isinstance(value, bool) and value >= 1:
                limits[key] = int(value)
        return limits

    def _client(self) -> httpx.AsyncClient:
        from services.tools.web import _USER_AGENT

        return build_guarded_client(
            timeout_s=min(20.0, self._deadline_s),
            headers={"User-Agent": _USER_AGENT, "Accept": "*/*"},
            resolver=_youtube_rule(self._resolver),
            transport=self._transport,
            max_redirects=MAX_REDIRECTS,
        )

    # -- transcript ----------------------------------------------------------

    async def _transcript(self, args: _Args, user_id: str, stop: Callable[[], bool]) -> dict[str, Any]:
        link = classify(args.url)
        if isinstance(link, Refused):
            return error(link.error, link.hint, code=link.code)
        limits: Optional[dict[str, int]]
        try:
            limits = await self._limits()
        except Exception as exc:  # noqa: BLE001 - the provider path refuses without them
            logger.warning("video_limits_unreadable", error_type=type(exc).__name__)
            limits = None
        keep_days = (limits or _defaults()).get("keep_transcripts_days", KEEP_DAYS_DEFAULT)
        await self._purge(user_id, keep_days)
        if isinstance(link, YouTubeLink):
            return await self._youtube(link, args, user_id, stop, limits, keep_days)
        routed: Union[dict[str, Any], _ToYouTube]
        try:
            async with asyncio.timeout(self._deadline_s):
                async with self._client() as client:
                    if isinstance(link, ApplePodcastLink):
                        routed = await self._apple(client, link, args, user_id, stop, keep_days)
                    else:
                        routed = await self._web(client, link, args, user_id, stop, keep_days)
        except TimeoutError:
            return error(
                f"The site took longer than {int(self._deadline_s)} seconds to answer.",
                "Try again later, or send a direct link to the captions or transcript file.",
                code="timeout",
            )
        except EgressBlocked as exc:
            return error(str(exc), blocked=True, code="blocked")
        if isinstance(routed, _ToYouTube):
            return await self._youtube(routed.link, args, user_id, stop, limits, keep_days)
        return routed

    async def _purge(self, user_id: str, keep_days: int) -> None:
        try:
            await self.store.purge_expired(user_id, keep_days=keep_days)
        except Exception as exc:  # noqa: BLE001 - a failed purge never blocks a read
            logger.warning("media_transcripts_purge_failed", error_type=type(exc).__name__)

    async def _fetch(
        self, client: httpx.AsyncClient, url: str, *, max_bytes: int, stop: Callable[[], bool], what: str
    ) -> Union[_Fetched, dict[str, Any]]:
        """_fetch_or_hop for a link found inside a page or feed: one that
        redirects to a YouTube video is refused with that video's link."""
        got = await self._fetch_or_hop(client, url, max_bytes=max_bytes, stop=stop, what=what)
        if isinstance(got, YouTubeLink):
            return _youtube_hop_refusal(got)
        return got

    async def _fetch_or_hop(
        self, client: httpx.AsyncClient, url: str, *, max_bytes: int, stop: Callable[[], bool], what: str
    ) -> Union[_Fetched, dict[str, Any], YouTubeLink]:
        """GET *url* through the guarded client: at most *max_bytes* of
        body (more is cut, never buffered), media answered without reading
        its body, an HTTP error reported (never retried). A redirect to a
        YouTube video is not followed: the video comes back instead (a
        shortened link), for the provider path."""
        if stop():
            return _stopped(what)
        try:
            async with client.stream("GET", url) as response:
                status = response.status_code
                if status >= 400:
                    return _http_refusal(status)
                media_type = (response.headers.get("content-type") or "").split(";", 1)[0].strip().lower()
                final = str(response.url)
                if media_type.startswith(_MEDIA_TYPES) or media_type in _STREAM_TYPES:
                    return _Fetched(final, media_type, b"", True)
                body = bytearray()
                cut = False
                async for chunk in response.aiter_bytes():
                    body += chunk
                    if len(body) > max_bytes:
                        del body[max_bytes:]
                        cut = True
                        break
                return _Fetched(final, media_type, bytes(body), False, cut)
        except _YouTubeHop as exc:
            return _youtube_hop(exc.url)
        except EgressBlocked as exc:
            return error(str(exc), blocked=True, code="blocked")
        except httpx.TooManyRedirects:
            return error(f"That link redirects more than {MAX_REDIRECTS} times.", code="redirects")
        except httpx.HTTPError as exc:
            return error(f"Request failed: {type(exc).__name__}", code="request_failed")

    async def _cached(
        self, user_id: str, key: str, method: str, detail: str, keep_days: int
    ) -> Optional[TranscriptRecord]:
        try:
            return await self.store.get(user_id, key, method, detail, keep_days=keep_days)
        except Exception as exc:  # noqa: BLE001 - no cache is a fresh read, not a failure
            logger.warning("media_transcripts_read_failed", error_type=type(exc).__name__)
            return None

    async def _cached_in(
        self,
        user_id: str,
        plain: str,
        in_language: str,
        language: Optional[str],
        method: str,
        detail: str,
        keep_days: int,
    ) -> tuple[str, Optional[TranscriptRecord]]:
        """The key a read of this source saves to, and what is saved there.
        With no *language* asked, the source's own key (*plain*). With one,
        the transcript under *plain* when it is already in that language
        (a read with no language asked that got it), else the key kept for
        that language (*in_language*): one language's captions never answer
        a call that asked for another."""
        if not language:
            return plain, await self._cached(user_id, plain, method, detail, keep_days)
        held = await self._cached(user_id, plain, method, detail, keep_days)
        if held is not None and same_language(language, held.language):
            return plain, held
        return in_language, await self._cached(user_id, in_language, method, detail, keep_days)

    async def _save(self, user_id: str, *, keep_days: int, **fields: Any) -> TranscriptRecord:
        """Store what was read, or (when the store cannot) an unsaved record
        so the answer still goes back."""
        try:
            return await self.store.save_merge(user_id, keep_days=keep_days, **fields)
        except Exception as exc:  # noqa: BLE001 - the answer outranks the cache
            logger.warning("media_transcripts_save_failed", error_type=type(exc).__name__)
            segments = tuple(fields.get("segments") or ())
            now = datetime.now(timezone.utc)
            window = fields.get("window")
            ends = [s[1] for s in segments if s[1] is not None]
            covered = (window,) if window else (((0.0, max(ends)),) if ends else ())
            return TranscriptRecord(
                id="",
                source_key=fields["source_key"],
                kind=fields["kind"],
                method=fields["method"],
                detail=fields["detail"],
                display_url=fields["display_url"],
                title=fields.get("title"),
                author=fields.get("author"),
                language=fields.get("language"),
                duration_s=fields.get("duration_s"),
                engine=fields["engine"],
                segments=segments,
                covered=covered,
                chars=sum(len(s[2]) for s in segments),
                created_at=now,
                last_used_at=now,
                expires_at=now,
            )

    # -- the publisher paths ------------------------------------------------

    async def _web(
        self,
        client: httpx.AsyncClient,
        link: WebLink,
        args: _Args,
        user_id: str,
        stop: Callable[[], bool],
        keep_days: int,
    ) -> Union[dict[str, Any], _ToYouTube]:
        key, cached = await self._cached_in(
            user_id,
            url_key(link.url),
            url_key(link.url, language=args.language),
            args.language,
            PUBLISHER,
            "verbatim",
            keep_days,
        )
        if cached is not None:
            return self._answer(cached, args, cached=True)
        fetched = await self._fetch_or_hop(
            client, link.url, max_bytes=MAX_FEED_BYTES, stop=stop, what="the link was read"
        )
        if isinstance(fetched, YouTubeLink):
            # A shortened link (bit.ly, t.co) to a YouTube video.
            return _ToYouTube(fetched)
        if isinstance(fetched, dict):
            return fetched
        if fetched.media:
            return error(NO_TRANSCRIPT, NO_TRANSCRIPT_HINT, code="no_transcript")
        kind = sniff(fetched.data, fetched.media_type, urlsplit(fetched.url).path)
        if kind == "feed":
            return await self._podcast(
                client, fetched.data, link.url, args, user_id, stop, keep_days, page_url=None, apple=None
            )
        if kind == "html":
            return await self._page(client, fetched, link.url, key, args, user_id, stop, keep_days)
        if kind in _CAPTION_KINDS:
            cues, cut = parse_captions_cut(fetched.data, kind)
            if not cues:
                return error("No captions or transcript could be read from that file.", code="empty")
            return await self._store_publisher(
                user_id,
                cues,
                args,
                keep_days=keep_days,
                key=key,
                kind="captions",
                url=link.url,
                title=None,
                author=None,
                language=args.language,
                duration_s=None,
                cut=cut or fetched.cut,
            )
        return error(
            "That link is not a video page, podcast feed or captions file Crawler can read.",
            "Send a YouTube link, a podcast feed or episode page, a lecture page, or a .vtt/.srt file.",
            code="unsupported",
        )

    async def _store_publisher(
        self,
        user_id: str,
        cues: list[Cue],
        args: _Args,
        *,
        keep_days: int,
        key: str,
        kind: str,
        url: str,
        title: Optional[str],
        author: Optional[str],
        language: Optional[str],
        duration_s: Optional[int],
        cut: bool = False,
    ) -> dict[str, Any]:
        """Save a publisher transcript and answer from it. *cut*: the file
        went on past what Crawler reads (MAX_CAPTION_BYTES or MAX_CUES); the
        store keeps at most MAX_ROW_CHARS too. Either way the answer says
        that only the first part was kept."""
        passages = build_passages(cues)
        if not passages:
            return error("No captions or transcript could be read.", code="empty")
        ends = [p.end_s for p in passages if p.end_s is not None]
        read_chars = sum(len(p.text) for p in passages)
        record = await self._save(
            user_id,
            keep_days=keep_days,
            source_key=key,
            kind=kind,
            method=PUBLISHER,
            detail="verbatim",
            display_url=display_url(url),
            engine="publisher",
            segments=[(p.start_s, p.end_s, p.text) for p in passages],
            title=title or None,
            author=author or None,
            language=language,
            duration_s=duration_s if duration_s is not None else (int(max(ends)) if ends else None),
        )
        if cut or record.chars < read_chars:
            return self._answer(record, args, cached=False, extra_note=_kept_only(record))
        return self._answer(record, args, cached=False)

    async def _page(
        self,
        client: httpx.AsyncClient,
        fetched: _Fetched,
        page_url: str,
        key: str,
        args: _Args,
        user_id: str,
        stop: Callable[[], bool],
        keep_days: int,
    ) -> Union[dict[str, Any], _ToYouTube]:
        """A web page: its captions track (in the asked language first), one
        embedded YouTube video, a podcast feed, or a transcript in its text.
        *key* is where _web looked in the cache (the page's key for the
        asked language)."""
        html = decode(fetched.data)
        found = discover(html, fetched.url)
        track = pick_track(found.tracks, args.language)
        if track is not None:
            track_link = classify(track.url)
            if isinstance(track_link, WebLink):
                got = await self._fetch(
                    client, track_link.url, max_bytes=MAX_CAPTION_BYTES, stop=stop, what="the captions were read"
                )
                if isinstance(got, dict):
                    return got
                kind = sniff(got.data, got.media_type, urlsplit(got.url).path)
                cues, cut = parse_captions_cut(got.data, kind if kind in _CAPTION_KINDS else "vtt")
                if cues:
                    return await self._store_publisher(
                        user_id,
                        cues,
                        args,
                        keep_days=keep_days,
                        key=key,
                        kind="page",
                        url=page_url,
                        title=found.title,
                        author=None,
                        language=track.language or args.language,
                        duration_s=None,
                        cut=cut or got.cut,
                    )
        videos = found.youtube
        if len(videos) == 1:
            start = videos[0].start_s
            return _ToYouTube(YouTubeLink(videos[0].video_id, start))
        if len(videos) > 1:
            return {
                "ok": True,
                "needs_choice": True,
                "title": found.title,
                "note": "This page embeds several YouTube videos. Ask the user which one, then call "
                "video.transcript with its url.",
                "candidates": [
                    {"title": f"Embedded video {i}", "url": watch_url(v.video_id)}
                    for i, v in enumerate(videos[:8], start=1)
                ],
            }
        for feed_url in found.feeds[:1]:
            feed_link = classify(feed_url)
            if not isinstance(feed_link, WebLink):
                continue
            got = await self._fetch(client, feed_link.url, max_bytes=MAX_FEED_BYTES, stop=stop, what="the feed was read")
            if isinstance(got, dict):
                return got
            if sniff(got.data, got.media_type, urlsplit(got.url).path) == "feed":
                return await self._podcast(
                    client, got.data, feed_link.url, args, user_id, stop, keep_days, page_url=fetched.url, apple=None
                )
        from services.tools.html_text import extract_readable_text

        _title, text = extract_readable_text(html)
        cues = parse_timed_text(text)
        if sum(1 for cue in cues if cue.start_s is not None) >= 5:
            return await self._store_publisher(
                user_id,
                cues,
                args,
                keep_days=keep_days,
                key=key,
                kind="page",
                url=page_url,
                title=found.title,
                author=None,
                language=args.language,
                duration_s=None,
                cut=fetched.cut,
            )
        if found.media:
            return error(NO_TRANSCRIPT, NO_TRANSCRIPT_HINT, code="no_transcript", title=found.title)
        if _CHALLENGE.search(html[:20000]):
            return error(
                "The site showed a bot check instead of the page.",
                "Crawler doesn't try to get past it or retry in the browser; the user can open the "
                "page and send the captions or transcript file.",
                code="challenge",
            )
        return error(
            "No captions, transcript, podcast feed or YouTube video was found on that page.",
            "If the page plays a video, look for a captions or transcript download link and send that.",
            code="nothing_found",
        )

    async def _apple(
        self,
        client: httpx.AsyncClient,
        link: ApplePodcastLink,
        args: _Args,
        user_id: str,
        stop: Callable[[], bool],
        keep_days: int,
    ) -> Union[dict[str, Any], _ToYouTube]:
        show = await self._fetch(
            client,
            podcasts.apple_lookup_url(link.podcast_id, episodes=False),
            max_bytes=podcasts.MAX_LOOKUP_BYTES,
            stop=stop,
            what="the show was looked up",
        )
        if isinstance(show, dict):
            return show
        listing: Optional[bytes] = None
        if link.episode_id:
            episodes = await self._fetch(
                client,
                podcasts.apple_lookup_url(link.podcast_id, episodes=True),
                max_bytes=podcasts.MAX_LOOKUP_BYTES,
                stop=stop,
                what="the episode was looked up",
            )
            listing = episodes.data if isinstance(episodes, _Fetched) else None
        try:
            found = podcasts.read_apple_lookup(show.data, listing, link.episode_id)
        except podcasts.FeedRefused as exc:
            return error(str(exc), "Send the show's RSS feed link instead.", code="bad_feed")
        feed_link = classify(found.feed_url)
        if not isinstance(feed_link, WebLink):
            return error("That show's feed address can't be read.", code="bad_feed")
        feed = await self._fetch(client, feed_link.url, max_bytes=MAX_FEED_BYTES, stop=stop, what="the feed was read")
        if isinstance(feed, dict):
            return feed
        return await self._podcast(client, feed.data, feed_link.url, args, user_id, stop, keep_days, page_url=None, apple=found)

    async def _podcast(
        self,
        client: httpx.AsyncClient,
        data: bytes,
        feed_url: str,
        args: _Args,
        user_id: str,
        stop: Callable[[], bool],
        keep_days: int,
        *,
        page_url: Optional[str],
        apple: Optional[podcasts.AppleShow],
    ) -> dict[str, Any]:
        try:
            feed = podcasts.parse_feed(data)
        except podcasts.FeedRefused as exc:
            return error(str(exc), code="bad_feed")
        choice = podcasts.choose_episode(
            feed,
            args.episode,
            page_url=page_url,
            guid=apple.episode_guid if apple else None,
            title_hint=apple.episode_title if apple else None,
        )
        if isinstance(choice, podcasts.Ambiguous):
            if not choice.candidates:
                return error("That feed lists no episodes.", code="empty")
            return {
                "ok": True,
                "needs_choice": True,
                "title": feed.title,
                "note": f"{choice.reason} Ask the user which one, then call video.transcript again "
                "with episode set to its guid or title.",
                "candidates": [
                    {"title": e.title, "date": e.date, "guid": e.guid} for e in choice.candidates
                ],
            }
        episode = choice.episode
        episode_part = episode.guid or episode.link or episode.title
        key, cached = await self._cached_in(
            user_id,
            url_key(feed_url, episode_part),
            url_key(feed_url, episode_part, language=args.language),
            args.language,
            PUBLISHER,
            "verbatim",
            keep_days,
        )
        if cached is not None:
            return self._answer(cached, args, cached=True)
        ref = podcasts.pick_transcript(episode.transcripts, args.language)
        if ref is None:
            return error(NO_TRANSCRIPT, NO_TRANSCRIPT_HINT, code="no_transcript", title=episode.title)
        ref_link = classify(urljoin(feed_url, ref.url))
        if not isinstance(ref_link, WebLink):
            return error("The episode's transcript address can't be read.", code="bad_feed", title=episode.title)
        got = await self._fetch(client, ref_link.url, max_bytes=MAX_CAPTION_BYTES, stop=stop, what="the transcript was read")
        if isinstance(got, dict):
            return got
        kind = podcasts.transcript_kind(ref) or sniff(got.data, got.media_type, urlsplit(got.url).path)
        cues, cut = parse_captions_cut(got.data, kind if kind in _CAPTION_KINDS | {"html"} else "text")
        if not cues:
            return error("The episode's transcript could not be read.", code="empty", title=episode.title)
        return await self._store_publisher(
            user_id,
            cues,
            args,
            keep_days=keep_days,
            key=key,
            kind="podcast",
            url=feed_url,
            title=episode.title,
            author=feed.title or feed.author,
            language=ref.language or args.language,
            duration_s=episode.duration_s,
            cut=cut or got.cut,
        )

    # -- YouTube ---------------------------------------------------------------

    async def _youtube(
        self,
        link: YouTubeLink,
        args: _Args,
        user_id: str,
        stop: Callable[[], bool],
        limits: Optional[dict[str, int]],
        keep_days: int,
    ) -> dict[str, Any]:
        video_id, detail = link.video_id, args.detail
        start = args.start if args.start is not None else float(link.start_s or 0)
        per_call_min = (limits or _defaults())["video_minutes_per_call"]
        per_call = max(60.0, per_call_min * 60.0 / (3 if detail == "verbatim" else 1))
        requested_end = args.end if args.end is not None else start + per_call
        end = min(requested_end, start + per_call)
        key, record = await self._cached_in(
            user_id,
            youtube_key(video_id),
            youtube_key(video_id, language=args.language),
            args.language,
            PROVIDER,
            detail,
            keep_days,
        )
        if record is not None and record.duration_s is not None and start >= record.duration_s:
            return error(
                f"The video ends at about {fmt_time(record.duration_s)}.",
                "Ask for an earlier part.",
                code="past_end",
            )
        if record is not None and record.duration_s is not None:
            end = min(end, float(record.duration_s) + 1)
        if end <= start:
            return error("end must come after start (the link's t= time counts as start).", code="bad_window")
        if record is not None and covers(record.covered, start, end):
            return self._answer(record, args, cached=True, window=(start, end), video_id=video_id)
        if record is not None and args.end is None:
            # "Continue from 20:00" inside a saved part: the saved part up
            # to its end, at no cost; next_start then reads on from there.
            held = next((b for a, b in record.covered if a <= start + 1 and b > start + 1), None)
            if held is not None:
                return self._answer(record, args, cached=True, window=(start, held), video_id=video_id)
        turn = turn_context.current()
        if turn is None or turn.read_video_url is None or turn.provider != "gemini":
            extra = {}
            if record is not None and record.covered:
                extra["saved_parts"] = ", ".join(f"{fmt_time(a)}-{fmt_time(b)}" for a, b in record.covered)
            return error(NOT_GEMINI_ERROR, NOT_GEMINI_HINT, code="provider", **extra)
        if limits is None:
            return error("Could not read the owner's video limits, so the video was not read.", code="limits")
        a = _first_uncovered(record, start, end)
        b = end
        try:
            used = await self.store.provider_seconds_today(user_id)
        except Exception as exc:  # noqa: BLE001 - an uncountable day is a spent day
            logger.warning("video_minutes_unreadable", error_type=type(exc).__name__)
            return error("Could not count today's video minutes, so the video was not read.", code="limits")
        per_day = limits["video_minutes_per_day"]
        left = per_day * 60 - used
        if left < 60:
            return error(
                f"Today's {per_day} minutes of provider video are used up.",
                "They reset at 00:00 UTC; the owner can raise \"Minutes per day\" under "
                "\"Summarise videos and podcasts\" in Settings → Permissions.",
                code="daily_cap",
            )
        shortened = b - a > left
        if shortened:
            b = a + left
            end = b
        if stop():
            return _stopped("the video was read")
        try:
            async with self._client() as client:
                meta = await oembed(client, video_id)
        except EgressBlocked as exc:
            return error(str(exc), blocked=True, code="blocked")
        if isinstance(meta, dict):
            return meta
        reading = await self.reader.read(
            turn,
            user_id=user_id,
            video_id=video_id,
            window=(a, b),
            detail=detail,
            find=args.find,
            language=args.language,
            cancelled=stop,
        )
        if isinstance(reading, dict):
            return reading
        record = await self._store_reading(user_id, key, video_id, detail, reading, meta, args, keep_days)
        note = f"Reading {fmt_time(a)}-{fmt_time(b)} cost about ${reading.est_usd:.2f}."
        if shortened:
            note += f" Shortened to the {int(left // 60)} minutes of provider video left today."
        return self._answer(record, args, cached=False, window=(start, end), video_id=video_id, extra_note=note)

    async def _store_reading(
        self,
        user_id: str,
        key: str,
        video_id: str,
        detail: str,
        reading: ProviderReading,
        meta: OEmbed,
        args: _Args,
        keep_days: int,
    ) -> TranscriptRecord:
        segments: list[Segment] = []
        for passage in reading.passages:
            for piece in _split_long(passage.text, 700):
                segments.append((passage.start_s, passage.end_s, piece))
        a, b = reading.window
        duration: Optional[int] = None
        if reading.ended:
            last = max((p.start_s for p in reading.passages if p.start_s is not None), default=a)
            duration = int(math.ceil(last)) + 1
        return await self._save(
            user_id,
            keep_days=keep_days,
            source_key=key,
            kind="youtube",
            method=PROVIDER,
            detail=detail,
            display_url=display_url("", video_id=video_id),
            engine=reading.engine,
            segments=segments,
            title=meta.title or reading.title or None,
            author=meta.author or None,
            language=reading.language or args.language,
            duration_s=duration,
            window=(a, float(duration) if duration is not None and duration < b else b),
            billed_seconds=int(math.ceil(b - a)),
        )

    # -- the answer ------------------------------------------------------------

    def _answer(
        self,
        record: TranscriptRecord,
        args: _Args,
        *,
        cached: bool,
        window: Optional[tuple[float, float]] = None,
        video_id: Optional[str] = None,
        extra_note: str = "",
    ) -> dict[str, Any]:
        """The result: metadata keys first (the audit keeps a prefix), then
        the passages from start (or those matching find, with one neighbour
        each), cut to RESULT_SHOWN_CHARS as shown, with next_start."""
        segments = list(record.segments)
        timed = any(s[0] is not None for s in segments)
        if window is not None:
            lo, hi = window
            scope = [s for s in segments if s[0] is not None and s[0] < hi and (s[1] or s[0]) > lo] if not args.find else [s for s in segments if s[0] is not None]
        elif timed:
            lo = args.start or 0.0
            hi = args.end if args.end is not None else math.inf
            scope = [s for s in segments if s[0] is not None and s[0] < hi and ((s[1] if s[1] is not None else s[0]) > lo or s[0] >= lo)]
            if args.find:
                scope = [s for s in segments if s[0] is not None]
        else:
            first = (args.start_index or 1) - 1
            scope = segments if args.find else segments[first:]
        matched = args.find is not None
        if matched:
            indexes = _find(scope, args.find or "")
            scope = [scope[i] for i in indexes]
        items: list[dict[str, Any]] = [
            {"at": fmt_time(s[0]), "s": None if s[0] is None else int(s[0]), "text": s[2]}
            for s in scope
        ]
        covered = ", ".join(f"{fmt_time(a)}-{fmt_time(b)}" for a, b in record.covered) or None
        base: dict[str, Any] = {
            "ok": True,
            "title": (record.title or "")[:200] or None,
            "by": (record.author or "")[:120] or None,
            "source": record.kind,
            "url": record.display_url,
            "method": record.method,
            "detail": record.detail,
            "engine": record.engine,
            "language": record.language,
            "duration": fmt_time(record.duration_s),
            "link": short_link(video_id) if video_id else None,
            "covered": covered,
            "cached": cached,
            "next_start": None,
            "note": "",
            "passages": [],
        }
        room = RESULT_SHOWN_CHARS - _FIT_MARGIN - shown_length(base)
        included: list[dict[str, Any]] = []
        for item in items:
            size = shown_length(item) + 2
            if size > room:
                break
            included.append(item)
            room -= size
        next_start: Optional[str] = None
        if len(included) < len(items) and not matched:
            nxt = items[len(included)]
            next_start = nxt["at"] if nxt["at"] is not None else f"#{segments.index(scope[len(included)]) + 1}"
        elif video_id and window is not None:
            # The window was shown whole (or searched): the video goes on
            # past it unless it is known to end there.
            ended = record.duration_s is not None and window[1] >= record.duration_s
            if not ended:
                next_start = fmt_time(window[1])
        base["passages"] = included
        base["next_start"] = next_start
        base["note"] = _note(record, cached=cached, matched=matched, found=len(included), next_start=next_start, timed=timed, video_id=video_id, window=window, extra=extra_note)
        while shown_length(base) > RESULT_SHOWN_CHARS and base["passages"]:
            dropped = base["passages"].pop()
            if not matched:
                base["next_start"] = dropped["at"] or base["next_start"]
        return base

    # -- list -------------------------------------------------------------------

    async def _list(self, params: dict[str, Any], user_id: str) -> dict[str, Any]:
        for key in _DROPPED:
            params.pop(key, None)
        unknown = sorted(str(k) for k in params if k != "limit")
        if unknown:
            return error(f"Unknown argument(s) for video.list: {', '.join(unknown)}.")
        raw = params.get("limit", LIST_DEFAULT)
        if raw is None:
            raw = LIST_DEFAULT
        if isinstance(raw, bool) or not isinstance(raw, (int, float)) or raw != raw:
            return error(f"limit must be a whole number from 1 to {LIST_MAX}.")
        limit = max(1, min(int(raw), LIST_MAX))
        try:
            keep_days = (await self._limits()).get("keep_transcripts_days", KEEP_DAYS_DEFAULT)
        except Exception:  # noqa: BLE001 - the default retention still purges
            keep_days = KEEP_DAYS_DEFAULT
        await self._purge(user_id, keep_days)
        try:
            records = await self.store.list(user_id, limit)
        except Exception as exc:  # noqa: BLE001 - reported, not raised
            logger.warning("media_transcripts_list_failed", error_type=type(exc).__name__)
            return error("Could not read the saved transcripts.", code="store")
        rows: list[dict[str, Any]] = []
        room = LIST_ROWS_CHARS
        for record in records:
            row = {
                "id": record.id,
                "title": (record.title or "")[:120] or None,
                "source": record.kind,
                "host": host_of(record.display_url),
                "url": record.display_url,
                "method": record.method,
                "detail": record.detail,
                # One saved transcript per asked language: tells them apart.
                "language": record.language,
                "covered": ", ".join(f"{fmt_time(a)}-{fmt_time(b)}" for a, b in record.covered) or None,
                "duration": fmt_time(record.duration_s),
                "saved": record.created_at.date().isoformat(),
                "expires": record.expires_at.date().isoformat(),
            }
            size = shown_length(row) + 2
            if size > room:
                break
            rows.append(row)
            room -= size
        return {
            "ok": True,
            "count": len(rows),
            "transcripts": rows,
            "note": "Metadata only. Call video.transcript with a url to read one again; a saved "
            "transcript costs nothing to reread.",
        }


def _first_uncovered(record: Optional[TranscriptRecord], start: float, end: float) -> float:
    """Where reading [start, end] must begin: past the saved window that
    already holds *start*, if one does."""
    if record is None:
        return start
    for a, b in record.covered:
        if a <= start + 1 and b > start and b < end:
            return b
    return start


def _find(segments: list[Segment], find: str) -> list[int]:
    """Indexes of the passages that mention *find*'s words (the whole phrase
    ranks first), best first, each with one neighbour on either side, at
    most FIND_MAX_PASSAGES in all, in order."""
    phrase = " ".join(find.lower().split())
    terms = {w for w in _WORDS.findall(phrase) if len(w) > 1 or w.isdigit()}
    if not terms:
        return []
    scored: list[tuple[int, int]] = []
    for index, segment in enumerate(segments):
        text = " ".join(segment[2].lower().split())
        words = set(_WORDS.findall(text))
        score = (10 if phrase in text else 0) + len(terms & words)
        if score:
            scored.append((-score, index))
    chosen: set[int] = set()
    for _score, index in sorted(scored):
        group = [i for i in (index - 1, index, index + 1) if 0 <= i < len(segments) and i not in chosen]
        if len(chosen) + len(group) > FIND_MAX_PASSAGES:
            if index not in chosen and len(chosen) < FIND_MAX_PASSAGES:
                chosen.add(index)
            continue
        chosen.update(group)
    return sorted(chosen)


def at_store_cap(record: TranscriptRecord) -> bool:
    """Whether *record* holds as much text as one saved transcript may. The
    store keeps whole passages (at most PASSAGE_MAX_CHARS each) up to
    MAX_ROW_CHARS, so a transcript it cut always ends this close to it."""
    return record.chars > MAX_ROW_CHARS - PASSAGE_MAX_CHARS


def _kept_only(record: TranscriptRecord) -> str:
    """The note for a transcript only partly kept: where the kept part ends,
    so the model does not take it for the whole."""
    ends = [b for _a, b in record.covered]
    if ends:
        kept = f"the first {fmt_time(max(ends))} of this transcript was kept"
    else:
        kept = f"the first {len(record.segments)} passages of this transcript were kept"
    return (
        f"Only {kept}; the rest was too long for Crawler to read, "
        "so say so if the user asks about later parts."
    )


def _note(
    record: TranscriptRecord,
    *,
    cached: bool,
    matched: bool,
    found: int,
    next_start: Optional[str],
    timed: bool,
    video_id: Optional[str],
    window: Optional[tuple[float, float]],
    extra: str,
) -> str:
    parts: list[str] = []
    if record.method == PROVIDER:
        what = "A word-for-word transcript" if record.detail == "verbatim" else "Notes"
        parts.append(f"{what} written by {record.engine} from the video; times are approximate.")
    else:
        parts.append("The publisher's own captions or transcript.")
    if not timed:
        parts.append("This transcript has no timestamps.")
    if cached and record.method == PUBLISHER and at_store_cap(record):
        parts.append(_kept_only(record))
    if matched:
        scope = (
            f"the saved part ({', '.join(f'{fmt_time(a)}-{fmt_time(b)}' for a, b in record.covered)})"
            if video_id
            else "the whole transcript"
        )
        parts.append(
            f"Only passages that mention the find words, with a neighbour each, from {scope}."
            if found
            else f"No passage in {scope} mentions those words."
        )
    if cached:
        parts.append("From the saved transcript (no new cost).")
    if extra:
        parts.append(extra)
    if next_start:
        parts.append(f"Continue with start={next_start}.")
    if video_id:
        parts.append("Cite a moment as link plus its s value.")
    return " ".join(parts)[:500]


__all__ = [
    "ACTIONS",
    "NO_TRANSCRIPT",
    "RESULT_SHOWN_CHARS",
    "VideoSettings",
    "VideoToolkit",
]
