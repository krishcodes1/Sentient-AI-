"""Reads podcast feeds for video.transcript: the episodes of an RSS or Atom
feed (up to 8 MB, through defusedxml), which episode the user means (by guid,
by title words, by the page it came from, or the newest), which of its
``<podcast:transcript>`` tags to read, and an Apple Podcasts link's feed
through the public iTunes lookup API.

Why it exists: podcast publishers increasingly ship transcripts as
``<podcast:transcript>`` files, which is what Crawler reads instead of
transcribing audio. A feed is hostile XML: DTDs (and with them entity
expansion such as billion laughs) and external references are refused
outright, and a feed cut at the byte cap still yields the items before the
cut. Nothing here fetches; the toolkit hands in the bytes and a guarded
client.
"""

from __future__ import annotations

import io
import json
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from typing import Any, Optional, Union

from services.tools.video.captions import clean_text, parse_clock

MAX_FEED_BYTES = 8 * 1024 * 1024
MAX_EPISODES = 2000
MAX_CANDIDATES = 8
ITUNES_LOOKUP_URL = "https://itunes.apple.com/lookup"
MAX_LOOKUP_BYTES = 2 * 1024 * 1024

_WORD = re.compile(r"[0-9a-z]+")


class FeedRefused(Exception):
    """A feed that cannot be read safely or at all; the message is
    Crawler's own, safe to show."""


@dataclass(frozen=True)
class TranscriptRef:
    url: str
    media_type: str
    language: str
    rel: str


@dataclass(frozen=True)
class Episode:
    guid: str
    title: str
    published: Optional[datetime]
    link: str
    transcripts: tuple[TranscriptRef, ...]
    enclosure_url: str
    enclosure_type: str
    duration_s: Optional[int]

    @property
    def date(self) -> Optional[str]:
        return self.published.date().isoformat() if self.published else None


@dataclass(frozen=True)
class Feed:
    title: str
    author: str
    episodes: tuple[Episode, ...]
    truncated: bool


@dataclass(frozen=True)
class Chosen:
    episode: Episode


@dataclass(frozen=True)
class Ambiguous:
    """Several episodes fit (or none did): the model asks the user."""

    candidates: tuple[Episode, ...]
    reason: str


Choice = Union[Chosen, Ambiguous]


def _local(tag: Any) -> str:
    return tag.rsplit("}", 1)[-1].lower() if isinstance(tag, str) else ""


def _namespace(tag: Any) -> str:
    return tag[1:].split("}", 1)[0].lower() if isinstance(tag, str) and tag.startswith("{") else ""


def _date(text: str) -> Optional[datetime]:
    value = (text or "").strip()
    if not value:
        return None
    try:
        parsed = parsedate_to_datetime(value)
    except (TypeError, ValueError, IndexError):
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def _duration(text: str) -> Optional[int]:
    seconds = parse_clock((text or "").strip())
    return int(seconds) if seconds is not None else None


def _child_text(element: Any, *names: str) -> str:
    for child in element:
        if _local(child.tag) in names and (child.text or "").strip():
            return (child.text or "").strip()
    return ""


def _episode(element: Any) -> Episode:
    title = clean_text(_child_text(element, "title"))[:300]
    guid = _child_text(element, "guid", "id")[:300]
    published = _date(_child_text(element, "pubdate", "published", "updated", "date"))
    link = ""
    enclosure_url, enclosure_type = "", ""
    duration: Optional[int] = None
    transcripts: list[TranscriptRef] = []
    for child in element:
        local = _local(child.tag)
        attrs = child.attrib
        if local == "link":
            rel = (attrs.get("rel") or "alternate").lower()
            href = attrs.get("href")
            if href and rel == "alternate" and not link:
                link = href.strip()
            elif href and rel == "enclosure" and not enclosure_url:
                enclosure_url, enclosure_type = href.strip(), (attrs.get("type") or "").lower()
            elif not href and (child.text or "").strip() and not link:
                link = (child.text or "").strip()
        elif local == "enclosure" and attrs.get("url") and not enclosure_url:
            enclosure_url, enclosure_type = attrs["url"].strip(), (attrs.get("type") or "").lower()
        elif local == "duration" and duration is None:
            duration = _duration(child.text or "")
        elif local == "transcript" and "podcast" in _namespace(child.tag) and attrs.get("url"):
            transcripts.append(
                TranscriptRef(
                    url=attrs["url"].strip(),
                    media_type=(attrs.get("type") or "").strip().lower(),
                    language=(attrs.get("language") or "").strip().lower()[:16],
                    rel=(attrs.get("rel") or "").strip().lower(),
                )
            )
    return Episode(
        guid=guid,
        title=title,
        published=published,
        link=link[:500],
        transcripts=tuple(transcripts[:20]),
        enclosure_url=enclosure_url[:500],
        enclosure_type=enclosure_type[:100],
        duration_s=duration,
    )


def parse_feed(data: bytes) -> Feed:
    """The feed's title, author and episodes (newest first when they are
    dated). Raises FeedRefused for a DTD, an entity or an external
    reference (billion laughs and friends are never expanded) or when no
    feed can be read; a feed cut short still yields the episodes before the
    cut (``truncated``)."""
    from defusedxml import ElementTree as SafeET
    from defusedxml.common import DefusedXmlException

    title, author = "", ""
    episodes: list[Episode] = []
    stack: list[str] = []
    truncated = False
    root_seen = False
    try:
        events = SafeET.iterparse(
            io.BytesIO(data[:MAX_FEED_BYTES]),
            events=("start", "end"),
            forbid_dtd=True,
            forbid_entities=True,
            forbid_external=True,
        )
        for event, element in events:
            local = _local(element.tag)
            if event == "start":
                if not root_seen:
                    root_seen = True
                    if local not in ("rss", "feed", "rdf"):
                        raise FeedRefused("That link is not a podcast feed.")
                stack.append(local)
                continue
            stack.pop()
            parent = stack[-1] if stack else ""
            if local in ("item", "entry"):
                if len(episodes) < MAX_EPISODES:
                    episodes.append(_episode(element))
                element.clear()
            elif local == "title" and parent in ("channel", "feed") and not title:
                title = clean_text(element.text or "")[:200]
            elif local in ("author", "name") and parent in ("channel", "feed", "author") and not author:
                author = clean_text(element.text or "")[:120]
    except FeedRefused:
        raise
    except DefusedXmlException:
        raise FeedRefused(
            "This feed could not be read safely (it declares a DTD, entities or external references)."
        ) from None
    except Exception:  # noqa: BLE001 - malformed or cut short: keep what was read
        if not episodes:
            raise FeedRefused("That feed could not be read (it is not well-formed XML).") from None
        truncated = True
    if len(data) > MAX_FEED_BYTES:
        truncated = True
    if not root_seen:
        raise FeedRefused("That link is not a podcast feed.")
    dated = [e for e in episodes if e.published is not None]
    if len(dated) == len(episodes) and episodes:
        episodes.sort(key=lambda e: e.published or datetime.min.replace(tzinfo=timezone.utc), reverse=True)
    return Feed(title=title, author=author, episodes=tuple(episodes), truncated=truncated)


def _words(text: str) -> set[str]:
    return {w for w in _WORD.findall((text or "").lower()) if len(w) > 1 or w.isdigit()}


def _same_page(a: str, b: str) -> bool:
    def norm(url: str) -> str:
        return re.sub(r"^https?://(www\.)?", "", (url or "").strip().lower()).rstrip("/")

    return bool(a) and bool(b) and norm(a) == norm(b)


def choose_episode(
    feed: Feed,
    episode: Optional[str] = None,
    *,
    page_url: Optional[str] = None,
    guid: Optional[str] = None,
    title_hint: Optional[str] = None,
) -> Choice:
    """The episode meant: the one whose guid is *guid* or *episode*, the one
    whose page is *page_url*, the one whose title holds every word of
    *episode* (or of *title_hint*, an Apple listing's title), else the
    newest. Several title matches, or none, are Ambiguous with up to 8
    candidates."""
    episodes = list(feed.episodes)
    if not episodes:
        return Ambiguous((), "The feed lists no episodes.")
    for wanted in (guid, episode):
        if wanted:
            exact = [e for e in episodes if e.guid and e.guid == wanted.strip()]
            if len(exact) == 1:
                return Chosen(exact[0])
    if page_url and not episode:
        same = [e for e in episodes if _same_page(e.link, page_url)]
        if len(same) == 1:
            return Chosen(same[0])
    query = episode or title_hint
    if not query:
        return Chosen(episodes[0])
    wanted_words = _words(query)
    if not wanted_words:
        return Chosen(episodes[0])
    scored = [(len(wanted_words & _words(e.title)), e) for e in episodes]
    full = [e for score, e in scored if score == len(wanted_words)]
    if len(full) == 1:
        return Chosen(full[0])
    if len(full) > 1:
        return Ambiguous(tuple(full[:MAX_CANDIDATES]), "Several episodes match.")
    best = max(score for score, _ in scored)
    if best == 0:
        return Ambiguous(tuple(episodes[:MAX_CANDIDATES]), "No episode title matches; these are the newest.")
    top = [e for score, e in scored if score == best]
    if len(top) == 1 and best * 2 >= len(wanted_words):
        return Chosen(top[0])
    return Ambiguous(tuple(top[:MAX_CANDIDATES]), "No episode matches every word.")


def transcript_kind(ref: TranscriptRef) -> str:
    """vtt, srt, json, html, text or '' (a type Crawler does not read)."""
    mime = ref.media_type.split(";", 1)[0].strip()
    path = ref.url.lower().split("?", 1)[0]
    if mime == "text/vtt" or path.endswith(".vtt"):
        return "vtt"
    if mime in ("application/x-subrip", "application/srt", "text/srt") or path.endswith(".srt"):
        return "srt"
    if mime == "application/json" or path.endswith(".json"):
        return "json"
    if mime in ("text/html", "application/xhtml+xml") or path.endswith((".html", ".htm")):
        return "html"
    if mime == "text/plain" or path.endswith(".txt"):
        return "text"
    return ""


def _rank(ref: TranscriptRef) -> int:
    kind = transcript_kind(ref)
    if kind in ("vtt", "srt") and ref.rel == "captions":
        return 0
    return {"json": 1, "vtt": 2, "srt": 2, "html": 3, "text": 4}.get(kind, 9)


def _language_matches(ref: TranscriptRef, language: str) -> bool:
    return bool(ref.language) and ref.language.split("-")[0] == language.lower().split("-")[0]


def pick_transcript(refs: tuple[TranscriptRef, ...], language: Optional[str] = None) -> Optional[TranscriptRef]:
    """The transcript to read: captions VTT/SRT, then JSON, then VTT/SRT,
    then HTML, then plain text; one in the asked *language* first."""
    usable = [r for r in refs if _rank(r) < 9]
    if not usable:
        return None
    if language:
        return min(usable, key=lambda r: (0 if _language_matches(r, language) else 1, _rank(r)))
    return min(usable, key=_rank)


@dataclass(frozen=True)
class AppleShow:
    feed_url: str
    title: str
    episode_guid: Optional[str]
    episode_title: Optional[str]


def apple_lookup_url(podcast_id: str, *, episodes: bool) -> str:
    entity = "podcastEpisode&limit=200" if episodes else "podcast"
    return f"{ITUNES_LOOKUP_URL}?id={podcast_id}&entity={entity}"


def read_apple_lookup(show: bytes, episodes: Optional[bytes], episode_id: Optional[str]) -> AppleShow:
    """The feed URL of an Apple Podcasts show (and, given the episode
    listing, the guid and title of *episode_id*) from the iTunes lookup
    answers. Raises FeedRefused when the show has no public feed."""
    try:
        doc = json.loads(show.decode("utf-8", errors="replace"))
    except ValueError:
        raise FeedRefused("Apple Podcasts did not answer the lookup.") from None
    results = doc.get("results") if isinstance(doc, dict) else None
    feed_url, title = "", ""
    for row in results if isinstance(results, list) else []:
        if isinstance(row, dict) and isinstance(row.get("feedUrl"), str):
            feed_url = row["feedUrl"].strip()
            title = clean_text(str(row.get("collectionName") or ""))[:200]
            break
    if not feed_url.lower().startswith(("http://", "https://")):
        raise FeedRefused("That show has no public feed Crawler can read.")
    guid = episode_title = None
    if episodes and episode_id:
        try:
            listing = json.loads(episodes.decode("utf-8", errors="replace"))
        except ValueError:
            listing = {}
        for row in listing.get("results", []) if isinstance(listing, dict) else []:
            if isinstance(row, dict) and str(row.get("trackId")) == episode_id:
                guid = str(row.get("episodeGuid") or "")[:300] or None
                episode_title = clean_text(str(row.get("trackName") or ""))[:300] or None
                break
    return AppleShow(feed_url=feed_url[:500], title=title, episode_guid=guid, episode_title=episode_title)
