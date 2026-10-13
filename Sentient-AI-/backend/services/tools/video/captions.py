"""Parses caption and transcript files into timed cues, and cues into the
passages video.transcript returns: WebVTT, SRT, SBV, TTML/DFXP, Podcast-Index
JSON, HTML and plain text.

Why it exists: publisher captions are the cheapest and most faithful source
of what a video or episode says, and every format is hostile input. The line
parsers are hand-written with byte and cue caps (4 MB, 20000 cues); TTML goes
through defusedxml (no DTDs, entities or external references); malformed
input yields fewer cues, never an exception. YouTube-style rolling captions
(each cue repeating the last line) are collapsed, tags, entities and control
or invisible characters are removed, and cues are grouped into passages of at
most 700 characters and 90 seconds, a list the runtime can redact one entry
of without losing the rest.
"""

from __future__ import annotations

import html
import json
import re
from dataclasses import dataclass
from typing import Any, Iterable, Optional

from services.agent.prompt_guard import _INVISIBLE_CHARS

MAX_CAPTION_BYTES = 4 * 1024 * 1024
MAX_CUES = 20000
# Plain text is read as timed only when its times run forward: at most this
# many steps back (a contents list at the top, a part that starts again at
# 0:00) and at most this share of all steps. A book's chapter:verse numbers
# ("37:12 And his brethren ...") start again in every book.
MAX_TIME_RESETS = 3
MAX_TIME_RESET_SHARE = 0.2
PASSAGE_MAX_CHARS = 700
PASSAGE_MAX_SECONDS = 90.0

_CONTROL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f]")
_TAG = re.compile(r"<[^>]{0,200}>")
_VOICE = re.compile(r"<v(?:\.[\w.-]+)?\s+([^>]{1,60})>")
_ASS_TAG = re.compile(r"\{\\[^}]{0,80}\}")
_SPACES = re.compile(r"[ \t ]+")
_CLOCK = re.compile(r"^(?:(\d{1,3}):)?(\d{1,2}):(\d{1,2})(?:[.,](\d{1,3}))?$")
_SBV_TIMING = re.compile(r"^\s*(\d{1,3}:\d{1,2}:\d{1,2}[.,]\d{1,3})\s*,\s*(\d{1,3}:\d{1,2}:\d{1,2}[.,]\d{1,3})\s*$")
_SRT_TIMING = re.compile(r"^\s*\d{1,3}:\d{2}:\d{2}[,.]\d{1,3}\s*-->", re.MULTILINE)
_LINE_TIME = re.compile(
    r"^\s*[\[(]?((?:\d{1,2}:)?\d{1,2}:\d{2})(?:[.,]\d{1,3})?[\])]?\s*(?:[-–—|:]\s*)?(.*)$"
)
_SPEAKER_TIME = re.compile(
    r"^\s*([^\[\](){}\d:][^\[\](){}:]{0,40}?)\s*[\[(]((?:\d{1,2}:)?\d{1,2}:\d{2})[\])]\s*:?\s*(.*)$"
)
_TTML_OFFSET = re.compile(r"^(\d+(?:\.\d+)?)(h|ms|m|s|f|t)$")
_TTML_CLOCK = re.compile(r"^(\d{1,3}):(\d{2}):(\d{2})(?:([.:])(\d{1,3}))?$")


@dataclass(frozen=True)
class Cue:
    """One caption: its start and end in seconds (None for an untimed
    transcript) and its cleaned text."""

    start_s: Optional[float]
    end_s: Optional[float]
    text: str


@dataclass(frozen=True)
class Passage:
    start_s: Optional[float]
    end_s: Optional[float]
    text: str


def clean_text(text: str) -> str:
    """*text* with control and invisible characters removed and runs of
    spaces collapsed (line breaks become spaces)."""
    text = re.sub(r"[\r\n\t\f\v]", " ", text or "")
    text = _INVISIBLE_CHARS.sub("", _CONTROL.sub("", text))
    return _SPACES.sub(" ", text).strip()


def _clean_line(line: str) -> str:
    line = _VOICE.sub(lambda m: m.group(1).strip() + ": ", line)
    line = _ASS_TAG.sub("", _TAG.sub("", line))
    return clean_text(html.unescape(line))


def fmt_time(seconds: Optional[float]) -> Optional[str]:
    """``M:SS``, or ``H:MM:SS`` from an hour on; None for None."""
    if seconds is None:
        return None
    total = max(0, int(seconds))
    hours, rest = divmod(total, 3600)
    minutes, secs = divmod(rest, 60)
    return f"{hours}:{minutes:02d}:{secs:02d}" if hours else f"{minutes}:{secs:02d}"


def parse_clock(text: object) -> Optional[float]:
    """Seconds from ``M:SS``, ``H:MM:SS`` (optionally with fractions), plain
    seconds (``754``) or ``1h2m3s``; None when it is none of these."""
    if isinstance(text, bool):
        return None
    if isinstance(text, (int, float)):
        return float(text) if text >= 0 else None
    if not isinstance(text, str):
        return None
    value = text.strip().lower()
    if not value:
        return None
    match = _CLOCK.fullmatch(value)
    if match:
        hours, minutes, seconds, frac = match.groups()
        if int(seconds) >= 60 or (hours is not None and int(minutes) >= 60):
            return None
        total = int(hours or 0) * 3600 + int(minutes) * 60 + int(seconds)
        return total + (int(frac.ljust(3, "0")) / 1000.0 if frac else 0.0)
    if re.fullmatch(r"\d{1,6}(?:\.\d+)?s?", value):
        return float(value.rstrip("s"))
    from services.tools.video.sources import parse_offset

    offset = parse_offset(value)
    return float(offset) if offset is not None else None


def decode(data: bytes) -> str:
    """Bytes as text: UTF-8 (a BOM dropped), else Latin-1; newlines
    normalised."""
    text = data.decode("utf-8-sig", errors="replace")
    return text.replace("\r\n", "\n").replace("\r", "\n")


# -- the line formats ---------------------------------------------------------


def _arrow_time(value: str) -> Optional[float]:
    token = value.strip().split()[0] if value.strip() else ""
    return parse_clock(token)


def parse_arrow_blocks(text: str) -> list[Cue]:
    """WebVTT and SRT: blocks separated by blank lines, each with a
    ``start --> end`` line; a header, NOTE, STYLE and REGION blocks, cue
    settings and a cue's id or index are skipped."""
    cues: list[Cue] = []
    for block in re.split(r"\n\s*\n", text):
        if len(cues) >= MAX_CUES:
            break
        lines = block.strip("\n").split("\n")
        if not lines or not lines[0].strip():
            continue
        head = lines[0].strip()
        if head.startswith(("WEBVTT", "NOTE", "STYLE", "REGION")) and "-->" not in head:
            continue
        timing = next((i for i, line in enumerate(lines[:3]) if "-->" in line), None)
        if timing is None:
            continue
        left, _, right = lines[timing].partition("-->")
        start, end = _arrow_time(left), _arrow_time(right)
        if start is None:
            continue
        body = [_clean_line(line) for line in lines[timing + 1 :]]
        body = [line for line in body if line]
        if body:
            cues.append(Cue(start, end if end is not None and end >= start else start, "\n".join(body)))
    return cues


def parse_sbv(text: str) -> list[Cue]:
    """SubViewer (YouTube's .sbv): ``0:00:00.599,0:00:04.160`` then text."""
    cues: list[Cue] = []
    for block in re.split(r"\n\s*\n", text):
        if len(cues) >= MAX_CUES:
            break
        lines = block.strip("\n").split("\n")
        match = _SBV_TIMING.match(lines[0]) if lines else None
        if match is None:
            continue
        start, end = parse_clock(match.group(1)), parse_clock(match.group(2))
        if start is None:
            continue
        body = [line for line in (_clean_line(x) for x in lines[1:]) if line]
        if body:
            cues.append(Cue(start, end if end is not None and end >= start else start, "\n".join(body)))
    return cues


def _ttml_time(value: Optional[str], tick_rate: float, frame_rate: float) -> Optional[float]:
    if not value:
        return None
    text = value.strip()
    match = _TTML_CLOCK.fullmatch(text)
    if match:
        hours, minutes, seconds, sep, frac = match.groups()
        total = float(int(hours) * 3600 + int(minutes) * 60 + int(seconds))
        if frac:
            total += int(frac) / frame_rate if sep == ":" else int(frac.ljust(3, "0")) / 1000.0
        return float(total)
    match = _TTML_OFFSET.fullmatch(text)
    if match:
        number, unit = float(match.group(1)), match.group(2)
        scale = {"h": 3600.0, "m": 60.0, "s": 1.0, "ms": 0.001, "f": 1.0 / frame_rate, "t": 1.0 / tick_rate}
        return number * scale[unit]
    return None


def _local(tag: Any) -> str:
    return tag.rsplit("}", 1)[-1] if isinstance(tag, str) else ""


def parse_ttml(data: bytes) -> list[Cue]:
    """TTML / DFXP through defusedxml (a DTD, an entity or an external
    reference is refused: no cues). Each ``<p>`` is one cue; begin and end
    in clock (``00:01:02.500``, ``00:01:02:12``) or offset (``62.5s``,
    ``1500ms``, ``100t``) form."""
    from defusedxml import ElementTree as SafeET

    try:
        root = SafeET.fromstring(data, forbid_dtd=True, forbid_entities=True, forbid_external=True)
    except Exception:  # noqa: BLE001 - DTD, entity, external reference or malformed: no cues
        return []
    tick_rate, frame_rate = 1.0, 30.0
    for name, value in root.attrib.items():
        local = _local(name)
        try:
            if local == "tickRate":
                tick_rate = max(1.0, float(value))
            elif local == "frameRate":
                frame_rate = max(1.0, float(value))
        except ValueError:
            continue
    cues: list[Cue] = []
    for element in root.iter():
        if len(cues) >= MAX_CUES:
            break
        if _local(element.tag) != "p":
            continue
        start = _ttml_time(element.attrib.get("begin"), tick_rate, frame_rate)
        if start is None:
            continue
        end = _ttml_time(element.attrib.get("end"), tick_rate, frame_rate)
        duration = _ttml_time(element.attrib.get("dur"), tick_rate, frame_rate)
        if end is None and duration is not None:
            end = start + duration
        text = _clean_line(" ".join(part for part in element.itertext()))
        if text:
            cues.append(Cue(start, end if end is not None and end >= start else start, text))
    return cues


def parse_podcast_json(data: bytes) -> list[Cue]:
    """Podcast-Index JSON (``{"segments": [{"startTime", "endTime", "body",
    "speaker"}]}``); a speaker is named when it changes."""
    try:
        doc = json.loads(decode(data))
    except (ValueError, RecursionError):
        return []
    segments = doc.get("segments") if isinstance(doc, dict) else doc
    if not isinstance(segments, list):
        return []
    cues: list[Cue] = []
    speaker = None
    for item in segments[: MAX_CUES * 2]:
        if len(cues) >= MAX_CUES:
            break
        if not isinstance(item, dict):
            continue
        start = parse_clock(item.get("startTime"))
        end = parse_clock(item.get("endTime"))
        body = item.get("body")
        if start is None or not isinstance(body, str):
            continue
        text = _clean_line(body)
        who = item.get("speaker")
        if isinstance(who, str) and clean_text(who) and clean_text(who) != speaker:
            speaker = clean_text(who)[:60]
            text = f"{speaker}: {text}"
        if text:
            cues.append(Cue(start, end if end is not None and end >= start else start, text))
    return cues


def parse_timed_text(text: str) -> list[Cue]:
    """Plain or extracted-HTML transcript text: a line that starts with a
    time (``00:01:23 Alice: …``, ``[1:23] …``) or names a speaker before
    one (``Alice (01:23): …``) starts a cue, and the lines after it are its
    text. With fewer than two times, or times that do not run forward (see
    ``times_run_forward``: numbers such as a book's chapter:verse are not
    times), the text is untimed: one cue per paragraph, with no times."""
    lines = text.split("\n")
    cues: list[Cue] = []
    current_start: Optional[float] = None
    current: list[str] = []
    timed = 0

    def flush() -> None:
        body = clean_text(" ".join(current))
        if body and current_start is not None:
            cues.append(Cue(current_start, current_start, body))

    for line in lines:
        if len(cues) >= MAX_CUES:
            break
        match = _SPEAKER_TIME.match(line)
        if match:
            start = parse_clock(match.group(2))
            rest = f"{clean_text(match.group(1))}: {match.group(3)}"
        else:
            match = _LINE_TIME.match(line)
            start = parse_clock(match.group(1)) if match else None
            rest = match.group(2) if match else ""
        if start is not None:
            flush()
            timed += 1
            current_start, current = start, [rest]
        elif current_start is not None:
            current.append(line)
    flush()
    if timed >= 2 and times_run_forward([cue.start_s for cue in cues if cue.start_s is not None]):
        # Each cue ends where the next starts.
        return [
            Cue(cue.start_s, cues[i + 1].start_s if i + 1 < len(cues) else cue.start_s, cue.text)
            for i, cue in enumerate(cues)
        ]
    paragraphs = [clean_text(p) for p in re.split(r"\n\s*\n", text)]
    return [Cue(None, None, p) for p in paragraphs if p][:MAX_CUES]


def times_run_forward(starts: list[float]) -> bool:
    """Whether *starts*, in the order the text gives them, read as a
    transcript's times: few steps back (MAX_TIME_RESETS, and at most
    MAX_TIME_RESET_SHARE of the steps). Cues are later sorted by time, so
    text whose numbers only look like times would come back shuffled."""
    steps = len(starts) - 1
    if steps < 1:
        return True
    back = sum(1 for i in range(steps) if starts[i + 1] < starts[i])
    return back <= MAX_TIME_RESETS and back <= steps * MAX_TIME_RESET_SHARE


def parse_html_transcript(data: bytes) -> tuple[str, list[Cue]]:
    """An HTML transcript's (title, cues), read as its readable text."""
    from services.tools.html_text import extract_readable_text

    title, text = extract_readable_text(decode(data))
    return clean_text(title), parse_timed_text(text)


# -- choosing the parser -----------------------------------------------------


def sniff(data: bytes, media_type: str, path: str) -> str:
    """Which parser *data* needs: vtt, srt, sbv, ttml, json, feed, html,
    text or unknown, from its content (first), its declared type and its
    name."""
    mime = (media_type or "").split(";", 1)[0].strip().lower()
    suffix = (path or "").lower().rsplit("/", 1)[-1]
    head = decode(data[:4096]).lstrip()
    lowered = head[:2048].lower()
    if head.startswith("WEBVTT") or mime == "text/vtt" or suffix.endswith(".vtt"):
        return "vtt"
    if suffix.endswith(".sbv") or _SBV_TIMING.match(head.split("\n", 1)[0] if head else ""):
        return "sbv"
    if mime in ("application/x-subrip", "application/srt", "text/srt") or suffix.endswith(".srt"):
        return "srt"
    if lowered.startswith("<?xml") or lowered.startswith("<"):
        if "<rss" in lowered or "<feed" in lowered or "<channel" in lowered:
            return "feed"
        if "<tt" in lowered and ("ttml" in lowered or "<body" in lowered or "<tt " in lowered or "<tt>" in lowered):
            return "ttml"
        if "<html" in lowered or "<!doctype html" in lowered or "<head" in lowered or "<body" in lowered:
            return "html"
    if mime in ("application/ttml+xml", "application/ttaf+xml") or suffix.endswith((".ttml", ".dfxp")):
        return "ttml"
    if mime in ("application/rss+xml", "application/atom+xml"):
        return "feed"
    if mime == "application/json" or suffix.endswith(".json") or head.startswith(("{", "[")):
        return "json"
    if _SRT_TIMING.search(head):
        return "srt"
    if mime in ("text/html", "application/xhtml+xml"):
        return "html"
    if mime.startswith("text/") or not mime:
        return "text"
    return "unknown"


def parse_captions(data: bytes, kind: str) -> list[Cue]:
    """Cues from *data* (at most MAX_CAPTION_BYTES of it) in format *kind*
    (see ``sniff``); rolling duplicates collapsed. Never raises."""
    return parse_captions_cut(data, kind)[0]


def parse_captions_cut(data: bytes, kind: str) -> tuple[list[Cue], bool]:
    """``parse_captions``, and whether part of *data* was left unread: over
    MAX_CAPTION_BYTES, or MAX_CUES cues reached."""
    cut = len(data) > MAX_CAPTION_BYTES
    data = data[:MAX_CAPTION_BYTES]
    try:
        if kind in ("vtt", "srt"):
            cues = parse_arrow_blocks(decode(data))
        elif kind == "sbv":
            cues = parse_sbv(decode(data))
        elif kind == "ttml":
            cues = parse_ttml(data)
        elif kind == "json":
            cues = parse_podcast_json(data)
        elif kind == "html":
            cues = parse_html_transcript(data)[1]
        elif kind == "text":
            cues = parse_timed_text(decode(data))
        else:
            cues = []
    except (ValueError, RecursionError, MemoryError):
        cues = []
    return collapse_rolling(cues[:MAX_CUES]), cut or len(cues) >= MAX_CUES


def collapse_rolling(cues: Iterable[Cue]) -> list[Cue]:
    """Drop what a cue repeats of the ones just before it: YouTube-style
    rolling captions show each line twice (once new, once as the line
    above the next) and grow a line word by word. A cue left with nothing
    new is merged into the previous one."""
    out: list[Cue] = []
    recent: list[str] = []
    for cue in sorted(cues, key=lambda c: (c.start_s is None, c.start_s or 0.0)):
        fresh: list[str] = []
        for line in (x.strip() for x in cue.text.split("\n")):
            if not line or line in recent:
                continue
            last = recent[-1] if recent else ""
            if last and line.startswith(last) and len(line) > len(last):
                suffix = line[len(last):].strip()
                recent[-1] = line
                if suffix:
                    fresh.append(suffix)
                continue
            fresh.append(line)
            recent.append(line)
            del recent[:-3]
        if fresh:
            out.append(Cue(cue.start_s, cue.end_s, clean_text(" ".join(fresh))))
        elif out and cue.end_s is not None and out[-1].start_s is not None:
            prev = out[-1]
            out[-1] = Cue(prev.start_s, max(prev.end_s or 0.0, cue.end_s), prev.text)
    return out


def _split_long(text: str, limit: int) -> list[str]:
    """*text* in pieces of at most *limit* characters, split at spaces."""
    pieces: list[str] = []
    while len(text) > limit:
        cut = text.rfind(" ", 0, limit + 1)
        if cut <= limit // 2:
            cut = limit
        pieces.append(text[:cut].strip())
        text = text[cut:].strip()
    if text:
        pieces.append(text)
    return pieces


def build_passages(
    cues: Iterable[Cue],
    *,
    max_chars: int = PASSAGE_MAX_CHARS,
    max_seconds: float = PASSAGE_MAX_SECONDS,
) -> list[Passage]:
    """Group *cues* into passages of at most *max_chars* characters that
    span at most *max_seconds* (a cue longer than either stands alone, split
    at spaces when it is too long). Untimed cues are grouped by size only."""
    passages: list[Passage] = []
    texts: list[str] = []
    size = 0
    start: Optional[float] = None
    end: Optional[float] = None

    def flush() -> None:
        nonlocal texts, size, start, end
        if texts:
            passages.append(Passage(start, end, " ".join(texts)))
        texts, size, start, end = [], 0, None, None

    for cue in cues:
        for piece in _split_long(cue.text, max_chars):
            too_long = texts and size + 1 + len(piece) > max_chars
            cue_end = cue.end_s if cue.end_s is not None else cue.start_s
            too_wide = (
                texts
                and start is not None
                and cue_end is not None
                and cue_end - start > max_seconds
            )
            if too_long or too_wide:
                flush()
            if not texts:
                start = cue.start_s
            texts.append(piece)
            size += len(piece) + (1 if size else 0)
            end = cue_end if cue_end is not None else end
    flush()
    return passages
