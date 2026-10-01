"""The Section and Extraction types every document reader returns, and the
normalisation and splitting that turn a parser's raw text into them.

Why it exists: the model reads documents as a list of labelled sections
("Page 3", "Slide 4: Title", "Sheet 'Grades' rows 1-120", "Part 2") of at
most 4000 characters, so one poisoned page can be redacted on its own and a
long document can be paged through with files.read. The parser worker sends
raw units; this module (in the parent process) cleans them: Unicode NFC,
invisible and bidi characters stripped and counted, control characters
dropped, blank lines collapsed, and anything longer than the maximum split
near a 3000-character target at a paragraph, line or sentence break.

Stdlib only.
"""

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass, field
from typing import Iterable, Optional

from services.files.limits import MAX_DOCUMENT_CHARS, SECTION_MAX_CHARS, SECTION_TARGET_CHARS

# The refusal codes a caller may see (ExtractionRefused.code).
REFUSAL_CODES: frozenset[str] = frozenset(
    {
        "too_large",
        "unsupported",
        "legacy_office",
        "encrypted",
        "corrupt",
        "timeout",
        "empty",
        "busy",
        "quota_full",
        "switched_off",
        # Beyond the plan's list: an upload over the hourly rate (HTTP 429).
        "rate_limited",
    }
)


@dataclass(frozen=True)
class Section:
    """One labelled piece of a document. ``page`` is the page, slide or
    sheet number it came from (None for a file without pages); ``src`` says
    how its text was read ("text" for a text layer, "ocr" for local OCR)."""

    label: str
    page: Optional[int]
    text: str
    src: str = "text"


@dataclass(frozen=True)
class Extraction:
    """A whole document as read. ``pages_total`` counts pages, slides or
    sheets (None for text files). ``truncated`` means some of the document
    was not read (a page, character or time limit). ``warnings`` hold codes
    only (``hidden_text``, ``timed_out_after_page:212`` ...), never text."""

    kind: str
    media_type: str
    title: str
    pages_total: Optional[int]
    sections: tuple[Section, ...]
    truncated: bool
    scanned_pages_unread: tuple[int, ...] = ()
    ocr_pages: int = 0
    warnings: tuple[str, ...] = field(default_factory=tuple)

    @property
    def chars(self) -> int:
        return sum(len(s.text) for s in self.sections)


class ExtractionRefused(Exception):
    """A document that cannot be read. ``code`` is one of REFUSAL_CODES and
    ``message`` the user-safe sentence (services/files/messages.py) that a
    route, a channel and a tool result can all show as it is."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


# Zero-width, bidi and other invisible characters: stripped and counted
# (the count becomes a warning). Same families as the prompt guard's list.
_INVISIBLE = re.compile(
    "[​-‏‪-‮⁠-⁤⁦-⁩﻿­͏"
    "؜ᅟᅠ឴឵᠎￹-￻\U000e0000-\U000e007f]"
)
# Control characters other than tab and line feed.
_CONTROL = re.compile("[\u0000-\u0008\u000b-\u001f\u007f-\u009f]")
_TRAILING_SPACE = re.compile(r"[ \t]+\n")
_BLANK_RUN = re.compile(r"\n{3,}")


def normalize_text(text: str) -> tuple[str, int]:
    """*text* cleaned for the model, and how many invisible characters were
    stripped from it. Line breaks are normalised to ``\\n``."""
    text = unicodedata.normalize("NFC", text.replace("\r\n", "\n").replace("\r", "\n"))
    stripped = len(_INVISIBLE.findall(text))
    if stripped:
        text = _INVISIBLE.sub("", text)
    text = _CONTROL.sub("", text)
    text = _TRAILING_SPACE.sub("\n", text)
    text = _BLANK_RUN.sub("\n\n", text)
    return text.strip(), stripped


_BREAKS: tuple[str, ...] = ("\n\n", "\n", ". ", " ")


def _cut_point(text: str, target: int, maximum: int) -> int:
    """Where to cut *text* (longer than *maximum*): the last break at or
    before *target* (not earlier than half of it), else the first break
    after it within *maximum*, trying paragraphs, then lines, sentences and
    spaces; a hard cut at *target* when there is no break at all."""
    floor = target // 2
    for mark in _BREAKS:
        before = text.rfind(mark, floor, target)
        if before != -1:
            return before + len(mark)
        after = text.find(mark, target, maximum)
        if after != -1:
            return after + len(mark)
    return target


def split_text(
    text: str, *, target: int = SECTION_TARGET_CHARS, maximum: int = SECTION_MAX_CHARS
) -> list[str]:
    """*text* in pieces of at most *maximum* characters, cut near *target*."""
    pieces: list[str] = []
    rest = text
    while len(rest) > maximum:
        cut = _cut_point(rest, target, maximum)
        piece = rest[:cut].strip()
        if piece:
            pieces.append(piece)
        rest = rest[cut:].lstrip()
    if rest.strip():
        pieces.append(rest.strip())
    return pieces


@dataclass(frozen=True)
class RawUnit:
    """What the worker sends for one page, slide, sheet range or file:
    its label ("" for a file without natural parts), its page number and
    its text as parsed."""

    label: str
    page: Optional[int]
    text: str
    src: str = "text"


@dataclass
class BuiltSections:
    sections: list[Section]
    invisible_stripped: int
    truncated: bool


def build_sections(
    units: Iterable[RawUnit], *, max_chars: int = MAX_DOCUMENT_CHARS
) -> BuiltSections:
    """Normalise *units* and split any longer than SECTION_MAX_CHARS.

    A unit with a label keeps it ("Page 3"), and its pieces become
    "Page 3 (part 2)". Units without one ("" from a text file) are numbered
    "Part 1", "Part 2" across the document. Empty units are dropped. The
    document stops at *max_chars* characters (``truncated``).
    """
    sections: list[Section] = []
    stripped_total = 0
    used = 0
    part = 0
    truncated = False
    for unit in units:
        text, stripped = normalize_text(unit.text)
        stripped_total += stripped
        if not text:
            continue
        pieces = split_text(text)
        for index, piece in enumerate(pieces, start=1):
            if used + len(piece) > max_chars:
                room = max_chars - used
                if room > 0:
                    piece = piece[:room]
                else:
                    truncated = True
                    break
                truncated = True
            if unit.label:
                label = unit.label if len(pieces) == 1 else f"{unit.label} (part {index})"
            else:
                part += 1
                label = f"Part {part}"
            sections.append(Section(label=label[:200], page=unit.page, text=piece, src=unit.src))
            used += len(piece)
            if truncated:
                break
        if truncated:
            break
    return BuiltSections(sections=sections, invisible_stripped=stripped_total, truncated=truncated)
