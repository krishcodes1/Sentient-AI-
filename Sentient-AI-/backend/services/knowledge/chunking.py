"""Splits a document into passages of about 1200 characters that keep their
page, slide, sheet or section, so every search hit can be cited.

Why it exists: an answer must say where it came from ('Syllabus.pdf, p. 3').
file_extraction hands over labelled sections ("Page 3", "Slide 4: Title",
"Sheet 'Grades' rows 1-120", "Part 2"); this module turns them into passages
with a short locator:

- 'p. 3' or 'pp. 3–4' for a PDF (the printed page label when the PDF has
  one), 'slide 4' or 'slides 4–6' for a deck, 'sheet Grades' for a
  workbook (a passage never spans two sheets);
- '§ Grading' for text with Markdown headings (Word files, Notion pages,
  notes), else 'part 7'.

Passages aim for CHUNK_TARGET_CHARS, never exceed CHUNK_MAX_CHARS, and start
with the last ~CHUNK_OVERLAP_CHARS of the passage before (never across a
heading or a sheet), so a sentence cut at a boundary is still found whole.
A heading starts a new passage and is kept as its ``heading`` (its terms
count twice in the index). The output depends on the input only.

Stdlib plus the file_extraction splitter.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Iterable, Optional, Sequence

from services.files.sections import Section, split_text
from services.knowledge.limits import (
    CHUNK_MAX_CHARS,
    CHUNK_OVERLAP_CHARS,
    CHUNK_TARGET_CHARS,
    HEADING_MAX,
    LOCATOR_MAX,
)

_PART_SUFFIX = r"(?: \((?:part|cont\.) \d+\))*"
_PAGE_LABEL = re.compile(r"^Page (\S{1,20})" + _PART_SUFFIX + r"$")
_SLIDE_LABEL = re.compile(r"^Slide (\d+)(?: \(hidden\))?(?:: (.*?))?" + _PART_SUFFIX + r"$")
_SHEET_LABEL = re.compile(r"^Sheet '(.+?)' rows \d+-\d+" + _PART_SUFFIX + r"$")
_HEADING_LINE = re.compile(r"^ {0,3}(#{1,6})[ \t]+(.+?)[ \t#]*$")

# A block longer than this is split first, so a block plus the overlap
# (and the blank line between them) still fits CHUNK_MAX_CHARS.
_BLOCK_MAX = CHUNK_MAX_CHARS - CHUNK_OVERLAP_CHARS - 2
_BLOCK_TARGET = CHUNK_TARGET_CHARS - CHUNK_OVERLAP_CHARS


@dataclass(frozen=True)
class Unit:
    """One page, slide, sheet or run of text. ``kind`` is 'page', 'slide',
    'sheet' or 'part'; ``label`` the printed page label ('3', 'iv'), the
    slide's title or the sheet's name; ``number`` the page or slide
    number."""

    kind: str
    text: str
    number: Optional[int] = None
    label: str = ""


@dataclass(frozen=True)
class Passage:
    ordinal: int
    locator: str
    heading: Optional[str]
    text: str


@dataclass(frozen=True)
class _Block:
    text: str
    unit: int
    heading: Optional[str] = None


def _unit_for(section: Section, doc_kind: str) -> Unit:
    label = section.label or ""
    if doc_kind == "pdf":
        match = _PAGE_LABEL.match(label)
        if match:
            return Unit("page", section.text, section.page, match.group(1))
        if section.page is not None:
            return Unit("page", section.text, section.page, str(section.page))
    if doc_kind == "pptx":
        match = _SLIDE_LABEL.match(label)
        if match:
            return Unit("slide", section.text, int(match.group(1)), (match.group(2) or "").strip())
    if doc_kind == "xlsx":
        match = _SHEET_LABEL.match(label)
        if match:
            return Unit("sheet", section.text, section.page, match.group(1).strip())
    return Unit("part", section.text)


def units_from_sections(doc_kind: str, sections: Iterable[Section]) -> list[Unit]:
    """file_extraction's sections as units; the pieces of one page, slide or
    sheet are joined back together."""
    units: list[Unit] = []
    for section in sections:
        unit = _unit_for(section, doc_kind)
        if units:
            last = units[-1]
            same = (
                last.kind == unit.kind
                and unit.kind != "part"
                and last.number == unit.number
                and last.label == unit.label
            )
            if same:
                units[-1] = Unit(last.kind, last.text + "\n\n" + unit.text, last.number, last.label)
                continue
        units.append(unit)
    return units


def _heading_of(line: str) -> Optional[str]:
    match = _HEADING_LINE.match(line)
    if not match:
        return None
    text = " ".join(match.group(2).split())
    return text[:HEADING_MAX] or None


def _paragraph(lines: list[str], index: int) -> list[_Block]:
    text = "\n".join(lines).strip()
    if not text:
        return []
    return [_Block(piece, index) for piece in split_text(text, target=_BLOCK_TARGET, maximum=_BLOCK_MAX)]


def _unit_blocks(index: int, unit: Unit) -> list[_Block]:
    blocks: list[_Block] = []
    lines: list[str] = []
    for raw in unit.text.split("\n"):
        line = raw.rstrip()
        if not line.strip():
            blocks.extend(_paragraph(lines, index))
            lines = []
            continue
        heading = _heading_of(line) if unit.kind == "part" else None
        if heading is not None:
            blocks.extend(_paragraph(lines, index))
            lines = []
            blocks.append(_Block(line.strip()[:_BLOCK_MAX], index, heading))
            continue
        lines.append(line)
    blocks.extend(_paragraph(lines, index))
    return blocks


def _blocks(units: Sequence[Unit]) -> list[_Block]:
    """Paragraphs (split on blank lines) and heading lines, in order, each
    at most _BLOCK_MAX characters."""
    blocks: list[_Block] = []
    for index, unit in enumerate(units):
        blocks.extend(_unit_blocks(index, unit))
    return blocks


def _clip(text: str, limit: int = LOCATOR_MAX) -> str:
    text = " ".join(text.split())
    return text if len(text) <= limit else text[: limit - 1].rstrip() + "…"


def _span(first: str, last: str, one: str, many: str) -> str:
    if first == last:
        return f"{one} {first}"
    return f"{many} {first}–{last}"


def _locator(units: Sequence[Unit], used: Sequence[int], ordinal: int, heading: Optional[str]) -> str:
    kinds = {units[i].kind for i in used}
    if kinds == {"page"}:
        first, last = units[min(used)], units[max(used)]
        return _clip(_span(first.label, last.label, "p.", "pp."))
    if kinds == {"slide"}:
        first, last = units[min(used)], units[max(used)]
        return _clip(_span(str(first.number), str(last.number), "slide", "slides"))
    if kinds == {"sheet"}:
        return _clip(f"sheet {units[min(used)].label}")
    if heading:
        return _clip(f"§ {heading}")
    return f"part {ordinal + 1}"


def _heading_for(unit: Unit, heading_now: Optional[str]) -> Optional[str]:
    """The heading a passage starting in *unit* is filed under: the Markdown
    heading in effect for text, the slide's title for a slide."""
    if unit.kind == "part":
        return heading_now
    if unit.kind == "slide":
        return unit.label[:HEADING_MAX] or None
    return None


def _overlap(text: str) -> str:
    """The last ~CHUNK_OVERLAP_CHARS of *text*, starting at a word."""
    if len(text) <= CHUNK_OVERLAP_CHARS * 2:
        return ""
    tail = text[-CHUNK_OVERLAP_CHARS:]
    cut = re.search(r"\s", tail)
    if cut is None:
        return ""
    return tail[cut.end() :].strip()


def chunk_units(units: Sequence[Unit]) -> list[Passage]:
    """The passages of a document made of *units* (see the module doc)."""
    passages: list[Passage] = []
    blocks = _blocks(units)

    parts: list[str] = []
    used: list[int] = []
    has_new = False
    length = 0
    heading_now: Optional[str] = None
    chunk_heading: Optional[str] = None
    sheet: Optional[int] = None

    def emit() -> None:
        nonlocal parts, used, has_new, length
        text = "\n\n".join(parts).strip()
        ordinal = len(passages)
        passages.append(Passage(ordinal, _locator(units, used, ordinal, chunk_heading), chunk_heading, text))
        parts, used, has_new, length = [], [], False, 0

    for block in blocks:
        unit = units[block.unit]
        forced = block.heading is not None or (unit.kind == "sheet" and sheet is not None and block.unit != sheet)
        sep = 2 if parts else 0
        if has_new and (forced or length >= CHUNK_TARGET_CHARS or length + sep + len(block.text) > CHUNK_MAX_CHARS):
            last_text, last_unit = "\n\n".join(parts), used[-1]
            emit()
            seed = "" if forced else _overlap(last_text)
            if seed:
                parts, used, length = [seed], [last_unit], len(seed)
        if block.heading is not None:
            heading_now = block.heading
        if not has_new:
            chunk_heading = _heading_for(unit, heading_now)
        if unit.kind == "sheet":
            sheet = block.unit
        parts.append(block.text)
        used.append(block.unit)
        length += (2 if len(parts) > 1 else 0) + len(block.text)
        has_new = True
    if has_new:
        emit()
    return passages


def chunk_sections(doc_kind: str, sections: Iterable[Section]) -> list[Passage]:
    """The passages of an extracted document."""
    return chunk_units(units_from_sections(doc_kind, sections))


def chunk_text(text: str) -> list[Passage]:
    """The passages of plain text or Markdown (a note, a web page)."""
    return chunk_units([Unit("part", text)])
