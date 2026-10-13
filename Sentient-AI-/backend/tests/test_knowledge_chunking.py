"""Tests for the knowledge base chunker: page, slide, sheet and section
locators ('p. 3', 'pp. 3–4', 'slides 4–6', 'sheet Grades', '§ Grading',
'part 7'), the 1200 / 1600 / 200 sizes, headings, and determinism.

Why it exists: every citation the assistant gives comes from these locators;
a passage that lost its page number cannot be cited.
"""

from __future__ import annotations

from services.files.sections import Section
from services.knowledge import chunking
from services.knowledge.limits import CHUNK_MAX_CHARS, CHUNK_OVERLAP_CHARS, CHUNK_TARGET_CHARS

SENTENCE = "The course covers algorithms and data structures in depth. "


def _pages(count: int, repeat: int = 12) -> list[Section]:
    return [Section(f"Page {n}", n, SENTENCE * repeat + f"Page marker {n}.") for n in range(1, count + 1)]


def test_short_pages_share_a_passage():
    passages = chunking.chunk_sections("pdf", _pages(2, repeat=5))
    assert [p.locator for p in passages] == ["pp. 1–2"]


def test_a_short_pdf_page_is_one_passage_cited_by_page():
    (passage,) = chunking.chunk_sections("pdf", [Section("Page 3", 3, "The midterm is on October 12.")])
    assert passage.locator == "p. 3" and passage.heading is None and passage.ordinal == 0


def test_pdf_passages_spanning_pages_say_pp():
    passages = chunking.chunk_sections("pdf", _pages(4, repeat=22))
    locators = [p.locator for p in passages]
    assert locators[0] == "p. 1"
    assert any(loc.startswith("pp. ") and "–" in loc for loc in locators[1:])
    assert all(len(p.text) <= CHUNK_MAX_CHARS for p in passages)


def test_the_printed_page_label_is_kept():
    passages = chunking.chunk_sections("pdf", [Section("Page iv", 4, "Preface text."), Section("Page 1", 5, "Intro.")])
    assert passages[0].locator == "pp. iv–1"


def test_the_parts_of_one_page_join_back_together():
    sections = [Section("Page 2", 2, "First half."), Section("Page 2 (part 2)", 2, "Second half.")]
    (passage,) = chunking.chunk_sections("pdf", sections)
    assert passage.locator == "p. 2" and "First half." in passage.text and "Second half." in passage.text


def test_slides_are_cited_as_slides_and_keep_their_title():
    sections = [Section(f"Slide {n}: Topic {n}", n, f"Bullet for slide {n}.") for n in range(4, 7)]
    (passage,) = chunking.chunk_sections("pptx", sections)
    assert passage.locator == "slides 4–6" and passage.heading == "Topic 4"
    (single,) = chunking.chunk_sections("pptx", sections[:1])
    assert single.locator == "slide 4"


def test_a_passage_never_spans_two_sheets():
    sections = [
        Section("Sheet 'Grades' rows 1-3", 1, "a | 90\nb | 80"),
        Section("Sheet 'Roster' rows 1-2", 2, "alice\nbob"),
    ]
    passages = chunking.chunk_sections("xlsx", sections)
    assert [p.locator for p in passages] == ["sheet Grades", "sheet Roster"]


def test_markdown_headings_become_section_locators_and_start_passages():
    text = "# Intro\nWelcome to the course.\n\n# Grading\nExams count 40 percent. Homework 60 percent."
    passages = chunking.chunk_text(text)
    assert [(p.locator, p.heading) for p in passages] == [("§ Intro", "Intro"), ("§ Grading", "Grading")]
    assert passages[1].text.startswith("# Grading")


def test_text_without_headings_is_cited_by_part():
    passages = chunking.chunk_text("\n\n".join(SENTENCE * 8 for _ in range(6)))
    assert [p.locator for p in passages] == [f"part {n}" for n in range(1, len(passages) + 1)]
    assert len(passages) > 1


def test_sizes_target_max_and_overlap():
    text = "\n\n".join(f"Paragraph {n}. " + SENTENCE * 5 for n in range(40))
    passages = chunking.chunk_text(text)
    assert all(len(p.text) <= CHUNK_MAX_CHARS for p in passages)
    # Every passage but the last reached the target before it was cut.
    assert all(len(p.text) >= CHUNK_TARGET_CHARS - 400 for p in passages[:-1])
    # Each later passage starts with the end of the one before.
    for before, after in zip(passages, passages[1:], strict=False):
        seed = after.text.split("\n\n", 1)[0]
        assert len(seed) <= CHUNK_OVERLAP_CHARS and before.text.endswith(seed)


def test_no_overlap_across_a_heading():
    text = "# One\n" + SENTENCE * 30 + "\n\n# Two\nShort."
    passages = chunking.chunk_text(text)
    assert passages[-1].text == "# Two\n\nShort."


def test_a_long_paragraph_is_split_under_the_maximum():
    passages = chunking.chunk_text("word " * 2000)
    assert len(passages) > 3 and all(len(p.text) <= CHUNK_MAX_CHARS for p in passages)


def test_chunking_is_deterministic():
    sections = _pages(6, repeat=20)
    assert chunking.chunk_sections("pdf", sections) == chunking.chunk_sections("pdf", sections)


def test_long_locators_are_clipped_to_forty_characters():
    heading = "A very long section heading that keeps going on and on"
    (passage,) = chunking.chunk_text(f"# {heading}\nBody.")
    assert len(passage.locator) <= 40 and passage.locator.endswith("…") and passage.heading == heading
