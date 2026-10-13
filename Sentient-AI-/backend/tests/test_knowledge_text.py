"""Tests for the knowledge base tokenizer: NFKC and casefold, course codes that
match however they are written, CJK bigrams, stopwords dropped from a query
unless it is only stopwords, and the plural-only stemmer.

Why it exists: the keyword index is rows of (term, passage); if indexing and
searching disagreed on what a term is, 'CS 101' would never find 'CS101'.
"""

from __future__ import annotations

from services.knowledge import text


def test_nfkc_and_casefold_fold_widths_ligatures_and_case():
    assert text.tokens("ＣＳ１０１ Straße ﬁnal") == ["cs", "101", "strasse", "final"]


def test_course_codes_match_however_they_are_written():
    joined, spaced, dashed = text.tokens("CS101"), text.tokens("CS 101"), text.tokens("cs-101")
    assert joined == spaced == dashed == ["cs", "101"]


def test_cjk_runs_become_bigrams_and_a_single_character_stays():
    assert text.tokens("東京大学") == ["東京", "京大", "大学"]
    assert text.tokens("猫") == ["猫"]
    assert text.tokens("Tokyo東京") == ["tokyo", "東京"]


def test_the_stemmer_only_folds_plurals():
    assert [text.stem(w) for w in ("exams", "studies", "classes", "boxes", "notes", "quizzes")] == [
        "exam",
        "study",
        "class",
        "box",
        "note",
        "quiz",
    ]
    # Words that end in s but are not plurals, and short words, are kept.
    assert [text.stem(w) for w in ("class", "syllabus", "analysis", "bus", "gas", "grading")] == [
        "class",
        "syllabus",
        "analysis",
        "bus",
        "gas",
        "grading",
    ]


def test_a_query_drops_stopwords_unless_it_is_only_stopwords():
    assert text.query_terms("When is the CS 101 midterm?") == ["cs", "101", "midterm"]
    assert text.query_terms("to be or not to be") == ["to", "be", "or", "not"]


def test_documents_index_every_term_including_stopwords():
    assert text.tokens("The midterm is on Monday") == ["the", "midterm", "is", "on", "monday"]


def test_heading_terms_count_twice():
    counts = text.term_counts("# Grading\nExams count 40 percent.", "Grading")
    assert counts["grading"] == 2 and counts["exam"] == 1


def test_overlong_tokens_are_dropped():
    blob = "x" * 41
    assert text.tokens(f"{blob} keep") == ["keep"]


def test_matched_names_the_query_terms_a_text_holds():
    assert text.matched(["midterm", "october", "room"], "The midterm is in Room 204.") == ["midterm", "room"]
