"""Tests for knowledge ranking: BM25 against hand-computed values, idf and
length taken over the searched collections only, very common terms skipped,
Reciprocal Rank Fusion, at most three passages per document, and ties broken
by passage id.

Why it exists: ranking is plain Python so SQLite and Postgres agree; these
numbers pin it so a refactor cannot silently change what the assistant cites.
"""

from __future__ import annotations

import math

import pytest

from services.knowledge import ranking
from services.knowledge.ranking import Posting
from services.knowledge.sources import from_text
from services.knowledge.store import KnowledgeService
from tests.conftest import make_user

# The five passages, as (id, terms):
#   1 "midterm exam october"          dl 3
#   2 "final exam december"           dl 3
#   3 "midterm review session midterm" dl 4 (midterm twice)
#   4 "office hours"                  dl 2
#   5 "grading policy exam"           dl 3
CORPUS = {
    1: ["midterm", "exam", "october"],
    2: ["final", "exam", "december"],
    3: ["midterm", "review", "session", "midterm"],
    4: ["office", "hours"],
    5: ["grading", "policy", "exam"],
}


def _postings() -> list[Posting]:
    rows = []
    for chunk_id, terms in CORPUS.items():
        for term in sorted(set(terms)):
            rows.append(Posting(chunk_id, term, terms.count(term), len(terms)))
    return rows


def _df() -> dict[str, int]:
    df: dict[str, int] = {}
    for terms in CORPUS.values():
        for term in set(terms):
            df[term] = df.get(term, 0) + 1
    return df


def test_bm25_matches_hand_computed_values():
    scores = ranking.bm25(_postings(), ["midterm", "exam"], _df(), n=5, avgdl=3.0)
    # idf(midterm) = ln(1 + 3.5/2.5) = ln 2.4; idf(exam) = ln(1 + 2.5/3.5)
    assert math.log(2.4) == pytest.approx(0.875468737)
    # Passage 1: dl = avgdl, so each tf-part is 1.0.
    assert scores[1] == pytest.approx(0.875468737 + 0.538996501, abs=1e-9)
    # Passage 3: tf 2, dl 4: 2 * 2.2 / (2 + 1.2 * (0.25 + 0.75 * 4/3)) = 4.4 / 3.5.
    assert scores[3] == pytest.approx(0.875468737 * 4.4 / 3.5, abs=1e-9)
    assert scores[2] == pytest.approx(0.538996501, abs=1e-9)
    assert scores[5] == pytest.approx(0.538996501, abs=1e-9)
    assert 4 not in scores


def test_ties_are_broken_by_passage_id():
    scores = ranking.bm25(_postings(), ["midterm", "exam"], _df(), n=5, avgdl=3.0)
    assert [c for c, _ in ranking.ranked(scores)] == [1, 3, 2, 5]


def test_very_common_terms_are_skipped_but_not_when_they_are_all_there_is():
    df = {"the": 9, "midterm": 1}
    assert ranking.useful_terms(["the", "midterm"], df, 12) == ["midterm"]
    assert ranking.useful_terms(["the"], df, 12) == ["the"]
    # A small scope keeps them (every term tells passages apart there).
    assert ranking.useful_terms(["the", "midterm"], df, 5) == ["the", "midterm"]


def test_rrf_with_overlapping_and_disjoint_lists():
    fused = ranking.rrf([[1, 2, 3], [3, 1, 4]])
    scores = dict(fused)
    assert scores[1] == pytest.approx(1 / 61 + 1 / 62)
    assert scores[3] == pytest.approx(1 / 63 + 1 / 61)
    assert scores[4] == pytest.approx(1 / 63)
    assert [c for c, _ in fused] == [1, 3, 2, 4]
    disjoint = ranking.rrf([[7, 8], [9]])
    # 7 and 9 tie at 1/61; the lower id comes first.
    assert [c for c, _ in disjoint] == [7, 9, 8]


def test_at_most_three_passages_per_document():
    ordered = [(n, 10.0 - n) for n in range(1, 8)]
    document_of = {1: "a", 2: "a", 3: "a", 4: "a", 5: "b", 6: "a", 7: "c"}
    picked = ranking.cap_per_document(ordered, document_of, limit=6)
    assert [c for c, _ in picked] == [1, 2, 3, 5, 7]


@pytest.mark.asyncio
async def test_idf_and_length_come_from_the_searched_collection_only(session_factory):
    user, _ = await make_user(session_factory, "rank@example.com")
    service = KnowledgeService(session_factory)
    for text, collection in (
        ("alpha beta", "B"),
        ("gamma delta", "B"),
        ("alpha one", "A"),
        ("alpha two", "A"),
        ("alpha three", "A"),
    ):
        outcome = await service.add_document(str(user.id), collection, from_text(text, text))
        assert outcome.status == "ready"
    b = await service.find_collection(str(user.id), "B")
    scoped, _ = await service.keyword_ranking(str(user.id), ["alpha"], collection_id=b.id)
    everywhere, matched = await service.keyword_ranking(str(user.id), ["alpha"])
    # In B: N = 2, df = 1, dl = avgdl = 2 -> idf ln(2), tf-part 1.
    ((chunk_id, score),) = scoped
    assert score == pytest.approx(math.log(2.0))
    # Over both: N = 5, df = 4 -> ln(1 + 1.5/4.5).
    assert dict(everywhere)[chunk_id] == pytest.approx(math.log(4 / 3))
    assert matched[chunk_id] == ["alpha"]
