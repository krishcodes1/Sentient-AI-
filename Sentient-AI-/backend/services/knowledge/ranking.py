"""Ranks passages: BM25 over the keyword index, Reciprocal Rank Fusion with the
meaning index, and at most a few passages per document.

Why it exists: the scores are computed here, in plain Python, from the rows
the store reads (a passage's term frequency and length), so SQLite and
Postgres rank the same way and the numbers can be checked by hand in tests.

- BM25 with k1 = 1.2 and b = 0.75 and the always-positive idf
  ln(1 + (N - df + 0.5) / (df + 0.5)); N, df and the average length are
  taken over the passages in the searched collections only.
- A query term found in more than half of those passages is skipped when
  there are enough passages and the query has another term.
- RRF adds 1 / (k + rank) per ranking (k = 60).
- Ties are broken by passage id, so the order never depends on the
  database's row order.

Stdlib only.
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from typing import Iterable, Mapping, Sequence

from services.knowledge.limits import (
    BM25_B,
    BM25_K1,
    COMMON_TERM_MIN_PASSAGES,
    COMMON_TERM_RATIO,
    PER_DOCUMENT_CAP,
    RRF_K,
)


@dataclass(frozen=True)
class Posting:
    """One (term, passage) row: the term's frequency in the passage and the
    passage's length in terms."""

    chunk_id: int
    term: str
    tf: int
    dl: int


def idf(n: int, df: int) -> float:
    return math.log(1.0 + (n - df + 0.5) / (df + 0.5))


def useful_terms(terms: Sequence[str], df: Mapping[str, int], n: int) -> list[str]:
    """*terms* without the very common ones (see the module doc), and
    without terms no passage has."""
    present = [t for t in terms if df.get(t, 0) > 0]
    if n < COMMON_TERM_MIN_PASSAGES:
        return present
    rare = [t for t in present if df[t] <= COMMON_TERM_RATIO * n]
    return rare or present


def bm25(
    postings: Iterable[Posting],
    terms: Sequence[str],
    df: Mapping[str, int],
    n: int,
    avgdl: float,
    *,
    k1: float = BM25_K1,
    b: float = BM25_B,
) -> dict[int, float]:
    """The BM25 score of every passage with at least one of *terms*."""
    wanted = set(useful_terms(terms, df, n))
    if not wanted or n <= 0:
        return {}
    weights = {t: idf(n, df[t]) for t in wanted}
    mean = avgdl if avgdl > 0 else 1.0
    scores: dict[int, float] = {}
    for row in postings:
        if row.term not in wanted or row.tf <= 0:
            continue
        norm = k1 * (1.0 - b + b * (row.dl / mean))
        scores[row.chunk_id] = scores.get(row.chunk_id, 0.0) + weights[row.term] * (
            row.tf * (k1 + 1.0) / (row.tf + norm)
        )
    return scores


def ranked(scores: Mapping[int, float]) -> list[tuple[int, float]]:
    """*scores* best first; equal scores by passage id."""
    return sorted(scores.items(), key=lambda item: (-item[1], item[0]))


def rrf(rankings: Sequence[Sequence[int]], *, k: int = RRF_K) -> list[tuple[int, float]]:
    """Reciprocal Rank Fusion of several best-first id lists."""
    fused: dict[int, float] = {}
    for ranking in rankings:
        for position, chunk_id in enumerate(ranking, start=1):
            fused[chunk_id] = fused.get(chunk_id, 0.0) + 1.0 / (k + position)
    return ranked(fused)


def cap_per_document(
    ordered: Iterable[tuple[int, float]],
    document_of: Mapping[int, str],
    *,
    limit: int,
    per_document: int = PER_DOCUMENT_CAP,
) -> list[tuple[int, float]]:
    """The first *limit* of *ordered*, at most *per_document* per document."""
    taken: list[tuple[int, float]] = []
    counts: dict[str, int] = {}
    for chunk_id, score in ordered:
        document = document_of.get(chunk_id)
        if document is None:
            continue
        if counts.get(document, 0) >= per_document:
            continue
        counts[document] = counts.get(document, 0) + 1
        taken.append((chunk_id, score))
        if len(taken) >= limit:
            break
    return taken
