"""Turns text into the terms the knowledge index stores and a query looks up.

Why it exists: the keyword index is plain rows of (term, passage), so what
counts as "the same word" is decided here, once, for indexing and searching
alike:
- NFKC and casefold, so full-width letters, ligatures and case fold together;
- letters and digits split apart, so a course code written 'CS101', 'CS 101'
  or 'cs-101' becomes the same two terms ('cs', '101');
- Chinese, Japanese and Korean text, which has no spaces, becomes
  overlapping character pairs (bigrams);
- a light English stemmer that only folds plurals ('exams' -> 'exam',
  'studies' -> 'study', 'classes' -> 'class'), so it never merges unrelated
  words;
- stopwords are indexed but dropped from a query, unless the query is only
  stopwords ('to be or not to be').

Stdlib only; deterministic.
"""

from __future__ import annotations

import re
import unicodedata
from collections import Counter
from typing import Iterable, Optional

from services.knowledge.limits import TERM_MAX_CHARS

# Runs of letters, or runs of digits (never both: 'CS101' is two terms).
_TOKEN_RE = re.compile(r"[^\W\d_]+|\d+")

# Scripts written without spaces, split into character bigrams: Hiragana,
# Katakana, CJK ideographs (with extension A and compatibility forms) and
# Hangul syllables.
_CJK_RE = re.compile(
    "[぀-ヿ㐀-䶿一-鿿豈-﫿가-힯\U00020000-\U0002ffff]+"
)

STOPWORDS: frozenset[str] = frozenset(
    """
    a about above after again against all am an and any are as at be because
    been before being below between both but by can could did do does doing
    down during each few for from further had has have having he her here hers
    herself him himself his how i if in into is it its itself just me more most
    my myself no nor not now of off on once only or other our ours ourselves
    out over own same she should so some such than that the their theirs them
    themselves then there these they this those through to too under until up
    very was we were what when where which while who whom why will with would
    you your yours yourself yourselves s t d ll m re ve
    """.split()
)


def normalize(text: str) -> str:
    """*text* in NFKC, casefolded."""
    return unicodedata.normalize("NFKC", text or "").casefold()


def stem(term: str) -> str:
    """The singular of an English plural; anything else unchanged.

    'studies' -> 'study', 'classes' -> 'class', 'boxes' -> 'box',
    'exams' -> 'exam', 'notes' -> 'note'. Words ending in 'ss', 'us' or
    'is' ('class', 'syllabus', 'analysis') and short words are kept.
    """
    if len(term) <= 3 or not term.isascii() or not term.isalpha() or term[-1] != "s":
        return term
    if term.endswith(("ss", "us", "is")):
        return term
    if term.endswith("ies") and len(term) > 4 and term[-4] not in "ae":
        return term[:-3] + "y"
    if term.endswith("zzes"):
        return term[:-3]
    if term.endswith(("sses", "xes", "ches", "shes")):
        return term[:-2]
    return term[:-1]


def _cjk_pieces(run: str) -> list[str]:
    if len(run) == 1:
        return [run]
    return [run[i : i + 2] for i in range(len(run) - 1)]


def tokens(text: str) -> list[str]:
    """Every term of *text*, in order, stopwords included."""
    out: list[str] = []
    for match in _TOKEN_RE.finditer(normalize(text)):
        word = match.group()
        if _CJK_RE.search(word):
            position = 0
            for cjk in _CJK_RE.finditer(word):
                before = word[position : cjk.start()]
                if before:
                    out.append(stem(before))
                out.extend(_cjk_pieces(cjk.group()))
                position = cjk.end()
            rest = word[position:]
            if rest:
                out.append(stem(rest))
            continue
        out.append(stem(word))
    return [t for t in out if 0 < len(t) <= TERM_MAX_CHARS]


def is_stopword(term: str) -> bool:
    return term in STOPWORDS


def term_counts(text: str, heading: Optional[str] = None) -> Counter[str]:
    """How often each term occurs in a passage. The heading's terms count
    once more, so a passage under "§ Grading" is found by 'grading' even
    where its own text does not say it."""
    counts: Counter[str] = Counter(tokens(text))
    if heading:
        counts.update(tokens(heading))
    return counts


def query_terms(query: str) -> list[str]:
    """The distinct terms a search looks up, in order: stopwords dropped,
    unless every term is one (then all are kept)."""
    seen: dict[str, None] = {}
    for term in tokens(query):
        seen.setdefault(term, None)
    terms = list(seen)
    content = [t for t in terms if not is_stopword(t)]
    return content or terms


def matched(terms: Iterable[str], text: str) -> list[str]:
    """Which of *terms* occur in *text* (for a result's ``matched_terms``)."""
    present = set(tokens(text))
    return [t for t in terms if t in present]
