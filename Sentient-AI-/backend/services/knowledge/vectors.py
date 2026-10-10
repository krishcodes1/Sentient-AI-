"""Stores and scores the meaning index's vectors: float32 little-endian bytes,
L2-normalised, scored by dot product in plain Python (numpy only when it is
already installed), with a small per-user cache.

Why it exists: the vectors live in a plain binary column so the index works
the same on SQLite and Postgres with no vector extension. Scoring 20,000
passages of 256 numbers is a fraction of a second in Python, run off the
event loop by the caller; numpy is never required, only used when present.
The cache is keyed by user and model, so one user's vectors are never
scored for another and vectors of an old model are never mixed with new.

Stdlib only (numpy optional).
"""

from __future__ import annotations

import importlib.util
import math
import operator
import struct
import sys
import threading
from array import array
from collections import OrderedDict
from dataclasses import dataclass
from typing import Any, Optional, Sequence

from services.knowledge.limits import VECTOR_CACHE_BYTES


def pack(vector: Sequence[float]) -> bytes:
    """*vector* as float32 little-endian bytes."""
    return struct.pack(f"<{len(vector)}f", *vector)


def unpack(blob: bytes) -> array:
    """The float32 values of *blob* (little-endian)."""
    values = array("f")
    values.frombytes(bytes(blob[: len(blob) - len(blob) % 4]))
    if sys.byteorder == "big":
        values.byteswap()
    return values


def normalize(vector: Sequence[float]) -> list[float]:
    """*vector* scaled to length 1 (all zeros stays all zeros)."""
    values = [float(x) for x in vector]
    norm = math.sqrt(sum(x * x for x in values))
    if norm == 0.0 or math.isnan(norm) or math.isinf(norm):
        return [0.0 for _ in values]
    return [x / norm for x in values]


def dot(a: Sequence[float], b: Sequence[float]) -> float:
    return float(sum(map(operator.mul, a, b)))


@dataclass(frozen=True)
class VectorRow:
    chunk_id: int
    document_id: str
    collection_id: str
    values: array


def numpy_available() -> bool:
    return importlib.util.find_spec("numpy") is not None


def score_pure(query: Sequence[float], rows: Sequence[VectorRow]) -> list[tuple[int, float]]:
    """(passage id, cosine) for every row of the query's length."""
    size = len(query)
    return [(row.chunk_id, dot(query, row.values)) for row in rows if len(row.values) == size]


def score_numpy(query: Sequence[float], rows: Sequence[VectorRow]) -> list[tuple[int, float]]:
    """The same scores as score_pure, as one matrix product (float64)."""
    import numpy as np

    size = len(query)
    usable = [row for row in rows if len(row.values) == size]
    if not usable:
        return []
    matrix = np.array([row.values for row in usable], dtype=np.float64)
    scores = matrix @ np.asarray(query, dtype=np.float64)
    return [(row.chunk_id, float(score)) for row, score in zip(usable, scores, strict=True)]


def best(
    query: Sequence[float], rows: Sequence[VectorRow], limit: int, *, use_numpy: Optional[bool] = None
) -> list[tuple[int, float]]:
    """The *limit* rows closest to *query*, best first, ties by passage id."""
    if use_numpy is None:
        use_numpy = numpy_available()
    scored = score_numpy(query, rows) if use_numpy else score_pure(query, rows)
    scored.sort(key=lambda item: (-item[1], item[0]))
    return scored[:limit]


def _row_bytes(row: VectorRow) -> int:
    return len(row.values) * 4 + 96


class VectorCache:
    """An LRU of each (user, model)'s vectors, at most *max_bytes* in all.
    A write to a user's knowledge base drops that user's entries."""

    def __init__(self, max_bytes: int = VECTOR_CACHE_BYTES) -> None:
        self._max_bytes = max_bytes
        self._entries: OrderedDict[tuple[str, str], tuple[list[VectorRow], int]] = OrderedDict()
        self._bytes = 0
        self._lock = threading.Lock()

    def get(self, user_id: str, model: str) -> Optional[list[VectorRow]]:
        key = (str(user_id), model)
        with self._lock:
            entry = self._entries.get(key)
            if entry is None:
                return None
            self._entries.move_to_end(key)
            return entry[0]

    def put(self, user_id: str, model: str, rows: list[VectorRow]) -> None:
        key = (str(user_id), model)
        size = sum(_row_bytes(r) for r in rows)
        with self._lock:
            old = self._entries.pop(key, None)
            if old is not None:
                self._bytes -= old[1]
            if size > self._max_bytes:
                return
            self._entries[key] = (rows, size)
            self._bytes += size
            while self._bytes > self._max_bytes and self._entries:
                _key, (_rows, dropped) = self._entries.popitem(last=False)
                self._bytes -= dropped

    def invalidate(self, user_id: Any) -> None:
        owner = str(user_id)
        with self._lock:
            for key in [k for k in self._entries if k[0] == owner]:
                self._bytes -= self._entries.pop(key)[1]

    @property
    def size_bytes(self) -> int:
        with self._lock:
            return self._bytes
