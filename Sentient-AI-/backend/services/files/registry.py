"""Keeps documents opened from the web or a connector in memory for 30
minutes, per user, so files.read can page through them.

Why it exists: a PDF read by web.fetch_page or a Drive file read by a
connector returns only its first window; the rest must be readable without
fetching it again, but it must not be stored (it is the connected app's
file, not an upload). Each document gets a 128-bit random ``tmp_`` id that
only its user can read. At most 20 documents per user and 64 MB of text per
process are kept; entries expire 30 minutes after their last read, and the
least recently used go first when a cap is reached.
"""

from __future__ import annotations

import secrets
import threading
import time
from collections import OrderedDict
from dataclasses import dataclass
from typing import Callable, Optional

from services.files.limits import REGISTRY_MAX_CHARS, REGISTRY_MAX_PER_USER, REGISTRY_TTL_S
from services.files.sections import Extraction

DOC_ID_PREFIX = "tmp_"


def is_doc_id(value: object) -> bool:
    """True for a string shaped like a registry id (tmp_ + 22 url-safe chars)."""
    if not isinstance(value, str) or not value.startswith(DOC_ID_PREFIX):
        return False
    rest = value[len(DOC_ID_PREFIX):]
    return 16 <= len(rest) <= 43 and all(c.isalnum() or c in "-_" for c in rest)


@dataclass(frozen=True)
class RegisteredDocument:
    extraction: Extraction
    name: str
    source: str


@dataclass
class _Entry:
    document: RegisteredDocument
    chars: int
    last_used: float


class DocumentRegistry:
    """In-memory, per-user store of opened documents (see the module doc)."""

    def __init__(
        self,
        *,
        max_per_user: int = REGISTRY_MAX_PER_USER,
        max_chars: int = REGISTRY_MAX_CHARS,
        ttl_s: float = REGISTRY_TTL_S,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._max_per_user = max_per_user
        self._max_chars = max_chars
        self._ttl_s = ttl_s
        self._clock = clock
        self._entries: OrderedDict[tuple[str, str], _Entry] = OrderedDict()
        self._chars = 0
        self._lock = threading.Lock()

    def put(self, user_id: str, extraction: Extraction, *, name: str, source: str) -> str:
        """Keep *extraction* for *user_id*; its new ``tmp_`` id."""
        doc_id = DOC_ID_PREFIX + secrets.token_urlsafe(16)
        chars = extraction.chars
        with self._lock:
            now = self._clock()
            self._expire(now)
            self._entries[(str(user_id), doc_id)] = _Entry(
                RegisteredDocument(extraction=extraction, name=name, source=source), chars, now
            )
            self._chars += chars
            self._evict(str(user_id))
        return doc_id

    def get(self, user_id: str, doc_id: str) -> Optional[RegisteredDocument]:
        """The document, or None when it is unknown, another user's or
        expired. A read keeps it for another TTL."""
        key = (str(user_id), str(doc_id))
        with self._lock:
            now = self._clock()
            self._expire(now)
            entry = self._entries.get(key)
            if entry is None:
                return None
            entry.last_used = now
            self._entries.move_to_end(key)
            return entry.document

    def __len__(self) -> int:
        with self._lock:
            return len(self._entries)

    def _drop(self, key: tuple[str, str]) -> None:
        entry = self._entries.pop(key, None)
        if entry is not None:
            self._chars -= entry.chars

    def _expire(self, now: float) -> None:
        stale = [k for k, e in self._entries.items() if now - e.last_used > self._ttl_s]
        for key in stale:
            self._drop(key)

    def _evict(self, user_id: str) -> None:
        mine = [k for k in self._entries if k[0] == user_id]
        while len(mine) > self._max_per_user:
            self._drop(mine.pop(0))
        while self._chars > self._max_chars and len(self._entries) > 1:
            self._drop(next(iter(self._entries)))


_default_registry: Optional[DocumentRegistry] = None


def default_registry() -> DocumentRegistry:
    """The process-wide registry used when nothing else was bound."""
    global _default_registry
    if _default_registry is None:
        _default_registry = DocumentRegistry()
    return _default_registry
