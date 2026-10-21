"""Keeps the bytes of a file that may be sent to VirusTotal after an approval card, in memory
only, per user and fingerprint, for a limited time.

Why it exists: Crawler never stores the original bytes of an upload (services/files/store.py
keeps extracted text). Telegram files and mail attachments can be fetched again when a card is
approved, but a web-chat or Slack upload, and a file the owner picks on the Security page,
cannot; for those the bytes wait here. The holder is bounded on purpose (64 MB in all, 3 files
per user, least-recently-used eviction with pinned entries last, a TTL per entry) and is never
written anywhere, so a restart empties it and an approved card then refuses instead of sending
anything (resolution S10).

``explicit=True`` marks bytes the owner picked on the Security page. Only such an entry lets a
file that is not risky (a PDF, a plain Office file, a picture) past the toolkit's
``personal_document`` precheck (review SEC-F2), so a model steered by injected text can never
propose a card that uploads a personal document someone merely sent in chat.

One user never reads another user's entry: every key is (user id, fingerprint).

Used by: services/file_reputation/service.py (intake, request_upload, the approved upload,
forget) and toolkit.py (``has_explicit``, ``pin`` when a card is bound).
"""

from __future__ import annotations

import time
from collections import OrderedDict
from collections.abc import Callable
from dataclasses import dataclass
from typing import Optional

import structlog

from services.file_reputation.byte_sink import normalise_sha256

logger = structlog.get_logger(__name__)

MB = 1024 * 1024

_Key = tuple[str, str]


@dataclass
class _Entry:
    data: bytes
    expires_at: float
    explicit: bool
    pinned: bool


class ByteHolder:
    """Bytes of files that may be sent to VirusTotal after an approval, in memory only, per user
    and fingerprint. Bounded: 64 MB in all, 3 files per user, least-recently-used eviction
    (pinned entries last). Gone after a restart by design."""

    def __init__(
        self,
        *,
        max_total_bytes: int = 64 * MB,
        max_per_user: int = 3,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        if max_total_bytes <= 0 or max_per_user <= 0:
            raise ValueError("the holder needs room for at least one file")
        self._max_total = max_total_bytes
        self._max_per_user = max_per_user
        self._clock = clock
        # Least recently used first.
        self._entries: OrderedDict[_Key, _Entry] = OrderedDict()
        self._total = 0

    # -- reading -----------------------------------------------------------------------------

    @property
    def total_bytes(self) -> int:
        return self._total

    def __len__(self) -> int:
        return len(self._entries)

    def _key(self, user_id: str, sha256: str) -> Optional[_Key]:
        digest = normalise_sha256(sha256)
        if not user_id or digest is None:
            return None
        return (str(user_id), digest)

    def _live(self, key: Optional[_Key]) -> Optional[_Entry]:
        if key is None:
            return None
        entry = self._entries.get(key)
        if entry is None:
            return None
        if entry.expires_at <= self._clock():
            self._remove(key)
            return None
        return entry

    def get(self, user_id: str, sha256: str) -> Optional[bytes]:
        """The held bytes, or None when there are none (never held, expired, evicted, or held
        for another user). Reading counts as a use for the eviction order."""
        key = self._key(user_id, sha256)
        entry = self._live(key)
        if entry is None or key is None:
            return None
        self._entries.move_to_end(key)
        return entry.data

    def has(self, user_id: str, sha256: str) -> bool:
        return self._live(self._key(user_id, sha256)) is not None

    def has_explicit(self, user_id: str, sha256: str) -> bool:
        """True when the owner picked these bytes on the Security page (``explicit=True``)."""
        entry = self._live(self._key(user_id, sha256))
        return entry is not None and entry.explicit

    # -- writing -----------------------------------------------------------------------------

    def put(
        self, user_id: str, sha256: str, data: bytes, *, ttl_s: float, explicit: bool = False
    ) -> None:
        """Hold *data* for *ttl_s* seconds. A file larger than the whole holder is not held.
        Holding the same file again keeps the later expiry and stays explicit once it was."""
        key = self._key(user_id, sha256)
        if key is None or not data or ttl_s <= 0:
            return
        if len(data) > self._max_total:
            logger.info("file_reputation_bytes_not_held", reason="too_large", size=len(data))
            return
        now = self._clock()
        self._expire(now)
        old = self._entries.get(key)
        entry = _Entry(
            data=bytes(data), expires_at=now + ttl_s, explicit=explicit, pinned=False
        )
        if old is not None:
            entry.expires_at = max(entry.expires_at, old.expires_at)
            entry.explicit = entry.explicit or old.explicit
            entry.pinned = old.pinned
            self._remove(key)
        self._entries[key] = entry
        self._total += len(entry.data)
        self._evict(keep=key)

    def pin(self, user_id: str, sha256: str, *, ttl_s: float) -> bool:
        """Keep an entry at least ttl_s longer (a card was made for it); False when gone."""
        key = self._key(user_id, sha256)
        entry = self._live(key)
        if entry is None or key is None:
            return False
        entry.expires_at = max(entry.expires_at, self._clock() + max(ttl_s, 0.0))
        entry.pinned = True
        self._entries.move_to_end(key)
        return True

    def drop(self, user_id: str, sha256: str) -> None:
        key = self._key(user_id, sha256)
        if key is not None and key in self._entries:
            self._remove(key)

    def drop_user(self, user_id: str) -> None:
        """Forget every file held for *user_id* (their account went away)."""
        for key in [key for key in self._entries if key[0] == str(user_id)]:
            self._remove(key)

    # -- internals ---------------------------------------------------------------------------

    def _remove(self, key: _Key) -> None:
        entry = self._entries.pop(key)
        self._total -= len(entry.data)

    def _expire(self, now: float) -> None:
        for key in [key for key, entry in self._entries.items() if entry.expires_at <= now]:
            self._remove(key)

    def _victim(self, keys: list[_Key]) -> Optional[_Key]:
        """The least recently used unpinned key among *keys*, else the least recently used
        pinned one."""
        for key in keys:
            if not self._entries[key].pinned:
                return key
        return keys[0] if keys else None

    def _evict(self, *, keep: _Key) -> None:
        user = keep[0]
        while True:
            mine = [key for key in self._entries if key[0] == user and key != keep]
            if len(mine) + 1 <= self._max_per_user:
                break
            victim = self._victim(mine)
            if victim is None:
                break
            self._remove(victim)
        while self._total > self._max_total:
            others = [key for key in self._entries if key != keep]
            victim = self._victim(others)
            if victim is None:
                break
            self._remove(victim)
