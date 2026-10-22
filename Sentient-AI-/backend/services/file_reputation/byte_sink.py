"""Fingerprints bytes (SHA-256) for the VirusTotal lookups, and hands the bytes of a re-fetched
mail attachment to an approved upload that is waiting for exactly that fingerprint.

Why it exists: every path that looks a file up (an upload in chat, a Telegram document, a mail
attachment, a fingerprint from the Security page) must agree on one thing, the lowercase hex
SHA-256 of the raw bytes, or a cached verdict, a stored row and an approval card would not match.
The helpers here are that one definition: a whole-buffer hash (in a worker thread above 1 MB so
a large file never stalls the event loop), and a streaming hash with a byte cap for readers that
get a file in chunks, so a file over ``MAX_HASH_BYTES`` is refused without being held whole.

The sink: an approved upload of a mail attachment has no bytes of its own (Crawler never keeps
attachments). It re-runs the connector's ``get_attachment_hash`` action through the executor
(scopes, rate limits and the network policy all apply) inside ``with expect(sha256) as sink:``.
The action hashes what it downloaded and calls ``offer(digest, data)``; the bytes reach the sink
only when the digest is the one expected, and otherwise die with the call. The sink is a mutable
object stored in a context variable, so a task the connector starts (which runs in a copy of the
context) still fills the same one. The service hashes the sink's bytes again before sending
anything, so a wrong offer can only lead to a refusal, never to the wrong file being sent.

Standard library only: the Gmail and Outlook connectors import this module.

Used by: services/connectors/google_api/attachment_hash.py and microsoft_api/attachment_hash.py
(hash, then offer), services/file_reputation/service.py (check_bytes, the approved upload).
"""

from __future__ import annotations

import asyncio
import contextlib
import contextvars
import hashlib
import re
from collections.abc import AsyncIterable, Iterable, Iterator
from dataclasses import dataclass
from typing import Any, Optional

# Gmail's own attachment limit; the connectors check the declared size first and never
# download a larger attachment just to fingerprint it.
MAX_HASH_BYTES = 25 * 1024 * 1024
# Above this size the hash runs in a worker thread (hashlib releases the GIL for large
# buffers), so fingerprinting a big upload never blocks other requests.
HASH_IN_THREAD_BYTES = 1024 * 1024

_SHA256_RE = re.compile(r"[0-9a-f]{64}")
_SHA256_ANY_CASE_RE = re.compile(r"[0-9A-Fa-f]{64}")


class TooLargeToHash(Exception):
    """More bytes arrived than the cap allows; nothing was fingerprinted.

    ``limit`` is the cap that was passed. The message names the cap only.
    """

    def __init__(self, limit: int) -> None:
        super().__init__(f"more than {limit} bytes; too large to fingerprint")
        self.limit = limit


def is_sha256(value: Any) -> bool:
    """True when *value* is a fingerprint in its stored form: exactly 64 lowercase hex
    characters, nothing around them."""
    return isinstance(value, str) and _SHA256_RE.fullmatch(value) is not None


def normalise_sha256(value: Any) -> Optional[str]:
    """*value* as a stored fingerprint (surrounding whitespace removed, lowercased) when it is
    64 hex characters; None for anything else. Callers use this on every fingerprint that comes
    from outside (the model, the browser, a stored entry) before it reaches a URL or a query."""
    if not isinstance(value, str):
        return None
    text = value.strip()
    if _SHA256_ANY_CASE_RE.fullmatch(text) is None:
        return None
    return text.lower()


def sha256_hex(data: bytes) -> str:
    """The fingerprint of *data*: lowercase hex SHA-256 of the raw bytes, exactly as given (no
    decoding, no newline translation)."""
    return hashlib.sha256(data).hexdigest()


async def sha256_hex_async(data: bytes) -> str:
    """``sha256_hex`` that moves to a worker thread above ``HASH_IN_THREAD_BYTES``."""
    if len(data) > HASH_IN_THREAD_BYTES:
        return await asyncio.to_thread(sha256_hex, data)
    return sha256_hex(data)


class Sha256Stream:
    """An incremental fingerprint with a byte cap.

    ``update`` raises ``TooLargeToHash`` as soon as the total passes *max_bytes*, so a reader can
    stop downloading at once instead of finishing a file that will be refused anyway.
    """

    def __init__(self, *, max_bytes: int = MAX_HASH_BYTES) -> None:
        if max_bytes < 0:
            raise ValueError("max_bytes must not be negative")
        self._hash = hashlib.sha256()
        self._size = 0
        self._max_bytes = max_bytes

    @property
    def size(self) -> int:
        """Bytes hashed so far."""
        return self._size

    def update(self, chunk: bytes) -> None:
        if not chunk:
            return
        if self._size + len(chunk) > self._max_bytes:
            raise TooLargeToHash(self._max_bytes)
        self._hash.update(chunk)
        self._size += len(chunk)

    def hexdigest(self) -> str:
        return self._hash.hexdigest()


def sha256_of_chunks(
    chunks: Iterable[bytes], *, max_bytes: int = MAX_HASH_BYTES
) -> tuple[str, int]:
    """(fingerprint, size) of the bytes *chunks* yields, in order. Raises ``TooLargeToHash``
    once they pass *max_bytes*; the rest of the iterable is not read."""
    stream = Sha256Stream(max_bytes=max_bytes)
    for chunk in chunks:
        stream.update(chunk)
    return stream.hexdigest(), stream.size


async def sha256_of_stream(
    chunks: AsyncIterable[bytes], *, max_bytes: int = MAX_HASH_BYTES
) -> tuple[str, int]:
    """``sha256_of_chunks`` for an async source (an httpx ``aiter_bytes()``, say). Large chunks
    are hashed in a worker thread, like ``sha256_hex_async``."""
    stream = Sha256Stream(max_bytes=max_bytes)
    async for chunk in chunks:
        if len(chunk) > HASH_IN_THREAD_BYTES:
            await asyncio.to_thread(stream.update, chunk)
        else:
            stream.update(chunk)
    return stream.hexdigest(), stream.size


# -- the sink -------------------------------------------------------------------------------


@dataclass(eq=False)
class _Sink:
    """Where ``offer`` puts the bytes of the one fingerprint an upload is waiting for. Compared
    by identity: two waits for the same fingerprint are two sinks."""

    sha256: str
    data: Optional[bytes] = None


_SINKS: contextvars.ContextVar[tuple[_Sink, ...]] = contextvars.ContextVar(
    "file_reputation_byte_sinks", default=()
)


@contextlib.contextmanager
def expect(sha256: str) -> Iterator[_Sink]:
    """Within the body, an attachment-hash action that computes exactly this fingerprint hands
    its bytes to the yielded sink (``sink.data``). The sink is a mutable object, so a task the
    connector starts (a copied context) still fills the same one. Raises ``ValueError`` for a
    value that is not a fingerprint."""
    digest = normalise_sha256(sha256)
    if digest is None:
        raise ValueError("expect() needs a SHA-256 fingerprint (64 hex characters)")
    sink = _Sink(digest)
    token = _SINKS.set((*_SINKS.get(), sink))
    try:
        yield sink
    finally:
        _SINKS.reset(token)


def offer(sha256: str, data: bytes) -> None:
    """Called by ``get_attachment_hash`` after hashing: gives the bytes to a bound sink that
    expects this fingerprint and has none yet; otherwise does nothing (the bytes die with the
    call). Bytes over ``MAX_HASH_BYTES`` are never taken."""
    digest = normalise_sha256(sha256)
    if digest is None or len(data) > MAX_HASH_BYTES:
        return
    for sink in _SINKS.get():
        if sink.sha256 == digest and sink.data is None:
            sink.data = bytes(data)
