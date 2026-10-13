"""The NDJSON lines the parser worker writes and the parent reads.

Why it exists: the worker and the sandbox (and the in-process sandbox the
tests use) must agree on one small, line-based format, so a partial read
(the deadline killed the worker) still yields every complete line. One JSON
object per line, each with a type ``t``:

- ``{"t": "meta", "title": str, "pages_total": int | null}``
- ``{"t": "unit", "label": str, "page": int | null, "text": str, "src": "text"}``
- ``{"t": "scan", "page": int}``: a scanned page left unread
- ``{"t": "warn", "code": str}``: a warning code, never text
- ``{"t": "error", "code": str}``: a refusal (encrypted, corrupt ...)
- ``{"t": "done", "truncated": bool}``

The header the parent writes first is one JSON line too:
``{"v": 1, "kind": str, "size": int, "deadline_s": float,
"max_pages": int, "ocr_pages": int, "delimiter": str}``, followed by exactly
``size`` bytes of the file.

Stdlib only.
"""

from __future__ import annotations

import json
from typing import Any, Callable, Optional

PROTOCOL_VERSION = 1
MAX_HEADER_BYTES = 4096
# The most text one line carries: escaped, even a worst case (six bytes per
# control character) stays well under the parent's 1 MB line cap.
UNIT_CHUNK_CHARS = 100_000


def _chunks(text: str) -> list[str]:
    if len(text) <= UNIT_CHUNK_CHARS:
        return [text]
    pieces: list[str] = []
    rest = text
    while len(rest) > UNIT_CHUNK_CHARS:
        cut = rest.rfind("\n", UNIT_CHUNK_CHARS // 2, UNIT_CHUNK_CHARS)
        cut = cut + 1 if cut != -1 else UNIT_CHUNK_CHARS
        pieces.append(rest[:cut])
        rest = rest[cut:]
    if rest:
        pieces.append(rest)
    return pieces


class ParseError(Exception):
    """A parser refusing a file, with a refusal code (encrypted, corrupt,
    unsupported, too_large, image_too_large, empty)."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def encode(message: dict[str, Any]) -> bytes:
    """One protocol line. ``json.dumps`` escapes every control character,
    so a line break inside text can never end the line early."""
    return json.dumps(message, ensure_ascii=False, separators=(",", ":")).encode("utf-8") + b"\n"


def encode_header(
    *,
    kind: str,
    size: int,
    deadline_s: float,
    max_pages: int,
    ocr_pages: int,
    delimiter: str = ",",
) -> bytes:
    return encode(
        {
            "v": PROTOCOL_VERSION,
            "kind": kind,
            "size": size,
            "deadline_s": deadline_s,
            "max_pages": max_pages,
            "ocr_pages": ocr_pages,
            "delimiter": delimiter,
        }
    )


class Emitter:
    """What a parser reports through; each call writes one line."""

    def __init__(self, write: Callable[[bytes], None]) -> None:
        self._write = write

    def meta(self, *, title: str = "", pages_total: Optional[int] = None) -> None:
        self._write(encode({"t": "meta", "title": title[:300], "pages_total": pages_total}))

    def unit(self, label: str, page: Optional[int], text: str, src: str = "text") -> None:
        """One unit of text. A long one goes out as several lines of at
        most UNIT_CHUNK_CHARS characters (cut at a line break where there
        is one), so no line nears the parent's 1 MB line cap even when every
        character is escaped; a labelled unit's later pieces say "cont."."""
        for index, piece in enumerate(_chunks(text)):
            piece_label = label if index == 0 or not label else f"{label} (cont. {index + 1})"
            self._write(
                encode({"t": "unit", "label": piece_label[:200], "page": page, "text": piece, "src": src})
            )

    def scan(self, page: int) -> None:
        self._write(encode({"t": "scan", "page": page}))

    def warn(self, code: str) -> None:
        self._write(encode({"t": "warn", "code": code[:64]}))

    def error(self, code: str) -> None:
        self._write(encode({"t": "error", "code": code[:64]}))

    def done(self, *, truncated: bool = False) -> None:
        self._write(encode({"t": "done", "truncated": bool(truncated)}))
