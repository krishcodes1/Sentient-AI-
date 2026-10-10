"""Reads plain-text files: .txt, .md, .csv/.tsv, .json and .html.

Why it exists: text files need only decoding, but "only" hides the usual
traps: byte-order marks, UTF-16, and Windows-1252 files that are not UTF-8.
Decoding tries a BOM first, then strict UTF-8, then cp1252 (with
replacement). CSV and TSV rows are read with the csv module (at most
MAX_CSV_ROWS rows, 60 columns and 1000 characters per cell) and grouped into
"Rows 1-120" units; JSON is pretty-printed when it parses; HTML goes through
the same readable-text extraction as web.fetch_page (services.tools.html_text,
stdlib only). Anything else is one unit the parent splits into parts.
"""

from __future__ import annotations

import csv
import io
import json
from typing import Any

from services.files.limits import MAX_CELL_CHARS, MAX_XLSX_COLUMNS, SECTION_TARGET_CHARS
from services.files.worker.protocol import Emitter

MAX_CSV_ROWS = 20_000
_PRETTY_JSON_LIMIT = 5 * 1024 * 1024


def decode(data: bytes) -> str:
    """*data* as text: a BOM wins, then strict UTF-8, then cp1252."""
    if data.startswith(b"\xef\xbb\xbf"):
        return data[3:].decode("utf-8", "replace")
    if data.startswith((b"\xff\xfe", b"\xfe\xff")):
        return data.decode("utf-16", "replace")
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return data.decode("cp1252", "replace")


def _csv_units(text: str, delimiter: str, emit: Emitter) -> bool:
    """Emit the rows of a CSV/TSV; True when rows were cut. A file the csv
    module refuses raises csv.Error, and the caller reads it as plain text."""
    reader = csv.reader(io.StringIO(text), delimiter=delimiter)
    lines: list[str] = []
    size = 0
    first = last = 0
    truncated = False
    for number, row in enumerate(reader, start=1):
        if number > MAX_CSV_ROWS:
            truncated = True
            break
        cells = [" ".join(c.split())[:MAX_CELL_CHARS] for c in row[:MAX_XLSX_COLUMNS]]
        while cells and not cells[-1]:
            cells.pop()
        if not cells:
            continue
        line = "\t".join(cells)
        if lines and size + len(line) > SECTION_TARGET_CHARS:
            emit.unit(f"Rows {first}-{last}", None, "\n".join(lines))
            lines, size = [], 0
        if not lines:
            first = number
        lines.append(line)
        size += len(line) + 1
        last = number
    if lines:
        emit.unit(f"Rows {first}-{last}", None, "\n".join(lines))
    return truncated


def parse(data: bytes, header: dict[str, Any], emit: Emitter) -> None:
    kind = str(header.get("kind") or "text")
    text = decode(data)
    title = ""
    truncated = False
    if kind == "html":
        from services.tools.html_text import extract_readable_text

        title, text = extract_readable_text(text)
    elif kind == "json" and len(data) <= _PRETTY_JSON_LIMIT:
        try:
            text = json.dumps(json.loads(text), indent=1, ensure_ascii=False)
        except (ValueError, RecursionError):
            pass
    emit.meta(title=title[:300], pages_total=None)
    if kind == "csv":
        delimiter = str(header.get("delimiter") or ",")[:1] or ","
        try:
            truncated = _csv_units(text, delimiter, emit)
        except csv.Error:
            emit.warn("csv_unparsed")
            emit.unit("", None, text)
    elif text.strip():
        emit.unit("", None, text)
    emit.done(truncated=truncated)
