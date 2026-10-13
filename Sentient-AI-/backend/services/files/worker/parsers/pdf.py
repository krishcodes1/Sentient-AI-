"""Reads a PDF's text layer page by page with pypdf.

Why it exists: PDFs are the most common document a student sends. Each page
becomes one unit labelled with its page label ("Page 3", or "Page iv" where
the PDF numbers its front matter), a page that is a scan (little or no text
over an embedded image) is reported as unread, and text drawn invisibly
(render mode 3) on a page with no scan behind it is flagged as
``hidden_text``: it is a known way to hide instructions for a model. A PDF
whose user password is empty is opened (``encrypted_empty_password``); a
real password is refused, never asked for. At most MAX_PDF_PAGES pages are
read. pypdf 6 bounds its own stream decompression.
"""

from __future__ import annotations

import io
import re
from typing import Any, Optional

from services.files.limits import MAX_PDF_PAGES
from services.files.worker.protocol import Emitter, ParseError

# A page with fewer characters than this over an image is a scan.
_SCAN_TEXT_CHARS = 20
# How much of a page's content stream is searched for invisible text.
_CONTENT_SCAN_BYTES = 2 * 1024 * 1024
_INVISIBLE_RENDER = re.compile(rb"(?:^|[\s\]])3\s+Tr\b")


def _open(data: bytes) -> Any:
    from pypdf import PdfReader

    try:
        return PdfReader(io.BytesIO(data), strict=False)
    except Exception:  # noqa: BLE001 - pypdf raises many types for bad files
        raise ParseError("corrupt") from None


def _decrypt(reader: Any, emit: Emitter) -> None:
    if not reader.is_encrypted:
        return
    try:
        result = reader.decrypt("")
    except Exception:  # noqa: BLE001 - an unsupported algorithm is a refusal too
        raise ParseError("encrypted") from None
    if not result:
        raise ParseError("encrypted")
    emit.warn("encrypted_empty_password")


def _title(reader: Any) -> str:
    try:
        meta = reader.metadata
        title = meta.title if meta is not None else None
    except Exception:  # noqa: BLE001 - a broken info dictionary is no title
        return ""
    return title.strip()[:300] if isinstance(title, str) else ""


def _labels(reader: Any, count: int) -> list[str]:
    try:
        labels = list(reader.page_labels)
    except Exception:  # noqa: BLE001 - fall back to physical numbers
        labels = []
    if len(labels) < count:
        labels += [str(i + 1) for i in range(len(labels), count)]
    return [str(label)[:40] if str(label).strip() else str(i + 1) for i, label in enumerate(labels)]


def _has_image(page: Any) -> bool:
    """True when the page draws an image XObject (directly or one form
    level down): what a scanned page is made of."""
    try:
        resources = page.get("/Resources")
        resources = resources.get_object() if resources is not None else None
        xobjects = resources.get("/XObject") if resources is not None else None
        xobjects = xobjects.get_object() if xobjects is not None else None
        if not xobjects:
            return False
        for ref in list(xobjects.values())[:200]:
            obj = ref.get_object()
            subtype = obj.get("/Subtype")
            if subtype == "/Image":
                return True
            if subtype == "/Form":
                inner = obj.get("/Resources")
                inner = inner.get_object() if inner is not None else None
                inner_x = inner.get("/XObject") if inner is not None else None
                inner_x = inner_x.get_object() if inner_x is not None else None
                if inner_x and any(
                    r.get_object().get("/Subtype") == "/Image" for r in list(inner_x.values())[:200]
                ):
                    return True
    except Exception:  # noqa: BLE001 - an unreadable resource tree has no scan
        return False
    return False


def _draws_invisible_text(page: Any) -> bool:
    try:
        contents = page.get_contents()
        if contents is None:
            return False
        data = contents.get_data()[:_CONTENT_SCAN_BYTES]
    except Exception:  # noqa: BLE001 - unreadable content has nothing to flag
        return False
    return _INVISIBLE_RENDER.search(data) is not None


def parse(data: bytes, header: dict[str, Any], emit: Emitter) -> None:
    reader = _open(data)
    _decrypt(reader, emit)
    try:
        total = len(reader.pages)
    except Exception:  # noqa: BLE001
        raise ParseError("corrupt") from None
    max_pages = int(header.get("max_pages") or MAX_PDF_PAGES)
    max_pages = max(1, min(max_pages, MAX_PDF_PAGES))
    emit.meta(title=_title(reader), pages_total=total)
    labels = _labels(reader, min(total, max_pages))
    hidden = False
    unreadable = False
    for index in range(min(total, max_pages)):
        try:
            page = reader.pages[index]
        except Exception:  # noqa: BLE001
            unreadable = True
            continue
        try:
            text: Optional[str] = page.extract_text()
        except Exception:  # noqa: BLE001 - one bad page is skipped, not fatal
            text = ""
            unreadable = True
        text = text or ""
        has_image = _has_image(page)
        number = index + 1
        if has_image and len(text.strip()) < _SCAN_TEXT_CHARS:
            emit.scan(number)
            continue
        if not has_image and _draws_invisible_text(page):
            hidden = True
        if text.strip():
            emit.unit(f"Page {labels[index]}", number, text)
    if hidden:
        emit.warn("hidden_text")
    if unreadable:
        emit.warn("page_unreadable")
    emit.done(truncated=total > max_pages)
