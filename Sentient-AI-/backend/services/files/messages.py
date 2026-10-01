"""The plain sentences a person reads when a file cannot be read, one per
refusal code.

Why it exists: the upload route, Telegram, Slack and the tool results all
refuse files for the same reasons; one module keeps the wording identical
everywhere and free of anything taken from the file (a sentence may name the
file's size or extension, never its name or text).

Stdlib only.
"""

from __future__ import annotations

import math
from typing import Optional

from services.files.limits import (
    MAX_FILES_PER_USER,
    MAX_STORED_BYTES_PER_USER,
    MAX_UPLOADS_PER_HOUR,
    MB,
    UPLOAD,
)

# file_reading's when_denied, repeated here so this module stays free of the
# capability registry (tests hold the two equal).
SWITCHED_OFF = (
    "Reading files is turned off. The owner can turn on 'Read files and documents' "
    "in Settings → Permissions."
)

READABLE_KINDS = (
    "PDF, Word (.docx), PowerPoint (.pptx), Excel (.xlsx), CSV, text, Markdown and HTML files"
)


def _megabytes(size: int, limit: Optional[int] = None) -> str:
    """*size* in MB, whole from 10 MB up. A file over *limit* never reads as
    within it: 15,864,875 bytes against a 15 MB cap is "15.1", not "15"
    (one decimal, rounded up when that is still not over the cap)."""
    value = size / MB
    shown = f"{value:.0f}" if value >= 10 else f"{value:.1f}".rstrip("0").rstrip(".")
    if limit is not None and size > limit and float(shown) <= limit / MB:
        shown = f"{value:.1f}"
        if float(shown) <= limit / MB:
            shown = f"{math.ceil(value * 10) / 10:.1f}"
    return shown


def too_large(size: Optional[int], limit: int = UPLOAD.max_bytes) -> str:
    cap = f"{limit // MB} MB"
    if size is None:
        return f"That file is too large; Crawler reads files up to {cap}. Send a smaller file or a link to it."
    return (
        f"That file is {_megabytes(size, limit)} MB; Crawler reads files up to {cap}. "
        "Send a smaller file or a link to it."
    )


def unsupported(extension: str = "") -> str:
    ext = extension.lower().lstrip(".")
    lead = f"Crawler can't read .{ext} files." if ext and ext.isalnum() and len(ext) <= 8 else (
        "Crawler can't read this kind of file."
    )
    return f"{lead} It reads {READABLE_KINDS}."


LEGACY_OFFICE = (
    "This is an older Office format (.doc/.xls/.ppt). Save it as .docx/.xlsx/.pptx or PDF "
    "and send it again."
)
ENCRYPTED = (
    "This file is password-protected. Save a copy without a password and send it again. "
    "Never send the password in chat."
)
CORRUPT = "This file looks damaged, so it can't be read."
IMAGE_TOO_LARGE = "That image is too large to read (over 40 megapixels)."
UNPACKS_TOO_LARGE = (
    "This file is too large to read once it is unpacked (it holds more than Crawler reads). "
    "Save the part you need as a smaller file."
)
HEIC = "Crawler can't read HEIC photos yet. Send it as a JPEG or PNG instead."
EMPTY = "No text was found in this file."
EMPTY_SCANS = (
    "No text was found in this file: its pages are scans (pictures of text) that this "
    "computer can't read."
)
BUSY = "Crawler is reading other files right now; try again in a minute."
QUOTA_FULL = (
    f"Your file space is full ({MAX_FILES_PER_USER} files / "
    f"{MAX_STORED_BYTES_PER_USER // MB} MB). Ask Crawler to forget files you no longer need."
)
RATE_LIMITED = (
    f"You've sent {MAX_UPLOADS_PER_HOUR} files in the last hour; try again a bit later."
)


def timeout(pages_read: int) -> str:
    if pages_read <= 0:
        return "This file took too long to read."
    unit = "page was" if pages_read == 1 else "pages were"
    return f"This file took too long to read; the first {pages_read} {unit} read."


def for_code(code: str) -> str:
    """The generic sentence for a refusal *code* (callers with more facts
    use the functions above)."""
    return {
        "too_large": too_large(None),
        "unsupported": unsupported(),
        "legacy_office": LEGACY_OFFICE,
        "encrypted": ENCRYPTED,
        "corrupt": CORRUPT,
        "timeout": timeout(0),
        "empty": EMPTY,
        "busy": BUSY,
        "quota_full": QUOTA_FULL,
        "switched_off": SWITCHED_OFF,
        "rate_limited": RATE_LIMITED,
    }.get(code, CORRUPT)
