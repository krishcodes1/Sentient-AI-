"""Decides what a file is from its bytes (never its name) and refuses the kinds
Crawler does not read, with a hint that says what to do instead.

Why it exists: a file's name and declared type come from whoever sent it, so a
hostile ".pdf" could be anything. The magic bytes decide the parser; a zip is
opened (bounded) to tell a Word, PowerPoint or Excel file apart; OLE files
(legacy Office, or an encrypted modern one), HEIC photos, archives and
executables are refused before any parser runs. A name or declared type that
disagrees with the bytes is recorded as the ``mime_mismatch`` warning.

Stdlib only; used in the parent process before the worker starts, and by the
connectors and web tool through ``is_document_type``.
"""

from __future__ import annotations

import io
import zipfile
from dataclasses import dataclass
from typing import Optional

from services.files import messages
from services.files.sections import ExtractionRefused

PDF_MIME = "application/pdf"
DOCX_MIME = "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
PPTX_MIME = "application/vnd.openxmlformats-officedocument.presentationml.presentation"
XLSX_MIME = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"

DOCUMENT_MIMES: dict[str, str] = {
    PDF_MIME: "pdf",
    DOCX_MIME: "docx",
    PPTX_MIME: "pptx",
    XLSX_MIME: "xlsx",
}
DOCUMENT_EXTENSIONS: dict[str, str] = {
    ".pdf": "pdf",
    ".docx": "docx",
    ".pptx": "pptx",
    ".xlsx": "xlsx",
}
LEGACY_OFFICE_EXTENSIONS = (".doc", ".xls", ".ppt")

_TEXT_EXTENSIONS: dict[str, str] = {
    ".txt": "text",
    ".text": "text",
    ".log": "text",
    ".md": "markdown",
    ".markdown": "markdown",
    ".csv": "csv",
    ".tsv": "csv",
    ".json": "json",
    ".html": "html",
    ".htm": "html",
}

_KIND_MIME: dict[str, str] = {
    "pdf": PDF_MIME,
    "docx": DOCX_MIME,
    "pptx": PPTX_MIME,
    "xlsx": XLSX_MIME,
    "text": "text/plain",
    "markdown": "text/markdown",
    "csv": "text/csv",
    "json": "application/json",
    "html": "text/html",
}

_OLE_MAGIC = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"
_ENCRYPTED_OOXML_MARK = "EncryptionInfo".encode("utf-16-le")
_HEIC_BRANDS = (b"heic", b"heix", b"hevc", b"hevx", b"mif1", b"msf1", b"heim", b"heis")
_IMAGE_MAGIC: tuple[tuple[bytes, str], ...] = (
    (b"\x89PNG\r\n\x1a\n", "image/png"),
    (b"\xff\xd8\xff", "image/jpeg"),
    (b"GIF87a", "image/gif"),
    (b"GIF89a", "image/gif"),
    (b"BM", "image/bmp"),
    (b"II*\x00", "image/tiff"),
    (b"MM\x00*", "image/tiff"),
)
# Binaries that are never documents: executables, archives, media.
_BINARY_MAGIC: tuple[bytes, ...] = (
    b"MZ",
    b"\x7fELF",
    b"\x1f\x8b",
    b"7z\xbc\xaf\x27\x1c",
    b"Rar!",
    b"\xfe\xed\xfa",
    b"\xcf\xfa\xed\xfe",
    b"ID3",
    b"OggS",
    b"fLaC",
    b"\x1aE\xdf\xa3",
)
# Zip members read to tell the Office kinds apart, and how much of the
# directory is looked at before giving up (the worker applies the full zip
# limits when it parses).
_ZIP_NAMES_LOOKED_AT = 5000


@dataclass(frozen=True)
class Detection:
    """What a file is: its kind (pdf, docx, pptx, xlsx, csv, text,
    markdown, html, json or image), the media type that goes with it, the
    CSV delimiter for a tab-separated file, and warning codes."""

    kind: str
    media_type: str
    warnings: tuple[str, ...] = ()
    delimiter: str = ","


def extension_of(name: Optional[str]) -> str:
    """The lower-case extension of *name* (".pdf"), or ""."""
    if not name:
        return ""
    base = name.replace("\\", "/").rsplit("/", 1)[-1]
    if "." not in base:
        return ""
    return "." + base.rsplit(".", 1)[-1].lower()[:16]


def _declared(mime: Optional[str]) -> str:
    return (mime or "").split(";", 1)[0].strip().lower()


def is_document_type(mime: Optional[str], name: Optional[str]) -> bool:
    """True when a connector or web response looks like a PDF, Word,
    PowerPoint or Excel file by its declared type or its name. This only
    picks the document path; the bytes still decide (``detect``)."""
    if _declared(mime) in DOCUMENT_MIMES:
        return True
    return extension_of(name) in DOCUMENT_EXTENSIONS


def looks_like_document(data: bytes) -> bool:
    """True when *data* starts like a PDF, an Office zip or an OLE container
    (a legacy .doc/.xls/.ppt, or a password-protected modern file): for a
    response declared ``application/octet-stream``. ``detect`` refuses an
    OLE file with its own sentence before any worker starts."""
    head = data[:1024]
    return b"%PDF-" in head or data[:4] == b"PK\x03\x04" or data[:8] == _OLE_MAGIC


def _ooxml_kind(data: bytes) -> Optional[str]:
    """docx, pptx or xlsx for an Office Open XML zip, "odf" for an
    OpenDocument file, else None."""
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            names = set()
            for index, info in enumerate(archive.infolist()):
                if index >= _ZIP_NAMES_LOOKED_AT:
                    break
                names.add(info.filename)
    except (zipfile.BadZipFile, OSError, ValueError, RuntimeError, NotImplementedError):
        raise ExtractionRefused("corrupt", messages.CORRUPT) from None
    if "word/document.xml" in names:
        return "docx"
    if "ppt/presentation.xml" in names:
        return "pptx"
    if "xl/workbook.xml" in names:
        return "xlsx"
    if "mimetype" in names and any(n.startswith("META-INF/") for n in names):
        return "odf"
    return None


def _looks_like_text(data: bytes) -> bool:
    head = data[:8192]
    if head.startswith((b"\xef\xbb\xbf", b"\xff\xfe", b"\xfe\xff")):
        return True
    if b"\x00" in head:
        return False
    # Mostly printable: control bytes other than tab, CR, LF, FF are rare
    # in text and common in binaries.
    controls = sum(1 for b in head if b < 32 and b not in (9, 10, 12, 13))
    return controls <= max(2, len(head) // 100)


def _text_kind(data: bytes, name: Optional[str], declared: str) -> tuple[str, str]:
    ext = extension_of(name)
    kind = _TEXT_EXTENSIONS.get(ext)
    if kind is None:
        if declared in ("text/html", "application/xhtml+xml"):
            kind = "html"
        elif declared == "text/csv":
            kind = "csv"
        elif declared == "text/tab-separated-values":
            kind = "csv"
            ext = ".tsv"
        elif declared == "application/json":
            kind = "json"
        elif declared == "text/markdown":
            kind = "markdown"
        else:
            sniff = data[:512].lstrip().lower()
            kind = "html" if sniff.startswith((b"<!doctype html", b"<html")) else "text"
    delimiter = "\t" if ext == ".tsv" else ","
    return kind, delimiter


def detect(data: bytes, *, name: Optional[str] = None, declared_mime: Optional[str] = None) -> Detection:
    """The kind of *data*. Raises ExtractionRefused (unsupported,
    legacy_office, encrypted, corrupt or empty) for what Crawler does not
    read."""
    if not data:
        raise ExtractionRefused("empty", messages.EMPTY)
    declared = _declared(declared_mime)
    ext = extension_of(name)
    kind: Optional[str] = None
    media_type = ""
    delimiter = ","

    if b"%PDF-" in data[:1024]:
        kind = "pdf"
    elif data[:4] in (b"PK\x03\x04", b"PK\x05\x06"):
        ooxml = _ooxml_kind(data)
        if ooxml == "odf":
            raise ExtractionRefused("unsupported", messages.unsupported(ext or ".odt"))
        if ooxml is None:
            raise ExtractionRefused("unsupported", messages.unsupported(ext if ext != ".pdf" else ".zip"))
        kind = ooxml
    elif data[:8] == _OLE_MAGIC:
        if _ENCRYPTED_OOXML_MARK in data:
            raise ExtractionRefused("encrypted", messages.ENCRYPTED)
        raise ExtractionRefused("legacy_office", messages.LEGACY_OFFICE)
    elif data[4:8] == b"ftyp" and data[8:12] in _HEIC_BRANDS:
        raise ExtractionRefused("unsupported", messages.HEIC)
    elif data[:4] == b"RIFF" and data[8:12] == b"WEBP":
        kind, media_type = "image", "image/webp"
    else:
        for magic, image_type in _IMAGE_MAGIC:
            if data.startswith(magic):
                kind, media_type = "image", image_type
                break
    if kind is None:
        if data.startswith(_BINARY_MAGIC) or data[4:8] == b"ftyp":
            raise ExtractionRefused("unsupported", messages.unsupported(ext))
        if not _looks_like_text(data):
            raise ExtractionRefused("unsupported", messages.unsupported(ext))
        kind, delimiter = _text_kind(data, name, declared)

    if not media_type:
        media_type = _KIND_MIME[kind]

    warnings: list[str] = []
    ext_kind = DOCUMENT_EXTENSIONS.get(ext)
    declared_kind = DOCUMENT_MIMES.get(declared)
    if (ext_kind is not None and ext_kind != kind) or (
        declared_kind is not None and declared_kind != kind
    ):
        warnings.append("mime_mismatch")
    elif ext in LEGACY_OFFICE_EXTENSIONS:
        warnings.append("mime_mismatch")
    return Detection(kind=kind, media_type=media_type, warnings=tuple(warnings), delimiter=delimiter)
