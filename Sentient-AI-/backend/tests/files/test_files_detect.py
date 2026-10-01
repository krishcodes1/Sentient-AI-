"""Tests for services/files/detect.py: the type comes from the bytes, never the
name; zip inspection tells Word, PowerPoint and Excel apart; OLE, HEIC and
plain zips are refused with a hint; a name that disagrees is a warning.

Why it exists: the parser a hostile file reaches is chosen here, so a wrong
answer (a ".pdf" that is really a zip) must never pick the wrong parser.
"""

from __future__ import annotations

import io
import zipfile

import pytest

from services.files.detect import detect, is_document_type, looks_like_document
from services.files.sections import ExtractionRefused
from tests.files import builders as b


def test_magic_beats_the_extension():
    found = detect(b.make_docx(), name="notes.pdf", declared_mime="application/pdf")
    assert found.kind == "docx"
    assert "mime_mismatch" in found.warnings


def test_each_office_kind_is_told_apart_by_its_members():
    assert detect(b.make_docx(), name="a").kind == "docx"
    assert detect(b.make_pptx([("T", "B", "")]), name="a").kind == "pptx"
    assert detect(b.make_xlsx({"S": [[1]]}), name="a").kind == "xlsx"
    assert detect(b.make_pdf(["x"]), name="a").kind == "pdf"


def test_octet_stream_is_resolved_by_the_magic_bytes():
    found = detect(b.make_pdf(["x"]), name="download", declared_mime="application/octet-stream")
    assert found.kind == "pdf" and found.media_type == "application/pdf"
    assert looks_like_document(b.make_pdf(["x"]))
    assert not looks_like_document(b"<html>")


@pytest.mark.parametrize(
    "data,code",
    [
        (b.OLE_HEADER, "legacy_office"),
        (b.OLE_HEADER + "EncryptionInfo".encode("utf-16-le"), "encrypted"),
        (b"\x00\x00\x00\x18ftypheic" + b"\0" * 32, "unsupported"),
        (b"MZ\x90\x00" + b"\0" * 64, "unsupported"),
        (b"", "empty"),
    ],
)
def test_refused_kinds(data, code):
    with pytest.raises(ExtractionRefused) as refused:
        detect(data, name="file.doc")
    assert refused.value.code == code
    assert refused.value.message


def test_a_zip_that_is_not_office_is_refused():
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w") as archive:
        archive.writestr("readme.txt", "hi")
    with pytest.raises(ExtractionRefused) as refused:
        detect(out.getvalue(), name="bundle.zip")
    assert refused.value.code == "unsupported"


def test_heic_gets_its_own_hint():
    with pytest.raises(ExtractionRefused) as refused:
        detect(b"\x00\x00\x00\x18ftypheic" + b"\0" * 32, name="IMG_1.HEIC")
    assert "JPEG" in refused.value.message


def test_text_kinds_follow_the_name_or_the_declared_type():
    assert detect(b"a,b\n1,2\n", name="grades.csv").kind == "csv"
    tsv = detect(b"a\tb\n", name="grades.tsv")
    assert tsv.kind == "csv" and tsv.delimiter == "\t"
    assert detect(b"# Title\n", name="notes.md").kind == "markdown"
    assert detect(b'{"a": 1}', name="x", declared_mime="application/json").kind == "json"
    assert detect(b"<!DOCTYPE html><p>x", name="page").kind == "html"
    assert detect(b"plain words", name="notes").kind == "text"
    assert detect(b"\xff\xfeh\x00i\x00", name="u16.txt").kind == "text"


def test_images_are_images():
    assert detect(b.png(), name="x.pdf").kind == "image"


def test_is_document_type_by_mime_or_name():
    assert is_document_type("application/pdf", None)
    assert is_document_type(None, "Week 5 Notes.DOCX")
    assert is_document_type("application/octet-stream", "deck.pptx")
    assert not is_document_type("text/plain", "notes.txt")
    assert not is_document_type("application/msword", "old.doc")
