"""Builds the documents the file tests read, in memory: minimal hand-made PDFs
(text, scanned, invisible text, page labels, encrypted), Word, PowerPoint and
Excel files, and the attack files (zip bombs, XML entities, an image bomb).

Why it exists: the tests need real files of every kind without checking
binaries into the repository, and the attack files must be built exactly at
the edge of each limit. Nothing here touches the network.
"""

from __future__ import annotations

import io
import struct
import zipfile
import zlib
from typing import Optional, Sequence

# -- PDF ----------------------------------------------------------------------


def _pdf_escape(text: str) -> str:
    return text.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")


def _text_stream(text: str, *, invisible: bool = False) -> bytes:
    lines = text.split("\n")
    ops = ["BT", "/F1 12 Tf", "14 TL", "72 720 Td"]
    if invisible:
        ops.append("3 Tr")
    for index, line in enumerate(lines):
        if index:
            ops.append("T*")
        ops.append(f"({_pdf_escape(line)}) Tj")
    ops.append("ET")
    return "\n".join(ops).encode("latin-1")


def _assemble(objects: list[bytes]) -> bytes:
    """Objects 1..n (object 1 the catalog) into a PDF with an xref."""
    out = bytearray(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
    offsets = []
    for number, body in enumerate(objects, start=1):
        offsets.append(len(out))
        out += f"{number} 0 obj\n".encode() + body + b"\nendobj\n"
    xref = len(out)
    out += f"xref\n0 {len(objects) + 1}\n".encode()
    out += b"0000000000 65535 f \n"
    for offset in offsets:
        out += f"{offset:010d} 00000 n \n".encode()
    out += f"trailer\n<< /Size {len(objects) + 1} /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF\n".encode()
    return bytes(out)


def _stream(data: bytes, extra: str = "") -> bytes:
    return f"<< /Length {len(data)} {extra}>>\nstream\n".encode() + data + b"\nendstream"


def make_pdf(
    pages: Sequence[str],
    *,
    scanned: Sequence[int] = (),
    invisible: Sequence[int] = (),
    labels: Optional[str] = None,
) -> bytes:
    """A PDF with one text page per entry of *pages*. Pages whose 1-based
    number is in *scanned* hold only an image (a scan); those in *invisible*
    draw their text in render mode 3. *labels* is a raw /PageLabels number
    tree (e.g. "<< /Nums [0 << /S /r >> 2 << /S /D >>] >>")."""
    # 1 catalog, 2 pages, 3 font, 4 image, then per page: page, content.
    count = len(pages)
    kids = " ".join(f"{5 + 2 * i} 0 R" for i in range(count))
    catalog = "<< /Type /Catalog /Pages 2 0 R"
    if labels:
        catalog += f" /PageLabels {labels}"
    catalog += " >>"
    objects: list[bytes] = [
        catalog.encode(),
        f"<< /Type /Pages /Kids [{kids}] /Count {count} >>".encode(),
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
        _stream(
            b"\x80\x40\x20\x10",
            "/Type /XObject /Subtype /Image /Width 2 /Height 2 /ColorSpace /DeviceGray /BitsPerComponent 8 ",
        ),
    ]
    for index, text in enumerate(pages):
        number = index + 1
        content_ref = 6 + 2 * index
        if number in scanned:
            resources = "<< /XObject << /Im1 4 0 R >> >>"
            content = b"q 400 0 0 500 100 100 cm /Im1 Do Q"
        else:
            resources = "<< /Font << /F1 3 0 R >> >>"
            content = _text_stream(text, invisible=number in invisible)
        objects.append(
            (
                f"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] "
                f"/Resources {resources} /Contents {content_ref} 0 R >>"
            ).encode()
        )
        objects.append(_stream(content))
    return _assemble(objects)


def make_encrypted_pdf(pages: Sequence[str], *, user_password: str) -> bytes:
    """make_pdf(pages) encrypted with *user_password* ("" opens without one)."""
    from pypdf import PdfReader, PdfWriter

    writer = PdfWriter()
    for page in PdfReader(io.BytesIO(make_pdf(pages))).pages:
        writer.add_page(page)
    writer.encrypt(user_password=user_password, owner_password="owner-secret", algorithm="AES-128")
    out = io.BytesIO()
    writer.write(out)
    return out.getvalue()


# -- OOXML --------------------------------------------------------------------

W_NS = "http://schemas.openxmlformats.org/wordprocessingml/2006/main"
A_NS = "http://schemas.openxmlformats.org/drawingml/2006/main"
P_NS = "http://schemas.openxmlformats.org/presentationml/2006/main"
R_NS = "http://schemas.openxmlformats.org/officeDocument/2006/relationships"
PKG_NS = "http://schemas.openxmlformats.org/package/2006/relationships"
SLIDE_REL = "http://schemas.openxmlformats.org/officeDocument/2006/relationships/slide"
NOTES_REL = "http://schemas.openxmlformats.org/officeDocument/2006/relationships/notesSlide"

_CONTENT_TYPES = (
    '<?xml version="1.0" encoding="UTF-8"?>'
    '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
    '<Default Extension="xml" ContentType="application/xml"/></Types>'
)


def _zip(members: dict[str, bytes | str]) -> bytes:
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as archive:
        for name, data in members.items():
            archive.writestr(name, data)
    return out.getvalue()


def _run(text: str, *, hidden: bool = False) -> str:
    props = "<w:rPr><w:vanish/></w:rPr>" if hidden else ""
    return f'<w:r>{props}<w:t xml:space="preserve">{text}</w:t></w:r>'


def docx_xml(body: str) -> str:
    return (
        '<?xml version="1.0" encoding="UTF-8"?>'
        f'<w:document xmlns:w="{W_NS}"><w:body>{body}</w:body></w:document>'
    )


def make_docx(
    *,
    heading: str = "Syllabus",
    paragraphs: Sequence[str] = ("Midterm is on October 12.",),
    hidden: str = "",
    table: Sequence[Sequence[str]] = (),
    document_xml: Optional[str] = None,
) -> bytes:
    """A Word file: a Heading1, paragraphs, an optional hidden (w:vanish)
    run, an optional table. *document_xml* replaces word/document.xml."""
    if document_xml is None:
        parts = [
            f'<w:p><w:pPr><w:pStyle w:val="Heading1"/></w:pPr>{_run(heading)}</w:p>',
            *(f"<w:p>{_run(p)}</w:p>" for p in paragraphs),
        ]
        if hidden:
            parts.append(f"<w:p>{_run('Visible part.')}{_run(hidden, hidden=True)}</w:p>")
        if table:
            rows = "".join(
                "<w:tr>" + "".join(f"<w:tc><w:p>{_run(c)}</w:p></w:tc>" for c in row) + "</w:tr>"
                for row in table
            )
            parts.append(f"<w:tbl>{rows}</w:tbl>")
        document_xml = docx_xml("".join(parts))
    return _zip({"[Content_Types].xml": _CONTENT_TYPES, "word/document.xml": document_xml})


def _slide_xml(title: str, body: str, *, hidden: bool = False) -> str:
    show = ' show="0"' if hidden else ""
    return (
        f'<p:sld xmlns:p="{P_NS}" xmlns:a="{A_NS}"{show}><p:cSld><p:spTree>'
        '<p:sp><p:nvSpPr><p:cNvPr id="1" name="Title"/><p:cNvSpPr/>'
        '<p:nvPr><p:ph type="title"/></p:nvPr></p:nvSpPr>'
        f"<p:txBody><a:p><a:r><a:t>{title}</a:t></a:r></a:p></p:txBody></p:sp>"
        '<p:sp><p:nvSpPr><p:cNvPr id="2" name="Body"/><p:cNvSpPr/><p:nvPr/></p:nvSpPr>'
        f"<p:txBody><a:p><a:r><a:t>{body}</a:t></a:r></a:p></p:txBody></p:sp>"
        "</p:spTree></p:cSld></p:sld>"
    )


def _notes_xml(text: str) -> str:
    return (
        f'<p:notes xmlns:p="{P_NS}" xmlns:a="{A_NS}"><p:cSld><p:spTree>'
        '<p:sp><p:nvSpPr><p:cNvPr id="1" name="Notes"/><p:cNvSpPr/>'
        '<p:nvPr><p:ph type="body"/></p:nvPr></p:nvSpPr>'
        f"<p:txBody><a:p><a:r><a:t>{text}</a:t></a:r></a:p></p:txBody></p:sp>"
        "</p:spTree></p:cSld></p:notes>"
    )


def make_pptx(slides: Sequence[tuple[str, str, str]], *, hidden: Sequence[int] = ()) -> bytes:
    """A PowerPoint deck. Each slide is (title, body, notes). The slide
    files are named in reverse order, so only the presentation's own
    relationship order gives the right sequence."""
    count = len(slides)
    members: dict[str, bytes | str] = {"[Content_Types].xml": _CONTENT_TYPES}
    ids = []
    rels = []
    for index, (title, body, notes) in enumerate(slides):
        file_number = count - index  # reverse naming
        rid = f"rId{index + 10}"
        ids.append(f'<p:sldId id="{256 + index}" r:id="{rid}"/>')
        rels.append(f'<Relationship Id="{rid}" Type="{SLIDE_REL}" Target="slides/slide{file_number}.xml"/>')
        members[f"ppt/slides/slide{file_number}.xml"] = _slide_xml(title, body, hidden=(index + 1) in hidden)
        if notes:
            members[f"ppt/slides/_rels/slide{file_number}.xml.rels"] = (
                f'<Relationships xmlns="{PKG_NS}"><Relationship Id="rId1" Type="{NOTES_REL}" '
                f'Target="../notesSlides/notesSlide{file_number}.xml"/></Relationships>'
            )
            members[f"ppt/notesSlides/notesSlide{file_number}.xml"] = _notes_xml(notes)
    members["ppt/presentation.xml"] = (
        f'<p:presentation xmlns:p="{P_NS}" xmlns:r="{R_NS}"><p:sldIdLst>{"".join(ids)}</p:sldIdLst></p:presentation>'
    )
    members["ppt/_rels/presentation.xml.rels"] = f'<Relationships xmlns="{PKG_NS}">{"".join(rels)}</Relationships>'
    return _zip(members)


def make_xlsx(sheets: dict[str, Sequence[Sequence[object]]], *, formula: bool = False) -> bytes:
    """An Excel workbook with one sheet per entry. With *formula*, cell C1
    of the first sheet is a formula whose cached value is absent."""
    from openpyxl import Workbook

    book = Workbook()
    first = True
    for name, rows in sheets.items():
        sheet = book.active if first else book.create_sheet()
        sheet.title = name
        first = False
        for row in rows:
            sheet.append(list(row))
        if formula and sheet is book.worksheets[0]:
            sheet["C1"] = "=A1*2"
    out = io.BytesIO()
    book.save(out)
    return out.getvalue()


# -- Attack files -------------------------------------------------------------


def zip_member_bomb(size: int = 60 * 1024 * 1024) -> bytes:
    """A .docx whose document.xml claims *size* bytes of zeros."""
    return _zip({"[Content_Types].xml": _CONTENT_TYPES, "word/document.xml": b"\0" * size})


def zip_ratio_bomb() -> bytes:
    """A .docx with a 2 MB member that compresses more than 100 to 1."""
    return _zip(
        {
            "[Content_Types].xml": _CONTENT_TYPES,
            "word/document.xml": docx_xml(""),
            "word/media/padding.bin": b"\0" * (2 * 1024 * 1024),
        }
    )


def zip_count_bomb(members: int = 2001) -> bytes:
    content: dict[str, bytes | str] = {"[Content_Types].xml": _CONTENT_TYPES, "word/document.xml": docx_xml("")}
    for index in range(members):
        content[f"word/x{index}.xml"] = b"x"
    return _zip(content)


def entity_docx() -> bytes:
    """A .docx whose XML declares an entity (the billion-laughs shape)."""
    xml = (
        '<?xml version="1.0"?><!DOCTYPE lolz [<!ENTITY lol "lol">'
        '<!ENTITY lol2 "&lol;&lol;&lol;&lol;">]>'
        f'<w:document xmlns:w="{W_NS}"><w:body><w:p><w:r><w:t>&lol2;</w:t></w:r></w:p>'
        "</w:body></w:document>"
    )
    return make_docx(document_xml=xml)


def _png_chunk(kind: bytes, data: bytes) -> bytes:
    return struct.pack(">I", len(data)) + kind + data + struct.pack(">I", zlib.crc32(kind + data) & 0xFFFFFFFF)


def png(width: int = 2, height: int = 2) -> bytes:
    """A valid grayscale PNG header of *width* x *height* (the pixel data is
    only right for tiny sizes: enough for Pillow to open and check it)."""
    ihdr = struct.pack(">IIBBBBB", width, height, 8, 0, 0, 0, 0)
    raw = b"".join(b"\x00" + b"\x7f" * min(width, 64) for _ in range(min(height, 64)))
    return b"\x89PNG\r\n\x1a\n" + _png_chunk(b"IHDR", ihdr) + _png_chunk(b"IDAT", zlib.compress(raw)) + _png_chunk(b"IEND", b"")


def png_bomb() -> bytes:
    """A PNG that says it is 8000 x 8000 (64 megapixels, over the 40 MP cap)."""
    return png(8000, 8000)


OLE_HEADER = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + b"\0" * 504
