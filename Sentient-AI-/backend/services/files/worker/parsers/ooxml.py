"""Reads Word (.docx) and PowerPoint (.pptx) files with zipfile and
defusedxml, and holds the zip limits the Excel parser shares.

Why it exists: an Office file is a zip of XML parts, and both layers are
classic attack surfaces (zip bombs, XML entity expansion, external
entities). Every archive is checked before any part is read: at most 2000
members, 200 MB uncompressed in total, 50 MB per member, a compression ratio
of at most 100 for any member over 1 MB, and no encrypted member; each part
is read with a bounded read, whatever its header claims. XML is parsed with
defusedxml with DTDs forbidden, so entities and external references never
resolve.

Word: body paragraphs and tables in order, headings marked with "#", runs
hidden with w:vanish skipped and counted (``hidden_text``), deleted text
skipped. PowerPoint: slides in the presentation's own order (its
relationship ids, not file names), each "Slide 4: Title", with the speaker
notes; hidden slides are marked and flagged (``hidden_slides``).
"""

from __future__ import annotations

import io
import posixpath
import zipfile
from typing import Any, Optional

from services.files.limits import (
    MAX_ZIP_MEMBER_BYTES,
    MAX_ZIP_MEMBERS,
    MAX_ZIP_RATIO,
    MAX_ZIP_TOTAL_BYTES,
)
from services.files.worker.protocol import Emitter, ParseError

_RATIO_CHECK_FROM = 1024 * 1024

W = "{http://schemas.openxmlformats.org/wordprocessingml/2006/main}"
A = "{http://schemas.openxmlformats.org/drawingml/2006/main}"
P = "{http://schemas.openxmlformats.org/presentationml/2006/main}"
R = "{http://schemas.openxmlformats.org/officeDocument/2006/relationships}"
PKG_REL = "{http://schemas.openxmlformats.org/package/2006/relationships}"
DC = "{http://purl.org/dc/elements/1.1/}"


def safe_zip(data: bytes) -> zipfile.ZipFile:
    """Open *data* as a zip after checking the whole directory against the
    limits. Raises ParseError (corrupt, too_large or encrypted)."""
    try:
        archive = zipfile.ZipFile(io.BytesIO(data))
        infos = archive.infolist()
    except (zipfile.BadZipFile, OSError, ValueError, RuntimeError, NotImplementedError):
        raise ParseError("corrupt") from None
    if len(infos) > MAX_ZIP_MEMBERS:
        raise ParseError("too_large")
    total = 0
    for info in infos:
        if info.flag_bits & 0x1:
            raise ParseError("encrypted")
        if info.file_size > MAX_ZIP_MEMBER_BYTES:
            raise ParseError("too_large")
        total += info.file_size
        if total > MAX_ZIP_TOTAL_BYTES:
            raise ParseError("too_large")
        if info.file_size > _RATIO_CHECK_FROM and info.file_size > MAX_ZIP_RATIO * max(
            info.compress_size, 1
        ):
            raise ParseError("too_large")
    return archive


def read_member(archive: zipfile.ZipFile, name: str, limit: int = MAX_ZIP_MEMBER_BYTES) -> Optional[bytes]:
    """The bytes of member *name*, read no further than *limit* (a header
    can lie about the size); None when there is no such member."""
    try:
        info = archive.getinfo(name)
    except KeyError:
        return None
    try:
        with archive.open(info) as handle:
            data = handle.read(limit + 1)
    except (zipfile.BadZipFile, OSError, ValueError, RuntimeError, NotImplementedError):
        raise ParseError("corrupt") from None
    if len(data) > limit:
        raise ParseError("too_large")
    return data


def parse_xml(data: bytes) -> Any:
    """An element tree from *data*, parsed by defusedxml with DTDs
    forbidden. Raises ParseError("corrupt") for a DTD, an entity, an
    external reference or malformed XML."""
    from defusedxml import ElementTree as SafeET
    from defusedxml.common import DefusedXmlException

    try:
        return SafeET.fromstring(data, forbid_dtd=True, forbid_entities=True, forbid_external=True)
    except DefusedXmlException:
        raise ParseError("corrupt") from None
    except Exception:  # noqa: BLE001 - ParseError from expat and friends
        raise ParseError("corrupt") from None


def _core_title(archive: zipfile.ZipFile) -> str:
    raw = read_member(archive, "docProps/core.xml", 1024 * 1024)
    if not raw:
        return ""
    try:
        root = parse_xml(raw)
    except ParseError:
        return ""
    node = root.find(f"{DC}title")
    return (node.text or "").strip()[:300] if node is not None else ""


# -- Word -------------------------------------------------------------------


class _DocxState:
    def __init__(self) -> None:
        self.hidden_runs = 0


def _run_text(run: Any, state: _DocxState) -> str:
    props = run.find(f"{W}rPr")
    if props is not None and props.find(f"{W}vanish") is not None:
        vanish = props.find(f"{W}vanish")
        value = vanish.get(f"{W}val") if vanish is not None else None
        if value not in ("0", "false", "off"):
            state.hidden_runs += 1
            return ""
    parts: list[str] = []
    for child in run:
        tag = child.tag
        if tag == f"{W}t":
            parts.append(child.text or "")
        elif tag == f"{W}tab":
            parts.append("\t")
        elif tag in (f"{W}br", f"{W}cr"):
            parts.append("\n")
        elif tag == f"{W}noBreakHyphen":
            parts.append("-")
    return "".join(parts)


def _inline_text(element: Any, state: _DocxState) -> str:
    parts: list[str] = []
    for child in element:
        tag = child.tag
        if tag in (f"{W}del", f"{W}moveFrom", f"{W}pPr", f"{W}rPr"):
            continue
        if tag == f"{W}r":
            parts.append(_run_text(child, state))
        else:
            parts.append(_inline_text(child, state))
    return "".join(parts)


def _paragraph(p: Any, state: _DocxState) -> str:
    text = _inline_text(p, state).strip()
    if not text:
        return ""
    props = p.find(f"{W}pPr")
    style = props.find(f"{W}pStyle") if props is not None else None
    value = (style.get(f"{W}val") or "") if style is not None else ""
    lowered = value.lower()
    if lowered == "title":
        return f"# {text}"
    if lowered.startswith("heading") and lowered[7:].isdigit():
        level = max(1, min(int(lowered[7:]), 6))
        return f"{'#' * level} {text}"
    return text


def _table(tbl: Any, state: _DocxState) -> list[str]:
    rows: list[str] = []
    for tr in tbl.iter(f"{W}tr"):
        cells: list[str] = []
        for tc in tr.findall(f"{W}tc"):
            texts = [_inline_text(p, state).strip() for p in tc.iter(f"{W}p")]
            cells.append(" ".join(t for t in texts if t))
        if any(cells):
            rows.append(" | ".join(cells))
    return rows


def _block_lines(container: Any, state: _DocxState, out: list[str]) -> None:
    for child in container:
        tag = child.tag
        if tag == f"{W}p":
            line = _paragraph(child, state)
            if line:
                out.append(line)
        elif tag == f"{W}tbl":
            out.extend(_table(child, state))
            out.append("")
        elif tag in (f"{W}sdt", f"{W}sdtContent", f"{W}customXml", f"{W}ins"):
            _block_lines(child, state, out)


def parse_docx(data: bytes, header: dict[str, Any], emit: Emitter) -> None:
    archive = safe_zip(data)
    raw = read_member(archive, "word/document.xml")
    if raw is None:
        raise ParseError("corrupt")
    root = parse_xml(raw)
    body = root.find(f"{W}body")
    state = _DocxState()
    lines: list[str] = []
    if body is not None:
        _block_lines(body, state, lines)
    emit.meta(title=_core_title(archive), pages_total=None)
    text = "\n".join(lines).strip()
    if text:
        emit.unit("", None, text)
    if state.hidden_runs:
        emit.warn("hidden_text")
    emit.done(truncated=False)


# -- PowerPoint ---------------------------------------------------------------


def _rels(archive: zipfile.ZipFile, part: str) -> dict[str, tuple[str, str]]:
    """rId -> (type, target part path) for *part*'s relationships."""
    folder, name = posixpath.split(part)
    raw = read_member(archive, posixpath.join(folder, "_rels", f"{name}.rels"), 4 * 1024 * 1024)
    if not raw:
        return {}
    root = parse_xml(raw)
    found: dict[str, tuple[str, str]] = {}
    for rel in root.findall(f"{PKG_REL}Relationship"):
        rid, target, kind = rel.get("Id"), rel.get("Target"), rel.get("Type") or ""
        if not rid or not target or rel.get("TargetMode") == "External":
            continue
        path = posixpath.normpath(posixpath.join(folder, target)).lstrip("/")
        found[rid] = (kind, path)
    return found


def _paragraph_texts(root: Any) -> list[str]:
    texts: list[str] = []
    for para in root.iter(f"{A}p"):
        parts: list[str] = []
        for node in para.iter():
            if node.tag == f"{A}t":
                parts.append(node.text or "")
            elif node.tag == f"{A}br":
                parts.append("\n")
        line = "".join(parts).strip()
        if line:
            texts.append(line)
    return texts


def _placeholder_type(shape: Any) -> Optional[str]:
    for nv in (f"{P}nvSpPr", f"{P}nvGraphicFramePr"):
        props = shape.find(nv)
        if props is None:
            continue
        nv_pr = props.find(f"{P}nvPr")
        ph = nv_pr.find(f"{P}ph") if nv_pr is not None else None
        if ph is not None:
            return ph.get("type") or "body"
    return None


def _slide_title(root: Any) -> str:
    for shape in root.iter(f"{P}sp"):
        if _placeholder_type(shape) in ("title", "ctrTitle"):
            text = " ".join(_paragraph_texts(shape)).strip()
            if text:
                return " ".join(text.split())[:80]
    return ""


def _notes_text(archive: zipfile.ZipFile, slide_part: str) -> str:
    for kind, target in _rels(archive, slide_part).values():
        if kind.endswith("/notesSlide"):
            raw = read_member(archive, target, 8 * 1024 * 1024)
            if not raw:
                return ""
            root = parse_xml(raw)
            texts: list[str] = []
            for shape in root.iter(f"{P}sp"):
                if _placeholder_type(shape) == "body":
                    texts.extend(_paragraph_texts(shape))
            return "\n".join(texts).strip()
    return ""


def parse_pptx(data: bytes, header: dict[str, Any], emit: Emitter) -> None:
    archive = safe_zip(data)
    raw = read_member(archive, "ppt/presentation.xml")
    if raw is None:
        raise ParseError("corrupt")
    presentation = parse_xml(raw)
    rels = _rels(archive, "ppt/presentation.xml")
    slide_parts: list[str] = []
    id_list = presentation.find(f"{P}sldIdLst")
    if id_list is not None:
        for sld in id_list.findall(f"{P}sldId"):
            rid = sld.get(f"{R}id")
            rel = rels.get(rid or "")
            if rel is not None and rel[0].endswith("/slide"):
                slide_parts.append(rel[1])
    emit.meta(title=_core_title(archive), pages_total=len(slide_parts))
    hidden_slides = 0
    for number, part in enumerate(slide_parts, start=1):
        slide_raw = read_member(archive, part)
        if not slide_raw:
            continue
        root = parse_xml(slide_raw)
        hidden = root.get("show") in ("0", "false")
        if hidden:
            hidden_slides += 1
        title = _slide_title(root)
        body = "\n".join(_paragraph_texts(root))
        notes = _notes_text(archive, part)
        text = body
        if notes:
            text = f"{body}\n\nSpeaker notes:\n{notes}" if body else f"Speaker notes:\n{notes}"
        label = f"Slide {number}" + (" (hidden)" if hidden else "") + (f": {title}" if title else "")
        if text.strip():
            emit.unit(label, number, text)
    if hidden_slides:
        emit.warn("hidden_slides")
    emit.done(truncated=False)
