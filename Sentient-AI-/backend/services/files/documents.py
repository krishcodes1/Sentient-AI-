"""The entry points every caller uses: ``extract`` a file into an Extraction,
or ``read_document`` it into the first window the model reads plus a doc_id.

Why it exists: uploads, connectors and the web share one path: the size cap
of the source's preset, the type from the magic bytes (detect), the parse in
the sandboxed worker, and the cleaning and splitting into sections. A file
that cannot be read raises ExtractionRefused with a user-safe sentence;
``read_document`` turns that into an ``{"ok": False, ...}`` tool result.
"""

from __future__ import annotations

from typing import Any, Optional

from services.files import context as document_context
from services.files import messages
from services.files.detect import detect, extension_of
from services.files.limits import MAX_PDF_PAGES, WINDOW_DEFAULT_CHARS, Preset
from services.files.prompting import prompt_name, sanitize_display_name
from services.files.registry import DocumentRegistry, default_registry
from services.files.sandbox import Sandbox, SubprocessSandbox, WorkerOutput
from services.files.sections import Extraction, ExtractionRefused, build_sections
from services.files.window import window

_default_sandbox: Optional[SubprocessSandbox] = None

CONTINUE_HINT = "Continue with files.read(file_id='{doc_id}', start={next_start})."
WHOLE_HINT = "This is the whole document."
# The end of what was read, when a limit stopped the reading early.
READ_ALL_HINT = "That is all of the document Crawler read."
# A PDF longer than MAX_PDF_PAGES: "page_cap:300". Set here from the page
# count the worker reported, never taken from a worker's own warning text.
PAGE_CAP_WARNING = "page_cap"
# Warnings for text dropped by a limit other than the page cap.
_OTHER_LIMIT_WARNINGS = ("truncated_at_chars", "output_capped", "timed_out_after_page:")


def default_sandbox() -> Sandbox:
    global _default_sandbox
    if _default_sandbox is None:
        _default_sandbox = SubprocessSandbox()
    return _default_sandbox


def _resolve_sandbox(sandbox: Optional[Sandbox]) -> Sandbox:
    if sandbox is not None:
        return sandbox
    bound = document_context.current()
    if bound is not None and bound.sandbox is not None:
        return bound.sandbox  # type: ignore[no-any-return]
    return default_sandbox()


def _resolve_registry(registry: Optional[DocumentRegistry]) -> DocumentRegistry:
    if registry is not None:
        return registry
    bound = document_context.current()
    if bound is not None and bound.registry is not None:
        return bound.registry  # type: ignore[no-any-return]
    return default_registry()


def _refusal(code: str, *, size: int, name: Optional[str], preset: Preset, pages_read: int = 0) -> ExtractionRefused:
    if code == "image_too_large":
        return ExtractionRefused("too_large", messages.IMAGE_TOO_LARGE)
    if code == "too_large":
        # The worker's too_large is about what the file unpacks to (a zip
        # member, the whole archive); its own size passed the preset's cap.
        return ExtractionRefused("too_large", messages.UNPACKS_TOO_LARGE)
    if code == "unsupported":
        return ExtractionRefused("unsupported", messages.unsupported(extension_of(name)))
    if code == "cancelled":
        return ExtractionRefused("timeout", "Stopped before this file was read.")
    if code == "timeout":
        return ExtractionRefused("timeout", messages.timeout(pages_read))
    if code in ("encrypted", "corrupt", "empty", "busy", "legacy_office"):
        return ExtractionRefused(code, messages.for_code(code))
    return ExtractionRefused("corrupt", messages.CORRUPT)


def _last_page(output: WorkerOutput) -> int:
    pages = [u.page for u in output.units if u.page is not None]
    return max(pages) if pages else len(output.units)


def build_extraction(output: WorkerOutput, *, kind: str, media_type: str, detect_warnings: tuple[str, ...], size: int, name: Optional[str], preset: Preset) -> Extraction:
    """The Extraction for one worker run, or ExtractionRefused."""
    if output.error is not None:
        raise _refusal(output.error, size=size, name=name, preset=preset)
    built = build_sections(output.units)
    warnings = list(detect_warnings) + list(output.warnings)
    if built.invisible_stripped:
        warnings.append(f"invisible_chars:{built.invisible_stripped}")
    if built.truncated:
        warnings.append("truncated_at_chars")
    if output.timed_out:
        warnings.append(f"timed_out_after_page:{_last_page(output)}")
    pages_total = output.pages_total
    if kind == "pdf" and isinstance(pages_total, int) and pages_total > MAX_PDF_PAGES:
        warnings.append(f"{PAGE_CAP_WARNING}:{MAX_PDF_PAGES}")
    if not built.sections:
        if output.timed_out:
            raise _refusal("timeout", size=size, name=name, preset=preset)
        if output.scanned:
            raise ExtractionRefused("empty", messages.EMPTY_SCANS)
        raise ExtractionRefused("empty", messages.EMPTY)
    unique_warnings = tuple(dict.fromkeys(w for w in warnings if w))
    return Extraction(
        kind=kind,
        media_type=media_type,
        title=output.title,
        pages_total=output.pages_total,
        sections=tuple(built.sections),
        truncated=output.truncated or built.truncated or output.timed_out,
        scanned_pages_unread=tuple(sorted(set(output.scanned)))[:500],
        ocr_pages=0,
        warnings=unique_warnings,
    )


async def extract(
    data: bytes,
    *,
    name: Optional[str],
    declared_mime: Optional[str],
    preset: Preset,
    sandbox: Optional[Sandbox] = None,
) -> Extraction:
    """Read *data* under *preset*. Raises ExtractionRefused (too_large,
    unsupported, legacy_office, encrypted, corrupt, timeout, empty, busy).
    ``sandbox`` defaults to the bound DocumentContext's, then the process's
    SubprocessSandbox."""
    size = len(data)
    if size > preset.max_bytes:
        raise ExtractionRefused("too_large", messages.too_large(size, preset.max_bytes))
    detection = detect(data, name=name, declared_mime=declared_mime)
    output = await _resolve_sandbox(sandbox).run(
        data, kind=detection.kind, preset=preset, delimiter=detection.delimiter
    )
    return build_extraction(
        output,
        kind=detection.kind,
        media_type=detection.media_type,
        detect_warnings=detection.warnings,
        size=size,
        name=name,
        preset=preset,
    )


def first_window(
    extraction: Extraction,
    *,
    doc_id: str,
    name: str,
    source: str,
    max_chars: int = WINDOW_DEFAULT_CHARS,
) -> dict[str, Any]:
    """The model-facing result for a newly opened document: its facts, its
    first window of sections (a list, so the runtime can redact one
    poisoned section and keep the rest) and how to continue."""
    view = window(extraction.sections, start=1, max_chars=max_chars)
    result: dict[str, Any] = {
        "ok": True,
        "name": name,
        "kind": extraction.kind,
        "source": source,
        "pages_total": extraction.pages_total,
        "sections_total": len(extraction.sections),
        "sections": list(view.sections),
        "doc_id": doc_id,
        "truncated": extraction.truncated,
    }
    if extraction.title:
        result["title"] = extraction.title[:200]
    if view.next_start is not None:
        result["next_start"] = view.next_start
    if extraction.scanned_pages_unread:
        result["scanned_pages_unread"] = list(extraction.scanned_pages_unread[:100])
    result["hint"] = document_hint(extraction, doc_id=doc_id, next_start=view.next_start)
    return result


def document_hint(extraction: Extraction, *, doc_id: str, next_start: Optional[int]) -> str:
    """What the model should do next, in plain words: continue, or it has
    everything; and which pages were scans nobody could read."""
    parts: list[str] = []
    if next_start is not None:
        parts.append(CONTINUE_HINT.format(doc_id=doc_id, next_start=next_start))
    else:
        parts.append(READ_ALL_HINT if extraction.truncated else WHOLE_HINT)
    if extraction.scanned_pages_unread:
        pages = ", ".join(str(p) for p in extraction.scanned_pages_unread[:20])
        more = "…" if len(extraction.scanned_pages_unread) > 20 else ""
        parts.append(
            f"Pages {pages}{more} are scans (pictures of text) that could not be read on "
            "this computer; tell the user which pages you could not read and never guess them."
        )
    parts.extend(limit_notes(extraction))
    return " ".join(parts)


def page_cap(extraction: Extraction) -> Optional[int]:
    """The page cap a PDF reached (its ``page_cap:N`` warning), else None."""
    for warning in extraction.warnings:
        name, _, value = warning.partition(":")
        if name == PAGE_CAP_WARNING and value.isdigit():
            return int(value)
    return None


def limit_notes(extraction: Extraction) -> list[str]:
    """What a page, size or time limit left unread, in plain words for the
    model: which pages a long PDF was read to, and a general line for any
    other limit."""
    notes: list[str] = []
    cap = page_cap(extraction)
    if cap is not None and extraction.pages_total:
        notes.append(
            f"Only pages 1-{cap} of {extraction.pages_total} were read (Crawler reads at most "
            f"{cap} pages of a PDF); say so if the user asks about a later page."
        )
    other = any(w.startswith(_OTHER_LIMIT_WARNINGS) for w in extraction.warnings)
    if extraction.truncated and (cap is None or other):
        notes.append("Not all of the document could be read (a size or time limit); say so if it matters.")
    return notes


async def read_document(
    data: bytes,
    *,
    name: Optional[str],
    declared_mime: Optional[str],
    source: str,
    preset: Preset,
    user_id: str,
    max_chars: int = WINDOW_DEFAULT_CHARS,
    registry: Optional[DocumentRegistry] = None,
    sandbox: Optional[Sandbox] = None,
) -> dict[str, Any]:
    """Extract *data*, keep it in the registry for *user_id*, and return
    ``{ok, name, kind, pages_total, sections, doc_id, next_start?,
    truncated, scanned_pages_unread?, hint}`` (``sections_total``,
    ``source`` and ``title`` too). A file that cannot be read answers
    ``{"ok": False, "error": <sentence>, "code": <code>}``."""
    display = sanitize_display_name(name)
    try:
        extraction = await extract(data, name=name, declared_mime=declared_mime, preset=preset, sandbox=sandbox)
    except ExtractionRefused as refused:
        return {"ok": False, "error": refused.message, "code": refused.code, "name": display}
    doc_id = _resolve_registry(registry).put(user_id, extraction, name=display, source=source)
    # The model sees the screened name ("a PDF file" when PromptGuard flags
    # the real one), as with uploads.
    return first_window(
        extraction,
        doc_id=doc_id,
        name=prompt_name(display, extraction.kind),
        source=source,
        max_chars=max_chars,
    )
