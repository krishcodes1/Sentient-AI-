"""Builds the document the knowledge base saves from each kind of source: text
the user dictated, a public web page or file, a connector file reader's
result, or an upload's extraction.

Why it exists: knowledge.add and the Telegram caption take very different
inputs, but the store wants one shape (SourceDocument: a screened title,
labelled sections and the facts a citation needs). Web pages are fetched
only through services/tools/net.build_guarded_client (the SSRF check and
DNS pin on every hop), streamed under a byte cap, with a total deadline and
a content-type allowlist; PDF and Office files go through file_extraction's
sandboxed reader (``extract``), HTML through the readable-text extractor.
A stored source reference never keeps a URL's query, fragment or userinfo,
so a pre-signed address or a token is never written down.

Errors are SourceError(code, message) with a user-safe sentence.
"""

from __future__ import annotations

import asyncio
import dataclasses
from dataclasses import dataclass
from typing import Any, Awaitable, Callable, Mapping, Optional, Sequence
from urllib.parse import urlsplit, urlunsplit

import httpx

from services.files.sections import Extraction, ExtractionRefused, RawUnit, Section, build_sections
from services.knowledge.limits import (
    MAX_DOCUMENT_CHARS,
    SOURCE_REF_MAX,
    URL_DEADLINE_S,
    URL_MAX,
)
from services.knowledge.screen import safe_file_name, safe_title
from services.tools.net import (
    AddressResolver,
    EgressBlocked,
    build_guarded_client,
    validated_addresses,
)

DocumentGate = Callable[[], Awaitable[Optional[str]]]

SOURCE_KINDS = frozenset(
    {"upload", "url", "text", "google_drive", "onedrive", "canvas", "notion", "telegram"}
)

_USER_AGENT = "Mozilla/5.0 (compatible; CrawlerAI knowledge base)"
_HTML_TYPES = frozenset({"text/html", "application/xhtml+xml"})
_TEXT_TYPES = {
    "text/plain": "text",
    "text/markdown": "markdown",
    "text/x-markdown": "markdown",
    "text/csv": "csv",
}
_DOCUMENT_TYPES = frozenset(
    {
        "application/pdf",
        "application/x-pdf",
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        "application/vnd.openxmlformats-officedocument.presentationml.presentation",
        "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    }
)
_GENERIC_BINARY = frozenset(
    {"application/octet-stream", "binary/octet-stream", "application/download", "application/force-download"}
)


class SourceError(Exception):
    """A source that cannot be saved; ``message`` is safe to show."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


@dataclass(frozen=True)
class SourceDocument:
    """What the store saves: ``doc_kind`` picks the locators (pdf, pptx,
    xlsx pages, slides and sheets; anything else is text with headings)."""

    title: str
    source_kind: str
    media_type: str
    doc_kind: str
    sections: tuple[Section, ...]
    source_ref: Optional[str] = None
    pages_total: Optional[int] = None
    original_name: Optional[str] = None
    byte_size: int = 0
    truncated: bool = False

    @property
    def chars(self) -> int:
        return sum(len(s.text) for s in self.sections)


def _sections_of_text(text: str) -> tuple[tuple[Section, ...], bool]:
    built = build_sections([RawUnit("", None, text)], max_chars=MAX_DOCUMENT_CHARS)
    return tuple(built.sections), built.truncated


def from_text(text: str, title: str, *, source_kind: str = "text") -> SourceDocument:
    """A note the user dictated (Markdown headings become '§' locators)."""
    sections, truncated = _sections_of_text(text)
    if not sections:
        raise SourceError("empty", "There is no text to save.")
    return SourceDocument(
        title=safe_title(title, fallback="a note"),
        source_kind=source_kind,
        media_type="text/markdown",
        doc_kind="markdown",
        sections=sections,
        byte_size=len(text.encode("utf-8")),
        truncated=truncated,
    )


def from_extraction(
    extraction: Extraction,
    *,
    title: Optional[str],
    source_kind: str,
    source_ref: Optional[str] = None,
    original_name: Optional[str] = None,
    byte_size: int = 0,
) -> SourceDocument:
    """A document file_extraction read (an upload, a connector file, a
    web document)."""
    if not extraction.sections:
        raise SourceError("empty", "No text could be read from this document.")
    name = safe_file_name(original_name) if original_name else None
    return SourceDocument(
        title=safe_title(title or extraction.title or name, extraction.kind),
        source_kind=source_kind,
        media_type=extraction.media_type[:100],
        doc_kind=extraction.kind,
        sections=tuple(extraction.sections),
        source_ref=_ref(source_ref),
        pages_total=extraction.pages_total,
        original_name=name,
        byte_size=byte_size,
        truncated=extraction.truncated,
    )


def from_plain(
    text: str,
    *,
    title: Optional[str],
    source_kind: str,
    media_type: str,
    doc_kind: str,
    source_ref: Optional[str] = None,
    truncated: bool = False,
) -> SourceDocument:
    """Text a connector returned (a Drive text file, a Notion page)."""
    sections, cut = _sections_of_text(text)
    if not sections:
        raise SourceError("empty", "No text could be read from this file.")
    return SourceDocument(
        title=safe_title(title, doc_kind),
        source_kind=source_kind,
        media_type=media_type[:100],
        doc_kind=doc_kind,
        sections=sections,
        source_ref=_ref(source_ref),
        byte_size=len(text.encode("utf-8")),
        truncated=truncated or cut,
    )


# -- URLs -----------------------------------------------------------------------


def check_url(value: Any) -> tuple[Optional[str], Optional[str]]:
    """(the URL, None) when *value* is an http(s) URL of at most URL_MAX
    characters with a host and no user name or password; else (None, why)."""
    if not isinstance(value, str) or not value.strip():
        return None, "url must be an http(s) address."
    url = value.strip()
    if len(url) > URL_MAX:
        return None, f"url must be at most {URL_MAX} characters."
    if any(c.isspace() or ord(c) < 32 or c == "\\" for c in url):
        return None, "url must not contain spaces, control characters or backslashes."
    try:
        parts = urlsplit(url)
        host = parts.hostname
    except ValueError:
        return None, "url is not a valid address."
    if parts.scheme not in ("http", "https") or not host:
        return None, "url must be an http(s) address with a host."
    if parts.username is not None or parts.password is not None or "@" in parts.netloc:
        return None, "url must not contain a user name or password."
    return url, None


def url_host(url: str) -> str:
    try:
        return (urlsplit(url).hostname or "").rstrip(".")
    except ValueError:
        return ""


def _ref(value: Optional[str]) -> Optional[str]:
    """A source reference as stored: a URL without its query, fragment or
    userinfo; anything else as given; at most SOURCE_REF_MAX characters."""
    if not value:
        return None
    if value.startswith(("http://", "https://")):
        try:
            parts = urlsplit(value)
            host = parts.hostname or ""
            netloc = host if parts.port is None else f"{host}:{parts.port}"
            value = urlunsplit((parts.scheme, netloc, parts.path, "", ""))
        except ValueError:
            return None
    return value[:SOURCE_REF_MAX]


def _decode(data: bytes, encoding: Optional[str]) -> str:
    try:
        return data.decode(encoding or "utf-8", errors="replace")
    except LookupError:
        return data.decode("utf-8", errors="replace")


async def fetch_url(
    url: str,
    *,
    max_bytes: int,
    sandbox: Any = None,
    document_gate: Optional[DocumentGate] = None,
    transport: Optional[httpx.AsyncBaseTransport] = None,
    resolver: AddressResolver = validated_addresses,
    deadline_s: float = URL_DEADLINE_S,
    extract: Optional[Callable[..., Awaitable[Extraction]]] = None,
) -> SourceDocument:
    """Fetch *url* and build its document. Raises SourceError."""
    try:
        return await asyncio.wait_for(
            _fetch(
                url,
                max_bytes=max_bytes,
                sandbox=sandbox,
                document_gate=document_gate,
                transport=transport,
                resolver=resolver,
                timeout_s=deadline_s,
                extract=extract,
            ),
            timeout=deadline_s,
        )
    except TimeoutError:
        raise SourceError("timeout", f"The page took longer than {int(deadline_s)} seconds to fetch.") from None
    except EgressBlocked as exc:
        raise SourceError("blocked", str(exc)) from None
    except httpx.HTTPError as exc:
        raise SourceError("fetch_failed", f"The page could not be fetched ({type(exc).__name__}).") from None


async def _read_body(response: httpx.Response, max_bytes: int) -> bytes:
    declared = response.headers.get("content-length")
    if declared and declared.isdigit() and int(declared) > max_bytes:
        raise SourceError("too_large", _too_large(max_bytes))
    body = bytearray()
    async for chunk in response.aiter_bytes():
        body += chunk
        if len(body) > max_bytes:
            raise SourceError("too_large", _too_large(max_bytes))
    return bytes(body)


def _too_large(max_bytes: int) -> str:
    return f"The page or file is larger than {max_bytes // (1024 * 1024)} MB, the most the knowledge base saves."


async def _fetch(
    url: str,
    *,
    max_bytes: int,
    sandbox: Any,
    document_gate: Optional[DocumentGate],
    transport: Optional[httpx.AsyncBaseTransport],
    resolver: AddressResolver,
    timeout_s: float,
    extract: Optional[Callable[..., Awaitable[Extraction]]],
) -> SourceDocument:
    from services.files.detect import looks_like_document
    from services.tools.html_text import extract_readable_text

    client = build_guarded_client(
        timeout_s=timeout_s,
        headers={"User-Agent": _USER_AGENT, "Accept-Language": "en-US,en;q=0.9"},
        resolver=resolver,
        transport=transport,
    )
    async with client:
        async with client.stream("GET", url) as response:
            if response.status_code >= 400:
                raise SourceError("http_error", f"The page answered HTTP {response.status_code}.")
            mime = (response.headers.get("content-type") or "").split(";", 1)[0].strip().lower()
            allowed = mime in _HTML_TYPES or mime in _TEXT_TYPES or mime in _DOCUMENT_TYPES or mime in _GENERIC_BINARY
            if not allowed:
                shown = mime or "unknown"
                raise SourceError(
                    "unsupported",
                    f"Content type '{shown[:60]}' cannot be saved; only web pages, text, PDF and Office files can.",
                )
            data = await _read_body(response, max_bytes)
            final_url = str(response.url)
            encoding = response.charset_encoding

    host = url_host(final_url)
    if mime in _HTML_TYPES:
        title, text = extract_readable_text(_decode(data, encoding))
        sections, truncated = _sections_of_text(text)
        if not sections:
            raise SourceError("empty", "The page has no readable text.")
        return SourceDocument(
            title=safe_title(title or host, fallback="a web page"),
            source_kind="url",
            media_type=mime,
            doc_kind="html",
            sections=sections,
            source_ref=_ref(final_url),
            byte_size=len(data),
            truncated=truncated,
        )
    if mime in _TEXT_TYPES:
        text_doc = from_plain(
            _decode(data, encoding),
            title=_path_name(final_url) or host,
            source_kind="url",
            media_type=mime,
            doc_kind=_TEXT_TYPES[mime],
            source_ref=final_url,
        )
        return dataclasses.replace(text_doc, byte_size=len(data))
    if mime in _GENERIC_BINARY and not looks_like_document(data[:1024]):
        raise SourceError("unsupported", "This file is not a web page, text, PDF or Office document.")
    if document_gate is not None:
        refusal = await document_gate()
        if refusal is not None:
            raise SourceError("switched_off", refusal)
    reader = extract or _default_extract
    name = _path_name(final_url) or "document"
    try:
        extraction = await reader(
            data, name=name, declared_mime=mime if mime in _DOCUMENT_TYPES else None, sandbox=sandbox
        )
    except ExtractionRefused as refused:
        raise SourceError(refused.code, refused.message) from None
    return from_extraction(
        extraction,
        title=extraction.title or name,
        source_kind="url",
        source_ref=final_url,
        original_name=name,
        byte_size=len(data),
    )


def _path_name(url: str) -> str:
    try:
        return urlsplit(url).path.rsplit("/", 1)[-1][:200]
    except ValueError:
        return ""


async def _default_extract(data: bytes, *, name: str, declared_mime: Optional[str], sandbox: Any) -> Extraction:
    from services.files.documents import extract
    from services.files.limits import CONNECTOR

    return await extract(data, name=name, declared_mime=declared_mime, preset=CONNECTOR, sandbox=sandbox)


# -- Connector file readers -------------------------------------------------------


@dataclass(frozen=True)
class IndexSource:
    """How one connector type's files are read for the knowledge base: its
    own READ action, the id argument, the stored source kind and the name
    the card uses."""

    action: str
    id_argument: str
    source_kind: str
    label: str


INDEX_SOURCES: Mapping[str, IndexSource] = {
    "google_workspace": IndexSource("get_file_text", "file_id", "google_drive", "Google Drive"),
    "microsoft": IndexSource("get_file_text", "file_id", "onedrive", "OneDrive"),
    "canvas": IndexSource("get_file_text", "file_id", "canvas", "Canvas"),
    "notion": IndexSource("get_page", "page_id", "notion", "Notion"),
}


def from_connector_result(
    source: IndexSource,
    namespace: str,
    item_id: str,
    data: Mapping[str, Any],
    *,
    extraction: Optional[Extraction],
    text_parts: Sequence[str] = (),
    truncated: bool = False,
) -> SourceDocument:
    """The document a connector reader returned: its registered extraction
    (PDF and Office files: every section, not just the first window), or
    its text (a Drive text file read page by page, a Notion page)."""
    ref = f"{namespace}:{item_id}"
    name = data.get("name") or data.get("title") or data.get("display_name")
    title = str(name) if isinstance(name, str) and name.strip() else f"{source.label} file {item_id}"
    if extraction is not None:
        return from_extraction(extraction, title=title, source_kind=source.source_kind, source_ref=ref, original_name=title)
    text = "\n".join(p for p in text_parts if p)
    if not text.strip():
        content = data.get("content") if source.source_kind == "notion" else data.get("text")
        text = content if isinstance(content, str) else ""
    mime = str(data.get("mime_type") or data.get("content_type") or "text/plain")
    doc_kind = "markdown" if source.source_kind == "notion" or mime in ("text/markdown", "text/x-markdown") else "text"
    return from_plain(
        text,
        title=title,
        source_kind=source.source_kind,
        media_type="text/markdown" if source.source_kind == "notion" else mime,
        doc_kind=doc_kind,
        source_ref=ref,
        truncated=truncated or bool(data.get("truncated")),
    )
