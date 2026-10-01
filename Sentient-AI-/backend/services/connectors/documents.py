"""Reads a PDF or Office file a connector downloads (Drive, OneDrive, Gmail and
Outlook attachments, Canvas course files) through the shared document reader.

Why it exists: the connector file readers used to refuse PDFs and Office files
as binary. They now hand the bytes to services/files (the sandboxed parser,
the CONNECTOR preset of 20 MB and 60 s) and return the first window of
sections plus a doc_id the model continues with files.read. The owner's "Read
files and documents" switch is checked before any download (through the
document context the executor binds around the call; unbound or off, the
call is refused with its when_denied text). Text files keep their own
offset paging; only is_document_type files come here.
"""

from __future__ import annotations

from typing import Any, Awaitable, Callable, Optional

from services.connectors.base import BoundedBody, ConnectorError
from services.files import messages
from services.files.context import DocumentContext, current, document_refusal
from services.files.detect import is_document_type
from services.files.documents import read_document
from services.files.limits import CONNECTOR

# The most a connector downloads for one document.
MAX_DOCUMENT_BYTES = CONNECTOR.max_bytes

__all__ = [
    "MAX_DOCUMENT_BYTES",
    "document_context_or_refuse",
    "is_document_type",
    "read_connector_document",
]


async def document_context_or_refuse() -> DocumentContext:
    """The bound document context when documents may be read; otherwise a
    ConnectorError with the switch's sentence."""
    context = current()
    refusal = await document_refusal(context)
    if refusal is not None or context is None:
        raise ConnectorError(refusal or messages.SWITCHED_OFF)
    return context


def refuse_if_too_large(size: Optional[int]) -> None:
    if isinstance(size, int) and not isinstance(size, bool) and size > MAX_DOCUMENT_BYTES:
        raise ConnectorError(messages.too_large(size, MAX_DOCUMENT_BYTES))


async def read_connector_document(
    *,
    download: Callable[[int], Awaitable[BoundedBody | bytes]],
    name: str,
    mime: Optional[str],
    source: str,
    size: Optional[int] = None,
) -> dict[str, Any]:
    """Check the switch and the size, download at most MAX_DOCUMENT_BYTES
    with *download(max_bytes)*, and read it. Returns the document result
    (``ok``, ``name``, ``kind``, ``pages_total``, ``sections``, ``doc_id``,
    ``next_start``, ``hint`` ...); raises ConnectorError with a plain
    sentence for anything that cannot be read."""
    context = await document_context_or_refuse()
    refuse_if_too_large(size)
    body = await download(MAX_DOCUMENT_BYTES)
    if isinstance(body, BoundedBody):
        if body.truncated:
            raise ConnectorError(messages.too_large(None, MAX_DOCUMENT_BYTES))
        data = body.content
    else:
        if len(body) > MAX_DOCUMENT_BYTES:
            raise ConnectorError(messages.too_large(len(body), MAX_DOCUMENT_BYTES))
        data = body
    result = await read_document(
        data,
        name=name,
        declared_mime=mime,
        source=source,
        preset=CONNECTOR,
        user_id=context.user_id,
    )
    if not result.get("ok"):
        raise ConnectorError(str(result.get("error") or messages.CORRUPT))
    return result
