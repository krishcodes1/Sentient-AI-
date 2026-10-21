"""Outlook body of ``get_attachment_hash`` (security S10): an attachment's
SHA-256, size, name and type for a malware lookup, never its content.

Why it exists: ``mail.py`` is shared by every skill, so the file check's own
download-and-hash code lives here, owned by its skill. ``MailActions`` keeps a
one-line delegation that passes itself as *actions*. The rules:

- The attachment's metadata is read first, as ``get_attachment_text`` does
  (``$select`` without ``contentBytes``, so nothing is downloaded yet). An
  attached item or a link (anything but a ``fileAttachment``) is refused.
- A declared size over ``MAX_HASH_BYTES`` (25 MB) answers ``too_large``
  without downloading; otherwise the raw ``$value`` is streamed with that cap,
  and a body that runs past it answers ``too_large`` too.
- The answer holds the fingerprint, the size, the name and the declared type
  only, never a byte of content. The bytes are offered to a byte sink a
  caller bound for exactly this fingerprint (an approved upload re-fetching
  the file) and otherwise die here.

Connects to: services/connectors/microsoft_api/mail.py (the delegation and
``_request_bytes``), services/file_reputation/byte_sink.py (the cap, the hash
and the sink).
"""

from __future__ import annotations

from typing import Any

from services.connectors.base import ConnectorError, path_segment
from services.file_reputation.byte_sink import MAX_HASH_BYTES, offer, sha256_hex_async

from .common import ME, require_id, text_of

_ATTACHMENT_FIELDS = "id,name,contentType,size,isInline"
_FILE_ATTACHMENT = "#microsoft.graph.fileAttachment"


def _declared_size(meta: dict[str, Any]) -> Any:
    size = meta.get("size")
    return size if isinstance(size, int) and not isinstance(size, bool) else None


async def outlook_attachment_hash(
    actions: Any, message_id: str, attachment_id: str
) -> dict[str, Any]:
    """``{"message_id", "attachment_id", "filename", "mime_type", "size",
    "sha256"}`` of one file attachment, or ``sha256: None, too_large: True``
    over the cap."""
    mid = require_id(message_id, "message_id")
    aid = require_id(attachment_id, "attachment_id")
    path = f"/messages/{path_segment(mid)}/attachments/{path_segment(aid)}"
    meta = await actions._graph_object("GET", path, params={"$select": _ATTACHMENT_FIELDS})
    kind = meta.get("@odata.type")
    if kind is not None and kind != _FILE_ATTACHMENT:
        raise ConnectorError(
            "That attachment is an attached item or link, not a file; it cannot be fingerprinted."
        )
    facts = {
        "message_id": mid,
        "attachment_id": aid,
        "filename": text_of(meta.get("name"), 300),
        "mime_type": text_of(meta.get("contentType"), 200),
    }
    declared = _declared_size(meta)
    if declared is not None and declared > MAX_HASH_BYTES:
        # Declared too large: nothing is downloaded.
        return {**facts, "size": declared, "sha256": None, "too_large": True}
    fetched = await actions._request_bytes("GET", f"{ME}{path}/$value", max_bytes=MAX_HASH_BYTES)
    if fetched.truncated:
        return {**facts, "size": declared, "sha256": None, "too_large": True}
    data = bytes(fetched.content)
    digest = await sha256_hex_async(data)
    offer(digest, data)
    return {**facts, "size": len(data), "sha256": digest}
