"""Gmail body of ``get_attachment_hash`` (security S10): an attachment's
SHA-256, size, name and type for a malware lookup, never its content.

Why it exists: ``gmail.py`` is shared by every skill, so the file check's own
download-and-hash code lives here, owned by its skill. ``GmailActions`` keeps a
one-line delegation that passes itself as *actions*; the download goes through
its ``_attachment_bytes`` (the same path the document reader uses). The rules:

- The message is read first and the part is selected by its ``part_id``:
  Gmail attachment ids change between reads, so the fresh id from this same
  read downloads it (as ``get_attachment_text`` does).
- A part whose declared size is over ``MAX_HASH_BYTES`` (25 MB, Gmail's own
  attachment limit) answers ``too_large`` without downloading anything; a part
  that turns out bigger while downloading answers ``too_large`` too.
- The answer holds the fingerprint, the size, the name and the declared type
  only, never a byte of content. The bytes are offered to a byte sink that a
  caller bound for exactly this fingerprint (an approved upload re-fetching
  the file, services/file_reputation/byte_sink.py) and otherwise die here.

Connects to: services/connectors/google_api/gmail.py (the delegation and
``_attachment_bytes``), services/file_reputation/byte_sink.py (the cap, the
hash and the sink).
"""

from __future__ import annotations

from typing import Any

from services.connectors.base import ConnectorError, path_segment
from services.file_reputation.byte_sink import MAX_HASH_BYTES, offer, sha256_hex_async

from .client import GMAIL_API, as_dict, require_id, scalar
from .mime import walk_parts

# The sentence ``_attachment_bytes`` raises for a download over its cap (gmail.py; pinned by
# tests/connectors/test_google_workspace_gmail.py): read here as "too large to hash".
_TOO_LARGE_MARK = "is too large to read"


def _too_large(mid: str, pid: str, filename: str, mime_type: str, size: Any) -> dict[str, Any]:
    return {
        "message_id": mid,
        "part_id": pid,
        "filename": filename,
        "mime_type": mime_type,
        "size": size if isinstance(size, int) and not isinstance(size, bool) else None,
        "sha256": None,
        "too_large": True,
    }


async def gmail_attachment_hash(actions: Any, message_id: str, part_id: str) -> dict[str, Any]:
    """``{"message_id", "part_id", "filename", "mime_type", "size", "sha256"}``
    of one attachment part, or ``sha256: None, too_large: True`` over the cap."""
    mid = require_id(message_id, "message_id")
    pid = require_id(part_id, "part_id")
    message = await actions._call_object(
        "GET", f"{GMAIL_API}/messages/{path_segment(mid)}", params={"format": "full"}
    )
    part = next(
        (p for p in walk_parts(as_dict(message.get("payload"))) if p.get("partId") == pid),
        None,
    )
    if part is None:
        raise ConnectorError(
            f"Message {mid} has no part '{pid}'; use get_message to list attachments."
        )
    filename = scalar(part.get("filename")) or ""
    mime_type = scalar(part.get("mimeType")) or ""
    body = as_dict(part.get("body"))
    declared = body.get("size")
    if isinstance(declared, int) and not isinstance(declared, bool) and declared > MAX_HASH_BYTES:
        # Declared too large: nothing is downloaded.
        return _too_large(mid, pid, filename, mime_type, declared)
    try:
        data = await actions._attachment_bytes(mid, pid, body, filename, cap=MAX_HASH_BYTES)
    except ConnectorError as exc:
        if _TOO_LARGE_MARK in str(exc):
            return _too_large(mid, pid, filename, mime_type, declared)
        raise
    if len(data) > MAX_HASH_BYTES:
        # The download bound leaves base64 slack; the hash cap is exact.
        return _too_large(mid, pid, filename, mime_type, len(data))
    digest = await sha256_hex_async(data)
    offer(digest, data)
    return {
        "message_id": mid,
        "part_id": pid,
        "filename": filename,
        "mime_type": mime_type,
        "size": len(data),
        "sha256": digest,
    }
