"""MIME helpers for the Gmail actions of the Google Workspace connector: read
headers, bodies and attachment parts out of Gmail's ``payload`` tree, and build
the base64url RFC 5322 messages Gmail's send and draft endpoints accept.

Why it exists: parsing and composing mail is pure data handling with no HTTP,
so it lives apart from ``gmail.py`` (which keeps the endpoints and shaping)
and is easy to test on its own. Every walk is depth-bounded and tolerates
hostile provider payloads (wrong types, bad base64, deep nesting).

External service: none (it shapes Gmail API payloads). Depends on
``google_api.client`` (``as_dict``, ``as_list``, ``scalar``) and the standard
``email`` package.
"""

from __future__ import annotations

import base64
import binascii
import email.policy
import re
from email.message import EmailMessage
from email.utils import getaddresses
from typing import Any, Optional

from .client import as_dict, as_list, scalar

# Deepest MIME nesting walked (real mail rarely passes 5).
MAX_MIME_DEPTH = 20
# Attachments listed per message.
MAX_ATTACHMENTS = 20
# Order matters: the whole tree is searched for text/plain before text/html
# is considered at all, so a plain part buried three levels deep still wins
# over a top-level HTML alternative.
BODY_MIME_PREFERENCE: tuple[str, ...] = ("text/plain", "text/html")

_HEADER_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]+")


def header_map(payload: dict[str, Any]) -> dict[str, str]:
    """Lower-cased header name to value; malformed entries are skipped."""
    headers: dict[str, str] = {}
    for item in as_list(payload.get("headers")):
        if not isinstance(item, dict):
            continue
        name, value = item.get("name"), item.get("value")
        if isinstance(name, str) and isinstance(value, str):
            headers.setdefault(name.lower(), value)
    return headers


def header_safe(value: str, limit: int = 2000) -> str:
    """A provider header value made safe to copy into a new header."""
    return _HEADER_CONTROL_RE.sub(" ", value).strip()[:limit]


def address_list(*values: Optional[str]) -> list[str]:
    """Unique bare addresses from header values, in order."""
    seen: dict[str, str] = {}
    for _, address in getaddresses([v for v in values if v]):
        address = address.strip()
        if "@" in address:
            seen.setdefault(address.lower(), address)
    return list(seen.values())


def reply_to_elsewhere(headers: dict[str, str]) -> bool:
    """True when Reply-To names a domain the From address is not on."""
    reply_to = address_list(headers.get("reply-to"))
    if not reply_to:
        return False
    sender_domains = {a.rsplit("@", 1)[1].lower() for a in address_list(headers.get("from"))}
    return any(a.rsplit("@", 1)[1].lower() not in sender_domains for a in reply_to)


def decode_part_data(part: dict[str, Any]) -> str:
    """Decode a MIME part's base64url body, tolerating missing padding."""
    encoded = as_dict(part.get("body")).get("data")
    if not isinstance(encoded, str) or not encoded:
        return ""
    try:
        return base64.urlsafe_b64decode(encoded + "==").decode("utf-8", errors="replace")
    except (binascii.Error, ValueError):
        return ""


def find_part(part: dict[str, Any], mime_type: str, depth: int = 0) -> Optional[dict[str, Any]]:
    """Depth-first search for the first *mime_type* part carrying data."""
    if depth > MAX_MIME_DEPTH:
        return None
    if part.get("mimeType") == mime_type and decode_part_data(part):
        return part
    for child in as_list(part.get("parts")):
        if isinstance(child, dict):
            found = find_part(child, mime_type, depth + 1)
            if found is not None:
                return found
    return None


def body_part(payload: dict[str, Any]) -> Optional[dict[str, Any]]:
    """The MIME part holding a Gmail ``payload``'s readable text, or None.

    The walk recurses: Gmail wraps the text/plain part in a
    multipart/alternative child as soon as the message carries an
    attachment, so scanning only the top level finds no body for most real
    mail. text/html is a last resort (markup beats nothing); the caller
    sanitizes the body with PromptGuard either way.
    """
    for mime_type in BODY_MIME_PREFERENCE:
        part = find_part(payload, mime_type)
        if part is not None:
            return part
    return None


def extract_body(payload: dict[str, Any]) -> str:
    """The readable text of a Gmail ``payload`` MIME tree (see body_part)."""
    part = body_part(payload)
    return decode_part_data(part) if part is not None else ""


def walk_parts(part: dict[str, Any], depth: int = 0) -> list[dict[str, Any]]:
    """Every MIME part of the tree, depth first (bounded)."""
    if depth > MAX_MIME_DEPTH:
        return []
    found = [part]
    for child in as_list(part.get("parts")):
        if isinstance(child, dict):
            found.extend(walk_parts(child, depth + 1))
    return found


def attachments(payload: dict[str, Any]) -> list[dict[str, Any]]:
    """Named parts (attachments) the model can ask get_attachment_text for."""
    out: list[dict[str, Any]] = []
    for part in walk_parts(payload):
        filename = scalar(part.get("filename"))
        if not filename:
            continue
        size = as_dict(part.get("body")).get("size")
        out.append(
            {
                "part_id": scalar(part.get("partId")),
                "filename": filename,
                "mime_type": scalar(part.get("mimeType")),
                "size": size if isinstance(size, int) and not isinstance(size, bool) else None,
            }
        )
        if len(out) >= MAX_ATTACHMENTS:
            break
    return out


def build_raw(
    to: str,
    subject: str,
    body: str,
    *,
    cc: Optional[str] = None,
    extra_headers: Optional[dict[str, str]] = None,
) -> str:
    """A base64url RFC 5322 message Gmail's ``raw`` field accepts."""
    message = EmailMessage(policy=email.policy.SMTP)
    message["To"] = to
    if cc:
        message["Cc"] = cc
    message["Subject"] = subject
    for name, value in (extra_headers or {}).items():
        message[name] = value
    message.set_content(body)
    return base64.urlsafe_b64encode(message.as_bytes()).decode()
