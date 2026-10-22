"""Normalises, validates, digests, seals, opens and hints the email addresses the
breach monitor watches. Pure: no I/O beyond the AES key in settings.

Why it exists: a watched address is sent to Have I Been Pwned and shown to the
owner, so Crawler must hold it in a form it can read back (sealed with
``core.security.encrypt_credentials``, AES-256-GCM, like connector
credentials), yet find it, compare it and spot a changed sign-in address
without plain text in the database. The digest is a keyed HMAC, so someone
holding only the database cannot confirm a guessed address offline. Only one
plain ASCII mailbox address is accepted: anything else (a list, a display
name, a non-ASCII look-alike, a host without a dot such as ``admin@localhost``)
is refused with a sentence that never quotes what was typed, because the
refusal reaches API answers and logs.
"""

from __future__ import annotations

import hashlib
import hmac
import re
from typing import Optional

import structlog

from core.config import settings
from core.security import decrypt_credentials, encrypt_credentials

logger = structlog.get_logger(__name__)

MAX_ADDRESS_CHARS = 254
MAX_ADDED_PER_OWNER = 10
# RFC 5321's local-part limit.
MAX_LOCAL_CHARS = 64
# A DNS name's limit (same as models.breach_watch.DOMAIN_MAX_CHARS).
MAX_DOMAIN_CHARS = 253

# The one refusal sentence. It never quotes the input: it reaches 422 answers.
REJECTED_MESSAGE = "Enter one email address, like name@example.com."

# Domain separation for the address HMAC key, the idiom of
# services/connectors/oauth.py (_state_key) and notifications/slack.py
# (_link_key): one ENCRYPTION_KEY, a distinct derived key per use.
_DIGEST_KEY_DOMAIN = b"sentientai.breach_watch.address.v1:"

# The local part: letters, digits and . _ % + ' - only (so never a slash, a
# backslash, a space, a comma or a quote pair), 1 to 64 characters; dots are
# checked separately (no leading, trailing or doubled dot).
_LOCAL_RE = re.compile(r"[a-z0-9._%+'-]{1,64}")
# A plain DNS name, the rule of services/connectors/canvas_schools.py
# (_DOMAIN_RE): dot-separated labels of letters, digits and inner hyphens, at
# least two labels, and a last label that starts with a letter (so never an
# IP address and never a single-label host such as "localhost").
_LABEL = "[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
_DOMAIN_RE = re.compile(f"(?:{_LABEL}[.])+[a-z](?:[a-z0-9-]{{0,61}}[a-z0-9])?")

# The hint's mask: three bullets stand in for the rest of the local part.
_MASK = "•••"


class AddressRejected(ValueError):
    """An address Crawler will not watch; the message is for the owner and never quotes the input."""

    def __init__(self, message: str = REJECTED_MESSAGE) -> None:
        super().__init__(message)


def normalize_address(value: object) -> str:
    """The address trimmed and lowercased, or AddressRejected unless it is one plain ASCII
    mailbox address: local part [a-z0-9._%+'-]{1,64} (no leading, trailing or doubled dot, no
    slash or backslash), '@', and a dotted DNS name whose last label starts with a letter
    (the canvas_schools._DOMAIN_RE rule). At most 254 characters."""
    if not isinstance(value, str):
        raise AddressRejected()
    candidate = value.strip()
    # ASCII is checked before lowercasing: str.lower() folds some non-ASCII
    # letters into ASCII ones (KELVIN SIGN becomes "k"), which would let a
    # look-alike through as a different address than the one typed.
    if not candidate or not candidate.isascii() or len(candidate) > MAX_ADDRESS_CHARS:
        raise AddressRejected()
    candidate = candidate.lower()
    local, at, domain = candidate.partition("@")
    if not at or "@" in domain:
        raise AddressRejected()
    if not _LOCAL_RE.fullmatch(local):
        raise AddressRejected()
    if local.startswith(".") or local.endswith(".") or ".." in local:
        raise AddressRejected()
    if len(domain) > MAX_DOMAIN_CHARS or not _DOMAIN_RE.fullmatch(domain):
        raise AddressRejected()
    return candidate


def plain_hostname(value: object) -> Optional[str]:
    """*value* trimmed and lowercased when it is a plain ASCII DNS name (the domain rule above,
    at most 253 characters), else None. Used for third-party domains (HIBP's breach Domain)."""
    if not isinstance(value, str):
        return None
    candidate = value.strip()
    if not candidate or not candidate.isascii() or len(candidate) > MAX_DOMAIN_CHARS:
        return None
    candidate = candidate.lower()
    return candidate if _DOMAIN_RE.fullmatch(candidate) else None


def _digest_key() -> bytes:
    return hashlib.sha256(_DIGEST_KEY_DOMAIN + settings.ENCRYPTION_KEY.encode("utf-8")).digest()


def address_digest(normalized: str) -> str:
    """HMAC-SHA256 hex of *normalized* under the breach-watch key derived from ENCRYPTION_KEY."""
    return hmac.new(_digest_key(), normalized.encode("utf-8"), hashlib.sha256).hexdigest()


def seal_address(normalized: str) -> bytes:
    """encrypt_credentials(normalized)."""
    return encrypt_credentials(normalized)


def open_address(blob: bytes) -> Optional[str]:
    """The address, or None when the blob no longer decrypts (ENCRYPTION_KEY changed); logs the
    exception type only."""
    try:
        return decrypt_credentials(blob)
    except Exception as exc:
        # The type only: neither the blob nor anything derived from it.
        logger.warning("breach_address_unreadable", error_type=type(exc).__name__)
        return None


def address_hint(normalized: str) -> str:
    """'k•••@example.com' (first character of the local part, then •••; just '•••@domain' for a
    one-character local part). Used in channel messages."""
    local, _, domain = normalized.partition("@")
    if len(local) <= 1:
        return f"{_MASK}@{domain}"
    return f"{local[0]}{_MASK}@{domain}"
