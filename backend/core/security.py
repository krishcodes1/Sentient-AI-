from __future__ import annotations

import base64
import hashlib
import json
import os
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

import jwt as pyjwt
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from jwt import ExpiredSignatureError, InvalidTokenError
from passlib.context import CryptContext

from core.config import settings

# ── Password hashing ─────────────────────────────────────────────────────────

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def hash_password(plain: str) -> str:
    """Return a bcrypt hash of *plain*."""
    return pwd_context.hash(plain)


def verify_password(plain: str, hashed: str) -> bool:
    """Return ``True`` if *plain* matches *hashed*."""
    return pwd_context.verify(plain, hashed)


# ── JWT tokens ────────────────────────────────────────────────────────────────

JWT_ALGORITHM = "HS256"

# Token type constants
TOKEN_TYPE_ACCESS = "access"
TOKEN_TYPE_REFRESH = "refresh"  # noqa: S105  # token-type label, not a credential


def create_access_token(
    subject: str | dict[str, Any] | None = None,
    expires_delta: Optional[timedelta] = None,
    extra_claims: Optional[dict[str, Any]] = None,
    *,
    data: Optional[dict[str, Any]] = None,
) -> str:
    """Create a signed access JWT.

    Calling forms (any one of these works):
      - ``create_access_token("user-id-123")``
      - ``create_access_token({"sub": "user-id-123", "email": "x@y"})``
      - ``create_access_token(data={"sub": "user-id-123", "email": "x@y"})``
        (legacy keyword form, retained for back-compat with older callers)
      - ``create_access_token("user-id-123", extra_claims={"email": "x@y"})``
    """
    now = datetime.now(timezone.utc)
    expire = now + (
        expires_delta or timedelta(minutes=settings.TOKEN_EXPIRE_MINUTES)
    )

    payload: dict[str, Any] = {}

    # Resolve subject + any embedded claims from positional / keyword forms.
    sub_value: str = ""
    if isinstance(subject, dict):
        payload.update(subject)
        sub_value = str(payload.get("sub", ""))
    elif subject is not None:
        sub_value = str(subject)

    if data is not None:
        # Legacy keyword form: dict carries sub + extra claims.
        payload.update(data)
        if not sub_value:
            sub_value = str(payload.get("sub", ""))

    if extra_claims:
        payload.update(extra_claims)

    payload.update(
        {
            "sub": sub_value,
            "exp": expire,
            "iat": now,
            "jti": uuid.uuid4().hex,
            "type": TOKEN_TYPE_ACCESS,
        }
    )
    return pyjwt.encode(payload, settings.SECRET_KEY, algorithm=JWT_ALGORITHM)


def create_refresh_token(
    subject: str,
    expires_delta: Optional[timedelta] = None,
    extra_claims: Optional[dict[str, Any]] = None,
) -> str:
    """Create a signed refresh JWT with a longer default expiry."""
    now = datetime.now(timezone.utc)
    expire = now + (
        expires_delta
        or timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS)
    )
    payload: dict[str, Any] = {}
    if extra_claims:
        payload.update(extra_claims)
    payload.update(
        {
            "sub": str(subject),
            "exp": expire,
            "iat": now,
            "jti": uuid.uuid4().hex,
            "type": TOKEN_TYPE_REFRESH,
        }
    )
    return pyjwt.encode(payload, settings.SECRET_KEY, algorithm=JWT_ALGORITHM)


def verify_token(token: str, expected_type: str = TOKEN_TYPE_ACCESS) -> dict[str, Any]:
    """Decode and validate a JWT. Raises ``InvalidTokenError`` on any mismatch.

    Callers (route handlers) should catch ``InvalidTokenError`` (also covers
    ``ExpiredSignatureError``) and translate to a 401 response.
    """
    payload: dict[str, Any] = pyjwt.decode(
        token,
        settings.SECRET_KEY,
        algorithms=[JWT_ALGORITHM],
    )
    if payload.get("type") != expected_type:
        raise InvalidTokenError(
            f"Token type mismatch: expected {expected_type!r}, "
            f"got {payload.get('type')!r}"
        )
    return payload


def verify_access_token(token: str) -> dict[str, Any]:
    """Backwards-compatible alias for :func:`verify_token` with ``access`` type."""
    return verify_token(token, TOKEN_TYPE_ACCESS)


def hash_token(token: str) -> str:
    """Return SHA-256 hex digest of *token*.

    Used to store refresh tokens as hashes rather than plaintext, so a
    database compromise does not yield usable refresh tokens.
    """
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


# ── AES-256-GCM credential encryption ────────────────────────────────────────
#
# Versioned blob format (current, v1):
#   version (1 byte = 0x01) || nonce (12 bytes) || ciphertext+tag
#
# Legacy blob format (v0, no version byte):
#   nonce (12 bytes) || ciphertext+tag
#
# Decryption transparently handles both formats so existing rows produced
# by ``encrypt_credentials`` continue to decrypt. New writes always use v1.
#
# AAD (Additional Authenticated Data) binds a ciphertext to its context
# (e.g. ``u<user_id>:<field>``). Without AAD, an attacker with DB write
# access could swap one user's encrypted blob into another user's row.
# Strongly prefer ``encrypt_for_user`` / ``decrypt_for_user`` for any new
# call sites.
#
# MIGRATION NOTES — files that should adopt ``encrypt_for_user``/``decrypt_for_user``
# (do NOT modify in this change; tracked in a follow-up):
#   - api/routes/auth.py            (User.llm_api_key_enc)
#   - api/routes/connectors.py      (ConnectorConfig.encrypted_credentials)
#   - api/routes/channels.py        (Channel.config_enc)
#   - api/routes/agent.py           (User.llm_api_key_enc decrypt path)
#   - services/openclaw/config_manager.py  (User.llm_api_key_enc decrypt path)
#   - services/connectors/*         (any new credential storage)

_AES_VERSION_V1 = 0x01


def _get_aes_key() -> bytes:
    """Decode the base64 ENCRYPTION_KEY into raw 32 bytes."""
    raw = base64.urlsafe_b64decode(settings.ENCRYPTION_KEY)
    if len(raw) != 32:
        raise ValueError("ENCRYPTION_KEY must decode to exactly 32 bytes")
    return raw


def encrypt_value(plaintext: str, aad: bytes | None = None) -> bytes:
    """Encrypt *plaintext* with AES-256-GCM, returning a versioned blob.

    Format: ``0x01 || nonce(12) || ciphertext+tag``. *aad* (if provided) is
    bound into the GCM tag; the same value MUST be supplied to
    :func:`decrypt_value`.
    """
    key = _get_aes_key()
    nonce = os.urandom(12)
    aesgcm = AESGCM(key)
    ct = aesgcm.encrypt(nonce, plaintext.encode("utf-8"), aad)
    return bytes([_AES_VERSION_V1]) + nonce + ct


def decrypt_value(blob: bytes, aad: bytes | None = None) -> str:
    """Decrypt a blob produced by :func:`encrypt_value` or the legacy
    :func:`encrypt_credentials`.

    Tries the v1 (versioned) format first; on failure, falls back to the
    legacy unversioned format (12-byte nonce prefix). The legacy fallback
    only succeeds if no AAD was supplied, since legacy blobs were written
    without AAD.
    """
    key = _get_aes_key()
    aesgcm = AESGCM(key)

    # v1: starts with version byte 0x01
    if len(blob) >= 1 + 12 + 16 and blob[0] == _AES_VERSION_V1:
        try:
            nonce = blob[1:13]
            ct = blob[13:]
            return aesgcm.decrypt(nonce, ct, aad).decode("utf-8")
        except Exception:
            # Fall through to legacy attempt.
            pass

    # Legacy v0: no version byte; nonce is the first 12 bytes.
    nonce, ct = blob[:12], blob[12:]
    return aesgcm.decrypt(nonce, ct, aad).decode("utf-8")


def _user_field_aad(user_id: int | str | uuid.UUID, field: str) -> bytes:
    return f"u{user_id}:{field}".encode("utf-8")


def encrypt_for_user(
    user_id: int | str | uuid.UUID,
    field: str,
    plaintext: str,
) -> bytes:
    """Encrypt *plaintext* binding it to ``(user_id, field)`` via AAD.

    Prefer this over :func:`encrypt_value` for any per-user credential
    storage so blobs cannot be transplanted between users or fields.
    """
    return encrypt_value(plaintext, aad=_user_field_aad(user_id, field))


def decrypt_for_user(
    user_id: int | str | uuid.UUID,
    field: str,
    blob: bytes,
) -> str:
    """Decrypt a blob written by :func:`encrypt_for_user`."""
    return decrypt_value(blob, aad=_user_field_aad(user_id, field))


# ── Legacy credential helpers (kept for back-compat) ─────────────────────────
#
# These now write the new versioned format but with NO AAD, matching the
# previous calling convention. Existing callers continue to work; the
# ``decrypt_value`` fallback handles both old and new blob formats.

def encrypt_credentials(plaintext: str) -> bytes:
    """Legacy alias — encrypt without AAD. Prefer :func:`encrypt_for_user`."""
    return encrypt_value(plaintext, aad=None)


def decrypt_credentials(blob: bytes) -> str:
    """Legacy alias — decrypt blobs written without AAD. Prefer
    :func:`decrypt_for_user`."""
    return decrypt_value(blob, aad=None)


# ── Request / audit helpers ───────────────────────────────────────────────────

def generate_request_id() -> str:
    """Return a new UUID4 string suitable for correlating logs."""
    return str(uuid.uuid4())


def compute_audit_hash(payload: dict[str, Any]) -> str:
    """Produce a SHA-256 hex digest over a canonical JSON serialization.

    This makes audit rows tamper-evident: any modification to the stored
    fields will invalidate the hash.
    """
    canonical = json.dumps(payload, sort_keys=True, default=str)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


_SENSITIVE_KEYS = frozenset(
    {
        "password",
        "secret",
        "token",
        "api_key",
        "apikey",
        "authorization",
        "credentials",
        "credit_card",
        "ssn",
        "encryption_key",
        "secret_key",
        "access_token",
        "refresh_token",
    }
)


def sanitize_for_logging(data: dict[str, Any]) -> dict[str, Any]:
    """Return a shallow copy of *data* with sensitive values replaced by ``'***'``.

    Keys are compared case-insensitively against a built-in deny-list.
    """
    sanitized: dict[str, Any] = {}
    for key, value in data.items():
        if key.lower() in _SENSITIVE_KEYS:
            sanitized[key] = "***"
        elif isinstance(value, dict):
            sanitized[key] = sanitize_for_logging(value)
        else:
            sanitized[key] = value
    return sanitized
