from __future__ import annotations

import base64
import hashlib
import json
import os
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from jose import JWTError, jwt
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


def create_access_token(
    data: dict[str, Any],
    expires_delta: timedelta | None = None,
) -> str:
    """Create a signed JWT containing *data* with an expiry claim."""
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + (
        expires_delta or timedelta(minutes=settings.TOKEN_EXPIRE_MINUTES)
    )
    to_encode.update({"exp": expire, "iat": datetime.now(timezone.utc)})
    return jwt.encode(to_encode, settings.SECRET_KEY, algorithm=JWT_ALGORITHM)


def verify_access_token(token: str) -> dict[str, Any]:
    """Decode and validate a JWT.  Raises ``JWTError`` on failure."""
    try:
        payload: dict[str, Any] = jwt.decode(
            token,
            settings.SECRET_KEY,
            algorithms=[JWT_ALGORITHM],
        )
        return payload
    except JWTError:
        raise


# ── AES-256-GCM credential encryption ────────────────────────────────────────

def _get_aes_key() -> bytes:
    """Decode the base64 ENCRYPTION_KEY into raw 32 bytes."""
    raw = base64.urlsafe_b64decode(settings.ENCRYPTION_KEY)
    if len(raw) != 32:
        raise ValueError("ENCRYPTION_KEY must decode to exactly 32 bytes")
    return raw


def encrypt_credentials(plaintext: str) -> bytes:
    """Encrypt *plaintext* with AES-256-GCM.

    Returns ``nonce (12 bytes) || ciphertext+tag``.
    """
    key = _get_aes_key()
    nonce = os.urandom(12)
    aesgcm = AESGCM(key)
    ct = aesgcm.encrypt(nonce, plaintext.encode("utf-8"), None)
    return nonce + ct


def decrypt_credentials(blob: bytes) -> str:
    """Decrypt a blob produced by :func:`encrypt_credentials`."""
    key = _get_aes_key()
    nonce, ct = blob[:12], blob[12:]
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ct, None).decode("utf-8")


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
