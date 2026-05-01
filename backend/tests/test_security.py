"""Tests for password hashing, JWT signing, and credential encryption."""

from __future__ import annotations

import base64
import os

import jwt as pyjwt
import pytest
from jwt import InvalidTokenError

from core.security import (
    JWT_ALGORITHM,
    create_access_token,
    decrypt_credentials,
    encrypt_credentials,
    hash_password,
    verify_access_token,
    verify_password,
)


# ---------------------------------------------------------------------------
# Symmetric encryption (AES-256-GCM) — alias-style names per the spec.
# ---------------------------------------------------------------------------


def encrypt_value(value: str) -> bytes:
    """Spec alias for :func:`encrypt_credentials`."""
    return encrypt_credentials(value)


def decrypt_value(blob: bytes) -> str:
    """Spec alias for :func:`decrypt_credentials`."""
    return decrypt_credentials(blob)


def test_encrypt_then_decrypt_round_trips() -> None:
    """A value encrypted and immediately decrypted must equal the original."""
    plaintext = "super-secret-api-key-1234567890"
    blob = encrypt_value(plaintext)
    assert isinstance(blob, bytes)
    assert blob != plaintext.encode("utf-8")
    assert decrypt_value(blob) == plaintext


def test_encrypt_produces_different_ciphertext_each_call() -> None:
    """AES-GCM with a random nonce must not produce identical ciphertexts."""
    plaintext = "same-value-twice"
    a = encrypt_value(plaintext)
    b = encrypt_value(plaintext)
    assert a != b
    assert decrypt_value(a) == plaintext
    assert decrypt_value(b) == plaintext


def test_decrypt_with_wrong_key_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    """Decrypting with a different key must raise."""
    plaintext = "very-secret"
    blob = encrypt_value(plaintext)

    # Swap the key by patching the env-derived setting.
    new_key = base64.urlsafe_b64encode(os.urandom(32)).decode()
    from core import config as _cfg

    monkeypatch.setattr(_cfg.settings, "ENCRYPTION_KEY", new_key, raising=False)

    with pytest.raises(Exception):
        decrypt_value(blob)


# ---------------------------------------------------------------------------
# JWT round-trips and tamper detection.
# ---------------------------------------------------------------------------


def test_jwt_create_and_verify_round_trip() -> None:
    """A token signed with the live key must verify and yield its claims."""
    token = create_access_token({"sub": "user-123", "email": "x@y.com"})
    payload = verify_access_token(token)
    assert payload["sub"] == "user-123"
    assert payload["email"] == "x@y.com"
    assert "exp" in payload


def test_jwt_with_tampered_signature_rejected() -> None:
    """Mutating any character past the last dot must invalidate the token."""
    token = create_access_token({"sub": "user-123"})
    head, body, sig = token.split(".")
    # Flip a character in the signature.
    bad_sig = "A" if sig[0] != "A" else "B"
    tampered = f"{head}.{body}.{bad_sig}{sig[1:]}"

    with pytest.raises(InvalidTokenError):
        verify_access_token(tampered)


def test_jwt_with_wrong_secret_rejected() -> None:
    """A token signed with a foreign key must not verify against ours."""
    foreign = pyjwt.encode(
        {"sub": "u", "type": "access"},
        "not-the-real-secret",
        algorithm=JWT_ALGORITHM,
    )
    with pytest.raises(InvalidTokenError):
        verify_access_token(foreign)


# ---------------------------------------------------------------------------
# Password hashing.
# ---------------------------------------------------------------------------


def test_bcrypt_password_round_trip() -> None:
    """``verify_password`` must accept the same plaintext that produced the hash."""
    pw = "Hunter2!Hunter2"
    hashed = hash_password(pw)
    assert hashed != pw
    assert verify_password(pw, hashed) is True
    assert verify_password("wrong-password", hashed) is False


def test_bcrypt_hash_is_not_deterministic() -> None:
    """Two hashes of the same password should differ (salt)."""
    pw = "same-password"
    a = hash_password(pw)
    b = hash_password(pw)
    assert a != b
    assert verify_password(pw, a) is True
    assert verify_password(pw, b) is True
