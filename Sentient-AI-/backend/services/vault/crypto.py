"""AES-256-GCM sealing for vault blobs, plus the card checks the vault runs
before it stores anything (Luhn, brand).

Why it exists: A blob must open only under its own row. The associated
data ``vault_items:{kind}:{item_id}`` is authenticated with the ciphertext,
so a blob copied into another row, or a login blob relabelled as a card,
fails the tag check instead of decrypting. A tag failure is reported as
``VaultUnavailable("cannot decrypt")`` on purpose: from the owner's side a
key that changed and a blob that was tampered with call for the same
action (store the card again), and neither message may hint at contents.
"""

from __future__ import annotations

import os

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from services.vault.keys import KEY_BYTES, VaultUnavailable

NONCE_BYTES = 12
_TAG_BYTES = 16


def _check_key(key: bytes) -> None:
    if len(key) != KEY_BYTES:
        raise VaultUnavailable("The vault key is not usable.")


def seal(key: bytes, plaintext: bytes, aad: bytes) -> bytes:
    """``nonce (12) || AES-256-GCM(plaintext, aad)`` under a fresh nonce."""
    _check_key(key)
    nonce = os.urandom(NONCE_BYTES)
    return nonce + AESGCM(key).encrypt(nonce, plaintext, aad)


def open_(key: bytes, blob: bytes, aad: bytes) -> bytes:
    """The plaintext of a blob from :func:`seal` under the same key and
    aad; ``VaultUnavailable("cannot decrypt")`` for anything else."""
    _check_key(key)
    if len(blob) < NONCE_BYTES + _TAG_BYTES:
        raise VaultUnavailable("cannot decrypt")
    try:
        return AESGCM(key).decrypt(blob[:NONCE_BYTES], blob[NONCE_BYTES:], aad)
    except InvalidTag:
        raise VaultUnavailable("cannot decrypt") from None


def luhn_ok(number: str) -> bool:
    """True for a 12-19 digit string that passes the Luhn check; anything
    with a non-digit in it is False rather than an error."""
    if not number.isdigit() or not 12 <= len(number) <= 19:
        return False
    total = 0
    for index, char in enumerate(reversed(number)):
        digit = ord(char) - 48
        if index % 2 == 1:
            digit *= 2
            if digit > 9:
                digit -= 9
        total += digit
    return total % 10 == 0


def card_brand(number: str) -> str:
    """The network a card number belongs to, by its leading digits; "Card"
    when it is none of the four the label needs to name."""
    if number.startswith("4"):
        return "Visa"
    if number[:2] in ("34", "37"):
        return "Amex"
    two = number[:2]
    four = number[:4]
    if two.isdigit() and 51 <= int(two) <= 55:
        return "Mastercard"
    if four.isdigit() and 2221 <= int(four) <= 2720:
        return "Mastercard"
    if four == "6011" or two == "65":
        return "Discover"
    if number[:3].isdigit() and 644 <= int(number[:3]) <= 649:
        return "Discover"
    return "Card"
