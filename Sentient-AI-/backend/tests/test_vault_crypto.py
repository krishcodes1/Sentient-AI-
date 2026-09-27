"""services/vault/crypto: a blob opens only under its own key and its own
row's associated data, every seal uses a fresh nonce, and the Luhn and
brand checks say what the vault relies on them for. Pure functions, no
database, no OS store."""

from __future__ import annotations

import os

import pytest

from services.vault import crypto
from services.vault.keys import VaultUnavailable

KEY = bytes(range(32))
AAD = b"vault_items:card:0f8fad5b-d9cb-469f-a165-70867728950e"


def test_seal_open_round_trip():
    blob = crypto.seal(KEY, b'{"number":"4242"}', AAD)
    assert blob[: crypto.NONCE_BYTES] != b"\0" * crypto.NONCE_BYTES
    assert b"4242" not in blob
    assert crypto.open_(KEY, blob, AAD) == b'{"number":"4242"}'


def test_every_seal_uses_a_fresh_nonce():
    a = crypto.seal(KEY, b"same", AAD)
    b = crypto.seal(KEY, b"same", AAD)
    assert a != b and a[: crypto.NONCE_BYTES] != b[: crypto.NONCE_BYTES]


def test_open_refuses_another_rows_aad():
    # The associated data pins a blob to its row: copied into another row
    # (or relabelled from login to card) it must not open.
    blob = crypto.seal(KEY, b"secret", AAD)
    with pytest.raises(VaultUnavailable, match="cannot decrypt"):
        crypto.open_(KEY, blob, b"vault_items:card:other-id")
    with pytest.raises(VaultUnavailable, match="cannot decrypt"):
        crypto.open_(KEY, blob, b"vault_items:login:0f8fad5b-d9cb-469f-a165-70867728950e")


def test_open_refuses_another_key_and_a_tampered_byte():
    blob = crypto.seal(KEY, b"secret", AAD)
    with pytest.raises(VaultUnavailable, match="cannot decrypt"):
        crypto.open_(os.urandom(32), blob, AAD)
    flipped = bytearray(blob)
    flipped[-1] ^= 0x01
    with pytest.raises(VaultUnavailable, match="cannot decrypt"):
        crypto.open_(KEY, bytes(flipped), AAD)


def test_open_refuses_a_blob_too_short_to_hold_a_tag():
    with pytest.raises(VaultUnavailable, match="cannot decrypt"):
        crypto.open_(KEY, b"short", AAD)


@pytest.mark.parametrize("bad_key", [b"", b"x" * 16, b"x" * 31, b"x" * 33])
def test_a_key_that_is_not_32_bytes_is_refused_both_ways(bad_key):
    with pytest.raises(VaultUnavailable):
        crypto.seal(bad_key, b"x", AAD)
    with pytest.raises(VaultUnavailable):
        crypto.open_(bad_key, b"x" * 40, AAD)


@pytest.mark.parametrize(
    "number, ok",
    [
        ("4242424242424242", True),
        ("4242424242424241", False),  # one digit off
        ("378282246310005", True),  # Amex, 15 digits
        ("6011111111111117", True),
        ("5555555555554444", True),
        ("4242 4242 4242 4242", False),  # separators are the caller's job
        ("", False),
        ("12345678901", False),  # 11 digits: too short even if Luhn-valid
        ("0000000000000000", True),  # Luhn-valid; brand/issuer checks are elsewhere
        ("4242424242424242x", False),
    ],
)
def test_luhn(number, ok):
    assert crypto.luhn_ok(number) is ok


@pytest.mark.parametrize(
    "number, brand",
    [
        ("4242424242424242", "Visa"),
        ("4000056655665556", "Visa"),
        ("5555555555554444", "Mastercard"),
        ("5105105105105100", "Mastercard"),
        ("2223003122003222", "Mastercard"),  # 2-series range
        ("378282246310005", "Amex"),
        ("371449635398431", "Amex"),
        ("6011111111111117", "Discover"),
        ("6500000000000002", "Discover"),
        ("6445000000000000", "Discover"),
        ("3530111333300000", "Card"),  # JCB: not one the label names
        ("", "Card"),
    ],
)
def test_card_brand(number, brand):
    assert crypto.card_brand(number) == brand
