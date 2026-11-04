"""Tests for core.security's bcrypt hashing: hashes written by the old passlib
code still verify (short, accented, emoji, exactly 72 bytes, longer than 72,
and a 72-byte cut that lands inside a character), new hashes are $2b$ at cost
12 like passlib's, only the first 72 bytes of a password count, and a NUL byte
or a stored value that is not a bcrypt hash raises ValueError as before.

Why it exists: passlib was replaced by direct bcrypt calls for bcrypt 5, which
raises on passwords over 72 bytes where passlib cut them silently. Every
account's stored hash came from passlib, so a difference here locks people out.
The fixture hashes below were made by passlib 1.7.4 on bcrypt 4.3.0, the
versions the app ran before the switch.
"""

from __future__ import annotations

import pytest

from core.security import hash_password, verify_password

# (plain text, hash written by passlib's CryptContext(schemes=["bcrypt"])).
PASSLIB_HASHES = [
    ("horse-battery-123", "$2b$12$k0c7I/4X5eijYHzEsU5hIevW7lwBb8NDW4SJj.tiq3T03Q7VOPiRW"),
    (
        "café-crème-brûlée",
        "$2b$12$TVhKSz/1aJNzlFGNd9VkT.lBRHgKzLWKC3lKQQibmNNdY/D2tpnQC",
    ),
    ("moon-\U0001f319-star-⭐", "$2b$12$C/F7RMstWhEK3CFctfhhkOhRVnMpqUFlQYQmCf.tBzUyeBwE5P5sy"),
    ("a" * 72, "$2b$12$0cgkN15xws4ST3EKMH/1BOHxpthdodYr9WfzMoiGKWvFKM9LtJjv2"),
    ("b" * 100, "$2b$12$1DPFkTYEG1sXV6981Iwrq.mcT6ys10bbg125xy.xbcYsIoOFX2cNS"),
    # Byte 72 is the first half of the two-byte é.
    ("x" * 71 + "étail", "$2b$12$ujUUxExcLBE6gx3MvDEidOJRkLVJWSNXKQKi.ISAaS/2ZNuruf3.2"),
]


@pytest.mark.parametrize(("plain", "hashed"), PASSLIB_HASHES)
def test_hashes_written_by_passlib_still_verify(plain, hashed):
    assert verify_password(plain, hashed) is True
    assert verify_password("!" + plain[1:], hashed) is False


def test_new_hashes_are_b_at_cost_12_salted_and_round_trip():
    first, second = hash_password("horse-battery-123"), hash_password("horse-battery-123")
    assert first.startswith("$2b$12$") and len(first) == 60
    assert first != second
    assert verify_password("horse-battery-123", first)
    assert verify_password("horse-battery-123", second)
    assert not verify_password("horse-battery-124", first)


def test_only_the_first_72_bytes_count_as_passlib_did():
    hashed = hash_password("b" * 100)
    assert verify_password("b" * 72 + "anything else", hashed)
    assert not verify_password("b" * 71, hashed)
    # The old long-password hashes agree with the new ones on the cut.
    assert verify_password("b" * 72 + "anything else", PASSLIB_HASHES[4][1])
    assert verify_password("x" * 71 + "éOTHER", PASSLIB_HASHES[5][1])
    assert verify_password("x" * 71 + "éOTHER", hash_password("x" * 71 + "étail"))


@pytest.mark.parametrize(
    "call",
    [
        lambda: hash_password("ab\x00cd"),
        lambda: verify_password("ab\x00cd", PASSLIB_HASHES[0][1]),
        lambda: verify_password("horse-battery-123", "not-a-hash"),
        lambda: verify_password("horse-battery-123", ""),
    ],
    ids=["hash-nul", "verify-nul", "verify-malformed", "verify-empty"],
)
def test_a_nul_byte_or_a_value_that_is_not_a_bcrypt_hash_raises_value_error(call):
    with pytest.raises(ValueError):
        call()
