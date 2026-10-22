"""Tests for services/breach/addresses.py: they prove that only one plain ASCII
mailbox address is accepted (trimmed and lowercased) and that a refusal never
quotes what was typed, that the address digest is a keyed HMAC that is stable
for one ENCRYPTION_KEY and is not a plain hash, that a sealed address opens
again and reads as None (logging the exception type only) once the key
changes, that the hint shows only the first character and the domain, and
that third-party domains pass only as plain DNS names.

Why it exists: these addresses are sent to Have I Been Pwned and shown on
the owner's channels, and the database must not reveal them. A look-alike or
a list slipping through would send someone else's address to a third party;
a refusal that echoed its input would put the address into API answers and
logs. Pure: no database, no network.
"""

from __future__ import annotations

import base64
import hashlib
import os

import pytest

from core.config import settings
from services.breach import addresses
from services.breach.addresses import (
    MAX_ADDED_PER_OWNER,
    MAX_ADDRESS_CHARS,
    REJECTED_MESSAGE,
    AddressRejected,
    address_digest,
    address_hint,
    normalize_address,
    open_address,
    plain_hostname,
    seal_address,
)


def _new_encryption_key() -> str:
    return base64.urlsafe_b64encode(os.urandom(32)).decode("utf-8")


def test_normalize_address_trims_and_lowercases_one_plain_mailbox_address():
    assert normalize_address("  Kash@Example.COM \n") == "kash@example.com"
    assert normalize_address("me.alt+news@mail.example.org") == "me.alt+news@mail.example.org"
    assert normalize_address("o'brien_99%x-y@sub-domain.example.co.uk") == (
        "o'brien_99%x-y@sub-domain.example.co.uk"
    )
    # The longest local part (64) and a long but valid address.
    local = "a" * 64
    assert normalize_address(f"{local}@example.com") == f"{local}@example.com"
    domain = ".".join(["b" * 63] * 3) + ".com"  # 195 characters
    address = f"{'c' * 40}@{domain}"
    assert len(address) <= MAX_ADDRESS_CHARS
    assert normalize_address(address) == address
    assert MAX_ADDED_PER_OWNER == 10


@pytest.mark.parametrize(
    "value",
    [
        "",
        "   ",
        None,
        42,
        b"kash@example.com",
        ["kash@example.com"],
        "kash@example.com, other@example.com",
        "kash@example.com;other@example.com",
        "kash@example.com other@example.com",
        "Kash Person <kash@example.com>",
        "kash example@example.com",
        "kash@exa mple.com",
        "käsh@example.com",  # non-ASCII local part
        "kash@exämple.com",  # non-ASCII domain
        "Kash@example.com",  # KELVIN SIGN, which str.lower() folds to "k"
        "kash@xn--exmple-cua.com​",  # zero-width space
        "ka/sh@example.com",
        "ka\\sh@example.com",
        "kash@example.com/path",
        ".kash@example.com",
        "kash.@example.com",
        "ka..sh@example.com",
        "kash@localhost",
        "admin@localhost",
        "kash@10.0.0.1",
        "kash@example.123",
        "kash@-example.com",
        "kash@example-.com",
        "kash@example..com",
        "kash@.example.com",
        "kash@example.com.",
        "kash@@example.com",
        "kash@sub@example.com",
        "@example.com",
        "kash@",
        "kash",
        '"kash"@example.com',
        "kash@[127.0.0.1]",
        "kash@example.com:8080",
        "a" * 65 + "@example.com",  # local part over 64
        "a" * 60 + "@" + ".".join(["b" * 63] * 4) + ".com",  # over 254 in all
    ],
)
def test_normalize_address_refuses_lists_spaces_non_ascii_slashes_doubled_dots_and_hosts_without_a_dot_without_quoting_the_input(
    value,
):
    with pytest.raises(AddressRejected) as caught:
        normalize_address(value)
    # The refusal is the one fixed sentence whatever was typed, so it quotes nothing.
    assert (
        str(caught.value) == REJECTED_MESSAGE == "Enter one email address, like name@example.com."
    )
    assert "kash" not in str(caught.value)
    assert isinstance(caught.value, ValueError)


def test_address_digest_is_keyed_stable_and_differs_from_a_plain_sha256(monkeypatch):
    first = address_digest("kash@example.com")
    assert first == address_digest("kash@example.com")
    assert len(first) == 64 and all(ch in "0123456789abcdef" for ch in first)
    assert first != address_digest("kash@example.org")
    # Not a plain hash: someone holding only the database cannot confirm a guess.
    assert first != hashlib.sha256(b"kash@example.com").hexdigest()
    # Keyed by ENCRYPTION_KEY: another install (or a rotated key) digests differently.
    monkeypatch.setattr(settings, "ENCRYPTION_KEY", _new_encryption_key())
    assert address_digest("kash@example.com") != first


def test_a_sealed_address_opens_again_and_reads_as_none_after_the_encryption_key_changes(
    monkeypatch,
):
    from structlog.testing import capture_logs

    sealed = seal_address("kash@example.com")
    assert isinstance(sealed, bytes)
    assert b"kash" not in sealed and b"example" not in sealed
    assert open_address(sealed) == "kash@example.com"
    # Sealing twice gives different bytes (a fresh nonce), so equal rows are not visible.
    assert seal_address("kash@example.com") != sealed

    monkeypatch.setattr(settings, "ENCRYPTION_KEY", _new_encryption_key())
    with capture_logs() as logs:
        assert open_address(sealed) is None
        assert open_address(b"short") is None
    assert [entry["event"] for entry in logs] == ["breach_address_unreadable"] * 2
    for entry in logs:
        assert set(entry) <= {"event", "log_level", "error_type"}
        assert "kash" not in repr(entry)


def test_address_hint_shows_the_first_character_and_the_domain_only():
    assert address_hint("kash@example.com") == "k•••@example.com"
    assert address_hint("me.alt@example.org") == "m•••@example.org"
    # A one-character local part shows none of it.
    assert address_hint("k@example.com") == "•••@example.com"
    assert "ash" not in address_hint("kash@example.com")


def test_plain_hostname_keeps_only_plain_dns_names_lowercased():
    assert plain_hostname(" Example-Shop.COM ") == "example-shop.com"
    assert plain_hostname("adobe.com") == "adobe.com"
    for value in (
        None,
        "",
        42,
        "localhost",
        "10.0.0.1",
        "https://example.com",
        "example.com/path",
        "example.com:443",
        "ex ample.com",
        "bücher.de",
        "example..com",
        "-example.com",
        ("a" * 63 + ".") * 4 + "com",
    ):
        assert plain_hostname(value) is None, value


def test_the_digest_key_is_domain_separated_from_other_uses_of_the_encryption_key():
    # The derived key is not the raw ENCRYPTION_KEY nor the audit/oauth derivations.
    key = addresses._digest_key()
    raw = settings.ENCRYPTION_KEY.encode("utf-8")
    assert key != raw
    assert key != hashlib.sha256(b"sentientai.audit.hmac.v1:" + raw).digest()
    assert key == hashlib.sha256(b"sentientai.breach_watch.address.v1:" + raw).digest()
