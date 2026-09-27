"""A self-signed certificate for the fake site's TLS mode (spec §9).

browser.act refuses to type on an ``http://`` page and browser.checkout
refuses to pay on one, so the tests need an ``https://`` site that is
still the local fake site. ``self_signed`` mints a throwaway certificate
for 127.0.0.1, valid for a day, into a fresh temp dir with 0600 files;
the test launcher trusts it with ``ignore_https_errors=True``, which the
production launcher never sets (test_browser_session's contract test).
Nothing here is ever imported by production code.
"""

from __future__ import annotations

import ipaddress
import os
import shutil
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

_DIR_PREFIX = "fakesite-tls-"


def _write_private(path: Path, data: bytes) -> None:
    """Create *path* readable by this user only (the mode is set at open,
    so there is no window where the key is world-readable)."""
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as handle:
        handle.write(data)


def self_signed(host: str = "127.0.0.1") -> tuple[Path, Path]:
    """``(cert_path, key_path)`` for a one-day self-signed certificate
    whose subject and alternative name are *host* (an IP literal or a DNS
    name). The files live in a new temp dir; ``remove(cert_path)`` drops
    it."""
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, host)])
    try:
        alt: x509.GeneralName = x509.IPAddress(ipaddress.ip_address(host))
    except ValueError:
        alt = x509.DNSName(host)
    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=1))
        .add_extension(x509.SubjectAlternativeName([alt]), critical=False)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    directory = Path(tempfile.mkdtemp(prefix=_DIR_PREFIX))
    cert_path, key_path = directory / "cert.pem", directory / "key.pem"
    _write_private(cert_path, cert.public_bytes(serialization.Encoding.PEM))
    _write_private(
        key_path,
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ),
    )
    return cert_path, key_path


def remove(cert_path: Path) -> None:
    """Delete the temp dir ``self_signed`` made (identified by its prefix,
    so a caller can never point this at anything else)."""
    directory = cert_path.parent
    if directory.name.startswith(_DIR_PREFIX):
        shutil.rmtree(directory, ignore_errors=True)
