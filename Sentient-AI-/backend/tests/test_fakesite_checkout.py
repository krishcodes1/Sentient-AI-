"""The fake site's checkout pages, /pay and its TLS mode (purchases spec
§9): plain HTTP clients, no browser. These pages are what the checkout
toolkit's tests drive, so their markers are pinned here first."""

from __future__ import annotations

import http.client
import os
import ssl
import stat
from urllib.parse import urlencode, urlsplit

import pytest

from tests.fakesite import FakeSite, luhn_ok
from tests.fakesite.tls import self_signed

VALID_CARD = "4242424242424242"


def request(site: FakeSite, method: str, path: str, body: dict | None = None, *, context=None):
    """One request without following redirects, so a 303 is visible."""
    parts = urlsplit(site.base)
    if parts.scheme == "https":
        connection: http.client.HTTPConnection = http.client.HTTPSConnection(
            parts.hostname, parts.port, context=context, timeout=5
        )
    else:
        connection = http.client.HTTPConnection(parts.hostname, parts.port, timeout=5)
    try:
        data = urlencode(body).encode() if body is not None else None
        headers = {"Content-Type": "application/x-www-form-urlencoded"} if data else {}
        connection.request(method, path, body=data, headers=headers)
        response = connection.getresponse()
        return response.status, dict(response.getheaders()), response.read().decode("utf-8")
    finally:
        connection.close()


@pytest.fixture
def site():
    site = FakeSite().start()
    try:
        yield site
    finally:
        site.stop()


@pytest.mark.parametrize(
    "number, ok",
    [
        (VALID_CARD, True),
        ("4242 4242 4242 4242", True),
        ("5555555555554444", True),
        ("4242424242424241", False),
        ("1234", False),
        ("", False),
        ("4242424242424242x", False),
    ],
)
def test_luhn(number, ok):
    assert luhn_ok(number) is ok


def test_checkout_page_has_the_markers_the_toolkit_reads(site):
    status, _headers, body = request(site, "GET", "/checkout")
    assert status == 200
    assert "<h1>Checkout</h1>" in body
    assert '<ul class="items"><li>Concert ticket — $19.00</li><li>Service fee — $4.40</li></ul>' in body
    assert "Subtotal $19.00" in body
    assert '<p id="total">Total: $23.40</p>' in body
    for autocomplete in ("cc-name", "cc-number", "cc-exp", "cc-csc"):
        assert f'autocomplete="{autocomplete}"' in body
    assert '<form method="post" action="/pay">' in body
    assert '<button type="submit">Place order</button>' in body


@pytest.mark.parametrize(
    "path, total",
    [("/checkout-eur", "Total: €23,40"), ("/checkout-big", "Total: $99.00")],
)
def test_checkout_variants_change_only_the_total(site, path, total):
    status, _headers, body = request(site, "GET", path)
    assert status == 200 and f'<p id="total">{total}</p>' in body
    assert "Concert ticket — $19.00" in body and 'autocomplete="cc-number"' in body


def test_checkout_without_a_total_still_has_the_form(site):
    status, _headers, body = request(site, "GET", "/checkout-no-total")
    assert status == 200 and 'id="total"' not in body and "Total" not in body
    assert "Subtotal $19.00" in body and 'autocomplete="cc-number"' in body


def test_pay_redirects_to_the_confirmation_for_a_luhn_valid_number(site):
    status, headers, _body = request(site, "POST", "/pay", {"cc-number": VALID_CARD, "cc-csc": "123"})
    assert status == 303 and headers["Location"] == "/order-confirmed"
    status, _headers, body = request(site, "GET", "/order-confirmed")
    assert status == 200 and "<h1>Thank you</h1>" in body and "Order number 8841" in body


@pytest.mark.parametrize("field", ["cc-number", "number", "card"])
def test_pay_reads_the_card_number_under_the_common_field_names(site, field):
    status, headers, _body = request(site, "POST", "/pay", {field: VALID_CARD})
    assert status == 303 and headers["Location"] == "/order-confirmed"


@pytest.mark.parametrize("body", [{"cc-number": "4242424242424241"}, {"cc-number": ""}, {}])
def test_pay_declines_anything_else(site, body):
    status, _headers, page = request(site, "POST", "/pay", body)
    assert status == 200 and "<h1>Card declined</h1>" in page


def test_self_signed_certificate_is_private_and_for_the_loopback_address():
    cert, key = self_signed()
    try:
        assert cert.parent == key.parent and cert.parent.name.startswith("fakesite-tls-")
        if os.name != "nt":
            assert stat.S_IMODE(cert.stat().st_mode) == 0o600
            assert stat.S_IMODE(key.stat().st_mode) == 0o600
        pem = cert.read_bytes()
        assert pem.startswith(b"-----BEGIN CERTIFICATE-----")
        from cryptography import x509

        parsed = x509.load_pem_x509_certificate(pem)
        assert parsed.subject.rfc4514_string() == "CN=127.0.0.1"
        san = parsed.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        assert [str(ip) for ip in san.get_values_for_type(x509.IPAddress)] == ["127.0.0.1"]
        assert (parsed.not_valid_after_utc - parsed.not_valid_before_utc).days <= 1
    finally:
        from tests.fakesite.tls import remove

        remove(cert)
        assert not cert.exists()


def test_tls_site_serves_https_with_its_own_certificate_only():
    site = FakeSite(tls=True).start()
    try:
        assert site.base.startswith("https://127.0.0.1:")
        trusted = ssl.create_default_context(cafile=str(site.cert))
        status, _headers, body = request(site, "GET", "/checkout", context=trusted)
        assert status == 200 and "<h1>Checkout</h1>" in body
        # the same POST flow works over TLS
        status, headers, _body = request(
            site, "POST", "/pay", {"cc-number": VALID_CARD}, context=trusted
        )
        assert status == 303 and headers["Location"] == "/order-confirmed"
        # and nothing outside the test trusts it: a default client refuses it
        with pytest.raises(ssl.SSLCertVerificationError):
            request(site, "GET", "/checkout", context=ssl.create_default_context())
        cert = site.cert
    finally:
        site.stop()
    assert cert is not None and not cert.exists()  # the temp dir is cleaned up


def test_tls_site_survives_a_connection_that_never_handshakes():
    """A browser opens speculative connections it may never use; one of
    those must not block the listener."""
    import socket

    site = FakeSite(tls=True).start()
    try:
        parts = urlsplit(site.base)
        idle = socket.create_connection((parts.hostname, parts.port), timeout=5)
        try:
            trusted = ssl.create_default_context(cafile=str(site.cert))
            status, _headers, _body = request(site, "GET", "/", context=trusted)
            assert status == 200
        finally:
            idle.close()
    finally:
        site.stop()
