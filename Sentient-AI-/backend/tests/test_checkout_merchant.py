"""The merchant check behind browser.checkout: punycode and look-alike
letters, typo and homograph domains and other-domain brands of well-known
merchants (a brand as a subdomain of another site, or glued to another
word, too), brand words, subdomains,
two-part public suffixes, bare IP addresses and user names in the host.
Pure; no network, no browser."""

from __future__ import annotations

import pytest

from services.tools.browser.checkout.merchant import (
    WELL_KNOWN_MERCHANTS,
    merchant_refusal,
    registrable_domain,
)

CYRILLIC_AMAZON = "аmazon.com"  # Cyrillic а, renders exactly like amazon.com
PUNYCODE_AMAZON = "аmazon".encode("idna").decode("ascii") + ".com"


@pytest.mark.parametrize(
    "host, expected",
    [
        ("shop.example.com", "shop.example.com"),
        ("shop.example.com", "example.com"),
        ("checkout.ticketmaster.com", "ticketmaster.com"),
        ("www.ticketmaster.com", "ticketmaster"),
        ("www.ticketmaster.com", "Ticketmaster"),
        ("www.ticketmaster.com", "https://www.ticketmaster.com/event/1?x=y"),
        ("www.ticketmaster.com", "ticketmaster.com/"),
        ("amazon.com", "amazon.com"),
        ("shop.example.co.uk", "example.co.uk"),
        ("localhost", "localhost"),
        ("SHOP.Example.com.", "shop.example.com"),
    ],
)
def test_the_merchant_asked_for_passes(host, expected):
    assert merchant_refusal(host, expected) is None


@pytest.mark.parametrize(
    "host, expected, words",
    [
        ("shop.example.com", "amazon.com", "not amazon.com"),
        ("amazon.de", "amazon.com", "not amazon.com"),
        ("other.co.uk", "example.co.uk", "not example.co.uk"),
        ("example.com.evil.net", "example.com", "not example.com"),
        ("ticketmaster.com.evil.net", "ticketmaster", "not ticketmaster"),
        ("notticketmaster.com", "ticketmaster", "not ticketmaster"),
    ],
)
def test_another_site_is_refused_by_name(host, expected, words):
    reason = merchant_refusal(host, expected)
    assert reason is not None and words in reason and host in reason


def test_a_loopback_address_passes_only_under_the_test_toggle(monkeypatch):
    """The fake site lives at https://127.0.0.1; a real checkout never
    does. Same toggle as the network guard's, read at call time."""
    monkeypatch.setenv("CRAWLER_ALLOW_LOOPBACK_FOR_TESTS", "1")
    assert merchant_refusal("127.0.0.1", "127.0.0.1") is None
    monkeypatch.delenv("CRAWLER_ALLOW_LOOPBACK_FOR_TESTS")
    reason = merchant_refusal("127.0.0.1", "127.0.0.1")
    assert reason is not None and "bare IP address" in reason


@pytest.mark.parametrize("host", ["203.0.113.5", "[2001:db8::1]", "10.0.0.7"])
def test_a_bare_ip_host_is_refused_even_when_asked_for(host, monkeypatch):
    monkeypatch.setenv("CRAWLER_ALLOW_LOOPBACK_FOR_TESTS", "1")  # loopback only, never any address
    reason = merchant_refusal(host, host)
    assert reason is not None and "bare IP address" in reason and "not a name" in reason


def test_a_host_with_a_user_name_is_refused():
    reason = merchant_refusal("amazon.com@evil.example", "amazon.com")
    assert reason is not None and "user name" in reason


@pytest.mark.parametrize("host", [CYRILLIC_AMAZON, PUNYCODE_AMAZON, "xn--pple-43d.com", "gооgle.com"])
def test_lookalike_letters_are_refused_even_when_asked_for(host):
    reason = merchant_refusal(host, host)
    assert reason is not None and "look-alike" in reason
    assert merchant_refusal(host, "amazon.com") == reason  # the script rule comes first


def test_mixed_script_label_is_refused():
    reason = merchant_refusal("payρal.com", "paypal.com")  # Greek rho
    assert reason is not None and "look-alike" in reason


@pytest.mark.parametrize(
    "host, known",
    [
        ("amazom.com", "amazon.com"),
        ("www.amazom.com", "amazon.com"),
        ("ticketmaster-tickets.co", "ticketmaster.com"),
        ("secure-paypal.com", "paypal.com"),
        ("tickemaster.com", "ticketmaster.com"),
    ],
)
def test_typo_and_hyphenated_lookalikes_of_known_merchants_are_refused(host, known):
    reason = merchant_refusal(host, host)
    assert reason is not None and f"looks like {known}" in reason
    # Asking for the brand does not launder it either.
    assert merchant_refusal(host, known.split(".")[0]) is not None


@pytest.mark.parametrize(
    "host, expected, known",
    [
        ("amazon.shop", "amazon", "amazon.com"),
        ("amazon.de", "amazon", "amazon.com"),
        ("ticketmaster.xyz", "ticketmaster", "ticketmaster.com"),
        ("paypal.help", "paypal", "paypal.com"),
        ("www.apple.support", "apple", "apple.com"),
        ("apple.co.uk", "apple.co.uk", "apple.com"),
    ],
)
def test_a_known_brand_on_another_domain_is_refused(host, expected, known):
    """The commonest phishing shape: the right brand, the wrong suffix.
    Only the exact known domain passes; the owner opens a real country
    site themselves."""
    reason = merchant_refusal(host, expected)
    assert reason is not None and f"looks like {known}" in reason


@pytest.mark.parametrize(
    "host, known",
    [
        ("amazon.com.evil.com", "amazon.com"),
        ("www.paypal.com.secure-login.xyz", "paypal.com"),
        ("ticketmaster.evil.com", "ticketmaster.com"),
        ("apple-support.com", "apple.com"),
        ("amazon-deals.shop", "amazon.com"),
        ("shop.amazon-deals.example.com", "amazon.com"),
        ("login.paypal-secure.example.net", "paypal.com"),
        ("aa.example.com", "aa.com"),
    ],
)
def test_a_known_brand_anywhere_in_another_sites_host_is_refused(host, known):
    """The brand as a subdomain of someone else's site, or as a
    hyphenated part of any label: the registrable domain is not the
    brand's, whatever the labels in front of it say. Asking for that
    exact host does not launder it."""
    reason = merchant_refusal(host, host)
    assert reason is not None and f"{host} looks like {known}" in reason
    assert "open it themselves" in reason


@pytest.mark.parametrize(
    "host, known",
    [
        ("arnazon.com", "amazon.com"),  # rn reads as m
        ("www.paypa1-login.com", "paypal.com"),
        ("vvalmart.com", "walmart.com"),  # vv reads as w
        ("amazonprime-deals.com", "amazon.com"),
        ("paypalsecure.com", "paypal.com"),
        ("appleid-verify.com", "apple.com"),
        ("ticketmasterresale.com", "ticketmaster.com"),
        ("nikestore.com", "nike.com"),
        ("www.bestbuyoutlet.com", "bestbuy.com"),
        ("my-paypal.help", "paypal.com"),
        ("secureamazonlogin.com", "amazon.com"),
    ],
)
def test_a_known_brand_read_into_or_glued_to_another_word_is_refused(host, known):
    """The model names the merchant, and a page's injected text can supply
    one of these hosts: a homograph of the brand (letters that read as
    others), or the brand glued to another word, on a domain that is not
    the brand's own."""
    reason = merchant_refusal(host, host)
    assert reason is not None and f"{host} looks like {known}" in reason, (host, reason)


@pytest.mark.parametrize("host", ["moniker.com", "consultant.com", "betsyjohnson.com", "tuberose.org", "shop.example.com"])
def test_a_four_letter_brand_inside_an_ordinary_word_is_not_a_lookalike(host):
    """A brand is looked for glued to a word at the start or the end of a
    label from four letters, and inside one only from five: "nike" is in
    "moniker", "ulta" in "consultant", "etsy" in "betsyjohnson"."""
    assert merchant_refusal(host, host) is None, host


@pytest.mark.parametrize(
    "host, expected",
    [
        ("www.amazon.com", "amazon.com"),
        ("smile.amazon.com", "amazon.com"),
        ("checkout.ticketmaster.com", "ticketmaster.com"),
        ("checkout.ticketmaster.com", "ticketmaster"),
        ("pay.google.com", "google.com"),
    ],
)
def test_a_known_brand_on_its_own_domain_passes_under_any_subdomain(host, expected):
    assert merchant_refusal(host, expected) is None


@pytest.mark.parametrize(
    "host",
    ["hpcomputers.com", "bath.com", "shop.aaa.com", "tickets.bath.co.uk", "cvsphotos.example.com",
     "hp-store.example.com", "aaa-tickets.example.com"],
)
def test_a_short_brand_is_not_read_into_a_longer_word(host):
    """Outside the brand label a label must name a known brand exactly:
    "aa" (a listed brand) is not in "aaa" or "bath", "cvs" is not in
    "cvsphotos"."""
    assert merchant_refusal(host, host) is None, host


@pytest.mark.parametrize(
    "host",
    ["hp.com", "dell.com", "ba.com", "ups.com", "att.com", "gap.com", "cbs.com", "nba.com",
     "aaa.com", "store.hp.com", "www.hp.com", "ford.com", "sony.com"],
)
def test_short_real_brands_are_not_typos_of_short_known_ones(host):
    """Edit distance is measured on the brand label without the suffix
    and scaled to its length: "hp" is within two edits of "aa" and "cvs",
    which says nothing."""
    assert merchant_refusal(host, host) is None, host


@pytest.mark.parametrize(
    "host, known",
    [("amazn.com", "amazon.com"), ("amazonn.com", "amazon.com"), ("paypa1.com", "paypal.com"),
     ("ticketmaster.com.co", "ticketmaster.com"), ("ebay.shop", "ebay.com")],
)
def test_typos_of_longer_brands_and_brand_suffix_tricks_are_still_refused(host, known):
    reason = merchant_refusal(host, host)
    assert reason is not None and f"looks like {known}" in reason


def test_a_known_merchant_is_not_its_own_lookalike():
    for known in WELL_KNOWN_MERCHANTS:
        assert merchant_refusal(known, known) is None, known
        assert merchant_refusal("www." + known, known) is None, known


def test_nothing_asked_for_is_refused():
    for expected in ("", "   ", None):
        reason = merchant_refusal("shop.example.com", expected)  # type: ignore[arg-type]
        assert reason is not None and "Say which site" in reason


def test_unreadable_hosts_are_refused():
    assert merchant_refusal("", "example.com") is not None
    assert merchant_refusal("xn--ÿ.com", "example.com") is not None


@pytest.mark.parametrize(
    "host, domain",
    [
        ("shop.example.com", "example.com"),
        ("a.b.example.co.uk", "example.co.uk"),
        ("example.co.uk", "example.co.uk"),
        ("example.com", "example.com"),
        ("localhost", "localhost"),
        ("127.0.0.1", "127.0.0.1"),
        ("Shop.Example.COM.", "example.com"),
        ("checkout.stripe.com", "stripe.com"),
    ],
)
def test_registrable_domain(host, domain):
    assert registrable_domain(host) == domain
