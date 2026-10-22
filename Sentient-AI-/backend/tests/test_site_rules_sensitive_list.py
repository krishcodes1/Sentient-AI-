"""Tests for the built-in sensitive-sites list and the protected hosts
(services/site_rules/sensitive_sites.py): they prove every built-in entry
is a valid "site and subdomains" pattern that the owner's own parser would
store unchanged, that no entry repeats or sits inside another, that the
four categories keep their stored keys and labels, that no built-in entry
covers a payment processor, sign-in or CAPTCHA host (except the two
government sign-in services, which stay Always ask), and that the
protected hosts include every MFA and CAPTCHA host the handoff detector
knows and the payment subset of the merchant list.

Why it exists: the list is Always ask by default, so a payment or sign-in
host on it would put a sensitive-site warning on every approved purchase
step, and a category set to Blocked would break sign-ins and 3-D Secure
mid-purchase. Category keys are stored in database rows, so renaming one
would orphan the owner's overrides. Pure: no database, no network.
"""

from __future__ import annotations

import itertools

import pytest

from services.site_rules.patterns import (
    host_of,
    is_protected,
    normalise_pattern,
    overlaps,
    parse_site,
    pattern_base,
)
from services.site_rules.sensitive_sites import (
    BANKS,
    CATEGORIES,
    CATEGORY_KEYS,
    CHECKOUT_EXEMPT_CATEGORY,
    DEFAULT_CATEGORY_KIND,
    PAYMENT_PROCESSORS,
    PROTECTED_PATTERNS,
    SENSITIVE_AND_PROTECTED,
    category,
)
from services.tools.browser import handoff
from services.tools.browser.checkout.merchant import WELL_KNOWN_MERCHANTS

ALL_ENTRIES = [(c.key, site) for c in CATEGORIES for site in c.sites]


@pytest.mark.parametrize("key, site", ALL_ENTRIES)
def test_every_built_in_entry_is_a_valid_wildcard_pattern_and_none_repeats(key, site):
    assert site.startswith("*."), site
    # What the owner's own parser would store for this site, unchanged.
    assert parse_site(site, include_subdomains=True) == site
    assert normalise_pattern(site) == site
    assert [s for _, s in ALL_ENTRIES].count(site) == 1, f"{site} is listed twice"


def test_no_built_in_entry_sits_inside_another():
    # A nested pair would make the inner one's category depend on lookup order.
    sites = [site for _, site in ALL_ENTRIES]
    nested = [(a, b) for a, b in itertools.combinations(sites, 2) if overlaps(a, b)]
    assert nested == []


def test_the_built_in_list_names_no_payment_sign_in_or_captcha_host():
    covering = {
        (site, protected)
        for _, site in ALL_ENTRIES
        for protected in PROTECTED_PATTERNS
        if overlaps(site, protected)
    }
    # Only the government sign-in services are both, on purpose: protected
    # only forbids Blocked, so they stay Always ask.
    assert {site for site, _ in covering} == set(SENSITIVE_AND_PROTECTED)
    assert all(site == protected for site, protected in covering)
    for processor in PAYMENT_PROCESSORS + ("klarna.com", "affirm.com", "afterpay.com"):
        assert not any(overlaps(site, f"*.{processor}") for _, site in ALL_ENTRIES), processor


def test_every_category_has_a_stable_key_a_label_and_at_least_five_sites():
    assert CATEGORY_KEYS == ("banks", "brokers", "crypto", "government")
    assert [c.label for c in CATEGORIES] == [
        "Banks and money accounts",
        "Brokers and investing",
        "Crypto exchanges and wallets",
        "Tax and government services",
    ]
    for c in CATEGORIES:
        assert len(c.sites) >= 5, c.key
        assert category(c.key) is c
    assert category("payments") is None
    assert category("") is None
    assert category(None) is None  # type: ignore[arg-type]
    assert DEFAULT_CATEGORY_KIND == "always_ask"
    # About 170 sites in all (S7 §0); the API reports the exact count.
    assert 150 <= len(ALL_ENTRIES) <= 200


def test_the_spec_examples_are_on_the_lists_they_belong_to():
    def keys_for(host: str) -> list[str]:
        normalised = host_of(host)
        return [
            key
            for key, site in ALL_ENTRIES
            if normalised == pattern_base(site) or normalised.endswith("." + pattern_base(site))
        ]

    assert keys_for("secure.chase.com") == ["banks"]
    assert keys_for("www.fidelity.com") == ["brokers"]
    assert keys_for("www.coinbase.com") == ["crypto"]
    assert keys_for("sa.www4.irs.gov") == ["government"]
    assert keys_for("www.tax.service.gov.uk") == ["government"]
    assert keys_for("example.com") == []


def test_protected_patterns_include_every_mfa_and_captcha_host_the_handoff_detector_knows():
    for host in handoff.MFA_HOSTS:
        assert f"*.{host}" in PROTECTED_PATTERNS, host
        assert is_protected(host) and is_protected(f"login.{host}"), host
    host_shaped = [host for host in handoff.CAPTCHA_HOSTS if "/" not in host]
    assert host_shaped, "the detector lists CAPTCHA hosts"
    for host in host_shaped:
        assert f"*.{host}" in PROTECTED_PATTERNS, host
        assert is_protected(host), host
    # A path entry ("google.com/recaptcha") is not a host and is not turned into one.
    assert all("/" not in pattern for pattern in PROTECTED_PATTERNS)


def test_the_payment_processors_are_the_payment_subset_of_the_merchant_list():
    for processor in PAYMENT_PROCESSORS:
        assert processor in WELL_KNOWN_MERCHANTS, processor
        assert f"*.{processor}" in PROTECTED_PATTERNS
        assert is_protected(f"www.{processor}")


def test_every_protected_pattern_is_valid_and_the_exact_ones_leave_their_parent_domains_open():
    assert len(PROTECTED_PATTERNS) == len(set(PROTECTED_PATTERNS))
    for pattern in PROTECTED_PATTERNS:
        assert normalise_pattern(pattern) == pattern, pattern
    for exact in ("pay.google.com", "appleid.apple.com", "login.live.com"):
        assert exact in PROTECTED_PATTERNS
        assert is_protected(exact)
        parent = exact.split(".", 1)[1]
        assert not is_protected(parent), parent
        assert not is_protected(f"www.{parent}"), parent
    for three_d_secure in ("acs.cardinalcommerce.com", "secure5.arcot.com", "x.3dsecure.io"):
        assert is_protected(three_d_secure)


def test_the_checkout_exempt_category_is_the_banks_list():
    assert CHECKOUT_EXEMPT_CATEGORY == "banks"
    assert category(CHECKOUT_EXEMPT_CATEGORY) is BANKS
