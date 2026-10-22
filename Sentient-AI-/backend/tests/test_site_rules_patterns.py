"""Tests for the site-rules pattern grammar (services/site_rules/patterns.py):
they prove that whatever the owner types (a URL, a host, a "*." pattern,
an IDN, a host with userinfo or a port) becomes one lower-case punycode
pattern or a plain refusal; that an exact rule covers one host and a "*."
rule the site and every subdomain but never a look-alike suffix; that
``host_of`` reads every spelling a browser treats as the same host (case,
trailing dot, port, percent-encoding, full-width letters, the numeric
forms of an IPv4 address, blob: and view-source: wrappers) and never
raises; that Blocked is refused over sign-in, CAPTCHA and payment hosts
and Trusted on look-alike addresses; and that the lookup agrees with
``core.network_security.match_host_pattern``.

Why it exists: a rule that a different spelling walks around is no rule,
and a rule that covers too much ("*.com", "*.co.uk", a sign-in host)
breaks the owner's browsing or approved purchases. Pure: no database,
no browser, no network.
"""

from __future__ import annotations

import pytest

from core.network_security import match_host_pattern
from services.site_rules import messages
from services.site_rules.patterns import (
    KINDS,
    MAX_HOST_CHARS,
    MAX_HOST_RULES,
    TARGET_TYPES,
    PatternIndex,
    SiteRuleError,
    as_kind,
    display_host,
    host_hash,
    host_of,
    is_protected,
    normalise_pattern,
    overlaps,
    parse_site,
    pattern_matches,
    protected_overlap,
    stricter,
    validate_kind,
)
from tests.site_rules_fakes import snapshot_of

BACKSLASH = chr(92)


def _refusal(site: str, *, include_subdomains: bool = False) -> SiteRuleError:
    with pytest.raises(SiteRuleError) as caught:
        parse_site(site, include_subdomains=include_subdomains)
    return caught.value


def test_the_public_constants_match_the_stored_vocabulary():
    assert KINDS == ("blocked", "always_ask", "trusted")
    assert TARGET_TYPES == ("host", "category")
    assert MAX_HOST_RULES == 500


@pytest.mark.parametrize(
    "typed, expected",
    [
        ("chase.com", "chase.com"),
        ("Chase.COM", "chase.com"),
        ("  chase.com.  ", "chase.com"),
        ("https://www.Chase.com/login?next=/x#y", "www.chase.com"),
        ("HTTP://CHASE.COM", "chase.com"),
        ("https:chase.com", "chase.com"),
        ("bücher.de", "xn--bcher-kva.de"),
        ("https://BÜCHER.de/", "xn--bcher-kva.de"),
        ("XN--BCHER-KVA.de", "xn--bcher-kva.de"),
        ("ｃｈａｓｅ.com", "chase.com"),
        ("chase。com", "chase.com"),
        ("chase.com/accounts", "chase.com"),
        ("chase.com?x=1", "chase.com"),
        ("pay.example.co.uk", "pay.example.co.uk"),
    ],
)
def test_a_typed_url_or_host_becomes_one_lowercase_punycode_pattern(typed, expected):
    assert parse_site(typed, include_subdomains=False) == expected


@pytest.mark.parametrize(
    "typed, expected",
    [
        ("chase.com", "*.chase.com"),
        ("www.chase.com", "*.chase.com"),
        ("https://www.Chase.com/x?y", "*.chase.com"),
        ("secure.chase.com", "*.secure.chase.com"),
        ("www.example.co.uk", "*.example.co.uk"),
        ("bücher.de", "*.xn--bcher-kva.de"),
    ],
)
def test_include_subdomains_stores_a_wildcard_and_drops_a_leading_www(typed, expected):
    assert parse_site(typed, include_subdomains=True) == expected


def test_a_leading_star_dot_means_include_subdomains_whatever_the_box_says():
    assert parse_site("*.chase.com", include_subdomains=False) == "*.chase.com"
    assert parse_site("https://*.chase.com/", include_subdomains=False) == "*.chase.com"
    # Without the box, www. is a real host of its own and stays.
    assert parse_site("www.chase.com", include_subdomains=False) == "www.chase.com"


def test_an_exact_host_rule_covers_only_that_host():
    assert pattern_matches("secure.chase.com", "secure.chase.com")
    assert pattern_matches("https://SECURE.chase.com:443/x", "secure.chase.com")
    assert not pattern_matches("chase.com", "secure.chase.com")
    assert not pattern_matches("a.secure.chase.com", "secure.chase.com")
    assert not pattern_matches("www.secure.chase.com", "secure.chase.com")


def test_a_wildcard_rule_covers_the_site_and_every_subdomain_but_not_a_lookalike_suffix():
    for host in ("chase.com", "www.chase.com", "secure.chase.com", "a.b.c.chase.com"):
        assert pattern_matches(host, "*.chase.com"), host
    for host in (
        "evilchase.com",
        "chase.com.evil.com",
        "chase.co",
        "chase-com.net",
        "xchase.com",
        "",
    ):
        assert not pattern_matches(host, "*.chase.com"), host
    # Any other glob (core's "*-my.sharepoint.com" shape) covers nothing here.
    assert not pattern_matches("a-my.sharepoint.com", "*-my.sharepoint.com")


@pytest.mark.parametrize(
    "typed",
    ["*", "*chase.com", "ch*se.com", "chase.*", "*.*.chase.com", "secure.*.chase.com", "https://a*.chase.com/"],
)
def test_a_star_anywhere_but_a_leading_star_dot_is_refused(typed):
    refusal = _refusal(typed)
    assert str(refusal) == messages.STAR_INSIDE
    assert refusal.status == 422


@pytest.mark.parametrize(
    "typed, shown",
    [
        ("*.com", "*.com"),
        ("com", "*.com"),
        ("*.co.uk", "*.co.uk"),
        ("www.co.uk", "*.co.uk"),
        ("https://www.com.au/", "*.com.au"),
        ("org.uk", "*.org.uk"),
    ],
)
def test_a_rule_over_a_whole_top_level_or_two_part_suffix_is_refused_as_too_broad(typed, shown):
    refusal = _refusal(typed, include_subdomains=True)
    assert str(refusal) == messages.TOO_BROAD.format(pattern=shown)
    # The spec's example sentence, word for word.
    assert str(_refusal("*.co.uk")) == (
        "*.co.uk would cover a whole top-level domain. Pick a site, like example.com."
    )


def test_an_exact_rule_on_a_two_part_suffix_is_allowed_because_it_covers_one_host():
    assert parse_site("co.uk", include_subdomains=False) == "co.uk"


def test_single_label_names_are_refused_and_ip_addresses_are_exact_only():
    for typed in ("localhost", "intranet", "com", "http://localhost:3000/"):
        assert str(_refusal(typed)) == messages.SINGLE_LABEL, typed
    assert parse_site("1.2.3.4", include_subdomains=False) == "1.2.3.4"
    assert parse_site("http://1.2.3.4:8080/x", include_subdomains=False) == "1.2.3.4"
    assert parse_site("[2001:DB8::1]", include_subdomains=False) == "2001:db8::1"
    assert parse_site("https://[2001:db8:0::1]:443/", include_subdomains=False) == "2001:db8::1"
    # The numeric forms browsers read as an IPv4 address are stored dotted.
    assert parse_site("0x7f.1", include_subdomains=False) == "127.0.0.1"
    for typed in ("1.2.3.4", "*.1.2.3.4", "[::1]"):
        assert str(_refusal(typed, include_subdomains=True)) == messages.IP_SUBDOMAINS, typed


def test_userinfo_ports_and_non_web_schemes_are_handled_with_plain_reasons():
    assert parse_site("https://user:secret@Chase.com:8443/x", include_subdomains=False) == "chase.com"
    assert parse_site("chase.com:8443", include_subdomains=False) == "chase.com"
    assert parse_site("someone@chase.com", include_subdomains=False) == "chase.com"
    for typed in (
        "ftp://files.example.com/",
        "ws://example.com/socket",
        "file:///etc/hosts",
        "mailto:someone@example.com",
        "javascript:alert(1)",
        "about:blank",
        "chrome://settings",
    ):
        assert str(_refusal(typed)) == messages.NOT_WEB, typed


@pytest.mark.parametrize(
    "typed",
    ["exa mple.com", "example..com", "https://", "*.", "a" * 64 + ".com", "-", "ex_am$ple.com", "fe80::1%eth0"],
)
def test_an_unreadable_site_is_refused_with_a_plain_reason(typed):
    assert str(_refusal(typed)) == messages.UNREADABLE_SITE


def test_an_empty_site_and_a_too_long_one_are_refused_with_their_own_reasons():
    for typed in ("", "   ", "\t\n"):
        assert str(_refusal(typed)) == messages.EMPTY_SITE
    with pytest.raises(SiteRuleError) as caught:
        parse_site(None, include_subdomains=False)  # type: ignore[arg-type]
    assert str(caught.value) == messages.EMPTY_SITE
    long_site = ".".join(["a" * 60] * 5) + ".com"  # valid labels, 308 characters
    assert len(long_site) > 253
    assert str(_refusal(long_site)) == messages.TOO_LONG


@pytest.mark.parametrize("typed", ["faß.de", "FAẞ.de", "ς.example.com", "a‍b.com", "a‌b.com"])
def test_a_letter_that_idna_versions_spell_two_ways_is_refused_with_a_plain_reason(typed):
    # Python's IDNA 2003 writes "faß.de" as fass.de; browsers open
    # xn--fa-hia.de. A rule stored either way would miss one of them.
    assert str(_refusal(typed)) == messages.TWO_SPELLINGS


@pytest.mark.parametrize(
    "pattern, protected_host",
    [
        ("*.google.com", "accounts.google.com"),
        ("accounts.google.com", "accounts.google.com"),
        ("*.paypal.com", "paypal.com"),
        ("www.paypal.com", "paypal.com"),
        ("*.cloudflare.com", "challenges.cloudflare.com"),
        ("*.hcaptcha.com", "hcaptcha.com"),
        ("*.okta.com", "okta.com"),
        ("mycompany.okta.com", "okta.com"),
        ("*.stripe.com", "stripe.com"),
        ("pay.google.com", "pay.google.com"),
        ("*.apple.com", "appleid.apple.com"),
        ("acs.cardinalcommerce.com", "cardinalcommerce.com"),
        ("*.login.gov", "login.gov"),
    ],
)
def test_blocking_a_sign_in_captcha_or_payment_host_is_refused_but_always_ask_is_allowed(
    pattern, protected_host
):
    with pytest.raises(SiteRuleError) as caught:
        validate_kind(pattern, "blocked")
    assert str(caught.value) == messages.PROTECTED_BLOCK.format(host=protected_host)
    assert caught.value.status == 422
    assert validate_kind(pattern, "always_ask") == "always_ask"
    assert validate_kind(pattern, "trusted") == "trusted"


def test_the_protected_refusal_names_the_first_protected_host_and_reads_as_the_spec_says():
    with pytest.raises(SiteRuleError) as caught:
        validate_kind("*.google.com", "blocked")
    assert str(caught.value) == (
        "accounts.google.com is used to sign in to other sites or to confirm payments, so it "
        "cannot be blocked here: blocking it would stop sign-ins and approved purchases half-way. "
        "Use Always ask instead."
    )


def test_blocking_an_ordinary_site_next_to_a_protected_one_is_allowed():
    # Exact protected hosts leave their parent domain open to an exact rule.
    for pattern in ("google.com", "www.google.com", "mail.google.com", "apple.com", "*.example.com"):
        assert validate_kind(pattern, "blocked") == "blocked", pattern
    assert protected_overlap("www.google.com") is None
    assert protected_overlap("*.google.com") == "*.accounts.google.com"


def test_trusting_a_lookalike_address_is_refused_but_blocking_it_is_allowed():
    lookalike = parse_site("аpple.com", include_subdomains=True)  # Cyrillic а
    assert lookalike == "*.xn--pple-43d.com"
    with pytest.raises(SiteRuleError) as caught:
        validate_kind(lookalike, "trusted")
    assert str(caught.value) == (
        "This address uses look-alike characters (xn--pple-43d.com, which reads as apple.com), so "
        "it cannot be marked Trusted. You can block it."
    )
    assert validate_kind(lookalike, "blocked") == "blocked"
    assert validate_kind(lookalike, "always_ask") == "always_ask"
    # Mixed scripts inside one label are look-alikes too.
    mixed = parse_site("pаypal-login.com", include_subdomains=False)
    with pytest.raises(SiteRuleError):
        validate_kind(mixed, "trusted")
    # Plain Latin, a real IDN without confusables, and IP addresses can be trusted.
    for pattern in ("*.chase.com", "*.xn--bcher-kva.de", "1.2.3.4", "2001:db8::1"):
        assert validate_kind(pattern, "trusted") == "trusted", pattern


def test_an_unknown_kind_is_refused():
    for kind in ("", "block", "BLOCKED", "allow", "always ask", None):
        with pytest.raises(SiteRuleError) as caught:
            validate_kind("example.com", kind)  # type: ignore[arg-type]
        assert str(caught.value) == messages.BAD_KIND
        assert as_kind(kind) is None
    assert [as_kind(kind) for kind in KINDS] == list(KINDS)


def test_overlaps_finds_patterns_that_cover_each_other_in_either_direction():
    assert overlaps("*.chase.com", "secure.chase.com")
    assert overlaps("secure.chase.com", "*.chase.com")
    assert overlaps("*.chase.com", "*.secure.chase.com")
    assert overlaps("*.secure.chase.com", "*.chase.com")
    assert overlaps("*.chase.com", "chase.com")
    assert overlaps("chase.com", "chase.com")
    assert not overlaps("chase.com", "secure.chase.com")
    assert not overlaps("*.secure.chase.com", "chase.com")
    assert not overlaps("*.chase.com", "*.evilchase.com")
    assert not overlaps("*.chase.com", "chase.com.evil.com")
    assert not overlaps("*.chase.com", "not a pattern")


def test_normalise_pattern_never_turns_a_path_port_or_glob_into_a_wider_pattern():
    assert normalise_pattern("*.Chase.COM.") == "*.chase.com"
    assert normalise_pattern("bücher.de") == "xn--bcher-kva.de"
    assert normalise_pattern("[2001:DB8::1]") == "2001:db8::1"
    for bad in (
        "google.com/recaptcha",
        "chase.com:443",
        "user@chase.com",
        "chase.com?x",
        "*-my.sharepoint.com",
        "*.*.com",
        "*",
        "",
        None,
        42,
    ):
        assert normalise_pattern(bad) == "", bad


@pytest.mark.parametrize(
    "url, host",
    [
        ("https://user:pw@WWW.Chase.com:8443/x?y", "www.chase.com"),
        ("https://chase.com./", "chase.com"),
        ("https://chase.com%2e/", "chase.com"),
        ("https://%63hase.com/", "chase.com"),
        ("HTTPS:" + BACKSLASH * 2 + "Chase.COM" + BACKSLASH + "x", "chase.com"),
        # A backslash ends the authority in a browser, so this opens chase.com
        # (Python's urlsplit would say evil.example: the host must be read
        # the browser's way or a rule on chase.com is walked around).
        ("https://chase.com" + BACKSLASH + "@evil.example/", "chase.com"),
        ("https://evil.example@chase.com/", "chase.com"),
        ("https:/chase.com", "chase.com"),
        ("https:chase.com", "chase.com"),
        (" \thttps://ch\nase.com/ ", "chase.com"),
        ("ws://chase.com/socket", "chase.com"),
        ("blob:https://chase.com/0b1c", "chase.com"),
        ("view-source:https://chase.com/", "chase.com"),
        ("https://xn--BCHER-kva.de/", "xn--bcher-kva.de"),
        ("https://bücher.de/", "xn--bcher-kva.de"),
        ("ｃｈａｓｅ.com", "chase.com"),
        ("chase.com:8443/x", "chase.com"),
        ("[2001:DB8::1]:443", "2001:db8::1"),
        ("https://[::1]:8000/", "::1"),
        ("fe80::1", "fe80::1"),
    ],
)
def test_host_of_reads_every_spelling_a_browser_treats_as_the_same_host(url, host):
    assert host_of(url) == host


@pytest.mark.parametrize(
    "url, host",
    [
        ("http://0x7f.1/", "127.0.0.1"),
        ("http://2130706433/", "127.0.0.1"),
        ("http://0177.0.0.1/", "127.0.0.1"),
        ("http://127.1/", "127.0.0.1"),
        ("http://1.2.3.4/", "1.2.3.4"),
        ("http://１２７.０.０.１/", "127.0.0.1"),
        # Not an address: a number that does not fit, or a name ending in one.
        ("http://256.256.256.256/", "256.256.256.256"),
        ("http://example.123/", "example.123"),
    ],
)
def test_host_of_reads_the_numeric_forms_of_an_ipv4_address_as_the_browser_does(url, host):
    assert host_of(url) == host


@pytest.mark.parametrize(
    "value",
    [
        "about:blank",
        "data:text/html,<p>hi</p>",
        "chrome-error://chromewebdata/",
        "file:///etc/passwd",
        "mailto:a@b.com",
        "javascript:alert(1)",
        "",
        "   ",
        None,
        42,
        b"https://chase.com",
        "https://[bad/",
        "fe80::1%25eth0",
        "https://[fe80::1%25eth0]/",
    ],
)
def test_host_of_answers_nothing_for_urls_without_a_web_host_and_never_raises(value):
    assert host_of(value) == ""


def test_a_host_with_letters_newer_than_python_idna_still_keeps_its_site_suffix():
    # Python's IDNA knows Unicode 3.2 only; the label is folded into
    # punycode so "*.chase.com" still covers it.
    host = host_of("https://😀x.chase.com/")
    assert host.endswith(".chase.com") and host.isascii()
    assert pattern_matches("https://😀x.chase.com/", "*.chase.com")


def test_the_stricter_kind_wins_a_tie_blocked_then_always_ask_then_trusted():
    assert stricter("trusted", "always_ask") == "always_ask"
    assert stricter("always_ask", "blocked") == "blocked"
    assert stricter("blocked", "trusted") == "blocked"
    assert stricter("trusted", "trusted") == "trusted"


def test_pattern_index_counts_entries_that_are_not_patterns_and_merges_duplicates():
    index: PatternIndex[str] = PatternIndex(
        [("*.Chase.com", "a"), ("*.chase.com.", "b"), ("ch*se.com", "c"), ("", "d")],
        merge=lambda held, new: held + new,
    )
    assert index.skipped == 2
    assert len(index) == 1
    assert index.lookup("secure.chase.com") == ("*.chase.com", "ab")
    first_wins: PatternIndex[str] = PatternIndex([("x.com", "first"), ("X.com", "second")])
    assert first_wins.lookup("x.com") == ("x.com", "first")
    assert first_wins.lookup("") is None


OWNER_PATTERNS = [
    "*.example.com",
    "docs.example.com",
    "*.b.example.com",
    "a.b.example.com",
    "*.c.b.example.com",
    "*.chase.com",
    "chase.com",
    "secure.chase.com",
    "*.co.uk",
    "1.2.3.4",
    "*.xn--bcher-kva.de",
]
HOSTS = [
    "example.com",
    "www.example.com",
    "docs.example.com",
    "x.docs.example.com",
    "b.example.com",
    "a.b.example.com",
    "z.a.b.example.com",
    "c.b.example.com",
    "d.c.b.example.com",
    "chase.com",
    "secure.chase.com",
    "www.secure.chase.com",
    "evilchase.com",
    "chase.com.evil.com",
    "anything.co.uk",
    "1.2.3.4",
    "1.2.3.5",
    "shop.xn--bcher-kva.de",
    "unrelated.org",
]


@pytest.mark.parametrize("host", HOSTS)
def test_the_snapshot_lookup_agrees_with_core_match_host_pattern_on_a_table_of_hosts(host):
    expected = match_host_pattern(host, OWNER_PATTERNS)
    index: PatternIndex[str] = PatternIndex((p, p) for p in OWNER_PATTERNS)
    hit = index.lookup(host_of(host))
    assert (hit[0] if hit else None) == expected
    # The same table through a snapshot of owner rules (no built-in site in it).
    snapshot = snapshot_of(dict.fromkeys(OWNER_PATTERNS, "always_ask"))
    verdict = snapshot.verdict(host)
    assert verdict.pattern == expected
    assert verdict.source == ("owner" if expected else None)


def test_is_protected_reads_the_host_however_it_is_spelled():
    assert is_protected("https://Accounts.Google.com./signin")
    assert is_protected("mycompany.okta.com")
    assert is_protected("pay.google.com")
    assert not is_protected("google.com")
    assert not is_protected("www.google.com")
    assert not is_protected("accounts.google.com.evil.com")
    assert not is_protected("")


def test_display_host_decodes_punycode_and_drops_the_wildcard():
    assert display_host("*.xn--bcher-kva.de") == "bücher.de"
    assert display_host("chase.com") == "chase.com"
    assert display_host("*.chase.com") == "chase.com"
    assert display_host("2001:db8::1") == "2001:db8::1"


def test_host_hash_is_keyed_stable_and_never_the_host_itself():
    first = host_hash("secure.chase.com", "key-one")
    assert first == host_hash("https://SECURE.chase.com./x?y", "key-one")
    assert len(first) == 16 and all(ch in "0123456789abcdef" for ch in first)
    assert first != host_hash("secure.chase.com", "key-two")
    assert first != host_hash("chase.com", "key-one")
    assert "chase" not in first


# --- Hostile spellings and hostile lengths (checker findings, early core) ---

# Code points Chromium drops from a host before it opens it, read from
# Chromium's own URL parser one code point at a time (build 1243). A rule
# on chase.com must cover "c<any of these>hase.com", or the model could
# name the site in a way the call check misreads while the browser opens it.
CHROMIUM_IGNORED_RANGES = [
    (0x00AD, 0x00AD),
    (0x034F, 0x034F),
    (0x115F, 0x1160),
    (0x17B4, 0x17B5),
    (0x180B, 0x180F),
    (0x200B, 0x200B),
    (0x2060, 0x2064),
    (0x206A, 0x206F),
    (0x3164, 0x3164),
    (0xFE00, 0xFE0F),
    (0xFEFF, 0xFEFF),
    (0xFFA0, 0xFFA0),
    (0x1BCA0, 0x1BCA3),
    (0x1D173, 0x1D17A),
    (0xE0100, 0xE01EF),
]


def _spelled(*parts: object) -> str:
    """A string from text pieces and code points (no invisible characters
    pasted into the source)."""
    return "".join(chr(part) if isinstance(part, int) else str(part) for part in parts)


def test_host_of_drops_every_code_point_chromium_drops_from_a_host():
    missed = [
        hex(code)
        for first, last in CHROMIUM_IGNORED_RANGES
        for code in range(first, last + 1)
        if host_of(_spelled("https://c", code, "hase.com/")) != "chase.com"
    ]
    assert missed == []
    # Padding a label with them (any number of them) changes nothing either.
    padding = _spelled(0x3164, 0xE0100, 0x2064) * 50
    assert host_of("https://c" + padding + "hase.com/") == "chase.com"
    assert host_of(_spelled("https://", 0x00AD, ".chase.com/")) == "chase.com"


@pytest.mark.parametrize(
    "parts, host",
    [
        # Modifier, subscript and outlined letters Chromium reads as plain
        # ASCII (Python's IDNA codec knows Unicode 3.2 only and left them).
        ((0x1D9C, "hase.com"), "chase.com"),  # modifier letter small c
        (("c", 0x1D34, "ase.com"), "chase.com"),  # modifier letter capital h
        (("c", 0x2095, "ase.com"), "chase.com"),  # subscript small h
        (("cha", 0xA7F1, "e.com"), "chase.com"),  # Unicode 16 modifier capital s
        ((0x1CCD8, "hase.com"), "chase.com"),  # Unicode 16 outlined c
        ((0x1CCD8, 0x1CCDD, 0x1CCD6, 0x1CCE8, 0x1CCDA, ".com"), "chase.com"),
        (("c", 0x3250, "hase.com"), "cptehase.com"),  # partnership sign
        # Case pairs newer than Unicode 3.2 fold the way Chromium folds them.
        ((0x13A0, "x.chase.com"), "xn--x-18h.chase.com"),  # Cherokee A
        ((0xAB70, "x.chase.com"), "xn--x-18h.chase.com"),  # Cherokee small a
        (("c", 0x2F868, "hase.com"), "xn--chase-el2e.com"),  # CJK compatibility ideograph
        # Nontransitional letters stay as Chromium keeps them.
        (("c", 0x00DF, "hase.com"), "xn--chase-lqa.com"),  # sharp s
        (("c", 0x1E9E, "hase.com"), "xn--chase-lqa.com"),  # capital sharp s reads as sharp s
        (("c", 0x03C2, "hase.com"), "xn--chase-9ce.com"),  # final sigma
        (("c", 0x1806, "hase.com"), "xn--chase-nr3a.com"),  # Mongolian todo soft hyphen is kept
    ],
)
def test_host_of_maps_compatibility_and_newer_letters_the_way_chromium_opens_them(parts, host):
    # Each expected host is what Chromium's URL parser gives for the same URL.
    assert host_of(_spelled("https://", *parts, "/")) == host


def test_the_lookup_agrees_with_core_match_host_pattern_on_a_seeded_table_of_long_and_odd_hosts():
    import random

    rng = random.Random(7)
    pieces = ["a", "b", "c", "example", "com", "docs", "chase", "x" * 70, "co", "uk"]
    index: PatternIndex[str] = PatternIndex((p, p) for p in OWNER_PATTERNS)
    for _ in range(2000):
        host = ".".join(rng.choice(pieces) for _ in range(rng.randint(1, 9)))
        hit = index.lookup(host_of(host))
        assert (hit[0] if hit else None) == match_host_pattern(host, OWNER_PATTERNS), host


class _CountingTable(dict):
    """A PatternIndex table that counts the characters its probes hash and
    stops a lookup the moment it hashes more than a rule could ever name."""

    def __init__(self, held, budget):
        super().__init__(held)
        self.probed = 0
        self.budget = budget

    def get(self, key, default=None):
        self.probed += len(key)
        assert self.probed <= self.budget, f"the lookup hashed {self.probed} characters"
        return super().get(key, default)


@pytest.mark.parametrize(
    "host",
    [
        ".".join(["abcdefghij"] * 100_000) + ".evil.com",  # a megabyte of ten-letter labels
        "a." * 500_000 + "evil.com",  # half a million one-letter labels
        "a" * 1_000_000 + ".evil.com",  # one megabyte-long label
    ],
    ids=["ten-letter-labels", "one-letter-labels", "one-long-label"],
)
def test_a_lookup_on_a_megabyte_host_probes_only_suffixes_as_long_as_the_longest_pattern(host):
    # Each probe used to slice and hash the rest of the host, one per label:
    # quadratic, about 36 s for a 1.1 MB host on the guard's event loop.
    index: PatternIndex[str] = PatternIndex(
        [("*.evil.com", "wild"), ("*.b.evil.com", "deeper"), ("chase.com", "exact")]
    )
    budget = 4 * MAX_HOST_CHARS
    index._exact = _CountingTable(index._exact, budget)  # type: ignore[assignment]
    index._wild = _CountingTable(index._wild, budget)  # type: ignore[assignment]
    # The site is still found however long the host is (fail closed).
    assert index.lookup(host) == ("*.evil.com", "wild")
    assert index.lookup(host + ".org") is None
    assert index.lookup(host[: -len(".evil.com")] + ".b.evil.com") == ("*.b.evil.com", "deeper")


def test_a_lookup_still_finds_a_suffix_exactly_as_long_as_the_longest_pattern():
    index: PatternIndex[str] = PatternIndex([("*.b.example.com", "b"), ("*.com", "com")])
    assert index.lookup("x" * 500 + ".b.example.com") == ("*.b.example.com", "b")
    assert index.lookup("x" * 500 + "b.example.com") == ("*.com", "com")
    assert index.lookup("b.example.com") == ("*.b.example.com", "b")
    assert index.lookup("x" * 500) is None
    exact_only: PatternIndex[str] = PatternIndex([("chase.com", "exact")])
    assert exact_only.lookup("chase.com") == ("chase.com", "exact")
    assert exact_only.lookup("x" * 500 + ".chase.com") is None


_DISTINCT_CJK = "".join(chr(0x4E00 + i) for i in range(20_000))


@pytest.mark.parametrize(
    "label",
    [
        _DISTINCT_CJK * 50,  # one megabyte-long label of distinct letters
        chr(0x1F600) * 1_000_000,  # one label of emoji
        ".".join(_DISTINCT_CJK[i % 19_000 : i % 19_000 + 60] for i in range(0, 960_000, 60)),
        "%E4%B8%80" * 100_000,  # percent-encoded
    ],
    ids=["distinct-letters", "emoji", "many-short-labels", "percent-encoded"],
)
def test_host_of_never_hands_the_quadratic_punycode_encoder_more_than_a_rule_can_name(
    monkeypatch, label
):
    # Python's punycode encoder is quadratic in a label's distinct letters:
    # 8,000 of them took 8 s here, and the IDNA codec runs it before it
    # checks the length. Only what a rule can name may reach it.
    import encodings.punycode

    real = encodings.punycode.punycode_encode
    handed: list[int] = []

    def counting(text):
        handed.append(len(text))
        assert len(text) <= MAX_HOST_CHARS and sum(handed) <= 4 * MAX_HOST_CHARS, handed[-5:]
        return real(text)

    monkeypatch.setattr(encodings.punycode, "punycode_encode", counting)
    url = "https://" + label + ".evil.com/"
    host = host_of(url)
    assert host.isascii() and host.endswith(".evil.com")
    # Still covered by the site's rule (fail closed), read the same way every time.
    assert pattern_matches(url, "*.evil.com")
    assert host_of(url) == host


@pytest.mark.parametrize(
    "stored",
    [
        "%2a.com",
        "%2A.com",
        _spelled(0xFF0A, ".com"),  # full-width star
        "*.%2a.com",
        "ch%61se.com",
        "*.ch%61se.com",
        _spelled("chase.com", 0xFF1A, "443"),  # full-width colon: a port once mapped
        _spelled("evil.com", 0xFF20, "chase.com"),  # full-width @: userinfo once mapped
        _spelled("chase.com", 0xFF0F, "x"),  # full-width slash: a path once mapped
        "a" * 254,
        "*." + ".".join(["a" * 60] * 5) + ".com",
    ],
    ids=lambda stored: ascii(stored)[:40],
)
def test_normalise_pattern_never_reads_a_stored_row_as_a_glob_escape_or_overlong_host(stored):
    # "%2a.com" used to decode into the wildcard "*.com" and cover every .com
    # site. A stored row is already decoded, so an escape means it was not
    # written by parse_site: it is skipped, never guessed at.
    assert normalise_pattern(stored) == ""
    index: PatternIndex[str] = PatternIndex([(stored, "row")])
    assert index.skipped == 1 and len(index) == 0
    assert index.lookup("foo.com") is None


def test_a_stored_row_of_the_longest_allowed_length_is_still_read():
    longest = ".".join(["a" * 63] * 3) + "." + "b" * 61  # 253 characters
    assert len(longest) == MAX_HOST_CHARS
    assert normalise_pattern(longest) == longest
    assert normalise_pattern("*." + longest) == "*." + longest
    assert parse_site(longest, include_subdomains=False) == longest


# --- NFKC on hostile hosts (recheck finding: quadratic combining marks) -------

_MARKS = "̖́"  # ccc 230 then 220: out of canonical order, so NFKC must sort them


@pytest.mark.parametrize(
    "host",
    [
        "a" + _MARKS * 500_000,  # one megabyte-long label of out-of-order marks
        "a" + "%CC%81%CC%96" * 90_000,  # the same, percent-encoded
        ".".join([_MARKS * 1_000] * 250),  # many labels, each just under the mapping limit
        ".".join([_MARKS * 1_000] * 3),  # few labels: all read (it may be an IPv4 address)
        "ﷺ" * 100_000,  # NFKC writes this letter as eighteen
        "é" * 300_000,  # a long label of a letter NFKC decomposes and recomposes
    ],
    ids=[
        "one-label-of-marks",
        "percent-encoded-marks",
        "many-labels-of-marks",
        "three-labels-of-marks",
        "eighteen-fold-letter",
        "long-precomposed-label",
    ],
)
def test_host_of_never_hands_nfkc_more_than_one_bounded_label_at_a_time(monkeypatch, host):
    # CPython's NFKC sorts a run of combining marks by insertion (quadratic),
    # and the host used to be normalised whole before anything was cut: a
    # megabyte took 9.5 s. Each label is now mapped on its own and only up
    # to _LABEL_MAP_LIMIT code points; a longer one becomes a stand-in
    # (longer than any rule can name) without being normalised.
    import unicodedata

    from services.site_rules import patterns

    real = unicodedata.normalize
    handed: list[int] = []

    def counting(form, text):
        handed.append(len(text))
        # One call: at most a label (its case-folded form may be a little longer).
        assert len(text) <= 4 * patterns._LABEL_MAP_LIMIT, handed[-5:]
        # All calls together: a few labels, never the host.
        assert sum(handed) <= 16 * patterns._LABEL_MAP_LIMIT, len(handed)
        return real(form, text)

    monkeypatch.setattr(unicodedata, "normalize", counting)
    url = "https://" + host + ".evil.com/"
    read = host_of(url)
    assert read.isascii() and read.endswith(".evil.com")
    # Still covered by the site's rule (fail closed), and read the same way every time.
    assert pattern_matches(url, "*.evil.com")
    assert host_of(url) == read


def test_every_code_point_whose_mapping_holds_a_full_stop_is_mapped_before_the_host_is_split():
    # A host is split on its full stops before its labels are normalised, so
    # a letter that NFKC writes with a full stop ("1." for U+2488, "a.m."
    # for U+33C2) must be mapped first, or it would hide a label boundary
    # the browser sees. This walks every code point.
    import sys
    import unicodedata

    from services.site_rules import patterns

    missed = []
    for code in range(0x80, sys.maxunicode + 1):
        if 0xD800 <= code <= 0xDFFF or code in patterns._HOST_MAP:
            continue
        char = chr(code)
        if not unicodedata.decomposition(char) and char.casefold() == char:
            continue  # NFKC and case folding leave it as it is
        if "." in patterns._mapped_label(char):
            missed.append(hex(code))
    assert missed == []
    for code in patterns._DOTTED:
        mapped = patterns._HOST_MAP[code]
        assert mapped is not None and "." in mapped and mapped.isascii(), hex(code)


_ALPHABET = (
    "abcxyz09-"  # ASCII letters, digits and the hyphen
    "̖̣́̂̓͂̇ͅ"  # combining marks
    "ßςẞΣİ"  # sharp s, final sigma, capital sharp s, Sigma, dotted I
    "Αα각"  # Greek alpha, Hangul jamo (compose into syllables)
    "ａＡﬀﬃΩÅ"  # full-width letters, ligatures, Ohm, Angstrom
    "⒈․…㏂﹒︒︙\U0001f100‥"  # letters that hold full stops
    "．。｡."  # the full stops themselves
    "­️​ㅤ"  # code points browsers drop
    "éḉᾏ가"  # precomposed letters
)


def _whole_host_reading(text: str) -> str:
    """The host as the earlier reader spelled it: the whole host mapped at
    once (``_HOST_MAP`` without the pre-split full stops, NFKC, case
    folding, "ß" and "ς" kept), then split and punycoded. Correct, but
    quadratic on a hostile host; kept here as the reference."""
    import re
    import unicodedata

    from services.site_rules import patterns

    base_map = {k: v for k, v in patterns._HOST_MAP.items() if k not in patterns._DOTTED}
    mapped = text.translate(base_map)
    mapped = "".join(
        part
        if part in ("ß", "ς")
        else unicodedata.normalize("NFKC", unicodedata.normalize("NFKC", part).casefold())
        for part in re.split("([ßς])", mapped)
    )
    mapped = mapped.replace("。", ".").strip(".")
    labels = [
        label if label.isascii() else "xn--" + label.encode("punycode").decode("ascii")
        for label in mapped.split(".")
    ]
    return ".".join(labels)


def test_reading_a_host_label_by_label_agrees_with_mapping_it_whole_on_a_seeded_table():
    # Mapping label by label must not change what any ordinary host reads
    # as: "." neither decomposes nor composes, and the letters that hold a
    # full stop are mapped before the split.
    import random

    rng = random.Random(20261021)
    checked = 0
    for _ in range(4_000):
        text = "".join(rng.choice(_ALPHABET) for _ in range(rng.randint(1, 24)))
        if text.isascii():
            continue
        # A last ASCII label, so no host reads as an IPv4 address.
        expected = _whole_host_reading(text + ".example")
        url = "https://" + text + ".example/"
        assert host_of(url) == expected, ascii(text)
        checked += 1
    assert checked > 3_000
