"""Tests for the shared look-alike host helpers (services/security/lookalike.py): they
prove that lookalike_of names the brand a host imitates and the rule that fired
(a brand label on another domain, a typo or homograph, a brand glued to another word)
and leaves the brand's own domain and ordinary words alone; that mixed-script and
confusable letters are read back to Latin, punycode included; that hosts decode,
encode and fold the way a person reads them; that registrable domains respect
two-part suffixes; that IP literals are recognised in every form a browser opens;
and that the consumer mail list holds the free providers and no organisation.

Why it exists: the browser checkout refused look-alike merchants first, and the
security wave's message, mail and link checks (S1, S2, S4) and site rules (S7) now
share these helpers. A change here changes all of them, so the rules are pinned in one
place. Written by WAVE 0, owned by S4 in WAVE 1. Pure: no network.
"""

from __future__ import annotations

import pytest

from services.security import lookalike
from services.security.lookalike import (
    CONFUSABLES,
    CONSUMER_MAIL_DOMAINS,
    TWO_PART_SUFFIXES,
    WELL_KNOWN_BRANDS,
    LookalikeHit,
    ascii_host,
    decode_host,
    edit_distance,
    is_ip_literal,
    lookalike_of,
    mixed_script_reading,
    reads_as,
    registrable_domain,
    script_of,
    skeleton,
)
from services.tools.browser.checkout import merchant

CYRILLIC_AMAZON = "аmazon.com"  # Cyrillic а, renders exactly like amazon.com
PUNYCODE_AMAZON = "аmazon".encode("idna").decode("ascii") + ".com"


# -- lookalike_of: the three rules, in order, naming the one that fired ---------------


@pytest.mark.parametrize(
    "host, known, rule",
    [
        # The brand as a label or hyphenated part of a label on another domain.
        ("amazon.shop", "amazon.com", "brand_label"),
        ("ticketmaster-tickets.co", "ticketmaster.com", "brand_label"),
        ("amazon.com.evil.com", "amazon.com", "brand_label"),
        ("www.paypal.com.secure-login.xyz", "paypal.com", "brand_label"),
        ("ticketmaster.evil.com", "ticketmaster.com", "brand_label"),
        # A typo of the brand label, or a word that only reads as the brand.
        ("amazom.com", "amazon.com", "typo"),
        ("arnazon.com", "amazon.com", "typo"),
        ("paypa1.com", "paypal.com", "typo"),
        ("ticketmastr.com", "ticketmaster.com", "typo"),
        # The brand glued to another word.
        ("paypalsecure.com", "paypal.com", "glued"),
        ("nikestore.com", "nike.com", "glued"),
        ("amazonprime-deals.com", "amazon.com", "glued"),
        ("appleid-verify.com", "apple.com", "glued"),
    ],
)
def test_lookalike_of_names_the_brand_and_the_rule_that_fired(host, known, rule):
    assert lookalike_of(host) == LookalikeHit(known, rule)


@pytest.mark.parametrize(
    "host",
    [
        "amazon.com", "www.amazon.com", "smile.amazon.com", "checkout.ticketmaster.com",
        "paypal.com", "example.com", "bath.com", "aaa.com", "cvsphotos.com",
        "moniker.com", "consultant.com", "school.edu", "",
    ],
)
def test_lookalike_of_leaves_a_brands_own_domain_and_ordinary_words_alone(host):
    """A short brand is never read into a longer word ("aa" in "aaa", "cvs" in
    "cvsphotos"); a four-letter brand only at a word's edge ("nike" is not in
    "moniker", "ulta" not in "consultant")."""
    assert lookalike_of(host) is None


def test_lookalike_of_takes_its_own_list_of_known_sites():
    known = ("northwind.com",)
    assert lookalike_of("northwlnd.com", known) == LookalikeHit("northwind.com", "typo")
    assert lookalike_of("northwind.com", known) is None
    assert lookalike_of("amazom.com", known) is None


def test_lookalike_of_reads_the_host_case_and_trailing_dot_insensitively():
    assert lookalike_of("PayPalSecure.COM.") == LookalikeHit("paypal.com", "glued")


def test_the_checkout_merchant_keeps_its_names_and_sentences():
    assert merchant.WELL_KNOWN_MERCHANTS is WELL_KNOWN_BRANDS
    assert merchant.registrable_domain is registrable_domain
    assert merchant._lookalike_of_known("arnazon.com") == "amazon.com"
    assert merchant._lookalike_of_known("amazon.com") is None


# -- scripts, confusables, decoding ---------------------------------------------------


def test_mixed_script_reading_reads_look_alike_letters_back_to_latin():
    assert mixed_script_reading(CYRILLIC_AMAZON) == "amazon.com"
    # A wholly Cyrillic label mixes nothing but carries confusables.
    assert mixed_script_reading("аррӏе.com") == "apple.com"
    # The IDNA form of a look-alike is read decoded.
    assert mixed_script_reading(PUNYCODE_AMAZON) == "amazon.com"
    assert mixed_script_reading("amazon.com") is None
    assert mixed_script_reading("例子.cn") is None  # one script, no confusable
    assert mixed_script_reading("例え.jp") == "例え.jp"  # two scripts in one label


def test_script_of_names_a_letters_script_and_nothing_for_other_characters():
    assert script_of("a") == "LATIN"
    assert script_of("а") == "CYRILLIC"
    assert script_of("ο") == "GREEK"
    assert script_of("-") == "" and script_of("7") == ""


def test_decode_host_shows_a_host_as_a_person_reads_it():
    assert decode_host(PUNYCODE_AMAZON) == CYRILLIC_AMAZON
    assert decode_host("SHOP.Example.com.") == "shop.example.com"
    assert decode_host("ｅxample.com") == "example.com"  # fullwidth folded (NFKC)
    assert decode_host("xn--zz-.com") is None  # undecodable punycode is refused
    assert decode_host("") is None


def test_ascii_host_gives_the_idna_form_and_leaves_ascii_hosts_alone():
    assert ascii_host(CYRILLIC_AMAZON) == PUNYCODE_AMAZON
    assert ascii_host(PUNYCODE_AMAZON) == PUNYCODE_AMAZON
    assert ascii_host("Shop.Example.COM") == "shop.example.com"
    assert ascii_host("xn--zz-.com") is None


def test_reads_as_folds_every_confusable_and_always_answers_a_string():
    assert reads_as("аррӏе.com") == "apple.com"
    assert reads_as(PUNYCODE_AMAZON) == "amazon.com"
    assert reads_as("Example.com") == "example.com"
    assert reads_as("xn--zz-.com") == "xn--zz-.com"
    assert reads_as("") == ""
    assert all(len(latin) == 1 and latin.isascii() for latin in CONFUSABLES.values())


def test_skeleton_and_edit_distance_measure_how_a_label_reads():
    assert skeleton("arnazon") == "amazon"
    assert skeleton("paypa1") == "paypal"
    assert skeleton("g00gle") == "google"
    assert edit_distance("amazom", "amazon") == 1
    assert edit_distance("amazon", "amazon") == 0
    assert edit_distance("a", "abcd") == 3  # capped: only "within two" is ever asked


# -- registrable domains and IP literals ----------------------------------------------


@pytest.mark.parametrize(
    "host, domain",
    [
        ("shop.example.com", "example.com"),
        ("a.b.example.co.uk", "example.co.uk"),
        ("example.co.uk", "example.co.uk"),
        ("Checkout.Ticketmaster.COM.", "ticketmaster.com"),
        ("localhost", "localhost"),
        ("10.0.0.1", "10.0.0.1"),
    ],
)
def test_registrable_domain_respects_two_part_suffixes(host, domain):
    assert registrable_domain(host) == domain


def test_two_part_suffixes_hold_only_two_label_suffixes():
    assert all(suffix.count(".") == 1 for suffix in TWO_PART_SUFFIXES)
    assert "co.uk" in TWO_PART_SUFFIXES and "com" not in TWO_PART_SUFFIXES


@pytest.mark.parametrize(
    "host",
    ["10.0.0.1", "93.184.216.34", "[::1]", "::1", "2001:db8::1", "2130706433", "0x7f.1", "127.1", "1.2.3.4."],
)
def test_is_ip_literal_recognises_every_form_a_browser_opens_as_an_address(host):
    assert is_ip_literal(host) is True


@pytest.mark.parametrize("host", ["example.com", "1password.com", "123.example.com", "localhost", "", "[]"])
def test_is_ip_literal_leaves_names_alone(host):
    assert is_ip_literal(host) is False


# -- the consumer mail list -----------------------------------------------------------


def test_consumer_mail_domains_hold_the_free_providers_and_no_organisation():
    for domain in ("gmail.com", "googlemail.com", "outlook.com", "hotmail.com", "yahoo.com",
                   "icloud.com", "proton.me", "gmx.de", "qq.com", "naver.com", "yahoo.co.uk"):
        assert domain in CONSUMER_MAIL_DOMAINS
    for domain in ("northwind.com", "google.com", "microsoft.com", "amazon.com"):
        assert domain not in CONSUMER_MAIL_DOMAINS
    assert all(domain == domain.lower().strip() and "." in domain for domain in CONSUMER_MAIL_DOMAINS)


def test_the_module_imports_nothing_from_the_browser():
    """S1, S2 and S4 import this without a browser; the loopback toggle stays
    in merchant.py."""
    source = lookalike.__loader__.get_source(lookalike.__name__)  # type: ignore[union-attr]
    assert source is not None
    assert "services.tools" not in source and "LOOPBACK" not in source


# -- the host a browser opens (link checks, S4) ---------------------------------------


@pytest.mark.parametrize(
    "host",
    ["amazon.shop", "amazom.com", "arnazon.com", "paypalsecure.com", "ticketmaster.evil.com",
     "nikestore.com", "aaa.com", "bath.com", "checkout.ticketmaster.com", "example.co.uk",
     "appleid-verify.com", "www.paypal.com.secure-login.xyz", "z00m.us", "united-airlines.com"],
)
def test_the_brand_rules_answer_exactly_what_checkout_answers(host):
    """Checkout's refusal must not change when it reads these helpers from here."""
    hit = lookalike_of(host)
    assert (hit.known if hit else None) == merchant._lookalike_of_known(host)
    assert registrable_domain(host) == merchant.registrable_domain(host)
    assert decode_host(host) == merchant._decode_host(host)


@pytest.mark.parametrize("host", ["pаypal.com", "аррӏе.com", "paypal.com", "пример.рф"])
def test_the_script_rule_flags_exactly_what_checkout_refuses(host):
    refused = merchant._lookalike_script_refusal(decode_host(host) or "") is not None
    assert (mixed_script_reading(host) is not None) == refused


def test_ascii_host_writes_the_host_the_way_a_browser_puts_it_on_the_wire():
    assert ascii_host("аррӏе.com") == "xn--80ak6aa92e.com"
    assert ascii_host("Shop.Example.com.") == "shop.example.com"
    # Another script's dot is a dot to a browser; an empty or over-long label is no host.
    assert ascii_host("example。com") == "example.com"
    assert ascii_host("a..com") is None
    assert ascii_host("x" * 63 + ".com") == "x" * 63 + ".com"
    assert ascii_host("x" * 64 + ".com") is None
    assert ascii_host("é" * 60 + ".com") is None
    assert ascii_host(("a" * 63 + ".") * 4 + "com") is None  # over 253 characters
    # UTS 46 nontransitional, as current browsers: the sharp s is kept, never folded to "ss".
    assert ascii_host("faß.de") == "xn--fa-hia.de"


def test_characters_a_browser_drops_from_a_host_are_dropped_here_too():
    """An e-mail's link can hide a soft hyphen or a zero-width character inside the host; the
    browser opens the host without it, so every reading here is that host too."""
    for hidden in ("\u00ad", "\u200b", "\u2060", "\ufeff", "\u034f", "\ufe0f", "\u180b", "\u200d"):
        assert ascii_host(f"ev{hidden}il.example.com") == "evil.example.com", repr(hidden)
        assert lookalike.browser_host(f"ev{hidden}il.example.com") == "evil.example.com"
    assert lookalike.strip_ignored("a\u00adb\U000e0100c") == "abc"
    assert lookalike.strip_ignored("plain text") == "plain text"


def test_browser_host_reads_names_only_idna_2008_allows_and_decode_host_keeps_checkouts_refusal():
    """IDNA 2003 (Python's idna codec) refuses a Hebrew name ending in digits and folds the
    sharp s; a browser opens both. The link checks read them as the browser does, while
    checkout keeps refusing a host it cannot decode the old way."""
    hebrew = "שלום123.com"
    written = ascii_host(hebrew)
    assert written is not None and written.startswith("xn--")
    assert lookalike.browser_host(written) == hebrew
    assert decode_host(written) is None
    assert lookalike.browser_host("xn--fa-hia.de") == "faß.de"
    assert decode_host("xn--fa-hia.de") is None
    # Not punycode a browser accepts: invalid, plain ASCII once decoded, or not its own encoding.
    for refused in ("xn--zz-.com", "xn--a.com", "xn--abc-.com", "xn--" + "a" * 70 + ".com"):
        assert lookalike.browser_host(refused) is None, refused
        assert ascii_host(refused) is None, refused


def test_a_host_too_long_to_be_a_name_is_refused_in_linear_time():
    """Python's punycode encoder is quadratic in a label's length: 20,000 distinct ideographs
    took about 100 s before the length was checked first. Refused before encoding, a host at the
    link checks' 32 KB cap takes milliseconds (the bound is generous: the machine may be busy)."""
    import time

    long_label = "".join(chr(0x4E00 + i) for i in range(32_000))
    many_labels = ".".join(["ab"] * 10_000) + ".com"
    start = time.perf_counter()
    for host in (long_label + ".com", "xn--" + "a" * 32_000 + ".com", many_labels):
        assert ascii_host(host) is None
        lookalike.browser_host(host)
        decode_host(host)
        mixed_script_reading(host)
    assert time.perf_counter() - start < 5


# ── hosts folded the way a current browser folds them (review of S4, batch 2) ──
# Every expected host below is what the Chromium that Playwright runs here writes for the same
# address (swept code point by code point). Letters are written as code points, so no line of
# this file hides an invisible or look-alike character.

OUTLINED = {ch: chr(0x1CCD6 + i) for i, ch in enumerate("abcdefghijklmnopqrstuvwxyz0123456789")}
PERSIAN_ZWNJ = "".join(map(chr, (0x645, 0x6CC, 0x200C, 0x62E, 0x648, 0x627, 0x647, 0x645)))


def outlined(word: str) -> str:
    """*word* in the outlined Latin letters Unicode 16 added (a browser reads them as ASCII)."""
    return "".join(OUTLINED[ch] for ch in word)


def test_hosts_are_folded_the_way_a_current_browser_folds_them_never_with_str_lower():
    """Review of S4 (batch 2): hosts were folded with NFKC and str.lower(), so for some letters
    this module read another host than the browser opens and looked that one up instead. The
    Cyrillic Extended-C letters are the ordinary Cyrillic ones to a browser, a Cherokee small
    letter is its capital (lower() went the other way), the combining iota is a letter mapped
    before anything is reordered, a capital, lunate or mathematical sigma is sigma wherever it
    stands, and letters newer than the standard library's Unicode database fold too (the
    outlined Latin letters and digits are plain ASCII, so "paypal" in them is paypal.com)."""
    assert ascii_host(chr(0x1C83) * 2 + ".com") == ascii_host(chr(0x441) * 2 + ".com")
    assert ascii_host(chr(0x1C83) * 2 + ".com") == "xn--q1aa.com"
    ordinary = [chr(c) for c in (0x432, 0x434, 0x43E, 0x441, 0x442, 0x442, 0x44A, 0x463, 0xA64B)]
    assert [lookalike.fold_host(chr(0x1C80 + i)) for i in range(9)] == ordinary
    assert ascii_host(chr(0xAB70) + chr(0xAB71) + ".com") == "xn--58dc.com"
    assert ascii_host(chr(0x13A0) + chr(0x13A1) + ".com") == "xn--58dc.com"
    assert ascii_host(chr(0x441) + chr(0x345) + chr(0x308) + ".com") == "xn--cya1v.com"
    sigma = chr(0x3C3)
    assert lookalike.fold_host(chr(0x391) + chr(0x3A3)) == chr(0x3B1) + sigma  # lower(): final sigma
    for written in (chr(0x3F2), chr(0x3F9), chr(0x1D6D3)):
        assert lookalike.fold_host(written) == sigma, hex(ord(written))
    # The letters a browser keeps as written (nontransitional): sharp s and final sigma.
    assert lookalike.fold_host(chr(0xDF) + chr(0x3C2)) == chr(0xDF) + chr(0x3C2)
    assert ascii_host("fa" + chr(0xDF) + ".de") == "xn--fa-hia.de"
    # The capital sharp s is the sharp s to a current browser (UTS 46 15.1 and later).
    assert lookalike.fold_host(chr(0x1E9E)) == chr(0xDF)
    assert ascii_host("account-a" + chr(0x1E9E) + "ist.com") == "xn--account-aist-t9a.com"
    assert ascii_host(outlined("paypal") + ".com") == "paypal.com"
    assert ascii_host("account-a" + chr(0xA7F1) * 2 + "ist.com") == "account-assist.com"
    assert ascii_host("x" + chr(0xA7CB) + "y.com") == ascii_host("x" + chr(0x264) + "y.com")
    for text in ("Shop.Example.COM", "pay" + chr(0x3164) + "pal", chr(0x1C83) + chr(0x1E9E)):
        once = lookalike.fold_host(text)
        assert lookalike.fold_host(once) == once


def test_the_form_a_browser_puts_on_the_wire_reads_back_as_the_same_host():
    """Review of S4 (batch 2): "xn--g9da0d5gqac.com", the form Chromium hands the guard for a
    Cherokee host, was refused as unreadable (its letters are capitals, which lower() changes),
    so it was never looked up for any purpose. Every form a browser writes reads back as itself;
    a label a browser refuses (a capital it would have folded, a joiner where none may stand)
    is still refused."""
    for ace in ("xn--g9da0d5gqac.com", "xn--58dc.com", "xn--q1aa.com", "xn--account-aist-t9a.com",
                "xn--mgbn2ecje63gr19l.com", "xn--11b2ezcw70k.com", "xn--fa-hia.de"):
        readable = lookalike.browser_host(ace)
        assert readable is not None and ascii_host(readable) == ace, ace
        assert ascii_host(ace) == ace
    for refused in (chr(0x416) + "x", "a" + chr(0x200D) + "b"):
        ace = "xn--" + refused.encode("punycode").decode("ascii") + ".com"
        assert lookalike.browser_host(ace) is None, ace
        assert ascii_host(ace) is None, ace


def test_characters_current_browsers_drop_are_dropped_and_joiners_kept_where_a_browser_keeps_them():
    """Review of S4 (batch 2), found while checking the fix against Chromium: UTS 46 16.0 drops
    the Hangul fillers, the Khmer inherent vowels, the Mongolian vowel separator, three invisible
    math operators, the deprecated format controls and the musical beam controls, so
    "pay" + U+3164 + "pal.com" opens paypal.com, while this module read another host or none.
    And every ZWNJ and ZWJ was dropped, although a browser keeps one right after a virama, or a
    ZWNJ between joining letters as Persian is written: a Persian name was read as another
    host. A joiner where a browser refuses the host is still dropped (that only looks up more)."""
    for hidden in (0x115F, 0x1160, 0x17B4, 0x17B5, 0x180E, 0x2061, 0x2062, 0x2063, 0x206A,
                   0x206F, 0x3164, 0xFFA0, 0x1D173, 0x1D17A):
        assert ascii_host("pay" + chr(hidden) + "pal.com") == "paypal.com", hex(hidden)
        assert lookalike.strip_ignored("pay" + chr(hidden) + "pal") == "paypal", hex(hidden)
    assert ascii_host(PERSIAN_ZWNJ + ".com") == "xn--mgbn2ecje63gr19l.com"
    devanagari = "".join(map(chr, (0x915, 0x94D, 0x200D, 0x937)))
    assert ascii_host(devanagari + ".com") == "xn--11b2ezcw70k.com"
    for hidden in (0x200C, 0x200D):
        assert ascii_host("ev" + chr(hidden) + "il.com") == "evil.com"
    beh = chr(0x628)
    assert ascii_host(beh + chr(0x200D) + beh + ".com") == ascii_host(beh + beh + ".com")


def test_folding_a_hostile_host_stays_linear_in_its_length():
    """Hosts of a million characters built from what the fold works hardest on (joiners between
    joining letters or after viramas, combining marks, capital sharp s, Cherokee, padded
    full-width digits, dropped fillers) are read in linear time (a generous bound; the machine
    may be busy)."""
    import time

    units = [
        chr(0x628) + chr(0x200C), chr(0x915) + chr(0x94D) + chr(0x200D), chr(0x200C),
        chr(0x441) + chr(0x345) + chr(0x308), chr(0x1E9E) + "a", chr(0xAB70), chr(0xFF10),
        chr(0x3164) + "a.", OUTLINED["a"],
    ]
    start = time.perf_counter()
    for unit in units:
        host = unit * (1_000_000 // len(unit))
        lookalike.fold_host(host)
        assert ascii_host(host) is None
        lookalike.browser_host(host)
    assert time.perf_counter() - start < 20
